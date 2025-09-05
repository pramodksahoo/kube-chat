package middleware

import (
	"fmt"
	"sync"
	"time"
)

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int

const (
	StateClosed CircuitBreakerState = iota
	StateOpen
	StateHalfOpen
)

// CircuitBreakerConfig holds configuration for the circuit breaker
type CircuitBreakerConfig struct {
	FailureThreshold   int           `json:"failure_threshold"`    // Number of failures to trigger open state
	SuccessThreshold   int           `json:"success_threshold"`    // Number of successes to close from half-open
	Timeout            time.Duration `json:"timeout"`              // Time to wait before transitioning to half-open
	MaxRequests        int           `json:"max_requests"`         // Max requests allowed in half-open state
	OnStateChange      func(CircuitBreakerState) `json:"-"`       // Callback for state changes
}

// CircuitBreaker implements the circuit breaker pattern for external service calls
type CircuitBreaker struct {
	config           CircuitBreakerConfig
	state            CircuitBreakerState
	failureCount     int
	successCount     int
	requestCount     int
	lastFailureTime  time.Time
	mu               sync.RWMutex
}

// CircuitBreakerError represents errors from circuit breaker
type CircuitBreakerError struct {
	State   CircuitBreakerState `json:"state"`
	Message string             `json:"message"`
}

func (e *CircuitBreakerError) Error() string {
	return fmt.Sprintf("circuit breaker %s: %s", e.stateString(), e.Message)
}

func (e *CircuitBreakerError) stateString() string {
	switch e.State {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// NewCircuitBreaker creates a new circuit breaker with the given configuration
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	// Set defaults
	if config.FailureThreshold == 0 {
		config.FailureThreshold = 5
	}
	if config.SuccessThreshold == 0 {
		config.SuccessThreshold = 2
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxRequests == 0 {
		config.MaxRequests = 10
	}

	return &CircuitBreaker{
		config:          config,
		state:           StateClosed,
		failureCount:    0,
		successCount:    0,
		requestCount:    0,
		lastFailureTime: time.Now(),
	}
}

// Execute runs a function with circuit breaker protection
func (cb *CircuitBreaker) Execute(fn func() error) error {
	// Check if we can execute the request
	if !cb.canExecute() {
		return &CircuitBreakerError{
			State:   cb.getState(),
			Message: "circuit breaker is open",
		}
	}

	// Execute the function
	err := fn()

	// Handle the result
	if err != nil {
		cb.onFailure()
		return err
	}

	cb.onSuccess()
	return nil
}

// canExecute determines if a request can be executed based on circuit breaker state
func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		// Check if timeout has passed to move to half-open
		if time.Since(cb.lastFailureTime) > cb.config.Timeout {
			cb.setState(StateHalfOpen)
			return true
		}
		return false
	case StateHalfOpen:
		// Allow limited requests in half-open state
		return cb.requestCount < cb.config.MaxRequests
	default:
		return false
	}
}

// onSuccess handles successful execution
func (cb *CircuitBreaker) onSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		// Reset failure count on success
		cb.failureCount = 0
	case StateHalfOpen:
		cb.successCount++
		cb.requestCount++
		
		// Close circuit if we have enough successes
		if cb.successCount >= cb.config.SuccessThreshold {
			cb.setState(StateClosed)
			cb.reset()
		}
	}
}

// onFailure handles failed execution
func (cb *CircuitBreaker) onFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		// Open circuit if failure threshold is reached
		if cb.failureCount >= cb.config.FailureThreshold {
			cb.setState(StateOpen)
		}
	case StateHalfOpen:
		// Go back to open on any failure in half-open state
		cb.setState(StateOpen)
		cb.requestCount = 0
		cb.successCount = 0
	}
}

// setState changes the circuit breaker state and calls the callback if configured
func (cb *CircuitBreaker) setState(state CircuitBreakerState) {
	if cb.state != state {
		cb.state = state
		if cb.config.OnStateChange != nil {
			cb.config.OnStateChange(state)
		}
	}
}

// getState returns the current circuit breaker state (thread-safe)
func (cb *CircuitBreaker) getState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// reset clears counters and resets the circuit breaker state
func (cb *CircuitBreaker) reset() {
	cb.failureCount = 0
	cb.successCount = 0
	cb.requestCount = 0
}

// GetMetrics returns current metrics for monitoring
func (cb *CircuitBreaker) GetMetrics() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	return map[string]interface{}{
		"state":                cb.state,
		"failure_count":        cb.failureCount,
		"success_count":        cb.successCount,
		"request_count":        cb.requestCount,
		"last_failure_time":    cb.lastFailureTime,
		"failure_threshold":    cb.config.FailureThreshold,
		"success_threshold":    cb.config.SuccessThreshold,
		"timeout":              cb.config.Timeout,
		"max_requests":         cb.config.MaxRequests,
	}
}

// IsOpen returns true if the circuit breaker is in open state
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.getState() == StateOpen
}

// IsClosed returns true if the circuit breaker is in closed state
func (cb *CircuitBreaker) IsClosed() bool {
	return cb.getState() == StateClosed
}

// IsHalfOpen returns true if the circuit breaker is in half-open state
func (cb *CircuitBreaker) IsHalfOpen() bool {
	return cb.getState() == StateHalfOpen
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.setState(StateOpen)
}

// ForceClose forces the circuit breaker to closed state
func (cb *CircuitBreaker) ForceClose() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.setState(StateClosed)
	cb.reset()
}