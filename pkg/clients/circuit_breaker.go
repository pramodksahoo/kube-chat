package clients

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// CircuitState represents the current state of the circuit breaker
type CircuitState string

const (
	CircuitStateClosed   CircuitState = "closed"   // Normal operation
	CircuitStateOpen     CircuitState = "open"     // Circuit is open, failing fast
	CircuitStateHalfOpen CircuitState = "half_open" // Testing if service has recovered
)

// CircuitBreakerConfig configures the circuit breaker behavior
type CircuitBreakerConfig struct {
	MaxFailures     int           `json:"maxFailures"`     // Number of failures before opening
	ResetTimeout    time.Duration `json:"resetTimeout"`    // Time to wait before attempting reset
	SuccessThreshold int          `json:"successThreshold"` // Consecutive successes needed to close from half-open
	Timeout         time.Duration `json:"timeout"`         // Operation timeout
}

// DefaultCircuitBreakerConfig returns default configuration
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures:     5,
		ResetTimeout:    60 * time.Second,
		SuccessThreshold: 2,
		Timeout:         30 * time.Second,
	}
}

// CircuitBreakerStats tracks circuit breaker statistics
type CircuitBreakerStats struct {
	State                CircuitState  `json:"state"`
	FailureCount        int           `json:"failureCount"`
	SuccessCount        int           `json:"successCount"`
	TotalRequests       int           `json:"totalRequests"`
	LastFailureTime     time.Time     `json:"lastFailureTime"`
	LastStateChange     time.Time     `json:"lastStateChange"`
	CircuitOpenDuration time.Duration `json:"circuitOpenDuration"`
}

// CircuitBreaker implements the circuit breaker pattern for external dependencies
type CircuitBreaker struct {
	name      string
	config    CircuitBreakerConfig
	state     CircuitState
	mutex     sync.RWMutex
	
	// Counters
	failureCount    int
	successCount    int
	totalRequests   int
	lastFailure     time.Time
	lastStateChange time.Time
	
	// State management
	nextAttemptAfter time.Time
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(name string, config CircuitBreakerConfig) *CircuitBreaker {
	return &CircuitBreaker{
		name:            name,
		config:          config,
		state:           CircuitStateClosed,
		lastStateChange: time.Now(),
	}
}

// Execute runs a function through the circuit breaker
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	cb.mutex.Lock()
	
	// Check if circuit is open and if we should attempt a reset
	if cb.state == CircuitStateOpen {
		if time.Now().Before(cb.nextAttemptAfter) {
			cb.mutex.Unlock()
			return fmt.Errorf("circuit breaker '%s' is open - failing fast", cb.name)
		}
		// Try to transition to half-open
		cb.state = CircuitStateHalfOpen
		cb.successCount = 0
		cb.lastStateChange = time.Now()
	}
	
	cb.totalRequests++
	cb.mutex.Unlock()
	
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, cb.config.Timeout)
	defer cancel()
	
	// Execute the function with timeout
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errChan <- fmt.Errorf("panic recovered in circuit breaker '%s': %v", cb.name, r)
			}
		}()
		errChan <- fn(timeoutCtx)
	}()
	
	select {
	case <-timeoutCtx.Done():
		cb.recordFailure()
		return fmt.Errorf("circuit breaker '%s' operation timed out", cb.name)
	case err := <-errChan:
		if err != nil {
			cb.recordFailure()
			return err
		}
		cb.recordSuccess()
		return nil
	}
}

// recordFailure records a failure and potentially opens the circuit
func (cb *CircuitBreaker) recordFailure() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.failureCount++
	cb.lastFailure = time.Now()
	
	if cb.state == CircuitStateHalfOpen {
		// Half-open failed, go back to open
		cb.state = CircuitStateOpen
		cb.nextAttemptAfter = time.Now().Add(cb.config.ResetTimeout)
		cb.lastStateChange = time.Now()
	} else if cb.state == CircuitStateClosed && cb.failureCount >= cb.config.MaxFailures {
		// Too many failures, open the circuit
		cb.state = CircuitStateOpen
		cb.nextAttemptAfter = time.Now().Add(cb.config.ResetTimeout)
		cb.lastStateChange = time.Now()
	}
}

// recordSuccess records a success and potentially closes the circuit
func (cb *CircuitBreaker) recordSuccess() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.successCount++
	
	if cb.state == CircuitStateHalfOpen && cb.successCount >= cb.config.SuccessThreshold {
		// Enough successes, close the circuit
		cb.state = CircuitStateClosed
		cb.failureCount = 0
		cb.successCount = 0
		cb.lastStateChange = time.Now()
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	return cb.state
}

// GetStats returns current statistics
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mutex.RLock()
	defer cb.mutex.RUnlock()
	
	var openDuration time.Duration
	if cb.state == CircuitStateOpen {
		openDuration = time.Since(cb.lastStateChange)
	}
	
	return CircuitBreakerStats{
		State:                cb.state,
		FailureCount:        cb.failureCount,
		SuccessCount:        cb.successCount,
		TotalRequests:       cb.totalRequests,
		LastFailureTime:     cb.lastFailure,
		LastStateChange:     cb.lastStateChange,
		CircuitOpenDuration: openDuration,
	}
}

// Reset manually resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mutex.Lock()
	defer cb.mutex.Unlock()
	
	cb.state = CircuitStateClosed
	cb.failureCount = 0
	cb.successCount = 0
	cb.lastStateChange = time.Now()
}

// IsHealthy returns whether the circuit breaker considers the service healthy
func (cb *CircuitBreaker) IsHealthy() bool {
	return cb.GetState() != CircuitStateOpen
}

// GetHealthReport returns a formatted health report
func (cb *CircuitBreaker) GetHealthReport() string {
	stats := cb.GetStats()
	
	var report string
	switch stats.State {
	case CircuitStateClosed:
		report = fmt.Sprintf("✅ **Circuit Breaker '%s': HEALTHY**\n", cb.name)
		report += fmt.Sprintf("**State:** Closed (normal operation)\n")
	case CircuitStateHalfOpen:
		report = fmt.Sprintf("🟡 **Circuit Breaker '%s': TESTING**\n", cb.name)
		report += fmt.Sprintf("**State:** Half-Open (testing recovery)\n")
		report += fmt.Sprintf("**Success Count:** %d/%d\n", stats.SuccessCount, cb.config.SuccessThreshold)
	case CircuitStateOpen:
		report = fmt.Sprintf("❌ **Circuit Breaker '%s': FAILING**\n", cb.name)
		report += fmt.Sprintf("**State:** Open (failing fast)\n")
		report += fmt.Sprintf("**Open Duration:** %s\n", stats.CircuitOpenDuration)
		report += fmt.Sprintf("**Next Attempt:** %s\n", cb.nextAttemptAfter.Format(time.RFC3339))
	}
	
	report += fmt.Sprintf("**Total Requests:** %d\n", stats.TotalRequests)
	report += fmt.Sprintf("**Failure Count:** %d\n", stats.FailureCount)
	
	if !stats.LastFailureTime.IsZero() {
		report += fmt.Sprintf("**Last Failure:** %s\n", stats.LastFailureTime.Format(time.RFC3339))
	}
	
	return report
}

// CircuitBreakerManager manages multiple circuit breakers
type CircuitBreakerManager struct {
	breakers map[string]*CircuitBreaker
	mutex    sync.RWMutex
}

// NewCircuitBreakerManager creates a new circuit breaker manager
func NewCircuitBreakerManager() *CircuitBreakerManager {
	return &CircuitBreakerManager{
		breakers: make(map[string]*CircuitBreaker),
	}
}

// GetOrCreateBreaker returns an existing circuit breaker or creates a new one
func (cbm *CircuitBreakerManager) GetOrCreateBreaker(name string, config CircuitBreakerConfig) *CircuitBreaker {
	cbm.mutex.RLock()
	if breaker, exists := cbm.breakers[name]; exists {
		cbm.mutex.RUnlock()
		return breaker
	}
	cbm.mutex.RUnlock()
	
	cbm.mutex.Lock()
	defer cbm.mutex.Unlock()
	
	// Double-check after acquiring write lock
	if breaker, exists := cbm.breakers[name]; exists {
		return breaker
	}
	
	breaker := NewCircuitBreaker(name, config)
	cbm.breakers[name] = breaker
	return breaker
}

// GetAllStats returns stats for all circuit breakers
func (cbm *CircuitBreakerManager) GetAllStats() map[string]CircuitBreakerStats {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()
	
	stats := make(map[string]CircuitBreakerStats)
	for name, breaker := range cbm.breakers {
		stats[name] = breaker.GetStats()
	}
	return stats
}

// GetHealthReport returns a consolidated health report for all circuit breakers
func (cbm *CircuitBreakerManager) GetHealthReport() string {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()
	
	if len(cbm.breakers) == 0 {
		return "No circuit breakers configured\n"
	}
	
	var report string
	healthyCount := 0
	
	for _, breaker := range cbm.breakers {
		report += breaker.GetHealthReport() + "\n"
		if breaker.IsHealthy() {
			healthyCount++
		}
	}
	
	report += fmt.Sprintf("\n**Summary:** %d/%d circuit breakers healthy\n", healthyCount, len(cbm.breakers))
	
	return report
}

// ResetAll resets all circuit breakers
func (cbm *CircuitBreakerManager) ResetAll() {
	cbm.mutex.RLock()
	defer cbm.mutex.RUnlock()
	
	for _, breaker := range cbm.breakers {
		breaker.Reset()
	}
}

// WrapKubernetesClient wraps a kubernetes client with circuit breaker protection
func (cbm *CircuitBreakerManager) WrapKubernetesClient(client KubernetesClient, config CircuitBreakerConfig) *CircuitBreakerKubernetesClient {
	breaker := cbm.GetOrCreateBreaker("kubernetes-api", config)
	return &CircuitBreakerKubernetesClient{
		client:  client,
		breaker: breaker,
	}
}

// CircuitBreakerKubernetesClient wraps KubernetesClient with circuit breaker pattern
type CircuitBreakerKubernetesClient struct {
	client  KubernetesClient
	breaker *CircuitBreaker
}

// ExecuteCommand executes a command through the circuit breaker
func (cbkc *CircuitBreakerKubernetesClient) ExecuteCommand(ctx context.Context, command *models.KubernetesCommand) (*models.CommandExecutionResult, error) {
	var result *models.CommandExecutionResult
	var execErr error
	
	err := cbkc.breaker.Execute(ctx, func(ctx context.Context) error {
		result, execErr = cbkc.client.ExecuteCommand(ctx, command)
		return execErr
	})
	
	if err != nil {
		// Circuit breaker error (timeout, circuit open, etc.)
		return &models.CommandExecutionResult{
			Success:         false,
			Output:          "",
			Error:           err.Error(),
			ExitCode:        1,
			ExecutionTime:   0,
			FormattedOutput: fmt.Sprintf("🔴 **Service Unavailable**\n\n%s\n\nThe Kubernetes API service is currently experiencing issues. Please try again later.", err.Error()),
		}, nil
	}
	
	return result, nil
}

// ValidateRBAC validates RBAC through the circuit breaker
func (cbkc *CircuitBreakerKubernetesClient) ValidateRBAC(ctx context.Context, command *models.KubernetesCommand) error {
	return cbkc.breaker.Execute(ctx, func(ctx context.Context) error {
		return cbkc.client.ValidateRBAC(ctx, command)
	})
}

// GetVersion gets version through the circuit breaker
func (cbkc *CircuitBreakerKubernetesClient) GetVersion(ctx context.Context) (string, error) {
	var version string
	err := cbkc.breaker.Execute(ctx, func(ctx context.Context) error {
		var versionErr error
		version, versionErr = cbkc.client.GetVersion(ctx)
		return versionErr
	})
	return version, err
}

// GetCircuitBreakerStats returns circuit breaker statistics
func (cbkc *CircuitBreakerKubernetesClient) GetCircuitBreakerStats() CircuitBreakerStats {
	return cbkc.breaker.GetStats()
}