package middleware

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCircuitBreakerError(t *testing.T) {
	tests := []struct {
		name        string
		state       CircuitBreakerState
		message     string
		expectedMsg string
	}{
		{
			name:        "closed state error",
			state:       StateClosed,
			message:     "test error",
			expectedMsg: "circuit breaker closed: test error",
		},
		{
			name:        "open state error",
			state:       StateOpen,
			message:     "circuit is open",
			expectedMsg: "circuit breaker open: circuit is open",
		},
		{
			name:        "half-open state error",
			state:       StateHalfOpen,
			message:     "half open test",
			expectedMsg: "circuit breaker half-open: half open test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &CircuitBreakerError{
				State:   tt.state,
				Message: tt.message,
			}
			assert.Equal(t, tt.expectedMsg, err.Error())
		})
	}
}

func TestNewCircuitBreaker(t *testing.T) {
	tests := []struct {
		name           string
		config         CircuitBreakerConfig
		expectedConfig CircuitBreakerConfig
	}{
		{
			name:   "default configuration",
			config: CircuitBreakerConfig{},
			expectedConfig: CircuitBreakerConfig{
				FailureThreshold: 5,
				SuccessThreshold: 2,
				Timeout:          30 * time.Second,
				MaxRequests:      10,
			},
		},
		{
			name: "custom configuration",
			config: CircuitBreakerConfig{
				FailureThreshold: 3,
				SuccessThreshold: 1,
				Timeout:          10 * time.Second,
				MaxRequests:      5,
			},
			expectedConfig: CircuitBreakerConfig{
				FailureThreshold: 3,
				SuccessThreshold: 1,
				Timeout:          10 * time.Second,
				MaxRequests:      5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := NewCircuitBreaker(tt.config)
			assert.NotNil(t, cb)
			assert.Equal(t, StateClosed, cb.state)
			assert.Equal(t, tt.expectedConfig.FailureThreshold, cb.config.FailureThreshold)
			assert.Equal(t, tt.expectedConfig.SuccessThreshold, cb.config.SuccessThreshold)
			assert.Equal(t, tt.expectedConfig.Timeout, cb.config.Timeout)
			assert.Equal(t, tt.expectedConfig.MaxRequests, cb.config.MaxRequests)
		})
	}
}

func TestCircuitBreakerExecute(t *testing.T) {
	tests := []struct {
		name        string
		config      CircuitBreakerConfig
		operations  []operation
		expectedFinal CircuitBreakerState
	}{
		{
			name: "all successful operations",
			config: CircuitBreakerConfig{
				FailureThreshold: 3,
				SuccessThreshold: 2,
				Timeout:          30 * time.Second,
				MaxRequests:      10,
			},
			operations: []operation{
				{shouldFail: false},
				{shouldFail: false},
				{shouldFail: false},
			},
			expectedFinal: StateClosed,
		},
		{
			name: "open circuit after failures",
			config: CircuitBreakerConfig{
				FailureThreshold: 2,
				SuccessThreshold: 1,
				Timeout:          30 * time.Second,
				MaxRequests:      10,
			},
			operations: []operation{
				{shouldFail: true},
				{shouldFail: true},
			},
			expectedFinal: StateOpen,
		},
		{
			name: "recovery from open to closed",
			config: CircuitBreakerConfig{
				FailureThreshold: 2,
				SuccessThreshold: 2,
				Timeout:          100 * time.Millisecond,
				MaxRequests:      5,
			},
			operations: []operation{
				{shouldFail: true},
				{shouldFail: true},
				{wait: 150 * time.Millisecond}, // Wait for timeout
				{shouldFail: false},            // Should work (half-open)
				{shouldFail: false},            // Should close circuit
			},
			expectedFinal: StateClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := NewCircuitBreaker(tt.config)

			for i, op := range tt.operations {
				if op.wait > 0 {
					time.Sleep(op.wait)
					continue
				}

				err := cb.Execute(func() error {
					if op.shouldFail {
						return errors.New("operation failed")
					}
					return nil
				})

				if op.shouldFail && cb.state != StateOpen {
					assert.Error(t, err, "Operation %d should fail", i)
				}
			}

			assert.Equal(t, tt.expectedFinal, cb.getState())
		})
	}
}

type operation struct {
	shouldFail bool
	wait       time.Duration
}

func TestCircuitBreakerStateTransitions(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 2,
		SuccessThreshold: 2,
		Timeout:          50 * time.Millisecond,
		MaxRequests:      3,
	}

	cb := NewCircuitBreaker(config)

	// Initially closed
	assert.True(t, cb.IsClosed())
	assert.False(t, cb.IsOpen())
	assert.False(t, cb.IsHalfOpen())

	// Trigger failures to open circuit
	for i := 0; i < 2; i++ {
		err := cb.Execute(func() error {
			return errors.New("failure")
		})
		assert.Error(t, err)
	}

	// Should be open now
	assert.True(t, cb.IsOpen())
	assert.False(t, cb.IsClosed())
	assert.False(t, cb.IsHalfOpen())

	// Requests should be rejected
	err := cb.Execute(func() error {
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Should allow requests in half-open state
	err = cb.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, cb.IsHalfOpen())

	// Another success should close the circuit
	err = cb.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, cb.IsClosed())
}

func TestCircuitBreakerMetrics(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 3,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
		MaxRequests:      5,
	}

	cb := NewCircuitBreaker(config)

	// Execute some operations
	cb.Execute(func() error { return nil })
	cb.Execute(func() error { return errors.New("fail") })

	metrics := cb.GetMetrics()
	assert.NotNil(t, metrics)
	assert.Equal(t, StateClosed, metrics["state"])
	assert.Equal(t, 1, metrics["failure_count"])
	assert.Equal(t, 0, metrics["success_count"])
	assert.Equal(t, 0, metrics["request_count"])
	assert.Equal(t, 3, metrics["failure_threshold"])
	assert.Equal(t, 2, metrics["success_threshold"])
	assert.Equal(t, 30*time.Second, metrics["timeout"])
	assert.Equal(t, 5, metrics["max_requests"])
}

func TestCircuitBreakerForceState(t *testing.T) {
	cb := NewCircuitBreaker(CircuitBreakerConfig{})

	// Test force open
	cb.ForceOpen()
	assert.True(t, cb.IsOpen())

	// Test force close
	cb.ForceClose()
	assert.True(t, cb.IsClosed())
}

func TestCircuitBreakerStateCallback(t *testing.T) {
	var stateChanges []CircuitBreakerState
	var mu sync.Mutex

	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 1,
		Timeout:          10 * time.Millisecond,
		MaxRequests:      2,
		OnStateChange: func(state CircuitBreakerState) {
			mu.Lock()
			stateChanges = append(stateChanges, state)
			mu.Unlock()
		},
	}

	cb := NewCircuitBreaker(config)

	// Trigger failure to open
	cb.Execute(func() error {
		return errors.New("fail")
	})

	// Wait for timeout and test recovery
	time.Sleep(15 * time.Millisecond)
	cb.Execute(func() error {
		return nil
	})

	mu.Lock()
	defer mu.Unlock()
	assert.Len(t, stateChanges, 3) // closed->open->half-open->closed
	assert.Equal(t, StateOpen, stateChanges[0])
	assert.Equal(t, StateHalfOpen, stateChanges[1])
	assert.Equal(t, StateClosed, stateChanges[2])
}

func TestCircuitBreakerHalfOpenLimits(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 1,
		SuccessThreshold: 3, // Require 3 successes to close
		Timeout:          50 * time.Millisecond,
		MaxRequests:      2, // Only allow 2 requests in half-open
	}

	cb := NewCircuitBreaker(config)

	// Open the circuit
	err := cb.Execute(func() error {
		return errors.New("fail")
	})
	assert.Error(t, err)
	assert.True(t, cb.IsOpen())

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// First request should be allowed (half-open)
	err = cb.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, cb.IsHalfOpen())

	// Second request should be allowed
	err = cb.Execute(func() error {
		return nil
	})
	assert.NoError(t, err)
	assert.True(t, cb.IsHalfOpen()) // Still half-open since we need 3 successes

	// Third request should be rejected (exceeds MaxRequests)
	err = cb.Execute(func() error {
		return nil
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker is open")
}

func TestCircuitBreakerConcurrency(t *testing.T) {
	config := CircuitBreakerConfig{
		FailureThreshold: 10,
		SuccessThreshold: 2,
		Timeout:          30 * time.Second,
		MaxRequests:      20,
	}

	cb := NewCircuitBreaker(config)

	const numGoroutines = 50
	const operationsPerGoroutine = 20

	var wg sync.WaitGroup
	var successCount, errorCount int64
	var mu sync.Mutex

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < operationsPerGoroutine; j++ {
				err := cb.Execute(func() error {
					// Occasionally fail
					if (id*operationsPerGoroutine+j)%20 == 0 {
						return errors.New("random failure")
					}
					return nil
				})

				mu.Lock()
				if err != nil {
					errorCount++
				} else {
					successCount++
				}
				mu.Unlock()
			}
		}(i)
	}

	wg.Wait()

	totalOps := int64(numGoroutines * operationsPerGoroutine)
	t.Logf("Total operations: %d, Successes: %d, Errors: %d", 
		totalOps, successCount, errorCount)
	
	// Most operations should succeed since we have a high failure threshold
	assert.Greater(t, successCount, errorCount)
	assert.Equal(t, totalOps, successCount+errorCount)
}