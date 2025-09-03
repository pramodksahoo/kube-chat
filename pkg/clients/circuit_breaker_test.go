package clients

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCircuitBreaker(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker("test-service", config)
	
	assert.NotNil(t, cb)
	assert.Equal(t, "test-service", cb.name)
	assert.Equal(t, config, cb.config)
	assert.Equal(t, CircuitStateClosed, cb.state)
	assert.Equal(t, 0, cb.failureCount)
}

func TestDefaultCircuitBreakerConfig(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	
	assert.Equal(t, 5, config.MaxFailures)
	assert.Equal(t, 60*time.Second, config.ResetTimeout)
	assert.Equal(t, 2, config.SuccessThreshold)
	assert.Equal(t, 30*time.Second, config.Timeout)
}

func TestCircuitBreakerExecuteSuccess(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Execute successful function
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})
	
	assert.NoError(t, err)
	assert.Equal(t, CircuitStateClosed, cb.GetState())
	
	stats := cb.GetStats()
	assert.Equal(t, CircuitStateClosed, stats.State)
	assert.Equal(t, 1, stats.TotalRequests)
	assert.Equal(t, 0, stats.FailureCount)
	assert.Equal(t, 1, stats.SuccessCount)
}

func TestCircuitBreakerExecuteFailure(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:     2,
		ResetTimeout:    1 * time.Second,
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	expectedError := fmt.Errorf("service error")
	
	// First failure - should remain closed
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return expectedError
	})
	
	assert.Equal(t, expectedError, err)
	assert.Equal(t, CircuitStateClosed, cb.GetState())
	
	// Second failure - should open circuit
	err = cb.Execute(ctx, func(ctx context.Context) error {
		return expectedError
	})
	
	assert.Equal(t, expectedError, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
	
	stats := cb.GetStats()
	assert.Equal(t, 2, stats.FailureCount)
}

func TestCircuitBreakerOpenStateFailsFast(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:     1,
		ResetTimeout:    1 * time.Hour, // Long reset timeout
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Cause circuit to open
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return fmt.Errorf("failure")
	})
	assert.Error(t, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
	
	// Next call should fail fast
	err = cb.Execute(ctx, func(ctx context.Context) error {
		t.Fatal("Function should not be called when circuit is open")
		return nil
	})
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "circuit breaker 'test-service' is open - failing fast")
}

func TestCircuitBreakerHalfOpenTransition(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:     1,
		ResetTimeout:    100 * time.Millisecond, // Short reset timeout for testing
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Open the circuit
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return fmt.Errorf("failure")
	})
	assert.Error(t, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
	
	// Wait for reset timeout
	time.Sleep(150 * time.Millisecond)
	
	// Next call should transition to half-open and succeed
	err = cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})
	
	assert.NoError(t, err)
	assert.Equal(t, CircuitStateClosed, cb.GetState()) // Should close after successful call
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:     1,
		ResetTimeout:    100 * time.Millisecond,
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Open the circuit
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return fmt.Errorf("failure")
	})
	assert.Error(t, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
	
	// Wait for reset timeout
	time.Sleep(150 * time.Millisecond)
	
	// Fail in half-open state - should go back to open
	err = cb.Execute(ctx, func(ctx context.Context) error {
		return fmt.Errorf("still failing")
	})
	
	assert.Error(t, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
}

func TestCircuitBreakerTimeout(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:     5,
		ResetTimeout:    1 * time.Second,
		SuccessThreshold: 1,
		Timeout:         50 * time.Millisecond, // Short timeout
	}
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Execute function that takes longer than timeout
	err := cb.Execute(ctx, func(ctx context.Context) error {
		time.Sleep(100 * time.Millisecond)
		return nil
	})
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	
	stats := cb.GetStats()
	assert.Equal(t, 1, stats.FailureCount)
}

func TestCircuitBreakerPanicRecovery(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Execute function that panics
	err := cb.Execute(ctx, func(ctx context.Context) error {
		panic("test panic")
	})
	
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "panic recovered")
	
	stats := cb.GetStats()
	assert.Equal(t, 1, stats.FailureCount)
}

func TestCircuitBreakerReset(t *testing.T) {
	config := CircuitBreakerConfig{
		MaxFailures:     1,
		ResetTimeout:    1 * time.Hour,
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	cb := NewCircuitBreaker("test-service", config)
	
	ctx := context.Background()
	
	// Open the circuit
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return fmt.Errorf("failure")
	})
	assert.Error(t, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
	
	// Manual reset
	cb.Reset()
	assert.Equal(t, CircuitStateClosed, cb.GetState())
	
	stats := cb.GetStats()
	assert.Equal(t, 0, stats.FailureCount)
	assert.Equal(t, 0, stats.SuccessCount)
}

func TestCircuitBreakerHealthReport(t *testing.T) {
	config := DefaultCircuitBreakerConfig()
	cb := NewCircuitBreaker("test-service", config)
	
	t.Run("healthy circuit", func(t *testing.T) {
		report := cb.GetHealthReport()
		assert.Contains(t, report, "HEALTHY")
		assert.Contains(t, report, "Closed")
		assert.Contains(t, report, "test-service")
	})
	
	t.Run("open circuit", func(t *testing.T) {
		// Force circuit open
		cb.state = CircuitStateOpen
		cb.failureCount = 5
		cb.lastStateChange = time.Now()
		cb.nextAttemptAfter = time.Now().Add(1 * time.Hour)
		
		report := cb.GetHealthReport()
		assert.Contains(t, report, "FAILING")
		assert.Contains(t, report, "Open")
		assert.Contains(t, report, "Next Attempt:")
	})
	
	t.Run("half-open circuit", func(t *testing.T) {
		cb.state = CircuitStateHalfOpen
		cb.successCount = 1
		
		report := cb.GetHealthReport()
		assert.Contains(t, report, "TESTING")
		assert.Contains(t, report, "Half-Open")
		assert.Contains(t, report, "Success Count:")
	})
}

func TestCircuitBreakerManager(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := DefaultCircuitBreakerConfig()
	
	// Get or create circuit breaker
	cb1 := manager.GetOrCreateBreaker("service1", config)
	cb2 := manager.GetOrCreateBreaker("service1", config) // Same service
	cb3 := manager.GetOrCreateBreaker("service2", config) // Different service
	
	assert.Equal(t, cb1, cb2, "should return same breaker for same service")
	assert.NotEqual(t, cb1, cb3, "should return different breakers for different services")
	
	// Test stats
	allStats := manager.GetAllStats()
	assert.Len(t, allStats, 2)
	assert.Contains(t, allStats, "service1")
	assert.Contains(t, allStats, "service2")
}

func TestCircuitBreakerManagerHealthReport(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := DefaultCircuitBreakerConfig()
	
	t.Run("no circuit breakers", func(t *testing.T) {
		report := manager.GetHealthReport()
		assert.Contains(t, report, "No circuit breakers configured")
	})
	
	t.Run("with circuit breakers", func(t *testing.T) {
		manager.GetOrCreateBreaker("service1", config)
		manager.GetOrCreateBreaker("service2", config)
		
		report := manager.GetHealthReport()
		assert.Contains(t, report, "service1")
		assert.Contains(t, report, "service2")
		assert.Contains(t, report, "2/2 circuit breakers healthy")
	})
}

func TestCircuitBreakerManagerResetAll(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := CircuitBreakerConfig{
		MaxFailures:     1,
		ResetTimeout:    1 * time.Second,
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	
	// Create and break a circuit
	cb := manager.GetOrCreateBreaker("service1", config)
	ctx := context.Background()
	
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return fmt.Errorf("failure")
	})
	assert.Error(t, err)
	assert.Equal(t, CircuitStateOpen, cb.GetState())
	
	// Reset all
	manager.ResetAll()
	assert.Equal(t, CircuitStateClosed, cb.GetState())
}

func TestCircuitBreakerKubernetesClient(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := DefaultCircuitBreakerConfig()
	
	// Create mock kubernetes client
	mockClient := &MockKubernetesClient{}
	
	// Wrap with circuit breaker
	cbClient := manager.WrapKubernetesClient(mockClient, config)
	require.NotNil(t, cbClient)
	
	ctx := context.Background()
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
		Status:          models.CommandStatusApproved,
	}
	
	expectedResult := &models.CommandExecutionResult{
		Success: true,
		Output:  "nginx-pod Running",
	}
	
	// Mock successful call
	mockClient.On("ExecuteCommand", ctx, command).Return(expectedResult, nil)
	
	result, err := cbClient.ExecuteCommand(ctx, command)
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	
	mockClient.AssertExpectations(t)
}

func TestCircuitBreakerKubernetesClientFailure(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := CircuitBreakerConfig{
		MaxFailures:     1,
		ResetTimeout:    1 * time.Second,
		SuccessThreshold: 1,
		Timeout:         1 * time.Second,
	}
	
	mockClient := &MockKubernetesClient{}
	cbClient := manager.WrapKubernetesClient(mockClient, config)
	
	ctx := context.Background()
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
		Status:          models.CommandStatusApproved,
	}
	
	// Mock failing call
	mockClient.On("ExecuteCommand", ctx, command).Return((*models.CommandExecutionResult)(nil), fmt.Errorf("connection failed"))
	
	// First call should fail and open circuit
	result, err := cbClient.ExecuteCommand(ctx, command)
	assert.NoError(t, err) // Circuit breaker returns result, not error
	assert.False(t, result.Success)
	assert.Contains(t, result.Error, "connection failed")
	
	// Second call should fail fast
	result, err = cbClient.ExecuteCommand(ctx, command)
	assert.NoError(t, err)
	assert.False(t, result.Success)
	assert.Contains(t, result.FormattedOutput, "Service Unavailable")
	
	mockClient.AssertExpectations(t)
}

func TestCircuitBreakerGetVersion(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := DefaultCircuitBreakerConfig()
	
	mockClient := &MockKubernetesClient{}
	cbClient := manager.WrapKubernetesClient(mockClient, config)
	
	ctx := context.Background()
	
	// Mock successful call
	mockClient.On("GetVersion", ctx).Return("v1.21.0", nil)
	
	version, err := cbClient.GetVersion(ctx)
	assert.NoError(t, err)
	assert.Equal(t, "v1.21.0", version)
	
	mockClient.AssertExpectations(t)
}

func TestCircuitBreakerValidateRBAC(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := DefaultCircuitBreakerConfig()
	
	mockClient := &MockKubernetesClient{}
	cbClient := manager.WrapKubernetesClient(mockClient, config)
	
	ctx := context.Background()
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	
	// Mock successful validation
	mockClient.On("ValidateRBAC", ctx, command).Return(nil)
	
	err := cbClient.ValidateRBAC(ctx, command)
	assert.NoError(t, err)
	
	mockClient.AssertExpectations(t)
}

func TestCircuitBreakerStats(t *testing.T) {
	manager := NewCircuitBreakerManager()
	config := DefaultCircuitBreakerConfig()
	
	mockClient := &MockKubernetesClient{}
	cbClient := manager.WrapKubernetesClient(mockClient, config)
	
	stats := cbClient.GetCircuitBreakerStats()
	assert.Equal(t, CircuitStateClosed, stats.State)
	assert.Equal(t, 0, stats.TotalRequests)
	assert.Equal(t, 0, stats.FailureCount)
}