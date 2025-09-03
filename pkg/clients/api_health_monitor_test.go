package clients

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockKubernetesClient for testing
type MockKubernetesClient struct {
	mock.Mock
}

func (m *MockKubernetesClient) ExecuteCommand(ctx context.Context, command *models.KubernetesCommand) (*models.CommandExecutionResult, error) {
	args := m.Called(ctx, command)
	return args.Get(0).(*models.CommandExecutionResult), args.Error(1)
}

func (m *MockKubernetesClient) ValidateRBAC(ctx context.Context, command *models.KubernetesCommand) error {
	args := m.Called(ctx, command)
	return args.Error(0)
}

func (m *MockKubernetesClient) GetVersion(ctx context.Context) (string, error) {
	args := m.Called(ctx)
	return args.String(0), args.Error(1)
}

func TestNewAPIHealthMonitor(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	assert.NotNil(t, monitor)
	assert.Equal(t, 30*time.Second, monitor.checkInterval)
	assert.Equal(t, 10*time.Second, monitor.timeout)
	assert.Equal(t, 3, monitor.maxFailures)
	assert.True(t, monitor.status.IsHealthy)
}

func TestAPIHealthMonitorConfiguration(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	// Test setting check interval
	monitor.SetCheckInterval(15 * time.Second)
	assert.Equal(t, 15*time.Second, monitor.checkInterval)
	
	// Test setting timeout
	monitor.SetTimeout(5 * time.Second)
	assert.Equal(t, 5*time.Second, monitor.timeout)
	
	// Test setting max failures
	monitor.SetMaxFailures(5)
	assert.Equal(t, 5, monitor.maxFailures)
}

func TestAPIHealthMonitorHealthyState(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	// Mock successful version call
	mockClient.On("GetVersion", mock.Anything).Return("v1.21.0", nil)
	
	ctx := context.Background()
	
	// Perform health check
	monitor.performHealthCheck(ctx)
	
	// Verify healthy state
	assert.True(t, monitor.IsHealthy())
	status := monitor.GetStatus()
	assert.True(t, status.IsHealthy)
	assert.Equal(t, 0, status.ConsecutiveFailures)
	assert.Equal(t, "v1.21.0", status.Version)
	assert.Empty(t, status.ErrorMessage)
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorUnhealthyState(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	monitor.SetMaxFailures(2) // Lower threshold for testing
	
	// Mock failing version calls
	mockClient.On("GetVersion", mock.Anything).Return("", fmt.Errorf("connection refused"))
	
	ctx := context.Background()
	
	// First failure - should still be healthy
	monitor.performHealthCheck(ctx)
	assert.True(t, monitor.IsHealthy())
	
	// Second failure - should become unhealthy
	monitor.performHealthCheck(ctx)
	assert.False(t, monitor.IsHealthy())
	
	status := monitor.GetStatus()
	assert.False(t, status.IsHealthy)
	assert.Equal(t, 2, status.ConsecutiveFailures)
	assert.Contains(t, status.ErrorMessage, "connection refused")
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorRecovery(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	monitor.SetMaxFailures(1) // Single failure makes it unhealthy
	
	// First make it unhealthy
	mockClient.On("GetVersion", mock.Anything).Return("", fmt.Errorf("connection refused")).Once()
	
	ctx := context.Background()
	monitor.performHealthCheck(ctx)
	assert.False(t, monitor.IsHealthy())
	
	// Then recover
	mockClient.On("GetVersion", mock.Anything).Return("v1.21.0", nil).Once()
	monitor.performHealthCheck(ctx)
	
	// Should be healthy again
	assert.True(t, monitor.IsHealthy())
	status := monitor.GetStatus()
	assert.True(t, status.IsHealthy)
	assert.Equal(t, 0, status.ConsecutiveFailures)
	assert.Equal(t, "v1.21.0", status.Version)
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorNotifications(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	monitor.SetMaxFailures(1)
	
	ctx := context.Background()
	
	// Mock the initial health check that happens on Start
	mockClient.On("GetVersion", mock.Anything).Return("v1.25.0", nil).Once()
	
	// Start monitoring to get notification channel
	err := monitor.Start(ctx)
	require.NoError(t, err)
	defer monitor.Stop()
	
	notifChan := monitor.GetNotificationChannel()
	
	// Make it unhealthy - should trigger notification
	mockClient.On("GetVersion", mock.Anything).Return("", fmt.Errorf("test error")).Once()
	monitor.performHealthCheck(ctx)
	
	// Check for notification
	select {
	case notification := <-notifChan:
		assert.False(t, notification.CurrentStatus.IsHealthy)
		assert.True(t, notification.PreviousStatus.IsHealthy)
		assert.Contains(t, notification.Message, "unhealthy")
		assert.Equal(t, models.EscalationLevelHigh, notification.Severity)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected notification but didn't receive one")
	}
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorHealthReport(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	t.Run("healthy report", func(t *testing.T) {
		mockClient.On("GetVersion", mock.Anything).Return("v1.21.0", nil).Once()
		
		ctx := context.Background()
		monitor.performHealthCheck(ctx)
		
		report := monitor.GetHealthReport()
		assert.Contains(t, report, "HEALTHY")
		assert.Contains(t, report, "v1.21.0")
		assert.Contains(t, report, "Last Check:")
		assert.Contains(t, report, "Response Time:")
	})
	
	t.Run("unhealthy report", func(t *testing.T) {
		monitor.SetMaxFailures(1)
		mockClient.On("GetVersion", mock.Anything).Return("", fmt.Errorf("connection refused")).Once()
		
		ctx := context.Background()
		monitor.performHealthCheck(ctx)
		
		report := monitor.GetHealthReport()
		assert.Contains(t, report, "UNHEALTHY")
		assert.Contains(t, report, "connection refused")
		assert.Contains(t, report, "Consecutive Failures:")
		assert.Contains(t, report, "Troubleshooting Steps:")
	})
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorDegradedModeRecommendations(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	// Initially healthy - no recommendations
	recommendations := monitor.GetDegradedModeRecommendations()
	assert.Empty(t, recommendations)
	
	// Make unhealthy
	monitor.SetMaxFailures(1)
	mockClient.On("GetVersion", mock.Anything).Return("", fmt.Errorf("test error")).Once()
	
	ctx := context.Background()
	monitor.performHealthCheck(ctx)
	
	// Should have recommendations
	recommendations = monitor.GetDegradedModeRecommendations()
	assert.Greater(t, len(recommendations), 0)
	assert.Contains(t, recommendations, "Use cached results when possible for read-only operations")
	assert.Contains(t, recommendations, "Defer write operations until API connectivity is restored")
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorWaitForHealthy(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	t.Run("already healthy returns immediately", func(t *testing.T) {
		ctx := context.Background()
		err := monitor.WaitForHealthy(ctx, 1*time.Second)
		assert.NoError(t, err)
	})
	
	t.Run("becomes healthy before timeout", func(t *testing.T) {
		// Make unhealthy first
		monitor.SetMaxFailures(1)
		mockClient.On("GetVersion", mock.Anything).Return("", fmt.Errorf("test error")).Once()
		
		ctx := context.Background()
		monitor.performHealthCheck(ctx)
		assert.False(t, monitor.IsHealthy())
		
		// Start wait in goroutine
		done := make(chan error, 1)
		go func() {
			done <- monitor.WaitForHealthy(ctx, 2*time.Second)
		}()
		
		// Make healthy after short delay
		time.Sleep(50 * time.Millisecond)
		mockClient.On("GetVersion", mock.Anything).Return("v1.21.0", nil).Once()
		monitor.performHealthCheck(ctx)
		
		// Should complete successfully
		select {
		case err := <-done:
			assert.NoError(t, err)
		case <-time.After(1 * time.Second):
			t.Fatal("WaitForHealthy did not return in time")
		}
	})
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthMonitorStartStop(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	
	ctx := context.Background()
	
	// Mock the initial health check that happens on Start
	mockClient.On("GetVersion", mock.Anything).Return("v1.25.0", nil).Once()
	
	// Test start
	err := monitor.Start(ctx)
	assert.NoError(t, err)
	
	// Test double start returns error
	err = monitor.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")
	
	// Test stop
	monitor.Stop()
	
	// Test double stop is safe
	monitor.Stop()
}

func TestAPIHealthMonitorTimeout(t *testing.T) {
	mockClient := &MockKubernetesClient{}
	monitor := NewAPIHealthMonitor(mockClient)
	monitor.SetTimeout(50 * time.Millisecond) // Very short timeout
	
	// Mock a slow response
	mockClient.On("GetVersion", mock.Anything).Run(func(args mock.Arguments) {
		time.Sleep(100 * time.Millisecond) // Sleep longer than timeout
	}).Return("v1.21.0", nil)
	
	ctx := context.Background()
	monitor.performHealthCheck(ctx)
	
	// Should be unhealthy due to timeout
	status := monitor.GetStatus()
	assert.Greater(t, status.ConsecutiveFailures, 0)
	
	mockClient.AssertExpectations(t)
}

func TestAPIHealthNotification(t *testing.T) {
	notification := APIHealthNotification{
		PreviousStatus: APIHealthStatus{IsHealthy: true},
		CurrentStatus:  APIHealthStatus{IsHealthy: false, ConsecutiveFailures: 3},
		Timestamp:     time.Now(),
		Severity:      models.EscalationLevelHigh,
		Message:       "API became unhealthy",
	}
	
	assert.True(t, notification.PreviousStatus.IsHealthy)
	assert.False(t, notification.CurrentStatus.IsHealthy)
	assert.Equal(t, models.EscalationLevelHigh, notification.Severity)
	assert.Contains(t, notification.Message, "unhealthy")
}