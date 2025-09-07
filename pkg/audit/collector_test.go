package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)


func TestDefaultCollectorConfig(t *testing.T) {
	config := DefaultCollectorConfig()
	
	assert.Equal(t, 4, config.Workers)
	assert.Equal(t, 10000, config.BufferSize)
	assert.Equal(t, 3, config.RetryAttempts)
	assert.Equal(t, time.Second*2, config.RetryDelay)
}

func TestNewEventCollector(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := DefaultCollectorConfig()
	
	collector := NewEventCollector(mockStorage, config)
	
	assert.NotNil(t, collector)
	assert.Equal(t, mockStorage, collector.storage)
	assert.Equal(t, config.Workers, collector.workers)
	assert.Equal(t, config.BufferSize, collector.bufferSize)
	assert.NotNil(t, collector.eventQueue)
	assert.NotNil(t, collector.stats)
}

func TestEventCollectorStartStop(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       2,
		BufferSize:    100,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond * 100,
	}
	
	collector := NewEventCollector(mockStorage, config)
	
	// Start collector
	err := collector.Start()
	assert.NoError(t, err)
	
	stats := collector.GetStats()
	assert.True(t, stats.IsRunning)
	
	// Try to start again (should fail)
	err = collector.Start()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already started")
	
	// Stop collector
	err = collector.Stop()
	assert.NoError(t, err)
	
	stats = collector.GetStats()
	assert.False(t, stats.IsRunning)
	
	// Try to stop again (should fail)
	err = collector.Stop()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not started")
}

func TestCollectEvent(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       1,
		BufferSize:    100,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond * 100,
	}
	
	collector := NewEventCollector(mockStorage, config)
	
	// Start collector
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Create test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("Test login").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Mock successful storage
	mockStorage.On("StoreEvent", mock.Anything, event).Return(nil)
	
	// Collect event
	err = collector.CollectEvent(event)
	assert.NoError(t, err)
	
	// Give time for processing
	time.Sleep(time.Millisecond * 200)
	
	stats := collector.GetStats()
	assert.Equal(t, int64(1), stats.EventsReceived)
	assert.Equal(t, int64(1), stats.EventsProcessed)
	assert.Equal(t, int64(0), stats.EventsFailed)
	
	mockStorage.AssertExpectations(t)
}

func TestCollectEventWithTimeout(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       1,
		BufferSize:    1, // Small buffer to test timeout
		RetryAttempts: 0,
		RetryDelay:    time.Millisecond * 10,
	}
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Create test events
	builder1 := models.NewAuditEventBuilder()
	event1, err := builder1.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("Event 1").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	builder2 := models.NewAuditEventBuilder()
	event2, err := builder2.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("Event 2").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Mock storage calls - make first one hang to fill buffer
	mockStorage.On("StoreEvent", mock.Anything, event1).Return(nil).WaitUntil(time.After(time.Millisecond * 500))
	
	// First event should succeed
	err = collector.CollectEventWithTimeout(event1, time.Millisecond*100)
	assert.NoError(t, err)
	
	// Second event should timeout due to full buffer
	err = collector.CollectEventWithTimeout(event2, time.Millisecond*50)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
	
	mockStorage.AssertExpectations(t)
}

func TestCollectEventWithStorageFailure(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       1,
		BufferSize:    100,
		RetryAttempts: 2,
		RetryDelay:    time.Millisecond * 10,
	}
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Create test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Test command").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Mock storage failure
	storageError := errors.New("storage unavailable")
	mockStorage.On("StoreEvent", mock.Anything, event).Return(storageError).Times(3) // Initial + 2 retries
	
	// Collect event
	err = collector.CollectEvent(event)
	assert.NoError(t, err)
	
	// Give time for processing and retries
	time.Sleep(time.Millisecond * 100)
	
	stats := collector.GetStats()
	assert.Equal(t, int64(1), stats.EventsReceived)
	assert.Equal(t, int64(0), stats.EventsProcessed)
	assert.Equal(t, int64(1), stats.EventsFailed)
	
	mockStorage.AssertExpectations(t)
}

func TestCollectorHealthCheck(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := DefaultCollectorConfig()
	
	collector := NewEventCollector(mockStorage, config)
	
	// Health check should fail when not running
	err := collector.HealthCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not running")
	
	// Start collector
	err = collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Mock healthy storage
	mockStorage.On("HealthCheck", mock.Anything).Return(nil)
	
	// Health check should pass
	err = collector.HealthCheck()
	assert.NoError(t, err)
	
	mockStorage.AssertExpectations(t)
}

func TestCollectorHealthCheckStorageFailure(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := DefaultCollectorConfig()
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Mock storage failure
	storageError := errors.New("database connection lost")
	mockStorage.On("HealthCheck", mock.Anything).Return(storageError)
	
	// Health check should fail
	err = collector.HealthCheck()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "storage health check failed")
	
	mockStorage.AssertExpectations(t)
}

func TestBatchEventCollector(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       1,
		BufferSize:    100,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond * 10,
	}
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	batchCollector := NewBatchEventCollector(collector, 3, time.Millisecond*100)
	
	// Create test events
	var events []*models.AuditEvent
	for i := 0; i < 3; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage("Batch test event").
			WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
			Build()
		require.NoError(t, err)
		events = append(events, event)
		
		// Mock storage for each event
		mockStorage.On("StoreEvent", mock.Anything, event).Return(nil)
	}
	
	// Add events to batch (should trigger flush on third event)
	for _, event := range events {
		err = batchCollector.CollectEvent(event)
		assert.NoError(t, err)
	}
	
	// Give time for processing
	time.Sleep(time.Millisecond * 200)
	
	stats := collector.GetStats()
	assert.Equal(t, int64(3), stats.EventsReceived)
	assert.Equal(t, int64(3), stats.EventsProcessed)
	
	mockStorage.AssertExpectations(t)
}

func TestBatchEventCollectorFlushTimer(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       1,
		BufferSize:    100,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond * 10,
	}
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Small batch size with short flush interval
	batchCollector := NewBatchEventCollector(collector, 10, time.Millisecond*50)
	
	// Create single test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("Timer flush test").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Mock storage
	mockStorage.On("StoreEvent", mock.Anything, event).Return(nil)
	
	// Add single event (should not trigger batch flush)
	err = batchCollector.CollectEvent(event)
	assert.NoError(t, err)
	
	// Wait for timer flush
	time.Sleep(time.Millisecond * 100)
	
	stats := collector.GetStats()
	assert.Equal(t, int64(1), stats.EventsReceived)
	assert.Equal(t, int64(1), stats.EventsProcessed)
	
	mockStorage.AssertExpectations(t)
}

func TestBatchEventCollectorManualFlush(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       1,
		BufferSize:    100,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond * 10,
	}
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Large batch size and long flush interval
	batchCollector := NewBatchEventCollector(collector, 100, time.Hour)
	
	// Create test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeLogout).
		WithMessage("Manual flush test").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Mock storage
	mockStorage.On("StoreEvent", mock.Anything, event).Return(nil)
	
	// Add event
	err = batchCollector.CollectEvent(event)
	assert.NoError(t, err)
	
	// Manually flush
	batchCollector.Flush()
	
	// Give time for processing
	time.Sleep(time.Millisecond * 100)
	
	stats := collector.GetStats()
	assert.Equal(t, int64(1), stats.EventsReceived)
	assert.Equal(t, int64(1), stats.EventsProcessed)
	
	mockStorage.AssertExpectations(t)
}

func BenchmarkEventCollector(b *testing.B) {
	mockStorage := &MockAuditStorage{}
	config := CollectorConfig{
		Workers:       4,
		BufferSize:    10000,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond,
	}
	
	collector := NewEventCollector(mockStorage, config)
	err := collector.Start()
	require.NoError(b, err)
	defer collector.Stop()
	
	// Mock storage to always succeed
	mockStorage.On("StoreEvent", mock.Anything, mock.Anything).Return(nil)
	
	// Create test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Benchmark event").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(b, err)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := collector.CollectEvent(event)
		if err != nil {
			b.Fatalf("Failed to collect event: %v", err)
		}
	}
}