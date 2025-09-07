package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// LoadTestMockStorage implements AuditStorage for high-volume load testing
type LoadTestMockStorage struct {
	processedCount int64
	errorCount     int64
	processingTime time.Duration
}

func (m *LoadTestMockStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	// Simulate realistic storage processing time
	if m.processingTime > 0 {
		time.Sleep(m.processingTime)
	}
	
	atomic.AddInt64(&m.processedCount, 1)
	return nil
}

func (m *LoadTestMockStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	return nil, fmt.Errorf("not implemented for load test")
}

func (m *LoadTestMockStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	return nil, fmt.Errorf("not implemented for load test")
}

func (m *LoadTestMockStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	return true, nil
}

func (m *LoadTestMockStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	return nil, fmt.Errorf("not implemented for load test")
}

func (m *LoadTestMockStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	return nil, fmt.Errorf("not implemented for load test")
}

func (m *LoadTestMockStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	return nil, fmt.Errorf("not implemented for load test")
}

func (m *LoadTestMockStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	return atomic.LoadInt64(&m.processedCount), nil
}

func (m *LoadTestMockStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	return 0, nil
}

func (m *LoadTestMockStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	return nil, fmt.Errorf("not implemented for load test")
}

func (m *LoadTestMockStorage) HealthCheck(ctx context.Context) error {
	return nil
}

func (m *LoadTestMockStorage) GetProcessedCount() int64 {
	return atomic.LoadInt64(&m.processedCount)
}

func (m *LoadTestMockStorage) GetErrorCount() int64 {
	return atomic.LoadInt64(&m.errorCount)
}

// TestHighVolumeAuditLogging tests the system under high load conditions
func TestHighVolumeAuditLogging(t *testing.T) {
	// Test configuration for high volume
	loadTestStorage := &LoadTestMockStorage{
		processingTime: time.Microsecond * 10, // Simulate realistic DB write time
	}
	
	config := CollectorConfig{
		Workers:       8,  // High worker count for load
		BufferSize:    50000, // Large buffer for high volume
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond * 10,
	}
	
	collector := NewEventCollector(loadTestStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Test parameters
	totalEvents := 10000
	concurrentClients := 20
	eventsPerClient := totalEvents / concurrentClients
	
	fmt.Printf("Load Test: %d total events, %d concurrent clients, %d events per client\n", 
		totalEvents, concurrentClients, eventsPerClient)
	
	startTime := time.Now()
	
	var wg sync.WaitGroup
	var submittedEvents int64
	var failedSubmissions int64
	
	// Launch concurrent clients
	for i := 0; i < concurrentClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()
			
			for j := 0; j < eventsPerClient; j++ {
				// Create audit event
				builder := models.NewAuditEventBuilder()
				event, err := builder.
					WithEventType(models.AuditEventTypeCommand).
					WithMessage(fmt.Sprintf("Load test event from client %d, event %d", clientID, j)).
					WithUserContextFromUser(
						&models.User{ID: fmt.Sprintf("user_%d", clientID)}, 
						fmt.Sprintf("session_%d_%d", clientID, j), 
						"127.0.0.1", 
						"LoadTestAgent/1.0",
					).
					WithService("load-test-service", "1.0").
					WithMetadata("client_id", clientID).
					WithMetadata("event_number", j).
					Build()
				
				if err != nil {
					atomic.AddInt64(&failedSubmissions, 1)
					continue
				}
				
				// Submit event (non-blocking)
				err = collector.CollectEvent(event)
				if err != nil {
					atomic.AddInt64(&failedSubmissions, 1)
				} else {
					atomic.AddInt64(&submittedEvents, 1)
				}
			}
		}(i)
	}
	
	// Wait for all clients to finish submitting
	wg.Wait()
	submissionTime := time.Since(startTime)
	
	// Wait for processing to complete
	fmt.Printf("All events submitted in %v, waiting for processing...\n", submissionTime)
	time.Sleep(time.Second * 3)
	
	totalTime := time.Since(startTime)
	
	// Get final stats
	stats := collector.GetStats()
	processedCount := loadTestStorage.GetProcessedCount()
	
	// Performance metrics
	submissionRate := float64(submittedEvents) / submissionTime.Seconds()
	processingRate := float64(processedCount) / totalTime.Seconds()
	
	fmt.Printf("\n=== LOAD TEST RESULTS ===\n")
	fmt.Printf("Total Events Target: %d\n", totalEvents)
	fmt.Printf("Events Submitted: %d\n", submittedEvents)
	fmt.Printf("Events Processed: %d\n", processedCount)
	fmt.Printf("Failed Submissions: %d\n", failedSubmissions)
	fmt.Printf("Submission Time: %v\n", submissionTime)
	fmt.Printf("Total Processing Time: %v\n", totalTime)
	fmt.Printf("Submission Rate: %.2f events/sec\n", submissionRate)
	fmt.Printf("Processing Rate: %.2f events/sec\n", processingRate)
	fmt.Printf("Events Received by Collector: %d\n", stats.EventsReceived)
	fmt.Printf("Events Successfully Processed: %d\n", stats.EventsProcessed)
	fmt.Printf("Events Failed: %d\n", stats.EventsFailed)
	fmt.Printf("=========================\n")
	
	// Assertions for high-volume requirements
	assert.Equal(t, int64(totalEvents), submittedEvents, "All events should be submitted successfully")
	assert.Equal(t, submittedEvents, stats.EventsReceived, "All submitted events should be received by collector")
	assert.Equal(t, stats.EventsReceived, stats.EventsProcessed, "All received events should be processed successfully")
	assert.Equal(t, int64(0), stats.EventsFailed, "No events should fail processing")
	assert.Equal(t, stats.EventsProcessed, processedCount, "All processed events should be stored")
	
	// Performance requirements
	assert.Greater(t, processingRate, 1000.0, "System should process >1000 events/second")
	assert.Less(t, failedSubmissions, int64(10), "Failed submissions should be minimal (<10)")
	
	// Zero audit event loss requirement
	assert.Equal(t, submittedEvents, processedCount, "Zero audit event loss: all submitted events must be processed")
}

// TestHighVolumeWithBackpressure tests system behavior when overwhelmed
func TestHighVolumeWithBackpressure(t *testing.T) {
	// Small buffer and slow processing to create backpressure
	loadTestStorage := &LoadTestMockStorage{
		processingTime: time.Millisecond * 5, // Slow processing
	}
	
	config := CollectorConfig{
		Workers:       2,   // Few workers
		BufferSize:    100, // Small buffer
		RetryAttempts: 3,
		RetryDelay:    time.Millisecond * 50,
	}
	
	collector := NewEventCollector(loadTestStorage, config)
	err := collector.Start()
	require.NoError(t, err)
	defer collector.Stop()
	
	// Send more events than buffer can handle quickly
	totalEvents := 500
	var submittedEvents int64
	var timeoutErrors int64
	
	fmt.Printf("Backpressure Test: %d events with small buffer (%d) and slow processing\n", 
		totalEvents, config.BufferSize)
	
	startTime := time.Now()
	
	for i := 0; i < totalEvents; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage(fmt.Sprintf("Backpressure test event %d", i)).
			WithUserContextFromUser(&models.User{ID: "backpressure_user"}, "session_bp", "127.0.0.1", "BackpressureAgent/1.0").
			WithService("backpressure-test", "1.0").
			Build()
		
		require.NoError(t, err)
		
		// Use timeout to detect backpressure
		err = collector.CollectEventWithTimeout(event, time.Millisecond*100)
		if err != nil {
			if err.Error() == "timeout: failed to submit audit event within deadline" {
				atomic.AddInt64(&timeoutErrors, 1)
			}
		} else {
			atomic.AddInt64(&submittedEvents, 1)
		}
	}
	
	// Wait for processing to complete
	time.Sleep(time.Second * 5)
	
	totalTime := time.Since(startTime)
	stats := collector.GetStats()
	processedCount := loadTestStorage.GetProcessedCount()
	
	fmt.Printf("\n=== BACKPRESSURE TEST RESULTS ===\n")
	fmt.Printf("Total Events: %d\n", totalEvents)
	fmt.Printf("Successfully Submitted: %d\n", submittedEvents)
	fmt.Printf("Timeout Errors: %d\n", timeoutErrors)
	fmt.Printf("Events Processed: %d\n", processedCount)
	fmt.Printf("Processing Time: %v\n", totalTime)
	fmt.Printf("Events Received: %d\n", stats.EventsReceived)
	fmt.Printf("Events Failed: %d\n", stats.EventsFailed)
	fmt.Printf("=================================\n")
	
	// Under backpressure, we should see some timeouts but no event loss
	assert.Greater(t, timeoutErrors, int64(0), "Should see timeout errors under backpressure")
	assert.Equal(t, submittedEvents, stats.EventsReceived, "All submitted events should be received")
	assert.Equal(t, stats.EventsReceived, stats.EventsProcessed, "All received events should be processed")
	assert.Equal(t, stats.EventsProcessed, processedCount, "No event loss during processing")
	
	// The system should gracefully handle backpressure
	assert.Less(t, float64(timeoutErrors)/float64(totalEvents), 0.5, "Timeout rate should be reasonable (<50%)")
}

// BenchmarkAuditEventCollection benchmarks the audit event collection performance
func BenchmarkAuditEventCollection(b *testing.B) {
	loadTestStorage := &LoadTestMockStorage{
		processingTime: time.Microsecond * 5,
	}
	
	config := CollectorConfig{
		Workers:       4,
		BufferSize:    10000,
		RetryAttempts: 1,
		RetryDelay:    time.Millisecond,
	}
	
	collector := NewEventCollector(loadTestStorage, config)
	err := collector.Start()
	require.NoError(b, err)
	defer collector.Stop()
	
	// Create a template event for benchmarking
	builder := models.NewAuditEventBuilder()
	templateEvent, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Benchmark audit event").
		WithUserContextFromUser(&models.User{ID: "benchmark_user"}, "benchmark_session", "127.0.0.1", "BenchmarkAgent/1.0").
		WithService("benchmark-service", "1.0").
		WithMetadata("benchmark", true).
		Build()
	require.NoError(b, err)
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			err := collector.CollectEvent(templateEvent)
			if err != nil {
				b.Fatalf("Failed to collect event: %v", err)
			}
		}
	})
	
	// Wait for processing to complete
	time.Sleep(time.Second)
	
	stats := collector.GetStats()
	processedCount := loadTestStorage.GetProcessedCount()
	
	b.Logf("Benchmark Results - Events Received: %d, Events Processed: %d, Storage Processed: %d", 
		stats.EventsReceived, stats.EventsProcessed, processedCount)
}