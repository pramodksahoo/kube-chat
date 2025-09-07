package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// BenchmarkSimpleAuditEventCollection benchmarks the audit event collection performance
func BenchmarkSimpleAuditEventCollection(b *testing.B) {
	// Use our load test storage which is optimized for performance testing
	loadTestStorage := &LoadTestMockStorage{
		processingTime: time.Microsecond * 1, // Very fast processing
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
	
	// Wait a bit for processing to complete
	time.Sleep(time.Millisecond * 100)
	
	stats := collector.GetStats()
	processedCount := loadTestStorage.GetProcessedCount()
	
	b.Logf("Benchmark Results:")
	b.Logf("  Events Received: %d", stats.EventsReceived)
	b.Logf("  Events Processed: %d", stats.EventsProcessed)  
	b.Logf("  Storage Processed: %d", processedCount)
	b.Logf("  Events per iteration: %.2f", float64(stats.EventsReceived)/float64(b.N))
	b.Logf("  Processing efficiency: %.2f%%", float64(processedCount)/float64(stats.EventsReceived)*100)
}