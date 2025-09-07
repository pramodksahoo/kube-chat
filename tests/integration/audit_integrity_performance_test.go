// Package integration provides performance benchmarks for tamper-proof audit storage
package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// BenchmarkAESEncryption benchmarks AES-256-GCM encryption operations
func BenchmarkAESEncryption(b *testing.B) {
	keyManager := audit.NewExternalSecretsKeyManager("benchmark", "test-key")
	service, err := audit.NewEncryptionService(keyManager)
	require.NoError(b, err)
	
	// Test different data sizes
	dataSizes := []int{100, 1024, 10240, 102400} // 100B, 1KB, 10KB, 100KB
	
	for _, size := range dataSizes {
		testData := make([]byte, size)
		_, err := rand.Read(testData)
		require.NoError(b, err)
		
		b.Run(fmt.Sprintf("encrypt_%dB", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := service.EncryptData(testData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkAESDecryption benchmarks AES-256-GCM decryption operations
func BenchmarkAESDecryption(b *testing.B) {
	keyManager := audit.NewExternalSecretsKeyManager("benchmark", "test-key")
	service, err := audit.NewEncryptionService(keyManager)
	require.NoError(b, err)
	
	// Pre-encrypt data of different sizes
	dataSizes := []int{100, 1024, 10240, 102400} // 100B, 1KB, 10KB, 100KB
	
	for _, size := range dataSizes {
		testData := make([]byte, size)
		_, err := rand.Read(testData)
		require.NoError(b, err)
		
		encryptedData, err := service.EncryptData(testData)
		require.NoError(b, err)
		
		b.Run(fmt.Sprintf("decrypt_%dB", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := service.DecryptData(encryptedData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkIntegrityVerification benchmarks integrity verification operations
func BenchmarkIntegrityVerification(b *testing.B) {
	// Setup mock storage for benchmarking
	mockStorage := &MockPerformanceAuditStorage{}
	integrityService := audit.NewIntegrityService(mockStorage)
	
	// Create test events
	events := createBenchmarkEvents(b, 1000)
	
	// Store events in mock storage
	ctx := context.Background()
	for _, event := range events {
		err := mockStorage.StoreEvent(ctx, event)
		require.NoError(b, err)
	}
	
	b.Run("verify_batch_integrity", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := integrityService.VerifyAllRecords(ctx)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkHashChainVerification benchmarks hash chain verification
func BenchmarkHashChainVerification(b *testing.B) {
	mockStorage := &MockPerformanceAuditStorage{}
	integrityService := audit.NewIntegrityService(mockStorage)
	
	// Create events with hash chain
	events := createBenchmarkEvents(b, 1000)
	
	// Build hash chain
	for i, event := range events {
		if i > 0 {
			event.PreviousHash = events[i-1].Checksum
			event.SequenceNumber = int64(i + 1)
			// Recalculate checksum with hash chain
			builder := models.NewAuditEventBuilder()
			newEvent, err := builder.
				WithEventType(event.EventType).
				WithMessage(event.Message).
				WithUserContextFromUser(
					&models.User{ID: event.UserContext.UserID, Email: event.UserContext.Email}, 
					event.UserContext.SessionID, 
					event.UserContext.IPAddress, 
					event.UserContext.UserAgent).
				WithCommandContext(
					event.CommandContext.NaturalLanguageInput,
					event.CommandContext.GeneratedCommand,
					event.CommandContext.RiskLevel,
					event.CommandContext.ExecutionStatus,
					event.CommandContext.ExecutionResult,
					event.CommandContext.ExecutionError,
					event.CommandContext.ExecutionDuration).
				WithHashChain(event.PreviousHash, event.SequenceNumber).
				Build()
			require.NoError(b, err)
			events[i] = newEvent
		}
		
		err := mockStorage.StoreEvent(context.Background(), event)
		require.NoError(b, err)
	}
	
	b.Run("verify_hash_chain", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := integrityService.VerifyHashChainIntegrity(context.Background())
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkEndToEndEncryptedStorage benchmarks complete encrypted storage workflow
func BenchmarkEndToEndEncryptedStorage(b *testing.B) {
	mockStorage := &MockPerformanceAuditStorage{}
	keyManager := audit.NewExternalSecretsKeyManager("benchmark", "test-key")
	encryptionService, err := audit.NewEncryptionService(keyManager)
	require.NoError(b, err)
	
	encryptedStorage := audit.NewEncryptedAuditStorage(mockStorage, encryptionService)
	ctx := context.Background()
	
	b.Run("store_and_retrieve_encrypted", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Create event
			event := createBenchmarkEvents(b, 1)[0]
			event.ID = fmt.Sprintf("benchmark_event_%d", i)
			
			// Store encrypted
			err := encryptedStorage.StoreEvent(ctx, event)
			if err != nil {
				b.Fatal(err)
			}
			
			// Retrieve and decrypt
			_, err = encryptedStorage.GetEvent(ctx, event.ID)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkKeyRotation benchmarks encryption key rotation performance
func BenchmarkKeyRotation(b *testing.B) {
	keyManager := audit.NewExternalSecretsKeyManager("benchmark", "test-key")
	service, err := audit.NewEncryptionService(keyManager)
	require.NoError(b, err)
	
	b.Run("key_rotation", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			err := service.RotateEncryptionKey()
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkConcurrentOperations benchmarks concurrent encryption operations
func BenchmarkConcurrentOperations(b *testing.B) {
	keyManager := audit.NewExternalSecretsKeyManager("benchmark", "test-key")
	service, err := audit.NewEncryptionService(keyManager)
	require.NoError(b, err)
	
	testData := make([]byte, 1024) // 1KB test data
	_, err = rand.Read(testData)
	require.NoError(b, err)
	
	b.Run("concurrent_encryption", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := service.EncryptData(testData)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	})
}

// MockPerformanceAuditStorage for benchmarking (simplified version)
type MockPerformanceAuditStorage struct {
	events map[string]*models.AuditEvent
}

func (m *MockPerformanceAuditStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	if m.events == nil {
		m.events = make(map[string]*models.AuditEvent)
	}
	eventCopy := *event
	m.events[event.ID] = &eventCopy
	return nil
}

func (m *MockPerformanceAuditStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	if event, exists := m.events[eventID]; exists {
		eventCopy := *event
		return &eventCopy, nil
	}
	return nil, fmt.Errorf("event not found")
}

func (m *MockPerformanceAuditStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	var events []*models.AuditEvent
	for _, event := range m.events {
		eventCopy := *event
		events = append(events, &eventCopy)
	}
	return events, nil
}

func (m *MockPerformanceAuditStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	event, err := m.GetEvent(ctx, eventID)
	if err != nil {
		return false, err
	}
	return event.VerifyIntegrity()
}

func (m *MockPerformanceAuditStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	return m.QueryEvents(ctx, models.AuditEventFilter{UserID: userID, Limit: limit})
}

func (m *MockPerformanceAuditStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	return m.QueryEvents(ctx, models.AuditEventFilter{StartTime: start, EndTime: end})
}

func (m *MockPerformanceAuditStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	counts := make(map[models.AuditEventType]int64)
	for _, event := range m.events {
		counts[event.EventType]++
	}
	return counts, nil
}

func (m *MockPerformanceAuditStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	return int64(len(m.events)), nil
}

func (m *MockPerformanceAuditStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	return 0, nil
}

func (m *MockPerformanceAuditStorage) GetStorageStats(ctx context.Context) (*audit.StorageStats, error) {
	return &audit.StorageStats{
		TotalEvents: int64(len(m.events)),
	}, nil
}

func (m *MockPerformanceAuditStorage) HealthCheck(ctx context.Context) error {
	return nil
}


// createBenchmarkEvents creates test events for benchmarking
func createBenchmarkEvents(b *testing.B, count int) []*models.AuditEvent {
	var events []*models.AuditEvent
	
	for i := 0; i < count; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage(fmt.Sprintf("Benchmark command execution %d", i)).
			WithUserContextFromUser(
				&models.User{ID: fmt.Sprintf("benchmark_user_%d", i), Email: fmt.Sprintf("benchmark%d@test.com", i)}, 
				fmt.Sprintf("benchmark_session_%d", i), 
				"192.168.1.100", 
				"benchmark-agent").
			WithCommandContext(
				fmt.Sprintf("benchmark command %d with sensitive data", i),
				fmt.Sprintf("kubectl get secrets -n benchmark-%d --all-namespaces", i),
				"safe",
				"completed",
				fmt.Sprintf("secret-%d: active, secret-%d-backup: archived", i, i),
				"",
				int64(500+i*10)).
			Build()
		
		require.NoError(b, err)
		events = append(events, event)
	}
	
	return events
}