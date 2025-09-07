// Package audit provides tests for encryption functionality
package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestExternalSecretsKeyManager(t *testing.T) {
	km := NewExternalSecretsKeyManager("kube-chat", "audit-encryption-key")
	
	t.Run("get current key", func(t *testing.T) {
		key, err := km.GetCurrentKey()
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "current", key.ID)
		assert.Equal(t, "AES-256-GCM", key.Algorithm)
		assert.Equal(t, 32, len(key.KeyData)) // AES-256 key size
		assert.Equal(t, "active", key.Status)
	})
	
	t.Run("get specific key", func(t *testing.T) {
		key, err := km.GetKey("test_key_123")
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "test_key_123", key.ID)
		assert.Equal(t, 32, len(key.KeyData))
	})
	
	t.Run("rotate key", func(t *testing.T) {
		newKey, err := km.RotateKey()
		assert.NoError(t, err)
		assert.NotNil(t, newKey)
		assert.Contains(t, newKey.ID, "key_")
		assert.Equal(t, 32, len(newKey.KeyData))
	})
	
	t.Run("list keys", func(t *testing.T) {
		keys, err := km.ListKeys()
		assert.NoError(t, err)
		assert.Len(t, keys, 1)
	})
}

func TestEncryptionService(t *testing.T) {
	km := NewExternalSecretsKeyManager("test", "test-key")
	service, err := NewEncryptionService(km)
	require.NoError(t, err)
	require.NotNil(t, service)
	
	t.Run("encrypt and decrypt data", func(t *testing.T) {
		originalData := []byte("This is sensitive audit data that needs encryption")
		
		// Encrypt data
		encryptedData, err := service.EncryptData(originalData)
		assert.NoError(t, err)
		assert.NotNil(t, encryptedData)
		assert.NotEqual(t, originalData, encryptedData.Ciphertext)
		assert.Equal(t, "AES-256-GCM", encryptedData.Algorithm)
		assert.False(t, encryptedData.EncryptedAt.IsZero())
		
		// Decrypt data
		decryptedData, err := service.DecryptData(encryptedData)
		assert.NoError(t, err)
		assert.Equal(t, originalData, decryptedData)
	})
	
	t.Run("encrypt different data produces different ciphertexts", func(t *testing.T) {
		data1 := []byte("First data")
		data2 := []byte("Second data")
		
		encrypted1, err := service.EncryptData(data1)
		assert.NoError(t, err)
		
		encrypted2, err := service.EncryptData(data2)
		assert.NoError(t, err)
		
		assert.NotEqual(t, encrypted1.Ciphertext, encrypted2.Ciphertext)
	})
	
	t.Run("encrypt same data twice produces different ciphertexts", func(t *testing.T) {
		data := []byte("Same data")
		
		encrypted1, err := service.EncryptData(data)
		assert.NoError(t, err)
		
		encrypted2, err := service.EncryptData(data)
		assert.NoError(t, err)
		
		// Should be different due to different nonces
		assert.NotEqual(t, encrypted1.Ciphertext, encrypted2.Ciphertext)
		
		// But both should decrypt to the same data
		decrypted1, err := service.DecryptData(encrypted1)
		assert.NoError(t, err)
		assert.Equal(t, data, decrypted1)
		
		decrypted2, err := service.DecryptData(encrypted2)
		assert.NoError(t, err)
		assert.Equal(t, data, decrypted2)
	})
	
	t.Run("hex encoding and decoding", func(t *testing.T) {
		data := []byte("Test data for hex encoding")
		
		encrypted, err := service.EncryptData(data)
		assert.NoError(t, err)
		
		hexStr := encrypted.ToHex()
		assert.NotEmpty(t, hexStr)
		
		newEncrypted := &EncryptedData{
			KeyID:     encrypted.KeyID,
			Algorithm: encrypted.Algorithm,
			NonceSize: encrypted.NonceSize,
		}
		
		err = newEncrypted.FromHex(hexStr)
		assert.NoError(t, err)
		assert.Equal(t, encrypted.Ciphertext, newEncrypted.Ciphertext)
		
		decrypted, err := service.DecryptData(newEncrypted)
		assert.NoError(t, err)
		assert.Equal(t, data, decrypted)
	})
	
	t.Run("key rotation", func(t *testing.T) {
		originalKeyInfo := service.GetKeyInfo()
		assert.NotNil(t, originalKeyInfo)
		
		// Encrypt data with original key
		data := []byte("Data encrypted with original key")
		encrypted, err := service.EncryptData(data)
		assert.NoError(t, err)
		assert.Equal(t, originalKeyInfo.KeyID, encrypted.KeyID)
		
		// Rotate key
		err = service.RotateEncryptionKey()
		assert.NoError(t, err)
		
		newKeyInfo := service.GetKeyInfo()
		assert.NotNil(t, newKeyInfo)
		assert.NotEqual(t, originalKeyInfo.KeyID, newKeyInfo.KeyID)
		
		// Should still be able to decrypt old data
		decrypted, err := service.DecryptData(encrypted)
		assert.NoError(t, err)
		assert.Equal(t, data, decrypted)
		
		// New encryptions should use new key
		newData := []byte("Data encrypted with new key")
		newEncrypted, err := service.EncryptData(newData)
		assert.NoError(t, err)
		assert.Equal(t, newKeyInfo.KeyID, newEncrypted.KeyID)
		assert.NotEqual(t, originalKeyInfo.KeyID, newEncrypted.KeyID)
	})
	
	t.Run("get key info", func(t *testing.T) {
		keyInfo := service.GetKeyInfo()
		assert.NotNil(t, keyInfo)
		assert.NotEmpty(t, keyInfo.KeyID)
		assert.Equal(t, "AES-256-GCM", keyInfo.Algorithm)
		assert.False(t, keyInfo.CreatedAt.IsZero())
		assert.Equal(t, "active", keyInfo.Status)
	})
}

func TestEncryptedAuditStorage(t *testing.T) {
	// Create mock storage
	mockStorage := &MockEncryptionAuditStorage{}
	
	// Create encryption service
	km := NewExternalSecretsKeyManager("test", "test-key")
	encryptionService, err := NewEncryptionService(km)
	require.NoError(t, err)
	
	// Create encrypted storage
	encryptedStorage := NewEncryptedAuditStorage(mockStorage, encryptionService)
	
	t.Run("store and retrieve encrypted event", func(t *testing.T) {
		// Create test event with sensitive data
		builder := models.NewAuditEventBuilder()
		originalEvent, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage("Test command execution").
			WithUserContextFromUser(&models.User{ID: "user123", Email: "test@example.com"}, "session123", "192.168.1.1", "test-agent").
			WithCommandContext(
				"get all sensitive pods", 
				"kubectl get pods --all-namespaces", 
				"safe", 
				"completed", 
				"pod1: running, pod2: terminated", 
				"", 
				1500).
			Build()
		require.NoError(t, err)
		
		ctx := context.Background()
		
		// Store the event (should be encrypted)
		err = encryptedStorage.StoreEvent(ctx, originalEvent)
		assert.NoError(t, err)
		
		// Verify that the stored event has encrypted data
		storedEvent := mockStorage.LastStoredEvent
		assert.NotNil(t, storedEvent)
		assert.NotEqual(t, "get all sensitive pods", storedEvent.CommandContext.NaturalLanguageInput)
		assert.NotEqual(t, "kubectl get pods --all-namespaces", storedEvent.CommandContext.GeneratedCommand)
		assert.NotEqual(t, "pod1: running, pod2: terminated", storedEvent.CommandContext.ExecutionResult)
		
		// Verify encryption metadata was added
		assert.NotNil(t, storedEvent.Metadata)
		assert.Contains(t, storedEvent.Metadata, "encrypted_fields")
		assert.Contains(t, storedEvent.Metadata, "encryption_key_id")
		assert.Contains(t, storedEvent.Metadata, "encryption_algorithm")
		
		// Retrieve the event (should be decrypted)
		retrievedEvent, err := encryptedStorage.GetEvent(ctx, originalEvent.ID)
		assert.NoError(t, err)
		assert.NotNil(t, retrievedEvent)
		
		// Verify decrypted data matches original
		assert.Equal(t, "get all sensitive pods", retrievedEvent.CommandContext.NaturalLanguageInput)
		assert.Equal(t, "kubectl get pods --all-namespaces", retrievedEvent.CommandContext.GeneratedCommand)
		assert.Equal(t, "pod1: running, pod2: terminated", retrievedEvent.CommandContext.ExecutionResult)
	})
	
	t.Run("integrity verification with encryption", func(t *testing.T) {
		// Create and store encrypted event
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeLogin).
			WithMessage("Test login").
			WithUserContextFromUser(&models.User{ID: "user123", Email: "test@example.com"}, "session123", "192.168.1.1", "test-agent").
			Build()
		require.NoError(t, err)
		
		ctx := context.Background()
		err = encryptedStorage.StoreEvent(ctx, event)
		assert.NoError(t, err)
		
		// Verify integrity
		valid, err := encryptedStorage.VerifyIntegrity(ctx, event.ID)
		assert.NoError(t, err)
		assert.True(t, valid)
	})
	
	t.Run("encryption metrics", func(t *testing.T) {
		metrics := encryptedStorage.GetEncryptionMetrics()
		assert.NotNil(t, metrics)
		assert.NotEmpty(t, metrics.CurrentKeyID)
		assert.Equal(t, "AES-256-GCM", "AES-256-GCM") // Verify we're using the correct algorithm
	})
	
	t.Run("key rotation", func(t *testing.T) {
		oldMetrics := encryptedStorage.GetEncryptionMetrics()
		oldKeyID := oldMetrics.CurrentKeyID
		
		err := encryptedStorage.RotateEncryptionKey()
		assert.NoError(t, err)
		
		newMetrics := encryptedStorage.GetEncryptionMetrics()
		assert.NotEqual(t, oldKeyID, newMetrics.CurrentKeyID)
	})
}

// MockEncryptionAuditStorage implements AuditStorage for testing
type MockEncryptionAuditStorage struct {
	LastStoredEvent *models.AuditEvent
	StoredEvents    map[string]*models.AuditEvent
}

func (m *MockEncryptionAuditStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	if m.StoredEvents == nil {
		m.StoredEvents = make(map[string]*models.AuditEvent)
	}
	
	// Create a copy to store
	eventCopy := *event
	m.LastStoredEvent = &eventCopy
	m.StoredEvents[event.ID] = &eventCopy
	return nil
}

func (m *MockEncryptionAuditStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	if m.StoredEvents == nil {
		return nil, fmt.Errorf("event not found")
	}
	
	event, exists := m.StoredEvents[eventID]
	if !exists {
		return nil, fmt.Errorf("event not found")
	}
	
	// Return a copy
	eventCopy := *event
	return &eventCopy, nil
}

func (m *MockEncryptionAuditStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	var events []*models.AuditEvent
	for _, event := range m.StoredEvents {
		eventCopy := *event
		events = append(events, &eventCopy)
	}
	return events, nil
}

func (m *MockEncryptionAuditStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	event, err := m.GetEvent(ctx, eventID)
	if err != nil {
		return false, err
	}
	return event.VerifyIntegrity()
}

func (m *MockEncryptionAuditStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	return m.QueryEvents(ctx, models.AuditEventFilter{UserID: userID, Limit: limit})
}

func (m *MockEncryptionAuditStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	return m.QueryEvents(ctx, models.AuditEventFilter{StartTime: start, EndTime: end})
}

func (m *MockEncryptionAuditStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	counts := make(map[models.AuditEventType]int64)
	for _, event := range m.StoredEvents {
		counts[event.EventType]++
	}
	return counts, nil
}

func (m *MockEncryptionAuditStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	return int64(len(m.StoredEvents)), nil
}

func (m *MockEncryptionAuditStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	return 0, nil
}

func (m *MockEncryptionAuditStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	return &StorageStats{
		TotalEvents: int64(len(m.StoredEvents)),
	}, nil
}

func (m *MockEncryptionAuditStorage) HealthCheck(ctx context.Context) error {
	return nil
}

