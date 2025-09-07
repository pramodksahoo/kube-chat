// Package audit provides encrypted wrapper for audit storage
package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// EncryptedAuditStorage wraps an AuditStorage implementation with encryption
type EncryptedAuditStorage struct {
	storage           AuditStorage
	encryptionService *EncryptionService
	encryptionEnabled bool
}

// NewEncryptedAuditStorage creates a new encrypted audit storage wrapper
func NewEncryptedAuditStorage(storage AuditStorage, encryptionService *EncryptionService) *EncryptedAuditStorage {
	return &EncryptedAuditStorage{
		storage:           storage,
		encryptionService: encryptionService,
		encryptionEnabled: true,
	}
}

// StoreEvent stores an audit event with encryption
func (eas *EncryptedAuditStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		// Fall back to unencrypted storage
		return eas.storage.StoreEvent(ctx, event)
	}
	
	// Create a copy of the event for encryption
	encryptedEvent := *event
	
	// Encrypt sensitive fields
	if err := eas.encryptSensitiveFields(&encryptedEvent); err != nil {
		return fmt.Errorf("failed to encrypt audit event: %w", err)
	}
	
	// Store the encrypted event
	return eas.storage.StoreEvent(ctx, &encryptedEvent)
}

// GetEvent retrieves and decrypts an audit event by ID
func (eas *EncryptedAuditStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	event, err := eas.storage.GetEvent(ctx, eventID)
	if err != nil {
		return nil, err
	}
	
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		return event, nil
	}
	
	// Decrypt sensitive fields
	if err := eas.decryptSensitiveFields(event); err != nil {
		return nil, fmt.Errorf("failed to decrypt audit event: %w", err)
	}
	
	return event, nil
}

// QueryEvents searches for audit events and decrypts them
func (eas *EncryptedAuditStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	events, err := eas.storage.QueryEvents(ctx, filter)
	if err != nil {
		return nil, err
	}
	
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		return events, nil
	}
	
	// Decrypt all events
	for _, event := range events {
		if err := eas.decryptSensitiveFields(event); err != nil {
			return nil, fmt.Errorf("failed to decrypt audit event %s: %w", event.ID, err)
		}
	}
	
	return events, nil
}

// VerifyIntegrity verifies integrity of encrypted audit events
func (eas *EncryptedAuditStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	// Get the encrypted event first
	event, err := eas.storage.GetEvent(ctx, eventID)
	if err != nil {
		return false, err
	}
	
	// If encryption is enabled, decrypt before verification
	if eas.encryptionEnabled && eas.encryptionService != nil {
		if err := eas.decryptSensitiveFields(event); err != nil {
			return false, fmt.Errorf("failed to decrypt event for integrity verification: %w", err)
		}
	}
	
	// Verify integrity of decrypted event
	return event.VerifyIntegrity()
}

// GetEventsByUser retrieves audit events for a specific user (with decryption)
func (eas *EncryptedAuditStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	events, err := eas.storage.GetEventsByUser(ctx, userID, limit)
	if err != nil {
		return nil, err
	}
	
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		return events, nil
	}
	
	// Decrypt all events
	for _, event := range events {
		if err := eas.decryptSensitiveFields(event); err != nil {
			return nil, fmt.Errorf("failed to decrypt audit event %s: %w", event.ID, err)
		}
	}
	
	return events, nil
}

// GetEventsByTimeRange retrieves audit events within a time range (with decryption)
func (eas *EncryptedAuditStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	events, err := eas.storage.GetEventsByTimeRange(ctx, start, end)
	if err != nil {
		return nil, err
	}
	
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		return events, nil
	}
	
	// Decrypt all events
	for _, event := range events {
		if err := eas.decryptSensitiveFields(event); err != nil {
			return nil, fmt.Errorf("failed to decrypt audit event %s: %w", event.ID, err)
		}
	}
	
	return events, nil
}

// CountEventsByType delegates to underlying storage
func (eas *EncryptedAuditStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	return eas.storage.CountEventsByType(ctx)
}

// CountEvents delegates to underlying storage
func (eas *EncryptedAuditStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	return eas.storage.CountEvents(ctx, filter)
}

// CleanupExpiredEvents delegates to underlying storage
func (eas *EncryptedAuditStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	return eas.storage.CleanupExpiredEvents(ctx, retentionDays)
}

// GetStorageStats delegates to underlying storage
func (eas *EncryptedAuditStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	return eas.storage.GetStorageStats(ctx)
}

// HealthCheck delegates to underlying storage
func (eas *EncryptedAuditStorage) HealthCheck(ctx context.Context) error {
	return eas.storage.HealthCheck(ctx)
}

// encryptSensitiveFields encrypts sensitive data within an audit event
func (eas *EncryptedAuditStorage) encryptSensitiveFields(event *models.AuditEvent) error {
	// Encrypt command context (contains potentially sensitive commands)
	if event.CommandContext.GeneratedCommand != "" {
		encryptedCmd, err := eas.encryptionService.EncryptData([]byte(event.CommandContext.GeneratedCommand))
		if err != nil {
			return fmt.Errorf("failed to encrypt generated command: %w", err)
		}
		event.CommandContext.GeneratedCommand = encryptedCmd.ToHex()
		
		// Add encryption metadata
		if event.Metadata == nil {
			event.Metadata = make(map[string]interface{})
		}
		event.Metadata["encrypted_fields"] = []string{"generated_command"}
		event.Metadata["encryption_key_id"] = encryptedCmd.KeyID
		event.Metadata["encryption_algorithm"] = encryptedCmd.Algorithm
	}
	
	// Encrypt natural language input (may contain sensitive information)
	if event.CommandContext.NaturalLanguageInput != "" {
		encryptedInput, err := eas.encryptionService.EncryptData([]byte(event.CommandContext.NaturalLanguageInput))
		if err != nil {
			return fmt.Errorf("failed to encrypt natural language input: %w", err)
		}
		event.CommandContext.NaturalLanguageInput = encryptedInput.ToHex()
		
		// Update metadata
		if event.Metadata == nil {
			event.Metadata = make(map[string]interface{})
		}
		encryptedFields, exists := event.Metadata["encrypted_fields"]
		if !exists {
			event.Metadata["encrypted_fields"] = []string{"natural_language_input"}
		} else {
			fields := encryptedFields.([]string)
			event.Metadata["encrypted_fields"] = append(fields, "natural_language_input")
		}
	}
	
	// Encrypt execution result (may contain sensitive output)
	if event.CommandContext.ExecutionResult != "" {
		encryptedResult, err := eas.encryptionService.EncryptData([]byte(event.CommandContext.ExecutionResult))
		if err != nil {
			return fmt.Errorf("failed to encrypt execution result: %w", err)
		}
		event.CommandContext.ExecutionResult = encryptedResult.ToHex()
		
		// Update metadata
		if event.Metadata == nil {
			event.Metadata = make(map[string]interface{})
		}
		encryptedFields, exists := event.Metadata["encrypted_fields"]
		if !exists {
			event.Metadata["encrypted_fields"] = []string{"execution_result"}
		} else {
			fields := encryptedFields.([]string)
			event.Metadata["encrypted_fields"] = append(fields, "execution_result")
		}
	}
	
	return nil
}

// decryptSensitiveFields decrypts sensitive data within an audit event
func (eas *EncryptedAuditStorage) decryptSensitiveFields(event *models.AuditEvent) error {
	// Check if event has encrypted fields
	if event.Metadata == nil {
		return nil
	}
	
	encryptedFieldsInterface, exists := event.Metadata["encrypted_fields"]
	if !exists {
		return nil
	}
	
	encryptedFields, ok := encryptedFieldsInterface.([]string)
	if !ok {
		// Try to handle it as []interface{} (from JSON unmarshaling)
		if fieldsList, ok := encryptedFieldsInterface.([]interface{}); ok {
			encryptedFields = make([]string, len(fieldsList))
			for i, field := range fieldsList {
				encryptedFields[i] = field.(string)
			}
		} else {
			return fmt.Errorf("invalid encrypted_fields metadata format")
		}
	}
	
	// Get encryption metadata
	keyID, _ := event.Metadata["encryption_key_id"].(string)
	algorithm, _ := event.Metadata["encryption_algorithm"].(string)
	
	// Decrypt each field
	for _, field := range encryptedFields {
		switch field {
		case "generated_command":
			if event.CommandContext.GeneratedCommand != "" {
				decrypted, err := eas.decryptField(event.CommandContext.GeneratedCommand, keyID, algorithm)
				if err != nil {
					return fmt.Errorf("failed to decrypt generated_command: %w", err)
				}
				event.CommandContext.GeneratedCommand = decrypted
			}
		case "natural_language_input":
			if event.CommandContext.NaturalLanguageInput != "" {
				decrypted, err := eas.decryptField(event.CommandContext.NaturalLanguageInput, keyID, algorithm)
				if err != nil {
					return fmt.Errorf("failed to decrypt natural_language_input: %w", err)
				}
				event.CommandContext.NaturalLanguageInput = decrypted
			}
		case "execution_result":
			if event.CommandContext.ExecutionResult != "" {
				decrypted, err := eas.decryptField(event.CommandContext.ExecutionResult, keyID, algorithm)
				if err != nil {
					return fmt.Errorf("failed to decrypt execution_result: %w", err)
				}
				event.CommandContext.ExecutionResult = decrypted
			}
		}
	}
	
	return nil
}

// decryptField decrypts a single encrypted field
func (eas *EncryptedAuditStorage) decryptField(hexData, keyID, algorithm string) (string, error) {
	encryptedData := &EncryptedData{
		KeyID:     keyID,
		Algorithm: algorithm,
		NonceSize: 12, // Standard GCM nonce size
	}
	
	if err := encryptedData.FromHex(hexData); err != nil {
		return "", fmt.Errorf("failed to decode encrypted field: %w", err)
	}
	
	decrypted, err := eas.encryptionService.DecryptData(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt field: %w", err)
	}
	
	return string(decrypted), nil
}

// GetEncryptionMetrics returns metrics about encryption operations
func (eas *EncryptedAuditStorage) GetEncryptionMetrics() *EncryptionMetrics {
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		return &EncryptionMetrics{
			TotalEncryptions: 0,
			TotalDecryptions: 0,
			CurrentKeyID:     "none",
			KeyRotationsDue:  false,
		}
	}
	
	keyInfo := eas.encryptionService.GetKeyInfo()
	if keyInfo == nil {
		return &EncryptionMetrics{
			TotalEncryptions: 0,
			TotalDecryptions: 0,
			CurrentKeyID:     "unknown",
			KeyRotationsDue:  true,
		}
	}
	
	// Check if key rotation is due (30 days)
	keyAge := time.Since(keyInfo.CreatedAt)
	rotationDue := keyAge > (30 * 24 * time.Hour)
	
	return &EncryptionMetrics{
		TotalEncryptions: 0, // Would be tracked in real implementation
		TotalDecryptions: 0, // Would be tracked in real implementation
		CurrentKeyID:     keyInfo.KeyID,
		LastKeyRotation:  keyInfo.CreatedAt,
		KeyRotationsDue:  rotationDue,
	}
}

// RotateEncryptionKey rotates the encryption key
func (eas *EncryptedAuditStorage) RotateEncryptionKey() error {
	if !eas.encryptionEnabled || eas.encryptionService == nil {
		return fmt.Errorf("encryption not enabled")
	}
	
	return eas.encryptionService.RotateEncryptionKey()
}