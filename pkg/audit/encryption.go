// Package audit provides AES-256 encryption for audit data at rest
package audit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"
)

// EncryptionService provides AES-256 encryption for audit data at rest
type EncryptionService struct {
	keyManager KeyManager
	gcm        cipher.AEAD
	currentKey *EncryptionKey
}

// KeyManager interface for managing encryption keys
type KeyManager interface {
	// GetCurrentKey retrieves the current active encryption key
	GetCurrentKey() (*EncryptionKey, error)
	
	// GetKey retrieves a specific encryption key by ID
	GetKey(keyID string) (*EncryptionKey, error)
	
	// RotateKey creates a new encryption key and marks it as current
	RotateKey() (*EncryptionKey, error)
	
	// ListKeys returns all available encryption keys
	ListKeys() ([]*EncryptionKey, error)
}

// ExternalSecretsKeyManager implements KeyManager using External Secrets Operator
type ExternalSecretsKeyManager struct {
	namespace     string
	secretName    string
	keyRotationInterval time.Duration
}

// NewExternalSecretsKeyManager creates a new key manager using External Secrets Operator
func NewExternalSecretsKeyManager(namespace, secretName string) *ExternalSecretsKeyManager {
	return &ExternalSecretsKeyManager{
		namespace:           namespace,
		secretName:          secretName,
		keyRotationInterval: 30 * 24 * time.Hour, // 30 days default
	}
}

// GetCurrentKey retrieves the current encryption key from External Secrets
func (km *ExternalSecretsKeyManager) GetCurrentKey() (*EncryptionKey, error) {
	// In a real implementation, this would fetch from Kubernetes secrets created by External Secrets Operator
	// For now, we'll simulate with a deterministic key generation based on current time period
	return km.generateMockKey("current"), nil
}

// GetKey retrieves a specific encryption key by ID
func (km *ExternalSecretsKeyManager) GetKey(keyID string) (*EncryptionKey, error) {
	// In a real implementation, this would fetch specific key versions from External Secrets
	return km.generateMockKey(keyID), nil
}

// RotateKey creates a new encryption key (would trigger External Secrets Operator)
func (km *ExternalSecretsKeyManager) RotateKey() (*EncryptionKey, error) {
	newKeyID := fmt.Sprintf("key_%d", time.Now().Unix())
	return km.generateMockKey(newKeyID), nil
}

// ListKeys returns all available encryption keys
func (km *ExternalSecretsKeyManager) ListKeys() ([]*EncryptionKey, error) {
	// In a real implementation, this would list all key versions from External Secrets
	currentKey, _ := km.GetCurrentKey()
	return []*EncryptionKey{currentKey}, nil
}

// generateMockKey generates a mock encryption key (for development/testing)
func (km *ExternalSecretsKeyManager) generateMockKey(keyID string) *EncryptionKey {
	// Generate deterministic key based on keyID and secret data
	keyData := fmt.Sprintf("%s_%s_%s", km.namespace, km.secretName, keyID)
	hash := sha256.Sum256([]byte(keyData))
	
	return &EncryptionKey{
		ID:        keyID,
		KeyData:   hash[:],
		Algorithm: "AES-256-GCM",
		CreatedAt: time.Now().UTC(),
		Status:    "active",
	}
}

// NewEncryptionService creates a new encryption service
func NewEncryptionService(keyManager KeyManager) (*EncryptionService, error) {
	service := &EncryptionService{
		keyManager: keyManager,
	}
	
	// Initialize with current key
	err := service.initializeWithCurrentKey()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}
	
	return service, nil
}

// initializeWithCurrentKey initializes the service with the current encryption key
func (es *EncryptionService) initializeWithCurrentKey() error {
	key, err := es.keyManager.GetCurrentKey()
	if err != nil {
		return fmt.Errorf("failed to get current encryption key: %w", err)
	}
	
	// Create AES cipher
	block, err := aes.NewCipher(key.KeyData)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	// Create GCM mode cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	
	es.gcm = gcm
	es.currentKey = key
	
	return nil
}

// EncryptData encrypts data using AES-256-GCM
func (es *EncryptionService) EncryptData(plaintext []byte) (*EncryptedData, error) {
	if es.gcm == nil {
		return nil, fmt.Errorf("encryption service not properly initialized")
	}
	
	// Generate a random nonce
	nonce := make([]byte, es.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	// Encrypt the data
	ciphertext := es.gcm.Seal(nonce, nonce, plaintext, nil)
	
	encryptedData := &EncryptedData{
		Ciphertext:    ciphertext,
		KeyID:         es.currentKey.ID,
		Algorithm:     es.currentKey.Algorithm,
		EncryptedAt:   time.Now().UTC(),
		NonceSize:     es.gcm.NonceSize(),
	}
	
	return encryptedData, nil
}

// DecryptData decrypts data using the appropriate key
func (es *EncryptionService) DecryptData(encryptedData *EncryptedData) ([]byte, error) {
	// Get the key used for encryption
	key, err := es.keyManager.GetKey(encryptedData.KeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve encryption key %s: %w", encryptedData.KeyID, err)
	}
	
	// Create cipher for this specific key
	block, err := aes.NewCipher(key.KeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	
	// Extract nonce and ciphertext
	nonceSize := encryptedData.NonceSize
	if len(encryptedData.Ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := encryptedData.Ciphertext[:nonceSize], encryptedData.Ciphertext[nonceSize:]
	
	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}
	
	return plaintext, nil
}

// RotateEncryptionKey rotates to a new encryption key
func (es *EncryptionService) RotateEncryptionKey() error {
	newKey, err := es.keyManager.RotateKey()
	if err != nil {
		return fmt.Errorf("failed to rotate encryption key: %w", err)
	}
	
	// Update service with new key
	block, err := aes.NewCipher(newKey.KeyData)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher with new key: %w", err)
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher with new key: %w", err)
	}
	
	es.gcm = gcm
	es.currentKey = newKey
	
	return nil
}

// GetKeyInfo returns information about the current encryption key
func (es *EncryptionService) GetKeyInfo() *EncryptionKeyInfo {
	if es.currentKey == nil {
		return nil
	}
	
	return &EncryptionKeyInfo{
		KeyID:     es.currentKey.ID,
		Algorithm: es.currentKey.Algorithm,
		CreatedAt: es.currentKey.CreatedAt,
		Status:    es.currentKey.Status,
	}
}

// EncryptionKey represents an encryption key with metadata
type EncryptionKey struct {
	ID        string    `json:"id"`
	KeyData   []byte    `json:"-"` // Never serialize key data
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"` // active, rotated, revoked
}

// EncryptedData represents encrypted data with metadata
type EncryptedData struct {
	Ciphertext  []byte    `json:"ciphertext"`
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	EncryptedAt time.Time `json:"encrypted_at"`
	NonceSize   int       `json:"nonce_size"`
}

// ToHex returns the ciphertext as a hex string
func (ed *EncryptedData) ToHex() string {
	return hex.EncodeToString(ed.Ciphertext)
}

// FromHex sets the ciphertext from a hex string
func (ed *EncryptedData) FromHex(hexStr string) error {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return fmt.Errorf("failed to decode hex string: %w", err)
	}
	ed.Ciphertext = data
	return nil
}

// EncryptionKeyInfo provides safe information about an encryption key
type EncryptionKeyInfo struct {
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
	CreatedAt time.Time `json:"created_at"`
	Status    string    `json:"status"`
}

// EncryptionMetrics provides metrics about encryption operations
type EncryptionMetrics struct {
	TotalEncryptions int64     `json:"total_encryptions"`
	TotalDecryptions int64     `json:"total_decryptions"`
	CurrentKeyID     string    `json:"current_key_id"`
	LastKeyRotation  time.Time `json:"last_key_rotation"`
	KeyRotationsDue  bool      `json:"key_rotations_due"`
}