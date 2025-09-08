// Package middleware provides multi-factor authentication support for KubeChat
package middleware

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v2"
	"github.com/pquerna/otp/totp"
)

// MFAMethod represents different MFA methods
type MFAMethod string

const (
	MFAMethodTOTP         MFAMethod = "TOTP"
	MFAMethodSMS          MFAMethod = "SMS"
	MFAMethodPush         MFAMethod = "PUSH"
	MFAMethodHardwareToken MFAMethod = "HARDWARE_TOKEN"
	MFAMethodFIDO2        MFAMethod = "FIDO2"
	MFAMethodWebAuthn     MFAMethod = "WEBAUTHN"
)

// MFAChallenge represents an active MFA challenge
type MFAChallenge struct {
	ChallengeID   string    `json:"challenge_id"`
	UserID        string    `json:"user_id"`
	Method        MFAMethod `json:"method"`
	CreatedAt     time.Time `json:"created_at"`
	ExpiresAt     time.Time `json:"expires_at"`
	AttemptCount  int       `json:"attempt_count"`
	MaxAttempts   int       `json:"max_attempts"`
	Status        string    `json:"status"` // "pending", "completed", "failed", "expired"
	ProviderData  map[string]interface{} `json:"provider_data,omitempty"`
	SessionData   map[string]interface{} `json:"session_data,omitempty"`
}

// MFAResponse represents the response to an MFA challenge
type MFAResponse struct {
	Success           bool          `json:"success"`
	Message           string        `json:"message"`
	Method            MFAMethod     `json:"method"`
	NextStep          string        `json:"next_step,omitempty"`
	ChallengeID       string        `json:"challenge_id,omitempty"`
	ExpiresAt         time.Time     `json:"expires_at,omitempty"`
	RetryAfter        int           `json:"retry_after,omitempty"` // seconds
	SessionID         string        `json:"session_id,omitempty"`
	UserID            string        `json:"user_id,omitempty"`
	ValidityDuration  time.Duration `json:"validity_duration,omitempty"`
	ErrorMessage      string        `json:"error_message,omitempty"`
}

// MFAConfig holds configuration for MFA methods
type MFAConfig struct {
	Enabled           bool                   `json:"enabled"`
	RequiredMethods   []MFAMethod           `json:"required_methods"`
	TOTPConfig        TOTPConfig            `json:"totp_config"`
	SMSConfig         SMSConfig             `json:"sms_config"`
	PushConfig        PushConfig            `json:"push_config"`
	HardwareConfig    HardwareTokenConfig   `json:"hardware_config"`
	PolicyConfig      MFAPolicyEngineConfig `json:"policy_config"`
	ProviderSettings  map[string]interface{} `json:"provider_settings"`
}

// TOTPConfig holds TOTP-specific configuration
type TOTPConfig struct {
	Issuer       string `json:"issuer"`
	AccountName  string `json:"account_name"`
	SecretLength int    `json:"secret_length"`
	Period       uint   `json:"period"`
	Skew         uint   `json:"skew"`
	Digits       int    `json:"digits"`
}

// SMSConfig holds SMS MFA configuration
type SMSConfig struct {
	Provider    string            `json:"provider"` // "twilio", "aws_sns", "azure", etc.
	Settings    map[string]string `json:"settings"`
	MessageTemplate string        `json:"message_template"`
	CodeLength  int               `json:"code_length"`
	CodeExpiry  time.Duration     `json:"code_expiry"`
}

// PushConfig holds push notification MFA configuration
type PushConfig struct {
	Providers []string          `json:"providers"` // "okta_verify", "duo", "auth0_guardian"
	Settings  map[string]string `json:"settings"`
	Timeout   time.Duration     `json:"timeout"`
}

// HardwareTokenConfig holds hardware token configuration
type HardwareTokenConfig struct {
	SupportedTypes []string          `json:"supported_types"` // "yubikey", "fido2", "webauthn"
	Settings       map[string]string `json:"settings"`
	Timeout        time.Duration     `json:"timeout"`
}

// MFAPolicyConfig holds MFA policy configuration
type MFAPolicyConfig struct {
	EnforceForAllUsers    bool              `json:"enforce_for_all_users"`
	UserGroupRequirements map[string][]MFAMethod `json:"user_group_requirements"`
	RiskBasedMFA         RiskBasedMFAConfig `json:"risk_based_mfa"`
	EmergencyAccess      EmergencyAccessConfig `json:"emergency_access"`
}

// RiskBasedMFAConfig holds risk-based MFA configuration
type RiskBasedMFAConfig struct {
	Enabled              bool     `json:"enabled"`
	UnknownIPRequiresMFA bool     `json:"unknown_ip_requires_mfa"`
	UnknownDeviceRequiresMFA bool `json:"unknown_device_requires_mfa"`
	OffHoursRequiresMFA  bool     `json:"off_hours_requires_mfa"`
	HighRiskCountries    []string `json:"high_risk_countries"`
	TrustedNetworks      []string `json:"trusted_networks"`
}

// EmergencyAccessConfig holds emergency access configuration
type EmergencyAccessConfig struct {
	Enabled       bool     `json:"enabled"`
	AdminUsers    []string `json:"admin_users"`
	BypassCodes   []string `json:"bypass_codes"`
	AuditRequired bool     `json:"audit_required"`
}

// MFAHandler manages multi-factor authentication challenges and validation
type MFAHandler struct {
	config      MFAConfig
	redisClient *redis.Client
	jwtService  JWTServiceInterface
}

// NewMFAHandler creates a new MFA handler instance
func NewMFAHandler(config MFAConfig, redisClient *redis.Client, jwtService JWTServiceInterface) *MFAHandler {
	return &MFAHandler{
		config:      config,
		redisClient: redisClient,
		jwtService:  jwtService,
	}
}

// CreateChallenge creates a new MFA challenge for a user
func (h *MFAHandler) CreateChallenge(ctx context.Context, userID string, method MFAMethod, sessionData map[string]interface{}) (*MFAChallenge, error) {
	challengeID := h.generateChallengeID()
	
	challenge := &MFAChallenge{
		ChallengeID:  challengeID,
		UserID:       userID,
		Method:       method,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(5 * time.Minute), // 5 minute default expiry
		AttemptCount: 0,
		MaxAttempts:  3,
		Status:       "pending",
		SessionData:  sessionData,
		ProviderData: make(map[string]interface{}),
	}

	// Method-specific challenge setup
	switch method {
	case MFAMethodTOTP:
		if err := h.setupTOTPChallenge(ctx, challenge); err != nil {
			return nil, fmt.Errorf("failed to setup TOTP challenge: %w", err)
		}
	case MFAMethodSMS:
		if err := h.setupSMSChallenge(ctx, challenge); err != nil {
			return nil, fmt.Errorf("failed to setup SMS challenge: %w", err)
		}
	case MFAMethodPush:
		if err := h.setupPushChallenge(ctx, challenge); err != nil {
			return nil, fmt.Errorf("failed to setup Push challenge: %w", err)
		}
	case MFAMethodHardwareToken, MFAMethodFIDO2, MFAMethodWebAuthn:
		if err := h.setupHardwareTokenChallenge(ctx, challenge); err != nil {
			return nil, fmt.Errorf("failed to setup hardware token challenge: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported MFA method: %s", method)
	}

	// Store challenge in Redis
	if err := h.storeChallengeInRedis(ctx, challenge); err != nil {
		return nil, fmt.Errorf("failed to store challenge: %w", err)
	}

	return challenge, nil
}

// ValidateChallenge validates an MFA challenge response
func (h *MFAHandler) ValidateChallenge(ctx context.Context, challengeID string, response map[string]interface{}) (*MFAResponse, error) {
	// Retrieve challenge from Redis
	challenge, err := h.getChallengeFromRedis(ctx, challengeID)
	if err != nil {
		return &MFAResponse{
			Success: false,
			Message: "Invalid or expired challenge",
		}, err
	}

	// Check if challenge is still valid
	if time.Now().After(challenge.ExpiresAt) {
		challenge.Status = "expired"
		h.storeChallengeInRedis(ctx, challenge) // Update status
		return &MFAResponse{
			Success: false,
			Message: "Challenge has expired",
		}, nil
	}

	// Check attempt limits
	if challenge.AttemptCount >= challenge.MaxAttempts {
		challenge.Status = "failed"
		h.storeChallengeInRedis(ctx, challenge)
		return &MFAResponse{
			Success: false,
			Message: "Maximum attempts exceeded",
			RetryAfter: 300, // 5 minutes
		}, nil
	}

	// Increment attempt count
	challenge.AttemptCount++

	// Method-specific validation
	var isValid bool
	switch challenge.Method {
	case MFAMethodTOTP:
		isValid, err = h.validateTOTP(ctx, challenge, response)
	case MFAMethodSMS:
		isValid, err = h.validateSMS(ctx, challenge, response)
	case MFAMethodPush:
		isValid, err = h.validatePush(ctx, challenge, response)
	case MFAMethodHardwareToken, MFAMethodFIDO2, MFAMethodWebAuthn:
		isValid, err = h.validateHardwareToken(ctx, challenge, response)
	default:
		return &MFAResponse{
			Success: false,
			Message: "Unsupported MFA method",
		}, fmt.Errorf("unsupported MFA method: %s", challenge.Method)
	}

	if err != nil {
		return &MFAResponse{
			Success: false,
			Message: "Validation error occurred",
		}, err
	}

	if isValid {
		challenge.Status = "completed"
		h.storeChallengeInRedis(ctx, challenge)
		
		// Extract session information from challenge data
		sessionID := ""
		if sessionData := challenge.SessionData; sessionData != nil {
			if sid, ok := sessionData["session_id"].(string); ok {
				sessionID = sid
			}
		}
		
		return &MFAResponse{
			Success:          true,
			Message:          "MFA validation successful",
			Method:           challenge.Method,
			ChallengeID:      challengeID,
			SessionID:        sessionID,
			UserID:           challenge.UserID,
			ValidityDuration: 4 * time.Hour, // Default validity
		}, nil
	}

	// Validation failed
	h.storeChallengeInRedis(ctx, challenge) // Update attempt count
	
	attemptsLeft := challenge.MaxAttempts - challenge.AttemptCount
	message := fmt.Sprintf("Invalid code. %d attempts remaining", attemptsLeft)
	
	return &MFAResponse{
		Success:      false,
		Message:      message,
		Method:       challenge.Method,
		ChallengeID:  challengeID,
		ExpiresAt:    challenge.ExpiresAt,
		UserID:       challenge.UserID,
		ErrorMessage: message,
	}, nil
}

// setupTOTPChallenge sets up a TOTP challenge
func (h *MFAHandler) setupTOTPChallenge(ctx context.Context, challenge *MFAChallenge) error {
	// For TOTP, we just need to indicate that user should use their authenticator app
	// The secret should already be registered during user enrollment
	challenge.ProviderData["instruction"] = "Enter the code from your authenticator app"
	return nil
}

// validateTOTP validates a TOTP code
func (h *MFAHandler) validateTOTP(ctx context.Context, challenge *MFAChallenge, response map[string]interface{}) (bool, error) {
	code, ok := response["code"].(string)
	if !ok {
		return false, fmt.Errorf("TOTP code not provided")
	}

	// In a real implementation, you would:
	// 1. Retrieve the user's TOTP secret from secure storage
	// 2. Validate the code against the secret
	// For this implementation, we'll use a mock validation

	// Get user's TOTP secret (would be from secure storage in production)
	secret, err := h.getUserTOTPSecret(ctx, challenge.UserID)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve TOTP secret: %w", err)
	}

	// Validate the TOTP code
	valid := totp.Validate(code, secret)
	return valid, nil
}

// setupSMSChallenge sets up an SMS challenge
func (h *MFAHandler) setupSMSChallenge(ctx context.Context, challenge *MFAChallenge) error {
	// Generate SMS code
	code := h.generateSMSCode()
	challenge.ProviderData["code"] = code
	challenge.ProviderData["phone"] = "*** *** **XX" // Masked phone number

	// In production, you would send the SMS here
	// For now, we'll just store the code for validation
	
	challenge.ProviderData["instruction"] = "Enter the code sent to your registered phone number"
	return nil
}

// validateSMS validates an SMS code
func (h *MFAHandler) validateSMS(ctx context.Context, challenge *MFAChallenge, response map[string]interface{}) (bool, error) {
	userCode, ok := response["code"].(string)
	if !ok {
		return false, fmt.Errorf("SMS code not provided")
	}

	expectedCode, ok := challenge.ProviderData["code"].(string)
	if !ok {
		return false, fmt.Errorf("SMS challenge not properly initialized")
	}

	return userCode == expectedCode, nil
}

// setupPushChallenge sets up a push notification challenge
func (h *MFAHandler) setupPushChallenge(ctx context.Context, challenge *MFAChallenge) error {
	// Generate push notification
	challenge.ProviderData["instruction"] = "Check your mobile device for a push notification"
	challenge.ProviderData["status"] = "sent"
	
	// In production, you would send the push notification here
	// For now, we'll simulate it
	
	return nil
}

// validatePush validates a push notification response
func (h *MFAHandler) validatePush(ctx context.Context, challenge *MFAChallenge, response map[string]interface{}) (bool, error) {
	action, ok := response["action"].(string)
	if !ok {
		return false, fmt.Errorf("push response not provided")
	}

	// In production, you would check with the push notification service
	// For now, we'll accept "approve" as valid
	return action == "approve", nil
}

// setupHardwareTokenChallenge sets up a hardware token challenge
func (h *MFAHandler) setupHardwareTokenChallenge(ctx context.Context, challenge *MFAChallenge) error {
	switch challenge.Method {
	case MFAMethodHardwareToken:
		challenge.ProviderData["instruction"] = "Use your hardware security key"
	case MFAMethodFIDO2:
		challenge.ProviderData["instruction"] = "Use your FIDO2 security key"
	case MFAMethodWebAuthn:
		challenge.ProviderData["instruction"] = "Use your WebAuthn device"
		// In production, you would generate WebAuthn challenge data here
		challenge.ProviderData["challenge_data"] = h.generateWebAuthnChallenge()
	}
	return nil
}

// validateHardwareToken validates a hardware token response
func (h *MFAHandler) validateHardwareToken(ctx context.Context, challenge *MFAChallenge, response map[string]interface{}) (bool, error) {
	// In production, you would validate against the hardware token/WebAuthn service
	// For now, we'll use basic validation
	
	switch challenge.Method {
	case MFAMethodWebAuthn:
		authenticatorData, ok := response["authenticatorData"].(string)
		if !ok {
			return false, fmt.Errorf("WebAuthn authenticator data not provided")
		}
		signature, ok := response["signature"].(string)
		if !ok {
			return false, fmt.Errorf("WebAuthn signature not provided")
		}
		
		// In production: validate WebAuthn response
		return len(authenticatorData) > 0 && len(signature) > 0, nil
	default:
		// For other hardware tokens, check for presence of response
		tokenResponse, ok := response["token_response"].(string)
		return ok && len(tokenResponse) > 0, nil
	}
}

// Helper methods

func (h *MFAHandler) generateChallengeID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.URLEncoding.EncodeToString(bytes)
}

func (h *MFAHandler) generateSMSCode() string {
	code := make([]byte, h.config.SMSConfig.CodeLength/2)
	rand.Read(code)
	
	// Convert to numeric code
	numCode := ""
	for _, b := range code {
		numCode += fmt.Sprintf("%02d", int(b)%100)
	}
	
	// Ensure it's the right length
	if len(numCode) > h.config.SMSConfig.CodeLength {
		numCode = numCode[:h.config.SMSConfig.CodeLength]
	}
	
	return numCode
}

func (h *MFAHandler) generateWebAuthnChallenge() string {
	challenge := make([]byte, 32)
	rand.Read(challenge)
	return base64.URLEncoding.EncodeToString(challenge)
}

func (h *MFAHandler) getUserTOTPSecret(ctx context.Context, userID string) (string, error) {
	// In production, this would retrieve from secure storage
	// For now, return a mock secret
	secretKey := fmt.Sprintf("totp_secret:%s", userID)
	secret, err := h.redisClient.Get(ctx, secretKey).Result()
	if err != nil {
		if err == redis.Nil {
			// Generate new secret if none exists
			secret = h.generateTOTPSecret()
			h.redisClient.Set(ctx, secretKey, secret, 0) // No expiration for TOTP secrets
		} else {
			return "", err
		}
	}
	return secret, nil
}

func (h *MFAHandler) generateTOTPSecret() string {
	secret := make([]byte, 20) // 160 bits
	rand.Read(secret)
	return base32.StdEncoding.EncodeToString(secret)
}

func (h *MFAHandler) storeChallengeInRedis(ctx context.Context, challenge *MFAChallenge) error {
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("mfa_challenge:%s", challenge.ChallengeID)
	expiration := time.Until(challenge.ExpiresAt)
	
	return h.redisClient.Set(ctx, key, challengeJSON, expiration).Err()
}

func (h *MFAHandler) getChallengeFromRedis(ctx context.Context, challengeID string) (*MFAChallenge, error) {
	key := fmt.Sprintf("mfa_challenge:%s", challengeID)
	challengeJSON, err := h.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("challenge not found")
		}
		return nil, err
	}

	var challenge MFAChallenge
	err = json.Unmarshal([]byte(challengeJSON), &challenge)
	return &challenge, err
}

// RequiresMFA determines if MFA is required for a user based on policy
func (h *MFAHandler) RequiresMFA(ctx context.Context, claims *JWTClaims, clientIP string, userAgent string) (bool, []MFAMethod, error) {
	if !h.config.Enabled {
		return false, nil, nil
	}

	// Check global enforcement
	if h.config.PolicyConfig.EnforceForAllUsers {
		return true, h.config.RequiredMethods, nil
	}

	// Check user group requirements
	for _, group := range claims.Groups {
		if methods, exists := h.config.PolicyConfig.UserGroupRequirements[group]; exists {
			return true, methods, nil
		}
	}

	// Check risk-based MFA
	if h.config.PolicyConfig.RiskBasedMFA.Enabled {
		isHighRisk, err := h.assessRisk(ctx, claims, clientIP, userAgent)
		if err != nil {
			return false, nil, fmt.Errorf("failed to assess risk: %w", err)
		}
		
		if isHighRisk {
			return true, h.config.RequiredMethods, nil
		}
	}

	return false, nil, nil
}

// assessRisk performs risk assessment for MFA requirements
func (h *MFAHandler) assessRisk(ctx context.Context, claims *JWTClaims, clientIP string, userAgent string) (bool, error) {
	riskConfig := h.config.PolicyConfig.RiskBasedMFA

	// Check for unknown IP
	if riskConfig.UnknownIPRequiresMFA {
		knownIP, err := h.isKnownIP(ctx, claims.UserID, clientIP)
		if err != nil {
			return false, err
		}
		if !knownIP {
			return true, nil
		}
	}

	// Check for unknown device
	if riskConfig.UnknownDeviceRequiresMFA {
		deviceFingerprint := h.generateDeviceFingerprint(userAgent, clientIP)
		knownDevice, err := h.isKnownDevice(ctx, claims.UserID, deviceFingerprint)
		if err != nil {
			return false, err
		}
		if !knownDevice {
			return true, nil
		}
	}

	// Check for off-hours access
	if riskConfig.OffHoursRequiresMFA {
		if h.isOffHours() {
			return true, nil
		}
	}

	return false, nil
}

// Helper methods for risk assessment
func (h *MFAHandler) isKnownIP(ctx context.Context, userID, clientIP string) (bool, error) {
	key := fmt.Sprintf("known_ips:%s", userID)
	return h.redisClient.SIsMember(ctx, key, clientIP).Result()
}

func (h *MFAHandler) isKnownDevice(ctx context.Context, userID, deviceFingerprint string) (bool, error) {
	key := fmt.Sprintf("known_devices:%s", userID)
	return h.redisClient.SIsMember(ctx, key, deviceFingerprint).Result()
}

func (h *MFAHandler) generateDeviceFingerprint(userAgent, clientIP string) string {
	data := fmt.Sprintf("%s:%s", userAgent, clientIP)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// IsHighRiskOperation checks if an operation is considered high-risk and requires fresh MFA
func (h *MFAHandler) IsHighRiskOperation(operation string) bool {
	highRiskOperations := []string{
		"delete-namespace",
		"modify-rbac",
		"access-secrets",
		"delete-secret", 
		"create-cluster-role",
		"delete-cluster-role",
		"modify-cluster-role-binding",
		"access-etcd",
		"modify-admission-controllers",
		"access-node-logs",
		"modify-network-policies",
		"create-persistent-volume",
		"modify-service-account",
		"access-cluster-credentials",
	}
	
	// Check exact matches first
	for _, riskOp := range highRiskOperations {
		if operation == riskOp {
			return true
		}
	}
	
	// Check for substring matches for operations like "delete-*", "modify-*"
	for _, riskOp := range highRiskOperations {
		if strings.Contains(operation, riskOp) {
			return true
		}
	}
	
	return false
}

// GetSupportedMethods returns all supported MFA methods
func (h *MFAHandler) GetSupportedMethods() []MFAMethod {
	return []MFAMethod{
		MFAMethodTOTP,
		MFAMethodSMS,
		MFAMethodPush,
		MFAMethodHardwareToken,
		MFAMethodFIDO2,
		MFAMethodWebAuthn,
	}
}

// GenerateTOTPSecret generates a new TOTP secret for user enrollment
func (h *MFAHandler) GenerateTOTPSecret(accountName string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      h.config.TOTPConfig.Issuer,
		AccountName: accountName,
	})
	if err != nil {
		return "", "", fmt.Errorf("failed to generate TOTP secret: %w", err)
	}
	
	return key.Secret(), key.URL(), nil
}

func (h *MFAHandler) isOffHours() bool {
	now := time.Now()
	hour := now.Hour()
	// Consider off-hours as before 8 AM or after 6 PM
	return hour < 8 || hour > 18
}

// UpdateMFAStatus updates the MFA status in JWT claims
func (h *MFAHandler) UpdateMFAStatus(claims *JWTClaims, method MFAMethod, validityDuration time.Duration) {
	claims.MFACompleted = true
	claims.MFAMethod = string(method)
	claims.MFATimestamp = time.Now()
	claims.MFAValidityDuration = validityDuration
	claims.RequiresMFAStepUp = false // Reset step-up requirement after successful MFA
}

// CheckEmergencyAccess checks if emergency access is allowed
func (h *MFAHandler) CheckEmergencyAccess(ctx context.Context, userID, emergencyCode string) (bool, error) {
	if !h.config.PolicyConfig.EmergencyAccess.Enabled {
		return false, nil
	}

	// Check if user is admin
	for _, adminUser := range h.config.PolicyConfig.EmergencyAccess.AdminUsers {
		if adminUser == userID {
			// Check emergency bypass code
			for _, code := range h.config.PolicyConfig.EmergencyAccess.BypassCodes {
				if code == emergencyCode {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// GetUserFriendlyInstruction returns user-friendly instructions for MFA methods
func (h *MFAHandler) GetUserFriendlyInstruction(method MFAMethod, step string) string {
	switch method {
	case MFAMethodTOTP:
		switch step {
		case "initial":
			return "Open your authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.) and enter the 6-digit code displayed for KubeChat."
		case "retry":
			return "The code was incorrect. Please wait for a new code to appear in your authenticator app and try again."
		case "expired":
			return "Your session has expired. Please refresh the page and try again."
		default:
			return "Enter the 6-digit code from your authenticator app."
		}
	case MFAMethodSMS:
		switch step {
		case "initial":
			return "A 6-digit verification code has been sent to your registered phone number. Enter the code below."
		case "retry":
			return "The code was incorrect. Please check your messages for the verification code and try again."
		case "resend":
			return "Didn't receive the code? We can resend it to your registered phone number."
		default:
			return "Enter the 6-digit code sent to your phone."
		}
	case MFAMethodPush:
		switch step {
		case "initial":
			return "A push notification has been sent to your registered device. Please check your phone and approve the login request."
		case "waiting":
			return "Waiting for approval... Please check your mobile device and tap 'Approve' in the notification."
		case "timeout":
			return "The push notification timed out. Please try again or use an alternative verification method."
		default:
			return "Check your mobile device for a push notification and approve the login."
		}
	case MFAMethodHardwareToken, MFAMethodFIDO2, MFAMethodWebAuthn:
		switch step {
		case "initial":
			return "Insert your security key and follow your browser's prompts to complete authentication."
		case "touch":
			return "Please touch your security key when it lights up or vibrates."
		case "error":
			return "Security key authentication failed. Please ensure your key is properly inserted and try again."
		default:
			return "Use your hardware security key to complete authentication."
		}
	default:
		return "Please complete the multi-factor authentication challenge."
	}
}

// GetMFAErrorMessage returns user-friendly error messages
func (h *MFAHandler) GetMFAErrorMessage(errorType string, method MFAMethod, context map[string]interface{}) string {
	switch errorType {
	case "invalid_code":
		remainingAttempts := context["remaining_attempts"].(int)
		switch method {
		case MFAMethodTOTP:
			if remainingAttempts == 1 {
				return "The authenticator code is incorrect. You have 1 attempt remaining before this session is locked."
			}
			return fmt.Sprintf("The authenticator code is incorrect. You have %d attempts remaining.", remainingAttempts)
		case MFAMethodSMS:
			if remainingAttempts == 1 {
				return "The SMS code is incorrect. You have 1 attempt remaining before this session is locked."
			}
			return fmt.Sprintf("The SMS code is incorrect. You have %d attempts remaining.", remainingAttempts)
		default:
			return fmt.Sprintf("The verification code is incorrect. You have %d attempts remaining.", remainingAttempts)
		}
	case "expired_code":
		switch method {
		case MFAMethodTOTP:
			return "The authenticator code has expired. Please wait for a new code to appear and try again."
		case MFAMethodSMS:
			return "The SMS code has expired. Please request a new code."
		default:
			return "The verification code has expired. Please try again."
		}
	case "too_many_attempts":
		lockoutTime := context["lockout_minutes"].(int)
		return fmt.Sprintf("Too many failed attempts. Please wait %d minutes before trying again, or contact your administrator for assistance.", lockoutTime)
	case "method_unavailable":
		return "The selected authentication method is currently unavailable. Please try a different method or contact support."
	case "network_error":
		return "A network error occurred. Please check your connection and try again."
	case "device_not_registered":
		return "No registered devices found for this authentication method. Please contact your administrator to set up multi-factor authentication."
	default:
		return "An error occurred during authentication. Please try again or contact support if the problem persists."
	}
}

// GetMFAMethodDisplayName returns user-friendly display names for MFA methods
func (h *MFAHandler) GetMFAMethodDisplayName(method MFAMethod) string {
	switch method {
	case MFAMethodTOTP:
		return "Authenticator App"
	case MFAMethodSMS:
		return "SMS Text Message"
	case MFAMethodPush:
		return "Push Notification"
	case MFAMethodHardwareToken:
		return "Hardware Security Key"
	case MFAMethodFIDO2:
		return "FIDO2 Security Key"
	case MFAMethodWebAuthn:
		return "WebAuthn Device"
	default:
		return "Unknown Method"
	}
}

// GetMFAStepGuidance provides step-by-step guidance for MFA completion
func (h *MFAHandler) GetMFAStepGuidance(method MFAMethod) []string {
	switch method {
	case MFAMethodTOTP:
		return []string{
			"1. Open your authenticator app (Google Authenticator, Authy, Microsoft Authenticator, etc.)",
			"2. Find the KubeChat entry in your app",
			"3. Enter the current 6-digit code displayed",
			"4. Click 'Verify' to complete authentication",
			"Note: Codes refresh every 30 seconds - use the current code shown",
		}
	case MFAMethodSMS:
		return []string{
			"1. Check your registered phone for a text message",
			"2. The message contains a 6-digit verification code",
			"3. Enter the code in the field below",
			"4. Click 'Verify' to complete authentication",
			"Note: If you don't receive the code, click 'Resend' after 1 minute",
		}
	case MFAMethodPush:
		return []string{
			"1. Check your registered mobile device for a notification",
			"2. Open the notification when it appears",
			"3. Review the login details (location, device, time)",
			"4. Tap 'Approve' if this login attempt is legitimate",
			"5. Return to this page - it will automatically continue",
		}
	case MFAMethodHardwareToken, MFAMethodFIDO2, MFAMethodWebAuthn:
		return []string{
			"1. Insert your security key into a USB port (if required)",
			"2. Your browser will prompt you to activate your key",
			"3. Touch your security key when it lights up or vibrates",
			"4. Authentication will complete automatically",
			"Note: Make sure your security key is registered with your account",
		}
	default:
		return []string{
			"1. Complete the authentication challenge",
			"2. Follow any prompts that appear",
			"3. Contact support if you need assistance",
		}
	}
}

// CreateRetryStrategy creates a retry strategy for failed MFA attempts
func (h *MFAHandler) CreateRetryStrategy(challenge *MFAChallenge, failureReason string) map[string]interface{} {
	strategy := map[string]interface{}{
		"can_retry":         challenge.AttemptCount < challenge.MaxAttempts,
		"remaining_attempts": challenge.MaxAttempts - challenge.AttemptCount,
		"lockout_time":      0,
		"alternative_methods": []string{},
		"guidance":          "",
	}

	if !strategy["can_retry"].(bool) {
		// Account is locked, provide lockout information
		strategy["lockout_time"] = 5 // 5 minutes default lockout
		strategy["guidance"] = "Account temporarily locked due to too many failed attempts. Please wait 5 minutes before trying again."
		return strategy
	}

	// Provide method-specific retry guidance
	switch challenge.Method {
	case MFAMethodTOTP:
		strategy["guidance"] = "Wait for a new code to appear in your authenticator app, then try again."
		strategy["alternative_methods"] = h.getAlternativeMethods(challenge.UserID, MFAMethodTOTP)
	case MFAMethodSMS:
		if failureReason == "expired" {
			strategy["can_resend"] = true
			strategy["resend_wait"] = 60 // 60 seconds before can resend
		}
		strategy["guidance"] = "Check your phone for the SMS code and try again."
		strategy["alternative_methods"] = h.getAlternativeMethods(challenge.UserID, MFAMethodSMS)
	case MFAMethodPush:
		strategy["can_resend"] = true
		strategy["resend_wait"] = 30
		strategy["guidance"] = "Check your mobile device for the push notification."
		strategy["alternative_methods"] = h.getAlternativeMethods(challenge.UserID, MFAMethodPush)
	}

	return strategy
}

// getAlternativeMethods returns available alternative MFA methods for a user
func (h *MFAHandler) getAlternativeMethods(userID string, currentMethod MFAMethod) []string {
	// In production, this would check user's registered MFA methods
	// For now, return common alternatives
	alternatives := []string{}
	
	switch currentMethod {
	case MFAMethodTOTP:
		if h.isMethodAvailable(userID, MFAMethodSMS) {
			alternatives = append(alternatives, "SMS")
		}
		if h.isMethodAvailable(userID, MFAMethodPush) {
			alternatives = append(alternatives, "Push")
		}
	case MFAMethodSMS:
		if h.isMethodAvailable(userID, MFAMethodTOTP) {
			alternatives = append(alternatives, "Authenticator")
		}
		if h.isMethodAvailable(userID, MFAMethodPush) {
			alternatives = append(alternatives, "Push")
		}
	case MFAMethodPush:
		if h.isMethodAvailable(userID, MFAMethodTOTP) {
			alternatives = append(alternatives, "Authenticator")
		}
		if h.isMethodAvailable(userID, MFAMethodSMS) {
			alternatives = append(alternatives, "SMS")
		}
	}
	
	return alternatives
}

// isMethodAvailable checks if a user has a specific MFA method registered
func (h *MFAHandler) isMethodAvailable(userID string, method MFAMethod) bool {
	// In production, this would check user's registered methods in the database
	// For now, assume all methods are available for demonstration
	return true
}

// HandleMFAMethodSwitch allows users to switch between MFA methods
func (h *MFAHandler) HandleMFAMethodSwitch() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var request struct {
			ChallengeID string `json:"challenge_id"`
			NewMethod   string `json:"new_method"`
		}

		if err := c.BodyParser(&request); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid request format",
			})
		}

		// Get current challenge
		challenge, err := h.getChallengeFromRedis(context.Background(), request.ChallengeID)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error":   true,
				"message": "Challenge not found or expired",
			})
		}

		// Check if the new method is available for this user
		newMethod := MFAMethod(strings.ToUpper(request.NewMethod))
		if !h.isMethodAvailable(challenge.UserID, newMethod) {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": fmt.Sprintf("Method %s is not available for this user", h.GetMFAMethodDisplayName(newMethod)),
			})
		}

		// Create new challenge with the requested method
		newChallenge, err := h.CreateChallenge(context.Background(), challenge.UserID, newMethod, challenge.SessionData)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Failed to create challenge with new method",
			})
		}

		// Invalidate old challenge
		challenge.Status = "cancelled"
		h.storeChallengeInRedis(context.Background(), challenge)

		return c.JSON(fiber.Map{
			"success":        true,
			"message":        fmt.Sprintf("Switched to %s", h.GetMFAMethodDisplayName(newMethod)),
			"challenge_id":   newChallenge.ChallengeID,
			"method":         newChallenge.Method,
			"method_display": h.GetMFAMethodDisplayName(newChallenge.Method),
			"instruction":    h.GetUserFriendlyInstruction(newChallenge.Method, "initial"),
			"guidance":       h.GetMFAStepGuidance(newChallenge.Method),
			"expires_at":     newChallenge.ExpiresAt.Unix(),
			"max_attempts":   newChallenge.MaxAttempts,
		})
	}
}

// HandleEmergencyAccess handles emergency access requests
func (h *MFAHandler) HandleEmergencyAccess() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var request struct {
			UserID        string `json:"user_id"`
			EmergencyCode string `json:"emergency_code"`
			Justification string `json:"justification"`
		}

		if err := c.BodyParser(&request); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid request format",
			})
		}

		// Validate emergency access
		isValid, err := h.CheckEmergencyAccess(context.Background(), request.UserID, request.EmergencyCode)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Failed to validate emergency access",
			})
		}

		if !isValid {
			// Log security event for invalid emergency access attempt
			fmt.Printf("SECURITY ALERT: Invalid emergency access attempt by user %s from IP %s\n", 
				request.UserID, c.IP())
			
			return c.Status(http.StatusForbidden).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid emergency access credentials",
			})
		}

		// Log successful emergency access
		fmt.Printf("AUDIT: Emergency access granted to user %s from IP %s. Justification: %s\n", 
			request.UserID, c.IP(), request.Justification)

		return c.JSON(fiber.Map{
			"success": true,
			"message": "Emergency access granted",
			"warning": "This access is being audited. Please complete your required tasks and enable MFA as soon as possible.",
		})
	}
}

// MFA HTTP Handlers

// HandleMFAChallenge creates a new MFA challenge
func (h *MFAHandler) HandleMFAChallenge() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var request struct {
			Method      string                 `json:"method"`
			SessionData map[string]interface{} `json:"session_data"`
		}

		if err := c.BodyParser(&request); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid request format",
			})
		}

		// Get user from context
		userClaims := c.Locals("user").(*JWTClaims)
		if userClaims == nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "User not authenticated",
			})
		}

		method := MFAMethod(strings.ToUpper(request.Method))
		challenge, err := h.CreateChallenge(context.Background(), userClaims.UserID, method, request.SessionData)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Failed to create MFA challenge",
				"details": err.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"success":      true,
			"challenge_id": challenge.ChallengeID,
			"method":       challenge.Method,
			"expires_at":   challenge.ExpiresAt.Unix(),
			"instruction":  challenge.ProviderData["instruction"],
			"max_attempts": challenge.MaxAttempts,
		})
	}
}

// HandleMFAValidation validates an MFA challenge response
func (h *MFAHandler) HandleMFAValidation() fiber.Handler {
	return func(c *fiber.Ctx) error {
		var request struct {
			ChallengeID string                 `json:"challenge_id"`
			Response    map[string]interface{} `json:"response"`
		}

		if err := c.BodyParser(&request); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":   true,
				"message": "Invalid request format",
			})
		}

		// Get challenge for enhanced error reporting
		challenge, err := h.getChallengeFromRedis(context.Background(), request.ChallengeID)
		if err != nil {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{
				"error":   true,
				"message": "Challenge not found or expired",
				"user_message": "Your session has expired. Please refresh the page and try again.",
			})
		}

		mfaResponse, err := h.ValidateChallenge(context.Background(), request.ChallengeID, request.Response)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Validation failed",
				"user_message": h.GetMFAErrorMessage("network_error", challenge.Method, map[string]interface{}{}),
				"details": err.Error(),
			})
		}

		if mfaResponse.Success {
			return c.JSON(fiber.Map{
				"success": true,
				"message": mfaResponse.Message,
				"method":  mfaResponse.Method,
				"method_display": h.GetMFAMethodDisplayName(mfaResponse.Method),
				"user_message": "Authentication successful! You will be redirected shortly.",
			})
		}

		// Enhanced error response with retry strategy
		status := http.StatusBadRequest
		if mfaResponse.RetryAfter > 0 {
			status = http.StatusTooManyRequests
		}

		// Get updated challenge for retry strategy
		updatedChallenge, _ := h.getChallengeFromRedis(context.Background(), request.ChallengeID)
		if updatedChallenge == nil {
			updatedChallenge = challenge // fallback
		}

		retryStrategy := h.CreateRetryStrategy(updatedChallenge, "invalid_code")
		
		errorContext := map[string]interface{}{
			"remaining_attempts": retryStrategy["remaining_attempts"],
			"lockout_minutes":   retryStrategy["lockout_time"],
		}

		userMessage := mfaResponse.Message
		if !retryStrategy["can_retry"].(bool) {
			userMessage = h.GetMFAErrorMessage("too_many_attempts", challenge.Method, errorContext)
		} else {
			userMessage = h.GetMFAErrorMessage("invalid_code", challenge.Method, errorContext)
		}

		response := fiber.Map{
			"success":       false,
			"message":       mfaResponse.Message,
			"user_message":  userMessage,
			"method":        mfaResponse.Method,
			"method_display": h.GetMFAMethodDisplayName(mfaResponse.Method),
			"retry_after":   mfaResponse.RetryAfter,
			"expires_at":    mfaResponse.ExpiresAt.Unix(),
			"retry_strategy": retryStrategy,
			"guidance":      h.GetUserFriendlyInstruction(challenge.Method, "retry"),
		}

		// Add alternative methods if available
		if alternatives, ok := retryStrategy["alternative_methods"].([]string); ok && len(alternatives) > 0 {
			response["alternative_methods"] = alternatives
			response["can_switch_method"] = true
		}

		return c.Status(status).JSON(response)
	}
}