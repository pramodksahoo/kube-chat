// Package middleware provides MFA session state management for KubeChat
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/gofiber/fiber/v3"
)

// MFASessionManager handles MFA session state and step-up authentication
type MFASessionManager struct {
	redisClient   *redis.Client
	jwtService    JWTServiceInterface
	mfaHandler    *MFAHandler
	auditLogger   *AuthAuditLogger // For logging MFA events
}

// MFAOperationRisk defines risk levels for operations requiring MFA step-up
type MFAOperationRisk string

const (
	MFARiskLow      MFAOperationRisk = "LOW"
	MFARiskMedium   MFAOperationRisk = "MEDIUM"
	MFARiskHigh     MFAOperationRisk = "HIGH"
	MFARiskCritical MFAOperationRisk = "CRITICAL"
)

// MFAOperationConfig defines MFA requirements for operations
type MFAOperationConfig struct {
	Operation      string           `json:"operation"`
	RiskLevel      MFAOperationRisk `json:"risk_level"`
	RequiresMFA    bool             `json:"requires_mfa"`
	MFAValidity    time.Duration    `json:"mfa_validity"`
	AllowedMethods []MFAMethod      `json:"allowed_methods"`
	Description    string           `json:"description"`
}

// High-risk operations that require MFA step-up
var DefaultMFAOperations = map[string]MFAOperationConfig{
	"delete-namespace": {
		Operation:      "delete-namespace",
		RiskLevel:      MFARiskCritical,
		RequiresMFA:    true,
		MFAValidity:    5 * time.Minute, // Short validity for critical operations
		AllowedMethods: []MFAMethod{MFAMethodTOTP, MFAMethodHardwareToken, MFAMethodWebAuthn},
		Description:    "Delete Kubernetes namespace",
	},
	"delete-cluster-resource": {
		Operation:      "delete-cluster-resource",
		RiskLevel:      MFARiskHigh,
		RequiresMFA:    true,
		MFAValidity:    10 * time.Minute,
		AllowedMethods: []MFAMethod{MFAMethodTOTP, MFAMethodHardwareToken, MFAMethodSMS},
		Description:    "Delete cluster-scoped resources",
	},
	"modify-rbac": {
		Operation:      "modify-rbac",
		RiskLevel:      MFARiskHigh,
		RequiresMFA:    true,
		MFAValidity:    15 * time.Minute,
		AllowedMethods: []MFAMethod{MFAMethodTOTP, MFAMethodHardwareToken},
		Description:    "Modify RBAC permissions",
	},
	"access-secrets": {
		Operation:      "access-secrets",
		RiskLevel:      MFARiskHigh,
		RequiresMFA:    true,
		MFAValidity:    10 * time.Minute,
		AllowedMethods: []MFAMethod{MFAMethodTOTP, MFAMethodHardwareToken, MFAMethodWebAuthn},
		Description:    "Access Kubernetes secrets",
	},
	"production-deployment": {
		Operation:      "production-deployment",
		RiskLevel:      MFARiskMedium,
		RequiresMFA:    true,
		MFAValidity:    30 * time.Minute,
		AllowedMethods: []MFAMethod{MFAMethodTOTP, MFAMethodPush, MFAMethodSMS},
		Description:    "Deploy to production environment",
	},
}

// NewMFASessionManager creates a new MFA session manager
func NewMFASessionManager(redisClient *redis.Client, jwtService JWTServiceInterface, mfaHandler *MFAHandler, auditLogger *AuthAuditLogger) *MFASessionManager {
	return &MFASessionManager{
		redisClient: redisClient,
		jwtService:  jwtService,
		mfaHandler:  mfaHandler,
		auditLogger: auditLogger,
	}
}

// RequiresMFAMiddleware is a middleware that checks if an operation requires MFA
func (m *MFASessionManager) RequiresMFAMiddleware(operation string) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Get user from context
		userClaims := c.Locals("user").(*JWTClaims)
		if userClaims == nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "User not authenticated",
			})
		}

		// Check if operation requires MFA
		config, requiresMFA := DefaultMFAOperations[operation]
		if !requiresMFA {
			// Operation doesn't require MFA, continue
			return c.Next()
		}

		// Check if user has valid MFA for this operation
		valid, err := m.ValidateMFAForOperation(context.Background(), userClaims.SessionID, operation)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Failed to validate MFA status",
				"details": err.Error(),
			})
		}

		if valid {
			// MFA is valid, log the operation and continue
			// Audit log: MFA-protected operation completed successfully
			// m.auditLogger.LogCommandExecution would be called here
			return c.Next()
		}

		// MFA is required but not valid, initiate step-up authentication
		return m.initiateMFAStepUp(c, userClaims, config)
	}
}

// ValidateMFAForOperation checks if MFA is valid for a specific operation
func (m *MFASessionManager) ValidateMFAForOperation(ctx context.Context, sessionID, operation string) (bool, error) {
	// Get MFA status for session
	mfaStatus, err := m.GetMFAStatus(ctx, sessionID)
	if err != nil {
		return false, err
	}

	// Check if MFA is completed
	if !mfaStatus.MFACompleted {
		return false, nil
	}

	// Check if MFA has expired
	if time.Now().After(mfaStatus.MFAExpiresAt) {
		return false, nil
	}

	// Check operation-specific MFA validity
	if config, exists := DefaultMFAOperations[operation]; exists {
		operationMFAExpiry := mfaStatus.MFATimestamp.Add(config.MFAValidity)
		if time.Now().After(operationMFAExpiry) {
			return false, nil
		}

		// Check if the MFA method used is allowed for this operation
		methodAllowed := false
		for _, allowedMethod := range config.AllowedMethods {
			if string(allowedMethod) == mfaStatus.MFAMethod {
				methodAllowed = true
				break
			}
		}
		if !methodAllowed {
			return false, nil
		}
	}

	return true, nil
}

// GetMFAStatus retrieves MFA status for a session
func (m *MFASessionManager) GetMFAStatus(ctx context.Context, sessionID string) (*MFASessionStatus, error) {
	key := fmt.Sprintf("mfa_status:%s", sessionID)
	statusJSON, err := m.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			// No MFA status found, return default
			return &MFASessionStatus{
				SessionID:    sessionID,
				MFACompleted: false,
				MFATimestamp: time.Time{},
				MFAExpiresAt: time.Time{},
			}, nil
		}
		return nil, err
	}

	var status MFASessionStatus
	err = json.Unmarshal([]byte(statusJSON), &status)
	return &status, err
}

// UpdateMFAStatus updates the MFA status for a session
func (m *MFASessionManager) UpdateMFAStatus(ctx context.Context, sessionID, userID string, mfaCompleted bool, method string, validity time.Duration) error {
	status := &MFASessionStatus{
		SessionID:           sessionID,
		UserID:              userID,
		MFACompleted:        mfaCompleted,
		MFAMethod:           method,
		MFATimestamp:        time.Now(),
		MFAValidityDuration: validity,
		MFAExpiresAt:        time.Now().Add(validity),
		LastMFAValidation:   time.Now(),
	}

	statusJSON, err := json.Marshal(status)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("mfa_status:%s", sessionID)
	expiration := validity + (1 * time.Hour) // Keep status slightly longer than MFA validity
	
	return m.redisClient.Set(ctx, key, statusJSON, expiration).Err()
}

// SetMFAStepUpRequirement sets MFA step-up requirement for a session
func (m *MFASessionManager) SetMFAStepUpRequirement(ctx context.Context, sessionID string, required bool, operation string) error {
	status, err := m.GetMFAStatus(ctx, sessionID)
	if err != nil {
		return err
	}

	status.RequiresMFAStepUp = required
	
	if required {
		// Add operation to step-up operations list
		found := false
		for _, op := range status.StepUpOperations {
			if op == operation {
				found = true
				break
			}
		}
		if !found {
			status.StepUpOperations = append(status.StepUpOperations, operation)
		}
	} else {
		// Remove operation from step-up operations list
		newOps := []string{}
		for _, op := range status.StepUpOperations {
			if op != operation {
				newOps = append(newOps, op)
			}
		}
		status.StepUpOperations = newOps
		status.RequiresMFAStepUp = len(newOps) > 0
	}

	// Save updated status
	statusJSON, err := json.Marshal(status)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("mfa_status:%s", sessionID)
	expiration := status.MFAValidityDuration + (1 * time.Hour)
	
	return m.redisClient.Set(ctx, key, statusJSON, expiration).Err()
}

// InvalidateMFAForSessions invalidates MFA for all sessions of a user
func (m *MFASessionManager) InvalidateMFAForSessions(ctx context.Context, userID string) error {
	// Get all active sessions for user
	sessions, err := m.jwtService.GetAllActiveSessions(userID)
	if err != nil {
		return err
	}

	// Invalidate MFA status for each session
	for _, session := range sessions {
		err := m.UpdateMFAStatus(ctx, session.SessionID, userID, false, "", 0)
		if err != nil {
			// Log error but continue with other sessions
			fmt.Printf("Error invalidating MFA for session %s: %v\n", session.SessionID, err)
		}
	}

	return nil
}

// initiateMFAStepUp initiates MFA step-up authentication for an operation
func (m *MFASessionManager) initiateMFAStepUp(c fiber.Ctx, claims *JWTClaims, config MFAOperationConfig) error {
	// Store step-up requirement
	err := m.SetMFAStepUpRequirement(context.Background(), claims.SessionID, true, config.Operation)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to set MFA step-up requirement",
		})
	}

	// Select appropriate MFA method
	var selectedMethod MFAMethod
	if len(config.AllowedMethods) > 0 {
		selectedMethod = config.AllowedMethods[0] // Use first allowed method
	} else {
		selectedMethod = MFAMethodTOTP // Default fallback
	}

	// Create MFA challenge for step-up
	sessionData := map[string]interface{}{
		"operation":    config.Operation,
		"risk_level":   config.RiskLevel,
		"description":  config.Description,
		"user_id":      claims.UserID,
		"session_id":   claims.SessionID,
		"step_up":      true,
	}

	challenge, err := m.mfaHandler.CreateChallenge(context.Background(), claims.UserID, selectedMethod, sessionData)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to create MFA step-up challenge",
		})
	}

	// Log MFA step-up requirement
	// m.auditLogger.LogSuspiciousActivity would be called here with proper parameters

	// Return MFA step-up challenge response
	return c.Status(http.StatusUpgradeRequired).JSON(fiber.Map{
		"mfa_stepup_required": true,
		"message":           fmt.Sprintf("This %s operation requires additional authentication", strings.ToLower(string(config.RiskLevel))),
		"operation":         config.Operation,
		"operation_desc":    config.Description,
		"risk_level":        config.RiskLevel,
		"challenge_id":      challenge.ChallengeID,
		"method":            challenge.Method,
		"method_display":    m.mfaHandler.GetMFAMethodDisplayName(challenge.Method),
		"instruction":       m.mfaHandler.GetUserFriendlyInstruction(challenge.Method, "initial"),
		"guidance":          m.mfaHandler.GetMFAStepGuidance(challenge.Method),
		"expires_at":        challenge.ExpiresAt.Unix(),
		"mfa_validity":      config.MFAValidity.String(),
		"allowed_methods":   config.AllowedMethods,
		"next_step":         "Complete MFA challenge using /auth/mfa/validate endpoint",
	})
}

// CompleteMFAStepUp completes MFA step-up authentication after successful challenge validation
func (m *MFASessionManager) CompleteMFAStepUp(ctx context.Context, sessionID, operation, method string) error {
	// Get operation config
	config, exists := DefaultMFAOperations[operation]
	if !exists {
		return fmt.Errorf("unknown operation: %s", operation)
	}

	// Update MFA status with operation-specific validity
	err := m.UpdateMFAStatus(ctx, sessionID, "", true, method, config.MFAValidity)
	if err != nil {
		return err
	}

	// Clear step-up requirement for this operation
	return m.SetMFAStepUpRequirement(ctx, sessionID, false, operation)
}

// GetMFAOperationRequirements returns MFA requirements for all operations
func (m *MFASessionManager) GetMFAOperationRequirements() fiber.Handler {
	return func(c fiber.Ctx) error {
		operations := make([]fiber.Map, 0, len(DefaultMFAOperations))
		
		for _, config := range DefaultMFAOperations {
			operations = append(operations, fiber.Map{
				"operation":       config.Operation,
				"description":     config.Description,
				"risk_level":      config.RiskLevel,
				"requires_mfa":    config.RequiresMFA,
				"mfa_validity":    config.MFAValidity.String(),
				"allowed_methods": config.AllowedMethods,
			})
		}

		return c.JSON(fiber.Map{
			"success":    true,
			"operations": operations,
		})
	}
}

// GetSessionMFAStatus returns current MFA status for the user's session
func (m *MFASessionManager) GetSessionMFAStatus() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Get user from context
		userClaims := c.Locals("user").(*JWTClaims)
		if userClaims == nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "User not authenticated",
			})
		}

		// Get MFA status
		mfaStatus, err := m.GetMFAStatus(context.Background(), userClaims.SessionID)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Failed to get MFA status",
			})
		}

		// Check what operations are available based on current MFA status
		availableOperations := []string{}
		unavailableOperations := []fiber.Map{}

		for operation, config := range DefaultMFAOperations {
			if config.RequiresMFA {
				valid, _ := m.ValidateMFAForOperation(context.Background(), userClaims.SessionID, operation)
				if valid {
					availableOperations = append(availableOperations, operation)
				} else {
					unavailableOperations = append(unavailableOperations, fiber.Map{
						"operation":    operation,
						"description":  config.Description,
						"risk_level":   config.RiskLevel,
						"mfa_required": true,
					})
				}
			} else {
				availableOperations = append(availableOperations, operation)
			}
		}

		response := fiber.Map{
			"success":    true,
			"session_id": userClaims.SessionID,
			"mfa_status": fiber.Map{
				"completed":              mfaStatus.MFACompleted,
				"method":                 mfaStatus.MFAMethod,
				"timestamp":              mfaStatus.MFATimestamp.Unix(),
				"expires_at":             mfaStatus.MFAExpiresAt.Unix(),
				"requires_stepup":        mfaStatus.RequiresMFAStepUp,
				"stepup_operations":      mfaStatus.StepUpOperations,
				"last_validation":        mfaStatus.LastMFAValidation.Unix(),
			},
			"available_operations":   availableOperations,
			"unavailable_operations": unavailableOperations,
		}

		return c.JSON(response)
	}
}

// InvalidateSessionMFA invalidates MFA for the current session
func (m *MFASessionManager) InvalidateSessionMFA() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Get user from context
		userClaims := c.Locals("user").(*JWTClaims)
		if userClaims == nil {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{
				"error":   true,
				"message": "User not authenticated",
			})
		}

		// Invalidate MFA status
		err := m.UpdateMFAStatus(context.Background(), userClaims.SessionID, userClaims.UserID, false, "", 0)
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"message": "Failed to invalidate MFA status",
			})
		}

		// Log MFA invalidation
		// Audit log: Manual MFA invalidation
		// m.auditLogger.LogSessionEvent would be called here

		return c.JSON(fiber.Map{
			"success": true,
			"message": "MFA status invalidated. You will need to complete MFA again for protected operations.",
		})
	}
}