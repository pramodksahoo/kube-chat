// Package middleware provides integration between MFA components (Story 2.4 Task 5)
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// MFAIntegrationService provides unified access to all MFA components
type MFAIntegrationService struct {
	handler       *MFAHandler
	policyEngine  *MFAPolicyEngine
	sessionManager *MFASessionManager
	jwtService    JWTServiceInterface
	config        MFAIntegrationConfig
}

// MFAIntegrationConfig holds configuration for MFA integration service
type MFAIntegrationConfig struct {
	DefaultPolicyEngine bool          `json:"default_policy_engine"` // Use default policy engine
	AuditLoggingEnabled bool          `json:"audit_logging_enabled"` // Enable audit logging
	ComplianceMode      bool          `json:"compliance_mode"`       // Enable strict compliance mode
	HealthCheckInterval time.Duration `json:"health_check_interval"` // Health check interval
}

// MFAIntegrationDecision represents a comprehensive MFA decision
type MFAIntegrationDecision struct {
	SessionID           string               `json:"session_id"`
	UserID              string               `json:"user_id"`
	Operation           string               `json:"operation"`
	PolicyDecision      *PolicyDecision      `json:"policy_decision"`
	CurrentMFAStatus    *MFASessionStatus    `json:"current_mfa_status"`
	RequiredAction      MFARequiredAction    `json:"required_action"`
	ChallengeRequired   bool                 `json:"challenge_required"`
	Challenge           *MFAChallenge        `json:"challenge,omitempty"`
	Reason              string               `json:"reason"`
	ComplianceMetadata  map[string]interface{} `json:"compliance_metadata"`
}

// MFARequiredAction defines the required MFA action
type MFARequiredAction string

const (
	MFAActionAllow          MFARequiredAction = "allow"           // Allow access without MFA
	MFAActionRequireInitial MFARequiredAction = "require_initial" // Require initial MFA
	MFAActionRequireStepUp  MFARequiredAction = "require_stepup"  // Require MFA step-up
	MFAActionDeny           MFARequiredAction = "deny"            // Deny access
	MFAActionEmergency      MFARequiredAction = "emergency"       // Allow emergency access
)

// NewMFAIntegrationService creates a new MFA integration service
func NewMFAIntegrationService(
	handler *MFAHandler,
	policyEngine *MFAPolicyEngine, 
	sessionManager *MFASessionManager,
	jwtService JWTServiceInterface,
	config MFAIntegrationConfig,
) *MFAIntegrationService {
	return &MFAIntegrationService{
		handler:       handler,
		policyEngine:  policyEngine,
		sessionManager: sessionManager,
		jwtService:    jwtService,
		config:        config,
	}
}

// EvaluateAccess performs comprehensive MFA evaluation for access requests
func (s *MFAIntegrationService) EvaluateAccess(ctx context.Context, request AccessRequest) (*MFAIntegrationDecision, error) {
	decision := &MFAIntegrationDecision{
		SessionID:          request.SessionID,
		UserID:             request.UserID,
		Operation:          request.Operation,
		RequiredAction:     MFAActionAllow,
		ChallengeRequired:  false,
		ComplianceMetadata: make(map[string]interface{}),
	}

	// 1. Get current session info and MFA status
	sessionInfo, err := s.jwtService.GetSessionInfo(request.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session info: %w", err)
	}

	mfaStatus, err := s.jwtService.GetMFAStatus(request.SessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get MFA status: %w", err)
	}
	decision.CurrentMFAStatus = mfaStatus

	// 2. Evaluate enterprise MFA policies
	policyContext := PolicyEvaluationContext{
		UserID:            request.UserID,
		Email:             sessionInfo.Email,
		UserGroups:        request.UserGroups,
		KubernetesGroups:  sessionInfo.KubernetesGroups,
		Role:              request.Role,
		RequestedOperation: request.Operation,
		TargetNamespace:   request.Namespace,
		IPAddress:         request.IPAddress,
		UserAgent:         request.UserAgent,
		DeviceFingerprint: sessionInfo.DeviceFingerprint,
		SessionContext:    request.SessionContext,
		Timestamp:         time.Now(),
	}

	policyDecision, err := s.policyEngine.EvaluatePolicy(ctx, policyContext)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate MFA policy: %w", err)
	}
	decision.PolicyDecision = policyDecision

	// 3. Make integrated decision based on policy and current state
	if !policyDecision.Allow {
		decision.RequiredAction = MFAActionDeny
		decision.Reason = policyDecision.Reason
		return decision, nil
	}

	// 4. Check if MFA is required by policy
	if policyDecision.RequireMFA {
		// Check current MFA status
		if !mfaStatus.MFACompleted || time.Now().After(mfaStatus.MFAExpiresAt) {
			// MFA required but not completed or expired
			decision.RequiredAction = MFAActionRequireInitial
			decision.ChallengeRequired = true
			decision.Reason = "MFA required by enterprise policy"
		} else {
			// Check for step-up requirements
			if policyDecision.RequireStepUp {
				stepUpRequired := false
				
				// Check policy-based step-up interval
				if time.Since(mfaStatus.MFATimestamp) > policyDecision.StepUpInterval {
					stepUpRequired = true
				}
				
				// Check high-risk operation requirements
				if s.handler.IsHighRiskOperation(request.Operation) {
					stepUpRequired = true
				}
				
				if stepUpRequired {
					decision.RequiredAction = MFAActionRequireStepUp
					decision.ChallengeRequired = true
					decision.Reason = "MFA step-up required for high-risk operation"
				}
			}
		}
	}

	// 5. Create MFA challenge if required
	if decision.ChallengeRequired {
		challenge, err := s.createMFAChallenge(ctx, request, policyDecision)
		if err != nil {
			return nil, fmt.Errorf("failed to create MFA challenge: %w", err)
		}
		decision.Challenge = challenge
	}

	// 6. Handle emergency access
	if policyDecision.EmergencyAccess && request.EmergencyAccess {
		decision.RequiredAction = MFAActionEmergency
		decision.ChallengeRequired = false
		decision.Reason = "Emergency access granted"
		decision.ComplianceMetadata["emergency_access"] = true
		decision.ComplianceMetadata["emergency_justification"] = request.EmergencyJustification
	}

	// 7. Add compliance metadata
	if policyDecision.ComplianceRequired {
		decision.ComplianceMetadata["compliance_required"] = true
		decision.ComplianceMetadata["applied_policies"] = policyDecision.AppliedPolicies
		decision.ComplianceMetadata["risk_factors"] = len(policyDecision.RiskFactorsDetected)
	}

	return decision, nil
}

// createMFAChallenge creates an appropriate MFA challenge based on policy decisions
func (s *MFAIntegrationService) createMFAChallenge(ctx context.Context, request AccessRequest, policy *PolicyDecision) (*MFAChallenge, error) {
	// Choose MFA method based on policy and user preferences
	var method MFAMethod = MFAMethodTOTP // Default
	if len(policy.AllowedMethods) > 0 {
		method = policy.AllowedMethods[0] // Use first allowed method
	}

	// Create session data for challenge
	sessionData := map[string]interface{}{
		"operation":        request.Operation,
		"namespace":        request.Namespace,
		"ip_address":       request.IPAddress,
		"user_agent":       request.UserAgent,
		"policy_decision":  policy,
		"step_up_required": request.StepUp,
	}

	return s.handler.CreateChallenge(ctx, request.UserID, method, sessionData)
}

// ValidateMFAChallenge validates an MFA challenge response and updates session state
func (s *MFAIntegrationService) ValidateMFAChallenge(ctx context.Context, challengeID string, response map[string]interface{}) (*MFAValidationResult, error) {
	// Validate the MFA challenge
	mfaResponse, err := s.handler.ValidateChallenge(ctx, challengeID, response)
	if err != nil {
		return nil, fmt.Errorf("MFA challenge validation failed: %w", err)
	}

	result := &MFAValidationResult{
		Success:     mfaResponse.Success,
		SessionID:   mfaResponse.SessionID,
		UserID:      mfaResponse.UserID,
		Method:      mfaResponse.Method,
		CompletedAt: time.Now(),
	}

	if mfaResponse.Success {
		// Update session MFA status
		validity := 4 * time.Hour // Default validity
		if mfaResponse.ValidityDuration > 0 {
			validity = mfaResponse.ValidityDuration
		}

		err = s.jwtService.UpdateMFAStatus(mfaResponse.SessionID, true, string(mfaResponse.Method), validity)
		if err != nil {
			return nil, fmt.Errorf("failed to update session MFA status: %w", err)
		}

		// Log successful MFA completion for compliance
		if s.config.AuditLoggingEnabled {
			s.logMFAEvent("mfa_completed", mfaResponse.SessionID, mfaResponse.UserID, map[string]interface{}{
				"method":    mfaResponse.Method,
				"challenge_id": challengeID,
				"validity": validity.String(),
			})
		}
	} else {
		// Log failed MFA attempt for compliance
		if s.config.AuditLoggingEnabled {
			s.logMFAEvent("mfa_failed", mfaResponse.SessionID, mfaResponse.UserID, map[string]interface{}{
				"method":    mfaResponse.Method,
				"challenge_id": challengeID,
				"failure_reason": mfaResponse.ErrorMessage,
			})
		}
	}

	return result, nil
}

// GetUserMFAStatus provides comprehensive MFA status for a user
func (s *MFAIntegrationService) GetUserMFAStatus(ctx context.Context, userID string) (*UserMFAStatus, error) {
	// Get all active sessions for the user
	sessions, err := s.jwtService.GetAllActiveSessions(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user sessions: %w", err)
	}

	status := &UserMFAStatus{
		UserID:               userID,
		ActiveSessions:       len(sessions),
		MFAEnabledSessions:   0,
		LastMFACompletion:    time.Time{},
		ApplicablePolicies:   []string{},
		ComplianceStatus:     "compliant",
		EmergencyAccessUsed:  false,
	}

	// Check MFA status for each session
	for _, session := range sessions {
		if session.MFACompleted && !time.Now().After(session.MFAExpiresAt) {
			status.MFAEnabledSessions++
			if session.MFATimestamp.After(status.LastMFACompletion) {
				status.LastMFACompletion = session.MFATimestamp
			}
		}
	}

	// Calculate compliance status
	if len(sessions) > 0 {
		complianceRate := float64(status.MFAEnabledSessions) / float64(status.ActiveSessions)
		if complianceRate < 0.8 {
			status.ComplianceStatus = "non_compliant"
		} else if complianceRate < 1.0 {
			status.ComplianceStatus = "partially_compliant"
		}
	}

	return status, nil
}

// RefreshPolicies reloads MFA policies from storage
func (s *MFAIntegrationService) RefreshPolicies(ctx context.Context) error {
	return s.policyEngine.loadPoliciesFromStorage()
}

// GenerateComplianceReport generates a comprehensive compliance report
func (s *MFAIntegrationService) GenerateComplianceReport(ctx context.Context, startTime, endTime time.Time) (*MFAComplianceReport, error) {
	return s.policyEngine.GenerateComplianceReport(startTime, endTime)
}

// InvalidateUserMFA invalidates MFA for all sessions of a user
func (s *MFAIntegrationService) InvalidateUserMFA(ctx context.Context, userID string, reason string) error {
	// Log MFA invalidation for audit
	if s.config.AuditLoggingEnabled {
		s.logMFAEvent("mfa_invalidated", "", userID, map[string]interface{}{
			"reason": reason,
		})
	}

	return s.jwtService.InvalidateMFAForSessions(userID)
}

// Helper methods and supporting types

// AccessRequest represents a request for access evaluation
type AccessRequest struct {
	SessionID            string                 `json:"session_id"`
	UserID               string                 `json:"user_id"`
	Operation            string                 `json:"operation"`
	Namespace            string                 `json:"namespace,omitempty"`
	UserGroups           []string               `json:"user_groups"`
	Role                 string                 `json:"role"`
	IPAddress            string                 `json:"ip_address"`
	UserAgent            string                 `json:"user_agent"`
	SessionContext       map[string]interface{} `json:"session_context"`
	StepUp               bool                   `json:"step_up"`
	EmergencyAccess      bool                   `json:"emergency_access"`
	EmergencyJustification string               `json:"emergency_justification,omitempty"`
}

// MFAValidationResult represents the result of MFA challenge validation
type MFAValidationResult struct {
	Success     bool         `json:"success"`
	SessionID   string       `json:"session_id"`
	UserID      string       `json:"user_id"`
	Method      MFAMethod    `json:"method"`
	CompletedAt time.Time    `json:"completed_at"`
	ErrorCode   string       `json:"error_code,omitempty"`
	ErrorMessage string      `json:"error_message,omitempty"`
}

// UserMFAStatus represents comprehensive MFA status for a user
type UserMFAStatus struct {
	UserID               string    `json:"user_id"`
	ActiveSessions       int       `json:"active_sessions"`
	MFAEnabledSessions   int       `json:"mfa_enabled_sessions"`
	LastMFACompletion    time.Time `json:"last_mfa_completion"`
	ApplicablePolicies   []string  `json:"applicable_policies"`
	ComplianceStatus     string    `json:"compliance_status"` // "compliant", "non_compliant", "partially_compliant"
	EmergencyAccessUsed  bool      `json:"emergency_access_used"`
}

// logMFAEvent logs MFA events for audit and compliance
func (s *MFAIntegrationService) logMFAEvent(eventType, sessionID, userID string, metadata map[string]interface{}) {
	if s.handler == nil || s.handler.redisClient == nil {
		return
	}

	event := map[string]interface{}{
		"event_type":  eventType,
		"session_id":  sessionID,
		"user_id":     userID,
		"timestamp":   time.Now().Unix(),
		"metadata":    metadata,
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return
	}

	ctx := context.Background()
	eventKey := fmt.Sprintf("kubechat:mfa:audit:%s:%d", eventType, time.Now().Unix())
	s.handler.redisClient.Set(ctx, eventKey, eventJSON, 90*24*time.Hour) // 90-day retention
}

// Health check method
func (s *MFAIntegrationService) HealthCheck(ctx context.Context) map[string]interface{} {
	status := map[string]interface{}{
		"service": "healthy",
		"components": map[string]interface{}{},
	}

	// Check MFA handler
	if s.handler != nil {
		status["components"].(map[string]interface{})["mfa_handler"] = "healthy"
	} else {
		status["components"].(map[string]interface{})["mfa_handler"] = "unavailable"
		status["service"] = "degraded"
	}

	// Check policy engine
	if s.policyEngine != nil {
		status["components"].(map[string]interface{})["policy_engine"] = "healthy"
	} else {
		status["components"].(map[string]interface{})["policy_engine"] = "unavailable"
		status["service"] = "degraded"
	}

	// Check JWT service
	if s.jwtService != nil {
		status["components"].(map[string]interface{})["jwt_service"] = "healthy"
	} else {
		status["components"].(map[string]interface{})["jwt_service"] = "unavailable"
		status["service"] = "critical"
	}

	return status
}