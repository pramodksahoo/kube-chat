// Package middleware provides MFA policy management for enterprise MFA integration
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
)

// MFAPolicyEngine manages enterprise MFA policies and enforcement (Story 2.4 Task 5)
type MFAPolicyEngine struct {
	redisClient redis.UniversalClient
	policies    map[string]*MFAPolicy
	config      MFAPolicyEngineConfig
}

// MFAPolicyEngineConfig holds configuration for MFA policy engine
type MFAPolicyEngineConfig struct {
	DefaultPolicy            string                          `json:"default_policy"`        // Default policy name
	PolicyRefreshInterval    time.Duration                   `json:"policy_refresh_interval"` // How often to refresh policies
	EmergencyAccessEnabled   bool                           `json:"emergency_access_enabled"` // Enable emergency access
	ComplianceLoggingEnabled bool                           `json:"compliance_logging_enabled"` // Enable compliance logging
	PolicyCacheTimeout       time.Duration                   `json:"policy_cache_timeout"`   // Policy cache timeout
	
	// Legacy fields for backward compatibility with MFAConfig
	EnforceForAllUsers      bool                            `json:"enforce_for_all_users"`
	UserGroupRequirements   map[string][]MFAMethod          `json:"user_group_requirements"`
	RiskBasedMFA           RiskBasedMFAConfig              `json:"risk_based_mfa"`
	EmergencyAccess        EmergencyAccessConfig           `json:"emergency_access"`
}

// Note: RiskBasedMFAConfig and EmergencyAccessConfig are defined in mfa_handler.go

// MFAPolicy defines MFA requirements for different user groups and scenarios
type MFAPolicy struct {
	Name                string                   `json:"name"`
	Description         string                   `json:"description"`
	Enabled             bool                     `json:"enabled"`
	Priority            int                      `json:"priority"` // Higher priority overrides lower
	
	// Target criteria
	UserGroups          []string                 `json:"user_groups"`          // OIDC/SAML groups
	KubernetesGroups    []string                 `json:"kubernetes_groups"`    // K8s RBAC groups  
	Roles               []string                 `json:"roles"`                // KubeChat roles
	Namespaces          []string                 `json:"namespaces"`           // Namespace restrictions
	
	// MFA requirements
	RequireMFA          bool                     `json:"require_mfa"`
	AllowedMethods      []MFAMethod              `json:"allowed_methods"`      // TOTP, SMS, Push, Hardware
	MFAValidityDuration time.Duration            `json:"mfa_validity_duration"`
	StepUpOperations    []string                 `json:"stepup_operations"`    // Operations requiring fresh MFA
	StepUpInterval      time.Duration            `json:"stepup_interval"`      // How fresh MFA must be for step-up
	
	// Risk-based conditions
	RiskFactors         []RiskFactor             `json:"risk_factors"`
	ConditionalMFA      bool                     `json:"conditional_mfa"`      // Enable risk-based MFA
	
	// Emergency access
	AllowEmergencyAccess bool                    `json:"allow_emergency_access"`
	EmergencyMethods    []MFAMethod              `json:"emergency_methods"`
	
	// Compliance and audit
	LogAllAccess        bool                     `json:"log_all_access"`       // Log all access attempts
	ComplianceRequired  bool                     `json:"compliance_required"`  // Mark as compliance-critical
	
	// Temporal restrictions
	ActiveHours         *TimeWindow              `json:"active_hours,omitempty"`
	ExpirationDate      *time.Time               `json:"expiration_date,omitempty"`
	
	CreatedAt           time.Time                `json:"created_at"`
	UpdatedAt           time.Time                `json:"updated_at"`
	CreatedBy           string                   `json:"created_by"`
}

// RiskFactor defines conditions that increase authentication risk
type RiskFactor struct {
	Type        RiskFactorType `json:"type"`
	Threshold   string         `json:"threshold"`
	Action      RiskAction     `json:"action"`
	Description string         `json:"description"`
}

// RiskFactorType defines types of risk factors
type RiskFactorType string

const (
	RiskFactorUnknownIP      RiskFactorType = "unknown_ip"
	RiskFactorUnknownDevice  RiskFactorType = "unknown_device"
	RiskFactorOffHours       RiskFactorType = "off_hours"
	RiskFactorHighPrivilege  RiskFactorType = "high_privilege"
	RiskFactorSuspiciousLocation RiskFactorType = "suspicious_location"
	RiskFactorConcurrentSessions RiskFactorType = "concurrent_sessions"
)

// RiskAction defines actions to take when risk factors are detected
type RiskAction string

const (
	RiskActionRequireMFA    RiskAction = "require_mfa"
	RiskActionStepUpMFA     RiskAction = "stepup_mfa"
	RiskActionDenyAccess    RiskAction = "deny_access"
	RiskActionLogOnly       RiskAction = "log_only"
)

// TimeWindow defines time-based restrictions
type TimeWindow struct {
	StartHour   int      `json:"start_hour"`   // 0-23
	EndHour     int      `json:"end_hour"`     // 0-23
	DaysOfWeek  []string `json:"days_of_week"` // "monday", "tuesday", etc.
	TimeZone    string   `json:"timezone"`     // IANA timezone
}

// PolicyEvaluationContext contains context for policy evaluation
type PolicyEvaluationContext struct {
	UserID            string            `json:"user_id"`
	Email             string            `json:"email"`
	UserGroups        []string          `json:"user_groups"`        // OIDC/SAML groups
	KubernetesGroups  []string          `json:"kubernetes_groups"`  // K8s RBAC groups
	Role              string            `json:"role"`               // KubeChat role
	RequestedOperation string           `json:"requested_operation"`
	TargetNamespace   string            `json:"target_namespace"`
	IPAddress         string            `json:"ip_address"`
	UserAgent         string            `json:"user_agent"`
	DeviceFingerprint string            `json:"device_fingerprint"`
	SessionContext    map[string]interface{} `json:"session_context"`
	Timestamp         time.Time         `json:"timestamp"`
}

// PolicyDecision represents the result of policy evaluation
type PolicyDecision struct {
	Allow               bool               `json:"allow"`
	RequireMFA          bool               `json:"require_mfa"`
	AllowedMethods      []MFAMethod        `json:"allowed_methods"`
	MFAValidityDuration time.Duration      `json:"mfa_validity_duration"`
	RequireStepUp       bool               `json:"require_stepup"`
	StepUpInterval      time.Duration      `json:"stepup_interval"`
	AppliedPolicies     []string           `json:"applied_policies"`
	RiskFactorsDetected []RiskFactor       `json:"risk_factors_detected"`
	EmergencyAccess     bool               `json:"emergency_access"`
	Reason              string             `json:"reason"`
	ComplianceRequired  bool               `json:"compliance_required"`
}

// MFAComplianceReport represents MFA compliance reporting data
type MFAComplianceReport struct {
	ReportID              string                    `json:"report_id"`
	GeneratedAt           time.Time                 `json:"generated_at"`
	PeriodStart           time.Time                 `json:"period_start"`
	PeriodEnd             time.Time                 `json:"period_end"`
	
	// Overall statistics
	TotalAccessAttempts   int64                     `json:"total_access_attempts"`
	MFARequiredAttempts   int64                     `json:"mfa_required_attempts"`
	MFACompletedAttempts  int64                     `json:"mfa_completed_attempts"`
	MFAFailedAttempts     int64                     `json:"mfa_failed_attempts"`
	EmergencyAccessCount  int64                     `json:"emergency_access_count"`
	
	// Compliance rates
	MFAComplianceRate     float64                   `json:"mfa_compliance_rate"`
	PolicyComplianceRate  float64                   `json:"policy_compliance_rate"`
	
	// Breakdown by policy
	PolicyStats           map[string]*PolicyStats   `json:"policy_stats"`
	
	// Risk analysis
	RiskFactorStats       map[RiskFactorType]int64  `json:"risk_factor_stats"`
	HighRiskOperations    []OperationStat           `json:"high_risk_operations"`
	
	// User analysis
	TopNonCompliantUsers  []UserComplianceStats     `json:"top_non_compliant_users"`
	MFAMethodUsage        map[MFAMethod]int64       `json:"mfa_method_usage"`
}

// PolicyStats holds statistics for a specific policy
type PolicyStats struct {
	PolicyName            string    `json:"policy_name"`
	TotalEvaluations      int64     `json:"total_evaluations"`
	AllowedCount          int64     `json:"allowed_count"`
	DeniedCount           int64     `json:"denied_count"`
	MFARequiredCount      int64     `json:"mfa_required_count"`
	ComplianceRate        float64   `json:"compliance_rate"`
}

// OperationStat holds statistics for high-risk operations
type OperationStat struct {
	Operation             string    `json:"operation"`
	Count                 int64     `json:"count"`
	MFARequiredCount      int64     `json:"mfa_required_count"`
	FailureCount          int64     `json:"failure_count"`
}

// UserComplianceStats holds compliance statistics for a user
type UserComplianceStats struct {
	UserID                string    `json:"user_id"`
	Email                 string    `json:"email"`
	TotalAttempts         int64     `json:"total_attempts"`
	MFARequiredAttempts   int64     `json:"mfa_required_attempts"`
	MFAFailedAttempts     int64     `json:"mfa_failed_attempts"`
	ComplianceRate        float64   `json:"compliance_rate"`
	LastViolation         time.Time `json:"last_violation"`
}

// NewMFAPolicyEngine creates a new MFA policy engine
func NewMFAPolicyEngine(redisClient redis.UniversalClient, config MFAPolicyEngineConfig) *MFAPolicyEngine {
	// Set defaults if not provided
	if config.DefaultPolicy == "" {
		config.DefaultPolicy = "default"
	}
	if config.PolicyRefreshInterval == 0 {
		config.PolicyRefreshInterval = 5 * time.Minute
	}
	if config.PolicyCacheTimeout == 0 {
		config.PolicyCacheTimeout = 1 * time.Hour
	}
	
	engine := &MFAPolicyEngine{
		redisClient: redisClient,
		policies:    make(map[string]*MFAPolicy),
		config:      config,
	}
	
	// Load initial policies
	engine.loadPoliciesFromStorage()
	
	// Create default policy if it doesn't exist
	if _, exists := engine.policies[config.DefaultPolicy]; !exists {
		engine.createDefaultPolicy()
	}
	
	return engine
}

// EvaluatePolicy evaluates MFA policies for a given context
func (e *MFAPolicyEngine) EvaluatePolicy(ctx context.Context, evalCtx PolicyEvaluationContext) (*PolicyDecision, error) {
	decision := &PolicyDecision{
		Allow:               true,
		RequireMFA:          false,
		AllowedMethods:      []MFAMethod{MFAMethodTOTP}, // Default to TOTP
		MFAValidityDuration: 4 * time.Hour, // Default validity
		RequireStepUp:       false,
		StepUpInterval:      15 * time.Minute, // Default step-up interval
		AppliedPolicies:     []string{},
		RiskFactorsDetected: []RiskFactor{},
		EmergencyAccess:     false,
		ComplianceRequired:  false,
	}
	
	// Find applicable policies
	applicablePolicies := e.findApplicablePolicies(evalCtx)
	if len(applicablePolicies) == 0 {
		// No applicable policies found, apply default policy
		if defaultPolicy, exists := e.policies[e.config.DefaultPolicy]; exists {
			applicablePolicies = []*MFAPolicy{defaultPolicy}
		}
	}
	
	// Evaluate policies in priority order
	for _, policy := range applicablePolicies {
		if !policy.Enabled {
			continue
		}
		
		decision.AppliedPolicies = append(decision.AppliedPolicies, policy.Name)
		
		// Apply policy requirements
		if policy.RequireMFA {
			decision.RequireMFA = true
			if len(policy.AllowedMethods) > 0 {
				decision.AllowedMethods = policy.AllowedMethods
			}
			if policy.MFAValidityDuration > 0 {
				decision.MFAValidityDuration = policy.MFAValidityDuration
			}
		}
		
		// Check for step-up requirements
		for _, stepUpOp := range policy.StepUpOperations {
			if strings.Contains(evalCtx.RequestedOperation, stepUpOp) || stepUpOp == "*" {
				decision.RequireStepUp = true
				if policy.StepUpInterval > 0 {
					decision.StepUpInterval = policy.StepUpInterval
				}
				break
			}
		}
		
		// Evaluate risk factors
		if policy.ConditionalMFA {
			riskFactors := e.evaluateRiskFactors(policy.RiskFactors, evalCtx)
			decision.RiskFactorsDetected = append(decision.RiskFactorsDetected, riskFactors...)
			
			for _, riskFactor := range riskFactors {
				switch riskFactor.Action {
				case RiskActionRequireMFA:
					decision.RequireMFA = true
				case RiskActionStepUpMFA:
					decision.RequireStepUp = true
				case RiskActionDenyAccess:
					decision.Allow = false
					decision.Reason = fmt.Sprintf("Access denied due to risk factor: %s", riskFactor.Type)
				}
			}
		}
		
		// Check emergency access
		if policy.AllowEmergencyAccess && len(policy.EmergencyMethods) > 0 {
			decision.EmergencyAccess = true
		}
		
		// Set compliance requirement
		if policy.ComplianceRequired {
			decision.ComplianceRequired = true
		}
		
		// Check temporal restrictions
		if !e.isWithinTimeWindow(policy.ActiveHours, evalCtx.Timestamp) {
			decision.Allow = false
			decision.Reason = "Access outside of allowed time window"
		}
		
		// Check policy expiration
		if policy.ExpirationDate != nil && evalCtx.Timestamp.After(*policy.ExpirationDate) {
			continue // Skip expired policy
		}
	}
	
	// Log compliance event if required
	if e.config.ComplianceLoggingEnabled {
		e.logComplianceEvent(evalCtx, decision)
	}
	
	return decision, nil
}

// findApplicablePolicies finds policies that apply to the evaluation context
func (e *MFAPolicyEngine) findApplicablePolicies(evalCtx PolicyEvaluationContext) []*MFAPolicy {
	var applicable []*MFAPolicy
	
	for _, policy := range e.policies {
		if e.policyMatches(policy, evalCtx) {
			applicable = append(applicable, policy)
		}
	}
	
	// Sort by priority (higher priority first)
	for i := 0; i < len(applicable)-1; i++ {
		for j := i + 1; j < len(applicable); j++ {
			if applicable[i].Priority < applicable[j].Priority {
				applicable[i], applicable[j] = applicable[j], applicable[i]
			}
		}
	}
	
	return applicable
}

// policyMatches checks if a policy matches the evaluation context
func (e *MFAPolicyEngine) policyMatches(policy *MFAPolicy, evalCtx PolicyEvaluationContext) bool {
	// Check user groups
	if len(policy.UserGroups) > 0 {
		if !e.hasAnyGroup(evalCtx.UserGroups, policy.UserGroups) {
			return false
		}
	}
	
	// Check Kubernetes groups  
	if len(policy.KubernetesGroups) > 0 {
		if !e.hasAnyGroup(evalCtx.KubernetesGroups, policy.KubernetesGroups) {
			return false
		}
	}
	
	// Check roles
	if len(policy.Roles) > 0 {
		found := false
		for _, role := range policy.Roles {
			if role == evalCtx.Role {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check namespaces
	if len(policy.Namespaces) > 0 && evalCtx.TargetNamespace != "" {
		found := false
		for _, ns := range policy.Namespaces {
			if ns == evalCtx.TargetNamespace || ns == "*" {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	return true
}

// hasAnyGroup checks if any of the user's groups match the policy groups
func (e *MFAPolicyEngine) hasAnyGroup(userGroups, policyGroups []string) bool {
	for _, userGroup := range userGroups {
		for _, policyGroup := range policyGroups {
			if userGroup == policyGroup {
				return true
			}
		}
	}
	return false
}

// evaluateRiskFactors evaluates risk factors and returns detected risks
func (e *MFAPolicyEngine) evaluateRiskFactors(riskFactors []RiskFactor, evalCtx PolicyEvaluationContext) []RiskFactor {
	var detected []RiskFactor
	
	for _, factor := range riskFactors {
		switch factor.Type {
		case RiskFactorUnknownIP:
			if e.isUnknownIP(evalCtx.IPAddress, evalCtx.UserID) {
				detected = append(detected, factor)
			}
		case RiskFactorUnknownDevice:
			if e.isUnknownDevice(evalCtx.DeviceFingerprint, evalCtx.UserID) {
				detected = append(detected, factor)
			}
		case RiskFactorOffHours:
			if e.isOffHours(evalCtx.Timestamp) {
				detected = append(detected, factor)
			}
		case RiskFactorHighPrivilege:
			if e.isHighPrivilege(evalCtx.Role, evalCtx.KubernetesGroups) {
				detected = append(detected, factor)
			}
		}
	}
	
	return detected
}

// isWithinTimeWindow checks if the timestamp is within the allowed time window
func (e *MFAPolicyEngine) isWithinTimeWindow(window *TimeWindow, timestamp time.Time) bool {
	if window == nil {
		return true // No time restrictions
	}
	
	// Parse timezone
	loc, err := time.LoadLocation(window.TimeZone)
	if err != nil {
		loc = time.UTC // Fallback to UTC
	}
	
	localTime := timestamp.In(loc)
	
	// Check day of week
	dayOfWeek := strings.ToLower(localTime.Weekday().String())
	dayAllowed := false
	for _, allowedDay := range window.DaysOfWeek {
		if strings.ToLower(allowedDay) == dayOfWeek {
			dayAllowed = true
			break
		}
	}
	if !dayAllowed {
		return false
	}
	
	// Check hour range
	hour := localTime.Hour()
	if window.StartHour <= window.EndHour {
		// Same day range
		return hour >= window.StartHour && hour <= window.EndHour
	} else {
		// Cross midnight range
		return hour >= window.StartHour || hour <= window.EndHour
	}
}

// Risk factor evaluation helpers (simplified implementations)
func (e *MFAPolicyEngine) isUnknownIP(ip, userID string) bool {
	// In a real implementation, this would check against known IPs for the user
	return false // Simplified for demo
}

func (e *MFAPolicyEngine) isUnknownDevice(deviceFingerprint, userID string) bool {
	// In a real implementation, this would check against known devices for the user
	return false // Simplified for demo
}

func (e *MFAPolicyEngine) isOffHours(timestamp time.Time) bool {
	// Simple off-hours check (outside 9 AM - 5 PM)
	hour := timestamp.Hour()
	return hour < 9 || hour > 17
}

func (e *MFAPolicyEngine) isHighPrivilege(role string, groups []string) bool {
	// Check for high privilege roles/groups
	highPrivilegeRoles := []string{"admin", "cluster-admin", "system:admin"}
	for _, privRole := range highPrivilegeRoles {
		if role == privRole {
			return true
		}
	}
	
	highPrivilegeGroups := []string{"system:masters", "system:cluster-admins"}
	for _, group := range groups {
		for _, privGroup := range highPrivilegeGroups {
			if group == privGroup {
				return true
			}
		}
	}
	
	return false
}

// Policy management methods

// CreatePolicy creates a new MFA policy
func (e *MFAPolicyEngine) CreatePolicy(policy *MFAPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	
	e.policies[policy.Name] = policy
	
	return e.savePolicyToStorage(policy)
}

// UpdatePolicy updates an existing MFA policy
func (e *MFAPolicyEngine) UpdatePolicy(policy *MFAPolicy) error {
	if policy.Name == "" {
		return fmt.Errorf("policy name cannot be empty")
	}
	
	existing, exists := e.policies[policy.Name]
	if !exists {
		return fmt.Errorf("policy not found: %s", policy.Name)
	}
	
	policy.CreatedAt = existing.CreatedAt // Preserve creation time
	policy.UpdatedAt = time.Now()
	
	e.policies[policy.Name] = policy
	
	return e.savePolicyToStorage(policy)
}

// DeletePolicy deletes an MFA policy
func (e *MFAPolicyEngine) DeletePolicy(policyName string) error {
	if policyName == e.config.DefaultPolicy {
		return fmt.Errorf("cannot delete default policy: %s", policyName)
	}
	
	delete(e.policies, policyName)
	
	if e.redisClient != nil {
		ctx := context.Background()
		return e.redisClient.Del(ctx, e.policyKey(policyName)).Err()
	}
	
	return nil
}

// GetPolicy retrieves a specific MFA policy
func (e *MFAPolicyEngine) GetPolicy(policyName string) (*MFAPolicy, error) {
	policy, exists := e.policies[policyName]
	if !exists {
		return nil, fmt.Errorf("policy not found: %s", policyName)
	}
	
	return policy, nil
}

// ListPolicies returns all MFA policies
func (e *MFAPolicyEngine) ListPolicies() map[string]*MFAPolicy {
	// Return a copy to prevent external modification
	policies := make(map[string]*MFAPolicy)
	for name, policy := range e.policies {
		policies[name] = policy
	}
	return policies
}

// Storage and persistence methods

func (e *MFAPolicyEngine) loadPoliciesFromStorage() error {
	if e.redisClient == nil {
		return nil // No storage available
	}
	
	ctx := context.Background()
	keys, err := e.redisClient.Keys(ctx, "kubechat:mfa:policy:*").Result()
	if err != nil {
		return fmt.Errorf("failed to load policy keys: %w", err)
	}
	
	for _, key := range keys {
		policyData, err := e.redisClient.Get(ctx, key).Result()
		if err != nil {
			continue // Skip policies we can't read
		}
		
		var policy MFAPolicy
		if err := json.Unmarshal([]byte(policyData), &policy); err != nil {
			continue // Skip policies we can't parse
		}
		
		e.policies[policy.Name] = &policy
	}
	
	return nil
}

func (e *MFAPolicyEngine) savePolicyToStorage(policy *MFAPolicy) error {
	if e.redisClient == nil {
		return nil // No storage available
	}
	
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return fmt.Errorf("failed to marshal policy: %w", err)
	}
	
	ctx := context.Background()
	return e.redisClient.Set(ctx, e.policyKey(policy.Name), policyJSON, e.config.PolicyCacheTimeout).Err()
}

func (e *MFAPolicyEngine) policyKey(policyName string) string {
	return fmt.Sprintf("kubechat:mfa:policy:%s", policyName)
}

// Compliance and reporting methods

func (e *MFAPolicyEngine) logComplianceEvent(evalCtx PolicyEvaluationContext, decision *PolicyDecision) {
	if e.redisClient == nil {
		return
	}
	
	event := map[string]interface{}{
		"timestamp":           evalCtx.Timestamp.Unix(),
		"user_id":             evalCtx.UserID,
		"email":               evalCtx.Email,
		"operation":           evalCtx.RequestedOperation,
		"namespace":           evalCtx.TargetNamespace,
		"ip_address":          evalCtx.IPAddress,
		"decision_allow":      decision.Allow,
		"require_mfa":         decision.RequireMFA,
		"require_stepup":      decision.RequireStepUp,
		"applied_policies":    decision.AppliedPolicies,
		"risk_factors":        len(decision.RiskFactorsDetected),
		"emergency_access":    decision.EmergencyAccess,
		"compliance_required": decision.ComplianceRequired,
	}
	
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return
	}
	
	ctx := context.Background()
	// Store compliance event with 90-day retention for audit
	eventKey := fmt.Sprintf("kubechat:mfa:compliance:event:%d:%s", evalCtx.Timestamp.Unix(), evalCtx.UserID)
	e.redisClient.Set(ctx, eventKey, eventJSON, 90*24*time.Hour)
}

// GenerateComplianceReport generates an MFA compliance report for the specified period
func (e *MFAPolicyEngine) GenerateComplianceReport(startTime, endTime time.Time) (*MFAComplianceReport, error) {
	if e.redisClient == nil {
		return nil, fmt.Errorf("redis client not available for compliance reporting")
	}
	
	report := &MFAComplianceReport{
		ReportID:      fmt.Sprintf("mfa-compliance-%d", time.Now().Unix()),
		GeneratedAt:   time.Now(),
		PeriodStart:   startTime,
		PeriodEnd:     endTime,
		PolicyStats:   make(map[string]*PolicyStats),
		RiskFactorStats: make(map[RiskFactorType]int64),
		MFAMethodUsage:  make(map[MFAMethod]int64),
	}
	
	// This would typically query stored compliance events
	// For now, return a basic report structure
	return report, nil
}

// createDefaultPolicy creates a default MFA policy if one doesn't exist
func (e *MFAPolicyEngine) createDefaultPolicy() {
	defaultPolicy := &MFAPolicy{
		Name:                "default",
		Description:         "Default MFA policy for all users",
		Enabled:             true,
		Priority:            1,
		UserGroups:          []string{}, // Applies to all users
		RequireMFA:          false,      // Default: no MFA required
		AllowedMethods:      []MFAMethod{MFAMethodTOTP, MFAMethodSMS, MFAMethodPush},
		MFAValidityDuration: 4 * time.Hour,
		StepUpOperations:    []string{"delete-namespace", "modify-rbac", "access-secrets"},
		StepUpInterval:      15 * time.Minute,
		ConditionalMFA:      false,
		AllowEmergencyAccess: true,
		EmergencyMethods:    []MFAMethod{MFAMethodTOTP},
		LogAllAccess:        true,
		ComplianceRequired:  false,
		CreatedAt:           time.Now(),
		UpdatedAt:           time.Now(),
		CreatedBy:           "system",
	}
	
	e.policies[defaultPolicy.Name] = defaultPolicy
	e.savePolicyToStorage(defaultPolicy)
}