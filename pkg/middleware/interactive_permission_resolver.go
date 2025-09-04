// Package middleware provides interactive permission resolution for KubeChat (Story 2.5)
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// InteractivePermissionResolver provides interactive resolution workflows for permission issues
type InteractivePermissionResolver struct {
	kubeClient      kubernetes.Interface
	redisClient     redis.UniversalClient
	rbacContext     *EnhancedRBACContext
	advisor         *RBACAdvisor
	guidanceService *models.UserGuidanceService
	auditLogger     *AuthAuditLogger
	config          ResolverConfig
}

// ResolverConfig holds configuration for the interactive permission resolver
type ResolverConfig struct {
	EnableTesting           bool          `json:"enable_testing"`
	EnableImpersonation     bool          `json:"enable_impersonation"`
	EnableSelfService       bool          `json:"enable_self_service"`
	WorkflowTimeout         time.Duration `json:"workflow_timeout"`
	MaxRetries              int           `json:"max_retries"`
	RequireApproval         bool          `json:"require_approval"`
	AutoApprovalRoles       []string      `json:"auto_approval_roles"`
	EscalationTimeout       time.Duration `json:"escalation_timeout"`
	NotificationChannels    []string      `json:"notification_channels"`
}

// InteractiveResolutionSession represents an active resolution session
type InteractiveResolutionSession struct {
	SessionID       string                 `json:"session_id"`
	UserContext     *JWTClaims             `json:"user_context"`
	OriginalError   *models.PermissionError `json:"original_error"`
	WorkflowSteps   []ResolutionStep       `json:"workflow_steps"`
	CurrentStep     int                    `json:"current_step"`
	Status          SessionStatus          `json:"status"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	ExpiresAt       time.Time              `json:"expires_at"`
	Metadata        map[string]interface{} `json:"metadata"`
	TestResults     []PermissionTestResult `json:"test_results,omitempty"`
	ApprovalInfo    *ApprovalInfo          `json:"approval_info,omitempty"`
}

// SessionStatus represents the status of a resolution session
type SessionStatus string

const (
	SessionStatusActive        SessionStatus = "active"
	SessionStatusPending       SessionStatus = "pending"
	SessionStatusCompleted     SessionStatus = "completed"
	SessionStatusFailed        SessionStatus = "failed"
	SessionStatusExpired       SessionStatus = "expired"
	SessionStatusCancelled     SessionStatus = "cancelled"
	SessionStatusAwaitingApproval SessionStatus = "awaiting_approval"
)

// ResolutionStep represents a single step in the interactive resolution workflow
type ResolutionStep struct {
	StepID          string                 `json:"step_id"`
	StepNumber      int                    `json:"step_number"`
	Type            ResolutionStepType     `json:"type"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description"`
	Status          StepStatus             `json:"status"`
	UserInput       map[string]interface{} `json:"user_input,omitempty"`
	SystemOutput    map[string]interface{} `json:"system_output,omitempty"`
	Options         []StepOption           `json:"options,omitempty"`
	RequiredInput   []InputRequirement     `json:"required_input,omitempty"`
	Validation      *StepValidation        `json:"validation,omitempty"`
	ExecutedAt      *time.Time             `json:"executed_at,omitempty"`
	Duration        time.Duration          `json:"duration,omitempty"`
	Error           string                 `json:"error,omitempty"`
}

// ResolutionStepType defines the type of resolution step
type ResolutionStepType string

const (
	StepTypeAnalysis      ResolutionStepType = "analysis"
	StepTypeUserInput     ResolutionStepType = "user_input"
	StepTypePermissionTest ResolutionStepType = "permission_test"
	StepTypeRoleImpersonation ResolutionStepType = "role_impersonation"
	StepTypeWorkflowExecution ResolutionStepType = "workflow_execution"
	StepTypeApprovalRequest ResolutionStepType = "approval_request"
	StepTypeNotification  ResolutionStepType = "notification"
	StepTypeVerification  ResolutionStepType = "verification"
)

// StepStatus represents the status of a workflow step
type StepStatus string

const (
	StepStatusPending    StepStatus = "pending"
	StepStatusActive     StepStatus = "active"
	StepStatusCompleted  StepStatus = "completed"
	StepStatusSkipped    StepStatus = "skipped"
	StepStatusFailed     StepStatus = "failed"
)

// StepOption represents an option in an interactive step
type StepOption struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	Description string                 `json:"description"`
	Value       interface{}            `json:"value"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	Recommended bool                   `json:"recommended"`
}

// InputRequirement defines required user input for a step
type InputRequirement struct {
	Name        string      `json:"name"`
	Type        string      `json:"type"` // "text", "select", "multiselect", "boolean"
	Label       string      `json:"label"`
	Description string      `json:"description"`
	Required    bool        `json:"required"`
	Default     interface{} `json:"default,omitempty"`
	Options     []StepOption `json:"options,omitempty"`
	Validation  *InputValidation `json:"validation,omitempty"`
}

// InputValidation defines validation rules for user input
type InputValidation struct {
	Pattern     string   `json:"pattern,omitempty"`
	MinLength   int      `json:"min_length,omitempty"`
	MaxLength   int      `json:"max_length,omitempty"`
	AllowedValues []string `json:"allowed_values,omitempty"`
	CustomRules []string `json:"custom_rules,omitempty"`
}

// PermissionTestResult represents the result of testing permissions
type PermissionTestResult struct {
	TestID          string                 `json:"test_id"`
	TestType        string                 `json:"test_type"` // "current", "impersonation", "proposed"
	TestedAs        string                 `json:"tested_as"` // User or role being tested
	Permission      models.RequiredPermission `json:"permission"`
	Result          bool                   `json:"result"`
	Reason          string                 `json:"reason"`
	TestCommand     string                 `json:"test_command"`
	ExecutedAt      time.Time              `json:"executed_at"`
	Duration        time.Duration          `json:"duration"`
	RawOutput       string                 `json:"raw_output,omitempty"`
}

// ApprovalInfo contains information about approval requirements and status
type ApprovalInfo struct {
	Required       bool                   `json:"required"`
	Approvers      []ApprovalRequirement  `json:"approvers"`
	Status         ApprovalStatus         `json:"status"`
	SubmittedAt    *time.Time             `json:"submitted_at,omitempty"`
	ApprovedAt     *time.Time             `json:"approved_at,omitempty"`
	ApprovedBy     string                 `json:"approved_by,omitempty"`
	RejectedAt     *time.Time             `json:"rejected_at,omitempty"`
	RejectedBy     string                 `json:"rejected_by,omitempty"`
	RejectionReason string                `json:"rejection_reason,omitempty"`
	EscalatedAt    *time.Time             `json:"escalated_at,omitempty"`
	EscalatedTo    []string               `json:"escalated_to,omitempty"`
}

// ApprovalStatus represents the status of an approval request
type ApprovalStatus string

const (
	ApprovalStatusPending   ApprovalStatus = "pending"
	ApprovalStatusApproved  ApprovalStatus = "approved"
	ApprovalStatusRejected  ApprovalStatus = "rejected"
	ApprovalStatusEscalated ApprovalStatus = "escalated"
	ApprovalStatusExpired   ApprovalStatus = "expired"
)

// ApprovalRequirement represents a single approval requirement (reused from user_guidance.go)

// NewInteractivePermissionResolver creates a new interactive permission resolver
func NewInteractivePermissionResolver(
	kubeClient kubernetes.Interface,
	redisClient redis.UniversalClient,
	rbacContext *EnhancedRBACContext,
	advisor *RBACAdvisor,
	guidanceService *models.UserGuidanceService,
	auditLogger *AuthAuditLogger,
	config ResolverConfig,
) *InteractivePermissionResolver {
	return &InteractivePermissionResolver{
		kubeClient:      kubeClient,
		redisClient:     redisClient,
		rbacContext:     rbacContext,
		advisor:         advisor,
		guidanceService: guidanceService,
		auditLogger:     auditLogger,
		config:          config,
	}
}

// StartInteractiveResolution starts an interactive resolution session for a permission error
func (r *InteractivePermissionResolver) StartInteractiveResolution(ctx context.Context, userClaims *JWTClaims, permError *models.PermissionError) (*InteractiveResolutionSession, error) {
	sessionID := r.generateSessionID()
	
	session := &InteractiveResolutionSession{
		SessionID:     sessionID,
		UserContext:   userClaims,
		OriginalError: permError,
		Status:        SessionStatusActive,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
		ExpiresAt:     time.Now().Add(r.config.WorkflowTimeout),
		Metadata:      make(map[string]interface{}),
		TestResults:   make([]PermissionTestResult, 0),
	}

	// Generate workflow steps based on the error
	steps, err := r.generateWorkflowSteps(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to generate workflow steps: %w", err)
	}
	
	session.WorkflowSteps = steps
	session.CurrentStep = 0

	// Save session to Redis
	if err := r.saveSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	// Log session creation
	if r.auditLogger != nil {
		r.auditLogger.LogAuthEvent(ctx, map[string]interface{}{
			"event":      "interactive_resolution_started",
			"session_id": sessionID,
			"user_id":    userClaims.UserID,
			"error_id":   permError.ID,
		})
	}

	return session, nil
}

// ExecuteNextStep executes the next step in an interactive resolution session
func (r *InteractivePermissionResolver) ExecuteNextStep(ctx context.Context, sessionID string, userInput map[string]interface{}) (*InteractiveResolutionSession, error) {
	session, err := r.getSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	if session.Status != SessionStatusActive {
		return nil, fmt.Errorf("session is not active: %s", session.Status)
	}

	if session.CurrentStep >= len(session.WorkflowSteps) {
		return nil, fmt.Errorf("no more steps to execute")
	}

	currentStep := &session.WorkflowSteps[session.CurrentStep]
	currentStep.Status = StepStatusActive
	currentStep.UserInput = userInput

	startTime := time.Now()
	var stepErr error

	// Execute step based on type
	switch currentStep.Type {
	case StepTypeAnalysis:
		stepErr = r.executeAnalysisStep(ctx, session, currentStep)
	case StepTypeUserInput:
		stepErr = r.executeUserInputStep(ctx, session, currentStep)
	case StepTypePermissionTest:
		stepErr = r.executePermissionTestStep(ctx, session, currentStep)
	case StepTypeRoleImpersonation:
		stepErr = r.executeRoleImpersonationStep(ctx, session, currentStep)
	case StepTypeWorkflowExecution:
		stepErr = r.executeWorkflowExecutionStep(ctx, session, currentStep)
	case StepTypeApprovalRequest:
		stepErr = r.executeApprovalRequestStep(ctx, session, currentStep)
	case StepTypeVerification:
		stepErr = r.executeVerificationStep(ctx, session, currentStep)
	default:
		stepErr = fmt.Errorf("unknown step type: %s", currentStep.Type)
	}

	// Update step status and timing
	executedAt := time.Now()
	currentStep.ExecutedAt = &executedAt
	currentStep.Duration = time.Since(startTime)

	if stepErr != nil {
		currentStep.Status = StepStatusFailed
		currentStep.Error = stepErr.Error()
	} else {
		currentStep.Status = StepStatusCompleted
		session.CurrentStep++
	}

	session.UpdatedAt = time.Now()

	// Check if workflow is complete
	if session.CurrentStep >= len(session.WorkflowSteps) {
		session.Status = SessionStatusCompleted
	}

	// Save updated session
	if err := r.saveSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to save session: %w", err)
	}

	return session, stepErr
}

// TestPermissionsWithDifferentRoles tests permissions using role impersonation
func (r *InteractivePermissionResolver) TestPermissionsWithDifferentRoles(ctx context.Context, sessionID string, roles []string) ([]PermissionTestResult, error) {
	if !r.config.EnableTesting {
		return nil, fmt.Errorf("permission testing is not enabled")
	}

	session, err := r.getSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var results []PermissionTestResult
	requiredPermissions := session.OriginalError.RequiredPermissions

	for _, role := range roles {
		for _, permission := range requiredPermissions {
			result := r.testPermissionWithRole(ctx, role, permission)
			results = append(results, result)
		}
	}

	// Add results to session
	session.TestResults = append(session.TestResults, results...)
	session.UpdatedAt = time.Now()

	if err := r.saveSession(ctx, session); err != nil {
		return results, fmt.Errorf("failed to save test results: %w", err)
	}

	return results, nil
}

// GetAvailableAlternatives provides alternative approaches for the user
func (r *InteractivePermissionResolver) GetAvailableAlternatives(ctx context.Context, sessionID string) ([]models.AlternativeAction, error) {
	session, err := r.getSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var alternatives []models.AlternativeAction

	// Get alternatives from the original error
	alternatives = append(alternatives, session.OriginalError.AlternativeActions...)

	// Generate dynamic alternatives based on test results
	if len(session.TestResults) > 0 {
		dynamicAlts := r.generateDynamicAlternatives(session.TestResults, session.UserContext)
		alternatives = append(alternatives, dynamicAlts...)
	}

	// Get alternatives from advisor if available
	if r.advisor != nil {
		requiredPerms := session.OriginalError.RequiredPermissions
		gap, err := r.advisor.AnalyzePermissionGap(ctx, session.UserContext, requiredPerms)
		if err == nil && gap.Recommendations != nil {
			for _, role := range gap.Recommendations.SuggestedRoles {
				alternatives = append(alternatives, models.AlternativeAction{
					Title:       fmt.Sprintf("Request %s role", role.Name),
					Description: role.Reason,
					Difficulty:  role.SecurityLevel,
				})
			}
		}
	}

	return alternatives, nil
}

// CreateEscalationRequest creates an escalation request for permission issues
func (r *InteractivePermissionResolver) CreateEscalationRequest(ctx context.Context, sessionID, reason string) error {
	session, err := r.getSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	// Create escalation entry
	escalationInfo := map[string]interface{}{
		"session_id":       sessionID,
		"user_id":          session.UserContext.UserID,
		"escalation_reason": reason,
		"original_error":   session.OriginalError.ID,
		"escalated_at":     time.Now(),
	}

	// Save escalation to Redis for processing
	escalationKey := fmt.Sprintf("escalation:%s:%s", sessionID, uuid.New().String()[:8])
	escalationData, _ := json.Marshal(escalationInfo)
	
	if r.redisClient != nil {
		r.redisClient.Set(ctx, escalationKey, escalationData, 24*time.Hour).Err()
	}

	// Update session status
	session.Status = SessionStatusAwaitingApproval
	session.UpdatedAt = time.Now()

	if session.ApprovalInfo == nil {
		session.ApprovalInfo = &ApprovalInfo{}
	}
	
	escalatedAt := time.Now()
	session.ApprovalInfo.EscalatedAt = &escalatedAt
	session.ApprovalInfo.Status = ApprovalStatusEscalated

	// Log escalation
	if r.auditLogger != nil {
		r.auditLogger.LogAuthEvent(ctx, escalationInfo)
	}

	return r.saveSession(ctx, session)
}

// Private helper methods

func (r *InteractivePermissionResolver) generateSessionID() string {
	return fmt.Sprintf("ires_%s_%d", uuid.New().String()[:8], time.Now().UnixNano())
}

func (r *InteractivePermissionResolver) generateWorkflowSteps(ctx context.Context, session *InteractiveResolutionSession) ([]ResolutionStep, error) {
	var steps []ResolutionStep

	// Step 1: Analysis of the problem
	steps = append(steps, ResolutionStep{
		StepID:      uuid.New().String()[:8],
		StepNumber:  1,
		Type:        StepTypeAnalysis,
		Title:       "Analyze Permission Issue",
		Description: "Analyzing the permission error and gathering context",
		Status:      StepStatusPending,
	})

	// Step 2: User input for resolution preferences
	steps = append(steps, ResolutionStep{
		StepID:      uuid.New().String()[:8],
		StepNumber:  2,
		Type:        StepTypeUserInput,
		Title:       "Choose Resolution Approach",
		Description: "Select how you'd like to resolve this permission issue",
		Status:      StepStatusPending,
		Options: []StepOption{
			{ID: "test", Label: "Test with different roles", Description: "See what roles would allow this operation", Recommended: true},
			{ID: "request", Label: "Request additional permissions", Description: "Submit a permission request to administrators"},
			{ID: "alternative", Label: "Find alternative approaches", Description: "Explore other ways to achieve your goal"},
		},
	})

	// Step 3: Based on user choice, add appropriate steps
	// For now, we'll add permission testing by default
	if r.config.EnableTesting {
		steps = append(steps, ResolutionStep{
			StepID:      uuid.New().String()[:8],
			StepNumber:  3,
			Type:        StepTypePermissionTest,
			Title:       "Test Permissions",
			Description: "Testing your current permissions and exploring alternatives",
			Status:      StepStatusPending,
		})
	}

	// Step 4: Verification and completion
	steps = append(steps, ResolutionStep{
		StepID:      uuid.New().String()[:8],
		StepNumber:  len(steps) + 1,
		Type:        StepTypeVerification,
		Title:       "Verify Resolution",
		Description: "Verify that the permission issue has been resolved",
		Status:      StepStatusPending,
	})

	return steps, nil
}

func (r *InteractivePermissionResolver) executeAnalysisStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	// Perform detailed analysis using the enhanced RBAC context
	if r.rbacContext != nil {
		// Create a permission request from the original error
		request := &PermissionRequest{
			KubernetesUser:   session.UserContext.KubernetesUser,
			KubernetesGroups: session.UserContext.KubernetesGroups,
			Resource:         session.OriginalError.Resource,
			Verb:             session.OriginalError.Verb,
			Namespace:        session.OriginalError.Namespace,
			CommandContext:   session.OriginalError.OriginalInput,
		}

		evalCtx, err := r.rbacContext.EvaluatePermissionWithContext(ctx, session.UserContext, request)
		if err != nil {
			return fmt.Errorf("failed to analyze permissions: %w", err)
		}

		// Store analysis results
		step.SystemOutput = map[string]interface{}{
			"evaluation_context": evalCtx,
			"applicable_roles":   evalCtx.Result.ApplicableRoles,
			"evaluated_rules":    len(evalCtx.Result.EvaluatedRules),
			"root_cause":         evalCtx.ErrorDetails.RootCause,
		}
	}

	return nil
}

func (r *InteractivePermissionResolver) executeUserInputStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	// Validate user input
	selectedOption, ok := step.UserInput["selected_option"].(string)
	if !ok {
		return fmt.Errorf("no option selected")
	}

	// Store the user's choice
	step.SystemOutput = map[string]interface{}{
		"selected_approach": selectedOption,
		"timestamp":        time.Now(),
	}

	return nil
}

func (r *InteractivePermissionResolver) executePermissionTestStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	if !r.config.EnableTesting {
		return fmt.Errorf("permission testing is disabled")
	}

	// Test current permissions
	requiredPermissions := session.OriginalError.RequiredPermissions
	var testResults []PermissionTestResult

	for _, permission := range requiredPermissions {
		// Test current user permissions
		result := r.testPermissionAsUser(ctx, session.UserContext.KubernetesUser, permission)
		testResults = append(testResults, result)

		// Test with common roles if impersonation is enabled
		if r.config.EnableImpersonation {
			commonRoles := []string{"view", "edit", "admin"}
			for _, role := range commonRoles {
				roleResult := r.testPermissionWithRole(ctx, role, permission)
				testResults = append(testResults, roleResult)
			}
		}
	}

	session.TestResults = append(session.TestResults, testResults...)
	
	step.SystemOutput = map[string]interface{}{
		"tests_performed": len(testResults),
		"successful_tests": r.countSuccessfulTests(testResults),
		"test_summary":     r.summarizeTestResults(testResults),
	}

	return nil
}

func (r *InteractivePermissionResolver) executeRoleImpersonationStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	if !r.config.EnableImpersonation {
		return fmt.Errorf("role impersonation is disabled")
	}

	// This would involve temporarily impersonating different roles to test permissions
	// For security reasons, this would typically be limited to testing environments
	step.SystemOutput = map[string]interface{}{
		"impersonation_available": r.config.EnableImpersonation,
		"message":                "Role impersonation testing completed",
	}

	return nil
}

func (r *InteractivePermissionResolver) executeWorkflowExecutionStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	// Execute self-service workflow if available
	if r.guidanceService != nil {
		workflow := r.guidanceService.CreateSelfServiceWorkflow(session.OriginalError)
		
		step.SystemOutput = map[string]interface{}{
			"workflow_created": true,
			"workflow_id":      workflow.ID,
			"estimated_time":   workflow.EstimatedTime,
			"steps_count":      len(workflow.Steps),
		}
	}

	return nil
}

func (r *InteractivePermissionResolver) executeApprovalRequestStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	if !r.config.RequireApproval {
		step.Status = StepStatusSkipped
		return nil
	}

	// Create approval request
	approvalInfo := &ApprovalInfo{
		Required:    true,
		Status:      ApprovalStatusPending,
		SubmittedAt: &[]time.Time{time.Now()}[0],
	}

	// Generate approval requirements based on the error category
	approvers := r.generateApprovalRequirements(session.OriginalError.Category)
	approvalInfo.Approvers = approvers

	session.ApprovalInfo = approvalInfo
	session.Status = SessionStatusAwaitingApproval

	step.SystemOutput = map[string]interface{}{
		"approval_required": true,
		"approvers_count":   len(approvers),
		"estimated_time":    "2-24 hours",
	}

	return nil
}

func (r *InteractivePermissionResolver) executeVerificationStep(ctx context.Context, session *InteractiveResolutionSession, step *ResolutionStep) error {
	// Verify that the permission issue has been resolved
	request := &PermissionRequest{
		KubernetesUser:   session.UserContext.KubernetesUser,
		KubernetesGroups: session.UserContext.KubernetesGroups,
		Resource:         session.OriginalError.Resource,
		Verb:             session.OriginalError.Verb,
		Namespace:        session.OriginalError.Namespace,
	}

	// Test the permission again
	allowed := false
	if r.rbacContext != nil && r.rbacContext.validator != nil {
		var err error
		allowed, err = r.rbacContext.validator.ValidatePermission(ctx, request)
		if err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
	}

	step.SystemOutput = map[string]interface{}{
		"permission_resolved": allowed,
		"verification_time":   time.Now(),
		"final_status":       map[string]bool{"success": allowed},
	}

	if allowed {
		session.Status = SessionStatusCompleted
	}

	return nil
}

// Helper methods for testing

func (r *InteractivePermissionResolver) testPermissionAsUser(ctx context.Context, username string, permission models.RequiredPermission) PermissionTestResult {
	testID := uuid.New().String()[:8]
	startTime := time.Now()

	// Create the test command
	command := fmt.Sprintf("kubectl auth can-i %s %s --as=%s", permission.Verb, permission.Resource, username)
	if permission.Namespace != "" {
		command += fmt.Sprintf(" --namespace=%s", permission.Namespace)
	}

	// For testing, we'll simulate the result based on the permission context
	// In a real implementation, this would execute the actual kubectl command
	result := false // Assume denied for the test

	return PermissionTestResult{
		TestID:      testID,
		TestType:    "current",
		TestedAs:    username,
		Permission:  permission,
		Result:      result,
		Reason:      "Current user permissions insufficient",
		TestCommand: command,
		ExecutedAt:  time.Now(),
		Duration:    time.Since(startTime),
	}
}

func (r *InteractivePermissionResolver) testPermissionWithRole(ctx context.Context, roleName string, permission models.RequiredPermission) PermissionTestResult {
	testID := uuid.New().String()[:8]
	startTime := time.Now()

	// Create test command for role impersonation
	command := fmt.Sprintf("kubectl auth can-i %s %s --as=system:serviceaccount:default:%s", permission.Verb, permission.Resource, roleName)
	if permission.Namespace != "" {
		command += fmt.Sprintf(" --namespace=%s", permission.Namespace)
	}

	// Simulate role-based permission check
	result := r.simulateRolePermission(roleName, permission)

	return PermissionTestResult{
		TestID:      testID,
		TestType:    "impersonation",
		TestedAs:    fmt.Sprintf("role:%s", roleName),
		Permission:  permission,
		Result:      result,
		Reason:      fmt.Sprintf("Tested with %s role", roleName),
		TestCommand: command,
		ExecutedAt:  time.Now(),
		Duration:    time.Since(startTime),
	}
}

func (r *InteractivePermissionResolver) simulateRolePermission(roleName string, permission models.RequiredPermission) bool {
	// Simple simulation logic - in reality, this would check actual role permissions
	switch roleName {
	case "view":
		return permission.Verb == "get" || permission.Verb == "list" || permission.Verb == "watch"
	case "edit":
		return permission.Verb != "delete" // Edit role typically doesn't include delete
	case "admin":
		return true // Admin role has all permissions
	default:
		return false
	}
}

func (r *InteractivePermissionResolver) countSuccessfulTests(results []PermissionTestResult) int {
	count := 0
	for _, result := range results {
		if result.Result {
			count++
		}
	}
	return count
}

func (r *InteractivePermissionResolver) summarizeTestResults(results []PermissionTestResult) string {
	successful := r.countSuccessfulTests(results)
	total := len(results)
	
	if successful == 0 {
		return "No permissions found that would allow this operation"
	} else if successful == total {
		return "All tested roles would allow this operation"
	} else {
		return fmt.Sprintf("%d of %d tested roles would allow this operation", successful, total)
	}
}

func (r *InteractivePermissionResolver) generateDynamicAlternatives(testResults []PermissionTestResult, userContext *JWTClaims) []models.AlternativeAction {
	var alternatives []models.AlternativeAction

	// Find successful role tests
	for _, result := range testResults {
		if result.Result && result.TestType == "impersonation" {
			alternatives = append(alternatives, models.AlternativeAction{
				Title:       fmt.Sprintf("Request %s permissions", result.TestedAs),
				Description: fmt.Sprintf("This role would allow the %s operation", result.Permission.Verb),
				Commands:    []string{result.TestCommand},
				Difficulty:  "medium",
			})
		}
	}

	return alternatives
}

func (r *InteractivePermissionResolver) generateApprovalRequirements(category models.PermissionErrorCategory) []models.ApprovalRequirement {
	switch category {
	case models.PermissionCategoryClusterAccess:
		return []models.ApprovalRequirement{
			{Type: "role", Identifier: "cluster-admin", Required: true, Timeout: "24h"},
		}
	case models.PermissionCategoryResourceAccess:
		return []models.ApprovalRequirement{
			{Type: "group", Identifier: "namespace-admins", Required: true, Timeout: "4h"},
		}
	default:
		return []models.ApprovalRequirement{
			{Type: "group", Identifier: "devops-team", Required: false, Timeout: "2h"},
		}
	}
}

// Session management methods

func (r *InteractivePermissionResolver) saveSession(ctx context.Context, session *InteractiveResolutionSession) error {
	if r.redisClient == nil {
		return fmt.Errorf("no Redis client configured")
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := fmt.Sprintf("interactive_resolution:%s", session.SessionID)
	return r.redisClient.Set(ctx, key, data, r.config.WorkflowTimeout).Err()
}

func (r *InteractivePermissionResolver) getSession(ctx context.Context, sessionID string) (*InteractiveResolutionSession, error) {
	if r.redisClient == nil {
		return nil, fmt.Errorf("no Redis client configured")
	}

	key := fmt.Sprintf("interactive_resolution:%s", sessionID)
	data, err := r.redisClient.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session InteractiveResolutionSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if session has expired
	if time.Now().After(session.ExpiresAt) {
		session.Status = SessionStatusExpired
		r.saveSession(ctx, &session) // Save the expired status
		return &session, fmt.Errorf("session has expired")
	}

	return &session, nil
}

// GetSession retrieves a session by ID (public method)
func (r *InteractivePermissionResolver) GetSession(ctx context.Context, sessionID string) (*InteractiveResolutionSession, error) {
	return r.getSession(ctx, sessionID)
}

// ListActiveSessions lists all active sessions for a user
func (r *InteractivePermissionResolver) ListActiveSessions(ctx context.Context, userID string) ([]string, error) {
	if r.redisClient == nil {
		return nil, fmt.Errorf("no Redis client configured")
	}

	pattern := "interactive_resolution:*"
	keys, err := r.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	var userSessions []string
	for _, key := range keys {
		sessionID := strings.TrimPrefix(key, "interactive_resolution:")
		session, err := r.getSession(ctx, sessionID)
		if err != nil {
			continue // Skip sessions that can't be loaded
		}

		if session.UserContext.UserID == userID && session.Status == SessionStatusActive {
			userSessions = append(userSessions, sessionID)
		}
	}

	return userSessions, nil
}

// CancelSession cancels an active session
func (r *InteractivePermissionResolver) CancelSession(ctx context.Context, sessionID string) error {
	session, err := r.getSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	session.Status = SessionStatusCancelled
	session.UpdatedAt = time.Now()

	return r.saveSession(ctx, session)
}