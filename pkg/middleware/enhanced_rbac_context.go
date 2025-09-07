// Package middleware provides enhanced error context and debugging for RBAC validation (Story 2.5)
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// EnhancedRBACContext provides enhanced error context and debugging for RBAC validation
type EnhancedRBACContext struct {
	kubeClient     kubernetes.Interface
	redisClient    redis.UniversalClient
	validator      *RBACValidator
	advisor        *RBACAdvisor
	guidanceService *models.UserGuidanceService
	auditLogger    *AuthAuditLogger
	enableTrace    bool
	cacheTTL       time.Duration
}

// EnhancedRBACContextConfig holds configuration for enhanced RBAC context
type EnhancedRBACContextConfig struct {
	KubeClient      kubernetes.Interface
	RedisClient     redis.UniversalClient
	Validator       *RBACValidator
	Advisor         *RBACAdvisor
	GuidanceService *models.UserGuidanceService
	AuditLogger     *AuthAuditLogger
	EnableTrace     bool
	CacheTTL        time.Duration
}

// PermissionEvaluationContext represents the full context of a permission evaluation
type PermissionEvaluationContext struct {
	RequestID      string                       `json:"request_id"`
	Timestamp      time.Time                    `json:"timestamp"`
	UserContext    *JWTClaims                   `json:"user_context"`
	Request        *PermissionRequest           `json:"request"`
	EvaluationPath []EvaluationStep             `json:"evaluation_path"`
	KubernetesAPICalls []KubernetesAPICall       `json:"kubernetes_api_calls"`
	CacheAccesses  []CacheAccess                `json:"cache_accesses"`
	Result         *PermissionEvaluationResult  `json:"result"`
	Duration       time.Duration                `json:"duration"`
	ErrorDetails   *EnhancedErrorDetails        `json:"error_details,omitempty"`
}

// EvaluationStep represents a single step in permission evaluation
type EvaluationStep struct {
	StepNumber    int                    `json:"step_number"`
	StepType      string                 `json:"step_type"`      // "cache_check", "api_call", "policy_eval", "decision"
	Description   string                 `json:"description"`
	Timestamp     time.Time              `json:"timestamp"`
	Duration      time.Duration          `json:"duration"`
	Success       bool                   `json:"success"`
	Details       map[string]interface{} `json:"details"`
	Error         string                 `json:"error,omitempty"`
}

// KubernetesAPICall represents a call to the Kubernetes API during evaluation
type KubernetesAPICall struct {
	CallID        string                 `json:"call_id"`
	APIPath       string                 `json:"api_path"`
	Method        string                 `json:"method"`
	RequestBody   interface{}            `json:"request_body,omitempty"`
	ResponseCode  int                    `json:"response_code"`
	ResponseBody  interface{}            `json:"response_body,omitempty"`
	Duration      time.Duration          `json:"duration"`
	Error         string                 `json:"error,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// CacheAccess represents a cache access during evaluation
type CacheAccess struct {
	CacheKey    string      `json:"cache_key"`
	Operation   string      `json:"operation"` // "get", "set", "delete"
	Hit         bool        `json:"hit"`
	Value       interface{} `json:"value,omitempty"`
	TTL         time.Duration `json:"ttl,omitempty"`
	Error       string      `json:"error,omitempty"`
	Timestamp   time.Time   `json:"timestamp"`
}

// PermissionEvaluationResult represents the final result of permission evaluation
type PermissionEvaluationResult struct {
	Allowed             bool                 `json:"allowed"`
	Reason              string               `json:"reason"`
	EvaluatedRules      []EvaluatedRule      `json:"evaluated_rules"`
	ApplicableRoles     []string             `json:"applicable_roles"`
	ApplicableBindings  []string             `json:"applicable_bindings"`
	ConflictingPolicies []ConflictingPolicy  `json:"conflicting_policies,omitempty"`
	Recommendations     *PermissionRecommendations `json:"recommendations,omitempty"`
	AuditTrail          []models.AuditEntry  `json:"audit_trail"`
}

// EvaluatedRule represents a single RBAC rule that was evaluated
type EvaluatedRule struct {
	RuleSource    string                 `json:"rule_source"`    // "ClusterRole:admin", "Role:viewer"
	PolicyRule    rbacv1.PolicyRule      `json:"policy_rule"`
	Matched       bool                   `json:"matched"`
	MatchDetails  RuleMatchDetails       `json:"match_details"`
	Priority      int                    `json:"priority"`
	ConflictsWith []string               `json:"conflicts_with,omitempty"`
}

// RuleMatchDetails provides details about how a rule matched (or didn't match)
type RuleMatchDetails struct {
	APIGroupMatch   bool   `json:"api_group_match"`
	ResourceMatch   bool   `json:"resource_match"`
	VerbMatch       bool   `json:"verb_match"`
	NamespaceMatch  bool   `json:"namespace_match"`
	FailureReason   string `json:"failure_reason,omitempty"`
	MatchScore      float64 `json:"match_score"` // 0.0-1.0 indicating closeness of match
}

// ConflictingPolicy represents conflicting RBAC policies
type ConflictingPolicy struct {
	PolicyName    string   `json:"policy_name"`
	ConflictType  string   `json:"conflict_type"` // "allow_deny", "precedence", "ambiguous"
	Description   string   `json:"description"`
	Resolution    string   `json:"resolution"`
	Affected      []string `json:"affected"`
}

// EnhancedErrorDetails provides comprehensive error information
type EnhancedErrorDetails struct {
	PrimaryError      *models.PermissionError     `json:"primary_error"`
	RootCause         string                      `json:"root_cause"`
	ErrorHierarchy    []string                    `json:"error_hierarchy"`
	SystemContext     map[string]interface{}      `json:"system_context"`
	UserImpact        string                      `json:"user_impact"`
	AdminGuidance     *models.AdminGuidance       `json:"admin_guidance"`
	TroubleshootingSteps []TroubleshootingStep     `json:"troubleshooting_steps"`
	RelatedIssues     []RelatedIssue              `json:"related_issues,omitempty"`
	CorrelationTrail  []CorrelationEntry          `json:"correlation_trail"`
}

// TroubleshootingStep represents a troubleshooting step for administrators
type TroubleshootingStep struct {
	StepNumber   int      `json:"step_number"`
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Commands     []string `json:"commands"`
	ExpectedResult string `json:"expected_result"`
	NextSteps    []string `json:"next_steps"`
	Difficulty   string   `json:"difficulty"` // "easy", "medium", "hard"
}

// RelatedIssue represents related permission issues that might be relevant
type RelatedIssue struct {
	IssueID     string    `json:"issue_id"`
	Description string    `json:"description"`
	Frequency   int       `json:"frequency"`
	LastSeen    time.Time `json:"last_seen"`
	Resolution  string    `json:"resolution,omitempty"`
	Similarity  float64   `json:"similarity"` // 0.0-1.0
}

// CorrelationEntry represents an entry in the error correlation trail
type CorrelationEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	Component     string                 `json:"component"`
	Event         string                 `json:"event"`
	Details       map[string]interface{} `json:"details"`
	CorrelationID string                 `json:"correlation_id"`
}

// NewEnhancedRBACContext creates a new enhanced RBAC context
func NewEnhancedRBACContext(config EnhancedRBACContextConfig) *EnhancedRBACContext {
	return &EnhancedRBACContext{
		kubeClient:      config.KubeClient,
		redisClient:     config.RedisClient,
		validator:       config.Validator,
		advisor:         config.Advisor,
		guidanceService: config.GuidanceService,
		auditLogger:     config.AuditLogger,
		enableTrace:     config.EnableTrace,
		cacheTTL:        config.CacheTTL,
	}
}

// EvaluatePermissionWithContext performs comprehensive permission evaluation with full context
func (ctx *EnhancedRBACContext) EvaluatePermissionWithContext(reqCtx context.Context, userClaims *JWTClaims, request *PermissionRequest) (*PermissionEvaluationContext, error) {
	startTime := time.Now()
	evaluationContext := &PermissionEvaluationContext{
		RequestID:      generateRequestID(),
		Timestamp:      startTime,
		UserContext:    userClaims,
		Request:        request,
		EvaluationPath: make([]EvaluationStep, 0),
		KubernetesAPICalls: make([]KubernetesAPICall, 0),
		CacheAccesses:  make([]CacheAccess, 0),
	}

	defer func() {
		evaluationContext.Duration = time.Since(startTime)
		ctx.saveEvaluationContext(reqCtx, evaluationContext)
	}()

	// Step 1: Check cache
	if ctx.redisClient != nil {
		ctx.addEvaluationStep(evaluationContext, "cache_check", "Checking permission cache", func() (bool, error) {
			return ctx.checkPermissionCache(reqCtx, userClaims, request, evaluationContext)
		})
	}

	// Step 2: Perform basic permission validation
	var allowed bool
	var basicError error
	var permissionResponse *PermissionResponse
	ctx.addEvaluationStep(evaluationContext, "basic_validation", "Performing basic RBAC validation", func() (bool, error) {
		permissionResponse, basicError = ctx.validator.ValidatePermission(reqCtx, *request)
		if permissionResponse != nil {
			allowed = permissionResponse.Allowed
		}
		return allowed, basicError
	})

	// Step 3: Gather detailed context if validation failed or if tracing is enabled
	if !allowed || ctx.enableTrace {
		ctx.addEvaluationStep(evaluationContext, "detailed_analysis", "Gathering detailed permission context", func() (bool, error) {
			return ctx.gatherDetailedContext(reqCtx, userClaims, request, evaluationContext)
		})
	}

	// Step 4: Create result with recommendations
	ctx.addEvaluationStep(evaluationContext, "result_generation", "Generating final result and recommendations", func() (bool, error) {
		return ctx.generateResult(reqCtx, userClaims, request, evaluationContext, allowed, basicError)
	})

	// Step 5: Generate enhanced error details if needed
	if !allowed {
		ctx.addEvaluationStep(evaluationContext, "error_enhancement", "Generating enhanced error details", func() (bool, error) {
			return ctx.generateEnhancedErrorDetails(reqCtx, userClaims, request, evaluationContext, basicError)
		})
	}

	return evaluationContext, nil
}

// GetPermissionTrace retrieves the full trace of a permission evaluation
func (ctx *EnhancedRBACContext) GetPermissionTrace(reqCtx context.Context, requestID string) (*PermissionEvaluationContext, error) {
	if ctx.redisClient == nil {
		return nil, fmt.Errorf("tracing not enabled: no Redis client configured")
	}

	key := fmt.Sprintf("rbac:trace:%s", requestID)
	data, err := ctx.redisClient.Get(reqCtx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("trace not found for request ID: %s", requestID)
		}
		return nil, fmt.Errorf("failed to retrieve trace: %w", err)
	}

	var trace PermissionEvaluationContext
	if err := json.Unmarshal([]byte(data), &trace); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trace data: %w", err)
	}

	return &trace, nil
}

// AnalyzePermissionFailure provides detailed analysis of permission failures
func (ctx *EnhancedRBACContext) AnalyzePermissionFailure(reqCtx context.Context, userClaims *JWTClaims, request *PermissionRequest, originalError error) (*models.PermissionError, error) {
	// Get or create evaluation context
	evalCtx, err := ctx.EvaluatePermissionWithContext(reqCtx, userClaims, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create evaluation context: %w", err)
	}

	// Build comprehensive permission error
	errorBuilder := models.NewPermissionErrorBuilder().
		WithBasicInfo(
			generateErrorCode(request),
			fmt.Sprintf("Permission denied: %s %s in %s", request.Verb, request.Resource, request.Namespace),
		).
		WithPermissionContext(request.Resource, request.Verb, request.Namespace, isClusterScoped(request)).
		WithUserContext(
			userClaims.UserID,
			userClaims.KubernetesUser,
			userClaims.KubernetesGroups,
			userClaims.AllowedNamespaces,
			userClaims.ClusterAccess,
		).
		WithNaturalLanguageContext(request.CommandContext, request.CommandContext)

	// Determine error category
	category := ctx.determineErrorCategory(request, evalCtx)
	errorBuilder.WithCategory(category)

	// Generate required permissions
	requiredPerms := ctx.generateRequiredPermissions(request)
	errorBuilder.WithRequiredPermissions(requiredPerms)

	// Get permission recommendations from advisor
	if ctx.advisor != nil {
		gap, err := ctx.advisor.AnalyzePermissionGap(reqCtx, userClaims, requiredPerms)
		if err == nil && gap.Recommendations != nil {
			// Convert advisor recommendations to permission error format
			alternatives := ctx.convertRecommendationsToAlternatives(gap.Recommendations)
			errorBuilder.WithAlternativeActions(alternatives)

			if len(gap.Recommendations.KubectlCommands) > 0 {
				adminGuidance := &models.AdminGuidance{
					RoleBindingCommands:     gap.Recommendations.KubectlCommands,
					SecurityConsiderations: strings.Join(gap.Recommendations.SecurityConsiderations, "; "),
				}
				errorBuilder.WithAdminGuidance(adminGuidance)
			}
		}
	}

	// Add trace information
	if evalCtx.ErrorDetails != nil {
		traceInfo := &models.PermissionTrace{
			EvaluatedRoles:     evalCtx.Result.ApplicableRoles,
			EvaluatedBindings:  evalCtx.Result.ApplicableBindings,
			FailurePoint:       evalCtx.ErrorDetails.RootCause,
			EvaluationPath:     ctx.extractEvaluationPath(evalCtx),
			EvaluationDuration: evalCtx.Duration,
		}
		
		if len(evalCtx.KubernetesAPICalls) > 0 {
			lastCall := evalCtx.KubernetesAPICalls[len(evalCtx.KubernetesAPICalls)-1]
			if lastCall.Error != "" {
				traceInfo.K8sAPIResponse = lastCall.Error
			}
		}
		
		errorBuilder.WithTrace(traceInfo)
	}

	// Add audit entries from evaluation context
	for _, step := range evalCtx.EvaluationPath {
		errorBuilder.AddAuditEntry(step.StepType, fmt.Sprintf("%v", step.Success), step.Description)
	}

	// Get guidance from the guidance service
	permError := errorBuilder.Build()
	if ctx.guidanceService != nil {
		contextualHelp := ctx.guidanceService.GenerateContextualHelp(permError)
		if contextualHelp != nil {
			// Update permission error with guidance information
			if contextualHelp.OperationGuidance != nil && len(contextualHelp.OperationGuidance.Alternatives) > 0 {
				permError.AlternativeActions = append(permError.AlternativeActions, contextualHelp.OperationGuidance.Alternatives...)
			}
			
			// Add self-service options
			permError.SelfServiceOptions = contextualHelp.SelfServiceOptions
			
			// Add documentation links
			permError.DocumentationLinks = contextualHelp.LearningResources
		}
	}

	return permError, nil
}

// Private helper methods

func (ctx *EnhancedRBACContext) addEvaluationStep(evalCtx *PermissionEvaluationContext, stepType, description string, operation func() (bool, error)) {
	step := EvaluationStep{
		StepNumber:  len(evalCtx.EvaluationPath) + 1,
		StepType:    stepType,
		Description: description,
		Timestamp:   time.Now(),
		Details:     make(map[string]interface{}),
	}

	startTime := time.Now()
	success, err := operation()
	step.Duration = time.Since(startTime)
	step.Success = success

	if err != nil {
		step.Error = err.Error()
	}

	evalCtx.EvaluationPath = append(evalCtx.EvaluationPath, step)
}

func (ctx *EnhancedRBACContext) checkPermissionCache(reqCtx context.Context, userClaims *JWTClaims, request *PermissionRequest, evalCtx *PermissionEvaluationContext) (bool, error) {
	cacheKey := ctx.generateCacheKey(userClaims, request)
	
	cacheAccess := CacheAccess{
		CacheKey:  cacheKey,
		Operation: "get",
		Timestamp: time.Now(),
	}

	result, err := ctx.redisClient.Get(reqCtx, cacheKey).Result()
	if err != nil {
		if err == redis.Nil {
			cacheAccess.Hit = false
		} else {
			cacheAccess.Error = err.Error()
			evalCtx.CacheAccesses = append(evalCtx.CacheAccesses, cacheAccess)
			return false, err
		}
	} else {
		cacheAccess.Hit = true
		cacheAccess.Value = result
	}

	evalCtx.CacheAccesses = append(evalCtx.CacheAccesses, cacheAccess)
	return cacheAccess.Hit, nil
}

func (ctx *EnhancedRBACContext) gatherDetailedContext(reqCtx context.Context, userClaims *JWTClaims, request *PermissionRequest, evalCtx *PermissionEvaluationContext) (bool, error) {
	// Gather role bindings
	evalCtx.Result = &PermissionEvaluationResult{
		ApplicableRoles:    make([]string, 0),
		ApplicableBindings: make([]string, 0),
		EvaluatedRules:     make([]EvaluatedRule, 0),
		AuditTrail:         make([]models.AuditEntry, 0),
	}

	// Get cluster role bindings
	ctx.addKubernetesAPICall(evalCtx, "GET", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", func() error {
		bindings, err := ctx.kubeClient.RbacV1().ClusterRoleBindings().List(reqCtx, metav1.ListOptions{})
		if err != nil {
			return err
		}

		for _, binding := range bindings.Items {
			if ctx.isUserInBinding(userClaims, binding.Subjects) {
				evalCtx.Result.ApplicableBindings = append(evalCtx.Result.ApplicableBindings, 
					fmt.Sprintf("ClusterRoleBinding:%s", binding.Name))
				evalCtx.Result.ApplicableRoles = append(evalCtx.Result.ApplicableRoles,
					fmt.Sprintf("ClusterRole:%s", binding.RoleRef.Name))
				
				// Get the cluster role details
				ctx.evaluateClusterRole(reqCtx, binding.RoleRef.Name, request, evalCtx)
			}
		}
		return nil
	})

	// Get namespace role bindings
	if request.Namespace != "" {
		ctx.addKubernetesAPICall(evalCtx, "GET", fmt.Sprintf("/apis/rbac.authorization.k8s.io/v1/namespaces/%s/rolebindings", request.Namespace), func() error {
			bindings, err := ctx.kubeClient.RbacV1().RoleBindings(request.Namespace).List(reqCtx, metav1.ListOptions{})
			if err != nil {
				return err
			}

			for _, binding := range bindings.Items {
				if ctx.isUserInBinding(userClaims, binding.Subjects) {
					evalCtx.Result.ApplicableBindings = append(evalCtx.Result.ApplicableBindings,
						fmt.Sprintf("RoleBinding:%s:%s", binding.Namespace, binding.Name))
					
					if binding.RoleRef.Kind == "ClusterRole" {
						evalCtx.Result.ApplicableRoles = append(evalCtx.Result.ApplicableRoles,
							fmt.Sprintf("ClusterRole:%s", binding.RoleRef.Name))
						ctx.evaluateClusterRole(reqCtx, binding.RoleRef.Name, request, evalCtx)
					} else {
						evalCtx.Result.ApplicableRoles = append(evalCtx.Result.ApplicableRoles,
							fmt.Sprintf("Role:%s:%s", binding.Namespace, binding.RoleRef.Name))
						ctx.evaluateRole(reqCtx, binding.Namespace, binding.RoleRef.Name, request, evalCtx)
					}
				}
			}
			return nil
		})
	}

	return true, nil
}

func (ctx *EnhancedRBACContext) generateResult(reqCtx context.Context, userClaims *JWTClaims, request *PermissionRequest, evalCtx *PermissionEvaluationContext, allowed bool, err error) (bool, error) {
	if evalCtx.Result == nil {
		evalCtx.Result = &PermissionEvaluationResult{}
	}

	evalCtx.Result.Allowed = allowed
	if err != nil {
		evalCtx.Result.Reason = err.Error()
	} else if allowed {
		evalCtx.Result.Reason = "Permission granted"
	} else {
		evalCtx.Result.Reason = "Permission denied"
	}

	// Generate recommendations if advisor is available
	if ctx.advisor != nil && !allowed {
		requiredPerms := ctx.generateRequiredPermissions(request)
		recommendations, err := ctx.advisor.AnalyzePermissionGap(reqCtx, userClaims, requiredPerms)
		if err == nil {
			evalCtx.Result.Recommendations = recommendations.Recommendations
		}
	}

	return true, nil
}

func (ctx *EnhancedRBACContext) generateEnhancedErrorDetails(reqCtx context.Context, userClaims *JWTClaims, request *PermissionRequest, evalCtx *PermissionEvaluationContext, originalError error) (bool, error) {
	// Create enhanced error details
	evalCtx.ErrorDetails = &EnhancedErrorDetails{
		RootCause:         ctx.determineRootCause(evalCtx, originalError),
		ErrorHierarchy:    ctx.buildErrorHierarchy(evalCtx, originalError),
		SystemContext:     ctx.gatherSystemContext(evalCtx),
		UserImpact:        ctx.assessUserImpact(request),
		CorrelationTrail:  ctx.buildCorrelationTrail(evalCtx),
	}

	// Generate troubleshooting steps
	evalCtx.ErrorDetails.TroubleshootingSteps = ctx.generateTroubleshootingSteps(request, evalCtx)

	// Find related issues
	evalCtx.ErrorDetails.RelatedIssues = ctx.findRelatedIssues(reqCtx, request, evalCtx)

	return true, nil
}

// Helper methods for detailed analysis

func (ctx *EnhancedRBACContext) addKubernetesAPICall(evalCtx *PermissionEvaluationContext, method, path string, operation func() error) {
	call := KubernetesAPICall{
		CallID:    generateRequestID(),
		APIPath:   path,
		Method:    method,
		Timestamp: time.Now(),
	}

	startTime := time.Now()
	err := operation()
	call.Duration = time.Since(startTime)

	if err != nil {
		call.Error = err.Error()
		call.ResponseCode = 500 // Assume server error for failed calls
	} else {
		call.ResponseCode = 200
	}

	evalCtx.KubernetesAPICalls = append(evalCtx.KubernetesAPICalls, call)
}

func (ctx *EnhancedRBACContext) isUserInBinding(userClaims *JWTClaims, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		if subject.Kind == "User" && subject.Name == userClaims.KubernetesUser {
			return true
		}
		if subject.Kind == "Group" {
			for _, group := range userClaims.KubernetesGroups {
				if subject.Name == group {
					return true
				}
			}
		}
	}
	return false
}

func (ctx *EnhancedRBACContext) evaluateClusterRole(reqCtx context.Context, roleName string, request *PermissionRequest, evalCtx *PermissionEvaluationContext) {
	role, err := ctx.kubeClient.RbacV1().ClusterRoles().Get(reqCtx, roleName, metav1.GetOptions{})
	if err != nil {
		return
	}

	for i, rule := range role.Rules {
		evaluatedRule := EvaluatedRule{
			RuleSource: fmt.Sprintf("ClusterRole:%s[%d]", roleName, i),
			PolicyRule: rule,
			Priority:   1, // Cluster roles have higher priority
		}

		evaluatedRule.Matched, evaluatedRule.MatchDetails = ctx.evaluateRule(rule, request)
		evalCtx.Result.EvaluatedRules = append(evalCtx.Result.EvaluatedRules, evaluatedRule)
	}
}

func (ctx *EnhancedRBACContext) evaluateRole(reqCtx context.Context, namespace, roleName string, request *PermissionRequest, evalCtx *PermissionEvaluationContext) {
	role, err := ctx.kubeClient.RbacV1().Roles(namespace).Get(reqCtx, roleName, metav1.GetOptions{})
	if err != nil {
		return
	}

	for i, rule := range role.Rules {
		evaluatedRule := EvaluatedRule{
			RuleSource: fmt.Sprintf("Role:%s:%s[%d]", namespace, roleName, i),
			PolicyRule: rule,
			Priority:   0, // Namespace roles have lower priority
		}

		evaluatedRule.Matched, evaluatedRule.MatchDetails = ctx.evaluateRule(rule, request)
		evalCtx.Result.EvaluatedRules = append(evalCtx.Result.EvaluatedRules, evaluatedRule)
	}
}

func (ctx *EnhancedRBACContext) evaluateRule(rule rbacv1.PolicyRule, request *PermissionRequest) (bool, RuleMatchDetails) {
	details := RuleMatchDetails{}
	score := 0.0

	// Check API group match
	details.APIGroupMatch = ctx.matchesStringSlice(rule.APIGroups, request.APIGroup)
	if details.APIGroupMatch {
		score += 0.25
	}

	// Check resource match
	details.ResourceMatch = ctx.matchesStringSlice(rule.Resources, request.Resource)
	if details.ResourceMatch {
		score += 0.25
	}

	// Check verb match
	details.VerbMatch = ctx.matchesStringSlice(rule.Verbs, request.Verb)
	if details.VerbMatch {
		score += 0.25
	}

	// Namespace match is always true for cluster-scoped resources or matching namespace
	details.NamespaceMatch = true
	score += 0.25

	details.MatchScore = score
	matched := details.APIGroupMatch && details.ResourceMatch && details.VerbMatch && details.NamespaceMatch

	if !matched {
		details.FailureReason = ctx.buildFailureReason(details)
	}

	return matched, details
}

func (ctx *EnhancedRBACContext) matchesStringSlice(slice []string, target string) bool {
	for _, item := range slice {
		if item == "*" || item == target {
			return true
		}
	}
	return false
}

// Utility methods

func generateRequestID() string {
	return fmt.Sprintf("req_%s_%d", uuid.New().String()[:8], time.Now().UnixNano())
}

func generateErrorCode(request *PermissionRequest) string {
	if request.Namespace == "" {
		return "CLUSTER_PERMISSION_DENIED"
	}
	return "NAMESPACE_PERMISSION_DENIED"
}

func isClusterScoped(request *PermissionRequest) bool {
	return request.Namespace == ""
}

func (ctx *EnhancedRBACContext) generateCacheKey(userClaims *JWTClaims, request *PermissionRequest) string {
	return fmt.Sprintf("rbac:permission:%s:%s:%s:%s:%s",
		userClaims.KubernetesUser,
		request.Namespace,
		request.Resource,
		request.Verb,
		request.APIGroup)
}

func (ctx *EnhancedRBACContext) determineErrorCategory(request *PermissionRequest, evalCtx *PermissionEvaluationContext) models.PermissionErrorCategory {
	if request.Namespace == "" {
		return models.PermissionCategoryClusterAccess
	}
	if len(evalCtx.Result.ApplicableRoles) == 0 {
		return models.PermissionCategoryRoleBinding
	}
	return models.PermissionCategoryResourceAccess
}

func (ctx *EnhancedRBACContext) generateRequiredPermissions(request *PermissionRequest) []models.RequiredPermission {
	return []models.RequiredPermission{
		{
			Resource:      request.Resource,
			Verb:          request.Verb,
			Namespace:     request.Namespace,
			APIGroup:      request.APIGroup,
			ClusterScoped: request.Namespace == "",
			Explanation:   fmt.Sprintf("Required to %s %s resources", request.Verb, request.Resource),
		},
	}
}

func (ctx *EnhancedRBACContext) convertRecommendationsToAlternatives(recommendations *PermissionRecommendations) []models.AlternativeAction {
	var alternatives []models.AlternativeAction

	for _, role := range recommendations.SuggestedRoles {
		alternatives = append(alternatives, models.AlternativeAction{
			Title:       fmt.Sprintf("Request %s role", role.Name),
			Description: role.Reason,
			Difficulty:  role.SecurityLevel,
		})
	}

	return alternatives
}

func (ctx *EnhancedRBACContext) extractEvaluationPath(evalCtx *PermissionEvaluationContext) []string {
	var path []string
	for _, step := range evalCtx.EvaluationPath {
		path = append(path, fmt.Sprintf("%s: %s", step.StepType, step.Description))
	}
	return path
}

func (ctx *EnhancedRBACContext) saveEvaluationContext(reqCtx context.Context, evalCtx *PermissionEvaluationContext) {
	if ctx.redisClient == nil {
		return
	}

	data, err := json.Marshal(evalCtx)
	if err != nil {
		return
	}

	key := fmt.Sprintf("rbac:trace:%s", evalCtx.RequestID)
	ctx.redisClient.Set(reqCtx, key, data, ctx.cacheTTL).Err()
}

// Additional helper methods for error analysis
func (ctx *EnhancedRBACContext) determineRootCause(evalCtx *PermissionEvaluationContext, err error) string {
	if len(evalCtx.Result.EvaluatedRules) == 0 {
		return "No applicable RBAC rules found for user"
	}
	
	for _, rule := range evalCtx.Result.EvaluatedRules {
		if !rule.Matched && rule.MatchDetails.MatchScore > 0.5 {
			return fmt.Sprintf("Rule partially matched but failed: %s", rule.MatchDetails.FailureReason)
		}
	}
	
	return "Permission denied by RBAC policy"
}

func (ctx *EnhancedRBACContext) buildErrorHierarchy(evalCtx *PermissionEvaluationContext, err error) []string {
	hierarchy := []string{
		"Kubernetes RBAC Permission Denied",
		"User Authentication Verified",
		"Permission Evaluation Failed",
	}
	
	if evalCtx.Result != nil && len(evalCtx.Result.ApplicableRoles) == 0 {
		hierarchy = append(hierarchy, "No Applicable Roles Found")
	} else {
		hierarchy = append(hierarchy, "Rules Evaluation Failed")
	}
	
	return hierarchy
}

func (ctx *EnhancedRBACContext) gatherSystemContext(evalCtx *PermissionEvaluationContext) map[string]interface{} {
	context := map[string]interface{}{
		"evaluation_duration": evalCtx.Duration.String(),
		"api_calls_made":      len(evalCtx.KubernetesAPICalls),
		"cache_accesses":      len(evalCtx.CacheAccesses),
		"rules_evaluated":     len(evalCtx.Result.EvaluatedRules),
	}
	
	if len(evalCtx.KubernetesAPICalls) > 0 {
		failedCalls := 0
		for _, call := range evalCtx.KubernetesAPICalls {
			if call.Error != "" {
				failedCalls++
			}
		}
		context["failed_api_calls"] = failedCalls
	}
	
	return context
}

func (ctx *EnhancedRBACContext) assessUserImpact(request *PermissionRequest) string {
	return fmt.Sprintf("User cannot perform '%s' operation on '%s' resources in namespace '%s'",
		request.Verb, request.Resource, request.Namespace)
}

func (ctx *EnhancedRBACContext) buildCorrelationTrail(evalCtx *PermissionEvaluationContext) []CorrelationEntry {
	var trail []CorrelationEntry
	
	for _, step := range evalCtx.EvaluationPath {
		trail = append(trail, CorrelationEntry{
			Timestamp:     step.Timestamp,
			Component:     "RBAC Validator",
			Event:         step.StepType,
			Details:       step.Details,
			CorrelationID: evalCtx.RequestID,
		})
	}
	
	return trail
}

func (ctx *EnhancedRBACContext) generateTroubleshootingSteps(request *PermissionRequest, evalCtx *PermissionEvaluationContext) []TroubleshootingStep {
	var steps []TroubleshootingStep

	// Step 1: Check user's current permissions
	steps = append(steps, TroubleshootingStep{
		StepNumber:  1,
		Title:       "Verify user permissions",
		Description: "Check what permissions the user currently has",
		Commands: []string{
			fmt.Sprintf("kubectl auth can-i %s %s --as=%s", request.Verb, request.Resource, request.KubernetesUser),
			fmt.Sprintf("kubectl auth can-i --list --as=%s", request.KubernetesUser),
		},
		ExpectedResult: "Should show current permissions and identify missing ones",
		NextSteps:      []string{"If user has no permissions, check role bindings"},
		Difficulty:     "easy",
	})

	// Step 2: Check role bindings
	steps = append(steps, TroubleshootingStep{
		StepNumber:  2,
		Title:       "Check role bindings",
		Description: "Verify the user's role bindings in the target namespace",
		Commands: []string{
			fmt.Sprintf("kubectl get rolebindings -n %s -o yaml", request.Namespace),
			"kubectl get clusterrolebindings -o yaml",
		},
		ExpectedResult: "Should list all role bindings and identify which ones apply to the user",
		NextSteps:      []string{"Check the roles referenced in the bindings"},
		Difficulty:     "medium",
	})

	return steps
}

func (ctx *EnhancedRBACContext) findRelatedIssues(reqCtx context.Context, request *PermissionRequest, evalCtx *PermissionEvaluationContext) []RelatedIssue {
	// This would typically query a database or log aggregation system
	// For now, return some example related issues
	return []RelatedIssue{
		{
			IssueID:     "RBAC-001",
			Description: "Similar permission denied for same resource type",
			Frequency:   5,
			LastSeen:    time.Now().Add(-2 * time.Hour),
			Similarity:  0.8,
		},
	}
}

func (ctx *EnhancedRBACContext) buildFailureReason(details RuleMatchDetails) string {
	var reasons []string
	
	if !details.APIGroupMatch {
		reasons = append(reasons, "API group mismatch")
	}
	if !details.ResourceMatch {
		reasons = append(reasons, "resource mismatch")
	}
	if !details.VerbMatch {
		reasons = append(reasons, "verb mismatch")
	}
	
	return strings.Join(reasons, ", ")
}