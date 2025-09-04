// Package middleware provides enhanced RBAC context tests for KubeChat (Story 2.5)
package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// MockAuthAuditLogger mocks the audit logger
type MockAuthAuditLogger struct {
	mock.Mock
}

func (m *MockAuthAuditLogger) LogAuthEvent(ctx context.Context, event interface{}) error {
	args := m.Called(ctx, event)
	return args.Error(0)
}

func TestNewEnhancedRBACContext(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()
	validator := &MockRBACValidator{}
	advisor := &RBACAdvisor{}
	guidanceService := models.NewUserGuidanceService(models.UserGuidanceConfig{})
	auditLogger := &MockAuthAuditLogger{}

	config := EnhancedRBACContextConfig{
		KubeClient:      kubeClient,
		Validator:       validator,
		Advisor:         advisor,
		GuidanceService: guidanceService,
		AuditLogger:     auditLogger,
		EnableTrace:     true,
		CacheTTL:        time.Hour,
	}

	enhancedCtx := NewEnhancedRBACContext(config)

	assert.NotNil(t, enhancedCtx)
	assert.Equal(t, kubeClient, enhancedCtx.kubeClient)
	assert.Equal(t, validator, enhancedCtx.validator)
	assert.Equal(t, advisor, enhancedCtx.advisor)
	assert.Equal(t, guidanceService, enhancedCtx.guidanceService)
	assert.Equal(t, auditLogger, enhancedCtx.auditLogger)
	assert.True(t, enhancedCtx.enableTrace)
	assert.Equal(t, time.Hour, enhancedCtx.cacheTTL)
}

func TestEvaluatePermissionWithContext(t *testing.T) {
	// Setup test data
	kubeClient := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "test-binding"},
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "test.user"},
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "ClusterRole",
				Name: "view",
			},
		},
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{Name: "view"},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		},
	)

	validator := &MockRBACValidator{}
	validator.On("ValidatePermission", mock.Anything, mock.Anything).Return(false, nil)

	config := EnhancedRBACContextConfig{
		KubeClient:  kubeClient,
		Validator:   validator,
		EnableTrace: true,
	}

	enhancedCtx := NewEnhancedRBACContext(config)

	userClaims := &JWTClaims{
		UserID:           "user123",
		KubernetesUser:   "test.user",
		KubernetesGroups: []string{"developers"},
		AllowedNamespaces: []string{"default"},
		ClusterAccess:    false,
	}

	request := &PermissionRequest{
		KubernetesUser:   "test.user",
		KubernetesGroups: []string{"developers"},
		Resource:         "pods",
		Verb:             "delete", // Not allowed by view role
		Namespace:        "default",
		CommandContext:   "delete pod",
	}

	evalCtx, err := enhancedCtx.EvaluatePermissionWithContext(context.Background(), userClaims, request)

	require.NoError(t, err)
	require.NotNil(t, evalCtx)

	// Verify evaluation context structure
	assert.NotEmpty(t, evalCtx.RequestID)
	assert.WithinDuration(t, time.Now(), evalCtx.Timestamp, time.Second)
	assert.Equal(t, userClaims, evalCtx.UserContext)
	assert.Equal(t, request, evalCtx.Request)
	assert.Greater(t, evalCtx.Duration, time.Duration(0))

	// Verify evaluation steps were recorded
	assert.NotEmpty(t, evalCtx.EvaluationPath)
	
	// Should have at least basic validation step
	hasBasicValidation := false
	for _, step := range evalCtx.EvaluationPath {
		if step.StepType == "basic_validation" {
			hasBasicValidation = true
			break
		}
	}
	assert.True(t, hasBasicValidation, "Should have basic validation step")

	// Verify result was generated
	assert.NotNil(t, evalCtx.Result)
	assert.False(t, evalCtx.Result.Allowed) // Should be denied
	assert.NotEmpty(t, evalCtx.Result.Reason)

	// Verify detailed analysis was performed
	assert.NotEmpty(t, evalCtx.Result.ApplicableRoles)
	assert.NotEmpty(t, evalCtx.Result.ApplicableBindings)
	assert.NotEmpty(t, evalCtx.Result.EvaluatedRules)

	// Verify Kubernetes API calls were recorded
	assert.NotEmpty(t, evalCtx.KubernetesAPICalls)

	// Verify error details were generated for denied request
	assert.NotNil(t, evalCtx.ErrorDetails)
	assert.NotEmpty(t, evalCtx.ErrorDetails.RootCause)

	validator.AssertExpectations(t)
}

func TestAnalyzePermissionFailure(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()
	validator := &MockRBACValidator{}
	validator.On("ValidatePermission", mock.Anything, mock.Anything).Return(false, nil)

	// Create advisor with mocked behavior
	advisor := &RBACAdvisor{
		kubeClient: kubeClient,
	}

	guidanceService := models.NewUserGuidanceService(models.UserGuidanceConfig{
		ContactInfo: &models.ContactInfo{
			AdminEmail: "admin@example.com",
		},
	})

	config := EnhancedRBACContextConfig{
		KubeClient:      kubeClient,
		Validator:       validator,
		Advisor:         advisor,
		GuidanceService: guidanceService,
		EnableTrace:     true,
	}

	enhancedCtx := NewEnhancedRBACContext(config)

	userClaims := &JWTClaims{
		UserID:           "user123",
		KubernetesUser:   "test.user",
		KubernetesGroups: []string{"developers"},
		AllowedNamespaces: []string{"default", "staging"},
		ClusterAccess:    false,
	}

	request := &PermissionRequest{
		KubernetesUser: "test.user",
		Resource:       "pods",
		Verb:           "delete",
		Namespace:      "production",
		CommandContext: "delete failing pod in production",
	}

	permError, err := enhancedCtx.AnalyzePermissionFailure(context.Background(), userClaims, request, nil)

	require.NoError(t, err)
	require.NotNil(t, permError)

	// Verify basic error information
	assert.NotEmpty(t, permError.ID)
	assert.NotEmpty(t, permError.Code)
	assert.NotEmpty(t, permError.Message)
	assert.NotEmpty(t, permError.CorrelationID)

	// Verify permission context
	assert.Equal(t, "pods", permError.Resource)
	assert.Equal(t, "delete", permError.Verb)
	assert.Equal(t, "production", permError.Namespace)

	// Verify user context
	assert.Equal(t, "user123", permError.UserID)
	assert.Equal(t, "test.user", permError.KubernetesUser)
	assert.Equal(t, []string{"developers"}, permError.KubernetesGroups)

	// Verify natural language context
	assert.Equal(t, "delete failing pod in production", permError.OriginalInput)
	assert.Equal(t, "delete failing pod in production", permError.AttemptedOperation)

	// Verify error categorization
	assert.NotEmpty(t, permError.Category)

	// Verify required permissions
	assert.NotEmpty(t, permError.RequiredPermissions)
	assert.Equal(t, "pods", permError.RequiredPermissions[0].Resource)
	assert.Equal(t, "delete", permError.RequiredPermissions[0].Verb)

	// Verify trace information was added
	assert.NotNil(t, permError.TraceInformation)
	assert.NotEmpty(t, permError.TraceInformation.EvaluationPath)

	// Verify audit trail was populated
	assert.NotEmpty(t, permError.AuditTrail)

	// Verify guidance was generated
	assert.NotEmpty(t, permError.SelfServiceOptions)

	validator.AssertExpectations(t)
}

func TestEvaluateRule(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	tests := []struct {
		name           string
		rule           rbacv1.PolicyRule
		request        *PermissionRequest
		expectedMatch  bool
		expectedScore  float64
	}{
		{
			name: "exact match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
			request: &PermissionRequest{
				APIGroup: "",
				Resource: "pods",
				Verb:     "get",
			},
			expectedMatch: true,
			expectedScore: 1.0,
		},
		{
			name: "wildcard match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			request: &PermissionRequest{
				APIGroup: "apps/v1",
				Resource: "deployments",
				Verb:     "create",
			},
			expectedMatch: true,
			expectedScore: 1.0,
		},
		{
			name: "partial match - wrong verb",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
			request: &PermissionRequest{
				APIGroup: "",
				Resource: "pods",
				Verb:     "delete",
			},
			expectedMatch: false,
			expectedScore: 0.75, // API group, resource, namespace match
		},
		{
			name: "no match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"create"},
			},
			request: &PermissionRequest{
				APIGroup: "",
				Resource: "pods",
				Verb:     "get",
			},
			expectedMatch: false,
			expectedScore: 0.25, // Only namespace matches
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, details := enhancedCtx.evaluateRule(tt.rule, tt.request)

			assert.Equal(t, tt.expectedMatch, matched)
			assert.Equal(t, tt.expectedScore, details.MatchScore)

			if !matched {
				assert.NotEmpty(t, details.FailureReason)
			}
		})
	}
}

func TestGenerateRequiredPermissions(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	tests := []struct {
		name                  string
		request               *PermissionRequest
		expectedPermCount     int
		expectedClusterScoped bool
	}{
		{
			name: "namespace-scoped permission",
			request: &PermissionRequest{
				Resource:  "pods",
				Verb:      "list",
				Namespace: "default",
				APIGroup:  "",
			},
			expectedPermCount:     1,
			expectedClusterScoped: false,
		},
		{
			name: "cluster-scoped permission",
			request: &PermissionRequest{
				Resource: "nodes",
				Verb:     "list",
				APIGroup: "",
			},
			expectedPermCount:     1,
			expectedClusterScoped: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permissions := enhancedCtx.generateRequiredPermissions(tt.request)

			assert.Len(t, permissions, tt.expectedPermCount)
			
			if len(permissions) > 0 {
				perm := permissions[0]
				assert.Equal(t, tt.request.Resource, perm.Resource)
				assert.Equal(t, tt.request.Verb, perm.Verb)
				assert.Equal(t, tt.request.Namespace, perm.Namespace)
				assert.Equal(t, tt.request.APIGroup, perm.APIGroup)
				assert.Equal(t, tt.expectedClusterScoped, perm.ClusterScoped)
				assert.NotEmpty(t, perm.Explanation)
			}
		})
	}
}

func TestDetermineErrorCategory(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	tests := []struct {
		name             string
		request          *PermissionRequest
		evalCtx          *PermissionEvaluationContext
		expectedCategory models.PermissionErrorCategory
	}{
		{
			name: "cluster access error",
			request: &PermissionRequest{
				Resource: "nodes",
				Verb:     "list",
			},
			evalCtx: &PermissionEvaluationContext{
				Result: &PermissionEvaluationResult{},
			},
			expectedCategory: models.PermissionCategoryClusterAccess,
		},
		{
			name: "role binding error",
			request: &PermissionRequest{
				Resource:  "pods",
				Verb:      "list",
				Namespace: "default",
			},
			evalCtx: &PermissionEvaluationContext{
				Result: &PermissionEvaluationResult{
					ApplicableRoles: []string{}, // No roles
				},
			},
			expectedCategory: models.PermissionCategoryRoleBinding,
		},
		{
			name: "resource access error",
			request: &PermissionRequest{
				Resource:  "pods",
				Verb:      "delete",
				Namespace: "default",
			},
			evalCtx: &PermissionEvaluationContext{
				Result: &PermissionEvaluationResult{
					ApplicableRoles: []string{"view"}, // Has roles but still denied
				},
			},
			expectedCategory: models.PermissionCategoryResourceAccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category := enhancedCtx.determineErrorCategory(tt.request, tt.evalCtx)
			assert.Equal(t, tt.expectedCategory, category)
		})
	}
}

func TestGenerateTroubleshootingSteps(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	request := &PermissionRequest{
		Resource:  "pods",
		Verb:      "delete",
		Namespace: "production",
		UserContext: &JWTClaims{
			KubernetesUser: "test.user",
		},
	}

	evalCtx := &PermissionEvaluationContext{
		Result: &PermissionEvaluationResult{},
	}

	steps := enhancedCtx.generateTroubleshootingSteps(request, evalCtx)

	require.NotEmpty(t, steps)

	// Verify step structure
	for i, step := range steps {
		assert.Equal(t, i+1, step.StepNumber)
		assert.NotEmpty(t, step.Title)
		assert.NotEmpty(t, step.Description)
		assert.NotEmpty(t, step.Commands)
		assert.NotEmpty(t, step.ExpectedResult)
		assert.NotEmpty(t, step.Difficulty)
	}

	// Verify first step checks user permissions
	firstStep := steps[0]
	assert.Contains(t, firstStep.Title, "permissions")
	assert.Contains(t, firstStep.Commands[0], "kubectl auth can-i")
	assert.Contains(t, firstStep.Commands[0], "test.user")
}

func TestMatchesStringSlice(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	tests := []struct {
		name     string
		slice    []string
		target   string
		expected bool
	}{
		{
			name:     "exact match",
			slice:    []string{"pods", "services"},
			target:   "pods",
			expected: true,
		},
		{
			name:     "wildcard match",
			slice:    []string{"*"},
			target:   "anything",
			expected: true,
		},
		{
			name:     "no match",
			slice:    []string{"deployments", "services"},
			target:   "pods",
			expected: false,
		},
		{
			name:     "empty slice",
			slice:    []string{},
			target:   "pods",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := enhancedCtx.matchesStringSlice(tt.slice, tt.target)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildFailureReason(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	tests := []struct {
		name           string
		details        RuleMatchDetails
		expectedReason string
	}{
		{
			name: "single failure",
			details: RuleMatchDetails{
				APIGroupMatch: true,
				ResourceMatch: true,
				VerbMatch:     false,
				NamespaceMatch: true,
			},
			expectedReason: "verb mismatch",
		},
		{
			name: "multiple failures",
			details: RuleMatchDetails{
				APIGroupMatch: false,
				ResourceMatch: false,
				VerbMatch:     true,
				NamespaceMatch: true,
			},
			expectedReason: "API group mismatch, resource mismatch",
		},
		{
			name: "all failures",
			details: RuleMatchDetails{
				APIGroupMatch: false,
				ResourceMatch: false,
				VerbMatch:     false,
				NamespaceMatch: true,
			},
			expectedReason: "API group mismatch, resource mismatch, verb mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason := enhancedCtx.buildFailureReason(tt.details)
			assert.Equal(t, tt.expectedReason, reason)
		})
	}
}

func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	assert.NotEqual(t, id1, id2, "Request IDs should be unique")
	assert.Contains(t, id1, "req_", "Request ID should have proper prefix")
	assert.Contains(t, id2, "req_", "Request ID should have proper prefix")
}

func TestGenerateErrorCode(t *testing.T) {
	tests := []struct {
		name         string
		request      *PermissionRequest
		expectedCode string
	}{
		{
			name: "cluster-scoped request",
			request: &PermissionRequest{
				Resource: "nodes",
				Verb:     "list",
			},
			expectedCode: "CLUSTER_PERMISSION_DENIED",
		},
		{
			name: "namespace-scoped request",
			request: &PermissionRequest{
				Resource:  "pods",
				Verb:      "list",
				Namespace: "default",
			},
			expectedCode: "NAMESPACE_PERMISSION_DENIED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := generateErrorCode(tt.request)
			assert.Equal(t, tt.expectedCode, code)
		})
	}
}

func TestIsClusterScoped(t *testing.T) {
	tests := []struct {
		name     string
		request  *PermissionRequest
		expected bool
	}{
		{
			name: "cluster-scoped resource",
			request: &PermissionRequest{
				Resource: "nodes",
				Verb:     "list",
			},
			expected: true,
		},
		{
			name: "namespace-scoped resource",
			request: &PermissionRequest{
				Resource:  "pods",
				Verb:      "list",
				Namespace: "default",
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isClusterScoped(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConvertRecommendationsToAlternatives(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	recommendations := &PermissionRecommendations{
		SuggestedRoles: []RoleRecommendation{
			{
				Name:          "view",
				Reason:        "Provides read-only access",
				SecurityLevel: "minimal",
			},
			{
				Name:          "edit",
				Reason:        "Provides read-write access",
				SecurityLevel: "standard",
			},
		},
	}

	alternatives := enhancedCtx.convertRecommendationsToAlternatives(recommendations)

	require.Len(t, alternatives, 2)

	assert.Equal(t, "Request view role", alternatives[0].Title)
	assert.Equal(t, "Provides read-only access", alternatives[0].Description)
	assert.Equal(t, "minimal", alternatives[0].Difficulty)

	assert.Equal(t, "Request edit role", alternatives[1].Title)
	assert.Equal(t, "Provides read-write access", alternatives[1].Description)
	assert.Equal(t, "standard", alternatives[1].Difficulty)
}

func TestGatherSystemContext(t *testing.T) {
	enhancedCtx := NewEnhancedRBACContext(EnhancedRBACContextConfig{})

	evalCtx := &PermissionEvaluationContext{
		Duration: time.Millisecond * 100,
		KubernetesAPICalls: []KubernetesAPICall{
			{Error: ""},
			{Error: "some error"},
		},
		CacheAccesses: []CacheAccess{
			{Hit: true},
		},
		Result: &PermissionEvaluationResult{
			EvaluatedRules: []EvaluatedRule{
				{Matched: false},
				{Matched: true},
			},
		},
	}

	context := enhancedCtx.gatherSystemContext(evalCtx)

	assert.Equal(t, "100ms", context["evaluation_duration"])
	assert.Equal(t, 2, context["api_calls_made"])
	assert.Equal(t, 1, context["cache_accesses"])
	assert.Equal(t, 2, context["rules_evaluated"])
	assert.Equal(t, 1, context["failed_api_calls"])
}