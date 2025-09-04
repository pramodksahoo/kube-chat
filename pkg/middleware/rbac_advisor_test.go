// Package middleware provides RBAC permission suggestion engine tests for KubeChat (Story 2.5)
package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	authv1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// MockRBACValidator mocks the RBAC validator
type MockRBACValidator struct {
	mock.Mock
}

func (m *MockRBACValidator) ValidatePermission(ctx context.Context, request *PermissionRequest) (bool, error) {
	args := m.Called(ctx, request)
	return args.Bool(0), args.Error(1)
}

func TestNewRBACAdvisor(t *testing.T) {
	tests := []struct {
		name        string
		config      RBACAdvisorConfig
		shouldError bool
		errorMsg    string
	}{
		{
			name: "valid configuration",
			config: RBACAdvisorConfig{
				KubeClient:  fake.NewSimpleClientset(),
				Validator:   &MockRBACValidator{},
				CacheTTL:    time.Hour,
				CachePrefix: "test",
			},
			shouldError: false,
		},
		{
			name: "missing kubernetes client",
			config: RBACAdvisorConfig{
				Validator:   &MockRBACValidator{},
				CacheTTL:    time.Hour,
				CachePrefix: "test",
			},
			shouldError: true,
			errorMsg:    "kubernetes client is required",
		},
		{
			name: "missing RBAC validator",
			config: RBACAdvisorConfig{
				KubeClient:  fake.NewSimpleClientset(),
				CacheTTL:    time.Hour,
				CachePrefix: "test",
			},
			shouldError: true,
			errorMsg:    "RBAC validator is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisor, err := NewRBACAdvisor(tt.config)

			if tt.shouldError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, advisor)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, advisor)
				assert.Equal(t, tt.config.KubeClient, advisor.kubeClient)
				assert.Equal(t, tt.config.Validator, advisor.validator)
			}
		})
	}
}

func TestAnalyzePermissionGap(t *testing.T) {
	// Setup test data
	userContext := &JWTClaims{
		KubernetesUser:    "test-user",
		KubernetesGroups:  []string{"developers"},
		AllowedNamespaces: []string{"default", "staging"},
		ClusterAccess:     false,
	}

	requiredPermissions := []models.RequiredPermission{
		{
			Resource:  "pods",
			Verb:      "list",
			Namespace: "default",
			APIGroup:  "",
		},
		{
			Resource:  "services",
			Verb:      "get",
			Namespace: "default",
			APIGroup:  "",
		},
	}

	tests := []struct {
		name           string
		setupValidator func() *MockRBACValidator
		expectedGap    func(*PermissionGap)
	}{
		{
			name: "missing permissions identified",
			setupValidator: func() *MockRBACValidator {
				validator := &MockRBACValidator{}
				// Mock both permissions as denied
				validator.On("ValidatePermission", mock.Anything, mock.MatchedBy(func(req *PermissionRequest) bool {
					return req.Resource == "pods" && req.Verb == "list"
				})).Return(false, nil)
				validator.On("ValidatePermission", mock.Anything, mock.MatchedBy(func(req *PermissionRequest) bool {
					return req.Resource == "services" && req.Verb == "get"
				})).Return(false, nil)
				return validator
			},
			expectedGap: func(gap *PermissionGap) {
				assert.Len(t, gap.MissingPermissions, 2)
				assert.NotNil(t, gap.Recommendations)
				assert.NotEmpty(t, gap.Recommendations.SuggestedRoles)
			},
		},
		{
			name: "partial permissions missing",
			setupValidator: func() *MockRBACValidator {
				validator := &MockRBACValidator{}
				// Mock first permission as allowed, second as denied
				validator.On("ValidatePermission", mock.Anything, mock.MatchedBy(func(req *PermissionRequest) bool {
					return req.Resource == "pods" && req.Verb == "list"
				})).Return(true, nil)
				validator.On("ValidatePermission", mock.Anything, mock.MatchedBy(func(req *PermissionRequest) bool {
					return req.Resource == "services" && req.Verb == "get"
				})).Return(false, nil)
				return validator
			},
			expectedGap: func(gap *PermissionGap) {
				assert.Len(t, gap.MissingPermissions, 1)
				assert.Equal(t, "services", gap.MissingPermissions[0].Resource)
			},
		},
		{
			name: "no missing permissions",
			setupValidator: func() *MockRBACValidator {
				validator := &MockRBACValidator{}
				// Mock all permissions as allowed
				validator.On("ValidatePermission", mock.Anything, mock.Anything).Return(true, nil)
				return validator
			},
			expectedGap: func(gap *PermissionGap) {
				assert.Len(t, gap.MissingPermissions, 0)
				assert.NotNil(t, gap.Recommendations)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := tt.setupValidator()
			
			// Create fake Kubernetes client with some test data
			kubeClient := fake.NewSimpleClientset()
			
			config := RBACAdvisorConfig{
				KubeClient:    kubeClient,
				Validator:     validator,
				CacheTTL:      time.Hour,
				EnableCaching: false, // Disable caching for tests
				CachePrefix:   "test",
			}
			
			advisor, err := NewRBACAdvisor(config)
			require.NoError(t, err)

			gap, err := advisor.AnalyzePermissionGap(context.Background(), userContext, requiredPermissions)
			require.NoError(t, err)
			require.NotNil(t, gap)

			tt.expectedGap(gap)
			
			// Verify validator calls
			validator.AssertExpectations(t)
		})
	}
}

func TestGenerateKubectlCommands(t *testing.T) {
	userContext := &JWTClaims{
		KubernetesUser: "john.doe",
	}

	tests := []struct {
		name                string
		missingPermissions  []models.RequiredPermission
		expectedCommands    int
		expectedPatterns    []string
	}{
		{
			name: "namespace-specific permissions",
			missingPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "list", Namespace: "default"},
				{Resource: "services", Verb: "get", Namespace: "default"},
			},
			expectedCommands: 4, // role, rolebinding, 2 verification commands
			expectedPatterns: []string{
				"kubectl create role",
				"kubectl create rolebinding",
				"kubectl auth can-i",
			},
		},
		{
			name: "cluster-scoped permissions",
			missingPermissions: []models.RequiredPermission{
				{Resource: "nodes", Verb: "list", ClusterScoped: true},
			},
			expectedCommands: 3, // clusterrole, clusterrolebinding, 1 verification
			expectedPatterns: []string{
				"kubectl create clusterrole",
				"kubectl create clusterrolebinding",
				"kubectl auth can-i",
			},
		},
		{
			name: "mixed permissions",
			missingPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "list", Namespace: "default"},
				{Resource: "nodes", Verb: "list", ClusterScoped: true},
			},
			expectedCommands: 6, // 2 roles, 2 bindings, 2 verifications
			expectedPatterns: []string{
				"kubectl create role",
				"kubectl create clusterrole",
				"kubectl create rolebinding",
				"kubectl create clusterrolebinding",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := RBACAdvisorConfig{
				KubeClient:  fake.NewSimpleClientset(),
				Validator:   &MockRBACValidator{},
				CachePrefix: "test",
			}
			
			advisor, err := NewRBACAdvisor(config)
			require.NoError(t, err)

			commands, err := advisor.GenerateKubectlCommands(context.Background(), userContext, tt.missingPermissions)
			require.NoError(t, err)

			assert.Len(t, commands, tt.expectedCommands)

			// Check for expected command patterns
			commandsStr := ""
			for _, cmd := range commands {
				commandsStr += cmd + " "
			}

			for _, pattern := range tt.expectedPatterns {
				assert.Contains(t, commandsStr, pattern)
			}

			// Verify user is referenced in commands
			assert.Contains(t, commandsStr, userContext.KubernetesUser)
		})
	}
}

func TestGetRoleSuggestions(t *testing.T) {
	tests := []struct {
		name                string
		requiredPermissions []models.RequiredPermission
		expectedRoles       int
		expectedStandard    bool // Whether standard roles should be suggested
	}{
		{
			name: "view role pattern",
			requiredPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "get"},
				{Resource: "pods", Verb: "list"},
				{Resource: "pods", Verb: "watch"},
			},
			expectedRoles:    1,
			expectedStandard: true,
		},
		{
			name: "edit role pattern",
			requiredPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "get"},
				{Resource: "pods", Verb: "list"},
				{Resource: "pods", Verb: "create"},
				{Resource: "pods", Verb: "update"},
				{Resource: "pods", Verb: "delete"},
			},
			expectedRoles:    1,
			expectedStandard: true,
		},
		{
			name: "custom permissions",
			requiredPermissions: []models.RequiredPermission{
				{Resource: "customresources", Verb: "patch"},
			},
			expectedRoles:    1,
			expectedStandard: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fake client with some standard roles
			kubeClient := fake.NewSimpleClientset(
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "view"},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"pods", "services"},
							Verbs:     []string{"get", "list", "watch"},
						},
					},
				},
				&rbacv1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{Name: "edit"},
					Rules: []rbacv1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"*"},
							Verbs:     []string{"*"},
						},
					},
				},
			)

			config := RBACAdvisorConfig{
				KubeClient:  kubeClient,
				Validator:   &MockRBACValidator{},
				CachePrefix: "test",
			}
			
			advisor, err := NewRBACAdvisor(config)
			require.NoError(t, err)

			suggestions, err := advisor.GetRoleSuggestions(context.Background(), tt.requiredPermissions)
			require.NoError(t, err)

			assert.GreaterOrEqual(t, len(suggestions), tt.expectedRoles)

			if tt.expectedStandard {
				hasStandardRole := false
				for _, suggestion := range suggestions {
					if suggestion.Exists && (suggestion.Name == "view" || suggestion.Name == "edit") {
						hasStandardRole = true
						break
					}
				}
				assert.True(t, hasStandardRole, "Expected to find standard role suggestion")
			}

			// Verify suggestions are sorted by security level
			for i := 1; i < len(suggestions); i++ {
				prev := suggestions[i-1].SecurityLevel
				curr := suggestions[i].SecurityLevel
				
				securityOrder := map[string]int{"minimal": 1, "standard": 2, "elevated": 3}
				assert.LessOrEqual(t, securityOrder[prev], securityOrder[curr], "Suggestions should be sorted by security level")
			}
		})
	}
}

func TestSuggestMinimalPermissions(t *testing.T) {
	tests := []struct {
		name                string
		inputPermissions    []models.RequiredPermission
		expectedReductions  int
	}{
		{
			name: "remove duplicates",
			inputPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "get", Namespace: "default"},
				{Resource: "pods", Verb: "get", Namespace: "default"}, // duplicate
				{Resource: "services", Verb: "list", Namespace: "default"},
			},
			expectedReductions: 1, // Should remove 1 duplicate
		},
		{
			name: "optimize verb combinations",
			inputPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "get", Namespace: "default"},
				{Resource: "pods", Verb: "list", Namespace: "default"},
				{Resource: "pods", Verb: "watch", Namespace: "default"},
			},
			expectedReductions: 2, // Should combine into single "get,list,watch"
		},
		{
			name: "no optimization needed",
			inputPermissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "create", Namespace: "default"},
				{Resource: "services", Verb: "delete", Namespace: "staging"},
			},
			expectedReductions: 0, // No reductions possible
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := RBACAdvisorConfig{
				KubeClient:  fake.NewSimpleClientset(),
				Validator:   &MockRBACValidator{},
				CachePrefix: "test",
			}
			
			advisor, err := NewRBACAdvisor(config)
			require.NoError(t, err)

			minimal, err := advisor.SuggestMinimalPermissions(context.Background(), tt.inputPermissions)
			require.NoError(t, err)

			expectedLength := len(tt.inputPermissions) - tt.expectedReductions
			assert.Len(t, minimal, expectedLength)

			// Verify no actual permissions are lost (just optimized)
			if tt.expectedReductions == 0 {
				assert.Equal(t, len(tt.inputPermissions), len(minimal))
			}
		})
	}
}

func TestRoleCoversPermission(t *testing.T) {
	tests := []struct {
		name       string
		rule       rbacv1.PolicyRule
		permission models.RequiredPermission
		shouldCover bool
	}{
		{
			name: "exact match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
			permission: models.RequiredPermission{
				APIGroup: "",
				Resource: "pods",
				Verb:     "get",
			},
			shouldCover: true,
		},
		{
			name: "wildcard match",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
			permission: models.RequiredPermission{
				APIGroup: "apps/v1",
				Resource: "deployments",
				Verb:     "create",
			},
			shouldCover: true,
		},
		{
			name: "no match - different resource",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"services"},
				Verbs:     []string{"get"},
			},
			permission: models.RequiredPermission{
				APIGroup: "",
				Resource: "pods",
				Verb:     "get",
			},
			shouldCover: false,
		},
		{
			name: "no match - different verb",
			rule: rbacv1.PolicyRule{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"list"},
			},
			permission: models.RequiredPermission{
				APIGroup: "",
				Resource: "pods",
				Verb:     "delete",
			},
			shouldCover: false,
		},
	}

	config := RBACAdvisorConfig{
		KubeClient:  fake.NewSimpleClientset(),
		Validator:   &MockRBACValidator{},
		CachePrefix: "test",
	}
	
	advisor, err := NewRBACAdvisor(config)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := advisor.ruleCoversPermission(tt.rule, tt.permission)
			assert.Equal(t, tt.shouldCover, result)
		})
	}
}

func TestAssessRoleSecurityLevel(t *testing.T) {
	tests := []struct {
		name          string
		rules         []rbacv1.PolicyRule
		expectedLevel string
	}{
		{
			name: "minimal security - read only",
			rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list"},
				},
			},
			expectedLevel: "minimal",
		},
		{
			name: "standard security - with delete",
			rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "delete"},
				},
			},
			expectedLevel: "standard",
		},
		{
			name: "elevated security - wildcards",
			rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
			expectedLevel: "elevated",
		},
		{
			name: "elevated security - delete on cluster resources",
			rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"nodes", "clusterroles"},
					Verbs:     []string{"delete"},
				},
			},
			expectedLevel: "elevated",
		},
	}

	config := RBACAdvisorConfig{
		KubeClient:  fake.NewSimpleClientset(),
		Validator:   &MockRBACValidator{},
		CachePrefix: "test",
	}
	
	advisor, err := NewRBACAdvisor(config)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := advisor.assessRoleSecurityLevel(tt.rules)
			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}

func TestGenerateSecurityConsiderations(t *testing.T) {
	tests := []struct {
		name                      string
		permissions               []models.RequiredPermission
		expectedConsiderations    int
		shouldContainDeleteWarning bool
		shouldContainClusterWarning bool
		shouldContainSecretWarning bool
	}{
		{
			name: "delete operations warning",
			permissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "delete"},
			},
			expectedConsiderations:    2,
			shouldContainDeleteWarning: true,
		},
		{
			name: "cluster access warning",
			permissions: []models.RequiredPermission{
				{Resource: "nodes", Verb: "list", ClusterScoped: true},
			},
			expectedConsiderations:     2,
			shouldContainClusterWarning: true,
		},
		{
			name: "secret access warning",
			permissions: []models.RequiredPermission{
				{Resource: "secrets", Verb: "get"},
			},
			expectedConsiderations:    2,
			shouldContainSecretWarning: true,
		},
		{
			name: "safe operations - default considerations",
			permissions: []models.RequiredPermission{
				{Resource: "pods", Verb: "get"},
			},
			expectedConsiderations: 2, // Default considerations
		},
	}

	config := RBACAdvisorConfig{
		KubeClient:  fake.NewSimpleClientset(),
		Validator:   &MockRBACValidator{},
		CachePrefix: "test",
	}
	
	advisor, err := NewRBACAdvisor(config)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			considerations := advisor.generateSecurityConsiderations(tt.permissions)
			
			assert.Len(t, considerations, tt.expectedConsiderations)
			
			considerationsStr := ""
			for _, c := range considerations {
				considerationsStr += c + " "
			}
			
			if tt.shouldContainDeleteWarning {
				assert.Contains(t, considerationsStr, "delete")
			}
			if tt.shouldContainClusterWarning {
				assert.Contains(t, considerationsStr, "cluster")
			}
			if tt.shouldContainSecretWarning {
				assert.Contains(t, considerationsStr, "secret")
			}
		})
	}
}

func TestMetrics(t *testing.T) {
	config := RBACAdvisorConfig{
		KubeClient:  fake.NewSimpleClientset(),
		Validator:   &MockRBACValidator{},
		CachePrefix: "test",
	}
	
	advisor, err := NewRBACAdvisor(config)
	require.NoError(t, err)

	// Initial metrics should be zero
	metrics := advisor.GetMetrics()
	assert.Equal(t, int64(0), metrics.AnalysisRequests)
	assert.Equal(t, int64(0), metrics.CacheHits)
	assert.Equal(t, int64(0), metrics.CacheMisses)

	// Update metrics
	advisor.updateMetrics(time.Millisecond * 100)

	// Check updated metrics
	metrics = advisor.GetMetrics()
	assert.Equal(t, int64(1), metrics.AnalysisRequests)
	assert.Equal(t, time.Millisecond*100, metrics.AverageAnalysisTime)

	// Update again to test average calculation
	advisor.updateMetrics(time.Millisecond * 200)
	
	metrics = advisor.GetMetrics()
	assert.Equal(t, int64(2), metrics.AnalysisRequests)
	assert.Equal(t, time.Millisecond*150, metrics.AverageAnalysisTime) // (100+200)/2
}

func TestHelperFunctions(t *testing.T) {
	config := RBACAdvisorConfig{
		KubeClient:  fake.NewSimpleClientset(),
		Validator:   &MockRBACValidator{},
		CachePrefix: "test",
	}
	
	advisor, err := NewRBACAdvisor(config)
	require.NoError(t, err)

	t.Run("groupPermissionsByContext", func(t *testing.T) {
		permissions := []models.RequiredPermission{
			{Resource: "pods", Namespace: "default"},
			{Resource: "services", Namespace: "default"},
			{Resource: "nodes", ClusterScoped: true},
		}

		groups := advisor.groupPermissionsByContext(permissions)
		assert.Len(t, groups, 2) // default namespace + cluster-scoped

		assert.Len(t, groups["default"], 2)
		assert.Len(t, groups[""], 1) // cluster-scoped
	})

	t.Run("generateRoleName", func(t *testing.T) {
		name1 := advisor.generateRoleName("john.doe", "default")
		assert.Equal(t, "kubechat-john-doe-default", name1)

		name2 := advisor.generateRoleName("jane.smith", "")
		assert.Equal(t, "kubechat-jane-smith", name2)
	})

	t.Run("containsAll", func(t *testing.T) {
		haystack := []string{"get", "list", "watch", "create"}
		
		assert.True(t, advisor.containsAll(haystack, []string{"get", "list"}))
		assert.True(t, advisor.containsAll(haystack, []string{"watch"}))
		assert.False(t, advisor.containsAll(haystack, []string{"delete"}))
		assert.False(t, advisor.containsAll(haystack, []string{"get", "delete"}))
	})
}