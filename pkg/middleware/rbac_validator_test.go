// Package middleware provides comprehensive RBAC validation testing
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	kubefake "k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	ktesting "k8s.io/client-go/testing"
)

// RBACValidatorTestSuite is the test suite for RBAC validation
type RBACValidatorTestSuite struct {
	suite.Suite
	validator     *RBACValidator
	kubeClient    *kubefake.Clientset
	redisClient   *MockRBACRedisClient
	circuitBreaker *MockCircuitBreaker
	ctx           context.Context
}

// MockRBACRedisClient is a mock Redis client for RBAC testing
type MockRBACRedisClient struct {
	mock.Mock
}

func (m *MockRBACRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	args := m.Called(ctx, key)
	cmd := redis.NewStringCmd(ctx, "get", key)
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal(args.String(0))
	}
	return cmd
}

func (m *MockRBACRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	cmd := redis.NewStatusCmd(ctx, "set", key, value)
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal("OK")
	}
	return cmd
}

func (m *MockRBACRedisClient) Del(ctx context.Context, keys ...string) *redis.IntCmd {
	args := m.Called(ctx, keys)
	cmd := redis.NewIntCmd(ctx, "del")
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal(int64(args.Int(0)))
	}
	return cmd
}

func (m *MockRBACRedisClient) Keys(ctx context.Context, pattern string) *redis.StringSliceCmd {
	args := m.Called(ctx, pattern)
	cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal(args.Get(0).([]string))
	}
	return cmd
}

// MockCircuitBreaker is a mock circuit breaker for testing
type MockCircuitBreaker struct {
	mock.Mock
}

func (m *MockCircuitBreaker) Execute(fn func() error) error {
	args := m.Called(fn)
	return args.Error(0)
}

func (m *MockCircuitBreaker) State() CircuitBreakerState {
	args := m.Called()
	return args.Get(0).(CircuitBreakerState)
}

// SetupTest sets up the test suite
func (suite *RBACValidatorTestSuite) SetupTest() {
	suite.ctx = context.Background()
	suite.kubeClient = kubefake.NewSimpleClientset()
	suite.redisClient = &MockRBACRedisClient{}
	suite.circuitBreaker = &MockCircuitBreaker{}

	// Create RBAC validator with mocked dependencies
	suite.validator = &RBACValidator{
		kubeClient:     suite.kubeClient,
		redisClient:    suite.redisClient,
		cacheTTL:       5 * time.Minute,
		cachePrefix:    "kubechat:rbac_test",
		enableCaching:  true,
		circuitBreaker: suite.circuitBreaker,
		metrics: &RBACValidationMetrics{
			MinLatency: time.Duration(^uint64(0) >> 1),
		},
	}
}

// TestValidatePermission_Allowed tests successful permission validation
func (suite *RBACValidatorTestSuite) TestValidatePermission_Allowed() {
	// Setup: Mock Kubernetes API to return allowed permission
	suite.kubeClient.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (handled bool, ret any, err error) {
		createAction := action.(ktesting.CreateAction)
		sar := createAction.GetObject().(*authv1.SubjectAccessReview)
		
		// Verify the SubjectAccessReview is properly formed
		suite.Assert().Equal("test-user", sar.Spec.User)
		suite.Assert().Equal([]string{"test-group"}, sar.Spec.Groups)
		suite.Assert().Equal("default", sar.Spec.ResourceAttributes.Namespace)
		suite.Assert().Equal("get", sar.Spec.ResourceAttributes.Verb)
		suite.Assert().Equal("pods", sar.Spec.ResourceAttributes.Resource)
		
		// Return allowed response
		sar.Status = authv1.SubjectAccessReviewStatus{
			Allowed: true,
			Reason:  "Permission granted by test",
		}
		return true, sar, nil
	})

	// Mock circuit breaker to pass through
	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() error")).Return(nil)

	// Mock cache miss
	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	request := PermissionRequest{
		KubernetesUser:   "test-user",
		KubernetesGroups: []string{"test-group"},
		SessionID:        "test-session",
		Namespace:        "default",
		Verb:             "get",
		Resource:         "pods",
		CommandContext:   "get pods",
	}

	// Execute
	response, err := suite.validator.ValidatePermission(suite.ctx, request)

	// Assert
	suite.Require().NoError(err)
	suite.Assert().True(response.Allowed)
	suite.Assert().Equal("Permission granted by test", response.Reason)
	suite.Assert().False(response.CacheHit)
	suite.Assert().Equal("test-user", response.UserInfo.User)
	suite.Assert().Equal([]string{"test-group"}, response.UserInfo.Groups)
	suite.Assert().NotEmpty(response.ValidationID)
	
	// Verify metrics were updated
	metrics := suite.validator.GetMetrics()
	suite.Assert().Equal(int64(1), metrics.TotalValidations)
	suite.Assert().Equal(int64(1), metrics.AllowedValidations)
	suite.Assert().Equal(int64(0), metrics.DeniedValidations)
}

// TestValidatePermission_Denied tests permission denial
func (suite *RBACValidatorTestSuite) TestValidatePermission_Denied() {
	// Setup: Mock Kubernetes API to return denied permission
	suite.kubeClient.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (handled bool, ret any, err error) {
		sar := action.(ktesting.CreateAction).GetObject().(*authv1.SubjectAccessReview)
		
		// Return denied response
		sar.Status = authv1.SubjectAccessReviewStatus{
			Allowed: false,
			Reason:  "User does not have permission to get pods in namespace default",
		}
		return true, sar, nil
	})

	// Mock circuit breaker to pass through
	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() error")).Return(nil)

	// Mock cache miss
	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	request := PermissionRequest{
		KubernetesUser:   "test-user",
		KubernetesGroups: []string{"test-group"},
		SessionID:        "test-session",
		Namespace:        "default",
		Verb:             "get",
		Resource:         "pods",
		CommandContext:   "get pods",
	}

	// Execute
	response, err := suite.validator.ValidatePermission(suite.ctx, request)

	// Assert
	suite.Require().NoError(err)
	suite.Assert().False(response.Allowed)
	suite.Assert().Contains(response.Reason, "does not have permission")
	suite.Assert().NotEmpty(response.Suggestions)
	
	// Verify metrics were updated
	metrics := suite.validator.GetMetrics()
	suite.Assert().Equal(int64(1), metrics.TotalValidations)
	suite.Assert().Equal(int64(0), metrics.AllowedValidations)
	suite.Assert().Equal(int64(1), metrics.DeniedValidations)
}

// TestValidatePermission_CacheHit tests cache functionality
func (suite *RBACValidatorTestSuite) TestValidatePermission_CacheHit() {
	// Setup: Mock cache hit
	cachedResponse := &PermissionResponse{
		Allowed:     true,
		Reason:      "Cached response",
		EvaluatedAt: time.Now(),
		CacheHit:    true,
		UserInfo: UserPermissionInfo{
			User:   "test-user",
			Groups: []string{"test-group"},
		},
	}
	
	cachedData, _ := json.Marshal(cachedResponse)
	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(string(cachedData), nil)

	request := PermissionRequest{
		KubernetesUser:   "test-user",
		KubernetesGroups: []string{"test-group"},
		SessionID:        "test-session",
		Namespace:        "default",
		Verb:             "get",
		Resource:         "pods",
	}

	// Execute
	response, err := suite.validator.ValidatePermission(suite.ctx, request)

	// Assert
	suite.Require().NoError(err)
	suite.Assert().True(response.Allowed)
	suite.Assert().True(response.CacheHit)
	suite.Assert().Equal("Cached response", response.Reason)
	
	// Verify metrics show cache hit
	metrics := suite.validator.GetMetrics()
	suite.Assert().Equal(int64(1), metrics.CacheHits)
	suite.Assert().Equal(int64(0), metrics.CacheMisses)
}

// TestValidatePermission_CircuitBreakerOpen tests circuit breaker functionality
func (suite *RBACValidatorTestSuite) TestValidatePermission_CircuitBreakerOpen() {
	// Setup: Mock circuit breaker failure
	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() error")).Return(
		fmt.Errorf("circuit breaker open"),
	)

	// Mock cache miss
	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	request := PermissionRequest{
		KubernetesUser:   "test-user",
		KubernetesGroups: []string{"test-group"},
		SessionID:        "test-session",
		Namespace:        "default",
		Verb:             "get",
		Resource:         "pods",
	}

	// Execute
	response, err := suite.validator.ValidatePermission(suite.ctx, request)

	// Assert: Should not error but should deny access due to API unavailability
	suite.Require().NoError(err)
	suite.Assert().False(response.Allowed)
	suite.Assert().Contains(response.Reason, "Kubernetes API unavailable")
	suite.Assert().Contains(response.Suggestions, "try again in a few moments")
	
	// Verify metrics show circuit breaker trip
	metrics := suite.validator.GetMetrics()
	suite.Assert().Equal(int64(1), metrics.CircuitBreakerTrips)
}

// TestValidatePermission_InvalidRequest tests input validation
func (suite *RBACValidatorTestSuite) TestValidatePermission_InvalidRequest() {
	testCases := []struct {
		name    string
		request PermissionRequest
		errMsg  string
	}{
		{
			name: "missing user",
			request: PermissionRequest{
				Verb:      "get",
				Resource:  "pods",
				SessionID: "test-session",
			},
			errMsg: "kubernetes_user is required",
		},
		{
			name: "missing verb",
			request: PermissionRequest{
				KubernetesUser: "test-user",
				Resource:       "pods",
				SessionID:      "test-session",
			},
			errMsg: "verb is required",
		},
		{
			name: "invalid verb",
			request: PermissionRequest{
				KubernetesUser: "test-user",
				Verb:           "invalid-verb",
				Resource:       "pods",
				SessionID:      "test-session",
			},
			errMsg: "invalid verb 'invalid-verb'",
		},
		{
			name: "missing session ID",
			request: PermissionRequest{
				KubernetesUser: "test-user",
				Verb:           "get",
				Resource:       "pods",
			},
			errMsg: "session_id is required for audit trail",
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			_, err := suite.validator.ValidatePermission(suite.ctx, tc.request)
			suite.Require().Error(err)
			suite.Assert().Contains(err.Error(), tc.errMsg)
		})
	}
}

// TestClusterRolePermissions tests cluster-level permissions
func (suite *RBACValidatorTestSuite) TestClusterRolePermissions() {
	// Setup: Mock cluster-level permission check
	suite.kubeClient.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (handled bool, ret any, err error) {
		sar := action.(ktesting.CreateAction).GetObject().(*authv1.SubjectAccessReview)
		
		// Verify cluster-scoped request
		suite.Assert().Empty(sar.Spec.ResourceAttributes.Namespace)
		suite.Assert().Equal("nodes", sar.Spec.ResourceAttributes.Resource)
		
		// Grant permission for cluster-admin users
		allowed := false
		for _, group := range sar.Spec.Groups {
			if group == "system:masters" {
				allowed = true
				break
			}
		}
		
		sar.Status = authv1.SubjectAccessReviewStatus{
			Allowed: allowed,
			Reason:  "Cluster-level permission check",
		}
		return true, sar, nil
	})

	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() (interface {}, error)")).Return(
		func(fn func() (interface{}, error)) interface{} {
			result, _ := fn()
			return result
		},
		nil,
	)

	// Mock cache miss
	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	// Test cluster-admin access
	adminRequest := PermissionRequest{
		KubernetesUser:   "admin-user",
		KubernetesGroups: []string{"system:masters"},
		SessionID:        "admin-session",
		Namespace:        "", // Cluster-scoped
		Verb:             "list",
		Resource:         "nodes",
	}

	response, err := suite.validator.ValidatePermission(suite.ctx, adminRequest)
	suite.Require().NoError(err)
	suite.Assert().True(response.Allowed)

	// Test regular user denied
	userRequest := PermissionRequest{
		KubernetesUser:   "regular-user",
		KubernetesGroups: []string{"regular-group"},
		SessionID:        "user-session",
		Namespace:        "",
		Verb:             "list",
		Resource:         "nodes",
	}

	response, err = suite.validator.ValidatePermission(suite.ctx, userRequest)
	suite.Require().NoError(err)
	suite.Assert().False(response.Allowed)
}

// TestServiceAccountPermissions tests service account permissions
func (suite *RBACValidatorTestSuite) TestServiceAccountPermissions() {
	// Setup service account permission test
	suite.kubeClient.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (handled bool, ret any, err error) {
		sar := action.(ktesting.CreateAction).GetObject().(*authv1.SubjectAccessReview)
		
		// Service accounts have specific naming pattern
		allowed := strings.HasPrefix(sar.Spec.User, "system:serviceaccount:")
		
		sar.Status = authv1.SubjectAccessReviewStatus{
			Allowed: allowed,
			Reason:  "Service account permission check",
		}
		return true, sar, nil
	})

	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() (interface {}, error)")).Return(
		func(fn func() (interface{}, error)) interface{} {
			result, _ := fn()
			return result
		},
		nil,
	)

	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	request := PermissionRequest{
		KubernetesUser:   "system:serviceaccount:default:kubechat-service",
		KubernetesGroups: []string{"system:serviceaccounts", "system:serviceaccounts:default"},
		SessionID:        "sa-session",
		Namespace:        "default",
		Verb:             "get",
		Resource:         "pods",
	}

	response, err := suite.validator.ValidatePermission(suite.ctx, request)
	suite.Require().NoError(err)
	suite.Assert().True(response.Allowed)
}

// TestPerformanceTargets tests performance requirements
func (suite *RBACValidatorTestSuite) TestPerformanceTargets() {
	// Setup fast response
	suite.kubeClient.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (handled bool, ret any, err error) {
		sar := action.(ktesting.CreateAction).GetObject().(*authv1.SubjectAccessReview)
		sar.Status = authv1.SubjectAccessReviewStatus{
			Allowed: true,
			Reason:  "Fast response test",
		}
		return true, sar, nil
	})

	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() (interface {}, error)")).Return(
		func(fn func() (interface{}, error)) interface{} {
			result, _ := fn()
			return result
		},
		nil,
	)

	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	// Perform multiple validations to test performance
	start := time.Now()
	for i := 0; i < 10; i++ {
		request := PermissionRequest{
			KubernetesUser:   fmt.Sprintf("test-user-%d", i),
			KubernetesGroups: []string{"test-group"},
			SessionID:        fmt.Sprintf("test-session-%d", i),
			Namespace:        "default",
			Verb:             "get",
			Resource:         "pods",
		}
		
		_, err := suite.validator.ValidatePermission(suite.ctx, request)
		suite.Require().NoError(err)
	}
	duration := time.Since(start)

	// Verify performance targets
	metrics := suite.validator.GetMetrics()
	suite.Assert().True(metrics.AverageLatency < 100*time.Millisecond, 
		"Average latency %v should be under 100ms", metrics.AverageLatency)
	
	avgPerRequest := duration / 10
	suite.Assert().True(avgPerRequest < 100*time.Millisecond,
		"Average per-request time %v should be under 100ms", avgPerRequest)

	// Check performance targets
	targets := suite.validator.IsPerformanceTarget()
	suite.Assert().True(targets["rbac_validation_under_100ms"])
	suite.Assert().True(targets["low_error_rate"])
}

// TestCacheInvalidation tests cache invalidation functionality
func (suite *RBACValidatorTestSuite) TestCacheInvalidation() {
	// Mock cache operations
	suite.redisClient.On("Keys", suite.ctx, "kubechat:rbac_test:test-user:*").Return(
		[]string{"kubechat:rbac_test:test-user:group1:default:get:pods:", "kubechat:rbac_test:test-user:group1:kube-system:list:pods:"},
		nil,
	)
	suite.redisClient.On("Del", suite.ctx, mock.AnythingOfType("[]string")).Return(2, nil)

	// Execute cache invalidation
	err := suite.validator.InvalidateUserCache(suite.ctx, "test-user")
	suite.Require().NoError(err)

	// Verify Redis operations were called
	suite.redisClient.AssertCalled(suite.T(), "Keys", suite.ctx, "kubechat:rbac_test:test-user:*")
	suite.redisClient.AssertCalled(suite.T(), "Del", suite.ctx, mock.AnythingOfType("[]string"))
}

// TestSecurityEscalationPrevention tests that the validator prevents permission escalation
func (suite *RBACValidatorTestSuite) TestSecurityEscalationPrevention() {
	// Setup: Mock that always denies permission escalation attempts
	suite.kubeClient.PrependReactor("create", "subjectaccessreviews", func(action ktesting.Action) (handled bool, ret any, err error) {
		sar := action.(ktesting.CreateAction).GetObject().(*authv1.SubjectAccessReview)
		
		// Deny any attempt to access cluster-admin resources
		denied := strings.Contains(sar.Spec.ResourceAttributes.Resource, "clusterrole") ||
		          strings.Contains(sar.Spec.ResourceAttributes.Resource, "role")
		
		sar.Status = authv1.SubjectAccessReviewStatus{
			Allowed: !denied,
			Reason:  "Permission escalation denied",
		}
		return true, sar, nil
	})

	suite.circuitBreaker.On("Execute", mock.AnythingOfType("func() (interface {}, error)")).Return(
		func(fn func() (interface{}, error)) interface{} {
			result, _ := fn()
			return result
		},
		nil,
	)

	suite.redisClient.On("Get", suite.ctx, mock.AnythingOfType("string")).Return(redis.Nil)

	// Test escalation attempts
	escalationAttempts := []PermissionRequest{
		{
			KubernetesUser:   "regular-user",
			KubernetesGroups: []string{"regular-group"},
			SessionID:        "escalation-session-1",
			Verb:             "create",
			Resource:         "clusterroles",
		},
		{
			KubernetesUser:   "regular-user",
			KubernetesGroups: []string{"regular-group"},
			SessionID:        "escalation-session-2",
			Verb:             "update",
			Resource:         "rolebindings",
			Namespace:        "kube-system",
		},
	}

	for _, request := range escalationAttempts {
		response, err := suite.validator.ValidatePermission(suite.ctx, request)
		suite.Require().NoError(err)
		suite.Assert().False(response.Allowed, "Permission escalation should be denied")
		suite.Assert().Contains(response.Reason, "escalation denied")
	}
}

// Run the test suite
func TestRBACValidatorSuite(t *testing.T) {
	suite.Run(t, new(RBACValidatorTestSuite))
}

// Unit tests for specific functions

// TestNewRBACValidator tests validator creation
func TestNewRBACValidator(t *testing.T) {
	tests := []struct {
		name      string
		config    RBACValidatorConfig
		shouldErr bool
		errMsg    string
	}{
		{
			name: "valid config",
			config: RBACValidatorConfig{
				KubeConfig:    &rest.Config{},
				EnableCaching: true,
				CacheTTL:      time.Minute,
			},
			shouldErr: false,
		},
		{
			name: "missing kube config",
			config: RBACValidatorConfig{
				EnableCaching: true,
			},
			shouldErr: true,
			errMsg:    "kubernetes configuration is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := NewRBACValidator(tt.config)
			
			if tt.shouldErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
				assert.Nil(t, validator)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, validator)
				assert.NotNil(t, validator.metrics)
			}
		})
	}
}

// TestBuildCacheKey tests cache key generation
func TestBuildCacheKey(t *testing.T) {
	validator := &RBACValidator{
		cachePrefix: "test:rbac",
	}

	request := PermissionRequest{
		KubernetesUser:   "test-user",
		KubernetesGroups: []string{"group1", "group2"},
		Namespace:        "default",
		Verb:             "get",
		Resource:         "pods",
		ResourceName:     "test-pod",
	}

	expected := "test:rbac:test-user:group1,group2:default:get:pods:test-pod"
	actual := validator.buildCacheKey(request)
	assert.Equal(t, expected, actual)
}

// TestGeneratePermissionSuggestions tests suggestion generation
func TestGeneratePermissionSuggestions(t *testing.T) {
	validator := &RBACValidator{}

	request := PermissionRequest{
		Verb:      "get",
		Resource:  "pods",
		Namespace: "default",
	}

	status := authv1.SubjectAccessReviewStatus{
		Allowed: false,
		Reason:  "permission denied",
	}

	suggestions := validator.generatePermissionSuggestions(request, status)
	
	assert.NotEmpty(t, suggestions)
	assert.Contains(t, suggestions[0], "read access")
	assert.Contains(t, suggestions[0], "pods")
	assert.Contains(t, suggestions[0], "default")
}

// TestMetricsCollection tests metrics collection
func TestMetricsCollection(t *testing.T) {
	validator := &RBACValidator{
		metrics: &RBACValidationMetrics{
			MinLatency: time.Duration(^uint64(0) >> 1),
		},
	}

	// Test metric updates
	validator.recordAllowedValidation()
	validator.recordDeniedValidation()
	validator.recordCacheHit()
	validator.recordCacheMiss()
	validator.updateMetrics(50 * time.Millisecond)

	metrics := validator.GetMetrics()
	assert.Equal(t, int64(1), metrics.AllowedValidations)
	assert.Equal(t, int64(1), metrics.DeniedValidations)
	assert.Equal(t, int64(1), metrics.CacheHits)
	assert.Equal(t, int64(1), metrics.CacheMisses)
	assert.Equal(t, 50*time.Millisecond, metrics.AverageLatency)

	// Test cache hit ratio
	ratio := validator.GetCacheHitRatio()
	assert.Equal(t, 0.5, ratio) // 1 hit out of 2 total (1 hit + 1 miss)

	// Test performance targets
	targets := validator.IsPerformanceTarget()
	assert.True(t, targets["rbac_validation_under_100ms"])
	assert.True(t, targets["cache_hit_ratio_above_70"]) // Should be false with 50% ratio
}