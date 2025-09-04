package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestNewMFAPolicyEngine(t *testing.T) {
	mockRedis := &MockRedisClient{}
	mockRedis.On("Keys", mock.Anything, "kubechat:mfa:policy:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
		cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
		cmd.SetVal([]string{})
		return cmd
	}(context.Background(), "kubechat:mfa:policy:*"))

	config := MFAPolicyEngineConfig{
		DefaultPolicy:         "default",
		PolicyRefreshInterval: 5 * time.Minute,
		EmergencyAccessEnabled: true,
		ComplianceLoggingEnabled: true,
		PolicyCacheTimeout:    1 * time.Hour,
	}

	engine := NewMFAPolicyEngine(mockRedis, config)
	
	assert.NotNil(t, engine)
	assert.Equal(t, config.DefaultPolicy, engine.config.DefaultPolicy)
	assert.Contains(t, engine.policies, "default") // Default policy should be created
	
	mockRedis.AssertExpectations(t)
}

func TestMFAPolicyEngine_CreatePolicy(t *testing.T) {
	mockRedis := &MockRedisClient{}
	mockRedis.On("Keys", mock.Anything, "kubechat:mfa:policy:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
		cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
		cmd.SetVal([]string{})
		return cmd
	}(context.Background(), "kubechat:mfa:policy:*"))
	
	mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))

	config := MFAPolicyEngineConfig{
		DefaultPolicy:      "default",
		PolicyCacheTimeout: 1 * time.Hour,
	}

	engine := NewMFAPolicyEngine(mockRedis, config)

	policy := &MFAPolicy{
		Name:                "test_policy",
		Description:         "Test MFA policy",
		Enabled:             true,
		Priority:            10,
		UserGroups:          []string{"admins", "developers"},
		KubernetesGroups:    []string{"system:masters"},
		RequireMFA:          true,
		AllowedMethods:      []MFAMethod{MFAMethodTOTP, MFAMethodSMS},
		MFAValidityDuration: 2 * time.Hour,
		StepUpOperations:    []string{"delete-namespace", "modify-rbac"},
		StepUpInterval:      15 * time.Minute,
		ConditionalMFA:      true,
		ComplianceRequired:  true,
		CreatedBy:           "admin@example.com",
	}

	err := engine.CreatePolicy(policy)
	assert.NoError(t, err)
	assert.Contains(t, engine.policies, "test_policy")
	
	storedPolicy := engine.policies["test_policy"]
	assert.Equal(t, policy.Name, storedPolicy.Name)
	assert.Equal(t, policy.Description, storedPolicy.Description)
	assert.Equal(t, policy.RequireMFA, storedPolicy.RequireMFA)
	assert.False(t, storedPolicy.CreatedAt.IsZero())
	assert.False(t, storedPolicy.UpdatedAt.IsZero())

	mockRedis.AssertExpectations(t)
}

func TestMFAPolicyEngine_EvaluatePolicy(t *testing.T) {
	tests := []struct {
		name              string
		policy            *MFAPolicy
		evalContext       PolicyEvaluationContext
		expectedDecision  func(*PolicyDecision)
	}{
		{
			name: "policy requires MFA for admin group",
			policy: &MFAPolicy{
				Name:                "admin_policy",
				Enabled:             true,
				Priority:            10,
				UserGroups:          []string{"admins"},
				RequireMFA:          true,
				AllowedMethods:      []MFAMethod{MFAMethodTOTP},
				MFAValidityDuration: 4 * time.Hour,
				ComplianceRequired:  true,
			},
			evalContext: PolicyEvaluationContext{
				UserID:            "admin1",
				Email:             "admin@example.com",
				UserGroups:        []string{"admins", "users"},
				Role:              "admin",
				RequestedOperation: "get-pods",
				TargetNamespace:   "default",
				Timestamp:         time.Now(),
			},
			expectedDecision: func(decision *PolicyDecision) {
				assert.True(decision.Allow)
				assert.True(decision.RequireMFA)
				assert.True(decision.ComplianceRequired)
				assert.Contains(decision.AllowedMethods, MFAMethodTOTP)
				assert.Contains(decision.AppliedPolicies, "admin_policy")
			},
		},
		{
			name: "policy requires step-up for high-risk operation",
			policy: &MFAPolicy{
				Name:             "stepup_policy",
				Enabled:          true,
				Priority:         5,
				UserGroups:       []string{"developers"},
				RequireMFA:       false,
				StepUpOperations: []string{"delete-namespace", "modify-rbac"},
				StepUpInterval:   10 * time.Minute,
			},
			evalContext: PolicyEvaluationContext{
				UserID:            "dev1",
				UserGroups:        []string{"developers"},
				RequestedOperation: "delete-namespace",
				TargetNamespace:   "test",
				Timestamp:         time.Now(),
			},
			expectedDecision: func(decision *PolicyDecision) {
				assert.True(decision.Allow)
				assert.True(decision.RequireStepUp)
				assert.Equal(10*time.Minute, decision.StepUpInterval)
				assert.Contains(decision.AppliedPolicies, "stepup_policy")
			},
		},
		{
			name: "policy with time window restriction",
			policy: &MFAPolicy{
				Name:     "time_restricted_policy",
				Enabled:  true,
				Priority: 8,
				UserGroups: []string{"contractors"},
				RequireMFA: true,
				ActiveHours: &TimeWindow{
					StartHour:  9,
					EndHour:    17,
					DaysOfWeek: []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
					TimeZone:   "UTC",
				},
			},
			evalContext: PolicyEvaluationContext{
				UserID:     "contractor1",
				UserGroups: []string{"contractors"},
				Timestamp:  time.Date(2023, 12, 15, 10, 0, 0, 0, time.UTC), // Friday 10 AM
			},
			expectedDecision: func(decision *PolicyDecision) {
				assert.True(decision.Allow)
				assert.True(decision.RequireMFA)
			},
		},
		{
			name: "policy denies access outside time window",
			policy: &MFAPolicy{
				Name:     "time_restricted_policy",
				Enabled:  true,
				Priority: 8,
				UserGroups: []string{"contractors"},
				RequireMFA: true,
				ActiveHours: &TimeWindow{
					StartHour:  9,
					EndHour:    17,
					DaysOfWeek: []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
					TimeZone:   "UTC",
				},
			},
			evalContext: PolicyEvaluationContext{
				UserID:     "contractor1",
				UserGroups: []string{"contractors"},
				Timestamp:  time.Date(2023, 12, 16, 10, 0, 0, 0, time.UTC), // Saturday 10 AM
			},
			expectedDecision: func(decision *PolicyDecision) {
				assert.False(decision.Allow)
				assert.Contains(decision.Reason, "time window")
			},
		},
		{
			name: "no applicable policy uses default",
			policy: &MFAPolicy{
				Name:               "default",
				Enabled:            true,
				Priority:           1,
				RequireMFA:         false,
				AllowEmergencyAccess: true,
				LogAllAccess:       true,
			},
			evalContext: PolicyEvaluationContext{
				UserID:            "user1",
				UserGroups:        []string{"regular_users"},
				RequestedOperation: "get-pods",
				Timestamp:         time.Now(),
			},
			expectedDecision: func(decision *PolicyDecision) {
				assert.True(decision.Allow)
				assert.False(decision.RequireMFA)
				assert.True(decision.EmergencyAccess)
				assert.Contains(decision.AppliedPolicies, "default")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRedis := &MockRedisClient{}
			mockRedis.On("Keys", mock.Anything, "kubechat:mfa:policy:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
				cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
				cmd.SetVal([]string{})
				return cmd
			}(context.Background(), "kubechat:mfa:policy:*"))

			config := MFAPolicyEngineConfig{
				DefaultPolicy:            "default",
				ComplianceLoggingEnabled: false, // Disable for testing
			}

			engine := NewMFAPolicyEngine(mockRedis, config)
			
			// Add the test policy
			engine.policies[tt.policy.Name] = tt.policy

			ctx := context.Background()
			decision, err := engine.EvaluatePolicy(ctx, tt.evalContext)
			
			require.NoError(t, err)
			require.NotNil(t, decision)
			
			tt.expectedDecision(decision)

			mockRedis.AssertExpectations(t)
		})
	}
}

func TestMFAPolicyEngine_findApplicablePolicies(t *testing.T) {
	engine := &MFAPolicyEngine{
		policies: make(map[string]*MFAPolicy),
	}

	// Create test policies with different criteria
	policies := []*MFAPolicy{
		{
			Name:           "high_priority",
			Priority:       100,
			UserGroups:     []string{"admins"},
			Enabled:        true,
		},
		{
			Name:           "medium_priority",
			Priority:       50,
			UserGroups:     []string{"admins", "developers"},
			Enabled:        true,
		},
		{
			Name:           "low_priority",
			Priority:       10,
			UserGroups:     []string{"users"},
			Enabled:        true,
		},
		{
			Name:           "disabled_policy",
			Priority:       200,
			UserGroups:     []string{"admins"},
			Enabled:        false, // This should not be returned
		},
		{
			Name:             "k8s_group_policy",
			Priority:         75,
			KubernetesGroups: []string{"system:masters"},
			Enabled:          true,
		},
	}

	for _, policy := range policies {
		engine.policies[policy.Name] = policy
	}

	evalContext := PolicyEvaluationContext{
		UserGroups:       []string{"admins", "developers"},
		KubernetesGroups: []string{"system:masters", "system:authenticated"},
	}

	applicable := engine.findApplicablePolicies(evalContext)

	// Should return policies in priority order (high to low)
	expectedNames := []string{"high_priority", "k8s_group_policy", "medium_priority"}
	
	assert.Len(t, applicable, len(expectedNames))
	for i, expectedName := range expectedNames {
		assert.Equal(t, expectedName, applicable[i].Name)
	}
}

func TestMFAPolicyEngine_policyMatches(t *testing.T) {
	engine := &MFAPolicyEngine{}

	tests := []struct {
		name        string
		policy      *MFAPolicy
		evalContext PolicyEvaluationContext
		expected    bool
	}{
		{
			name: "matches user group",
			policy: &MFAPolicy{
				UserGroups: []string{"admins", "developers"},
			},
			evalContext: PolicyEvaluationContext{
				UserGroups: []string{"developers", "testers"},
			},
			expected: true,
		},
		{
			name: "matches kubernetes group",
			policy: &MFAPolicy{
				KubernetesGroups: []string{"system:masters"},
			},
			evalContext: PolicyEvaluationContext{
				KubernetesGroups: []string{"system:masters", "system:authenticated"},
			},
			expected: true,
		},
		{
			name: "matches role",
			policy: &MFAPolicy{
				Roles: []string{"admin", "operator"},
			},
			evalContext: PolicyEvaluationContext{
				Role: "admin",
			},
			expected: true,
		},
		{
			name: "matches namespace",
			policy: &MFAPolicy{
				Namespaces: []string{"production", "staging"},
			},
			evalContext: PolicyEvaluationContext{
				TargetNamespace: "production",
			},
			expected: true,
		},
		{
			name: "matches wildcard namespace",
			policy: &MFAPolicy{
				Namespaces: []string{"*"},
			},
			evalContext: PolicyEvaluationContext{
				TargetNamespace: "any-namespace",
			},
			expected: true,
		},
		{
			name: "no match - different groups",
			policy: &MFAPolicy{
				UserGroups: []string{"admins"},
			},
			evalContext: PolicyEvaluationContext{
				UserGroups: []string{"users", "guests"},
			},
			expected: false,
		},
		{
			name: "empty policy matches all",
			policy: &MFAPolicy{
				// No criteria specified
			},
			evalContext: PolicyEvaluationContext{
				UserGroups: []string{"anything"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.policyMatches(tt.policy, tt.evalContext)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMFAPolicyEngine_isWithinTimeWindow(t *testing.T) {
	engine := &MFAPolicyEngine{}

	tests := []struct {
		name      string
		window    *TimeWindow
		timestamp time.Time
		expected  bool
	}{
		{
			name:      "nil window allows all times",
			window:    nil,
			timestamp: time.Now(),
			expected:  true,
		},
		{
			name: "within business hours on weekday",
			window: &TimeWindow{
				StartHour:  9,
				EndHour:    17,
				DaysOfWeek: []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
				TimeZone:   "UTC",
			},
			timestamp: time.Date(2023, 12, 18, 14, 0, 0, 0, time.UTC), // Monday 2 PM
			expected:  true,
		},
		{
			name: "outside business hours on weekday",
			window: &TimeWindow{
				StartHour:  9,
				EndHour:    17,
				DaysOfWeek: []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
				TimeZone:   "UTC",
			},
			timestamp: time.Date(2023, 12, 18, 19, 0, 0, 0, time.UTC), // Monday 7 PM
			expected:  false,
		},
		{
			name: "weekend not allowed",
			window: &TimeWindow{
				StartHour:  9,
				EndHour:    17,
				DaysOfWeek: []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
				TimeZone:   "UTC",
			},
			timestamp: time.Date(2023, 12, 16, 14, 0, 0, 0, time.UTC), // Saturday 2 PM
			expected:  false,
		},
		{
			name: "cross midnight hours",
			window: &TimeWindow{
				StartHour:  22,
				EndHour:    6,
				DaysOfWeek: []string{"monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"},
				TimeZone:   "UTC",
			},
			timestamp: time.Date(2023, 12, 18, 2, 0, 0, 0, time.UTC), // Monday 2 AM
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.isWithinTimeWindow(tt.window, tt.timestamp)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMFAPolicyEngine_isHighPrivilege(t *testing.T) {
	engine := &MFAPolicyEngine{}

	tests := []struct {
		name     string
		role     string
		groups   []string
		expected bool
	}{
		{
			name:     "admin role is high privilege",
			role:     "admin",
			groups:   []string{"users"},
			expected: true,
		},
		{
			name:     "cluster-admin role is high privilege",
			role:     "cluster-admin",
			groups:   []string{"users"},
			expected: true,
		},
		{
			name:     "system:masters group is high privilege",
			role:     "user",
			groups:   []string{"system:masters", "users"},
			expected: true,
		},
		{
			name:     "regular user is not high privilege",
			role:     "user",
			groups:   []string{"users", "developers"},
			expected: false,
		},
		{
			name:     "empty role and groups not high privilege",
			role:     "",
			groups:   []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.isHighPrivilege(tt.role, tt.groups)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestMFAPolicyEngine_UpdatePolicy(t *testing.T) {
	mockRedis := &MockRedisClient{}
	mockRedis.On("Keys", mock.Anything, "kubechat:mfa:policy:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
		cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
		cmd.SetVal([]string{})
		return cmd
	}(context.Background(), "kubechat:mfa:policy:*"))
	
	mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))

	config := MFAPolicyEngineConfig{
		DefaultPolicy:      "default",
		PolicyCacheTimeout: 1 * time.Hour,
	}

	engine := NewMFAPolicyEngine(mockRedis, config)

	// Create initial policy
	originalPolicy := &MFAPolicy{
		Name:        "test_policy",
		Description: "Original description",
		RequireMFA:  false,
		CreatedBy:   "admin@example.com",
	}
	
	err := engine.CreatePolicy(originalPolicy)
	require.NoError(t, err)

	// Update the policy
	updatedPolicy := &MFAPolicy{
		Name:        "test_policy",
		Description: "Updated description",
		RequireMFA:  true,
		AllowedMethods: []MFAMethod{MFAMethodTOTP, MFAMethodSMS},
	}

	err = engine.UpdatePolicy(updatedPolicy)
	assert.NoError(t, err)

	// Verify update
	storedPolicy := engine.policies["test_policy"]
	assert.Equal(t, "Updated description", storedPolicy.Description)
	assert.True(t, storedPolicy.RequireMFA)
	assert.Equal(t, originalPolicy.CreatedAt, storedPolicy.CreatedAt) // Should preserve creation time
	assert.True(t, storedPolicy.UpdatedAt.After(storedPolicy.CreatedAt)) // Should update timestamp

	mockRedis.AssertExpectations(t)
}

func TestMFAPolicyEngine_DeletePolicy(t *testing.T) {
	mockRedis := &MockRedisClient{}
	mockRedis.On("Keys", mock.Anything, "kubechat:mfa:policy:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
		cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
		cmd.SetVal([]string{})
		return cmd
	}(context.Background(), "kubechat:mfa:policy:*"))
	
	mockRedis.On("Set", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).Return(redis.NewStatusCmd(context.Background()))
	mockRedis.On("Del", mock.Anything, "kubechat:mfa:policy:test_policy").Return(func(ctx context.Context, key string) *redis.IntCmd {
		cmd := redis.NewIntCmd(ctx, "del", key)
		cmd.SetVal(1)
		return cmd
	}(context.Background(), "kubechat:mfa:policy:test_policy"))

	config := MFAPolicyEngineConfig{
		DefaultPolicy:      "default",
		PolicyCacheTimeout: 1 * time.Hour,
	}

	engine := NewMFAPolicyEngine(mockRedis, config)

	// Create a policy to delete
	policy := &MFAPolicy{
		Name:        "test_policy",
		Description: "Policy to delete",
	}
	
	err := engine.CreatePolicy(policy)
	require.NoError(t, err)
	assert.Contains(t, engine.policies, "test_policy")

	// Delete the policy
	err = engine.DeletePolicy("test_policy")
	assert.NoError(t, err)
	assert.NotContains(t, engine.policies, "test_policy")

	// Try to delete default policy (should fail)
	err = engine.DeletePolicy("default")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot delete default policy")

	mockRedis.AssertExpectations(t)
}

// Benchmark tests
func BenchmarkMFAPolicyEngine_EvaluatePolicy(b *testing.B) {
	mockRedis := &MockRedisClient{}
	mockRedis.On("Keys", mock.Anything, "kubechat:mfa:policy:*").Return(func(ctx context.Context, pattern string) *redis.StringSliceCmd {
		cmd := redis.NewStringSliceCmd(ctx, "keys", pattern)
		cmd.SetVal([]string{})
		return cmd
	}(context.Background(), "kubechat:mfa:policy:*"))

	config := MFAPolicyEngineConfig{
		DefaultPolicy:            "default",
		ComplianceLoggingEnabled: false,
	}

	engine := NewMFAPolicyEngine(mockRedis, config)

	// Add some test policies
	policies := []*MFAPolicy{
		{
			Name:       "admin_policy",
			Enabled:    true,
			Priority:   100,
			UserGroups: []string{"admins"},
			RequireMFA: true,
		},
		{
			Name:       "dev_policy", 
			Enabled:    true,
			Priority:   50,
			UserGroups: []string{"developers"},
			RequireMFA: false,
		},
		{
			Name:       "user_policy",
			Enabled:    true,
			Priority:   10,
			UserGroups: []string{"users"},
			RequireMFA: false,
		},
	}

	for _, policy := range policies {
		engine.policies[policy.Name] = policy
	}

	evalContext := PolicyEvaluationContext{
		UserID:            "test_user",
		UserGroups:        []string{"developers", "users"},
		RequestedOperation: "get-pods",
		Timestamp:         time.Now(),
	}

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := engine.EvaluatePolicy(ctx, evalContext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMFAPolicyEngine_findApplicablePolicies(b *testing.B) {
	engine := &MFAPolicyEngine{
		policies: make(map[string]*MFAPolicy),
	}

	// Create many test policies
	for i := 0; i < 100; i++ {
		policy := &MFAPolicy{
			Name:       fmt.Sprintf("policy_%d", i),
			Enabled:    true,
			Priority:   i,
			UserGroups: []string{fmt.Sprintf("group_%d", i%10)},
		}
		engine.policies[policy.Name] = policy
	}

	evalContext := PolicyEvaluationContext{
		UserGroups: []string{"group_5", "group_7"},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		engine.findApplicablePolicies(evalContext)
	}
}