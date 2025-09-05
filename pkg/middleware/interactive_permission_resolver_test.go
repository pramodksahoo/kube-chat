// Package middleware provides interactive permission resolver tests for KubeChat (Story 2.5)
package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewInteractivePermissionResolver(t *testing.T) {
	kubeClient := fake.NewSimpleClientset()
	rbacContext := &EnhancedRBACContext{}
	advisor := &RBACAdvisor{}
	guidanceService := models.NewUserGuidanceService(models.UserGuidanceConfig{})
	auditLogger := &MockAuthAuditLogger{}

	config := ResolverConfig{
		EnableTesting:       true,
		EnableImpersonation: true,
		EnableSelfService:   true,
		WorkflowTimeout:     time.Hour,
		MaxRetries:          3,
		RequireApproval:     true,
	}

	resolver := NewInteractivePermissionResolver(
		kubeClient,
		nil, // no Redis for this test
		rbacContext,
		advisor,
		guidanceService,
		auditLogger,
		config,
	)

	assert.NotNil(t, resolver)
	assert.Equal(t, kubeClient, resolver.kubeClient)
	assert.Equal(t, rbacContext, resolver.rbacContext)
	assert.Equal(t, advisor, resolver.advisor)
	assert.Equal(t, guidanceService, resolver.guidanceService)
	assert.Equal(t, auditLogger, resolver.auditLogger)
	assert.Equal(t, config, resolver.config)
}

func TestStartInteractiveResolution(t *testing.T) {
	resolver := createTestResolver()
	
	userClaims := &JWTClaims{
		UserID:           "user123",
		KubernetesUser:   "test.user",
		KubernetesGroups: []string{"developers"},
		AllowedNamespaces: []string{"default"},
		ClusterAccess:    false,
	}

	permError := models.NewPermissionErrorBuilder().
		WithBasicInfo("TEST_ERROR", "Test permission error").
		WithPermissionContext("pods", "delete", "default", false).
		WithUserContext("user123", "test.user", []string{"developers"}, []string{"default"}, false).
		WithCategory(models.PermissionCategoryResourceAccess).
		Build()

	// Mock audit logger
	resolver.auditLogger.(*MockAuthAuditLogger).On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)

	session, err := resolver.StartInteractiveResolution(context.Background(), userClaims, permError)

	require.NoError(t, err)
	require.NotNil(t, session)

	// Verify session structure
	assert.NotEmpty(t, session.SessionID)
	assert.Contains(t, session.SessionID, "ires_")
	assert.Equal(t, userClaims, session.UserContext)
	assert.Equal(t, permError, session.OriginalError)
	assert.Equal(t, SessionStatusActive, session.Status)
	assert.WithinDuration(t, time.Now(), session.CreatedAt, time.Second)
	assert.WithinDuration(t, time.Now().Add(time.Hour), session.ExpiresAt, time.Second)

	// Verify workflow steps were generated
	assert.NotEmpty(t, session.WorkflowSteps)
	assert.Equal(t, 0, session.CurrentStep)

	// Verify step structure
	for i, step := range session.WorkflowSteps {
		assert.NotEmpty(t, step.StepID)
		assert.Equal(t, i+1, step.StepNumber)
		assert.NotEmpty(t, step.Title)
		assert.NotEmpty(t, step.Description)
		assert.Equal(t, StepStatusPending, step.Status)
	}

	// Verify first step is analysis
	assert.Equal(t, StepTypeAnalysis, session.WorkflowSteps[0].Type)
}

func TestGenerateWorkflowSteps(t *testing.T) {
	resolver := createTestResolver()

	userClaims := &JWTClaims{
		UserID: "user123",
	}

	permError := models.NewPermissionErrorBuilder().
		WithBasicInfo("TEST_ERROR", "Test error").
		Build()

	session := &InteractiveResolutionSession{
		SessionID:     "test-session",
		UserContext:   userClaims,
		OriginalError: permError,
	}

	steps, err := resolver.generateWorkflowSteps(context.Background(), session)

	require.NoError(t, err)
	require.NotEmpty(t, steps)

	// Verify step sequence
	expectedStepTypes := []ResolutionStepType{
		StepTypeAnalysis,
		StepTypeUserInput,
		StepTypePermissionTest, // Because testing is enabled
		StepTypeVerification,
	}

	require.Len(t, steps, len(expectedStepTypes))

	for i, expectedType := range expectedStepTypes {
		assert.Equal(t, expectedType, steps[i].Type)
		assert.Equal(t, i+1, steps[i].StepNumber)
		assert.Equal(t, StepStatusPending, steps[i].Status)
	}

	// Verify user input step has options
	userInputStep := steps[1] // Second step should be user input
	assert.NotEmpty(t, userInputStep.Options)
	
	optionIDs := make([]string, len(userInputStep.Options))
	for i, option := range userInputStep.Options {
		optionIDs[i] = option.ID
	}
	
	assert.Contains(t, optionIDs, "test")
	assert.Contains(t, optionIDs, "request")
	assert.Contains(t, optionIDs, "alternative")
}

func TestExecuteNextStep(t *testing.T) {
	resolver := createTestResolver()

	// Create a test session with steps
	session := &InteractiveResolutionSession{
		SessionID:   "test-session",
		UserContext: &JWTClaims{UserID: "user123"},
		OriginalError: models.NewPermissionErrorBuilder().
			WithBasicInfo("TEST", "Test error").
			WithPermissionContext("pods", "delete", "default", false).
			Build(),
		Status:      SessionStatusActive,
		CurrentStep: 0,
		WorkflowSteps: []ResolutionStep{
			{
				StepID:      "step1",
				StepNumber:  1,
				Type:        StepTypeAnalysis,
				Title:       "Analysis",
				Description: "Test analysis step",
				Status:      StepStatusPending,
			},
		},
		UpdatedAt: time.Now(),
	}

	// Mock Redis operations (session will be stored in memory for test)
	resolver.sessions = map[string]*InteractiveResolutionSession{
		"test-session": session,
	}

	userInput := map[string]interface{}{
		"test_input": "test_value",
	}

	updatedSession, err := resolver.ExecuteNextStep(context.Background(), "test-session", userInput)

	require.NoError(t, err)
	require.NotNil(t, updatedSession)

	// Verify step execution
	assert.Equal(t, 1, updatedSession.CurrentStep) // Should advance to next step
	assert.Equal(t, StepStatusCompleted, updatedSession.WorkflowSteps[0].Status)
	assert.NotNil(t, updatedSession.WorkflowSteps[0].ExecutedAt)
	assert.Greater(t, updatedSession.WorkflowSteps[0].Duration, time.Duration(0))
	assert.Equal(t, userInput, updatedSession.WorkflowSteps[0].UserInput)
}

func TestExecuteAnalysisStep(t *testing.T) {
	resolver := createTestResolver()

	session := &InteractiveResolutionSession{
		UserContext: &JWTClaims{
			KubernetesUser:   "test.user",
			KubernetesGroups: []string{"developers"},
		},
		OriginalError: models.NewPermissionErrorBuilder().
			WithPermissionContext("pods", "list", "default", false).
			WithNaturalLanguageContext("list pods", "list pods in default").
			Build(),
	}

	step := &ResolutionStep{
		Type:        StepTypeAnalysis,
		Status:      StepStatusActive,
		SystemOutput: make(map[string]interface{}),
	}

	err := resolver.executeAnalysisStep(context.Background(), session, step)

	// Should not error even without full RBAC context
	assert.NoError(t, err)
}

func TestExecuteUserInputStep(t *testing.T) {
	resolver := createTestResolver()

	session := &InteractiveResolutionSession{}

	tests := []struct {
		name        string
		userInput   map[string]interface{}
		shouldError bool
	}{
		{
			name: "valid option selected",
			userInput: map[string]interface{}{
				"selected_option": "test",
			},
			shouldError: false,
		},
		{
			name:        "no option selected",
			userInput:   map[string]interface{}{},
			shouldError: true,
		},
		{
			name: "invalid option type",
			userInput: map[string]interface{}{
				"selected_option": 123,
			},
			shouldError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			step := &ResolutionStep{
				Type:         StepTypeUserInput,
				Status:       StepStatusActive,
				UserInput:    tt.userInput,
				SystemOutput: make(map[string]interface{}),
			}

			err := resolver.executeUserInputStep(context.Background(), session, step)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, step.SystemOutput)
				assert.Contains(t, step.SystemOutput, "selected_approach")
			}
		})
	}
}

func TestExecutePermissionTestStep(t *testing.T) {
	tests := []struct {
		name          string
		enableTesting bool
		shouldError   bool
	}{
		{
			name:          "testing enabled",
			enableTesting: true,
			shouldError:   false,
		},
		{
			name:          "testing disabled",
			enableTesting: false,
			shouldError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := ResolverConfig{
				EnableTesting:       tt.enableTesting,
				EnableImpersonation: true,
			}

			resolver := NewInteractivePermissionResolver(
				fake.NewSimpleClientset(),
				nil,
				&EnhancedRBACContext{},
				&RBACAdvisor{},
				nil,
				&MockAuthAuditLogger{},
				config,
			)

			session := &InteractiveResolutionSession{
				UserContext: &JWTClaims{
					KubernetesUser: "test.user",
				},
				OriginalError: models.NewPermissionErrorBuilder().
					WithRequiredPermissions([]models.RequiredPermission{
						{Resource: "pods", Verb: "list", Namespace: "default"},
					}).
					Build(),
				TestResults: make([]PermissionTestResult, 0),
			}

			step := &ResolutionStep{
				Type:         StepTypePermissionTest,
				Status:       StepStatusActive,
				SystemOutput: make(map[string]interface{}),
			}

			err := resolver.executePermissionTestStep(context.Background(), session, step)

			if tt.shouldError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, step.SystemOutput)
				assert.Contains(t, step.SystemOutput, "tests_performed")
				assert.NotEmpty(t, session.TestResults)
			}
		})
	}
}

func TestTestPermissionWithRole(t *testing.T) {
	resolver := createTestResolver()

	permission := models.RequiredPermission{
		Resource:  "pods",
		Verb:      "list",
		Namespace: "default",
	}

	tests := []struct {
		name           string
		roleName       string
		expectedResult bool
	}{
		{
			name:           "view role allows list",
			roleName:       "view",
			expectedResult: true,
		},
		{
			name:           "view role denies delete",
			roleName:       "view",
			expectedResult: false, // Would be false for delete verb
		},
		{
			name:           "admin role allows everything",
			roleName:       "admin",
			expectedResult: true,
		},
		{
			name:           "unknown role denies",
			roleName:       "unknown",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Adjust permission verb for view role test
			testPermission := permission
			if tt.name == "view role denies delete" {
				testPermission.Verb = "delete"
			}

			result := resolver.testPermissionWithRole(context.Background(), tt.roleName, testPermission)

			assert.NotEmpty(t, result.TestID)
			assert.Equal(t, "impersonation", result.TestType)
			assert.Equal(t, fmt.Sprintf("role:%s", tt.roleName), result.TestedAs)
			assert.Equal(t, testPermission, result.Permission)
			assert.Equal(t, tt.expectedResult, result.Result)
			assert.NotEmpty(t, result.TestCommand)
			assert.WithinDuration(t, time.Now(), result.ExecutedAt, time.Second)
		})
	}
}

func TestTestPermissionAsUser(t *testing.T) {
	resolver := createTestResolver()

	permission := models.RequiredPermission{
		Resource:  "pods",
		Verb:      "list",
		Namespace: "default",
	}

	result := resolver.testPermissionAsUser(context.Background(), "test.user", permission)

	assert.NotEmpty(t, result.TestID)
	assert.Equal(t, "current", result.TestType)
	assert.Equal(t, "test.user", result.TestedAs)
	assert.Equal(t, permission, result.Permission)
	assert.Contains(t, result.TestCommand, "kubectl auth can-i")
	assert.Contains(t, result.TestCommand, "test.user")
	assert.Contains(t, result.TestCommand, "list pods")
	assert.WithinDuration(t, time.Now(), result.ExecutedAt, time.Second)
}

func TestSimulateRolePermission(t *testing.T) {
	resolver := createTestResolver()

	tests := []struct {
		name       string
		roleName   string
		permission models.RequiredPermission
		expected   bool
	}{
		{
			name:       "view role - get pods",
			roleName:   "view",
			permission: models.RequiredPermission{Verb: "get", Resource: "pods"},
			expected:   true,
		},
		{
			name:       "view role - delete pods",
			roleName:   "view",
			permission: models.RequiredPermission{Verb: "delete", Resource: "pods"},
			expected:   false,
		},
		{
			name:       "edit role - create pods",
			roleName:   "edit",
			permission: models.RequiredPermission{Verb: "create", Resource: "pods"},
			expected:   true,
		},
		{
			name:       "edit role - delete pods",
			roleName:   "edit",
			permission: models.RequiredPermission{Verb: "delete", Resource: "pods"},
			expected:   false,
		},
		{
			name:       "admin role - delete pods",
			roleName:   "admin",
			permission: models.RequiredPermission{Verb: "delete", Resource: "pods"},
			expected:   true,
		},
		{
			name:       "unknown role - get pods",
			roleName:   "unknown",
			permission: models.RequiredPermission{Verb: "get", Resource: "pods"},
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.simulateRolePermission(tt.roleName, tt.permission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCountSuccessfulTests(t *testing.T) {
	resolver := createTestResolver()

	testResults := []PermissionTestResult{
		{Result: true},
		{Result: false},
		{Result: true},
		{Result: false},
		{Result: true},
	}

	count := resolver.countSuccessfulTests(testResults)
	assert.Equal(t, 3, count)
}

func TestSummarizeTestResults(t *testing.T) {
	resolver := createTestResolver()

	tests := []struct {
		name        string
		results     []PermissionTestResult
		expectedMsg string
	}{
		{
			name:        "no successful tests",
			results:     []PermissionTestResult{{Result: false}, {Result: false}},
			expectedMsg: "No permissions found that would allow this operation",
		},
		{
			name:        "all successful tests",
			results:     []PermissionTestResult{{Result: true}, {Result: true}},
			expectedMsg: "All tested roles would allow this operation",
		},
		{
			name:        "partial successful tests",
			results:     []PermissionTestResult{{Result: true}, {Result: false}, {Result: true}},
			expectedMsg: "2 of 3 tested roles would allow this operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			summary := resolver.summarizeTestResults(tt.results)
			assert.Equal(t, tt.expectedMsg, summary)
		})
	}
}

func TestGenerateDynamicAlternatives(t *testing.T) {
	resolver := createTestResolver()

	testResults := []PermissionTestResult{
		{
			TestType: "impersonation",
			TestedAs: "role:view",
			Result:   true,
			Permission: models.RequiredPermission{Verb: "list", Resource: "pods"},
			TestCommand: "kubectl auth can-i list pods --as=role:view",
		},
		{
			TestType: "impersonation",
			TestedAs: "role:edit",
			Result:   false,
			Permission: models.RequiredPermission{Verb: "delete", Resource: "pods"},
		},
		{
			TestType: "current",
			TestedAs: "user123",
			Result:   false,
		},
	}

	userContext := &JWTClaims{UserID: "user123"}

	alternatives := resolver.generateDynamicAlternatives(testResults, userContext)

	// Should only include successful impersonation tests
	assert.Len(t, alternatives, 1)
	
	alt := alternatives[0]
	assert.Contains(t, alt.Title, "role:view")
	assert.Contains(t, alt.Description, "list operation")
	assert.Contains(t, alt.Commands, "kubectl auth can-i list pods --as=role:view")
	assert.Equal(t, "medium", alt.Difficulty)
}

func TestGenerateApprovalRequirements(t *testing.T) {
	resolver := createTestResolver()

	tests := []struct {
		name                    string
		category                models.PermissionErrorCategory
		expectedApproverType    string
		expectedTimeout         string
	}{
		{
			name:                 "cluster access requires cluster-admin",
			category:             models.PermissionCategoryClusterAccess,
			expectedApproverType: "cluster-admin",
			expectedTimeout:      "24h",
		},
		{
			name:                 "resource access requires namespace admin",
			category:             models.PermissionCategoryResourceAccess,
			expectedApproverType: "namespace-admins",
			expectedTimeout:      "4h",
		},
		{
			name:                 "other category requires team approval",
			category:             models.PermissionCategoryNamespaceAccess,
			expectedApproverType: "devops-team",
			expectedTimeout:      "2h",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requirements := resolver.generateApprovalRequirements(tt.category)
			
			require.NotEmpty(t, requirements)
			assert.Contains(t, requirements[0].Identifier, tt.expectedApproverType)
			assert.Equal(t, tt.expectedTimeout, requirements[0].Timeout)
		})
	}
}

func TestSessionManagement(t *testing.T) {
	resolver := createTestResolver()

	// Test session storage and retrieval (using memory for testing)
	session := &InteractiveResolutionSession{
		SessionID:   "test-session-123",
		Status:      SessionStatusActive,
		UserContext: &JWTClaims{UserID: "user123"},
		CreatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(time.Hour),
	}

	// Initialize memory storage for testing
	resolver.sessions = make(map[string]*InteractiveResolutionSession)
	resolver.sessions[session.SessionID] = session

	// Test retrieval
	retrieved, err := resolver.GetSession(context.Background(), "test-session-123")
	require.NoError(t, err)
	assert.Equal(t, session.SessionID, retrieved.SessionID)
	assert.Equal(t, session.Status, retrieved.Status)

	// Test non-existent session
	_, err = resolver.GetSession(context.Background(), "non-existent")
	assert.Error(t, err)
}

func TestCancelSession(t *testing.T) {
	resolver := createTestResolver()

	session := &InteractiveResolutionSession{
		SessionID: "test-session",
		Status:    SessionStatusActive,
		UpdatedAt: time.Now().Add(-time.Hour), // Old timestamp
	}

	// Initialize memory storage
	resolver.sessions = make(map[string]*InteractiveResolutionSession)
	resolver.sessions[session.SessionID] = session

	err := resolver.CancelSession(context.Background(), "test-session")
	require.NoError(t, err)

	// Verify session was cancelled
	updated, err := resolver.GetSession(context.Background(), "test-session")
	require.NoError(t, err)
	assert.Equal(t, SessionStatusCancelled, updated.Status)
	assert.True(t, updated.UpdatedAt.After(session.UpdatedAt))
}

// Helper function to create a test resolver
func createTestResolver() *InteractivePermissionResolver {
	config := ResolverConfig{
		EnableTesting:       true,
		EnableImpersonation: true,
		EnableSelfService:   true,
		WorkflowTimeout:     time.Hour,
		MaxRetries:          3,
		RequireApproval:     false, // Disable approval for simpler tests
	}

	resolver := NewInteractivePermissionResolver(
		fake.NewSimpleClientset(),
		nil, // No Redis for basic tests
		&EnhancedRBACContext{},
		&RBACAdvisor{},
		models.NewUserGuidanceService(models.UserGuidanceConfig{}),
		&MockAuthAuditLogger{},
		config,
	)

	// Add memory storage for testing (simulate Redis)
	resolver.sessions = make(map[string]*InteractiveResolutionSession)

	return resolver
}

// Add memory storage field to resolver for testing
type TestInteractivePermissionResolver struct {
	*InteractivePermissionResolver
	sessions map[string]*InteractiveResolutionSession
}

// Override session methods for testing
func (r *InteractivePermissionResolver) saveSessionToMemory(ctx context.Context, session *InteractiveResolutionSession) error {
	if r.sessions == nil {
		r.sessions = make(map[string]*InteractiveResolutionSession)
	}
	r.sessions[session.SessionID] = session
	return nil
}

func (r *InteractivePermissionResolver) getSessionFromMemory(ctx context.Context, sessionID string) (*InteractiveResolutionSession, error) {
	if r.sessions == nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	
	session, exists := r.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Check expiration
	if time.Now().After(session.ExpiresAt) {
		session.Status = SessionStatusExpired
		return session, fmt.Errorf("session has expired")
	}

	return session, nil
}

// Add memory storage field to resolver for testing purposes
var resolverSessions = make(map[string]*InteractiveResolutionSession)

// Override the resolver methods to use memory storage in tests
func (r *InteractivePermissionResolver) GetSession(ctx context.Context, sessionID string) (*InteractiveResolutionSession, error) {
	if r.redisClient == nil {
		// Use memory storage for testing
		session, exists := resolverSessions[sessionID]
		if !exists {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}

		if time.Now().After(session.ExpiresAt) {
			session.Status = SessionStatusExpired
			return session, fmt.Errorf("session has expired")
		}

		return session, nil
	}
	return r.getSession(ctx, sessionID)
}

func (r *InteractivePermissionResolver) CancelSession(ctx context.Context, sessionID string) error {
	if r.redisClient == nil {
		// Use memory storage for testing
		session, exists := resolverSessions[sessionID]
		if !exists {
			return fmt.Errorf("session not found: %s", sessionID)
		}

		session.Status = SessionStatusCancelled
		session.UpdatedAt = time.Now()
		resolverSessions[sessionID] = session
		return nil
	}

	session, err := r.getSession(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	session.Status = SessionStatusCancelled
	session.UpdatedAt = time.Now()

	return r.saveSession(ctx, session)
}