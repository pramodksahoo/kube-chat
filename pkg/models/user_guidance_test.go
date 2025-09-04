// Package models provides user guidance and help system tests for KubeChat (Story 2.5)
package models

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserGuidanceService(t *testing.T) {
	contactInfo := &ContactInfo{
		AdminEmail:   "admin@example.com",
		SlackChannel: "#k8s-support",
	}

	config := UserGuidanceConfig{
		ContactInfo:          contactInfo,
		DocumentationBaseURL: "https://docs.example.com",
		EnableSelfService:    true,
		DefaultApprovers:     []string{"admin", "team-lead"},
	}

	service := NewUserGuidanceService(config)

	assert.NotNil(t, service)
	assert.Equal(t, contactInfo, service.contactInfo)
	assert.NotEmpty(t, service.operationPatterns)
	assert.NotEmpty(t, service.documentationLinks)
	assert.NotNil(t, service.templates)

	// Verify default operations were loaded
	assert.Contains(t, service.operationPatterns, "list_pods")
	assert.Contains(t, service.operationPatterns, "create_deployment")
	assert.Contains(t, service.operationPatterns, "delete_pod")
}

func TestParseOperation(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	tests := []struct {
		input    string
		expected string
	}{
		{
			input:    "show me all pods",
			expected: "list_pods",
		},
		{
			input:    "list pods in default namespace",
			expected: "list_pods",
		},
		{
			input:    "create a deployment",
			expected: "create_deployment",
		},
		{
			input:    "deploy my application",
			expected: "create_deployment",
		},
		{
			input:    "delete that pod",
			expected: "delete_pod",
		},
		{
			input:    "remove the failing pod",
			expected: "delete_pod",
		},
		{
			input:    "get logs from pod",
			expected: "get_logs",
		},
		{
			input:    "show pod logs",
			expected: "get_logs",
		},
		{
			input:    "describe the service",
			expected: "describe_resource",
		},
		{
			input:    "scale deployment to 3 replicas",
			expected: "scale_deployment",
		},
		{
			input:    "some random command that doesn't match",
			expected: "general",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := service.parseOperation(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetOperationGuidance(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	tests := []struct {
		name           string
		input          string
		expectedOp     string
		shouldHavePerms bool
	}{
		{
			name:           "list pods operation",
			input:          "show me all pods",
			expectedOp:     "list_pods",
			shouldHavePerms: true,
		},
		{
			name:           "create deployment operation",
			input:          "create a deployment",
			expectedOp:     "create_deployment", 
			shouldHavePerms: true,
		},
		{
			name:           "unknown operation",
			input:          "some unknown command",
			expectedOp:     "general",
			shouldHavePerms: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guidance, err := service.GetOperationGuidance(tt.input)
			require.NoError(t, err)
			require.NotNil(t, guidance)

			assert.Equal(t, tt.expectedOp, guidance.Operation)
			assert.NotEmpty(t, guidance.Description)
			
			if tt.shouldHavePerms {
				assert.NotEmpty(t, guidance.RequiredPermissions)
			}
			
			assert.NotEmpty(t, guidance.Alternatives)
		})
	}
}

func TestGenerateContextualHelp(t *testing.T) {
	contactInfo := &ContactInfo{
		AdminEmail:   "admin@example.com",
		SlackChannel: "#k8s-support",
	}

	service := NewUserGuidanceService(UserGuidanceConfig{
		ContactInfo: contactInfo,
	})

	// Create a sample permission error
	permError := NewPermissionErrorBuilder().
		WithBasicInfo("POD_LIST_DENIED", "Permission denied").
		WithPermissionContext("pods", "list", "default", false).
		WithUserContext("testuser", "test.user", []string{"developers"}, []string{"dev", "staging"}, false).
		WithNaturalLanguageContext("show me all pods", "list pods in default namespace").
		WithCategory(PermissionCategoryResourceAccess).
		Build()

	help := service.GenerateContextualHelp(permError)

	require.NotNil(t, help)
	assert.Equal(t, permError, help.ErrorContext)
	assert.NotEmpty(t, help.Explanations)
	assert.NotEmpty(t, help.NextSteps)
	assert.NotEmpty(t, help.LearningResources)
	assert.NotEmpty(t, help.SelfServiceOptions)
	assert.WithinDuration(t, time.Now(), help.Timestamp, time.Second)
	assert.Equal(t, permError.CorrelationID, help.SessionID)

	// Verify operation guidance was found
	assert.NotNil(t, help.OperationGuidance)
	assert.Equal(t, "list_pods", help.OperationGuidance.Operation)
}

func TestGenerateExplanations(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	tests := []struct {
		name              string
		setupError        func() *PermissionError
		expectedPatterns  []string
	}{
		{
			name: "with operation context",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithNaturalLanguageContext("show pods", "list pods").
					WithCategory(PermissionCategoryResourceAccess).
					Build()
			},
			expectedPatterns: []string{"tried to list pods", "don't have the required permissions"},
		},
		{
			name: "with resource and verb context",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithPermissionContext("deployments", "create", "production", false).
					WithCategory(PermissionCategoryResourceAccess).
					Build()
			},
			expectedPatterns: []string{"need permission to 'create' 'deployments'", "production"},
		},
		{
			name: "namespace access category",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithCategory(PermissionCategoryNamespaceAccess).
					Build()
			},
			expectedPatterns: []string{"namespace-level permission issue", "access to other namespaces"},
		},
		{
			name: "cluster access category",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithCategory(PermissionCategoryClusterAccess).
					Build()
			},
			expectedPatterns: []string{"cluster-level permissions", "typically restricted"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permError := tt.setupError()
			explanations := service.generateExplanations(permError)

			require.NotEmpty(t, explanations)

			explanationText := strings.Join(explanations, " ")
			for _, pattern := range tt.expectedPatterns {
				assert.Contains(t, strings.ToLower(explanationText), strings.ToLower(pattern))
			}
		})
	}
}

func TestGenerateNextSteps(t *testing.T) {
	contactInfo := &ContactInfo{
		AdminEmail: "admin@example.com",
	}

	service := NewUserGuidanceService(UserGuidanceConfig{
		ContactInfo: contactInfo,
	})

	alternatives := []AlternativeAction{
		{Title: "Try different namespace", Description: "Use another namespace", Difficulty: "easy"},
	}

	permError := NewPermissionErrorBuilder().
		WithPermissionContext("pods", "list", "default", false).
		WithAlternativeActions(alternatives).
		Build()

	steps := service.generateNextSteps(permError)

	require.Len(t, steps, 3) // verify, alternatives, contact

	// Verify first step is permission check
	assert.Contains(t, steps[0].Step, "current permissions")
	assert.Equal(t, "high", steps[0].Priority)
	assert.Contains(t, steps[0].Actions[0], "kubectl auth can-i")

	// Verify alternative step
	assert.Contains(t, steps[1].Step, "alternative")
	assert.Equal(t, "medium", steps[1].Priority)

	// Verify contact step
	assert.Contains(t, steps[2].Step, "administrator")
	assert.Equal(t, "medium", steps[2].Priority)
}

func TestGenerateSelfServiceOptions(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	tests := []struct {
		name            string
		setupError      func() *PermissionError
		expectedOptions int
		shouldHaveNS    bool
		shouldHaveAlt   bool
	}{
		{
			name: "with multiple allowed namespaces",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithPermissionContext("pods", "list", "production", false).
					WithUserContext("user", "test.user", []string{}, []string{"dev", "staging", "production"}, false).
					Build()
			},
			expectedOptions: 2, // namespace option + request option
			shouldHaveNS:    true,
		},
		{
			name: "with easy alternatives",
			setupError: func() *PermissionError {
				alternatives := []AlternativeAction{
					{Title: "Easy option", Description: "This is easy", Difficulty: "easy", Commands: []string{"kubectl get pods"}},
				}
				return NewPermissionErrorBuilder().
					WithAlternativeActions(alternatives).
					Build()
			},
			expectedOptions: 2, // alternative option + request option
			shouldHaveAlt:    true,
		},
		{
			name: "minimal options",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithPermissionContext("pods", "list", "default", false).
					WithUserContext("user", "test.user", []string{}, []string{"default"}, false).
					Build()
			},
			expectedOptions: 1, // just request option
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permError := tt.setupError()
			options := service.generateSelfServiceOptions(permError)

			assert.Len(t, options, tt.expectedOptions)

			if tt.shouldHaveNS {
				hasNSOption := false
				for _, opt := range options {
					if strings.Contains(strings.ToLower(opt.Title), "namespace") {
						hasNSOption = true
						break
					}
				}
				assert.True(t, hasNSOption, "Expected namespace option")
			}

			if tt.shouldHaveAlt {
				hasAltOption := false
				for _, opt := range options {
					if len(opt.Actions) > 0 && strings.Contains(opt.Actions[0], "kubectl") {
						hasAltOption = true
						break
					}
				}
				assert.True(t, hasAltOption, "Expected alternative option")
			}

			// Always should have request option
			hasRequestOption := false
			for _, opt := range options {
				if strings.Contains(strings.ToLower(opt.Title), "request") {
					hasRequestOption = true
					break
				}
			}
			assert.True(t, hasRequestOption, "Expected request option")
		})
	}
}

func TestCreateSelfServiceWorkflow(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	permError := NewPermissionErrorBuilder().
		WithBasicInfo("TEST_ERROR", "Test error").
		WithNaturalLanguageContext("show pods", "list pods").
		WithCategory(PermissionCategoryResourceAccess).
		Build()

	workflow := service.CreateSelfServiceWorkflow(permError)

	require.NotNil(t, workflow)
	assert.Contains(t, workflow.ID, permError.ID)
	assert.NotEmpty(t, workflow.Title)
	assert.NotEmpty(t, workflow.Description)
	assert.Contains(t, workflow.Description, "list pods")
	assert.NotEmpty(t, workflow.Steps)
	assert.NotEmpty(t, workflow.RequiredApprovals)
	assert.NotEmpty(t, workflow.EstimatedTime)
	assert.Equal(t, "semi-automated", workflow.AutomationLevel)
}

func TestGenerateWorkflowSteps(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	permError := NewPermissionErrorBuilder().
		WithNaturalLanguageContext("show pods", "list pods").
		Build()

	steps := service.generateWorkflowSteps(permError)

	require.Len(t, steps, 3)

	// Step 1: Business justification
	assert.Equal(t, 1, steps[0].StepNumber)
	assert.Contains(t, steps[0].Title, "permission request")
	assert.Equal(t, "user_input", steps[0].Action)
	assert.True(t, steps[0].Validation.Required)
	assert.Contains(t, steps[0].Parameters["placeholder"], "list pods")

	// Step 2: Duration
	assert.Equal(t, 2, steps[1].StepNumber)
	assert.Contains(t, steps[1].Title, "long")
	assert.Equal(t, "user_input", steps[1].Action)
	assert.True(t, steps[1].Validation.Required)

	// Step 3: Review
	assert.Equal(t, 3, steps[2].StepNumber)
	assert.Contains(t, steps[2].Title, "Review")
	assert.Equal(t, "automated", steps[2].Action)
}

func TestGenerateApprovalRequirements(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	tests := []struct {
		name                  string
		category              PermissionErrorCategory
		expectedRequirements  int
		expectedApproverType  string
	}{
		{
			name:                 "cluster access requires cluster-admin",
			category:             PermissionCategoryClusterAccess,
			expectedRequirements: 1,
			expectedApproverType: "cluster-admin",
		},
		{
			name:                 "resource access requires namespace admin",
			category:             PermissionCategoryResourceAccess,
			expectedRequirements: 1,
			expectedApproverType: "namespace-admin",
		},
		{
			name:                 "other categories require team approval",
			category:             PermissionCategoryNamespaceAccess,
			expectedRequirements: 1,
			expectedApproverType: "devops-team",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permError := NewPermissionErrorBuilder().
				WithCategory(tt.category).
				Build()

			requirements := service.generateApprovalRequirements(permError)

			assert.Len(t, requirements, tt.expectedRequirements)
			if len(requirements) > 0 {
				assert.Contains(t, requirements[0].Identifier, tt.expectedApproverType)
				assert.NotEmpty(t, requirements[0].Timeout)
			}
		})
	}
}

func TestDefaultTemplates(t *testing.T) {
	templates := getDefaultTemplates()

	require.NotNil(t, templates)
	assert.NotEmpty(t, templates.PermissionDenied)
	assert.NotEmpty(t, templates.NamespaceAccessDenied)
	assert.NotEmpty(t, templates.ClusterAccessDenied)
	assert.NotEmpty(t, templates.ResourceNotFound)
	assert.NotEmpty(t, templates.InsufficientPrivileges)

	// Verify templates contain helpful content
	assert.Contains(t, templates.PermissionDenied, "don't have permission")
	assert.Contains(t, templates.ClusterAccessDenied, "cluster-level")
	assert.Contains(t, templates.NamespaceAccessDenied, "namespace")
}

func TestOperationDifficulty(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	// Test that operations have appropriate difficulty levels
	listPods := service.operationPatterns["list_pods"]
	assert.Equal(t, "beginner", listPods.Difficulty)

	createDeployment := service.operationPatterns["create_deployment"]
	assert.Equal(t, "intermediate", createDeployment.Difficulty)

	deletePod := service.operationPatterns["delete_pod"]
	assert.Equal(t, "intermediate", deletePod.Difficulty)
}

func TestDocumentationLinks(t *testing.T) {
	baseURL := "https://docs.example.com"
	service := NewUserGuidanceService(UserGuidanceConfig{
		DocumentationBaseURL: baseURL,
	})

	require.NotEmpty(t, service.documentationLinks)

	// Check that custom base URL is used
	hasCustomLink := false
	for _, link := range service.documentationLinks {
		if strings.Contains(link.URL, baseURL) {
			hasCustomLink = true
			break
		}
	}
	assert.True(t, hasCustomLink, "Expected to find link with custom base URL")

	// Verify link types
	hasReference := false
	hasTutorial := false
	hasTroubleshooting := false

	for _, link := range service.documentationLinks {
		switch link.Type {
		case "reference":
			hasReference = true
		case "tutorial":
			hasTutorial = true
		case "troubleshooting":
			hasTroubleshooting = true
		}
	}

	assert.True(t, hasReference, "Expected reference documentation")
	assert.True(t, hasTutorial, "Expected tutorial documentation")
	assert.True(t, hasTroubleshooting, "Expected troubleshooting documentation")
}

func TestStepValidation(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	permError := NewPermissionErrorBuilder().Build()
	steps := service.generateWorkflowSteps(permError)

	// Check validation on first step
	firstStep := steps[0]
	require.NotNil(t, firstStep.Validation)
	assert.True(t, firstStep.Validation.Required)
	assert.Equal(t, 20, firstStep.Validation.MinLength)
	assert.NotEmpty(t, firstStep.Validation.ErrorMessage)

	// Check validation on second step
	secondStep := steps[1]
	require.NotNil(t, secondStep.Validation)
	assert.True(t, secondStep.Validation.Required)
	assert.NotEmpty(t, secondStep.Validation.AllowedValues)
	assert.Contains(t, secondStep.Validation.AllowedValues, "1 hour")
	assert.Contains(t, secondStep.Validation.AllowedValues, "Permanent")
}

func TestContextualHelpSessionTracking(t *testing.T) {
	service := NewUserGuidanceService(UserGuidanceConfig{})

	permError := NewPermissionErrorBuilder().
		WithBasicInfo("TEST", "Test error").
		Build()

	help := service.GenerateContextualHelp(permError)

	// Verify session tracking
	assert.Equal(t, permError.CorrelationID, help.SessionID)
	assert.WithinDuration(t, time.Now(), help.Timestamp, time.Second)
	assert.Equal(t, permError, help.ErrorContext)
}