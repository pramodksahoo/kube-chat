// Package models provides structured permission error handling tests for KubeChat (Story 2.5)
package models

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissionErrorBuilder(t *testing.T) {
	tests := []struct {
		name           string
		setupBuilder   func() *PermissionErrorBuilder
		expectedFields map[string]interface{}
	}{
		{
			name: "basic permission error creation",
			setupBuilder: func() *PermissionErrorBuilder {
				return NewPermissionErrorBuilder().
					WithBasicInfo("RBAC_PERMISSION_DENIED", "Permission denied for resource access").
					WithPermissionContext("pods", "list", "default", false).
					WithUserContext("user123", "john.doe", []string{"dev-team"}, []string{"default"}, false).
					WithCategory(PermissionCategoryResourceAccess)
			},
			expectedFields: map[string]interface{}{
				"code":           "RBAC_PERMISSION_DENIED",
				"message":        "Permission denied for resource access",
				"resource":       "pods",
				"verb":           "list",
				"namespace":      "default",
				"cluster_scoped": false,
				"user_id":        "user123",
				"category":       PermissionCategoryResourceAccess,
				"severity":       ErrorSeverityLow,
				"recoverable":    true,
			},
		},
		{
			name: "cluster-level permission error",
			setupBuilder: func() *PermissionErrorBuilder {
				return NewPermissionErrorBuilder().
					WithBasicInfo("CLUSTER_ACCESS_DENIED", "Cluster access denied").
					WithPermissionContext("nodes", "list", "", true).
					WithUserContext("user456", "jane.smith", []string{"operators"}, []string{}, true).
					WithCategory(PermissionCategoryClusterAccess)
			},
			expectedFields: map[string]interface{}{
				"code":           "CLUSTER_ACCESS_DENIED",
				"resource":       "nodes",
				"verb":           "list",
				"cluster_scoped": true,
				"category":       PermissionCategoryClusterAccess,
				"severity":       ErrorSeverityHigh,
				"escalation_level": EscalationLevelHigh,
			},
		},
		{
			name: "natural language context error",
			setupBuilder: func() *PermissionErrorBuilder {
				return NewPermissionErrorBuilder().
					WithBasicInfo("NL_OPERATION_DENIED", "Natural language operation denied").
					WithNaturalLanguageContext("show me all pods in production", "list pods in production namespace").
					WithPermissionContext("pods", "list", "production", false).
					WithCategory(PermissionCategoryNamespaceAccess)
			},
			expectedFields: map[string]interface{}{
				"original_input":      "show me all pods in production",
				"attempted_operation": "list pods in production namespace",
				"resource":           "pods",
				"namespace":          "production",
				"category":           PermissionCategoryNamespaceAccess,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := tt.setupBuilder()
			permError := builder.Build()

			// Verify basic structure
			assert.NotEmpty(t, permError.ID)
			assert.NotEmpty(t, permError.CorrelationID)
			assert.WithinDuration(t, time.Now(), permError.Timestamp, time.Second)

			// Verify expected fields
			for field, expected := range tt.expectedFields {
				switch field {
				case "code":
					assert.Equal(t, expected, permError.Code)
				case "message":
					assert.Equal(t, expected, permError.Message)
				case "resource":
					assert.Equal(t, expected, permError.Resource)
				case "verb":
					assert.Equal(t, expected, permError.Verb)
				case "namespace":
					assert.Equal(t, expected, permError.Namespace)
				case "cluster_scoped":
					assert.Equal(t, expected, permError.ClusterScoped)
				case "user_id":
					assert.Equal(t, expected, permError.UserID)
				case "category":
					assert.Equal(t, expected, permError.Category)
				case "severity":
					assert.Equal(t, expected, permError.Severity)
				case "recoverable":
					assert.Equal(t, expected, permError.Recoverable)
				case "escalation_level":
					assert.Equal(t, expected, permError.EscalationLevel)
				case "original_input":
					assert.Equal(t, expected, permError.OriginalInput)
				case "attempted_operation":
					assert.Equal(t, expected, permError.AttemptedOperation)
				}
			}
		})
	}
}

func TestPermissionErrorGuidance(t *testing.T) {
	tests := []struct {
		name                    string
		setupPermError          func() *PermissionError
		expectedGuidanceContent []string
		expectedPermissions     int
		expectedAlternatives    int
	}{
		{
			name: "comprehensive guidance for pod access",
			setupPermError: func() *PermissionError {
				requiredPerms := []RequiredPermission{
					{
						Resource:    "pods",
						Verb:        "list",
						Namespace:   "default",
						APIGroup:    "core/v1",
						Explanation: "Required to list pods in the namespace",
					},
				}

				alternatives := []AlternativeAction{
					{
						Title:       "Try a different namespace",
						Description: "You might have access to other namespaces",
						Difficulty:  "easy",
					},
					{
						Title:       "Request additional permissions",
						Description: "Contact your administrator for pod listing access",
						Difficulty:  "medium",
					},
				}

				return NewPermissionErrorBuilder().
					WithBasicInfo("POD_LIST_DENIED", "Cannot list pods").
					WithGuidance("You don't have permission to list pods in the default namespace", 
						[]string{"Check your available namespaces", "Contact administrator for access"}).
					WithRequiredPermissions(requiredPerms).
					WithAlternativeActions(alternatives).
					Build()
			},
			expectedGuidanceContent: []string{"don't have permission", "list pods", "default namespace"},
			expectedPermissions:     1,
			expectedAlternatives:    2,
		},
		{
			name: "admin guidance for role binding",
			setupPermError: func() *PermissionError {
				adminGuidance := &AdminGuidance{
					RoleBindingCommands: []string{
						"kubectl create rolebinding pod-reader --clusterrole=view --user=john.doe --namespace=default",
					},
					PolicyRecommendations: []string{
						"Consider using least-privilege principle",
						"Review existing role bindings before adding new ones",
					},
					SecurityConsiderations: "Ensure user only gets minimum required permissions",
				}

				return NewPermissionErrorBuilder().
					WithBasicInfo("BINDING_REQUIRED", "Role binding required").
					WithAdminGuidance(adminGuidance).
					Build()
			},
			expectedGuidanceContent: []string{},
			expectedPermissions:     0,
			expectedAlternatives:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permError := tt.setupPermError()

			// Test guidance content
			for _, content := range tt.expectedGuidanceContent {
				assert.Contains(t, permError.UserFriendlyMessage, content)
			}

			// Test permissions count
			assert.Len(t, permError.RequiredPermissions, tt.expectedPermissions)

			// Test alternatives count
			assert.Len(t, permError.AlternativeActions, tt.expectedAlternatives)

			// Test admin guidance if present
			if permError.AdminGuidance != nil {
				assert.NotEmpty(t, permError.AdminGuidance.RoleBindingCommands)
				assert.NotEmpty(t, permError.AdminGuidance.PolicyRecommendations)
			}
		})
	}
}

func TestPermissionErrorSerialization(t *testing.T) {
	// Create a comprehensive permission error
	permError := NewPermissionErrorBuilder().
		WithBasicInfo("COMPREHENSIVE_TEST", "Test error message").
		WithPermissionContext("deployments", "create", "production", false).
		WithUserContext("testuser", "test.user", []string{"developers"}, []string{"dev", "staging"}, false).
		WithNaturalLanguageContext("deploy my app to production", "create deployment in production").
		WithCategory(PermissionCategoryResourceAccess).
		WithGuidance("Comprehensive test guidance", []string{"Step 1", "Step 2"}).
		Build()

	// Test JSON serialization
	jsonData, err := permError.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Test deserialization
	var deserializedError PermissionError
	err = json.Unmarshal(jsonData, &deserializedError)
	require.NoError(t, err)

	// Verify key fields
	assert.Equal(t, permError.ID, deserializedError.ID)
	assert.Equal(t, permError.Code, deserializedError.Code)
	assert.Equal(t, permError.Resource, deserializedError.Resource)
	assert.Equal(t, permError.UserID, deserializedError.UserID)
	assert.Equal(t, permError.Category, deserializedError.Category)
}

func TestPermissionErrorUserFriendlyString(t *testing.T) {
	tests := []struct {
		name           string
		setupError     func() *PermissionError
		expectedItems  []string
		shouldNotContain []string
	}{
		{
			name: "comprehensive user-friendly format",
			setupError: func() *PermissionError {
				requiredPerms := []RequiredPermission{
					{Resource: "pods", Verb: "list", Namespace: "default", Explanation: "List pods"},
				}
				alternatives := []AlternativeAction{
					{Title: "Try different namespace", Description: "Check other accessible namespaces"},
				}
				contact := &ContactInfo{
					AdminEmail:   "admin@company.com",
					SlackChannel: "#k8s-support",
				}

				return NewPermissionErrorBuilder().
					WithBasicInfo("TEST_ERROR", "Test message").
					WithGuidance("You don't have the required permissions", 
						[]string{"Contact administrator", "Check your role bindings"}).
					WithRequiredPermissions(requiredPerms).
					WithAlternativeActions(alternatives).
					WithContactInfo(contact).
					Build()
			},
			expectedItems: []string{
				"❌", // Error emoji
				"🔧", // Action steps
				"🔑", // Required permissions
				"💡", // Alternative approaches
				"📞", // Contact info
				"🔍", // Reference ID
				"admin@company.com",
				"#k8s-support",
			},
		},
		{
			name: "minimal error format",
			setupError: func() *PermissionError {
				return NewPermissionErrorBuilder().
					WithBasicInfo("MINIMAL_ERROR", "Minimal test").
					Build()
			},
			expectedItems: []string{
				"❌", // Error emoji should always be present
				"🔍", // Reference ID should always be present
			},
			shouldNotContain: []string{
				"🔧", // No action steps
				"🔑", // No required permissions
				"💡", // No alternatives
				"📞", // No contact info
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permError := tt.setupError()
			friendlyString := permError.ToUserFriendlyString()

			// Check expected items
			for _, item := range tt.expectedItems {
				assert.Contains(t, friendlyString, item, "Expected item not found: %s", item)
			}

			// Check items that should not be present
			for _, item := range tt.shouldNotContain {
				assert.NotContains(t, friendlyString, item, "Unexpected item found: %s", item)
			}

			// Verify basic structure
			assert.Contains(t, friendlyString, permError.ID)
			assert.NotEmpty(t, friendlyString)
		})
	}
}

func TestPermissionErrorIntegration(t *testing.T) {
	// Test integration with existing Epic 1 error handling
	permError := NewPermissionErrorBuilder().
		WithBasicInfo("INTEGRATION_TEST", "Integration test error").
		WithPermissionContext("services", "delete", "kube-system", false).
		WithCategory(PermissionCategoryResourceAccess).
		Build()

	// Convert to KubectlError for Epic 1 integration
	kubectlError := permError.ToKubectlError()

	assert.NotNil(t, kubectlError)
	assert.Equal(t, ErrorTypePermissionDenied, kubectlError.Type)
	assert.Equal(t, "INTEGRATION_TEST", kubectlError.Code)
	assert.Equal(t, "services", kubectlError.Resource)
	assert.Equal(t, "kube-system", kubectlError.Namespace)
	assert.True(t, kubectlError.Recoverable)
	assert.False(t, kubectlError.RetryRecommended) // Permission errors don't benefit from retries
}

func TestPermissionErrorAuditTrail(t *testing.T) {
	builder := NewPermissionErrorBuilder().
		WithBasicInfo("AUDIT_TEST", "Test audit trail")

	// Add multiple audit entries
	permError := builder.
		AddAuditEntry("permission_check", "denied", "User lacks required permissions").
		AddAuditEntry("fallback_check", "attempted", "Checking alternative permissions").
		AddAuditEntry("error_generation", "completed", "Permission error created").
		Build()

	assert.Len(t, permError.AuditTrail, 3)
	
	// Verify audit entries are in chronological order
	for i := 1; i < len(permError.AuditTrail); i++ {
		assert.True(t, 
			permError.AuditTrail[i].Timestamp.After(permError.AuditTrail[i-1].Timestamp) ||
			permError.AuditTrail[i].Timestamp.Equal(permError.AuditTrail[i-1].Timestamp))
	}

	// Verify audit entry content
	assert.Equal(t, "permission_check", permError.AuditTrail[0].Action)
	assert.Equal(t, "denied", permError.AuditTrail[0].Result)
	assert.Contains(t, permError.AuditTrail[0].Details, "lacks required permissions")
}

func TestCategoryInference(t *testing.T) {
	tests := []struct {
		category              PermissionErrorCategory
		expectedSeverity      ErrorSeverity
		expectedEscalation    EscalationLevel
		expectedRecoverable   bool
	}{
		{
			category:            PermissionCategoryClusterAccess,
			expectedSeverity:    ErrorSeverityHigh,
			expectedEscalation:  EscalationLevelHigh,
			expectedRecoverable: true,
		},
		{
			category:            PermissionCategoryRoleBinding,
			expectedSeverity:    ErrorSeverityMedium,
			expectedEscalation:  EscalationLevelMedium,
			expectedRecoverable: true,
		},
		{
			category:            PermissionCategoryNamespaceAccess,
			expectedSeverity:    ErrorSeverityLow,
			expectedEscalation:  EscalationLevelLow,
			expectedRecoverable: true,
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			permError := NewPermissionErrorBuilder().
				WithCategory(tt.category).
				Build()

			assert.Equal(t, tt.expectedSeverity, permError.Severity)
			assert.Equal(t, tt.expectedEscalation, permError.EscalationLevel)
			assert.Equal(t, tt.expectedRecoverable, permError.Recoverable)
		})
	}
}

func TestCorrelationIDGeneration(t *testing.T) {
	// Test correlation ID generation
	id1 := generateCorrelationID()
	id2 := generateCorrelationID()

	assert.NotEqual(t, id1, id2, "Correlation IDs should be unique")
	assert.Contains(t, id1, "perm_", "Correlation ID should have proper prefix")
	assert.Contains(t, id2, "perm_", "Correlation ID should have proper prefix")

	// Test that builder sets correlation ID
	permError := NewPermissionErrorBuilder().Build()
	assert.NotEmpty(t, permError.CorrelationID)
	assert.Contains(t, permError.CorrelationID, "perm_")
}

func TestUserFriendlyMessageGeneration(t *testing.T) {
	tests := []struct {
		name            string
		setupBuilder    func() *PermissionErrorBuilder
		expectedContent []string
	}{
		{
			name: "with natural language context",
			setupBuilder: func() *PermissionErrorBuilder {
				return NewPermissionErrorBuilder().
					WithNaturalLanguageContext("show me pods", "list pods in default")
			},
			expectedContent: []string{"don't have permission to list pods", "show me pods"},
		},
		{
			name: "with resource and verb context",
			setupBuilder: func() *PermissionErrorBuilder {
				return NewPermissionErrorBuilder().
					WithPermissionContext("deployments", "create", "production", false)
			},
			expectedContent: []string{"don't have permission to create deployments", "production"},
		},
		{
			name: "minimal context",
			setupBuilder: func() *PermissionErrorBuilder {
				return NewPermissionErrorBuilder()
			},
			expectedContent: []string{"don't have sufficient permissions"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			permError := tt.setupBuilder().Build()

			for _, content := range tt.expectedContent {
				assert.Contains(t, strings.ToLower(permError.UserFriendlyMessage), 
					strings.ToLower(content))
			}
		})
	}
}