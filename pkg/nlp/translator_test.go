package nlp

import (
	"context"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
)

// TestStory11Implementation verifies all Story 1.1 acceptance criteria
func TestStory11Implementation(t *testing.T) {
	translator := NewTranslatorService()

	// Story 1.1 target patterns with 90%+ accuracy requirement
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"show me all pods", "show me all pods", "kubectl get pods"},
		{"list pods in namespace default", "list pods in namespace default", "kubectl get pods -n default"},
		{"describe service nginx", "describe service nginx", "kubectl describe service nginx"},
		{"get deployments", "get deployments", "kubectl get deployments"},
		{"show nodes", "show nodes", "kubectl get nodes"},
		{"describe pod example-pod", "describe pod example-pod", "kubectl describe pod example-pod"},
		{"list namespaces", "list namespaces", "kubectl get namespaces"},
	}

	successCount := 0
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := translator.TranslateCommand(context.Background(), tc.input)

			if err == nil && result != nil && result.GeneratedCommand == tc.expected {
				successCount++
				assert.Equal(t, models.RiskLevelSafe, result.RiskLevel, "Should be safe read operation")
				assert.Equal(t, models.CommandStatusApproved, result.Status, "Should be auto-approved")
				assert.True(t, result.IsReadOnly(), "Should be read-only operation")
				assert.True(t, result.CanExecuteDirectly(), "Should be executable directly")
			} else {
				t.Logf("Failed: %s -> %v", tc.input, err)
			}
		})
	}

	// Story 1.1 AC5: System SHALL achieve 90%+ accuracy
	accuracy := float64(successCount) / float64(len(testCases)) * 100
	t.Logf("Story 1.1 Accuracy: %.1f%% (%d/%d)", accuracy, successCount, len(testCases))
	assert.GreaterOrEqual(t, accuracy, 90.0, "Must achieve 90%+ accuracy per Story 1.1 requirements")
}

// TestStory12WriteOperations verifies all Story 1.2 acceptance criteria for write operations
func TestStory12WriteOperations(t *testing.T) {
	translator := NewTranslatorService()

	// Story 1.2 write operation patterns with 90%+ accuracy requirement
	testCases := []struct {
		name           string
		input          string
		expectedCmd    string
		expectedRisk   models.RiskLevel
		expectedStatus models.CommandStatus
		expectedAction string
	}{
		{
			name:           "create deployment nginx",
			input:          "create deployment nginx",
			expectedCmd:    "kubectl create deployment nginx --image=nginx",
			expectedRisk:   models.RiskLevelCaution,
			expectedStatus: models.CommandStatusPendingApproval,
			expectedAction: "create",
		},
		{
			name:           "scale nginx to 5 replicas",
			input:          "scale nginx to 5 replicas",
			expectedCmd:    "kubectl scale deployment nginx --replicas=5",
			expectedRisk:   models.RiskLevelCaution,
			expectedStatus: models.CommandStatusPendingApproval,
			expectedAction: "update",
		},
		{
			name:           "delete pod nginx-123",
			input:          "delete pod nginx-123",
			expectedCmd:    "kubectl delete pod nginx-123",
			expectedRisk:   models.RiskLevelDestructive,
			expectedStatus: models.CommandStatusPendingApproval,
			expectedAction: "delete",
		},
		{
			name:           "delete deployment nginx",
			input:          "delete deployment nginx",
			expectedCmd:    "kubectl delete deployment nginx",
			expectedRisk:   models.RiskLevelDestructive,
			expectedStatus: models.CommandStatusPendingApproval,
			expectedAction: "delete",
		},
		{
			name:           "update service nginx",
			input:          "update service nginx",
			expectedCmd:    "kubectl patch service nginx --patch='{\"spec\":{\"type\":\"NodePort\"}}'",
			expectedRisk:   models.RiskLevelCaution,
			expectedStatus: models.CommandStatusPendingApproval,
			expectedAction: "update",
		},
		{
			name:           "apply manifest.yaml",
			input:          "apply manifest.yaml",
			expectedCmd:    "kubectl apply -f manifest.yaml",
			expectedRisk:   models.RiskLevelCaution,
			expectedStatus: models.CommandStatusPendingApproval,
			expectedAction: "create",
		},
	}

	successCount := 0
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := translator.TranslateCommand(context.Background(), tc.input)

			assert.NoError(t, err, "Should not return error for valid write operation")
			assert.NotNil(t, result, "Should return result for valid write operation")

			if result != nil {
				if result.GeneratedCommand == tc.expectedCmd &&
					result.RiskLevel == tc.expectedRisk &&
					result.Status == tc.expectedStatus {
					successCount++
				}

				// Story 1.2 AC1: System SHALL identify write/modify operations
				assert.Equal(t, tc.expectedCmd, result.GeneratedCommand, "Should generate correct kubectl command")
				assert.Equal(t, tc.expectedRisk, result.RiskLevel, "Should classify risk level correctly")
				assert.Equal(t, tc.expectedStatus, result.Status, "Should require approval for write operations")

				// Story 1.2 AC2: System SHALL display confirmation with exact operation
				assert.True(t, result.RequiresApproval(), "Write operations should require approval")
				assert.NotNil(t, result.ApprovalToken, "Should generate approval token")
				assert.NotNil(t, result.ApprovalExpiresAt, "Should set approval expiry")

				// Verify resource metadata for confirmation dialog
				assert.NotEmpty(t, result.Resources, "Should populate resource metadata")
				if len(result.Resources) > 0 {
					assert.Equal(t, tc.expectedAction, result.Resources[0].Action, "Should set correct action type")
				}
			}
		})
	}

	// Story 1.2 AC1: Must achieve 90%+ accuracy for write operations
	accuracy := float64(successCount) / float64(len(testCases)) * 100
	t.Logf("Story 1.2 Write Operations Accuracy: %.1f%% (%d/%d)", accuracy, successCount, len(testCases))
	assert.GreaterOrEqual(t, accuracy, 90.0, "Must achieve 90%+ accuracy per Story 1.2 requirements")
}

// TestConfirmationWorkflow tests the complete confirmation workflow
func TestConfirmationWorkflow(t *testing.T) {
	confirmationManager := NewConfirmationManager()

	// Create a write command that requires approval
	translator := NewTranslatorService()
	result, err := translator.TranslateCommand(context.Background(), "delete pod nginx-123")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, models.CommandStatusPendingApproval, result.Status)

	// Add to confirmation manager
	err = confirmationManager.AddPendingCommand(result)
	assert.NoError(t, err)

	// Save original token before confirmation
	originalToken := *result.ApprovalToken

	// Test confirmation with correct token
	confirmedCmd, err := confirmationManager.ConfirmCommand(result.ID, originalToken)
	assert.NoError(t, err)
	assert.NotNil(t, confirmedCmd)
	assert.Equal(t, models.CommandStatusApproved, confirmedCmd.Status)
	assert.Nil(t, confirmedCmd.ApprovalToken, "Token should be cleared after confirmation")

	// Test confirming already processed command
	_, err = confirmationManager.ConfirmCommand(result.ID, originalToken)
	assert.Error(t, err, "Should error when trying to confirm already processed command")
}

// TestCancellationWorkflow tests command cancellation
func TestCancellationWorkflow(t *testing.T) {
	confirmationManager := NewConfirmationManager()

	// Create a write command that requires approval
	translator := NewTranslatorService()
	result, err := translator.TranslateCommand(context.Background(), "scale nginx to 10 replicas")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Add to confirmation manager
	err = confirmationManager.AddPendingCommand(result)
	assert.NoError(t, err)

	// Test cancellation
	cancelledCmd, err := confirmationManager.CancelCommand(result.ID)
	assert.NoError(t, err)
	assert.NotNil(t, cancelledCmd)
	assert.Equal(t, models.CommandStatusCancelled, cancelledCmd.Status)

	// Test cancelling already processed command
	_, err = confirmationManager.CancelCommand(result.ID)
	assert.Error(t, err, "Should error when trying to cancel already processed command")
}

// TestTokenValidation tests approval token validation
func TestTokenValidation(t *testing.T) {
	confirmationManager := NewConfirmationManager()
	translator := NewTranslatorService()

	result, err := translator.TranslateCommand(context.Background(), "create deployment test")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	err = confirmationManager.AddPendingCommand(result)
	assert.NoError(t, err)

	// Test with invalid token
	_, err = confirmationManager.ConfirmCommand(result.ID, "invalid-token")
	assert.Error(t, err, "Should error with invalid token")

	// Test with correct token
	_, err = confirmationManager.ConfirmCommand(result.ID, *result.ApprovalToken)
	assert.NoError(t, err, "Should succeed with valid token")
}

// TestTimeoutHandling tests automatic cancellation after timeout
func TestTimeoutHandling(t *testing.T) {
	translator := NewTranslatorService()
	result, err := translator.TranslateCommand(context.Background(), "delete deployment nginx")
	assert.NoError(t, err)
	assert.NotNil(t, result)

	// Check that expiry is set (5 minutes from now)
	assert.NotNil(t, result.ApprovalExpiresAt, "Should set approval expiry")
	assert.True(t, result.ApprovalExpiresAt.After(result.CreatedAt), "Expiry should be after creation")

	// Test IsExpired method
	assert.False(t, result.IsExpired(), "Should not be expired immediately")

	// Test with expired command (simulate by setting past expiry)
	pastTime := time.Now().Add(-1 * time.Hour)
	result.ApprovalExpiresAt = &pastTime
	assert.True(t, result.IsExpired(), "Should be expired with past time")
}

// TestNegativeScenarios tests unauthorized operations and edge cases
func TestNegativeScenarios(t *testing.T) {
	translator := NewTranslatorService()

	negativeTests := []struct {
		name        string
		input       string
		expectError bool
	}{
		{"empty input", "", true},
		{"unsupported operation", "restart all services", true},
		{"malformed command", "create pod without name", true},
		{"random text", "this is just random text", true},
	}

	for _, tc := range negativeTests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := translator.TranslateCommand(context.Background(), tc.input)
			if tc.expectError {
				assert.Error(t, err, "Should return error for invalid input")
				assert.Nil(t, result, "Should not return result for invalid input")
			}
		})
	}
}

func TestErrorHandling(t *testing.T) {
	translator := NewTranslatorService()

	errorTests := []string{
		"",                         // Empty input
		"unsupported command here", // Unsupported operation
		"this is random text",      // Random text
	}

	for _, input := range errorTests {
		t.Run(input, func(t *testing.T) {
			result, err := translator.TranslateCommand(context.Background(), input)
			assert.Error(t, err, "Should return error for invalid input")
			assert.Nil(t, result, "Should not return result for invalid input")
		})
	}
}
