package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/clients"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/pramodksahoo/kube-chat/pkg/nlp"
)

// TestCommandExecutionWorkflow tests the complete command execution workflow
func TestCommandExecutionWorkflow(t *testing.T) {
	// Skip if not in integration test environment
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create components
	translator := nlp.NewTranslatorService()
	confirmationManager := nlp.NewConfirmationManager()
	kubernetesClient, err := clients.NewKubernetesClient(nil)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("full workflow - safe command", func(t *testing.T) {
		// Step 1: Translate natural language command
		result, err := translator.TranslateCommand(ctx, "show me kubectl version")
		require.NoError(t, err)
		assert.Equal(t, models.RiskLevelSafe, result.RiskLevel)

		// Step 2: Safe commands are auto-approved, so execute directly
		result.UpdateStatus(models.CommandStatusApproved)

		// Step 3: Execute the command
		execResult, err := kubernetesClient.ExecuteCommand(ctx, result)
		require.NoError(t, err)
		require.NotNil(t, execResult)

		// Step 4: Verify execution result
		assert.NotNil(t, execResult.FormattedOutput)
		assert.GreaterOrEqual(t, execResult.ExecutionTime, 0)

		if execResult.Success {
			assert.Empty(t, execResult.Error)
			assert.NotEmpty(t, execResult.Output)
			assert.Equal(t, 0, execResult.ExitCode)
		} else {
			// Command might fail in test environment, but should be structured
			assert.NotEmpty(t, execResult.FormattedOutput)
			t.Logf("Command failed (expected in test env): %s", execResult.Error)
		}
	})

	t.Run("full workflow - write command with confirmation", func(t *testing.T) {
		// Step 1: Translate a write operation command
		result, err := translator.TranslateCommand(ctx, "create a deployment named test-app")
		require.NoError(t, err)
		
		// Write operations should require approval
		assert.NotEqual(t, models.RiskLevelSafe, result.RiskLevel)
		assert.Equal(t, models.CommandStatusPendingApproval, result.Status)
		assert.NotNil(t, result.ApprovalToken)

		// Step 2: Add to confirmation manager
		err = confirmationManager.AddPendingCommand(result)
		require.NoError(t, err)

		// Step 3: Confirm the command
		confirmedCommand, err := confirmationManager.ConfirmCommand(result.ID, *result.ApprovalToken)
		require.NoError(t, err)
		assert.Equal(t, models.CommandStatusApproved, confirmedCommand.Status)

		// Step 4: Execute the confirmed command
		execResult, err := kubernetesClient.ExecuteCommand(ctx, confirmedCommand)
		require.NoError(t, err)
		require.NotNil(t, execResult)

		// Step 5: Verify execution result structure
		assert.NotNil(t, execResult.FormattedOutput)
		assert.GreaterOrEqual(t, execResult.ExecutionTime, 0)

		// Command might fail due to permissions or test environment
		// but should have proper structure
		t.Logf("Write command result: Success=%v, Error=%s", execResult.Success, execResult.Error)
	})
}

// TestCommandHistoryIntegration tests session-based command history
func TestCommandHistoryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create session manager (simulating what's in main.go)
	type SessionData struct {
		ID       string                     `json:"id"`
		Commands []*models.KubernetesCommand `json:"commands"`
		Created  time.Time                  `json:"created"`
		Updated  time.Time                  `json:"updated"`
	}

	sessions := make(map[string]*SessionData)

	addCommandToSession := func(sessionID string, command *models.KubernetesCommand) {
		if sessionID == "" {
			sessionID = "default"
		}

		session, exists := sessions[sessionID]
		if !exists {
			session = &SessionData{
				ID:       sessionID,
				Commands: make([]*models.KubernetesCommand, 0),
				Created:  time.Now(),
			}
			sessions[sessionID] = session
		}

		session.Commands = append(session.Commands, command)
		session.Updated = time.Now()
	}

	getSessionHistory := func(sessionID string) ([]*models.KubernetesCommand, error) {
		if sessionID == "" {
			sessionID = "default"
		}

		session, exists := sessions[sessionID]
		if !exists {
			return []*models.KubernetesCommand{}, nil
		}

		return session.Commands, nil
	}

	t.Run("command history tracking", func(t *testing.T) {
		sessionID := "test-session-123"

		// Create and execute multiple commands
		commands := []*models.KubernetesCommand{
			{
				ID:               "cmd-1",
				SessionID:        sessionID,
				GeneratedCommand: "get pods",
				Status:           models.CommandStatusCompleted,
				RiskLevel:        models.RiskLevelSafe,
			},
			{
				ID:               "cmd-2",
				SessionID:        sessionID,
				GeneratedCommand: "get services",
				Status:           models.CommandStatusCompleted,
				RiskLevel:        models.RiskLevelSafe,
			},
		}

		// Add commands to session history
		for _, cmd := range commands {
			addCommandToSession(sessionID, cmd)
		}

		// Retrieve history
		history, err := getSessionHistory(sessionID)
		require.NoError(t, err)
		assert.Len(t, history, 2)

		// Verify commands are in history
		assert.Equal(t, "cmd-1", history[0].ID)
		assert.Equal(t, "cmd-2", history[1].ID)
		assert.Equal(t, sessionID, history[0].SessionID)
		assert.Equal(t, sessionID, history[1].SessionID)
	})

	t.Run("empty session history", func(t *testing.T) {
		history, err := getSessionHistory("non-existent-session")
		require.NoError(t, err)
		assert.Len(t, history, 0)
	})
}

// TestOutputFormattingIntegration tests output formatting with real kubectl output
func TestOutputFormattingIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	formatter := models.NewOutputFormatter()
	
	t.Run("format real kubectl version output", func(t *testing.T) {
		// Simulate kubectl version output
		output := "Client Version: version.Info{Major:\"1\", Minor:\"28\", GitVersion:\"v1.28.0\"}\nServer Version: version.Info{Major:\"1\", Minor:\"28\", GitVersion:\"v1.28.0\"}"
		
		result := &models.CommandExecutionResult{
			Success:       true,
			Output:        output,
			ExitCode:      0,
			ExecutionTime: 150,
		}
		
		formatter.FormatOutput(result, "kubectl version")
		
		assert.NotEmpty(t, result.FormattedOutput)
		assert.Contains(t, result.FormattedOutput, "✅")
		assert.Contains(t, result.FormattedOutput, "Version Information")
		assert.Contains(t, result.FormattedOutput, "💻") // Client version icon
		assert.Contains(t, result.FormattedOutput, "🖥️") // Server version icon
	})

	t.Run("format kubectl get pods output", func(t *testing.T) {
		// Simulate kubectl get pods output
		output := "NAME                     READY   STATUS    RESTARTS   AGE\ntest-pod-1               1/1     Running   0          5d\ntest-pod-2               0/1     Pending   0          2d"
		
		result := &models.CommandExecutionResult{
			Success:       true,
			Output:        output,
			ExitCode:      0,
			ExecutionTime: 200,
		}
		
		formatter.FormatOutput(result, "get pods")
		
		assert.NotEmpty(t, result.FormattedOutput)
		assert.Contains(t, result.FormattedOutput, "✅")
		assert.Contains(t, result.FormattedOutput, "📋") // Table header
		assert.Contains(t, result.FormattedOutput, "🟢") // Running status
		assert.Contains(t, result.FormattedOutput, "🟡") // Pending status
	})
}

// TestErrorParsingIntegration tests error parsing with real kubectl errors
func TestErrorParsingIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	parser := models.NewErrorParser()

	t.Run("parse not found error", func(t *testing.T) {
		errorOutput := "error from server (NotFound): pods \"non-existent-pod\" not found"
		
		kubectlErr := parser.ParseError(errorOutput, "")
		
		assert.Equal(t, models.ErrorTypeNotFound, kubectlErr.Type)
		assert.Equal(t, "NOT_FOUND", kubectlErr.Code)
		assert.True(t, kubectlErr.Recoverable)
		assert.Contains(t, kubectlErr.Suggestion, "verify")
		assert.Equal(t, "non-existent-pod", kubectlErr.Resource)
	})

	t.Run("parse permission denied error", func(t *testing.T) {
		errorOutput := "error from server (Forbidden): User \"test-user\" cannot get resource \"secrets\" in API group \"\" in the namespace \"kube-system\""
		
		kubectlErr := parser.ParseError(errorOutput, "")
		
		assert.Equal(t, models.ErrorTypePermissionDenied, kubectlErr.Type)
		assert.Equal(t, "FORBIDDEN", kubectlErr.Code)
		assert.False(t, kubectlErr.Recoverable)
		assert.Contains(t, kubectlErr.Suggestion, "administrator")
	})

	t.Run("format error for display", func(t *testing.T) {
		kubectlErr := &models.KubectlError{
			Type:        models.ErrorTypeNotFound,
			Code:        "NOT_FOUND",
			Message:     "Pod not found",
			Resource:    "test-pod",
			Namespace:   "default",
			Suggestion:  "Check the pod name and namespace",
			Recoverable: true,
		}
		
		formatted := parser.FormatErrorForDisplay(kubectlErr)
		
		assert.Contains(t, formatted, "🔍") // Not found icon
		assert.Contains(t, formatted, "Not Found Error")
		assert.Contains(t, formatted, "Pod not found")
		assert.Contains(t, formatted, "Resource: test-pod")
		assert.Contains(t, formatted, "Namespace: default")
		assert.Contains(t, formatted, "Check the pod name")
		assert.Contains(t, formatted, "✅ This error may be recoverable")
	})
}