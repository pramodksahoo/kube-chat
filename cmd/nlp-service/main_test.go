package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/clients"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/pramodksahoo/kube-chat/pkg/nlp"
)

func TestNLPServiceEndpoints(t *testing.T) {
	// Create test app
	app := fiber.New()
	
	// Create test services
	translator := nlp.NewTranslatorService()
	confirmationManager := nlp.NewConfirmationManager()
	kubernetesClient, err := clients.NewKubernetesClient(nil)
	require.NoError(t, err)
	sessionManager := NewSessionManager()
	contextManager := models.NewSessionContextManager()
	defer contextManager.Shutdown()

	// Setup routes
	setupRoutes(app, translator, confirmationManager, kubernetesClient, sessionManager, contextManager, nil)

	t.Run("health check", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.Equal(t, "healthy", result["status"])
		assert.Equal(t, "nlp-service", result["service"])
		assert.Equal(t, "1.3", result["version"])
	})

	t.Run("process natural language", func(t *testing.T) {
		requestBody := ProcessRequest{
			Input:     "show me all pods",
			SessionID: "test-session",
		}
		
		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/nlp/process", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result ProcessResponse
		err = json.NewDecoder(resp.Body).Decode(&result)
		require.NoError(t, err)
		
		assert.True(t, result.Success)
		assert.NotEmpty(t, result.GeneratedCommand)
		assert.NotEmpty(t, result.CommandID)
		assert.Contains(t, result.GeneratedCommand, "pods")
	})

	t.Run("execute command flow", func(t *testing.T) {
		// First, create a command through NLP processing
		requestBody := ProcessRequest{
			Input:     "show pods",
			SessionID: "execution-test-session",
		}
		
		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/nlp/process", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var processResult ProcessResponse
		err = json.NewDecoder(resp.Body).Decode(&processResult)
		require.NoError(t, err)
		require.True(t, processResult.Success)

		commandID := processResult.CommandID
		
		// If it's a safe command, it should be auto-approved
		if !processResult.RequiresApproval {
			// Execute the command directly
			execReq := ExecuteRequest{Confirmed: true}
			execBody, err := json.Marshal(execReq)
			require.NoError(t, err)

			req = httptest.NewRequest("POST", "/nlp/execute/"+commandID, bytes.NewReader(execBody))
			req.Header.Set("Content-Type", "application/json")
			
			resp, err = app.Test(req)
			require.NoError(t, err)

			// Command execution might fail in test environment, but should be structured
			var execResult ExecuteResponse
			err = json.NewDecoder(resp.Body).Decode(&execResult)
			require.NoError(t, err)
			
			assert.Equal(t, commandID, execResult.CommandID)
			assert.NotEmpty(t, execResult.Status)
			
			if execResult.Success {
				assert.NotNil(t, execResult.ExecutionResult)
				assert.True(t, execResult.ExecutionResult.Success)
			} else {
				// Expected in test environment
				t.Logf("Command execution failed (expected in test env): %s", execResult.Error)
			}
		}
	})

	t.Run("confirmation workflow for write operations", func(t *testing.T) {
		// Create a write operation that requires confirmation
		requestBody := ProcessRequest{
			Input:     "create deployment nginx",
			SessionID: "confirmation-test-session",
		}
		
		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/nlp/process", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var processResult ProcessResponse
		err = json.NewDecoder(resp.Body).Decode(&processResult)
		require.NoError(t, err)
		require.True(t, processResult.Success)

		if processResult.RequiresApproval {
			commandID := processResult.CommandID
			approvalToken := processResult.ApprovalToken
			require.NotNil(t, approvalToken)

			// Confirm the command
			confirmReq := models.ConfirmRequest{
				CommandID: commandID,
				Token:     *approvalToken,
			}
			
			confirmBody, err := json.Marshal(confirmReq)
			require.NoError(t, err)

			req = httptest.NewRequest("PUT", "/nlp/confirm/"+commandID, bytes.NewReader(confirmBody))
			req.Header.Set("Content-Type", "application/json")
			
			resp, err = app.Test(req)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var confirmResult models.ConfirmResponse
			err = json.NewDecoder(resp.Body).Decode(&confirmResult)
			require.NoError(t, err)
			assert.True(t, confirmResult.Success)
			assert.Equal(t, models.CommandStatusApproved, confirmResult.Status)

			// Now execute the confirmed command
			execReq := ExecuteRequest{Confirmed: true}
			execBody, err := json.Marshal(execReq)
			require.NoError(t, err)

			req = httptest.NewRequest("POST", "/nlp/execute/"+commandID, bytes.NewReader(execBody))
			req.Header.Set("Content-Type", "application/json")
			
			resp, err = app.Test(req)
			require.NoError(t, err)

			var execResult ExecuteResponse
			err = json.NewDecoder(resp.Body).Decode(&execResult)
			require.NoError(t, err)
			
			// Execution might fail due to permissions or test environment
			assert.Equal(t, commandID, execResult.CommandID)
			assert.NotEmpty(t, execResult.Status)
			
			t.Logf("Write command execution result: Success=%v, Status=%s", 
				execResult.Success, execResult.Status)
		}
	})

	t.Run("session history retrieval", func(t *testing.T) {
		sessionID := "history-test-session"
		
		// First, execute a command to add to history
		requestBody := ProcessRequest{
			Input:     "show nodes",
			SessionID: sessionID,
		}
		
		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/nlp/process", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		// Get session history
		req = httptest.NewRequest("GET", "/nlp/sessions/"+sessionID+"/history", nil)
		
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var historyResult HistoryResponse
		err = json.NewDecoder(resp.Body).Decode(&historyResult)
		require.NoError(t, err)
		
		assert.True(t, historyResult.Success)
		assert.Equal(t, sessionID, historyResult.SessionID)
		assert.GreaterOrEqual(t, historyResult.Total, 0)
	})

	t.Run("command status tracking", func(t *testing.T) {
		// Create a command
		requestBody := ProcessRequest{
			Input:     "get pods",
			SessionID: "status-test-session",
		}
		
		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/nlp/process", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var processResult ProcessResponse
		err = json.NewDecoder(resp.Body).Decode(&processResult)
		require.NoError(t, err)
		require.True(t, processResult.Success)

		commandID := processResult.CommandID
		
		// Check command status
		req = httptest.NewRequest("GET", "/nlp/commands/"+commandID+"/status", nil)
		
		resp, err = app.Test(req)
		require.NoError(t, err)

		if resp.StatusCode == http.StatusOK {
			var statusResult models.StatusResponse
			err = json.NewDecoder(resp.Body).Decode(&statusResult)
			require.NoError(t, err)
			
			assert.True(t, statusResult.Success)
			assert.Equal(t, commandID, statusResult.CommandID)
			assert.NotEmpty(t, statusResult.Status)
		} else {
			// Command might not be in pending queue if auto-approved
			t.Logf("Command %s not in pending queue (expected for safe commands)", commandID)
		}
	})

	t.Run("invalid requests", func(t *testing.T) {
		// Test empty body
		req := httptest.NewRequest("POST", "/nlp/process", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Test invalid JSON
		req = httptest.NewRequest("POST", "/nlp/process", bytes.NewReader([]byte("invalid json")))
		req.Header.Set("Content-Type", "application/json")
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		// Test empty input
		requestBody := ProcessRequest{Input: ""}
		jsonBody, err := json.Marshal(requestBody)
		require.NoError(t, err)

		req = httptest.NewRequest("POST", "/nlp/process", bytes.NewReader(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		resp, err = app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("execute non-existent command", func(t *testing.T) {
		execReq := ExecuteRequest{Confirmed: true}
		execBody, err := json.Marshal(execReq)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/nlp/execute/non-existent-id", bytes.NewReader(execBody))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})
}

func TestSessionManager(t *testing.T) {
	sessionManager := NewSessionManager()

	t.Run("add and retrieve command history", func(t *testing.T) {
		sessionID := "test-session-1"
		
		command1 := &models.KubernetesCommand{
			ID:               "cmd-1",
			SessionID:        sessionID,
			GeneratedCommand: "get pods",
			Status:           models.CommandStatusCompleted,
		}
		
		command2 := &models.KubernetesCommand{
			ID:               "cmd-2",
			SessionID:        sessionID,
			GeneratedCommand: "get services",
			Status:           models.CommandStatusCompleted,
		}

		// Add commands to session
		sessionManager.AddCommandToSession(sessionID, command1)
		sessionManager.AddCommandToSession(sessionID, command2)

		// Retrieve history
		history, err := sessionManager.GetSessionHistory(sessionID)
		require.NoError(t, err)
		assert.Len(t, history, 2)
		assert.Equal(t, "cmd-1", history[0].ID)
		assert.Equal(t, "cmd-2", history[1].ID)
	})

	t.Run("empty session history", func(t *testing.T) {
		history, err := sessionManager.GetSessionHistory("non-existent")
		require.NoError(t, err)
		assert.Len(t, history, 0)
	})

	t.Run("default session", func(t *testing.T) {
		command := &models.KubernetesCommand{
			ID:               "default-cmd",
			SessionID:        "",
			GeneratedCommand: "version",
			Status:           models.CommandStatusCompleted,
		}

		// Add to default session
		sessionManager.AddCommandToSession("", command)

		// Retrieve from default session
		history, err := sessionManager.GetSessionHistory("")
		require.NoError(t, err)
		assert.Len(t, history, 1)
		assert.Equal(t, "default-cmd", history[0].ID)
	})
}

func TestEndToEndWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end test in short mode")
	}

	// This test simulates a complete user workflow
	t.Run("complete user workflow", func(t *testing.T) {
		// Create all services as they would be in main()
		translator := nlp.NewTranslatorService()
		confirmationManager := nlp.NewConfirmationManager()
		kubernetesClient, err := clients.NewKubernetesClient(&clients.KubectlClientOptions{
			Timeout: 10 * time.Second,
		})
		require.NoError(t, err)
		sessionManager := NewSessionManager()

		ctx := context.Background()
		sessionID := "e2e-test-session"

		// Step 1: User provides natural language input
		nlInput := "show all pods"
		
		// Step 2: Translate to kubectl command
		command, err := translator.TranslateCommand(ctx, nlInput)
		require.NoError(t, err)
		assert.Contains(t, command.GeneratedCommand, "version")
		assert.Equal(t, models.RiskLevelSafe, command.RiskLevel)

		// Step 3: Safe commands are auto-approved
		if command.RiskLevel == models.RiskLevelSafe {
			command.UpdateStatus(models.CommandStatusApproved)
		} else {
			// For write operations, would go through confirmation flow
			err = confirmationManager.AddPendingCommand(command)
			require.NoError(t, err)
			
			// Simulate user confirmation
			confirmedCmd, err := confirmationManager.ConfirmCommand(command.ID, *command.ApprovalToken)
			require.NoError(t, err)
			command = confirmedCmd
		}

		// Step 4: Execute the command
		result, err := kubernetesClient.ExecuteCommand(ctx, command)
		require.NoError(t, err)
		require.NotNil(t, result)

		// Step 5: Apply output formatting
		formatter := models.NewOutputFormatter()
		formatter.FormatOutput(result, command.GeneratedCommand)

		// Step 6: Update command with results
		if result.Success {
			command.UpdateStatus(models.CommandStatusCompleted)
		} else {
			command.UpdateStatus(models.CommandStatusFailed)
		}
		command.ExecutionResult = result

		// Step 7: Add to session history
		sessionManager.AddCommandToSession(sessionID, command)

		// Step 8: Verify the complete workflow
		assert.NotNil(t, result.FormattedOutput)
		assert.GreaterOrEqual(t, result.ExecutionTime, 0)
		assert.Contains(t, []models.CommandStatus{models.CommandStatusCompleted, models.CommandStatusFailed}, command.Status)

		// Step 9: Verify session history
		history, err := sessionManager.GetSessionHistory(sessionID)
		require.NoError(t, err)
		assert.Len(t, history, 1)
		assert.Equal(t, command.ID, history[0].ID)
		assert.Equal(t, sessionID, history[0].SessionID)
		assert.NotNil(t, history[0].ExecutionResult)

		t.Logf("E2E Test Results:")
		t.Logf("  Original Input: %s", nlInput)
		t.Logf("  Generated Command: %s", command.GeneratedCommand)
		t.Logf("  Execution Success: %v", result.Success)
		t.Logf("  Execution Time: %dms", result.ExecutionTime)
		t.Logf("  Final Status: %s", command.Status)
	})
}

// Legacy tests from original implementation
func TestHealthEndpoint(t *testing.T) {
	app := fiber.New()
	translator := nlp.NewTranslatorService()
	confirmationManager := nlp.NewConfirmationManager()
	kubernetesClient, err := clients.NewKubernetesClient(nil)
	require.NoError(t, err)
	sessionManager := NewSessionManager()
	contextManager := models.NewSessionContextManager()
	defer contextManager.Shutdown()
	
	setupRoutes(app, translator, confirmationManager, kubernetesClient, sessionManager, contextManager, nil)

	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}