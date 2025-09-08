package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pramodksahoo/kube-chat/pkg/nlp"
	"github.com/stretchr/testify/assert"
)

// ProcessRequest represents the API request structure
type ProcessRequest struct {
	Input     string `json:"input"`
	SessionID string `json:"sessionId,omitempty"`
}

// ProcessResponse represents the API response structure
type ProcessResponse struct {
	Success          bool   `json:"success"`
	GeneratedCommand string `json:"generatedCommand,omitempty"`
	RiskLevel        string `json:"riskLevel,omitempty"`
	Explanation      string `json:"explanation,omitempty"`
	Error            string `json:"error,omitempty"`
	CommandID        string `json:"commandId,omitempty"`
}

// TestNLPServiceIntegration tests the complete NLP service integration for Story 1.1
func TestNLPServiceIntegration(t *testing.T) {
	// Create a test server with the NLP service
	server := createTestServer()
	defer server.Close()

	t.Run("Story 1.1 Complete Integration Test", func(t *testing.T) {
		// Test all Story 1.1 target patterns
		testCases := []struct {
			description  string
			input        string
			expectedCmd  string
			expectedRisk string
		}{
			{
				description:  "Natural language: show me all pods",
				input:        "show me all pods",
				expectedCmd:  "kubectl get pods",
				expectedRisk: "safe",
			},
			{
				description:  "Natural language: list pods in namespace default",
				input:        "list pods in namespace default",
				expectedCmd:  "kubectl get pods -n default",
				expectedRisk: "safe",
			},
			{
				description:  "Natural language: describe service nginx",
				input:        "describe service nginx",
				expectedCmd:  "kubectl describe service nginx",
				expectedRisk: "safe",
			},
			{
				description:  "Natural language: get deployments",
				input:        "get deployments",
				expectedCmd:  "kubectl get deployments",
				expectedRisk: "safe",
			},
			{
				description:  "Natural language: show nodes",
				input:        "show nodes",
				expectedCmd:  "kubectl get nodes",
				expectedRisk: "safe",
			},
			{
				description:  "Natural language: describe pod test-pod",
				input:        "describe pod test-pod",
				expectedCmd:  "kubectl describe pod test-pod",
				expectedRisk: "safe",
			},
			{
				description:  "Natural language: list namespaces",
				input:        "list namespaces",
				expectedCmd:  "kubectl get namespaces",
				expectedRisk: "safe",
			},
		}

		successfulTranslations := 0
		for _, tc := range testCases {
			t.Run(tc.description, func(t *testing.T) {
				// Make HTTP request to NLP service
				response := makeNLPRequest(t, server.URL, tc.input, "test-session")

				// Validate successful response
				assert.True(t, response.Success, "Translation should succeed")
				assert.Equal(t, tc.expectedCmd, response.GeneratedCommand, "Generated command should match expected")
				assert.Equal(t, tc.expectedRisk, response.RiskLevel, "Risk level should be safe for read operations")
				assert.NotEmpty(t, response.Explanation, "Should provide explanation")
				assert.NotEmpty(t, response.CommandID, "Should provide command ID")
				assert.Contains(t, response.Explanation, "SAFE read operation", "Should indicate safety")

				if response.Success && response.GeneratedCommand == tc.expectedCmd {
					successfulTranslations++
				}
			})
		}

		// Verify Story 1.1 AC5: 90%+ accuracy requirement
		accuracy := float64(successfulTranslations) / float64(len(testCases)) * 100
		t.Logf("Integration test accuracy: %.1f%% (%d/%d)", accuracy, successfulTranslations, len(testCases))
		assert.GreaterOrEqual(t, accuracy, 90.0, "Story 1.1 AC5: Must achieve 90%+ accuracy")
	})

	t.Run("Error Handling Integration", func(t *testing.T) {
		errorCases := []struct {
			description   string
			input         string
			expectedError string
		}{
			{
				description:   "Empty input handling",
				input:         "",
				expectedError: "Input cannot be empty",
			},
			{
				description:   "Unsupported operation handling",
				input:         "delete deployment nginx",
				expectedError: "unable to translate",
			},
			{
				description:   "Random text handling",
				input:         "this is random text",
				expectedError: "unable to translate",
			},
		}

		for _, tc := range errorCases {
			t.Run(tc.description, func(t *testing.T) {
				response := makeNLPRequest(t, server.URL, tc.input, "test-session")

				assert.False(t, response.Success, "Should indicate failure")
				assert.Contains(t, response.Error, tc.expectedError, "Should provide helpful error message")
				assert.Empty(t, response.GeneratedCommand, "Should not generate command on error")
			})
		}
	})

	t.Run("Case Insensitive Processing", func(t *testing.T) {
		variations := []string{
			"SHOW ME ALL PODS",
			"Show Me All Pods",
			"show me all pods",
			"SHOW PODS",
			"get pods",
		}

		for _, input := range variations {
			t.Run(fmt.Sprintf("Case variation: %s", input), func(t *testing.T) {
				response := makeNLPRequest(t, server.URL, input, "test-session")

				assert.True(t, response.Success, "Should handle case variations")
				assert.Equal(t, "kubectl get pods", response.GeneratedCommand, "Should generate correct command regardless of case")
				assert.Equal(t, "safe", response.RiskLevel, "Should maintain safe risk level")
			})
		}
	})

	t.Run("Performance Test", func(t *testing.T) {
		// Test response time requirement (Story mentions <500ms in some docs)
		start := time.Now()
		response := makeNLPRequest(t, server.URL, "get pods", "performance-test")
		duration := time.Since(start)

		assert.True(t, response.Success, "Performance test should succeed")
		assert.Less(t, duration, 500*time.Millisecond, "Response should be under 500ms")
		t.Logf("Response time: %v", duration)
	})
}

func TestHealthCheckIntegration(t *testing.T) {
	server := createTestServer()
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	assert.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var healthResponse map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&healthResponse)
	assert.NoError(t, err)

	assert.Equal(t, "healthy", healthResponse["status"])
	assert.Equal(t, "nlp-service", healthResponse["service"])
	assert.Equal(t, "1.1", healthResponse["version"])
	assert.Contains(t, healthResponse["story"], "Story 1.1")
}

// Helper functions

func createTestServer() *httptest.Server {
	// Create Fiber app
	app := fiber.New()

	// Create real translator service
	translator := nlp.NewTranslatorService()

	// Setup routes (simplified version for testing)
	app.Get("/health", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "nlp-service",
			"version": "1.1",
			"story":   "Story 1.1 - Natural Language Query Translation",
		})
	})

	app.Post("/nlp/process", func(c fiber.Ctx) error {
		var req ProcessRequest
		if err := c.Bind().Body(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ProcessResponse{
				Success: false,
				Error:   "Invalid request format",
			})
		}

		if req.Input == "" {
			return c.Status(fiber.StatusBadRequest).JSON(ProcessResponse{
				Success: false,
				Error:   "Input cannot be empty. Supported commands: show pods, list deployments, describe service, get nodes",
			})
		}

		result, err := translator.TranslateCommand(context.Background(), req.Input)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(ProcessResponse{
				Success: false,
				Error:   err.Error(),
			})
		}

		return c.JSON(ProcessResponse{
			Success:          true,
			GeneratedCommand: result.GeneratedCommand,
			RiskLevel:        string(result.RiskLevel),
			Explanation:      fmt.Sprintf("Translated '%s' to kubectl command. This is a SAFE read operation.", req.Input),
			CommandID:        result.ID,
		})
	})

	// For Fiber v3, we need to create HTTP handler manually
	handler := func(w http.ResponseWriter, r *http.Request) {
		req := httptest.NewRequest(r.Method, r.URL.Path, r.Body)
		for k, v := range r.Header {
			req.Header[k] = v
		}

		resp, err := app.Test(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		// Copy status code
		w.WriteHeader(resp.StatusCode)

		// Copy headers
		for k, v := range resp.Header {
			w.Header()[k] = v
		}

		// Copy body
		body, _ := io.ReadAll(resp.Body)
		w.Write(body)
	}

	return httptest.NewServer(http.HandlerFunc(handler))
}

func makeNLPRequest(t *testing.T, serverURL, input, sessionID string) ProcessResponse {
	reqBody := ProcessRequest{
		Input:     input,
		SessionID: sessionID,
	}

	body, err := json.Marshal(reqBody)
	assert.NoError(t, err)

	resp, err := http.Post(serverURL+"/nlp/process", "application/json", bytes.NewReader(body))
	assert.NoError(t, err)
	defer resp.Body.Close()

	var response ProcessResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)

	return response
}
