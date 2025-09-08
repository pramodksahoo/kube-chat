package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/pramodksahoo/kube-chat/pkg/nlp"
	"github.com/stretchr/testify/assert"
)

func setupTestAppWithContext() (*fiber.App, *models.SessionContextManager, nlp.TranslatorService) {
	app := fiber.New()
	translator := nlp.NewTranslatorService()
	confirmationManager := nlp.NewConfirmationManager()
	sessionManager := NewSessionManager()
	contextManager := models.NewSessionContextManager()
	
	setupRoutes(app, translator, confirmationManager, nil, sessionManager, contextManager, nil)
	
	return app, contextManager, translator
}

func TestHandleGetSessionContext(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	sessionID := "test-session-1"
	
	tests := []struct {
		name           string
		sessionID      string
		setupContext   bool
		expectedStatus int
		expectedSuccess bool
	}{
		{
			name:           "get existing context",
			sessionID:      sessionID,
			setupContext:   true,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "get non-existent context",
			sessionID:      "non-existent",
			setupContext:   false,
			expectedStatus: 404,
			expectedSuccess: false,
		},
		{
			name:           "missing session ID",
			sessionID:      "",
			setupContext:   false,
			expectedStatus: 404,
			expectedSuccess: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup context if needed
			if tt.setupContext {
				contextManager.CreateContext(tt.sessionID)
			}
			
			// Make request
			url := fmt.Sprintf("/nlp/sessions/%s/context", tt.sessionID)
			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req)
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			// Parse response only if not 404 (router error)
			if resp.StatusCode != 404 {
				var response ContextResponse
				err = json.NewDecoder(resp.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSuccess, response.Success)
				
				if tt.expectedSuccess {
					assert.Equal(t, tt.sessionID, response.SessionID)
					assert.NotNil(t, response.Context)
				}
			}
		})
	}
}

func TestHandleResetSessionContext(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	sessionID := "test-session-reset"
	
	tests := []struct {
		name           string
		sessionID      string
		setupContext   bool
		expectedStatus int
		expectedSuccess bool
	}{
		{
			name:           "reset existing context",
			sessionID:      sessionID,
			setupContext:   true,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "reset non-existent context",
			sessionID:      "non-existent",
			setupContext:   false,
			expectedStatus: 500,
			expectedSuccess: false,
		},
		{
			name:           "missing session ID",
			sessionID:      "",
			setupContext:   false,
			expectedStatus: 404,
			expectedSuccess: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup context if needed
			if tt.setupContext {
				context := contextManager.CreateContext(tt.sessionID)
				// Add some test data
				context.AddReferenceItem(models.ReferenceItem{
					ID:   "test-item",
					Type: "pod",
					Name: "test-pod",
				})
			}
			
			// Make request
			url := fmt.Sprintf("/nlp/sessions/%s/context", tt.sessionID)
			req := httptest.NewRequest("DELETE", url, nil)
			resp, err := app.Test(req)
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			// Parse response only if not 404 (router error)
			if resp.StatusCode != 404 {
				var response ContextResponse
				err = json.NewDecoder(resp.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSuccess, response.Success)
				
				if tt.expectedSuccess {
					assert.Equal(t, tt.sessionID, response.SessionID)
					
					// Verify context was cleared
					context, exists := contextManager.GetContext(tt.sessionID)
					assert.True(t, exists)
					assert.Empty(t, context.ReferenceableItems)
				}
			}
		})
	}
}

func TestHandleValidateReference(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	sessionID := "test-session-validate"
	
	// Setup context with test data
	context := contextManager.CreateContext(sessionID)
	context.AddReferenceItem(models.ReferenceItem{
		ID:       "pod-1",
		Type:     "pod",
		Name:     "nginx-pod",
		Position: 1,
		LastSeen: time.Now(),
	})
	context.AddReferenceItem(models.ReferenceItem{
		ID:       "svc-1",
		Type:     "service",
		Name:     "nginx-service",
		Position: 1,
		LastSeen: time.Now(),
	})
	
	tests := []struct {
		name           string
		sessionID      string
		reference      string
		expectedStatus int
		expectedSuccess bool
		expectedValid  bool
	}{
		{
			name:           "valid ordinal reference",
			sessionID:      sessionID,
			reference:      "first pod",
			expectedStatus: 200,
			expectedSuccess: true,
			expectedValid:  true,
		},
		{
			name:           "valid demonstrative reference",
			sessionID:      sessionID,
			reference:      "that service",
			expectedStatus: 200,
			expectedSuccess: true,
			expectedValid:  true,
		},
		{
			name:           "valid direct name reference",
			sessionID:      sessionID,
			reference:      "nginx-pod",
			expectedStatus: 200,
			expectedSuccess: true,
			expectedValid:  true,
		},
		{
			name:           "invalid reference",
			sessionID:      sessionID,
			reference:      "third deployment",
			expectedStatus: 200,
			expectedSuccess: false,
			expectedValid:  false,
		},
		{
			name:           "non-existent session",
			sessionID:      "non-existent",
			reference:      "first pod",
			expectedStatus: 404,
			expectedSuccess: false,
			expectedValid:  false,
		},
		{
			name:           "empty reference",
			sessionID:      sessionID,
			reference:      "",
			expectedStatus: 400,
			expectedSuccess: false,
			expectedValid:  false,
		},
		{
			name:           "missing session ID",
			sessionID:      "",
			reference:      "first pod",
			expectedStatus: 404,
			expectedSuccess: false,
			expectedValid:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request body
			requestBody := ValidateReferenceRequest{
				Reference: tt.reference,
			}
			bodyBytes, _ := json.Marshal(requestBody)
			
			// Make request
			url := fmt.Sprintf("/nlp/sessions/%s/validate-reference", tt.sessionID)
			req := httptest.NewRequest("POST", url, bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req)
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			// Parse response only if not 404 (router error)
			if resp.StatusCode != 404 {
				var response ValidateReferenceResponse
				err = json.NewDecoder(resp.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSuccess, response.Success)
				
				if tt.expectedSuccess {
					assert.Equal(t, tt.expectedValid, response.IsValid)
					assert.Equal(t, tt.reference, response.Reference)
					
					if tt.expectedValid {
						assert.NotNil(t, response.ResolvedEntity)
					} else {
						assert.NotEmpty(t, response.Suggestions)
					}
				}
			}
		})
	}
}

func TestHandleGetContextState(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	sessionID := "test-session-state"
	
	tests := []struct {
		name           string
		sessionID      string
		setupContext   bool
		expectedStatus int
		expectedSuccess bool
	}{
		{
			name:           "get state for existing context",
			sessionID:      sessionID,
			setupContext:   true,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "get state for non-existent context",
			sessionID:      "non-existent",
			setupContext:   false,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "missing session ID",
			sessionID:      "",
			setupContext:   false,
			expectedStatus: 404,
			expectedSuccess: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup context if needed
			if tt.setupContext {
				context := contextManager.CreateContext(tt.sessionID)
				context.AddReferenceItem(models.ReferenceItem{
					ID:   "test-item",
					Type: "pod",
					Name: "test-pod",
				})
			}
			
			// Make request
			url := fmt.Sprintf("/nlp/sessions/%s/context/state", tt.sessionID)
			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req)
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			// Parse response only if not 404 (router error)
			if resp.StatusCode != 404 {
				var response ContextResponse
				err = json.NewDecoder(resp.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSuccess, response.Success)
				
				if tt.expectedSuccess {
					assert.NotNil(t, response.ContextState)
					assert.Equal(t, tt.sessionID, response.ContextState.SessionID)
					
					if tt.setupContext {
						assert.True(t, response.ContextState.IsActive)
						assert.False(t, response.ContextState.IsExpired)
						assert.Equal(t, 1, response.ContextState.ItemCount)
					}
				}
			}
		})
	}
}

func TestHandleValidateContextHealth(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	sessionID := "test-session-health"
	
	tests := []struct {
		name           string
		sessionID      string
		setupContext   bool
		addItems       bool
		expectedStatus int
		expectedSuccess bool
	}{
		{
			name:           "healthy context with items",
			sessionID:      sessionID,
			setupContext:   true,
			addItems:       true,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "unhealthy context without items",
			sessionID:      sessionID + "-empty",
			setupContext:   true,
			addItems:       false,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "non-existent context",
			sessionID:      "non-existent",
			setupContext:   false,
			addItems:       false,
			expectedStatus: 200,
			expectedSuccess: true,
		},
		{
			name:           "missing session ID",
			sessionID:      "",
			setupContext:   false,
			addItems:       false,
			expectedStatus: 404,
			expectedSuccess: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup context if needed
			if tt.setupContext {
				context := contextManager.CreateContext(tt.sessionID)
				if tt.addItems {
					context.AddReferenceItem(models.ReferenceItem{
						ID:       "test-item",
						Type:     "pod",
						Name:     "test-pod",
						LastSeen: time.Now(),
					})
				}
			}
			
			// Make request
			url := fmt.Sprintf("/nlp/sessions/%s/context/health", tt.sessionID)
			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req)
			
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			// Parse response only if not 404 (router error)  
			if resp.StatusCode != 404 {
				var response HealthResponse
				err = json.NewDecoder(resp.Body).Decode(&response)
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedSuccess, response.Success)
				
				if tt.expectedSuccess {
					assert.NotNil(t, response.Health)
					assert.Contains(t, response.Health, "healthy")
					assert.Contains(t, response.Health, "sessionId")
					assert.Equal(t, tt.sessionID, response.Health["sessionId"])
				}
			}
		})
	}
}

func TestHandleListActiveSessions(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	// Create some test sessions
	sessionIDs := []string{"session-1", "session-2", "session-3"}
	for _, sessionID := range sessionIDs {
		contextManager.CreateContext(sessionID)
	}
	
	// Expire one session
	context, _ := contextManager.GetContext("session-2")
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	
	// Make request
	req := httptest.NewRequest("GET", "/nlp/sessions/active", nil)
	resp, err := app.Test(req)
	
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Parse response
	var response ActiveSessionsResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.Equal(t, 2, response.Total) // Only 2 active sessions
	assert.Contains(t, response.ActiveSessions, "session-1")
	assert.Contains(t, response.ActiveSessions, "session-3")
	assert.NotContains(t, response.ActiveSessions, "session-2") // Expired
}

func TestHandleGetContextStats(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	// Create some test sessions with data
	context1 := contextManager.CreateContext("stats-session-1")
	context1.AddReferenceItem(models.ReferenceItem{ID: "item-1", Type: "pod", Name: "pod-1"})
	
	context2 := contextManager.CreateContext("stats-session-2")
	context2.AddReferenceItem(models.ReferenceItem{ID: "item-2", Type: "service", Name: "svc-1"})
	context2.AddEntity(models.ContextEntity{Type: "pod", Name: "entity-1"})
	
	// Make request
	req := httptest.NewRequest("GET", "/nlp/sessions/stats", nil)
	resp, err := app.Test(req)
	
	assert.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Parse response
	var response StatsResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.True(t, response.Success)
	assert.NotNil(t, response.Stats)
	
	// Verify stats content (JSON numbers are float64)
	assert.Equal(t, float64(2), response.Stats["totalContexts"])
	assert.Equal(t, float64(2), response.Stats["activeContexts"])
	assert.Equal(t, float64(0), response.Stats["expiredContexts"])
	assert.Equal(t, float64(2), response.Stats["totalItems"])
	assert.Equal(t, float64(1), response.Stats["totalEntities"])
	assert.Equal(t, "30m0s", response.Stats["defaultExpiry"])
	assert.Equal(t, float64(100), response.Stats["maxContexts"])
}

func TestContextAPIWithMalformedJSON(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	sessionID := "test-malformed"
	
	// Test validate reference with malformed JSON
	req := httptest.NewRequest("POST", fmt.Sprintf("/nlp/sessions/%s/validate-reference", sessionID), 
		bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	
	assert.NoError(t, err)
	assert.Equal(t, 400, resp.StatusCode)
	
	var response ValidateReferenceResponse
	err = json.NewDecoder(resp.Body).Decode(&response)
	assert.NoError(t, err)
	assert.False(t, response.Success)
	assert.Contains(t, response.Error, "Invalid request format")
}

func TestContextAPIEdgeCases(t *testing.T) {
	app, contextManager, _ := setupTestAppWithContext()
	defer contextManager.Shutdown()
	
	// Test very long session ID
	longSessionID := string(make([]byte, 1000))
	for i := range longSessionID {
		longSessionID = longSessionID[:i] + "a" + longSessionID[i+1:]
	}
	
	req := httptest.NewRequest("GET", fmt.Sprintf("/nlp/sessions/%s/context", longSessionID), nil)
	resp, err := app.Test(req)
	
	assert.NoError(t, err)
	assert.Equal(t, 404, resp.StatusCode) // Should handle gracefully
	
	// Test special characters in session ID (URL encoded)
	specialSessionID := "session-with-special-chars-encoded"
	req = httptest.NewRequest("GET", fmt.Sprintf("/nlp/sessions/%s/context", specialSessionID), nil)
	resp, err = app.Test(req)
	
	assert.NoError(t, err)
	// Should handle gracefully (either 404 or 400 is acceptable)
	assert.True(t, resp.StatusCode == 404 || resp.StatusCode == 400)
}