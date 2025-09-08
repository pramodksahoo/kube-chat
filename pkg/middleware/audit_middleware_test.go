package middleware

import (
	"bytes"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// MockEventCollector implements EventCollectorInterface for testing
type MockEventCollector struct {
	mock.Mock
}

func (m *MockEventCollector) CollectEvent(event *models.AuditEvent) error {
	args := m.Called(event)
	return args.Error(0)
}

func (m *MockEventCollector) CollectEventWithTimeout(event *models.AuditEvent, timeout time.Duration) error {
	args := m.Called(event, timeout)
	return args.Error(0)
}

func TestDefaultAuditConfig(t *testing.T) {
	config := DefaultAuditConfig()
	
	assert.Equal(t, "api-gateway", config.ServiceName)
	assert.Equal(t, "1.0.0", config.ServiceVersion)
	assert.Contains(t, config.SkipPaths, "/health")
	assert.Contains(t, config.SkipPaths, "/metrics")
	assert.Contains(t, config.SkipMethods, "OPTIONS")
	assert.False(t, config.LogRequestBody)
	assert.False(t, config.LogResponseBody)
	assert.Equal(t, int64(4096), config.MaxBodySize)
	assert.NotNil(t, config.UserContextExtractor)
	assert.NotNil(t, config.CorrelationIDExtractor)
	assert.NotNil(t, config.TraceIDExtractor)
}

func TestNewAuditMiddleware(t *testing.T) {
	mockCollector := &MockEventCollector{}
	config := DefaultAuditConfig()
	config.Collector = mockCollector
	
	middleware := NewAuditMiddleware(config)
	assert.NotNil(t, middleware)
}

func TestAuditMiddlewareSkipPaths(t *testing.T) {
	mockCollector := &MockEventCollector{}
	config := DefaultAuditConfig()
	config.Collector = mockCollector
	config.SkipPaths = []string{"/health", "/metrics"}
	
	app := fiber.New()
	app.Use(NewAuditMiddleware(config))
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	app.Get("/api/test", func(c *fiber.Ctx) error {
		return c.SendString("Test")
	})
	
	// Test skipped path
	req := httptest.NewRequest("GET", "/health", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Test non-skipped path
	mockCollector.On("CollectEventWithTimeout", mock.Anything, mock.Anything).Return(nil)
	
	req = httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Verify collector was called for non-skipped path
	mockCollector.AssertExpectations(t)
}

func TestAuditMiddlewareSkipMethods(t *testing.T) {
	mockCollector := &MockEventCollector{}
	config := DefaultAuditConfig()
	config.Collector = mockCollector
	config.SkipMethods = []string{"OPTIONS"}
	
	app := fiber.New()
	app.Use(NewAuditMiddleware(config))
	app.Options("/api/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	app.Get("/api/test", func(c *fiber.Ctx) error {
		return c.SendString("Test")
	})
	
	// Test skipped method
	req := httptest.NewRequest("OPTIONS", "/api/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Test non-skipped method
	mockCollector.On("CollectEventWithTimeout", mock.Anything, mock.Anything).Return(nil)
	
	req = httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	resp, err = app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Verify collector was called for non-skipped method
	mockCollector.AssertExpectations(t)
}

func TestAuditMiddlewareRequestCapture(t *testing.T) {
	var capturedEvent *models.AuditEvent
	
	mockCollector := &MockEventCollector{}
	mockCollector.On("CollectEventWithTimeout", mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		capturedEvent = args.Get(0).(*models.AuditEvent)
	})
	
	config := DefaultAuditConfig()
	config.Collector = mockCollector
	config.LogRequestBody = true
	
	app := fiber.New()
	app.Use(NewAuditMiddleware(config))
	app.Post("/api/test", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"result": "success"})
	})
	
	requestBody := `{"test": "data"}`
	req := httptest.NewRequest("POST", "/api/test?param=value", bytes.NewReader([]byte(requestBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	req.Header.Set("X-Correlation-ID", "corr789")
	req.Header.Set("X-Trace-ID", "trace101")
	
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Verify event was captured
	require.NotNil(t, capturedEvent)
	assert.Equal(t, models.AuditEventTypeCommand, capturedEvent.EventType)
	assert.Equal(t, models.AuditSeverityInfo, capturedEvent.Severity)
	assert.Equal(t, "user123", capturedEvent.UserContext.UserID)
	assert.Equal(t, "session456", capturedEvent.UserContext.SessionID)
	assert.Equal(t, "corr789", capturedEvent.CorrelationID)
	assert.Equal(t, "trace101", capturedEvent.TraceID)
	assert.Contains(t, capturedEvent.Message, "POST /api/test completed")
	
	// Check metadata
	requestMetadata, ok := capturedEvent.Metadata["request"]
	assert.True(t, ok)
	assert.NotNil(t, requestMetadata)
	
	responseMetadata, ok := capturedEvent.Metadata["response"]  
	assert.True(t, ok)
	assert.NotNil(t, responseMetadata)
	
	mockCollector.AssertExpectations(t)
}

func TestDetermineEventType(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		path       string
		statusCode int
		expected   models.AuditEventType
	}{
		{
			name:       "login success",
			method:     "POST",
			path:       "/auth/login",
			statusCode: 200,
			expected:   models.AuditEventTypeLogin,
		},
		{
			name:       "login failure",
			method:     "POST",
			path:       "/auth/login",
			statusCode: 401,
			expected:   models.AuditEventTypeAuthentication,
		},
		{
			name:       "logout",
			method:     "POST",
			path:       "/auth/logout",
			statusCode: 200,
			expected:   models.AuditEventTypeLogout,
		},
		{
			name:       "nlp translate",
			method:     "POST",
			path:       "/nlp/translate",
			statusCode: 200,
			expected:   models.AuditEventTypeNLPInput,
		},
		{
			name:       "command execute",
			method:     "POST",
			path:       "/api/execute",
			statusCode: 200,
			expected:   models.AuditEventTypeCommandExecute,
		},
		{
			name:       "rbac denied",
			method:     "GET",
			path:       "/api/rbac/check",
			statusCode: 403,
			expected:   models.AuditEventTypeRBACDenied,
		},
		{
			name:       "rbac check",
			method:     "GET",
			path:       "/api/permissions",
			statusCode: 200,
			expected:   models.AuditEventTypeRBACCheck,
		},
		{
			name:       "generic api",
			method:     "GET",
			path:       "/api/users",
			statusCode: 200,
			expected:   models.AuditEventTypeCommand,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineEventType(tt.method, tt.path, tt.statusCode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDetermineSeverity(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		err        error
		expected   models.AuditSeverity
	}{
		{
			name:       "success",
			statusCode: 200,
			err:        nil,
			expected:   models.AuditSeverityInfo,
		},
		{
			name:       "redirect",
			statusCode: 301,
			err:        nil,
			expected:   models.AuditSeverityInfo,
		},
		{
			name:       "client error",
			statusCode: 400,
			err:        nil,
			expected:   models.AuditSeverityWarning,
		},
		{
			name:       "unauthorized",
			statusCode: 401,
			err:        nil,
			expected:   models.AuditSeverityCritical,
		},
		{
			name:       "forbidden",
			statusCode: 403,
			err:        nil,
			expected:   models.AuditSeverityCritical,
		},
		{
			name:       "server error",
			statusCode: 500,
			err:        nil,
			expected:   models.AuditSeverityError,
		},
		{
			name:       "with error",
			statusCode: 200,
			err:        assert.AnError,
			expected:   models.AuditSeverityError,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := determineSeverity(tt.statusCode, tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCaptureRequestInfo(t *testing.T) {
	app := fiber.New()
	app.Post("/api/test", func(c *fiber.Ctx) error {
		config := DefaultAuditConfig()
		config.LogRequestBody = true
		config.MaxBodySize = 1024
		
		info := captureRequestInfo(c, config)
		
		assert.Equal(t, "POST", info.Method)
		assert.Equal(t, "/api/test?param=value", info.URL)
		assert.Equal(t, "/api/test", info.Path)
		assert.Equal(t, "application/json", info.Headers["Content-Type"])
		assert.Equal(t, "value", info.QueryParams["param"])
		assert.Equal(t, `{"test":"data"}`, info.Body)
		assert.Equal(t, int64(16), info.BodySize)
		assert.NotEmpty(t, info.IPAddress)
		
		return c.SendString("OK")
	})
	
	requestBody := `{"test":"data"}`
	req := httptest.NewRequest("POST", "/api/test?param=value", bytes.NewReader([]byte(requestBody)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "test-agent")
	
	_, err := app.Test(req)
	require.NoError(t, err)
}

func TestCaptureResponseInfo(t *testing.T) {
	app := fiber.New()
	app.Get("/api/test", func(c *fiber.Ctx) error {
		config := DefaultAuditConfig()
		config.LogResponseBody = true
		config.MaxBodySize = 1024
		
		// Set response and then capture info
		c.Status(201).JSON(fiber.Map{"result": "success"})
		
		info := captureResponseInfo(c, config)
		
		assert.Equal(t, 201, info.StatusCode)
		assert.Contains(t, info.Headers, "Content-Type")
		assert.NotEmpty(t, info.Body)
		assert.Greater(t, info.BodySize, int64(0))
		
		return nil
	})
	
	req := httptest.NewRequest("GET", "/api/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 201, resp.StatusCode)
}

func TestDefaultUserContextExtractor(t *testing.T) {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		user, sessionCtx, err := defaultUserContextExtractor(c)
		
		if c.Get("X-User-ID") == "" {
			assert.Error(t, err)
			assert.Nil(t, user)
			assert.Nil(t, sessionCtx)
		} else {
			assert.NoError(t, err)
			assert.NotNil(t, user)
			assert.NotNil(t, sessionCtx)
			assert.Equal(t, "user123", user.ID)
			assert.Equal(t, "test@example.com", user.Email)
			assert.Equal(t, "user123", sessionCtx.UserID)
			assert.Equal(t, "session456", sessionCtx.SessionID)
		}
		
		return c.SendString("OK")
	})
	
	// Test without user headers
	req := httptest.NewRequest("GET", "/test", nil)
	_, err := app.Test(req)
	require.NoError(t, err)
	
	// Test with user headers
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	req.Header.Set("X-User-Email", "test@example.com")
	_, err = app.Test(req)
	require.NoError(t, err)
}

func TestDefaultCorrelationIDExtractor(t *testing.T) {
	app := fiber.New()
	app.Get("/test", func(c *fiber.Ctx) error {
		correlationID := defaultCorrelationIDExtractor(c)
		
		if c.Get("X-Correlation-ID") != "" {
			assert.Equal(t, "corr123", correlationID)
		} else if c.Get("X-Request-ID") != "" {
			assert.Equal(t, "req456", correlationID)
		} else {
			assert.Empty(t, correlationID)
		}
		
		return c.SendString("OK")
	})
	
	// Test with X-Correlation-ID
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Correlation-ID", "corr123")
	_, err := app.Test(req)
	require.NoError(t, err)
	
	// Test with X-Request-ID
	req = httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Request-ID", "req456")
	_, err = app.Test(req)
	require.NoError(t, err)
	
	// Test without headers
	req = httptest.NewRequest("GET", "/test", nil)
	_, err = app.Test(req)
	require.NoError(t, err)
}

func TestSessionLifecycleAuditMiddleware(t *testing.T) {
	var capturedEvent *models.AuditEvent
	
	mockCollector := &MockEventCollector{}
	mockCollector.On("CollectEventWithTimeout", mock.Anything, mock.Anything).Return(nil).Run(func(args mock.Arguments) {
		capturedEvent = args.Get(0).(*models.AuditEvent)
	})
	
	app := fiber.New()
	app.Use(SessionLifecycleAuditMiddleware(mockCollector, "test-service", "1.0.0"))
	app.Get("/test", func(c *fiber.Ctx) error {
		c.Locals("session_event", "session_created")
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	
	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
	
	// Verify session audit event was captured
	require.NotNil(t, capturedEvent)
	assert.Equal(t, models.AuditEventTypeLogin, capturedEvent.EventType)
	assert.Equal(t, "User session created", capturedEvent.Message)
	assert.Equal(t, "user123", capturedEvent.UserContext.UserID)
	assert.Equal(t, "session456", capturedEvent.UserContext.SessionID)
	
	mockCollector.AssertExpectations(t)
}

func TestShouldSkipAudit(t *testing.T) {
	config := AuditConfig{
		SkipPaths:   []string{"/health", "/metrics"},
		SkipMethods: []string{"OPTIONS"},
	}
	
	app := fiber.New()
	
	// Create test routes to validate skip logic
	testResults := make(map[string]bool)
	
	app.Get("/health", func(c *fiber.Ctx) error {
		testResults["health"] = shouldSkipAudit(c, config)
		return c.SendString("ok")
	})
	
	app.All("/api/*", func(c *fiber.Ctx) error {
		testResults[c.Method()+":"+c.Path()] = shouldSkipAudit(c, config)
		return c.SendString("ok")
	})
	
	// Test skip paths
	app.Test(httptest.NewRequest("GET", "/health", nil))
	assert.True(t, testResults["health"])
	
	// Test skip methods
	app.Test(httptest.NewRequest("OPTIONS", "/api/test", nil))
	assert.True(t, testResults["OPTIONS:/api/test"])
	
	// Test normal request
	app.Test(httptest.NewRequest("GET", "/api/test", nil))
	assert.False(t, testResults["GET:/api/test"])
}

func TestCreateAuditMessage(t *testing.T) {
	reqInfo := &RequestInfo{
		Method: "POST",
		Path:   "/api/test",
	}
	
	respInfo := &ResponseInfo{
		StatusCode: 201,
	}
	
	// Test success message
	message := createAuditMessage(reqInfo, respInfo, nil)
	assert.Equal(t, "POST /api/test completed with status 201", message)
	
	// Test error message  
	message = createAuditMessage(reqInfo, respInfo, assert.AnError)
	assert.Contains(t, message, "POST /api/test failed with error:")
}

func BenchmarkAuditMiddleware(b *testing.B) {
	mockCollector := &MockEventCollector{}
	mockCollector.On("CollectEventWithTimeout", mock.Anything, mock.Anything).Return(nil)
	
	config := DefaultAuditConfig()
	config.Collector = mockCollector
	
	app := fiber.New()
	app.Use(NewAuditMiddleware(config))
	app.Get("/api/test", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})
	
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("X-Session-ID", "session456")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := app.Test(req)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
	}
}