package middleware

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock implementations
type MockJWTServiceSecurity struct {
	mock.Mock
}

// Essential interface methods for session security testing
func (m *MockJWTServiceSecurity) ValidateToken(tokenString string) (*JWTClaims, error) {
	args := m.Called(tokenString)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*JWTClaims), args.Error(1)
}

// Stub implementations for required interface methods (not used in security tests)
func (m *MockJWTServiceSecurity) GenerateToken(userID, email, name string) (*TokenPair, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) GenerateTokenWithClaims(claims *JWTClaims) (*TokenPair, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) GenerateTokenWithNamespaceValidation(claims *JWTClaims, validateNamespaces bool) (*TokenPair, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) ValidateTokenWithRefresh(tokenString string, refreshPermissions bool) (*JWTClaims, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) RefreshToken(refreshToken string) (*TokenPair, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) RefreshTokenWithNamespaceValidation(refreshToken string, validateNamespaces bool) (*TokenPair, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) BlacklistToken(sessionID string) error {
	return fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) CleanupExpiredSessions() error {
	return fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) GetPublicKey() *rsa.PublicKey {
	return nil
}
func (m *MockJWTServiceSecurity) GetPublicKeyPEM() (string, error) {
	return "", fmt.Errorf("not implemented")
}
func (m *MockJWTServiceSecurity) MigrateLegacyClaims(claims *JWTClaims) *JWTClaims {
	return nil
}
func (m *MockJWTServiceSecurity) SetNamespaceValidator(validator *NamespaceValidator) {
	// no-op
}

func (m *MockJWTServiceSecurity) UpdateSessionActivity(sessionID string) error {
	args := m.Called(sessionID)
	return args.Error(0)
}

func (m *MockJWTServiceSecurity) GetSessionInfo(sessionID string) (*SessionInfo, error) {
	args := m.Called(sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SessionInfo), args.Error(1)
}

func (m *MockJWTServiceSecurity) GetAllActiveSessions(userID string) ([]*SessionInfo, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*SessionInfo), args.Error(1)
}

func (m *MockJWTServiceSecurity) TerminateSession(sessionID, reason string) error {
	args := m.Called(sessionID, reason)
	return args.Error(0)
}

func (m *MockJWTServiceSecurity) TerminateAllUserSessions(userID, reason string) error {
	args := m.Called(userID, reason)
	return args.Error(0)
}

func (m *MockJWTServiceSecurity) SetSessionTimeoutPolicies(idle, absolute time.Duration) error {
	args := m.Called(idle, absolute)
	return args.Error(0)
}

func (m *MockJWTServiceSecurity) GetSessionMetrics() *SessionMetrics {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*SessionMetrics)
}

type MockAuditLoggerSecurity struct {
	mock.Mock
}

func (m *MockAuditLoggerSecurity) LogAuthEvent(entry AuthAuditEntry) error {
	args := m.Called(entry)
	return args.Error(0)
}

func (m *MockAuditLoggerSecurity) LogLoginAttempt(userID, username, ipAddress, userAgent string, success bool, reason string) error {
	args := m.Called(userID, username, ipAddress, userAgent, success, reason)
	return args.Error(0)
}

func (m *MockAuditLoggerSecurity) LogCommandExecution(userID, command, kubeContext string, success bool, resources []string) error {
	args := m.Called(userID, command, kubeContext, success, resources)
	return args.Error(0)
}

func (m *MockAuditLoggerSecurity) LogSessionEvent(sessionID, userID, eventType, ipAddress string, metadata map[string]string) error {
	args := m.Called(sessionID, userID, eventType, ipAddress, metadata)
	return args.Error(0)
}

func (m *MockAuditLoggerSecurity) LogSuspiciousActivity(userID, activityType, description, ipAddress string, severity AuditSeverity, metadata map[string]string) error {
	args := m.Called(userID, activityType, description, ipAddress, severity, metadata)
	return args.Error(0)
}

func (m *MockAuditLoggerSecurity) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Test Setup
func setupSessionSecurityTest() (*SessionSecurityManager, *MockJWTServiceSecurity, *MockAuditLoggerSecurity, redis.Cmdable, redismock.ClientMock) {
	db, mock := redismock.NewClientMock()
	mockJWT := &MockJWTServiceSecurity{}
	mockAudit := &MockAuditLoggerSecurity{}

	config := SessionSecurityConfig{
		ConcurrentSessionLimit:   3,
		EnableDeviceFingerprinting: true,
		EnableIPBinding:          true,
		EnableUserAgentValidation: true,
		SuspiciousActivityThreshold: 5,
		SessionTimeoutMinutes:    30,
		MaxFailedAttempts:        3,
		LockoutDurationMinutes:   15,
	}

	manager := NewSessionSecurityManager(mockJWT, mockAudit, db, config)
	return manager, mockJWT, mockAudit, db, mock
}

func createSecurityTestRequest(method, path string, headers map[string]string, body interface{}) *http.Request {
	var reqBody *bytes.Buffer
	if body != nil {
		jsonBody, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(jsonBody)
	} else {
		reqBody = bytes.NewBuffer([]byte{})
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return req
}

// Test Device Fingerprinting
func TestGenerateDeviceFingerprint(t *testing.T) {
	manager, _, _, _, _ := setupSessionSecurityTest()

	tests := []struct {
		name        string
		userAgent   string
		acceptLang  string
		expectEmpty bool
	}{
		{
			name:       "Valid browser fingerprint",
			userAgent:  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			acceptLang: "en-US,en;q=0.9",
		},
		{
			name:       "Different user agent",
			userAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
			acceptLang: "en-US,en;q=0.9",
		},
		{
			name:        "Empty user agent",
			userAgent:   "",
			acceptLang:  "en-US,en;q=0.9",
			expectEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createSecurityTestRequest("GET", "/test", map[string]string{
				"User-Agent":      tt.userAgent,
				"Accept-Language": tt.acceptLang,
			}, nil)

			fingerprint := manager.generateDeviceFingerprint(req)
			
			if tt.expectEmpty {
				assert.Empty(t, fingerprint)
			} else {
				assert.NotEmpty(t, fingerprint)
				assert.Len(t, fingerprint, 64) // SHA256 hash length
			}
		})
	}
}

func TestDeviceFingerprintConsistency(t *testing.T) {
	manager, _, _, _, _ := setupSessionSecurityTest()

	req1 := createSecurityTestRequest("GET", "/test", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept-Language": "en-US,en;q=0.9",
	}, nil)

	req2 := createSecurityTestRequest("GET", "/test", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept-Language": "en-US,en;q=0.9",
	}, nil)

	fingerprint1 := manager.generateDeviceFingerprint(req1)
	fingerprint2 := manager.generateDeviceFingerprint(req2)

	assert.Equal(t, fingerprint1, fingerprint2, "Same device should generate same fingerprint")
}

// Test Session Security Validation
func TestValidateSessionSecurity(t *testing.T) {
	manager, mockJWT, mockAudit, _, redisMock := setupSessionSecurityTest()

	sessionID := "test-session-123"
	userID := "user123"
	
	session := &SessionInfo{
		SessionID:       sessionID,
		UserID:         userID,
		DeviceFingerprint: "test-fingerprint",
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	tests := []struct {
		name           string
		sessionInfo    *SessionInfo
		requestIP      string
		requestUA      string
		expectedValid  bool
		expectedError  string
		setupMocks     func()
	}{
		{
			name:          "Valid session security",
			sessionInfo:   session,
			requestIP:     "192.168.1.1",
			requestUA:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expectedValid: true,
			setupMocks: func() {
				mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)
			},
		},
		{
			name:          "IP address mismatch",
			sessionInfo:   session,
			requestIP:     "192.168.1.100",
			requestUA:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expectedValid: false,
			expectedError: "IP address mismatch detected",
			setupMocks: func() {
				mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)
				mockAudit.On("LogSuspiciousActivity", userID, "ip_mismatch", mock.AnythingOfType("string"), "192.168.1.100", AuditSeverityWarning, mock.AnythingOfType("map[string]string")).Return(nil)
			},
		},
		{
			name:          "User agent mismatch",
			sessionInfo:   session,
			requestIP:     "192.168.1.1",
			requestUA:     "Different User Agent",
			expectedValid: false,
			expectedError: "User agent mismatch detected",
			setupMocks: func() {
				mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)
				mockAudit.On("LogSuspiciousActivity", userID, "user_agent_mismatch", mock.AnythingOfType("string"), "192.168.1.1", AuditSeverityInfo, mock.AnythingOfType("map[string]string")).Return(nil)
			},
		},
		{
			name:          "Session not found",
			sessionInfo:   nil,
			requestIP:     "192.168.1.1",
			requestUA:     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			expectedValid: false,
			expectedError: "session not found",
			setupMocks: func() {
				mockJWT.On("GetSessionInfo", sessionID).Return(nil, fmt.Errorf("session not found"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockJWT.ExpectedCalls = nil
			mockAudit.ExpectedCalls = nil
			
			tt.setupMocks()

			req := createTestRequest("GET", "/test", map[string]string{
				"User-Agent": tt.requestUA,
			}, nil)
			req.RemoteAddr = tt.requestIP + ":12345"

			valid, err := manager.ValidateSessionSecurity(sessionID, req)

			assert.Equal(t, tt.expectedValid, valid)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockJWT.AssertExpectations(t)
			mockAudit.AssertExpectations(t)
		})
	}

	_ = redisMock // Suppress unused variable warning
}

// Test Concurrent Session Limits
func TestEnforceConcurrentSessionLimits(t *testing.T) {
	manager, mockJWT, mockAudit, _, _ := setupSessionSecurityTest()

	userID := "user123"
	
	tests := []struct {
		name              string
		activeSessions    []SessionInfo
		expectedAllowed   bool
		expectedError     string
		setupMocks        func()
	}{
		{
			name: "Under session limit",
			activeSessions: []SessionInfo{
				{SessionID: "session1", UserID: userID},
				{SessionID: "session2", UserID: userID},
			},
			expectedAllowed: true,
			setupMocks: func() {
				sessions := []SessionInfo{
					{SessionID: "session1", UserID: userID},
					{SessionID: "session2", UserID: userID},
				}
				mockJWT.On("GetAllActiveSessions", userID).Return(sessions, nil)
			},
		},
		{
			name: "At session limit",
			activeSessions: []SessionInfo{
				{SessionID: "session1", UserID: userID},
				{SessionID: "session2", UserID: userID},
				{SessionID: "session3", UserID: userID},
			},
			expectedAllowed: false,
			expectedError:   "concurrent session limit exceeded",
			setupMocks: func() {
				sessions := []SessionInfo{
					{SessionID: "session1", UserID: userID},
					{SessionID: "session2", UserID: userID},
					{SessionID: "session3", UserID: userID},
				}
				mockJWT.On("GetAllActiveSessions", userID).Return(sessions, nil)
				mockAudit.On("LogSuspiciousActivity", userID, "concurrent_session_limit", mock.AnythingOfType("string"), mock.AnythingOfType("string"), AuditSeverityWarning, mock.AnythingOfType("map[string]string")).Return(nil)
			},
		},
		{
			name:            "Error getting sessions",
			expectedAllowed: false,
			expectedError:   "failed to get active sessions",
			setupMocks: func() {
				mockJWT.On("GetAllActiveSessions", userID).Return(nil, fmt.Errorf("database error"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockJWT.ExpectedCalls = nil
			mockAudit.ExpectedCalls = nil
			
			tt.setupMocks()

			req := createTestRequest("POST", "/login", map[string]string{}, nil)
			req.RemoteAddr = "192.168.1.1:12345"

			allowed, err := manager.EnforceConcurrentSessionLimits(userID, req)

			assert.Equal(t, tt.expectedAllowed, allowed)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}

			mockJWT.AssertExpectations(t)
			mockAudit.AssertExpectations(t)
		})
	}
}

// Test Suspicious Activity Detection
func TestDetectSuspiciousActivity(t *testing.T) {
	manager, _, mockAudit, _, redisMock := setupSessionSecurityTest()

	userID := "user123"
	ipAddress := "192.168.1.1"
	
	tests := []struct {
		name           string
		activityType   string
		description    string
		severity       AuditSeverity
		metadata       map[string]string
		setupRedis     func()
		expectedLogged bool
	}{
		{
			name:         "Multiple failed logins",
			activityType: "multiple_failed_logins",
			description:  "5 consecutive failed login attempts",
			severity:     AuditSeverityError,
			metadata: map[string]string{
				"attempt_count": "5",
				"time_window":   "5m",
			},
			setupRedis: func() {
				redisMock.ExpectIncr(fmt.Sprintf("suspicious_activity:%s:%s", userID, "multiple_failed_logins")).SetVal(1)
				redisMock.ExpectExpire(fmt.Sprintf("suspicious_activity:%s:%s", userID, "multiple_failed_logins"), 15*time.Minute).SetVal(true)
			},
			expectedLogged: true,
		},
		{
			name:         "Unusual IP access",
			activityType: "unusual_ip_access",
			description:  "Login from new geographic location",
			severity:     AuditSeverityWarning,
			metadata: map[string]string{
				"previous_ip": "10.0.0.1",
				"new_ip":      "203.0.113.1",
			},
			setupRedis: func() {
				redisMock.ExpectIncr(fmt.Sprintf("suspicious_activity:%s:%s", userID, "unusual_ip_access")).SetVal(1)
				redisMock.ExpectExpire(fmt.Sprintf("suspicious_activity:%s:%s", userID, "unusual_ip_access"), 15*time.Minute).SetVal(true)
			},
			expectedLogged: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockAudit.ExpectedCalls = nil
			
			tt.setupRedis()
			
			if tt.expectedLogged {
				mockAudit.On("LogSuspiciousActivity", userID, tt.activityType, tt.description, ipAddress, tt.severity, tt.metadata).Return(nil)
			}

			err := manager.DetectSuspiciousActivity(userID, tt.activityType, tt.description, ipAddress, tt.severity, tt.metadata)

			assert.NoError(t, err)
			mockAudit.AssertExpectations(t)

			// Verify Redis expectations
			if err := redisMock.ExpectationsWereMet(); err != nil {
				t.Errorf("Redis expectations were not met: %v", err)
			}
		})
	}
}

// Test Secure Cookie Configuration
func TestConfigureSecureCookie(t *testing.T) {
	manager, _, _, _, _ := setupSessionSecurityTest()

	tests := []struct {
		name        string
		cookieName  string
		value       string
		isSecure    bool
		expectedFlags []string
	}{
		{
			name:       "Secure HTTPS cookie",
			cookieName: "session_token",
			value:      "test-token-value",
			isSecure:   true,
			expectedFlags: []string{"HttpOnly", "Secure", "SameSite=Strict"},
		},
		{
			name:       "HTTP cookie (development)",
			cookieName: "session_token",
			value:      "test-token-value",
			isSecure:   false,
			expectedFlags: []string{"HttpOnly", "SameSite=Strict"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			
			if tt.isSecure {
				c.Request = createTestRequest("GET", "https://example.com/test", map[string]string{}, nil)
			} else {
				c.Request = createTestRequest("GET", "http://localhost/test", map[string]string{}, nil)
			}

			manager.ConfigureSecureCookie(c, tt.cookieName, tt.value, time.Hour)

			cookies := w.Header().Get("Set-Cookie")
			assert.NotEmpty(t, cookies)
			assert.Contains(t, cookies, tt.cookieName+"="+tt.value)
			
			for _, flag := range tt.expectedFlags {
				assert.Contains(t, cookies, flag)
			}
			
			if !tt.isSecure {
				assert.NotContains(t, cookies, "Secure")
			}
		})
	}
}

// Test Security Middleware
func TestSessionSecurityMiddleware(t *testing.T) {
	manager, mockJWT, mockAudit, _, _ := setupSessionSecurityTest()

	sessionID := "test-session-123"
	userID := "user123"
	
	session := &SessionInfo{
		SessionID:       sessionID,
		UserID:         userID,
		DeviceFingerprint: "test-fingerprint",
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	tests := []struct {
		name           string
		token          string
		sessionValid   bool
		expectedStatus int
		setupMocks     func()
	}{
		{
			name:           "Valid session with security validation",
			token:          "valid-token",
			sessionValid:   true,
			expectedStatus: http.StatusOK,
			setupMocks: func() {
				claims := &CustomClaims{
					UserID:    userID,
					Username:  "testuser",
					Roles:     []string{"user"},
					SessionID: sessionID,
				}
				mockJWT.On("ValidateToken", "valid-token").Return(claims, nil)
				mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)
			},
		},
		{
			name:           "Invalid token",
			token:          "invalid-token",
			expectedStatus: http.StatusUnauthorized,
			setupMocks: func() {
				mockJWT.On("ValidateToken", "invalid-token").Return(nil, fmt.Errorf("invalid token"))
			},
		},
		{
			name:           "Security validation failure",
			token:          "valid-token-bad-security",
			expectedStatus: http.StatusForbidden,
			setupMocks: func() {
				claims := &CustomClaims{
					UserID:    userID,
					Username:  "testuser",
					Roles:     []string{"user"},
					SessionID: sessionID,
				}
				mockJWT.On("ValidateToken", "valid-token-bad-security").Return(claims, nil)
				mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)
				mockAudit.On("LogSuspiciousActivity", userID, "ip_mismatch", mock.AnythingOfType("string"), "192.168.1.100", AuditSeverityWarning, mock.AnythingOfType("map[string]string")).Return(nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockJWT.ExpectedCalls = nil
			mockAudit.ExpectedCalls = nil
			
			tt.setupMocks()

			// Create Gin context
			w := httptest.NewRecorder()
			c, r := gin.CreateTestContext(w)

			// Setup middleware
			middleware := manager.SessionSecurityMiddleware()
			r.Use(middleware)
			r.GET("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			var remoteAddr string
			if tt.name == "Security validation failure" {
				remoteAddr = "192.168.1.100:12345"
			} else {
				remoteAddr = "192.168.1.1:12345"
			}

			req := createTestRequest("GET", "/test", map[string]string{
				"Authorization": "Bearer " + tt.token,
				"User-Agent":    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
			}, nil)
			req.RemoteAddr = remoteAddr

			// Execute request
			c.Request = req
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockJWT.AssertExpectations(t)
			mockAudit.AssertExpectations(t)
		})
	}
}

// Test Session Timeout Management
func TestSessionTimeoutManagement(t *testing.T) {
	manager, mockJWT, _, _, _ := setupSessionSecurityTest()

	userID := "user123"
	sessionID := "session123"

	// Test session timeout validation
	t.Run("Valid session within timeout", func(t *testing.T) {
		session := &SessionInfo{
			SessionID:    sessionID,
			UserID:      userID,
			LastActivity: time.Now().Add(-10 * time.Minute), // 10 minutes ago
		}

		mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)

		valid := manager.IsSessionExpired(sessionID, 30*time.Minute)
		assert.False(t, valid)
		
		mockJWT.AssertExpectations(t)
	})

	t.Run("Expired session beyond timeout", func(t *testing.T) {
		mockJWT.ExpectedCalls = nil // Reset mocks
		
		session := &SessionInfo{
			SessionID:    sessionID,
			UserID:      userID,
			LastActivity: time.Now().Add(-45 * time.Minute), // 45 minutes ago
		}

		mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)

		valid := manager.IsSessionExpired(sessionID, 30*time.Minute)
		assert.True(t, valid)
		
		mockJWT.AssertExpectations(t)
	})
}

// Test Security Metrics
func TestGetSecurityMetrics(t *testing.T) {
	manager, _, _, _, redisMock := setupSessionSecurityTest()

	userID := "user123"

	// Setup Redis expectations for metrics
	redisMock.ExpectGet(fmt.Sprintf("failed_attempts:%s", userID)).SetVal("3")
	redisMock.ExpectGet(fmt.Sprintf("suspicious_activity:%s:multiple_failed_logins", userID)).SetVal("1")

	metrics := manager.GetSecurityMetrics(userID)

	assert.NotNil(t, metrics)
	assert.Equal(t, 3, metrics.FailedAttempts)
	assert.Equal(t, 1, metrics.SuspiciousActivities)

	// Verify Redis expectations
	if err := redisMock.ExpectationsWereMet(); err != nil {
		t.Errorf("Redis expectations were not met: %v", err)
	}
}

// Benchmark tests
func BenchmarkGenerateDeviceFingerprint(b *testing.B) {
	manager, _, _, _, _ := setupSessionSecurityTest()
	
	req := createTestRequest("GET", "/test", map[string]string{
		"User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Accept-Language": "en-US,en;q=0.9",
	}, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.generateDeviceFingerprint(req)
	}
}

func BenchmarkValidateSessionSecurity(b *testing.B) {
	manager, mockJWT, _, _, _ := setupSessionSecurityTest()

	sessionID := "test-session-123"
	session := &SessionInfo{
		SessionID:       sessionID,
		UserID:         "user123",
		DeviceFingerprint: "test-fingerprint",
		IPAddress:      "192.168.1.1",
		UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		CreatedAt:      time.Now(),
		LastActivity:   time.Now(),
	}

	mockJWT.On("GetSessionInfo", sessionID).Return(session, nil)

	req := createTestRequest("GET", "/test", map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}, nil)
	req.RemoteAddr = "192.168.1.1:12345"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.ValidateSessionSecurity(sessionID, req)
	}
}