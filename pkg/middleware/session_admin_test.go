// Package middleware provides comprehensive tests for administrative session management
package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// SessionAdminTestSuite is the test suite for administrative session management
type SessionAdminTestSuite struct {
	suite.Suite
	manager     *AdminSessionManager
	jwtService  *MockJWTService
	auditLogger *MockAuditLogger
	router      *mux.Router
}

// MockJWTService is a mock JWT service for testing
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GetSessionInfo(sessionID string) (*SessionInfo, error) {
	args := m.Called(sessionID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*SessionInfo), args.Error(1)
}

func (m *MockJWTService) GetAllActiveSessions(userID string) ([]*SessionInfo, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*SessionInfo), args.Error(1)
}

func (m *MockJWTService) TerminateSession(sessionID string, reason string) error {
	args := m.Called(sessionID, reason)
	return args.Error(0)
}

func (m *MockJWTService) TerminateAllUserSessions(userID string, reason string) error {
	args := m.Called(userID, reason)
	return args.Error(0)
}

func (m *MockJWTService) GetSessionMetrics() *SessionMetrics {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*SessionMetrics)
}

// Implement other required methods as no-ops for testing
func (m *MockJWTService) GenerateToken(userID, email, name string) (*TokenPair, error) {
	return nil, nil
}

func (m *MockJWTService) GenerateTokenWithClaims(claims *JWTClaims) (*TokenPair, error) {
	return nil, nil
}

func (m *MockJWTService) GenerateTokenWithNamespaceValidation(claims *JWTClaims, validateNamespaces bool) (*TokenPair, error) {
	return nil, nil
}

func (m *MockJWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	return nil, nil
}

func (m *MockJWTService) ValidateTokenWithRefresh(tokenString string, refreshPermissions bool) (*JWTClaims, error) {
	return nil, nil
}

func (m *MockJWTService) RefreshToken(refreshToken string) (*TokenPair, error) {
	return nil, nil
}

func (m *MockJWTService) RefreshTokenWithNamespaceValidation(refreshToken string, validateNamespaces bool) (*TokenPair, error) {
	return nil, nil
}

func (m *MockJWTService) BlacklistToken(sessionID string) error {
	return nil
}

func (m *MockJWTService) CleanupExpiredSessions() error {
	return nil
}

func (m *MockJWTService) GetPublicKey() interface{} {
	return nil
}

func (m *MockJWTService) GetPublicKeyPEM() (string, error) {
	return "", nil
}

func (m *MockJWTService) MigrateLegacyClaims(claims *JWTClaims) *JWTClaims {
	return claims
}

func (m *MockJWTService) SetNamespaceValidator(validator interface{}) {
	// No-op for testing
}

func (m *MockJWTService) UpdateSessionActivity(sessionID string) error {
	return nil
}

func (m *MockJWTService) SetSessionTimeoutPolicies(idle, absolute time.Duration) error {
	return nil
}

// MockAuditLogger is a mock audit logger for testing
type MockAuditLogger struct {
	mock.Mock
	events []AuthAuditEntry
}

func (m *MockAuditLogger) LogAuthEvent(ctx interface{}, event *AuthAuditEntry) error {
	args := m.Called(ctx, event)
	if event != nil {
		m.events = append(m.events, *event)
	}
	return args.Error(0)
}

func (m *MockAuditLogger) GetAuditMetrics() map[string]interface{} {
	args := m.Called()
	if args.Get(0) == nil {
		return make(map[string]interface{})
	}
	return args.Get(0).(map[string]interface{})
}

// SetupTest sets up the test suite
func (suite *SessionAdminTestSuite) SetupTest() {
	suite.jwtService = &MockJWTService{}
	suite.auditLogger = &MockAuditLogger{}
	
	config := SessionAdminConfig{
		JWTService:   suite.jwtService,
		AuditLogger:  suite.auditLogger,
		AllowedRoles: []string{"admin", "security_officer"},
	}
	
	manager, err := NewAdminSessionManager(config)
	require.NoError(suite.T(), err)
	suite.manager = manager
	
	// Setup router
	suite.router = mux.NewRouter()
	suite.manager.SetupAdminRoutes(suite.router)
}

// TestNewAdminSessionManager tests session manager creation
func (suite *SessionAdminTestSuite) TestNewAdminSessionManager() {
	// Test valid configuration
	config := SessionAdminConfig{
		JWTService:  suite.jwtService,
		AuditLogger: suite.auditLogger,
	}
	
	manager, err := NewAdminSessionManager(config)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), manager)
	assert.Equal(suite.T(), []string{"admin", "security_officer"}, manager.allowedRoles)
	
	// Test missing JWT service
	config.JWTService = nil
	_, err = NewAdminSessionManager(config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "JWT service is required")
	
	// Test missing audit logger
	config.JWTService = suite.jwtService
	config.AuditLogger = nil
	_, err = NewAdminSessionManager(config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "audit logger is required")
}

// TestListActiveSessions tests GET /admin/sessions endpoint
func (suite *SessionAdminTestSuite) TestListActiveSessions() {
	// Setup mock data
	sessions := []*SessionInfo{
		{
			SessionID:    "session-1",
			UserID:       "user-1",
			Email:        "user1@example.com",
			Active:       true,
			SessionType:  "web",
			CreatedAt:    time.Now().Add(-time.Hour),
			LastActivity: time.Now().Add(-time.Minute * 30),
		},
		{
			SessionID:    "session-2",
			UserID:       "user-1",
			Email:        "user1@example.com",
			Active:       true,
			SessionType:  "api",
			CreatedAt:    time.Now().Add(-time.Hour * 2),
			LastActivity: time.Now().Add(-time.Minute * 10),
		},
	}
	
	// Setup expectations
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	// Test with user_id filter
	req := httptest.NewRequest("GET", "/admin/sessions?user_id=user-1", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.jwtService.On("GetAllActiveSessions", "user-1").Return(sessions, nil)
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response SessionListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 2, response.Total)
	assert.Equal(suite.T(), 2, len(response.Sessions))
	assert.Equal(suite.T(), "user-1", response.Filters.UserID)
}

// TestGetSessionDetails tests GET /admin/sessions/{sessionId} endpoint
func (suite *SessionAdminTestSuite) TestGetSessionDetails() {
	sessionInfo := &SessionInfo{
		SessionID:         "session-123",
		UserID:            "user-456",
		Email:             "user@example.com",
		Active:            true,
		SessionType:       "web",
		CreatedAt:         time.Now().Add(-time.Hour),
		LastActivity:      time.Now().Add(-time.Minute * 5),
		DeviceFingerprint: "fp-123456",
		IPAddress:         "192.168.1.100",
	}
	
	// Setup expectations
	suite.jwtService.On("GetSessionInfo", "session-123").Return(sessionInfo, nil)
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	req := httptest.NewRequest("GET", "/admin/sessions/session-123", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response SessionInfo
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "session-123", response.SessionID)
	assert.Equal(suite.T(), "user-456", response.UserID)
}

// TestGetSessionDetailsNotFound tests session not found scenario
func (suite *SessionAdminTestSuite) TestGetSessionDetailsNotFound() {
	suite.jwtService.On("GetSessionInfo", "nonexistent-session").Return(nil, 
		fmt.Errorf("session not found: nonexistent-session"))
	
	req := httptest.NewRequest("GET", "/admin/sessions/nonexistent-session", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusNotFound, w.Code)
}

// TestTerminateSession tests DELETE /admin/sessions/{sessionId} endpoint
func (suite *SessionAdminTestSuite) TestTerminateSession() {
	sessionInfo := &SessionInfo{
		SessionID: "session-123",
		UserID:    "user-456",
		Active:    true,
	}
	
	// Setup expectations
	suite.jwtService.On("GetSessionInfo", "session-123").Return(sessionInfo, nil)
	suite.jwtService.On("TerminateSession", "session-123", "security_violation").Return(nil)
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	req := httptest.NewRequest("DELETE", "/admin/sessions/session-123?reason=security_violation", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusNoContent, w.Code)
	
	// Verify JWT service was called correctly
	suite.jwtService.AssertCalled(suite.T(), "TerminateSession", "session-123", "security_violation")
}

// TestGetUserSessions tests GET /admin/sessions/user/{userId} endpoint
func (suite *SessionAdminTestSuite) TestGetUserSessions() {
	sessions := []*SessionInfo{
		{
			SessionID: "session-1",
			UserID:    "user-123",
			Active:    true,
		},
		{
			SessionID: "session-2",
			UserID:    "user-123",
			Active:    true,
		},
	}
	
	// Setup expectations
	suite.jwtService.On("GetAllActiveSessions", "user-123").Return(sessions, nil)
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	req := httptest.NewRequest("GET", "/admin/sessions/user/user-123", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response SessionListResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 2, response.Total)
	assert.Equal(suite.T(), len(sessions), len(response.Sessions))
}

// TestTerminateUserSessions tests DELETE /admin/sessions/user/{userId} endpoint
func (suite *SessionAdminTestSuite) TestTerminateUserSessions() {
	// Setup expectations
	suite.jwtService.On("TerminateAllUserSessions", "user-123", "admin_initiated").Return(nil)
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	req := httptest.NewRequest("DELETE", "/admin/sessions/user/user-123?reason=admin_initiated", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusNoContent, w.Code)
	
	// Verify JWT service was called correctly
	suite.jwtService.AssertCalled(suite.T(), "TerminateAllUserSessions", "user-123", "admin_initiated")
}

// TestBulkTerminateSessions tests POST /admin/sessions/bulk/terminate endpoint
func (suite *SessionAdminTestSuite) TestBulkTerminateSessions() {
	requestBody := SessionTerminationRequest{
		SessionIDs: []string{"session-1", "session-2", "session-3"},
		UserIDs:    []string{"user-456"},
		Reason:     "security_incident",
		Force:      true,
	}
	
	// Setup expectations
	suite.jwtService.On("TerminateSession", "session-1", "security_incident").Return(nil)
	suite.jwtService.On("TerminateSession", "session-2", "security_incident").Return(nil)
	suite.jwtService.On("TerminateSession", "session-3", "security_incident").Return(fmt.Errorf("session not found"))
	suite.jwtService.On("TerminateAllUserSessions", "user-456", "security_incident").Return(nil)
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	body, _ := json.Marshal(requestBody)
	req := httptest.NewRequest("POST", "/admin/sessions/bulk/terminate", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response SessionTerminationResponse
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), 2, response.TotalTerminated)
	assert.Equal(suite.T(), 2, len(response.TerminatedSessions))
	assert.Equal(suite.T(), 1, len(response.FailedSessions))
	assert.Equal(suite.T(), "session-3", response.FailedSessions[0])
	assert.Equal(suite.T(), 1, len(response.Errors))
}

// TestGetSessionMetrics tests GET /admin/sessions/metrics endpoint
func (suite *SessionAdminTestSuite) TestGetSessionMetrics() {
	sessionMetrics := &SessionMetrics{
		TotalActiveSessions:  10,
		TotalExpiredSessions: 5,
		ActiveSessionsByType: map[string]int64{"web": 7, "api": 3},
		SessionTimeouts:      2,
	}
	
	auditMetrics := map[string]interface{}{
		"total_logs":   100,
		"failed_logs":  2,
		"buffer_size":  5,
		"siem_enabled": true,
	}
	
	// Setup expectations
	suite.jwtService.On("GetSessionMetrics").Return(sessionMetrics)
	suite.auditLogger.On("GetAuditMetrics").Return(auditMetrics)
	
	req := httptest.NewRequest("GET", "/admin/sessions/metrics", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), response, "session_metrics")
	assert.Contains(suite.T(), response, "audit_metrics")
	assert.Contains(suite.T(), response, "timestamp")
}

// TestGenerateActivityReport tests GET /admin/sessions/report endpoint
func (suite *SessionAdminTestSuite) TestGenerateActivityReport() {
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	req := httptest.NewRequest("GET", "/admin/sessions/report?period=7d", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response SessionActivityReport
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "7d", response.Period)
	assert.NotNil(suite.T(), response.SessionsByType)
	assert.NotNil(suite.T(), response.SessionsByUser)
}

// TestGenerateComplianceAudit tests GET /admin/sessions/compliance-audit endpoint
func (suite *SessionAdminTestSuite) TestGenerateComplianceAudit() {
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	req := httptest.NewRequest("GET", "/admin/sessions/compliance-audit", nil)
	req.Header.Set("X-User-Role", "admin")
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusOK, w.Code)
	
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(suite.T(), err)
	
	assert.Contains(suite.T(), response, "audit_timestamp")
	assert.Contains(suite.T(), response, "session_compliance")
	assert.Contains(suite.T(), response, "audit_trail_integrity")
	assert.Contains(suite.T(), response, "compliance_flags")
	
	complianceFlags := response["compliance_flags"].([]interface{})
	assert.Contains(suite.T(), complianceFlags, "SOC2")
	assert.Contains(suite.T(), complianceFlags, "HIPAA")
	assert.Contains(suite.T(), complianceFlags, "GDPR")
}

// TestUnauthorizedAccess tests access control for admin endpoints
func (suite *SessionAdminTestSuite) TestUnauthorizedAccess() {
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	// Test with unauthorized role
	req := httptest.NewRequest("GET", "/admin/sessions", nil)
	req.Header.Set("X-User-Role", "user") // Not in allowed roles
	w := httptest.NewRecorder()
	
	suite.router.ServeHTTP(w, req)
	
	assert.Equal(suite.T(), http.StatusForbidden, w.Code)
	assert.Contains(suite.T(), w.Body.String(), "Access denied: insufficient privileges")
}

// TestAuthorizedRoles tests that different authorized roles can access endpoints
func (suite *SessionAdminTestSuite) TestAuthorizedRoles() {
	suite.jwtService.On("GetAllActiveSessions", mock.Anything).Return([]*SessionInfo{}, nil)
	suite.auditLogger.On("LogAuthEvent", mock.Anything, mock.Anything).Return(nil)
	
	authorizedRoles := []string{"admin", "security_officer"}
	
	for _, role := range authorizedRoles {
		req := httptest.NewRequest("GET", "/admin/sessions", nil)
		req.Header.Set("X-User-Role", role)
		w := httptest.NewRecorder()
		
		suite.router.ServeHTTP(w, req)
		
		assert.Equal(suite.T(), http.StatusOK, w.Code, "Role %s should be authorized", role)
	}
}

// TestSessionFiltering tests session filtering functionality
func (suite *SessionAdminTestSuite) TestSessionFiltering() {
	sessions := []*SessionInfo{
		{SessionID: "s1", UserID: "user1", Active: true, SessionType: "web", IPAddress: "192.168.1.1"},
		{SessionID: "s2", UserID: "user1", Active: false, SessionType: "api", IPAddress: "192.168.1.2"},
		{SessionID: "s3", UserID: "user2", Active: true, SessionType: "web", IPAddress: "192.168.1.1"},
		{SessionID: "s4", UserID: "user2", Active: true, SessionType: "mobile", IPAddress: "192.168.1.3"},
	}
	
	tests := []struct {
		name            string
		filters         SessionFilters
		expectedCount   int
		expectedSessions []string
	}{
		{
			name:            "filter_by_user",
			filters:         SessionFilters{UserID: "user1"},
			expectedCount:   2,
			expectedSessions: []string{"s1", "s2"},
		},
		{
			name:            "filter_by_active",
			filters:         SessionFilters{Active: boolPtr(true)},
			expectedCount:   3,
			expectedSessions: []string{"s1", "s3", "s4"},
		},
		{
			name:            "filter_by_session_type",
			filters:         SessionFilters{SessionType: "web"},
			expectedCount:   2,
			expectedSessions: []string{"s1", "s3"},
		},
		{
			name:            "filter_by_ip",
			filters:         SessionFilters{IPAddress: "192.168.1.1"},
			expectedCount:   2,
			expectedSessions: []string{"s1", "s3"},
		},
		{
			name:            "multiple_filters",
			filters:         SessionFilters{UserID: "user1", Active: boolPtr(true)},
			expectedCount:   1,
			expectedSessions: []string{"s1"},
		},
	}
	
	for _, tt := range tests {
		suite.T().Run(tt.name, func(t *testing.T) {
			filtered := applyFilters(sessions, tt.filters)
			assert.Equal(t, tt.expectedCount, len(filtered))
			
			actualSessionIDs := make([]string, len(filtered))
			for i, session := range filtered {
				actualSessionIDs[i] = session.SessionID
			}
			
			for _, expectedID := range tt.expectedSessions {
				assert.Contains(t, actualSessionIDs, expectedID)
			}
		})
	}
}

// Helper function for test
func boolPtr(b bool) *bool {
	return &b
}

// TestSuite runner
func TestSessionAdminTestSuite(t *testing.T) {
	suite.Run(t, new(SessionAdminTestSuite))
}

// Additional unit tests

func TestParseSessionFilters(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		expected SessionFilters
	}{
		{
			name:  "basic_filters",
			query: "user_id=user123&session_type=web&ip_address=192.168.1.1",
			expected: SessionFilters{
				UserID:      "user123",
				SessionType: "web",
				IPAddress:   "192.168.1.1",
			},
		},
		{
			name:  "with_active_filter",
			query: "active=true&user_id=user456",
			expected: SessionFilters{
				UserID: "user456",
				Active: boolPtr(true),
			},
		},
		{
			name:  "time_filters",
			query: "since=2023-01-01T00:00:00Z&until=2023-12-31T23:59:59Z",
			expected: SessionFilters{
				Since: "2023-01-01T00:00:00Z",
				Until: "2023-12-31T23:59:59Z",
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/admin/sessions?"+tt.query, nil)
			filters := parseSessionFilters(req)
			
			assert.Equal(t, tt.expected.UserID, filters.UserID)
			assert.Equal(t, tt.expected.SessionType, filters.SessionType)
			assert.Equal(t, tt.expected.IPAddress, filters.IPAddress)
			assert.Equal(t, tt.expected.Since, filters.Since)
			assert.Equal(t, tt.expected.Until, filters.Until)
			
			if tt.expected.Active != nil {
				require.NotNil(t, filters.Active)
				assert.Equal(t, *tt.expected.Active, *filters.Active)
			} else {
				assert.Nil(t, filters.Active)
			}
		})
	}
}

func TestGetIntQueryParam(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		param        string
		defaultValue int
		expected     int
	}{
		{
			name:         "valid_param",
			query:        "page=5&page_size=25",
			param:        "page",
			defaultValue: 1,
			expected:     5,
		},
		{
			name:         "missing_param",
			query:        "other=value",
			param:        "page",
			defaultValue: 1,
			expected:     1,
		},
		{
			name:         "invalid_param",
			query:        "page=invalid",
			param:        "page",
			defaultValue: 1,
			expected:     1,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test?"+tt.query, nil)
			result := getIntQueryParam(req, tt.param, tt.defaultValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}