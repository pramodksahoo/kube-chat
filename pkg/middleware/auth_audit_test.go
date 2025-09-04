// Package middleware provides comprehensive tests for authentication audit logging
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// AuthAuditTestSuite is the test suite for authentication audit logging
type AuthAuditTestSuite struct {
	suite.Suite
	logger      *AuthAuditLogger
	redisClient *MockAuditRedisClient
	ctx         context.Context
}

// MockAuditRedisClient is a mock Redis client for audit testing
type MockAuditRedisClient struct {
	mock.Mock
}

func (m *MockAuditRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	args := m.Called(ctx, key, value, expiration)
	cmd := redis.NewStatusCmd(ctx, "set", key, value)
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal("OK")
	}
	return cmd
}

func (m *MockAuditRedisClient) ZAdd(ctx context.Context, key string, members ...*redis.Z) *redis.IntCmd {
	args := m.Called(ctx, key, members)
	cmd := redis.NewIntCmd(ctx, "zadd", key)
	if args.Error(0) != nil {
		cmd.SetErr(args.Error(0))
	} else {
		cmd.SetVal(int64(len(members)))
	}
	return cmd
}

func (m *MockAuditRedisClient) Pipeline() redis.Pipeliner {
	return &MockPipeliner{}
}

type MockPipeliner struct {
	mock.Mock
}

func (m *MockPipeliner) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	return redis.NewStatusCmd(ctx, "set", key, value)
}

func (m *MockPipeliner) ZAdd(ctx context.Context, key string, members ...*redis.Z) *redis.IntCmd {
	return redis.NewIntCmd(ctx, "zadd", key)
}

func (m *MockPipeliner) Exec(ctx context.Context) ([]redis.Cmder, error) {
	args := m.Called(ctx)
	return nil, args.Error(0)
}

func (m *MockPipeliner) Discard() error {
	return nil
}

func (m *MockPipeliner) Close() error {
	return nil
}

func (m *MockPipeliner) Len() int {
	return 0
}

// SetupTest sets up the test suite
func (suite *AuthAuditTestSuite) SetupTest() {
	suite.redisClient = &MockAuditRedisClient{}
	suite.ctx = context.Background()
	
	config := AuthAuditConfig{
		RedisClient:   suite.redisClient,
		SecretKey:     "test-secret-key-for-audit-logging",
		BatchSize:     5,
		FlushInterval: 100 * time.Millisecond,
	}
	
	logger, err := NewAuthAuditLogger(config)
	require.NoError(suite.T(), err)
	suite.logger = logger
}

// TestNewAuthAuditLogger tests audit logger creation
func (suite *AuthAuditTestSuite) TestNewAuthAuditLogger() {
	// Test valid configuration
	config := AuthAuditConfig{
		RedisClient: suite.redisClient,
		SecretKey:   "test-secret",
	}
	
	logger, err := NewAuthAuditLogger(config)
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), logger)
	assert.Equal(suite.T(), 24*time.Hour*365*7, logger.retention) // 7 years default
	
	// Test missing Redis client
	config.RedisClient = nil
	_, err = NewAuthAuditLogger(config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "redis client is required")
	
	// Test missing secret key
	config.RedisClient = suite.redisClient
	config.SecretKey = ""
	_, err = NewAuthAuditLogger(config)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "secret key is required")
}

// TestLogAuthEvent tests basic audit event logging
func (suite *AuthAuditTestSuite) TestLogAuthEvent() {
	entry := &AuthAuditEntry{
		EventType:     AuthEventLogin,
		UserID:        "test-user-123",
		Username:      "testuser",
		Email:         "test@example.com",
		Success:       true,
		IPAddress:     "192.168.1.100",
		UserAgent:     "Mozilla/5.0",
		AuthMethod:    "oidc",
	}
	
	err := suite.logger.LogAuthEvent(suite.ctx, entry)
	assert.NoError(suite.T(), err)
	
	// Verify event was enriched
	assert.NotEmpty(suite.T(), entry.EventID)
	assert.NotZero(suite.T(), entry.EventTime)
	assert.Equal(suite.T(), AuditSeverityInfo, entry.Severity)
	assert.NotZero(suite.T(), entry.RiskScore)
	assert.NotEmpty(suite.T(), entry.Signature)
	assert.Equal(suite.T(), "HMAC-SHA256", entry.SignatureMethod)
}

// TestLogLoginAttempt tests login attempt logging (AC1)
func (suite *AuthAuditTestSuite) TestLogLoginAttempt() {
	// Test successful login
	req := createTestRequest("POST", "/auth/login", "192.168.1.100")
	
	err := suite.logger.LogLoginAttempt(suite.ctx, "user-123", "testuser", "test@example.com", true, "", req)
	assert.NoError(suite.T(), err)
	
	// Test failed login
	err = suite.logger.LogLoginAttempt(suite.ctx, "", "testuser", "test@example.com", false, "invalid_credentials", req)
	assert.NoError(suite.T(), err)
	
	// Verify request context is captured
	assert.Equal(suite.T(), "user-123", suite.logger.entryBuffer[0].UserID)
	assert.Equal(suite.T(), "192.168.1.100", suite.logger.entryBuffer[0].IPAddress)
}

// TestLogCommandExecution tests command execution logging (AC2)
func (suite *AuthAuditTestSuite) TestLogCommandExecution() {
	claims := &JWTClaims{
		UserID:           "user-123",
		Email:            "test@example.com",
		KubernetesUser:   "test-k8s-user",
		KubernetesGroups: []string{"developers", "viewers"},
	}
	
	req := createTestRequest("POST", "/api/v1/command", "10.0.0.1")
	
	err := suite.logger.LogCommandExecution(suite.ctx, "user-123", "session-456", claims, 
		"get all pods in default namespace", "kubectl get pods -n default", req)
	assert.NoError(suite.T(), err)
	
	// Verify command context is captured
	entry := suite.logger.entryBuffer[0]
	assert.Equal(suite.T(), "kubectl get pods -n default", entry.KubernetesCommand)
	assert.Equal(suite.T(), "get all pods in default namespace", entry.NaturalLanguageInput)
	assert.Equal(suite.T(), claims.KubernetesUser, entry.KubernetesUser)
	assert.Equal(suite.T(), claims.KubernetesGroups, entry.KubernetesGroups)
}

// TestLogSessionEvent tests session-related event logging
func (suite *AuthAuditTestSuite) TestLogSessionEvent() {
	err := suite.logger.LogSessionEvent(suite.ctx, AuthEventSessionTimeout, "session-123", "user-456", "idle_timeout")
	assert.NoError(suite.T(), err)
	
	entry := suite.logger.entryBuffer[0]
	assert.Equal(suite.T(), AuthEventSessionTimeout, entry.EventType)
	assert.Equal(suite.T(), "session-123", entry.SessionID)
	assert.Equal(suite.T(), "user-456", entry.UserID)
	assert.Equal(suite.T(), "idle_timeout", entry.Message)
}

// TestLogSuspiciousActivity tests suspicious activity logging
func (suite *AuthAuditTestSuite) TestLogSuspiciousActivity() {
	req := createTestRequest("POST", "/auth/login", "192.168.1.100")
	
	err := suite.logger.LogSuspiciousActivity(suite.ctx, "user-123", "session-456", 
		"Multiple failed login attempts from same IP", 8, req)
	assert.NoError(suite.T(), err)
	
	entry := suite.logger.entryBuffer[0]
	assert.Equal(suite.T(), AuthEventSuspiciousActivity, entry.EventType)
	assert.Equal(suite.T(), 8, entry.RiskScore)
	assert.Equal(suite.T(), AuditSeverityCritical, entry.Severity)
	assert.Contains(suite.T(), entry.ComplianceFlags, "SOC2")
	assert.Contains(suite.T(), entry.ComplianceFlags, "SECURITY_INCIDENT")
}

// TestSignatureGeneration tests tamper-proof signature generation
func (suite *AuthAuditTestSuite) TestSignatureGeneration() {
	entry := &AuthAuditEntry{
		EventID:   "test-event-123",
		EventType: AuthEventLogin,
		EventTime: time.Now(),
		UserID:    "user-123",
		SessionID: "session-456",
		IPAddress: "192.168.1.100",
		Success:   true,
		Message:   "Successful login",
	}
	
	// Generate signature
	signature, err := suite.logger.generateSignature(entry)
	assert.NoError(suite.T(), err)
	assert.NotEmpty(suite.T(), signature)
	assert.Equal(suite.T(), 64, len(signature)) // SHA256 hex = 64 chars
	
	// Set signature and verify
	entry.Signature = signature
	assert.True(suite.T(), suite.logger.VerifySignature(entry))
	
	// Test tampering detection
	entry.Success = false // Tamper with the entry
	assert.False(suite.T(), suite.logger.VerifySignature(entry))
}

// TestSeverityDetermination tests automatic severity determination
func (suite *AuthAuditTestSuite) TestSeverityDetermination() {
	tests := []struct {
		eventType        AuthEvent
		success          bool
		expectedSeverity AuditSeverity
	}{
		{AuthEventLogin, true, AuditSeverityInfo},
		{AuthEventLoginFailure, false, AuditSeverityWarning},
		{AuthEventAccountLocked, false, AuditSeverityCritical},
		{AuthEventSuspiciousActivity, false, AuditSeverityCritical},
		{AuthEventPermissionDenied, false, AuditSeverityError},
		{AuthEventSessionTimeout, true, AuditSeverityWarning},
		{AuthEventMFASuccess, true, AuditSeverityInfo},
	}
	
	for _, tt := range tests {
		severity := suite.logger.determineSeverity(tt.eventType, tt.success)
		assert.Equal(suite.T(), tt.expectedSeverity, severity, 
			"Event: %s, Success: %t", tt.eventType, tt.success)
	}
}

// TestRiskScoreCalculation tests risk score calculation
func (suite *AuthAuditTestSuite) TestRiskScoreCalculation() {
	tests := []struct {
		name           string
		entry          *AuthAuditEntry
		expectedScore  int
		description    string
	}{
		{
			name: "successful_login",
			entry: &AuthAuditEntry{
				EventType: AuthEventLogin,
				Success:   true,
			},
			expectedScore: 1,
			description:   "Base score for successful login",
		},
		{
			name: "failed_login",
			entry: &AuthAuditEntry{
				EventType: AuthEventLoginFailure,
				Success:   false,
			},
			expectedScore: 6, // 1 base + 3 failed + 2 login failure
			description:   "Higher score for failed login",
		},
		{
			name: "account_locked",
			entry: &AuthAuditEntry{
				EventType: AuthEventAccountLocked,
				Success:   false,
			},
			expectedScore: 9, // 1 base + 3 failed + 5 account locked
			description:   "High score for account lockout",
		},
		{
			name: "brute_force_attempt",
			entry: &AuthAuditEntry{
				EventType:     AuthEventLoginFailure,
				Success:       false,
				FailureReason: "brute force attack detected",
			},
			expectedScore: 9, // 1 base + 3 failed + 2 login failure + 3 brute force
			description:   "Maximum risk for brute force",
		},
	}
	
	for _, tt := range tests {
		suite.T().Run(tt.name, func(t *testing.T) {
			score := suite.logger.calculateRiskScore(tt.entry)
			assert.Equal(t, tt.expectedScore, score, tt.description)
		})
	}
}

// TestBatchProcessing tests batch processing functionality
func (suite *AuthAuditTestSuite) TestBatchProcessing() {
	// Mock Redis pipeline operations
	mockPipeline := &MockPipeliner{}
	mockPipeline.On("Exec", mock.Anything).Return(nil, nil)
	suite.redisClient.On("Pipeline").Return(mockPipeline)
	
	// Add multiple entries to trigger batch flush
	for i := 0; i < suite.logger.batchSize+1; i++ {
		entry := &AuthAuditEntry{
			EventType: AuthEventLogin,
			UserID:    fmt.Sprintf("user-%d", i),
			Success:   true,
		}
		
		err := suite.logger.LogAuthEvent(suite.ctx, entry)
		assert.NoError(suite.T(), err)
	}
	
	// Should have triggered automatic flush, buffer should be smaller
	assert.True(suite.T(), len(suite.logger.entryBuffer) <= suite.logger.batchSize)
}

// TestComplianceIntegration tests compliance-related features
func (suite *AuthAuditTestSuite) TestComplianceIntegration() {
	entry := &AuthAuditEntry{
		EventType:       AuthEventAccountLocked,
		UserID:          "user-123",
		Success:         false,
		ComplianceFlags: []string{"SOC2", "HIPAA"},
	}
	
	err := suite.logger.LogAuthEvent(suite.ctx, entry)
	assert.NoError(suite.T(), err)
	
	// Verify compliance flags are preserved
	loggedEntry := suite.logger.entryBuffer[0]
	assert.Contains(suite.T(), loggedEntry.ComplianceFlags, "SOC2")
	assert.Contains(suite.T(), loggedEntry.ComplianceFlags, "HIPAA")
	
	// Verify tamper-proof signature
	assert.NotEmpty(suite.T(), loggedEntry.Signature)
	assert.True(suite.T(), suite.logger.VerifySignature(loggedEntry))
}

// TestSIEMFormatting tests SIEM integration formatting
func (suite *AuthAuditTestSuite) TestSIEMFormatting() {
	entry := &AuthAuditEntry{
		EventType: AuthEventLogin,
		UserID:    "user-123",
		Username:  "testuser",
		SessionID: "session-456",
		IPAddress: "192.168.1.100",
		Severity:  AuditSeverityInfo,
		Success:   true,
		Message:   "User login successful",
	}
	
	siemFormat := suite.logger.formatForSIEM(entry)
	
	// Verify CEF format
	assert.True(suite.T(), strings.HasPrefix(siemFormat, "CEF:0|KubeChat|AuthAudit|1.0|"))
	assert.Contains(suite.T(), siemFormat, "src=192.168.1.100")
	assert.Contains(suite.T(), siemFormat, "suser=testuser")
	assert.Contains(suite.T(), siemFormat, "cs1=session-456")
}

// TestAuditMetrics tests audit logging metrics
func (suite *AuthAuditTestSuite) TestAuditMetrics() {
	// Log some events to generate metrics
	for i := 0; i < 3; i++ {
		entry := &AuthAuditEntry{
			EventType: AuthEventLogin,
			UserID:    fmt.Sprintf("user-%d", i),
			Success:   true,
		}
		suite.logger.LogAuthEvent(suite.ctx, entry)
	}
	
	metrics := suite.logger.GetAuditMetrics()
	
	assert.Contains(suite.T(), metrics, "total_logs")
	assert.Contains(suite.T(), metrics, "failed_logs")
	assert.Contains(suite.T(), metrics, "buffer_size")
	assert.Contains(suite.T(), metrics, "siem_enabled")
	
	// Buffer should contain the logged events
	assert.Equal(suite.T(), 3, metrics["buffer_size"])
}

// Helper functions

func createTestRequest(method, path, clientIP string) *http.Request {
	req, _ := http.NewRequest(method, path, nil)
	req.Header.Set("X-Forwarded-For", clientIP)
	req.Header.Set("User-Agent", "KubeChat-Test/1.0")
	req.Header.Set("X-Request-ID", "test-request-123")
	return req
}

// TestSuite runner
func TestAuthAuditTestSuite(t *testing.T) {
	suite.Run(t, new(AuthAuditTestSuite))
}

// Additional unit tests for utility functions

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name       string
		setupReq   func() *http.Request
		expectedIP string
	}{
		{
			name: "x_forwarded_for",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("X-Forwarded-For", "192.168.1.100, 10.0.0.1")
				return req
			},
			expectedIP: "192.168.1.100",
		},
		{
			name: "x_real_ip",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.Header.Set("X-Real-IP", "203.0.113.1")
				return req
			},
			expectedIP: "203.0.113.1",
		},
		{
			name: "remote_addr",
			setupReq: func() *http.Request {
				req, _ := http.NewRequest("GET", "/", nil)
				req.RemoteAddr = "198.51.100.1:12345"
				return req
			},
			expectedIP: "198.51.100.1",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			ip := getClientIP(req)
			assert.Equal(t, tt.expectedIP, ip)
		})
	}
}

func TestIsSensitiveHeader(t *testing.T) {
	tests := []struct {
		header     string
		isSensitive bool
	}{
		{"Authorization", true},
		{"Cookie", true},
		{"X-API-Key", true},
		{"X-Auth-Token", true},
		{"User-Agent", false},
		{"Content-Type", false},
		{"X-Request-ID", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			result := isSensitiveHeader(tt.header)
			assert.Equal(t, tt.isSensitive, result)
		})
	}
}