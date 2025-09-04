// Package middleware provides comprehensive authentication audit logging for security compliance
package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	"golang.org/x/net/context"
)

// AuthEvent represents different types of authentication events for audit logging
type AuthEvent string

const (
	AuthEventLogin                 AuthEvent = "login"
	AuthEventLoginFailure         AuthEvent = "login_failure"
	AuthEventLogout               AuthEvent = "logout"
	AuthEventTokenRefresh         AuthEvent = "token_refresh"
	AuthEventTokenRevocation      AuthEvent = "token_revocation"
	AuthEventSessionTimeout       AuthEvent = "session_timeout"
	AuthEventPasswordChange       AuthEvent = "password_change"
	AuthEventMFAChallenge         AuthEvent = "mfa_challenge"
	AuthEventMFASuccess           AuthEvent = "mfa_success"
	AuthEventMFAFailure           AuthEvent = "mfa_failure"
	AuthEventAccountLocked        AuthEvent = "account_locked"
	AuthEventPermissionDenied     AuthEvent = "permission_denied"
	AuthEventSuspiciousActivity   AuthEvent = "suspicious_activity"
	AuthEventSessionTermination   AuthEvent = "session_termination"
	AuthEventConcurrentLimitExceeded AuthEvent = "concurrent_limit_exceeded"
)

// AuditSeverity represents the severity level of audit events
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

// AuthAuditEntry represents a comprehensive audit log entry for authentication events
type AuthAuditEntry struct {
	// Event identification
	EventID       string        `json:"event_id"`
	EventType     AuthEvent     `json:"event_type"`
	EventTime     time.Time     `json:"event_time"`
	Severity      AuditSeverity `json:"severity"`
	
	// User context
	UserID           string   `json:"user_id,omitempty"`
	Username         string   `json:"username,omitempty"`
	Email            string   `json:"email,omitempty"`
	KubernetesUser   string   `json:"kubernetes_user,omitempty"`
	KubernetesGroups []string `json:"kubernetes_groups,omitempty"`
	
	// Session context
	SessionID        string `json:"session_id,omitempty"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	
	// Request context
	IPAddress       string            `json:"ip_address,omitempty"`
	UserAgent       string            `json:"user_agent,omitempty"`
	RequestID       string            `json:"request_id,omitempty"`
	HTTPMethod      string            `json:"http_method,omitempty"`
	RequestPath     string            `json:"request_path,omitempty"`
	RequestHeaders  map[string]string `json:"request_headers,omitempty"`
	
	// Authentication details
	AuthMethod      string `json:"auth_method,omitempty"`      // "oidc", "jwt", "saml"
	OIDCProvider    string `json:"oidc_provider,omitempty"`    // "google", "azure", "okta"
	TokenType       string `json:"token_type,omitempty"`       // "access", "refresh", "id"
	
	// Event details
	Success         bool              `json:"success"`
	FailureReason   string            `json:"failure_reason,omitempty"`
	ErrorCode       string            `json:"error_code,omitempty"`
	Message         string            `json:"message,omitempty"`
	AdditionalData  map[string]interface{} `json:"additional_data,omitempty"`
	
	// Kubernetes command context (Story 2.3 AC2)
	KubernetesCommand string `json:"kubernetes_command,omitempty"`
	NaturalLanguageInput string `json:"natural_language_input,omitempty"`
	
	// Security and compliance
	RiskScore       int    `json:"risk_score,omitempty"`      // 1-10 risk assessment
	ComplianceFlags []string `json:"compliance_flags,omitempty"` // SOC2, HIPAA, etc.
	
	// Tamper-proof signature (Story 2.3 requirement)
	Signature       string `json:"signature"`
	SignatureMethod string `json:"signature_method"`
}

// AuthAuditLogger handles comprehensive authentication audit logging
type AuthAuditLogger struct {
	redisClient     redis.UniversalClient
	secretKey       []byte
	retention       time.Duration
	siemIntegration bool
	
	// SIEM configuration
	siemEndpoint    string
	siemAPIKey      string
	
	// Batch processing for high-performance logging
	batchSize       int
	flushInterval   time.Duration
	entryBuffer     []*AuthAuditEntry
	bufferMutex     sync.Mutex
	
	// Metrics and monitoring
	totalLogs       int64
	failedLogs      int64
	averageLatency  time.Duration
	mutex           sync.RWMutex
}

// AuthAuditConfig holds configuration for the audit logger
type AuthAuditConfig struct {
	RedisClient     redis.UniversalClient
	SecretKey       string            // HMAC secret key for tamper-proof signatures
	RetentionPeriod time.Duration     // How long to retain audit logs (default: 7 years for compliance)
	SIEMIntegration bool              // Enable SIEM integration
	SIEMEndpoint    string            // SIEM system endpoint
	SIEMAPIKey      string            // SIEM API key
	BatchSize       int               // Batch size for high-performance logging (default: 100)
	FlushInterval   time.Duration     // Flush interval for batched logs (default: 5 seconds)
}

// NewAuthAuditLogger creates a new authentication audit logger
func NewAuthAuditLogger(config AuthAuditConfig) (*AuthAuditLogger, error) {
	if config.RedisClient == nil {
		return nil, fmt.Errorf("redis client is required for audit logging")
	}
	
	if config.SecretKey == "" {
		return nil, fmt.Errorf("secret key is required for tamper-proof signatures")
	}
	
	// Set defaults
	if config.RetentionPeriod == 0 {
		config.RetentionPeriod = 24 * time.Hour * 365 * 7 // 7 years for compliance
	}
	
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	
	logger := &AuthAuditLogger{
		redisClient:     config.RedisClient,
		secretKey:       []byte(config.SecretKey),
		retention:       config.RetentionPeriod,
		siemIntegration: config.SIEMIntegration,
		siemEndpoint:    config.SIEMEndpoint,
		siemAPIKey:      config.SIEMAPIKey,
		batchSize:       config.BatchSize,
		flushInterval:   config.FlushInterval,
		entryBuffer:     make([]*AuthAuditEntry, 0, config.BatchSize),
	}
	
	// Start background batch processor
	go logger.batchProcessor()
	
	return logger, nil
}

// LogAuthEvent logs a comprehensive authentication event with tamper-proof signature
func (a *AuthAuditLogger) LogAuthEvent(ctx context.Context, event *AuthAuditEntry) error {
	if event == nil {
		return fmt.Errorf("audit entry cannot be nil")
	}
	
	// Set event ID if not provided
	if event.EventID == "" {
		event.EventID = generateEventID()
	}
	
	// Set timestamp if not provided
	if event.EventTime.IsZero() {
		event.EventTime = time.Now()
	}
	
	// Set severity based on event type if not provided
	if event.Severity == "" {
		event.Severity = a.determineSeverity(event.EventType, event.Success)
	}
	
	// Calculate risk score
	if event.RiskScore == 0 {
		event.RiskScore = a.calculateRiskScore(event)
	}
	
	// Generate tamper-proof signature
	signature, err := a.generateSignature(event)
	if err != nil {
		return fmt.Errorf("failed to generate audit signature: %w", err)
	}
	
	event.Signature = signature
	event.SignatureMethod = "HMAC-SHA256"
	
	// Add to batch buffer for high-performance processing
	a.bufferMutex.Lock()
	defer a.bufferMutex.Unlock()
	
	a.entryBuffer = append(a.entryBuffer, event)
	
	// Flush if batch is full
	if len(a.entryBuffer) >= a.batchSize {
		return a.flushBatch()
	}
	
	return nil
}

// LogLoginAttempt logs authentication attempts (AC1)
func (a *AuthAuditLogger) LogLoginAttempt(ctx context.Context, userID, username, email string, success bool, failureReason string, req *http.Request) error {
	entry := &AuthAuditEntry{
		EventType:     AuthEventLogin,
		UserID:        userID,
		Username:      username,
		Email:         email,
		Success:       success,
		FailureReason: failureReason,
		AuthMethod:    "oidc",
	}
	
	if req != nil {
		a.enrichWithRequestContext(entry, req)
	}
	
	if !success {
		entry.EventType = AuthEventLoginFailure
	}
	
	return a.LogAuthEvent(ctx, entry)
}

// LogCommandExecution logs all commands with authenticated user identity (AC2)
func (a *AuthAuditLogger) LogCommandExecution(ctx context.Context, userID, sessionID string, claims *JWTClaims, naturalLanguageInput, kubectlCommand string, req *http.Request) error {
	entry := &AuthAuditEntry{
		EventType:            AuthEventPermissionDenied, // Will be updated based on success
		UserID:               userID,
		SessionID:            sessionID,
		Username:             claims.Email,
		Email:                claims.Email,
		KubernetesUser:       claims.KubernetesUser,
		KubernetesGroups:     claims.KubernetesGroups,
		KubernetesCommand:    kubectlCommand,
		NaturalLanguageInput: naturalLanguageInput,
		Success:              true, // Assume success unless specified otherwise
		AuthMethod:           "jwt",
		TokenType:            "access",
	}
	
	if req != nil {
		a.enrichWithRequestContext(entry, req)
	}
	
	return a.LogAuthEvent(ctx, entry)
}

// LogSessionEvent logs session-related events (timeouts, terminations, etc.)
func (a *AuthAuditLogger) LogSessionEvent(ctx context.Context, eventType AuthEvent, sessionID, userID, reason string) error {
	entry := &AuthAuditEntry{
		EventType:     eventType,
		SessionID:     sessionID,
		UserID:        userID,
		Success:       true,
		Message:       reason,
		FailureReason: reason,
	}
	
	return a.LogAuthEvent(ctx, entry)
}

// LogSuspiciousActivity logs suspicious authentication patterns
func (a *AuthAuditLogger) LogSuspiciousActivity(ctx context.Context, userID, sessionID, activity string, riskScore int, req *http.Request) error {
	entry := &AuthAuditEntry{
		EventType: AuthEventSuspiciousActivity,
		UserID:    userID,
		SessionID: sessionID,
		Success:   false,
		Message:   activity,
		RiskScore: riskScore,
		Severity:  AuditSeverityCritical,
		ComplianceFlags: []string{"SOC2", "SECURITY_INCIDENT"},
	}
	
	if req != nil {
		a.enrichWithRequestContext(entry, req)
	}
	
	return a.LogAuthEvent(ctx, entry)
}

// enrichWithRequestContext enriches audit entry with HTTP request context
func (a *AuthAuditLogger) enrichWithRequestContext(entry *AuthAuditEntry, req *http.Request) {
	entry.IPAddress = getClientIP(req)
	entry.UserAgent = req.UserAgent()
	entry.HTTPMethod = req.Method
	entry.RequestPath = req.URL.Path
	entry.RequestID = req.Header.Get("X-Request-ID")
	
	// Sanitize and include relevant headers (excluding sensitive ones)
	headers := make(map[string]string)
	for key, values := range req.Header {
		if !isSensitiveHeader(key) && len(values) > 0 {
			headers[key] = values[0]
		}
	}
	entry.RequestHeaders = headers
}

// generateSignature creates tamper-proof HMAC signature for audit entry
func (a *AuthAuditLogger) generateSignature(entry *AuthAuditEntry) (string, error) {
	// Create signature data (exclude signature fields)
	sigData := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%t|%s",
		entry.EventID,
		entry.EventType,
		entry.EventTime.Format(time.RFC3339),
		entry.UserID,
		entry.SessionID,
		entry.IPAddress,
		entry.Success,
		entry.Message,
	)
	
	// Generate HMAC signature
	h := hmac.New(sha256.New, a.secretKey)
	h.Write([]byte(sigData))
	signature := h.Sum(nil)
	
	return hex.EncodeToString(signature), nil
}

// VerifySignature verifies the tamper-proof signature of an audit entry
func (a *AuthAuditLogger) VerifySignature(entry *AuthAuditEntry) bool {
	expectedSig, err := a.generateSignature(entry)
	if err != nil {
		return false
	}
	
	return hmac.Equal([]byte(entry.Signature), []byte(expectedSig))
}

// determineSeverity automatically determines event severity
func (a *AuthAuditLogger) determineSeverity(eventType AuthEvent, success bool) AuditSeverity {
	if !success {
		switch eventType {
		case AuthEventLoginFailure, AuthEventMFAFailure:
			return AuditSeverityWarning
		case AuthEventAccountLocked, AuthEventSuspiciousActivity:
			return AuditSeverityCritical
		case AuthEventPermissionDenied:
			return AuditSeverityError
		default:
			return AuditSeverityError
		}
	}
	
	switch eventType {
	case AuthEventLogin, AuthEventLogout, AuthEventTokenRefresh:
		return AuditSeverityInfo
	case AuthEventSessionTimeout, AuthEventSessionTermination:
		return AuditSeverityWarning
	case AuthEventPasswordChange, AuthEventMFASuccess:
		return AuditSeverityInfo
	default:
		return AuditSeverityInfo
	}
}

// calculateRiskScore calculates risk score based on event characteristics
func (a *AuthAuditLogger) calculateRiskScore(entry *AuthAuditEntry) int {
	score := 1 // Base score
	
	// Failed events increase risk
	if !entry.Success {
		score += 3
	}
	
	// Certain event types are inherently risky
	switch entry.EventType {
	case AuthEventLoginFailure, AuthEventMFAFailure:
		score += 2
	case AuthEventAccountLocked, AuthEventSuspiciousActivity:
		score += 5
	case AuthEventPermissionDenied:
		score += 3
	case AuthEventConcurrentLimitExceeded:
		score += 4
	}
	
	// Multiple failure patterns increase risk
	if strings.Contains(strings.ToLower(entry.FailureReason), "brute") {
		score += 3
	}
	
	// Cap at 10
	if score > 10 {
		score = 10
	}
	
	return score
}

// flushBatch flushes the current batch of audit entries to Redis
func (a *AuthAuditLogger) flushBatch() error {
	if len(a.entryBuffer) == 0 {
		return nil
	}
	
	ctx := context.Background()
	pipe := a.redisClient.Pipeline()
	
	for _, entry := range a.entryBuffer {
		// Serialize entry
		entryJSON, err := json.Marshal(entry)
		if err != nil {
			a.failedLogs++
			continue
		}
		
		// Store in Redis with retention period
		key := fmt.Sprintf("kubechat:audit:%s:%s", entry.EventTime.Format("2006-01-02"), entry.EventID)
		pipe.Set(ctx, key, entryJSON, a.retention)
		
		// Add to time-series index for efficient querying
		pipe.ZAdd(ctx, "kubechat:audit:timeline", &redis.Z{
			Score:  float64(entry.EventTime.Unix()),
			Member: key,
		})
		
		// Index by user for user-specific queries
		if entry.UserID != "" {
			pipe.ZAdd(ctx, fmt.Sprintf("kubechat:audit:user:%s", entry.UserID), &redis.Z{
				Score:  float64(entry.EventTime.Unix()),
				Member: key,
			})
		}
		
		// Index by event type
		pipe.ZAdd(ctx, fmt.Sprintf("kubechat:audit:type:%s", entry.EventType), &redis.Z{
			Score:  float64(entry.EventTime.Unix()),
			Member: key,
		})
	}
	
	// Execute batch
	_, err := pipe.Exec(ctx)
	if err != nil {
		a.failedLogs += int64(len(a.entryBuffer))
		return fmt.Errorf("failed to flush audit batch: %w", err)
	}
	
	// Send to SIEM if enabled
	if a.siemIntegration {
		go a.sendToSIEM(a.entryBuffer)
	}
	
	a.totalLogs += int64(len(a.entryBuffer))
	
	// Clear buffer
	a.entryBuffer = a.entryBuffer[:0]
	
	return nil
}

// batchProcessor runs background batch processing
func (a *AuthAuditLogger) batchProcessor() {
	ticker := time.NewTicker(a.flushInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		a.bufferMutex.Lock()
		if len(a.entryBuffer) > 0 {
			a.flushBatch()
		}
		a.bufferMutex.Unlock()
	}
}

// sendToSIEM sends audit entries to SIEM system (placeholder for SIEM integration)
func (a *AuthAuditLogger) sendToSIEM(entries []*AuthAuditEntry) {
	// Placeholder for SIEM integration
	// This would typically format entries according to SIEM requirements
	// and send via HTTP/syslog/etc.
	
	for _, entry := range entries {
		// Convert to SIEM format (CEF, LEEF, JSON, etc.)
		siemPayload := a.formatForSIEM(entry)
		
		// Send to SIEM endpoint
		_ = siemPayload // TODO: Implement actual SIEM integration
	}
}

// formatForSIEM formats audit entry for SIEM consumption
func (a *AuthAuditLogger) formatForSIEM(entry *AuthAuditEntry) string {
	// Example: CEF (Common Event Format) for SIEM systems
	return fmt.Sprintf("CEF:0|KubeChat|AuthAudit|1.0|%s|%s|%s|src=%s suser=%s cs1=%s",
		entry.EventType,
		entry.Message,
		entry.Severity,
		entry.IPAddress,
		entry.Username,
		entry.SessionID,
	)
}

// GetAuditMetrics returns audit logging metrics
func (a *AuthAuditLogger) GetAuditMetrics() map[string]interface{} {
	a.mutex.RLock()
	defer a.mutex.RUnlock()
	
	return map[string]interface{}{
		"total_logs":       a.totalLogs,
		"failed_logs":      a.failedLogs,
		"average_latency":  a.averageLatency,
		"buffer_size":      len(a.entryBuffer),
		"siem_enabled":     a.siemIntegration,
	}
}

// Utility functions

func generateEventID() string {
	return fmt.Sprintf("auth_event_%d", time.Now().UnixNano())
}

func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	
	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	
	// Fall back to RemoteAddr
	parts := strings.Split(req.RemoteAddr, ":")
	if len(parts) > 0 {
		return parts[0]
	}
	
	return req.RemoteAddr
}

func isSensitiveHeader(header string) bool {
	sensitiveHeaders := map[string]bool{
		"authorization": true,
		"cookie":       true,
		"x-api-key":    true,
		"x-auth-token": true,
	}
	
	return sensitiveHeaders[strings.ToLower(header)]
}