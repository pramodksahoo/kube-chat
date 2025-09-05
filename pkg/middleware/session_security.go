// Package middleware provides session security hardening for enhanced protection
package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SessionSecurityManager handles session security hardening and protection
type SessionSecurityManager struct {
	jwtService      JWTServiceInterface
	auditLogger     *AuthAuditLogger
	
	// Security configuration
	concurrentLimit       int
	enableFingerprinting  bool
	enableIPBinding       bool
	enableUserAgentCheck  bool
	suspiciousThreshold   int
	lockoutDuration      time.Duration
	
	// Runtime tracking
	activeSessions       map[string]*SecurityContext // sessionID -> context
	userSessionCounts    map[string]int              // userID -> count
	suspiciousActivities map[string]*SuspiciousTracker // userID -> tracker
	mutex               sync.RWMutex
}

// SecurityContext represents security context for a session
type SecurityContext struct {
	SessionID         string
	UserID            string
	DeviceFingerprint string
	IPAddress         string
	UserAgent         string
	CreatedAt         time.Time
	LastActivity      time.Time
	LoginAttempts     int
	SuspiciousFlags   []string
	Locked            bool
	LockReason        string
	LockExpiry        time.Time
}

// SuspiciousTracker tracks suspicious activities for a user
type SuspiciousTracker struct {
	UserID               string
	FailedLogins         int
	LastFailedLogin      time.Time
	SuspiciousIPs        map[string]int
	DeviceChanges        int
	ConcurrentSessions   int
	RiskScore           int
	AlertTriggered      bool
}

// SessionSecurityConfig holds configuration for session security
type SessionSecurityConfig struct {
	JWTService             JWTServiceInterface
	AuditLogger           *AuthAuditLogger
	ConcurrentLimit       int           // Max concurrent sessions per user (default: 5)
	EnableFingerprinting  bool          // Enable device fingerprinting (default: true)
	EnableIPBinding       bool          // Bind sessions to IP addresses (default: true)
	EnableUserAgentCheck  bool          // Check user agent consistency (default: true)
	SuspiciousThreshold   int           // Threshold for suspicious activity (default: 3)
	LockoutDuration      time.Duration // Account lockout duration (default: 30 minutes)
}

// SessionCookieConfig represents secure cookie configuration
type SessionCookieConfig struct {
	Name     string
	Domain   string
	Path     string
	MaxAge   int
	Secure   bool
	HttpOnly bool
	SameSite http.SameSite
}

// NewSessionSecurityManager creates a new session security manager
func NewSessionSecurityManager(config SessionSecurityConfig) (*SessionSecurityManager, error) {
	if config.JWTService == nil {
		return nil, fmt.Errorf("JWT service is required")
	}
	
	if config.AuditLogger == nil {
		return nil, fmt.Errorf("audit logger is required")
	}
	
	// Set defaults
	if config.ConcurrentLimit == 0 {
		config.ConcurrentLimit = 5
	}
	
	if config.SuspiciousThreshold == 0 {
		config.SuspiciousThreshold = 3
	}
	
	if config.LockoutDuration == 0 {
		config.LockoutDuration = 30 * time.Minute
	}
	
	return &SessionSecurityManager{
		jwtService:           config.JWTService,
		auditLogger:         config.AuditLogger,
		concurrentLimit:     config.ConcurrentLimit,
		enableFingerprinting: config.EnableFingerprinting,
		enableIPBinding:     config.EnableIPBinding,
		enableUserAgentCheck: config.EnableUserAgentCheck,
		suspiciousThreshold: config.SuspiciousThreshold,
		lockoutDuration:     config.LockoutDuration,
		activeSessions:      make(map[string]*SecurityContext),
		userSessionCounts:   make(map[string]int),
		suspiciousActivities: make(map[string]*SuspiciousTracker),
	}, nil
}

// SecureSessionMiddleware creates middleware for secure session handling
func (ssm *SessionSecurityManager) SecureSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		
		// Extract session information from request
		sessionID, userID, err := ssm.extractSessionInfo(r)
		if err != nil {
			ssm.auditLogger.LogAuthEvent(ctx, &AuthAuditEntry{
				EventType:     AuthEventPermissionDenied,
				Success:       false,
				FailureReason: fmt.Sprintf("Session extraction failed: %v", err),
				IPAddress:     getClientIP(r),
				UserAgent:     r.UserAgent(),
			})
			http.Error(w, "Invalid session", http.StatusUnauthorized)
			return
		}
		
		// Check if session is locked
		if ssm.isSessionLocked(userID) {
			ssm.auditLogger.LogSuspiciousActivity(ctx, userID, sessionID, 
				"Attempted access with locked session", 9, r)
			http.Error(w, "Session locked due to suspicious activity", http.StatusLocked)
			return
		}
		
		// Validate security constraints
		if err := ssm.validateSessionSecurity(ctx, sessionID, userID, r); err != nil {
			ssm.auditLogger.LogSuspiciousActivity(ctx, userID, sessionID, 
				fmt.Sprintf("Security validation failed: %v", err), 7, r)
			http.Error(w, "Security validation failed", http.StatusForbidden)
			return
		}
		
		// Update session activity
		ssm.updateSessionActivity(sessionID, userID, r)
		
		// Set secure session cookie
		ssm.setSecureCookie(w, sessionID)
		
		next.ServeHTTP(w, r)
	})
}

// CreateSessionWithSecurity creates a new session with security hardening
func (ssm *SessionSecurityManager) CreateSessionWithSecurity(ctx context.Context, userID, email, name string, r *http.Request) (*TokenPair, error) {
	// Check concurrent session limits
	if ssm.checkConcurrentLimit(userID) {
		ssm.auditLogger.LogAuthEvent(ctx, &AuthAuditEntry{
			EventType:     AuthEventConcurrentLimitExceeded,
			Success:       false,
			UserID:        userID,
			FailureReason: fmt.Sprintf("Concurrent session limit (%d) exceeded", ssm.concurrentLimit),
			IPAddress:     getClientIP(r),
			UserAgent:     r.UserAgent(),
		})
		return nil, fmt.Errorf("concurrent session limit exceeded")
	}
	
	// Generate device fingerprint
	fingerprint := ssm.generateDeviceFingerprint(r)
	
	// Check for suspicious device changes
	if ssm.checkDeviceChange(userID, fingerprint) {
		ssm.auditLogger.LogSuspiciousActivity(ctx, userID, "", 
			"Suspicious device change detected", 6, r)
	}
	
	// Create JWT token
	tokenPair, err := ssm.jwtService.GenerateToken(userID, email, name)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	
	// Create security context
	securityContext := &SecurityContext{
		SessionID:         extractSessionIDFromToken(tokenPair.AccessToken),
		UserID:            userID,
		DeviceFingerprint: fingerprint,
		IPAddress:         getClientIP(r),
		UserAgent:         r.UserAgent(),
		CreatedAt:         time.Now(),
		LastActivity:      time.Now(),
		LoginAttempts:     0,
		SuspiciousFlags:   []string{},
		Locked:            false,
	}
	
	// Store security context
	ssm.storeSecurityContext(securityContext)
	
	// Log successful session creation
	ssm.auditLogger.LogAuthEvent(ctx, &AuthAuditEntry{
		EventType:         AuthEventLogin,
		Success:           true,
		UserID:            userID,
		SessionID:         securityContext.SessionID,
		IPAddress:         securityContext.IPAddress,
		UserAgent:         securityContext.UserAgent,
		DeviceFingerprint: securityContext.DeviceFingerprint,
		Message:           "Secure session created with hardening",
	})
	
	return tokenPair, nil
}

// ValidateSessionSecurity validates session security constraints
func (ssm *SessionSecurityManager) validateSessionSecurity(ctx context.Context, sessionID, userID string, r *http.Request) error {
	ssm.mutex.RLock()
	securityContext, exists := ssm.activeSessions[sessionID]
	ssm.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("security context not found for session")
	}
	
	currentIP := getClientIP(r)
	currentUA := r.UserAgent()
	currentFingerprint := ssm.generateDeviceFingerprint(r)
	
	// IP binding validation
	if ssm.enableIPBinding && securityContext.IPAddress != currentIP {
		ssm.recordSuspiciousActivity(userID, "ip_address_change")
		return fmt.Errorf("IP address mismatch: session bound to %s, request from %s", 
			securityContext.IPAddress, currentIP)
	}
	
	// User agent consistency check
	if ssm.enableUserAgentCheck && !ssm.isUserAgentConsistent(securityContext.UserAgent, currentUA) {
		ssm.recordSuspiciousActivity(userID, "user_agent_change")
		return fmt.Errorf("suspicious user agent change detected")
	}
	
	// Device fingerprint validation
	if ssm.enableFingerprinting && securityContext.DeviceFingerprint != currentFingerprint {
		ssm.recordSuspiciousActivity(userID, "device_fingerprint_change")
		return fmt.Errorf("device fingerprint mismatch")
	}
	
	return nil
}

// generateDeviceFingerprint creates a unique fingerprint for the device
func (ssm *SessionSecurityManager) generateDeviceFingerprint(r *http.Request) string {
	// Collect fingerprinting data
	fingerprint := strings.Builder{}
	
	// User Agent
	fingerprint.WriteString(r.UserAgent())
	fingerprint.WriteString("|")
	
	// Accept headers (indicating browser capabilities)
	fingerprint.WriteString(r.Header.Get("Accept"))
	fingerprint.WriteString("|")
	
	fingerprint.WriteString(r.Header.Get("Accept-Language"))
	fingerprint.WriteString("|")
	
	fingerprint.WriteString(r.Header.Get("Accept-Encoding"))
	fingerprint.WriteString("|")
	
	// Connection info
	fingerprint.WriteString(r.Header.Get("Connection"))
	fingerprint.WriteString("|")
	
	// Other identifying headers (without sensitive info)
	if dnt := r.Header.Get("DNT"); dnt != "" {
		fingerprint.WriteString(dnt)
	}
	fingerprint.WriteString("|")
	
	if upgradeInsecure := r.Header.Get("Upgrade-Insecure-Requests"); upgradeInsecure != "" {
		fingerprint.WriteString(upgradeInsecure)
	}
	
	// Hash the fingerprint for consistency
	hash := sha256.Sum256([]byte(fingerprint.String()))
	return hex.EncodeToString(hash[:16]) // Use first 16 bytes for shorter fingerprint
}

// checkConcurrentLimit checks if user has exceeded concurrent session limit
func (ssm *SessionSecurityManager) checkConcurrentLimit(userID string) bool {
	ssm.mutex.RLock()
	count := ssm.userSessionCounts[userID]
	ssm.mutex.RUnlock()
	
	return count >= ssm.concurrentLimit
}

// checkDeviceChange checks for suspicious device changes
func (ssm *SessionSecurityManager) checkDeviceChange(userID, fingerprint string) bool {
	ssm.mutex.RLock()
	tracker, exists := ssm.suspiciousActivities[userID]
	ssm.mutex.RUnlock()
	
	if !exists {
		// First time user, initialize tracker
		tracker = &SuspiciousTracker{
			UserID:        userID,
			SuspiciousIPs: make(map[string]int),
		}
		ssm.mutex.Lock()
		ssm.suspiciousActivities[userID] = tracker
		ssm.mutex.Unlock()
		return false
	}
	
	// Check if device changed too frequently
	tracker.DeviceChanges++
	if tracker.DeviceChanges > 3 { // More than 3 device changes
		return true
	}
	
	return false
}

// recordSuspiciousActivity records suspicious activity for a user
func (ssm *SessionSecurityManager) recordSuspiciousActivity(userID, activityType string) {
	ssm.mutex.Lock()
	defer ssm.mutex.Unlock()
	
	tracker, exists := ssm.suspiciousActivities[userID]
	if !exists {
		tracker = &SuspiciousTracker{
			UserID:        userID,
			SuspiciousIPs: make(map[string]int),
		}
		ssm.suspiciousActivities[userID] = tracker
	}
	
	// Increment risk score based on activity type
	switch activityType {
	case "ip_address_change":
		tracker.RiskScore += 2
	case "user_agent_change":
		tracker.RiskScore += 3
	case "device_fingerprint_change":
		tracker.RiskScore += 4
	case "failed_login":
		tracker.FailedLogins++
		tracker.LastFailedLogin = time.Now()
		tracker.RiskScore += 2
	}
	
	// Check if risk threshold exceeded
	if tracker.RiskScore >= ssm.suspiciousThreshold && !tracker.AlertTriggered {
		ssm.triggerSecurityAlert(userID, tracker)
		tracker.AlertTriggered = true
	}
}

// triggerSecurityAlert triggers security alert for suspicious activity
func (ssm *SessionSecurityManager) triggerSecurityAlert(userID string, tracker *SuspiciousTracker) {
	// Lock user sessions
	ssm.lockUserSessions(userID, "suspicious_activity_detected")
	
	// Log security incident
	ssm.auditLogger.LogAuthEvent(context.Background(), &AuthAuditEntry{
		EventType:       AuthEventSuspiciousActivity,
		Success:         false,
		UserID:          userID,
		Message:         fmt.Sprintf("Security alert triggered: risk score %d", tracker.RiskScore),
		RiskScore:       tracker.RiskScore,
		Severity:        AuditSeverityCritical,
		ComplianceFlags: []string{"SECURITY_INCIDENT", "AUTO_LOCKOUT"},
	})
}

// lockUserSessions locks all sessions for a user
func (ssm *SessionSecurityManager) lockUserSessions(userID, reason string) {
	ssm.mutex.Lock()
	defer ssm.mutex.Unlock()
	
	lockExpiry := time.Now().Add(ssm.lockoutDuration)
	
	for _, secContext := range ssm.activeSessions {
		if secContext.UserID == userID {
			secContext.Locked = true
			secContext.LockReason = reason
			secContext.LockExpiry = lockExpiry
		}
	}
	
	// Terminate all JWT tokens for the user
	ssm.jwtService.TerminateAllUserSessions(userID, reason)
}

// isSessionLocked checks if a user's sessions are locked
func (ssm *SessionSecurityManager) isSessionLocked(userID string) bool {
	ssm.mutex.RLock()
	defer ssm.mutex.RUnlock()
	
	for _, secContext := range ssm.activeSessions {
		if secContext.UserID == userID && secContext.Locked {
			// Check if lock has expired
			if time.Now().After(secContext.LockExpiry) {
				// Unlock expired locks
				secContext.Locked = false
				secContext.LockReason = ""
				return false
			}
			return true
		}
	}
	
	return false
}

// isUserAgentConsistent checks if user agent changes are suspicious
func (ssm *SessionSecurityManager) isUserAgentConsistent(original, current string) bool {
	// Extract major components for comparison
	originalParts := strings.Fields(original)
	currentParts := strings.Fields(current)
	
	if len(originalParts) < 2 || len(currentParts) < 2 {
		return false
	}
	
	// Compare major browser/OS identifiers
	// This is a simplified check - production would be more sophisticated
	return strings.Contains(current, originalParts[0]) || 
		   strings.Contains(original, currentParts[0])
}

// storeSecurityContext stores security context for session tracking
func (ssm *SessionSecurityManager) storeSecurityContext(secContext *SecurityContext) {
	ssm.mutex.Lock()
	defer ssm.mutex.Unlock()
	
	ssm.activeSessions[secContext.SessionID] = secContext
	ssm.userSessionCounts[secContext.UserID]++
}

// updateSessionActivity updates session activity timestamp
func (ssm *SessionSecurityManager) updateSessionActivity(sessionID, userID string, r *http.Request) {
	ssm.mutex.Lock()
	defer ssm.mutex.Unlock()
	
	if secContext, exists := ssm.activeSessions[sessionID]; exists {
		secContext.LastActivity = time.Now()
		
		// Update JWT service as well
		ssm.jwtService.UpdateSessionActivity(sessionID)
	}
}

// setSecureCookie sets secure session cookie with hardened flags
func (ssm *SessionSecurityManager) setSecureCookie(w http.ResponseWriter, sessionID string) {
	config := SessionCookieConfig{
		Name:     "kubechat_session",
		Path:     "/",
		MaxAge:   3600 * 8, // 8 hours
		Secure:   true,     // HTTPS only
		HttpOnly: true,     // No JavaScript access
		SameSite: http.SameSiteStrictMode, // CSRF protection
	}
	
	cookie := &http.Cookie{
		Name:     config.Name,
		Value:    sessionID,
		Path:     config.Path,
		MaxAge:   config.MaxAge,
		Secure:   config.Secure,
		HttpOnly: config.HttpOnly,
		SameSite: config.SameSite,
	}
	
	http.SetCookie(w, cookie)
}

// extractSessionInfo extracts session information from request
func (ssm *SessionSecurityManager) extractSessionInfo(r *http.Request) (string, string, error) {
	// Try to get session ID from cookie first
	if cookie, err := r.Cookie("kubechat_session"); err == nil {
		sessionID := cookie.Value
		
		// Get user ID from JWT token (simplified)
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := ssm.jwtService.ValidateToken(token)
			if err != nil {
				return "", "", fmt.Errorf("invalid JWT token: %w", err)
			}
			return sessionID, claims.UserID, nil
		}
		
		return sessionID, "", fmt.Errorf("no JWT token found")
	}
	
	return "", "", fmt.Errorf("no session cookie found")
}

// GetSecurityMetrics returns security-related metrics
func (ssm *SessionSecurityManager) GetSecurityMetrics() map[string]interface{} {
	ssm.mutex.RLock()
	defer ssm.mutex.RUnlock()
	
	lockedSessions := 0
	suspiciousActivities := 0
	highRiskUsers := 0
	
	for _, secContext := range ssm.activeSessions {
		if secContext.Locked {
			lockedSessions++
		}
		if len(secContext.SuspiciousFlags) > 0 {
			suspiciousActivities++
		}
	}
	
	for _, tracker := range ssm.suspiciousActivities {
		if tracker.RiskScore >= ssm.suspiciousThreshold {
			highRiskUsers++
		}
	}
	
	return map[string]interface{}{
		"total_active_sessions":   len(ssm.activeSessions),
		"locked_sessions":         lockedSessions,
		"suspicious_activities":   suspiciousActivities,
		"high_risk_users":         highRiskUsers,
		"concurrent_limit":        ssm.concurrentLimit,
		"fingerprinting_enabled":  ssm.enableFingerprinting,
		"ip_binding_enabled":      ssm.enableIPBinding,
		"user_agent_check_enabled": ssm.enableUserAgentCheck,
		"lockout_duration_minutes": int(ssm.lockoutDuration.Minutes()),
	}
}

// CleanupExpiredSessions removes expired and inactive sessions
func (ssm *SessionSecurityManager) CleanupExpiredSessions() {
	ssm.mutex.Lock()
	defer ssm.mutex.Unlock()
	
	now := time.Now()
	expiredThreshold := now.Add(-24 * time.Hour) // 24 hours of inactivity
	
	for sessionID, secContext := range ssm.activeSessions {
		// Remove expired sessions
		if secContext.LastActivity.Before(expiredThreshold) {
			delete(ssm.activeSessions, sessionID)
			ssm.userSessionCounts[secContext.UserID]--
			
			// Log session expiration
			ssm.auditLogger.LogSessionEvent(context.Background(), 
				AuthEventSessionTimeout, sessionID, secContext.UserID, "session_expired_cleanup")
		}
		
		// Unlock expired locks
		if secContext.Locked && now.After(secContext.LockExpiry) {
			secContext.Locked = false
			secContext.LockReason = ""
			
			// Log lock expiration
			ssm.auditLogger.LogSessionEvent(context.Background(), 
				AuthEventLogin, sessionID, secContext.UserID, "security_lock_expired")
		}
	}
}

// Utility functions

func extractSessionIDFromToken(token string) string {
	// This would properly decode JWT and extract session ID
	// For now, return a simplified session ID
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:8])
}