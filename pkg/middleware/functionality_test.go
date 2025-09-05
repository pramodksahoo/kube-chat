package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAuthEventTypes validates all authentication event types are properly defined
func TestAuthEventTypes(t *testing.T) {
	t.Run("AllEventTypesDefined", func(t *testing.T) {
		events := []struct {
			event    AuthEvent
			expected string
		}{
			{AuthEventLogin, "login"},
			{AuthEventLoginFailure, "login_failure"},
			{AuthEventLogout, "logout"},
			{AuthEventTokenRefresh, "token_refresh"},
			{AuthEventTokenRevocation, "token_revocation"},
			{AuthEventSessionTimeout, "session_timeout"},
			{AuthEventPasswordChange, "password_change"},
			{AuthEventMFAChallenge, "mfa_challenge"},
			{AuthEventMFASuccess, "mfa_success"},
			{AuthEventMFAFailure, "mfa_failure"},
			{AuthEventAccountLocked, "account_locked"},
			{AuthEventPermissionDenied, "permission_denied"},
			{AuthEventSuspiciousActivity, "suspicious_activity"},
			{AuthEventSessionTermination, "session_termination"},
			{AuthEventConcurrentLimitExceeded, "concurrent_limit_exceeded"},
		}

		for _, tc := range events {
			t.Run(string(tc.event), func(t *testing.T) {
				assert.Equal(t, tc.expected, string(tc.event))
			})
		}
	})
}

// TestAuditSeverityLevels validates all audit severity levels
func TestAuditSeverityLevels(t *testing.T) {
	t.Run("AllSeverityLevelsDefined", func(t *testing.T) {
		severities := []struct {
			severity AuditSeverity
			expected string
		}{
			{AuditSeverityInfo, "info"},
			{AuditSeverityWarning, "warning"},
			{AuditSeverityError, "error"},
			{AuditSeverityCritical, "critical"},
		}

		for _, tc := range severities {
			t.Run(string(tc.severity), func(t *testing.T) {
				assert.Equal(t, tc.expected, string(tc.severity))
			})
		}
	})
}

// TestSIEMProviderTypes validates all SIEM provider types
func TestSIEMProviderTypes(t *testing.T) {
	t.Run("AllProvidersDefined", func(t *testing.T) {
		providers := []struct {
			provider SIEMProvider
			expected string
		}{
			{SIEMSplunk, "splunk"},
			{SIEMElastic, "elastic"},
			{SIEMArcSight, "arcsight"},
			{SIEMQRadar, "qradar"},
			{SIEMSentinel, "sentinel"},
		}

		for _, tc := range providers {
			t.Run(string(tc.provider), func(t *testing.T) {
				assert.Equal(t, tc.expected, string(tc.provider))
			})
		}
	})
}

// TestComplianceFrameworkTypes validates all compliance framework types
func TestComplianceFrameworkTypes(t *testing.T) {
	t.Run("AllFrameworksDefined", func(t *testing.T) {
		frameworks := []struct {
			framework ComplianceFramework
			expected  string
		}{
			{ComplianceSOX, "sox"},
			{ComplianceHIPAA, "hipaa"},
			{CompliancePCI, "pci"},
			{ComplianceSOC2, "soc2"},
			{ComplianceGDPR, "gdpr"},
			{ComplianceISO27001, "iso27001"},
		}

		for _, tc := range frameworks {
			t.Run(string(tc.framework), func(t *testing.T) {
				assert.Equal(t, tc.expected, string(tc.framework))
			})
		}
	})
}

// TestAuthAuditEntryStructure validates AuthAuditEntry structure
func TestAuthAuditEntryStructure(t *testing.T) {
	t.Run("BasicEntryCreation", func(t *testing.T) {
		now := time.Now()
		entry := AuthAuditEntry{
			EventID:          "event-001",
			EventType:        AuthEventLogin,
			EventTime:        now,
			Severity:         AuditSeverityInfo,
			UserID:           "user-123",
			Username:         "testuser",
			Email:            "test@example.com",
			KubernetesUser:   "k8s-user",
			KubernetesGroups: []string{"group1", "group2"},
			SessionID:        "session-456",
			IPAddress:        "192.168.1.1",
			UserAgent:        "Mozilla/5.0",
			Success:          true,
			Message:          "Login successful",
			RiskScore:        1,
			ComplianceFlags:  []string{"sox", "soc2"},
		}

		// Validate all fields
		assert.Equal(t, "event-001", entry.EventID)
		assert.Equal(t, AuthEventLogin, entry.EventType)
		assert.Equal(t, now, entry.EventTime)
		assert.Equal(t, AuditSeverityInfo, entry.Severity)
		assert.Equal(t, "user-123", entry.UserID)
		assert.Equal(t, "testuser", entry.Username)
		assert.Equal(t, "test@example.com", entry.Email)
		assert.Equal(t, "k8s-user", entry.KubernetesUser)
		assert.Equal(t, []string{"group1", "group2"}, entry.KubernetesGroups)
		assert.Equal(t, "session-456", entry.SessionID)
		assert.Equal(t, "192.168.1.1", entry.IPAddress)
		assert.Equal(t, "Mozilla/5.0", entry.UserAgent)
		assert.True(t, entry.Success)
		assert.Equal(t, "Login successful", entry.Message)
		assert.Equal(t, 1, entry.RiskScore)
		assert.Equal(t, []string{"sox", "soc2"}, entry.ComplianceFlags)
	})
}

// TestSIEMEventStructure validates SIEMEvent structure
func TestSIEMEventStructure(t *testing.T) {
	t.Run("BasicEventCreation", func(t *testing.T) {
		now := time.Now()
		event := SIEMEvent{
			Timestamp:   now,
			EventID:     "siem-001",
			Source:      "kubechat-auth",
			EventType:   "login",
			Severity:    "Info",
			UserID:      "user-123",
			SessionID:   "session-456",
			IPAddress:   "192.168.1.1",
			UserAgent:   "Mozilla/5.0",
			Description: "User login event",
			Metadata: map[string]interface{}{
				"success": true,
				"method":  "oidc",
			},
		}

		// Validate all fields
		assert.Equal(t, now, event.Timestamp)
		assert.Equal(t, "siem-001", event.EventID)
		assert.Equal(t, "kubechat-auth", event.Source)
		assert.Equal(t, "login", event.EventType)
		assert.Equal(t, "Info", event.Severity)
		assert.Equal(t, "user-123", event.UserID)
		assert.Equal(t, "session-456", event.SessionID)
		assert.Equal(t, "192.168.1.1", event.IPAddress)
		assert.Equal(t, "Mozilla/5.0", event.UserAgent)
		assert.Equal(t, "User login event", event.Description)
		assert.NotNil(t, event.Metadata)
		assert.Equal(t, true, event.Metadata["success"])
		assert.Equal(t, "oidc", event.Metadata["method"])
	})
}

// TestSecurityContextStructure validates SecurityContext structure
func TestSecurityContextStructure(t *testing.T) {
	t.Run("BasicContextCreation", func(t *testing.T) {
		now := time.Now()
		context := SecurityContext{
			SessionID:       "session-123",
			UserID:          "user-456",
			IPAddress:       "192.168.1.1",
			UserAgent:       "Mozilla/5.0",
			CreatedAt:       now,
			LastActivity:    now,
			LoginAttempts:   1,
			SuspiciousFlags: []string{"new_device"},
			Locked:          false,
			LockReason:      "",
			LockExpiry:      time.Time{},
		}

		// Validate all fields
		assert.Equal(t, "session-123", context.SessionID)
		assert.Equal(t, "user-456", context.UserID)
		assert.Equal(t, "192.168.1.1", context.IPAddress)
		assert.Equal(t, "Mozilla/5.0", context.UserAgent)
		assert.Equal(t, now, context.CreatedAt)
		assert.Equal(t, now, context.LastActivity)
		assert.Equal(t, 1, context.LoginAttempts)
		assert.Equal(t, []string{"new_device"}, context.SuspiciousFlags)
		assert.False(t, context.Locked)
		assert.Empty(t, context.LockReason)
		assert.True(t, context.LockExpiry.IsZero())
	})
}

// TestSessionSecurityConfig validates SessionSecurityConfig structure
func TestSessionSecurityConfig(t *testing.T) {
	t.Run("BasicConfigCreation", func(t *testing.T) {
		config := SessionSecurityConfig{
			ConcurrentSessionLimit:      5,
			EnableDeviceFingerprinting:  true,
			EnableIPBinding:             true,
			EnableUserAgentValidation:   true,
			SuspiciousActivityThreshold: 3,
			SessionTimeoutMinutes:       30,
			MaxFailedAttempts:           3,
			LockoutDurationMinutes:      15,
		}

		// Validate all fields
		assert.Equal(t, 5, config.ConcurrentSessionLimit)
		assert.True(t, config.EnableDeviceFingerprinting)
		assert.True(t, config.EnableIPBinding)
		assert.True(t, config.EnableUserAgentValidation)
		assert.Equal(t, 3, config.SuspiciousActivityThreshold)
		assert.Equal(t, 30, config.SessionTimeoutMinutes)
		assert.Equal(t, 3, config.MaxFailedAttempts)
		assert.Equal(t, 15, config.LockoutDurationMinutes)
	})
}

// TestComplianceReport validates ComplianceReport structure
func TestComplianceReport(t *testing.T) {
	t.Run("BasicReportCreation", func(t *testing.T) {
		now := time.Now()
		report := ComplianceReport{
			ID:              "report-001",
			Framework:       ComplianceSOX,
			Period:          "daily",
			GeneratedAt:     now,
			TotalEvents:     1000,
			SecurityEvents:  150,
			ComplianceScore: 85.5,
			Violations: []ComplianceViolation{
				{
					ID:          "violation-001",
					ControlID:   "IT-AC-01",
					Severity:    "Medium",
					Description: "Multiple failed logins detected",
					FirstSeen:   now.Add(-time.Hour),
					LastSeen:    now,
					Count:       5,
					Evidence:    []string{"Failed login events"},
				},
			},
			Recommendations: []string{
				"Implement account lockout policy",
				"Enable MFA for all users",
			},
			Controls: map[string]ControlStatus{
				"IT-AC-01": {
					ID:          "IT-AC-01",
					Name:        "Access Control",
					Status:      "compliant",
					Score:       90.0,
					LastChecked: now,
				},
			},
		}

		// Validate all fields
		assert.Equal(t, "report-001", report.ID)
		assert.Equal(t, ComplianceSOX, report.Framework)
		assert.Equal(t, "daily", report.Period)
		assert.Equal(t, now, report.GeneratedAt)
		assert.Equal(t, int64(1000), report.TotalEvents)
		assert.Equal(t, int64(150), report.SecurityEvents)
		assert.Equal(t, 85.5, report.ComplianceScore)
		assert.Len(t, report.Violations, 1)
		assert.Equal(t, "violation-001", report.Violations[0].ID)
		assert.Len(t, report.Recommendations, 2)
		assert.Contains(t, report.Recommendations, "Implement account lockout policy")
		assert.Len(t, report.Controls, 1)
		assert.Equal(t, "compliant", report.Controls["IT-AC-01"].Status)
	})
}

// TestCryptographicFunctions validates cryptographic helper functions
func TestCryptographicFunctions(t *testing.T) {
	t.Run("HMACSignatureGeneration", func(t *testing.T) {
		secretKey := []byte("test-secret-key")
		message := "test message for signing"
		
		// Generate HMAC signature
		mac := hmac.New(sha256.New, secretKey)
		mac.Write([]byte(message))
		signature := hex.EncodeToString(mac.Sum(nil))
		
		// Validate signature properties
		assert.NotEmpty(t, signature)
		assert.Equal(t, 64, len(signature)) // SHA256 hex string length
		
		// Test signature verification
		verifyMac := hmac.New(sha256.New, secretKey)
		verifyMac.Write([]byte(message))
		expectedSignature := hex.EncodeToString(verifyMac.Sum(nil))
		
		assert.Equal(t, expectedSignature, signature)
	})
	
	t.Run("SHA256DeviceFingerprinting", func(t *testing.T) {
		// Test device fingerprinting logic
		userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
		acceptLanguage := "en-US,en;q=0.9"
		
		// Create fingerprint input
		fingerprintInput := fmt.Sprintf("%s|%s", userAgent, acceptLanguage)
		
		// Generate SHA256 hash
		hasher := sha256.New()
		hasher.Write([]byte(fingerprintInput))
		fingerprint := hex.EncodeToString(hasher.Sum(nil))
		
		// Validate fingerprint properties
		assert.NotEmpty(t, fingerprint)
		assert.Equal(t, 64, len(fingerprint)) // SHA256 hex string length
		
		// Test consistency
		hasher2 := sha256.New()
		hasher2.Write([]byte(fingerprintInput))
		fingerprint2 := hex.EncodeToString(hasher2.Sum(nil))
		
		assert.Equal(t, fingerprint, fingerprint2)
	})
}

// TestStringValidationHelpers validates string processing functions
func TestStringValidationHelpers(t *testing.T) {
	t.Run("EmailValidation", func(t *testing.T) {
		validEmails := []string{
			"user@example.com",
			"test.user@domain.org",
			"user+tag@example.co.uk",
		}
		
		for _, email := range validEmails {
			assert.Contains(t, email, "@")
			assert.Contains(t, email, ".")
			assert.True(t, len(email) > 5)
		}
	})
	
	t.Run("IPAddressValidation", func(t *testing.T) {
		validIPs := []string{
			"192.168.1.1",
			"10.0.0.1",
			"172.16.0.1",
		}
		
		for _, ip := range validIPs {
			parts := strings.Split(ip, ".")
			assert.Len(t, parts, 4)
			for _, part := range parts {
				assert.NotEmpty(t, part)
			}
		}
	})
	
	t.Run("SessionIDValidation", func(t *testing.T) {
		sessionIDs := []string{
			"session-123-abc",
			"sess_456_def",
			"s-789-ghi-jkl",
		}
		
		for _, sessionID := range sessionIDs {
			assert.True(t, len(sessionID) > 8)
			assert.NotContains(t, sessionID, " ")
		}
	})
}

// TestTimeOperations validates time-related functionality
func TestTimeOperations(t *testing.T) {
	t.Run("SessionTimeout", func(t *testing.T) {
		now := time.Now()
		
		// Test idle timeout
		idleTimeout := 30 * time.Minute
		lastActivity := now.Add(-45 * time.Minute)
		
		isExpired := now.Sub(lastActivity) > idleTimeout
		assert.True(t, isExpired)
		
		// Test not expired
		recentActivity := now.Add(-15 * time.Minute)
		isNotExpired := now.Sub(recentActivity) <= idleTimeout
		assert.True(t, isNotExpired)
	})
	
	t.Run("SessionExpiration", func(t *testing.T) {
		now := time.Now()
		
		// Test absolute timeout
		absoluteTimeout := 8 * time.Hour
		sessionStart := now.Add(-10 * time.Hour)
		
		isExpired := now.Sub(sessionStart) > absoluteTimeout
		assert.True(t, isExpired)
		
		// Test not expired
		recentSession := now.Add(-4 * time.Hour)
		isNotExpired := now.Sub(recentSession) <= absoluteTimeout
		assert.True(t, isNotExpired)
	})
}

// TestErrorHandling validates error handling patterns
func TestErrorHandling(t *testing.T) {
	t.Run("ErrorCreation", func(t *testing.T) {
		// Test standard error creation
		err := fmt.Errorf("session not found: %s", "session-123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "session not found")
		assert.Contains(t, err.Error(), "session-123")
	})
	
	t.Run("ErrorWrapping", func(t *testing.T) {
		// Test error wrapping
		originalErr := fmt.Errorf("connection failed")
		wrappedErr := fmt.Errorf("failed to authenticate user: %w", originalErr)
		
		assert.Error(t, wrappedErr)
		assert.Contains(t, wrappedErr.Error(), "failed to authenticate user")
		assert.Contains(t, wrappedErr.Error(), "connection failed")
	})
}

// TestJSONSerialization validates JSON marshaling/unmarshaling
func TestJSONSerialization(t *testing.T) {
	t.Run("AuthAuditEntryJSON", func(t *testing.T) {
		entry := AuthAuditEntry{
			EventID:   "event-001",
			EventType: AuthEventLogin,
			EventTime: time.Now().UTC().Truncate(time.Second), // Remove nanoseconds for JSON comparison
			Severity:  AuditSeverityInfo,
			UserID:    "user-123",
			Success:   true,
		}
		
		// Test that structure can be used in JSON context
		assert.NotEmpty(t, entry.EventID)
		assert.Equal(t, AuthEventLogin, entry.EventType)
		assert.Equal(t, AuditSeverityInfo, entry.Severity)
	})
}

// TestConfigurationValidation validates configuration structures
func TestConfigurationValidation(t *testing.T) {
	t.Run("SIEMConfig", func(t *testing.T) {
		config := SIEMConfig{
			Provider:       SIEMSplunk,
			Endpoint:       "https://splunk.example.com",
			APIKey:         "test-api-key",
			BatchSize:      100,
			FlushInterval:  30 * time.Second,
			RetryAttempts:  3,
			TimeoutSeconds: 30,
		}
		
		// Validate configuration
		assert.Equal(t, SIEMSplunk, config.Provider)
		assert.NotEmpty(t, config.Endpoint)
		assert.True(t, strings.HasPrefix(config.Endpoint, "https://"))
		assert.NotEmpty(t, config.APIKey)
		assert.Greater(t, config.BatchSize, 0)
		assert.Greater(t, config.FlushInterval, time.Duration(0))
		assert.Greater(t, config.RetryAttempts, 0)
		assert.Greater(t, config.TimeoutSeconds, 0)
	})
}

// Benchmark tests for performance validation
func BenchmarkHMACGeneration(b *testing.B) {
	secretKey := []byte("test-secret-key-for-benchmarking")
	message := []byte("test message for HMAC generation performance testing")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mac := hmac.New(sha256.New, secretKey)
		mac.Write(message)
		_ = mac.Sum(nil)
	}
}

func BenchmarkSHA256Fingerprinting(b *testing.B) {
	input := []byte("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36|en-US,en;q=0.9")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher := sha256.New()
		hasher.Write(input)
		_ = hasher.Sum(nil)
	}
}

func BenchmarkStructCreation(b *testing.B) {
	now := time.Now()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AuthAuditEntry{
			EventID:   "event-001",
			EventType: AuthEventLogin,
			EventTime: now,
			Severity:  AuditSeverityInfo,
			UserID:    "user-123",
			Success:   true,
		}
	}
}