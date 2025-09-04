package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-redis/redismock/v9"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Setup
func setupSIEMIntegrationTest(provider SIEMProvider) (*SIEMIntegrationManager, redis.Cmdable, redismock.ClientMock, *httptest.Server) {
	db, mock := redismock.NewClientMock()

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock SIEM endpoint responses
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "success"}`))
	}))

	siemConfig := SIEMConfig{
		Provider:       provider,
		Endpoint:       server.URL,
		APIKey:         "test-api-key",
		Index:          "kubechat-events",
		BatchSize:      10,
		FlushInterval:  100 * time.Millisecond,
		RetryAttempts:  2,
		TimeoutSeconds: 5,
	}

	complianceConfig := ComplianceConfig{
		Frameworks:      []ComplianceFramework{ComplianceSOX, ComplianceSOC2},
		ReportingPeriod: "daily",
		RetentionDays:   365,
		AlertThresholds: map[string]int{
			"failed_logins": 5,
			"suspicious_activity": 3,
		},
	}

	manager := NewSIEMIntegrationManager(siemConfig, complianceConfig, db)
	
	return manager, db, mock, server
}

// Test SIEM Configuration
func TestNewSIEMIntegrationManager(t *testing.T) {
	tests := []struct {
		name           string
		siemConfig     SIEMConfig
		expectedBatch  int
		expectedFlush  time.Duration
		expectedRetry  int
		expectedTimeout int
	}{
		{
			name: "Default configuration",
			siemConfig: SIEMConfig{
				Provider: SIEMSplunk,
				Endpoint: "https://splunk.example.com",
			},
			expectedBatch:   100,
			expectedFlush:   30 * time.Second,
			expectedRetry:   3,
			expectedTimeout: 30,
		},
		{
			name: "Custom configuration",
			siemConfig: SIEMConfig{
				Provider:       SIEMElastic,
				Endpoint:       "https://elastic.example.com",
				BatchSize:      50,
				FlushInterval:  10 * time.Second,
				RetryAttempts:  5,
				TimeoutSeconds: 60,
			},
			expectedBatch:   50,
			expectedFlush:   10 * time.Second,
			expectedRetry:   5,
			expectedTimeout: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, _ := redismock.NewClientMock()
			complianceConfig := ComplianceConfig{}

			manager := NewSIEMIntegrationManager(tt.siemConfig, complianceConfig, db)

			assert.Equal(t, tt.expectedBatch, manager.config.BatchSize)
			assert.Equal(t, tt.expectedFlush, manager.config.FlushInterval)
			assert.Equal(t, tt.expectedRetry, manager.config.RetryAttempts)
			assert.Equal(t, tt.expectedTimeout, manager.config.TimeoutSeconds)

			// Cleanup
			manager.Close()
		})
	}
}

// Test Sending Auth Events
func TestSendAuthEvent(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	entry := AuthAuditEntry{
		EventID:          "test-event-123",
		EventType:        AuthEventLogin,
		EventTime:        time.Now(),
		Severity:         AuditSeverityWarning,
		UserID:           "user123",
		Username:         "testuser",
		SessionID:        "session123",
		IPAddress:        "192.168.1.1",
		UserAgent:        "Mozilla/5.0",
		EventDescription: "User login successful",
		Namespace:        "default",
		Resource:         "pods",
		Action:           "get",
		Success:          true,
	}

	err := manager.SendAuthEvent(entry)
	assert.NoError(t, err)

	// Wait for event processing
	time.Sleep(200 * time.Millisecond)
}

// Test Sending Security Events
func TestSendSecurityEvent(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMElastic)
	defer server.Close()
	defer manager.Close()

	metadata := map[string]string{
		"attempt_count": "3",
		"source_ip":     "203.0.113.1",
	}

	err := manager.SendSecurityEvent(
		"suspicious_activity",
		"Multiple failed login attempts detected",
		"user123",
		"session123",
		"203.0.113.1",
		AuditSeverityError,
		metadata,
	)

	assert.NoError(t, err)

	// Wait for event processing
	time.Sleep(200 * time.Millisecond)
}

// Test SIEM Provider-Specific Sending
func TestSIEMProviderSending(t *testing.T) {
	providers := []SIEMProvider{
		SIEMSplunk,
		SIEMElastic,
		SIEMArcSight,
		SIEMQRadar,
		SIEMSentinel,
	}

	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			manager, _, _, server := setupSIEMIntegrationTest(provider)
			defer server.Close()
			defer manager.Close()

			// Create test events
			events := []SIEMEvent{
				{
					Timestamp:   time.Now(),
					EventID:     "test-001",
					Source:      "kubechat-test",
					EventType:   "test_event",
					Severity:    "Medium",
					UserID:      "user123",
					SessionID:   "session123",
					IPAddress:   "192.168.1.1",
					Description: "Test event",
					Metadata: map[string]interface{}{
						"test": "data",
					},
				},
			}

			err := manager.sendToSIEM(events)
			assert.NoError(t, err)
		})
	}
}

// Test CEF Format Conversion
func TestConvertToCEF(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMArcSight)
	defer server.Close()
	defer manager.Close()

	event := SIEMEvent{
		Timestamp:   time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		EventID:     "test-001",
		EventType:   "login",
		Severity:    "Medium",
		UserID:      "user123",
		SessionID:   "session123",
		IPAddress:   "192.168.1.1",
		Description: "User login event",
	}

	cef := manager.convertToCEF(event)
	
	assert.Contains(t, cef, "CEF:0")
	assert.Contains(t, cef, "Anthropic")
	assert.Contains(t, cef, "KubeChat")
	assert.Contains(t, cef, "login")
	assert.Contains(t, cef, "User login event")
	assert.Contains(t, cef, "Medium")
	assert.Contains(t, cef, "src=192.168.1.1")
	assert.Contains(t, cef, "suser=user123")
	assert.Contains(t, cef, "cs1=session123")
}

// Test LEEF Format Conversion
func TestConvertToLEEF(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMQRadar)
	defer server.Close()
	defer manager.Close()

	event := SIEMEvent{
		Timestamp:   time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		EventID:     "test-001",
		EventType:   "login",
		Severity:    "Medium",
		UserID:      "user123",
		SessionID:   "session123",
		IPAddress:   "192.168.1.1",
		Description: "User login event",
	}

	leef := manager.convertToLEEF(event)
	
	assert.Contains(t, leef, "LEEF:2.0")
	assert.Contains(t, leef, "Anthropic")
	assert.Contains(t, leef, "KubeChat")
	assert.Contains(t, leef, "login")
	assert.Contains(t, leef, "src=192.168.1.1")
	assert.Contains(t, leef, "usrName=user123")
	assert.Contains(t, leef, "msg=User login event")
}

// Test Compliance Context Generation
func TestGetComplianceContext(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	tests := []struct {
		name       string
		entry      AuthAuditEntry
		frameworks []ComplianceFramework
		expectedControlID string
	}{
		{
			name: "Login event with SOX compliance",
			entry: AuthAuditEntry{
				EventType: AuthEventLogin,
				Severity:  AuditSeverityWarning,
			},
			frameworks:        []ComplianceFramework{ComplianceSOX},
			expectedControlID: "IT-AC-01",
		},
		{
			name: "Failed login with SOC2 compliance",
			entry: AuthAuditEntry{
				EventType: AuthEventLoginFailure,
				Severity:  AuditSeverityError,
			},
			frameworks:        []ComplianceFramework{ComplianceSOC2},
			expectedControlID: "CC6.2",
		},
		{
			name: "Permission denied with ISO27001",
			entry: AuthAuditEntry{
				EventType: AuthEventPermissionDenied,
				Severity:  AuditSeverityCritical,
			},
			frameworks:        []ComplianceFramework{ComplianceISO27001},
			expectedControlID: "A.9.2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Update manager's compliance frameworks
			manager.compliance.Frameworks = tt.frameworks

			context := manager.getComplianceContext(tt.entry)
			
			require.NotNil(t, context)
			assert.Equal(t, tt.frameworks[0], context.Framework)
			assert.Equal(t, tt.expectedControlID, context.ControlID)
			assert.NotEmpty(t, context.Requirement)
			assert.NotEmpty(t, context.RiskLevel)
		})
	}
}

// Test Severity Mapping
func TestMapAuditSeverityToSIEM(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	tests := []struct {
		input    AuditSeverity
		expected string
	}{
		{AuditSeverityInfo, "Low"},
		{AuditSeverityWarning, "Medium"},
		{AuditSeverityError, "High"},
		{AuditSeverityCritical, "Critical"},
	}

	for _, tt := range tests {
		result := manager.mapAuditSeverityToSIEM(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

// Test Risk Level Mapping
func TestMapSeverityToRisk(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	tests := []struct {
		input    AuditSeverity
		expected string
	}{
		{AuditSeverityInfo, "Low"},
		{AuditSeverityWarning, "Medium"},
		{AuditSeverityError, "High"},
		{AuditSeverityCritical, "Critical"},
	}

	for _, tt := range tests {
		result := manager.mapSeverityToRisk(tt.input)
		assert.Equal(t, tt.expected, result)
	}
}

// Test Failed Event Storage
func TestStoreFailedEvents(t *testing.T) {
	manager, _, redisMock, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	events := []SIEMEvent{
		{
			EventID:     "failed-001",
			Timestamp:   time.Now(),
			Source:      "test",
			EventType:   "test_event",
			Severity:    "Medium",
			Description: "Test failed event",
		},
	}

	// Setup Redis expectations
	redisMock.ExpectSet("failed_siem_events:failed-001", 
		".*", // Match any JSON content
		24*time.Hour).SetVal("OK")

	manager.storeFailedEvents(events)

	// Verify Redis expectations
	err := redisMock.ExpectationsWereMet()
	assert.NoError(t, err)
}

// Test Compliance Report Generation
func TestGenerateComplianceReport(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	report, err := manager.GenerateComplianceReport(ComplianceSOX, "daily")
	
	require.NoError(t, err)
	require.NotNil(t, report)
	
	assert.NotEmpty(t, report.ID)
	assert.Equal(t, ComplianceSOX, report.Framework)
	assert.Equal(t, "daily", report.Period)
	assert.NotZero(t, report.GeneratedAt)
	assert.Greater(t, report.TotalEvents, int64(0))
	assert.Greater(t, report.SecurityEvents, int64(0))
	assert.Greater(t, report.ComplianceScore, float64(0))
	assert.NotEmpty(t, report.Controls)
	assert.NotEmpty(t, report.Violations)
	assert.NotEmpty(t, report.Recommendations)
}

// Test Control Requirements
func TestGetControlRequirement(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	tests := []struct {
		framework ComplianceFramework
		controlID string
		expected  string
	}{
		{
			ComplianceSOX,
			"IT-AC-01",
			"Access controls must be properly configured and monitored",
		},
		{
			ComplianceSOC2,
			"CC6.1",
			"Logical access security measures protect information assets",
		},
		{
			ComplianceSOX,
			"unknown-control",
			"Access control and monitoring requirement",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s-%s", tt.framework, tt.controlID), func(t *testing.T) {
			result := manager.getControlRequirement(tt.framework, tt.controlID)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test Event Buffer Handling
func TestEventBufferHandling(t *testing.T) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()

	// Test buffer overflow protection
	for i := 0; i < manager.config.BatchSize*3; i++ {
		err := manager.SendSecurityEvent(
			"test_event",
			fmt.Sprintf("Test event %d", i),
			"user123",
			"session123",
			"192.168.1.1",
			AuditSeverityInfo,
			nil,
		)
		
		if i < manager.config.BatchSize*2 {
			assert.NoError(t, err)
		} else {
			// Buffer should be full at this point
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "event buffer full")
		}
	}

	manager.Close()
}

// Test HTTP Client Timeout
func TestHTTPClientTimeout(t *testing.T) {
	// Create a slow server
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second) // Longer than our configured timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	db, _ := redismock.NewClientMock()

	siemConfig := SIEMConfig{
		Provider:       SIEMSplunk,
		Endpoint:       slowServer.URL,
		APIKey:         "test-key",
		TimeoutSeconds: 1, // 1 second timeout
	}

	complianceConfig := ComplianceConfig{}
	manager := NewSIEMIntegrationManager(siemConfig, complianceConfig, db)
	defer manager.Close()

	events := []SIEMEvent{
		{
			EventID:     "timeout-test",
			Timestamp:   time.Now(),
			Source:      "test",
			EventType:   "test",
			Severity:    "Low",
			Description: "Timeout test event",
		},
	}

	err := manager.sendToSIEM(events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

// Test SIEM Error Handling
func TestSIEMErrorHandling(t *testing.T) {
	// Create error server
	errorServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal Server Error"))
	}))
	defer errorServer.Close()

	db, _ := redismock.NewClientMock()

	siemConfig := SIEMConfig{
		Provider: SIEMSplunk,
		Endpoint: errorServer.URL,
		APIKey:   "test-key",
	}

	complianceConfig := ComplianceConfig{}
	manager := NewSIEMIntegrationManager(siemConfig, complianceConfig, db)
	defer manager.Close()

	events := []SIEMEvent{
		{
			EventID:     "error-test",
			Timestamp:   time.Now(),
			Source:      "test",
			EventType:   "test",
			Severity:    "Low",
			Description: "Error test event",
		},
	}

	err := manager.sendToSIEM(events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SIEM returned error status: 500")
}

// Benchmark Tests
func BenchmarkSendAuthEvent(b *testing.B) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMSplunk)
	defer server.Close()
	defer manager.Close()

	entry := AuthAuditEntry{
		EventID:          "bench-event",
		EventType:        AuthEventLogin,
		EventTime:        time.Now(),
		Severity:         AuditSeverityWarning,
		UserID:           "user123",
		EventDescription: "Benchmark test event",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.SendAuthEvent(entry)
	}
}

func BenchmarkConvertToCEF(b *testing.B) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMArcSight)
	defer server.Close()
	defer manager.Close()

	event := SIEMEvent{
		Timestamp:   time.Now(),
		EventID:     "bench-001",
		EventType:   "login",
		Severity:    "Medium",
		UserID:      "user123",
		IPAddress:   "192.168.1.1",
		Description: "Benchmark event",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.convertToCEF(event)
	}
}

func BenchmarkConvertToLEEF(b *testing.B) {
	manager, _, _, server := setupSIEMIntegrationTest(SIEMQRadar)
	defer server.Close()
	defer manager.Close()

	event := SIEMEvent{
		Timestamp:   time.Now(),
		EventID:     "bench-001",
		EventType:   "login",
		Severity:    "Medium",
		UserID:      "user123",
		IPAddress:   "192.168.1.1",
		Description: "Benchmark event",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = manager.convertToLEEF(event)
	}
}