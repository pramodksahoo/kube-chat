// Package audit provides comprehensive compliance reporting capabilities tests
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewComplianceReportingService(t *testing.T) {
	tests := []struct {
		name         string
		storage      AuditStorage
		traceService *TraceabilityService
		wantError    bool
		expectedErr  string
	}{
		{
			name:         "nil storage",
			storage:      nil,
			traceService: &TraceabilityService{},
			wantError:    true,
			expectedErr:  "storage cannot be nil",
		},
		{
			name:         "nil trace service",
			storage:      &MockAuditStorage{},
			traceService: nil,
			wantError:    true,
			expectedErr:  "trace service cannot be nil",
		},
		{
			name:         "valid parameters",
			storage:      &MockAuditStorage{},
			traceService: &TraceabilityService{},
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewComplianceReportingService(tt.storage, tt.traceService)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestComplianceReportingService_validateReportRequest(t *testing.T) {
	service := &ComplianceReportingService{}

	tests := []struct {
		name        string
		request     ComplianceReportRequest
		wantError   bool
		expectedErr string
	}{
		{
			name: "valid request",
			request: ComplianceReportRequest{
				Framework:   FrameworkSOC2,
				StartTime:   time.Now().Add(-24 * time.Hour),
				EndTime:     time.Now(),
				RequestedBy: "test-user",
			},
			wantError: false,
		},
		{
			name: "missing framework",
			request: ComplianceReportRequest{
				StartTime:   time.Now().Add(-24 * time.Hour),
				EndTime:     time.Now(),
				RequestedBy: "test-user",
			},
			wantError:   true,
			expectedErr: "compliance framework is required",
		},
		{
			name: "missing start time",
			request: ComplianceReportRequest{
				Framework:   FrameworkSOC2,
				EndTime:     time.Now(),
				RequestedBy: "test-user",
			},
			wantError:   true,
			expectedErr: "start time is required",
		},
		{
			name: "missing end time",
			request: ComplianceReportRequest{
				Framework:   FrameworkSOC2,
				StartTime:   time.Now().Add(-24 * time.Hour),
				RequestedBy: "test-user",
			},
			wantError:   true,
			expectedErr: "end time is required",
		},
		{
			name: "start time after end time",
			request: ComplianceReportRequest{
				Framework:   FrameworkSOC2,
				StartTime:   time.Now(),
				EndTime:     time.Now().Add(-24 * time.Hour),
				RequestedBy: "test-user",
			},
			wantError:   true,
			expectedErr: "start time cannot be after end time",
		},
		{
			name: "missing requestor",
			request: ComplianceReportRequest{
				Framework: FrameworkSOC2,
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
			},
			wantError:   true,
			expectedErr: "requestor information is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateReportRequest(tt.request)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestComplianceReportingService_generateReportID(t *testing.T) {
	service := &ComplianceReportingService{}

	request := ComplianceReportRequest{
		Framework:   FrameworkSOC2,
		RequestedBy: "test-user",
		Purpose:     "quarterly-review",
		StartTime:   time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	reportID := service.generateReportID(request)

	assert.NotEmpty(t, reportID)
	assert.Contains(t, reportID, "RPT-SOC2-")
	assert.Len(t, reportID, 25) // "RPT-SOC2-" + 16 char hash

	// Test consistency - same input should produce same ID
	reportID2 := service.generateReportID(request)
	assert.Equal(t, reportID, reportID2)
}

func TestComplianceReportingService_calculateComplianceScore(t *testing.T) {
	service := &ComplianceReportingService{}

	tests := []struct {
		name          string
		framework     ComplianceFramework
		events        []*models.AuditEvent
		expectedScore float64
	}{
		{
			name:          "no events returns perfect score",
			framework:     FrameworkSOC2,
			events:        []*models.AuditEvent{},
			expectedScore: 100.0,
		},
		{
			name:      "all info events returns perfect score",
			framework: FrameworkSOC2,
			events: []*models.AuditEvent{
				{Severity: models.AuditSeverityInfo},
				{Severity: models.AuditSeverityInfo},
				{Severity: models.AuditSeverityInfo},
			},
			expectedScore: 100.0,
		},
		{
			name:      "one error out of three events",
			framework: FrameworkSOC2,
			events: []*models.AuditEvent{
				{Severity: models.AuditSeverityInfo},
				{Severity: models.AuditSeverityError},
				{Severity: models.AuditSeverityInfo},
			},
			expectedScore: 66.67, // 2/3 * 100 = 66.67 (approximately)
		},
		{
			name:      "all critical events returns zero score",
			framework: FrameworkSOC2,
			events: []*models.AuditEvent{
				{Severity: models.AuditSeverityCritical},
				{Severity: models.AuditSeverityCritical},
			},
			expectedScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := service.calculateComplianceScore(tt.framework, tt.events)

			if tt.expectedScore == 66.67 {
				assert.InDelta(t, tt.expectedScore, score, 0.1)
			} else {
				assert.Equal(t, tt.expectedScore, score)
			}
		})
	}
}

func TestComplianceReportingService_determineImpactLevel(t *testing.T) {
	service := &ComplianceReportingService{}

	tests := []struct {
		name     string
		event    *models.AuditEvent
		expected string
	}{
		{
			name: "critical severity is high impact",
			event: &models.AuditEvent{
				Severity: models.AuditSeverityCritical,
			},
			expected: "high",
		},
		{
			name: "error severity is medium impact",
			event: &models.AuditEvent{
				Severity: models.AuditSeverityError,
			},
			expected: "medium",
		},
		{
			name: "warning severity is low impact",
			event: &models.AuditEvent{
				Severity: models.AuditSeverityWarning,
			},
			expected: "low",
		},
		{
			name: "info severity is low impact",
			event: &models.AuditEvent{
				Severity: models.AuditSeverityInfo,
			},
			expected: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			impact := service.determineImpactLevel(tt.event)
			assert.Equal(t, tt.expected, impact)
		})
	}
}

func TestComplianceReportingService_classifySecurityIncident(t *testing.T) {
	service := &ComplianceReportingService{}

	tests := []struct {
		name     string
		event    *models.AuditEvent
		expected string
	}{
		{
			name: "RBAC denied event",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeRBACDenied,
			},
			expected: "unauthorized_access_attempt",
		},
		{
			name: "system error event",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeSystemError,
			},
			expected: "system_error",
		},
		{
			name: "other event type",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeAuthentication,
			},
			expected: "general_security_event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			classification := service.classifySecurityIncident(tt.event)
			assert.Equal(t, tt.expected, classification)
		})
	}
}

func TestComplianceReportingService_isConfigurationChange(t *testing.T) {
	service := &ComplianceReportingService{}

	tests := []struct {
		name     string
		event    *models.AuditEvent
		expected bool
	}{
		{
			name: "kubectl create command",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeCommandExecute,
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl create deployment test",
				},
			},
			expected: true,
		},
		{
			name: "kubectl delete command",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeCommandExecute,
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl delete pod test-pod",
				},
			},
			expected: true,
		},
		{
			name: "kubectl get command",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeCommandExecute,
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl get pods",
				},
			},
			expected: false,
		},
		{
			name: "non-command event",
			event: &models.AuditEvent{
				EventType: models.AuditEventTypeAuthentication,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isConfigurationChange(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestComplianceReportingService_classifyConfigurationChange(t *testing.T) {
	service := &ComplianceReportingService{}

	tests := []struct {
		name     string
		event    *models.AuditEvent
		expected string
	}{
		{
			name: "create command",
			event: &models.AuditEvent{
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl create deployment test",
				},
			},
			expected: "resource_creation",
		},
		{
			name: "delete command",
			event: &models.AuditEvent{
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl delete pod test-pod",
				},
			},
			expected: "resource_deletion",
		},
		{
			name: "update command",
			event: &models.AuditEvent{
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl update deployment test",
				},
			},
			expected: "resource_modification",
		},
		{
			name: "patch command",
			event: &models.AuditEvent{
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl patch pod test-pod",
				},
			},
			expected: "resource_modification",
		},
		{
			name: "other command",
			event: &models.AuditEvent{
				CommandContext: models.CommandContext{
					GeneratedCommand: "kubectl apply -f config.yaml",
				},
			},
			expected: "configuration_change",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.classifyConfigurationChange(tt.event)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestComplianceReportingService_generateSOC2Attestations(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		AccessControls: AccessControlReport{
			UserAccounts: []UserAccountSummary{{}, {}}, // 2 accounts
		},
		SecurityIncidents: SecurityIncidentReport{
			IncidentTimeline: []SecurityIncident{{}, {}, {}}, // 3 incidents
		},
	}

	attestations := service.generateSOC2Attestations(report)

	assert.Len(t, attestations, 2)
	
	// Check first attestation (CC6.1)
	assert.Equal(t, "CC6.1", attestations[0].Control)
	assert.Equal(t, "compliant", attestations[0].Status)
	assert.Contains(t, attestations[0].Evidence, "2 user accounts")
	
	// Check second attestation (CC7.1)
	assert.Equal(t, "CC7.1", attestations[1].Control)
	assert.Equal(t, "compliant", attestations[1].Status)
	assert.Contains(t, attestations[1].Evidence, "3 incidents")
}

func TestComplianceReportingService_generateHIPAAAcertifications(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		Summary: ComplianceSummary{
			TotalAuditEvents: 1000,
		},
	}

	attestations := service.generateHIPAAAcertifications(report)

	assert.Len(t, attestations, 2)
	
	// Check access control attestation
	assert.Equal(t, "164.312(a)(1)", attestations[0].Control)
	assert.Equal(t, "compliant", attestations[0].Status)
	
	// Check audit control attestation
	assert.Equal(t, "164.312(b)", attestations[1].Control)
	assert.Equal(t, "compliant", attestations[1].Status)
	assert.Contains(t, attestations[1].Evidence, "1000 events")
}

func TestComplianceReportingService_calculateIntegrityHash(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:    "TEST-001",
		Framework:   FrameworkSOC2,
		GeneratedAt: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
		Summary: ComplianceSummary{
			TotalAuditEvents: 100,
		},
	}

	hash, err := service.calculateIntegrityHash(report)

	assert.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.Len(t, hash, 64) // SHA-256 hash length

	// Test consistency - same report should produce same hash
	hash2, err := service.calculateIntegrityHash(report)
	assert.NoError(t, err)
	assert.Equal(t, hash, hash2)

	// Test that changing report changes hash
	report.Summary.TotalAuditEvents = 200
	hash3, err := service.calculateIntegrityHash(report)
	assert.NoError(t, err)
	assert.NotEqual(t, hash, hash3)
}

func TestComplianceReportingService_generateDigitalSignature(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:      "TEST-001",
		IntegrityHash: "abcdef123456",
		GeneratedAt:   time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	signature, err := service.generateDigitalSignature(report)

	assert.NoError(t, err)
	assert.NotEmpty(t, signature)
	assert.Len(t, signature, 64) // SHA-256 hash length

	// Test consistency
	signature2, err := service.generateDigitalSignature(report)
	assert.NoError(t, err)
	assert.Equal(t, signature, signature2)
}

func TestComplianceReportingService_ExportReport_JSON(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:  "TEST-001",
		Framework: FrameworkSOC2,
		Summary: ComplianceSummary{
			TotalAuditEvents: 100,
		},
	}

	var buf bytes.Buffer
	err := service.ExportReport(report, ReportFormatJSON, &buf)

	assert.NoError(t, err)
	
	// Verify JSON is valid
	var exported ComplianceReport
	err = json.Unmarshal(buf.Bytes(), &exported)
	assert.NoError(t, err)
	assert.Equal(t, report.ReportID, exported.ReportID)
	assert.Equal(t, report.Framework, exported.Framework)
	assert.Equal(t, report.Summary.TotalAuditEvents, exported.Summary.TotalAuditEvents)
}

func TestComplianceReportingService_ExportReport_XML(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:  "TEST-001",
		Framework: FrameworkSOC2,
		Summary: ComplianceSummary{
			TotalAuditEvents: 100,
		},
	}

	var buf bytes.Buffer
	err := service.ExportReport(report, ReportFormatXML, &buf)

	assert.NoError(t, err)
	
	output := buf.String()
	assert.Contains(t, output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
	assert.Contains(t, output, "<report_id>TEST-001</report_id>")
	assert.Contains(t, output, "<framework>SOC2</framework>")
}

func TestComplianceReportingService_ExportReport_CSV(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:    "TEST-001",
		Framework:   FrameworkSOC2,
		GeneratedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		Summary: ComplianceSummary{
			TotalAuditEvents: 100,
			UniqueUsers:      10,
			SecurityIncidents: 5,
			ComplianceScore:  95.5,
		},
	}

	var buf bytes.Buffer
	err := service.ExportReport(report, ReportFormatCSV, &buf)

	assert.NoError(t, err)
	
	output := buf.String()
	lines := bytes.Split(buf.Bytes(), []byte("\n"))
	
	// Check header
	assert.Contains(t, string(lines[0]), "Section,Metric,Value,Timestamp")
	
	// Check data rows
	assert.Contains(t, output, "Summary,Total Audit Events,100")
	assert.Contains(t, output, "Summary,Unique Users,10")
	assert.Contains(t, output, "Summary,Security Incidents,5")
	assert.Contains(t, output, "Summary,Compliance Score,95.50")
}

func TestComplianceReportingService_ExportReport_HTML(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:    "TEST-001",
		Framework:   FrameworkSOC2,
		GeneratedAt: time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		ReportingPeriod: ReportingPeriod{
			StartDate: time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC),
			EndDate:   time.Date(2023, 1, 31, 0, 0, 0, 0, time.UTC),
		},
		Summary: ComplianceSummary{
			TotalAuditEvents: 100,
			UniqueUsers:      10,
			SecurityIncidents: 5,
			ComplianceScore:  95.5,
		},
	}

	var buf bytes.Buffer
	err := service.ExportReport(report, ReportFormatHTML, &buf)

	assert.NoError(t, err)
	
	output := buf.String()
	assert.Contains(t, output, "<!DOCTYPE html>")
	assert.Contains(t, output, "<title>SOC2 Compliance Report")
	assert.Contains(t, output, "TEST-001")
	assert.Contains(t, output, "100") // Total events
	assert.Contains(t, output, "10")  // Unique users
	assert.Contains(t, output, "5")   // Security incidents
	assert.Contains(t, output, "95.50") // Compliance score
}

func TestComplianceReportingService_ExportReport_UnsupportedFormat(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{}
	var buf bytes.Buffer

	err := service.ExportReport(report, "INVALID", &buf)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported export format")
}

func TestComplianceReportingService_ValidateReportIntegrity(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		ReportID:  "TEST-001",
		Framework: FrameworkSOC2,
		Summary: ComplianceSummary{
			TotalAuditEvents: 100,
		},
	}

	// Calculate initial hash
	hash, err := service.calculateIntegrityHash(report)
	require.NoError(t, err)
	report.IntegrityHash = hash

	// Validate integrity - should be valid
	valid, err := service.ValidateReportIntegrity(report)
	assert.NoError(t, err)
	assert.True(t, valid)

	// Tamper with report
	report.Summary.TotalAuditEvents = 200

	// Validate integrity - should be invalid
	valid, err = service.ValidateReportIntegrity(report)
	assert.NoError(t, err)
	assert.False(t, valid)
}

// Mock implementation for testing GenerateComplianceReport
func TestComplianceReportingService_GenerateComplianceReport(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	traceService := &TraceabilityService{}
	service := &ComplianceReportingService{
		storage:      mockStorage,
		traceService: traceService,
	}

	ctx := context.Background()
	request := ComplianceReportRequest{
		Framework:   FrameworkSOC2,
		StartTime:   time.Now().Add(-24 * time.Hour),
		EndTime:     time.Now(),
		RequestedBy: "test-auditor",
		Purpose:     "quarterly-review",
		Format:      ReportFormatJSON,
	}

	// Mock audit events
	testEvents := []*models.AuditEvent{
		createTestComplianceEvent("event-1", models.AuditEventTypeAuthentication, models.AuditSeverityInfo),
		createTestComplianceEvent("event-2", models.AuditEventTypeRBACCheck, models.AuditSeverityInfo),
		createTestComplianceEvent("event-3", models.AuditEventTypeRBACDenied, models.AuditSeverityWarning),
	}

	// Setup mock expectations
	expectedFilter := models.AuditEventFilter{
		StartTime: request.StartTime,
		EndTime:   request.EndTime,
		Limit:     10000,
	}

	mockStorage.On("QueryEvents", ctx, expectedFilter).Return(testEvents, nil)

	// Additional mock calls for different report sections
	rbacFilter := models.AuditEventFilter{
		StartTime:  request.StartTime,
		EndTime:    request.EndTime,
		EventTypes: []models.AuditEventType{models.AuditEventTypeRBACCheck, models.AuditEventTypeRBACDenied, models.AuditEventTypeAuthentication},
		Limit:      5000,
	}
	mockStorage.On("QueryEvents", ctx, rbacFilter).Return(testEvents[:2], nil)

	criticalFilter := models.AuditEventFilter{
		StartTime:  request.StartTime,
		EndTime:    request.EndTime,
		Severities: []models.AuditSeverity{models.AuditSeverityCritical, models.AuditSeverityError},
		Limit:      1000,
	}
	mockStorage.On("QueryEvents", ctx, criticalFilter).Return([]*models.AuditEvent{}, nil)

	eventTypeCounts := map[models.AuditEventType]int64{
		models.AuditEventTypeAuthentication: 1,
		models.AuditEventTypeRBACCheck:      1,
		models.AuditEventTypeRBACDenied:     1,
	}
	mockStorage.On("CountEventsByType", ctx).Return(eventTypeCounts, nil)

	// Additional mock calls for other report sections
	securityFilter := models.AuditEventFilter{
		StartTime:  request.StartTime,
		EndTime:    request.EndTime,
		EventTypes: []models.AuditEventType{models.AuditEventTypeRBACDenied, models.AuditEventTypeSystemError},
		Limit:      1000,
	}
	mockStorage.On("QueryEvents", ctx, securityFilter).Return([]*models.AuditEvent{testEvents[2]}, nil)

	systemChangeFilter := models.AuditEventFilter{
		StartTime:  request.StartTime,
		EndTime:    request.EndTime,
		EventTypes: []models.AuditEventType{models.AuditEventTypeCommandExecute},
		Limit:      5000,
	}
	mockStorage.On("QueryEvents", ctx, systemChangeFilter).Return([]*models.AuditEvent{}, nil)

	userActivityFilter := models.AuditEventFilter{
		StartTime: request.StartTime,
		EndTime:   request.EndTime,
		Limit:     10000,
	}
	mockStorage.On("QueryEvents", ctx, userActivityFilter).Return(testEvents, nil)

	// Test the method
	report, err := service.GenerateComplianceReport(ctx, request)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.NotEmpty(t, report.ReportID)
	assert.Equal(t, FrameworkSOC2, report.Framework)
	assert.Equal(t, "test-auditor", report.GeneratedBy)
	assert.Equal(t, "quarterly-review", report.Purpose)
	assert.Equal(t, int64(3), report.Summary.TotalAuditEvents)
	assert.Equal(t, int64(1), report.Summary.UniqueUsers) // Only one unique user in test events
	assert.NotEmpty(t, report.IntegrityHash)
	
	mockStorage.AssertExpectations(t)
}

// Helper function to create test audit events for compliance testing
func createTestComplianceEvent(eventID string, eventType models.AuditEventType, severity models.AuditSeverity) *models.AuditEvent {
	now := time.Now().UTC()
	return &models.AuditEvent{
		ID:        eventID,
		Timestamp: now,
		EventType: eventType,
		Severity:  severity,
		Message:   fmt.Sprintf("Test %s event", eventType),
		UserContext: models.UserContext{
			UserID:    "test-user-001",
			Email:     "test@example.com",
			SessionID: "session-123",
		},
		ClusterContext: models.ClusterContext{
			ClusterName: "test-cluster",
			Namespace:   "default",
		},
		CreatedAt: now,
	}
}

func TestComplianceReportingService_GenerateComplianceReport_InvalidRequest(t *testing.T) {
	service := &ComplianceReportingService{}

	ctx := context.Background()
	invalidRequest := ComplianceReportRequest{
		// Missing required fields
	}

	report, err := service.GenerateComplianceReport(ctx, invalidRequest)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid report request")
	assert.Nil(t, report)
}

// Test different compliance frameworks
func TestComplianceReportingService_generateComplianceAttestations_Frameworks(t *testing.T) {
	service := &ComplianceReportingService{}

	report := &ComplianceReport{
		AccessControls: AccessControlReport{
			UserAccounts: []UserAccountSummary{{}, {}},
		},
		SecurityIncidents: SecurityIncidentReport{
			IncidentTimeline: []SecurityIncident{},
		},
	}

	tests := []struct {
		name         string
		framework    ComplianceFramework
		expectedSize int
	}{
		{
			name:         "SOC2 framework",
			framework:    FrameworkSOC2,
			expectedSize: 2,
		},
		{
			name:         "HIPAA framework",
			framework:    FrameworkHIPAA,
			expectedSize: 2,
		},
		{
			name:         "PCI-DSS framework",
			framework:    FrameworkPCIDSS,
			expectedSize: 1,
		},
		{
			name:         "Generic framework",
			framework:    "CUSTOM",
			expectedSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attestations := service.generateComplianceAttestations(tt.framework, report)
			assert.Len(t, attestations, tt.expectedSize)
			
			// All attestations should have required fields
			for _, attestation := range attestations {
				assert.NotEmpty(t, attestation.Control)
				assert.NotEmpty(t, attestation.Description)
				assert.NotEmpty(t, attestation.Status)
				assert.NotEmpty(t, attestation.TestedBy)
			}
		})
	}
}