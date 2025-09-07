package templates

import (
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSOC2Template(t *testing.T) {
	template := NewSOC2Template()
	
	assert.NotNil(t, template)
	assert.Equal(t, "SOC 2 Type I", template.FrameworkName)
	assert.Equal(t, "2017 Trust Services Criteria", template.FrameworkVersion)
	assert.Len(t, template.RequiredControls, 8) // Should have 8 common criteria controls
	
	// Validate first control
	firstControl := template.RequiredControls[0]
	assert.Equal(t, "CC1.1", firstControl.ControlID)
	assert.Equal(t, "Control Environment - Integrity and Ethical Values", firstControl.ControlName)
	assert.Equal(t, "Common Criteria", firstControl.Category)
	assert.NotEmpty(t, firstControl.RequiredEvents)
}

func TestNewHIPAATemplate(t *testing.T) {
	template := NewHIPAATemplate()
	
	assert.NotNil(t, template)
	assert.Equal(t, "HIPAA Technical Safeguards", template.FrameworkName)
	assert.Equal(t, "45 CFR Parts 160, 162, and 164", template.FrameworkVersion)
	assert.Len(t, template.RequiredSafeguards, 8) // Should have 8 technical safeguards
	
	// Validate first safeguard
	firstSafeguard := template.RequiredSafeguards[0]
	assert.Equal(t, "164.308(a)(1)(i)", firstSafeguard.SafeguardID)
	assert.Equal(t, "Security Management Process", firstSafeguard.SafeguardName)
	assert.Equal(t, "Required", firstSafeguard.RequirementLevel)
	assert.NotEmpty(t, firstSafeguard.RequiredEvents)
}

func TestNewISO27001Template(t *testing.T) {
	template := NewISO27001Template()
	
	assert.NotNil(t, template)
	assert.Equal(t, "ISO 27001:2022", template.FrameworkName)
	assert.Equal(t, "ISO/IEC 27001:2022", template.FrameworkVersion)
	assert.Len(t, template.RequiredControls, 10) // Should have 10 selected controls
	
	// Validate first control
	firstControl := template.RequiredControls[0]
	assert.Equal(t, "A.5.1", firstControl.ControlID)
	assert.Equal(t, "Policies for Information Security", firstControl.ControlName)
	assert.Equal(t, "Organizational Controls", firstControl.ControlDomain)
	assert.NotEmpty(t, firstControl.RequiredEvents)
}

func TestSOC2ReportGeneration(t *testing.T) {
	template := NewSOC2Template()
	
	reportInfo := SOC2ReportInfo{
		ReportID:         "SOC2-001",
		ReportPeriod:     "2024-01-01 to 2024-12-31",
		GeneratedAt:      time.Now(),
		ReportType:       "Type I",
		Framework:        "SOC 2",
		OrganizationName: "Test Organization",
		PreparedBy:       "Test Auditor",
	}
	
	events := createTestAuditEvents()
	
	report, err := template.GenerateSOC2Report(reportInfo, events)
	
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, "SOC2-001", report.ReportInfo.ReportID)
	assert.Equal(t, "KubeChat Service", report.ServiceEntity.Name)
	assert.NotEmpty(t, report.TrustCategories)
	assert.NotEmpty(t, report.Sections)
	assert.NotNil(t, report.Conclusion)
	
	// Validate conclusion
	assert.Contains(t, []string{"COMPLIANT", "NON-COMPLIANT"}, report.Conclusion.OverallStatus)
	assert.Greater(t, report.Conclusion.ComplianceScore, 0.0)
	assert.Equal(t, len(template.RequiredControls), report.Conclusion.TotalControls)
}

func TestHIPAAReportGeneration(t *testing.T) {
	template := NewHIPAATemplate()
	
	reportInfo := HIPAAReportInfo{
		ReportID:           "HIPAA-001",
		ReportPeriod:       "2024-Q1",
		GeneratedAt:        time.Now(),
		ComplianceStandard: "HIPAA",
		OrganizationName:   "Test Healthcare Org",
		PreparedBy:         "Compliance Officer",
		ReviewPeriod:       "Quarterly",
	}
	
	events := createTestAuditEvents()
	
	report, err := template.GenerateHIPAAReport(reportInfo, events)
	
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, "HIPAA-001", report.ReportInfo.ReportID)
	assert.Equal(t, "KubeChat Service", report.CoveredEntity.Name)
	assert.True(t, report.CoveredEntity.PHIProcessing)
	assert.NotEmpty(t, report.TechnicalSafeguards)
	assert.NotNil(t, report.Conclusion)
	
	// Validate conclusion
	assert.Contains(t, []string{"COMPLIANT", "PARTIALLY COMPLIANT", "NON-COMPLIANT"}, report.Conclusion.OverallStatus)
	assert.Contains(t, []string{"LOW RISK", "MEDIUM RISK", "HIGH RISK"}, report.Conclusion.RiskAssessment)
	assert.Greater(t, report.Conclusion.ComplianceScore, 0.0)
}

func TestISO27001ReportGeneration(t *testing.T) {
	template := NewISO27001Template()
	
	reportInfo := ISO27001ReportInfo{
		ReportID:         "ISO27001-001",
		ReportPeriod:     "2024 Annual Review",
		GeneratedAt:      time.Now(),
		Standard:         "ISO 27001:2022",
		OrganizationName: "Test Organization",
		PreparedBy:       "Security Manager",
		ReviewPeriod:     "Annual",
	}
	
	events := createTestAuditEvents()
	
	report, err := template.GenerateISO27001Report(reportInfo, events)
	
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, "ISO27001-001", report.ReportInfo.ReportID)
	assert.Equal(t, "KubeChat Service", report.Organization.Name)
	assert.NotEmpty(t, report.SecurityDomains)
	assert.NotNil(t, report.RiskAssessment)
	assert.NotNil(t, report.Conclusion)
	
	// Validate security domains
	assert.True(t, len(report.SecurityDomains) >= 1)
	for _, domain := range report.SecurityDomains {
		assert.NotEmpty(t, domain.DomainName)
		assert.Contains(t, []string{"IMPLEMENTED", "PARTIALLY IMPLEMENTED", "NOT IMPLEMENTED"}, domain.DomainStatus)
	}
	
	// Validate conclusion
	assert.Contains(t, []string{"COMPLIANT", "PARTIALLY COMPLIANT", "NON-COMPLIANT"}, report.Conclusion.OverallStatus)
	assert.Greater(t, report.Conclusion.ComplianceScore, 0.0)
}

func TestJSONFormatting(t *testing.T) {
	tests := []struct {
		name     string
		template interface{}
		testFunc func(t *testing.T)
	}{
		{
			name:     "SOC2 JSON formatting",
			template: NewSOC2Template(),
			testFunc: func(t *testing.T) {
				template := NewSOC2Template()
				reportInfo := SOC2ReportInfo{ReportID: "TEST-001", GeneratedAt: time.Now()}
				events := createTestAuditEvents()
				
				report, err := template.GenerateSOC2Report(reportInfo, events)
				require.NoError(t, err)
				
				jsonData, err := template.FormatSOC2ReportJSON(report)
				assert.NoError(t, err)
				assert.NotEmpty(t, jsonData)
				assert.Contains(t, string(jsonData), "TEST-001")
			},
		},
		{
			name:     "HIPAA JSON formatting",
			template: NewHIPAATemplate(),
			testFunc: func(t *testing.T) {
				template := NewHIPAATemplate()
				reportInfo := HIPAAReportInfo{ReportID: "HIPAA-TEST-001", GeneratedAt: time.Now()}
				events := createTestAuditEvents()
				
				report, err := template.GenerateHIPAAReport(reportInfo, events)
				require.NoError(t, err)
				
				jsonData, err := template.FormatHIPAAReportJSON(report)
				assert.NoError(t, err)
				assert.NotEmpty(t, jsonData)
				assert.Contains(t, string(jsonData), "HIPAA-TEST-001")
			},
		},
		{
			name:     "ISO27001 JSON formatting",
			template: NewISO27001Template(),
			testFunc: func(t *testing.T) {
				template := NewISO27001Template()
				reportInfo := ISO27001ReportInfo{ReportID: "ISO-TEST-001", GeneratedAt: time.Now()}
				events := createTestAuditEvents()
				
				report, err := template.GenerateISO27001Report(reportInfo, events)
				require.NoError(t, err)
				
				jsonData, err := template.FormatISO27001ReportJSON(report)
				assert.NoError(t, err)
				assert.NotEmpty(t, jsonData)
				assert.Contains(t, string(jsonData), "ISO-TEST-001")
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, tt.testFunc)
	}
}

func TestComplianceValidation(t *testing.T) {
	events := createTestAuditEvents()
	
	tests := []struct {
		name             string
		template         interface{}
		expectedValid    bool
		expectedIssues   int
	}{
		{
			name:          "SOC2 compliance validation",
			template:      NewSOC2Template(),
			expectedValid: true, // Should be valid with our test events
			expectedIssues: 0,
		},
		{
			name:          "HIPAA compliance validation", 
			template:      NewHIPAATemplate(),
			expectedValid: true, // Should be valid with our test events
			expectedIssues: 0,
		},
		{
			name:          "ISO27001 compliance validation",
			template:      NewISO27001Template(),
			expectedValid: true, // Should be valid with our test events
			expectedIssues: 0,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch template := tt.template.(type) {
			case *SOC2Template:
				valid, issues := template.ValidateSOC2Compliance(events)
				assert.Equal(t, tt.expectedValid, valid)
				if tt.expectedIssues > 0 {
					assert.Len(t, issues, tt.expectedIssues)
				}
				
			case *HIPAATemplate:
				valid, issues := template.ValidateHIPAACompliance(events)
				assert.Equal(t, tt.expectedValid, valid)
				if tt.expectedIssues > 0 {
					assert.Len(t, issues, tt.expectedIssues)
				}
				
			case *ISO27001Template:
				valid, issues := template.ValidateISO27001Compliance(events)
				assert.Equal(t, tt.expectedValid, valid)
				if tt.expectedIssues > 0 {
					assert.Len(t, issues, tt.expectedIssues)
				}
			}
		})
	}
}

func TestEmptyEventsValidation(t *testing.T) {
	emptyEvents := []*models.AuditEvent{}
	
	tests := []struct {
		name     string
		template interface{}
	}{
		{"SOC2 empty events", NewSOC2Template()},
		{"HIPAA empty events", NewHIPAATemplate()},
		{"ISO27001 empty events", NewISO27001Template()},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch template := tt.template.(type) {
			case *SOC2Template:
				valid, issues := template.ValidateSOC2Compliance(emptyEvents)
				assert.False(t, valid)
				assert.NotEmpty(t, issues)
				
			case *HIPAATemplate:
				valid, issues := template.ValidateHIPAACompliance(emptyEvents)
				assert.False(t, valid)
				assert.NotEmpty(t, issues)
				
			case *ISO27001Template:
				valid, issues := template.ValidateISO27001Compliance(emptyEvents)
				assert.False(t, valid)
				assert.NotEmpty(t, issues)
			}
		})
	}
}

// createTestAuditEvents creates a comprehensive set of test audit events
func createTestAuditEvents() []*models.AuditEvent {
	now := time.Now()
	
	return []*models.AuditEvent{
		{
			ID:        "event-001",
			Timestamp: now.Add(-1 * time.Hour),
			EventType: models.AuditEventTypeAuthentication,
			Message:   "User authentication successful",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				Email:     "test@example.com",
				SessionID: "session-001",
				IPAddress: "192.168.1.100",
				UserAgent: "kubectl/v1.28.0",
			},
			ClusterContext: models.ClusterContext{
				ClusterName:  "test-cluster",
				Namespace:    "default",
				ResourceName: "authentication",
			},
			Checksum: "hash-001",
		},
		{
			ID:        "event-002",
			Timestamp: now.Add(-45 * time.Minute),
			EventType: models.AuditEventTypeLogin,
			Message:   "User login",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
				IPAddress: "192.168.1.100",
			},
			Checksum: "hash-002",
		},
		{
			ID:        "event-003",
			Timestamp: now.Add(-30 * time.Minute),
			EventType: models.AuditEventTypeRBACCheck,
			Message:   "RBAC permission check",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			ClusterContext: models.ClusterContext{
				Namespace:    "kube-system",
				ResourceName: "pods",
			},
			Checksum: "hash-003",
		},
		{
			ID:        "event-004",
			Timestamp: now.Add(-20 * time.Minute),
			EventType: models.AuditEventTypeCommand,
			Message:   "Kubectl command executed",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			CommandContext: models.CommandContext{
				NaturalLanguageInput: "show me all pods",
				GeneratedCommand:     "kubectl get pods",
				RiskLevel:           "safe",
			},
			Checksum: "hash-004",
		},
		{
			ID:        "event-005",
			Timestamp: now.Add(-15 * time.Minute),
			EventType: models.AuditEventTypeCommandExecute,
			Message:   "Command execution",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			CommandContext: models.CommandContext{
				GeneratedCommand:  "kubectl get pods",
				ExecutionStatus:   "success",
				ExecutionDuration: 1250,
			},
			Checksum: "hash-005",
		},
		{
			ID:        "event-006",
			Timestamp: now.Add(-10 * time.Minute),
			EventType: models.AuditEventTypeHealthCheck,
			Message:   "System health check",
			UserContext: models.UserContext{
				UserID: "system",
			},
			ClusterContext: models.ClusterContext{
				ClusterName: "test-cluster",
			},
			Checksum: "hash-006",
		},
		{
			ID:        "event-007",
			Timestamp: now.Add(-5 * time.Minute),
			EventType: models.AuditEventTypeNLPInput,
			Message:   "Natural language input processed",
			UserContext: models.UserContext{
				UserID:    "test-user-2",
				SessionID: "session-002",
			},
			CommandContext: models.CommandContext{
				NaturalLanguageInput: "delete the failing pod",
				RiskLevel:           "destructive",
			},
			Checksum: "hash-007",
		},
		{
			ID:        "event-008",
			Timestamp: now.Add(-2 * time.Minute),
			EventType: models.AuditEventTypePermissionGrant,
			Message:   "Permission granted",
			UserContext: models.UserContext{
				UserID: "admin-user",
			},
			ClusterContext: models.ClusterContext{
				Namespace:    "production",
				ResourceName: "pods",
			},
			Checksum: "hash-008",
		},
		{
			ID:        "event-009",
			Timestamp: now.Add(-1 * time.Minute),
			EventType: models.AuditEventTypeLogout,
			Message:   "User logout",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			Checksum: "hash-009",
		},
		{
			ID:        "event-010",
			Timestamp: now.Add(-30 * time.Second),
			EventType: models.AuditEventTypeRBACDenied,
			Message:   "RBAC permission denied",
			UserContext: models.UserContext{
				UserID: "test-user-2",
			},
			ClusterContext: models.ClusterContext{
				Namespace:    "restricted",
				ResourceName: "secrets",
			},
			Checksum: "hash-010",
		},
		{
			ID:        "event-011",
			Timestamp: now.Add(-25 * time.Second),
			EventType: models.AuditEventTypeCommandResult,
			Message:   "Command execution result",
			UserContext: models.UserContext{
				UserID: "test-user-1",
			},
			CommandContext: models.CommandContext{
				GeneratedCommand:  "kubectl get pods",
				ExecutionStatus:   "success",
				ExecutionDuration: 1250,
			},
			Checksum: "hash-011",
		},
		{
			ID:        "event-012",
			Timestamp: now.Add(-20 * time.Second),
			EventType: models.AuditEventTypeSystemError,
			Message:   "System error occurred",
			UserContext: models.UserContext{
				UserID: "system",
			},
			ClusterContext: models.ClusterContext{
				ClusterName: "test-cluster",
			},
			Checksum: "hash-012",
		},
		{
			ID:        "event-013",
			Timestamp: now.Add(-15 * time.Second),
			EventType: models.AuditEventTypeServiceStart,
			Message:   "Service started",
			UserContext: models.UserContext{
				UserID: "system",
			},
			ClusterContext: models.ClusterContext{
				ClusterName:  "test-cluster",
				ResourceName: "kubechat-service",
			},
			Checksum: "hash-013",
		},
		{
			ID:        "event-014",
			Timestamp: now.Add(-10 * time.Second),
			EventType: models.AuditEventTypeServiceStop,
			Message:   "Service stopped",
			UserContext: models.UserContext{
				UserID: "system",
			},
			ClusterContext: models.ClusterContext{
				ClusterName:  "test-cluster",
				ResourceName: "kubechat-service",
			},
			Checksum: "hash-014",
		},
		{
			ID:        "event-015",
			Timestamp: now.Add(-8 * time.Second),
			EventType: models.AuditEventTypeNLPTranslation,
			Message:   "NLP translation completed",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			CommandContext: models.CommandContext{
				NaturalLanguageInput: "show all running pods",
				GeneratedCommand:     "kubectl get pods --field-selector=status.phase=Running",
			},
			Checksum: "hash-015",
		},
		{
			ID:        "event-016",
			Timestamp: now.Add(-5 * time.Second),
			EventType: models.AuditEventTypeCommandGenerate,
			Message:   "Command generated from NLP",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			CommandContext: models.CommandContext{
				NaturalLanguageInput: "delete failed pods",
				GeneratedCommand:     "kubectl delete pods --field-selector=status.phase=Failed",
				RiskLevel:           "destructive",
			},
			Checksum: "hash-016",
		},
		{
			ID:        "event-017",
			Timestamp: now.Add(-3 * time.Second),
			EventType: models.AuditEventTypeSessionExpiry,
			Message:   "User session expired",
			UserContext: models.UserContext{
				UserID:    "test-user-2",
				SessionID: "session-002",
				IPAddress: "192.168.1.101",
			},
			Checksum: "hash-017",
		},
	}
}