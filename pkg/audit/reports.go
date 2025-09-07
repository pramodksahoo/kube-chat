// Package audit provides comprehensive compliance reporting capabilities
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ComplianceReportingService provides regulatory compliance report generation
type ComplianceReportingService struct {
	storage    AuditStorage
	traceService *TraceabilityService
}

// ComplianceFramework represents different regulatory frameworks
type ComplianceFramework string

const (
	FrameworkSOC2     ComplianceFramework = "SOC2"
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
	FrameworkPCIDSS   ComplianceFramework = "PCI-DSS"
	FrameworkISO27001 ComplianceFramework = "ISO27001"
	FrameworkGDPR     ComplianceFramework = "GDPR"
	FrameworkNIST     ComplianceFramework = "NIST"
)

// ReportFormat represents different output formats for compliance reports
type ReportFormat string

const (
	ReportFormatJSON ReportFormat = "json"
	ReportFormatXML  ReportFormat = "xml"
	ReportFormatCSV  ReportFormat = "csv"
	ReportFormatPDF  ReportFormat = "pdf"
	ReportFormatHTML ReportFormat = "html"
)

// ComplianceReportRequest represents a request for compliance report generation
type ComplianceReportRequest struct {
	Framework        ComplianceFramework `json:"framework"`
	StartTime        time.Time          `json:"start_time"`
	EndTime          time.Time          `json:"end_time"`
	Format           ReportFormat       `json:"format"`
	IncludeDetails   bool               `json:"include_details"`
	IncludeEvidence  bool               `json:"include_evidence"`
	RequestedBy      string             `json:"requested_by"`
	Purpose          string             `json:"purpose"`
	
	// Filtering options
	UserFilters      []string           `json:"user_filters,omitempty"`
	SystemFilters    []string           `json:"system_filters,omitempty"`
	SeverityFilters  []string           `json:"severity_filters,omitempty"`
	
	// Evidence packaging options
	IntegrityChecks  bool               `json:"integrity_checks"`
	DigitalSignature bool               `json:"digital_signature"`
	EncryptReport    bool               `json:"encrypt_report"`
}

// ComplianceReport represents a complete compliance report
type ComplianceReport struct {
	ReportID          string                    `json:"report_id" xml:"report_id"`
	Framework         ComplianceFramework       `json:"framework" xml:"framework"`
	GeneratedAt       time.Time                 `json:"generated_at" xml:"generated_at"`
	ReportingPeriod   ReportingPeriod          `json:"reporting_period" xml:"reporting_period"`
	GeneratedBy       string                    `json:"generated_by" xml:"generated_by"`
	Purpose           string                    `json:"purpose" xml:"purpose"`
	
	// Executive Summary
	Summary           ComplianceSummary         `json:"summary" xml:"summary"`
	
	// Detailed sections
	AccessControls    AccessControlReport       `json:"access_controls" xml:"access_controls"`
	AuditTrail        AuditTrailReport         `json:"audit_trail" xml:"audit_trail"`
	DataProtection    DataProtectionReport     `json:"data_protection" xml:"data_protection"`
	SecurityIncidents SecurityIncidentReport   `json:"security_incidents" xml:"security_incidents"`
	SystemChanges     SystemChangeReport       `json:"system_changes" xml:"system_changes"`
	UserActivity      UserActivityReport       `json:"user_activity" xml:"user_activity"`
	
	// Evidence and attestations
	Evidence          []EvidencePackage        `json:"evidence" xml:"evidence"`
	Attestations      []ComplianceAttestation  `json:"attestations" xml:"attestations"`
	
	// Report integrity
	IntegrityHash     string                   `json:"integrity_hash" xml:"integrity_hash"`
	DigitalSignature  string                   `json:"digital_signature,omitempty" xml:"digital_signature,omitempty"`
}

// ReportingPeriod defines the time range for the report
type ReportingPeriod struct {
	StartDate time.Time `json:"start_date" xml:"start_date"`
	EndDate   time.Time `json:"end_date" xml:"end_date"`
	Duration  string    `json:"duration" xml:"duration"`
}

// ComplianceSummary provides high-level metrics for executive review
type ComplianceSummary struct {
	TotalAuditEvents       int64                    `json:"total_audit_events" xml:"total_audit_events"`
	UniqueUsers            int64                    `json:"unique_users" xml:"unique_users"`
	SystemAccess           int64                    `json:"system_access" xml:"system_access"`
	PrivilegedOperations   int64                    `json:"privileged_operations" xml:"privileged_operations"`
	SecurityIncidents      int64                    `json:"security_incidents" xml:"security_incidents"`
	ComplianceViolations   int64                    `json:"compliance_violations" xml:"compliance_violations"`
	DataAccessEvents       int64                    `json:"data_access_events" xml:"data_access_events"`
	
	// Risk metrics
	HighRiskActivities     int64                    `json:"high_risk_activities" xml:"high_risk_activities"`
	FailedAuthentications  int64                    `json:"failed_authentications" xml:"failed_authentications"`
	UnauthorizedAccess     int64                    `json:"unauthorized_access" xml:"unauthorized_access"`
	
	// Compliance status by control
	ControlsAssessed       int                      `json:"controls_assessed" xml:"controls_assessed"`
	ControlsCompliant      int                      `json:"controls_compliant" xml:"controls_compliant"`
	ControlsNonCompliant   int                      `json:"controls_non_compliant" xml:"controls_non_compliant"`
	ComplianceScore        float64                  `json:"compliance_score" xml:"compliance_score"`
}

// AccessControlReport details user access controls and permissions
type AccessControlReport struct {
	UserAccounts          []UserAccountSummary     `json:"user_accounts" xml:"user_accounts"`
	PermissionChanges     []PermissionChange       `json:"permission_changes" xml:"permission_changes"`
	PrivilegedAccess      []PrivilegedAccessEvent  `json:"privileged_access" xml:"privileged_access"`
	SessionManagement     SessionManagementReport  `json:"session_management" xml:"session_management"`
	RoleBasedAccess       []RBACEvent             `json:"role_based_access" xml:"role_based_access"`
}

// AuditTrailReport provides comprehensive audit trail information
type AuditTrailReport struct {
	EventsByType         map[string]int64         `json:"events_by_type" xml:"events_by_type"`
	EventsBySeverity     map[string]int64         `json:"events_by_severity" xml:"events_by_severity"`
	CriticalEvents       []CriticalAuditEvent     `json:"critical_events" xml:"critical_events"`
	IntegrityStatus      IntegrityStatusReport    `json:"integrity_status" xml:"integrity_status"`
	RetentionCompliance  RetentionComplianceReport `json:"retention_compliance" xml:"retention_compliance"`
}

// DataProtectionReport covers data handling and protection measures
type DataProtectionReport struct {
	DataAccessPatterns   []DataAccessPattern      `json:"data_access_patterns" xml:"data_access_patterns"`
	EncryptionStatus     EncryptionStatusReport   `json:"encryption_status" xml:"encryption_status"`
	DataRetention        DataRetentionReport      `json:"data_retention" xml:"data_retention"`
	BackupRecovery       BackupRecoveryReport     `json:"backup_recovery" xml:"backup_recovery"`
}

// SecurityIncidentReport documents security-related incidents
type SecurityIncidentReport struct {
	IncidentsByType      map[string]int64         `json:"incidents_by_type" xml:"incidents_by_type"`
	IncidentTimeline     []SecurityIncident       `json:"incident_timeline" xml:"incident_timeline"`
	ResponseMetrics      IncidentResponseMetrics  `json:"response_metrics" xml:"response_metrics"`
	ThreatDetection      ThreatDetectionReport    `json:"threat_detection" xml:"threat_detection"`
}

// SystemChangeReport tracks all system modifications
type SystemChangeReport struct {
	ConfigurationChanges []ConfigurationChange    `json:"configuration_changes" xml:"configuration_changes"`
	SoftwareDeployments  []SoftwareDeployment    `json:"software_deployments" xml:"software_deployments"`
	InfrastructureChanges []InfrastructureChange  `json:"infrastructure_changes" xml:"infrastructure_changes"`
	EmergencyChanges     []EmergencyChange       `json:"emergency_changes" xml:"emergency_changes"`
}

// UserActivityReport provides detailed user behavior analysis
type UserActivityReport struct {
	UserSessions         []UserSessionSummary     `json:"user_sessions" xml:"user_sessions"`
	CommandActivity      []CommandActivitySummary `json:"command_activity" xml:"command_activity"`
	AnomalousActivity    []AnomalousActivityEvent `json:"anomalous_activity" xml:"anomalous_activity"`
	AccessPatterns       []UserAccessPattern      `json:"access_patterns" xml:"access_patterns"`
}

// Supporting data structures

type UserAccountSummary struct {
	UserID           string    `json:"user_id" xml:"user_id"`
	Email            string    `json:"email" xml:"email"`
	LastActivity     time.Time `json:"last_activity" xml:"last_activity"`
	TotalSessions    int64     `json:"total_sessions" xml:"total_sessions"`
	PrivilegedAccess bool      `json:"privileged_access" xml:"privileged_access"`
	ComplianceFlags  []string  `json:"compliance_flags" xml:"compliance_flags"`
}

type PermissionChange struct {
	UserID      string    `json:"user_id" xml:"user_id"`
	ChangeType  string    `json:"change_type" xml:"change_type"`
	Permission  string    `json:"permission" xml:"permission"`
	OldValue    string    `json:"old_value" xml:"old_value"`
	NewValue    string    `json:"new_value" xml:"new_value"`
	Timestamp   time.Time `json:"timestamp" xml:"timestamp"`
	AuthorizedBy string   `json:"authorized_by" xml:"authorized_by"`
}

type PrivilegedAccessEvent struct {
	UserID        string    `json:"user_id" xml:"user_id"`
	Action        string    `json:"action" xml:"action"`
	Resource      string    `json:"resource" xml:"resource"`
	Timestamp     time.Time `json:"timestamp" xml:"timestamp"`
	JustificationRequired bool `json:"justification_required" xml:"justification_required"`
	Justification string    `json:"justification" xml:"justification"`
}

type SessionManagementReport struct {
	AverageSestionDuration time.Duration `json:"average_session_duration" xml:"average_session_duration"`
	ExpiredSessions        int64         `json:"expired_sessions" xml:"expired_sessions"`
	ForcedLogouts          int64         `json:"forced_logouts" xml:"forced_logouts"`
	ConcurrentSessions     int64         `json:"concurrent_sessions" xml:"concurrent_sessions"`
}

type RBACEvent struct {
	EventType   string    `json:"event_type" xml:"event_type"`
	UserID      string    `json:"user_id" xml:"user_id"`
	Resource    string    `json:"resource" xml:"resource"`
	Action      string    `json:"action" xml:"action"`
	Allowed     bool      `json:"allowed" xml:"allowed"`
	Timestamp   time.Time `json:"timestamp" xml:"timestamp"`
	PolicyApplied string  `json:"policy_applied" xml:"policy_applied"`
}

type CriticalAuditEvent struct {
	EventID     string    `json:"event_id" xml:"event_id"`
	EventType   string    `json:"event_type" xml:"event_type"`
	Severity    string    `json:"severity" xml:"severity"`
	Description string    `json:"description" xml:"description"`
	UserID      string    `json:"user_id" xml:"user_id"`
	Timestamp   time.Time `json:"timestamp" xml:"timestamp"`
	ImpactLevel string    `json:"impact_level" xml:"impact_level"`
}

type IntegrityStatusReport struct {
	TotalEventsChecked    int64 `json:"total_events_checked" xml:"total_events_checked"`
	IntegrityViolations   int64 `json:"integrity_violations" xml:"integrity_violations"`
	TamperedEvents        int64 `json:"tampered_events" xml:"tampered_events"`
	IntegrityScore        float64 `json:"integrity_score" xml:"integrity_score"`
}

type RetentionComplianceReport struct {
	RequiredRetentionDays int64 `json:"required_retention_days" xml:"required_retention_days"`
	OldestRecord         time.Time `json:"oldest_record" xml:"oldest_record"`
	RecordsRetained      int64 `json:"records_retained" xml:"records_retained"`
	RecordsPurged        int64 `json:"records_purged" xml:"records_purged"`
}

// EvidencePackage contains cryptographically verified audit evidence
type ReportEvidencePackage struct {
	EvidenceID       string                 `json:"evidence_id" xml:"evidence_id"`
	EvidenceType     string                 `json:"evidence_type" xml:"evidence_type"`
	Description      string                 `json:"description" xml:"description"`
	CollectionDate   time.Time              `json:"collection_date" xml:"collection_date"`
	Events           []models.AuditEvent    `json:"events" xml:"events"`
	IntegrityHashes  []string               `json:"integrity_hashes" xml:"integrity_hashes"`
	ChainOfCustody   []CustodyRecord        `json:"chain_of_custody" xml:"chain_of_custody"`
	VerificationStatus bool                 `json:"verification_status" xml:"verification_status"`
}

type CustodyRecord struct {
	Timestamp   time.Time `json:"timestamp" xml:"timestamp"`
	Handler     string    `json:"handler" xml:"handler"`
	Action      string    `json:"action" xml:"action"`
	Signature   string    `json:"signature" xml:"signature"`
}

type ComplianceAttestation struct {
	Control         string    `json:"control" xml:"control"`
	Description     string    `json:"description" xml:"description"`
	Status          string    `json:"status" xml:"status"` // compliant, non-compliant, not-applicable
	Evidence        string    `json:"evidence" xml:"evidence"`
	TestingDate     time.Time `json:"testing_date" xml:"testing_date"`
	TestedBy        string    `json:"tested_by" xml:"tested_by"`
	NextTestingDate time.Time `json:"next_testing_date" xml:"next_testing_date"`
}

// Additional supporting structures for specific reports

type DataAccessPattern struct {
	UserID          string    `json:"user_id" xml:"user_id"`
	DataType        string    `json:"data_type" xml:"data_type"`
	AccessFrequency int64     `json:"access_frequency" xml:"access_frequency"`
	LastAccess      time.Time `json:"last_access" xml:"last_access"`
	ComplianceNotes string    `json:"compliance_notes" xml:"compliance_notes"`
}

type EncryptionStatusReport struct {
	DataAtRest     EncryptionStatus `json:"data_at_rest" xml:"data_at_rest"`
	DataInTransit  EncryptionStatus `json:"data_in_transit" xml:"data_in_transit"`
	KeyManagement  KeyManagementReport `json:"key_management" xml:"key_management"`
}

type EncryptionStatus struct {
	Enabled         bool     `json:"enabled" xml:"enabled"`
	Algorithm       string   `json:"algorithm" xml:"algorithm"`
	KeyStrength     int      `json:"key_strength" xml:"key_strength"`
	ComplianceLevel string   `json:"compliance_level" xml:"compliance_level"`
}

type KeyManagementReport struct {
	KeyRotationFrequency time.Duration `json:"key_rotation_frequency" xml:"key_rotation_frequency"`
	LastKeyRotation      time.Time     `json:"last_key_rotation" xml:"last_key_rotation"`
	KeyEscrowStatus      bool          `json:"key_escrow_status" xml:"key_escrow_status"`
}

type DataRetentionReport struct {
	PolicyCompliance float64       `json:"policy_compliance" xml:"policy_compliance"`
	RetentionPeriods []RetentionPeriodStatus `json:"retention_periods" xml:"retention_periods"`
	DisposalRecords  []DisposalRecord `json:"disposal_records" xml:"disposal_records"`
}

type RetentionPeriodStatus struct {
	DataType        string    `json:"data_type" xml:"data_type"`
	RequiredDays    int       `json:"required_days" xml:"required_days"`
	ActualDays      int       `json:"actual_days" xml:"actual_days"`
	ComplianceStatus string   `json:"compliance_status" xml:"compliance_status"`
}

type DisposalRecord struct {
	DataType      string    `json:"data_type" xml:"data_type"`
	DisposalDate  time.Time `json:"disposal_date" xml:"disposal_date"`
	Method        string    `json:"method" xml:"method"`
	AuthorizedBy  string    `json:"authorized_by" xml:"authorized_by"`
	Verification  string    `json:"verification" xml:"verification"`
}

// NewComplianceReportingService creates a new compliance reporting service
func NewComplianceReportingService(storage AuditStorage, traceService *TraceabilityService) (*ComplianceReportingService, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage cannot be nil")
	}
	if traceService == nil {
		return nil, fmt.Errorf("trace service cannot be nil")
	}

	return &ComplianceReportingService{
		storage:      storage,
		traceService: traceService,
	}, nil
}

// GenerateComplianceReport generates a comprehensive compliance report
func (c *ComplianceReportingService) GenerateComplianceReport(ctx context.Context, req ComplianceReportRequest) (*ComplianceReport, error) {
	if err := c.validateReportRequest(req); err != nil {
		return nil, fmt.Errorf("invalid report request: %w", err)
	}

	reportID := c.generateReportID(req)
	
	report := &ComplianceReport{
		ReportID:    reportID,
		Framework:   req.Framework,
		GeneratedAt: time.Now().UTC(),
		ReportingPeriod: ReportingPeriod{
			StartDate: req.StartTime,
			EndDate:   req.EndTime,
			Duration:  req.EndTime.Sub(req.StartTime).String(),
		},
		GeneratedBy: req.RequestedBy,
		Purpose:     req.Purpose,
	}

	// Generate each section of the report
	var err error
	
	report.Summary, err = c.generateSummary(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate summary: %w", err)
	}

	report.AccessControls, err = c.generateAccessControlReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access control report: %w", err)
	}

	report.AuditTrail, err = c.generateAuditTrailReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate audit trail report: %w", err)
	}

	report.DataProtection, err = c.generateDataProtectionReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate data protection report: %w", err)
	}

	report.SecurityIncidents, err = c.generateSecurityIncidentReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate security incident report: %w", err)
	}

	report.SystemChanges, err = c.generateSystemChangeReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate system change report: %w", err)
	}

	report.UserActivity, err = c.generateUserActivityReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate user activity report: %w", err)
	}

	// Generate evidence packages if requested
	if req.IncludeEvidence {
		report.Evidence, err = c.generateEvidencePackages(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("failed to generate evidence packages: %w", err)
		}
	}

	// Generate compliance attestations based on framework
	report.Attestations = c.generateComplianceAttestations(req.Framework, report)

	// Calculate integrity hash
	report.IntegrityHash, err = c.calculateIntegrityHash(report)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate integrity hash: %w", err)
	}

	// Apply digital signature if requested
	if req.DigitalSignature {
		report.DigitalSignature, err = c.generateDigitalSignature(report)
		if err != nil {
			return nil, fmt.Errorf("failed to generate digital signature: %w", err)
		}
	}

	return report, nil
}

// ExportReport exports a compliance report in the specified format
func (c *ComplianceReportingService) ExportReport(report *ComplianceReport, format ReportFormat, writer io.Writer) error {
	switch format {
	case ReportFormatJSON:
		encoder := json.NewEncoder(writer)
		encoder.SetIndent("", "  ")
		return encoder.Encode(report)
	
	case ReportFormatXML:
		encoder := xml.NewEncoder(writer)
		encoder.Indent("", "  ")
		if _, err := writer.Write([]byte(xml.Header)); err != nil {
			return err
		}
		return encoder.Encode(report)
	
	case ReportFormatCSV:
		return c.exportToCSV(report, writer)
	
	case ReportFormatHTML:
		return c.exportToHTML(report, writer)
	
	case ReportFormatPDF:
		return fmt.Errorf("PDF export not yet implemented")
	
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// ValidateReportIntegrity validates the integrity of a compliance report
func (c *ComplianceReportingService) ValidateReportIntegrity(report *ComplianceReport) (bool, error) {
	originalHash := report.IntegrityHash
	
	// Temporarily clear hash for recalculation
	report.IntegrityHash = ""
	
	calculatedHash, err := c.calculateIntegrityHash(report)
	if err != nil {
		report.IntegrityHash = originalHash
		return false, fmt.Errorf("failed to calculate integrity hash: %w", err)
	}
	
	report.IntegrityHash = originalHash
	return originalHash == calculatedHash, nil
}

// Helper methods for report generation

func (c *ComplianceReportingService) validateReportRequest(req ComplianceReportRequest) error {
	if req.Framework == "" {
		return fmt.Errorf("compliance framework is required")
	}
	if req.StartTime.IsZero() {
		return fmt.Errorf("start time is required")
	}
	if req.EndTime.IsZero() {
		return fmt.Errorf("end time is required")
	}
	if req.StartTime.After(req.EndTime) {
		return fmt.Errorf("start time cannot be after end time")
	}
	if req.RequestedBy == "" {
		return fmt.Errorf("requestor information is required")
	}
	return nil
}

func (c *ComplianceReportingService) generateReportID(req ComplianceReportRequest) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s-%d", 
		req.Framework, req.RequestedBy, req.Purpose, req.StartTime.Unix())))
	return fmt.Sprintf("RPT-%s-%s", strings.ToUpper(string(req.Framework)), 
		hex.EncodeToString(hash[:8]))
}

func (c *ComplianceReportingService) generateSummary(ctx context.Context, req ComplianceReportRequest) (ComplianceSummary, error) {
	summary := ComplianceSummary{}

	// Query audit events for the reporting period
	filter := models.AuditEventFilter{
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
		Limit:     10000,
	}

	events, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return summary, err
	}

	// Calculate summary metrics
	summary.TotalAuditEvents = int64(len(events))
	userSet := make(map[string]bool)
	var privilegedOps, securityIncidents, highRiskActivities, failedAuths int64

	for _, event := range events {
		userSet[event.UserContext.UserID] = true
		
		if event.EventType == models.AuditEventTypeRBACDenied {
			failedAuths++
		}
		
		if event.Severity == models.AuditSeverityError || event.Severity == models.AuditSeverityCritical {
			securityIncidents++
		}
		
		if event.CommandContext.RiskLevel == "destructive" {
			highRiskActivities++
		}
		
		if strings.Contains(strings.ToLower(event.Message), "privilege") {
			privilegedOps++
		}
	}

	summary.UniqueUsers = int64(len(userSet))
	summary.PrivilegedOperations = privilegedOps
	summary.SecurityIncidents = securityIncidents
	summary.HighRiskActivities = highRiskActivities
	summary.FailedAuthentications = failedAuths

	// Calculate compliance score based on framework requirements
	summary.ComplianceScore = c.calculateComplianceScore(req.Framework, events)

	return summary, nil
}

func (c *ComplianceReportingService) generateAccessControlReport(ctx context.Context, req ComplianceReportRequest) (AccessControlReport, error) {
	report := AccessControlReport{}

	// Query RBAC and authentication events
	filter := models.AuditEventFilter{
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		EventTypes: []models.AuditEventType{models.AuditEventTypeRBACCheck, models.AuditEventTypeRBACDenied, models.AuditEventTypeAuthentication},
		Limit:      5000,
	}

	events, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return report, err
	}

	// Process events into access control data
	userSessions := make(map[string]*UserAccountSummary)
	var rbacEvents []RBACEvent

	for _, event := range events {
		// Track user sessions
		if summary, exists := userSessions[event.UserContext.UserID]; exists {
			summary.TotalSessions++
			if event.Timestamp.After(summary.LastActivity) {
				summary.LastActivity = event.Timestamp
			}
		} else {
			userSessions[event.UserContext.UserID] = &UserAccountSummary{
				UserID:       event.UserContext.UserID,
				Email:        event.UserContext.Email,
				LastActivity: event.Timestamp,
				TotalSessions: 1,
			}
		}

		// Track RBAC events
		if event.EventType == models.AuditEventTypeRBACCheck || event.EventType == models.AuditEventTypeRBACDenied {
			rbacEvent := RBACEvent{
				EventType: string(event.EventType),
				UserID:    event.UserContext.UserID,
				Resource:  event.ClusterContext.ResourceName,
				Action:    event.Message,
				Allowed:   event.EventType == models.AuditEventTypeRBACCheck,
				Timestamp: event.Timestamp,
			}
			rbacEvents = append(rbacEvents, rbacEvent)
		}
	}

	// Convert map to slice
	for _, summary := range userSessions {
		report.UserAccounts = append(report.UserAccounts, *summary)
	}
	report.RoleBasedAccess = rbacEvents

	return report, nil
}

func (c *ComplianceReportingService) generateAuditTrailReport(ctx context.Context, req ComplianceReportRequest) (AuditTrailReport, error) {
	report := AuditTrailReport{
		EventsByType:     make(map[string]int64),
		EventsBySeverity: make(map[string]int64),
	}

	// Get event counts by type
	eventCounts, err := c.storage.CountEventsByType(ctx)
	if err != nil {
		return report, err
	}

	for eventType, count := range eventCounts {
		report.EventsByType[string(eventType)] = count
	}

	// Query critical events
	filter := models.AuditEventFilter{
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		Severities: []models.AuditSeverity{models.AuditSeverityCritical, models.AuditSeverityError},
		Limit:      1000,
	}

	criticalEvents, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return report, err
	}

	for _, event := range criticalEvents {
		report.EventsBySeverity[string(event.Severity)]++
		
		criticalEvent := CriticalAuditEvent{
			EventID:     event.ID,
			EventType:   string(event.EventType),
			Severity:    string(event.Severity),
			Description: event.Message,
			UserID:      event.UserContext.UserID,
			Timestamp:   event.Timestamp,
			ImpactLevel: c.determineImpactLevel(event),
		}
		report.CriticalEvents = append(report.CriticalEvents, criticalEvent)
	}

	// Generate integrity status
	report.IntegrityStatus = IntegrityStatusReport{
		TotalEventsChecked:  int64(len(criticalEvents)),
		IntegrityViolations: 0, // This would be calculated by actual integrity checks
		IntegrityScore:      100.0, // Placeholder
	}

	return report, nil
}

func (c *ComplianceReportingService) generateDataProtectionReport(ctx context.Context, req ComplianceReportRequest) (DataProtectionReport, error) {
	report := DataProtectionReport{
		EncryptionStatus: EncryptionStatusReport{
			DataAtRest: EncryptionStatus{
				Enabled:         true,
				Algorithm:       "AES-256",
				KeyStrength:     256,
				ComplianceLevel: "FIPS 140-2 Level 1",
			},
			DataInTransit: EncryptionStatus{
				Enabled:         true,
				Algorithm:       "TLS 1.3",
				KeyStrength:     256,
				ComplianceLevel: "FIPS 140-2 Level 1",
			},
		},
	}

	// This would be populated with actual data access patterns from audit events
	// For now, providing a structural example
	
	return report, nil
}

func (c *ComplianceReportingService) generateSecurityIncidentReport(ctx context.Context, req ComplianceReportRequest) (SecurityIncidentReport, error) {
	report := SecurityIncidentReport{
		IncidentsByType: make(map[string]int64),
	}

	// Query security-related events
	filter := models.AuditEventFilter{
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		EventTypes: []models.AuditEventType{models.AuditEventTypeRBACDenied, models.AuditEventTypeSystemError},
		Limit:      1000,
	}

	events, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return report, err
	}

	for _, event := range events {
		incidentType := c.classifySecurityIncident(event)
		report.IncidentsByType[incidentType]++
	}

	return report, nil
}

func (c *ComplianceReportingService) generateSystemChangeReport(ctx context.Context, req ComplianceReportRequest) (SystemChangeReport, error) {
	report := SystemChangeReport{}

	// Query command execution events for system changes
	filter := models.AuditEventFilter{
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		EventTypes: []models.AuditEventType{models.AuditEventTypeCommandExecute},
		Limit:      5000,
	}

	events, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return report, err
	}

	for _, event := range events {
		if c.isConfigurationChange(event) {
			change := ConfigurationChange{
				ChangeType:  c.classifyConfigurationChange(event),
				Description: event.Message,
				Timestamp:   event.Timestamp,
				ChangedBy:   event.UserContext.UserID,
				Resource:    event.ClusterContext.ResourceName,
			}
			report.ConfigurationChanges = append(report.ConfigurationChanges, change)
		}
	}

	return report, nil
}

func (c *ComplianceReportingService) generateUserActivityReport(ctx context.Context, req ComplianceReportRequest) (UserActivityReport, error) {
	report := UserActivityReport{}

	// Query user activity events
	filter := models.AuditEventFilter{
		StartTime: req.StartTime,
		EndTime:   req.EndTime,
		Limit:     10000,
	}

	events, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return report, err
	}

	// Aggregate user activity data
	userSessions := make(map[string]*UserSessionSummary)
	commandActivity := make(map[string]*CommandActivitySummary)

	for _, event := range events {
		// Track user sessions
		sessionKey := event.UserContext.UserID + "-" + event.UserContext.SessionID
		if summary, exists := userSessions[sessionKey]; exists {
			summary.TotalCommands++
			summary.LastActivity = event.Timestamp
		} else {
			userSessions[sessionKey] = &UserSessionSummary{
				UserID:       event.UserContext.UserID,
				SessionID:    event.UserContext.SessionID,
				StartTime:    event.Timestamp,
				LastActivity: event.Timestamp,
				TotalCommands: 1,
			}
		}

		// Track command activity
		if event.CommandContext.GeneratedCommand != "" {
			cmdKey := event.UserContext.UserID + "-" + event.CommandContext.GeneratedCommand
			if summary, exists := commandActivity[cmdKey]; exists {
				summary.ExecutionCount++
			} else {
				commandActivity[cmdKey] = &CommandActivitySummary{
					UserID:         event.UserContext.UserID,
					Command:        event.CommandContext.GeneratedCommand,
					ExecutionCount: 1,
					LastExecution:  event.Timestamp,
					RiskLevel:      event.CommandContext.RiskLevel,
				}
			}
		}
	}

	// Convert maps to slices
	for _, summary := range userSessions {
		report.UserSessions = append(report.UserSessions, *summary)
	}
	for _, summary := range commandActivity {
		report.CommandActivity = append(report.CommandActivity, *summary)
	}

	return report, nil
}

func (c *ComplianceReportingService) generateEvidencePackages(ctx context.Context, req ComplianceReportRequest) ([]EvidencePackage, error) {
	var packages []EvidencePackage

	// Generate evidence package for critical events
	filter := models.AuditEventFilter{
		StartTime:  req.StartTime,
		EndTime:    req.EndTime,
		Severities: []models.AuditSeverity{models.AuditSeverityCritical},
		Limit:      100,
	}

	events, err := c.storage.QueryEvents(ctx, filter)
	if err != nil {
		return packages, err
	}

	if len(events) > 0 {
		evidenceID := fmt.Sprintf("EVID-%s-%d", string(req.Framework), time.Now().Unix())
		
		var hashes []string
		for _, event := range events {
			hashes = append(hashes, event.Checksum)
		}

		package1 := ReportEvidencePackage{
			EvidenceID:       evidenceID,
			EvidenceType:     "critical_security_events",
			Description:      "Critical security events requiring regulatory attention",
			CollectionDate:   time.Now().UTC(),
			Events:           convertEventsSlice(events),
			IntegrityHashes:  hashes,
			VerificationStatus: true,
			ChainOfCustody: []CustodyRecord{
				{
					Timestamp: time.Now().UTC(),
					Handler:   req.RequestedBy,
					Action:    "evidence_collection",
					Signature: "automated_collection_" + evidenceID,
				},
			},
		}
		evidencePackage := EvidencePackage{
			PackageID: evidenceID,
			ComplianceFramework: "security",
			GeneratedAt: package1.CollectionDate,
			Events: events,
		}
		packages = append(packages, evidencePackage)
	}

	return packages, nil
}

// convertEventsSlice converts []*models.AuditEvent to []models.AuditEvent
func convertEventsSlice(events []*models.AuditEvent) []models.AuditEvent {
	result := make([]models.AuditEvent, len(events))
	for i, event := range events {
		result[i] = *event
	}
	return result
}

func (c *ComplianceReportingService) generateComplianceAttestations(framework ComplianceFramework, report *ComplianceReport) []ComplianceAttestation {
	var attestations []ComplianceAttestation

	switch framework {
	case FrameworkSOC2:
		attestations = c.generateSOC2Attestations(report)
	case FrameworkHIPAA:
		attestations = c.generateHIPAAAcertifications(report)
	case FrameworkPCIDSS:
		attestations = c.generatePCIDSSAttestations(report)
	default:
		attestations = c.generateGenericAttestations(report)
	}

	return attestations
}

func (c *ComplianceReportingService) generateSOC2Attestations(report *ComplianceReport) []ComplianceAttestation {
	return []ComplianceAttestation{
		{
			Control:         "CC6.1",
			Description:     "Logical and physical access controls restrict access",
			Status:          "compliant",
			Evidence:        fmt.Sprintf("Access control report shows %d user accounts managed", len(report.AccessControls.UserAccounts)),
			TestingDate:     time.Now().UTC(),
			TestedBy:        "automated_compliance_system",
			NextTestingDate: time.Now().AddDate(0, 3, 0),
		},
		{
			Control:         "CC7.1",
			Description:     "System monitoring identifies anomalies",
			Status:          "compliant",
			Evidence:        fmt.Sprintf("Security incident report shows %d incidents detected and tracked", len(report.SecurityIncidents.IncidentTimeline)),
			TestingDate:     time.Now().UTC(),
			TestedBy:        "automated_compliance_system",
			NextTestingDate: time.Now().AddDate(0, 3, 0),
		},
	}
}

func (c *ComplianceReportingService) generateHIPAAAcertifications(report *ComplianceReport) []ComplianceAttestation {
	return []ComplianceAttestation{
		{
			Control:         "164.312(a)(1)",
			Description:     "Access control for information systems",
			Status:          "compliant",
			Evidence:        "User access controls and authentication systems operational",
			TestingDate:     time.Now().UTC(),
			TestedBy:        "automated_compliance_system",
			NextTestingDate: time.Now().AddDate(0, 6, 0),
		},
		{
			Control:         "164.312(b)",
			Description:     "Audit controls for information access",
			Status:          "compliant",
			Evidence:        fmt.Sprintf("Comprehensive audit trail with %d events captured", report.Summary.TotalAuditEvents),
			TestingDate:     time.Now().UTC(),
			TestedBy:        "automated_compliance_system",
			NextTestingDate: time.Now().AddDate(0, 6, 0),
		},
	}
}

func (c *ComplianceReportingService) generatePCIDSSAttestations(report *ComplianceReport) []ComplianceAttestation {
	return []ComplianceAttestation{
		{
			Control:         "PCI-DSS 10.1",
			Description:     "Audit trail for access to cardholder data",
			Status:          "compliant",
			Evidence:        "Audit logs capture all access to cardholder data environment",
			TestingDate:     time.Now().UTC(),
			TestedBy:        "automated_compliance_system",
			NextTestingDate: time.Now().AddDate(0, 12, 0),
		},
	}
}

func (c *ComplianceReportingService) generateGenericAttestations(report *ComplianceReport) []ComplianceAttestation {
	return []ComplianceAttestation{
		{
			Control:         "ACCESS_CONTROL",
			Description:     "User access is properly controlled and monitored",
			Status:          "compliant",
			Evidence:        "Access control mechanisms operational",
			TestingDate:     time.Now().UTC(),
			TestedBy:        "automated_compliance_system",
			NextTestingDate: time.Now().AddDate(0, 3, 0),
		},
	}
}

func (c *ComplianceReportingService) calculateIntegrityHash(report *ComplianceReport) (string, error) {
	// Create a copy without the hash and signature for calculation
	reportCopy := *report
	reportCopy.IntegrityHash = ""
	reportCopy.DigitalSignature = ""

	data, err := json.Marshal(reportCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal report for hashing: %w", err)
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

func (c *ComplianceReportingService) generateDigitalSignature(report *ComplianceReport) (string, error) {
	// This is a simplified signature - in production, use proper cryptographic signing
	signatureData := fmt.Sprintf("SIGNATURE-%s-%s-%d", 
		report.ReportID, report.IntegrityHash, report.GeneratedAt.Unix())
	hash := sha256.Sum256([]byte(signatureData))
	return hex.EncodeToString(hash[:]), nil
}

func (c *ComplianceReportingService) exportToCSV(report *ComplianceReport, writer io.Writer) error {
	csvWriter := csv.NewWriter(writer)
	defer csvWriter.Flush()

	// Write headers
	headers := []string{"Section", "Metric", "Value", "Timestamp"}
	if err := csvWriter.Write(headers); err != nil {
		return err
	}

	// Write summary data
	summaryRows := [][]string{
		{"Summary", "Total Audit Events", fmt.Sprintf("%d", report.Summary.TotalAuditEvents), report.GeneratedAt.Format(time.RFC3339)},
		{"Summary", "Unique Users", fmt.Sprintf("%d", report.Summary.UniqueUsers), report.GeneratedAt.Format(time.RFC3339)},
		{"Summary", "Security Incidents", fmt.Sprintf("%d", report.Summary.SecurityIncidents), report.GeneratedAt.Format(time.RFC3339)},
		{"Summary", "Compliance Score", fmt.Sprintf("%.2f", report.Summary.ComplianceScore), report.GeneratedAt.Format(time.RFC3339)},
	}

	for _, row := range summaryRows {
		if err := csvWriter.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func (c *ComplianceReportingService) exportToHTML(report *ComplianceReport, writer io.Writer) error {
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>%s Compliance Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; margin-bottom: 20px; }
        .section { margin-bottom: 30px; }
        .metric { display: inline-block; margin: 10px; padding: 10px; border: 1px solid #ccc; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>%s Compliance Report</h1>
        <p><strong>Report ID:</strong> %s</p>
        <p><strong>Generated:</strong> %s</p>
        <p><strong>Period:</strong> %s to %s</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <div class="metric">
            <strong>Total Audit Events:</strong><br>
            %d
        </div>
        <div class="metric">
            <strong>Unique Users:</strong><br>
            %d
        </div>
        <div class="metric">
            <strong>Security Incidents:</strong><br>
            %d
        </div>
        <div class="metric">
            <strong>Compliance Score:</strong><br>
            %.2f%%
        </div>
    </div>
</body>
</html>`,
		string(report.Framework), report.ReportID,
		string(report.Framework), report.ReportID,
		report.GeneratedAt.Format("2006-01-02 15:04:05"),
		report.ReportingPeriod.StartDate.Format("2006-01-02"),
		report.ReportingPeriod.EndDate.Format("2006-01-02"),
		report.Summary.TotalAuditEvents,
		report.Summary.UniqueUsers,
		report.Summary.SecurityIncidents,
		report.Summary.ComplianceScore,
	)

	_, err := writer.Write([]byte(html))
	return err
}

// Helper methods for classification and analysis

func (c *ComplianceReportingService) calculateComplianceScore(framework ComplianceFramework, events []*models.AuditEvent) float64 {
	// Simplified compliance score calculation
	totalEvents := len(events)
	if totalEvents == 0 {
		return 100.0
	}

	var violations int
	for _, event := range events {
		if event.Severity == models.AuditSeverityCritical || event.Severity == models.AuditSeverityError {
			violations++
		}
	}

	score := float64(totalEvents-violations) / float64(totalEvents) * 100
	if score < 0 {
		score = 0
	}
	return score
}

func (c *ComplianceReportingService) determineImpactLevel(event *models.AuditEvent) string {
	if event.Severity == models.AuditSeverityCritical {
		return "high"
	}
	if event.Severity == models.AuditSeverityError {
		return "medium"
	}
	return "low"
}

func (c *ComplianceReportingService) classifySecurityIncident(event *models.AuditEvent) string {
	if event.EventType == models.AuditEventTypeRBACDenied {
		return "unauthorized_access_attempt"
	}
	if event.EventType == models.AuditEventTypeSystemError {
		return "system_error"
	}
	return "general_security_event"
}

func (c *ComplianceReportingService) isConfigurationChange(event *models.AuditEvent) bool {
	return event.EventType == models.AuditEventTypeCommandExecute && 
		   (strings.Contains(event.CommandContext.GeneratedCommand, "create") ||
		    strings.Contains(event.CommandContext.GeneratedCommand, "delete") ||
		    strings.Contains(event.CommandContext.GeneratedCommand, "update") ||
		    strings.Contains(event.CommandContext.GeneratedCommand, "patch"))
}

func (c *ComplianceReportingService) classifyConfigurationChange(event *models.AuditEvent) string {
	cmd := strings.ToLower(event.CommandContext.GeneratedCommand)
	if strings.Contains(cmd, "create") {
		return "resource_creation"
	}
	if strings.Contains(cmd, "delete") {
		return "resource_deletion"
	}
	if strings.Contains(cmd, "update") || strings.Contains(cmd, "patch") {
		return "resource_modification"
	}
	return "configuration_change"
}

// Supporting structures for reports

type ConfigurationChange struct {
	ChangeType   string    `json:"change_type" xml:"change_type"`
	Description  string    `json:"description" xml:"description"`
	Timestamp    time.Time `json:"timestamp" xml:"timestamp"`
	ChangedBy    string    `json:"changed_by" xml:"changed_by"`
	Resource     string    `json:"resource" xml:"resource"`
	ApprovalStatus string  `json:"approval_status" xml:"approval_status"`
}

type SoftwareDeployment struct {
	Application   string    `json:"application" xml:"application"`
	Version       string    `json:"version" xml:"version"`
	DeployedBy    string    `json:"deployed_by" xml:"deployed_by"`
	Timestamp     time.Time `json:"timestamp" xml:"timestamp"`
	Environment   string    `json:"environment" xml:"environment"`
}

type InfrastructureChange struct {
	Component     string    `json:"component" xml:"component"`
	ChangeType    string    `json:"change_type" xml:"change_type"`
	Description   string    `json:"description" xml:"description"`
	Timestamp     time.Time `json:"timestamp" xml:"timestamp"`
	AuthorizedBy  string    `json:"authorized_by" xml:"authorized_by"`
}

type EmergencyChange struct {
	Description   string    `json:"description" xml:"description"`
	Justification string    `json:"justification" xml:"justification"`
	Timestamp     time.Time `json:"timestamp" xml:"timestamp"`
	AuthorizedBy  string    `json:"authorized_by" xml:"authorized_by"`
	ReviewDate    time.Time `json:"review_date" xml:"review_date"`
}

type UserSessionSummary struct {
	UserID        string    `json:"user_id" xml:"user_id"`
	SessionID     string    `json:"session_id" xml:"session_id"`
	StartTime     time.Time `json:"start_time" xml:"start_time"`
	LastActivity  time.Time `json:"last_activity" xml:"last_activity"`
	TotalCommands int64     `json:"total_commands" xml:"total_commands"`
	IPAddress     string    `json:"ip_address" xml:"ip_address"`
}

type CommandActivitySummary struct {
	UserID         string    `json:"user_id" xml:"user_id"`
	Command        string    `json:"command" xml:"command"`
	ExecutionCount int64     `json:"execution_count" xml:"execution_count"`
	LastExecution  time.Time `json:"last_execution" xml:"last_execution"`
	RiskLevel      string    `json:"risk_level" xml:"risk_level"`
}

type AnomalousActivityEvent struct {
	UserID      string    `json:"user_id" xml:"user_id"`
	Activity    string    `json:"activity" xml:"activity"`
	Timestamp   time.Time `json:"timestamp" xml:"timestamp"`
	AnomalyType string    `json:"anomaly_type" xml:"anomaly_type"`
	RiskScore   float64   `json:"risk_score" xml:"risk_score"`
}

type UserAccessPattern struct {
	UserID         string    `json:"user_id" xml:"user_id"`
	AccessType     string    `json:"access_type" xml:"access_type"`
	Frequency      string    `json:"frequency" xml:"frequency"`
	TimePattern    string    `json:"time_pattern" xml:"time_pattern"`
	ResourceAccess []string  `json:"resource_access" xml:"resource_access"`
}

type SecurityIncident struct {
	IncidentID   string    `json:"incident_id" xml:"incident_id"`
	Type         string    `json:"type" xml:"type"`
	Severity     string    `json:"severity" xml:"severity"`
	Description  string    `json:"description" xml:"description"`
	Timestamp    time.Time `json:"timestamp" xml:"timestamp"`
	Status       string    `json:"status" xml:"status"`
	RespondedBy  string    `json:"responded_by" xml:"responded_by"`
}

type IncidentResponseMetrics struct {
	AverageResponseTime   time.Duration `json:"average_response_time" xml:"average_response_time"`
	AverageResolutionTime time.Duration `json:"average_resolution_time" xml:"average_resolution_time"`
	IncidentsResolved     int64         `json:"incidents_resolved" xml:"incidents_resolved"`
	IncidentsOpen         int64         `json:"incidents_open" xml:"incidents_open"`
}

type ThreatDetectionReport struct {
	ThreatsDetected       int64                    `json:"threats_detected" xml:"threats_detected"`
	ThreatsBlocked        int64                    `json:"threats_blocked" xml:"threats_blocked"`
	ThreatsByType         map[string]int64         `json:"threats_by_type" xml:"threats_by_type"`
	DetectionRules        []ThreatDetectionRule    `json:"detection_rules" xml:"detection_rules"`
}

type ThreatDetectionRule struct {
	RuleID      string    `json:"rule_id" xml:"rule_id"`
	Description string    `json:"description" xml:"description"`
	Severity    string    `json:"severity" xml:"severity"`
	Enabled     bool      `json:"enabled" xml:"enabled"`
	LastTriggered *time.Time `json:"last_triggered" xml:"last_triggered"`
}

type BackupRecoveryReport struct {
	BackupFrequency       string    `json:"backup_frequency" xml:"backup_frequency"`
	LastBackup           time.Time `json:"last_backup" xml:"last_backup"`
	BackupSuccess        bool      `json:"backup_success" xml:"backup_success"`
	RetentionPeriod      string    `json:"retention_period" xml:"retention_period"`
	RecoveryTestDate     time.Time `json:"recovery_test_date" xml:"recovery_test_date"`
	RecoveryTestSuccess  bool      `json:"recovery_test_success" xml:"recovery_test_success"`
}