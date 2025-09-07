// Package templates provides HIPAA compliance framework templates for evidence generation
package templates

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// HIPAATemplate provides HIPAA Technical Safeguards compliance framework template
type HIPAATemplate struct {
	FrameworkName    string `json:"framework_name"`
	FrameworkVersion string `json:"framework_version"`
	RequiredSafeguards []HIPAASafeguard `json:"required_safeguards"`
}

// HIPAASafeguard represents a HIPAA technical safeguard requirement
type HIPAASafeguard struct {
	SafeguardID       string   `json:"safeguard_id"`
	SafeguardName     string   `json:"safeguard_name"`
	RegulationSection string   `json:"regulation_section"`
	Description       string   `json:"description"`
	RequiredEvents    []string `json:"required_events"`
	ComplianceTests   []string `json:"compliance_tests"`
	RequirementLevel  string   `json:"requirement_level"` // Required, Addressable
}

// HIPAAEvidenceSection represents a section in the HIPAA evidence report
type HIPAAEvidenceSection struct {
	SectionID    string `json:"section_id"`
	SectionTitle string `json:"section_title"`
	RegulationRef string `json:"regulation_ref"`
	Safeguards   []HIPAASafeguard `json:"safeguards"`
	EvidenceData []HIPAAEvidenceItem `json:"evidence_data"`
}

// HIPAAEvidenceItem represents individual evidence for HIPAA compliance
type HIPAAEvidenceItem struct {
	SafeguardID      string    `json:"safeguard_id"`
	EventID          string    `json:"event_id"`
	EventType        string    `json:"event_type"`
	Timestamp        time.Time `json:"timestamp"`
	UserID           string    `json:"user_id"`
	PHIAccessDetails string    `json:"phi_access_details,omitempty"`
	Description      string    `json:"description"`
	ComplianceStatus string    `json:"compliance_status"`
}

// HIPAAReport represents a complete HIPAA compliance evidence report
type HIPAAReport struct {
	ReportInfo       HIPAAReportInfo `json:"report_info"`
	CoveredEntity    HIPAACoveredEntity `json:"covered_entity"`
	TechnicalSafeguards []HIPAAEvidenceSection `json:"technical_safeguards"`
	PHIAccessLog     []PHIAccessEntry `json:"phi_access_log"`
	Conclusion       HIPAAConclusion `json:"conclusion"`
}

// HIPAAReportInfo contains metadata about the HIPAA report
type HIPAAReportInfo struct {
	ReportID         string    `json:"report_id"`
	ReportPeriod     string    `json:"report_period"`
	GeneratedAt      time.Time `json:"generated_at"`
	ComplianceStandard string  `json:"compliance_standard"` // HIPAA
	OrganizationName string    `json:"organization_name"`
	PreparedBy       string    `json:"prepared_by"`
	ReviewPeriod     string    `json:"review_period"`
}

// HIPAACoveredEntity describes the organization being audited
type HIPAACoveredEntity struct {
	Name              string `json:"name"`
	EntityType        string `json:"entity_type"` // Healthcare Provider, Health Plan, etc.
	Description       string `json:"description"`
	SystemDescription string `json:"system_description"`
	PHIProcessing     bool   `json:"phi_processing"`
}

// PHIAccessEntry tracks Protected Health Information access
type PHIAccessEntry struct {
	AccessID          string    `json:"access_id"`
	UserID            string    `json:"user_id"`
	Timestamp         time.Time `json:"timestamp"`
	AccessType        string    `json:"access_type"` // READ, WRITE, DELETE, etc.
	ResourceAccessed  string    `json:"resource_accessed"`
	BusinessJustification string `json:"business_justification"`
	AuthorizationLevel string   `json:"authorization_level"`
}

// HIPAAConclusion contains the overall HIPAA compliance conclusion
type HIPAAConclusion struct {
	OverallStatus       string    `json:"overall_status"`
	ComplianceScore     float64   `json:"compliance_score"`
	TotalSafeguards     int       `json:"total_safeguards"`
	CompliantSafeguards int       `json:"compliant_safeguards"`
	NonCompliantSafeguards int    `json:"non_compliant_safeguards"`
	Recommendations     []string  `json:"recommendations"`
	RiskAssessment      string    `json:"risk_assessment"`
	ConclusionDate      time.Time `json:"conclusion_date"`
}

// NewHIPAATemplate creates a new HIPAA compliance template
func NewHIPAATemplate() *HIPAATemplate {
	return &HIPAATemplate{
		FrameworkName:    "HIPAA Technical Safeguards",
		FrameworkVersion: "45 CFR Parts 160, 162, and 164",
		RequiredSafeguards: getHIPAASafeguards(),
	}
}

// getHIPAASafeguards returns the standard HIPAA technical safeguards
func getHIPAASafeguards() []HIPAASafeguard {
	return []HIPAASafeguard{
		{
			SafeguardID:       "164.308(a)(1)(i)",
			SafeguardName:     "Security Management Process",
			RegulationSection: "§164.308(a)(1)(i)",
			Description:       "Conduct an accurate and thorough assessment of the potential risks and vulnerabilities",
			RequiredEvents:    []string{"authentication", "login", "logout", "rbac_check"},
			ComplianceTests:   []string{"Review security policies", "Test access controls", "Verify user management"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.308(a)(5)(ii)(D)",
			SafeguardName:     "Assigned Security Responsibility",
			RegulationSection: "§164.308(a)(5)(ii)(D)",
			Description:       "Procedures for determining that the access of a workforce member is appropriate",
			RequiredEvents:    []string{"rbac_check", "permission_grant", "rbac_denied"},
			ComplianceTests:   []string{"Review role assignments", "Test permission controls", "Verify access reviews"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.310(d)(1)",
			SafeguardName:     "Device and Media Controls",
			RegulationSection: "§164.310(d)(1)",
			Description:       "Implement policies and procedures that govern the receipt and removal of hardware and electronic media",
			RequiredEvents:    []string{"system_error", "service_start", "service_stop"},
			ComplianceTests:   []string{"Review media handling", "Test device controls", "Verify disposal procedures"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.312(a)(1)",
			SafeguardName:     "Access Control",
			RegulationSection: "§164.312(a)(1)",
			Description:       "Implement technical policies and procedures that allow only authorized persons access to electronic PHI",
			RequiredEvents:    []string{"authentication", "rbac_check", "rbac_denied", "permission_grant"},
			ComplianceTests:   []string{"Test user authentication", "Review access permissions", "Verify authorization controls"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.312(b)",
			SafeguardName:     "Audit Controls",
			RegulationSection: "§164.312(b)",
			Description:       "Implement hardware, software, and/or procedural mechanisms that record and examine access",
			RequiredEvents:    []string{"authentication", "command", "command_execute", "nlp_input"},
			ComplianceTests:   []string{"Review audit logs", "Test logging mechanisms", "Verify log retention"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.312(c)(1)",
			SafeguardName:     "Integrity",
			RegulationSection: "§164.312(c)(1)",
			Description:       "Implement electronic mechanisms to corroborate that PHI has not been improperly altered or destroyed",
			RequiredEvents:    []string{"command_execute", "command_result", "system_error"},
			ComplianceTests:   []string{"Test data integrity", "Review integrity controls", "Verify checksum validation"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.312(d)",
			SafeguardName:     "Person or Entity Authentication",
			RegulationSection: "§164.312(d)",
			Description:       "Implement procedures to verify that a person or entity seeking access is the one claimed",
			RequiredEvents:    []string{"authentication", "login", "logout", "session_expiry"},
			ComplianceTests:   []string{"Test identity verification", "Review authentication mechanisms", "Verify MFA implementation"},
			RequirementLevel:  "Required",
		},
		{
			SafeguardID:       "164.312(e)(1)",
			SafeguardName:     "Transmission Security",
			RegulationSection: "§164.312(e)(1)",
			Description:       "Implement technical security measures to guard against unauthorized access to PHI transmitted over networks",
			RequiredEvents:    []string{"command", "nlp_translation", "command_generate"},
			ComplianceTests:   []string{"Test encryption in transit", "Review transmission protocols", "Verify network security"},
			RequirementLevel:  "Required",
		},
	}
}

// GenerateHIPAAReport creates a HIPAA compliance report from audit events
func (t *HIPAATemplate) GenerateHIPAAReport(reportInfo HIPAAReportInfo, events []*models.AuditEvent) (*HIPAAReport, error) {
	// Group events by safeguard requirements
	safeguardEvidence := make(map[string][]HIPAAEvidenceItem)
	phiAccessLog := []PHIAccessEntry{}
	
	for _, event := range events {
		// Track potential PHI access
		if isPHIRelatedEvent(event) {
			phiEntry := PHIAccessEntry{
				AccessID:             event.ID,
				UserID:               event.UserContext.UserID,
				Timestamp:            event.Timestamp,
				AccessType:           string(event.EventType),
				ResourceAccessed:     event.ClusterContext.ResourceName,
				BusinessJustification: "Kubernetes cluster management",
				AuthorizationLevel:   "Authorized",
			}
			phiAccessLog = append(phiAccessLog, phiEntry)
		}
		
		// Find applicable safeguards for this event type
		for _, safeguard := range t.RequiredSafeguards {
			for _, requiredEventType := range safeguard.RequiredEvents {
				if string(event.EventType) == requiredEventType {
					evidenceItem := HIPAAEvidenceItem{
						SafeguardID:      safeguard.SafeguardID,
						EventID:          event.ID,
						EventType:        string(event.EventType),
						Timestamp:        event.Timestamp,
						UserID:           event.UserContext.UserID,
						Description:      event.Message,
						ComplianceStatus: "COMPLIANT",
					}
					
					// Add PHI access details if applicable
					if isPHIRelatedEvent(event) {
						evidenceItem.PHIAccessDetails = fmt.Sprintf("Accessed resource: %s in namespace: %s", 
							event.ClusterContext.ResourceName, event.ClusterContext.Namespace)
					}
					
					safeguardEvidence[safeguard.SafeguardID] = append(safeguardEvidence[safeguard.SafeguardID], evidenceItem)
				}
			}
		}
	}
	
	// Create technical safeguards sections
	sections := []HIPAAEvidenceSection{}
	for _, safeguard := range t.RequiredSafeguards {
		section := HIPAAEvidenceSection{
			SectionID:    safeguard.SafeguardID,
			SectionTitle: safeguard.SafeguardName,
			RegulationRef: safeguard.RegulationSection,
			Safeguards:   []HIPAASafeguard{safeguard},
			EvidenceData: safeguardEvidence[safeguard.SafeguardID],
		}
		sections = append(sections, section)
	}
	
	// Calculate compliance metrics
	totalSafeguards := len(t.RequiredSafeguards)
	compliantSafeguards := 0
	nonCompliantSafeguards := 0
	
	for _, safeguard := range t.RequiredSafeguards {
		if len(safeguardEvidence[safeguard.SafeguardID]) > 0 {
			compliantSafeguards++
		} else {
			nonCompliantSafeguards++
		}
	}
	
	complianceScore := float64(compliantSafeguards) / float64(totalSafeguards) * 100
	overallStatus := "NON-COMPLIANT"
	riskAssessment := "HIGH RISK"
	
	if complianceScore >= 90 {
		overallStatus = "COMPLIANT"
		riskAssessment = "LOW RISK"
	} else if complianceScore >= 70 {
		overallStatus = "PARTIALLY COMPLIANT"
		riskAssessment = "MEDIUM RISK"
	}
	
	// Create conclusion
	conclusion := HIPAAConclusion{
		OverallStatus:          overallStatus,
		ComplianceScore:        complianceScore,
		TotalSafeguards:        totalSafeguards,
		CompliantSafeguards:    compliantSafeguards,
		NonCompliantSafeguards: nonCompliantSafeguards,
		Recommendations:        generateHIPAARecommendations(safeguardEvidence, t.RequiredSafeguards),
		RiskAssessment:         riskAssessment,
		ConclusionDate:         time.Now(),
	}
	
	// Create covered entity
	coveredEntity := HIPAACoveredEntity{
		Name:              "KubeChat Service",
		EntityType:        "Business Associate",
		Description:       "Kubernetes natural language interface service",
		SystemDescription: "Cloud-based Kubernetes management platform with audit capabilities",
		PHIProcessing:     true,
	}
	
	report := &HIPAAReport{
		ReportInfo:          reportInfo,
		CoveredEntity:       coveredEntity,
		TechnicalSafeguards: sections,
		PHIAccessLog:        phiAccessLog,
		Conclusion:          conclusion,
	}
	
	return report, nil
}

// isPHIRelatedEvent determines if an event potentially involves PHI access
func isPHIRelatedEvent(event *models.AuditEvent) bool {
	phiRelatedTypes := map[models.AuditEventType]bool{
		models.AuditEventTypeCommand:        true,
		models.AuditEventTypeCommandExecute: true,
		models.AuditEventTypeCommandResult:  true,
		models.AuditEventTypeNLPInput:       true,
	}
	
	return phiRelatedTypes[event.EventType]
}

// generateHIPAARecommendations creates recommendations based on compliance gaps
func generateHIPAARecommendations(safeguardEvidence map[string][]HIPAAEvidenceItem, safeguards []HIPAASafeguard) []string {
	recommendations := []string{}
	
	for _, safeguard := range safeguards {
		if len(safeguardEvidence[safeguard.SafeguardID]) == 0 {
			recommendation := fmt.Sprintf("Implement monitoring and controls for %s (%s) to ensure HIPAA compliance", 
				safeguard.SafeguardName, safeguard.SafeguardID)
			recommendations = append(recommendations, recommendation)
		}
	}
	
	// Add general HIPAA recommendations
	if len(recommendations) > 0 {
		recommendations = append(recommendations, "Conduct regular HIPAA risk assessments")
		recommendations = append(recommendations, "Implement comprehensive workforce training on PHI handling")
		recommendations = append(recommendations, "Establish incident response procedures for PHI breaches")
	} else {
		recommendations = append(recommendations, "All HIPAA technical safeguards are adequately supported by audit evidence")
		recommendations = append(recommendations, "Continue regular monitoring and periodic compliance reviews")
	}
	
	return recommendations
}

// FormatHIPAAReportJSON formats the HIPAA report as JSON
func (t *HIPAATemplate) FormatHIPAAReportJSON(report *HIPAAReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ValidateHIPAACompliance validates events against HIPAA requirements
func (t *HIPAATemplate) ValidateHIPAACompliance(events []*models.AuditEvent) (bool, []string) {
	issues := []string{}
	requiredEventTypes := make(map[string]bool)
	
	// Collect all required event types
	for _, safeguard := range t.RequiredSafeguards {
		for _, eventType := range safeguard.RequiredEvents {
			requiredEventTypes[eventType] = false
		}
	}
	
	// Check which required events are present
	for _, event := range events {
		eventTypeStr := string(event.EventType)
		if _, required := requiredEventTypes[eventTypeStr]; required {
			requiredEventTypes[eventTypeStr] = true
		}
	}
	
	// Identify missing event types
	for eventType, found := range requiredEventTypes {
		if !found {
			issues = append(issues, fmt.Sprintf("Missing required event type for HIPAA compliance: %s", eventType))
		}
	}
	
	// Additional HIPAA-specific validations
	hasAuthenticationEvents := false
	hasAuditControls := false
	
	for _, event := range events {
		switch event.EventType {
		case models.AuditEventTypeAuthentication, models.AuditEventTypeLogin:
			hasAuthenticationEvents = true
		case models.AuditEventTypeCommand, models.AuditEventTypeCommandExecute:
			hasAuditControls = true
		}
	}
	
	if !hasAuthenticationEvents {
		issues = append(issues, "HIPAA requires robust authentication logging - no authentication events found")
	}
	
	if !hasAuditControls {
		issues = append(issues, "HIPAA requires comprehensive audit controls - insufficient audit events found")
	}
	
	return len(issues) == 0, issues
}