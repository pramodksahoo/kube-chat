// Package templates provides ISO 27001 compliance framework templates for evidence generation
package templates

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ISO27001Template provides ISO 27001:2022 compliance framework template
type ISO27001Template struct {
	FrameworkName    string `json:"framework_name"`
	FrameworkVersion string `json:"framework_version"`
	RequiredControls []ISO27001Control `json:"required_controls"`
}

// ISO27001Control represents an ISO 27001 security control requirement
type ISO27001Control struct {
	ControlID         string   `json:"control_id"`
	ControlName       string   `json:"control_name"`
	ControlDomain     string   `json:"control_domain"`
	Description       string   `json:"description"`
	RequiredEvents    []string `json:"required_events"`
	ObjectiveStatements []string `json:"objective_statements"`
	ImplementationGuidance string `json:"implementation_guidance"`
}

// ISO27001EvidenceSection represents a section in the ISO 27001 evidence report
type ISO27001EvidenceSection struct {
	SectionID    string `json:"section_id"`
	SectionTitle string `json:"section_title"`
	ControlDomain string `json:"control_domain"`
	Controls     []ISO27001Control `json:"controls"`
	EvidenceData []ISO27001EvidenceItem `json:"evidence_data"`
}

// ISO27001EvidenceItem represents individual evidence for ISO 27001 compliance
type ISO27001EvidenceItem struct {
	ControlID        string    `json:"control_id"`
	EventID          string    `json:"event_id"`
	EventType        string    `json:"event_type"`
	Timestamp        time.Time `json:"timestamp"`
	UserID           string    `json:"user_id"`
	SecurityContext  string    `json:"security_context"`
	Description      string    `json:"description"`
	ComplianceStatus string    `json:"compliance_status"`
	RiskLevel        string    `json:"risk_level"`
}

// ISO27001Report represents a complete ISO 27001 compliance evidence report
type ISO27001Report struct {
	ReportInfo      ISO27001ReportInfo `json:"report_info"`
	Organization    ISO27001Organization `json:"organization"`
	SecurityDomains []ISO27001SecurityDomain `json:"security_domains"`
	RiskAssessment  ISO27001RiskAssessment `json:"risk_assessment"`
	Conclusion      ISO27001Conclusion `json:"conclusion"`
}

// ISO27001ReportInfo contains metadata about the ISO 27001 report
type ISO27001ReportInfo struct {
	ReportID         string    `json:"report_id"`
	ReportPeriod     string    `json:"report_period"`
	GeneratedAt      time.Time `json:"generated_at"`
	Standard         string    `json:"standard"` // ISO 27001:2022
	OrganizationName string    `json:"organization_name"`
	PreparedBy       string    `json:"prepared_by"`
	ReviewPeriod     string    `json:"review_period"`
	CertificationBody string   `json:"certification_body,omitempty"`
}

// ISO27001Organization describes the organization being audited
type ISO27001Organization struct {
	Name                string `json:"name"`
	Scope               string `json:"scope"`
	Description         string `json:"description"`
	InformationSystems  string `json:"information_systems"`
	BusinessContext     string `json:"business_context"`
	RegulatoryContext   string `json:"regulatory_context"`
}

// ISO27001SecurityDomain represents one of the 14 security control domains
type ISO27001SecurityDomain struct {
	DomainID     string `json:"domain_id"`
	DomainName   string `json:"domain_name"`
	Description  string `json:"description"`
	Sections     []ISO27001EvidenceSection `json:"sections"`
	DomainStatus string `json:"domain_status"`
}

// ISO27001RiskAssessment contains risk assessment results
type ISO27001RiskAssessment struct {
	TotalRisks         int      `json:"total_risks"`
	HighRisks          int      `json:"high_risks"`
	MediumRisks        int      `json:"medium_risks"`
	LowRisks           int      `json:"low_risks"`
	ResiduaRisks       int      `json:"residual_risks"`
	RiskMitigation     []string `json:"risk_mitigation"`
	TreatmentPlan      string   `json:"treatment_plan"`
}

// ISO27001Conclusion contains the overall ISO 27001 compliance conclusion
type ISO27001Conclusion struct {
	OverallStatus       string    `json:"overall_status"`
	ComplianceScore     float64   `json:"compliance_score"`
	TotalControls       int       `json:"total_controls"`
	ImplementedControls int       `json:"implemented_controls"`
	PartialControls     int       `json:"partial_controls"`
	MissingControls     int       `json:"missing_controls"`
	Recommendations     []string  `json:"recommendations"`
	NextReviewDate      time.Time `json:"next_review_date"`
	ConclusionDate      time.Time `json:"conclusion_date"`
}

// NewISO27001Template creates a new ISO 27001 compliance template
func NewISO27001Template() *ISO27001Template {
	return &ISO27001Template{
		FrameworkName:    "ISO 27001:2022",
		FrameworkVersion: "ISO/IEC 27001:2022",
		RequiredControls: getISO27001Controls(),
	}
}

// getISO27001Controls returns the key ISO 27001:2022 controls relevant to KubeChat
func getISO27001Controls() []ISO27001Control {
	return []ISO27001Control{
		{
			ControlID:     "A.5.1",
			ControlName:   "Policies for Information Security",
			ControlDomain: "Organizational Controls",
			Description:   "Information security policy and topic-specific policies should be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties, and reviewed at planned intervals or if significant changes occur.",
			RequiredEvents: []string{"authentication", "rbac_check", "service_start"},
			ObjectiveStatements: []string{"Management direction and support for information security", "Policy implementation across the organization"},
			ImplementationGuidance: "Establish, implement, maintain and continually improve an information security management system",
		},
		{
			ControlID:     "A.5.2",
			ControlName:   "Information Security Roles and Responsibilities",
			ControlDomain: "Organizational Controls",
			Description:   "Information security roles and responsibilities should be defined and allocated according to the organization needs.",
			RequiredEvents: []string{"rbac_check", "permission_grant", "rbac_denied"},
			ObjectiveStatements: []string{"Clear assignment of information security responsibilities", "Accountability for information security"},
			ImplementationGuidance: "Define roles and responsibilities for information security activities",
		},
		{
			ControlID:     "A.8.2",
			ControlName:   "Privileged Access Rights",
			ControlDomain: "Technology Controls",
			Description:   "The allocation and use of privileged access rights should be restricted and managed.",
			RequiredEvents: []string{"authentication", "rbac_check", "permission_grant", "rbac_denied"},
			ObjectiveStatements: []string{"Control privileged access", "Minimize risk from privileged access"},
			ImplementationGuidance: "Implement controls for privileged access management and monitoring",
		},
		{
			ControlID:     "A.8.3",
			ControlName:   "Information Access Restriction",
			ControlDomain: "Technology Controls", 
			Description:   "Access to information and other associated assets should be restricted in accordance with the established topic-specific policy on access control.",
			RequiredEvents: []string{"rbac_check", "rbac_denied", "command_execute"},
			ObjectiveStatements: []string{"Restrict information access", "Ensure authorized access only"},
			ImplementationGuidance: "Implement access control mechanisms and monitor compliance",
		},
		{
			ControlID:     "A.8.5",
			ControlName:   "Secure Authentication",
			ControlDomain: "Technology Controls",
			Description:   "Secure authentication technologies and procedures should be implemented based on information access restrictions and the topic-specific policy on access control.",
			RequiredEvents: []string{"authentication", "login", "logout", "session_expiry"},
			ObjectiveStatements: []string{"Strong authentication mechanisms", "Prevent unauthorized access"},
			ImplementationGuidance: "Implement multi-factor authentication where appropriate",
		},
		{
			ControlID:     "A.8.15",
			ControlName:   "Logging",
			ControlDomain: "Technology Controls",
			Description:   "Logs that record activities, exceptions, faults and other relevant events should be produced, stored, protected and analysed.",
			RequiredEvents: []string{"authentication", "command", "command_execute", "system_error", "health_check"},
			ObjectiveStatements: []string{"Comprehensive activity logging", "Security event detection"},
			ImplementationGuidance: "Implement comprehensive logging and monitoring systems",
		},
		{
			ControlID:     "A.8.16",
			ControlName:   "Monitoring Activities", 
			ControlDomain: "Technology Controls",
			Description:   "Networks, systems and applications should be monitored for anomalous behaviour and appropriate actions taken to evaluate potential information security incidents.",
			RequiredEvents: []string{"system_error", "health_check", "service_start", "service_stop"},
			ObjectiveStatements: []string{"Continuous monitoring", "Anomaly detection"},
			ImplementationGuidance: "Implement security monitoring and incident detection capabilities",
		},
		{
			ControlID:     "A.5.7",
			ControlName:   "Threat Intelligence",
			ControlDomain: "Organizational Controls",
			Description:   "Information relating to information security threats should be collected and analysed to produce threat intelligence.",
			RequiredEvents: []string{"system_error", "rbac_denied", "authentication"},
			ObjectiveStatements: []string{"Threat awareness", "Proactive security measures"},
			ImplementationGuidance: "Establish threat intelligence capabilities and analysis processes",
		},
		{
			ControlID:     "A.5.23",
			ControlName:   "Information Security for Use of Cloud Services",
			ControlDomain: "Organizational Controls",
			Description:   "Processes for the acquisition, use, management and exit from cloud services should be established in accordance with the organization's information security requirements.",
			RequiredEvents: []string{"service_start", "service_stop", "health_check", "command"},
			ObjectiveStatements: []string{"Secure cloud service usage", "Cloud security governance"},
			ImplementationGuidance: "Establish cloud security controls and monitoring",
		},
		{
			ControlID:     "A.5.30",
			ControlName:   "ICT Readiness for Business Continuity",
			ControlDomain: "Organizational Controls",
			Description:   "ICT readiness should be planned, implemented, maintained and tested based on business continuity objectives and ICT continuity requirements.",
			RequiredEvents: []string{"service_start", "service_stop", "health_check", "system_error"},
			ObjectiveStatements: []string{"Business continuity", "System availability"},
			ImplementationGuidance: "Implement business continuity and disaster recovery procedures",
		},
	}
}

// GenerateISO27001Report creates an ISO 27001 compliance report from audit events
func (t *ISO27001Template) GenerateISO27001Report(reportInfo ISO27001ReportInfo, events []*models.AuditEvent) (*ISO27001Report, error) {
	// Group events by control requirements
	controlEvidence := make(map[string][]ISO27001EvidenceItem)
	
	for _, event := range events {
		// Determine risk level based on event type
		riskLevel := determineRiskLevel(event)
		
		// Find applicable controls for this event type
		for _, control := range t.RequiredControls {
			for _, requiredEventType := range control.RequiredEvents {
				if string(event.EventType) == requiredEventType {
					evidenceItem := ISO27001EvidenceItem{
						ControlID:        control.ControlID,
						EventID:          event.ID,
						EventType:        string(event.EventType),
						Timestamp:        event.Timestamp,
						UserID:           event.UserContext.UserID,
						SecurityContext:  fmt.Sprintf("Namespace: %s, Resource: %s", event.ClusterContext.Namespace, event.ClusterContext.ResourceName),
						Description:      event.Message,
						ComplianceStatus: "IMPLEMENTED",
						RiskLevel:        riskLevel,
					}
					controlEvidence[control.ControlID] = append(controlEvidence[control.ControlID], evidenceItem)
				}
			}
		}
	}
	
	// Group controls by domain
	domainControls := make(map[string][]ISO27001Control)
	for _, control := range t.RequiredControls {
		domainControls[control.ControlDomain] = append(domainControls[control.ControlDomain], control)
	}
	
	// Create security domains
	securityDomains := []ISO27001SecurityDomain{}
	for domainName, controls := range domainControls {
		sections := []ISO27001EvidenceSection{}
		domainStatus := "IMPLEMENTED"
		
		for _, control := range controls {
			section := ISO27001EvidenceSection{
				SectionID:     control.ControlID,
				SectionTitle:  control.ControlName,
				ControlDomain: control.ControlDomain,
				Controls:      []ISO27001Control{control},
				EvidenceData:  controlEvidence[control.ControlID],
			}
			sections = append(sections, section)
			
			// Determine domain status based on evidence
			if len(controlEvidence[control.ControlID]) == 0 {
				domainStatus = "PARTIALLY IMPLEMENTED"
			}
		}
		
		domain := ISO27001SecurityDomain{
			DomainID:     getDomainID(domainName),
			DomainName:   domainName,
			Description:  getDomainDescription(domainName),
			Sections:     sections,
			DomainStatus: domainStatus,
		}
		securityDomains = append(securityDomains, domain)
	}
	
	// Calculate compliance metrics
	totalControls := len(t.RequiredControls)
	implementedControls := 0
	partialControls := 0
	missingControls := 0
	
	for _, control := range t.RequiredControls {
		evidenceCount := len(controlEvidence[control.ControlID])
		if evidenceCount > 10 { // Arbitrary threshold for "well implemented"
			implementedControls++
		} else if evidenceCount > 0 {
			partialControls++
		} else {
			missingControls++
		}
	}
	
	complianceScore := float64(implementedControls*100 + partialControls*50) / float64(totalControls*100) * 100
	overallStatus := "NON-COMPLIANT"
	
	if complianceScore >= 85 {
		overallStatus = "COMPLIANT"
	} else if complianceScore >= 60 {
		overallStatus = "PARTIALLY COMPLIANT"
	}
	
	// Risk assessment
	riskAssessment := calculateRiskAssessment(events, controlEvidence)
	
	// Create conclusion
	conclusion := ISO27001Conclusion{
		OverallStatus:       overallStatus,
		ComplianceScore:     complianceScore,
		TotalControls:       totalControls,
		ImplementedControls: implementedControls,
		PartialControls:     partialControls,
		MissingControls:     missingControls,
		Recommendations:     generateISO27001Recommendations(controlEvidence, t.RequiredControls),
		NextReviewDate:      time.Now().AddDate(1, 0, 0), // Annual review
		ConclusionDate:      time.Now(),
	}
	
	// Create organization info
	organization := ISO27001Organization{
		Name:               "KubeChat Service",
		Scope:              "Kubernetes natural language interface service and audit capabilities",
		Description:        "Cloud-based Kubernetes management platform with comprehensive audit and compliance features",
		InformationSystems: "KubeChat platform, audit logging system, NLP services",
		BusinessContext:    "Cloud-native Kubernetes management service",
		RegulatoryContext:  "Information security management for cloud services",
	}
	
	report := &ISO27001Report{
		ReportInfo:      reportInfo,
		Organization:    organization,
		SecurityDomains: securityDomains,
		RiskAssessment:  riskAssessment,
		Conclusion:      conclusion,
	}
	
	return report, nil
}

// determineRiskLevel determines the risk level for an audit event
func determineRiskLevel(event *models.AuditEvent) string {
	switch event.EventType {
	case models.AuditEventTypeRBACDenied, models.AuditEventTypeSystemError:
		return "HIGH"
	case models.AuditEventTypeCommandExecute, models.AuditEventTypePermissionGrant:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// getDomainID returns the domain identifier
func getDomainID(domainName string) string {
	switch domainName {
	case "Organizational Controls":
		return "A.5"
	case "Technology Controls":
		return "A.8"
	default:
		return "A.X"
	}
}

// getDomainDescription returns the domain description
func getDomainDescription(domainName string) string {
	switch domainName {
	case "Organizational Controls":
		return "Controls that are administrative in nature and relate to the organization's management"
	case "Technology Controls":
		return "Controls that are technical in nature and implemented through technology"
	default:
		return "Security controls domain"
	}
}

// calculateRiskAssessment performs a basic risk assessment
func calculateRiskAssessment(events []*models.AuditEvent, controlEvidence map[string][]ISO27001EvidenceItem) ISO27001RiskAssessment {
	highRisks := 0
	mediumRisks := 0
	lowRisks := 0
	
	for _, event := range events {
		switch determineRiskLevel(event) {
		case "HIGH":
			highRisks++
		case "MEDIUM":
			mediumRisks++
		case "LOW":
			lowRisks++
		}
	}
	
	totalRisks := highRisks + mediumRisks + lowRisks
	residualRisks := highRisks // Assume high risks are residual
	
	riskMitigation := []string{
		"Continuous monitoring and alerting for high-risk events",
		"Regular access reviews and privilege management",
		"Incident response procedures for security events",
		"Employee training on information security policies",
	}
	
	treatmentPlan := "Implement additional controls for high-risk areas and maintain monitoring for all identified risks"
	
	return ISO27001RiskAssessment{
		TotalRisks:     totalRisks,
		HighRisks:      highRisks,
		MediumRisks:    mediumRisks,
		LowRisks:       lowRisks,
		ResiduaRisks:   residualRisks,
		RiskMitigation: riskMitigation,
		TreatmentPlan:  treatmentPlan,
	}
}

// generateISO27001Recommendations creates recommendations based on compliance gaps
func generateISO27001Recommendations(controlEvidence map[string][]ISO27001EvidenceItem, controls []ISO27001Control) []string {
	recommendations := []string{}
	
	for _, control := range controls {
		evidenceCount := len(controlEvidence[control.ControlID])
		if evidenceCount == 0 {
			recommendation := fmt.Sprintf("Implement monitoring and controls for %s (%s) to meet ISO 27001 requirements", 
				control.ControlName, control.ControlID)
			recommendations = append(recommendations, recommendation)
		} else if evidenceCount < 5 { // Arbitrary threshold for "sufficient evidence"
			recommendation := fmt.Sprintf("Enhance monitoring for %s (%s) to provide more comprehensive evidence", 
				control.ControlName, control.ControlID)
			recommendations = append(recommendations, recommendation)
		}
	}
	
	// Add general ISO 27001 recommendations
	if len(recommendations) > 0 {
		recommendations = append(recommendations, "Conduct annual risk assessments and management reviews")
		recommendations = append(recommendations, "Implement continuous improvement processes for ISMS")
		recommendations = append(recommendations, "Establish incident management and business continuity procedures")
	} else {
		recommendations = append(recommendations, "All ISO 27001 controls are adequately implemented with sufficient audit evidence")
		recommendations = append(recommendations, "Continue regular monitoring and maintain certification through surveillance audits")
	}
	
	return recommendations
}

// FormatISO27001ReportJSON formats the ISO 27001 report as JSON
func (t *ISO27001Template) FormatISO27001ReportJSON(report *ISO27001Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ValidateISO27001Compliance validates events against ISO 27001 requirements
func (t *ISO27001Template) ValidateISO27001Compliance(events []*models.AuditEvent) (bool, []string) {
	issues := []string{}
	requiredEventTypes := make(map[string]bool)
	
	// Collect all required event types
	for _, control := range t.RequiredControls {
		for _, eventType := range control.RequiredEvents {
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
			issues = append(issues, fmt.Sprintf("Missing required event type for ISO 27001 compliance: %s", eventType))
		}
	}
	
	// Additional ISO 27001-specific validations
	hasLoggingEvents := false
	hasAccessControlEvents := false
	hasMonitoringEvents := false
	
	for _, event := range events {
		switch event.EventType {
		case models.AuditEventTypeAuthentication, models.AuditEventTypeLogin, models.AuditEventTypeRBACCheck:
			hasAccessControlEvents = true
		case models.AuditEventTypeCommand, models.AuditEventTypeCommandExecute:
			hasLoggingEvents = true
		case models.AuditEventTypeHealthCheck, models.AuditEventTypeSystemError:
			hasMonitoringEvents = true
		}
	}
	
	if !hasAccessControlEvents {
		issues = append(issues, "ISO 27001 requires comprehensive access control logging - insufficient access control events found")
	}
	
	if !hasLoggingEvents {
		issues = append(issues, "ISO 27001 requires detailed activity logging - insufficient activity events found")
	}
	
	if !hasMonitoringEvents {
		issues = append(issues, "ISO 27001 requires system monitoring - insufficient monitoring events found")
	}
	
	return len(issues) == 0, issues
}