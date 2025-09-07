// Package templates provides compliance framework templates for evidence generation
package templates

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// SOC2Template provides SOC 2 Type I compliance framework template
type SOC2Template struct {
	FrameworkName    string `json:"framework_name"`
	FrameworkVersion string `json:"framework_version"`
	RequiredControls []SOC2Control `json:"required_controls"`
}

// SOC2Control represents a SOC 2 control requirement
type SOC2Control struct {
	ControlID          string   `json:"control_id"`
	ControlName        string   `json:"control_name"`
	ControlDescription string   `json:"control_description"`
	Category           string   `json:"category"`
	RequiredEvents     []string `json:"required_events"`
	TestProcedures     []string `json:"test_procedures"`
}

// SOC2EvidenceSection represents a section in the SOC 2 evidence report
type SOC2EvidenceSection struct {
	SectionID    string `json:"section_id"`
	SectionTitle string `json:"section_title"`
	Controls     []SOC2Control `json:"controls"`
	EvidenceData []SOC2EvidenceItem `json:"evidence_data"`
}

// SOC2EvidenceItem represents individual evidence for SOC 2 compliance
type SOC2EvidenceItem struct {
	ControlID     string    `json:"control_id"`
	EventID       string    `json:"event_id"`
	EventType     string    `json:"event_type"`
	Timestamp     time.Time `json:"timestamp"`
	UserID        string    `json:"user_id"`
	Description   string    `json:"description"`
	ComplianceStatus string `json:"compliance_status"`
}

// SOC2Report represents a complete SOC 2 compliance evidence report
type SOC2Report struct {
	ReportInfo     SOC2ReportInfo `json:"report_info"`
	ServiceEntity  SOC2ServiceEntity `json:"service_entity"`
	TrustCategories []SOC2TrustCategory `json:"trust_categories"`
	Sections       []SOC2EvidenceSection `json:"sections"`
	Conclusion     SOC2Conclusion `json:"conclusion"`
}

// SOC2ReportInfo contains metadata about the SOC 2 report
type SOC2ReportInfo struct {
	ReportID        string    `json:"report_id"`
	ReportPeriod    string    `json:"report_period"`
	GeneratedAt     time.Time `json:"generated_at"`
	ReportType      string    `json:"report_type"` // Type I or Type II
	Framework       string    `json:"framework"`   // SOC 2
	OrganizationName string   `json:"organization_name"`
	PreparedBy      string    `json:"prepared_by"`
}

// SOC2ServiceEntity describes the organization being audited
type SOC2ServiceEntity struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	ServiceType  string `json:"service_type"`
	LocationInfo string `json:"location_info"`
}

// SOC2TrustCategory represents the five trust service categories
type SOC2TrustCategory struct {
	CategoryID   string `json:"category_id"` // CC1, CC2, etc.
	CategoryName string `json:"category_name"`
	Description  string `json:"description"`
	Controls     []SOC2Control `json:"controls"`
}

// SOC2Conclusion contains the overall compliance conclusion
type SOC2Conclusion struct {
	OverallStatus    string    `json:"overall_status"`
	ComplianceScore  float64   `json:"compliance_score"`
	TotalControls    int       `json:"total_controls"`
	PassingControls  int       `json:"passing_controls"`
	FailingControls  int       `json:"failing_controls"`
	Recommendations  []string  `json:"recommendations"`
	ConclusionDate   time.Time `json:"conclusion_date"`
}

// NewSOC2Template creates a new SOC 2 compliance template
func NewSOC2Template() *SOC2Template {
	return &SOC2Template{
		FrameworkName:    "SOC 2 Type I",
		FrameworkVersion: "2017 Trust Services Criteria",
		RequiredControls: getSOC2Controls(),
	}
}

// getSOC2Controls returns the standard SOC 2 controls
func getSOC2Controls() []SOC2Control {
	return []SOC2Control{
		{
			ControlID:          "CC1.1",
			ControlName:        "Control Environment - Integrity and Ethical Values",
			ControlDescription: "The entity demonstrates a commitment to integrity and ethical values",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"authentication", "login", "logout", "rbac_check"},
			TestProcedures:    []string{"Review user access policies", "Test authentication mechanisms", "Verify access controls"},
		},
		{
			ControlID:          "CC2.1",
			ControlName:        "Communication and Information",
			ControlDescription: "The entity obtains or generates and uses relevant, quality information",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"command", "command_execute", "command_result"},
			TestProcedures:    []string{"Review information systems", "Test data accuracy", "Verify information flow"},
		},
		{
			ControlID:          "CC3.1",
			ControlName:        "Risk Assessment",
			ControlDescription: "The entity specifies objectives with sufficient clarity",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"rbac_denied", "system_error", "permission_grant"},
			TestProcedures:    []string{"Review risk management processes", "Test security controls", "Verify risk mitigation"},
		},
		{
			ControlID:          "CC4.1",
			ControlName:        "Monitoring Activities",
			ControlDescription: "The entity selects, develops, and performs ongoing and/or separate evaluations",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"health_check", "service_start", "service_stop"},
			TestProcedures:    []string{"Review monitoring procedures", "Test alerting mechanisms", "Verify log retention"},
		},
		{
			ControlID:          "CC5.1",
			ControlName:        "Control Activities",
			ControlDescription: "The entity selects and develops control activities",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"nlp_input", "nlp_translation", "command_generate"},
			TestProcedures:    []string{"Review control design", "Test control operation", "Verify control effectiveness"},
		},
		{
			ControlID:          "CC6.1",
			ControlName:        "Logical and Physical Access Controls",
			ControlDescription: "The entity implements logical access security software",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"authentication", "rbac_check", "rbac_denied"},
			TestProcedures:    []string{"Test user authentication", "Review access permissions", "Verify access revocation"},
		},
		{
			ControlID:          "CC7.1",
			ControlName:        "System Operations",
			ControlDescription: "The entity manages the system to ensure processing integrity",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"command_execute", "command_result", "system_error"},
			TestProcedures:    []string{"Review system operations", "Test data processing", "Verify error handling"},
		},
		{
			ControlID:          "CC8.1",
			ControlName:        "Change Management",
			ControlDescription: "The entity authorizes, designs, develops or acquires, implements, operates, approves and maintains system changes",
			Category:          "Common Criteria",
			RequiredEvents:    []string{"service_start", "service_stop", "health_check"},
			TestProcedures:    []string{"Review change procedures", "Test change controls", "Verify change authorization"},
		},
	}
}

// GenerateSOC2Report creates a SOC 2 compliance report from audit events
func (t *SOC2Template) GenerateSOC2Report(reportInfo SOC2ReportInfo, events []*models.AuditEvent) (*SOC2Report, error) {
	// Group events by control requirements
	controlEvidence := make(map[string][]SOC2EvidenceItem)
	
	for _, event := range events {
		// Find applicable controls for this event type
		for _, control := range t.RequiredControls {
			for _, requiredEventType := range control.RequiredEvents {
				if string(event.EventType) == requiredEventType {
					evidenceItem := SOC2EvidenceItem{
						ControlID:        control.ControlID,
						EventID:          event.ID,
						EventType:        string(event.EventType),
						Timestamp:        event.Timestamp,
						UserID:           event.UserContext.UserID,
						Description:      event.Message,
						ComplianceStatus: "COMPLIANT",
					}
					controlEvidence[control.ControlID] = append(controlEvidence[control.ControlID], evidenceItem)
				}
			}
		}
	}
	
	// Create trust categories
	trustCategories := []SOC2TrustCategory{
		{
			CategoryID:   "CC",
			CategoryName: "Common Criteria",
			Description:  "Common criteria applicable to all trust service categories",
			Controls:     t.RequiredControls,
		},
	}
	
	// Create evidence sections
	sections := []SOC2EvidenceSection{}
	for _, control := range t.RequiredControls {
		section := SOC2EvidenceSection{
			SectionID:    control.ControlID,
			SectionTitle: control.ControlName,
			Controls:     []SOC2Control{control},
			EvidenceData: controlEvidence[control.ControlID],
		}
		sections = append(sections, section)
	}
	
	// Calculate compliance metrics
	totalControls := len(t.RequiredControls)
	passingControls := 0
	failingControls := 0
	
	for _, control := range t.RequiredControls {
		if len(controlEvidence[control.ControlID]) > 0 {
			passingControls++
		} else {
			failingControls++
		}
	}
	
	complianceScore := float64(passingControls) / float64(totalControls) * 100
	overallStatus := "NON-COMPLIANT"
	if complianceScore >= 80 {
		overallStatus = "COMPLIANT"
	}
	
	// Create conclusion
	conclusion := SOC2Conclusion{
		OverallStatus:   overallStatus,
		ComplianceScore: complianceScore,
		TotalControls:   totalControls,
		PassingControls: passingControls,
		FailingControls: failingControls,
		Recommendations: generateSOC2Recommendations(controlEvidence, t.RequiredControls),
		ConclusionDate:  time.Now(),
	}
	
	// Create service entity
	serviceEntity := SOC2ServiceEntity{
		Name:         "KubeChat Service",
		Description:  "Kubernetes natural language interface service",
		ServiceType:  "Cloud-based Kubernetes Management Platform",
		LocationInfo: "Cloud Infrastructure",
	}
	
	report := &SOC2Report{
		ReportInfo:      reportInfo,
		ServiceEntity:   serviceEntity,
		TrustCategories: trustCategories,
		Sections:        sections,
		Conclusion:      conclusion,
	}
	
	return report, nil
}

// generateSOC2Recommendations creates recommendations based on compliance gaps
func generateSOC2Recommendations(controlEvidence map[string][]SOC2EvidenceItem, controls []SOC2Control) []string {
	recommendations := []string{}
	
	for _, control := range controls {
		if len(controlEvidence[control.ControlID]) == 0 {
			recommendation := fmt.Sprintf("Implement additional monitoring for %s (%s) to ensure adequate evidence collection", 
				control.ControlName, control.ControlID)
			recommendations = append(recommendations, recommendation)
		}
	}
	
	if len(recommendations) == 0 {
		recommendations = append(recommendations, "All SOC 2 controls are adequately supported by audit evidence")
	}
	
	return recommendations
}

// FormatSOC2ReportJSON formats the SOC 2 report as JSON
func (t *SOC2Template) FormatSOC2ReportJSON(report *SOC2Report) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

// ValidateSOC2Compliance validates events against SOC 2 requirements
func (t *SOC2Template) ValidateSOC2Compliance(events []*models.AuditEvent) (bool, []string) {
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
			issues = append(issues, fmt.Sprintf("Missing required event type for SOC 2 compliance: %s", eventType))
		}
	}
	
	return len(issues) == 0, issues
}