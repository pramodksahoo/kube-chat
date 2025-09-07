package formats

import (
	"fmt"
	"strings"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// CEFExporter handles Common Event Format export for SIEM systems like Splunk
type CEFExporter struct {
	deviceVendor    string
	deviceProduct   string
	deviceVersion   string
	signaturePrefix string
}

// CEFExporterConfig configures the CEF exporter behavior
type CEFExporterConfig struct {
	DeviceVendor    string `json:"device_vendor"`
	DeviceProduct   string `json:"device_product"`
	DeviceVersion   string `json:"device_version"`
	SignaturePrefix string `json:"signature_prefix"`
}

// DefaultCEFConfig returns default CEF configuration
func DefaultCEFConfig() CEFExporterConfig {
	return CEFExporterConfig{
		DeviceVendor:    "KubeChat",
		DeviceProduct:   "Kubernetes Chat Interface",
		DeviceVersion:   "1.0",
		SignaturePrefix: "KUBECHAT",
	}
}

// NewCEFExporter creates a new CEF format exporter
func NewCEFExporter(config CEFExporterConfig) *CEFExporter {
	if config.DeviceVendor == "" {
		config = DefaultCEFConfig()
	}
	
	return &CEFExporter{
		deviceVendor:    config.DeviceVendor,
		deviceProduct:   config.DeviceProduct,
		deviceVersion:   config.DeviceVersion,
		signaturePrefix: config.SignaturePrefix,
	}
}

// Export converts an audit event to CEF format for SIEM ingestion
func (c *CEFExporter) Export(event *models.AuditEvent) ([]byte, error) {
	if event == nil {
		return nil, fmt.Errorf("audit event cannot be nil")
	}

	cefEvent := c.createCEFEvent(event)
	return []byte(cefEvent), nil
}

// ExportBatch converts multiple audit events to CEF format (one per line)
func (c *CEFExporter) ExportBatch(events []*models.AuditEvent) ([]byte, error) {
	if len(events) == 0 {
		return []byte(""), nil
	}

	var lines []string
	for _, event := range events {
		cefEvent := c.createCEFEvent(event)
		lines = append(lines, cefEvent)
	}

	return []byte(strings.Join(lines, "\n")), nil
}

// createCEFEvent creates a CEF-formatted event string
func (c *CEFExporter) createCEFEvent(event *models.AuditEvent) string {
	// CEF Header format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity
	header := fmt.Sprintf("CEF:0|%s|%s|%s|%s|%s|%d",
		c.escapeField(c.deviceVendor),
		c.escapeField(c.deviceProduct),
		c.escapeField(c.deviceVersion),
		c.escapeField(c.createSignatureID(event)),
		c.escapeField(event.Message),
		c.mapSeverityToCEF(event.Severity),
	)

	// CEF Extensions - key=value pairs separated by space
	extensions := c.createCEFExtensions(event)
	
	return fmt.Sprintf("%s %s", header, extensions)
}

// createSignatureID creates a unique signature ID for the event type
func (c *CEFExporter) createSignatureID(event *models.AuditEvent) string {
	return fmt.Sprintf("%s:%s", c.signaturePrefix, strings.ToUpper(string(event.EventType)))
}

// mapSeverityToCEF maps audit severity to CEF severity levels (0-10)
func (c *CEFExporter) mapSeverityToCEF(severity models.AuditSeverity) int {
	switch severity {
	case models.AuditSeverityInfo:
		return 3
	case models.AuditSeverityWarning:
		return 6
	case models.AuditSeverityError:
		return 8
	case models.AuditSeverityCritical:
		return 10
	default:
		return 3
	}
}

// createCEFExtensions creates the CEF extension fields
func (c *CEFExporter) createCEFExtensions(event *models.AuditEvent) string {
	var extensions []string

	// Standard CEF fields
	extensions = append(extensions, fmt.Sprintf("rt=%d", event.Timestamp.Unix()*1000)) // Receipt time in milliseconds
	extensions = append(extensions, fmt.Sprintf("deviceExternalId=%s", c.escapeValue(event.ID)))
	
	// User context extensions
	if event.UserContext.UserID != "" {
		extensions = append(extensions, fmt.Sprintf("suser=%s", c.escapeValue(event.UserContext.UserID)))
	}
	if event.UserContext.Email != "" {
		extensions = append(extensions, fmt.Sprintf("cs1=%s", c.escapeValue(event.UserContext.Email)))
		extensions = append(extensions, "cs1Label=UserEmail")
	}
	if event.UserContext.SessionID != "" {
		extensions = append(extensions, fmt.Sprintf("cs2=%s", c.escapeValue(event.UserContext.SessionID)))
		extensions = append(extensions, "cs2Label=SessionID")
	}
	if event.UserContext.IPAddress != "" {
		extensions = append(extensions, fmt.Sprintf("src=%s", c.escapeValue(event.UserContext.IPAddress)))
	}
	if len(event.UserContext.Groups) > 0 {
		extensions = append(extensions, fmt.Sprintf("cs3=%s", c.escapeValue(strings.Join(event.UserContext.Groups, ","))))
		extensions = append(extensions, "cs3Label=UserGroups")
	}

	// Kubernetes context extensions
	if event.ClusterContext.ClusterName != "" {
		extensions = append(extensions, fmt.Sprintf("cs4=%s", c.escapeValue(event.ClusterContext.ClusterName)))
		extensions = append(extensions, "cs4Label=ClusterName")
	}
	if event.ClusterContext.Namespace != "" {
		extensions = append(extensions, fmt.Sprintf("cs5=%s", c.escapeValue(event.ClusterContext.Namespace)))
		extensions = append(extensions, "cs5Label=Namespace")
	}
	if event.ClusterContext.ResourceType != "" {
		extensions = append(extensions, fmt.Sprintf("cs6=%s", c.escapeValue(event.ClusterContext.ResourceType)))
		extensions = append(extensions, "cs6Label=ResourceType")
	}

	// Command context extensions
	if event.CommandContext.GeneratedCommand != "" {
		extensions = append(extensions, fmt.Sprintf("act=%s", c.escapeValue(event.CommandContext.GeneratedCommand)))
	}
	if event.CommandContext.RiskLevel != "" {
		extensions = append(extensions, fmt.Sprintf("cn1=%s", c.mapRiskLevelToNumber(event.CommandContext.RiskLevel)))
		extensions = append(extensions, "cn1Label=RiskLevel")
	}
	if event.CommandContext.ExecutionStatus != "" {
		extensions = append(extensions, fmt.Sprintf("outcome=%s", c.mapExecutionStatus(event.CommandContext.ExecutionStatus)))
	}
	if event.CommandContext.ExecutionDuration > 0 {
		extensions = append(extensions, fmt.Sprintf("cn2=%d", event.CommandContext.ExecutionDuration))
		extensions = append(extensions, "cn2Label=ExecutionDurationMs")
	}

	// Natural language input (critical for security analysis)
	if event.CommandContext.NaturalLanguageInput != "" {
		extensions = append(extensions, fmt.Sprintf("msg=%s", c.escapeValue(event.CommandContext.NaturalLanguageInput)))
	}

	// Service context
	if event.ServiceName != "" {
		extensions = append(extensions, fmt.Sprintf("dvchost=%s", c.escapeValue(event.ServiceName)))
	}

	// Correlation and tracing
	if event.CorrelationID != "" {
		extensions = append(extensions, fmt.Sprintf("externalId=%s", c.escapeValue(event.CorrelationID)))
	}
	if event.TraceID != "" {
		extensions = append(extensions, fmt.Sprintf("requestContext=%s", c.escapeValue(event.TraceID)))
	}

	// Integrity verification
	if event.Checksum != "" {
		extensions = append(extensions, fmt.Sprintf("fileHash=%s", c.escapeValue(event.Checksum)))
	}

	return strings.Join(extensions, " ")
}

// mapRiskLevelToNumber converts risk level to numeric value for CEF
func (c *CEFExporter) mapRiskLevelToNumber(riskLevel string) string {
	switch strings.ToLower(riskLevel) {
	case "safe":
		return "1"
	case "caution":
		return "5"
	case "destructive":
		return "10"
	default:
		return "1"
	}
}

// mapExecutionStatus maps execution status to CEF outcome values
func (c *CEFExporter) mapExecutionStatus(status string) string {
	switch strings.ToLower(status) {
	case "success", "completed":
		return "success"
	case "failed", "error":
		return "failure"
	case "pending", "executing":
		return "unknown"
	default:
		return "unknown"
	}
}

// escapeField escapes special characters in CEF header fields
func (c *CEFExporter) escapeField(field string) string {
	// Escape pipe characters in header fields
	return strings.ReplaceAll(field, "|", "\\|")
}

// escapeValue escapes special characters in CEF extension values
func (c *CEFExporter) escapeValue(value string) string {
	// Escape equals and backslashes in extension values
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "=", "\\=")
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	return value
}

// GetFormatName returns the format name for identification
func (c *CEFExporter) GetFormatName() string {
	return "CEF"
}

// GetContentType returns the appropriate content type for HTTP responses
func (c *CEFExporter) GetContentType() string {
	return "text/plain"
}

// ValidateEvent validates that the audit event can be properly exported to CEF
func (c *CEFExporter) ValidateEvent(event *models.AuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event cannot be nil")
	}
	if event.ID == "" {
		return fmt.Errorf("audit event ID is required for CEF export")
	}
	if event.EventType == "" {
		return fmt.Errorf("audit event type is required for CEF signature")
	}
	if event.Message == "" {
		return fmt.Errorf("audit event message is required for CEF name field")
	}
	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required for CEF receipt time")
	}
	return nil
}

// GetSampleOutput returns a sample CEF output for testing and documentation
func (c *CEFExporter) GetSampleOutput() string {
	return `CEF:0|KubeChat|Kubernetes Chat Interface|1.0|KUBECHAT:COMMAND_EXECUTE|User executed kubectl command successfully|3 rt=1725446200000 deviceExternalId=audit_1725446200_123456789 suser=user123 cs1=user@company.com cs1Label=UserEmail cs2=session_abc123 cs2Label=SessionID src=192.168.1.100 cs4=production-cluster cs4Label=ClusterName cs5=default cs5Label=Namespace act=kubectl get pods cn1=1 cn1Label=RiskLevel outcome=success msg=show me all pods dvchost=audit-service`
}