package formats

import (
	"fmt"
	"strings"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// LEEFExporter handles Log Event Extended Format export for SIEM systems like IBM QRadar
type LEEFExporter struct {
	deviceVendor    string
	deviceProduct   string
	deviceVersion   string
	eventIdPrefix   string
}

// LEEFExporterConfig configures the LEEF exporter behavior
type LEEFExporterConfig struct {
	DeviceVendor    string `json:"device_vendor"`
	DeviceProduct   string `json:"device_product"`
	DeviceVersion   string `json:"device_version"`
	EventIdPrefix   string `json:"event_id_prefix"`
}

// DefaultLEEFConfig returns default LEEF configuration
func DefaultLEEFConfig() LEEFExporterConfig {
	return LEEFExporterConfig{
		DeviceVendor:  "KubeChat",
		DeviceProduct: "KubernetesAuditService",
		DeviceVersion: "1.0",
		EventIdPrefix: "KUBECHAT",
	}
}

// NewLEEFExporter creates a new LEEF format exporter
func NewLEEFExporter(config LEEFExporterConfig) *LEEFExporter {
	if config.DeviceVendor == "" {
		config = DefaultLEEFConfig()
	}
	
	return &LEEFExporter{
		deviceVendor:  config.DeviceVendor,
		deviceProduct: config.DeviceProduct,
		deviceVersion: config.DeviceVersion,
		eventIdPrefix: config.EventIdPrefix,
	}
}

// Export converts an audit event to LEEF format for SIEM ingestion
func (l *LEEFExporter) Export(event *models.AuditEvent) ([]byte, error) {
	if event == nil {
		return nil, fmt.Errorf("audit event cannot be nil")
	}

	leefEvent := l.createLEEFEvent(event)
	return []byte(leefEvent), nil
}

// ExportBatch converts multiple audit events to LEEF format (one per line)
func (l *LEEFExporter) ExportBatch(events []*models.AuditEvent) ([]byte, error) {
	if len(events) == 0 {
		return []byte(""), nil
	}

	var lines []string
	for _, event := range events {
		leefEvent := l.createLEEFEvent(event)
		lines = append(lines, leefEvent)
	}

	return []byte(strings.Join(lines, "\n")), nil
}

// createLEEFEvent creates a LEEF-formatted event string
func (l *LEEFExporter) createLEEFEvent(event *models.AuditEvent) string {
	// LEEF Header format: LEEF:Version|Vendor|Product|Version|EventID|Delimiter|
	delimiter := "^"  // Using ^ as delimiter to avoid conflicts with data
	header := fmt.Sprintf("LEEF:2.0|%s|%s|%s|%s|%s|",
		l.escapeField(l.deviceVendor),
		l.escapeField(l.deviceProduct),
		l.escapeField(l.deviceVersion),
		l.escapeField(l.createEventID(event)),
		delimiter,
	)

	// LEEF Attributes - key=value pairs separated by delimiter
	attributes := l.createLEEFAttributes(event, delimiter)
	
	return fmt.Sprintf("%s%s", header, attributes)
}

// createEventID creates a LEEF event ID based on the audit event type
func (l *LEEFExporter) createEventID(event *models.AuditEvent) string {
	return fmt.Sprintf("%s_%s", l.eventIdPrefix, strings.ToUpper(string(event.EventType)))
}

// createLEEFAttributes creates the LEEF attribute fields
func (l *LEEFExporter) createLEEFAttributes(event *models.AuditEvent, delimiter string) string {
	var attributes []string

	// Standard LEEF fields
	attributes = append(attributes, fmt.Sprintf("devTime=%s", event.Timestamp.Format("MMM dd yyyy HH:mm:ss")))
	attributes = append(attributes, fmt.Sprintf("devTimeFormat=MMM dd yyyy HH:mm:ss"))
	attributes = append(attributes, fmt.Sprintf("severity=%d", l.mapSeverityToLEEF(event.Severity)))
	attributes = append(attributes, fmt.Sprintf("cat=%s", l.escapeValue(string(event.EventType), delimiter)))
	attributes = append(attributes, fmt.Sprintf("msg=%s", l.escapeValue(event.Message, delimiter)))
	
	// User identity fields
	if event.UserContext.UserID != "" {
		attributes = append(attributes, fmt.Sprintf("usrName=%s", l.escapeValue(event.UserContext.UserID, delimiter)))
	}
	if event.UserContext.Email != "" {
		attributes = append(attributes, fmt.Sprintf("usrEmail=%s", l.escapeValue(event.UserContext.Email, delimiter)))
	}
	if event.UserContext.Name != "" {
		attributes = append(attributes, fmt.Sprintf("usrFullName=%s", l.escapeValue(event.UserContext.Name, delimiter)))
	}
	if event.UserContext.SessionID != "" {
		attributes = append(attributes, fmt.Sprintf("sessionId=%s", l.escapeValue(event.UserContext.SessionID, delimiter)))
	}
	if event.UserContext.IPAddress != "" {
		attributes = append(attributes, fmt.Sprintf("src=%s", l.escapeValue(event.UserContext.IPAddress, delimiter)))
	}
	if event.UserContext.UserAgent != "" {
		attributes = append(attributes, fmt.Sprintf("userAgent=%s", l.escapeValue(event.UserContext.UserAgent, delimiter)))
	}
	if len(event.UserContext.Groups) > 0 {
		attributes = append(attributes, fmt.Sprintf("usrGroups=%s", l.escapeValue(strings.Join(event.UserContext.Groups, ","), delimiter)))
	}
	if event.UserContext.Provider != "" {
		attributes = append(attributes, fmt.Sprintf("authProvider=%s", l.escapeValue(event.UserContext.Provider, delimiter)))
	}

	// Kubernetes context fields
	if event.ClusterContext.ClusterName != "" {
		attributes = append(attributes, fmt.Sprintf("clusterName=%s", l.escapeValue(event.ClusterContext.ClusterName, delimiter)))
	}
	if event.ClusterContext.Namespace != "" {
		attributes = append(attributes, fmt.Sprintf("k8sNamespace=%s", l.escapeValue(event.ClusterContext.Namespace, delimiter)))
	}
	if event.ClusterContext.ResourceType != "" {
		attributes = append(attributes, fmt.Sprintf("resourceType=%s", l.escapeValue(event.ClusterContext.ResourceType, delimiter)))
	}
	if event.ClusterContext.ResourceName != "" {
		attributes = append(attributes, fmt.Sprintf("resourceName=%s", l.escapeValue(event.ClusterContext.ResourceName, delimiter)))
	}
	if event.ClusterContext.KubectlContext != "" {
		attributes = append(attributes, fmt.Sprintf("kubectlContext=%s", l.escapeValue(event.ClusterContext.KubectlContext, delimiter)))
	}

	// Command context fields (critical for security analysis)
	if event.CommandContext.NaturalLanguageInput != "" {
		attributes = append(attributes, fmt.Sprintf("nlInput=%s", l.escapeValue(event.CommandContext.NaturalLanguageInput, delimiter)))
	}
	if event.CommandContext.GeneratedCommand != "" {
		attributes = append(attributes, fmt.Sprintf("cmd=%s", l.escapeValue(event.CommandContext.GeneratedCommand, delimiter)))
	}
	if len(event.CommandContext.CommandArgs) > 0 {
		attributes = append(attributes, fmt.Sprintf("cmdArgs=%s", l.escapeValue(strings.Join(event.CommandContext.CommandArgs, " "), delimiter)))
	}
	if event.CommandContext.RiskLevel != "" {
		attributes = append(attributes, fmt.Sprintf("riskLevel=%s", l.escapeValue(event.CommandContext.RiskLevel, delimiter)))
		attributes = append(attributes, fmt.Sprintf("riskScore=%s", l.mapRiskLevelToScore(event.CommandContext.RiskLevel)))
	}
	if event.CommandContext.ExecutionStatus != "" {
		attributes = append(attributes, fmt.Sprintf("executionStatus=%s", l.escapeValue(event.CommandContext.ExecutionStatus, delimiter)))
	}
	if event.CommandContext.ExecutionResult != "" && len(event.CommandContext.ExecutionResult) < 1000 {
		// Truncate long results for LEEF compatibility
		attributes = append(attributes, fmt.Sprintf("executionResult=%s", l.escapeValue(l.truncateString(event.CommandContext.ExecutionResult, 500), delimiter)))
	}
	if event.CommandContext.ExecutionError != "" {
		attributes = append(attributes, fmt.Sprintf("executionError=%s", l.escapeValue(event.CommandContext.ExecutionError, delimiter)))
	}
	if event.CommandContext.ExecutionDuration > 0 {
		attributes = append(attributes, fmt.Sprintf("executionDurationMs=%d", event.CommandContext.ExecutionDuration))
	}

	// Service and system context
	if event.ServiceName != "" {
		attributes = append(attributes, fmt.Sprintf("srcServiceName=%s", l.escapeValue(event.ServiceName, delimiter)))
	}
	if event.ServiceVersion != "" {
		attributes = append(attributes, fmt.Sprintf("srcServiceVersion=%s", l.escapeValue(event.ServiceVersion, delimiter)))
	}

	// Correlation and tracing
	if event.CorrelationID != "" {
		attributes = append(attributes, fmt.Sprintf("correlationId=%s", l.escapeValue(event.CorrelationID, delimiter)))
	}
	if event.TraceID != "" {
		attributes = append(attributes, fmt.Sprintf("traceId=%s", l.escapeValue(event.TraceID, delimiter)))
	}

	// Event lifecycle
	attributes = append(attributes, fmt.Sprintf("eventId=%s", l.escapeValue(event.ID, delimiter)))
	if !event.CreatedAt.IsZero() {
		attributes = append(attributes, fmt.Sprintf("createdAt=%s", event.CreatedAt.Format(time.RFC3339)))
	}
	if !event.ProcessedAt.IsZero() {
		attributes = append(attributes, fmt.Sprintf("processedAt=%s", event.ProcessedAt.Format(time.RFC3339)))
	}

	// Integrity verification
	if event.Checksum != "" {
		attributes = append(attributes, fmt.Sprintf("checksum=%s", l.escapeValue(event.Checksum, delimiter)))
		attributes = append(attributes, fmt.Sprintf("checksumAlgorithm=SHA256"))
		if !event.ChecksumAt.IsZero() {
			attributes = append(attributes, fmt.Sprintf("checksumAt=%s", event.ChecksumAt.Format(time.RFC3339)))
		}
	}

	// Additional metadata (limited to avoid LEEF size limits)
	if event.Metadata != nil && len(event.Metadata) > 0 {
		metadataStr := l.serializeMetadata(event.Metadata, delimiter)
		if metadataStr != "" {
			attributes = append(attributes, fmt.Sprintf("metadata=%s", metadataStr))
		}
	}

	return strings.Join(attributes, delimiter)
}

// mapSeverityToLEEF maps audit severity to LEEF severity levels (1-10)
func (l *LEEFExporter) mapSeverityToLEEF(severity models.AuditSeverity) int {
	switch severity {
	case models.AuditSeverityInfo:
		return 2
	case models.AuditSeverityWarning:
		return 5
	case models.AuditSeverityError:
		return 8
	case models.AuditSeverityCritical:
		return 10
	default:
		return 2
	}
}

// mapRiskLevelToScore converts risk level to numeric score for QRadar analysis
func (l *LEEFExporter) mapRiskLevelToScore(riskLevel string) string {
	switch strings.ToLower(riskLevel) {
	case "safe":
		return "10"   // Low risk score
	case "caution":
		return "50"   // Medium risk score
	case "destructive":
		return "100"  // High risk score
	default:
		return "10"
	}
}

// escapeField escapes special characters in LEEF header fields
func (l *LEEFExporter) escapeField(field string) string {
	// Escape pipe characters in header fields
	return strings.ReplaceAll(field, "|", "\\|")
}

// escapeValue escapes special characters in LEEF attribute values
func (l *LEEFExporter) escapeValue(value, delimiter string) string {
	// Escape delimiter characters and control characters
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, delimiter, "\\"+delimiter)
	value = strings.ReplaceAll(value, "\n", "\\n")
	value = strings.ReplaceAll(value, "\r", "\\r")
	value = strings.ReplaceAll(value, "\t", "\\t")
	return value
}

// truncateString safely truncates a string to a maximum length
func (l *LEEFExporter) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// serializeMetadata converts metadata map to a string representation
func (l *LEEFExporter) serializeMetadata(metadata map[string]interface{}, delimiter string) string {
	if len(metadata) == 0 {
		return ""
	}

	var pairs []string
	for key, value := range metadata {
		// Convert value to string and limit size
		valueStr := fmt.Sprintf("%v", value)
		if len(valueStr) > 100 {
			valueStr = valueStr[:100] + "..."
		}
		pair := fmt.Sprintf("%s:%s", key, l.escapeValue(valueStr, delimiter))
		pairs = append(pairs, pair)
		
		// Limit number of metadata fields to prevent LEEF message size issues
		if len(pairs) >= 5 {
			break
		}
	}
	
	return strings.Join(pairs, ",")
}

// GetFormatName returns the format name for identification
func (l *LEEFExporter) GetFormatName() string {
	return "LEEF"
}

// GetContentType returns the appropriate content type for HTTP responses
func (l *LEEFExporter) GetContentType() string {
	return "text/plain"
}

// ValidateEvent validates that the audit event can be properly exported to LEEF
func (l *LEEFExporter) ValidateEvent(event *models.AuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event cannot be nil")
	}
	if event.ID == "" {
		return fmt.Errorf("audit event ID is required for LEEF export")
	}
	if event.EventType == "" {
		return fmt.Errorf("audit event type is required for LEEF event ID")
	}
	if event.Message == "" {
		return fmt.Errorf("audit event message is required for LEEF msg field")
	}
	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required for LEEF devTime field")
	}
	return nil
}

// GetSampleOutput returns a sample LEEF output for testing and documentation
func (l *LEEFExporter) GetSampleOutput() string {
	return `LEEF:2.0|KubeChat|KubernetesAuditService|1.0|KUBECHAT_COMMAND_EXECUTE|^|devTime=Sep 04 2025 10:30:00^devTimeFormat=MMM dd yyyy HH:mm:ss^severity=2^cat=command_execute^msg=User executed kubectl command successfully^usrName=user123^usrEmail=user@company.com^sessionId=session_abc123^src=192.168.1.100^clusterName=production-cluster^k8sNamespace=default^nlInput=show me all pods^cmd=kubectl get pods^riskLevel=safe^riskScore=10^executionStatus=success^srcServiceName=audit-service^correlationId=req_789^eventId=audit_1725446200_123456789`
}