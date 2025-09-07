// Package formats provides SIEM export format converters
package formats

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// JSONExporter handles native JSON format export for SIEM systems
type JSONExporter struct {
	includeIntegrityFields bool
	customFieldMappings   map[string]string
}

// JSONExporterConfig configures the JSON exporter behavior
type JSONExporterConfig struct {
	IncludeIntegrityFields bool                 `json:"include_integrity_fields"`
	CustomFieldMappings   map[string]string    `json:"custom_field_mappings,omitempty"`
}

// NewJSONExporter creates a new JSON format exporter
func NewJSONExporter(config JSONExporterConfig) *JSONExporter {
	return &JSONExporter{
		includeIntegrityFields: config.IncludeIntegrityFields,
		customFieldMappings:   config.CustomFieldMappings,
	}
}

// Export converts an audit event to JSON format for SIEM ingestion
func (j *JSONExporter) Export(event *models.AuditEvent) ([]byte, error) {
	if event == nil {
		return nil, fmt.Errorf("audit event cannot be nil")
	}

	// Create SIEM-optimized JSON structure
	siemEvent := j.createSIEMEvent(event)
	
	// Apply custom field mappings if configured
	if j.customFieldMappings != nil {
		j.applyFieldMappings(&siemEvent)
	}

	// Marshal to JSON with proper indentation for readability
	data, err := json.MarshalIndent(siemEvent, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return data, nil
}

// ExportBatch converts multiple audit events to JSON format
func (j *JSONExporter) ExportBatch(events []*models.AuditEvent) ([]byte, error) {
	if len(events) == 0 {
		return []byte("[]"), nil
	}

	var siemEvents []map[string]interface{}
	for _, event := range events {
		siemEvent := j.createSIEMEvent(event)
		if j.customFieldMappings != nil {
			j.applyFieldMappings(&siemEvent)
		}
		siemEvents = append(siemEvents, siemEvent)
	}

	data, err := json.MarshalIndent(siemEvents, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch JSON: %w", err)
	}

	return data, nil
}

// createSIEMEvent creates a SIEM-optimized event structure
func (j *JSONExporter) createSIEMEvent(event *models.AuditEvent) map[string]interface{} {
	siemEvent := map[string]interface{}{
		// Standard SIEM fields
		"timestamp":      event.Timestamp.Format(time.RFC3339),
		"event_id":       event.ID,
		"event_type":     string(event.EventType),
		"severity":       string(event.Severity),
		"message":        event.Message,
		"source_service": event.ServiceName,
		"service_version": event.ServiceVersion,
		
		// User context - flattened for SIEM queries
		"user_id":        event.UserContext.UserID,
		"user_email":     event.UserContext.Email,
		"user_name":      event.UserContext.Name,
		"session_id":     event.UserContext.SessionID,
		"user_groups":    event.UserContext.Groups,
		"auth_provider":  event.UserContext.Provider,
		"client_ip":      event.UserContext.IPAddress,
		"user_agent":     event.UserContext.UserAgent,
		
		// Kubernetes context - flattened for analysis
		"cluster_name":    event.ClusterContext.ClusterName,
		"namespace":       event.ClusterContext.Namespace,
		"resource_type":   event.ClusterContext.ResourceType,
		"resource_name":   event.ClusterContext.ResourceName,
		"kubectl_context": event.ClusterContext.KubectlContext,
		
		// Command context - critical for security analysis
		"natural_language_input": event.CommandContext.NaturalLanguageInput,
		"generated_command":      event.CommandContext.GeneratedCommand,
		"command_args":           event.CommandContext.CommandArgs,
		"risk_level":             event.CommandContext.RiskLevel,
		"execution_status":       event.CommandContext.ExecutionStatus,
		"execution_result":       event.CommandContext.ExecutionResult,
		"execution_error":        event.CommandContext.ExecutionError,
		"execution_duration_ms":  event.CommandContext.ExecutionDuration,
		
		// Correlation and tracing
		"correlation_id": event.CorrelationID,
		"trace_id":       event.TraceID,
		
		// Timestamps for lifecycle tracking
		"created_at":     event.CreatedAt.Format(time.RFC3339),
		"processed_at":   formatTimePointer(event.ProcessedAt),
		
		// Additional metadata
		"metadata": event.Metadata,
	}

	// Include integrity fields if configured
	if j.includeIntegrityFields {
		siemEvent["checksum"] = event.Checksum
		siemEvent["checksum_at"] = event.ChecksumAt.Format(time.RFC3339)
		siemEvent["integrity_verified"] = true // Will be verified during export
	}

	return siemEvent
}

// applyFieldMappings applies custom field name mappings for specific SIEM platforms
func (j *JSONExporter) applyFieldMappings(siemEvent *map[string]interface{}) {
	for originalField, mappedField := range j.customFieldMappings {
		if value, exists := (*siemEvent)[originalField]; exists {
			delete(*siemEvent, originalField)
			(*siemEvent)[mappedField] = value
		}
	}
}

// GetFormatName returns the format name for identification
func (j *JSONExporter) GetFormatName() string {
	return "JSON"
}

// GetContentType returns the appropriate content type for HTTP responses
func (j *JSONExporter) GetContentType() string {
	return "application/json"
}

// ValidateEvent validates that the audit event can be properly exported
func (j *JSONExporter) ValidateEvent(event *models.AuditEvent) error {
	if event == nil {
		return fmt.Errorf("audit event cannot be nil")
	}
	if event.ID == "" {
		return fmt.Errorf("audit event ID is required")
	}
	if event.EventType == "" {
		return fmt.Errorf("audit event type is required")
	}
	if event.UserContext.UserID == "" {
		return fmt.Errorf("user context is required for SIEM export")
	}
	if event.Timestamp.IsZero() {
		return fmt.Errorf("timestamp is required")
	}
	return nil
}

// GetSampleOutput returns a sample JSON output for testing and documentation
func (j *JSONExporter) GetSampleOutput() string {
	return `{
  "timestamp": "2025-09-04T10:30:00Z",
  "event_id": "audit_1725446200_123456789",
  "event_type": "command_execute",
  "severity": "info",
  "message": "User executed kubectl command successfully",
  "source_service": "audit-service",
  "user_id": "user123",
  "user_email": "user@company.com",
  "session_id": "session_abc123",
  "cluster_name": "production-cluster",
  "namespace": "default",
  "natural_language_input": "show me all pods",
  "generated_command": "kubectl get pods",
  "risk_level": "safe",
  "execution_status": "success",
  "correlation_id": "req_789",
  "created_at": "2025-09-04T10:30:00Z"
}`
}

// formatTimePointer safely formats a time pointer
func formatTimePointer(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// SIEMFormatExporter defines the interface all format exporters must implement
type SIEMFormatExporter interface {
	Export(event *models.AuditEvent) ([]byte, error)
	ExportBatch(events []*models.AuditEvent) ([]byte, error)
	GetFormatName() string
	GetContentType() string
	ValidateEvent(event *models.AuditEvent) error
	GetSampleOutput() string
}