// Package models provides data models for the KubeChat application
package models

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// AuditEventType represents the type of audit event
type AuditEventType string

const (
	// Authentication related events
	AuditEventTypeAuthentication AuditEventType = "authentication"
	AuditEventTypeLogin         AuditEventType = "login"
	AuditEventTypeLogout        AuditEventType = "logout"
	AuditEventTypeSessionExpiry AuditEventType = "session_expiry"
	
	// Command related events
	AuditEventTypeCommand         AuditEventType = "command"
	AuditEventTypeCommandGenerate AuditEventType = "command_generate"
	AuditEventTypeCommandExecute  AuditEventType = "command_execute"
	AuditEventTypeCommandResult   AuditEventType = "command_result"
	
	// Natural language processing events
	AuditEventTypeNLPInput       AuditEventType = "nlp_input"
	AuditEventTypeNLPTranslation AuditEventType = "nlp_translation"
	
	// RBAC and security events
	AuditEventTypeRBACCheck      AuditEventType = "rbac_check"
	AuditEventTypeRBACDenied     AuditEventType = "rbac_denied"
	AuditEventTypePermissionGrant AuditEventType = "permission_grant"
	
	// System events
	AuditEventTypeSystemError    AuditEventType = "system_error"
	AuditEventTypeHealthCheck    AuditEventType = "health_check"
	AuditEventTypeServiceStart   AuditEventType = "service_start"
	AuditEventTypeServiceStop    AuditEventType = "service_stop"
)

// AuditSeverity represents the severity level of audit events
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

// ClusterContext holds Kubernetes cluster context information
type ClusterContext struct {
	ClusterName   string `json:"cluster_name,omitempty"`   // Kubernetes cluster name
	Namespace     string `json:"namespace,omitempty"`      // Target namespace
	ResourceType  string `json:"resource_type,omitempty"`  // Resource type (pod, service, etc.)
	ResourceName  string `json:"resource_name,omitempty"`  // Specific resource name
	KubectlContext string `json:"kubectl_context,omitempty"` // kubectl context used
}

// UserContext holds user identity and session information
type UserContext struct {
	UserID           string   `json:"user_id"`                    // User identifier
	Email            string   `json:"email"`                      // User email
	Name             string   `json:"name"`                       // User display name
	SessionID        string   `json:"session_id"`                 // Session identifier
	Groups           []string `json:"groups,omitempty"`           // User groups
	KubernetesUser   string   `json:"kubernetes_user,omitempty"`  // Kubernetes user for RBAC
	KubernetesGroups []string `json:"kubernetes_groups,omitempty"` // Kubernetes groups for RBAC
	Provider         string   `json:"provider,omitempty"`         // OIDC provider
	IPAddress        string   `json:"ip_address,omitempty"`       // Client IP address
	UserAgent        string   `json:"user_agent,omitempty"`       // User agent string
}

// CommandContext holds information about executed commands
type CommandContext struct {
	NaturalLanguageInput string `json:"natural_language_input,omitempty"` // Original NL input
	GeneratedCommand     string `json:"generated_command,omitempty"`      // Generated kubectl command
	CommandArgs          []string `json:"command_args,omitempty"`         // Command arguments
	RiskLevel           string `json:"risk_level,omitempty"`             // Command risk assessment
	ExecutionStatus     string `json:"execution_status,omitempty"`       // Execution status
	ExecutionResult     string `json:"execution_result,omitempty"`       // Command output/result
	ExecutionError      string `json:"execution_error,omitempty"`        // Error message if failed
	ExecutionDuration   int64  `json:"execution_duration,omitempty"`     // Execution time in milliseconds
}

// AuditEvent represents a comprehensive audit event with tamper-proof integrity
type AuditEvent struct {
	// Core event fields
	ID        string         `json:"id"`         // Unique event identifier
	Timestamp time.Time      `json:"timestamp"`  // Event timestamp (UTC)
	EventType AuditEventType `json:"event_type"` // Type of audit event
	Severity  AuditSeverity  `json:"severity"`   // Event severity level
	Message   string         `json:"message"`    // Human-readable event description
	
	// Context information
	UserContext    UserContext     `json:"user_context"`              // User identity and session
	ClusterContext ClusterContext  `json:"cluster_context,omitempty"` // Kubernetes context
	CommandContext CommandContext  `json:"command_context,omitempty"` // Command execution context
	
	// Metadata and tracking
	CorrelationID  string            `json:"correlation_id,omitempty"`  // Request correlation ID
	TraceID        string            `json:"trace_id,omitempty"`        // Distributed tracing ID
	ServiceName    string            `json:"service_name,omitempty"`    // Originating service
	ServiceVersion string            `json:"service_version,omitempty"` // Service version
	Metadata       map[string]interface{} `json:"metadata,omitempty"`  // Additional metadata
	
	// Integrity verification
	Checksum       string    `json:"checksum"`        // SHA-256 checksum for integrity
	ChecksumAt     time.Time `json:"checksum_at"`     // When checksum was generated
	PreviousHash   string    `json:"previous_hash,omitempty"` // Hash of previous event for chain linking
	SequenceNumber int64     `json:"sequence_number,omitempty"` // Sequential number for hash chain
	
	// Lifecycle tracking
	CreatedAt      time.Time `json:"created_at"`      // Event creation timestamp
	ProcessedAt    time.Time `json:"processed_at,omitempty"` // When event was processed
}

// AuditEventBuilder provides a fluent builder pattern for creating audit events
type AuditEventBuilder struct {
	event *AuditEvent
}

// NewAuditEventBuilder creates a new audit event builder
func NewAuditEventBuilder() *AuditEventBuilder {
	now := time.Now().UTC()
	return &AuditEventBuilder{
		event: &AuditEvent{
			ID:        generateEventID(),
			Timestamp: now,
			Severity:  AuditSeverityInfo,
			CreatedAt: now,
			Metadata:  make(map[string]interface{}),
		},
	}
}

// WithEventType sets the event type
func (b *AuditEventBuilder) WithEventType(eventType AuditEventType) *AuditEventBuilder {
	b.event.EventType = eventType
	return b
}

// WithSeverity sets the event severity
func (b *AuditEventBuilder) WithSeverity(severity AuditSeverity) *AuditEventBuilder {
	b.event.Severity = severity
	return b
}

// WithMessage sets the event message
func (b *AuditEventBuilder) WithMessage(message string) *AuditEventBuilder {
	b.event.Message = message
	return b
}

// WithUserContext sets the user context from SessionAuthContext
func (b *AuditEventBuilder) WithUserContext(sessionCtx *SessionAuthContext) *AuditEventBuilder {
	if sessionCtx != nil {
		b.event.UserContext = UserContext{
			UserID:    sessionCtx.UserID,
			SessionID: sessionCtx.SessionID,
			IPAddress: sessionCtx.IPAddress,
			UserAgent: sessionCtx.UserAgent,
		}
	}
	return b
}

// WithUserContextFromUser sets the user context from User model
func (b *AuditEventBuilder) WithUserContextFromUser(user *User, sessionID, ipAddress, userAgent string) *AuditEventBuilder {
	if user != nil {
		b.event.UserContext = UserContext{
			UserID:    user.ID,
			Email:     user.Email,
			Name:      user.Name,
			SessionID: sessionID,
			Groups:    user.GetKubernetesGroups(),
			Provider:  user.OIDCAttributes.Provider,
			IPAddress: ipAddress,
			UserAgent: userAgent,
		}
	}
	return b
}

// WithClusterContext sets the cluster context
func (b *AuditEventBuilder) WithClusterContext(clusterName, namespace, resourceType, resourceName, kubectlContext string) *AuditEventBuilder {
	b.event.ClusterContext = ClusterContext{
		ClusterName:   clusterName,
		Namespace:     namespace,
		ResourceType:  resourceType,
		ResourceName:  resourceName,
		KubectlContext: kubectlContext,
	}
	return b
}

// WithCommandContext sets the command context
func (b *AuditEventBuilder) WithCommandContext(nlInput, generatedCmd, riskLevel, status, result, error string, duration int64) *AuditEventBuilder {
	b.event.CommandContext = CommandContext{
		NaturalLanguageInput: nlInput,
		GeneratedCommand:     generatedCmd,
		RiskLevel:           riskLevel,
		ExecutionStatus:     status,
		ExecutionResult:     result,
		ExecutionError:      error,
		ExecutionDuration:   duration,
	}
	return b
}

// WithCorrelationID sets the correlation ID
func (b *AuditEventBuilder) WithCorrelationID(correlationID string) *AuditEventBuilder {
	b.event.CorrelationID = correlationID
	return b
}

// WithTraceID sets the trace ID for distributed tracing
func (b *AuditEventBuilder) WithTraceID(traceID string) *AuditEventBuilder {
	b.event.TraceID = traceID
	return b
}

// WithService sets the service name and version
func (b *AuditEventBuilder) WithService(name, version string) *AuditEventBuilder {
	b.event.ServiceName = name
	b.event.ServiceVersion = version
	return b
}

// WithMetadata adds metadata key-value pairs
func (b *AuditEventBuilder) WithMetadata(key string, value interface{}) *AuditEventBuilder {
	if b.event.Metadata == nil {
		b.event.Metadata = make(map[string]interface{})
	}
	b.event.Metadata[key] = value
	return b
}

// Build creates the final audit event with integrity checksum
func (b *AuditEventBuilder) Build() (*AuditEvent, error) {
	// Validate required fields
	if b.event.EventType == "" {
		return nil, fmt.Errorf("event type is required")
	}
	if b.event.Message == "" {
		return nil, fmt.Errorf("message is required")
	}
	if b.event.UserContext.UserID == "" {
		return nil, fmt.Errorf("user context is required")
	}
	
	// Generate integrity checksum (use hash chain if available)
	var checksum string
	var err error
	if b.event.PreviousHash != "" {
		checksum, err = b.generateHashChainChecksum()
	} else {
		checksum, err = b.generateChecksum()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to generate checksum: %w", err)
	}
	
	b.event.Checksum = checksum
	b.event.ChecksumAt = time.Now().UTC()
	
	return b.event, nil
}

// generateChecksum creates SHA-256 checksum for tamper-proof integrity verification
func (b *AuditEventBuilder) generateChecksum() (string, error) {
	// Create a copy of the event without checksum fields for consistent hashing
	eventCopy := *b.event
	eventCopy.Checksum = ""
	eventCopy.ChecksumAt = time.Time{}
	eventCopy.ProcessedAt = time.Time{}
	
	// Serialize to JSON for consistent representation
	data, err := json.Marshal(eventCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for checksum: %w", err)
	}
	
	// Generate SHA-256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// WithHashChain sets the hash chain linking parameters
func (b *AuditEventBuilder) WithHashChain(previousHash string, sequenceNumber int64) *AuditEventBuilder {
	b.event.PreviousHash = previousHash
	b.event.SequenceNumber = sequenceNumber
	return b
}

// generateHashChainChecksum creates SHA-256 checksum including hash chain data
func (b *AuditEventBuilder) generateHashChainChecksum() (string, error) {
	// Create a copy of the event without checksum fields for consistent hashing
	eventCopy := *b.event
	eventCopy.Checksum = ""
	eventCopy.ChecksumAt = time.Time{}
	eventCopy.ProcessedAt = time.Time{}
	
	// Include hash chain data in checksum calculation
	chainData := struct {
		Event          interface{} `json:"event"`
		PreviousHash   string      `json:"previous_hash"`
		SequenceNumber int64       `json:"sequence_number"`
	}{
		Event:          eventCopy,
		PreviousHash:   b.event.PreviousHash,
		SequenceNumber: b.event.SequenceNumber,
	}
	
	// Serialize to JSON for consistent representation
	data, err := json.Marshal(chainData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for hash chain checksum: %w", err)
	}
	
	// Generate SHA-256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// VerifyIntegrity verifies the integrity of an audit event using its checksum
func (event *AuditEvent) VerifyIntegrity() (bool, error) {
	// Store original checksum for comparison
	originalChecksum := event.Checksum
	
	var computedChecksum string
	var err error
	
	// Choose verification method based on hash chain presence
	if event.PreviousHash != "" {
		computedChecksum, err = event.computeHashChainChecksum()
	} else {
		computedChecksum, err = event.computeSimpleChecksum()
	}
	
	if err != nil {
		return false, fmt.Errorf("failed to compute checksum for verification: %w", err)
	}
	
	// Compare checksums
	return computedChecksum == originalChecksum, nil
}

// computeSimpleChecksum computes SHA-256 checksum for events without hash chain
func (event *AuditEvent) computeSimpleChecksum() (string, error) {
	// Create a copy without checksum fields for consistent hashing
	eventCopy := *event
	eventCopy.Checksum = ""
	eventCopy.ChecksumAt = time.Time{}
	eventCopy.ProcessedAt = time.Time{}
	
	// Generate checksum for comparison
	data, err := json.Marshal(eventCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for verification: %w", err)
	}
	
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// computeHashChainChecksum computes SHA-256 checksum for events with hash chain
func (event *AuditEvent) computeHashChainChecksum() (string, error) {
	// Create a copy without checksum fields for consistent hashing
	eventCopy := *event
	eventCopy.Checksum = ""
	eventCopy.ChecksumAt = time.Time{}
	eventCopy.ProcessedAt = time.Time{}
	
	// Include hash chain data in checksum calculation
	chainData := struct {
		Event          interface{} `json:"event"`
		PreviousHash   string      `json:"previous_hash"`
		SequenceNumber int64       `json:"sequence_number"`
	}{
		Event:          eventCopy,
		PreviousHash:   event.PreviousHash,
		SequenceNumber: event.SequenceNumber,
	}
	
	// Serialize to JSON for consistent representation
	data, err := json.Marshal(chainData)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event for hash chain verification: %w", err)
	}
	
	// Generate SHA-256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// VerifyHashChain verifies the hash chain linking between events
func (event *AuditEvent) VerifyHashChain(previousEvent *AuditEvent) (bool, error) {
	if event.PreviousHash == "" {
		// First event in chain, no previous hash to verify
		return true, nil
	}
	
	if previousEvent == nil {
		return false, fmt.Errorf("previous event required for hash chain verification")
	}
	
	// First verify the integrity of the previous event
	previousValid, err := previousEvent.VerifyIntegrity()
	if err != nil {
		return false, fmt.Errorf("failed to verify previous event integrity: %w", err)
	}
	if !previousValid {
		return false, nil // Previous event has been tampered with
	}
	
	// Verify the previous hash matches
	if event.PreviousHash != previousEvent.Checksum {
		return false, nil
	}
	
	// Verify sequence number is incremental
	if event.SequenceNumber != previousEvent.SequenceNumber + 1 {
		return false, nil
	}
	
	return true, nil
}

// ToJSON serializes the audit event to JSON
func (event *AuditEvent) ToJSON() ([]byte, error) {
	return json.Marshal(event)
}

// FromJSON deserializes an audit event from JSON
func (event *AuditEvent) FromJSON(data []byte) error {
	return json.Unmarshal(data, event)
}

// generateEventID creates a unique event identifier
func generateEventID() string {
	now := time.Now().UTC()
	return fmt.Sprintf("audit_%d_%d", now.Unix(), now.Nanosecond())
}

// AuditEventService interface defines operations for audit event management
type AuditEventService interface {
	// LogEvent logs a new audit event
	LogEvent(event *AuditEvent) error
	
	// GetEvent retrieves an audit event by ID
	GetEvent(eventID string) (*AuditEvent, error)
	
	// QueryEvents searches for audit events with filtering
	QueryEvents(filter AuditEventFilter) ([]*AuditEvent, error)
	
	// VerifyEventIntegrity verifies the integrity of an audit event
	VerifyEventIntegrity(eventID string) (bool, error)
	
	// GetEventsByUser retrieves audit events for a specific user
	GetEventsByUser(userID string, limit int) ([]*AuditEvent, error)
	
	// GetEventsByTimeRange retrieves audit events within a time range
	GetEventsByTimeRange(start, end time.Time) ([]*AuditEvent, error)
	
	// CountEventsByType returns count of events by type
	CountEventsByType() (map[AuditEventType]int64, error)
}

// AuditEventFilter provides filtering options for audit event queries
type AuditEventFilter struct {
	UserID         string            `json:"user_id,omitempty"`
	EventTypes     []AuditEventType  `json:"event_types,omitempty"`
	Severities     []AuditSeverity   `json:"severities,omitempty"`
	StartTime      time.Time         `json:"start_time,omitempty"`
	EndTime        time.Time         `json:"end_time,omitempty"`
	ClusterName    string            `json:"cluster_name,omitempty"`
	Namespace      string            `json:"namespace,omitempty"`
	ServiceName    string            `json:"service_name,omitempty"`
	CorrelationID  string            `json:"correlation_id,omitempty"`
	TraceID        string            `json:"trace_id,omitempty"`
	Limit          int               `json:"limit,omitempty"`
	Offset         int               `json:"offset,omitempty"`
	SortBy         string            `json:"sort_by,omitempty"`
	SortOrder      string            `json:"sort_order,omitempty"` // asc, desc
}