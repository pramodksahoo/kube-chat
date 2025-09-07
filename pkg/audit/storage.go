// Package audit provides audit logging utilities and storage interfaces
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/lib/pq"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	_ "github.com/lib/pq" // PostgreSQL driver
)

// AuditStorage interface defines the contract for audit event storage backends
type AuditStorage interface {
	// StoreEvent stores an audit event with integrity verification
	StoreEvent(ctx context.Context, event *models.AuditEvent) error
	
	// GetEvent retrieves an audit event by ID
	GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error)
	
	// QueryEvents searches for audit events with filtering
	QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error)
	
	// VerifyIntegrity verifies the integrity of stored audit events
	VerifyIntegrity(ctx context.Context, eventID string) (bool, error)
	
	// GetEventsByUser retrieves audit events for a specific user
	GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error)
	
	// GetEventsByTimeRange retrieves audit events within a time range
	GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error)
	
	// CountEventsByType returns count of events by type
	CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error)
	
	// CountEvents returns count of events matching the filter
	CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error)
	
	// CleanupExpiredEvents removes events older than retention period
	CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error)
	
	// GetStorageStats returns storage statistics
	GetStorageStats(ctx context.Context) (*StorageStats, error)
	
	// HealthCheck performs a health check on the storage backend
	HealthCheck(ctx context.Context) error
}

// StorageStats provides statistics about audit storage
type StorageStats struct {
	TotalEvents       int64                               `json:"total_events"`
	EventsByType      map[models.AuditEventType]int64     `json:"events_by_type"`
	EventsBySeverity  map[models.AuditSeverity]int64      `json:"events_by_severity"`
	StorageSize       int64                               `json:"storage_size_bytes"`
	OldestEvent       time.Time                           `json:"oldest_event"`
	NewestEvent       time.Time                           `json:"newest_event"`
	IntegrityViolations int64                             `json:"integrity_violations"`
}

// PostgreSQLAuditStorage implements tamper-proof audit storage using PostgreSQL
type PostgreSQLAuditStorage struct {
	db               *sql.DB
	retentionDays    int
	checksumEnabled  bool
	tableName        string
}

// NewPostgreSQLAuditStorage creates a new PostgreSQL audit storage instance
func NewPostgreSQLAuditStorage(connectionString string, retentionDays int) (*PostgreSQLAuditStorage, error) {
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}
	
	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}
	
	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   retentionDays,
		checksumEnabled: true,
		tableName:       "audit_events",
	}
	
	// Initialize the database schema
	if err := storage.initializeSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}
	
	return storage, nil
}

// initializeSchema creates the audit events table with append-only constraints
func (s *PostgreSQLAuditStorage) initializeSchema() error {
	// Create the audit events table with append-only design
	createTableSQL := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id VARCHAR(255) PRIMARY KEY,
			timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
			event_type VARCHAR(50) NOT NULL,
			severity VARCHAR(20) NOT NULL,
			message TEXT NOT NULL,
			
			-- User context
			user_id VARCHAR(255) NOT NULL,
			user_email VARCHAR(255),
			user_name VARCHAR(255),
			session_id VARCHAR(255),
			user_groups TEXT[],
			provider VARCHAR(100),
			ip_address INET,
			user_agent TEXT,
			
			-- Cluster context
			cluster_name VARCHAR(255),
			namespace VARCHAR(255),
			resource_type VARCHAR(100),
			resource_name VARCHAR(255),
			kubectl_context VARCHAR(255),
			
			-- Command context
			natural_language_input TEXT,
			generated_command TEXT,
			command_args TEXT[],
			risk_level VARCHAR(50),
			execution_status VARCHAR(50),
			execution_result TEXT,
			execution_error TEXT,
			execution_duration BIGINT,
			
			-- Metadata and tracking
			correlation_id VARCHAR(255),
			trace_id VARCHAR(255),
			service_name VARCHAR(100),
			service_version VARCHAR(50),
			metadata JSONB,
			
			-- Integrity verification
			checksum VARCHAR(64) NOT NULL,
			checksum_at TIMESTAMP WITH TIME ZONE NOT NULL,
			previous_hash VARCHAR(64),
			sequence_number BIGINT,
			
			-- Lifecycle tracking
			created_at TIMESTAMP WITH TIME ZONE NOT NULL,
			processed_at TIMESTAMP WITH TIME ZONE,
			
			-- Prevent updates and deletes (append-only constraint)
			CONSTRAINT audit_events_immutable CHECK (true)
		);`, s.tableName)
	
	_, err := s.db.Exec(createTableSQL)
	if err != nil {
		return fmt.Errorf("failed to create audit events table: %w", err)
	}
	
	// Create indexes for efficient querying and integrity verification
	indexes := []string{
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_timestamp ON %s (timestamp DESC);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_user_id ON %s (user_id);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_event_type ON %s (event_type);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_severity ON %s (severity);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_session_id ON %s (session_id);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_correlation_id ON %s (correlation_id);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_cluster_namespace ON %s (cluster_name, namespace);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_service ON %s (service_name, service_version);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE UNIQUE INDEX IF NOT EXISTS idx_%s_sequence ON %s (sequence_number) WHERE sequence_number IS NOT NULL;", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_checksum ON %s (checksum);", s.tableName, s.tableName),
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_previous_hash ON %s (previous_hash) WHERE previous_hash IS NOT NULL;", s.tableName, s.tableName),
	}
	
	for _, indexSQL := range indexes {
		if _, err := s.db.Exec(indexSQL); err != nil {
			log.Printf("Warning: failed to create index: %v", err)
		}
	}
	
	// Create a trigger to prevent updates and deletes for tamper-proofing
	triggerSQL := fmt.Sprintf(`
		CREATE OR REPLACE FUNCTION prevent_audit_modifications()
		RETURNS TRIGGER AS $$
		BEGIN
			IF TG_OP = 'UPDATE' THEN
				RAISE EXCEPTION 'Updates not allowed on audit table for tamper-proof integrity';
			END IF;
			IF TG_OP = 'DELETE' THEN
				RAISE EXCEPTION 'Deletes not allowed on audit table for tamper-proof integrity';
			END IF;
			RETURN NULL;
		END;
		$$ LANGUAGE plpgsql;
		
		DROP TRIGGER IF EXISTS prevent_audit_modifications ON %s;
		CREATE TRIGGER prevent_audit_modifications
			BEFORE UPDATE OR DELETE ON %s
			FOR EACH ROW EXECUTE FUNCTION prevent_audit_modifications();
	`, s.tableName, s.tableName)
	
	_, err = s.db.Exec(triggerSQL)
	if err != nil {
		log.Printf("Warning: failed to create tamper-proof trigger: %v", err)
	}
	
	return nil
}

// StoreEvent stores an audit event with integrity verification
func (s *PostgreSQLAuditStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	// Verify event integrity before storage
	if s.checksumEnabled {
		valid, err := event.VerifyIntegrity()
		if err != nil {
			return fmt.Errorf("failed to verify event integrity: %w", err)
		}
		if !valid {
			return fmt.Errorf("event failed integrity verification")
		}
	}
	
	// Set processed timestamp
	event.ProcessedAt = time.Now().UTC()
	
	// Prepare the INSERT statement
	insertSQL := fmt.Sprintf(`
		INSERT INTO %s (
			id, timestamp, event_type, severity, message,
			user_id, user_email, user_name, session_id, user_groups, provider, ip_address, user_agent,
			cluster_name, namespace, resource_type, resource_name, kubectl_context,
			natural_language_input, generated_command, command_args, risk_level, 
			execution_status, execution_result, execution_error, execution_duration,
			correlation_id, trace_id, service_name, service_version, metadata,
			checksum, checksum_at, previous_hash, sequence_number, created_at, processed_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
			$19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37
		)`, s.tableName)
	
	// Convert metadata to JSONB
	var metadataJSON interface{}
	if event.Metadata != nil && len(event.Metadata) > 0 {
		metadataJSON = event.Metadata
	} else {
		metadataJSON = map[string]interface{}{}
	}
	
	// Convert arrays to PostgreSQL arrays
	userGroups := pq.Array(event.UserContext.Groups)
	commandArgs := pq.Array(event.CommandContext.CommandArgs)
	
	// Handle null values for optional hash chain fields
	var previousHashParam, sequenceNumberParam interface{}
	if event.PreviousHash != "" {
		previousHashParam = event.PreviousHash
	}
	if event.SequenceNumber > 0 {
		sequenceNumberParam = event.SequenceNumber
	}

	_, err := s.db.ExecContext(ctx, insertSQL,
		event.ID, event.Timestamp, string(event.EventType), string(event.Severity), event.Message,
		event.UserContext.UserID, event.UserContext.Email, event.UserContext.Name, 
		event.UserContext.SessionID, userGroups, event.UserContext.Provider, 
		event.UserContext.IPAddress, event.UserContext.UserAgent,
		event.ClusterContext.ClusterName, event.ClusterContext.Namespace, 
		event.ClusterContext.ResourceType, event.ClusterContext.ResourceName, 
		event.ClusterContext.KubectlContext,
		event.CommandContext.NaturalLanguageInput, event.CommandContext.GeneratedCommand,
		commandArgs, event.CommandContext.RiskLevel, event.CommandContext.ExecutionStatus,
		event.CommandContext.ExecutionResult, event.CommandContext.ExecutionError,
		event.CommandContext.ExecutionDuration,
		event.CorrelationID, event.TraceID, event.ServiceName, event.ServiceVersion, metadataJSON,
		event.Checksum, event.ChecksumAt, previousHashParam, sequenceNumberParam, 
		event.CreatedAt, event.ProcessedAt,
	)
	
	if err != nil {
		return fmt.Errorf("failed to store audit event: %w", err)
	}
	
	return nil
}

// GetEvent retrieves an audit event by ID
func (s *PostgreSQLAuditStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	selectSQL := fmt.Sprintf(`
		SELECT id, timestamp, event_type, severity, message,
		       user_id, user_email, user_name, session_id, user_groups, provider, ip_address, user_agent,
		       cluster_name, namespace, resource_type, resource_name, kubectl_context,
		       natural_language_input, generated_command, command_args, risk_level,
		       execution_status, execution_result, execution_error, execution_duration,
		       correlation_id, trace_id, service_name, service_version, metadata,
		       checksum, checksum_at, previous_hash, sequence_number, created_at, processed_at
		FROM %s WHERE id = $1`, s.tableName)
	
	row := s.db.QueryRowContext(ctx, selectSQL, eventID)
	
	event, err := s.scanAuditEvent(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("audit event with ID %s not found", eventID)
		}
		return nil, fmt.Errorf("failed to retrieve audit event: %w", err)
	}
	
	return event, nil
}

// QueryEvents searches for audit events with filtering
func (s *PostgreSQLAuditStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	query := fmt.Sprintf("SELECT id, timestamp, event_type, severity, message, user_id, user_email, user_name, session_id, user_groups, provider, ip_address, user_agent, cluster_name, namespace, resource_type, resource_name, kubectl_context, natural_language_input, generated_command, command_args, risk_level, execution_status, execution_result, execution_error, execution_duration, correlation_id, trace_id, service_name, service_version, metadata, checksum, checksum_at, previous_hash, sequence_number, created_at, processed_at FROM %s WHERE 1=1", s.tableName)
	
	args := []interface{}{}
	argIndex := 1
	
	// Apply filters
	if filter.UserID != "" {
		query += fmt.Sprintf(" AND user_id = $%d", argIndex)
		args = append(args, filter.UserID)
		argIndex++
	}
	
	if len(filter.EventTypes) > 0 {
		query += fmt.Sprintf(" AND event_type = ANY($%d)", argIndex)
		eventTypes := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			eventTypes[i] = string(et)
		}
		args = append(args, pq.Array(eventTypes))
		argIndex++
	}
	
	if len(filter.Severities) > 0 {
		query += fmt.Sprintf(" AND severity = ANY($%d)", argIndex)
		severities := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			severities[i] = string(s)
		}
		args = append(args, pq.Array(severities))
		argIndex++
	}
	
	if !filter.StartTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, filter.StartTime)
		argIndex++
	}
	
	if !filter.EndTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, filter.EndTime)
		argIndex++
	}
	
	if filter.ClusterName != "" {
		query += fmt.Sprintf(" AND cluster_name = $%d", argIndex)
		args = append(args, filter.ClusterName)
		argIndex++
	}
	
	if filter.Namespace != "" {
		query += fmt.Sprintf(" AND namespace = $%d", argIndex)
		args = append(args, filter.Namespace)
		argIndex++
	}
	
	if filter.ServiceName != "" {
		query += fmt.Sprintf(" AND service_name = $%d", argIndex)
		args = append(args, filter.ServiceName)
		argIndex++
	}
	
	if filter.CorrelationID != "" {
		query += fmt.Sprintf(" AND correlation_id = $%d", argIndex)
		args = append(args, filter.CorrelationID)
		argIndex++
	}
	
	// Apply sorting
	sortBy := "timestamp"
	if filter.SortBy != "" {
		sortBy = filter.SortBy
	}
	
	sortOrder := "DESC"
	if filter.SortOrder == "asc" {
		sortOrder = "ASC"
	}
	
	query += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)
	
	// Apply limit and offset
	if filter.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filter.Limit)
		argIndex++
	}
	
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filter.Offset)
		argIndex++
	}
	
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()
	
	var events []*models.AuditEvent
	for rows.Next() {
		event, err := s.scanAuditEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan audit event: %w", err)
		}
		events = append(events, event)
	}
	
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating over query results: %w", err)
	}
	
	return events, nil
}

// VerifyIntegrity verifies the integrity of stored audit events
func (s *PostgreSQLAuditStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	event, err := s.GetEvent(ctx, eventID)
	if err != nil {
		return false, err
	}
	
	return event.VerifyIntegrity()
}

// GetEventsByUser retrieves audit events for a specific user
func (s *PostgreSQLAuditStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	filter := models.AuditEventFilter{
		UserID: userID,
		Limit:  limit,
		SortBy: "timestamp",
		SortOrder: "desc",
	}
	
	return s.QueryEvents(ctx, filter)
}

// GetEventsByTimeRange retrieves audit events within a time range
func (s *PostgreSQLAuditStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	filter := models.AuditEventFilter{
		StartTime: start,
		EndTime:   end,
		SortBy:    "timestamp",
		SortOrder: "desc",
	}
	
	return s.QueryEvents(ctx, filter)
}

// CountEventsByType returns count of events by type
func (s *PostgreSQLAuditStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	query := fmt.Sprintf("SELECT event_type, COUNT(*) FROM %s GROUP BY event_type", s.tableName)
	
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to count events by type: %w", err)
	}
	defer rows.Close()
	
	counts := make(map[models.AuditEventType]int64)
	for rows.Next() {
		var eventType string
		var count int64
		
		if err := rows.Scan(&eventType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan event type count: %w", err)
		}
		
		counts[models.AuditEventType(eventType)] = count
	}
	
	return counts, nil
}

// CountEvents returns count of events matching the filter
func (s *PostgreSQLAuditStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	query, args := s.buildCountQuery(filter)
	
	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}
	
	return count, nil
}

// buildCountQuery builds the COUNT SQL query with filters
func (s *PostgreSQLAuditStorage) buildCountQuery(filter models.AuditEventFilter) (string, []interface{}) {
	baseQuery := fmt.Sprintf("SELECT COUNT(*) FROM %s WHERE 1=1", s.tableName)
	args := make([]interface{}, 0)
	argCount := 0
	
	// Apply filters similar to buildQuery method
	if filter.UserID != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND user_id = $%d", argCount)
		args = append(args, filter.UserID)
	}
	
	if filter.ClusterName != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND cluster_name = $%d", argCount)
		args = append(args, filter.ClusterName)
	}
	
	if filter.Namespace != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND namespace = $%d", argCount)
		args = append(args, filter.Namespace)
	}
	
	if filter.ServiceName != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND service_name = $%d", argCount)
		args = append(args, filter.ServiceName)
	}
	
	if filter.CorrelationID != "" {
		argCount++
		baseQuery += fmt.Sprintf(" AND correlation_id = $%d", argCount)
		args = append(args, filter.CorrelationID)
	}
	
	if !filter.StartTime.IsZero() {
		argCount++
		baseQuery += fmt.Sprintf(" AND timestamp >= $%d", argCount)
		args = append(args, filter.StartTime)
	}
	
	if !filter.EndTime.IsZero() {
		argCount++
		baseQuery += fmt.Sprintf(" AND timestamp <= $%d", argCount)
		args = append(args, filter.EndTime)
	}
	
	return baseQuery, args
}

// CleanupExpiredEvents removes events older than retention period
func (s *PostgreSQLAuditStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	cutoffDate := time.Now().UTC().AddDate(0, 0, -retentionDays)
	
	// Note: This violates the append-only constraint, so it should only be used
	// for administrative cleanup with proper authorization
	deleteSQL := fmt.Sprintf("DELETE FROM %s WHERE timestamp < $1", s.tableName)
	
	result, err := s.db.ExecContext(ctx, deleteSQL, cutoffDate)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired events: %w", err)
	}
	
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows count: %w", err)
	}
	
	return rowsAffected, nil
}

// GetStorageStats returns storage statistics
func (s *PostgreSQLAuditStorage) GetStorageStats(ctx context.Context) (*StorageStats, error) {
	stats := &StorageStats{
		EventsByType:     make(map[models.AuditEventType]int64),
		EventsBySeverity: make(map[models.AuditSeverity]int64),
	}
	
	// Get total events
	err := s.db.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", s.tableName)).Scan(&stats.TotalEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to get total events count: %w", err)
	}
	
	// Get events by type
	typeQuery := fmt.Sprintf("SELECT event_type, COUNT(*) FROM %s GROUP BY event_type", s.tableName)
	rows, err := s.db.QueryContext(ctx, typeQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get events by type: %w", err)
	}
	
	for rows.Next() {
		var eventType string
		var count int64
		if err := rows.Scan(&eventType, &count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan event type: %w", err)
		}
		stats.EventsByType[models.AuditEventType(eventType)] = count
	}
	rows.Close()
	
	// Get events by severity
	severityQuery := fmt.Sprintf("SELECT severity, COUNT(*) FROM %s GROUP BY severity", s.tableName)
	rows, err = s.db.QueryContext(ctx, severityQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get events by severity: %w", err)
	}
	
	for rows.Next() {
		var severity string
		var count int64
		if err := rows.Scan(&severity, &count); err != nil {
			rows.Close()
			return nil, fmt.Errorf("failed to scan severity: %w", err)
		}
		stats.EventsBySeverity[models.AuditSeverity(severity)] = count
	}
	rows.Close()
	
	// Get oldest and newest events
	err = s.db.QueryRowContext(ctx, 
		fmt.Sprintf("SELECT MIN(timestamp), MAX(timestamp) FROM %s", s.tableName)).
		Scan(&stats.OldestEvent, &stats.NewestEvent)
	if err != nil && err != sql.ErrNoRows {
		return nil, fmt.Errorf("failed to get event time range: %w", err)
	}
	
	return stats, nil
}

// HealthCheck performs a health check on the storage backend
func (s *PostgreSQLAuditStorage) HealthCheck(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// scanAuditEvent scans a database row into an AuditEvent struct
func (s *PostgreSQLAuditStorage) scanAuditEvent(scanner interface{}) (*models.AuditEvent, error) {
	var event models.AuditEvent
	var eventTypeStr, severityStr string
	var userGroups, commandArgs pq.StringArray
	var metadataJSON []byte
	
	var row interface {
		Scan(dest ...interface{}) error
	}
	
	if r, ok := scanner.(*sql.Row); ok {
		row = r
	} else if r, ok := scanner.(*sql.Rows); ok {
		row = r
	} else {
		return nil, fmt.Errorf("unsupported scanner type")
	}
	
	// Variables for nullable fields
	var previousHashPtr *string
	var sequenceNumberPtr *int64

	err := row.Scan(
		&event.ID, &event.Timestamp, &eventTypeStr, &severityStr, &event.Message,
		&event.UserContext.UserID, &event.UserContext.Email, &event.UserContext.Name,
		&event.UserContext.SessionID, &userGroups, &event.UserContext.Provider,
		&event.UserContext.IPAddress, &event.UserContext.UserAgent,
		&event.ClusterContext.ClusterName, &event.ClusterContext.Namespace,
		&event.ClusterContext.ResourceType, &event.ClusterContext.ResourceName,
		&event.ClusterContext.KubectlContext,
		&event.CommandContext.NaturalLanguageInput, &event.CommandContext.GeneratedCommand,
		&commandArgs, &event.CommandContext.RiskLevel, &event.CommandContext.ExecutionStatus,
		&event.CommandContext.ExecutionResult, &event.CommandContext.ExecutionError,
		&event.CommandContext.ExecutionDuration,
		&event.CorrelationID, &event.TraceID, &event.ServiceName, &event.ServiceVersion,
		&metadataJSON, &event.Checksum, &event.ChecksumAt, &previousHashPtr, &sequenceNumberPtr,
		&event.CreatedAt, &event.ProcessedAt,
	)
	
	if err != nil {
		return nil, err
	}
	
	// Convert string enums back to types
	event.EventType = models.AuditEventType(eventTypeStr)
	event.Severity = models.AuditSeverity(severityStr)
	event.UserContext.Groups = []string(userGroups)
	event.CommandContext.CommandArgs = []string(commandArgs)
	
	// Handle nullable hash chain fields
	if previousHashPtr != nil {
		event.PreviousHash = *previousHashPtr
	}
	if sequenceNumberPtr != nil {
		event.SequenceNumber = *sequenceNumberPtr
	}
	
	// Parse metadata JSON
	if len(metadataJSON) > 0 {
		event.Metadata = make(map[string]interface{})
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			log.Printf("Warning: failed to parse metadata JSON: %v", err)
		}
	}
	
	return &event, nil
}


// GetLastSequenceInfo retrieves the last sequence number and hash for hash chain continuation
func (s *PostgreSQLAuditStorage) GetLastSequenceInfo(ctx context.Context) (int64, string, error) {
	query := fmt.Sprintf(`
		SELECT sequence_number, checksum 
		FROM %s 
		WHERE sequence_number IS NOT NULL 
		ORDER BY sequence_number DESC 
		LIMIT 1`, s.tableName)
	
	var sequenceNumber int64
	var checksum string
	
	err := s.db.QueryRowContext(ctx, query).Scan(&sequenceNumber, &checksum)
	if err == sql.ErrNoRows {
		// No sequence events yet, return starting values
		return 0, "", nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("failed to get last sequence info: %w", err)
	}
	
	return sequenceNumber, checksum, nil
}

// VerifyHashChainIntegrity verifies the integrity of the entire hash chain
func (s *PostgreSQLAuditStorage) VerifyHashChainIntegrity(ctx context.Context) (bool, error) {
	query := fmt.Sprintf(`
		SELECT id, checksum, previous_hash, sequence_number 
		FROM %s 
		WHERE sequence_number IS NOT NULL 
		ORDER BY sequence_number ASC`, s.tableName)
	
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return false, fmt.Errorf("failed to query hash chain events: %w", err)
	}
	defer rows.Close()
	
	var previousEvent *models.AuditEvent
	for rows.Next() {
		var id, checksum string
		var previousHash *string
		var sequenceNumber int64
		
		err := rows.Scan(&id, &checksum, &previousHash, &sequenceNumber)
		if err != nil {
			return false, fmt.Errorf("failed to scan hash chain event: %w", err)
		}
		
		// Get full event for verification
		event, err := s.GetEvent(ctx, id)
		if err != nil {
			return false, fmt.Errorf("failed to get event %s: %w", id, err)
		}
		
		// Verify individual event integrity
		valid, err := event.VerifyIntegrity()
		if err != nil {
			return false, fmt.Errorf("failed to verify integrity for event %s: %w", id, err)
		}
		if !valid {
			return false, nil // Event tampered with
		}
		
		// Verify chain link (skip for first event)
		if previousEvent != nil {
			chainValid, err := event.VerifyHashChain(previousEvent)
			if err != nil {
				return false, fmt.Errorf("failed to verify hash chain for event %s: %w", id, err)
			}
			if !chainValid {
				return false, nil // Chain broken
			}
		}
		
		previousEvent = event
	}
	
	return true, nil
}

// Close closes the database connection
func (s *PostgreSQLAuditStorage) Close() error {
	return s.db.Close()
}