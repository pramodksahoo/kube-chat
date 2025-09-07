package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewPostgreSQLAuditStorage(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	// Mock successful connection and schema initialization
	mock.ExpectPing()
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS audit_events").WillReturnResult(sqlmock.NewResult(0, 0))
	
	// Mock index creation (multiple indexes including new hash chain indexes)
	for i := 0; i < 11; i++ {
		mock.ExpectExec("CREATE INDEX IF NOT EXISTS").WillReturnResult(sqlmock.NewResult(0, 0))
	}
	
	// Mock trigger creation
	mock.ExpectExec("CREATE OR REPLACE FUNCTION prevent_audit_modifications").WillReturnResult(sqlmock.NewResult(0, 0))

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	err = storage.initializeSchema()
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestStoreEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Create a test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Test audit event").
		WithUserContextFromUser(&models.User{ID: "user123"}, "session456", "192.168.1.1", "test-agent").
		Build()
	require.NoError(t, err)

	// Mock the INSERT statement (with new hash chain fields)
	mock.ExpectExec("INSERT INTO audit_events").
		WithArgs(
			event.ID, event.Timestamp, string(event.EventType), string(event.Severity), event.Message,
			event.UserContext.UserID, event.UserContext.Email, event.UserContext.Name,
			event.UserContext.SessionID, sqlmock.AnyArg(), event.UserContext.Provider,
			event.UserContext.IPAddress, event.UserContext.UserAgent,
			event.ClusterContext.ClusterName, event.ClusterContext.Namespace,
			event.ClusterContext.ResourceType, event.ClusterContext.ResourceName,
			event.ClusterContext.KubectlContext,
			event.CommandContext.NaturalLanguageInput, event.CommandContext.GeneratedCommand,
			sqlmock.AnyArg(), event.CommandContext.RiskLevel, event.CommandContext.ExecutionStatus,
			event.CommandContext.ExecutionResult, event.CommandContext.ExecutionError,
			event.CommandContext.ExecutionDuration,
			event.CorrelationID, event.TraceID, event.ServiceName, event.ServiceVersion,
			sqlmock.AnyArg(), event.Checksum, event.ChecksumAt, 
			nil, nil, // previous_hash, sequence_number (null for non-chain events)
			event.CreatedAt, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storage.StoreEvent(context.Background(), event)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetEvent(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	eventID := "test-event-123"
	now := time.Now().UTC()

	// Mock the SELECT statement (with new hash chain fields)
	rows := sqlmock.NewRows([]string{
		"id", "timestamp", "event_type", "severity", "message",
		"user_id", "user_email", "user_name", "session_id", "user_groups", "provider", "ip_address", "user_agent",
		"cluster_name", "namespace", "resource_type", "resource_name", "kubectl_context",
		"natural_language_input", "generated_command", "command_args", "risk_level",
		"execution_status", "execution_result", "execution_error", "execution_duration",
		"correlation_id", "trace_id", "service_name", "service_version", "metadata",
		"checksum", "checksum_at", "previous_hash", "sequence_number", "created_at", "processed_at",
	}).AddRow(
		eventID, now, "command", "info", "Test message",
		"user123", "test@example.com", "Test User", "session456", pq.StringArray{"admin"}, "test-provider", "192.168.1.1", "test-agent",
		"test-cluster", "default", "pod", "nginx", "test-context",
		"get pods", "kubectl get pods", pq.StringArray{"get", "pods"}, "safe",
		"completed", "3 pods found", "", int64(1500),
		"corr123", "trace456", "api-gateway", "v1.0.0", []byte(`{"key":"value"}`),
		"abc123", now, nil, nil, now, now, // previous_hash and sequence_number are null
	)

	mock.ExpectQuery("SELECT .* FROM audit_events WHERE id = \\$1").
		WithArgs(eventID).
		WillReturnRows(rows)

	event, err := storage.GetEvent(context.Background(), eventID)
	assert.NoError(t, err)
	assert.NotNil(t, event)
	assert.Equal(t, eventID, event.ID)
	assert.Equal(t, models.AuditEventType("command"), event.EventType)
	assert.Equal(t, "user123", event.UserContext.UserID)
	assert.Equal(t, "test-cluster", event.ClusterContext.ClusterName)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestQueryEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Test basic query with user filter
	filter := models.AuditEventFilter{
		UserID: "user123",
		Limit:  10,
	}

	now := time.Now().UTC()
	rows := sqlmock.NewRows([]string{
		"id", "timestamp", "event_type", "severity", "message",
		"user_id", "user_email", "user_name", "session_id", "user_groups", "provider", "ip_address", "user_agent",
		"cluster_name", "namespace", "resource_type", "resource_name", "kubectl_context",
		"natural_language_input", "generated_command", "command_args", "risk_level",
		"execution_status", "execution_result", "execution_error", "execution_duration",
		"correlation_id", "trace_id", "service_name", "service_version", "metadata",
		"checksum", "checksum_at", "previous_hash", "sequence_number", "created_at", "processed_at",
	}).AddRow(
		"event1", now, "login", "info", "User logged in",
		"user123", "test@example.com", "Test User", "session456", pq.StringArray{}, "", "192.168.1.1", "browser",
		"", "", "", "", "",
		"", "", pq.StringArray{}, "",
		"", "", "", int64(0),
		"", "", "", "", []byte(`{}`),
		"hash1", now, nil, nil, now, now, // previous_hash and sequence_number are null
	)

	mock.ExpectQuery("SELECT .* FROM audit_events WHERE 1=1 AND user_id = \\$1 ORDER BY timestamp DESC LIMIT \\$2").
		WithArgs("user123", 10).
		WillReturnRows(rows)

	events, err := storage.QueryEvents(context.Background(), filter)
	assert.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "event1", events[0].ID)
	assert.Equal(t, "user123", events[0].UserContext.UserID)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCountEventsByType(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	rows := sqlmock.NewRows([]string{"event_type", "count"}).
		AddRow("login", 10).
		AddRow("command", 25).
		AddRow("logout", 5)

	mock.ExpectQuery("SELECT event_type, COUNT\\(\\*\\) FROM audit_events GROUP BY event_type").
		WillReturnRows(rows)

	counts, err := storage.CountEventsByType(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, int64(10), counts[models.AuditEventType("login")])
	assert.Equal(t, int64(25), counts[models.AuditEventType("command")])
	assert.Equal(t, int64(5), counts[models.AuditEventType("logout")])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetStorageStats(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	now := time.Now().UTC()

	// Mock total count query
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_events").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(100))

	// Mock events by type query
	mock.ExpectQuery("SELECT event_type, COUNT\\(\\*\\) FROM audit_events GROUP BY event_type").
		WillReturnRows(sqlmock.NewRows([]string{"event_type", "count"}).
			AddRow("login", 40).
			AddRow("command", 60))

	// Mock events by severity query
	mock.ExpectQuery("SELECT severity, COUNT\\(\\*\\) FROM audit_events GROUP BY severity").
		WillReturnRows(sqlmock.NewRows([]string{"severity", "count"}).
			AddRow("info", 80).
			AddRow("warning", 20))

	// Mock time range query
	mock.ExpectQuery("SELECT MIN\\(timestamp\\), MAX\\(timestamp\\) FROM audit_events").
		WillReturnRows(sqlmock.NewRows([]string{"min", "max"}).AddRow(now.Add(-24*time.Hour), now))

	stats, err := storage.GetStorageStats(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, stats)
	assert.Equal(t, int64(100), stats.TotalEvents)
	assert.Equal(t, int64(40), stats.EventsByType[models.AuditEventType("login")])
	assert.Equal(t, int64(80), stats.EventsBySeverity[models.AuditSeverity("info")])
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestHealthCheck(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Mock successful ping
	mock.ExpectPing()

	err = storage.HealthCheck(context.Background())
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestVerifyIntegrity(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Create a test event with valid checksum
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("Test login event").
		WithUserContextFromUser(&models.User{ID: "user123"}, "session456", "", "").
		Build()
	require.NoError(t, err)

	eventID := event.ID
	now := time.Now().UTC()

	// Mock the SELECT statement for the event (with new hash chain fields)
	rows := sqlmock.NewRows([]string{
		"id", "timestamp", "event_type", "severity", "message",
		"user_id", "user_email", "user_name", "session_id", "user_groups", "provider", "ip_address", "user_agent",
		"cluster_name", "namespace", "resource_type", "resource_name", "kubectl_context",
		"natural_language_input", "generated_command", "command_args", "risk_level",
		"execution_status", "execution_result", "execution_error", "execution_duration",
		"correlation_id", "trace_id", "service_name", "service_version", "metadata",
		"checksum", "checksum_at", "previous_hash", "sequence_number", "created_at", "processed_at",
	}).AddRow(
		event.ID, event.Timestamp, string(event.EventType), string(event.Severity), event.Message,
		event.UserContext.UserID, event.UserContext.Email, event.UserContext.Name,
		event.UserContext.SessionID, pq.StringArray{}, event.UserContext.Provider,
		event.UserContext.IPAddress, event.UserContext.UserAgent,
		event.ClusterContext.ClusterName, event.ClusterContext.Namespace,
		event.ClusterContext.ResourceType, event.ClusterContext.ResourceName,
		event.ClusterContext.KubectlContext,
		event.CommandContext.NaturalLanguageInput, event.CommandContext.GeneratedCommand,
		pq.StringArray{}, event.CommandContext.RiskLevel, event.CommandContext.ExecutionStatus,
		event.CommandContext.ExecutionResult, event.CommandContext.ExecutionError,
		event.CommandContext.ExecutionDuration,
		event.CorrelationID, event.TraceID, event.ServiceName, event.ServiceVersion,
		[]byte(`{}`), event.Checksum, event.ChecksumAt, nil, nil, event.CreatedAt, now,
	)

	mock.ExpectQuery("SELECT .* FROM audit_events WHERE id = \\$1").
		WithArgs(eventID).
		WillReturnRows(rows)

	valid, err := storage.VerifyIntegrity(context.Background(), eventID)
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.NoError(t, mock.ExpectationsWereMet())
}


// AnyTime matches any time.Time value for sqlmock
type AnyTime struct{}

func (a AnyTime) Match(v driver.Value) bool {
	_, ok := v.(time.Time)
	return ok
}

func TestCleanupExpiredEvents(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Mock the DELETE statement
	mock.ExpectExec("DELETE FROM audit_events WHERE timestamp < \\$1").
		WithArgs(AnyTime{}).
		WillReturnResult(sqlmock.NewResult(0, 5))

	deletedCount, err := storage.CleanupExpiredEvents(context.Background(), 30)
	assert.NoError(t, err)
	assert.Equal(t, int64(5), deletedCount)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestGetLastSequenceInfo(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	t.Run("with existing sequence events", func(t *testing.T) {
		rows := sqlmock.NewRows([]string{"sequence_number", "checksum"}).
			AddRow(int64(5), "hash_5")

		mock.ExpectQuery("SELECT sequence_number, checksum FROM audit_events WHERE sequence_number IS NOT NULL ORDER BY sequence_number DESC LIMIT 1").
			WillReturnRows(rows)

		seqNum, hash, err := storage.GetLastSequenceInfo(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int64(5), seqNum)
		assert.Equal(t, "hash_5", hash)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("with no sequence events", func(t *testing.T) {
		mock.ExpectQuery("SELECT sequence_number, checksum FROM audit_events WHERE sequence_number IS NOT NULL ORDER BY sequence_number DESC LIMIT 1").
			WillReturnError(sql.ErrNoRows)

		seqNum, hash, err := storage.GetLastSequenceInfo(context.Background())
		assert.NoError(t, err)
		assert.Equal(t, int64(0), seqNum)
		assert.Equal(t, "", hash)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestStoreEventWithHashChain(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Create a test event with hash chain
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Test hash chain event").
		WithUserContextFromUser(&models.User{ID: "user123"}, "session456", "192.168.1.1", "test-agent").
		WithHashChain("previous_hash_123", 2).
		Build()
	require.NoError(t, err)

	// Mock the INSERT statement with hash chain parameters
	mock.ExpectExec("INSERT INTO audit_events").
		WithArgs(
			event.ID, event.Timestamp, string(event.EventType), string(event.Severity), event.Message,
			event.UserContext.UserID, event.UserContext.Email, event.UserContext.Name,
			event.UserContext.SessionID, sqlmock.AnyArg(), event.UserContext.Provider,
			event.UserContext.IPAddress, event.UserContext.UserAgent,
			event.ClusterContext.ClusterName, event.ClusterContext.Namespace,
			event.ClusterContext.ResourceType, event.ClusterContext.ResourceName,
			event.ClusterContext.KubectlContext,
			event.CommandContext.NaturalLanguageInput, event.CommandContext.GeneratedCommand,
			sqlmock.AnyArg(), event.CommandContext.RiskLevel, event.CommandContext.ExecutionStatus,
			event.CommandContext.ExecutionResult, event.CommandContext.ExecutionError,
			event.CommandContext.ExecutionDuration,
			event.CorrelationID, event.TraceID, event.ServiceName, event.ServiceVersion,
			sqlmock.AnyArg(), event.Checksum, event.ChecksumAt, 
			"previous_hash_123", int64(2), // previous_hash, sequence_number
			event.CreatedAt, sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = storage.StoreEvent(context.Background(), event)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestVerifyHashChainIntegrity(t *testing.T) {
	db, mock, err := sqlmock.New()
	require.NoError(t, err)
	defer db.Close()

	storage := &PostgreSQLAuditStorage{
		db:              db,
		retentionDays:   365,
		checksumEnabled: true,
		tableName:       "audit_events",
	}

	// Create test events for hash chain verification
	builder1 := models.NewAuditEventBuilder()
	event1, err := builder1.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("First event").
		WithUserContextFromUser(&models.User{ID: "user123"}, "session123", "192.168.1.1", "test-agent").
		WithHashChain("", 1).
		Build()
	require.NoError(t, err)

	builder2 := models.NewAuditEventBuilder()
	event2, err := builder2.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Second event").
		WithUserContextFromUser(&models.User{ID: "user123"}, "session123", "192.168.1.1", "test-agent").
		WithHashChain(event1.Checksum, 2).
		Build()
	require.NoError(t, err)

	// Mock the hash chain query
	chainRows := sqlmock.NewRows([]string{"id", "checksum", "previous_hash", "sequence_number"}).
		AddRow(event1.ID, event1.Checksum, nil, int64(1)).
		AddRow(event2.ID, event2.Checksum, event1.Checksum, int64(2))

	mock.ExpectQuery("SELECT id, checksum, previous_hash, sequence_number FROM audit_events WHERE sequence_number IS NOT NULL ORDER BY sequence_number ASC").
		WillReturnRows(chainRows)

	// Mock GetEvent calls for each event in chain
	for _, event := range []*models.AuditEvent{event1, event2} {
		rows := sqlmock.NewRows([]string{
			"id", "timestamp", "event_type", "severity", "message",
			"user_id", "user_email", "user_name", "session_id", "user_groups", "provider", "ip_address", "user_agent",
			"cluster_name", "namespace", "resource_type", "resource_name", "kubectl_context",
			"natural_language_input", "generated_command", "command_args", "risk_level",
			"execution_status", "execution_result", "execution_error", "execution_duration",
			"correlation_id", "trace_id", "service_name", "service_version", "metadata",
			"checksum", "checksum_at", "previous_hash", "sequence_number", "created_at", "processed_at",
		}).AddRow(
			event.ID, event.Timestamp, string(event.EventType), string(event.Severity), event.Message,
			event.UserContext.UserID, event.UserContext.Email, event.UserContext.Name,
			event.UserContext.SessionID, pq.StringArray{}, event.UserContext.Provider,
			event.UserContext.IPAddress, event.UserContext.UserAgent,
			event.ClusterContext.ClusterName, event.ClusterContext.Namespace,
			event.ClusterContext.ResourceType, event.ClusterContext.ResourceName,
			event.ClusterContext.KubectlContext,
			event.CommandContext.NaturalLanguageInput, event.CommandContext.GeneratedCommand,
			pq.StringArray{}, event.CommandContext.RiskLevel, event.CommandContext.ExecutionStatus,
			event.CommandContext.ExecutionResult, event.CommandContext.ExecutionError,
			event.CommandContext.ExecutionDuration,
			event.CorrelationID, event.TraceID, event.ServiceName, event.ServiceVersion,
			[]byte(`{}`), event.Checksum, event.ChecksumAt, 
			func() interface{} { if event.PreviousHash == "" { return nil } else { return event.PreviousHash } }(),
			func() interface{} { if event.SequenceNumber == 0 { return nil } else { return event.SequenceNumber } }(),
			event.CreatedAt, event.CreatedAt,
		)

		mock.ExpectQuery("SELECT .* FROM audit_events WHERE id = \\$1").
			WithArgs(event.ID).
			WillReturnRows(rows)
	}

	valid, err := storage.VerifyHashChainIntegrity(context.Background())
	assert.NoError(t, err)
	assert.True(t, valid)
	assert.NoError(t, mock.ExpectationsWereMet())
}