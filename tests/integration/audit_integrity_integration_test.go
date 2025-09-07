// Package integration provides comprehensive integration tests for tamper-proof audit storage
package integration

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "github.com/lib/pq"

	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// TestEnvironment manages test infrastructure
type TestEnvironment struct {
	DB               *sql.DB
	Storage          audit.AuditStorage
	EncryptedStorage *audit.EncryptedAuditStorage
	IntegrityService *audit.IntegrityService
}

// SetupTestEnvironment initializes test infrastructure
func SetupTestEnvironment(t *testing.T) *TestEnvironment {
	// Use environment variable or default test database
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://test:test@localhost:5432/kubechat_audit_test?sslmode=disable"
	}

	// Connect to test database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("Test database not available: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		t.Skipf("Cannot connect to test database: %v", err)
	}

	// Clean up any existing test data
	_, err = db.Exec("TRUNCATE TABLE audit_events CASCADE")
	if err != nil {
		t.Logf("Warning: Could not clean test data: %v", err)
	}

	// Initialize storage
	storage, err := audit.NewPostgreSQLAuditStorage(dbURL, 365)
	require.NoError(t, err)

	// Initialize encryption
	keyManager := audit.NewExternalSecretsKeyManager("test", "test-key")
	encryptionService, err := audit.NewEncryptionService(keyManager)
	require.NoError(t, err)
	
	encryptedStorage := audit.NewEncryptedAuditStorage(storage, encryptionService)
	integrityService := audit.NewIntegrityService(encryptedStorage)

	return &TestEnvironment{
		DB:               db,
		Storage:          storage,
		EncryptedStorage: encryptedStorage,
		IntegrityService: integrityService,
	}
}

// TeardownTestEnvironment cleans up test infrastructure
func (env *TestEnvironment) TeardownTestEnvironment() {
	if env.DB != nil {
		env.DB.Close()
	}
}

// TestTamperProofAuditWorkflow tests the complete tamper-proof audit workflow
func TestTamperProofAuditWorkflow(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.TeardownTestEnvironment()

	ctx := context.Background()

	t.Run("end-to-end tamper-proof audit workflow", func(t *testing.T) {
		// Step 1: Create and store multiple audit events with hash chain
		events := createTestAuditEvents(t, 5)
		
		// Store events sequentially to build hash chain
		for i, event := range events {
			err := env.EncryptedStorage.StoreEvent(ctx, event)
			require.NoError(t, err, "Failed to store event %d", i)
			
			// Verify the event can be retrieved and decrypted
			retrieved, err := env.EncryptedStorage.GetEvent(ctx, event.ID)
			require.NoError(t, err, "Failed to retrieve event %d", i)
			
			// Verify decryption worked correctly by checking sensitive data
			assert.Equal(t, event.CommandContext.GeneratedCommand, retrieved.CommandContext.GeneratedCommand)
			assert.Equal(t, event.CommandContext.NaturalLanguageInput, retrieved.CommandContext.NaturalLanguageInput)
			assert.Equal(t, event.CommandContext.ExecutionResult, retrieved.CommandContext.ExecutionResult)
		}
		
		// Step 2: Verify integrity of all stored events
		report, err := env.IntegrityService.VerifyAllRecords(ctx)
		require.NoError(t, err)
		assert.True(t, report.OverallValid, "Integrity verification failed")
		assert.Equal(t, 5, int(report.TotalRecords), "Expected 5 records")
		assert.Equal(t, 5, int(report.ValidRecords), "All records should be valid")
		assert.Empty(t, report.Violations, "Should have no integrity violations")
		
		// Step 3: Verify hash chain integrity
		hashChainReport, err := env.IntegrityService.VerifyHashChainIntegrity(ctx)
		require.NoError(t, err)
		assert.True(t, hashChainReport.ChainValid, "Hash chain should be valid")
		
		// Step 4: Test encryption key rotation
		oldMetrics := env.EncryptedStorage.GetEncryptionMetrics()
		oldKeyID := oldMetrics.CurrentKeyID
		
		err = env.EncryptedStorage.RotateEncryptionKey()
		require.NoError(t, err)
		
		newMetrics := env.EncryptedStorage.GetEncryptionMetrics()
		newKeyID := newMetrics.CurrentKeyID
		assert.NotEqual(t, oldKeyID, newKeyID, "Key should have rotated")
		
		// Step 5: Verify old data still decrypts after key rotation
		for _, event := range events {
			retrieved, err := env.EncryptedStorage.GetEvent(ctx, event.ID)
			require.NoError(t, err, "Failed to retrieve event after key rotation")
			assert.Equal(t, event.CommandContext.GeneratedCommand, retrieved.CommandContext.GeneratedCommand)
		}
		
		// Step 6: Store new event with new key
		newEvent := createTestAuditEvents(t, 1)[0]
		err = env.EncryptedStorage.StoreEvent(ctx, newEvent)
		require.NoError(t, err)
		
		// Verify it uses the new key
		retrieved, err := env.EncryptedStorage.GetEvent(ctx, newEvent.ID)
		require.NoError(t, err)
		assert.Equal(t, newEvent.CommandContext.GeneratedCommand, retrieved.CommandContext.GeneratedCommand)
		
		// Step 7: Final integrity verification
		finalReport, err := env.IntegrityService.VerifyAllRecords(ctx)
		require.NoError(t, err)
		assert.True(t, finalReport.OverallValid, "Final integrity verification failed")
		assert.Equal(t, 6, int(finalReport.TotalRecords), "Expected 6 records after adding one more")
		
		// Step 8: Test compliance reporting
		complianceReport, err := env.IntegrityService.GenerateComplianceReport(ctx, "SOC2")
		require.NoError(t, err)
		assert.NotEmpty(t, complianceReport.ReportID)
		assert.Equal(t, "SOC2", complianceReport.ComplianceFramework)
		assert.True(t, complianceReport.OverallCompliance, "Should be SOC2 compliant")
		
		t.Logf("✅ Complete tamper-proof audit workflow verified:")
		t.Logf("  - Stored %d events with encryption", len(events)+1)
		t.Logf("  - Verified hash chain integrity")
		t.Logf("  - Successfully rotated encryption key")
		t.Logf("  - Verified backward compatibility after rotation")
		t.Logf("  - Generated compliance report: %s", complianceReport.ReportID)
	})
}

// TestTamperDetection tests that tampering is detected
func TestTamperDetection(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.TeardownTestEnvironment()

	ctx := context.Background()

	t.Run("tamper detection", func(t *testing.T) {
		// Store a test event
		event := createTestAuditEvents(t, 1)[0]
		err := env.EncryptedStorage.StoreEvent(ctx, event)
		require.NoError(t, err)
		
		// Verify integrity initially
		valid, err := env.Storage.VerifyIntegrity(ctx, event.ID)
		require.NoError(t, err)
		assert.True(t, valid, "Event should be valid initially")
		
		// Attempt to tamper with the event directly in database (this should fail due to immutable constraints)
		_, err = env.DB.Exec("UPDATE audit_events SET message = 'TAMPERED' WHERE id = $1", event.ID)
		assert.Error(t, err, "Direct database modification should be prevented by constraints")
		
		// Verify the event is still intact
		retrieved, err := env.EncryptedStorage.GetEvent(ctx, event.ID)
		require.NoError(t, err)
		assert.Equal(t, event.Message, retrieved.Message, "Event message should be unchanged")
		
		// Verify integrity detection would catch any hypothetical tampering
		violations, err := env.IntegrityService.DetectAndReportViolations(ctx)
		require.NoError(t, err)
		assert.Empty(t, violations.Violations, "Should have no violations in tamper-proof storage")
	})
}

// TestEncryptionPerformance benchmarks encryption performance
func TestEncryptionPerformance(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.TeardownTestEnvironment()

	ctx := context.Background()

	t.Run("encryption performance benchmark", func(t *testing.T) {
		const numEvents = 100
		events := createTestAuditEvents(t, numEvents)
		
		// Measure encryption and storage time
		start := time.Now()
		for _, event := range events {
			err := env.EncryptedStorage.StoreEvent(ctx, event)
			require.NoError(t, err)
		}
		encryptionTime := time.Since(start)
		
		// Measure decryption and retrieval time
		start = time.Now()
		for _, event := range events {
			_, err := env.EncryptedStorage.GetEvent(ctx, event.ID)
			require.NoError(t, err)
		}
		decryptionTime := time.Since(start)
		
		// Performance assertions
		avgEncryptionTime := encryptionTime / numEvents
		avgDecryptionTime := decryptionTime / numEvents
		
		assert.Less(t, avgEncryptionTime, 100*time.Millisecond, "Encryption should be under 100ms per event")
		assert.Less(t, avgDecryptionTime, 50*time.Millisecond, "Decryption should be under 50ms per event")
		
		t.Logf("📊 Encryption Performance Results:")
		t.Logf("  - Total events: %d", numEvents)
		t.Logf("  - Total encryption time: %v", encryptionTime)
		t.Logf("  - Average encryption time: %v", avgEncryptionTime)
		t.Logf("  - Total decryption time: %v", decryptionTime)
		t.Logf("  - Average decryption time: %v", avgDecryptionTime)
		t.Logf("  - Encryption throughput: %.2f events/sec", float64(numEvents)/encryptionTime.Seconds())
		t.Logf("  - Decryption throughput: %.2f events/sec", float64(numEvents)/decryptionTime.Seconds())
	})
}

// TestHashChainIntegrity specifically tests hash chain integrity
func TestHashChainIntegrity(t *testing.T) {
	env := SetupTestEnvironment(t)
	defer env.TeardownTestEnvironment()

	ctx := context.Background()

	t.Run("hash chain integrity", func(t *testing.T) {
		// Create events with proper hash chain linking
		events := createTestAuditEvents(t, 3)
		
		// Store events to build hash chain
		for _, event := range events {
			err := env.EncryptedStorage.StoreEvent(ctx, event)
			require.NoError(t, err)
		}
		
		// Verify hash chain integrity
		report, err := env.IntegrityService.VerifyHashChainIntegrity(ctx)
		require.NoError(t, err)
		assert.True(t, report.ChainValid, "Hash chain should be valid")
		assert.Equal(t, 3, int(report.ChainLength), "Chain should have 3 events")
		
		// Verify sequential integrity
		sequenceReport, err := env.IntegrityService.VerifySequenceRange(ctx, 1, 3)
		require.NoError(t, err)
		assert.True(t, sequenceReport.OverallValid, "Sequence should be valid")
	})
}

// createTestAuditEvents creates test audit events with sensitive data
func createTestAuditEvents(t *testing.T, count int) []*models.AuditEvent {
	var events []*models.AuditEvent
	
	for i := 0; i < count; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage(fmt.Sprintf("Test command execution %d", i)).
			WithUserContextFromUser(
				&models.User{ID: fmt.Sprintf("user_%d", i), Email: fmt.Sprintf("user%d@test.com", i)}, 
				fmt.Sprintf("session_%d", i), 
				"192.168.1.1", 
				"test-agent").
			WithCommandContext(
				fmt.Sprintf("get pods in namespace test-%d", i),
				fmt.Sprintf("kubectl get pods -n test-%d --show-labels", i),
				"safe",
				"completed",
				fmt.Sprintf("pod-%d: running, pod-%d-backup: terminated", i, i),
				"",
				int64(1000+i*100)).
			Build()
		
		require.NoError(t, err)
		events = append(events, event)
	}
	
	return events
}