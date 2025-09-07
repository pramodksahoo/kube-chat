package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewIntegrityVerifier(t *testing.T) {
	verifier := NewIntegrityVerifier()
	assert.NotNil(t, verifier)
	assert.Equal(t, "SHA-256", verifier.hashAlgorithm)
}

func TestVerifyBatchIntegrity(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	// Create test events
	builder1 := models.NewAuditEventBuilder()
	event1, err := builder1.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("User logged in").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	builder2 := models.NewAuditEventBuilder()
	event2, err := builder2.
		WithEventType(models.AuditEventTypeLogout).
		WithMessage("User logged out").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	events := []*models.AuditEvent{event1, event2}
	
	report, err := verifier.VerifyBatchIntegrity(events)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, 2, report.TotalEvents)
	assert.Equal(t, 2, report.VerifiedEvents)
	assert.Equal(t, 0, report.FailedEvents)
	assert.Equal(t, float64(100), report.IntegrityScore)
	assert.Empty(t, report.IntegrityViolations)
}

func TestVerifyBatchIntegrityWithTamperedEvent(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	// Create test event
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Original message").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Tamper with the event
	originalMessage := event.Message
	event.Message = "Tampered message"
	
	events := []*models.AuditEvent{event}
	
	report, err := verifier.VerifyBatchIntegrity(events)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, 1, report.TotalEvents)
	assert.Equal(t, 0, report.VerifiedEvents)
	assert.Equal(t, 1, report.FailedEvents)
	assert.Equal(t, float64(0), report.IntegrityScore)
	assert.Len(t, report.IntegrityViolations, 1)
	assert.Equal(t, "checksum_mismatch", report.IntegrityViolations[0].ViolationType)
	assert.Equal(t, "critical", report.IntegrityViolations[0].Severity)
	
	// Restore original message
	event.Message = originalMessage
}

func TestGenerateIntegrityChain(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	// Create a sequence of test events
	var events []*models.AuditEvent
	for i := 0; i < 3; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage("Test event").
			WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
			Build()
		require.NoError(t, err)
		
		// Add slight delay to ensure different timestamps
		time.Sleep(time.Millisecond)
		events = append(events, event)
	}
	
	chain, err := verifier.GenerateIntegrityChain(events)
	require.NoError(t, err)
	assert.NotNil(t, chain)
	assert.Len(t, chain.Events, 3)
	assert.NotEmpty(t, chain.ChainID)
	assert.NotEmpty(t, chain.ChainChecksum)
	assert.Equal(t, "SHA-256", chain.Algorithm)
	
	// Verify chain structure
	assert.Equal(t, "", chain.Events[0].PreviousHash) // First event has no previous
	assert.Equal(t, chain.Events[0].ChainHash, chain.Events[1].PreviousHash)
	assert.Equal(t, chain.Events[1].ChainHash, chain.Events[2].PreviousHash)
	
	// Each event should have proper chain indices
	for i, chainedEvent := range chain.Events {
		assert.Equal(t, i, chainedEvent.ChainIndex)
		assert.NotEmpty(t, chainedEvent.EventID)
		assert.NotEmpty(t, chainedEvent.EventHash)
		assert.NotEmpty(t, chainedEvent.ChainHash)
	}
}

func TestVerifyIntegrityChain(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	// Create test events and generate chain
	var events []*models.AuditEvent
	for i := 0; i < 3; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeLogin).
			WithMessage("Chain test event").
			WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
			Build()
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
		events = append(events, event)
	}
	
	chain, err := verifier.GenerateIntegrityChain(events)
	require.NoError(t, err)
	
	// Verify the intact chain
	report, err := verifier.VerifyIntegrityChain(chain)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.True(t, report.IsValid)
	assert.Equal(t, 3, report.TotalEvents)
	assert.Equal(t, 3, report.VerifiedEvents)
	assert.Empty(t, report.BrokenLinks)
	assert.Equal(t, float64(100), report.IntegrityScore)
}

func TestVerifyIntegrityChainWithBrokenLink(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	// Create test events and generate chain
	var events []*models.AuditEvent
	for i := 0; i < 3; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage("Chain test event").
			WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
			Build()
		require.NoError(t, err)
		time.Sleep(time.Millisecond)
		events = append(events, event)
	}
	
	chain, err := verifier.GenerateIntegrityChain(events)
	require.NoError(t, err)
	
	// Break the chain by tampering with a hash
	originalHash := chain.Events[1].PreviousHash
	chain.Events[1].PreviousHash = "tampered_hash"
	
	// Verify the broken chain
	report, err := verifier.VerifyIntegrityChain(chain)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.False(t, report.IsValid)
	assert.Equal(t, 3, report.TotalEvents)
	assert.Equal(t, 2, report.VerifiedEvents) // First and third events are still linked correctly
	assert.Len(t, report.BrokenLinks, 1)
	assert.Equal(t, chain.Events[1].EventID, report.BrokenLinks[0].EventID)
	assert.Equal(t, 1, report.BrokenLinks[0].ChainIndex)
	
	// Restore original hash
	chain.Events[1].PreviousHash = originalHash
}

func TestGenerateIntegrityChainEmptyEvents(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	_, err := verifier.GenerateIntegrityChain([]*models.AuditEvent{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot generate integrity chain for empty event list")
}

func TestGenerateIntegrityChainWithInvalidEvent(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	// Create an event and tamper with it before chain generation
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeCommand).
		WithMessage("Original message").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	// Tamper with the event to make it invalid
	event.Message = "Tampered message"
	
	events := []*models.AuditEvent{event}
	
	_, err = verifier.GenerateIntegrityChain(events)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "has invalid checksum")
}

func TestComputeEventHash(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	builder := models.NewAuditEventBuilder()
	event, err := builder.
		WithEventType(models.AuditEventTypeLogin).
		WithMessage("Test hash computation").
		WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
		Build()
	require.NoError(t, err)
	
	hash := verifier.computeEventHash(event)
	assert.NotEmpty(t, hash)
	assert.Equal(t, 64, len(hash)) // SHA-256 produces 64-character hex string
	
	// Hash should be consistent
	hash2 := verifier.computeEventHash(event)
	assert.Equal(t, hash, hash2)
}

func TestGenerateChainID(t *testing.T) {
	verifier := NewIntegrityVerifier()
	
	id1 := verifier.generateChainID()
	id2 := verifier.generateChainID()
	
	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2)
	assert.Equal(t, 16, len(id1)) // First 16 characters of SHA-256
	assert.Equal(t, 16, len(id2))
}

func BenchmarkVerifyBatchIntegrity(b *testing.B) {
	verifier := NewIntegrityVerifier()
	
	// Create test events
	events := make([]*models.AuditEvent, 100)
	for i := 0; i < 100; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage("Benchmark event").
			WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
			Build()
		require.NoError(b, err)
		events[i] = event
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.VerifyBatchIntegrity(events)
		if err != nil {
			b.Fatalf("Verification failed: %v", err)
		}
	}
}

func BenchmarkGenerateIntegrityChain(b *testing.B) {
	verifier := NewIntegrityVerifier()
	
	// Create test events
	events := make([]*models.AuditEvent, 50)
	for i := 0; i < 50; i++ {
		builder := models.NewAuditEventBuilder()
		event, err := builder.
			WithEventType(models.AuditEventTypeCommand).
			WithMessage("Benchmark event").
			WithUserContextFromUser(&models.User{ID: "user1"}, "sess1", "", "").
			Build()
		require.NoError(b, err)
		events[i] = event
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.GenerateIntegrityChain(events)
		if err != nil {
			b.Fatalf("Chain generation failed: %v", err)
		}
	}
}