package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuditEventBuilder(t *testing.T) {
	builder := NewAuditEventBuilder()
	
	assert.NotNil(t, builder)
	assert.NotNil(t, builder.event)
	assert.NotEmpty(t, builder.event.ID)
	assert.False(t, builder.event.Timestamp.IsZero())
	assert.Equal(t, AuditSeverityInfo, builder.event.Severity)
	assert.NotNil(t, builder.event.Metadata)
}

func TestAuditEventBuilderFluentInterface(t *testing.T) {
	user := &User{
		ID:    "user123",
		Email: "test@example.com",
		Name:  "Test User",
		OIDCAttributes: OIDCAttributes{
			Provider: "test-provider",
			Groups:   []string{"admin", "developers"},
		},
	}

	sessionCtx := &SessionAuthContext{
		UserID:    "user123",
		SessionID: "session456",
		IPAddress: "192.168.1.100",
		UserAgent: "Mozilla/5.0 Test",
	}

	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeCommand).
		WithSeverity(AuditSeverityInfo).
		WithMessage("User executed kubectl command").
		WithUserContext(sessionCtx).
		WithUserContextFromUser(user, "session456", "192.168.1.100", "Mozilla/5.0 Test").
		WithClusterContext("test-cluster", "default", "pod", "nginx-pod", "test-context").
		WithCommandContext("get all pods", "kubectl get pods", "safe", "completed", "3 pods found", "", 1500).
		WithCorrelationID("corr123").
		WithTraceID("trace456").
		WithService("api-gateway", "v1.0.0").
		WithMetadata("source", "cli").
		Build()

	require.NoError(t, err)
	require.NotNil(t, event)

	// Verify core fields
	assert.Equal(t, AuditEventTypeCommand, event.EventType)
	assert.Equal(t, AuditSeverityInfo, event.Severity)
	assert.Equal(t, "User executed kubectl command", event.Message)

	// Verify user context
	assert.Equal(t, "user123", event.UserContext.UserID)
	assert.Equal(t, "test@example.com", event.UserContext.Email)
	assert.Equal(t, "Test User", event.UserContext.Name)
	assert.Equal(t, "session456", event.UserContext.SessionID)
	assert.Equal(t, "test-provider", event.UserContext.Provider)
	assert.Contains(t, event.UserContext.Groups, "admin")

	// Verify cluster context
	assert.Equal(t, "test-cluster", event.ClusterContext.ClusterName)
	assert.Equal(t, "default", event.ClusterContext.Namespace)
	assert.Equal(t, "pod", event.ClusterContext.ResourceType)

	// Verify command context
	assert.Equal(t, "get all pods", event.CommandContext.NaturalLanguageInput)
	assert.Equal(t, "kubectl get pods", event.CommandContext.GeneratedCommand)
	assert.Equal(t, "safe", event.CommandContext.RiskLevel)

	// Verify metadata and tracking
	assert.Equal(t, "corr123", event.CorrelationID)
	assert.Equal(t, "trace456", event.TraceID)
	assert.Equal(t, "api-gateway", event.ServiceName)
	assert.Equal(t, "cli", event.Metadata["source"])

	// Verify checksum is generated
	assert.NotEmpty(t, event.Checksum)
	assert.False(t, event.ChecksumAt.IsZero())
}

func TestAuditEventBuilderValidation(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func(*AuditEventBuilder) *AuditEventBuilder
		expectError bool
		errorMsg    string
	}{
		{
			name: "missing event type",
			setupFunc: func(b *AuditEventBuilder) *AuditEventBuilder {
				return b.WithMessage("test message").WithUserContextFromUser(&User{ID: "user1"}, "sess1", "", "")
			},
			expectError: true,
			errorMsg:    "event type is required",
		},
		{
			name: "missing message",
			setupFunc: func(b *AuditEventBuilder) *AuditEventBuilder {
				return b.WithEventType(AuditEventTypeAuthentication).WithUserContextFromUser(&User{ID: "user1"}, "sess1", "", "")
			},
			expectError: true,
			errorMsg:    "message is required",
		},
		{
			name: "missing user context",
			setupFunc: func(b *AuditEventBuilder) *AuditEventBuilder {
				return b.WithEventType(AuditEventTypeAuthentication).WithMessage("test message")
			},
			expectError: true,
			errorMsg:    "user context is required",
		},
		{
			name: "valid minimal event",
			setupFunc: func(b *AuditEventBuilder) *AuditEventBuilder {
				return b.
					WithEventType(AuditEventTypeAuthentication).
					WithMessage("test message").
					WithUserContextFromUser(&User{ID: "user1"}, "sess1", "", "")
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := NewAuditEventBuilder()
			builder = tt.setupFunc(builder)
			
			event, err := builder.Build()
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, event)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, event)
				assert.NotEmpty(t, event.Checksum)
			}
		})
	}
}

func TestAuditEventIntegrityVerification(t *testing.T) {
	// Create a valid audit event
	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeAuthentication).
		WithMessage("User login successful").
		WithUserContextFromUser(&User{ID: "user123"}, "session456", "", "").
		Build()
	
	require.NoError(t, err)
	require.NotNil(t, event)

	// Verify integrity of unmodified event
	valid, err := event.VerifyIntegrity()
	assert.NoError(t, err)
	assert.True(t, valid)

	// Test integrity after modification
	originalMessage := event.Message
	event.Message = "Modified message"
	
	valid, err = event.VerifyIntegrity()
	assert.NoError(t, err)
	assert.False(t, valid, "Event should fail integrity check after modification")
	
	// Restore original message
	event.Message = originalMessage
	
	valid, err = event.VerifyIntegrity()
	assert.NoError(t, err)
	assert.True(t, valid, "Event should pass integrity check after restoration")
}

func TestAuditEventJSONSerialization(t *testing.T) {
	// Create a comprehensive audit event
	builder := NewAuditEventBuilder()
	originalEvent, err := builder.
		WithEventType(AuditEventTypeCommand).
		WithSeverity(AuditSeverityWarning).
		WithMessage("High-risk command executed").
		WithUserContextFromUser(
			&User{
				ID:    "user123",
				Email: "admin@example.com",
				Name:  "Admin User",
			},
			"session456",
			"10.0.0.1",
			"kubectl/1.28.0",
		).
		WithClusterContext("prod-cluster", "kube-system", "deployment", "critical-service", "prod").
		WithCommandContext("delete all deployments", "kubectl delete deployments --all", "destructive", "completed", "5 deployments deleted", "", 3000).
		WithMetadata("approval_required", true).
		WithMetadata("approver", "security-team").
		Build()
	
	require.NoError(t, err)

	// Test JSON serialization
	jsonData, err := originalEvent.ToJSON()
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)

	// Verify JSON contains expected fields
	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	assert.NoError(t, err)
	assert.Equal(t, "command", jsonMap["event_type"])
	assert.Equal(t, "warning", jsonMap["severity"])
	assert.Equal(t, "High-risk command executed", jsonMap["message"])

	// Test JSON deserialization
	var deserializedEvent AuditEvent
	err = deserializedEvent.FromJSON(jsonData)
	assert.NoError(t, err)
	
	// Verify deserialized event matches original
	assert.Equal(t, originalEvent.ID, deserializedEvent.ID)
	assert.Equal(t, originalEvent.EventType, deserializedEvent.EventType)
	assert.Equal(t, originalEvent.Severity, deserializedEvent.Severity)
	assert.Equal(t, originalEvent.Message, deserializedEvent.Message)
	assert.Equal(t, originalEvent.UserContext.UserID, deserializedEvent.UserContext.UserID)
	assert.Equal(t, originalEvent.ClusterContext.ClusterName, deserializedEvent.ClusterContext.ClusterName)
	assert.Equal(t, originalEvent.CommandContext.NaturalLanguageInput, deserializedEvent.CommandContext.NaturalLanguageInput)
	assert.Equal(t, originalEvent.Checksum, deserializedEvent.Checksum)
	
	// Verify integrity of deserialized event
	valid, err := deserializedEvent.VerifyIntegrity()
	assert.NoError(t, err)
	assert.True(t, valid)
}

func TestAuditEventTypes(t *testing.T) {
	expectedTypes := []AuditEventType{
		AuditEventTypeAuthentication,
		AuditEventTypeLogin,
		AuditEventTypeLogout,
		AuditEventTypeSessionExpiry,
		AuditEventTypeCommand,
		AuditEventTypeCommandGenerate,
		AuditEventTypeCommandExecute,
		AuditEventTypeCommandResult,
		AuditEventTypeNLPInput,
		AuditEventTypeNLPTranslation,
		AuditEventTypeRBACCheck,
		AuditEventTypeRBACDenied,
		AuditEventTypePermissionGrant,
		AuditEventTypeSystemError,
		AuditEventTypeHealthCheck,
		AuditEventTypeServiceStart,
		AuditEventTypeServiceStop,
	}

	// Test that all expected types are properly defined
	for _, eventType := range expectedTypes {
		assert.NotEmpty(t, string(eventType))
	}
}

func TestAuditEventSeverities(t *testing.T) {
	expectedSeverities := []AuditSeverity{
		AuditSeverityInfo,
		AuditSeverityWarning,
		AuditSeverityError,
		AuditSeverityCritical,
	}

	// Test that all expected severities are properly defined
	for _, severity := range expectedSeverities {
		assert.NotEmpty(t, string(severity))
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	assert.NotEmpty(t, id1)
	assert.NotEmpty(t, id2)
	assert.NotEqual(t, id1, id2, "Event IDs should be unique")
	assert.Contains(t, id1, "audit_")
	assert.Contains(t, id2, "audit_")
}

func TestUserContextIntegration(t *testing.T) {
	// Test integration with SessionAuthContext
	sessionCtx := &SessionAuthContext{
		UserID:           "user123",
		SessionID:        "session456",
		AuthProvider:     "okta",
		IPAddress:        "192.168.1.100",
		UserAgent:        "Mozilla/5.0 Test",
		KubernetesContext: "production",
	}

	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeLogin).
		WithMessage("User logged in successfully").
		WithUserContext(sessionCtx).
		Build()

	require.NoError(t, err)
	assert.Equal(t, sessionCtx.UserID, event.UserContext.UserID)
	assert.Equal(t, sessionCtx.SessionID, event.UserContext.SessionID)
	assert.Equal(t, sessionCtx.IPAddress, event.UserContext.IPAddress)
	assert.Equal(t, sessionCtx.UserAgent, event.UserContext.UserAgent)
}

func TestClusterContextCapture(t *testing.T) {
	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeCommand).
		WithMessage("Kubectl command executed").
		WithUserContextFromUser(&User{ID: "user1"}, "sess1", "", "").
		WithClusterContext("production", "default", "deployment", "nginx", "prod-context").
		Build()

	require.NoError(t, err)
	assert.Equal(t, "production", event.ClusterContext.ClusterName)
	assert.Equal(t, "default", event.ClusterContext.Namespace)
	assert.Equal(t, "deployment", event.ClusterContext.ResourceType)
	assert.Equal(t, "nginx", event.ClusterContext.ResourceName)
	assert.Equal(t, "prod-context", event.ClusterContext.KubectlContext)
}

func TestCommandContextTracking(t *testing.T) {
	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeCommandExecute).
		WithMessage("Command execution completed").
		WithUserContextFromUser(&User{ID: "user1"}, "sess1", "", "").
		WithCommandContext(
			"show me all running pods",
			"kubectl get pods --field-selector=status.phase=Running",
			"safe",
			"completed",
			"5 pods are running",
			"",
			2500,
		).
		Build()

	require.NoError(t, err)
	assert.Equal(t, "show me all running pods", event.CommandContext.NaturalLanguageInput)
	assert.Equal(t, "kubectl get pods --field-selector=status.phase=Running", event.CommandContext.GeneratedCommand)
	assert.Equal(t, "safe", event.CommandContext.RiskLevel)
	assert.Equal(t, "completed", event.CommandContext.ExecutionStatus)
	assert.Equal(t, "5 pods are running", event.CommandContext.ExecutionResult)
	assert.Equal(t, int64(2500), event.CommandContext.ExecutionDuration)
}

func BenchmarkAuditEventCreation(b *testing.B) {
	user := &User{
		ID:    "user123",
		Email: "test@example.com",
		Name:  "Test User",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		builder := NewAuditEventBuilder()
		_, err := builder.
			WithEventType(AuditEventTypeCommand).
			WithMessage("Benchmark test event").
			WithUserContextFromUser(user, "session456", "192.168.1.1", "test-agent").
			WithCommandContext("test command", "kubectl test", "safe", "completed", "success", "", 1000).
			Build()
		
		if err != nil {
			b.Fatalf("Failed to create audit event: %v", err)
		}
	}
}

func BenchmarkIntegrityVerification(b *testing.B) {
	// Create a test event
	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeCommand).
		WithMessage("Benchmark integrity test").
		WithUserContextFromUser(&User{ID: "user1"}, "sess1", "", "").
		Build()
	
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := event.VerifyIntegrity()
		if err != nil {
			b.Fatalf("Integrity verification failed: %v", err)
		}
	}
}

// TestHashChainIntegrity tests the new hash chain integrity features
func TestHashChainIntegrity(t *testing.T) {
	// Create first event in chain (genesis)
	builder1 := NewAuditEventBuilder()
	event1, err := builder1.
		WithEventType(AuditEventTypeLogin).
		WithMessage("User login").
		WithUserContextFromUser(&User{ID: "user123", Email: "test@example.com", Name: "Test User"}, "session123", "192.168.1.1", "test-agent").
		WithHashChain("", 1). // Genesis event
		Build()
	
	require.NoError(t, err)
	require.NotNil(t, event1)
	assert.Equal(t, int64(1), event1.SequenceNumber)
	assert.Empty(t, event1.PreviousHash)

	// Create second event in chain
	builder2 := NewAuditEventBuilder()
	event2, err := builder2.
		WithEventType(AuditEventTypeCommand).
		WithMessage("Command execution").
		WithUserContextFromUser(&User{ID: "user123", Email: "test@example.com", Name: "Test User"}, "session123", "192.168.1.1", "test-agent").
		WithHashChain(event1.Checksum, 2).
		Build()
	
	require.NoError(t, err)
	require.NotNil(t, event2)
	assert.Equal(t, int64(2), event2.SequenceNumber)
	assert.Equal(t, event1.Checksum, event2.PreviousHash)

	t.Run("hash chain verification succeeds for valid chain", func(t *testing.T) {
		// Verify individual event integrity
		valid1, err := event1.VerifyIntegrity()
		assert.NoError(t, err)
		assert.True(t, valid1)
		
		valid2, err := event2.VerifyIntegrity()
		assert.NoError(t, err)
		assert.True(t, valid2)
		
		// Verify hash chain linking
		chainValid, err := event2.VerifyHashChain(event1)
		assert.NoError(t, err)
		assert.True(t, chainValid)
	})

	t.Run("hash chain verification fails for tampered previous event", func(t *testing.T) {
		// Create a tampered version of event1
		tamperedEvent1 := *event1
		tamperedEvent1.Message = "Tampered message"
		
		chainValid, err := event2.VerifyHashChain(&tamperedEvent1)
		assert.NoError(t, err)
		assert.False(t, chainValid)
	})

	t.Run("hash chain verification fails for wrong sequence", func(t *testing.T) {
		// Create event with wrong sequence number
		builder3 := NewAuditEventBuilder()
		event3, err := builder3.
			WithEventType(AuditEventTypeLogout).
			WithMessage("User logout").
			WithUserContextFromUser(&User{ID: "user123", Email: "test@example.com", Name: "Test User"}, "session123", "192.168.1.1", "test-agent").
			WithHashChain(event2.Checksum, 5). // Wrong sequence - should be 3
			Build()
		
		require.NoError(t, err)
		
		chainValid, err := event3.VerifyHashChain(event2)
		assert.NoError(t, err)
		assert.False(t, chainValid)
	})

	t.Run("genesis event validation", func(t *testing.T) {
		// First event should validate without previous event
		chainValid, err := event1.VerifyHashChain(nil)
		assert.NoError(t, err)
		assert.True(t, chainValid)
	})

	t.Run("missing previous event error", func(t *testing.T) {
		chainValid, err := event2.VerifyHashChain(nil)
		assert.Error(t, err)
		assert.False(t, chainValid)
		assert.Contains(t, err.Error(), "previous event required")
	})
}

func TestTamperDetection(t *testing.T) {
	builder := NewAuditEventBuilder()
	event, err := builder.
		WithEventType(AuditEventTypeCommand).
		WithMessage("Test command").
		WithUserContextFromUser(&User{ID: "user123", Email: "test@example.com", Name: "Test User"}, "session123", "192.168.1.1", "test-agent").
		WithCommandContext("get pods", "kubectl get pods", "safe", "completed", "3 pods found", "", 1000).
		WithMetadata("sensitive_data", "classified").
		Build()
	
	require.NoError(t, err)

	// Original event should verify successfully
	valid, err := event.VerifyIntegrity()
	assert.NoError(t, err)
	assert.True(t, valid)

	tamperings := []struct {
		name   string
		tamper func(*AuditEvent) func()
	}{
		{
			name: "message tampering",
			tamper: func(e *AuditEvent) func() {
				original := e.Message
				e.Message = "Tampered message"
				return func() { e.Message = original }
			},
		},
		{
			name: "user ID tampering",
			tamper: func(e *AuditEvent) func() {
				original := e.UserContext.UserID
				e.UserContext.UserID = "malicious_user"
				return func() { e.UserContext.UserID = original }
			},
		},
		{
			name: "command tampering",
			tamper: func(e *AuditEvent) func() {
				original := e.CommandContext.GeneratedCommand
				e.CommandContext.GeneratedCommand = "kubectl delete --all"
				return func() { e.CommandContext.GeneratedCommand = original }
			},
		},
		{
			name: "metadata tampering",
			tamper: func(e *AuditEvent) func() {
				original := e.Metadata["sensitive_data"]
				e.Metadata["sensitive_data"] = "exposed"
				return func() { e.Metadata["sensitive_data"] = original }
			},
		},
		{
			name: "severity tampering",
			tamper: func(e *AuditEvent) func() {
				original := e.Severity
				e.Severity = AuditSeverityCritical
				return func() { e.Severity = original }
			},
		},
	}

	for _, tt := range tamperings {
		t.Run(tt.name, func(t *testing.T) {
			// Apply tampering
			restore := tt.tamper(event)
			
			// Verify tampering is detected
			valid, err := event.VerifyIntegrity()
			assert.NoError(t, err)
			assert.False(t, valid, "Tampering should be detected")
			
			// Restore original value
			restore()
			
			// Verify restoration works
			valid, err = event.VerifyIntegrity()
			assert.NoError(t, err)
			assert.True(t, valid, "Event should verify after restoration")
		})
	}
}

func TestHashChainSequenceIntegrity(t *testing.T) {
	// Create a chain of 5 events
	events := make([]*AuditEvent, 5)
	
	for i := 0; i < 5; i++ {
		builder := NewAuditEventBuilder()
		var previousHash string
		var sequenceNum int64
		
		if i == 0 {
			// Genesis event
			previousHash = ""
			sequenceNum = 1
		} else {
			previousHash = events[i-1].Checksum
			sequenceNum = int64(i + 1)
		}
		
		event, err := builder.
			WithEventType(AuditEventTypeCommand).
			WithMessage("Command " + string(rune('A'+i))).
			WithUserContextFromUser(&User{ID: "user123", Email: "test@example.com", Name: "Test User"}, "session123", "192.168.1.1", "test-agent").
			WithHashChain(previousHash, sequenceNum).
			Build()
		
		require.NoError(t, err)
		events[i] = event
	}

	t.Run("entire chain verification", func(t *testing.T) {
		// Verify each event and its chain link
		for i, event := range events {
			// Verify individual integrity
			valid, err := event.VerifyIntegrity()
			assert.NoError(t, err)
			assert.True(t, valid, "Event %d should verify", i)
			
			// Verify chain link
			if i == 0 {
				chainValid, err := event.VerifyHashChain(nil)
				assert.NoError(t, err)
				assert.True(t, chainValid, "Genesis event should verify")
			} else {
				chainValid, err := event.VerifyHashChain(events[i-1])
				assert.NoError(t, err)
				assert.True(t, chainValid, "Event %d chain should verify", i)
			}
		}
	})

	t.Run("middle event tampering breaks chain", func(t *testing.T) {
		// Tamper with middle event
		originalMessage := events[2].Message
		events[2].Message = "Tampered middle event"
		
		// Event 3 (index 2) should fail integrity
		valid, err := events[2].VerifyIntegrity()
		assert.NoError(t, err)
		assert.False(t, valid)
		
		// Event 4 (index 3) should fail chain verification with tampered event 3
		chainValid, err := events[3].VerifyHashChain(events[2])
		assert.NoError(t, err)
		assert.False(t, chainValid, "Chain should break after tampering")
		
		// Restore original message
		events[2].Message = originalMessage
	})
}