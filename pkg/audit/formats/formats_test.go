package formats

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestAuditEvent creates a comprehensive audit event for testing
func createTestAuditEvent() *models.AuditEvent {
	event, err := models.NewAuditEventBuilder().
		WithEventType(models.AuditEventTypeCommandExecute).
		WithSeverity(models.AuditSeverityInfo).
		WithMessage("User executed kubectl command successfully").
		WithUserContextFromUser(&models.User{
			ID:    "user123",
			Email: "test@company.com",
			Name:  "Test User",
		}, "session_abc123", "192.168.1.100", "Mozilla/5.0").
		WithClusterContext("production-cluster", "default", "pod", "test-pod", "prod-context").
		WithCommandContext("show me all pods", "kubectl get pods", "safe", "success", "3 pods running", "", 250).
		WithCorrelationID("req_789").
		WithTraceID("trace_456").
		WithService("audit-service", "1.0.0").
		WithMetadata("test_key", "test_value").
		Build()
	
	if err != nil {
		panic(err)
	}
	return event
}

// TestJSONExporter tests JSON format export functionality
func TestJSONExporter(t *testing.T) {
	tests := []struct {
		name   string
		config JSONExporterConfig
	}{
		{
			name: "default_config",
			config: JSONExporterConfig{
				IncludeIntegrityFields: true,
			},
		},
		{
			name: "with_custom_mappings",
			config: JSONExporterConfig{
				IncludeIntegrityFields: false,
				CustomFieldMappings: map[string]string{
					"timestamp": "event_time",
					"user_id":   "username",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := NewJSONExporter(tt.config)
			event := createTestAuditEvent()

			// Test single event export
			data, err := exporter.Export(event)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			// Validate JSON structure
			var jsonEvent map[string]interface{}
			err = json.Unmarshal(data, &jsonEvent)
			require.NoError(t, err)

			// Check required fields
			assert.Equal(t, event.ID, jsonEvent["event_id"])
			assert.Equal(t, string(event.EventType), jsonEvent["event_type"])
			assert.Equal(t, event.UserContext.UserID, jsonEvent["user_id"])

			// Check custom field mappings
			if tt.config.CustomFieldMappings != nil {
				if _, hasMapping := tt.config.CustomFieldMappings["timestamp"]; hasMapping {
					assert.Contains(t, jsonEvent, "event_time")
					assert.NotContains(t, jsonEvent, "timestamp")
				}
			}

			// Check integrity fields
			if tt.config.IncludeIntegrityFields {
				assert.Contains(t, jsonEvent, "checksum")
				assert.Contains(t, jsonEvent, "checksum_at")
			}

			// Test format methods
			assert.Equal(t, "JSON", exporter.GetFormatName())
			assert.Equal(t, "application/json", exporter.GetContentType())

			// Test validation
			err = exporter.ValidateEvent(event)
			assert.NoError(t, err)

			// Test sample output
			sample := exporter.GetSampleOutput()
			assert.NotEmpty(t, sample)
			var sampleData map[string]interface{}
			err = json.Unmarshal([]byte(sample), &sampleData)
			assert.NoError(t, err)
		})
	}
}

// TestJSONExporterBatch tests batch export functionality
func TestJSONExporterBatch(t *testing.T) {
	exporter := NewJSONExporter(JSONExporterConfig{})
	
	// Create multiple test events
	events := []*models.AuditEvent{
		createTestAuditEvent(),
		createTestAuditEvent(),
		createTestAuditEvent(),
	}

	// Test batch export
	data, err := exporter.ExportBatch(events)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	// Validate JSON array structure
	var jsonEvents []map[string]interface{}
	err = json.Unmarshal(data, &jsonEvents)
	require.NoError(t, err)
	assert.Len(t, jsonEvents, 3)

	// Test empty batch
	emptyData, err := exporter.ExportBatch([]*models.AuditEvent{})
	require.NoError(t, err)
	assert.Equal(t, "[]", string(emptyData))
}

// TestCEFExporter tests CEF format export functionality
func TestCEFExporter(t *testing.T) {
	tests := []struct {
		name   string
		config CEFExporterConfig
	}{
		{
			name:   "default_config",
			config: DefaultCEFConfig(),
		},
		{
			name: "custom_config",
			config: CEFExporterConfig{
				DeviceVendor:    "TestVendor",
				DeviceProduct:   "TestProduct",
				DeviceVersion:   "2.0",
				SignaturePrefix: "TEST",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := NewCEFExporter(tt.config)
			event := createTestAuditEvent()

			// Test single event export
			data, err := exporter.Export(event)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			cefLine := string(data)

			// Validate CEF structure
			assert.True(t, strings.HasPrefix(cefLine, "CEF:0|"))
			assert.Contains(t, cefLine, tt.config.DeviceVendor)
			assert.Contains(t, cefLine, tt.config.DeviceProduct)
			assert.Contains(t, cefLine, event.ID)
			assert.Contains(t, cefLine, event.UserContext.UserID)

			// Check for proper field escaping
			assert.NotContains(t, cefLine, "unescaped|pipe")

			// Test format methods
			assert.Equal(t, "CEF", exporter.GetFormatName())
			assert.Equal(t, "text/plain", exporter.GetContentType())

			// Test validation
			err = exporter.ValidateEvent(event)
			assert.NoError(t, err)

			// Test sample output
			sample := exporter.GetSampleOutput()
			assert.NotEmpty(t, sample)
			assert.True(t, strings.HasPrefix(sample, "CEF:0|"))
		})
	}
}

// TestCEFExporterBatch tests CEF batch export functionality
func TestCEFExporterBatch(t *testing.T) {
	exporter := NewCEFExporter(DefaultCEFConfig())
	
	events := []*models.AuditEvent{
		createTestAuditEvent(),
		createTestAuditEvent(),
	}

	// Test batch export
	data, err := exporter.ExportBatch(events)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	lines := strings.Split(string(data), "\n")
	assert.Len(t, lines, 2)
	
	for _, line := range lines {
		assert.True(t, strings.HasPrefix(line, "CEF:0|"))
	}

	// Test empty batch
	emptyData, err := exporter.ExportBatch([]*models.AuditEvent{})
	require.NoError(t, err)
	assert.Empty(t, string(emptyData))
}

// TestLEEFExporter tests LEEF format export functionality
func TestLEEFExporter(t *testing.T) {
	tests := []struct {
		name   string
		config LEEFExporterConfig
	}{
		{
			name:   "default_config",
			config: DefaultLEEFConfig(),
		},
		{
			name: "custom_config",
			config: LEEFExporterConfig{
				DeviceVendor:  "TestVendor",
				DeviceProduct: "TestProduct",
				DeviceVersion: "2.0",
				EventIdPrefix: "TEST",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exporter := NewLEEFExporter(tt.config)
			event := createTestAuditEvent()

			// Test single event export
			data, err := exporter.Export(event)
			require.NoError(t, err)
			require.NotEmpty(t, data)

			leefLine := string(data)

			// Validate LEEF structure
			assert.True(t, strings.HasPrefix(leefLine, "LEEF:2.0|"))
			assert.Contains(t, leefLine, tt.config.DeviceVendor)
			assert.Contains(t, leefLine, tt.config.DeviceProduct)
			assert.Contains(t, leefLine, event.ID)
			assert.Contains(t, leefLine, event.UserContext.UserID)

			// Test format methods
			assert.Equal(t, "LEEF", exporter.GetFormatName())
			assert.Equal(t, "text/plain", exporter.GetContentType())

			// Test validation
			err = exporter.ValidateEvent(event)
			assert.NoError(t, err)

			// Test sample output
			sample := exporter.GetSampleOutput()
			assert.NotEmpty(t, sample)
			assert.True(t, strings.HasPrefix(sample, "LEEF:2.0|"))
		})
	}
}

// TestLEEFExporterBatch tests LEEF batch export functionality
func TestLEEFExporterBatch(t *testing.T) {
	exporter := NewLEEFExporter(DefaultLEEFConfig())
	
	events := []*models.AuditEvent{
		createTestAuditEvent(),
		createTestAuditEvent(),
	}

	// Test batch export
	data, err := exporter.ExportBatch(events)
	require.NoError(t, err)
	require.NotEmpty(t, data)

	lines := strings.Split(string(data), "\n")
	assert.Len(t, lines, 2)
	
	for _, line := range lines {
		assert.True(t, strings.HasPrefix(line, "LEEF:2.0|"))
	}

	// Test empty batch
	emptyData, err := exporter.ExportBatch([]*models.AuditEvent{})
	require.NoError(t, err)
	assert.Empty(t, string(emptyData))
}

// TestFieldMappings tests field mapping functionality
func TestFieldMappings(t *testing.T) {
	tests := []struct {
		name     string
		platform SIEMPlatform
	}{
		{"splunk", SIEMPlatformSplunk},
		{"qradar", SIEMPlatformQRadar},
		{"sentinel", SIEMPlatformSentinel},
		{"elastic", SIEMPlatformElastic},
		{"generic", SIEMPlatformGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mappings, err := GetPlatformMappings(tt.platform)
			require.NoError(t, err)
			
			if tt.platform == SIEMPlatformGeneric {
				assert.Empty(t, mappings)
			} else {
				assert.NotEmpty(t, mappings)
				
				// Validate mappings structure
				err = ValidateMappings(mappings)
				assert.NoError(t, err)
			}
		})
	}
}

// TestEventTypeMappings tests event type mapping functionality
func TestEventTypeMappings(t *testing.T) {
	mappings := GetEventTypeMappings()
	assert.NotEmpty(t, mappings)

	// Test specific mappings
	eventType := GetEventTypeForPlatform(models.AuditEventTypeCommandExecute, SIEMPlatformSplunk)
	assert.Equal(t, "command_execution", eventType)

	eventType = GetEventTypeForPlatform(models.AuditEventTypeLogin, SIEMPlatformSentinel)
	assert.Equal(t, "SigninSuccess", eventType)

	// Test unknown event type
	eventType = GetEventTypeForPlatform("unknown", SIEMPlatformSplunk)
	assert.Equal(t, "unknown", eventType)
}

// TestRiskLevelMappings tests risk level mapping functionality
func TestRiskLevelMappings(t *testing.T) {
	mappings := GetRiskLevelMappings()
	assert.NotEmpty(t, mappings)

	// Test specific mappings
	riskLevel := GetRiskLevelForPlatform("safe", SIEMPlatformQRadar)
	assert.Equal(t, 2, riskLevel)

	riskLevel = GetRiskLevelForPlatform("destructive", SIEMPlatformElastic)
	assert.Equal(t, 90, riskLevel)

	// Test unknown risk level
	riskLevel = GetRiskLevelForPlatform("unknown", SIEMPlatformSplunk)
	assert.Equal(t, "unknown", riskLevel)
}

// TestIntegrityVerifier tests export integrity verification
func TestIntegrityVerifier(t *testing.T) {
	config := IntegrityConfig{
		VerifyOriginalChecksum: true,
		GenerateExportChecksum: true,
	}
	verifier := NewExportIntegrityVerifier(config)
	
	event := createTestAuditEvent()
	exporter := NewJSONExporter(JSONExporterConfig{IncludeIntegrityFields: true})
	
	exportedData, err := exporter.Export(event)
	require.NoError(t, err)

	// Test single event integrity verification
	report, err := verifier.VerifyExportIntegrity(event, exportedData, "JSON")
	require.NoError(t, err)
	require.NotNil(t, report)
	
	assert.Equal(t, event.ID, report.EventID)
	assert.Equal(t, "JSON", report.ExportFormat)
	assert.True(t, report.IntegrityMaintained)
	assert.NotEmpty(t, report.ExportChecksum)

	// Test batch integrity verification
	events := []*models.AuditEvent{event, createTestAuditEvent()}
	batchData, err := exporter.ExportBatch(events)
	require.NoError(t, err)

	batchReport, err := verifier.VerifyBatchExportIntegrity(events, batchData, "JSON", "test_batch")
	require.NoError(t, err)
	require.NotNil(t, batchReport)
	
	assert.Equal(t, "test_batch", batchReport.BatchID)
	assert.Equal(t, len(events), batchReport.TotalEvents)
	assert.True(t, batchReport.IntegrityMaintained)
	assert.NotEmpty(t, batchReport.BatchChecksum)
}

// TestSIEMCompatibilityValidator tests SIEM format validation
func TestSIEMCompatibilityValidator(t *testing.T) {
	platforms := []SIEMPlatform{
		SIEMPlatformGeneric,
		SIEMPlatformSplunk,
		SIEMPlatformQRadar,
	}

	for _, platform := range platforms {
		t.Run(string(platform), func(t *testing.T) {
			validator := NewSIEMCompatibilityValidator(platform, false)
			event := createTestAuditEvent()

			// Test JSON validation
			jsonExporter := NewJSONExporter(JSONExporterConfig{})
			jsonData, err := jsonExporter.Export(event)
			require.NoError(t, err)
			
			result := validator.ValidateJSONFormat(jsonData)
			assert.True(t, result.IsValid)
			assert.Equal(t, "JSON", result.Format)

			// Test CEF validation
			cefExporter := NewCEFExporter(DefaultCEFConfig())
			cefData, err := cefExporter.Export(event)
			require.NoError(t, err)
			
			result = validator.ValidateCEFFormat(cefData)
			assert.True(t, result.IsValid)
			assert.Equal(t, "CEF", result.Format)

			// Test LEEF validation
			leefExporter := NewLEEFExporter(DefaultLEEFConfig())
			leefData, err := leefExporter.Export(event)
			require.NoError(t, err)
			
			result = validator.ValidateLEEFFormat(leefData)
			assert.True(t, result.IsValid)
			assert.Equal(t, "LEEF", result.Format)
		})
	}
}

// TestValidationErrorHandling tests validation error scenarios
func TestValidationErrorHandling(t *testing.T) {
	validator := NewSIEMCompatibilityValidator(SIEMPlatformGeneric, true)

	// Test invalid JSON
	result := validator.ValidateJSONFormat([]byte("invalid json"))
	assert.False(t, result.IsValid)
	assert.Contains(t, result.Errors, "Invalid JSON structure")

	// Test invalid CEF
	result = validator.ValidateCEFFormat([]byte("not cef format"))
	assert.False(t, result.IsValid)
	assert.Contains(t, result.Errors, "Missing CEF header")

	// Test invalid LEEF
	result = validator.ValidateLEEFFormat([]byte("not leef format"))
	assert.False(t, result.IsValid)
	assert.Contains(t, result.Errors, "Missing LEEF header")
}

// TestExporterErrorHandling tests error handling in exporters
func TestExporterErrorHandling(t *testing.T) {
	exporters := []SIEMFormatExporter{
		NewJSONExporter(JSONExporterConfig{}),
		NewCEFExporter(DefaultCEFConfig()),
		NewLEEFExporter(DefaultLEEFConfig()),
	}

	for _, exporter := range exporters {
		t.Run(exporter.GetFormatName(), func(t *testing.T) {
			// Test nil event
			_, err := exporter.Export(nil)
			assert.Error(t, err)

			// Test validation of invalid event
			invalidEvent := &models.AuditEvent{} // Missing required fields
			err = exporter.ValidateEvent(invalidEvent)
			assert.Error(t, err)

			// Test empty batch export
			data, err := exporter.ExportBatch([]*models.AuditEvent{})
			assert.NoError(t, err)
			assert.NotNil(t, data)
		})
	}
}

// TestSIEMCompatibilityTestFunction tests the comprehensive compatibility test
func TestSIEMCompatibilityTestFunction(t *testing.T) {
	event := createTestAuditEvent()
	platforms := []SIEMPlatform{
		SIEMPlatformGeneric,
		SIEMPlatformSplunk,
		SIEMPlatformQRadar,
	}

	results := TestSIEMCompatibility(event, platforms)
	
	// Should have results for all formats
	assert.Contains(t, results, "JSON")
	assert.Contains(t, results, "CEF")
	assert.Contains(t, results, "LEEF")

	// Each format should have results for all platforms
	for _, format := range []string{"JSON", "CEF", "LEEF"} {
		formatResults := results[format]
		assert.Contains(t, formatResults, "generic")
		assert.Contains(t, formatResults, "splunk")
		assert.Contains(t, formatResults, "qradar")
		
		// All results should be valid for a properly formed event
		for platform, result := range formatResults {
			assert.True(t, result.IsValid, "Format %s should be valid for platform %s", format, platform)
		}
	}
}

// Benchmark tests for performance validation
func BenchmarkJSONExport(b *testing.B) {
	exporter := NewJSONExporter(JSONExporterConfig{})
	event := createTestAuditEvent()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.Export(event)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCEFExport(b *testing.B) {
	exporter := NewCEFExporter(DefaultCEFConfig())
	event := createTestAuditEvent()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.Export(event)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLEEFExport(b *testing.B) {
	exporter := NewLEEFExporter(DefaultLEEFConfig())
	event := createTestAuditEvent()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.Export(event)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBatchExport(b *testing.B) {
	exporter := NewJSONExporter(JSONExporterConfig{})
	events := make([]*models.AuditEvent, 100)
	for i := range events {
		events[i] = createTestAuditEvent()
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := exporter.ExportBatch(events)
		if err != nil {
			b.Fatal(err)
		}
	}
}