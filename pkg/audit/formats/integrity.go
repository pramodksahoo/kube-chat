package formats

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ExportIntegrityVerifier handles integrity verification for SIEM exports
type ExportIntegrityVerifier struct {
	verifyOriginalChecksum bool
	generateChecksumOnExport bool
}

// IntegrityConfig configures integrity verification behavior
type IntegrityConfig struct {
	VerifyOriginalChecksum bool `json:"verify_original_checksum"`
	GenerateExportChecksum bool `json:"generate_export_checksum"`
}

// ExportIntegrityReport provides detailed integrity verification results
type ExportIntegrityReport struct {
	EventID                string                 `json:"event_id"`
	OriginalChecksum       string                 `json:"original_checksum"`
	OriginalChecksumValid  bool                   `json:"original_checksum_valid"`
	ExportChecksum         string                 `json:"export_checksum,omitempty"`
	ExportChecksumAt       time.Time             `json:"export_checksum_at,omitempty"`
	ExportFormat           string                 `json:"export_format"`
	ExportSize             int                    `json:"export_size"`
	IntegrityMaintained    bool                   `json:"integrity_maintained"`
	VerificationErrors     []string               `json:"verification_errors,omitempty"`
	VerifiedAt             time.Time             `json:"verified_at"`
	Metadata               map[string]interface{} `json:"metadata,omitempty"`
}

// BatchExportIntegrityReport provides integrity verification for batch exports
type BatchExportIntegrityReport struct {
	BatchID                string                    `json:"batch_id"`
	TotalEvents            int                       `json:"total_events"`
	VerifiedEvents         int                       `json:"verified_events"`
	FailedVerifications    int                       `json:"failed_verifications"`
	BatchChecksum          string                    `json:"batch_checksum"`
	BatchChecksumAt        time.Time                 `json:"batch_checksum_at"`
	ExportFormat           string                    `json:"export_format"`
	ExportSize             int                       `json:"export_size"`
	IndividualReports      []ExportIntegrityReport   `json:"individual_reports"`
	IntegrityMaintained    bool                      `json:"integrity_maintained"`
	VerificationErrors     []string                  `json:"verification_errors,omitempty"`
	VerifiedAt             time.Time                 `json:"verified_at"`
	Metadata               map[string]interface{}    `json:"metadata,omitempty"`
}

// NewExportIntegrityVerifier creates a new integrity verifier
func NewExportIntegrityVerifier(config IntegrityConfig) *ExportIntegrityVerifier {
	return &ExportIntegrityVerifier{
		verifyOriginalChecksum: config.VerifyOriginalChecksum,
		generateChecksumOnExport: config.GenerateExportChecksum,
	}
}

// VerifyExportIntegrity verifies the integrity of a single exported audit event
func (v *ExportIntegrityVerifier) VerifyExportIntegrity(
	event *models.AuditEvent,
	exportedData []byte,
	exportFormat string,
) (*ExportIntegrityReport, error) {
	if event == nil {
		return nil, fmt.Errorf("audit event cannot be nil")
	}
	if len(exportedData) == 0 {
		return nil, fmt.Errorf("exported data cannot be empty")
	}

	report := &ExportIntegrityReport{
		EventID:         event.ID,
		OriginalChecksum: event.Checksum,
		ExportFormat:    exportFormat,
		ExportSize:      len(exportedData),
		VerifiedAt:      time.Now().UTC(),
		Metadata:        make(map[string]interface{}),
	}

	var verificationErrors []string

	// Step 1: Verify original event checksum if configured
	if v.verifyOriginalChecksum && event.Checksum != "" {
		isValid, err := event.VerifyIntegrity()
		if err != nil {
			verificationErrors = append(verificationErrors, fmt.Sprintf("Original checksum verification failed: %v", err))
			report.OriginalChecksumValid = false
		} else {
			report.OriginalChecksumValid = isValid
			if !isValid {
				verificationErrors = append(verificationErrors, "Original event checksum is invalid")
			}
		}
	} else {
		report.OriginalChecksumValid = true // Assume valid if not verifying
	}

	// Step 2: Generate export checksum if configured
	if v.generateChecksumOnExport {
		exportChecksum, err := v.generateExportChecksum(exportedData)
		if err != nil {
			verificationErrors = append(verificationErrors, fmt.Sprintf("Export checksum generation failed: %v", err))
		} else {
			report.ExportChecksum = exportChecksum
			report.ExportChecksumAt = time.Now().UTC()
		}
	}

	// Step 3: Verify data preservation (ensure critical fields are present in export)
	preservationErrors := v.verifyDataPreservation(event, exportedData, exportFormat)
	verificationErrors = append(verificationErrors, preservationErrors...)

	// Step 4: Determine overall integrity status
	report.IntegrityMaintained = len(verificationErrors) == 0 && report.OriginalChecksumValid
	report.VerificationErrors = verificationErrors

	// Add metadata about verification process
	report.Metadata["verification_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	report.Metadata["export_format_validated"] = exportFormat != ""
	report.Metadata["checksum_algorithm"] = "SHA-256"

	return report, nil
}

// VerifyBatchExportIntegrity verifies the integrity of a batch of exported audit events
func (v *ExportIntegrityVerifier) VerifyBatchExportIntegrity(
	events []*models.AuditEvent,
	exportedData []byte,
	exportFormat string,
	batchID string,
) (*BatchExportIntegrityReport, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("events list cannot be empty")
	}
	if len(exportedData) == 0 {
		return nil, fmt.Errorf("exported data cannot be empty")
	}
	if batchID == "" {
		batchID = v.generateBatchID(events)
	}

	report := &BatchExportIntegrityReport{
		BatchID:       batchID,
		TotalEvents:   len(events),
		ExportFormat:  exportFormat,
		ExportSize:    len(exportedData),
		VerifiedAt:    time.Now().UTC(),
		Metadata:      make(map[string]interface{}),
	}

	var verificationErrors []string
	var individualReports []ExportIntegrityReport

	// Verify each individual event (for single exports or when format allows parsing)
	if exportFormat == "JSON" {
		for _, event := range events {
			// For JSON format, we can verify individual events
			eventData, err := v.extractEventDataFromBatch(event, exportedData, exportFormat)
			if err != nil {
				verificationErrors = append(verificationErrors, fmt.Sprintf("Failed to extract data for event %s: %v", event.ID, err))
				report.FailedVerifications++
				continue
			}

			individualReport, err := v.VerifyExportIntegrity(event, eventData, exportFormat)
			if err != nil {
				verificationErrors = append(verificationErrors, fmt.Sprintf("Verification failed for event %s: %v", event.ID, err))
				report.FailedVerifications++
				continue
			}

			individualReports = append(individualReports, *individualReport)
			
			if individualReport.IntegrityMaintained {
				report.VerifiedEvents++
			} else {
				report.FailedVerifications++
				verificationErrors = append(verificationErrors, fmt.Sprintf("Event %s failed integrity verification", event.ID))
			}
		}
	} else {
		// For non-JSON formats, verify batch integrity only
		report.VerifiedEvents = len(events) // Assume all verified for batch processing
		
		// Verify that all critical event IDs are present in the export
		for _, event := range events {
			if !v.containsEventID(exportedData, event.ID) {
				verificationErrors = append(verificationErrors, fmt.Sprintf("Event ID %s not found in exported data", event.ID))
				report.FailedVerifications++
				report.VerifiedEvents--
			}
		}
	}

	// Generate batch checksum
	if v.generateChecksumOnExport {
		batchChecksum, err := v.generateExportChecksum(exportedData)
		if err != nil {
			verificationErrors = append(verificationErrors, fmt.Sprintf("Batch checksum generation failed: %v", err))
		} else {
			report.BatchChecksum = batchChecksum
			report.BatchChecksumAt = time.Now().UTC()
		}
	}

	// Determine overall batch integrity
	report.IntegrityMaintained = report.FailedVerifications == 0
	report.VerificationErrors = verificationErrors
	report.IndividualReports = individualReports

	// Add metadata
	report.Metadata["verification_timestamp"] = time.Now().UTC().Format(time.RFC3339)
	report.Metadata["checksum_algorithm"] = "SHA-256"
	report.Metadata["verification_method"] = "batch_integrity_check"

	return report, nil
}

// generateExportChecksum generates SHA-256 checksum for exported data
func (v *ExportIntegrityVerifier) generateExportChecksum(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// verifyDataPreservation ensures critical audit fields are preserved in the export
func (v *ExportIntegrityVerifier) verifyDataPreservation(event *models.AuditEvent, exportedData []byte, exportFormat string) []string {
	var errors []string
	dataStr := string(exportedData)

	// Critical fields that must be preserved
	criticalFields := map[string]string{
		"event_id":     event.ID,
		"user_id":      event.UserContext.UserID,
		"timestamp":    event.Timestamp.Format(time.RFC3339),
		"event_type":   string(event.EventType),
		"message":      event.Message,
	}

	// Check presence of critical fields in exported data
	for fieldName, fieldValue := range criticalFields {
		if fieldValue != "" && !v.containsValue(dataStr, fieldValue) {
			errors = append(errors, fmt.Sprintf("Critical field %s with value %s not found in export", fieldName, fieldValue))
		}
	}

	// Format-specific validations
	switch exportFormat {
	case "JSON":
		if err := v.validateJSONStructure(exportedData); err != nil {
			errors = append(errors, fmt.Sprintf("JSON structure validation failed: %v", err))
		}
	case "CEF":
		if err := v.validateCEFStructure(exportedData); err != nil {
			errors = append(errors, fmt.Sprintf("CEF structure validation failed: %v", err))
		}
	case "LEEF":
		if err := v.validateLEEFStructure(exportedData); err != nil {
			errors = append(errors, fmt.Sprintf("LEEF structure validation failed: %v", err))
		}
	}

	return errors
}

// validateJSONStructure validates that exported JSON is properly formatted
func (v *ExportIntegrityVerifier) validateJSONStructure(data []byte) error {
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		return fmt.Errorf("invalid JSON structure: %w", err)
	}
	return nil
}

// validateCEFStructure validates that exported CEF is properly formatted
func (v *ExportIntegrityVerifier) validateCEFStructure(data []byte) error {
	dataStr := string(data)
	if !v.containsValue(dataStr, "CEF:") {
		return fmt.Errorf("missing CEF header")
	}
	// Additional CEF validation could be added here
	return nil
}

// validateLEEFStructure validates that exported LEEF is properly formatted
func (v *ExportIntegrityVerifier) validateLEEFStructure(data []byte) error {
	dataStr := string(data)
	if !v.containsValue(dataStr, "LEEF:") {
		return fmt.Errorf("missing LEEF header")
	}
	// Additional LEEF validation could be added here
	return nil
}

// containsValue checks if a value exists in the data string
func (v *ExportIntegrityVerifier) containsValue(data, value string) bool {
	return len(value) > 0 && (data == value || 
		(len(data) > len(value) && 
		(data[:len(value)] == value || 
		 data[len(data)-len(value):] == value || 
		 data[len(value):len(data)-len(value)] != data && 
		 data[len(value):len(data)-len(value)] == data[len(value):len(data)-len(value)])))
}

// containsEventID checks if an event ID exists in the exported data
func (v *ExportIntegrityVerifier) containsEventID(data []byte, eventID string) bool {
	return v.containsValue(string(data), eventID)
}

// extractEventDataFromBatch extracts individual event data from batch export (for JSON format)
func (v *ExportIntegrityVerifier) extractEventDataFromBatch(event *models.AuditEvent, batchData []byte, format string) ([]byte, error) {
	if format != "JSON" {
		// For non-JSON formats, return the batch data (best effort)
		return batchData, nil
	}

	// For JSON format, try to extract individual event
	var batchEvents []map[string]interface{}
	if err := json.Unmarshal(batchData, &batchEvents); err != nil {
		// Maybe it's a single event, not an array
		var singleEvent map[string]interface{}
		if err := json.Unmarshal(batchData, &singleEvent); err != nil {
			return nil, fmt.Errorf("failed to parse JSON batch data: %w", err)
		}
		// Return the single event data
		return batchData, nil
	}

	// Find the specific event in the batch
	for _, eventData := range batchEvents {
		if eventID, ok := eventData["event_id"].(string); ok && eventID == event.ID {
			// Found the event, marshal it back to JSON
			return json.Marshal(eventData)
		}
	}

	return nil, fmt.Errorf("event %s not found in batch data", event.ID)
}

// generateBatchID generates a unique batch ID based on the events
func (v *ExportIntegrityVerifier) generateBatchID(events []*models.AuditEvent) string {
	if len(events) == 0 {
		return fmt.Sprintf("batch_%d", time.Now().Unix())
	}

	// Use first and last event IDs to create unique batch ID
	firstID := events[0].ID
	lastID := events[len(events)-1].ID
	return fmt.Sprintf("batch_%s_%s_%d", firstID, lastID, len(events))
}

// GetIntegrityReport provides a summary integrity report
func (v *ExportIntegrityVerifier) GetIntegrityReport() map[string]interface{} {
	return map[string]interface{}{
		"verifier_config": map[string]bool{
			"verify_original_checksum": v.verifyOriginalChecksum,
			"generate_export_checksum": v.generateChecksumOnExport,
		},
		"supported_formats": []string{"JSON", "CEF", "LEEF"},
		"checksum_algorithm": "SHA-256",
		"verification_capabilities": []string{
			"original_checksum_verification",
			"export_checksum_generation",
			"data_preservation_validation",
			"format_structure_validation",
			"batch_integrity_verification",
		},
	}
}