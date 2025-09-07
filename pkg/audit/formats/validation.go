package formats

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// SIEMCompatibilityValidator validates export formats for SIEM system compatibility
type SIEMCompatibilityValidator struct {
	platform SIEMPlatform
	strict   bool
}

// ValidationResult contains the results of format validation
type ValidationResult struct {
	IsValid          bool                   `json:"is_valid"`
	Format           string                 `json:"format"`
	Platform         string                 `json:"platform,omitempty"`
	Warnings         []string               `json:"warnings,omitempty"`
	Errors           []string               `json:"errors,omitempty"`
	Recommendations  []string               `json:"recommendations,omitempty"`
	ValidatedAt      time.Time              `json:"validated_at"`
	ValidationRules  []string               `json:"validation_rules"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// FormatRequirements defines the requirements for each SIEM format
type FormatRequirements struct {
	RequiredFields    []string `json:"required_fields"`
	OptionalFields    []string `json:"optional_fields"`
	MaxMessageLength  int      `json:"max_message_length"`
	MaxFieldLength    int      `json:"max_field_length"`
	AllowedCharacters string   `json:"allowed_characters"`
	FieldValidation   map[string]string `json:"field_validation"` // field -> regex pattern
}

// NewSIEMCompatibilityValidator creates a new compatibility validator
func NewSIEMCompatibilityValidator(platform SIEMPlatform, strict bool) *SIEMCompatibilityValidator {
	return &SIEMCompatibilityValidator{
		platform: platform,
		strict:   strict,
	}
}

// ValidateJSONFormat validates JSON format for SIEM compatibility
func (v *SIEMCompatibilityValidator) ValidateJSONFormat(data []byte) *ValidationResult {
	result := &ValidationResult{
		Format:          "JSON",
		ValidatedAt:     time.Now().UTC(),
		ValidationRules: []string{"json_structure", "field_presence", "data_types", "siem_compatibility"},
		Metadata:        make(map[string]interface{}),
	}

	if v.platform != SIEMPlatformGeneric {
		result.Platform = string(v.platform)
	}

	// 1. Validate JSON structure
	var jsonData interface{}
	if err := json.Unmarshal(data, &jsonData); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Invalid JSON structure: %v", err))
		result.IsValid = false
		return result
	}

	// 2. Handle both single events and arrays
	var events []map[string]interface{}
	switch jsonData := jsonData.(type) {
	case map[string]interface{}:
		events = []map[string]interface{}{jsonData}
	case []interface{}:
		for i, item := range jsonData {
			if eventMap, ok := item.(map[string]interface{}); ok {
				events = append(events, eventMap)
			} else {
				result.Errors = append(result.Errors, fmt.Sprintf("Array item %d is not a valid event object", i))
			}
		}
	default:
		result.Errors = append(result.Errors, "JSON must be an object or array of objects")
		result.IsValid = false
		return result
	}

	// 3. Validate each event
	requirements := v.getJSONRequirements()
	for i, event := range events {
		v.validateEventFields(event, requirements, result, i)
	}

	// 4. Platform-specific validations
	v.validatePlatformSpecificJSON(events, result)

	// 5. Set overall validity
	result.IsValid = len(result.Errors) == 0

	// 6. Add metadata
	result.Metadata["total_events"] = len(events)
	result.Metadata["json_size"] = len(data)
	result.Metadata["validation_mode"] = v.getValidationMode()

	return result
}

// ValidateCEFFormat validates CEF format for SIEM compatibility
func (v *SIEMCompatibilityValidator) ValidateCEFFormat(data []byte) *ValidationResult {
	result := &ValidationResult{
		Format:          "CEF",
		ValidatedAt:     time.Now().UTC(),
		ValidationRules: []string{"cef_header", "cef_extensions", "field_escaping", "siem_compatibility"},
		Metadata:        make(map[string]interface{}),
	}

	if v.platform != SIEMPlatformGeneric {
		result.Platform = string(v.platform)
	}

	dataStr := string(data)
	lines := strings.Split(strings.TrimSpace(dataStr), "\n")
	
	for i, line := range lines {
		if line == "" {
			continue
		}
		v.validateCEFLine(line, result, i)
	}

	// Platform-specific CEF validations
	v.validatePlatformSpecificCEF(lines, result)

	result.IsValid = len(result.Errors) == 0
	result.Metadata["total_lines"] = len(lines)
	result.Metadata["cef_size"] = len(data)

	return result
}

// ValidateLEEFFormat validates LEEF format for SIEM compatibility
func (v *SIEMCompatibilityValidator) ValidateLEEFFormat(data []byte) *ValidationResult {
	result := &ValidationResult{
		Format:          "LEEF",
		ValidatedAt:     time.Now().UTC(),
		ValidationRules: []string{"leef_header", "leef_attributes", "field_escaping", "siem_compatibility"},
		Metadata:        make(map[string]interface{}),
	}

	if v.platform != SIEMPlatformGeneric {
		result.Platform = string(v.platform)
	}

	dataStr := string(data)
	lines := strings.Split(strings.TrimSpace(dataStr), "\n")
	
	for i, line := range lines {
		if line == "" {
			continue
		}
		v.validateLEEFLine(line, result, i)
	}

	// Platform-specific LEEF validations
	v.validatePlatformSpecificLEEF(lines, result)

	result.IsValid = len(result.Errors) == 0
	result.Metadata["total_lines"] = len(lines)
	result.Metadata["leef_size"] = len(data)

	return result
}

// validateCEFLine validates a single CEF format line
func (v *SIEMCompatibilityValidator) validateCEFLine(line string, result *ValidationResult, lineNum int) {
	// CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
	
	// Check CEF header presence
	if !strings.HasPrefix(line, "CEF:") {
		result.Errors = append(result.Errors, fmt.Sprintf("Line %d: Missing CEF header", lineNum+1))
		return
	}

	// Split header and extensions
	parts := strings.SplitN(line, " ", 2)
	header := parts[0]
	
	// Validate header structure
	headerParts := strings.Split(header, "|")
	if len(headerParts) < 7 {
		result.Errors = append(result.Errors, fmt.Sprintf("Line %d: CEF header must have 7 pipe-separated fields", lineNum+1))
		return
	}

	// Validate CEF version
	if !strings.HasPrefix(headerParts[0], "CEF:0") {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: CEF version should be 0", lineNum+1))
	}

	// Validate severity (must be numeric 0-10)
	severityStr := headerParts[6]
	if !v.isValidCEFSeverity(severityStr) {
		result.Errors = append(result.Errors, fmt.Sprintf("Line %d: CEF severity must be numeric 0-10, got: %s", lineNum+1, severityStr))
	}

	// Validate extensions if present
	if len(parts) > 1 {
		v.validateCEFExtensions(parts[1], result, lineNum)
	}

	// Check field length limits
	if len(line) > 2048 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: CEF line exceeds recommended 2048 character limit", lineNum+1))
	}
}

// validateLEEFLine validates a single LEEF format line
func (v *SIEMCompatibilityValidator) validateLEEFLine(line string, result *ValidationResult, lineNum int) {
	// LEEF format: LEEF:Version|Vendor|Product|Version|EventID|Delimiter|Attributes
	
	// Check LEEF header presence
	if !strings.HasPrefix(line, "LEEF:") {
		result.Errors = append(result.Errors, fmt.Sprintf("Line %d: Missing LEEF header", lineNum+1))
		return
	}

	// Find delimiter (6th field after LEEF:)
	pipeCount := 0
	for i, char := range line {
		if char == '|' {
			pipeCount++
			if pipeCount == 5 {
				if i+1 < len(line) {
					delimiter := string(line[i+1])
					v.validateLEEFAttributes(line[i+2:], delimiter, result, lineNum)
				}
				break
			}
		}
	}

	// Validate LEEF version
	if !strings.HasPrefix(line, "LEEF:2.0") && !strings.HasPrefix(line, "LEEF:1.0") {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: LEEF version should be 1.0 or 2.0", lineNum+1))
	}

	// Check field length limits
	if len(line) > 4096 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: LEEF line exceeds recommended 4096 character limit", lineNum+1))
	}
}

// validateEventFields validates required and optional fields for JSON events
func (v *SIEMCompatibilityValidator) validateEventFields(event map[string]interface{}, requirements FormatRequirements, result *ValidationResult, eventIndex int) {
	// Check required fields
	for _, field := range requirements.RequiredFields {
		if _, exists := event[field]; !exists {
			result.Errors = append(result.Errors, fmt.Sprintf("Event %d: Required field '%s' is missing", eventIndex, field))
		}
	}

	// Validate field types and formats
	for field, value := range event {
		if pattern, hasValidation := requirements.FieldValidation[field]; hasValidation {
			v.validateFieldPattern(field, value, pattern, result, eventIndex)
		}

		// Check field length limits
		if str, ok := value.(string); ok {
			if len(str) > requirements.MaxFieldLength {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Event %d: Field '%s' exceeds maximum length of %d characters", eventIndex, field, requirements.MaxFieldLength))
			}
		}
	}
}

// validateFieldPattern validates field value against regex pattern
func (v *SIEMCompatibilityValidator) validateFieldPattern(field string, value interface{}, pattern string, result *ValidationResult, eventIndex int) {
	str := fmt.Sprintf("%v", value)
	if matched, err := regexp.MatchString(pattern, str); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Event %d: Invalid regex pattern for field '%s': %v", eventIndex, field, err))
	} else if !matched {
		if v.strict {
			result.Errors = append(result.Errors, fmt.Sprintf("Event %d: Field '%s' value '%s' doesn't match required pattern", eventIndex, field, str))
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Event %d: Field '%s' value '%s' doesn't match recommended pattern", eventIndex, field, str))
		}
	}
}

// validateCEFExtensions validates CEF extension fields
func (v *SIEMCompatibilityValidator) validateCEFExtensions(extensions string, result *ValidationResult, lineNum int) {
	// CEF extensions are space-separated key=value pairs
	if extensions == "" {
		return
	}

	// Simple validation - check for proper key=value format
	extensionRegex := regexp.MustCompile(`\w+=[^=\s]*(\s|$)`)
	if !extensionRegex.MatchString(extensions) {
		result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: CEF extensions may not be properly formatted", lineNum+1))
	}
}

// validateLEEFAttributes validates LEEF attribute fields
func (v *SIEMCompatibilityValidator) validateLEEFAttributes(attributes, delimiter string, result *ValidationResult, lineNum int) {
	if attributes == "" {
		return
	}

	// LEEF attributes are delimiter-separated key=value pairs
	attributePairs := strings.Split(attributes, delimiter)
	for _, pair := range attributePairs {
		if pair == "" {
			continue
		}
		if !strings.Contains(pair, "=") {
			result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: LEEF attribute '%s' is not in key=value format", lineNum+1, pair))
		}
	}
}

// Platform-specific validation methods
func (v *SIEMCompatibilityValidator) validatePlatformSpecificJSON(events []map[string]interface{}, result *ValidationResult) {
	switch v.platform {
	case SIEMPlatformSplunk:
		v.validateSplunkCompatibility(events, result)
	case SIEMPlatformQRadar:
		v.validateQRadarCompatibility(events, result)
	case SIEMPlatformSentinel:
		v.validateSentinelCompatibility(events, result)
	case SIEMPlatformElastic:
		v.validateElasticCompatibility(events, result)
	}
}

func (v *SIEMCompatibilityValidator) validatePlatformSpecificCEF(lines []string, result *ValidationResult) {
	if v.platform == SIEMPlatformSplunk {
		// Splunk-specific CEF validations
		for i, line := range lines {
			if len(line) > 2048 {
				result.Warnings = append(result.Warnings, fmt.Sprintf("Line %d: Splunk recommends CEF lines under 2048 characters", i+1))
			}
		}
	}
}

func (v *SIEMCompatibilityValidator) validatePlatformSpecificLEEF(lines []string, result *ValidationResult) {
	if v.platform == SIEMPlatformQRadar {
		// QRadar-specific LEEF validations
		for i, line := range lines {
			if !strings.HasPrefix(line, "LEEF:2.0") {
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Line %d: QRadar performs better with LEEF 2.0 format", i+1))
			}
		}
	}
}

// Platform-specific compatibility validators
func (v *SIEMCompatibilityValidator) validateSplunkCompatibility(events []map[string]interface{}, result *ValidationResult) {
	for i, event := range events {
		// Check for Splunk CIM compliance
		if _, hasTime := event["index_time"]; !hasTime {
			if _, hasTimestamp := event["timestamp"]; hasTimestamp {
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Event %d: Consider using 'index_time' field for better Splunk integration", i))
			}
		}
		
		// Check for user field
		if _, hasUser := event["user"]; !hasUser {
			if _, hasUserId := event["user_id"]; hasUserId {
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Event %d: Consider mapping 'user_id' to 'user' for Splunk CIM compliance", i))
			}
		}
	}
}

func (v *SIEMCompatibilityValidator) validateQRadarCompatibility(events []map[string]interface{}, result *ValidationResult) {
	for i, event := range events {
		// Check for QRadar DSM standard fields
		requiredQRadarFields := []string{"EventTime", "SourceIP", "UserName"}
		for _, field := range requiredQRadarFields {
			if _, exists := event[field]; !exists {
				result.Recommendations = append(result.Recommendations, fmt.Sprintf("Event %d: Consider adding '%s' field for better QRadar integration", i, field))
			}
		}
	}
}

func (v *SIEMCompatibilityValidator) validateSentinelCompatibility(events []map[string]interface{}, result *ValidationResult) {
	for i, event := range events {
		// Check for Microsoft Sentinel required fields
		if _, hasTimeGenerated := event["TimeGenerated"]; !hasTimeGenerated {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Event %d: Consider using 'TimeGenerated' field for Sentinel compatibility", i))
		}
	}
}

func (v *SIEMCompatibilityValidator) validateElasticCompatibility(events []map[string]interface{}, result *ValidationResult) {
	for i, event := range events {
		// Check for Elastic ECS compliance
		if _, hasTimestamp := event["@timestamp"]; !hasTimestamp {
			result.Recommendations = append(result.Recommendations, fmt.Sprintf("Event %d: Consider using '@timestamp' field for Elastic ECS compliance", i))
		}
	}
}

// Helper methods
func (v *SIEMCompatibilityValidator) getJSONRequirements() FormatRequirements {
	return FormatRequirements{
		RequiredFields:   []string{"timestamp", "event_id", "event_type", "user_id"},
		OptionalFields:   []string{"severity", "message", "cluster_name", "namespace"},
		MaxMessageLength: 8192,
		MaxFieldLength:   2048,
		FieldValidation: map[string]string{
			"timestamp": `\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z?`,
			"event_id":  `^[a-zA-Z0-9_-]+$`,
			"user_id":   `^[a-zA-Z0-9_@.-]+$`,
		},
	}
}

func (v *SIEMCompatibilityValidator) isValidCEFSeverity(severity string) bool {
	severityRegex := regexp.MustCompile(`^([0-9]|10)$`)
	return severityRegex.MatchString(severity)
}

func (v *SIEMCompatibilityValidator) getValidationMode() string {
	if v.strict {
		return "strict"
	}
	return "lenient"
}

// TestSIEMCompatibility runs a comprehensive compatibility test
func TestSIEMCompatibility(event *models.AuditEvent, platforms []SIEMPlatform) map[string]map[string]*ValidationResult {
	results := make(map[string]map[string]*ValidationResult)
	
	formats := []struct {
		name     string
		exporter SIEMFormatExporter
	}{
		{"JSON", NewJSONExporter(JSONExporterConfig{})},
		{"CEF", NewCEFExporter(DefaultCEFConfig())},
		{"LEEF", NewLEEFExporter(DefaultLEEFConfig())},
	}

	for _, format := range formats {
		results[format.name] = make(map[string]*ValidationResult)
		
		// Export event to format
		exportedData, err := format.exporter.Export(event)
		if err != nil {
			// Create error result
			errorResult := &ValidationResult{
				IsValid:     false,
				Format:      format.name,
				Errors:      []string{fmt.Sprintf("Export failed: %v", err)},
				ValidatedAt: time.Now().UTC(),
			}
			results[format.name]["export_error"] = errorResult
			continue
		}

		// Test against each platform
		for _, platform := range platforms {
			validator := NewSIEMCompatibilityValidator(platform, false)
			
			var result *ValidationResult
			switch format.name {
			case "JSON":
				result = validator.ValidateJSONFormat(exportedData)
			case "CEF":
				result = validator.ValidateCEFFormat(exportedData)
			case "LEEF":
				result = validator.ValidateLEEFFormat(exportedData)
			}
			
			results[format.name][string(platform)] = result
		}
		
		// Also test generic compatibility
		genericValidator := NewSIEMCompatibilityValidator(SIEMPlatformGeneric, false)
		var genericResult *ValidationResult
		switch format.name {
		case "JSON":
			genericResult = genericValidator.ValidateJSONFormat(exportedData)
		case "CEF":
			genericResult = genericValidator.ValidateCEFFormat(exportedData)
		case "LEEF":
			genericResult = genericValidator.ValidateLEEFFormat(exportedData)
		}
		results[format.name]["generic"] = genericResult
	}

	return results
}