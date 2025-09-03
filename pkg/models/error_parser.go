package models

import (
	"fmt"
	"regexp"
	"strings"
)

// ErrorParser provides structured parsing of kubectl error messages
type ErrorParser struct{}

// NewErrorParser creates a new error parser
func NewErrorParser() *ErrorParser {
	return &ErrorParser{}
}

// KubectlError represents a structured kubectl error
type KubectlError struct {
	Type             ErrorType         `json:"type"`
	Code             string            `json:"code"`
	Message          string            `json:"message"`
	Suggestion       string            `json:"suggestion"`
	Resource         string            `json:"resource,omitempty"`
	Namespace        string            `json:"namespace,omitempty"`
	Recoverable      bool              `json:"recoverable"`
	RecoveryActions  []RecoveryAction  `json:"recoveryActions,omitempty"`
	RollbackSuggestion string          `json:"rollbackSuggestion,omitempty"`
	EscalationLevel  EscalationLevel   `json:"escalationLevel"`
	RetryRecommended bool              `json:"retryRecommended"`
	MaxRetries       int               `json:"maxRetries,omitempty"`
}

// ErrorType represents different categories of kubectl errors
type ErrorType string

const (
	ErrorTypeNotFound          ErrorType = "not_found"
	ErrorTypePermissionDenied  ErrorType = "permission_denied"
	ErrorTypeAlreadyExists     ErrorType = "already_exists"
	ErrorTypeValidationFailed  ErrorType = "validation_failed"
	ErrorTypeConnectionFailed  ErrorType = "connection_failed"
	ErrorTypeTimeout           ErrorType = "timeout"
	ErrorTypeResourceExhausted ErrorType = "resource_exhausted"
	ErrorTypeInvalidArgument   ErrorType = "invalid_argument"
	ErrorTypeInternal          ErrorType = "internal_error"
	ErrorTypeUnknown           ErrorType = "unknown"
	// New error types for NLP processing
	ErrorTypeNLPMalformed      ErrorType = "nlp_malformed"
	ErrorTypeNLPAmbiguous      ErrorType = "nlp_ambiguous"
	ErrorTypeNLPUnsupported    ErrorType = "nlp_unsupported"
)

// EscalationLevel represents how urgently an error needs attention
type EscalationLevel string

const (
	EscalationLevelNone      EscalationLevel = "none"       // User can resolve themselves
	EscalationLevelLow       EscalationLevel = "low"        // May need documentation consultation
	EscalationLevelMedium    EscalationLevel = "medium"     // May need team assistance
	EscalationLevelHigh      EscalationLevel = "high"       // Needs admin or expert help
	EscalationLevelCritical  EscalationLevel = "critical"   // System-wide impact, immediate attention required
)

// ParseError analyzes kubectl error output and returns structured error information
func (ep *ErrorParser) ParseError(errorOutput, stdOutput string) *KubectlError {
	if errorOutput == "" && stdOutput == "" {
		return &KubectlError{
			Type:        ErrorTypeUnknown,
			Code:        "UNKNOWN",
			Message:     "Command failed with no error output",
			Suggestion:  "Check kubectl configuration and cluster connectivity",
			Recoverable: false,
		}
	}

	// Combine error and standard output for analysis
	fullOutput := strings.TrimSpace(errorOutput + "\n" + stdOutput)
	
	// Try to parse different error patterns
	if kubectlErr := ep.parseNotFoundError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parsePermissionError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parseAlreadyExistsError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parseValidationError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parseConnectionError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parseTimeoutError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parseResourceExhaustedError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	if kubectlErr := ep.parseInvalidArgumentError(fullOutput); kubectlErr != nil {
		return kubectlErr
	}
	
	// Default case - unknown error
	return &KubectlError{
		Type:        ErrorTypeUnknown,
		Code:        "UNKNOWN",
		Message:     ep.cleanErrorMessage(fullOutput),
		Suggestion:  "Review the error message and check kubectl documentation",
		Recoverable: false,
	}
}

// parseNotFoundError handles "not found" errors
func (ep *ErrorParser) parseNotFoundError(output string) *KubectlError {
	patterns := []string{
		`([a-zA-Z]+) "([^"]+)" not found`,
		`error from server \(NotFound\): ([a-zA-Z]+)\.([a-zA-Z/.]+) "([^"]+)" not found`,
		`No resources found in ([a-zA-Z0-9-]+) namespace`,
		`the server doesn't have a resource type "([^"]+)"`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		
		if len(matches) > 0 {
			var resource, suggestion string
			
			switch {
			case strings.Contains(pattern, `No resources found`):
				return &KubectlError{
					Type:        ErrorTypeNotFound,
					Code:        "NOT_FOUND",
					Message:     "No resources found in the specified namespace",
					Namespace:   matches[1],
					Suggestion:  fmt.Sprintf("Try checking a different namespace or verify that resources exist in '%s'", matches[1]),
					Recoverable: true,
				}
			case strings.Contains(pattern, `doesn't have a resource type`):
				return &KubectlError{
					Type:        ErrorTypeNotFound,
					Code:        "INVALID_RESOURCE_TYPE",
					Message:     fmt.Sprintf("Unknown resource type: %s", matches[1]),
					Resource:    matches[1],
					Suggestion:  "Check the resource type spelling or use 'kubectl api-resources' to see available types",
					Recoverable: true,
				}
			case len(matches) >= 3:
				resource = matches[2]
				suggestion = fmt.Sprintf("Verify that the %s '%s' exists or check the resource name spelling", matches[1], resource)
			default:
				resource = matches[1]
				suggestion = fmt.Sprintf("Verify that the resource '%s' exists", resource)
			}
			
			return &KubectlError{
				Type:        ErrorTypeNotFound,
				Code:        "NOT_FOUND",
				Message:     matches[0],
				Resource:    resource,
				Suggestion:  suggestion,
				Recoverable: true,
			}
		}
	}
	
	return nil
}

// parsePermissionError handles permission denied errors
func (ep *ErrorParser) parsePermissionError(output string) *KubectlError {
	patterns := []string{
		`error from server \(Forbidden\): (.+)`,
		`User "([^"]+)" cannot ([a-zA-Z]+) resource "([^"]+)"`,
		`forbidden: (.+)`,
		`access denied`,
		`insufficient permissions`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		matches := re.FindStringSubmatch(output)
		
		if len(matches) > 0 {
			suggestion := "Contact your cluster administrator to request the necessary permissions"
			if strings.Contains(output, "User") && len(matches) >= 4 {
				suggestion = fmt.Sprintf("Request '%s' permissions for resource '%s' from your cluster administrator", matches[2], matches[3])
			}
			
			return &KubectlError{
				Type:        ErrorTypePermissionDenied,
				Code:        "FORBIDDEN",
				Message:     matches[0],
				Suggestion:  suggestion,
				Recoverable: false,
			}
		}
	}
	
	return nil
}

// parseAlreadyExistsError handles "already exists" errors
func (ep *ErrorParser) parseAlreadyExistsError(output string) *KubectlError {
	patterns := []string{
		`error from server \(AlreadyExists\): ([a-zA-Z]+) "([^"]+)" already exists`,
		`([a-zA-Z]+) "([^"]+)" already exists`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		
		if len(matches) >= 3 {
			return &KubectlError{
				Type:        ErrorTypeAlreadyExists,
				Code:        "ALREADY_EXISTS",
				Message:     matches[0],
				Resource:    matches[2],
				Suggestion:  fmt.Sprintf("Use 'kubectl apply' to update the existing %s or choose a different name", matches[1]),
				Recoverable: true,
			}
		}
	}
	
	return nil
}

// parseValidationError handles validation failures
func (ep *ErrorParser) parseValidationError(output string) *KubectlError {
	patterns := []string{
		`error validating "([^"]+)": (.+)`,
		`ValidationError\(([^)]+)\): (.+)`,
		`invalid (.+): (.+)`,
		`field is required: (.+)`,
		`field is invalid: (.+)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		
		if len(matches) > 0 {
			return &KubectlError{
				Type:        ErrorTypeValidationFailed,
				Code:        "VALIDATION_FAILED",
				Message:     matches[0],
				Suggestion:  "Review the resource specification and fix validation errors",
				Recoverable: true,
			}
		}
	}
	
	return nil
}

// parseConnectionError handles connection-related errors
func (ep *ErrorParser) parseConnectionError(output string) *KubectlError {
	patterns := []string{
		`unable to connect to the server: (.+)`,
		`connection refused`,
		`no such host`,
		`network is unreachable`,
		`context deadline exceeded`,
		`server could not find the requested resource`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(output) {
			return &KubectlError{
				Type:        ErrorTypeConnectionFailed,
				Code:        "CONNECTION_FAILED",
				Message:     ep.extractFirstLine(output),
				Suggestion:  "Check cluster connectivity, kubectl configuration, and ensure the API server is accessible",
				Recoverable: false,
			}
		}
	}
	
	return nil
}

// parseTimeoutError handles timeout errors
func (ep *ErrorParser) parseTimeoutError(output string) *KubectlError {
	patterns := []string{
		`timeout`,
		`deadline exceeded`,
		`request timeout`,
		`operation timed out`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(output) {
			return &KubectlError{
				Type:        ErrorTypeTimeout,
				Code:        "TIMEOUT",
				Message:     ep.extractFirstLine(output),
				Suggestion:  "The operation timed out. Try increasing the timeout or check cluster performance",
				Recoverable: true,
			}
		}
	}
	
	return nil
}

// parseResourceExhaustedError handles resource quota/limit errors
func (ep *ErrorParser) parseResourceExhaustedError(output string) *KubectlError {
	patterns := []string{
		`exceeded quota`,
		`insufficient (.+) resources`,
		`resource quota exceeded`,
		`limit exceeded`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(output) {
			return &KubectlError{
				Type:        ErrorTypeResourceExhausted,
				Code:        "RESOURCE_EXHAUSTED",
				Message:     ep.extractFirstLine(output),
				Suggestion:  "Check resource quotas and limits. You may need to request more resources or cleanup existing ones",
				Recoverable: true,
			}
		}
	}
	
	return nil
}

// parseInvalidArgumentError handles invalid argument errors
func (ep *ErrorParser) parseInvalidArgumentError(output string) *KubectlError {
	patterns := []string{
		`invalid argument`,
		`unknown flag`,
		`unknown command`,
		`accepts (.+) arg\(s\), received (.+)`,
		`error: (.+) is not a valid (.+)`,
	}
	
	for _, pattern := range patterns {
		re := regexp.MustCompile(`(?i)` + pattern)
		if re.MatchString(output) {
			return &KubectlError{
				Type:        ErrorTypeInvalidArgument,
				Code:        "INVALID_ARGUMENT",
				Message:     ep.extractFirstLine(output),
				Suggestion:  "Review the command syntax and arguments. Use 'kubectl help' for usage information",
				Recoverable: true,
			}
		}
	}
	
	return nil
}

// cleanErrorMessage cleans up error messages for display
func (ep *ErrorParser) cleanErrorMessage(message string) string {
	// Remove common prefixes and suffixes
	cleaners := []string{
		`error from server \([^)]+\): `,
		`Error: `,
		`error: `,
		`kubectl: `,
		`^[\s\n\r]+`,
		`[\s\n\r]+$`,
	}
	
	result := message
	for _, cleaner := range cleaners {
		re := regexp.MustCompile(cleaner)
		result = re.ReplaceAllString(result, "")
	}
	
	return strings.TrimSpace(result)
}

// extractFirstLine extracts the first meaningful line from error output
func (ep *ErrorParser) extractFirstLine(output string) string {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			return trimmed
		}
	}
	return output
}

// FormatErrorForDisplay formats a KubectlError for user-friendly display
func (ep *ErrorParser) FormatErrorForDisplay(kubectlErr *KubectlError) string {
	if kubectlErr == nil {
		return "❌ An unknown error occurred"
	}
	
	var icon string
	switch kubectlErr.Type {
	case ErrorTypeNotFound:
		icon = "🔍"
	case ErrorTypePermissionDenied:
		icon = "🚫"
	case ErrorTypeAlreadyExists:
		icon = "⚠️"
	case ErrorTypeValidationFailed:
		icon = "📋"
	case ErrorTypeConnectionFailed:
		icon = "🔌"
	case ErrorTypeTimeout:
		icon = "⏰"
	case ErrorTypeResourceExhausted:
		icon = "💾"
	case ErrorTypeInvalidArgument:
		icon = "❓"
	default:
		icon = "❌"
	}
	
	result := fmt.Sprintf("%s **%s Error**\n", icon, strings.Title(strings.ReplaceAll(string(kubectlErr.Type), "_", " ")))
	result += fmt.Sprintf("**Message:** %s\n", kubectlErr.Message)
	
	if kubectlErr.Resource != "" {
		result += fmt.Sprintf("**Resource:** %s\n", kubectlErr.Resource)
	}
	
	if kubectlErr.Namespace != "" {
		result += fmt.Sprintf("**Namespace:** %s\n", kubectlErr.Namespace)
	}
	
	result += fmt.Sprintf("**Suggestion:** %s\n", kubectlErr.Suggestion)
	
	if kubectlErr.Recoverable {
		result += "\n✅ This error may be recoverable with the suggested action."
	} else {
		result += "\n❌ This error requires administrative action to resolve."
	}
	
	return result
}

// ParseNLPError analyzes natural language input errors and returns structured error information
func (ep *ErrorParser) ParseNLPError(input string, errorMessage string) *KubectlError {
	if input == "" {
		return &KubectlError{
			Type:        ErrorTypeNLPMalformed,
			Code:        "EMPTY_INPUT",
			Message:     "No command provided",
			Suggestion:  "Please provide a command to execute. For example: 'get pods' or 'describe service nginx'",
			Recoverable: true,
		}
	}

	// Check for common malformed input patterns
	if malformedErr := ep.detectMalformedNLP(input); malformedErr != nil {
		return malformedErr
	}

	// Check for ambiguous input patterns
	if ambiguousErr := ep.detectAmbiguousNLP(input); ambiguousErr != nil {
		return ambiguousErr
	}

	// Check for unsupported operations
	if unsupportedErr := ep.detectUnsupportedNLP(input); unsupportedErr != nil {
		return unsupportedErr
	}

	// Generic NLP error
	return &KubectlError{
		Type:        ErrorTypeNLPUnsupported,
		Code:        "NLP_PROCESSING_FAILED",
		Message:     fmt.Sprintf("Could not understand command: %s", input),
		Suggestion:  "Try rephrasing your command using common kubectl terminology like 'get', 'describe', 'delete', or 'create'",
		Recoverable: true,
	}
}

// detectMalformedNLP identifies clearly malformed natural language input
func (ep *ErrorParser) detectMalformedNLP(input string) *KubectlError {
	input = strings.ToLower(strings.TrimSpace(input))
	
	// Too short or just random characters
	if len(input) < 3 || regexp.MustCompile(`^[^a-zA-Z]*$`).MatchString(input) {
		return &KubectlError{
			Type:        ErrorTypeNLPMalformed,
			Code:        "MALFORMED_INPUT",
			Message:     "Input appears to be malformed or too short",
			Suggestion:  "Please provide a clear command like 'show all pods' or 'get services'",
			Recoverable: true,
		}
	}

	// Common typos or gibberish patterns
	gibberishPatterns := []string{
		`^[qwerty]+$`,     // keyboard mashing
		`^[asdfgh]+$`,     // more keyboard mashing
		`^[0-9]+$`,        // only numbers
		`[!@#$%^&*()]+`,   // excessive special characters
	}

	for _, pattern := range gibberishPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return &KubectlError{
				Type:        ErrorTypeNLPMalformed,
				Code:        "GIBBERISH_INPUT",
				Message:     "Input contains invalid characters or appears to be random text",
				Suggestion:  "Please provide a valid kubernetes command like 'list pods' or 'show deployments'",
				Recoverable: true,
			}
		}
	}

	return nil
}

// detectAmbiguousNLP identifies ambiguous natural language that could mean multiple things
func (ep *ErrorParser) detectAmbiguousNLP(input string) *KubectlError {
	input = strings.ToLower(strings.TrimSpace(input))
	
	ambiguousPatterns := map[string]string{
		`\b(it|that|this|those|these)\b`:     "Please specify what resource you're referring to instead of using pronouns",
		`\bfirst|second|third\b`:             "Please specify which resource by name instead of using ordinal numbers",
		`\bsomething|anything|everything\b`:   "Please be more specific about what you want to do",
		`\bstuff|things\b`:                   "Please specify the exact resource type (pods, services, deployments, etc.)",
		`\bmake it work\b`:                   "Please describe the specific action you want to perform",
	}

	for pattern, suggestion := range ambiguousPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return &KubectlError{
				Type:        ErrorTypeNLPAmbiguous,
				Code:        "AMBIGUOUS_REFERENCE",
				Message:     fmt.Sprintf("Command is ambiguous: %s", input),
				Suggestion:  suggestion,
				Recoverable: true,
			}
		}
	}

	// Check for vague action words
	vague_actions := []string{"do", "handle", "manage", "work with", "deal with", "fix"}
	for _, action := range vague_actions {
		if strings.Contains(input, action) && !strings.Contains(input, "get") && !strings.Contains(input, "describe") {
			return &KubectlError{
				Type:        ErrorTypeNLPAmbiguous,
				Code:        "VAGUE_ACTION",
				Message:     fmt.Sprintf("Action '%s' is too vague", action),
				Suggestion:  "Please use specific actions like 'get', 'describe', 'delete', 'create', or 'update'",
				Recoverable: true,
			}
		}
	}

	return nil
}

// detectUnsupportedNLP identifies operations that are not currently supported
func (ep *ErrorParser) detectUnsupportedNLP(input string) *KubectlError {
	input = strings.ToLower(strings.TrimSpace(input))
	
	// Complex operations that might need breaking down
	complexPatterns := map[string]string{
		`\bmigrate|migration\b`:              "Database migrations are not supported through natural language commands",
		`\bbackup|restore\b`:                 "Backup and restore operations require specialized tools and are not supported",
		`\binstall.*operator\b`:              "Operator installation should be done through Helm or kubectl apply with proper manifests",
		`\bupgrade.*cluster\b`:               "Cluster upgrades require careful planning and should be done through your cloud provider or cluster admin tools",
		`\bdelete.*cluster\b`:                "Cluster deletion is not supported for safety reasons",
		`\bcomplex.*query\b`:                 "Complex queries may need to be broken down into simpler commands",
	}

	for pattern, reason := range complexPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return &KubectlError{
				Type:        ErrorTypeNLPUnsupported,
				Code:        "UNSUPPORTED_OPERATION",
				Message:     fmt.Sprintf("Operation not supported: %s", input),
				Suggestion:  reason + ". Try using simpler, specific commands like 'get pods' or 'describe service'",
				Recoverable: false,
			}
		}
	}

	// Check for non-kubernetes related requests
	nonK8sPatterns := []string{
		`\b(email|send email|notification)\b`,
		`\b(file system|ls|cd|mkdir)\b`,
		`\b(database|sql|query)\b`,
		`\b(weather|news|internet)\b`,
	}

	for _, pattern := range nonK8sPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			return &KubectlError{
				Type:        ErrorTypeNLPUnsupported,
				Code:        "NON_KUBERNETES",
				Message:     "This appears to be a non-Kubernetes related request",
				Suggestion:  "I can only help with Kubernetes operations like managing pods, services, deployments, etc.",
				Recoverable: false,
			}
		}
	}

	return nil
}

// EnhanceWithRecoveryActions enhances a KubectlError with recovery actions and escalation info
func (ep *ErrorParser) EnhanceWithRecoveryActions(kubectlErr *KubectlError, originalCommand string) *KubectlError {
	if kubectlErr == nil {
		return kubectlErr
	}

	// Create recovery manager to get recovery plans
	recoveryManager := NewRecoveryManager()
	
	// Get context for the recovery plan
	context := map[string]string{
		"originalCommand": originalCommand,
		"resource":       kubectlErr.Resource,
		"namespace":      kubectlErr.Namespace,
	}
	
	// Extract resource type and name if available
	if kubectlErr.Resource != "" {
		parts := strings.Split(kubectlErr.Resource, "/")
		if len(parts) >= 2 {
			context["resourceType"] = parts[0]
			context["name"] = parts[1]
		} else {
			context["resourceType"] = kubectlErr.Resource
		}
	}
	
	// Get recovery plan
	recoveryPlan := recoveryManager.GetRecoveryPlan(kubectlErr.Type, context)
	if recoveryPlan != nil {
		kubectlErr.RecoveryActions = recoveryPlan.Actions
	}
	
	// Set escalation level and retry recommendations based on error type
	kubectlErr.EscalationLevel = ep.determineEscalationLevel(kubectlErr.Type)
	kubectlErr.RetryRecommended = recoveryManager.IsRetryable(kubectlErr.Type)
	kubectlErr.MaxRetries = ep.getMaxRetries(kubectlErr.Type)
	
	// Set rollback suggestions for write operations
	kubectlErr.RollbackSuggestion = ep.generateRollbackSuggestion(originalCommand, kubectlErr.Type)
	
	return kubectlErr
}

// determineEscalationLevel sets appropriate escalation level based on error type
func (ep *ErrorParser) determineEscalationLevel(errorType ErrorType) EscalationLevel {
	escalationMap := map[ErrorType]EscalationLevel{
		ErrorTypeNotFound:         EscalationLevelNone,    // User can fix themselves
		ErrorTypeValidationFailed: EscalationLevelNone,    // Input validation error
		ErrorTypeAlreadyExists:    EscalationLevelNone,    // Can use apply instead of create
		ErrorTypeInvalidArgument:  EscalationLevelLow,     // May need docs consultation
		ErrorTypeTimeout:          EscalationLevelLow,     // May be transient
		ErrorTypePermissionDenied: EscalationLevelMedium,  // Need RBAC changes
		ErrorTypeResourceExhausted: EscalationLevelMedium, // Need quota changes
		ErrorTypeConnectionFailed: EscalationLevelHigh,    // Network/cluster issues
		ErrorTypeInternal:         EscalationLevelHigh,    // Server-side problems
		ErrorTypeNLPMalformed:     EscalationLevelNone,    // User input issue
		ErrorTypeNLPAmbiguous:     EscalationLevelNone,    // User input issue  
		ErrorTypeNLPUnsupported:   EscalationLevelLow,     // May need feature request
		ErrorTypeUnknown:          EscalationLevelMedium,  // Requires investigation
	}
	
	if level, exists := escalationMap[errorType]; exists {
		return level
	}
	return EscalationLevelMedium // Default to medium
}

// getMaxRetries returns recommended max retries for error type
func (ep *ErrorParser) getMaxRetries(errorType ErrorType) int {
	retryMap := map[ErrorType]int{
		ErrorTypeTimeout:          3, // Worth multiple retries
		ErrorTypeConnectionFailed: 3, // Network issues might resolve
		ErrorTypeInternal:         2, // Some server errors are transient
		ErrorTypeResourceExhausted: 1, // Unlikely to resolve quickly
		ErrorTypeNotFound:        0, // Retrying won't help
		ErrorTypePermissionDenied: 0, // Need permission changes
		ErrorTypeValidationFailed: 0, // Input needs fixing
		ErrorTypeAlreadyExists:    0, // Won't change by retrying
		ErrorTypeInvalidArgument:  0, // Command needs fixing
	}
	
	if maxRetries, exists := retryMap[errorType]; exists {
		return maxRetries
	}
	return 1 // Default
}

// generateRollbackSuggestion creates rollback suggestions for failed write operations
func (ep *ErrorParser) generateRollbackSuggestion(originalCommand string, errorType ErrorType) string {
	if originalCommand == "" {
		return ""
	}
	
	command := strings.ToLower(originalCommand)
	
	// Only provide rollback for write operations that might have partial success
	if strings.Contains(command, "create") {
		if errorType == ErrorTypeAlreadyExists {
			return "If the resource was partially created, you may need to delete it first: kubectl delete <resource-type> <resource-name>"
		}
		if errorType == ErrorTypeTimeout {
			return "Check if the resource was created despite the timeout: kubectl get <resource-type> <resource-name>"
		}
	}
	
	if strings.Contains(command, "apply") {
		if errorType == ErrorTypeTimeout || errorType == ErrorTypeConnectionFailed {
			return "Check if changes were applied: kubectl get <resource-type> <resource-name> -o yaml"
		}
		if errorType == ErrorTypeValidationFailed {
			return "Fix the manifest file and try applying again. No rollback needed as changes weren't applied."
		}
	}
	
	if strings.Contains(command, "delete") {
		if errorType == ErrorTypeTimeout {
			return "Check if resource was deleted: kubectl get <resource-type> <resource-name>"
		}
	}
	
	if strings.Contains(command, "patch") || strings.Contains(command, "edit") {
		if errorType == ErrorTypeTimeout || errorType == ErrorTypeConnectionFailed {
			return "Check current resource state and compare with intended changes: kubectl get <resource-type> <resource-name> -o yaml"
		}
	}
	
	if strings.Contains(command, "scale") {
		if errorType == ErrorTypeTimeout {
			return "Check current replica count: kubectl get deployment <deployment-name> -o jsonpath='{.spec.replicas}'"
		}
	}
	
	// No specific rollback suggestion for this command/error combination
	return ""
}