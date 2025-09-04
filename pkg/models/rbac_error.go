// Package models provides RBAC permission error handling for secure Kubernetes operations
package models

import (
	"fmt"
	"strings"
	"time"
)

// RBACPermissionError represents a structured RBAC permission denial error
type RBACPermissionError struct {
	// Basic error information
	User          string    `json:"user"`
	Groups        []string  `json:"groups"`
	Resource      string    `json:"resource"`
	Verb          string    `json:"verb"`
	Namespace     string    `json:"namespace"`
	Reason        string    `json:"reason"`
	
	// Command context
	Command       string    `json:"command"`
	OriginalInput string    `json:"original_input"`
	
	// Suggestions and guidance
	Suggestions   []string  `json:"suggestions"`
	
	// Audit trail
	ValidationID  string    `json:"validation_id"`
	Timestamp     time.Time `json:"timestamp"`
	
	// Error classification
	Type          ErrorType         `json:"type"`
	Severity      ErrorSeverity     `json:"severity"`
	Recoverable   bool              `json:"recoverable"`
	EscalationLevel EscalationLevel `json:"escalation_level"`
}

// ErrorSeverity represents the severity level of RBAC errors
type ErrorSeverity string

const (
	ErrorSeverityLow      ErrorSeverity = "low"      // User can try alternative namespace
	ErrorSeverityMedium   ErrorSeverity = "medium"   // User needs different role
	ErrorSeverityHigh     ErrorSeverity = "high"     // User lacks fundamental permissions
	ErrorSeverityCritical ErrorSeverity = "critical" // System-level RBAC misconfiguration
)

// NewRBACPermissionError creates a new RBAC permission error with proper classification
func NewRBACPermissionError(user string, groups []string, resource, verb, namespace, reason string) *RBACPermissionError {
	rbacError := &RBACPermissionError{
		User:            user,
		Groups:          groups,
		Resource:        resource,
		Verb:            verb,
		Namespace:       namespace,
		Reason:          reason,
		Type:            ErrorTypePermissionDenied,
		Timestamp:       time.Now(),
		ValidationID:    generateValidationID(),
	}

	// Classify error severity and recoverability
	rbacError.classifyError()
	
	// Generate contextual suggestions
	rbacError.generateSuggestions()
	
	return rbacError
}

// Error implements the error interface
func (r *RBACPermissionError) Error() string {
	return fmt.Sprintf("RBAC permission denied: user '%s' cannot '%s' resource '%s' in namespace '%s': %s", 
		r.User, r.Verb, r.Resource, r.Namespace, r.Reason)
}

// GetUserFriendlyMessage returns a user-friendly explanation of the permission denial
func (r *RBACPermissionError) GetUserFriendlyMessage() string {
	var msg strings.Builder
	
	msg.WriteString("🔒 Permission Denied\n\n")
	
	// Explain what was attempted
	if r.OriginalInput != "" {
		msg.WriteString(fmt.Sprintf("You asked: \"%s\"\n", r.OriginalInput))
	}
	if r.Command != "" {
		msg.WriteString(fmt.Sprintf("This translates to: %s\n\n", r.Command))
	}
	
	// Explain why it was denied
	msg.WriteString("❌ Access Denied Because:\n")
	msg.WriteString(fmt.Sprintf("• You don't have permission to '%s' %s", r.Verb, r.Resource))
	if r.Namespace != "" {
		msg.WriteString(fmt.Sprintf(" in namespace '%s'", r.Namespace))
	}
	msg.WriteString("\n")
	
	// Add specific reason from Kubernetes
	if r.Reason != "" && r.Reason != "Permission denied by Kubernetes RBAC" {
		msg.WriteString(fmt.Sprintf("• System reason: %s\n", r.Reason))
	}
	
	// Explain user context
	msg.WriteString(fmt.Sprintf("• Your user: %s\n", r.User))
	if len(r.Groups) > 0 {
		msg.WriteString(fmt.Sprintf("• Your groups: %s\n", strings.Join(r.Groups, ", ")))
	}
	
	// Add suggestions if available
	if len(r.Suggestions) > 0 {
		msg.WriteString("\n💡 What You Can Do:\n")
		for _, suggestion := range r.Suggestions {
			msg.WriteString(fmt.Sprintf("• %s\n", suggestion))
		}
	}
	
	// Add severity-specific guidance
	switch r.Severity {
	case ErrorSeverityLow:
		msg.WriteString("\nℹ️ This is likely a namespace access issue that can be resolved quickly.")
	case ErrorSeverityMedium:
		msg.WriteString("\n⚠️ You may need additional role permissions from your cluster administrator.")
	case ErrorSeverityHigh:
		msg.WriteString("\n🚨 This requires significant permission changes from your cluster administrator.")
	case ErrorSeverityCritical:
		msg.WriteString("\n💥 This may indicate a system configuration issue. Contact support immediately.")
	}
	
	return msg.String()
}

// GetTechnicalDetails returns technical details for debugging and audit purposes
func (r *RBACPermissionError) GetTechnicalDetails() map[string]interface{} {
	return map[string]interface{}{
		"validation_id":     r.ValidationID,
		"timestamp":         r.Timestamp.Format(time.RFC3339),
		"user":              r.User,
		"groups":            r.Groups,
		"resource":          r.Resource,
		"verb":              r.Verb,
		"namespace":         r.Namespace,
		"reason":            r.Reason,
		"severity":          r.Severity,
		"type":              r.Type,
		"recoverable":       r.Recoverable,
		"escalation_level":  r.EscalationLevel,
		"command":           r.Command,
		"original_input":    r.OriginalInput,
		"suggestions_count": len(r.Suggestions),
	}
}

// ToKubectlError converts RBACPermissionError to the standard KubectlError format
func (r *RBACPermissionError) ToKubectlError() *KubectlError {
	// Generate recovery actions based on suggestions
	recoveryActions := make([]RecoveryAction, 0, len(r.Suggestions))
	for _, suggestion := range r.Suggestions {
		recoveryActions = append(recoveryActions, RecoveryAction{
			Type:        RecoveryActionRequestPermission,
			Description: suggestion,
			Command:     "", // No direct command for permission requests
			RiskLevel:   "low",
		})
	}
	
	return &KubectlError{
		Type:               r.Type,
		Code:               "RBAC_PERMISSION_DENIED",
		Message:            r.Error(),
		Suggestion:         r.GetPrimarySuggestion(),
		Resource:           r.Resource,
		Namespace:          r.Namespace,
		Recoverable:        r.Recoverable,
		RecoveryActions:    recoveryActions,
		EscalationLevel:    r.EscalationLevel,
		RetryRecommended:   false, // RBAC errors shouldn't be retried without permission changes
		MaxRetries:         0,
	}
}

// classifyError classifies the error severity and recoverability
func (r *RBACPermissionError) classifyError() {
	// Classify based on verb and resource type
	switch r.Verb {
	case "get", "list", "watch":
		// Read operations - usually low to medium severity
		if r.Resource == "pods" || r.Resource == "services" {
			r.Severity = ErrorSeverityLow
			r.EscalationLevel = EscalationLevelNone
		} else {
			r.Severity = ErrorSeverityMedium
			r.EscalationLevel = EscalationLevelMedium
		}
		r.Recoverable = true
		
	case "create", "update", "patch":
		// Write operations - medium to high severity
		if r.isClusterScopeResource() {
			r.Severity = ErrorSeverityHigh
			r.EscalationLevel = EscalationLevelHigh
		} else {
			r.Severity = ErrorSeverityMedium
			r.EscalationLevel = EscalationLevelMedium
		}
		r.Recoverable = true
		
	case "delete", "deletecollection":
		// Delete operations - high to critical severity
		if r.isClusterScopeResource() || r.isCriticalResource() {
			r.Severity = ErrorSeverityCritical
			r.EscalationLevel = EscalationLevelCritical
		} else {
			r.Severity = ErrorSeverityHigh
			r.EscalationLevel = EscalationLevelHigh
		}
		r.Recoverable = true
		
	default:
		// Unknown verbs - medium severity by default
		r.Severity = ErrorSeverityMedium
		r.EscalationLevel = EscalationLevelMedium
		r.Recoverable = true
	}
	
	// Check for system-level issues
	if strings.Contains(r.Reason, "system:") || 
	   strings.Contains(r.Reason, "cluster-admin") ||
	   len(r.Groups) == 0 {
		r.Severity = ErrorSeverityCritical
		r.EscalationLevel = EscalationLevelCritical
	}
}

// generateSuggestions generates contextual suggestions for resolving the permission issue
func (r *RBACPermissionError) generateSuggestions() {
	suggestions := []string{}
	
	// Verb-specific suggestions
	switch r.Verb {
	case "get", "list", "watch":
		suggestions = append(suggestions, fmt.Sprintf("Request read access to %s in namespace '%s'", r.Resource, r.Namespace))
		suggestions = append(suggestions, "Try a different namespace where you have read permissions")
		suggestions = append(suggestions, "Ask your team lead to add you to a role with view permissions")
		
	case "create":
		suggestions = append(suggestions, fmt.Sprintf("Request create permission for %s in namespace '%s'", r.Resource, r.Namespace))
		suggestions = append(suggestions, "Check if you have a personal/development namespace for testing")
		suggestions = append(suggestions, "Consider using 'kubectl auth can-i create %s' to check permissions")
		
	case "update", "patch":
		suggestions = append(suggestions, fmt.Sprintf("Request update permission for %s in namespace '%s'", r.Resource, r.Namespace))
		suggestions = append(suggestions, "Verify the resource exists and you have access to it")
		
	case "delete", "deletecollection":
		suggestions = append(suggestions, fmt.Sprintf("Request delete permission for %s in namespace '%s'", r.Resource, r.Namespace))
		suggestions = append(suggestions, "Consider if this deletion is really necessary - destructive operations require elevated permissions")
		suggestions = append(suggestions, "Ask a cluster administrator to review and perform the deletion if approved")
	}
	
	// Resource-specific suggestions
	if r.isClusterScopeResource() {
		suggestions = append(suggestions, "This is a cluster-scoped resource requiring ClusterRole permissions")
		suggestions = append(suggestions, "Contact your cluster administrator for cluster-wide permissions")
	}
	
	// Namespace-specific suggestions
	if r.Namespace != "" && r.Namespace != "default" {
		suggestions = append(suggestions, "Try the 'default' namespace if appropriate")
		suggestions = append(suggestions, fmt.Sprintf("Verify namespace '%s' exists and you have access", r.Namespace))
	}
	
	// General suggestions
	suggestions = append(suggestions, "Use 'kubectl auth can-i --list' to see your current permissions")
	suggestions = append(suggestions, "Contact your cluster administrator to review your RBAC configuration")
	
	r.Suggestions = suggestions
}

// GetPrimarySuggestion returns the most relevant suggestion
func (r *RBACPermissionError) GetPrimarySuggestion() string {
	if len(r.Suggestions) > 0 {
		return r.Suggestions[0]
	}
	return "Contact your cluster administrator to review your permissions"
}

// isClusterScopeResource returns true if the resource is cluster-scoped
func (r *RBACPermissionError) isClusterScopeResource() bool {
	clusterResources := map[string]bool{
		"nodes":                    true,
		"persistentvolumes":        true,
		"clusterroles":            true,
		"clusterrolebindings":     true,
		"customresourcedefinitions": true,
		"storageclasses":          true,
		"namespaces":              true,
	}
	
	return clusterResources[r.Resource]
}

// isCriticalResource returns true if the resource is considered critical
func (r *RBACPermissionError) isCriticalResource() bool {
	criticalResources := map[string]bool{
		"namespaces":           true,
		"nodes":                true,
		"clusterroles":         true,
		"clusterrolebindings":  true,
		"secrets":              true,
		"serviceaccounts":      true,
	}
	
	return criticalResources[r.Resource]
}

// generateValidationID generates a unique validation ID for audit purposes
func generateValidationID() string {
	return fmt.Sprintf("rbac_error_%d", time.Now().UnixNano())
}

// RBAC-specific recovery actions (extending existing RecoveryActionType)
const (
	RecoveryActionRequestPermission RecoveryActionType = "request_permission"
	RecoveryActionChangeNamespace   RecoveryActionType = "change_namespace"  
	RecoveryActionContactAdmin      RecoveryActionType = "contact_admin"
	RecoveryActionCheckPermissions  RecoveryActionType = "check_permissions"
)

// RBACErrorParser provides parsing and enhancement of RBAC-related errors
type RBACErrorParser struct {
	baseParser *ErrorParser
}

// NewRBACErrorParser creates a new RBAC error parser
func NewRBACErrorParser() *RBACErrorParser {
	return &RBACErrorParser{
		baseParser: NewErrorParser(),
	}
}

// ParseRBACError parses RBAC errors and enhances them with contextual information
func (p *RBACErrorParser) ParseRBACError(err error, context map[string]interface{}) *RBACPermissionError {
	if rbacErr, ok := err.(*RBACPermissionError); ok {
		// Already an RBACPermissionError, enhance with context
		p.enhanceWithContext(rbacErr, context)
		return rbacErr
	}
	
	// Try to parse as general kubectl error and convert
	kubectlErr := p.baseParser.ParseError(err.Error(), "")
	if kubectlErr.Type == ErrorTypePermissionDenied {
		return p.convertToRBACError(kubectlErr, context)
	}
	
	return nil
}

// enhanceWithContext enhances RBAC error with additional context information
func (p *RBACErrorParser) enhanceWithContext(rbacErr *RBACPermissionError, context map[string]interface{}) {
	if context == nil {
		return
	}
	
	// Add command context if available
	if cmd, ok := context["command"].(string); ok && rbacErr.Command == "" {
		rbacErr.Command = cmd
	}
	
	// Add original input if available
	if input, ok := context["original_input"].(string); ok && rbacErr.OriginalInput == "" {
		rbacErr.OriginalInput = input
	}
	
	// Add client IP if available for audit trail
	if _, ok := context["client_ip"].(string); ok {
		// Refresh timestamp with context when client IP is available
		rbacErr.Timestamp = time.Now()
	}
}

// convertToRBACError converts a generic permission error to RBAC error
func (p *RBACErrorParser) convertToRBACError(kubectlErr *KubectlError, context map[string]interface{}) *RBACPermissionError {
	rbacErr := &RBACPermissionError{
		Type:            kubectlErr.Type,
		Resource:        kubectlErr.Resource,
		Namespace:       kubectlErr.Namespace,
		Reason:          kubectlErr.Message,
		Timestamp:       time.Now(),
		ValidationID:    generateValidationID(),
		Recoverable:     kubectlErr.Recoverable,
		EscalationLevel: kubectlErr.EscalationLevel,
	}
	
	// Extract user information from context
	if context != nil {
		if user, ok := context["user"].(string); ok {
			rbacErr.User = user
		}
		if groups, ok := context["groups"].([]string); ok {
			rbacErr.Groups = groups
		}
		if verb, ok := context["verb"].(string); ok {
			rbacErr.Verb = verb
		}
	}
	
	// Classify and generate suggestions
	rbacErr.classifyError()
	rbacErr.generateSuggestions()
	
	return rbacErr
}