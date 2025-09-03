package nlp

import (
	"fmt"
	"strings"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ErrorHandler provides user-friendly error handling and messaging for NLP operations
type ErrorHandler struct {
	parser           *models.ErrorParser
	suggestionEngine *SuggestionEngine
}

// NewErrorHandler creates a new error handler with parser and suggestion engine
func NewErrorHandler() *ErrorHandler {
	return &ErrorHandler{
		parser:           models.NewErrorParser(),
		suggestionEngine: NewSuggestionEngine(),
	}
}

// ErrorTemplate represents a template for formatting error messages
type ErrorTemplate struct {
	Icon        string
	Title       string
	Description string
	Suggestion  string
	Examples    []string
	Severity    string // "info", "warning", "error", "critical"
}

// GetErrorTemplate returns a user-friendly error template based on error type
func (eh *ErrorHandler) GetErrorTemplate(errorType models.ErrorType) ErrorTemplate {
	templates := map[models.ErrorType]ErrorTemplate{
		models.ErrorTypeNLPMalformed: {
			Icon:        "❓",
			Title:       "I didn't understand that command",
			Description: "The command appears to be incomplete or contains unexpected characters.",
			Suggestion:  "Please try rephrasing using clear, simple language.",
			Examples: []string{
				"get pods",
				"show all services",
				"describe deployment nginx",
			},
			Severity: "warning",
		},
		models.ErrorTypeNLPAmbiguous: {
			Icon:        "🤔",
			Title:       "That command is a bit unclear",
			Description: "The command could mean several different things.",
			Suggestion:  "Please be more specific about what you want to do.",
			Examples: []string{
				"Instead of 'that pod' → 'describe pod nginx-123'",
				"Instead of 'fix it' → 'restart deployment my-app'",
				"Instead of 'first one' → 'delete pod my-app-abc123'",
			},
			Severity: "info",
		},
		models.ErrorTypeNLPUnsupported: {
			Icon:        "🚫",
			Title:       "That operation isn't supported",
			Description: "The requested operation is either too complex or not available through natural language commands.",
			Suggestion:  "Try breaking down complex operations into simpler steps.",
			Examples: []string{
				"get pods (to see current resources)",
				"describe service my-service (for detailed info)",
				"scale deployment my-app --replicas=3 (for scaling)",
			},
			Severity: "error",
		},
		models.ErrorTypeNotFound: {
			Icon:        "🔍",
			Title:       "Resource not found",
			Description: "The specified resource doesn't exist in the current namespace.",
			Suggestion:  "Check the resource name and namespace, or list available resources first.",
			Examples: []string{
				"get pods (to see available pods)",
				"get namespaces (to see all namespaces)",
				"get pods -n <namespace> (to check specific namespace)",
			},
			Severity: "warning",
		},
		models.ErrorTypePermissionDenied: {
			Icon:        "🚫",
			Title:       "Permission denied",
			Description: "You don't have the required permissions to perform this operation.",
			Suggestion:  "Check your RBAC permissions or contact your cluster administrator.",
			Examples: []string{
				"kubectl auth can-i <verb> <resource>",
				"Try read-only operations like 'get' or 'describe'",
			},
			Severity: "error",
		},
		models.ErrorTypeConnectionFailed: {
			Icon:        "🔌",
			Title:       "Connection to Kubernetes failed",
			Description: "Unable to connect to the Kubernetes cluster.",
			Suggestion:  "Check your cluster connection and try again in a moment.",
			Examples: []string{
				"kubectl cluster-info",
				"Check your kubeconfig settings",
				"Verify cluster is accessible",
			},
			Severity: "critical",
		},
		models.ErrorTypeTimeout: {
			Icon:        "⏰",
			Title:       "Operation timed out",
			Description: "The operation took too long to complete.",
			Suggestion:  "The cluster might be busy. Try again or use simpler queries.",
			Examples: []string{
				"get pods (instead of complex queries)",
				"Try again in a moment",
				"Check cluster performance",
			},
			Severity: "warning",
		},
	}

	if template, exists := templates[errorType]; exists {
		return template
	}

	// Default template for unknown error types
	return ErrorTemplate{
		Icon:        "❌",
		Title:       "Something went wrong",
		Description: "An unexpected error occurred while processing your command.",
		Suggestion:  "Please try rephrasing your request or try a simpler command.",
		Examples: []string{
			"get pods",
			"get services", 
			"describe pod <name>",
		},
		Severity: "error",
	}
}

// FormatError creates a comprehensive, user-friendly error message
func (eh *ErrorHandler) FormatError(kubectlError *models.KubectlError, sessionContext *models.SessionContext) string {
	if kubectlError == nil {
		return eh.formatUnknownError()
	}

	template := eh.GetErrorTemplate(kubectlError.Type)
	
	var message strings.Builder
	
	// Header with icon and title
	message.WriteString(fmt.Sprintf("%s **%s**\n\n", template.Icon, template.Title))
	
	// Error description
	message.WriteString(fmt.Sprintf("**What happened:** %s\n\n", template.Description))
	
	// Specific error message if available
	if kubectlError.Message != "" && kubectlError.Message != template.Description {
		message.WriteString(fmt.Sprintf("**Details:** %s\n\n", kubectlError.Message))
	}
	
	// Resource context if available
	if kubectlError.Resource != "" {
		message.WriteString(fmt.Sprintf("**Resource:** %s", kubectlError.Resource))
		if kubectlError.Namespace != "" {
			message.WriteString(fmt.Sprintf(" (namespace: %s)", kubectlError.Namespace))
		}
		message.WriteString("\n\n")
	}
	
	// Suggestion section
	message.WriteString(fmt.Sprintf("**💡 What to try next:** %s\n\n", template.Suggestion))
	
	// Get contextual suggestions if we have session context
	var suggestions []string
	if sessionContext != nil {
		suggestions = eh.suggestionEngine.GetContextualSuggestions("", sessionContext)
	} else {
		suggestions = template.Examples
	}
	
	// Format suggestions
	if len(suggestions) > 0 {
		message.WriteString("**Examples:**\n")
		for i, suggestion := range suggestions {
			message.WriteString(fmt.Sprintf("• `%s`\n", suggestion))
			if i >= 2 { // Limit to 3 examples for readability
				break
			}
		}
	}
	
	// Recovery information
	if kubectlError.Recoverable {
		message.WriteString("\n✅ *This issue can usually be resolved by trying the suggestions above.*")
	} else {
		message.WriteString("\n⚠️ *This may require administrator assistance to resolve.*")
	}
	
	return message.String()
}

// FormatNLPError specifically handles NLP processing errors with enhanced suggestions
func (eh *ErrorHandler) FormatNLPError(input string, errorType models.ErrorType, sessionContext *models.SessionContext) string {
	// Get the error template
	template := eh.GetErrorTemplate(errorType)
	
	var message strings.Builder
	
	// Header
	message.WriteString(fmt.Sprintf("%s **%s**\n\n", template.Icon, template.Title))
	
	// Show the problematic input
	if input != "" {
		message.WriteString(fmt.Sprintf("**Your command:** `%s`\n\n", input))
	}
	
	// Description
	message.WriteString(fmt.Sprintf("**Issue:** %s\n\n", template.Description))
	
	// Specific suggestions based on the input
	suggestions := eh.suggestionEngine.SuggestCorrections(input, errorType)
	
	if len(suggestions) > 0 {
		message.WriteString("**💡 Try instead:**\n")
		for i, suggestion := range suggestions {
			message.WriteString(fmt.Sprintf("• `%s`\n", suggestion))
			if i >= 2 { // Limit to 3 suggestions
				break
			}
		}
		message.WriteString("\n")
	}
	
	// Contextual help if available
	if sessionContext != nil && len(sessionContext.ReferenceableItems) > 0 {
		contextSuggestions := eh.suggestionEngine.GetContextualSuggestions(input, sessionContext)
		if len(contextSuggestions) > 0 {
			message.WriteString("**Based on your recent activity:**\n")
			for i, suggestion := range contextSuggestions {
				message.WriteString(fmt.Sprintf("• `%s`\n", suggestion))
				if i >= 1 { // Limit to 2 contextual suggestions
					break
				}
			}
			message.WriteString("\n")
		}
	}
	
	// General examples if no specific suggestions
	if len(suggestions) == 0 {
		message.WriteString("**Common commands:**\n")
		for _, example := range template.Examples {
			message.WriteString(fmt.Sprintf("• `%s`\n", example))
		}
		message.WriteString("\n")
	}
	
	// Footer based on severity
	switch template.Severity {
	case "info":
		message.WriteString("💬 *Just need a bit more clarity to help you better!*")
	case "warning":  
		message.WriteString("⚠️ *Please try one of the suggestions above.*")
	case "error":
		message.WriteString("❌ *This operation isn't available, but you can try the alternatives above.*")
	case "critical":
		message.WriteString("🚨 *There may be a connectivity issue. Please try again shortly.*")
	default:
		message.WriteString("✨ *Try the suggestions above and I'll be happy to help!*")
	}
	
	return message.String()
}

// FormatKubectlError handles kubectl-specific errors with recovery suggestions
func (eh *ErrorHandler) FormatKubectlError(kubectlError *models.KubectlError, originalInput string, sessionContext *models.SessionContext) string {
	if kubectlError == nil {
		return eh.formatUnknownError()
	}
	
	template := eh.GetErrorTemplate(kubectlError.Type)
	
	var message strings.Builder
	
	// Header
	message.WriteString(fmt.Sprintf("%s **%s**\n\n", template.Icon, template.Title))
	
	// Original command context
	if originalInput != "" {
		message.WriteString(fmt.Sprintf("**Your command:** \"%s\"\n", originalInput))
	}
	
	// Generated kubectl command if available
	if kubectlError.Code != "" {
		message.WriteString(fmt.Sprintf("**Kubectl error:** %s\n\n", kubectlError.Code))
	}
	
	// Error details
	message.WriteString(fmt.Sprintf("**What happened:** %s\n\n", kubectlError.Message))
	
	// Resource context
	if kubectlError.Resource != "" {
		resourceInfo := kubectlError.Resource
		if kubectlError.Namespace != "" {
			resourceInfo += fmt.Sprintf(" (in namespace: %s)", kubectlError.Namespace)
		}
		message.WriteString(fmt.Sprintf("**Resource:** %s\n\n", resourceInfo))
	}
	
	// Recovery suggestions
	message.WriteString(fmt.Sprintf("**💡 How to fix this:** %s\n\n", kubectlError.Suggestion))
	
	// Additional contextual suggestions
	if sessionContext != nil {
		contextualSuggestions := eh.suggestionEngine.GetContextualSuggestions(originalInput, sessionContext)
		if len(contextualSuggestions) > 0 {
			message.WriteString("**You can also try:**\n")
			for i, suggestion := range contextualSuggestions {
				message.WriteString(fmt.Sprintf("• `%s`\n", suggestion))
				if i >= 2 {
					break
				}
			}
			message.WriteString("\n")
		}
	}
	
	// Recovery status
	if kubectlError.Recoverable {
		message.WriteString("✅ *This can usually be fixed by following the suggestions above.*")
	} else {
		message.WriteString("⚠️ *You may need administrator help or additional permissions.*")
	}
	
	return message.String()
}

// formatUnknownError provides a fallback error message
func (eh *ErrorHandler) formatUnknownError() string {
	return "❌ **Something unexpected happened**\n\n" +
		"**What happened:** An unknown error occurred while processing your command.\n\n" +
		"**💡 What to try next:**\n" +
		"• Try a simpler command like `get pods`\n" +
		"• Check if your cluster is accessible\n" +
		"• Try rephrasing your request\n\n" +
		"**Examples:**\n" +
		"• `get pods`\n" +
		"• `get services`\n" +
		"• `describe pod <name>`\n\n" +
		"✨ *Please try again with a different command.*"
}

// GetSeverityColor returns a color code for different error severities (useful for UI)
func (eh *ErrorHandler) GetSeverityColor(errorType models.ErrorType) string {
	template := eh.GetErrorTemplate(errorType)
	
	colorMap := map[string]string{
		"info":     "#3498db", // Blue
		"warning":  "#f39c12", // Orange
		"error":    "#e74c3c", // Red
		"critical": "#8e44ad", // Purple
	}
	
	if color, exists := colorMap[template.Severity]; exists {
		return color
	}
	
	return "#95a5a6" // Default gray
}