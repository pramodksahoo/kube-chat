package nlp

import (
	"testing"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNewErrorHandler(t *testing.T) {
	eh := NewErrorHandler()
	assert.NotNil(t, eh)
	assert.NotNil(t, eh.parser)
	assert.NotNil(t, eh.suggestionEngine)
}

func TestGetErrorTemplate(t *testing.T) {
	eh := NewErrorHandler()
	
	tests := []struct {
		name      string
		errorType models.ErrorType
		wantIcon  string
		wantTitle string
		severity  string
	}{
		{
			name:      "NLP Malformed Error",
			errorType: models.ErrorTypeNLPMalformed,
			wantIcon:  "❓",
			wantTitle: "I didn't understand that command",
			severity:  "warning",
		},
		{
			name:      "NLP Ambiguous Error",
			errorType: models.ErrorTypeNLPAmbiguous,
			wantIcon:  "🤔",
			wantTitle: "That command is a bit unclear",
			severity:  "info",
		},
		{
			name:      "NLP Unsupported Error",
			errorType: models.ErrorTypeNLPUnsupported,
			wantIcon:  "🚫",
			wantTitle: "That operation isn't supported",
			severity:  "error",
		},
		{
			name:      "Not Found Error",
			errorType: models.ErrorTypeNotFound,
			wantIcon:  "🔍",
			wantTitle: "Resource not found",
			severity:  "warning",
		},
		{
			name:      "Permission Denied Error",
			errorType: models.ErrorTypePermissionDenied,
			wantIcon:  "🚫",
			wantTitle: "Permission denied",
			severity:  "error",
		},
		{
			name:      "Connection Failed Error",
			errorType: models.ErrorTypeConnectionFailed,
			wantIcon:  "🔌",
			wantTitle: "Connection to Kubernetes failed",
			severity:  "critical",
		},
		{
			name:      "Timeout Error",
			errorType: models.ErrorTypeTimeout,
			wantIcon:  "⏰",
			wantTitle: "Operation timed out",
			severity:  "warning",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			template := eh.GetErrorTemplate(tt.errorType)
			assert.Equal(t, tt.wantIcon, template.Icon)
			assert.Equal(t, tt.wantTitle, template.Title)
			assert.Equal(t, tt.severity, template.Severity)
			assert.NotEmpty(t, template.Description)
			assert.NotEmpty(t, template.Suggestion)
		})
	}
}

func TestFormatError(t *testing.T) {
	eh := NewErrorHandler()
	
	tests := []struct {
		name         string
		kubectlError *models.KubectlError
		sessionCtx   *models.SessionContext
		wantContains []string
	}{
		{
			name:         "nil error",
			kubectlError: nil,
			sessionCtx:   nil,
			wantContains: []string{"Something went wrong"},
		},
		{
			name: "NLP malformed error",
			kubectlError: &models.KubectlError{
				Type:        models.ErrorTypeNLPMalformed,
				Code:        "MALFORMED_INPUT",
				Message:     "Input too short",
				Suggestion:  "Try a longer command",
				Recoverable: true,
			},
			sessionCtx:   nil,
			wantContains: []string{"❓", "I didn't understand", "Input too short", "Try a longer command", "✅"},
		},
		{
			name: "kubectl error with resource context",
			kubectlError: &models.KubectlError{
				Type:        models.ErrorTypeNotFound,
				Code:        "NOT_FOUND",
				Message:     "Pod not found",
				Resource:    "nginx-pod",
				Namespace:   "default",
				Suggestion:  "Check the pod name",
				Recoverable: true,
			},
			sessionCtx:   nil,
			wantContains: []string{"🔍", "Resource not found", "nginx-pod", "default", "Check the pod name"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eh.FormatError(tt.kubectlError, tt.sessionCtx)
			
			for _, want := range tt.wantContains {
				assert.Contains(t, result, want, "Result should contain: %s", want)
			}
		})
	}
}

func TestFormatNLPError(t *testing.T) {
	eh := NewErrorHandler()
	
	tests := []struct {
		name       string
		input      string
		errorType  models.ErrorType
		sessionCtx *models.SessionContext
		wantContains []string
	}{
		{
			name:       "malformed input",
			input:      "xyz",
			errorType:  models.ErrorTypeNLPMalformed,
			sessionCtx: nil,
			wantContains: []string{"❓", "Your command:", "xyz", "Try instead:"},
		},
		{
			name:       "ambiguous input",
			input:      "describe that thing",
			errorType:  models.ErrorTypeNLPAmbiguous,
			sessionCtx: nil,
			wantContains: []string{"🤔", "unclear", "describe that thing", "Try instead:"},
		},
		{
			name:       "unsupported operation",
			input:      "migrate database",
			errorType:  models.ErrorTypeNLPUnsupported,
			sessionCtx: nil,
			wantContains: []string{"🚫", "isn't supported", "migrate database"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eh.FormatNLPError(tt.input, tt.errorType, tt.sessionCtx)
			
			for _, want := range tt.wantContains {
				assert.Contains(t, result, want, "Result should contain: %s", want)
			}
		})
	}
}

func TestFormatNLPErrorWithContext(t *testing.T) {
	eh := NewErrorHandler()
	
	// Create session context with some items
	sessionCtx := &models.SessionContext{
		ReferenceableItems: []models.ReferenceItem{
			{
				ID:   "pod-1",
				Type: "pod",
				Name: "nginx-123",
			},
			{
				ID:   "svc-1", 
				Type: "service",
				Name: "web-service",
			},
		},
	}
	
	result := eh.FormatNLPError("describe something", models.ErrorTypeNLPAmbiguous, sessionCtx)
	
	assert.Contains(t, result, "Based on your recent activity:")
	assert.Contains(t, result, "nginx-123")
}

func TestFormatKubectlError(t *testing.T) {
	eh := NewErrorHandler()
	
	tests := []struct {
		name         string
		kubectlError *models.KubectlError
		originalInput string
		sessionCtx   *models.SessionContext
		wantContains []string
	}{
		{
			name:         "nil kubectl error",
			kubectlError: nil,
			originalInput: "get pods",
			sessionCtx:   nil,
			wantContains: []string{"Something unexpected happened"},
		},
		{
			name: "kubectl permission error",
			kubectlError: &models.KubectlError{
				Type:        models.ErrorTypePermissionDenied,
				Code:        "FORBIDDEN",
				Message:     "pods is forbidden",
				Resource:    "pods",
				Suggestion:  "Check RBAC permissions",
				Recoverable: false,
			},
			originalInput: "get pods",
			sessionCtx:   nil,
			wantContains: []string{"🚫", "Permission denied", "get pods", "FORBIDDEN", "pods is forbidden", "Check RBAC permissions", "⚠️"},
		},
		{
			name: "kubectl not found with context",
			kubectlError: &models.KubectlError{
				Type:        models.ErrorTypeNotFound,
				Code:        "NOT_FOUND",
				Message:     "service not found",
				Resource:    "missing-service",
				Namespace:   "default",
				Suggestion:  "Check service name",
				Recoverable: true,
			},
			originalInput: "describe service missing-service",
			sessionCtx: &models.SessionContext{
				ReferenceableItems: []models.ReferenceItem{
					{ID: "svc-1", Type: "service", Name: "web-service"},
				},
			},
			wantContains: []string{"🔍", "Resource not found", "missing-service", "default", "You can also try:", "web-service"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := eh.FormatKubectlError(tt.kubectlError, tt.originalInput, tt.sessionCtx)
			
			for _, want := range tt.wantContains {
				assert.Contains(t, result, want, "Result should contain: %s", want)
			}
		})
	}
}

func TestGetSeverityColor(t *testing.T) {
	eh := NewErrorHandler()
	
	tests := []struct {
		name      string
		errorType models.ErrorType
		wantColor string
	}{
		{
			name:      "info severity",
			errorType: models.ErrorTypeNLPAmbiguous,
			wantColor: "#3498db", // Blue
		},
		{
			name:      "warning severity",
			errorType: models.ErrorTypeNLPMalformed,
			wantColor: "#f39c12", // Orange
		},
		{
			name:      "error severity",
			errorType: models.ErrorTypeNLPUnsupported,
			wantColor: "#e74c3c", // Red
		},
		{
			name:      "critical severity",
			errorType: models.ErrorTypeConnectionFailed,
			wantColor: "#8e44ad", // Purple
		},
		{
			name:      "unknown error type",
			errorType: "unknown_type",
			wantColor: "#95a5a6", // Default gray
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			color := eh.GetSeverityColor(tt.errorType)
			assert.Equal(t, tt.wantColor, color)
		})
	}
}