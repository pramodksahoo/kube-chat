package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnhanceWithRecoveryActions(t *testing.T) {
	parser := NewErrorParser()
	
	tests := []struct {
		name            string
		kubectlError    *KubectlError
		originalCommand string
		expectActions   bool
		expectRollback  bool
		expectRetry     bool
		expectedEscalation EscalationLevel
	}{
		{
			name: "not found error with recovery actions",
			kubectlError: &KubectlError{
				Type:        ErrorTypeNotFound,
				Code:        "NOT_FOUND",
				Message:     "pod nginx not found",
				Resource:    "pod/nginx",
				Namespace:   "default",
				Recoverable: true,
			},
			originalCommand:    "kubectl get pod nginx",
			expectActions:      true,
			expectRollback:     false,
			expectRetry:        false,
			expectedEscalation: EscalationLevelNone,
		},
		{
			name: "permission denied error",
			kubectlError: &KubectlError{
				Type:        ErrorTypePermissionDenied,
				Code:        "FORBIDDEN",
				Message:     "access denied",
				Recoverable: false,
			},
			originalCommand:    "kubectl delete pod nginx",
			expectActions:      true,
			expectRollback:     false,
			expectRetry:        false,
			expectedEscalation: EscalationLevelMedium,
		},
		{
			name: "timeout error with retry and rollback",
			kubectlError: &KubectlError{
				Type:        ErrorTypeTimeout,
				Code:        "TIMEOUT",
				Message:     "operation timed out",
				Recoverable: true,
			},
			originalCommand:    "kubectl create deployment test --image=nginx",
			expectActions:      true,
			expectRollback:     true,
			expectRetry:        true,
			expectedEscalation: EscalationLevelLow,
		},
		{
			name: "connection failed error",
			kubectlError: &KubectlError{
				Type:        ErrorTypeConnectionFailed,
				Code:        "CONNECTION_REFUSED",
				Message:     "connection refused",
				Recoverable: true,
			},
			originalCommand:    "kubectl get pods",
			expectActions:      true,
			expectRollback:     false,
			expectRetry:        true,
			expectedEscalation: EscalationLevelHigh,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enhanced := parser.EnhanceWithRecoveryActions(tt.kubectlError, tt.originalCommand)
			
			require.NotNil(t, enhanced)
			assert.Equal(t, tt.expectedEscalation, enhanced.EscalationLevel)
			assert.Equal(t, tt.expectRetry, enhanced.RetryRecommended)
			
			if tt.expectActions {
				assert.Greater(t, len(enhanced.RecoveryActions), 0, "should have recovery actions")
			}
			
			if tt.expectRollback {
				assert.NotEmpty(t, enhanced.RollbackSuggestion, "should have rollback suggestion")
			} else {
				assert.Empty(t, enhanced.RollbackSuggestion, "should not have rollback suggestion")
			}
			
			if tt.expectRetry {
				assert.Greater(t, enhanced.MaxRetries, 0, "should have max retries > 0")
			}
		})
	}
}

func TestDetermineEscalationLevel(t *testing.T) {
	parser := NewErrorParser()
	
	tests := []struct {
		errorType     ErrorType
		expectedLevel EscalationLevel
	}{
		{ErrorTypeNotFound, EscalationLevelNone},
		{ErrorTypeValidationFailed, EscalationLevelNone},
		{ErrorTypeAlreadyExists, EscalationLevelNone},
		{ErrorTypeInvalidArgument, EscalationLevelLow},
		{ErrorTypeTimeout, EscalationLevelLow},
		{ErrorTypePermissionDenied, EscalationLevelMedium},
		{ErrorTypeResourceExhausted, EscalationLevelMedium},
		{ErrorTypeConnectionFailed, EscalationLevelHigh},
		{ErrorTypeInternal, EscalationLevelHigh},
		{ErrorTypeUnknown, EscalationLevelMedium},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.errorType), func(t *testing.T) {
			level := parser.determineEscalationLevel(tt.errorType)
			assert.Equal(t, tt.expectedLevel, level)
		})
	}
}

func TestGetMaxRetries(t *testing.T) {
	parser := NewErrorParser()
	
	tests := []struct {
		errorType       ErrorType
		expectedRetries int
	}{
		{ErrorTypeTimeout, 3},
		{ErrorTypeConnectionFailed, 3},
		{ErrorTypeInternal, 2},
		{ErrorTypeResourceExhausted, 1},
		{ErrorTypeNotFound, 0},
		{ErrorTypePermissionDenied, 0},
		{ErrorTypeValidationFailed, 0},
		{ErrorTypeAlreadyExists, 0},
		{ErrorTypeInvalidArgument, 0},
	}
	
	for _, tt := range tests {
		t.Run(string(tt.errorType), func(t *testing.T) {
			retries := parser.getMaxRetries(tt.errorType)
			assert.Equal(t, tt.expectedRetries, retries)
		})
	}
}

func TestGenerateRollbackSuggestion(t *testing.T) {
	parser := NewErrorParser()
	
	tests := []struct {
		name            string
		originalCommand string
		errorType       ErrorType
		expectSuggestion bool
	}{
		{
			name:            "create timeout has rollback",
			originalCommand: "kubectl create deployment test --image=nginx",
			errorType:       ErrorTypeTimeout,
			expectSuggestion: true,
		},
		{
			name:            "apply timeout has rollback",
			originalCommand: "kubectl apply -f deployment.yaml",
			errorType:       ErrorTypeTimeout,
			expectSuggestion: true,
		},
		{
			name:            "create already exists has rollback",
			originalCommand: "kubectl create service clusterip test --tcp=80:8080",
			errorType:       ErrorTypeAlreadyExists,
			expectSuggestion: true,
		},
		{
			name:            "get command no rollback",
			originalCommand: "kubectl get pods",
			errorType:       ErrorTypeTimeout,
			expectSuggestion: false,
		},
		{
			name:            "delete timeout has rollback",
			originalCommand: "kubectl delete pod nginx",
			errorType:       ErrorTypeTimeout,
			expectSuggestion: true,
		},
		{
			name:            "scale timeout has rollback",
			originalCommand: "kubectl scale deployment nginx --replicas=3",
			errorType:       ErrorTypeTimeout,
			expectSuggestion: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestion := parser.generateRollbackSuggestion(tt.originalCommand, tt.errorType)
			
			if tt.expectSuggestion {
				assert.NotEmpty(t, suggestion, "should have rollback suggestion")
			} else {
				assert.Empty(t, suggestion, "should not have rollback suggestion")
			}
		})
	}
}

func TestErrorParserIntegration(t *testing.T) {
	parser := NewErrorParser()
	
	t.Run("end to end error parsing and enhancement", func(t *testing.T) {
		errorOutput := "Error from server (NotFound): pods \"nginx\" not found"
		stdOutput := ""
		
		// Parse the error
		kubectlError := parser.ParseError(errorOutput, stdOutput)
		require.NotNil(t, kubectlError)
		assert.Equal(t, ErrorTypeNotFound, kubectlError.Type)
		
		// Enhance with recovery actions
		enhanced := parser.EnhanceWithRecoveryActions(kubectlError, "kubectl get pod nginx")
		require.NotNil(t, enhanced)
		
		// Verify enhancement
		assert.Equal(t, EscalationLevelNone, enhanced.EscalationLevel)
		assert.False(t, enhanced.RetryRecommended)
		assert.Equal(t, 0, enhanced.MaxRetries)
		assert.Greater(t, len(enhanced.RecoveryActions), 0)
		assert.Empty(t, enhanced.RollbackSuggestion)
	})
}

func TestNLPErrorParsing(t *testing.T) {
	parser := NewErrorParser()
	
	tests := []struct {
		name          string
		input         string
		errorMessage  string
		expectedType  ErrorType
		expectedCode  string
	}{
		{
			name:         "empty input",
			input:        "",
			errorMessage: "",
			expectedType: ErrorTypeNLPMalformed,
			expectedCode: "EMPTY_INPUT",
		},
		{
			name:         "too short input",
			input:        "ab",
			errorMessage: "input too short",
			expectedType: ErrorTypeNLPMalformed,
			expectedCode: "MALFORMED_INPUT",
		},
		{
			name:         "gibberish input",
			input:        "qwerty123",
			errorMessage: "invalid input",
			expectedType: ErrorTypeNLPMalformed,
			expectedCode: "GIBBERISH_INPUT",
		},
		{
			name:         "ambiguous pronoun",
			input:        "describe that pod",
			errorMessage: "unclear reference",
			expectedType: ErrorTypeNLPAmbiguous,
			expectedCode: "AMBIGUOUS_REFERENCE",
		},
		{
			name:         "vague action",
			input:        "fix the deployment",
			errorMessage: "action too vague",
			expectedType: ErrorTypeNLPAmbiguous,
			expectedCode: "VAGUE_ACTION",
		},
		{
			name:         "unsupported migration",
			input:        "migrate database to new version",
			errorMessage: "not supported",
			expectedType: ErrorTypeNLPUnsupported,
			expectedCode: "UNSUPPORTED_OPERATION",
		},
		{
			name:         "non-kubernetes request",
			input:        "send email to admin",
			errorMessage: "not kubernetes related",
			expectedType: ErrorTypeNLPUnsupported,
			expectedCode: "NON_KUBERNETES",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parser.ParseNLPError(tt.input, tt.errorMessage)
			
			require.NotNil(t, result)
			assert.Equal(t, tt.expectedType, result.Type)
			assert.Equal(t, tt.expectedCode, result.Code)
			assert.NotEmpty(t, result.Message)
			assert.NotEmpty(t, result.Suggestion)
		})
	}
}

func TestEnhancedErrorWithNilInput(t *testing.T) {
	parser := NewErrorParser()
	
	t.Run("nil error input", func(t *testing.T) {
		result := parser.EnhanceWithRecoveryActions(nil, "some command")
		assert.Nil(t, result, "should return nil for nil input")
	})
	
	t.Run("empty command string", func(t *testing.T) {
		kubectlError := &KubectlError{
			Type:    ErrorTypeTimeout,
			Message: "test timeout",
		}
		
		result := parser.EnhanceWithRecoveryActions(kubectlError, "")
		require.NotNil(t, result)
		assert.Equal(t, ErrorTypeTimeout, result.Type)
		assert.Empty(t, result.RollbackSuggestion, "should not have rollback for empty command")
	})
}

func TestEscalationLevelConstants(t *testing.T) {
	// Test that all escalation level constants are properly defined
	escalationLevels := []EscalationLevel{
		EscalationLevelNone,
		EscalationLevelLow,
		EscalationLevelMedium,
		EscalationLevelHigh,
		EscalationLevelCritical,
	}
	
	expectedValues := []string{
		"none",
		"low",
		"medium",
		"high",
		"critical",
	}
	
	for i, level := range escalationLevels {
		assert.Equal(t, expectedValues[i], string(level))
	}
}