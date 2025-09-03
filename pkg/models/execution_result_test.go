package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOutputFormatter(t *testing.T) {
	formatter := NewOutputFormatter()

	t.Run("format get command output", func(t *testing.T) {
		output := "NAME                     READY   STATUS    RESTARTS   AGE\ntest-pod-1               1/1     Running   0          5d\ntest-pod-2               0/1     Pending   0          2d\ntest-pod-3               0/1     Failed    0          1d"
		
		formatted := formatter.formatGetOutput(output)
		
		assert.Contains(t, formatted, "📋")      // Table header
		assert.Contains(t, formatted, "🟢")      // Running status
		assert.Contains(t, formatted, "🟡")      // Pending status  
		assert.Contains(t, formatted, "🔴")      // Failed status
	})

	t.Run("format describe output", func(t *testing.T) {
		output := "Name:         test-pod\nNamespace:    default\nLabels:       app=test\nAnnotations:  none\nStatus:       Running\nIP:           10.244.0.1\nContainers:\n  test-container:\n    Port:     8080/TCP"
		
		formatted := formatter.formatDescribeOutput(output)
		
		assert.Contains(t, formatted, "📌")      // Section headers
		assert.Contains(t, formatted, "🔸")      // Key-value pairs
	})

	t.Run("format version output", func(t *testing.T) {
		output := "Client Version: v1.28.0\nServer Version: v1.28.0"
		
		formatted := formatter.formatVersionOutput(output)
		
		assert.Contains(t, formatted, "🔧")      // Version info header
		assert.Contains(t, formatted, "💻")      // Client version
		assert.Contains(t, formatted, "🖥️")       // Server version
	})

	t.Run("format create output", func(t *testing.T) {
		output := "deployment.apps/test-app created\nconfigmap/test-config configured\nservice/test-service unchanged"
		
		formatted := formatter.formatCreateOutput(output)
		
		assert.Contains(t, formatted, "✨")      // Created
		assert.Contains(t, formatted, "🔄")      // Configured
		assert.Contains(t, formatted, "⏸️")       // Unchanged
	})

	t.Run("format delete output", func(t *testing.T) {
		output := "pod \"test-pod\" deleted\nservice \"test-service\" deleted"
		
		formatted := formatter.formatDeleteOutput(output)
		
		assert.Contains(t, formatted, "🗑️")       // Deleted
	})

	t.Run("format JSON output", func(t *testing.T) {
		output := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"test-pod"},"status":{"phase":"Running"}}`
		
		formatted := formatter.formatJSON(output)
		
		assert.Contains(t, formatted, "📄")      // JSON header
		assert.Contains(t, formatted, "\"name\": \"test-pod\"")
	})

	t.Run("format YAML output", func(t *testing.T) {
		output := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test-pod\nspec:\n  containers:\n  - name: test\nstatus:\n  phase: Running"
		
		formatted := formatter.formatYAML(output)
		
		assert.Contains(t, formatted, "📋")      // YAML header
		assert.Contains(t, formatted, "🏷️")       // apiVersion/kind
		assert.Contains(t, formatted, "📝")      // metadata
		assert.Contains(t, formatted, "⚙️")       // spec
		assert.Contains(t, formatted, "📊")      // status
	})

	t.Run("format logs output", func(t *testing.T) {
		output := "2024-01-01T10:00:00Z Starting application\n2024-01-01T10:00:01Z Application ready\nReady to accept connections"
		
		formatted := formatter.formatLogsOutput(output)
		
		assert.Contains(t, formatted, "📝")      // Logs header
		assert.Contains(t, formatted, "⏰")      // Timestamp lines
	})

	t.Run("determine command type", func(t *testing.T) {
		tests := []struct {
			command  string
			expected string
		}{
			{"get pods", "get"},
			{"kubectl get pods", "get"},
			{"describe pod test-pod", "describe"},
			{"logs test-pod", "logs"},
			{"version --client", "version"},
			{"create -f manifest.yaml", "create"},
			{"apply -f manifest.yaml", "apply"},
			{"delete pod test-pod", "delete"},
			{"", "unknown"},
		}

		for _, tt := range tests {
			result := formatter.determineCommandType(tt.command)
			assert.Equal(t, tt.expected, result, "Command: %s", tt.command)
		}
	})

	t.Run("timestamp detection", func(t *testing.T) {
		tests := []struct {
			line     string
			expected bool
		}{
			{"2024-01-01T10:00:00Z Starting application", true},
			{"2024-01-01 10:00:00 Application started", true},
			{"Jan 01 10:00:00 System message", true},
			{"Regular log message", false},
			{"Application ready", false},
		}

		for _, tt := range tests {
			result := formatter.containsTimestamp(tt.line)
			assert.Equal(t, tt.expected, result, "Line: %s", tt.line)
		}
	})

	t.Run("JSON detection", func(t *testing.T) {
		tests := []struct {
			output   string
			expected bool
		}{
			{`{"key":"value"}`, true},
			{`{"apiVersion":"v1","kind":"Pod"}`, true},
			{`apiVersion: v1\nkind: Pod`, false},
			{`plain text output`, false},
			{``, false},
		}

		for _, tt := range tests {
			result := formatter.isJSON(tt.output)
			assert.Equal(t, tt.expected, result, "Output: %s", tt.output)
		}
	})

	t.Run("YAML detection", func(t *testing.T) {
		tests := []struct {
			output   string
			expected bool
		}{
			{"apiVersion: v1\nkind: Pod\nmetadata:\n  name: test", true},
			{"key1: value1\nkey2: value2\nkey3: value3", true},
			{`{"key":"value"}`, false},
			{"plain text output", false},
			{"", false},
		}

		for _, tt := range tests {
			result := formatter.isYAML(tt.output)
			assert.Equal(t, tt.expected, result, "Output: %s", tt.output)
		}
	})
}

func TestErrorParser(t *testing.T) {
	parser := NewErrorParser()

	t.Run("parse not found errors", func(t *testing.T) {
		tests := []struct {
			name        string
			errorOutput string
			expectType  ErrorType
			expectCode  string
		}{
			{
				name:        "pod not found",
				errorOutput: `error from server (NotFound): pods "test-pod" not found`,
				expectType:  ErrorTypeNotFound,
				expectCode:  "NOT_FOUND",
			},
			{
				name:        "no resources found",
				errorOutput: `No resources found in default namespace`,
				expectType:  ErrorTypeNotFound,
				expectCode:  "NOT_FOUND",
			},
			{
				name:        "resource type not found",
				errorOutput: `the server doesn't have a resource type "invalidresource"`,
				expectType:  ErrorTypeNotFound,
				expectCode:  "INVALID_RESOURCE_TYPE",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := parser.ParseError(tt.errorOutput, "")
				assert.Equal(t, tt.expectType, result.Type)
				assert.Equal(t, tt.expectCode, result.Code)
				assert.True(t, result.Recoverable)
				assert.NotEmpty(t, result.Suggestion)
			})
		}
	})

	t.Run("parse permission errors", func(t *testing.T) {
		tests := []struct {
			name        string
			errorOutput string
		}{
			{
				name:        "forbidden error",
				errorOutput: `error from server (Forbidden): User "test-user" cannot get resource "secrets"`,
			},
			{
				name:        "access denied",
				errorOutput: `access denied: insufficient permissions`,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := parser.ParseError(tt.errorOutput, "")
				assert.Equal(t, ErrorTypePermissionDenied, result.Type)
				assert.Equal(t, "FORBIDDEN", result.Code)
				assert.False(t, result.Recoverable)
				assert.Contains(t, result.Suggestion, "administrator")
			})
		}
	})

	t.Run("parse already exists errors", func(t *testing.T) {
		errorOutput := `error from server (AlreadyExists): deployments.apps "test-deployment" already exists`
		
		result := parser.ParseError(errorOutput, "")
		
		assert.Equal(t, ErrorTypeAlreadyExists, result.Type)
		assert.Equal(t, "ALREADY_EXISTS", result.Code)
		assert.True(t, result.Recoverable)
		assert.Contains(t, result.Suggestion, "apply")
		assert.Equal(t, "test-deployment", result.Resource)
	})

	t.Run("parse validation errors", func(t *testing.T) {
		tests := []struct {
			name        string
			errorOutput string
		}{
			{
				name:        "validation error",
				errorOutput: `error validating "manifest.yaml": ValidationError(Pod.spec): missing required field "containers"`,
			},
			{
				name:        "invalid field",
				errorOutput: `field is invalid: spec.invalidField`,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := parser.ParseError(tt.errorOutput, "")
				assert.Equal(t, ErrorTypeValidationFailed, result.Type)
				assert.Equal(t, "VALIDATION_FAILED", result.Code)
				assert.True(t, result.Recoverable)
			})
		}
	})

	t.Run("parse connection errors", func(t *testing.T) {
		tests := []struct {
			name        string
			errorOutput string
		}{
			{
				name:        "connection refused",
				errorOutput: `unable to connect to the server: connection refused`,
			},
			{
				name:        "timeout",
				errorOutput: `context deadline exceeded`,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := parser.ParseError(tt.errorOutput, "")
				assert.Equal(t, ErrorTypeConnectionFailed, result.Type)
				assert.Equal(t, "CONNECTION_FAILED", result.Code)
				assert.False(t, result.Recoverable)
				assert.Contains(t, result.Suggestion, "connectivity")
			})
		}
	})

	t.Run("parse timeout errors", func(t *testing.T) {
		errorOutput := `request timeout exceeded`
		
		result := parser.ParseError(errorOutput, "")
		
		assert.Equal(t, ErrorTypeTimeout, result.Type)
		assert.Equal(t, "TIMEOUT", result.Code)
		assert.True(t, result.Recoverable)
		assert.Contains(t, result.Suggestion, "timeout")
	})

	t.Run("parse resource exhausted errors", func(t *testing.T) {
		errorOutput := `exceeded quota: pods quota exceeded`
		
		result := parser.ParseError(errorOutput, "")
		
		assert.Equal(t, ErrorTypeResourceExhausted, result.Type)
		assert.Equal(t, "RESOURCE_EXHAUSTED", result.Code)
		assert.True(t, result.Recoverable)
		assert.Contains(t, result.Suggestion, "quota")
	})

	t.Run("parse invalid argument errors", func(t *testing.T) {
		tests := []struct {
			name        string
			errorOutput string
		}{
			{
				name:        "unknown flag",
				errorOutput: `unknown flag: --invalid-flag`,
			},
			{
				name:        "invalid argument",
				errorOutput: `accepts 1 arg(s), received 2`,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := parser.ParseError(tt.errorOutput, "")
				assert.Equal(t, ErrorTypeInvalidArgument, result.Type)
				assert.Equal(t, "INVALID_ARGUMENT", result.Code)
				assert.True(t, result.Recoverable)
			})
		}
	})

	t.Run("format error for display", func(t *testing.T) {
		kubectlErr := &KubectlError{
			Type:        ErrorTypeNotFound,
			Code:        "NOT_FOUND",
			Message:     "Resource not found",
			Resource:    "test-pod",
			Namespace:   "default",
			Suggestion:  "Check the resource name",
			Recoverable: true,
		}
		
		formatted := parser.FormatErrorForDisplay(kubectlErr)
		
		assert.Contains(t, formatted, "🔍")
		assert.Contains(t, formatted, "Not Found Error")
		assert.Contains(t, formatted, "Resource not found")
		assert.Contains(t, formatted, "**Resource:** test-pod")
		assert.Contains(t, formatted, "**Namespace:** default")
		assert.Contains(t, formatted, "Check the resource name")
		assert.Contains(t, formatted, "✅ This error may be recoverable")
	})

	t.Run("clean error messages", func(t *testing.T) {
		tests := []struct {
			input    string
			expected string
		}{
			{
				input:    "error from server (NotFound): pods \"test\" not found",
				expected: "pods \"test\" not found",
			},
			{
				input:    "Error: command failed",
				expected: "command failed",
			},
			{
				input:    "   \n\n  clean this  \n\n   ",
				expected: "clean this",
			},
		}

		for _, tt := range tests {
			result := parser.cleanErrorMessage(tt.input)
			assert.Equal(t, tt.expected, result, "Input: %s", tt.input)
		}
	})
}

func TestCommandExecutionResultSerialization(t *testing.T) {
	t.Run("JSON serialization", func(t *testing.T) {
		result := &CommandExecutionResult{
			Success:         true,
			Output:          "test output",
			Error:           "",
			ExitCode:        0,
			ExecutionTime:   150,
			FormattedOutput: "✅ test output",
		}
		
		// Test ToJSON
		jsonData, err := result.ToJSON()
		require.NoError(t, err)
		assert.Contains(t, string(jsonData), "test output")
		assert.Contains(t, string(jsonData), "true")
		
		// Test FromJSON
		var decoded CommandExecutionResult
		err = decoded.FromJSON(jsonData)
		require.NoError(t, err)
		
		assert.Equal(t, result.Success, decoded.Success)
		assert.Equal(t, result.Output, decoded.Output)
		assert.Equal(t, result.ExitCode, decoded.ExitCode)
		assert.Equal(t, result.ExecutionTime, decoded.ExecutionTime)
		assert.Equal(t, result.FormattedOutput, decoded.FormattedOutput)
	})

	t.Run("NewCommandExecutionResult", func(t *testing.T) {
		result := NewCommandExecutionResult(true, "output", "", 0, 100)
		
		assert.True(t, result.Success)
		assert.Equal(t, "output", result.Output)
		assert.Empty(t, result.Error)
		assert.Equal(t, 0, result.ExitCode)
		assert.Equal(t, 100, result.ExecutionTime)
		assert.NotEmpty(t, result.FormattedOutput)
		assert.Contains(t, result.FormattedOutput, "✅")
	})

	t.Run("NewCommandExecutionResult with error", func(t *testing.T) {
		result := NewCommandExecutionResult(false, "partial output", "command failed", 1, 200)
		
		assert.False(t, result.Success)
		assert.Equal(t, "partial output", result.Output)
		assert.Equal(t, "command failed", result.Error)
		assert.Equal(t, 1, result.ExitCode)
		assert.Equal(t, 200, result.ExecutionTime)
		assert.NotEmpty(t, result.FormattedOutput)
		assert.Contains(t, result.FormattedOutput, "❌")
		assert.Contains(t, result.FormattedOutput, "command failed")
		assert.Contains(t, result.FormattedOutput, "partial output")
	})
}