package clients

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewKubernetesClient(t *testing.T) {
	tests := []struct {
		name    string
		opts    *KubectlClientOptions
		wantErr bool
	}{
		{
			name: "default options",
			opts: nil,
			wantErr: false,
		},
		{
			name: "custom options",
			opts: &KubectlClientOptions{
				KubectlPath: "/usr/local/bin/kubectl",
				Timeout:     1 * time.Minute,
				Kubeconfig:  "/path/to/kubeconfig",
				Context:     "test-context",
				Namespace:   "test-namespace",
			},
			wantErr: false,
		},
		{
			name: "max timeout enforcement",
			opts: &KubectlClientOptions{
				Timeout: 10 * time.Minute, // Should be capped to MaxTimeout
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewKubernetesClient(tt.opts)
			
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			
			require.NoError(t, err)
			assert.NotNil(t, client)
			
			// Verify client implementation
			kubectlClient, ok := client.(*kubectlClient)
			require.True(t, ok)
			
			if tt.opts != nil && tt.opts.Timeout > MaxTimeout {
				assert.Equal(t, MaxTimeout, kubectlClient.timeout)
			}
		})
	}
}

func TestKubectlClient_ExecuteCommand(t *testing.T) {
	// Create a test client (we'll mock kubectl execution in real tests)
	client, err := NewKubernetesClient(&KubectlClientOptions{
		Timeout: 5 * time.Second,
	})
	require.NoError(t, err)

	tests := []struct {
		name        string
		command     *models.KubernetesCommand
		wantErr     bool
		expectError string
	}{
		{
			name:        "nil command",
			command:     nil,
			wantErr:     true,
			expectError: "command cannot be nil",
		},
		{
			name: "unapproved command",
			command: &models.KubernetesCommand{
				ID:               "test-1",
				SessionID:        "session-1",
				GeneratedCommand: "get pods",
				Status:           models.CommandStatusPending,
			},
			wantErr:     true,
			expectError: "command must be approved",
		},
		{
			name: "approved command - basic structure test",
			command: &models.KubernetesCommand{
				ID:               "test-2",
				SessionID:        "session-1",
				GeneratedCommand: "version --short",
				Status:           models.CommandStatusApproved,
				Resources:        []models.KubernetesResource{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := client.ExecuteCommand(ctx, tt.command)
			
			if tt.wantErr {
				if tt.expectError != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tt.expectError)
				} else if result != nil {
					// Error in result, not returned error
					assert.False(t, result.Success)
					assert.NotEmpty(t, result.Error)
				}
				return
			}
			
			// For approved commands, we expect either success or a structured error result
			if err != nil {
				// Command might fail due to kubectl not being available in test env
				// but the error should be structured
				require.NoError(t, err, "ExecuteCommand should return structured results, not errors")
			}
		})
	}
}

func TestKubectlClient_ParseKubectlCommand(t *testing.T) {
	client := &kubectlClient{}

	tests := []struct {
		name        string
		commandStr  string
		expected    []string
		wantErr     bool
		expectError string
	}{
		{
			name:       "simple get command",
			commandStr: "get pods",
			expected:   []string{"get", "pods"},
			wantErr:    false,
		},
		{
			name:       "kubectl prefix removal",
			commandStr: "kubectl get pods",
			expected:   []string{"get", "pods"},
			wantErr:    false,
		},
		{
			name:       "command with flags",
			commandStr: "get pods --namespace=default -o yaml",
			expected:   []string{"get", "pods", "--namespace=default", "-o", "yaml"},
			wantErr:    false,
		},
		{
			name:        "empty command",
			commandStr:  "",
			expected:    nil,
			wantErr:     true,
			expectError: "empty command",
		},
		{
			name:        "unsafe characters - semicolon",
			commandStr:  "get pods; rm -rf /",
			expected:    nil,
			wantErr:     true,
			expectError: "unsafe characters detected",
		},
		{
			name:        "unsafe characters - pipe",
			commandStr:  "get pods | cat",
			expected:    nil,
			wantErr:     true,
			expectError: "unsafe characters detected",
		},
		{
			name:        "unsafe characters - backtick",
			commandStr:  "get pods `whoami`",
			expected:    nil,
			wantErr:     true,
			expectError: "unsafe characters detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := client.parseKubectlCommand(tt.commandStr)
			
			if tt.wantErr {
				require.Error(t, err)
				if tt.expectError != "" {
					assert.Contains(t, err.Error(), tt.expectError)
				}
				return
			}
			
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlClient_ContainsUnsafeCharacters(t *testing.T) {
	client := &kubectlClient{}

	tests := []struct {
		name     string
		arg      string
		expected bool
	}{
		{
			name:     "safe argument",
			arg:      "get-pods",
			expected: false,
		},
		{
			name:     "safe with equals",
			arg:      "--namespace=default",
			expected: false,
		},
		{
			name:     "unsafe semicolon",
			arg:      "pods;rm",
			expected: true,
		},
		{
			name:     "unsafe ampersand",
			arg:      "pods&background",
			expected: true,
		},
		{
			name:     "unsafe pipe",
			arg:      "pods|grep",
			expected: true,
		},
		{
			name:     "unsafe backtick",
			arg:      "pods`cmd`",
			expected: true,
		},
		{
			name:     "unsafe dollar",
			arg:      "pods$var",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.containsUnsafeCharacters(tt.arg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlClient_SupportsNamespace(t *testing.T) {
	client := &kubectlClient{}

	tests := []struct {
		name     string
		args     []string
		expected bool
	}{
		{
			name:     "get command supports namespace",
			args:     []string{"get", "pods"},
			expected: true,
		},
		{
			name:     "describe command supports namespace",
			args:     []string{"describe", "pod", "test-pod"},
			expected: true,
		},
		{
			name:     "version command does not support namespace",
			args:     []string{"version"},
			expected: false,
		},
		{
			name:     "cluster-info does not support namespace",
			args:     []string{"cluster-info"},
			expected: false,
		},
		{
			name:     "create command supports namespace",
			args:     []string{"create", "-f", "manifest.yaml"},
			expected: true,
		},
		{
			name:     "empty args",
			args:     []string{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.supportsNamespace(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlClient_ActionToVerb(t *testing.T) {
	client := &kubectlClient{}

	tests := []struct {
		name     string
		action   string
		expected string
	}{
		{
			name:     "create action",
			action:   "create",
			expected: "create",
		},
		{
			name:     "read action",
			action:   "read",
			expected: "get",
		},
		{
			name:     "get action",
			action:   "get",
			expected: "get",
		},
		{
			name:     "update action",
			action:   "update",
			expected: "update",
		},
		{
			name:     "patch action",
			action:   "patch",
			expected: "update",
		},
		{
			name:     "delete action",
			action:   "delete",
			expected: "delete",
		},
		{
			name:     "unknown action defaults to get",
			action:   "unknown",
			expected: "get",
		},
		{
			name:     "case insensitive",
			action:   "CREATE",
			expected: "create",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.actionToVerb(tt.action)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestKubectlClient_FormatOutput(t *testing.T) {
	client := &kubectlClient{}

	t.Run("format success output", func(t *testing.T) {
		output := client.formatSuccessOutput("pod1\npod2\npod3", "get pods")
		expected := "✅ Command: get pods\n\npod1\npod2\npod3"
		assert.Equal(t, expected, output)
	})

	t.Run("format success output with empty result", func(t *testing.T) {
		output := client.formatSuccessOutput("", "delete pod test-pod")
		expected := "✅ Command executed successfully (no output)"
		assert.Equal(t, expected, output)
	})

	t.Run("format error output", func(t *testing.T) {
		output := client.formatErrorOutput("command failed", "partial output")
		expected := "❌ Error: command failed\n\nOutput:\npartial output"
		assert.Equal(t, expected, output)
	})

	t.Run("format error output without stdout", func(t *testing.T) {
		output := client.formatErrorOutput("permission denied", "")
		expected := "❌ Error: permission denied"
		assert.Equal(t, expected, output)
	})
}

// TestKubectlClient_ValidateRBAC tests RBAC validation logic
func TestKubectlClient_ValidateRBAC(t *testing.T) {
	client := &kubectlClient{
		timeout: 5 * time.Second,
	}

	tests := []struct {
		name    string
		command *models.KubernetesCommand
		wantErr bool
	}{
		{
			name: "command with no resources - basic auth check",
			command: &models.KubernetesCommand{
				ID:        "test-1",
				SessionID: "session-1",
				Status:    models.CommandStatusApproved,
				Resources: []models.KubernetesResource{},
			},
			wantErr: false, // Will fail in real environment, but test structure is valid
		},
		{
			name: "command with resources",
			command: &models.KubernetesCommand{
				ID:        "test-2",
				SessionID: "session-1",
				Status:    models.CommandStatusApproved,
				Resources: []models.KubernetesResource{
					{
						Kind:      "pods",
						Name:      "test-pod",
						Namespace: "default",
						Action:    "get",
					},
				},
			},
			wantErr: false, // Structure is valid, will test actual RBAC in integration tests
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := client.ValidateRBAC(ctx, tt.command)
			
			// In unit tests, we expect the validation to be attempted
			// Actual RBAC validation will be tested in integration tests
			// Here we just verify the method doesn't panic and handles the structure correctly
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				// Note: This might still error due to kubectl not being available
				// or not being connected to a cluster, which is expected in unit tests
				t.Logf("RBAC validation result: %v", err)
			}
		})
	}
}

// TestKubectlClient_ExecuteKubectl tests kubectl command execution
func TestKubectlClient_ExecuteKubectl(t *testing.T) {
	client := &kubectlClient{
		kubectlPath: "kubectl",
		timeout:     5 * time.Second,
	}

	t.Run("version command", func(t *testing.T) {
		ctx := context.Background()
		args := []string{"version", "--client", "--short"}
		
		result, err := client.executeKubectl(ctx, args)
		
		// In CI/testing environment, kubectl might not be available
		// Test should handle both cases gracefully
		if err != nil {
			t.Logf("kubectl not available in test environment: %v", err)
			// This is expected in many test environments
			return
		}
		
		// If kubectl is available, verify result structure
		assert.NotNil(t, result)
		// Version output should contain "Client Version"
		if result.Stdout != "" {
			assert.Contains(t, result.Stdout, "Client Version")
		}
	})
}

// TestKubectlClient_ExecuteCommandValidation tests command execution validation
func TestKubectlClient_ExecuteCommandValidation(t *testing.T) {
	client, err := NewKubernetesClient(nil)
	require.NoError(t, err)

	tests := []struct {
		name    string
		command *models.KubernetesCommand
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil command",
			command: nil,
			wantErr: true,
			errMsg:  "command cannot be nil",
		},
		{
			name: "unapproved command",
			command: &models.KubernetesCommand{
				ID:               "test-1",
				GeneratedCommand: "get pods",
				Status:           models.CommandStatusPending,
			},
			wantErr: true,
			errMsg:  "command must be approved",
		},
		{
			name: "approved command structure",
			command: &models.KubernetesCommand{
				ID:               "test-2",
				GeneratedCommand: "version --client",
				Status:           models.CommandStatusApproved,
				Resources:        []models.KubernetesResource{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			result, err := client.ExecuteCommand(ctx, tt.command)
			
			if tt.wantErr {
				if tt.errMsg != "" {
					require.Error(t, err)
					assert.Contains(t, err.Error(), tt.errMsg)
				} else {
					// Error should be in result, not returned error
					require.NoError(t, err)
					require.NotNil(t, result)
					assert.False(t, result.Success)
					assert.NotEmpty(t, result.Error)
				}
			} else {
				// Command might still fail due to environment, but should be structured
				if err != nil {
					t.Logf("Expected command structure valid, but execution failed (normal in test env): %v", err)
				}
				if result != nil {
					assert.NotNil(t, result.FormattedOutput)
					assert.GreaterOrEqual(t, result.ExecutionTime, 0)
				}
			}
		})
	}
}

// TestKubectlClient_TimeoutHandling tests command timeout behavior
func TestKubectlClient_TimeoutHandling(t *testing.T) {
	// Create client with very short timeout for testing
	client, err := NewKubernetesClient(&KubectlClientOptions{
		Timeout: 1 * time.Millisecond, // Very short timeout
	})
	require.NoError(t, err)

	command := &models.KubernetesCommand{
		ID:               "timeout-test",
		GeneratedCommand: "get pods --watch", // Long-running command
		Status:           models.CommandStatusApproved,
		Resources:        []models.KubernetesResource{},
	}

	ctx := context.Background()
	result, err := client.ExecuteCommand(ctx, command)
	
	// Should get a result (not error) with timeout information
	require.NoError(t, err)
	require.NotNil(t, result)
	
	// Result should indicate failure due to timeout or execution issues
	// (In real scenarios, this would be a timeout, in test env might be other errors)
	assert.False(t, result.Success)
	assert.NotEmpty(t, result.FormattedOutput)
}

// TestKubectlClient_ErrorParsing tests error parsing and formatting
func TestKubectlClient_ErrorParsing(t *testing.T) {
	client := &kubectlClient{}

	t.Run("format error output", func(t *testing.T) {
		output := client.formatErrorOutput("command not found", "some stdout")
		expected := "❌ Error: command not found\n\nOutput:\nsome stdout"
		assert.Equal(t, expected, output)
	})

	t.Run("format error output without stdout", func(t *testing.T) {
		output := client.formatErrorOutput("permission denied", "")
		expected := "❌ Error: permission denied"
		assert.Equal(t, expected, output)
	})

	t.Run("format success output", func(t *testing.T) {
		output := client.formatSuccessOutput("pod1\npod2", "get pods")
		expected := "✅ Command: get pods\n\npod1\npod2"
		assert.Equal(t, expected, output)
	})

	t.Run("format success output empty", func(t *testing.T) {
		output := client.formatSuccessOutput("", "delete pod test")
		expected := "✅ Command executed successfully (no output)"
		assert.Equal(t, expected, output)
	})
}

// TestKubectlClient_FullWorkflow tests a complete workflow
func TestKubectlClient_FullWorkflow(t *testing.T) {
	client, err := NewKubernetesClient(nil)
	require.NoError(t, err)

	// Test command that should work in most environments
	command := &models.KubernetesCommand{
		ID:               "workflow-test",
		SessionID:        "test-session",
		GeneratedCommand: "version --client --output=yaml",
		Status:           models.CommandStatusApproved,
		RiskLevel:        models.RiskLevelSafe,
		Resources:        []models.KubernetesResource{},
	}

	ctx := context.Background()
	result, err := client.ExecuteCommand(ctx, command)
	
	// Should always get a result structure
	require.NoError(t, err)
	require.NotNil(t, result)
	
	// Verify result structure
	assert.NotNil(t, result.FormattedOutput)
	assert.GreaterOrEqual(t, result.ExecutionTime, 0)
	assert.Contains(t, []int{0, 1}, result.ExitCode) // Success or failure
	
	// If kubectl is available, should succeed
	if result.Success {
		assert.Empty(t, result.Error)
		assert.NotEmpty(t, result.Output)
	} else {
		// If failed, should have error information
		assert.NotEmpty(t, result.Error)
		assert.Contains(t, result.FormattedOutput, "❌")
	}
	
	t.Logf("Command execution result: Success=%v, ExitCode=%d, ExecutionTime=%dms", 
		result.Success, result.ExitCode, result.ExecutionTime)
}