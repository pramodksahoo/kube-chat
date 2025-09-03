package clients

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"math/rand"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

const (
	// DefaultTimeout is the default timeout for kubectl commands
	DefaultTimeout = 30 * time.Second
	// MaxTimeout is the maximum allowed timeout for kubectl commands
	MaxTimeout = 5 * time.Minute
	// DefaultMaxRetries is the default maximum number of retry attempts
	DefaultMaxRetries = 3
	// DefaultRetryDelay is the default initial retry delay
	DefaultRetryDelay = 5 * time.Second
	// MaxRetryDelay is the maximum retry delay
	MaxRetryDelay = 60 * time.Second
)

// KubernetesClient provides an interface for executing kubectl commands
type KubernetesClient interface {
	// ExecuteCommand executes a kubectl command with RBAC enforcement
	ExecuteCommand(ctx context.Context, command *models.KubernetesCommand) (*models.CommandExecutionResult, error)
	// ValidateRBAC validates if the current user has permissions for the command
	ValidateRBAC(ctx context.Context, command *models.KubernetesCommand) error
	// GetVersion returns the kubectl and cluster version information
	GetVersion(ctx context.Context) (string, error)
}

// kubectlClient implements the KubernetesClient interface
type kubectlClient struct {
	kubectlPath     string
	timeout         time.Duration
	kubeconfig      string
	context         string
	namespace       string
	maxRetries      int
	baseRetryDelay  time.Duration
	recoveryManager *models.RecoveryManager
	errorParser     *models.ErrorParser
	healthMonitor   *APIHealthMonitor
	cache           *APICache
	degradedMode    bool
}

// KubectlClientOptions configures the kubectl client
type KubectlClientOptions struct {
	KubectlPath      string
	Timeout          time.Duration
	Kubeconfig       string
	Context          string
	Namespace        string
	MaxRetries       int
	BaseRetryDelay   time.Duration
}

// NewKubernetesClient creates a new kubectl client with the specified options
func NewKubernetesClient(opts *KubectlClientOptions) (KubernetesClient, error) {
	if opts == nil {
		opts = &KubectlClientOptions{}
	}

	// Set default kubectl path if not specified
	kubectlPath := opts.KubectlPath
	if kubectlPath == "" {
		path, err := exec.LookPath("kubectl")
		if err != nil {
			return nil, fmt.Errorf("kubectl not found in PATH: %w", err)
		}
		kubectlPath = path
	}

	// Set default timeout if not specified
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout > MaxTimeout {
		timeout = MaxTimeout
	}

	// Set default retry configuration
	maxRetries := opts.MaxRetries
	if maxRetries == 0 {
		maxRetries = DefaultMaxRetries
	}
	
	baseRetryDelay := opts.BaseRetryDelay
	if baseRetryDelay == 0 {
		baseRetryDelay = DefaultRetryDelay
	}

	client := &kubectlClient{
		kubectlPath:     kubectlPath,
		timeout:         timeout,
		kubeconfig:      opts.Kubeconfig,
		context:         opts.Context,
		namespace:       opts.Namespace,
		maxRetries:      maxRetries,
		baseRetryDelay:  baseRetryDelay,
		recoveryManager: models.NewRecoveryManager(),
		errorParser:     models.NewErrorParser(),
		cache:           NewAPICache(),
		degradedMode:    false,
	}
	
	// Initialize health monitor
	client.healthMonitor = NewAPIHealthMonitor(client)
	
	return client, nil
}

// ExecuteCommand executes a kubectl command with proper RBAC enforcement and error handling
func (k *kubectlClient) ExecuteCommand(ctx context.Context, command *models.KubernetesCommand) (*models.CommandExecutionResult, error) {
	if command == nil {
		return nil, fmt.Errorf("command cannot be nil")
	}

	// Validate that the command is approved
	if command.Status != models.CommandStatusApproved {
		return nil, fmt.Errorf("command must be approved before execution, current status: %s", command.Status)
	}

	// Check cache first for read-only operations, especially during degraded mode
	if cachedResult, found := k.cache.Get(command); found {
		// Add degraded mode warning if applicable
		if k.degradedMode {
			cachedResult.FormattedOutput += "\n\n⚠️ **Operating in degraded mode** - API connectivity issues detected"
		}
		return cachedResult, nil
	}

	// Check API health and enter degraded mode if necessary
	if !k.healthMonitor.IsHealthy() {
		k.degradedMode = true
		
		// For read-only commands, try to serve from cache even if expired
		if k.cache.isReadOnlyCommand(command.GeneratedCommand) {
			// Check for any cached version, even expired
			if staleResult := k.getStaleCache(command); staleResult != nil {
				staleResult.FormattedOutput += "\n\n⚠️ **Stale cached data** - API is currently unavailable"
				staleResult.FormattedOutput += "\n" + k.healthMonitor.GetHealthReport()
				return staleResult, nil
			}
		}
		
		// If no cache available, try to execute but warn about degraded mode
	} else {
		k.degradedMode = false
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, k.timeout)
	defer cancel()

	// Validate RBAC permissions first
	if err := k.ValidateRBAC(timeoutCtx, command); err != nil {
		rbacResult := &models.CommandExecutionResult{
			Success:         false,
			Output:          "",
			Error:           fmt.Sprintf("RBAC validation failed: %v", err),
			ExitCode:        1,
			ExecutionTime:   0,
			FormattedOutput: fmt.Sprintf("❌ Permission denied: %v", err),
		}
		
		// Add degraded mode warning if applicable
		if k.degradedMode {
			rbacResult.FormattedOutput += "\n\n⚠️ **API connectivity issues detected** - some operations may be unavailable"
		}
		
		return rbacResult, nil // Return result with error, not error itself
	}

	// Parse and sanitize the kubectl command
	args, err := k.parseKubectlCommand(command.GeneratedCommand)
	if err != nil {
		return &models.CommandExecutionResult{
			Success:         false,
			Output:          "",
			Error:           fmt.Sprintf("command parsing failed: %v", err),
			ExitCode:        1,
			ExecutionTime:   0,
			FormattedOutput: fmt.Sprintf("❌ Invalid command: %v", err),
		}, nil
	}

	// Execute the command with retry logic
	startTime := time.Now()
	result, err := k.executeWithRetry(timeoutCtx, args, command)
	executionTime := time.Since(startTime)

	if err != nil {
		// Handle execution errors with enhanced parsing
		exitCode := 1
		if exitError, ok := err.(*exec.ExitError); ok {
			exitCode = exitError.ExitCode()
		}

		errorMsg := err.Error()
		if result != nil && result.Stderr != "" {
			errorMsg = result.Stderr
		}

		// Parse the error using enhanced error parser
		kubectlError := k.errorParser.ParseError(errorMsg, result.Stdout)
		if kubectlError != nil {
			// Enhance with recovery actions and rollback suggestions
			kubectlError = k.errorParser.EnhanceWithRecoveryActions(kubectlError, command.GeneratedCommand)
		}

		// Format enhanced error output
		var formattedOutput string
		if kubectlError != nil {
			formattedOutput = k.formatEnhancedErrorOutput(kubectlError)
		} else {
			formattedOutput = k.formatErrorOutput(errorMsg, result.Stdout)
		}

		return &models.CommandExecutionResult{
			Success:         false,
			Output:          result.Stdout,
			Error:           errorMsg,
			ExitCode:        exitCode,
			ExecutionTime:   int(executionTime.Milliseconds()),
			FormattedOutput: formattedOutput,
		}, nil
	}

	// Success case
	successResult := &models.CommandExecutionResult{
		Success:         true,
		Output:          result.Stdout,
		Error:           "",
		ExitCode:        0,
		ExecutionTime:   int(executionTime.Milliseconds()),
		FormattedOutput: k.formatSuccessOutput(result.Stdout, command.GeneratedCommand),
	}
	
	// Cache the successful result for read-only operations
	k.cache.Put(command, successResult)
	
	// Add degraded mode warning if applicable
	if k.degradedMode {
		successResult.FormattedOutput += "\n\n⚠️ **Degraded mode** - API connectivity was recently restored"
	}
	
	return successResult, nil
}

// ValidateRBAC validates if the current user has permissions for the command
func (k *kubectlClient) ValidateRBAC(ctx context.Context, command *models.KubernetesCommand) error {
	// For each resource in the command, check if the user has permissions
	for _, resource := range command.Resources {
		if err := k.validateResourcePermissions(ctx, resource); err != nil {
			return fmt.Errorf("insufficient permissions for %s %s: %w", resource.Kind, resource.Name, err)
		}
	}

	// If no specific resources, perform a basic auth check
	if len(command.Resources) == 0 {
		return k.validateBasicAuth(ctx)
	}

	return nil
}

// GetVersion returns kubectl and cluster version information
func (k *kubectlClient) GetVersion(ctx context.Context) (string, error) {
	args := []string{"version", "--short"}
	result, err := k.executeKubectl(ctx, args)
	if err != nil {
		return "", fmt.Errorf("failed to get version: %w", err)
	}
	return result.Stdout, nil
}

// executeResult holds the result of a kubectl execution
type executeResult struct {
	Stdout string
	Stderr string
}

// executeKubectl executes kubectl with the given arguments
func (k *kubectlClient) executeKubectl(ctx context.Context, args []string) (*executeResult, error) {
	// Add global flags if specified
	if k.kubeconfig != "" {
		args = append([]string{"--kubeconfig", k.kubeconfig}, args...)
	}
	if k.context != "" {
		args = append([]string{"--context", k.context}, args...)
	}
	if k.namespace != "" {
		// Only add namespace for commands that support it
		if k.supportsNamespace(args) {
			args = append([]string{"--namespace", k.namespace}, args...)
		}
	}

	cmd := exec.CommandContext(ctx, k.kubectlPath, args...)
	
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	
	result := &executeResult{
		Stdout: strings.TrimSpace(stdout.String()),
		Stderr: strings.TrimSpace(stderr.String()),
	}

	return result, err
}

// parseKubectlCommand parses and validates a kubectl command string
func (k *kubectlClient) parseKubectlCommand(commandStr string) ([]string, error) {
	// Remove "kubectl" prefix if present
	commandStr = strings.TrimSpace(commandStr)
	if strings.HasPrefix(commandStr, "kubectl ") {
		commandStr = strings.TrimPrefix(commandStr, "kubectl ")
	}

	// Basic command parsing (split by spaces, handle quoted arguments)
	args := strings.Fields(commandStr)
	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	// Validate that the command is safe (no shell injection)
	for _, arg := range args {
		if k.containsUnsafeCharacters(arg) {
			return nil, fmt.Errorf("unsafe characters detected in command argument: %s", arg)
		}
	}

	return args, nil
}

// containsUnsafeCharacters checks for potentially dangerous characters
func (k *kubectlClient) containsUnsafeCharacters(arg string) bool {
	unsafeChars := []string{";", "&", "|", "`", "$", "(", ")", "<", ">"}
	for _, char := range unsafeChars {
		if strings.Contains(arg, char) {
			return true
		}
	}
	return false
}

// supportsNamespace checks if a kubectl command supports the --namespace flag
func (k *kubectlClient) supportsNamespace(args []string) bool {
	if len(args) == 0 {
		return false
	}

	namespacedCommands := []string{"get", "describe", "logs", "exec", "port-forward", "create", "apply", "delete", "patch", "edit"}
	command := args[0]
	
	for _, cmd := range namespacedCommands {
		if command == cmd {
			return true
		}
	}
	return false
}

// validateResourcePermissions validates permissions for a specific resource
func (k *kubectlClient) validateResourcePermissions(ctx context.Context, resource models.KubernetesResource) error {
	// Use kubectl auth can-i to check permissions
	verb := k.actionToVerb(resource.Action)
	args := []string{"auth", "can-i", verb, resource.Kind}
	
	if resource.Name != "" {
		args = append(args, resource.Name)
	}
	if resource.Namespace != "" {
		args = append(args, "--namespace", resource.Namespace)
	}

	result, err := k.executeKubectl(ctx, args)
	if err != nil {
		return fmt.Errorf("permission check failed: %w", err)
	}

	if strings.TrimSpace(result.Stdout) != "yes" {
		return fmt.Errorf("permission denied for %s %s %s", verb, resource.Kind, resource.Name)
	}

	return nil
}

// validateBasicAuth performs a basic authentication check
func (k *kubectlClient) validateBasicAuth(ctx context.Context) error {
	args := []string{"auth", "can-i", "get", "pods"}
	_, err := k.executeKubectl(ctx, args)
	if err != nil {
		return fmt.Errorf("basic authentication check failed: %w", err)
	}
	return nil
}

// actionToVerb converts a resource action to a kubectl verb
func (k *kubectlClient) actionToVerb(action string) string {
	switch strings.ToLower(action) {
	case "create":
		return "create"
	case "read", "get":
		return "get"
	case "update", "patch":
		return "update"
	case "delete":
		return "delete"
	default:
		return "get" // Default to read operation
	}
}

// formatSuccessOutput formats successful command output for display
func (k *kubectlClient) formatSuccessOutput(output, command string) string {
	if output == "" {
		return "✅ Command executed successfully (no output)"
	}
	
	return fmt.Sprintf("✅ Command: %s\n\n%s", command, output)
}

// formatErrorOutput formats error output for display
func (k *kubectlClient) formatErrorOutput(errorMsg, stdout string) string {
	result := fmt.Sprintf("❌ Error: %s", errorMsg)
	if stdout != "" {
		result += fmt.Sprintf("\n\nOutput:\n%s", stdout)
	}
	return result
}

// executeWithRetry executes a kubectl command with retry logic for transient failures
func (k *kubectlClient) executeWithRetry(ctx context.Context, args []string, command *models.KubernetesCommand) (*executeResult, error) {
	var lastErr error
	var lastResult *executeResult
	
	for attempt := 1; attempt <= k.maxRetries; attempt++ {
		// Execute the command
		result, err := k.executeKubectl(ctx, args)
		
		if err == nil {
			return result, nil
		}
		
		// Store last error and result
		lastErr = err
		lastResult = result
		
		// Determine if error is retryable
		if !k.isRetryableError(err, result) {
			// Not retryable, return immediately
			return result, err
		}
		
		// Don't retry if this is the last attempt
		if attempt >= k.maxRetries {
			break
		}
		
		// Calculate retry delay with exponential backoff and jitter
		delay := k.calculateRetryDelay(attempt)
		
		// Wait before retrying, but respect context cancellation
		select {
		case <-ctx.Done():
			return lastResult, ctx.Err()
		case <-time.After(delay):
			// Continue to next retry
		}
	}
	
	// All retries exhausted, return last error
	return lastResult, lastErr
}

// isRetryableError determines if an error is worth retrying
func (k *kubectlClient) isRetryableError(err error, result *executeResult) bool {
	if err == nil {
		return false
	}
	
	// Check for context cancellation/timeout - not retryable
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	
	// Check stderr for retryable error patterns
	if result != nil && result.Stderr != "" {
		stderr := strings.ToLower(result.Stderr)
		
		// Retryable patterns
		retryablePatterns := []string{
			"connection refused",
			"timeout",
			"temporary failure",
			"try again",
			"server temporarily unavailable",
			"internal error",
			"service unavailable",
			"too many requests",
			"rate limit",
			"network is unreachable",
			"no route to host",
		}
		
		for _, pattern := range retryablePatterns {
			if strings.Contains(stderr, pattern) {
				return true
			}
		}
		
		// Non-retryable patterns
		nonRetryablePatterns := []string{
			"not found",
			"already exists",
			"forbidden",
			"unauthorized",
			"invalid",
			"malformed",
			"bad request",
			"permission denied",
			"access denied",
		}
		
		for _, pattern := range nonRetryablePatterns {
			if strings.Contains(stderr, pattern) {
				return false
			}
		}
	}
	
	// Check exit codes
	if exitError, ok := err.(*exec.ExitError); ok {
		exitCode := exitError.ExitCode()
		
		// Retryable exit codes (generally transient errors)
		retryableExitCodes := []int{
			1,   // General errors (could be transient)
			124, // Timeout
			125, // Docker container errors
			126, // Command not executable
			130, // Process terminated by Ctrl+C
		}
		
		for _, code := range retryableExitCodes {
			if exitCode == code {
				return true
			}
		}
		
		// Non-retryable exit codes  
		nonRetryableExitCodes := []int{
			2,   // Misuse of shell built-ins
			127, // Command not found  
			128, // Invalid argument to exit
			129, // Hangup
		}
		
		for _, code := range nonRetryableExitCodes {
			if exitCode == code {
				return false
			}
		}
	}
	
	// Default to retryable for unknown errors
	return true
}

// calculateRetryDelay calculates the delay before the next retry attempt
func (k *kubectlClient) calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff: baseDelay * 2^(attempt-1)
	multiplier := 1 << uint(attempt-1) // 1, 2, 4, 8, 16...
	if multiplier > 16 {
		multiplier = 16 // Cap at 16x
	}
	
	delay := k.baseRetryDelay * time.Duration(multiplier)
	
	// Cap at maximum delay
	if delay > MaxRetryDelay {
		delay = MaxRetryDelay
	}
	
	// Add jitter to avoid thundering herd (±25%)
	jitter := time.Duration(float64(delay) * (rand.Float64()*0.5 - 0.25))
	delay += jitter
	
	// Ensure minimum delay
	if delay < time.Second {
		delay = time.Second
	}
	
	return delay
}

// GetRetryConfiguration returns the current retry configuration
func (k *kubectlClient) GetRetryConfiguration() (int, time.Duration) {
	return k.maxRetries, k.baseRetryDelay
}

// SetRetryConfiguration updates the retry configuration
func (k *kubectlClient) SetRetryConfiguration(maxRetries int, baseDelay time.Duration) {
	if maxRetries > 0 {
		k.maxRetries = maxRetries
	}
	if baseDelay > 0 {
		k.baseRetryDelay = baseDelay
	}
}

// formatEnhancedErrorOutput formats enhanced kubectl errors with recovery actions
func (k *kubectlClient) formatEnhancedErrorOutput(kubectlError *models.KubectlError) string {
	if kubectlError == nil {
		return "❌ Unknown error occurred"
	}

	var result strings.Builder

	// Error icon and title based on escalation level
	var icon string
	switch kubectlError.EscalationLevel {
	case models.EscalationLevelCritical:
		icon = "🚨"
	case models.EscalationLevelHigh:
		icon = "🔴"
	case models.EscalationLevelMedium:
		icon = "🟡"
	case models.EscalationLevelLow:
		icon = "🔵"
	default:
		icon = "ℹ️"
	}

	result.WriteString(fmt.Sprintf("%s **%s Error**\n\n", icon, strings.Title(strings.ReplaceAll(string(kubectlError.Type), "_", " "))))
	result.WriteString(fmt.Sprintf("**Message:** %s\n\n", kubectlError.Message))

	// Resource context
	if kubectlError.Resource != "" {
		resource := kubectlError.Resource
		if kubectlError.Namespace != "" {
			resource += fmt.Sprintf(" (namespace: %s)", kubectlError.Namespace)
		}
		result.WriteString(fmt.Sprintf("**Resource:** %s\n\n", resource))
	}

	// Escalation information
	result.WriteString(fmt.Sprintf("**Escalation Level:** %s\n", kubectlError.EscalationLevel))
	
	// Recovery actions
	if len(kubectlError.RecoveryActions) > 0 {
		result.WriteString("\n🔧 **Recovery Actions:**\n")
		for i, action := range kubectlError.RecoveryActions {
			result.WriteString(fmt.Sprintf("%d. **%s**\n", i+1, action.Description))
			if action.Command != "" {
				result.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", action.Command))
			}
			if action.RiskLevel == "high" {
				result.WriteString("   ⚠️ **High risk - proceed with caution**\n")
			} else if action.RiskLevel == "medium" {
				result.WriteString("   ⚡ **Medium risk - verify before executing**\n")
			}
			result.WriteString("\n")
		}
	}

	// Rollback suggestion
	if kubectlError.RollbackSuggestion != "" {
		result.WriteString(fmt.Sprintf("🔄 **Rollback Suggestion:** %s\n\n", kubectlError.RollbackSuggestion))
	}

	// Retry recommendation
	if kubectlError.RetryRecommended && kubectlError.MaxRetries > 0 {
		result.WriteString(fmt.Sprintf("🔄 **Retry:** This error is retryable. Max recommended retries: %d\n\n", kubectlError.MaxRetries))
	}

	// Escalation guidance
	switch kubectlError.EscalationLevel {
	case models.EscalationLevelNone:
		result.WriteString("✅ *You can resolve this yourself using the suggestions above.*")
	case models.EscalationLevelLow:
		result.WriteString("📚 *You may want to consult documentation or ask for guidance.*")
	case models.EscalationLevelMedium:
		result.WriteString("👥 *Consider asking a team member or system administrator for help.*")
	case models.EscalationLevelHigh:
		result.WriteString("🆘 *This requires administrator or expert assistance.*")
	case models.EscalationLevelCritical:
		result.WriteString("🚨 *CRITICAL: This issue requires immediate attention from system administrators.*")
	}

	return result.String()
}

// getStaleCache retrieves even expired cache entries during API outages
func (k *kubectlClient) getStaleCache(command *models.KubernetesCommand) *models.CommandExecutionResult {
	if !k.cache.isReadOnlyCommand(command.GeneratedCommand) {
		return nil
	}
	
	k.cache.mutex.RLock()
	defer k.cache.mutex.RUnlock()
	
	key := k.cache.generateCacheKey(command)
	entry, exists := k.cache.entries[key]
	
	if !exists {
		return nil
	}
	
	// Return the result regardless of expiration during API outages
	result := *entry.Result
	age := time.Since(entry.Timestamp)
	result.FormattedOutput = result.FormattedOutput + fmt.Sprintf("\n\n⚠️ **Stale Cache Warning**\nData is %s old and may not reflect current state.", k.cache.formatDuration(age))
	
	return &result
}

// StartHealthMonitoring starts the API health monitoring
func (k *kubectlClient) StartHealthMonitoring(ctx context.Context) error {
	return k.healthMonitor.Start(ctx)
}

// StopHealthMonitoring stops the API health monitoring  
func (k *kubectlClient) StopHealthMonitoring() {
	k.healthMonitor.Stop()
}

// GetHealthStatus returns the current API health status
func (k *kubectlClient) GetHealthStatus() APIHealthStatus {
	return k.healthMonitor.GetStatus()
}

// IsInDegradedMode returns whether the client is operating in degraded mode
func (k *kubectlClient) IsInDegradedMode() bool {
	return k.degradedMode
}

// GetCacheStats returns cache statistics
func (k *kubectlClient) GetCacheStats() map[string]interface{} {
	return k.cache.GetStats()
}

// ClearCache clears all cached entries
func (k *kubectlClient) ClearCache() {
	k.cache.Clear()
}