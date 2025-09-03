package models

import (
	"fmt"
	"strings"
	"time"
)

// RecoveryAction represents a specific action that can be taken to recover from an error
type RecoveryAction struct {
	Type         RecoveryActionType `json:"type"`
	Description  string            `json:"description"`
	Command      string            `json:"command,omitempty"`
	AutoRetry    bool              `json:"autoRetry"`
	RetryDelay   time.Duration     `json:"retryDelay,omitempty"`
	Prerequisites []string         `json:"prerequisites,omitempty"`
	RiskLevel    string            `json:"riskLevel"` // "low", "medium", "high"
}

// RecoveryActionType represents the type of recovery action
type RecoveryActionType string

const (
	RecoveryActionRetry           RecoveryActionType = "retry"
	RecoveryActionWait            RecoveryActionType = "wait"
	RecoveryActionAlternative     RecoveryActionType = "alternative"
	RecoveryActionPermissions     RecoveryActionType = "permissions"
	RecoveryActionNamespace       RecoveryActionType = "namespace"
	RecoveryActionResource        RecoveryActionType = "resource"
	RecoveryActionConnection      RecoveryActionType = "connection"
	RecoveryActionManual          RecoveryActionType = "manual"
)

// RecoveryPlan contains multiple recovery actions for a specific error scenario
type RecoveryPlan struct {
	ErrorType       ErrorType        `json:"errorType"`
	Priority        int              `json:"priority"` // Lower number = higher priority
	Actions         []RecoveryAction `json:"actions"`
	EstimatedTime   time.Duration    `json:"estimatedTime"`
	SuccessRate     float64          `json:"successRate"` // 0.0 to 1.0
	RequiresManual  bool             `json:"requiresManual"`
}

// RecoveryManager manages error recovery suggestions and execution
type RecoveryManager struct {
	// Pre-defined recovery plans for different error types
	recoveryPlans map[ErrorType][]RecoveryPlan
}

// NewRecoveryManager creates a new recovery manager with predefined plans
func NewRecoveryManager() *RecoveryManager {
	rm := &RecoveryManager{
		recoveryPlans: make(map[ErrorType][]RecoveryPlan),
	}
	
	rm.initializeRecoveryPlans()
	return rm
}

// initializeRecoveryPlans sets up default recovery plans for common error scenarios
func (rm *RecoveryManager) initializeRecoveryPlans() {
	// Not Found Error Recovery
	rm.recoveryPlans[ErrorTypeNotFound] = []RecoveryPlan{
		{
			ErrorType:     ErrorTypeNotFound,
			Priority:      1,
			EstimatedTime: 30 * time.Second,
			SuccessRate:   0.8,
			RequiresManual: false,
			Actions: []RecoveryAction{
				{
					Type:        RecoveryActionNamespace,
					Description: "Check if resource exists in a different namespace",
					Command:     "kubectl get {resource} --all-namespaces",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionResource,
					Description: "List available resources of this type",
					Command:     "kubectl get {resourceType}",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionAlternative,
					Description: "Verify resource name spelling and try similar names",
					Command:     "",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
			},
		},
	}
	
	// Permission Denied Error Recovery
	rm.recoveryPlans[ErrorTypePermissionDenied] = []RecoveryPlan{
		{
			ErrorType:     ErrorTypePermissionDenied,
			Priority:      1,
			EstimatedTime: 60 * time.Second,
			SuccessRate:   0.6,
			RequiresManual: true,
			Actions: []RecoveryAction{
				{
					Type:        RecoveryActionPermissions,
					Description: "Check your current permissions for this resource",
					Command:     "kubectl auth can-i {verb} {resource}",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionAlternative,
					Description: "Try read-only operations first",
					Command:     "kubectl get {resourceType}",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionManual,
					Description: "Contact cluster administrator for required permissions",
					Command:     "",
					AutoRetry:   false,
					RiskLevel:   "low",
					Prerequisites: []string{"Identify required RBAC permissions", "Contact admin with specific resource and action"},
				},
			},
		},
	}
	
	// Connection Failed Error Recovery
	rm.recoveryPlans[ErrorTypeConnectionFailed] = []RecoveryPlan{
		{
			ErrorType:     ErrorTypeConnectionFailed,
			Priority:      1,
			EstimatedTime: 2 * time.Minute,
			SuccessRate:   0.7,
			RequiresManual: false,
			Actions: []RecoveryAction{
				{
					Type:        RecoveryActionConnection,
					Description: "Check cluster connection status",
					Command:     "kubectl cluster-info",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionWait,
					Description: "Wait for temporary network issues to resolve",
					Command:     "",
					AutoRetry:   true,
					RetryDelay:  30 * time.Second,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionRetry,
					Description: "Retry the original command",
					Command:     "{originalCommand}",
					AutoRetry:   true,
					RetryDelay:  10 * time.Second,
					RiskLevel:   "low",
				},
			},
		},
	}
	
	// Timeout Error Recovery
	rm.recoveryPlans[ErrorTypeTimeout] = []RecoveryPlan{
		{
			ErrorType:     ErrorTypeTimeout,
			Priority:      1,
			EstimatedTime: 1 * time.Minute,
			SuccessRate:   0.8,
			RequiresManual: false,
			Actions: []RecoveryAction{
				{
					Type:        RecoveryActionRetry,
					Description: "Retry with longer timeout",
					Command:     "{originalCommand} --request-timeout=60s",
					AutoRetry:   true,
					RetryDelay:  15 * time.Second,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionAlternative,
					Description: "Try a simpler query to reduce load",
					Command:     "kubectl get {resourceType} --no-headers",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
			},
		},
	}
	
	// Already Exists Error Recovery
	rm.recoveryPlans[ErrorTypeAlreadyExists] = []RecoveryPlan{
		{
			ErrorType:     ErrorTypeAlreadyExists,
			Priority:      1,
			EstimatedTime: 30 * time.Second,
			SuccessRate:   0.9,
			RequiresManual: false,
			Actions: []RecoveryAction{
				{
					Type:        RecoveryActionResource,
					Description: "Check current state of existing resource",
					Command:     "kubectl describe {resource} {name}",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionAlternative,
					Description: "Update existing resource instead of creating new",
					Command:     "kubectl apply -f {file}",
					AutoRetry:   false,
					RiskLevel:   "medium",
					Prerequisites: []string{"Verify resource configuration", "Backup existing state if needed"},
				},
				{
					Type:        RecoveryActionAlternative,
					Description: "Use different resource name",
					Command:     "",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
			},
		},
	}
	
	// Resource Exhausted Error Recovery
	rm.recoveryPlans[ErrorTypeResourceExhausted] = []RecoveryPlan{
		{
			ErrorType:     ErrorTypeResourceExhausted,
			Priority:      1,
			EstimatedTime: 5 * time.Minute,
			SuccessRate:   0.5,
			RequiresManual: true,
			Actions: []RecoveryAction{
				{
					Type:        RecoveryActionResource,
					Description: "Check resource quotas and limits",
					Command:     "kubectl describe quota",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionResource,
					Description: "Check node resource availability",
					Command:     "kubectl top nodes",
					AutoRetry:   false,
					RiskLevel:   "low",
				},
				{
					Type:        RecoveryActionManual,
					Description: "Clean up unused resources or request quota increase",
					Command:     "",
					AutoRetry:   false,
					RiskLevel:   "medium",
					Prerequisites: []string{"Identify unused resources", "Contact admin for quota increase"},
				},
			},
		},
	}
}

// GetRecoveryPlan returns the best recovery plan for the given error
func (rm *RecoveryManager) GetRecoveryPlan(errorType ErrorType, context map[string]string) *RecoveryPlan {
	plans, exists := rm.recoveryPlans[errorType]
	if !exists || len(plans) == 0 {
		return rm.getDefaultRecoveryPlan(errorType)
	}
	
	// For now, return the highest priority plan
	// In the future, could add logic to choose based on context
	bestPlan := plans[0]
	
	// Customize the plan based on context
	customizedPlan := rm.customizePlan(&bestPlan, context)
	
	return customizedPlan
}

// getDefaultRecoveryPlan provides a generic recovery plan for unknown error types
func (rm *RecoveryManager) getDefaultRecoveryPlan(errorType ErrorType) *RecoveryPlan {
	return &RecoveryPlan{
		ErrorType:     errorType,
		Priority:      10, // Low priority
		EstimatedTime: 1 * time.Minute,
		SuccessRate:   0.3,
		RequiresManual: true,
		Actions: []RecoveryAction{
			{
				Type:        RecoveryActionRetry,
				Description: "Wait and retry the command",
				Command:     "{originalCommand}",
				AutoRetry:   true,
				RetryDelay:  30 * time.Second,
				RiskLevel:   "low",
			},
			{
				Type:        RecoveryActionAlternative,
				Description: "Try a simpler variation of the command",
				Command:     "",
				AutoRetry:   false,
				RiskLevel:   "low",
			},
			{
				Type:        RecoveryActionManual,
				Description: "Check cluster status and logs for more information",
				Command:     "",
				AutoRetry:   false,
				RiskLevel:   "low",
			},
		},
	}
}

// customizePlan personalizes a recovery plan based on the provided context
func (rm *RecoveryManager) customizePlan(plan *RecoveryPlan, context map[string]string) *RecoveryPlan {
	customized := *plan
	customized.Actions = make([]RecoveryAction, len(plan.Actions))
	
	for i, action := range plan.Actions {
		customizedAction := action
		
		// Replace placeholders in commands
		if customizedAction.Command != "" {
			customizedAction.Command = rm.replacePlaceholders(customizedAction.Command, context)
		}
		
		// Replace placeholders in description
		customizedAction.Description = rm.replacePlaceholders(customizedAction.Description, context)
		
		customized.Actions[i] = customizedAction
	}
	
	return &customized
}

// replacePlaceholders replaces template placeholders with actual values
func (rm *RecoveryManager) replacePlaceholders(template string, context map[string]string) string {
	result := template
	
	for key, value := range context {
		placeholder := fmt.Sprintf("{%s}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}
	
	return result
}

// GetRecoveryActionsByType returns all available recovery actions of a specific type
func (rm *RecoveryManager) GetRecoveryActionsByType(actionType RecoveryActionType) []RecoveryAction {
	var actions []RecoveryAction
	
	for _, plans := range rm.recoveryPlans {
		for _, plan := range plans {
			for _, action := range plan.Actions {
				if action.Type == actionType {
					actions = append(actions, action)
				}
			}
		}
	}
	
	return actions
}

// FormatRecoveryPlan formats a recovery plan for user-friendly display
func (rm *RecoveryManager) FormatRecoveryPlan(plan *RecoveryPlan) string {
	if plan == nil {
		return "No recovery plan available"
	}
	
	var result strings.Builder
	
	result.WriteString(fmt.Sprintf("🔧 **Recovery Plan for %s Error**\n\n", strings.Title(string(plan.ErrorType))))
	result.WriteString(fmt.Sprintf("**Estimated time:** %s\n", plan.EstimatedTime))
	result.WriteString(fmt.Sprintf("**Success rate:** %.0f%%\n", plan.SuccessRate*100))
	
	if plan.RequiresManual {
		result.WriteString("⚠️ **Manual intervention required**\n")
	}
	
	result.WriteString("\n**Steps to resolve:**\n")
	
	for i, action := range plan.Actions {
		result.WriteString(fmt.Sprintf("%d. **%s**\n", i+1, action.Description))
		
		if action.Command != "" {
			result.WriteString(fmt.Sprintf("   ```\n   %s\n   ```\n", action.Command))
		}
		
		if len(action.Prerequisites) > 0 {
			result.WriteString("   **Prerequisites:**\n")
			for _, prereq := range action.Prerequisites {
				result.WriteString(fmt.Sprintf("   • %s\n", prereq))
			}
		}
		
		if action.RiskLevel == "high" {
			result.WriteString("   ⚠️ **High risk operation - proceed with caution**\n")
		} else if action.RiskLevel == "medium" {
			result.WriteString("   ⚡ **Medium risk - verify before executing**\n")
		}
		
		result.WriteString("\n")
	}
	
	return result.String()
}

// IsRetryable determines if an error type is generally retryable
func (rm *RecoveryManager) IsRetryable(errorType ErrorType) bool {
	retryableErrors := map[ErrorType]bool{
		ErrorTypeTimeout:          true,
		ErrorTypeConnectionFailed: true,
		ErrorTypeInternal:         true,
		ErrorTypeResourceExhausted: false, // Usually requires manual intervention
		ErrorTypeNotFound:        false, // Retrying won't help
		ErrorTypePermissionDenied: false, // Retrying won't help
		ErrorTypeAlreadyExists:    false, // Retrying won't help
		ErrorTypeValidationFailed: false, // Need to fix the input
	}
	
	if retryable, exists := retryableErrors[errorType]; exists {
		return retryable
	}
	
	return false // Default to not retryable for unknown errors
}

// GetRetryDelay returns appropriate retry delay for error type
func (rm *RecoveryManager) GetRetryDelay(errorType ErrorType, attemptNumber int) time.Duration {
	baseDelays := map[ErrorType]time.Duration{
		ErrorTypeTimeout:          5 * time.Second,
		ErrorTypeConnectionFailed: 10 * time.Second,
		ErrorTypeInternal:         15 * time.Second,
	}
	
	baseDelay, exists := baseDelays[errorType]
	if !exists {
		baseDelay = 30 * time.Second // Default delay
	}
	
	// Exponential backoff with jitter
	multiplier := 1 << uint(attemptNumber-1) // 1, 2, 4, 8, 16...
	if multiplier > 16 {
		multiplier = 16 // Cap at 16x
	}
	
	return baseDelay * time.Duration(multiplier)
}