// Package models provides user guidance and help system for KubeChat (Story 2.5)
package models

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// UserGuidanceService provides contextual help and guidance for permission errors
type UserGuidanceService struct {
	contactInfo     *ContactInfo
	documentationLinks []DocumentationLink
	operationPatterns  map[string]*OperationGuidance
	templates         *GuidanceTemplates
}

// OperationGuidance provides specific guidance for different operation types
type OperationGuidance struct {
	Operation         string                    `json:"operation"`
	Description       string                    `json:"description"`
	RequiredPermissions []RequiredPermission    `json:"required_permissions"`
	CommonScenarios   []ScenarioGuidance        `json:"common_scenarios"`
	Alternatives      []AlternativeAction       `json:"alternatives"`
	Examples          []OperationExample        `json:"examples"`
	Difficulty        string                    `json:"difficulty"` // "beginner", "intermediate", "advanced"
}

// ScenarioGuidance provides help for specific permission scenarios
type ScenarioGuidance struct {
	Scenario          string   `json:"scenario"`
	Explanation       string   `json:"explanation"`
	Solution          string   `json:"solution"`
	PreventionTips    []string `json:"prevention_tips"`
	RelatedOperations []string `json:"related_operations"`
}

// OperationExample shows example commands and their permission requirements
type OperationExample struct {
	Description       string               `json:"description"`
	Command           string               `json:"command"`
	RequiredPermissions []RequiredPermission `json:"required_permissions"`
	ExpectedOutcome   string               `json:"expected_outcome"`
}

// GuidanceTemplates provides templated responses for different error types
type GuidanceTemplates struct {
	PermissionDenied        string `json:"permission_denied"`
	NamespaceAccessDenied   string `json:"namespace_access_denied"`
	ClusterAccessDenied     string `json:"cluster_access_denied"`
	ResourceNotFound        string `json:"resource_not_found"`
	InsufficientPrivileges  string `json:"insufficient_privileges"`
}

// SelfServiceWorkflow represents a self-service permission request workflow
type SelfServiceWorkflow struct {
	ID                string                    `json:"id"`
	Title             string                    `json:"title"`
	Description       string                    `json:"description"`
	Steps             []WorkflowStep            `json:"steps"`
	RequiredApprovals []ApprovalRequirement     `json:"required_approvals"`
	EstimatedTime     string                    `json:"estimated_time"`
	AutomationLevel   string                    `json:"automation_level"` // "manual", "semi-automated", "automated"
}

// WorkflowStep represents a single step in a self-service workflow
type WorkflowStep struct {
	StepNumber   int                    `json:"step_number"`
	Title        string                 `json:"title"`
	Description  string                 `json:"description"`
	Action       string                 `json:"action"`       // "user_input", "automated", "approval_required"
	Parameters   map[string]interface{} `json:"parameters"`
	Validation   *StepValidation        `json:"validation,omitempty"`
	HelpText     string                 `json:"help_text"`
}

// StepValidation defines validation rules for workflow steps
type StepValidation struct {
	Required      bool     `json:"required"`
	Pattern       string   `json:"pattern,omitempty"`       // Regex pattern
	AllowedValues []string `json:"allowed_values,omitempty"`
	MinLength     int      `json:"min_length,omitempty"`
	MaxLength     int      `json:"max_length,omitempty"`
	ErrorMessage  string   `json:"error_message"`
}

// ApprovalRequirement defines what approvals are needed
type ApprovalRequirement struct {
	Type        string   `json:"type"`        // "role", "group", "specific_user"
	Identifier  string   `json:"identifier"`  // Role name, group name, or username
	Required    bool     `json:"required"`    // Is this approval required or optional
	Timeout     string   `json:"timeout"`     // "24h", "1w", etc.
	Escalation  []string `json:"escalation"`  // Who to escalate to if timeout
}

// UserGuidanceConfig holds configuration for the guidance service
type UserGuidanceConfig struct {
	ContactInfo           *ContactInfo
	DocumentationBaseURL  string
	EnableSelfService     bool
	DefaultApprovers      []string
	MaxWorkflowDuration   time.Duration
}

// NewUserGuidanceService creates a new user guidance service
func NewUserGuidanceService(config UserGuidanceConfig) *UserGuidanceService {
	service := &UserGuidanceService{
		contactInfo:       config.ContactInfo,
		operationPatterns: make(map[string]*OperationGuidance),
		templates:         getDefaultTemplates(),
	}

	// Initialize with default operation patterns
	service.initializeDefaultOperations()
	
	// Initialize documentation links
	service.initializeDocumentationLinks(config.DocumentationBaseURL)
	
	return service
}

// GetOperationGuidance provides specific guidance for a natural language operation
func (service *UserGuidanceService) GetOperationGuidance(originalInput string) (*OperationGuidance, error) {
	// Parse the operation from natural language
	operation := service.parseOperation(originalInput)
	
	// Look up specific guidance for this operation
	if guidance, exists := service.operationPatterns[operation]; exists {
		return guidance, nil
	}
	
	// Fall back to general guidance
	return service.getGeneralGuidance(originalInput), nil
}

// GenerateContextualHelp generates contextual help based on the permission error
func (service *UserGuidanceService) GenerateContextualHelp(permError *PermissionError) *ContextualHelp {
	help := &ContextualHelp{
		ErrorContext:    permError,
		Timestamp:       time.Now(),
		SessionID:       permError.CorrelationID,
	}

	// Generate operation-specific guidance
	if guidance, err := service.GetOperationGuidance(permError.OriginalInput); err == nil {
		help.OperationGuidance = guidance
	}

	// Generate user-friendly explanations
	help.Explanations = service.generateExplanations(permError)
	
	// Generate next steps
	help.NextSteps = service.generateNextSteps(permError)
	
	// Add learning resources
	help.LearningResources = service.getRelevantDocumentation(permError)
	
	// Add self-service options
	help.SelfServiceOptions = service.generateSelfServiceOptions(permError)
	
	return help
}

// ContextualHelp represents comprehensive contextual help
type ContextualHelp struct {
	ErrorContext        *PermissionError      `json:"error_context"`
	OperationGuidance   *OperationGuidance    `json:"operation_guidance,omitempty"`
	Explanations        []string              `json:"explanations"`
	NextSteps           []NextStepGuidance    `json:"next_steps"`
	LearningResources   []DocumentationLink   `json:"learning_resources"`
	SelfServiceOptions  []SelfServiceOption   `json:"self_service_options"`
	ContactOptions      []ContactOption       `json:"contact_options"`
	RelatedErrors       []string              `json:"related_errors,omitempty"`
	Timestamp           time.Time             `json:"timestamp"`
	SessionID           string                `json:"session_id"`
}

// NextStepGuidance provides specific next step guidance
type NextStepGuidance struct {
	Step        string   `json:"step"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
	Priority    string   `json:"priority"` // "high", "medium", "low"
	Difficulty  string   `json:"difficulty"` // "easy", "medium", "hard"
	EstimatedTime string `json:"estimated_time"`
}

// ContactOption provides different ways to get help
type ContactOption struct {
	Method      string `json:"method"`      // "email", "slack", "ticket", "documentation"
	Contact     string `json:"contact"`     // Actual contact information
	Description string `json:"description"` // When to use this option
	Availability string `json:"availability"` // "24/7", "business hours", etc.
}

// CreateSelfServiceWorkflow creates a self-service workflow for permission requests
func (service *UserGuidanceService) CreateSelfServiceWorkflow(permError *PermissionError) *SelfServiceWorkflow {
	workflow := &SelfServiceWorkflow{
		ID:          fmt.Sprintf("workflow_%s", permError.ID),
		Title:       "Request Additional Permissions",
		Description: fmt.Sprintf("Self-service workflow to request permissions for: %s", permError.AttemptedOperation),
		EstimatedTime: "5-30 minutes",
		AutomationLevel: "semi-automated",
	}

	// Add steps based on the error type
	workflow.Steps = service.generateWorkflowSteps(permError)
	
	// Add approval requirements
	workflow.RequiredApprovals = service.generateApprovalRequirements(permError)
	
	return workflow
}

// Private helper methods

func (service *UserGuidanceService) parseOperation(input string) string {
	input = strings.ToLower(strings.TrimSpace(input))
	
	// Define operation patterns with specific order for precedence
	type PatternMatch struct {
		operation string
		pattern   *regexp.Regexp
	}
	
	patterns := []PatternMatch{
		{"get_logs", regexp.MustCompile(`.*logs?.*pod|pod.*logs?|show.*pod.*logs?|get.*logs?`)},
		{"create_deployment", regexp.MustCompile(`(deploy).*application|(create).*deployment`)},
		{"delete_pod", regexp.MustCompile(`(delete|remove|kill).*pods?`)},
		{"describe_resource", regexp.MustCompile(`(describe|info|details)`)},
		{"scale_deployment", regexp.MustCompile(`(scale|resize).*deployment`)},
		{"apply_manifest", regexp.MustCompile(`(apply|create).*from.*file`)},
		{"list_pods", regexp.MustCompile(`(list|show|get|see).*pods?`)},
		{"list_services", regexp.MustCompile(`(list|show|get).*services?`)},
		{"get_nodes", regexp.MustCompile(`(list|show|get).*nodes?`)},
	}

	for _, pm := range patterns {
		if pm.pattern.MatchString(input) {
			return pm.operation
		}
	}

	return "general"
}

func (service *UserGuidanceService) initializeDefaultOperations() {
	service.operationPatterns = map[string]*OperationGuidance{
		"list_pods": {
			Operation:   "list_pods",
			Description: "List pods in a namespace",
			RequiredPermissions: []RequiredPermission{
				{Resource: "pods", Verb: "list", APIGroup: "", Explanation: "Required to list pods in the namespace"},
			},
			CommonScenarios: []ScenarioGuidance{
				{
					Scenario:    "Permission denied when listing pods",
					Explanation: "You don't have the 'list' permission for pods in this namespace",
					Solution:    "Request a role that includes 'list pods' permission, such as the 'view' role",
					PreventionTips: []string{
						"Check which namespaces you have access to",
						"Understand your current role assignments",
					},
				},
			},
			Alternatives: []AlternativeAction{
				{
					Title:       "Try a different namespace",
					Description: "You might have pod listing access in other namespaces",
					Difficulty:  "easy",
				},
				{
					Title:       "Request view role",
					Description: "Ask administrator to grant you the 'view' role for this namespace",
					Difficulty:  "medium",
				},
			},
			Difficulty: "beginner",
		},
		"create_deployment": {
			Operation:   "create_deployment",
			Description: "Create a new deployment",
			RequiredPermissions: []RequiredPermission{
				{Resource: "deployments", Verb: "create", APIGroup: "apps", Explanation: "Required to create deployments"},
			},
			CommonScenarios: []ScenarioGuidance{
				{
					Scenario:    "Cannot create deployments",
					Explanation: "You need the 'create' permission for deployments in the target namespace",
					Solution:    "Request the 'edit' role or a custom role with deployment creation permissions",
				},
			},
			Alternatives: []AlternativeAction{
				{Title: "Use kubectl run", Description: "Use kubectl run for simple pod creation", Difficulty: "easy"},
				{Title: "Apply from manifest", Description: "Apply a deployment manifest from file", Difficulty: "medium"},
			},
			Difficulty: "intermediate",
		},
		"delete_pod": {
			Operation:   "delete_pod",
			Description: "Delete a pod",
			RequiredPermissions: []RequiredPermission{
				{Resource: "pods", Verb: "delete", APIGroup: "", Explanation: "Required to delete pods"},
			},
			CommonScenarios: []ScenarioGuidance{
				{
					Scenario:    "Cannot delete pods",
					Explanation: "Delete operations require special permissions and should be used carefully",
					Solution:    "Request appropriate delete permissions, but understand this is a destructive operation",
					PreventionTips: []string{
						"Consider if restart or scale operations might be safer alternatives",
						"Ensure you understand the impact before deleting resources",
					},
				},
			},
			Difficulty: "intermediate",
		},
		"get_logs": {
			Operation:   "get_logs",
			Description: "View pod logs",
			RequiredPermissions: []RequiredPermission{
				{Resource: "pods/log", Verb: "get", APIGroup: "", Explanation: "Required to access pod logs"},
			},
			Difficulty: "beginner",
		},
	}
}

func (service *UserGuidanceService) initializeDocumentationLinks(baseURL string) {
	service.documentationLinks = []DocumentationLink{
		{
			Title:       "Kubernetes RBAC Documentation",
			URL:         "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
			Description: "Official Kubernetes RBAC documentation",
			Type:        "reference",
		},
		{
			Title:       "Understanding Kubernetes Permissions",
			URL:         baseURL + "/guides/rbac-guide",
			Description: "Guide to understanding and troubleshooting permissions",
			Type:        "tutorial",
		},
		{
			Title:       "Common Permission Errors",
			URL:         baseURL + "/troubleshooting/permission-errors",
			Description: "Troubleshooting guide for common permission issues",
			Type:        "troubleshooting",
		},
	}
}

func (service *UserGuidanceService) getGeneralGuidance(input string) *OperationGuidance {
	return &OperationGuidance{
		Operation:   "general",
		Description: "General Kubernetes operation",
		RequiredPermissions: []RequiredPermission{
			{Explanation: "Specific permissions depend on the operation you're trying to perform"},
		},
		Alternatives: []AlternativeAction{
			{
				Title:       "Check available resources",
				Description: "Use 'kubectl auth can-i --list' to see what you can do",
				Difficulty:  "easy",
			},
			{
				Title:       "Contact administrator",
				Description: "Reach out for help with specific permission requirements",
				Difficulty:  "easy",
			},
		},
		Difficulty: "beginner",
	}
}

func (service *UserGuidanceService) generateExplanations(permError *PermissionError) []string {
	var explanations []string

	// Add operation-specific explanation
	if permError.AttemptedOperation != "" {
		explanations = append(explanations, 
			fmt.Sprintf("You tried to %s, but don't have the required permissions.", permError.AttemptedOperation))
	}

	// Add resource-specific explanation
	if permError.Resource != "" && permError.Verb != "" {
		namespace := permError.Namespace
		if namespace == "" {
			namespace = "cluster-wide"
		}
		explanations = append(explanations,
			fmt.Sprintf("Specifically, you need permission to '%s' '%s' resources in %s.", 
				permError.Verb, permError.Resource, namespace))
	}

	// Add category-specific explanation
	switch permError.Category {
	case PermissionCategoryNamespaceAccess:
		explanations = append(explanations, "This is a namespace-level permission issue. You may have access to other namespaces.")
	case PermissionCategoryClusterAccess:
		explanations = append(explanations, "This requires cluster-level permissions, which are typically restricted.")
	case PermissionCategoryResourceAccess:
		explanations = append(explanations, "This is a resource-specific permission issue.")
	}

	return explanations
}

func (service *UserGuidanceService) generateNextSteps(permError *PermissionError) []NextStepGuidance {
	var steps []NextStepGuidance

	// Immediate steps
	steps = append(steps, NextStepGuidance{
		Step:        "Verify your current permissions",
		Description: "Check what you can currently do in this namespace",
		Actions:     []string{"kubectl auth can-i --list --namespace=" + permError.Namespace},
		Priority:    "high",
		Difficulty:  "easy",
		EstimatedTime: "1 minute",
	})

	// Check alternatives
	if len(permError.AlternativeActions) > 0 {
		actions := make([]string, len(permError.AlternativeActions))
		for i, alt := range permError.AlternativeActions {
			actions[i] = alt.Description
		}
		
		steps = append(steps, NextStepGuidance{
			Step:        "Try alternative approaches",
			Description: "Consider these alternative ways to achieve your goal",
			Actions:     actions,
			Priority:    "medium",
			Difficulty:  "easy",
			EstimatedTime: "2-5 minutes",
		})
	}

	// Contact administrator
	if service.contactInfo != nil {
		steps = append(steps, NextStepGuidance{
			Step:        "Contact administrator",
			Description: "Request additional permissions from your cluster administrator",
			Actions:     []string{"Use the contact information provided in this error"},
			Priority:    "medium",
			Difficulty:  "easy",
			EstimatedTime: "Depends on approval process",
		})
	}

	return steps
}

func (service *UserGuidanceService) getRelevantDocumentation(permError *PermissionError) []DocumentationLink {
	var relevant []DocumentationLink
	
	// Always include general RBAC documentation
	for _, link := range service.documentationLinks {
		if link.Type == "reference" || link.Type == "troubleshooting" {
			relevant = append(relevant, link)
		}
	}
	
	return relevant
}

func (service *UserGuidanceService) generateSelfServiceOptions(permError *PermissionError) []SelfServiceOption {
	var options []SelfServiceOption

	// Option 1: Try different namespace
	if permError.Namespace != "" && len(permError.AllowedNamespaces) > 1 {
		options = append(options, SelfServiceOption{
			Title:       "Try a different namespace",
			Description: "You have access to other namespaces where this operation might work",
			Actions:     []string{fmt.Sprintf("Try the same operation in: %s", strings.Join(permError.AllowedNamespaces, ", "))},
			Automated:   false,
			Estimated:   "Immediate",
		})
	}

	// Option 2: Use alternative commands
	if len(permError.AlternativeActions) > 0 {
		for _, alt := range permError.AlternativeActions {
			if alt.Difficulty == "easy" {
				options = append(options, SelfServiceOption{
					Title:       alt.Title,
					Description: alt.Description,
					Actions:     alt.Commands,
					Automated:   false,
					Estimated:   "1-2 minutes",
				})
			}
		}
	}

	// Option 3: Self-service permission request
	options = append(options, SelfServiceOption{
		Title:       "Request permissions through self-service portal",
		Description: "Submit a permission request that can be automatically processed",
		Actions:     []string{"Use the workflow provided below"},
		Automated:   true,
		Estimated:   "5-30 minutes (depending on approvals)",
	})

	return options
}

func (service *UserGuidanceService) generateWorkflowSteps(permError *PermissionError) []WorkflowStep {
	var steps []WorkflowStep

	// Step 1: Describe what you need
	steps = append(steps, WorkflowStep{
		StepNumber:  1,
		Title:       "Describe your permission request",
		Description: "Explain what you're trying to do and why you need these permissions",
		Action:      "user_input",
		Parameters: map[string]interface{}{
			"field_name": "business_justification",
			"field_type": "text_area",
			"placeholder": fmt.Sprintf("I need to %s for...", permError.AttemptedOperation),
		},
		Validation: &StepValidation{
			Required:     true,
			MinLength:    20,
			ErrorMessage: "Please provide a clear business justification",
		},
		HelpText: "Explain the business reason for needing these permissions",
	})

	// Step 2: Specify duration
	steps = append(steps, WorkflowStep{
		StepNumber:  2,
		Title:       "How long do you need these permissions?",
		Description: "Specify if this is temporary or permanent access",
		Action:      "user_input",
		Parameters: map[string]interface{}{
			"field_name": "duration",
			"field_type": "select",
			"options":    []string{"1 hour", "1 day", "1 week", "1 month", "Permanent"},
		},
		Validation: &StepValidation{
			Required:      true,
			AllowedValues: []string{"1 hour", "1 day", "1 week", "1 month", "Permanent"},
			ErrorMessage:  "Please select a duration",
		},
		HelpText: "Temporary access is usually approved faster",
	})

	// Step 3: Review and submit
	steps = append(steps, WorkflowStep{
		StepNumber:  3,
		Title:       "Review and submit request",
		Description: "Review your permission request before submission",
		Action:      "automated",
		Parameters: map[string]interface{}{
			"auto_populate": true,
			"review_fields": []string{"business_justification", "duration", "required_permissions"},
		},
		HelpText: "Your request will be automatically routed to the appropriate approvers",
	})

	return steps
}

func (service *UserGuidanceService) generateApprovalRequirements(permError *PermissionError) []ApprovalRequirement {
	var requirements []ApprovalRequirement

	// Determine approval requirements based on error severity and category
	switch permError.Category {
	case PermissionCategoryClusterAccess:
		requirements = append(requirements, ApprovalRequirement{
			Type:       "role",
			Identifier: "cluster-admin",
			Required:   true,
			Timeout:    "24h",
			Escalation: []string{"security-team"},
		})
	case PermissionCategoryResourceAccess:
		requirements = append(requirements, ApprovalRequirement{
			Type:       "role",
			Identifier: "namespace-admin",
			Required:   true,
			Timeout:    "4h",
			Escalation: []string{"team-lead"},
		})
	default:
		requirements = append(requirements, ApprovalRequirement{
			Type:       "group",
			Identifier: "devops-team",
			Required:   false,
			Timeout:    "2h",
		})
	}

	return requirements
}

func getDefaultTemplates() *GuidanceTemplates {
	return &GuidanceTemplates{
		PermissionDenied: "You don't have permission to perform this operation. This typically means your current role doesn't include the necessary access rights.",
		
		NamespaceAccessDenied: "You don't have access to this namespace. You might have access to other namespaces, or you might need to request access to this specific namespace.",
		
		ClusterAccessDenied: "You don't have cluster-level permissions. This type of access is typically restricted to administrators and requires special approval.",
		
		ResourceNotFound: "The resource you're looking for doesn't exist or you don't have permission to see it. Check the resource name and namespace.",
		
		InsufficientPrivileges: "Your current privileges are insufficient for this operation. You may need additional permissions or a different role.",
	}
}