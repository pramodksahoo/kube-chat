package nlp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/pramodksahoo/kube-chat/pkg/middleware"
)

// TranslatorService defines the interface for natural language to kubectl translation
type TranslatorService interface {
	TranslateCommand(ctx context.Context, input string) (*models.KubernetesCommand, error)
	TranslateCommandWithContext(ctx context.Context, input string, sessionContext *models.SessionContext) (*models.KubernetesCommand, error)
	TranslateCommandWithRBAC(ctx context.Context, input string, sessionContext *models.SessionContext, jwtClaims *middleware.JWTClaims) (*models.KubernetesCommand, error)
	SetRBACValidator(validator *middleware.RBACValidator)
}

// translatorService implements the TranslatorService interface for Story 1.1
type translatorService struct {
	patterns        []TranslationPattern
	contextResolver *ContextResolver
	rbacValidator   *middleware.RBACValidator
}

// TranslationPattern represents a pattern for translating natural language to kubectl commands
type TranslationPattern struct {
	Pattern     *regexp.Regexp
	CommandFunc func(matches []string) string
	RiskLevel   interface{} // Can be models.RiskLevel or func([]string) models.RiskLevel
	Description string
	ActionType  interface{} // Can be string or func([]string) string
}

// NewTranslatorService creates a new translator service with predefined patterns including write operations
func NewTranslatorService() TranslatorService {
	patterns := getStory11TranslationPatterns()                 // Read operations from Story 1.1
	patterns = append(patterns, getWriteOperationPatterns()...) // Write operations for Story 1.2
	patterns = append(patterns, getContextAwarePatterns()...)   // Context-aware patterns for Story 1.4

	return &translatorService{
		patterns:        patterns,
		contextResolver: NewContextResolver(),
	}
}

// TranslateCommand translates natural language input to a kubectl command with safety analysis
func (t *translatorService) TranslateCommand(ctx context.Context, input string) (*models.KubernetesCommand, error) {
	return t.TranslateCommandWithContext(ctx, input, nil)
}

// TranslateCommandWithContext translates natural language input to a kubectl command using session context for reference resolution
func (t *translatorService) TranslateCommandWithContext(ctx context.Context, input string, sessionContext *models.SessionContext) (*models.KubernetesCommand, error) {
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}

	originalInput := input
	var resolvedReferences []string
	var contextEnhancement map[string]interface{}

	// Check if input contains references that need context resolution
	if t.contextResolver.ContainsReferences(originalInput) {
		// If references are present but context is not available or expired, return error
		if sessionContext == nil || sessionContext.IsExpired() {
			return nil, fmt.Errorf("context references detected in input %q but no active session context available", originalInput)
		}
		
		// Check for ambiguous references first
		ambiguous := t.contextResolver.DetectAmbiguousReferences(input, sessionContext)
		if len(ambiguous) > 0 {
			suggestions := t.contextResolver.SuggestClarifications(input, sessionContext)
			return nil, fmt.Errorf("ambiguous reference in input: %q. Issues: %v. Suggestions: %v", 
				input, ambiguous, suggestions)
		}
		
		// Resolve context references
		resolvedInput, references, err := t.contextResolver.ResolveReferences(input, sessionContext)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve references in input: %q. Error: %w", input, err)
		}
		
		input = resolvedInput
		resolvedReferences = references
	}

	// Normalize input (lowercase, trim whitespace)
	normalizedInput := strings.ToLower(strings.TrimSpace(input))

	// Try to match against known patterns
	for _, pattern := range t.patterns {
		var matches []string
		var command string
		
		// For context-aware patterns, match against original input before resolution
		if len(resolvedReferences) > 0 {
			originalNormalizedInput := strings.ToLower(strings.TrimSpace(originalInput))
			if pattern.Pattern.MatchString(originalNormalizedInput) {
				matches = pattern.Pattern.FindStringSubmatch(originalNormalizedInput)
				// For context patterns, we need to construct the kubectl command manually
				command = t.buildKubectlCommandWithContext(originalInput, input, resolvedReferences, sessionContext)
			} else {
				continue
			}
		} else {
			// For regular patterns, match against current input
			if pattern.Pattern.MatchString(normalizedInput) {
				matches = pattern.Pattern.FindStringSubmatch(normalizedInput)
				command = pattern.CommandFunc(matches)
			} else {
				continue
			}
		}

		// Determine risk level (static or dynamic)
		var riskLevel models.RiskLevel
		if riskFunc, ok := pattern.RiskLevel.(func([]string) models.RiskLevel); ok {
			riskLevel = riskFunc(matches)
		} else if staticRisk, ok := pattern.RiskLevel.(models.RiskLevel); ok {
			riskLevel = staticRisk
		} else {
			riskLevel = models.RiskLevelCaution // Default fallback
		}

		// Create KubernetesCommand object
		kubeCommand := models.NewKubernetesCommand("", originalInput, command, riskLevel)

		// Determine action type (static or dynamic)
		var actionType string
		if actionFunc, ok := pattern.ActionType.(func([]string) string); ok {
			actionType = actionFunc(matches)
		} else if staticAction, ok := pattern.ActionType.(string); ok {
			actionType = staticAction
		} else {
			actionType = "read" // Default fallback
		}

		// Set action type for resource impact analysis
		if len(kubeCommand.Resources) == 0 {
			kubeCommand.Resources = []models.KubernetesResource{
				{
					Kind:   extractResourceKind(command),
					Action: actionType,
				},
			}
		}

		// Enhance command with context if references were resolved
		if len(resolvedReferences) > 0 {
			contextEnhancement = t.contextResolver.EnhanceCommandWithContext(
				command, input, resolvedReferences, sessionContext)
			
			// Update the command if context provides namespace enhancement
			if enhancedCmd, ok := contextEnhancement["resolved_command"].(string); ok && enhancedCmd != command {
				kubeCommand.GeneratedCommand = enhancedCmd
			}
			
			// Store context information - for now, we'll add this to a custom field in future iterations
			// TODO: Add Metadata field to KubernetesCommand struct
		}

		// Auto-approve SAFE read operations (Story 1.1 compatibility)
		// Write operations require explicit approval (Story 1.2)
		if kubeCommand.RiskLevel == models.RiskLevelSafe {
			kubeCommand.UpdateStatus(models.CommandStatusApproved)
		} else {
			kubeCommand.UpdateStatus(models.CommandStatusPendingApproval)
			// Generate approval token for write operations
			kubeCommand.SetApprovalToken(generateApprovalToken())
		}

		return kubeCommand, nil
	}

	// If no pattern matches, check for context availability and provide helpful suggestions
	errorMsg := fmt.Sprintf("unable to translate input: %q", originalInput)
	
	if sessionContext != nil && !sessionContext.IsExpired() {
		// Check if the input contains references that couldn't be resolved
		if t.contextResolver.ContainsReferences(originalInput) {
			ambiguous := t.contextResolver.DetectAmbiguousReferences(originalInput, sessionContext)
			suggestions := t.contextResolver.SuggestClarifications(originalInput, sessionContext)
			if len(ambiguous) > 0 || len(suggestions) > 0 {
				errorMsg += fmt.Sprintf(". Reference issues: %v. Suggestions: %v", ambiguous, suggestions)
			}
		} else {
			// Show available references if context is available
			availableRefs := t.contextResolver.GetAvailableReferences(sessionContext)
			if availableRefs["available"].(bool) {
				errorMsg += ". Available references: " + fmt.Sprintf("%v", availableRefs["by_type"])
			}
		}
	}
	
	errorMsg += ". Supported commands include: show pods, create deployment, scale deployment, delete pod, describe the first pod, delete that service"
	
	return nil, fmt.Errorf("%s", errorMsg)
}

// TranslateCommandWithRBAC translates natural language input with RBAC permission validation
func (t *translatorService) TranslateCommandWithRBAC(ctx context.Context, input string, sessionContext *models.SessionContext, jwtClaims *middleware.JWTClaims) (*models.KubernetesCommand, error) {
	if jwtClaims == nil {
		return nil, fmt.Errorf("JWT claims required for RBAC validation")
	}

	if t.rbacValidator == nil {
		return nil, fmt.Errorf("RBAC validator not configured")
	}

	// First, translate the command using existing logic
	kubeCommand, err := t.TranslateCommandWithContext(ctx, input, sessionContext)
	if err != nil {
		return nil, fmt.Errorf("command translation failed: %w", err)
	}

	// Extract resource details from the generated kubectl command for RBAC validation
	resourceDetails, err := t.extractResourceDetails(kubeCommand.GeneratedCommand, sessionContext)
	if err != nil {
		return nil, fmt.Errorf("failed to extract resource details for RBAC validation: %w", err)
	}

	// Perform RBAC validation before allowing command execution
	for _, resource := range resourceDetails {
		permissionRequest := middleware.PermissionRequest{
			KubernetesUser:   jwtClaims.KubernetesUser,
			KubernetesGroups: jwtClaims.KubernetesGroups,
			SessionID:        jwtClaims.SessionID,
			Namespace:        resource.Namespace,
			Verb:             resource.Verb,
			Resource:         resource.Resource,
			ResourceName:     resource.ResourceName,
			APIGroup:         resource.APIGroup,
			CommandContext:   input,
			AllowedActions:   extractAllowedActions(kubeCommand),
		}

		// Validate permission
		response, err := t.rbacValidator.ValidatePermission(ctx, permissionRequest)
		if err != nil {
			return nil, fmt.Errorf("RBAC validation error: %w", err)
		}

		// If permission is denied, create and return an RBAC error
		if !response.Allowed {
			rbacError := &models.RBACPermissionError{
				User:          jwtClaims.KubernetesUser,
				Groups:        jwtClaims.KubernetesGroups,
				Resource:      resource.Resource,
				Verb:          resource.Verb,
				Namespace:     resource.Namespace,
				Reason:        response.Reason,
				Suggestions:   response.Suggestions,
				ValidationID:  response.ValidationID,
				Command:       kubeCommand.GeneratedCommand,
				OriginalInput: input,
			}
			return nil, rbacError
		}

		// Add RBAC validation metadata to the command
		kubeCommand.RBACValidated = true
		kubeCommand.ValidationID = response.ValidationID
		kubeCommand.ValidatedAt = response.EvaluatedAt
	}

	// Create secure audit trail for successful RBAC validation
	t.recordSuccessfulRBACValidation(ctx, kubeCommand, jwtClaims, resourceDetails)

	return kubeCommand, nil
}

// SetRBACValidator sets the RBAC validator for permission checking
func (t *translatorService) SetRBACValidator(validator *middleware.RBACValidator) {
	t.rbacValidator = validator
}

// extractResourceDetails extracts resource details from kubectl command for RBAC validation
func (t *translatorService) extractResourceDetails(kubectlCommand string, sessionContext *models.SessionContext) ([]ResourceDetails, error) {
	var resources []ResourceDetails

	// Parse kubectl command to extract verb, resource type, namespace, etc.
	parts := strings.Fields(kubectlCommand)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid kubectl command format")
	}

	if parts[0] != "kubectl" {
		return nil, fmt.Errorf("command must start with 'kubectl'")
	}

	verb := parts[1]
	
	// Map kubectl verbs to Kubernetes RBAC verbs
	rbacVerb := mapKubectlVerbToRBAC(verb)
	if rbacVerb == "" {
		return nil, fmt.Errorf("unsupported kubectl verb: %s", verb)
	}

	// Extract resource type
	var resourceType, namespace, resourceName, apiGroup string
	
	// Look for resource type (pods, deployments, services, etc.)
	if len(parts) >= 3 {
		resourceType = parts[2]
		
		// Handle resource type with API group (e.g., apps/v1/deployments)
		if strings.Contains(resourceType, "/") {
			apiParts := strings.Split(resourceType, "/")
			if len(apiParts) >= 2 {
				apiGroup = apiParts[0]
				resourceType = apiParts[len(apiParts)-1]
			}
		}
	}

	// Extract namespace from -n or --namespace flags
	for i, part := range parts {
		if (part == "-n" || part == "--namespace") && i+1 < len(parts) {
			namespace = parts[i+1]
			break
		}
		if strings.HasPrefix(part, "--namespace=") {
			namespace = strings.TrimPrefix(part, "--namespace=")
			break
		}
	}

	// Extract resource name if specified
	if len(parts) >= 4 && !strings.HasPrefix(parts[3], "-") {
		resourceName = parts[3]
	}

	// SessionContext doesn't have namespace field - will be handled by user context later

	// Default to "default" namespace if still not specified
	if namespace == "" {
		namespace = "default"
	}

	// Normalize resource type to singular form for RBAC
	resourceType = normalizeResourceType(resourceType)

	resource := ResourceDetails{
		Namespace:    namespace,
		Verb:         rbacVerb,
		Resource:     resourceType,
		ResourceName: resourceName,
		APIGroup:     apiGroup,
	}

	resources = append(resources, resource)
	return resources, nil
}

// ResourceDetails represents the details needed for RBAC validation
type ResourceDetails struct {
	Namespace    string
	Verb         string
	Resource     string
	ResourceName string
	APIGroup     string
}

// mapKubectlVerbToRBAC maps kubectl verbs to Kubernetes RBAC verbs
func mapKubectlVerbToRBAC(kubectlVerb string) string {
	verbMap := map[string]string{
		"get":         "get",
		"list":        "list",
		"describe":    "get",
		"create":      "create",
		"apply":       "create", // Also requires update for existing resources
		"replace":     "update",
		"patch":       "patch",
		"edit":        "update",
		"delete":      "delete",
		"scale":       "update", // Scaling requires update permission
		"rollout":     "update", // Rollout operations require update
		"expose":      "create", // Expose creates a service
		"port-forward": "get",   // Port-forward requires get permission on pods
		"logs":        "get",    // Logs require get permission
		"exec":        "get",    // Exec requires get permission (and create for pods/exec)
		"attach":      "get",    // Attach requires get permission
		"cp":          "get",    // Copy requires get permission
	}

	return verbMap[kubectlVerb]
}

// normalizeResourceType normalizes resource types to their singular RBAC form
func normalizeResourceType(resourceType string) string {
	// Map plural forms to singular forms for RBAC
	typeMap := map[string]string{
		"pods":                   "pods",
		"pod":                    "pods",
		"services":               "services",
		"service":                "services",
		"svc":                    "services",
		"deployments":            "deployments",
		"deployment":             "deployments",
		"deploy":                 "deployments",
		"configmaps":             "configmaps",
		"configmap":              "configmaps",
		"cm":                     "configmaps",
		"secrets":                "secrets",
		"secret":                 "secrets",
		"nodes":                  "nodes",
		"node":                   "nodes",
		"namespaces":             "namespaces",
		"namespace":              "namespaces",
		"ns":                     "namespaces",
		"replicasets":            "replicasets",
		"replicaset":             "replicasets",
		"rs":                     "replicasets",
		"daemonsets":             "daemonsets",
		"daemonset":              "daemonsets",
		"ds":                     "daemonsets",
		"statefulsets":           "statefulsets",
		"statefulset":            "statefulsets",
		"sts":                    "statefulsets",
		"jobs":                   "jobs",
		"job":                    "jobs",
		"cronjobs":               "cronjobs",
		"cronjob":                "cronjobs",
		"cj":                     "cronjobs",
		"persistentvolumes":      "persistentvolumes",
		"persistentvolume":       "persistentvolumes",
		"pv":                     "persistentvolumes",
		"persistentvolumeclaims": "persistentvolumeclaims",
		"persistentvolumeclaim":  "persistentvolumeclaims",
		"pvc":                    "persistentvolumeclaims",
		"ingresses":              "ingresses",
		"ingress":                "ingresses",
		"ing":                    "ingresses",
	}

	if normalized, exists := typeMap[strings.ToLower(resourceType)]; exists {
		return normalized
	}

	// Return as-is if not found in map
	return strings.ToLower(resourceType)
}

// extractAllowedActions extracts allowed actions from the kubernetes command
func extractAllowedActions(kubeCommand *models.KubernetesCommand) []string {
	actions := []string{}
	
	// Extract actions based on risk level and command type
	switch kubeCommand.RiskLevel {
	case models.RiskLevelSafe:
		actions = append(actions, "read", "list", "describe")
	case models.RiskLevelCaution:
		actions = append(actions, "read", "list", "describe", "create", "update")
	case models.RiskLevelDestructive:
		actions = append(actions, "read", "list", "describe", "create", "update", "delete")
	}

	return actions
}

// recordSuccessfulRBACValidation records successful RBAC validation for audit trail
func (t *translatorService) recordSuccessfulRBACValidation(ctx context.Context, kubeCommand *models.KubernetesCommand, jwtClaims *middleware.JWTClaims, resources []ResourceDetails) {
	// Create audit entry for successful validation
	auditEntry := map[string]interface{}{
		"timestamp":      time.Now(),
		"user":           jwtClaims.KubernetesUser,
		"session_id":     jwtClaims.SessionID,
		"validation_id":  kubeCommand.ValidationID,
		"command":        kubeCommand.GeneratedCommand,
		"original_input": kubeCommand.NaturalLanguageInput,
		"resources":      resources,
		"risk_level":     kubeCommand.RiskLevel,
		"status":         "rbac_validated",
	}

	// TODO: Integrate with proper audit logging service
	// For now, this creates a structured audit record
	_ = auditEntry
}

// getStory11TranslationPatterns returns the predefined translation patterns for Story 1.1 (read operations)
func getStory11TranslationPatterns() []TranslationPattern {
	return []TranslationPattern{
		// Get all pods - "show me all pods" → kubectl get pods
		{
			Pattern:     regexp.MustCompile(`^(?:show|get|list)(?:\s+me)?(?:\s+all)?\s+pods?$`),
			CommandFunc: func(matches []string) string { return "kubectl get pods" },
			RiskLevel:   models.RiskLevelSafe,
			Description: "List all pods in current namespace",
			ActionType:  "read",
		},
		// Get pods in specific namespace
		{
			Pattern: regexp.MustCompile(`^(?:show|get|list)(?:\s+me)?\s+pods?\s+in\s+namespace\s+(\w+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl get pods -n %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "List pods in specific namespace",
			ActionType:  "read",
		},
		// Get deployments
		{
			Pattern:     regexp.MustCompile(`^(?:show|get|list)(?:\s+me)?(?:\s+all)?\s+deployments?$`),
			CommandFunc: func(matches []string) string { return "kubectl get deployments" },
			RiskLevel:   models.RiskLevelSafe,
			Description: "List all deployments",
			ActionType:  "read",
		},
		// Get services
		{
			Pattern:     regexp.MustCompile(`^(?:show|get|list)(?:\s+me)?(?:\s+all)?\s+services?$`),
			CommandFunc: func(matches []string) string { return "kubectl get services" },
			RiskLevel:   models.RiskLevelSafe,
			Description: "List all services",
			ActionType:  "read",
		},
		// Get nodes
		{
			Pattern:     regexp.MustCompile(`^(?:show|get|list)(?:\s+me)?(?:\s+all)?\s+nodes?$`),
			CommandFunc: func(matches []string) string { return "kubectl get nodes" },
			RiskLevel:   models.RiskLevelSafe,
			Description: "List all nodes",
			ActionType:  "read",
		},
		// Get namespaces
		{
			Pattern:     regexp.MustCompile(`^(?:show|get|list)(?:\s+me)?(?:\s+all)?\s+namespaces?$`),
			CommandFunc: func(matches []string) string { return "kubectl get namespaces" },
			RiskLevel:   models.RiskLevelSafe,
			Description: "List all namespaces",
			ActionType:  "read",
		},
		// Describe specific service
		{
			Pattern: regexp.MustCompile(`^describe\s+service\s+(\w+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl describe service %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Describe a specific service",
			ActionType:  "read",
		},
		// Describe specific pod
		{
			Pattern: regexp.MustCompile(`^describe\s+pod\s+([a-zA-Z0-9\-]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl describe pod %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Describe a specific pod",
			ActionType:  "read",
		},
		// Describe specific deployment
		{
			Pattern: regexp.MustCompile(`^describe\s+deployment\s+([a-zA-Z0-9\-]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl describe deployment %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Describe a specific deployment",
			ActionType:  "read",
		},
		// Describe specific node
		{
			Pattern: regexp.MustCompile(`^describe\s+node\s+([a-zA-Z0-9\-\.]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl describe node %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Describe a specific node",
			ActionType:  "read",
		},
	}
}

// getWriteOperationPatterns returns patterns for write operations (Story 1.2)
func getWriteOperationPatterns() []TranslationPattern {
	return []TranslationPattern{
		// Create deployment - "create deployment nginx" → kubectl create deployment nginx --image=nginx (CAUTION)
		{
			Pattern: regexp.MustCompile(`^create\s+deployment\s+([a-zA-Z0-9\-]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl create deployment %s --image=%s", matches[1], matches[1])
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Create a deployment",
			ActionType:  "create",
		},
		// Scale deployment - "scale nginx to 5 replicas" → kubectl scale deployment nginx --replicas=5 (CAUTION)
		{
			Pattern: regexp.MustCompile(`^scale\s+([a-zA-Z0-9\-]+)\s+to\s+(\d+)\s+replicas?$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl scale deployment %s --replicas=%s", matches[1], matches[2])
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Scale a deployment",
			ActionType:  "update",
		},
		// Delete pod - "delete pod nginx-123" → kubectl delete pod nginx-123 (DESTRUCTIVE)
		{
			Pattern: regexp.MustCompile(`^delete\s+pod\s+([a-zA-Z0-9\-]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl delete pod %s", matches[1])
			},
			RiskLevel:   models.RiskLevelDestructive,
			Description: "Delete a pod",
			ActionType:  "delete",
		},
		// Delete deployment - "delete deployment nginx" → kubectl delete deployment nginx (DESTRUCTIVE)
		{
			Pattern: regexp.MustCompile(`^delete\s+deployment\s+([a-zA-Z0-9\-]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl delete deployment %s", matches[1])
			},
			RiskLevel:   models.RiskLevelDestructive,
			Description: "Delete a deployment",
			ActionType:  "delete",
		},
		// Update service - "update service nginx" → kubectl patch service nginx (CAUTION)
		{
			Pattern: regexp.MustCompile(`^update\s+service\s+([a-zA-Z0-9\-]+)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl patch service %s --patch='{\"spec\":{\"type\":\"NodePort\"}}'", matches[1])
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Update a service",
			ActionType:  "update",
		},
		// Apply manifest - "apply manifest.yaml" → kubectl apply -f manifest.yaml (CAUTION)
		{
			Pattern: regexp.MustCompile(`^apply\s+([a-zA-Z0-9\-\.]+\.ya?ml)$`),
			CommandFunc: func(matches []string) string {
				return fmt.Sprintf("kubectl apply -f %s", matches[1])
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Apply a manifest file",
			ActionType:  "create",
		},
	}
}

// Helper functions for write operations

// generateApprovalToken generates a secure random token for approval workflows
func generateApprovalToken() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// extractResourceKind extracts the Kubernetes resource kind from kubectl command
func extractResourceKind(command string) string {
	parts := strings.Split(command, " ")
	if len(parts) >= 3 {
		kind := parts[2]
		// Handle plural to singular conversion for common resources
		switch kind {
		case "pods":
			return "pod"
		case "deployments":
			return "deployment"
		case "services":
			return "service"
		case "nodes":
			return "node"
		case "namespaces":
			return "namespace"
		default:
			return kind
		}
	}
	return "unknown"
}

// getContextAwarePatterns returns patterns specifically designed for context-aware commands (Story 1.4)
func getContextAwarePatterns() []TranslationPattern {
	return []TranslationPattern{
		// Describe with ordinal reference - "describe the first pod" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^describe\s+(?:the\s+)?(first|second|third|fourth|fifth|\d+st|\d+nd|\d+rd|\d+th)\s+(pod|service|deployment|namespace|node)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl describe %s %s", matches[2], matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Describe resource by ordinal reference",
			ActionType:  "read",
		},
		// Describe with demonstrative reference - "describe that pod" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^describe\s+(that|this|the)\s+(pod|service|deployment|namespace|node)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl describe %s %s", matches[2], matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Describe resource by demonstrative reference",
			ActionType:  "read",
		},
		// Delete with ordinal reference - "delete the first pod" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^delete\s+(?:the\s+)?(first|second|third|fourth|fifth|\d+st|\d+nd|\d+rd|\d+th)\s+(pod|service|deployment)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl delete %s %s", matches[2], matches[1])
			},
			RiskLevel:   models.RiskLevelDestructive,
			Description: "Delete resource by ordinal reference",
			ActionType:  "delete",
		},
		// Delete with demonstrative reference - "delete that pod" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^delete\s+(that|this|the)\s+(pod|service|deployment)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl delete %s %s", matches[2], matches[1])
			},
			RiskLevel:   models.RiskLevelDestructive,
			Description: "Delete resource by demonstrative reference",
			ActionType:  "delete",
		},
		// Scale with ordinal reference - "scale the first deployment to 3" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^scale\s+(?:the\s+)?(first|second|third|fourth|fifth|\d+st|\d+nd|\d+rd|\d+th)\s+deployment\s+to\s+(\d+)(?:\s+replicas?)?$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl scale deployment %s --replicas=%s", matches[1], matches[2])
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Scale deployment by ordinal reference",
			ActionType:  "update",
		},
		// Scale with demonstrative reference - "scale that deployment to 3" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^scale\s+(that|this|the)\s+deployment\s+to\s+(\d+)(?:\s+replicas?)?$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl scale deployment %s --replicas=%s", matches[1], matches[2])
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Scale deployment by demonstrative reference",
			ActionType:  "update",
		},
		// Generic pronoun commands - "describe it", "delete them" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^(describe|delete|get|show)\s+(it|them|they|those|these)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				action := matches[1]
				return fmt.Sprintf("kubectl %s %s", action, matches[2])
			},
			RiskLevel:   determineRiskLevelFromAction,
			Description: "Execute command with pronoun reference",
			ActionType:  determineActionTypeFromVerb,
		},
		// Logs with context reference - "logs from the first pod/service" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^(?:get\s+)?logs?\s+(?:from\s+)?(?:the\s+)?(first|second|third|fourth|fifth|\d+st|\d+nd|\d+rd|\d+th)\s+(pod|service)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl logs %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Get logs from resource by ordinal reference",
			ActionType:  "read",
		},
		// Logs with demonstrative reference - "logs from that pod/service" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^(?:get\s+)?logs?\s+(?:from\s+)?(that|this|the)\s+(pod|service)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				return fmt.Sprintf("kubectl logs %s", matches[1])
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Get logs from resource by demonstrative reference",
			ActionType:  "read",
		},
		// Numbered reference patterns - "describe pod 1", "delete service 2" → resolved by context resolver
		{
			Pattern:     regexp.MustCompile(`^(describe|delete|get|show)\s+(pod|service|deployment|namespace|node)\s+(\d+)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				action := matches[1]
				resourceType := matches[2]
				number := matches[3]
				return fmt.Sprintf("kubectl %s %s %s", action, resourceType, number)
			},
			RiskLevel:   determineRiskLevelFromAction,
			Description: "Execute command with numbered reference",
			ActionType:  determineActionTypeFromVerb,
		},
		// Scale with numbered reference - "scale deployment 1 to 3"
		{
			Pattern:     regexp.MustCompile(`^scale\s+(deployment)\s+(\d+)\s+to\s+(\d+)(?:\s+replicas?)?$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				resourceType := matches[1]
				number := matches[2]
				replicas := matches[3]
				return fmt.Sprintf("kubectl scale %s %s --replicas=%s", resourceType, number, replicas)
			},
			RiskLevel:   models.RiskLevelCaution,
			Description: "Scale deployment by numbered reference",
			ActionType:  "update",
		},
		// Logs with numbered reference - "logs from pod 1"
		{
			Pattern:     regexp.MustCompile(`^(?:get\s+)?logs?\s+(?:from\s+)?(pod|service)\s+(\d+)$`),
			CommandFunc: func(matches []string) string {
				// This will be resolved by context resolver before reaching here
				number := matches[2]
				return fmt.Sprintf("kubectl logs %s", number) // Will be resolved to actual name
			},
			RiskLevel:   models.RiskLevelSafe,
			Description: "Get logs from resource by numbered reference",
			ActionType:  "read",
		},
	}
}

// Helper functions for dynamic risk and action type determination
func determineRiskLevelFromAction(matches []string) models.RiskLevel {
	if len(matches) >= 2 {
		action := strings.ToLower(matches[1])
		switch action {
		case "delete":
			return models.RiskLevelDestructive
		case "describe", "get", "show":
			return models.RiskLevelSafe
		default:
			return models.RiskLevelCaution
		}
	}
	return models.RiskLevelCaution
}

func determineActionTypeFromVerb(matches []string) string {
	if len(matches) >= 2 {
		action := strings.ToLower(matches[1])
		switch action {
		case "delete":
			return "delete"
		case "describe", "get", "show":
			return "read"
		case "scale", "update":
			return "update"
		case "create":
			return "create"
		default:
			return "read"
		}
	}
	return "read"
}

// buildKubectlCommand constructs a kubectl command from original input and resolved input
func (t *translatorService) buildKubectlCommand(originalInput, resolvedInput string, matches []string) string {
	// Extract the action from the original input and resource name from resolved input
	originalLower := strings.ToLower(strings.TrimSpace(originalInput))
	resolvedLower := strings.ToLower(strings.TrimSpace(resolvedInput))
	
	// Get the resource name from resolved input (it should be the last meaningful word)
	resolvedParts := strings.Fields(resolvedLower)
	var resourceName string
	if len(resolvedParts) > 0 {
		resourceName = resolvedParts[len(resolvedParts)-1] // Last word is usually the resolved resource name
	}
	
	// Map of common actions with the resolved resource name
	if strings.HasPrefix(originalLower, "describe") {
		resourceType := extractResourceTypeFromResolved(resourceName)
		return fmt.Sprintf("kubectl describe %s %s", resourceType, resourceName)
	} else if strings.HasPrefix(originalLower, "delete") {
		resourceType := extractResourceTypeFromResolved(resourceName)
		return fmt.Sprintf("kubectl delete %s %s", resourceType, resourceName)
	} else if strings.HasPrefix(originalLower, "scale") && strings.Contains(originalLower, "to") {
		// Extract replica count from original input
		originalParts := strings.Fields(originalLower)
		replicas := "1" // default
		for i, part := range originalParts {
			if part == "to" && i+1 < len(originalParts) {
				replicas = originalParts[i+1]
				break
			}
		}
		// Extract number from replicas (remove "replicas" if present)
		replicas = strings.TrimSuffix(replicas, "replicas")
		replicas = strings.TrimSuffix(replicas, "replica")
		return fmt.Sprintf("kubectl scale deployment %s --replicas=%s", resourceName, replicas)
	} else if strings.HasPrefix(originalLower, "logs") || strings.Contains(originalLower, "logs") {
		return fmt.Sprintf("kubectl logs %s", resourceName)
	} else if strings.HasPrefix(originalLower, "get") || strings.HasPrefix(originalLower, "show") {
		resourceType := extractResourceTypeFromResolved(resourceName)
		return fmt.Sprintf("kubectl get %s %s", resourceType, resourceName)
	}
	
	// Default fallback - try to infer action and resource
	action := "describe" // default action
	if strings.Contains(originalLower, "delete") {
		action = "delete"
	} else if strings.Contains(originalLower, "get") || strings.Contains(originalLower, "show") {
		action = "get"
	}
	
	resourceType := extractResourceTypeFromResolved(resourceName)
	return fmt.Sprintf("kubectl %s %s %s", action, resourceType, resourceName)
}

// buildKubectlCommandWithContext constructs a kubectl command using session context information
func (t *translatorService) buildKubectlCommandWithContext(originalInput, resolvedInput string, resolvedReferences []string, sessionContext *models.SessionContext) string {
	originalLower := strings.ToLower(strings.TrimSpace(originalInput))
	
	// Parse the resolved references to get resource type and name
	var resourceType, resourceName string
	
	if len(resolvedReferences) > 0 {
		// Parse the first resolved reference: "first pod -> nginx-deployment-1"
		for _, ref := range resolvedReferences {
			parts := strings.Split(ref, " -> ")
			if len(parts) == 2 {
				resourceName = parts[1]
				
				// Find the corresponding reference item to get the resource type
				if sessionContext != nil {
					for _, item := range sessionContext.ReferenceableItems {
						if item.Name == resourceName {
							resourceType = item.Type
							break
						}
					}
				}
				break
			}
		}
	}
	
	// If we couldn't determine resource type from context, fall back to inference
	if resourceType == "" {
		resourceType = extractResourceTypeFromResolved(resourceName)
	}
	
	// Build the kubectl command based on the action in original input
	if strings.HasPrefix(originalLower, "describe") {
		return fmt.Sprintf("kubectl describe %s %s", resourceType, resourceName)
	} else if strings.HasPrefix(originalLower, "delete") {
		return fmt.Sprintf("kubectl delete %s %s", resourceType, resourceName)
	} else if strings.HasPrefix(originalLower, "scale") && strings.Contains(originalLower, "to") {
		// Extract replica count from original input
		originalParts := strings.Fields(originalLower)
		replicas := "1" // default
		for i, part := range originalParts {
			if part == "to" && i+1 < len(originalParts) {
				replicas = originalParts[i+1]
				break
			}
		}
		// Clean up replica count
		replicas = strings.TrimSuffix(replicas, "replicas")
		replicas = strings.TrimSuffix(replicas, "replica")
		replicas = strings.TrimSpace(replicas)
		return fmt.Sprintf("kubectl scale %s %s --replicas=%s", resourceType, resourceName, replicas)
	} else if strings.HasPrefix(originalLower, "logs") || strings.Contains(originalLower, "logs") {
		return fmt.Sprintf("kubectl logs %s", resourceName)
	} else if strings.HasPrefix(originalLower, "get") || strings.HasPrefix(originalLower, "show") {
		return fmt.Sprintf("kubectl get %s %s", resourceType, resourceName)
	}
	
	// Default fallback
	return fmt.Sprintf("kubectl describe %s %s", resourceType, resourceName)
}

// extractResourceTypeFromResolved tries to determine resource type from a resolved resource name
func extractResourceTypeFromResolved(resourceName string) string {
	name := strings.ToLower(resourceName)
	
	// Common resource name patterns
	if strings.Contains(name, "deployment") {
		return "deployment"
	} else if strings.Contains(name, "service") || strings.Contains(name, "svc") {
		return "service"
	} else if strings.Contains(name, "pod") {
		return "pod"
	} else if strings.Contains(name, "namespace") || strings.Contains(name, "ns") {
		return "namespace"
	} else if strings.Contains(name, "node") {
		return "node"
	} else if strings.Contains(name, "configmap") || strings.Contains(name, "cm") {
		return "configmap"
	} else if strings.Contains(name, "secret") {
		return "secret"
	}
	
	// Default to pod if we can't determine
	return "pod"
}
