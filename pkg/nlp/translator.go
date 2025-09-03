package nlp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// TranslatorService defines the interface for natural language to kubectl translation
type TranslatorService interface {
	TranslateCommand(ctx context.Context, input string) (*models.KubernetesCommand, error)
}

// translatorService implements the TranslatorService interface for Story 1.1
type translatorService struct {
	patterns []TranslationPattern
}

// TranslationPattern represents a pattern for translating natural language to kubectl commands
type TranslationPattern struct {
	Pattern     *regexp.Regexp
	CommandFunc func(matches []string) string
	RiskLevel   models.RiskLevel
	Description string
	ActionType  string // NEW: Action type classification (create, read, update, delete)
}

// NewTranslatorService creates a new translator service with predefined patterns including write operations
func NewTranslatorService() TranslatorService {
	patterns := getStory11TranslationPatterns()                 // Read operations from Story 1.1
	patterns = append(patterns, getWriteOperationPatterns()...) // Write operations for Story 1.2

	return &translatorService{
		patterns: patterns,
	}
}

// TranslateCommand translates natural language input to a kubectl command with safety analysis
func (t *translatorService) TranslateCommand(ctx context.Context, input string) (*models.KubernetesCommand, error) {
	if input == "" {
		return nil, fmt.Errorf("input cannot be empty")
	}

	// Normalize input (lowercase, trim whitespace)
	normalizedInput := strings.ToLower(strings.TrimSpace(input))

	// Try to match against known patterns
	for _, pattern := range t.patterns {
		if pattern.Pattern.MatchString(normalizedInput) {
			matches := pattern.Pattern.FindStringSubmatch(normalizedInput)
			command := pattern.CommandFunc(matches)

			// Create KubernetesCommand object
			kubeCommand := models.NewKubernetesCommand("", input, command, pattern.RiskLevel)

			// Set action type for resource impact analysis
			if len(kubeCommand.Resources) == 0 {
				kubeCommand.Resources = []models.KubernetesResource{
					{
						Kind:   extractResourceKind(command),
						Action: pattern.ActionType,
					},
				}
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
	}

	// If no pattern matches, return helpful error message
	return nil, fmt.Errorf("unable to translate input: %q. Supported commands include: show pods, create deployment, scale deployment, delete pod", input)
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
