// Package models provides structured permission error handling for KubeChat (Story 2.5)
package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PermissionError represents a comprehensive permission error with guidance
// Extends Story 2.2 RBAC validation errors with user guidance and context
type PermissionError struct {
	// Basic error identification
	ID          string    `json:"id"`
	Type        ErrorType `json:"type"`
	Code        string    `json:"code"`
	Message     string    `json:"message"`
	Timestamp   time.Time `json:"timestamp"`
	CorrelationID string  `json:"correlation_id"`

	// Permission context (from Story 2.2 RBAC validation)
	Resource      string `json:"resource"`                // pods, deployments, etc.
	Verb          string `json:"verb"`                   // get, list, create, delete
	Namespace     string `json:"namespace"`              // target namespace
	ClusterScoped bool   `json:"cluster_scoped"`         // cluster-level operation
	ResourceGroup string `json:"resource_group"`         // api group (apps/v1, etc.)
	
	// User context (from Story 2.1.2 JWT claims)
	UserID            string   `json:"user_id"`
	KubernetesUser    string   `json:"kubernetes_user"`    // K8s user for impersonation
	KubernetesGroups  []string `json:"kubernetes_groups"`  // Current user groups
	AllowedNamespaces []string `json:"allowed_namespaces"` // Accessible namespaces
	ClusterAccess     bool     `json:"cluster_access"`     // Cluster permissions
	
	// Natural language context
	OriginalInput     string `json:"original_input"`      // User's original NL command
	AttemptedOperation string `json:"attempted_operation"` // What the user was trying to do
	
	// Error categorization
	Category        PermissionErrorCategory `json:"category"`
	Severity        ErrorSeverity          `json:"severity"`
	Recoverable     bool                   `json:"recoverable"`
	EscalationLevel EscalationLevel        `json:"escalation_level"`
	
	// User guidance and suggestions
	UserFriendlyMessage string               `json:"user_friendly_message"`
	ActionableSteps     []string            `json:"actionable_steps"`
	RequiredPermissions []RequiredPermission `json:"required_permissions"`
	AlternativeActions  []AlternativeAction  `json:"alternative_actions"`
	AdminGuidance       *AdminGuidance       `json:"admin_guidance,omitempty"`
	
	// Debugging and audit context
	TraceInformation  *PermissionTrace `json:"trace_information,omitempty"`
	AuditTrail        []AuditEntry     `json:"audit_trail"`
	SuggestedCommands []string         `json:"suggested_commands"`
	
	// Error resolution context
	SelfServiceOptions []SelfServiceOption `json:"self_service_options"`
	ContactInformation *ContactInfo        `json:"contact_information,omitempty"`
	DocumentationLinks []DocumentationLink `json:"documentation_links"`
}

// PermissionErrorCategory defines specific permission error types
type PermissionErrorCategory string

const (
	PermissionCategoryNamespaceAccess   PermissionErrorCategory = "namespace_access"
	PermissionCategoryResourceAccess    PermissionErrorCategory = "resource_access"
	PermissionCategoryVerbRestriction   PermissionErrorCategory = "verb_restriction"
	PermissionCategoryClusterAccess     PermissionErrorCategory = "cluster_access"
	PermissionCategoryRoleBinding       PermissionErrorCategory = "role_binding"
	PermissionCategoryServiceAccount    PermissionErrorCategory = "service_account"
	PermissionCategoryNetworkPolicy     PermissionErrorCategory = "network_policy"
	PermissionCategoryQuotaExceeded     PermissionErrorCategory = "quota_exceeded"
)

// RequiredPermission represents a specific permission needed
type RequiredPermission struct {
	Resource      string `json:"resource"`
	Verb          string `json:"verb"`
	Namespace     string `json:"namespace,omitempty"`
	ClusterScoped bool   `json:"cluster_scoped"`
	APIGroup      string `json:"api_group,omitempty"`
	Explanation   string `json:"explanation"`
}

// AlternativeAction suggests alternative approaches
type AlternativeAction struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Commands    []string `json:"commands,omitempty"`
	Permissions []RequiredPermission `json:"permissions,omitempty"`
	Difficulty  string   `json:"difficulty"` // "easy", "medium", "hard"
}

// AdminGuidance provides information for administrators
type AdminGuidance struct {
	RoleBindingCommands []string `json:"role_binding_commands"`
	ClusterRoleCommands []string `json:"cluster_role_commands"`
	PolicyRecommendations []string `json:"policy_recommendations"`
	SecurityConsiderations string `json:"security_considerations"`
}

// PermissionTrace provides detailed information about permission evaluation
type PermissionTrace struct {
	EvaluatedRoles     []string    `json:"evaluated_roles"`
	EvaluatedBindings  []string    `json:"evaluated_bindings"`
	FailurePoint       string      `json:"failure_point"`
	EvaluationPath     []string    `json:"evaluation_path"`
	K8sAPIResponse     string      `json:"k8s_api_response,omitempty"`
	EvaluationDuration time.Duration `json:"evaluation_duration"`
}

// AuditEntry represents an audit log entry for the permission failure
type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	Action      string    `json:"action"`
	Result      string    `json:"result"`
	Details     string    `json:"details"`
	UserAgent   string    `json:"user_agent,omitempty"`
	SourceIP    string    `json:"source_ip,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
}

// SelfServiceOption provides user self-service resolution options
type SelfServiceOption struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Actions     []string `json:"actions"`
	Automated   bool     `json:"automated"` // Can be automated through KubeChat
	Estimated   string   `json:"estimated"` // "5 minutes", "requires admin approval"
}

// ContactInfo provides administrator contact information
type ContactInfo struct {
	AdminEmail      string `json:"admin_email,omitempty"`
	SupportURL      string `json:"support_url,omitempty"`
	SlackChannel    string `json:"slack_channel,omitempty"`
	TicketingSystem string `json:"ticketing_system,omitempty"`
	EscalationPath  string `json:"escalation_path,omitempty"`
}

// DocumentationLink provides relevant documentation
type DocumentationLink struct {
	Title       string `json:"title"`
	URL         string `json:"url"`
	Description string `json:"description"`
	Type        string `json:"type"` // "tutorial", "reference", "troubleshooting"
}

// PermissionErrorBuilder provides a fluent interface for building permission errors
type PermissionErrorBuilder struct {
	error *PermissionError
}

// NewPermissionErrorBuilder creates a new permission error builder
func NewPermissionErrorBuilder() *PermissionErrorBuilder {
	return &PermissionErrorBuilder{
		error: &PermissionError{
			ID:            uuid.New().String(),
			Timestamp:     time.Now(),
			CorrelationID: generateCorrelationID(),
			Type:          ErrorTypePermissionDenied,
			AuditTrail:    make([]AuditEntry, 0),
		},
	}
}

// WithBasicInfo sets basic error information
func (b *PermissionErrorBuilder) WithBasicInfo(code, message string) *PermissionErrorBuilder {
	b.error.Code = code
	b.error.Message = message
	return b
}

// WithPermissionContext sets permission context from RBAC validation
func (b *PermissionErrorBuilder) WithPermissionContext(resource, verb, namespace string, clusterScoped bool) *PermissionErrorBuilder {
	b.error.Resource = resource
	b.error.Verb = verb
	b.error.Namespace = namespace
	b.error.ClusterScoped = clusterScoped
	return b
}

// WithUserContext sets user context from JWT claims
func (b *PermissionErrorBuilder) WithUserContext(userID, k8sUser string, k8sGroups, allowedNs []string, clusterAccess bool) *PermissionErrorBuilder {
	b.error.UserID = userID
	b.error.KubernetesUser = k8sUser
	b.error.KubernetesGroups = k8sGroups
	b.error.AllowedNamespaces = allowedNs
	b.error.ClusterAccess = clusterAccess
	return b
}

// WithNaturalLanguageContext sets natural language context
func (b *PermissionErrorBuilder) WithNaturalLanguageContext(originalInput, attemptedOperation string) *PermissionErrorBuilder {
	b.error.OriginalInput = originalInput
	b.error.AttemptedOperation = attemptedOperation
	return b
}

// WithCategory sets error category and automatically infers severity
func (b *PermissionErrorBuilder) WithCategory(category PermissionErrorCategory) *PermissionErrorBuilder {
	b.error.Category = category
	b.error.Severity = inferSeverity(category)
	b.error.Recoverable = isRecoverable(category)
	b.error.EscalationLevel = inferEscalationLevel(category)
	return b
}

// WithGuidance sets user guidance and suggestions
func (b *PermissionErrorBuilder) WithGuidance(message string, steps []string) *PermissionErrorBuilder {
	b.error.UserFriendlyMessage = message
	b.error.ActionableSteps = steps
	return b
}

// WithRequiredPermissions adds required permissions
func (b *PermissionErrorBuilder) WithRequiredPermissions(permissions []RequiredPermission) *PermissionErrorBuilder {
	b.error.RequiredPermissions = permissions
	return b
}

// WithAlternativeActions adds alternative actions
func (b *PermissionErrorBuilder) WithAlternativeActions(actions []AlternativeAction) *PermissionErrorBuilder {
	b.error.AlternativeActions = actions
	return b
}

// WithAdminGuidance adds administrator guidance
func (b *PermissionErrorBuilder) WithAdminGuidance(guidance *AdminGuidance) *PermissionErrorBuilder {
	b.error.AdminGuidance = guidance
	return b
}

// WithTrace adds permission evaluation trace information
func (b *PermissionErrorBuilder) WithTrace(trace *PermissionTrace) *PermissionErrorBuilder {
	b.error.TraceInformation = trace
	return b
}

// WithSelfServiceOptions adds self-service resolution options
func (b *PermissionErrorBuilder) WithSelfServiceOptions(options []SelfServiceOption) *PermissionErrorBuilder {
	b.error.SelfServiceOptions = options
	return b
}

// WithContactInfo adds administrator contact information
func (b *PermissionErrorBuilder) WithContactInfo(contact *ContactInfo) *PermissionErrorBuilder {
	b.error.ContactInformation = contact
	return b
}

// AddAuditEntry adds an audit entry
func (b *PermissionErrorBuilder) AddAuditEntry(action, result, details string) *PermissionErrorBuilder {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Result:    result,
		Details:   details,
	}
	b.error.AuditTrail = append(b.error.AuditTrail, entry)
	return b
}

// Build creates the final permission error
func (b *PermissionErrorBuilder) Build() *PermissionError {
	// Set correlation ID if not set
	if b.error.CorrelationID == "" {
		b.error.CorrelationID = generateCorrelationID()
	}
	
	// Generate user-friendly message if not set
	if b.error.UserFriendlyMessage == "" {
		b.error.UserFriendlyMessage = b.generateUserFriendlyMessage()
	}
	
	return b.error
}

// Error implements the error interface
func (pe *PermissionError) Error() string {
	return fmt.Sprintf("Permission denied: %s (Code: %s, ID: %s)", pe.Message, pe.Code, pe.ID)
}

// ToJSON serializes the permission error to JSON
func (pe *PermissionError) ToJSON() ([]byte, error) {
	return json.MarshalIndent(pe, "", "  ")
}

// ToUserFriendlyString returns a user-friendly string representation
func (pe *PermissionError) ToUserFriendlyString() string {
	var sb strings.Builder
	
	sb.WriteString(fmt.Sprintf("❌ %s\n\n", pe.UserFriendlyMessage))
	
	if len(pe.ActionableSteps) > 0 {
		sb.WriteString("🔧 **What you can do:**\n")
		for i, step := range pe.ActionableSteps {
			sb.WriteString(fmt.Sprintf("   %d. %s\n", i+1, step))
		}
		sb.WriteString("\n")
	}
	
	if len(pe.RequiredPermissions) > 0 {
		sb.WriteString("🔑 **Required permissions:**\n")
		for _, perm := range pe.RequiredPermissions {
			ns := perm.Namespace
			if ns == "" {
				ns = "cluster-wide"
			}
			sb.WriteString(fmt.Sprintf("   • %s %s in %s (%s)\n", perm.Verb, perm.Resource, ns, perm.Explanation))
		}
		sb.WriteString("\n")
	}
	
	if len(pe.AlternativeActions) > 0 {
		sb.WriteString("💡 **Alternative approaches:**\n")
		for _, action := range pe.AlternativeActions {
			sb.WriteString(fmt.Sprintf("   • %s - %s\n", action.Title, action.Description))
		}
		sb.WriteString("\n")
	}
	
	if pe.ContactInformation != nil {
		sb.WriteString("📞 **Need help?**\n")
		if pe.ContactInformation.AdminEmail != "" {
			sb.WriteString(fmt.Sprintf("   • Email: %s\n", pe.ContactInformation.AdminEmail))
		}
		if pe.ContactInformation.SlackChannel != "" {
			sb.WriteString(fmt.Sprintf("   • Slack: %s\n", pe.ContactInformation.SlackChannel))
		}
		sb.WriteString("\n")
	}
	
	sb.WriteString(fmt.Sprintf("🔍 **Reference ID:** %s\n", pe.ID))
	
	return sb.String()
}

// Helper functions

func generateCorrelationID() string {
	return fmt.Sprintf("perm_%s_%d", uuid.New().String()[:8], time.Now().Unix())
}

func inferSeverity(category PermissionErrorCategory) ErrorSeverity {
	switch category {
	case PermissionCategoryClusterAccess:
		return ErrorSeverityHigh
	case PermissionCategoryRoleBinding, PermissionCategoryServiceAccount:
		return ErrorSeverityMedium
	case PermissionCategoryNamespaceAccess, PermissionCategoryResourceAccess:
		return ErrorSeverityLow
	default:
		return ErrorSeverityMedium
	}
}

func isRecoverable(category PermissionErrorCategory) bool {
	// Most permission errors are recoverable through proper RBAC configuration
	return true
}

func inferEscalationLevel(category PermissionErrorCategory) EscalationLevel {
	switch category {
	case PermissionCategoryClusterAccess:
		return EscalationLevelHigh
	case PermissionCategoryServiceAccount, PermissionCategoryRoleBinding:
		return EscalationLevelMedium
	default:
		return EscalationLevelLow
	}
}

func (b *PermissionErrorBuilder) generateUserFriendlyMessage() string {
	if b.error.OriginalInput != "" && b.error.AttemptedOperation != "" {
		return fmt.Sprintf("You don't have permission to %s. Your request '%s' requires additional access rights.",
			b.error.AttemptedOperation, b.error.OriginalInput)
	}
	
	if b.error.Resource != "" && b.error.Verb != "" {
		ns := b.error.Namespace
		if ns == "" {
			ns = "cluster-wide"
		}
		return fmt.Sprintf("You don't have permission to %s %s resources in %s.",
			b.error.Verb, b.error.Resource, ns)
	}
	
	return "You don't have sufficient permissions to perform this operation."
}

// Integration with existing error handling from Epic 1
func (pe *PermissionError) ToKubectlError() *KubectlError {
	return &KubectlError{
		Type:             pe.Type,
		Code:             pe.Code,
		Message:          pe.Message,
		Suggestion:       pe.UserFriendlyMessage,
		Resource:         pe.Resource,
		Namespace:        pe.Namespace,
		Recoverable:      pe.Recoverable,
		EscalationLevel:  pe.EscalationLevel,
		RetryRecommended: false, // Permission errors typically don't benefit from retries
	}
}