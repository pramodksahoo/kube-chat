// Package middleware provides RBAC permission suggestion engine for KubeChat (Story 2.5)
package middleware

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// RBACAdvisor provides intelligent RBAC permission suggestions and analysis
type RBACAdvisor struct {
	kubeClient     kubernetes.Interface
	redisClient    redis.UniversalClient
	validator      *RBACValidator
	cacheTTL       time.Duration
	cachePrefix    string
	enableCaching  bool
	mutex          sync.RWMutex
	metrics        *RBACAdvisorMetrics
}

// RBACAdvisorConfig holds configuration for the RBAC advisor
type RBACAdvisorConfig struct {
	KubeClient    kubernetes.Interface
	RedisClient   redis.UniversalClient
	Validator     *RBACValidator
	CacheTTL      time.Duration
	EnableCaching bool
	CachePrefix   string
}

// PermissionGap represents the difference between current and required permissions
type PermissionGap struct {
	MissingPermissions []models.RequiredPermission `json:"missing_permissions"`
	ExcessPermissions  []models.RequiredPermission `json:"excess_permissions"`
	CurrentRoles       []string                    `json:"current_roles"`
	CurrentBindings    []string                    `json:"current_bindings"`
	Recommendations    *PermissionRecommendations  `json:"recommendations"`
}

// PermissionRecommendations provides specific RBAC recommendations
type PermissionRecommendations struct {
	SuggestedRoles        []RoleRecommendation        `json:"suggested_roles"`
	SuggestedBindings     []RoleBindingRecommendation `json:"suggested_bindings"`
	KubectlCommands       []string                    `json:"kubectl_commands"`
	SecurityConsiderations []string                   `json:"security_considerations"`
	MinimalPermissionSet   []models.RequiredPermission `json:"minimal_permission_set"`
}

// RoleRecommendation suggests specific roles for the user
type RoleRecommendation struct {
	Name          string   `json:"name"`
	Type          string   `json:"type"` // "ClusterRole" or "Role"
	Namespace     string   `json:"namespace,omitempty"`
	Reason        string   `json:"reason"`
	Permissions   []string `json:"permissions"`
	SecurityLevel string   `json:"security_level"` // "minimal", "standard", "elevated"
	Exists        bool     `json:"exists"`         // Whether role already exists
}

// RoleBindingRecommendation suggests specific role bindings
type RoleBindingRecommendation struct {
	Name           string   `json:"name"`
	Type           string   `json:"type"` // "ClusterRoleBinding" or "RoleBinding"
	RoleName       string   `json:"role_name"`
	Namespace      string   `json:"namespace,omitempty"`
	Subject        string   `json:"subject"`
	SubjectType    string   `json:"subject_type"` // "User", "Group", "ServiceAccount"
	Justification  string   `json:"justification"`
	TemporarySuggestion bool `json:"temporary_suggestion"`
	ExpiryRecommendation string `json:"expiry_recommendation,omitempty"`
}

// RBACAdvisorMetrics tracks advisor performance and usage
type RBACAdvisorMetrics struct {
	AnalysisRequests      int64         `json:"analysis_requests"`
	CacheHits             int64         `json:"cache_hits"`
	CacheMisses           int64         `json:"cache_misses"`
	AverageAnalysisTime   time.Duration `json:"average_analysis_time"`
	RecommendationAccuracy float64      `json:"recommendation_accuracy"`
	mutex                 sync.RWMutex
}

// NewRBACAdvisor creates a new RBAC advisor instance
func NewRBACAdvisor(config RBACAdvisorConfig) (*RBACAdvisor, error) {
	if config.KubeClient == nil {
		return nil, fmt.Errorf("kubernetes client is required")
	}

	if config.Validator == nil {
		return nil, fmt.Errorf("RBAC validator is required")
	}

	return &RBACAdvisor{
		kubeClient:    config.KubeClient,
		redisClient:   config.RedisClient,
		validator:     config.Validator,
		cacheTTL:      config.CacheTTL,
		enableCaching: config.EnableCaching,
		cachePrefix:   config.CachePrefix + ":rbac_advisor",
		metrics:       &RBACAdvisorMetrics{},
	}, nil
}

// AnalyzePermissionGap analyzes the gap between current and required permissions
func (advisor *RBACAdvisor) AnalyzePermissionGap(ctx context.Context, userContext *JWTClaims, requiredPermissions []models.RequiredPermission) (*PermissionGap, error) {
	startTime := time.Now()
	defer func() {
		advisor.updateMetrics(time.Since(startTime))
	}()

	// Check cache first
	if advisor.enableCaching {
		if gap, found := advisor.getCachedGap(ctx, userContext, requiredPermissions); found {
			advisor.metrics.mutex.Lock()
			advisor.metrics.CacheHits++
			advisor.metrics.mutex.Unlock()
			return gap, nil
		}
	}

	advisor.metrics.mutex.Lock()
	advisor.metrics.CacheMisses++
	advisor.metrics.mutex.Unlock()

	// Analyze current permissions
	currentRoles, currentBindings, err := advisor.getCurrentPermissions(ctx, userContext)
	if err != nil {
		return nil, fmt.Errorf("failed to get current permissions: %w", err)
	}

	// Identify missing permissions
	missingPermissions, err := advisor.identifyMissingPermissions(ctx, userContext, requiredPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to identify missing permissions: %w", err)
	}

	// Generate recommendations
	recommendations, err := advisor.generateRecommendations(ctx, userContext, missingPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate recommendations: %w", err)
	}

	gap := &PermissionGap{
		MissingPermissions: missingPermissions,
		CurrentRoles:       currentRoles,
		CurrentBindings:    currentBindings,
		Recommendations:    recommendations,
	}

	// Cache the result
	if advisor.enableCaching {
		advisor.cacheGap(ctx, userContext, requiredPermissions, gap)
	}

	return gap, nil
}

// GenerateKubectlCommands generates specific kubectl commands for permission resolution
func (advisor *RBACAdvisor) GenerateKubectlCommands(ctx context.Context, userContext *JWTClaims, missingPermissions []models.RequiredPermission) ([]string, error) {
	var commands []string

	// Group permissions by resource type and namespace
	permissionGroups := advisor.groupPermissionsByContext(missingPermissions)

	for namespace, permissions := range permissionGroups {
		// Generate role and role binding commands
		roleName := advisor.generateRoleName(userContext.KubernetesUser, namespace)
		
		if namespace == "" {
			// Cluster-wide permissions - use ClusterRole and ClusterRoleBinding
			commands = append(commands, advisor.generateClusterRoleCommand(roleName, permissions))
			commands = append(commands, advisor.generateClusterRoleBindingCommand(roleName, userContext))
		} else {
			// Namespace-specific permissions - use Role and RoleBinding
			commands = append(commands, advisor.generateRoleCommand(roleName, namespace, permissions))
			commands = append(commands, advisor.generateRoleBindingCommand(roleName, namespace, userContext))
		}
	}

	// Add verification commands
	commands = append(commands, advisor.generateVerificationCommands(userContext, missingPermissions)...)

	return commands, nil
}

// SuggestMinimalPermissions suggests the minimal set of permissions required
func (advisor *RBACAdvisor) SuggestMinimalPermissions(ctx context.Context, requiredPermissions []models.RequiredPermission) ([]models.RequiredPermission, error) {
	// Remove redundant permissions
	minimalSet := advisor.deduplicatePermissions(requiredPermissions)
	
	// Optimize verb combinations
	minimalSet = advisor.optimizeVerbs(minimalSet)
	
	// Group by resource hierarchy
	minimalSet = advisor.optimizeResourceHierarchy(minimalSet)
	
	return minimalSet, nil
}

// GetRoleSuggestions provides intelligent role suggestions based on permission patterns
func (advisor *RBACAdvisor) GetRoleSuggestions(ctx context.Context, requiredPermissions []models.RequiredPermission) ([]RoleRecommendation, error) {
	var suggestions []RoleRecommendation

	// Check for standard role patterns
	standardRoles := advisor.matchStandardRoles(requiredPermissions)
	suggestions = append(suggestions, standardRoles...)

	// Check for existing roles that could work
	existingRoles, err := advisor.findSuitableExistingRoles(ctx, requiredPermissions)
	if err == nil {
		suggestions = append(suggestions, existingRoles...)
	}

	// Generate custom role suggestions if needed
	if len(suggestions) == 0 {
		customRole := advisor.generateCustomRoleRecommendation(requiredPermissions)
		suggestions = append(suggestions, customRole)
	}

	// Sort by security level (minimal permissions first)
	sort.Slice(suggestions, func(i, j int) bool {
		securityOrder := map[string]int{"minimal": 1, "standard": 2, "elevated": 3}
		return securityOrder[suggestions[i].SecurityLevel] < securityOrder[suggestions[j].SecurityLevel]
	})

	return suggestions, nil
}

// Private helper methods

func (advisor *RBACAdvisor) getCurrentPermissions(ctx context.Context, userContext *JWTClaims) ([]string, []string, error) {
	var roles []string
	var bindings []string

	// Get ClusterRoleBindings for the user
	clusterBindings, err := advisor.kubeClient.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
	}

	for _, binding := range clusterBindings.Items {
		if advisor.isSubjectInBinding(userContext, binding.Subjects) {
			bindings = append(bindings, fmt.Sprintf("ClusterRoleBinding:%s", binding.Name))
			roles = append(roles, fmt.Sprintf("ClusterRole:%s", binding.RoleRef.Name))
		}
	}

	// Get RoleBindings for accessible namespaces
	for _, namespace := range userContext.AllowedNamespaces {
		roleBindings, err := advisor.kubeClient.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue // Skip if we can't access this namespace
		}

		for _, binding := range roleBindings.Items {
			if advisor.isSubjectInBinding(userContext, binding.Subjects) {
				bindings = append(bindings, fmt.Sprintf("RoleBinding:%s:%s", binding.Namespace, binding.Name))
				roles = append(roles, fmt.Sprintf("Role:%s:%s", binding.Namespace, binding.RoleRef.Name))
			}
		}
	}

	return roles, bindings, nil
}

func (advisor *RBACAdvisor) isSubjectInBinding(userContext *JWTClaims, subjects []rbacv1.Subject) bool {
	for _, subject := range subjects {
		if subject.Kind == "User" && subject.Name == userContext.KubernetesUser {
			return true
		}
		if subject.Kind == "Group" {
			for _, group := range userContext.KubernetesGroups {
				if subject.Name == group {
					return true
				}
			}
		}
	}
	return false
}

func (advisor *RBACAdvisor) identifyMissingPermissions(ctx context.Context, userContext *JWTClaims, requiredPermissions []models.RequiredPermission) ([]models.RequiredPermission, error) {
	var missing []models.RequiredPermission

	for _, permission := range requiredPermissions {
		request := &PermissionRequest{
			KubernetesUser:   userContext.KubernetesUser,
			KubernetesGroups: userContext.KubernetesGroups,
			Resource:         permission.Resource,
			Verb:             permission.Verb,
			Namespace:        permission.Namespace,
			APIGroup:         permission.APIGroup,
		}

		permissionResponse, err := advisor.validator.ValidatePermission(ctx, *request)
		if err != nil || permissionResponse == nil || !permissionResponse.Allowed {
			missing = append(missing, permission)
		}
	}

	return missing, nil
}

func (advisor *RBACAdvisor) generateRecommendations(ctx context.Context, userContext *JWTClaims, missingPermissions []models.RequiredPermission) (*PermissionRecommendations, error) {
	// Get role suggestions
	roleSuggestions, err := advisor.GetRoleSuggestions(ctx, missingPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to get role suggestions: %w", err)
	}

	// Generate role binding suggestions
	bindingSuggestions := advisor.generateRoleBindingSuggestions(userContext, roleSuggestions)

	// Generate kubectl commands
	kubectlCommands, err := advisor.GenerateKubectlCommands(ctx, userContext, missingPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to generate kubectl commands: %w", err)
	}

	// Generate security considerations
	securityConsiderations := advisor.generateSecurityConsiderations(missingPermissions)

	// Get minimal permission set
	minimalPermissions, err := advisor.SuggestMinimalPermissions(ctx, missingPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to suggest minimal permissions: %w", err)
	}

	return &PermissionRecommendations{
		SuggestedRoles:         roleSuggestions,
		SuggestedBindings:      bindingSuggestions,
		KubectlCommands:        kubectlCommands,
		SecurityConsiderations: securityConsiderations,
		MinimalPermissionSet:   minimalPermissions,
	}, nil
}

func (advisor *RBACAdvisor) matchStandardRoles(requiredPermissions []models.RequiredPermission) []RoleRecommendation {
	var suggestions []RoleRecommendation

	// Define standard role patterns
	standardRoles := map[string]struct {
		resources []string
		verbs     []string
		level     string
		reason    string
	}{
		"view": {
			resources: []string{"pods", "services", "configmaps", "secrets"},
			verbs:     []string{"get", "list", "watch"},
			level:     "minimal",
			reason:    "Read-only access to common resources",
		},
		"edit": {
			resources: []string{"pods", "services", "configmaps", "deployments"},
			verbs:     []string{"get", "list", "watch", "create", "update", "patch", "delete"},
			level:     "standard",
			reason:    "Standard developer access",
		},
		"admin": {
			resources: []string{"*"},
			verbs:     []string{"*"},
			level:     "elevated",
			reason:    "Administrative access to namespace resources",
		},
	}

	for roleName, rolePattern := range standardRoles {
		if advisor.permissionsMatchPattern(requiredPermissions, rolePattern.resources, rolePattern.verbs) {
			suggestions = append(suggestions, RoleRecommendation{
				Name:          roleName,
				Type:          "ClusterRole",
				Reason:        rolePattern.reason,
				Permissions:   rolePattern.verbs,
				SecurityLevel: rolePattern.level,
				Exists:        true,
			})
		}
	}

	return suggestions
}

func (advisor *RBACAdvisor) permissionsMatchPattern(permissions []models.RequiredPermission, resources, verbs []string) bool {
	// Simple pattern matching logic - can be enhanced
	for _, perm := range permissions {
		resourceMatch := false
		verbMatch := false

		for _, resource := range resources {
			if resource == "*" || resource == perm.Resource {
				resourceMatch = true
				break
			}
		}

		for _, verb := range verbs {
			if verb == "*" || verb == perm.Verb {
				verbMatch = true
				break
			}
		}

		if !resourceMatch || !verbMatch {
			return false
		}
	}

	return true
}

func (advisor *RBACAdvisor) findSuitableExistingRoles(ctx context.Context, requiredPermissions []models.RequiredPermission) ([]RoleRecommendation, error) {
	var suggestions []RoleRecommendation

	// List all ClusterRoles
	clusterRoles, err := advisor.kubeClient.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return suggestions, err
	}

	for _, role := range clusterRoles.Items {
		if advisor.roleCoversPermissions(role.Rules, requiredPermissions) {
			suggestions = append(suggestions, RoleRecommendation{
				Name:          role.Name,
				Type:          "ClusterRole",
				Reason:        fmt.Sprintf("Existing role that covers required permissions"),
				SecurityLevel: advisor.assessRoleSecurityLevel(role.Rules),
				Exists:        true,
			})
		}
	}

	return suggestions, nil
}

func (advisor *RBACAdvisor) roleCoversPermissions(rules []rbacv1.PolicyRule, requiredPermissions []models.RequiredPermission) bool {
	for _, permission := range requiredPermissions {
		covered := false
		for _, rule := range rules {
			if advisor.ruleCoversPermission(rule, permission) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func (advisor *RBACAdvisor) ruleCoversPermission(rule rbacv1.PolicyRule, permission models.RequiredPermission) bool {
	// Check API groups
	apiGroupMatch := false
	for _, group := range rule.APIGroups {
		if group == "*" || group == permission.APIGroup {
			apiGroupMatch = true
			break
		}
	}
	if !apiGroupMatch {
		return false
	}

	// Check resources
	resourceMatch := false
	for _, resource := range rule.Resources {
		if resource == "*" || resource == permission.Resource {
			resourceMatch = true
			break
		}
	}
	if !resourceMatch {
		return false
	}

	// Check verbs
	verbMatch := false
	for _, verb := range rule.Verbs {
		if verb == "*" || verb == permission.Verb {
			verbMatch = true
			break
		}
	}

	return verbMatch
}

func (advisor *RBACAdvisor) assessRoleSecurityLevel(rules []rbacv1.PolicyRule) string {
	hasWildcard := false
	hasDeleteVerbs := false
	hasClusterResources := false

	for _, rule := range rules {
		for _, group := range rule.APIGroups {
			if group == "*" {
				hasWildcard = true
			}
		}
		for _, resource := range rule.Resources {
			if resource == "*" || strings.Contains(resource, "cluster") {
				hasClusterResources = true
			}
		}
		for _, verb := range rule.Verbs {
			if verb == "*" || verb == "delete" || verb == "deletecollection" {
				hasDeleteVerbs = true
			}
		}
	}

	if hasWildcard || (hasDeleteVerbs && hasClusterResources) {
		return "elevated"
	} else if hasDeleteVerbs {
		return "standard"
	}
	return "minimal"
}

func (advisor *RBACAdvisor) generateCustomRoleRecommendation(requiredPermissions []models.RequiredPermission) RoleRecommendation {
	return RoleRecommendation{
		Name:          "custom-kubechat-role",
		Type:          "Role",
		Reason:        "Custom role tailored to specific permission requirements",
		SecurityLevel: "minimal",
		Exists:        false,
	}
}

// Additional helper methods for command generation, caching, etc.

func (advisor *RBACAdvisor) groupPermissionsByContext(permissions []models.RequiredPermission) map[string][]models.RequiredPermission {
	groups := make(map[string][]models.RequiredPermission)
	
	for _, perm := range permissions {
		namespace := perm.Namespace
		if perm.ClusterScoped {
			namespace = "" // Empty string for cluster-scoped
		}
		groups[namespace] = append(groups[namespace], perm)
	}
	
	return groups
}

func (advisor *RBACAdvisor) generateRoleName(username, namespace string) string {
	base := fmt.Sprintf("kubechat-%s", strings.ReplaceAll(username, ".", "-"))
	if namespace != "" {
		return fmt.Sprintf("%s-%s", base, namespace)
	}
	return base
}

func (advisor *RBACAdvisor) generateClusterRoleCommand(roleName string, permissions []models.RequiredPermission) string {
	var rules []string
	for _, perm := range permissions {
		rule := fmt.Sprintf("--verb=%s --resource=%s", perm.Verb, perm.Resource)
		if perm.APIGroup != "" && perm.APIGroup != "core" {
			rule += fmt.Sprintf(" --api-group=%s", perm.APIGroup)
		}
		rules = append(rules, rule)
	}
	
	return fmt.Sprintf("kubectl create clusterrole %s %s", roleName, strings.Join(rules, " "))
}

func (advisor *RBACAdvisor) generateClusterRoleBindingCommand(roleName string, userContext *JWTClaims) string {
	return fmt.Sprintf("kubectl create clusterrolebinding %s-binding --clusterrole=%s --user=%s",
		roleName, roleName, userContext.KubernetesUser)
}

func (advisor *RBACAdvisor) generateRoleCommand(roleName, namespace string, permissions []models.RequiredPermission) string {
	var rules []string
	for _, perm := range permissions {
		rule := fmt.Sprintf("--verb=%s --resource=%s", perm.Verb, perm.Resource)
		if perm.APIGroup != "" && perm.APIGroup != "core" {
			rule += fmt.Sprintf(" --api-group=%s", perm.APIGroup)
		}
		rules = append(rules, rule)
	}
	
	return fmt.Sprintf("kubectl create role %s --namespace=%s %s", roleName, namespace, strings.Join(rules, " "))
}

func (advisor *RBACAdvisor) generateRoleBindingCommand(roleName, namespace string, userContext *JWTClaims) string {
	return fmt.Sprintf("kubectl create rolebinding %s-binding --namespace=%s --role=%s --user=%s",
		roleName, namespace, roleName, userContext.KubernetesUser)
}

func (advisor *RBACAdvisor) generateVerificationCommands(userContext *JWTClaims, permissions []models.RequiredPermission) []string {
	var commands []string
	
	for _, perm := range permissions {
		cmd := fmt.Sprintf("kubectl auth can-i %s %s --as=%s", perm.Verb, perm.Resource, userContext.KubernetesUser)
		if perm.Namespace != "" {
			cmd += fmt.Sprintf(" --namespace=%s", perm.Namespace)
		}
		commands = append(commands, cmd)
	}
	
	return commands
}

func (advisor *RBACAdvisor) generateRoleBindingSuggestions(userContext *JWTClaims, roleSuggestions []RoleRecommendation) []RoleBindingRecommendation {
	var suggestions []RoleBindingRecommendation
	
	for _, role := range roleSuggestions {
		bindingType := "RoleBinding"
		if role.Type == "ClusterRole" {
			bindingType = "ClusterRoleBinding"
		}
		
		suggestions = append(suggestions, RoleBindingRecommendation{
			Name:           fmt.Sprintf("%s-binding", role.Name),
			Type:           bindingType,
			RoleName:       role.Name,
			Namespace:      role.Namespace,
			Subject:        userContext.KubernetesUser,
			SubjectType:    "User",
			Justification:  fmt.Sprintf("Bind %s to required role for operation access", userContext.KubernetesUser),
		})
	}
	
	return suggestions
}

func (advisor *RBACAdvisor) generateSecurityConsiderations(permissions []models.RequiredPermission) []string {
	var considerations []string
	
	hasDeleteVerbs := false
	hasClusterAccess := false
	hasSecretAccess := false
	
	for _, perm := range permissions {
		if strings.Contains(perm.Verb, "delete") {
			hasDeleteVerbs = true
		}
		if perm.ClusterScoped {
			hasClusterAccess = true
		}
		if perm.Resource == "secrets" {
			hasSecretAccess = true
		}
	}
	
	if hasDeleteVerbs {
		considerations = append(considerations, "Consider using separate roles for delete operations")
		considerations = append(considerations, "Implement approval workflow for destructive operations")
	}
	
	if hasClusterAccess {
		considerations = append(considerations, "Cluster-level permissions should be granted sparingly")
		considerations = append(considerations, "Consider using namespace-specific roles instead")
	}
	
	if hasSecretAccess {
		considerations = append(considerations, "Secret access requires careful audit and monitoring")
		considerations = append(considerations, "Consider using service accounts with limited scope")
	}
	
	if len(considerations) == 0 {
		considerations = append(considerations, "Follow principle of least privilege")
		considerations = append(considerations, "Regularly audit and review granted permissions")
	}
	
	return considerations
}

// Optimization helper methods

func (advisor *RBACAdvisor) deduplicatePermissions(permissions []models.RequiredPermission) []models.RequiredPermission {
	seen := make(map[string]bool)
	var result []models.RequiredPermission
	
	for _, perm := range permissions {
		key := fmt.Sprintf("%s:%s:%s:%s", perm.APIGroup, perm.Resource, perm.Verb, perm.Namespace)
		if !seen[key] {
			seen[key] = true
			result = append(result, perm)
		}
	}
	
	return result
}

func (advisor *RBACAdvisor) optimizeVerbs(permissions []models.RequiredPermission) []models.RequiredPermission {
	// Group by resource and namespace
	groups := make(map[string][]string) // key: resource:namespace, value: verbs
	permMap := make(map[string]models.RequiredPermission)
	
	for _, perm := range permissions {
		key := fmt.Sprintf("%s:%s:%s", perm.APIGroup, perm.Resource, perm.Namespace)
		groups[key] = append(groups[key], perm.Verb)
		permMap[key] = perm
	}
	
	var result []models.RequiredPermission
	for key, verbs := range groups {
		basePerm := permMap[key]
		
		// If we have get, list, watch - we can use "view" pattern
		if advisor.containsAll(verbs, []string{"get", "list", "watch"}) && len(verbs) == 3 {
			basePerm.Verb = "get,list,watch"
			result = append(result, basePerm)
		} else {
			// Keep individual verbs for complex cases
			for _, verb := range verbs {
				basePerm.Verb = verb
				result = append(result, basePerm)
			}
		}
	}
	
	return result
}

func (advisor *RBACAdvisor) optimizeResourceHierarchy(permissions []models.RequiredPermission) []models.RequiredPermission {
	// This could be enhanced to recognize resource hierarchies
	// For now, just return as-is
	return permissions
}

func (advisor *RBACAdvisor) containsAll(haystack, needles []string) bool {
	found := make(map[string]bool)
	for _, item := range haystack {
		found[item] = true
	}
	
	for _, needle := range needles {
		if !found[needle] {
			return false
		}
	}
	
	return true
}

// Caching methods

func (advisor *RBACAdvisor) getCachedGap(ctx context.Context, userContext *JWTClaims, permissions []models.RequiredPermission) (*PermissionGap, bool) {
	if advisor.redisClient == nil {
		return nil, false
	}
	
	_ = advisor.generateCacheKey(userContext, permissions)
	// Implementation would retrieve from Redis cache
	return nil, false // Placeholder
}

func (advisor *RBACAdvisor) cacheGap(ctx context.Context, userContext *JWTClaims, permissions []models.RequiredPermission, gap *PermissionGap) {
	if advisor.redisClient == nil {
		return
	}
	
	key := advisor.generateCacheKey(userContext, permissions)
	// Implementation would cache in Redis
	_ = key // Placeholder
}

func (advisor *RBACAdvisor) generateCacheKey(userContext *JWTClaims, permissions []models.RequiredPermission) string {
	// Generate a unique cache key based on user and permissions
	return fmt.Sprintf("%s:gap:%s:%d", advisor.cachePrefix, userContext.KubernetesUser, len(permissions))
}

func (advisor *RBACAdvisor) updateMetrics(duration time.Duration) {
	advisor.metrics.mutex.Lock()
	defer advisor.metrics.mutex.Unlock()
	
	advisor.metrics.AnalysisRequests++
	
	// Update average analysis time
	if advisor.metrics.AverageAnalysisTime == 0 {
		advisor.metrics.AverageAnalysisTime = duration
	} else {
		advisor.metrics.AverageAnalysisTime = (advisor.metrics.AverageAnalysisTime + duration) / 2
	}
}

// GetMetrics returns current metrics
func (advisor *RBACAdvisor) GetMetrics() *RBACAdvisorMetrics {
	advisor.metrics.mutex.RLock()
	defer advisor.metrics.mutex.RUnlock()
	
	// Return a copy to avoid race conditions
	return &RBACAdvisorMetrics{
		AnalysisRequests:       advisor.metrics.AnalysisRequests,
		CacheHits:              advisor.metrics.CacheHits,
		CacheMisses:            advisor.metrics.CacheMisses,
		AverageAnalysisTime:    advisor.metrics.AverageAnalysisTime,
		RecommendationAccuracy: advisor.metrics.RecommendationAccuracy,
	}
}