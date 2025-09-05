// Package config provides OIDC group mapping configuration for RBAC integration
package config

import (
	"fmt"
	"strings"
)

// OIDCGroupMapping defines how OIDC provider groups map to Kubernetes groups
type OIDCGroupMapping struct {
	// Provider-specific mappings
	Okta        *ProviderGroupMapping `json:"okta,omitempty" yaml:"okta,omitempty"`
	AzureAD     *ProviderGroupMapping `json:"azure_ad,omitempty" yaml:"azure_ad,omitempty"`
	Auth0       *ProviderGroupMapping `json:"auth0,omitempty" yaml:"auth0,omitempty"`
	Google      *ProviderGroupMapping `json:"google,omitempty" yaml:"google,omitempty"`
	Generic     *GenericProviderMapping `json:"generic,omitempty" yaml:"generic,omitempty"`
	
	// Global fallback settings
	GlobalConfig *GlobalMappingConfig `json:"global_config,omitempty" yaml:"global_config,omitempty"`
}

// ProviderGroupMapping maps OIDC groups to Kubernetes groups for a specific provider
type ProviderGroupMapping struct {
	// Direct group mappings: Kubernetes group -> list of OIDC groups
	KubernetesAdmins     []string `json:"kubernetes_admins" yaml:"kubernetes_admins"`
	NamespaceOperators   []string `json:"namespace_operators" yaml:"namespace_operators"`
	ClusterViewers       []string `json:"cluster_viewers" yaml:"cluster_viewers"`
	
	// Custom mappings for additional roles
	CustomMappings       map[string][]string `json:"custom_mappings,omitempty" yaml:"custom_mappings,omitempty"`
	
	// Provider-specific configuration
	GroupClaimName       string              `json:"group_claim_name,omitempty" yaml:"group_claim_name,omitempty"`
	NestedGroupSupport   bool                `json:"nested_group_support,omitempty" yaml:"nested_group_support,omitempty"`
	GroupPrefix          string              `json:"group_prefix,omitempty" yaml:"group_prefix,omitempty"`
	CaseSensitive        bool                `json:"case_sensitive,omitempty" yaml:"case_sensitive,omitempty"`
}

// GenericProviderMapping provides fallback configuration for unknown providers
type GenericProviderMapping struct {
	GroupClaimName            string   `json:"group_claim_name" yaml:"group_claim_name"`
	KubernetesUserClaim       string   `json:"kubernetes_user_claim" yaml:"kubernetes_user_claim"`
	DefaultKubernetesGroups   []string `json:"default_kubernetes_groups" yaml:"default_kubernetes_groups"`
	RequiredClaims            []string `json:"required_claims,omitempty" yaml:"required_claims,omitempty"`
}

// GlobalMappingConfig provides global fallback settings
type GlobalMappingConfig struct {
	DefaultNamespace          string   `json:"default_namespace" yaml:"default_namespace"`
	AllowedNamespacesDefault  []string `json:"allowed_namespaces_default" yaml:"allowed_namespaces_default"`
	ClusterAccessDefault      bool     `json:"cluster_access_default" yaml:"cluster_access_default"`
	RequireGroupMembership    bool     `json:"require_group_membership" yaml:"require_group_membership"`
	EnableGroupCaching        bool     `json:"enable_group_caching" yaml:"enable_group_caching"`
	GroupCacheTTL             int      `json:"group_cache_ttl" yaml:"group_cache_ttl"` // seconds
}

// GroupMappingResult represents the result of group mapping operation
type GroupMappingResult struct {
	KubernetesUser      string   `json:"kubernetes_user"`
	KubernetesGroups    []string `json:"kubernetes_groups"`
	DefaultNamespace    string   `json:"default_namespace"`
	AllowedNamespaces   []string `json:"allowed_namespaces"`
	ClusterAccess       bool     `json:"cluster_access"`
	MappingSource       string   `json:"mapping_source"` // Which provider/rule was used
}

// OIDCGroupMapper handles the mapping logic
type OIDCGroupMapper struct {
	config *OIDCGroupMapping
}

// NewOIDCGroupMapper creates a new group mapper with configuration
func NewOIDCGroupMapper(config *OIDCGroupMapping) *OIDCGroupMapper {
	if config == nil {
		config = getDefaultMapping()
	}
	return &OIDCGroupMapper{config: config}
}

// MapGroups maps OIDC claims to Kubernetes groups and permissions
func (m *OIDCGroupMapper) MapGroups(providerName string, oidcClaims map[string]interface{}) (*GroupMappingResult, error) {
	// Extract user information
	userEmail, _ := oidcClaims["email"].(string)
	preferredUsername, _ := oidcClaims["preferred_username"].(string)
	
	// Determine Kubernetes user name
	kubernetesUser := userEmail
	if kubernetesUser == "" {
		kubernetesUser = preferredUsername
	}
	if kubernetesUser == "" {
		return nil, fmt.Errorf("unable to determine kubernetes user from claims")
	}
	
	// Extract groups from claims
	oidcGroups, err := m.extractGroups(providerName, oidcClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract groups: %w", err)
	}
	
	// Map groups based on provider
	result, err := m.mapProviderGroups(providerName, oidcGroups)
	if err != nil {
		return nil, fmt.Errorf("failed to map groups: %w", err)
	}
	
	// Set user information
	result.KubernetesUser = kubernetesUser
	result.MappingSource = providerName
	
	// Apply global defaults if needed
	m.applyGlobalDefaults(result)
	
	return result, nil
}

// extractGroups extracts group information from OIDC claims based on provider
func (m *OIDCGroupMapper) extractGroups(providerName string, claims map[string]interface{}) ([]string, error) {
	var groupClaimName string
	var provider *ProviderGroupMapping
	
	// Determine group claim name based on provider
	switch providerName {
	case "okta":
		provider = m.config.Okta
		groupClaimName = "groups"
	case "azure", "microsoft":
		provider = m.config.AzureAD
		groupClaimName = "groups"
	case "auth0":
		provider = m.config.Auth0
		groupClaimName = "https://kubechat.com/groups" // Custom namespace for Auth0
	case "google":
		provider = m.config.Google
		groupClaimName = "groups"
	default:
		// Use generic configuration
		if m.config.Generic != nil {
			groupClaimName = m.config.Generic.GroupClaimName
		}
	}
	
	// Override with provider-specific claim name if configured
	if provider != nil && provider.GroupClaimName != "" {
		groupClaimName = provider.GroupClaimName
	}
	
	// Fallback to default claim name
	if groupClaimName == "" {
		groupClaimName = "groups"
	}
	
	// Extract groups from claims
	groupsClaim, exists := claims[groupClaimName]
	if !exists {
		return []string{}, nil // No groups found, return empty slice
	}
	
	// Handle different group claim formats
	switch groups := groupsClaim.(type) {
	case []interface{}:
		// Standard array format
		result := make([]string, 0, len(groups))
		for _, g := range groups {
			if groupStr, ok := g.(string); ok {
				result = append(result, groupStr)
			}
		}
		return result, nil
	case []string:
		// Direct string array
		return groups, nil
	case string:
		// Single group as string
		return []string{groups}, nil
	default:
		return nil, fmt.Errorf("unsupported groups claim format: %T", groupsClaim)
	}
}

// mapProviderGroups maps OIDC groups to Kubernetes groups based on provider configuration
func (m *OIDCGroupMapper) mapProviderGroups(providerName string, oidcGroups []string) (*GroupMappingResult, error) {
	result := &GroupMappingResult{
		KubernetesGroups:  []string{"system:authenticated"}, // Always include authenticated group
		DefaultNamespace:  "default",
		AllowedNamespaces: []string{},
		ClusterAccess:     false,
	}
	
	var provider *ProviderGroupMapping
	
	// Get provider configuration
	switch providerName {
	case "okta":
		provider = m.config.Okta
	case "azure", "microsoft":
		provider = m.config.AzureAD
	case "auth0":
		provider = m.config.Auth0
	case "google":
		provider = m.config.Google
	}
	
	// If no provider found, use generic mapping
	if provider == nil {
		return m.mapGenericGroups(oidcGroups)
	}
	
	// Map standard groups
	hasAdminAccess := false
	hasOperatorAccess := false
	hasViewerAccess := false
	
	for _, oidcGroup := range oidcGroups {
		// Check for admin groups
		for _, adminGroup := range provider.KubernetesAdmins {
			if m.groupMatches(oidcGroup, adminGroup, provider.CaseSensitive) {
				result.KubernetesGroups = append(result.KubernetesGroups, "system:masters")
				result.ClusterAccess = true
				hasAdminAccess = true
				break
			}
		}
		
		// Check for operator groups
		for _, operatorGroup := range provider.NamespaceOperators {
			if m.groupMatches(oidcGroup, operatorGroup, provider.CaseSensitive) {
				result.KubernetesGroups = append(result.KubernetesGroups, "kubechat:operators")
				hasOperatorAccess = true
				break
			}
		}
		
		// Check for viewer groups
		for _, viewerGroup := range provider.ClusterViewers {
			if m.groupMatches(oidcGroup, viewerGroup, provider.CaseSensitive) {
				result.KubernetesGroups = append(result.KubernetesGroups, "kubechat:viewers")
				hasViewerAccess = true
				break
			}
		}
		
		// Check custom mappings
		for k8sGroup, oidcGroupList := range provider.CustomMappings {
			for _, customGroup := range oidcGroupList {
				if m.groupMatches(oidcGroup, customGroup, provider.CaseSensitive) {
					result.KubernetesGroups = append(result.KubernetesGroups, k8sGroup)
					break
				}
			}
		}
	}
	
	// Set default namespaces based on access level
	if hasAdminAccess {
		result.AllowedNamespaces = []string{"*"} // All namespaces
		result.ClusterAccess = true
	} else if hasOperatorAccess {
		result.AllowedNamespaces = []string{"default", "kube-system", "kubechat"} // Common namespaces
	} else if hasViewerAccess {
		result.AllowedNamespaces = []string{"default"} // Limited access
	}
	
	return result, nil
}

// mapGenericGroups handles generic group mapping for unknown providers
func (m *OIDCGroupMapper) mapGenericGroups(oidcGroups []string) (*GroupMappingResult, error) {
	result := &GroupMappingResult{
		KubernetesGroups:  []string{"system:authenticated"},
		DefaultNamespace:  "default",
		AllowedNamespaces: []string{"default"},
		ClusterAccess:     false,
	}
	
	if m.config.Generic != nil {
		// Add default groups from generic configuration
		result.KubernetesGroups = append(result.KubernetesGroups, m.config.Generic.DefaultKubernetesGroups...)
	}
	
	// Add all OIDC groups as Kubernetes groups (with prefix)
	for _, group := range oidcGroups {
		result.KubernetesGroups = append(result.KubernetesGroups, "oidc:"+group)
	}
	
	return result, nil
}

// groupMatches checks if an OIDC group matches a configured group (with case sensitivity support)
func (m *OIDCGroupMapper) groupMatches(oidcGroup, configGroup string, caseSensitive bool) bool {
	if caseSensitive {
		return oidcGroup == configGroup
	}
	return strings.EqualFold(oidcGroup, configGroup)
}

// applyGlobalDefaults applies global configuration defaults to mapping result
func (m *OIDCGroupMapper) applyGlobalDefaults(result *GroupMappingResult) {
	if m.config.GlobalConfig == nil {
		return
	}
	
	global := m.config.GlobalConfig
	
	// Apply default namespace if not set
	if result.DefaultNamespace == "" || result.DefaultNamespace == "default" {
		if global.DefaultNamespace != "" {
			result.DefaultNamespace = global.DefaultNamespace
		}
	}
	
	// Apply default allowed namespaces if empty
	if len(result.AllowedNamespaces) == 0 {
		result.AllowedNamespaces = global.AllowedNamespacesDefault
	}
	
	// Apply default cluster access if not already granted
	if !result.ClusterAccess {
		result.ClusterAccess = global.ClusterAccessDefault
	}
}

// getDefaultMapping returns a default OIDC group mapping configuration
func getDefaultMapping() *OIDCGroupMapping {
	return &OIDCGroupMapping{
		Okta: &ProviderGroupMapping{
			KubernetesAdmins:   []string{"okta-k8s-admins", "platform-team"},
			NamespaceOperators: []string{"okta-devops", "okta-developers"},
			ClusterViewers:     []string{"okta-readonly"},
			GroupClaimName:     "groups",
			CaseSensitive:      false,
		},
		AzureAD: &ProviderGroupMapping{
			KubernetesAdmins:   []string{"aad-kubernetes-admins"},
			NamespaceOperators: []string{"aad-developers", "aad-platform"},
			ClusterViewers:     []string{"aad-viewers"},
			GroupClaimName:     "groups",
			CaseSensitive:      false,
		},
		Auth0: &ProviderGroupMapping{
			KubernetesAdmins:   []string{"auth0-admins"},
			NamespaceOperators: []string{"auth0-developers"},
			ClusterViewers:     []string{"auth0-users"},
			GroupClaimName:     "https://kubechat.com/groups",
			CaseSensitive:      false,
		},
		Google: &ProviderGroupMapping{
			KubernetesAdmins:   []string{"google-admins@company.com"},
			NamespaceOperators: []string{"google-developers@company.com"},
			ClusterViewers:     []string{"google-users@company.com"},
			GroupClaimName:     "groups",
			CaseSensitive:      false,
		},
		Generic: &GenericProviderMapping{
			GroupClaimName:          "groups",
			KubernetesUserClaim:     "preferred_username",
			DefaultKubernetesGroups: []string{"system:authenticated"},
			RequiredClaims:          []string{"sub", "email"},
		},
		GlobalConfig: &GlobalMappingConfig{
			DefaultNamespace:         "default",
			AllowedNamespacesDefault: []string{"default"},
			ClusterAccessDefault:     false,
			RequireGroupMembership:   false,
			EnableGroupCaching:       true,
			GroupCacheTTL:           300, // 5 minutes
		},
	}
}

// ValidateOIDCGroupMapping validates the group mapping configuration
func ValidateOIDCGroupMapping(config *OIDCGroupMapping) error {
	if config == nil {
		return fmt.Errorf("group mapping configuration cannot be nil")
	}
	
	// Validate generic configuration if present
	if config.Generic != nil {
		if config.Generic.GroupClaimName == "" {
			return fmt.Errorf("generic group claim name cannot be empty")
		}
		if config.Generic.KubernetesUserClaim == "" {
			return fmt.Errorf("generic kubernetes user claim cannot be empty")
		}
	}
	
	// Validate global configuration if present
	if config.GlobalConfig != nil {
		if config.GlobalConfig.GroupCacheTTL < 0 {
			return fmt.Errorf("group cache TTL cannot be negative")
		}
	}
	
	return nil
}