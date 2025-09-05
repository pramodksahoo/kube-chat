// Package middleware provides authentication and authorization middleware for the KubeChat API
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gofiber/fiber/v3"
	"golang.org/x/oauth2"
	
	"github.com/pramodksahoo/kube-chat/pkg/config"
)

// OIDCProvider represents configuration for different OIDC providers
type OIDCProvider struct {
	Name         string `json:"name"`
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURL  string `json:"redirect_url"`
	Scopes       []string `json:"scopes"`
	// Provider-specific settings
	ExtraParams map[string]string `json:"extra_params,omitempty"`
}

// AuthMiddleware handles OIDC authentication for KubeChat
type AuthMiddleware struct {
	providers       map[string]*ProviderConfig
	jwtService      JWTServiceInterface
	circuitBreakers map[string]*CircuitBreaker
	enableFallback  bool
	groupMapper     *config.OIDCGroupMapper
	mfaHandler      *MFAHandler // Story 2.4: MFA Handler integration
}

// ProviderConfig holds runtime configuration for an OIDC provider
type ProviderConfig struct {
	Provider     *oidc.Provider
	OAuth2Config oauth2.Config
	Settings     OIDCProvider
	Verifier     *oidc.IDTokenVerifier
}

// AuthenticationError represents authentication-related errors
type AuthenticationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *AuthenticationError) Error() string {
	return fmt.Sprintf("Authentication error [%s]: %s", e.Code, e.Message)
}

// NewAuthMiddleware creates a new authentication middleware instance
func NewAuthMiddleware(providers []OIDCProvider, jwtService JWTServiceInterface, groupMapping *config.OIDCGroupMapping, mfaHandler *MFAHandler) (*AuthMiddleware, error) {
	if len(providers) == 0 {
		return nil, &AuthenticationError{
			Code:    "CONFIG_ERROR",
			Message: "At least one OIDC provider must be configured",
		}
	}

	middleware := &AuthMiddleware{
		providers:       make(map[string]*ProviderConfig),
		jwtService:      jwtService,
		circuitBreakers: make(map[string]*CircuitBreaker),
		enableFallback:  true,
		groupMapper:     config.NewOIDCGroupMapper(groupMapping),
		mfaHandler:      mfaHandler,
	}

	// Initialize each provider
	for _, providerSettings := range providers {
		config, err := middleware.initializeProvider(providerSettings)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize provider %s: %w", providerSettings.Name, err)
		}
		middleware.providers[providerSettings.Name] = config

		// Initialize circuit breaker for each provider
		cbConfig := CircuitBreakerConfig{
			FailureThreshold: 5,
			SuccessThreshold: 2,
			Timeout:          30 * time.Second,
			MaxRequests:      10,
			OnStateChange: func(state CircuitBreakerState) {
				// Log state changes for monitoring
				fmt.Printf("Circuit breaker for provider %s changed to %v\n", providerSettings.Name, state)
			},
		}
		middleware.circuitBreakers[providerSettings.Name] = NewCircuitBreaker(cbConfig)
	}

	return middleware, nil
}

// initializeProvider initializes a single OIDC provider
func (m *AuthMiddleware) initializeProvider(settings OIDCProvider) (*ProviderConfig, error) {
	ctx := context.Background()

	// Discover OIDC provider
	provider, err := oidc.NewProvider(ctx, settings.Issuer)
	if err != nil {
		return nil, &AuthenticationError{
			Code:    "PROVIDER_DISCOVERY_FAILED",
			Message: fmt.Sprintf("Failed to discover OIDC provider at %s", settings.Issuer),
			Details: err.Error(),
		}
	}

	// Create OAuth2 configuration
	oauth2Config := oauth2.Config{
		ClientID:     settings.ClientID,
		ClientSecret: settings.ClientSecret,
		RedirectURL:  settings.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       append([]string{oidc.ScopeOpenID}, settings.Scopes...),
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{ClientID: settings.ClientID})

	return &ProviderConfig{
		Provider:     provider,
		OAuth2Config: oauth2Config,
		Settings:     settings,
		Verifier:     verifier,
	}, nil
}

// RequireAuthentication middleware that requires valid authentication
func (m *AuthMiddleware) RequireAuthentication() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Check for JWT token in Authorization header
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return m.sendAuthenticationError(c, "MISSING_TOKEN", "Authorization header required", http.StatusUnauthorized)
		}

		// Extract token from "Bearer <token>" format
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			return m.sendAuthenticationError(c, "INVALID_TOKEN_FORMAT", "Authorization header must be in format 'Bearer <token>'", http.StatusUnauthorized)
		}

		token := tokenParts[1]

		// Validate JWT token
		claims, err := m.jwtService.ValidateToken(token)
		if err != nil {
			return m.sendAuthenticationError(c, "INVALID_TOKEN", "Token validation failed", http.StatusUnauthorized)
		}

		// Add user context to request
		c.Locals("user", claims)
		c.Locals("user_id", claims.UserID)
		c.Locals("session_id", claims.SessionID)

		return c.Next()
	}
}

// GetAuthURL returns the authorization URL for a specific provider
func (m *AuthMiddleware) GetAuthURL(providerName string, state string) (string, error) {
	config, exists := m.providers[providerName]
	if !exists {
		return "", &AuthenticationError{
			Code:    "PROVIDER_NOT_FOUND",
			Message: fmt.Sprintf("Provider %s not configured", providerName),
		}
	}

	// Add provider-specific extra parameters
	opts := []oauth2.AuthCodeOption{}
	for key, value := range config.Settings.ExtraParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}

	// Handle MFA requirements for specific providers
	switch strings.ToLower(providerName) {
	case "okta":
		// Okta-specific MFA handling
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	case "auth0":
		// Auth0-specific MFA handling
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	case "azure", "microsoft":
		// Azure AD-specific MFA handling
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "login"))
	case "google":
		// Google Workspace MFA handling
		opts = append(opts, oauth2.SetAuthURLParam("prompt", "select_account consent"))
	}

	return config.OAuth2Config.AuthCodeURL(state, opts...), nil
}

// HandleCallback processes the OIDC callback
func (m *AuthMiddleware) HandleCallback(c fiber.Ctx) error {
	// Get provider from query parameter or path
	providerName := c.Query("provider")
	if providerName == "" {
		providerName = c.Params("provider")
	}
	if providerName == "" {
		return m.sendAuthenticationError(c, "MISSING_PROVIDER", "Provider parameter required", http.StatusBadRequest)
	}

	config, exists := m.providers[providerName]
	if !exists {
		return m.sendAuthenticationError(c, "PROVIDER_NOT_FOUND", fmt.Sprintf("Provider %s not configured", providerName), http.StatusBadRequest)
	}

	// Get authorization code
	code := c.Query("code")
	if code == "" {
		errorDesc := c.Query("error_description")
		if errorDesc == "" {
			errorDesc = "Authorization code not received"
		}
		return m.sendAuthenticationError(c, "AUTHORIZATION_FAILED", errorDesc, http.StatusBadRequest)
	}

	// Exchange code for token
	ctx := context.Background()
	token, err := config.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return m.sendAuthenticationError(c, "TOKEN_EXCHANGE_FAILED", "Failed to exchange authorization code for token", http.StatusInternalServerError)
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return m.sendAuthenticationError(c, "MISSING_ID_TOKEN", "ID token not found in response", http.StatusInternalServerError)
	}

	// Verify ID token
	idToken, err := config.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return m.sendAuthenticationError(c, "TOKEN_VERIFICATION_FAILED", "Failed to verify ID token", http.StatusInternalServerError)
	}

	// Extract claims
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return m.sendAuthenticationError(c, "CLAIMS_EXTRACTION_FAILED", "Failed to extract claims from ID token", http.StatusInternalServerError)
	}

	// Create user session
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		return m.sendAuthenticationError(c, "INVALID_USER_ID", "User ID (sub) not found in token claims", http.StatusInternalServerError)
	}

	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)

	// Map OIDC groups to Kubernetes groups using the group mapper
	groupMappingResult, err := m.groupMapper.MapGroups(providerName, claims)
	if err != nil {
		return m.sendAuthenticationError(c, "GROUP_MAPPING_FAILED", "Failed to map OIDC groups to Kubernetes groups", http.StatusInternalServerError)
	}

	// Create enhanced JWT claims with RBAC information
	now := time.Now()
	jwtClaims := &JWTClaims{
		// Basic user information
		UserID:    userID,
		Email:     email,
		Name:      name,
		IssuedAt:  now,
		ExpiresAt: now.Add(8 * time.Hour), // Default 8 hour expiration
		
		// Enhanced RBAC fields from group mapping
		Role:                "user", // Default role, can be enhanced based on groups
		Groups:              m.extractOIDCGroups(claims, providerName),
		KubernetesUser:      groupMappingResult.KubernetesUser,
		KubernetesGroups:    groupMappingResult.KubernetesGroups,
		DefaultNamespace:    groupMappingResult.DefaultNamespace,
		AllowedNamespaces:   groupMappingResult.AllowedNamespaces,
		ClusterAccess:       groupMappingResult.ClusterAccess,
		ServiceAccountName:  "", // No service account for OIDC users
		
		// Claims metadata
		ClaimsVersion:       2, // Enhanced version with RBAC
		LastPermissionCheck: now,
		
		// Initialize MFA fields (Story 2.4)
		MFACompleted:        false,
		MFAMethod:          "",
		MFATimestamp:       time.Time{},
		MFAValidityDuration: 0,
		RequiresMFAStepUp:  false,
	}

	// Determine role based on Kubernetes groups
	jwtClaims.Role = m.determineUserRole(jwtClaims.KubernetesGroups)

	// Story 2.4: Check if MFA is required
	if m.mfaHandler != nil {
		clientIP := c.IP()
		userAgent := c.Get("User-Agent")
		
		requiresMFA, requiredMethods, err := m.mfaHandler.RequiresMFA(ctx, jwtClaims, clientIP, userAgent)
		if err != nil {
			return m.sendAuthenticationError(c, "MFA_POLICY_CHECK_FAILED", "Failed to check MFA requirements", http.StatusInternalServerError)
		}

		// Check provider-specific MFA claims (e.g., from Okta, Azure AD)
		providerMFACompleted := m.extractMFAStatusFromProvider(claims, providerName)
		
		if requiresMFA && !providerMFACompleted {
			// MFA is required but not completed - initiate MFA challenge
			return m.initiateMFAChallenge(c, jwtClaims, requiredMethods, providerName)
		}
		
		if providerMFACompleted {
			// MFA was completed at provider level, update claims
			mfaMethod := m.extractMFAMethodFromProvider(claims, providerName)
			m.mfaHandler.UpdateMFAStatus(jwtClaims, MFAMethod(mfaMethod), 4*time.Hour) // 4 hour MFA validity
		}
	}

	// Generate JWT token with enhanced claims
	jwtToken, err := m.jwtService.GenerateTokenWithClaims(jwtClaims)
	if err != nil {
		return m.sendAuthenticationError(c, "JWT_GENERATION_FAILED", "Failed to generate session token", http.StatusInternalServerError)
	}

	// Return successful authentication response with enhanced RBAC and MFA information
	response := fiber.Map{
		"success": true,
		"token":   jwtToken,
		"user": fiber.Map{
			"id":                 userID,
			"email":              email,
			"name":               name,
			"role":               jwtClaims.Role,
			"kubernetes_user":    jwtClaims.KubernetesUser,
			"kubernetes_groups":  jwtClaims.KubernetesGroups,
			"default_namespace":  jwtClaims.DefaultNamespace,
			"allowed_namespaces": jwtClaims.AllowedNamespaces,
			"cluster_access":     jwtClaims.ClusterAccess,
		},
		"rbac": fiber.Map{
			"claims_version":         jwtClaims.ClaimsVersion,
			"last_permission_check":  jwtClaims.LastPermissionCheck.Unix(),
			"mapping_source":         groupMappingResult.MappingSource,
		},
		"expires_at": jwtClaims.ExpiresAt.Unix(),
	}
	
	// Add MFA information if applicable
	if jwtClaims.MFACompleted {
		response["mfa"] = fiber.Map{
			"completed":  jwtClaims.MFACompleted,
			"method":     jwtClaims.MFAMethod,
			"timestamp":  jwtClaims.MFATimestamp.Unix(),
			"expires_at": jwtClaims.MFATimestamp.Add(jwtClaims.MFAValidityDuration).Unix(),
		}
	}
	
	return c.JSON(response)
}

// ListProviders returns available authentication providers
func (m *AuthMiddleware) ListProviders() fiber.Handler {
	return func(c fiber.Ctx) error {
		providers := make([]fiber.Map, 0, len(m.providers))
		for name, config := range m.providers {
			providers = append(providers, fiber.Map{
				"name":   name,
				"issuer": config.Settings.Issuer,
				"scopes": config.Settings.Scopes,
			})
		}

		return c.JSON(fiber.Map{
			"providers": providers,
		})
	}
}

// GetProviders returns the list of configured provider names
func (m *AuthMiddleware) GetProviders() []string {
	providers := make([]string, 0, len(m.providers))
	for name := range m.providers {
		providers = append(providers, name)
	}
	return providers
}


// sendAuthenticationError sends a standardized authentication error response
func (m *AuthMiddleware) sendAuthenticationError(c fiber.Ctx, code, message string, statusCode int) error {
	// Log the error (structured logging would be used in production)
	fmt.Printf("Authentication error: %s - %s\n", code, message)

	return c.Status(statusCode).JSON(fiber.Map{
		"error":   true,
		"code":    code,
		"message": message,
	})
}

// ValidateProviderConfiguration validates that a provider configuration is complete
func ValidateProviderConfiguration(provider OIDCProvider) error {
	if provider.Name == "" {
		return &AuthenticationError{Code: "INVALID_CONFIG", Message: "Provider name is required"}
	}
	if provider.Issuer == "" {
		return &AuthenticationError{Code: "INVALID_CONFIG", Message: "Provider issuer is required"}
	}
	if provider.ClientID == "" {
		return &AuthenticationError{Code: "INVALID_CONFIG", Message: "Client ID is required"}
	}
	if provider.ClientSecret == "" {
		return &AuthenticationError{Code: "INVALID_CONFIG", Message: "Client secret is required"}
	}
	if provider.RedirectURL == "" {
		return &AuthenticationError{Code: "INVALID_CONFIG", Message: "Redirect URL is required"}
	}
	return nil
}

// GetSupportedProviders returns a list of pre-configured provider templates
func GetSupportedProviders() map[string]OIDCProvider {
	return map[string]OIDCProvider{
		"okta": {
			Name:   "okta",
			Scopes: []string{"email", "profile", "groups"},
			ExtraParams: map[string]string{
				"prompt": "login", // Force MFA
			},
		},
		"auth0": {
			Name:   "auth0",
			Scopes: []string{"email", "profile"},
			ExtraParams: map[string]string{
				"prompt": "login",
			},
		},
		"azure": {
			Name:   "azure",
			Scopes: []string{"email", "profile", "User.Read"},
			ExtraParams: map[string]string{
				"prompt": "login",
			},
		},
		"google": {
			Name:   "google",
			Issuer: "https://accounts.google.com",
			Scopes: []string{"email", "profile"},
			ExtraParams: map[string]string{
				"prompt": "select_account consent",
			},
		},
	}
}

// extractOIDCGroups extracts groups from OIDC claims for the given provider
func (m *AuthMiddleware) extractOIDCGroups(claims map[string]interface{}, providerName string) []string {
	var groupClaimName string
	
	// Determine group claim name based on provider
	switch strings.ToLower(providerName) {
	case "okta":
		groupClaimName = "groups"
	case "azure", "microsoft":
		groupClaimName = "groups"
	case "auth0":
		groupClaimName = "https://kubechat.com/groups" // Custom namespace for Auth0
	case "google":
		groupClaimName = "groups"
	default:
		groupClaimName = "groups" // Default fallback
	}
	
	// Extract groups from claims
	groupsClaim, exists := claims[groupClaimName]
	if !exists {
		return []string{} // No groups found
	}
	
	// Handle different group claim formats
	switch groups := groupsClaim.(type) {
	case []interface{}:
		result := make([]string, 0, len(groups))
		for _, g := range groups {
			if groupStr, ok := g.(string); ok {
				result = append(result, groupStr)
			}
		}
		return result
	case []string:
		return groups
	case string:
		return []string{groups}
	default:
		return []string{} // Unsupported format
	}
}

// determineUserRole determines the KubeChat role based on Kubernetes groups
func (m *AuthMiddleware) determineUserRole(kubernetesGroups []string) string {
	// Check for admin role
	for _, group := range kubernetesGroups {
		if group == "system:masters" || strings.Contains(group, "admin") {
			return "admin"
		}
	}
	
	// Check for operator role
	for _, group := range kubernetesGroups {
		if strings.Contains(group, "operator") || strings.Contains(group, "developer") {
			return "operator"
		}
	}
	
	// Check for viewer role
	for _, group := range kubernetesGroups {
		if strings.Contains(group, "viewer") || strings.Contains(group, "readonly") {
			return "viewer"
		}
	}
	
	// Default role
	return "user"
}

// extractMFAStatusFromProvider extracts MFA completion status from provider claims
func (m *AuthMiddleware) extractMFAStatusFromProvider(claims map[string]interface{}, providerName string) bool {
	switch strings.ToLower(providerName) {
	case "okta":
		// Okta provides amr (Authentication Methods Reference) claim
		if amr, exists := claims["amr"]; exists {
			if amrSlice, ok := amr.([]interface{}); ok {
				for _, method := range amrSlice {
					if methodStr, ok := method.(string); ok {
						// Check for MFA methods in AMR
						if methodStr == "otp" || methodStr == "sms" || methodStr == "push" || 
						   methodStr == "hwk" || methodStr == "mfa" || methodStr == "fido" {
							return true
						}
					}
				}
			}
		}
	case "azure", "microsoft":
		// Azure AD provides amr claim and authentication_method
		if amr, exists := claims["amr"]; exists {
			if amrSlice, ok := amr.([]interface{}); ok {
				for _, method := range amrSlice {
					if methodStr, ok := method.(string); ok {
						if methodStr == "mfa" || methodStr == "otp" || methodStr == "sms" || 
						   methodStr == "oath" || methodStr == "fido" {
							return true
						}
					}
				}
			}
		}
		// Also check authentication_method claim
		if authMethod, exists := claims["authentication_method"]; exists {
			if authMethodStr, ok := authMethod.(string); ok {
				if strings.Contains(authMethodStr, "mfa") || strings.Contains(authMethodStr, "totp") {
					return true
				}
			}
		}
	case "auth0":
		// Auth0 uses custom claims for MFA
		if mfaClaim, exists := claims["https://kubechat.com/mfa_completed"]; exists {
			if mfaCompleted, ok := mfaClaim.(bool); ok {
				return mfaCompleted
			}
		}
	case "google":
		// Google uses amr claim
		if amr, exists := claims["amr"]; exists {
			if amrSlice, ok := amr.([]interface{}); ok {
				for _, method := range amrSlice {
					if methodStr, ok := method.(string); ok {
						if methodStr == "mfa" || methodStr == "otp" || methodStr == "sms" {
							return true
						}
					}
				}
			}
		}
	}
	
	return false
}

// extractMFAMethodFromProvider extracts the MFA method used from provider claims
func (m *AuthMiddleware) extractMFAMethodFromProvider(claims map[string]interface{}, providerName string) string {
	switch strings.ToLower(providerName) {
	case "okta", "azure", "microsoft", "google":
		if amr, exists := claims["amr"]; exists {
			if amrSlice, ok := amr.([]interface{}); ok {
				for _, method := range amrSlice {
					if methodStr, ok := method.(string); ok {
						switch methodStr {
						case "otp", "oath":
							return "TOTP"
						case "sms":
							return "SMS"
						case "push":
							return "PUSH"
						case "fido", "hwk":
							return "HARDWARE_TOKEN"
						case "mfa":
							return "TOTP" // Default to TOTP for generic MFA
						}
					}
				}
			}
		}
	case "auth0":
		if mfaMethod, exists := claims["https://kubechat.com/mfa_method"]; exists {
			if method, ok := mfaMethod.(string); ok {
				return strings.ToUpper(method)
			}
		}
	}
	
	return "UNKNOWN"
}

// initiateMFAChallenge initiates an MFA challenge when required
func (m *AuthMiddleware) initiateMFAChallenge(c fiber.Ctx, claims *JWTClaims, requiredMethods []MFAMethod, providerName string) error {
	// Store partial authentication state for MFA completion
	partialAuthData := map[string]interface{}{
		"user_id":            claims.UserID,
		"email":              claims.Email,
		"name":               claims.Name,
		"role":               claims.Role,
		"groups":             claims.Groups,
		"kubernetes_user":    claims.KubernetesUser,
		"kubernetes_groups":  claims.KubernetesGroups,
		"default_namespace":  claims.DefaultNamespace,
		"allowed_namespaces": claims.AllowedNamespaces,
		"cluster_access":     claims.ClusterAccess,
		"provider":           providerName,
		"client_ip":          c.IP(),
		"user_agent":         c.Get("User-Agent"),
	}

	// Determine the best MFA method to use
	var selectedMethod MFAMethod
	if len(requiredMethods) > 0 {
		// Use the first required method (could be enhanced with user preference logic)
		selectedMethod = requiredMethods[0]
	} else {
		// Default to TOTP if no specific method required
		selectedMethod = MFAMethodTOTP
	}

	// Create MFA challenge
	challenge, err := m.mfaHandler.CreateChallenge(context.Background(), claims.UserID, selectedMethod, partialAuthData)
	if err != nil {
		return m.sendAuthenticationError(c, "MFA_CHALLENGE_FAILED", "Failed to create MFA challenge", http.StatusInternalServerError)
	}

	// Return MFA challenge response
	return c.Status(http.StatusAccepted).JSON(fiber.Map{
		"success":        false,
		"mfa_required":   true,
		"message":        "Multi-factor authentication required",
		"challenge_id":   challenge.ChallengeID,
		"method":         challenge.Method,
		"instruction":    challenge.ProviderData["instruction"],
		"expires_at":     challenge.ExpiresAt.Unix(),
		"max_attempts":   challenge.MaxAttempts,
		"required_methods": requiredMethods,
		"next_step":      "Complete MFA challenge using /auth/mfa/validate endpoint",
	})
}