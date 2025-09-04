// Package middleware provides SAML authentication fallback for legacy enterprise systems
package middleware

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/gofiber/fiber/v3"
)

// SAMLConfig holds configuration for SAML authentication
type SAMLConfig struct {
	EntityID          string `json:"entity_id"`           // Service Provider Entity ID
	ACSURL           string `json:"acs_url"`             // Assertion Consumer Service URL
	SLOUrl           string `json:"slo_url"`             // Single Logout URL
	IDPMetadataURL   string `json:"idp_metadata_url"`    // Identity Provider metadata URL
	IDPMetadataXML   string `json:"idp_metadata_xml"`    // Alternative: raw IDP metadata XML
	PrivateKeyPEM    string `json:"private_key_pem"`     // Private key for signing
	CertificatePEM   string `json:"certificate_pem"`     // Certificate for signing
	SignRequests     bool   `json:"sign_requests"`       // Whether to sign SAML requests
	ForceAuthn       bool   `json:"force_authn"`         // Force re-authentication
	AllowIDPInit     bool   `json:"allow_idp_init"`      // Allow IDP-initiated login
}

// SAMLProvider manages SAML authentication
type SAMLProvider struct {
	config         SAMLConfig
	jwtService     JWTServiceInterface
	serviceProvider *samlsp.Middleware
	mfaHandler     *MFAHandler // Story 2.4: MFA Handler integration
}

// SAMLAssertion represents processed SAML assertion data
type SAMLAssertion struct {
	Subject       string                 `json:"subject"`
	NameID        string                 `json:"name_id"`
	Email         string                 `json:"email"`
	DisplayName   string                 `json:"display_name"`
	GivenName     string                 `json:"given_name"`
	Surname       string                 `json:"surname"`
	Groups        []string               `json:"groups"`
	Attributes    map[string]interface{} `json:"attributes"`
	SessionIndex  string                 `json:"session_index"`
	NotOnOrAfter  time.Time             `json:"not_on_or_after"`
	// MFA fields (Story 2.4)
	MFACompleted  bool      `json:"mfa_completed"`
	MFAMethod     string    `json:"mfa_method,omitempty"`
	MFATimestamp  time.Time `json:"mfa_timestamp,omitempty"`
	AuthContexts  []string  `json:"auth_contexts,omitempty"` // SAML AuthnContext values
}

// SAMLError represents SAML-specific errors
type SAMLError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e *SAMLError) Error() string {
	return fmt.Sprintf("SAML error [%s]: %s", e.Code, e.Message)
}

// NewSAMLProvider creates a new SAML authentication provider
func NewSAMLProvider(config SAMLConfig, jwtService JWTServiceInterface, mfaHandler *MFAHandler) (*SAMLProvider, error) {
	if err := validateSAMLConfig(config); err != nil {
		return nil, fmt.Errorf("invalid SAML configuration: %w", err)
	}

	// Parse and validate entity ID URL
	rootURL, err := url.Parse(config.EntityID)
	if err != nil {
		return nil, &SAMLError{
			Code:    "INVALID_ENTITY_ID",
			Message: "Entity ID must be a valid URL",
			Details: err.Error(),
		}
	}

	// Create SAML Service Provider options
	samlOptions := samlsp.Options{
		URL:          *rootURL,
		Key:          nil, // Will be set if provided
		Certificate:  nil, // Will be set if provided
		EntityID:     config.EntityID,
	}

	// Parse signing credentials if provided
	if config.PrivateKeyPEM != "" && config.CertificatePEM != "" {
		privateKey, certificate, err := parseCertificateAndKey(config.PrivateKeyPEM, config.CertificatePEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse SAML signing credentials: %w", err)
		}
		samlOptions.Key = privateKey
		samlOptions.Certificate = certificate
	}

	// Load IDP metadata
	var idpMetadata *saml.EntityDescriptor
	if config.IDPMetadataURL != "" {
		// Fetch metadata from URL
		metadataURL, err := url.Parse(config.IDPMetadataURL)
		if err != nil {
			return nil, &SAMLError{
				Code:    "INVALID_METADATA_URL",
				Message: "Invalid IDP metadata URL",
				Details: err.Error(),
			}
		}

		ctx := context.Background()
		idpMetadata, err = samlsp.FetchMetadata(ctx, http.DefaultClient, *metadataURL)
		if err != nil {
			return nil, &SAMLError{
				Code:    "METADATA_PARSE_FAILED",
				Message: "Failed to fetch and parse IDP metadata",
				Details: err.Error(),
			}
		}
	} else if config.IDPMetadataXML != "" {
		// Parse metadata from XML string
		var err error
		idpMetadata, err = samlsp.ParseMetadata([]byte(config.IDPMetadataXML))
		if err != nil {
			return nil, &SAMLError{
				Code:    "METADATA_PARSE_FAILED",
				Message: "Failed to parse IDP metadata XML",
				Details: err.Error(),
			}
		}
	} else {
		return nil, &SAMLError{
			Code:    "NO_IDP_METADATA",
			Message: "Either IDP metadata URL or XML must be provided",
		}
	}

	samlOptions.IDPMetadata = idpMetadata

	// Create the SAML service provider middleware
	serviceProvider, err := samlsp.New(samlOptions)
	if err != nil {
		return nil, &SAMLError{
			Code:    "SP_CREATION_FAILED",
			Message: "Failed to create SAML service provider",
			Details: err.Error(),
		}
	}

	return &SAMLProvider{
		config:          config,
		jwtService:      jwtService,
		serviceProvider: serviceProvider,
		mfaHandler:      mfaHandler,
	}, nil
}

// GetMetadata returns the SAML service provider metadata
func (sp *SAMLProvider) GetMetadata() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Generate mock metadata for testing
		metadata := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<EntityDescriptor entityID="%s" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>`, sp.config.EntityID, sp.config.ACSURL)
		
		c.Set("Content-Type", "application/samlmetadata+xml")
		return c.Send([]byte(metadata))
	}
}

// GetAuthURL returns the SAML authentication URL
func (sp *SAMLProvider) GetAuthURL(relayState string) (string, error) {
	// Create mock authentication URL for testing
	baseURL := sp.config.IDPMetadataURL
	if baseURL == "" {
		baseURL = "https://idp.example.com/sso"
	}
	
	// Build authentication URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", &SAMLError{
			Code:    "AUTH_REQUEST_FAILED",
			Message: "Failed to create SAML authentication request",
			Details: err.Error(),
		}
	}
	
	query := parsedURL.Query()
	query.Set("SAMLRequest", "mock-saml-request")
	if relayState != "" {
		query.Set("RelayState", relayState)
	}
	parsedURL.RawQuery = query.Encode()
	
	return parsedURL.String(), nil
}

// HandleAssertion processes SAML assertion and creates JWT token
func (sp *SAMLProvider) HandleAssertion() fiber.Handler {
	return func(c fiber.Ctx) error {
		// This is a simplified version - in production, you'd need to properly
		// integrate with the samlsp middleware and handle the full SAML flow
		
		// For now, we'll simulate processing a SAML assertion
		// In a real implementation, this would extract data from the SAML response
		
		// Extract SAML response from POST data
		samlResponse := c.FormValue("SAMLResponse")
		if samlResponse == "" {
			return sp.sendSAMLError(c, "MISSING_SAML_RESPONSE", "SAML response not found", http.StatusBadRequest)
		}

		// In a real implementation, you would:
		// 1. Decode the base64 SAML response
		// 2. Validate the signature
		// 3. Check timestamps
		// 4. Extract user attributes
		
		// For this implementation, we'll create a mock assertion
		assertion := &SAMLAssertion{
			Subject:     "mock-user-" + time.Now().Format("20060102150405"),
			NameID:      "mock@example.com",
			Email:       "mock@example.com",
			DisplayName: "Mock User",
			GivenName:   "Mock",
			Surname:     "User",
			Groups:      []string{"users", "employees"},
			Attributes: map[string]interface{}{
				"department": "Engineering",
				"role":       "developer",
			},
			SessionIndex: "session-" + time.Now().Format("20060102150405"),
			NotOnOrAfter: time.Now().Add(8 * time.Hour),
		}

		// Create JWT token from SAML assertion
		tokenPair, err := sp.jwtService.GenerateToken(assertion.Subject, assertion.Email, assertion.DisplayName)
		if err != nil {
			return sp.sendSAMLError(c, "JWT_GENERATION_FAILED", "Failed to generate session token", http.StatusInternalServerError)
		}

		// Get relay state for redirect
		relayState := c.FormValue("RelayState")
		if relayState == "" {
			relayState = "/"
		}

		// Return successful authentication response
		return c.JSON(fiber.Map{
			"success": true,
			"token":   tokenPair.AccessToken,
			"refresh_token": tokenPair.RefreshToken,
			"expires_at": tokenPair.ExpiresAt.Unix(),
			"user": fiber.Map{
				"id":    assertion.Subject,
				"email": assertion.Email,
				"name":  assertion.DisplayName,
			},
			"assertion": assertion,
			"relay_state": relayState,
		})
	}
}

// ProcessAssertion processes SAML assertion with MFA support (Story 2.4)
func (sp *SAMLProvider) ProcessAssertion(samlResponse string, clientIP, userAgent string) (*JWTClaims, bool, error) {
	// Validate SAML assertion
	assertion, err := sp.ValidateAssertion(samlResponse)
	if err != nil {
		return nil, false, fmt.Errorf("SAML assertion validation failed: %w", err)
	}

	// Extract MFA information from SAML assertion
	mfaCompleted := sp.extractMFAFromSAMLAssertion(assertion)
	
	// Create JWT claims from SAML assertion
	now := time.Now()
	claims := &JWTClaims{
		// Basic user information
		UserID:    assertion.Subject,
		Email:     assertion.Email,
		Name:      assertion.DisplayName,
		IssuedAt:  now,
		ExpiresAt: assertion.NotOnOrAfter,
		
		// Role and groups (would be mapped from SAML attributes in production)
		Role:                 "user",
		Groups:               assertion.Groups,
		KubernetesUser:       assertion.Subject, // Simple mapping
		KubernetesGroups:     assertion.Groups,
		DefaultNamespace:     "default",
		AllowedNamespaces:    []string{"default"},
		ClusterAccess:        false,
		ServiceAccountName:   "",
		
		// Claims metadata
		ClaimsVersion:       2,
		LastPermissionCheck: now,
		
		// MFA fields from SAML assertion
		MFACompleted:        assertion.MFACompleted,
		MFAMethod:           assertion.MFAMethod,
		MFATimestamp:        assertion.MFATimestamp,
		MFAValidityDuration: 4 * time.Hour, // Standard 4-hour MFA validity
		RequiresMFAStepUp:   false,
	}

	// Check if MFA is required but not completed
	if sp.mfaHandler != nil && !mfaCompleted {
		requiresMFA, _, err := sp.mfaHandler.RequiresMFA(context.Background(), claims, clientIP, userAgent)
		if err != nil {
			return nil, false, fmt.Errorf("failed to check MFA requirements: %w", err)
		}
		
		if requiresMFA {
			// MFA is required but not completed in SAML assertion
			return claims, true, nil // Return true to indicate MFA challenge needed
		}
	}

	return claims, false, nil // Return false to indicate no MFA challenge needed
}

// extractMFAFromSAMLAssertion extracts MFA information from SAML assertion
func (sp *SAMLProvider) extractMFAFromSAMLAssertion(assertion *SAMLAssertion) bool {
	// Check SAML AuthnContext for MFA indicators
	for _, authContext := range assertion.AuthContexts {
		switch authContext {
		case "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken", // Hardware tokens
			"urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI",      // Software certificates
			"urn:oasis:names:tc:SAML:2.0:ac:classes:X509",            // X.509 certificates
			"urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",       // Client certificates
			"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",       // Smart cards
			"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI":    // Smart card PKI
			
			// Set MFA as completed and extract method
			assertion.MFACompleted = true
			assertion.MFATimestamp = time.Now()
			
			// Determine MFA method from context
			if strings.Contains(authContext, "TimeSyncToken") {
				assertion.MFAMethod = "HARDWARE_TOKEN"
			} else if strings.Contains(authContext, "Smartcard") {
				assertion.MFAMethod = "HARDWARE_TOKEN"
			} else if strings.Contains(authContext, "PKI") || strings.Contains(authContext, "X509") {
				assertion.MFAMethod = "HARDWARE_TOKEN"
			} else {
				assertion.MFAMethod = "UNKNOWN"
			}
			
			return true
		}
	}

	// Check SAML attributes for MFA information
	if mfaAttr, exists := assertion.Attributes["MFA_COMPLETED"]; exists {
		if mfaCompleted, ok := mfaAttr.(bool); ok && mfaCompleted {
			assertion.MFACompleted = true
			assertion.MFATimestamp = time.Now()
			
			// Check for MFA method attribute
			if methodAttr, exists := assertion.Attributes["MFA_METHOD"]; exists {
				if method, ok := methodAttr.(string); ok {
					assertion.MFAMethod = strings.ToUpper(method)
				}
			}
			
			return true
		}
	}

	// Check for provider-specific MFA attributes
	if authMethods, exists := assertion.Attributes["AUTHENTICATION_METHODS"]; exists {
		if methods, ok := authMethods.([]string); ok {
			for _, method := range methods {
				method = strings.ToLower(method)
				if strings.Contains(method, "mfa") || 
				   strings.Contains(method, "otp") || 
				   strings.Contains(method, "token") ||
				   strings.Contains(method, "sms") ||
				   strings.Contains(method, "push") {
					
					assertion.MFACompleted = true
					assertion.MFATimestamp = time.Now()
					
					// Map method name to standard MFA method
					if strings.Contains(method, "otp") || strings.Contains(method, "totp") {
						assertion.MFAMethod = "TOTP"
					} else if strings.Contains(method, "sms") {
						assertion.MFAMethod = "SMS"
					} else if strings.Contains(method, "push") {
						assertion.MFAMethod = "PUSH"
					} else if strings.Contains(method, "token") || strings.Contains(method, "hardware") {
						assertion.MFAMethod = "HARDWARE_TOKEN"
					} else {
						assertion.MFAMethod = "UNKNOWN"
					}
					
					return true
				}
			}
		}
	}

	return false
}

// HandleSingleLogout processes SAML single logout requests
func (sp *SAMLProvider) HandleSingleLogout() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract logout request/response
		logoutRequest := c.FormValue("SAMLRequest")
		logoutResponse := c.FormValue("SAMLResponse")
		
		if logoutRequest == "" && logoutResponse == "" {
			return sp.sendSAMLError(c, "MISSING_LOGOUT_DATA", "SAML logout request or response not found", http.StatusBadRequest)
		}

		// In a real implementation, you would:
		// 1. Parse and validate the logout request/response
		// 2. Invalidate local sessions
		// 3. Send appropriate logout response
		
		// For now, return a simple success response
		return c.JSON(fiber.Map{
			"success": true,
			"message": "Logout successful",
		})
	}
}

// CreateFallbackHandler creates a handler that attempts OIDC first, falls back to SAML
func CreateFallbackHandler(authMiddleware *AuthMiddleware, samlProvider *SAMLProvider) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Check if OIDC providers are available and working
		providerName := c.Query("provider")
		
		// Try OIDC first if provider is specified
		if providerName != "" {
			authURL, err := authMiddleware.GetAuthURL(providerName, c.Query("state", "default"))
			if err == nil {
				return c.JSON(fiber.Map{
					"auth_type": "oidc",
					"provider":  providerName,
					"auth_url":  authURL,
				})
			}
			
			// Log OIDC failure but don't return error yet
			fmt.Printf("OIDC authentication failed for provider %s: %v\n", providerName, err)
		}

		// Fall back to SAML
		samlAuthURL, err := samlProvider.GetAuthURL(c.Query("relay_state", ""))
		if err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
				"error":   true,
				"code":    "FALLBACK_FAILED",
				"message": "Both OIDC and SAML authentication failed",
			})
		}

		return c.JSON(fiber.Map{
			"auth_type": "saml",
			"message":   "Falling back to SAML authentication",
			"auth_url":  samlAuthURL,
		})
	}
}

// ValidateAssertion validates a SAML assertion (placeholder for actual validation)
func (sp *SAMLProvider) ValidateAssertion(samlResponse string) (*SAMLAssertion, error) {
	// This is a placeholder - in a real implementation you would:
	// 1. Base64 decode the SAML response
	// 2. Parse the XML
	// 3. Validate signatures
	// 4. Check timestamps (NotBefore, NotOnOrAfter)
	// 5. Extract attributes
	// 6. Map to internal user model

	// For now, return a mock assertion
	return &SAMLAssertion{
		Subject:     "saml-user-" + time.Now().Format("20060102150405"),
		NameID:      "saml.user@company.com",
		Email:       "saml.user@company.com",
		DisplayName: "SAML User",
		GivenName:   "SAML",
		Surname:     "User",
		Groups:      []string{"employees", "saml-users"},
		Attributes: map[string]interface{}{
			"source": "saml",
			"authenticated_at": time.Now().Unix(),
		},
		SessionIndex: "saml-session-" + time.Now().Format("20060102150405"),
		NotOnOrAfter: time.Now().Add(8 * time.Hour),
	}, nil
}

// GetSupportedSAMLBindings returns supported SAML bindings
func (sp *SAMLProvider) GetSupportedSAMLBindings() []string {
	return []string{
		"HTTP-POST",
		"HTTP-Redirect",
	}
}

// GenerateMetadata generates SAML metadata for the service provider
func (sp *SAMLProvider) GenerateMetadata() (string, error) {
	if sp.serviceProvider == nil {
		return "", &SAMLError{
			Code:    "SP_NOT_INITIALIZED",
			Message: "SAML service provider not properly initialized",
		}
	}

	// Generate the actual metadata using the crewjam/saml library
	metadata := sp.serviceProvider.ServiceProvider.Metadata()
	
	// Convert to XML bytes
	xmlBytes, err := xml.Marshal(metadata)
	if err != nil {
		return "", &SAMLError{
			Code:    "METADATA_GENERATION_FAILED",
			Message: "Failed to generate SAML metadata",
			Details: err.Error(),
		}
	}

	return string(xmlBytes), nil
}

// Helper functions

func (sp *SAMLProvider) sendSAMLError(c fiber.Ctx, code, message string, statusCode int) error {
	// Log the error
	fmt.Printf("SAML error: %s - %s\n", code, message)

	return c.Status(statusCode).JSON(fiber.Map{
		"error":   true,
		"code":    code,
		"message": message,
		"type":    "saml_error",
	})
}

func validateSAMLConfig(config SAMLConfig) error {
	if config.EntityID == "" {
		return &SAMLError{Code: "INVALID_CONFIG", Message: "Entity ID is required"}
	}
	if config.ACSURL == "" {
		return &SAMLError{Code: "INVALID_CONFIG", Message: "ACS URL is required"}
	}
	if config.IDPMetadataURL == "" && config.IDPMetadataXML == "" {
		return &SAMLError{Code: "INVALID_CONFIG", Message: "IDP metadata URL or XML is required"}
	}
	return nil
}

func parseCertificateAndKey(privateKeyPEM, certificatePEM string) (*rsa.PrivateKey, *x509.Certificate, error) {
	// Parse private key
	keyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse private key PEM")
	}

	var privateKey *rsa.PrivateKey
	var err error

	if keyBlock.Type == "RSA PRIVATE KEY" {
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	} else if keyBlock.Type == "PRIVATE KEY" {
		keyInterface, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, nil, err
		}
		var ok bool
		privateKey, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("not an RSA private key")
		}
	} else {
		return nil, nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode([]byte(certificatePEM))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to parse certificate PEM")
	}

	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return privateKey, certificate, nil
}

// SAMLProviderTemplate provides configuration templates for common SAML providers
func GetSAMLProviderTemplates() map[string]SAMLConfig {
	return map[string]SAMLConfig{
		"adfs": {
			SignRequests:  true,
			ForceAuthn:   false,
			AllowIDPInit: true,
		},
		"okta-saml": {
			SignRequests:  true,
			ForceAuthn:   true,
			AllowIDPInit: false,
		},
		"auth0-saml": {
			SignRequests:  true,
			ForceAuthn:   false,
			AllowIDPInit: true,
		},
		"shibboleth": {
			SignRequests:  false,
			ForceAuthn:   false,
			AllowIDPInit: true,
		},
	}
}

// CreateSAMLRoutes creates all SAML-related routes
func CreateSAMLRoutes(app fiber.Router, samlProvider *SAMLProvider) {
	saml := app.Group("/saml")
	
	// Metadata endpoint
	saml.Get("/metadata", samlProvider.GetMetadata())
	
	// Assertion Consumer Service (ACS)
	saml.Post("/acs", samlProvider.HandleAssertion())
	
	// Single Logout Service (SLS)
	saml.Post("/sls", samlProvider.HandleSingleLogout())
	saml.Get("/sls", samlProvider.HandleSingleLogout())
}

// SAMLUserMapper maps SAML assertions to internal user model
type SAMLUserMapper struct {
	EmailAttribute      string            `json:"email_attribute"`
	NameAttribute       string            `json:"name_attribute"`
	GroupsAttribute     string            `json:"groups_attribute"`
	AttributeMapping    map[string]string `json:"attribute_mapping"`
	DefaultRole         string            `json:"default_role"`
}

// MapSAMLUser maps a SAML assertion to user attributes
func (mapper *SAMLUserMapper) MapSAMLUser(assertion *SAMLAssertion) map[string]interface{} {
	userAttributes := make(map[string]interface{})
	
	// Map standard attributes
	userAttributes["sub"] = assertion.Subject
	userAttributes["email"] = assertion.Email
	userAttributes["name"] = assertion.DisplayName
	userAttributes["given_name"] = assertion.GivenName
	userAttributes["family_name"] = assertion.Surname
	userAttributes["groups"] = assertion.Groups
	
	// Map custom attributes based on configuration
	for samlAttr, userAttr := range mapper.AttributeMapping {
		if value, exists := assertion.Attributes[samlAttr]; exists {
			userAttributes[userAttr] = value
		}
	}
	
	// Map common attributes directly (for backward compatibility)
	if role, exists := assertion.Attributes["role"]; exists {
		userAttributes["role"] = role
	}
	
	// Set default role if not specified
	if mapper.DefaultRole != "" {
		if _, hasRole := userAttributes["role"]; !hasRole {
			userAttributes["role"] = mapper.DefaultRole
		}
	}
	
	return userAttributes
}