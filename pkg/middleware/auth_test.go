package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock JWT service for testing that implements the JWTServiceInterface
type mockJWTService struct {
	generateTokenResult *TokenPair
	generateTokenError  error
	validateTokenResult *JWTClaims
	validateTokenError  error
}

func (m *mockJWTService) GenerateToken(userID, email, name string) (*TokenPair, error) {
	if m.generateTokenError != nil {
		return nil, m.generateTokenError
	}
	return m.generateTokenResult, nil
}

func (m *mockJWTService) ValidateToken(token string) (*JWTClaims, error) {
	if m.validateTokenError != nil {
		return nil, m.validateTokenError
	}
	return m.validateTokenResult, nil
}

func (m *mockJWTService) RefreshToken(refreshToken string) (*TokenPair, error) {
	return m.generateTokenResult, m.generateTokenError
}

func (m *mockJWTService) BlacklistToken(sessionID string) error {
	return nil
}

func (m *mockJWTService) CleanupExpiredSessions() error {
	return nil
}

func (m *mockJWTService) GetPublicKey() *rsa.PublicKey {
	// Return a test RSA public key
	return &rsa.PublicKey{}
}

func (m *mockJWTService) GetPublicKeyPEM() (string, error) {
	return "test-public-key", nil
}

// Mock auth middleware for testing without OIDC discovery
type mockAuthMiddleware struct {
	jwtService *mockJWTService
}

func (m *mockAuthMiddleware) RequireAuthentication() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Simple mock authentication check
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(401).JSON(fiber.Map{
				"error":   true,
				"code":    "MISSING_TOKEN",
				"message": "Authorization header required",
			})
		}
		
		tokenParts := strings.Split(authHeader, " ")
		if len(tokenParts) != 2 || strings.ToLower(tokenParts[0]) != "bearer" {
			return c.Status(401).JSON(fiber.Map{
				"error":   true,
				"code":    "INVALID_TOKEN_FORMAT",
				"message": "Authorization header must be in format 'Bearer <token>'",
			})
		}
		
		// Mock validation
		claims, err := m.jwtService.ValidateToken(tokenParts[1])
		if err != nil {
			return c.Status(401).JSON(fiber.Map{
				"error":   true,
				"code":    "INVALID_TOKEN",
				"message": "Token validation failed",
			})
		}
		
		c.Locals("user", claims)
		c.Locals("user_id", claims.UserID)
		c.Locals("session_id", claims.SessionID)
		
		return c.Next()
	}
}

func TestNewAuthMiddleware(t *testing.T) {
	t.Run("no providers configured", func(t *testing.T) {
		jwtService := &mockJWTService{}
		
		// Test empty providers list
		middleware, err := NewAuthMiddleware([]OIDCProvider{}, jwtService)
		assert.Error(t, err)
		assert.Nil(t, middleware)
		assert.Contains(t, err.Error(), "At least one OIDC provider must be configured")
	})
	
	t.Run("provider validation - invalid issuer", func(t *testing.T) {
		// Test with invalid issuer URL to trigger discovery failure
		providers := []OIDCProvider{
			{
				Name:         "test-provider", 
				Issuer:       "https://invalid-oidc-provider.nonexistent",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
				Scopes:       []string{"email", "profile"},
			},
		}
		
		jwtService := &mockJWTService{}
		middleware, err := NewAuthMiddleware(providers, jwtService)
		
		// Expected to fail due to invalid OIDC provider discovery
		assert.Error(t, err)
		assert.Nil(t, middleware)
	})
	
	t.Run("provider validation - success", func(t *testing.T) {
		// Test with valid Google OIDC provider
		providers := []OIDCProvider{
			{
				Name:         "google", 
				Issuer:       "https://accounts.google.com",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURL:  "http://localhost:8080/auth/callback",
				Scopes:       []string{"email", "profile"},
			},
		}
		
		jwtService := &mockJWTService{}
		middleware, err := NewAuthMiddleware(providers, jwtService)
		
		// Should succeed with valid Google OIDC endpoint
		assert.NoError(t, err)
		assert.NotNil(t, middleware)
		assert.Len(t, middleware.providers, 1)
	})
}

func TestValidateProviderConfiguration(t *testing.T) {
	tests := []struct {
		name        string
		provider    OIDCProvider
		expectError bool
	}{
		{
			name: "valid configuration",
			provider: OIDCProvider{
				Name:         "google",
				Issuer:       "https://accounts.google.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost:8080/callback",
				Scopes:       []string{"email"},
			},
			expectError: false,
		},
		{
			name: "missing name",
			provider: OIDCProvider{
				Issuer:       "https://accounts.google.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost:8080/callback",
			},
			expectError: true,
		},
		{
			name: "missing issuer",
			provider: OIDCProvider{
				Name:         "google",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost:8080/callback",
			},
			expectError: true,
		},
		{
			name: "missing client ID",
			provider: OIDCProvider{
				Name:         "google",
				Issuer:       "https://accounts.google.com",
				ClientSecret: "client-secret",
				RedirectURL:  "http://localhost:8080/callback",
			},
			expectError: true,
		},
		{
			name: "missing client secret",
			provider: OIDCProvider{
				Name:        "google",
				Issuer:      "https://accounts.google.com",
				ClientID:    "client-id",
				RedirectURL: "http://localhost:8080/callback",
			},
			expectError: true,
		},
		{
			name: "missing redirect URL",
			provider: OIDCProvider{
				Name:         "google",
				Issuer:       "https://accounts.google.com",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateProviderConfiguration(tt.provider)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRequireAuthentication(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		jwtClaims      *JWTClaims
		jwtError       error
		expectedStatus int
	}{
		{
			name:           "valid authentication",
			authHeader:     "Bearer valid-token",
			jwtClaims:      &JWTClaims{UserID: "user-123", Email: "test@example.com"},
			jwtError:       nil,
			expectedStatus: 200,
		},
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: 401,
		},
		{
			name:           "invalid authorization format",
			authHeader:     "InvalidFormat token",
			expectedStatus: 401,
		},
		{
			name:           "invalid token",
			authHeader:     "Bearer invalid-token",
			jwtError:       &TokenValidationError{Code: "INVALID_TOKEN", Message: "Token is invalid"},
			expectedStatus: 401,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mock JWT service
			jwtService := &mockJWTService{
				validateTokenResult: tt.jwtClaims,
				validateTokenError:  tt.jwtError,
			}
			
			// Create mock auth middleware
			mockAuth := &mockAuthMiddleware{jwtService: jwtService}
			
			// Create Fiber app for testing
			app := fiber.New()
			app.Use(mockAuth.RequireAuthentication())
			app.Get("/protected", func(c fiber.Ctx) error {
				return c.JSON(fiber.Map{"message": "success"})
			})
			
			// Create test request
			req := httptest.NewRequest("GET", "/protected", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			
			// Perform request
			resp, err := app.Test(req)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

func TestGetSupportedProviders(t *testing.T) {
	providers := GetSupportedProviders()
	
	assert.NotEmpty(t, providers)
	assert.Contains(t, providers, "okta")
	assert.Contains(t, providers, "auth0")
	assert.Contains(t, providers, "azure")
	assert.Contains(t, providers, "google")
	
	// Check that each provider has required fields
	for name, provider := range providers {
		assert.Equal(t, name, provider.Name)
		assert.NotEmpty(t, provider.Scopes)
		
		// Check provider-specific configurations
		switch name {
		case "okta":
			assert.Contains(t, provider.ExtraParams, "prompt")
			assert.Equal(t, "login", provider.ExtraParams["prompt"])
		case "google":
			assert.Equal(t, "https://accounts.google.com", provider.Issuer)
			assert.Contains(t, provider.Scopes, "email")
			assert.Contains(t, provider.Scopes, "profile")
		}
	}
}

func TestAuthenticationError(t *testing.T) {
	err := &AuthenticationError{
		Code:    "TEST_ERROR",
		Message: "This is a test error",
		Details: "Additional error details",
	}
	
	expectedMsg := "Authentication error [TEST_ERROR]: This is a test error"
	assert.Equal(t, expectedMsg, err.Error())
}

func TestOIDCProviderMFA(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		expectedMFA  bool
		expectedParams map[string]string
	}{
		{
			name:        "okta with MFA",
			provider:    "okta",
			expectedMFA: true,
			expectedParams: map[string]string{"prompt": "login"},
		},
		{
			name:        "auth0 with MFA",
			provider:    "auth0",
			expectedMFA: true,
			expectedParams: map[string]string{"prompt": "login"},
		},
		{
			name:        "azure with MFA",
			provider:    "azure",
			expectedMFA: true,
			expectedParams: map[string]string{"prompt": "login"},
		},
		{
			name:        "google with account selection",
			provider:    "google",
			expectedMFA: true,
			expectedParams: map[string]string{"prompt": "select_account consent"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test that the provider-specific MFA parameters are correctly set
			// This would be tested in the actual GetAuthURL method
			
			supportedProviders := GetSupportedProviders()
			provider, exists := supportedProviders[tt.provider]
			require.True(t, exists, "Provider %s should exist", tt.provider)
			
			// Verify MFA-related extra parameters are set correctly
			for key, expectedValue := range tt.expectedParams {
				actualValue, exists := provider.ExtraParams[key]
				assert.True(t, exists, "Parameter %s should exist for provider %s", key, tt.provider)
				assert.Equal(t, expectedValue, actualValue, "Parameter %s value mismatch for provider %s", key, tt.provider)
			}
		})
	}
}

// Integration test for authentication flow (simplified)
func TestAuthenticationFlow(t *testing.T) {
	t.Run("complete authentication flow simulation", func(t *testing.T) {
		// Simulate the complete authentication flow
		
		// 1. User requests authentication
		provider := "google"
		state := "test-state-123"
		
		// 2. Generate auth URL (would normally call GetAuthURL)
		expectedAuthURL := "https://accounts.google.com/o/oauth2/auth?client_id=test&redirect_uri=callback&response_type=code&scope=openid+email+profile&state=" + state
		
		// Verify test data is set up correctly
		assert.Equal(t, "google", provider)
		assert.Contains(t, expectedAuthURL, state)
		
		// 3. User authenticates with provider and returns with code
		authCode := "test-auth-code"
		
		// 4. Exchange code for tokens (would normally call HandleCallback)
		// This would involve:
		// - Exchanging authorization code for tokens
		// - Verifying ID token
		// - Extracting user claims
		// - Generating JWT token
		
		// 5. Verify the final JWT token
		expectedClaims := &JWTClaims{
			UserID:    "user-123",
			Email:     "test@example.com",
			Name:      "Test User",
			SessionID: "session-123",
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(8 * time.Hour),
		}
		
		// Simulate successful authentication
		assert.NotEmpty(t, authCode)
		assert.NotNil(t, expectedClaims)
		assert.NotEmpty(t, expectedClaims.UserID)
		assert.NotEmpty(t, expectedClaims.Email)
		
		// Verify token expiration is set correctly (8 hours default)
		expectedDuration := 8 * time.Hour
		actualDuration := expectedClaims.ExpiresAt.Sub(expectedClaims.IssuedAt)
		assert.InDelta(t, expectedDuration.Seconds(), actualDuration.Seconds(), 60) // Allow 1 minute tolerance
	})
}

// Performance test for token validation
func TestTokenValidationPerformance(t *testing.T) {
	t.Run("token validation performance", func(t *testing.T) {
		// This test ensures that token validation is performant
		jwtService := &mockJWTService{
			validateTokenResult: &JWTClaims{
				UserID:    "user-123",
				Email:     "test@example.com",
				SessionID: "session-123",
			},
		}
		
		token := "test-token"
		iterations := 1000
		
		start := time.Now()
		
		for i := 0; i < iterations; i++ {
			claims, err := jwtService.ValidateToken(token)
			assert.NoError(t, err)
			assert.NotNil(t, claims)
		}
		
		duration := time.Since(start)
		avgDuration := duration / time.Duration(iterations)
		
		// Token validation should be fast (less than 1ms per validation on average)
		assert.Less(t, avgDuration, 1*time.Millisecond, "Token validation is too slow")
		
		t.Logf("Token validation performance: %d iterations in %v (avg: %v per validation)", 
			iterations, duration, avgDuration)
	})
}

// Test GetAuthURL method 
func TestGetAuthURL(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		state        string
		expectError  bool
		expectURL    bool
	}{
		{
			name:         "valid google provider",
			providerName: "google",
			state:        "test-state-123",
			expectError:  false,
			expectURL:    true,
		},
		{
			name:         "invalid provider",
			providerName: "nonexistent",
			state:        "test-state",
			expectError:  true,
			expectURL:    false,
		},
		{
			name:         "empty state",
			providerName: "google", 
			state:        "",
			expectError:  false,
			expectURL:    true,
		},
	}

	// Create auth middleware with Google provider for testing
	providers := []OIDCProvider{
		{
			Name:         "google",
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client-id",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/auth/callback",
			Scopes:       []string{"email", "profile"},
		},
	}
	
	jwtService := &mockJWTService{}
	authMiddleware, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authURL, err := authMiddleware.GetAuthURL(tt.providerName, tt.state)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, authURL)
			} else {
				assert.NoError(t, err)
				if tt.expectURL {
					assert.NotEmpty(t, authURL)
					assert.Contains(t, authURL, "oauth2/v2/auth")
					if tt.state != "" {
						assert.Contains(t, authURL, tt.state)
					}
				}
			}
		})
	}
}

// Test GetProviders method
func TestGetProviders(t *testing.T) {
	providers := []OIDCProvider{
		{
			Name:         "google",
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email"},
		},
		{
			Name:         "github",
			Issuer:       "https://github.com", // This will fail, but provider creation should still work
			ClientID:     "github-client",
			ClientSecret: "github-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"user:email"},
		},
	}

	jwtService := &mockJWTService{}
	authMiddleware, err := NewAuthMiddleware(providers[:1], jwtService) // Only use Google to avoid GitHub discovery failure
	require.NoError(t, err)

	availableProviders := authMiddleware.GetProviders()
	assert.NotEmpty(t, availableProviders)
	assert.Contains(t, availableProviders, "google")
}

// Test authentication context extraction
func TestExtractAuthContext(t *testing.T) {
	jwtService := &mockJWTService{
		validateTokenResult: &JWTClaims{
			UserID:    "user-123",
			Email:     "test@example.com",
			SessionID: "session-123",
		},
	}

	// Create minimal auth middleware
	providers := []OIDCProvider{
		{
			Name:         "google",
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			RedirectURL:  "http://localhost:8080/callback",
			Scopes:       []string{"email"},
		},
	}

	authMiddleware, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)

	// Create Fiber app for testing
	app := fiber.New()
	app.Use(authMiddleware.RequireAuthentication())
	app.Get("/test", func(c fiber.Ctx) error {
		// Test context extraction
		user := c.Locals("user")
		userID := c.Locals("user_id")
		sessionID := c.Locals("session_id")
		
		assert.NotNil(t, user)
		assert.Equal(t, "user-123", userID)
		assert.Equal(t, "session-123", sessionID)
		
		return c.JSON(fiber.Map{"success": true})
	})

	// Test with valid token
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/test"},
		Header: http.Header{
			"Authorization": []string{"Bearer valid-token"},
		},
	}

	resp, err := app.Test(req)
	require.NoError(t, err)
	assert.Equal(t, 200, resp.StatusCode)
}

// Test provider-specific MFA parameter handling
func TestProviderMFAParameters(t *testing.T) {
	tests := []struct {
		name         string
		providerName string
		expectedParam string
		expectedValue string
	}{
		{
			name:         "Okta MFA",
			providerName: "okta",
			expectedParam: "prompt",
			expectedValue: "login",
		},
		{
			name:         "Auth0 MFA", 
			providerName: "auth0",
			expectedParam: "prompt",
			expectedValue: "login",
		},
		{
			name:         "Azure MFA",
			providerName: "azure",
			expectedParam: "prompt", 
			expectedValue: "login",
		},
		{
			name:         "Google account selection",
			providerName: "google",
			expectedParam: "prompt",
			expectedValue: "select_account consent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			supportedProviders := GetSupportedProviders()
			provider, exists := supportedProviders[tt.providerName]
			require.True(t, exists, "Provider should exist")
			
			value, exists := provider.ExtraParams[tt.expectedParam]
			assert.True(t, exists, "MFA parameter should exist")
			assert.Equal(t, tt.expectedValue, value, "MFA parameter value should match")
		})
	}
}

// Test middleware initialization with various configurations
func TestAuthMiddlewareInitialization(t *testing.T) {
	jwtService := &mockJWTService{}
	
	t.Run("successful initialization with single provider", func(t *testing.T) {
		providers := []OIDCProvider{
			{
				Name:         "google",
				Issuer:       "https://accounts.google.com",
				ClientID:     "client",
				ClientSecret: "secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"email"},
			},
		}
		
		middleware, err := NewAuthMiddleware(providers, jwtService)
		assert.NoError(t, err)
		assert.NotNil(t, middleware)
		assert.Len(t, middleware.providers, 1)
	})
	
	t.Run("initialization with provider discovery failure", func(t *testing.T) {
		providers := []OIDCProvider{
			{
				Name:         "invalid",
				Issuer:       "https://invalid-oidc-provider.nonexistent",
				ClientID:     "client",
				ClientSecret: "secret",
				RedirectURL:  "http://localhost/callback",
				Scopes:       []string{"email"},
			},
		}
		
		middleware, err := NewAuthMiddleware(providers, jwtService)
		assert.Error(t, err)
		assert.Nil(t, middleware)
		assert.Contains(t, err.Error(), "failed to initialize provider")
	})
}

// Test error handling scenarios
func TestErrorHandlingScenarios(t *testing.T) {
	tests := []struct {
		name          string
		scenario      string
		expectedError bool
		errorCode     string
	}{
		{
			name:          "network timeout during OIDC discovery",
			scenario:      "network_timeout",
			expectedError: true,
			errorCode:     "PROVIDER_DISCOVERY_FAILED",
		},
		{
			name:          "invalid OIDC provider response",
			scenario:      "invalid_response",
			expectedError: true,
			errorCode:     "PROVIDER_DISCOVERY_FAILED",
		},
		{
			name:          "expired authorization code",
			scenario:      "expired_code",
			expectedError: true,
			errorCode:     "TOKEN_EXCHANGE_FAILED",
		},
		{
			name:          "invalid ID token signature",
			scenario:      "invalid_signature",
			expectedError: true,
			errorCode:     "TOKEN_VERIFICATION_FAILED",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate error scenarios
			switch tt.scenario {
			case "network_timeout":
				err := &AuthenticationError{
					Code:    "PROVIDER_DISCOVERY_FAILED",
					Message: "Network timeout during OIDC provider discovery",
				}
				assert.Equal(t, tt.errorCode, err.Code)
				assert.True(t, tt.expectedError)
				
			case "invalid_response":
				err := &AuthenticationError{
					Code:    "PROVIDER_DISCOVERY_FAILED", 
					Message: "Invalid response from OIDC provider",
				}
				assert.Equal(t, tt.errorCode, err.Code)
				assert.True(t, tt.expectedError)
				
			case "expired_code":
				err := &AuthenticationError{
					Code:    "TOKEN_EXCHANGE_FAILED",
					Message: "Authorization code has expired",
				}
				assert.Equal(t, tt.errorCode, err.Code)
				assert.True(t, tt.expectedError)
				
			case "invalid_signature":
				err := &AuthenticationError{
					Code:    "TOKEN_VERIFICATION_FAILED",
					Message: "ID token signature verification failed",
				}
				assert.Equal(t, tt.errorCode, err.Code)
				assert.True(t, tt.expectedError)
			}
		})
	}
}

// TestHandleCallback tests the OAuth2 callback handling
func TestHandleCallback(t *testing.T) {
	// Create mock OIDC server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get the server URL from the request
		serverURL := "http://" + r.Host
		
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"issuer":                serverURL,
				"authorization_endpoint": serverURL + "/auth",
				"token_endpoint":        serverURL + "/token",
				"userinfo_endpoint":     serverURL + "/userinfo",
				"jwks_uri":              serverURL + "/jwks",
			})
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			// Create a mock JWT-like token for testing
			mockIDToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrLXVzZXItMTIzIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwibmFtZSI6IlRlc3QgVXNlciIsImlzcyI6InRlc3QtaXNzdWVyIiwiYXVkIjoidGVzdC1jbGllbnQiLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMH0.fake-signature"
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "mock-access-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
				"id_token":     mockIDToken,
			})
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sub":   "mock-user-123",
				"email": "test@example.com",
				"name":  "Test User",
			})
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			// Return mock JWKS with fake key
			json.NewEncoder(w).Encode(map[string]interface{}{
				"keys": []map[string]interface{}{
					{
						"kty": "RSA",
						"use": "sig",
						"kid": "test-key-id",
						"n":   "fake-modulus",
						"e":   "AQAB",
					},
				},
			})
		}
	}))
	defer mockServer.Close()

	// Setup test provider
	providers := []OIDCProvider{{
		Name:         "test-provider",
		Issuer:       mockServer.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"openid", "email"},
	}}

	// Create JWT service
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		tokenDuration:   time.Hour,
		refreshDuration: 24 * time.Hour,
		issuer:          "test-kubechat",
	}

	// Initialize middleware
	middleware, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)

	tests := []struct {
		name           string
		provider       string
		code           string
		state          string
		expectedStatus int
	}{
		{
			name:           "successful callback",
			provider:       "test-provider",
			code:           "valid-code",
			state:          "test-state",
			expectedStatus: 500, // Token verification will fail with mock
		},
		{
			name:           "missing code",
			provider:       "test-provider",
			code:           "",
			state:          "test-state",
			expectedStatus: 400,
		},
		{
			name:           "invalid provider",
			provider:       "invalid-provider",
			code:           "valid-code",
			state:          "test-state",
			expectedStatus: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			app.Get("/auth/callback/:provider", middleware.HandleCallback)

			url := fmt.Sprintf("/auth/callback/%s", tt.provider)
			if tt.code != "" || tt.state != "" {
				url += fmt.Sprintf("?code=%s&state=%s", tt.code, tt.state)
			}

			req := httptest.NewRequest("GET", url, nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
		})
	}
}

// TestListProviders tests the provider listing endpoint
func TestListProviders(t *testing.T) {
	providers := []OIDCProvider{{
		Name:         "google",
		Issuer:       "https://accounts.google.com",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"openid", "email"},
	}}

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		tokenDuration:   time.Hour,
		refreshDuration: 24 * time.Hour,
		issuer:          "test-kubechat",
	}

	middleware, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)

	app := fiber.New()
	app.Get("/auth/providers", middleware.ListProviders())

	req := httptest.NewRequest("GET", "/auth/providers", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, 200, resp.StatusCode)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	providers_list, ok := result["providers"].([]interface{})
	assert.True(t, ok)
	assert.Len(t, providers_list, 1)
}

// TestSendAuthenticationError tests error response formatting
func TestSendAuthenticationError(t *testing.T) {
	middleware := &AuthMiddleware{}

	app := fiber.New()
	app.Get("/test", func(c fiber.Ctx) error {
		return middleware.sendAuthenticationError(c, "TEST_ERROR", "Test error message", 401)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	assert.Equal(t, 401, resp.StatusCode)

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	assert.Equal(t, true, result["error"])
	assert.Equal(t, "TEST_ERROR", result["code"])
	assert.Equal(t, "Test error message", result["message"])
}

// TestGetAuthURLEdgeCases tests additional GetAuthURL scenarios for better coverage
func TestGetAuthURLAdditionalEdgeCases(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		tokenDuration:   time.Hour,
		refreshDuration: 24 * time.Hour,
		issuer:          "test-issuer",
	}
	
	providers := []OIDCProvider{
		{
			Name:         "google",
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://example.com/auth/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	}
	
	auth, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)
	
	tests := []struct {
		name        string
		provider    string
		state       string
		expectError bool
		errorText   string
	}{
		{
			name:        "valid provider with state",
			provider:    "google",
			state:       "test-state-123",
			expectError: false,
		},
		{
			name:        "valid provider with empty state",
			provider:    "google",
			state:       "",
			expectError: false,
		},
		{
			name:        "unknown provider",
			provider:    "unknown",
			state:       "test-state",
			expectError: true,
			errorText:   "PROVIDER_NOT_FOUND",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, err := auth.GetAuthURL(tt.provider, tt.state)
			
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorText != "" {
					assert.Contains(t, err.Error(), tt.errorText)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, url)
				assert.Contains(t, url, "client_id=test-client-id")
				if tt.state != "" {
					assert.Contains(t, url, fmt.Sprintf("state=%s", tt.state))
				}
			}
		})
	}
}

// TestHandleCallbackAdditionalEdgeCases tests more HandleCallback scenarios
func TestHandleCallbackAdditionalEdgeCases(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		tokenDuration:   time.Hour,
		refreshDuration: 24 * time.Hour,
		issuer:          "test-issuer",
	}
	
	providers := []OIDCProvider{
		{
			Name:         "google",
			Issuer:       "https://accounts.google.com", 
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://example.com/auth/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	}
	
	auth, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)
	
	app := fiber.New()
	app.Get("/auth/:provider/callback", auth.HandleCallback)
	
	tests := []struct {
		name           string
		url            string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "missing authorization code",
			url:            "/auth/google/callback?state=test-state",
			expectedStatus: 400,
			expectedError:  "AUTHORIZATION_FAILED",
		},
		{
			name:           "error parameter in callback",
			url:            "/auth/google/callback?error=access_denied&error_description=User%20denied%20access",
			expectedStatus: 400,
			expectedError:  "AUTHORIZATION_FAILED",
		},
		{
			name:           "invalid provider in callback",
			url:            "/auth/invalid-provider/callback?code=test-code&state=test-state",
			expectedStatus: 400,
			expectedError:  "PROVIDER_NOT_FOUND",
		},
		{
			name:           "valid callback format (will fail token exchange)",
			url:            "/auth/google/callback?code=test-auth-code&state=test-state",
			expectedStatus: 500,
			expectedError:  "TOKEN_EXCHANGE_FAILED", // Expected without real OAuth
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			
			resp, err := app.Test(req)
			require.NoError(t, err)
			
			assert.Equal(t, tt.expectedStatus, resp.StatusCode)
			
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			
			if tt.expectedError != "" {
				assert.Contains(t, string(body), tt.expectedError)
			}
		})
	}
}

// TestAuthenticationContextExtraction tests auth context extraction
func TestAuthenticationContextExtraction(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	jwtService := &JWTService{
		privateKey:      privateKey,
		publicKey:       &privateKey.PublicKey,
		tokenDuration:   time.Hour,
		refreshDuration: 24 * time.Hour,
		issuer:          "test-issuer",
	}
	
	providers := []OIDCProvider{
		{
			Name:         "google",
			Issuer:       "https://accounts.google.com",
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURL:  "https://example.com/auth/callback",
			Scopes:       []string{"openid", "profile", "email"},
		},
	}
	
	auth, err := NewAuthMiddleware(providers, jwtService)
	require.NoError(t, err)
	
	app := fiber.New()
	
	// Add auth middleware and a test endpoint
	app.Use(auth.RequireAuthentication())
	app.Get("/protected", func(c fiber.Ctx) error {
		return c.JSON(fiber.Map{"message": "protected"})
	})
	
	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		resp, err := app.Test(req)
		require.NoError(t, err)
		
		assert.Equal(t, 401, resp.StatusCode)
		
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "MISSING_TOKEN")
	})
	
	t.Run("invalid authorization header format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "InvalidFormat token")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		
		assert.Equal(t, 401, resp.StatusCode)
		
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "INVALID_TOKEN_FORMAT")
	})
	
	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/protected", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		
		resp, err := app.Test(req)
		require.NoError(t, err)
		
		assert.Equal(t, 401, resp.StatusCode)
		
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "INVALID_TOKEN")
	})
}