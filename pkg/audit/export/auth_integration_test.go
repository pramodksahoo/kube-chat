package export

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTTokenValidation(t *testing.T) {
	// Test JWT token validation - addresses QA issue SEC-001
	secret := "test-jwt-secret-key-for-integration-testing"
	
	config := ExportAuthConfig{
		RequireAuthentication: true,
		JWTSecret:            secret,
		SessionTimeout:       time.Hour,
	}
	
	authService := NewExportAuthService(config)
	
	t.Run("Valid JWT Token", func(t *testing.T) {
		// Create a valid JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub":    "user123",
			"email":  "test@example.com", 
			"name":   "Test User",
			"roles":  []string{"admin", "user"},
			"groups": []string{"developers", "ops"},
			"sid":    "session456",
			"iss":    "kubechat-auth",
			"iat":    time.Now().Unix(),
			"exp":    time.Now().Add(time.Hour).Unix(),
		})
		
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)
		
		// Validate the token
		authContext, err := authService.ValidateSessionToken(context.Background(), tokenString)
		
		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, authContext)
		assert.Equal(t, "user123", authContext.UserID)
		assert.Equal(t, "test@example.com", authContext.Email)
		assert.Equal(t, "Test User", authContext.Name)
		assert.Contains(t, authContext.Roles, "admin")
		assert.Contains(t, authContext.Groups, "developers")
		assert.Equal(t, "session456", authContext.SessionID)
		assert.Equal(t, "kubechat-auth", authContext.AuthProvider)
	})
	
	t.Run("Expired JWT Token", func(t *testing.T) {
		// Create an expired JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
			"iat": time.Now().Add(-2 * time.Hour).Unix(),
		})
		
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)
		
		// Validate the token - should fail
		authContext, err := authService.ValidateSessionToken(context.Background(), tokenString)
		
		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authContext)
		assert.Contains(t, err.Error(), "expired")
	})
	
	t.Run("Invalid Signature", func(t *testing.T) {
		// Create a token with wrong secret
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": "user123",
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		
		tokenString, err := token.SignedString([]byte("wrong-secret"))
		require.NoError(t, err)
		
		// Validate the token - should fail
		authContext, err := authService.ValidateSessionToken(context.Background(), tokenString)
		
		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authContext)
		assert.Contains(t, err.Error(), "invalid")
	})
	
	t.Run("Missing Subject Claim", func(t *testing.T) {
		// Create a token without required 'sub' claim
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"email": "test@example.com",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
		})
		
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)
		
		// Validate the token - should fail
		authContext, err := authService.ValidateSessionToken(context.Background(), tokenString)
		
		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authContext)
		assert.Contains(t, err.Error(), "missing required 'sub' claim")
	})
	
	t.Run("Authentication Disabled", func(t *testing.T) {
		// Test with authentication disabled
		disabledConfig := ExportAuthConfig{
			RequireAuthentication: false,
			SessionTimeout:       time.Hour,
		}
		
		disabledAuthService := NewExportAuthService(disabledConfig)
		
		// Should return anonymous context without validating token
		authContext, err := disabledAuthService.ValidateSessionToken(context.Background(), "invalid-token")
		
		// Assertions
		assert.NoError(t, err)
		assert.NotNil(t, authContext)
		assert.Equal(t, "anonymous", authContext.UserID)
		assert.Equal(t, "anonymous@localhost", authContext.Email)
		assert.Contains(t, authContext.Roles, "user")
	})
	
	t.Run("Missing JWT Secret", func(t *testing.T) {
		// Test with missing JWT secret
		noSecretConfig := ExportAuthConfig{
			RequireAuthentication: true,
			JWTSecret:            "", // Missing secret
			SessionTimeout:       time.Hour,
		}
		
		noSecretAuthService := NewExportAuthService(noSecretConfig)
		
		// Should fail due to missing secret
		authContext, err := noSecretAuthService.ValidateSessionToken(context.Background(), "any-token")
		
		// Assertions
		assert.Error(t, err)
		assert.Nil(t, authContext)
		assert.Contains(t, err.Error(), "JWT secret not configured")
	})
}

func TestPermissionValidation(t *testing.T) {
	// Test permission validation - addresses QA authentication requirements
	config := ExportAuthConfig{
		RequireAuthentication: true,
		RequiredPermissions: []ExportPermission{
			{
				Resource: "audit",
				Actions:  []string{"read", "export"},
				Scope:    "global",
			},
		},
		AllowedRoles: []string{"admin", "auditor"},
	}
	
	authService := NewExportAuthService(config)
	
	t.Run("Valid Permissions", func(t *testing.T) {
		authContext := &AuthContext{
			UserID: "user123",
			Roles:  []string{"admin"},
			Permissions: []ExportPermission{
				{
					Resource: "audit",
					Actions:  []string{"read", "export", "manage"},
					Scope:    "global",
				},
			},
		}
		
		hasPermission := authService.HasRequiredPermissions(authContext)
		assert.True(t, hasPermission)
	})
	
	t.Run("Missing Required Role", func(t *testing.T) {
		authContext := &AuthContext{
			UserID: "user123",
			Roles:  []string{"user"}, // Not in allowed roles
			Permissions: []ExportPermission{
				{
					Resource: "audit",
					Actions:  []string{"read", "export"},
					Scope:    "global",
				},
			},
		}
		
		hasPermission := authService.HasRequiredPermissions(authContext)
		assert.False(t, hasPermission)
	})
	
	t.Run("Insufficient Permissions", func(t *testing.T) {
		authContext := &AuthContext{
			UserID: "user123",
			Roles:  []string{"admin"},
			Permissions: []ExportPermission{
				{
					Resource: "audit",
					Actions:  []string{"read"}, // Missing 'export' action
					Scope:    "global",
				},
			},
		}
		
		hasPermission := authService.HasRequiredPermissions(authContext)
		assert.False(t, hasPermission)
	})
}