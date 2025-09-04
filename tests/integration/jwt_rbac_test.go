// Package integration provides integration tests for JWT RBAC functionality
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/pramodksahoo/kube-chat/pkg/config"
	"github.com/pramodksahoo/kube-chat/pkg/middleware"
)

// JWTRBACIntegrationTestSuite is the test suite for JWT RBAC integration tests
type JWTRBACIntegrationTestSuite struct {
	suite.Suite
	jwtService    middleware.JWTServiceInterface
	redisClient   redis.UniversalClient
	groupMapper   *config.OIDCGroupMapper
}

// SetupSuite sets up the test suite
func (suite *JWTRBACIntegrationTestSuite) SetupSuite() {
	// Setup Redis client for testing
	suite.redisClient = redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       15, // Use test database
	})

	// Test Redis connection
	ctx := context.Background()
	err := suite.redisClient.Ping(ctx).Err()
	if err != nil {
		suite.T().Skip("Redis not available for integration tests")
	}

	// Setup JWT service
	config := middleware.JWTConfig{
		RedisAddr:       "localhost:6379",
		RedisDB:         15,
		TokenDuration:   time.Hour,
		RefreshDuration: 24 * time.Hour,
		Issuer:          "kubechat-integration-test",
	}

	jwtService, err := middleware.NewJWTService(config)
	require.NoError(suite.T(), err)
	suite.jwtService = jwtService

	// Setup OIDC group mapper
	suite.groupMapper = config.NewOIDCGroupMapper(nil) // Use default mapping
}

// TearDownSuite cleans up the test suite
func (suite *JWTRBACIntegrationTestSuite) TearDownSuite() {
	if suite.redisClient != nil {
		// Clean up test data
		ctx := context.Background()
		suite.redisClient.FlushDB(ctx)
		suite.redisClient.Close()
	}
}

// TestOktaUserFlow tests the complete flow for an Okta user
func (suite *JWTRBACIntegrationTestSuite) TestOktaUserFlow() {
	t := suite.T()
	ctx := context.Background()

	// Simulate OIDC claims from Okta
	oidcClaims := map[string]interface{}{
		"sub":               "okta-user-123",
		"email":             "admin@company.com",
		"name":              "Admin User",
		"preferred_username": "admin",
		"groups":            []interface{}{"okta-k8s-admins", "platform-team"},
	}

	// Step 1: Map OIDC groups to Kubernetes groups
	groupResult, err := suite.groupMapper.MapGroups("okta", oidcClaims)
	require.NoError(t, err)

	assert.Equal(t, "admin@company.com", groupResult.KubernetesUser)
	assert.Contains(t, groupResult.KubernetesGroups, "system:masters")
	assert.True(t, groupResult.ClusterAccess)
	assert.Equal(t, "okta", groupResult.MappingSource)

	// Step 2: Create enhanced JWT claims
	jwtClaims := &middleware.JWTClaims{
		UserID:              "okta-user-123",
		Email:               "admin@company.com",
		Name:                "Admin User",
		Role:                "admin",
		Groups:              []string{"okta-k8s-admins", "platform-team"},
		KubernetesUser:      groupResult.KubernetesUser,
		KubernetesGroups:    groupResult.KubernetesGroups,
		DefaultNamespace:    groupResult.DefaultNamespace,
		AllowedNamespaces:   groupResult.AllowedNamespaces,
		ClusterAccess:       groupResult.ClusterAccess,
		ServiceAccountName:  "",
		ClaimsVersion:       2,
		LastPermissionCheck: time.Now(),
	}

	// Step 3: Generate JWT token
	tokenPair, err := suite.jwtService.GenerateTokenWithClaims(jwtClaims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenPair.AccessToken)
	assert.NotEmpty(t, tokenPair.RefreshToken)

	// Step 4: Validate the generated token
	validatedClaims, err := suite.jwtService.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, jwtClaims.UserID, validatedClaims.UserID)
	assert.Equal(t, jwtClaims.KubernetesUser, validatedClaims.KubernetesUser)
	assert.Equal(t, jwtClaims.ClusterAccess, validatedClaims.ClusterAccess)
	assert.Equal(t, 2, validatedClaims.ClaimsVersion)

	// Step 5: Test token refresh
	refreshedTokenPair, err := suite.jwtService.RefreshToken(tokenPair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshedTokenPair.AccessToken)
	assert.NotEqual(t, tokenPair.AccessToken, refreshedTokenPair.AccessToken) // Should be different

	// Step 6: Validate refreshed token
	refreshedClaims, err := suite.jwtService.ValidateToken(refreshedTokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, jwtClaims.UserID, refreshedClaims.UserID)
	assert.Equal(t, jwtClaims.KubernetesUser, refreshedClaims.KubernetesUser)
}

// TestAzureADUserFlow tests the complete flow for an Azure AD user
func (suite *JWTRBACIntegrationTestSuite) TestAzureADUserFlow() {
	t := suite.T()

	// Simulate OIDC claims from Azure AD
	oidcClaims := map[string]interface{}{
		"sub":   "aad-user-456",
		"email": "developer@company.com",
		"name":  "Developer User",
		"groups": []interface{}{"aad-developers", "aad-platform"},
	}

	// Step 1: Map OIDC groups to Kubernetes groups
	groupResult, err := suite.groupMapper.MapGroups("azure", oidcClaims)
	require.NoError(t, err)

	assert.Equal(t, "developer@company.com", groupResult.KubernetesUser)
	assert.Contains(t, groupResult.KubernetesGroups, "kubechat:operators")
	assert.False(t, groupResult.ClusterAccess) // Developers don't have cluster access
	assert.Equal(t, "azure", groupResult.MappingSource)

	// Step 2: Create enhanced JWT claims
	jwtClaims := &middleware.JWTClaims{
		UserID:              "aad-user-456",
		Email:               "developer@company.com",
		Name:                "Developer User",
		Role:                "operator",
		Groups:              []string{"aad-developers", "aad-platform"},
		KubernetesUser:      groupResult.KubernetesUser,
		KubernetesGroups:    groupResult.KubernetesGroups,
		DefaultNamespace:    groupResult.DefaultNamespace,
		AllowedNamespaces:   groupResult.AllowedNamespaces,
		ClusterAccess:       groupResult.ClusterAccess,
		ClaimsVersion:       2,
		LastPermissionCheck: time.Now(),
	}

	// Step 3: Generate and validate JWT token
	tokenPair, err := suite.jwtService.GenerateTokenWithClaims(jwtClaims)
	require.NoError(t, err)

	validatedClaims, err := suite.jwtService.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)

	assert.Equal(t, "operator", validatedClaims.Role)
	assert.False(t, validatedClaims.ClusterAccess)
	assert.Len(t, validatedClaims.AllowedNamespaces, 3) // default, kube-system, kubechat
}

// TestLegacyTokenMigration tests legacy token migration
func (suite *JWTRBACIntegrationTestSuite) TestLegacyTokenMigration() {
	t := suite.T()

	// Create legacy claims (version 1)
	legacyClaims := &middleware.JWTClaims{
		UserID:        "legacy-user",
		Email:         "legacy@company.com",
		Name:          "Legacy User",
		Role:          "user",
		Groups:        []string{"legacy-group"},
		ClaimsVersion: 1,
	}

	// Generate token with legacy claims
	tokenPair, err := suite.jwtService.GenerateTokenWithClaims(legacyClaims)
	require.NoError(t, err)

	// Validate token (should trigger migration)
	validatedClaims, err := suite.jwtService.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)

	// Verify migration occurred
	assert.Equal(t, 2, validatedClaims.ClaimsVersion)
	assert.Equal(t, "legacy@company.com", validatedClaims.KubernetesUser)
	assert.Contains(t, validatedClaims.KubernetesGroups, "system:authenticated")
	assert.Contains(t, validatedClaims.KubernetesGroups, "legacy-group")
	assert.Equal(t, "default", validatedClaims.DefaultNamespace)
	assert.False(t, validatedClaims.ClusterAccess)
}

// TestSessionPersistence tests session persistence in Redis
func (suite *JWTRBACIntegrationTestSuite) TestSessionPersistence() {
	t := suite.T()
	ctx := context.Background()

	// Create enhanced claims
	claims := &middleware.JWTClaims{
		UserID:              "session-test-user",
		Email:               "session@company.com",
		Name:                "Session Test User",
		Role:                "admin",
		KubernetesUser:      "session@company.com",
		KubernetesGroups:    []string{"system:masters"},
		DefaultNamespace:    "default",
		AllowedNamespaces:   []string{"*"},
		ClusterAccess:       true,
		ClaimsVersion:       2,
		LastPermissionCheck: time.Now(),
	}

	// Generate token
	tokenPair, err := suite.jwtService.GenerateTokenWithClaims(claims)
	require.NoError(t, err)

	// Verify session was stored in Redis
	sessionKey := "kubechat:session:" + claims.SessionID
	sessionData, err := suite.redisClient.Get(ctx, sessionKey).Result()
	require.NoError(t, err)

	// Parse session data
	var session map[string]interface{}
	err = json.Unmarshal([]byte(sessionData), &session)
	require.NoError(t, err)

	assert.Equal(t, claims.UserID, session["user_id"])
	assert.Equal(t, claims.KubernetesUser, session["kubernetes_user"])
	assert.Equal(t, claims.ClusterAccess, session["cluster_access"])
	assert.Equal(t, float64(2), session["claims_version"])
}

// TestGroupMappingVariations tests different group mapping scenarios
func (suite *JWTRBACIntegrationTestSuite) TestGroupMappingVariations() {
	t := suite.T()

	testCases := []struct {
		name         string
		provider     string
		oidcClaims   map[string]interface{}
		expectedRole string
		clusterAccess bool
	}{
		{
			name:     "Okta Admin",
			provider: "okta",
			oidcClaims: map[string]interface{}{
				"sub":    "okta-admin",
				"email":  "admin@company.com",
				"groups": []interface{}{"okta-k8s-admins"},
			},
			expectedRole:  "admin",
			clusterAccess: true,
		},
		{
			name:     "Azure Developer",
			provider: "azure",
			oidcClaims: map[string]interface{}{
				"sub":    "azure-dev",
				"email":  "dev@company.com",
				"groups": []interface{}{"aad-developers"},
			},
			expectedRole:  "operator",
			clusterAccess: false,
		},
		{
			name:     "Google Viewer",
			provider: "google",
			oidcClaims: map[string]interface{}{
				"sub":    "google-viewer",
				"email":  "viewer@company.com",
				"groups": []interface{}{"google-users@company.com"},
			},
			expectedRole:  "viewer",
			clusterAccess: false,
		},
		{
			name:     "Auth0 User",
			provider: "auth0",
			oidcClaims: map[string]interface{}{
				"sub":   "auth0-user",
				"email": "user@company.com",
				"https://kubechat.com/groups": []interface{}{"auth0-users"},
			},
			expectedRole:  "viewer",
			clusterAccess: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Map groups
			groupResult, err := suite.groupMapper.MapGroups(tc.provider, tc.oidcClaims)
			require.NoError(t, err)

			// Determine role based on groups (simplified logic)
			var role string
			for _, group := range groupResult.KubernetesGroups {
				if group == "system:masters" {
					role = "admin"
					break
				} else if group == "kubechat:operators" {
					role = "operator"
				} else if group == "kubechat:viewers" && role == "" {
					role = "viewer"
				}
			}
			if role == "" {
				role = "user"
			}

			assert.Equal(t, tc.expectedRole, role)
			assert.Equal(t, tc.clusterAccess, groupResult.ClusterAccess)
		})
	}
}

// TestPerformanceUnderLoad tests performance under simulated load
func (suite *JWTRBACIntegrationTestSuite) TestPerformanceUnderLoad() {
	t := suite.T()

	const numTokens = 100
	const concurrency = 10

	// Create a channel to collect results
	results := make(chan time.Duration, numTokens)
	semaphore := make(chan struct{}, concurrency)

	start := time.Now()

	// Generate tokens concurrently
	for i := 0; i < numTokens; i++ {
		go func(index int) {
			semaphore <- struct{}{} // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			tokenStart := time.Now()

			claims := &middleware.JWTClaims{
				UserID:              fmt.Sprintf("perf-user-%d", index),
				Email:               fmt.Sprintf("perf%d@company.com", index),
				Name:                fmt.Sprintf("Performance User %d", index),
				Role:                "user",
				KubernetesUser:      fmt.Sprintf("perf%d@company.com", index),
				KubernetesGroups:    []string{"system:authenticated"},
				DefaultNamespace:    "default",
				AllowedNamespaces:   []string{"default"},
				ClusterAccess:       false,
				ClaimsVersion:       2,
				LastPermissionCheck: time.Now(),
			}

			_, err := suite.jwtService.GenerateTokenWithClaims(claims)
			require.NoError(t, err)

			results <- time.Since(tokenStart)
		}(i)
	}

	// Collect all results
	var totalDuration time.Duration
	var maxDuration time.Duration
	var minDuration time.Duration = time.Hour // Initialize to large value

	for i := 0; i < numTokens; i++ {
		duration := <-results
		totalDuration += duration
		if duration > maxDuration {
			maxDuration = duration
		}
		if duration < minDuration {
			minDuration = duration
		}
	}

	totalTime := time.Since(start)
	averageDuration := totalDuration / numTokens

	t.Logf("Performance Results:")
	t.Logf("  Total time: %v", totalTime)
	t.Logf("  Average token generation: %v", averageDuration)
	t.Logf("  Max token generation: %v", maxDuration)
	t.Logf("  Min token generation: %v", minDuration)
	t.Logf("  Tokens per second: %.2f", float64(numTokens)/totalTime.Seconds())

	// Assert performance targets
	assert.Less(t, averageDuration, 200*time.Millisecond, "Average token generation should be under 200ms")
	assert.Less(t, maxDuration, 500*time.Millisecond, "Max token generation should be under 500ms")
	assert.Greater(t, float64(numTokens)/totalTime.Seconds(), 10.0, "Should generate at least 10 tokens per second")
}

// TestRedisFailureRecovery tests behavior when Redis is unavailable
func (suite *JWTRBACIntegrationTestSuite) TestRedisFailureRecovery() {
	t := suite.T()

	// Create JWT service without Redis
	config := middleware.JWTConfig{
		TokenDuration:   time.Hour,
		RefreshDuration: 24 * time.Hour,
		Issuer:          "kubechat-no-redis-test",
	}

	jwtServiceNoRedis, err := middleware.NewJWTService(config)
	require.NoError(t, err)

	// Test token generation still works without Redis
	claims := &middleware.JWTClaims{
		UserID:              "no-redis-user",
		Email:               "noredis@company.com",
		Name:                "No Redis User",
		Role:                "user",
		KubernetesUser:      "noredis@company.com",
		KubernetesGroups:    []string{"system:authenticated"},
		DefaultNamespace:    "default",
		ClusterAccess:       false,
		ClaimsVersion:       2,
		LastPermissionCheck: time.Now(),
	}

	tokenPair, err := jwtServiceNoRedis.GenerateTokenWithClaims(claims)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenPair.AccessToken)

	// Token validation should work (but won't check Redis session)
	validatedClaims, err := jwtServiceNoRedis.ValidateToken(tokenPair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claims.UserID, validatedClaims.UserID)
}

// Run the integration test suite
func TestJWTRBACIntegrationSuite(t *testing.T) {
	suite.Run(t, new(JWTRBACIntegrationTestSuite))
}