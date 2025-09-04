// Package middleware provides JWT token management for secure authentication
package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/net/context"
)

// JWTClaims represents the claims stored in JWT tokens with enhanced RBAC support
type JWTClaims struct {
	// Existing fields (backward compatibility)
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	SessionID string    `json:"session_id"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	
	// Enhanced RBAC fields
	Role                string    `json:"role"`                    // Required KubeChat role
	Groups              []string  `json:"groups"`                  // Required OIDC groups
	
	// NEW: Kubernetes-specific RBAC fields
	KubernetesUser      string    `json:"kubernetes_user"`         // K8s user for impersonation
	KubernetesGroups    []string  `json:"kubernetes_groups"`       // K8s groups for RBAC
	DefaultNamespace    string    `json:"default_namespace"`       // User's default namespace
	AllowedNamespaces   []string  `json:"allowed_namespaces"`      // Accessible namespaces
	ClusterAccess       bool      `json:"cluster_access"`          // Cluster-level permissions
	ServiceAccountName  string    `json:"service_account,omitempty"` // For service account auth
	
	// Claims metadata
	ClaimsVersion       int       `json:"claims_version"`          // For backward compatibility
	LastPermissionCheck time.Time `json:"last_permission_check"`  // Claims freshness
	
	// MFA fields (Story 2.4)
	MFACompleted        bool      `json:"mfa_completed"`           // MFA validation status
	MFAMethod          string    `json:"mfa_method,omitempty"`    // TOTP, SMS, Push, etc.
	MFATimestamp       time.Time `json:"mfa_timestamp"`           // When MFA was completed
	MFAValidityDuration time.Duration `json:"mfa_validity"`        // How long MFA is valid
	RequiresMFAStepUp  bool      `json:"requires_mfa_stepup"`     // High-risk operation flag
	
	jwt.RegisteredClaims
}

// JWTServiceInterface defines the contract for JWT token operations
type JWTServiceInterface interface {
	GenerateToken(userID, email, name string) (*TokenPair, error)
	GenerateTokenWithClaims(claims *JWTClaims) (*TokenPair, error)
	GenerateTokenWithNamespaceValidation(claims *JWTClaims, validateNamespaces bool) (*TokenPair, error)
	ValidateToken(tokenString string) (*JWTClaims, error)
	ValidateTokenWithRefresh(tokenString string, refreshPermissions bool) (*JWTClaims, error)
	RefreshToken(refreshToken string) (*TokenPair, error)
	RefreshTokenWithNamespaceValidation(refreshToken string, validateNamespaces bool) (*TokenPair, error)
	BlacklistToken(sessionID string) error
	CleanupExpiredSessions() error
	GetPublicKey() *rsa.PublicKey
	GetPublicKeyPEM() (string, error)
	MigrateLegacyClaims(claims *JWTClaims) *JWTClaims
	SetNamespaceValidator(validator *NamespaceValidator)
	
	// Enhanced Session Lifecycle Management (Story 2.3 Task 1)
	UpdateSessionActivity(sessionID string) error
	GetSessionInfo(sessionID string) (*SessionInfo, error)
	GetAllActiveSessions(userID string) ([]*SessionInfo, error)
	TerminateSession(sessionID string, reason string) error
	TerminateAllUserSessions(userID string, reason string) error
	SetSessionTimeoutPolicies(idle, absolute time.Duration) error
	GetSessionMetrics() *SessionMetrics
	
	// MFA Session State Management (Story 2.4 Task 4)
	UpdateMFAStatus(sessionID string, mfaCompleted bool, method string, validity time.Duration) error
	GetMFAStatus(sessionID string) (*MFASessionStatus, error)
	RequiresMFAStepUp(sessionID string, operation string) (bool, error)
	SetMFAStepUpRequirement(sessionID string, required bool, operation string) error
	ValidateMFAForOperation(sessionID string, operation string) (bool, error)
	InvalidateMFAForSessions(userID string) error
}

// SessionInfo represents comprehensive session information
type SessionInfo struct {
	SessionID           string    `json:"session_id"`
	UserID              string    `json:"user_id"`
	Email               string    `json:"email"`
	Name                string    `json:"name"`
	KubernetesUser      string    `json:"kubernetes_user"`
	KubernetesGroups    []string  `json:"kubernetes_groups"`
	CreatedAt           time.Time `json:"created_at"`
	LastActivity        time.Time `json:"last_activity"`
	ExpiresAt           time.Time `json:"expires_at"`
	RefreshExpiresAt    time.Time `json:"refresh_expires_at"`
	Active              bool      `json:"active"`
	IPAddress           string    `json:"ip_address,omitempty"`
	UserAgent           string    `json:"user_agent,omitempty"`
	DeviceFingerprint   string    `json:"device_fingerprint,omitempty"`
	SessionType         string    `json:"session_type"` // "web", "api", "mobile"
	IdleTimeout         time.Duration `json:"idle_timeout"`
	AbsoluteTimeout     time.Duration `json:"absolute_timeout"`
	TerminationReason   string    `json:"termination_reason,omitempty"`
	ConcurrentSessions  int       `json:"concurrent_sessions"`
	// MFA fields (Story 2.4)
	MFACompleted        bool      `json:"mfa_completed"`
	MFAMethod           string    `json:"mfa_method,omitempty"`
	MFATimestamp        time.Time `json:"mfa_timestamp"`
	MFAExpiresAt        time.Time `json:"mfa_expires_at"`
	RequiresMFAStepUp   bool      `json:"requires_mfa_stepup"`
}

// SessionMetrics provides session-related metrics
type SessionMetrics struct {
	TotalActiveSessions     int64         `json:"total_active_sessions"`
	TotalExpiredSessions    int64         `json:"total_expired_sessions"`
	TotalTerminatedSessions int64         `json:"total_terminated_sessions"`
	AverageSessionDuration  time.Duration `json:"average_session_duration"`
	ActiveSessionsByType    map[string]int64 `json:"active_sessions_by_type"`
	SessionTimeouts         int64         `json:"session_timeouts"`
	ConcurrentSessionLimits int64         `json:"concurrent_session_limits"`
}

// SessionTimeoutPolicy defines timeout policies for sessions
type SessionTimeoutPolicy struct {
	IdleTimeout     time.Duration `json:"idle_timeout"`     // Default 4 hours
	AbsoluteTimeout time.Duration `json:"absolute_timeout"` // Default 24 hours
	EnableIdleCheck bool          `json:"enable_idle_check"`
}

// MFASessionStatus represents the MFA status for a session (Story 2.4)
type MFASessionStatus struct {
	SessionID           string            `json:"session_id"`
	UserID              string            `json:"user_id"`
	MFACompleted        bool              `json:"mfa_completed"`
	MFAMethod           string            `json:"mfa_method,omitempty"`
	MFATimestamp        time.Time         `json:"mfa_timestamp"`
	MFAValidityDuration time.Duration     `json:"mfa_validity_duration"`
	MFAExpiresAt        time.Time         `json:"mfa_expires_at"`
	RequiresMFAStepUp   bool              `json:"requires_mfa_stepup"`
	StepUpOperations    []string          `json:"stepup_operations,omitempty"`
	LastMFAValidation   time.Time         `json:"last_mfa_validation"`
	MFAFailureCount     int               `json:"mfa_failure_count"`
	MFALockedUntil      time.Time         `json:"mfa_locked_until,omitempty"`
}

// JWTService handles JWT token generation, validation, and management
type JWTService struct {
	privateKey         *rsa.PrivateKey
	publicKey          *rsa.PublicKey
	redisClient        redis.UniversalClient
	tokenDuration      time.Duration
	refreshDuration    time.Duration
	issuer             string
	namespaceValidator *NamespaceValidator
	
	// Enhanced session management (Story 2.3 Task 1)
	timeoutPolicy      *SessionTimeoutPolicy
	concurrentLimit    int
	sessionMetrics     *SessionMetrics
	
	// MFA session management (Story 2.4 Task 4)
	mfaHandler         *MFAHandler
	defaultMFAValidity time.Duration
}

// JWTConfig holds configuration for JWT service
type JWTConfig struct {
	PrivateKeyPEM        string        `json:"private_key_pem"`
	RedisAddr            string        `json:"redis_addr"`         // Redis server address (single instance)
	RedisCluster         []string      `json:"redis_cluster"`      // Redis cluster addresses
	RedisPassword        string        `json:"redis_password"`     // Redis password
	RedisDB              int           `json:"redis_db"`           // Redis database number
	TokenDuration        time.Duration `json:"token_duration"`     // Access token lifetime
	RefreshDuration      time.Duration `json:"refresh_duration"`   // Refresh token lifetime
	Issuer               string        `json:"issuer"`             // JWT issuer
	PoolSize             int           `json:"pool_size"`          // Redis connection pool size
	MinIdleConns         int           `json:"min_idle_conns"`     // Minimum idle connections
	MaxRetries           int           `json:"max_retries"`        // Maximum retry attempts
	RetryDelay           time.Duration `json:"retry_delay"`        // Delay between retries
	DialTimeout          time.Duration `json:"dial_timeout"`       // Connection dial timeout
	ReadTimeout          time.Duration `json:"read_timeout"`       // Read operation timeout
	WriteTimeout         time.Duration `json:"write_timeout"`      // Write operation timeout
	EnableCircuitBreaker bool          `json:"enable_circuit_breaker"` // Enable circuit breaker for Redis failures
	
	// Enhanced Session Management (Story 2.3 Task 1)
	IdleTimeout         time.Duration `json:"idle_timeout"`         // Session idle timeout (default 4 hours)
	AbsoluteTimeout     time.Duration `json:"absolute_timeout"`     // Session absolute timeout (default 24 hours)
	ConcurrentLimit     int           `json:"concurrent_limit"`     // Max concurrent sessions per user (default 5)
	EnableIdleCheck     bool          `json:"enable_idle_check"`    // Enable idle timeout checking (default true)
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	TokenType    string    `json:"token_type"`
}

// TokenValidationError represents JWT validation errors
type TokenValidationError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *TokenValidationError) Error() string {
	return fmt.Sprintf("Token validation error [%s]: %s", e.Code, e.Message)
}

// NewJWTService creates a new JWT service instance
func NewJWTService(config JWTConfig) (*JWTService, error) {
	// Parse private key
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	if config.PrivateKeyPEM != "" {
		// Use provided private key
		key, err := parsePrivateKey(config.PrivateKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		privateKey = key
		publicKey = &key.PublicKey
	} else {
		// Generate new key pair
		key, err := generateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key pair: %w", err)
		}
		privateKey = key
		publicKey = &key.PublicKey
	}

	// Initialize Redis client with enhanced configuration
	var redisAddrs []string
	if len(config.RedisCluster) > 0 {
		// Use cluster addresses
		redisAddrs = config.RedisCluster
	} else if config.RedisAddr != "" {
		// Use single instance
		redisAddrs = []string{config.RedisAddr}
	} else {
		// Default fallback
		redisAddrs = []string{"localhost:6379"}
	}

	// Set performance defaults
	poolSize := config.PoolSize
	if poolSize == 0 {
		poolSize = 10 // Default pool size
	}
	
	minIdleConns := config.MinIdleConns
	if minIdleConns == 0 {
		minIdleConns = 2 // Default minimum idle connections
	}

	maxRetries := config.MaxRetries
	if maxRetries == 0 {
		maxRetries = 3 // Default max retries
	}

	dialTimeout := config.DialTimeout
	if dialTimeout == 0 {
		dialTimeout = 5 * time.Second // Default dial timeout
	}

	readTimeout := config.ReadTimeout
	if readTimeout == 0 {
		readTimeout = 3 * time.Second // Default read timeout
	}

	writeTimeout := config.WriteTimeout
	if writeTimeout == 0 {
		writeTimeout = 3 * time.Second // Default write timeout
	}

	redisClient := redis.NewUniversalClient(&redis.UniversalOptions{
		Addrs:        redisAddrs,
		Password:     config.RedisPassword,
		DB:           config.RedisDB,
		PoolSize:     poolSize,
		MinIdleConns: minIdleConns,
		MaxRetries:  maxRetries,
		DialTimeout: dialTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	})

	// Test Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	// Set default durations
	tokenDuration := config.TokenDuration
	if tokenDuration == 0 {
		tokenDuration = 8 * time.Hour // Default 8 hours as per requirements
	}

	refreshDuration := config.RefreshDuration
	if refreshDuration == 0 {
		refreshDuration = 24 * time.Hour * 7 // Default 7 days
	}

	issuer := config.Issuer
	if issuer == "" {
		issuer = "kubechat-api"
	}

	// Enhanced Session Management (Story 2.3 Task 1)
	idleTimeout := config.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = 4 * time.Hour // Default 4 hours as per AC3
	}

	absoluteTimeout := config.AbsoluteTimeout
	if absoluteTimeout == 0 {
		absoluteTimeout = 24 * time.Hour // Default 24 hours
	}

	concurrentLimit := config.ConcurrentLimit
	if concurrentLimit == 0 {
		concurrentLimit = 5 // Default 5 concurrent sessions per user
	}

	timeoutPolicy := &SessionTimeoutPolicy{
		IdleTimeout:     idleTimeout,
		AbsoluteTimeout: absoluteTimeout,
		EnableIdleCheck: config.EnableIdleCheck,
	}

	sessionMetrics := &SessionMetrics{
		ActiveSessionsByType: make(map[string]int64),
	}

	return &JWTService{
		privateKey:         privateKey,
		publicKey:          publicKey,
		redisClient:        redisClient,
		tokenDuration:      tokenDuration,
		refreshDuration:    refreshDuration,
		issuer:             issuer,
		timeoutPolicy:      timeoutPolicy,
		concurrentLimit:    concurrentLimit,
		sessionMetrics:     sessionMetrics,
		defaultMFAValidity: 4 * time.Hour, // Default MFA validity: 4 hours
	}, nil
}

// GenerateToken creates a new JWT token for the user with basic claims
func (j *JWTService) GenerateToken(userID, email, name string) (*TokenPair, error) {
	if userID == "" {
		return nil, &TokenValidationError{
			Code:    "INVALID_USER_ID",
			Message: "User ID is required for token generation",
		}
	}

	sessionID := uuid.New().String()
	now := time.Now()
	expiresAt := now.Add(j.tokenDuration)

	// Create basic JWT claims (backward compatibility - version 1)
	claims := &JWTClaims{
		UserID:              userID,
		Email:               email,
		Name:                name,
		SessionID:           sessionID,
		IssuedAt:            now,
		ExpiresAt:           expiresAt,
		ClaimsVersion:       1, // Backward compatibility version
		LastPermissionCheck: now,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   userID,
			ID:        sessionID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	return j.GenerateTokenWithClaims(claims)
}

// GenerateTokenWithClaims creates a new JWT token with provided claims
func (j *JWTService) GenerateTokenWithClaims(claims *JWTClaims) (*TokenPair, error) {
	if claims.UserID == "" {
		return nil, &TokenValidationError{
			Code:    "INVALID_USER_ID",
			Message: "User ID is required for token generation",
		}
	}

	// Set default session ID if not provided
	if claims.SessionID == "" {
		claims.SessionID = uuid.New().String()
	}
	
	// Set default timestamps if not provided
	now := time.Now()
	if claims.IssuedAt.IsZero() {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt.IsZero() {
		claims.ExpiresAt = now.Add(j.tokenDuration)
	}
	if claims.LastPermissionCheck.IsZero() {
		claims.LastPermissionCheck = now
	}
	
	// Set default claims version if not provided
	if claims.ClaimsVersion == 0 {
		claims.ClaimsVersion = 2 // Enhanced version with RBAC fields
	}

	// Set registered claims
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    j.issuer,
		Subject:   claims.UserID,
		ID:        claims.SessionID,
		IssuedAt:  jwt.NewNumericDate(claims.IssuedAt),
		ExpiresAt: jwt.NewNumericDate(claims.ExpiresAt),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	accessToken, err := token.SignedString(j.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	// Generate refresh token
	refreshToken := uuid.New().String()
	refreshExpiresAt := claims.ExpiresAt.Add(j.refreshDuration - j.tokenDuration)

	// Store enhanced session in Redis with all claims data and session management info
	sessionData := map[string]interface{}{
		"user_id":                claims.UserID,
		"email":                  claims.Email,
		"name":                   claims.Name,
		"session_id":             claims.SessionID,
		"role":                   claims.Role,
		"groups":                 claims.Groups,
		"kubernetes_user":        claims.KubernetesUser,
		"kubernetes_groups":      claims.KubernetesGroups,
		"default_namespace":      claims.DefaultNamespace,
		"allowed_namespaces":     claims.AllowedNamespaces,
		"cluster_access":         claims.ClusterAccess,
		"service_account":        claims.ServiceAccountName,
		"claims_version":         claims.ClaimsVersion,
		"last_permission_check":  claims.LastPermissionCheck.Unix(),
		"refresh_token":          refreshToken,
		"created_at":             claims.IssuedAt.Unix(),
		"expires_at":             claims.ExpiresAt.Unix(),
		"refresh_expires_at":     refreshExpiresAt.Unix(),
		"active":                 true,
		
		// Enhanced Session Management (Story 2.3 Task 1)
		"last_activity":          claims.IssuedAt.Unix(),
		"session_type":           "api", // Default type
		"idle_timeout":           j.timeoutPolicy.IdleTimeout.Seconds(),
		"absolute_timeout":       j.timeoutPolicy.AbsoluteTimeout.Seconds(),
		"device_fingerprint":     "", // To be set by middleware
		"ip_address":             "", // To be set by middleware
		"user_agent":             "", // To be set by middleware
		"concurrent_sessions":    0,  // To be updated by session tracking
		"termination_reason":     "",
		
		// MFA fields (Story 2.4 Task 4)
		"mfa_completed":          claims.MFACompleted,
		"mfa_method":             claims.MFAMethod,
		"mfa_timestamp":          claims.MFATimestamp.Unix(),
		"mfa_expires_at":         claims.MFATimestamp.Add(claims.MFAValidityDuration).Unix(),
		"mfa_validity_duration":  claims.MFAValidityDuration.Seconds(),
		"requires_mfa_stepup":    claims.RequiresMFAStepUp,
		"stepup_operations":      []string{}, // Empty initially
		"last_mfa_validation":    claims.MFATimestamp.Unix(),
		"mfa_failure_count":      0,  // Reset on new session
		"mfa_locked_until":       time.Time{}.Unix(), // Not locked initially
	}

	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal session data: %w", err)
	}

	// Store session data only if Redis is available
	if j.redisClient != nil {
		ctx := context.Background()
		
		// Store session data with expiration
		if err := j.redisClient.Set(ctx, j.sessionKey(claims.SessionID), sessionJSON, j.refreshDuration).Err(); err != nil {
			return nil, fmt.Errorf("failed to store session in Redis: %w", err)
		}

		// Store refresh token mapping
		if err := j.redisClient.Set(ctx, j.refreshKey(refreshToken), claims.SessionID, j.refreshDuration).Err(); err != nil {
			return nil, fmt.Errorf("failed to store refresh token in Redis: %w", err)
		}
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    claims.ExpiresAt,
		TokenType:    "Bearer",
	}, nil
}

// ValidateToken validates and parses a JWT token
func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, &TokenValidationError{
				Code:    "INVALID_SIGNING_METHOD",
				Message: fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]),
			}
		}
		return j.publicKey, nil
	})

	if err != nil {
		return nil, &TokenValidationError{
			Code:    "TOKEN_PARSE_ERROR",
			Message: "Failed to parse token",
		}
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, &TokenValidationError{
			Code:    "INVALID_TOKEN",
			Message: "Token is invalid",
		}
	}

	// Handle backward compatibility for legacy claims (version 1 or unversioned)
	if claims.ClaimsVersion == 0 || claims.ClaimsVersion == 1 {
		claims = j.MigrateLegacyClaims(claims)
	}

	// Check if session is still active in Redis (if available)
	if j.redisClient != nil {
		ctx := context.Background()
		sessionData, err := j.redisClient.Get(ctx, j.sessionKey(claims.SessionID)).Result()
		if err != nil {
			if err == redis.Nil {
				return nil, &TokenValidationError{
					Code:    "SESSION_NOT_FOUND",
					Message: "Session not found or expired",
				}
			}
			return nil, fmt.Errorf("failed to check session in Redis: %w", err)
		}

		// Parse session data to verify it's active
		var session map[string]interface{}
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			return nil, fmt.Errorf("failed to parse session data: %w", err)
		}
		
		if active, ok := session["active"].(bool); !ok || !active {
			return nil, &TokenValidationError{
				Code:    "SESSION_INACTIVE",
				Message: "Session is no longer active",
			}
		}
	}

	return claims, nil
}

// RefreshToken creates a new token pair using a refresh token
func (j *JWTService) RefreshToken(refreshToken string) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, &TokenValidationError{
			Code:    "INVALID_REFRESH_TOKEN",
			Message: "Refresh token cannot be empty",
		}
	}

	if j.redisClient == nil {
		return nil, &TokenValidationError{
			Code:    "SERVICE_UNAVAILABLE",
			Message: "Redis client not available for refresh tokens",
		}
	}

	ctx := context.Background()

	// Get session ID from refresh token
	sessionID, err := j.redisClient.Get(ctx, j.refreshKey(refreshToken)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, &TokenValidationError{
				Code:    "INVALID_REFRESH_TOKEN",
				Message: "Refresh token not found or expired",
			}
		}
		return nil, fmt.Errorf("failed to lookup refresh token: %w", err)
	}

	// Get session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, &TokenValidationError{
				Code:    "SESSION_NOT_FOUND",
				Message: "Session not found or expired",
			}
		}
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Extract user information
	userID, _ := session["user_id"].(string)
	email, _ := session["email"].(string)
	name, _ := session["name"].(string)

	if userID == "" {
		return nil, &TokenValidationError{
			Code:    "INVALID_SESSION",
			Message: "Invalid session data",
		}
	}

	// Invalidate old refresh token
	if err := j.redisClient.Del(ctx, j.refreshKey(refreshToken)).Err(); err != nil {
		return nil, fmt.Errorf("failed to invalidate old refresh token: %w", err)
	}

	// Generate new token pair
	return j.GenerateToken(userID, email, name)
}

// BlacklistToken adds a token to the blacklist
func (j *JWTService) BlacklistToken(sessionID string) error {
	if j.redisClient == nil {
		return fmt.Errorf("Redis client not available for blacklisting tokens")
	}

	ctx := context.Background()

	// Get session data to find refresh token
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil && err != redis.Nil {
		return fmt.Errorf("failed to get session data: %w", err)
	}

	// Mark session as inactive
	if err == nil {
		var session map[string]interface{}
		if err := json.Unmarshal([]byte(sessionData), &session); err == nil {
			session["active"] = false
			updatedData, _ := json.Marshal(session)
			j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedData, time.Hour) // Keep for audit

			// Remove refresh token if it exists
			if refreshToken, ok := session["refresh_token"].(string); ok {
				j.redisClient.Del(ctx, j.refreshKey(refreshToken))
			}
		}
	}

	return nil
}

// CleanupExpiredSessions removes expired sessions from Redis
func (j *JWTService) CleanupExpiredSessions() error {
	if j.redisClient == nil {
		return fmt.Errorf("Redis client not available for session cleanup")
	}

	ctx := context.Background()

	// This would typically be run as a background job
	// For now, we rely on Redis TTL for cleanup
	
	// Get all session keys
	keys, err := j.redisClient.Keys(ctx, "kubechat:session:*").Result()
	if err != nil {
		return fmt.Errorf("failed to get session keys: %w", err)
	}

	now := time.Now().Unix()
	
	for _, key := range keys {
		sessionData, err := j.redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var session map[string]interface{}
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			continue
		}

		if expiresAt, ok := session["expires_at"].(float64); ok {
			if int64(expiresAt) < now {
				j.redisClient.Del(ctx, key)
				
				// Also remove refresh token
				if refreshToken, ok := session["refresh_token"].(string); ok {
					j.redisClient.Del(ctx, j.refreshKey(refreshToken))
				}
			}
		}
	}

	return nil
}

// GetPublicKey returns the RSA public key for token verification
func (j *JWTService) GetPublicKey() *rsa.PublicKey {
	return j.publicKey
}

// GetPublicKeyPEM returns the public key in PEM format
func (j *JWTService) GetPublicKeyPEM() (string, error) {
	publicKeyDER, err := x509.MarshalPKIXPublicKey(j.publicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDER,
	})

	return string(publicKeyPEM), nil
}

// MigrateLegacyClaims upgrades v1 claims to v2 with default RBAC values
func (j *JWTService) MigrateLegacyClaims(claims *JWTClaims) *JWTClaims {
	// Create upgraded claims with v2 structure
	upgradedClaims := &JWTClaims{
		// Copy existing fields
		UserID:    claims.UserID,
		Email:     claims.Email,
		Name:      claims.Name,
		SessionID: claims.SessionID,
		IssuedAt:  claims.IssuedAt,
		ExpiresAt: claims.ExpiresAt,
		Role:      claims.Role,
		Groups:    claims.Groups,

		// Set enhanced RBAC fields with safe defaults
		KubernetesUser:      claims.Email, // Use email as default K8s user
		KubernetesGroups:    []string{"system:authenticated"}, // Default authenticated group
		DefaultNamespace:    "default", // Safe default namespace
		AllowedNamespaces:   []string{}, // Empty - requires explicit validation
		ClusterAccess:       false, // No cluster access by default
		ServiceAccountName:  "", // No service account by default

		// Claims metadata
		ClaimsVersion:       2, // Upgrade to version 2
		LastPermissionCheck: time.Now(), // Mark as needing validation

		RegisteredClaims: claims.RegisteredClaims,
	}

	// Map legacy groups to Kubernetes groups if available
	if len(claims.Groups) > 0 {
		// Simple mapping: add claims groups to kubernetes groups
		upgradedClaims.KubernetesGroups = append(upgradedClaims.KubernetesGroups, claims.Groups...)
	}

	return upgradedClaims
}

// SetNamespaceValidator sets the namespace validator for the JWT service
func (j *JWTService) SetNamespaceValidator(validator *NamespaceValidator) {
	j.namespaceValidator = validator
}

// SetMFAHandler sets the MFA handler for the JWT service (Story 2.4 Task 4)
func (j *JWTService) SetMFAHandler(handler *MFAHandler) {
	j.mfaHandler = handler
}

// GenerateTokenWithNamespaceValidation creates a JWT token with optional namespace validation
func (j *JWTService) GenerateTokenWithNamespaceValidation(claims *JWTClaims, validateNamespaces bool) (*TokenPair, error) {
	if validateNamespaces && j.namespaceValidator != nil && claims.KubernetesUser != "" {
		// Validate namespace access during token generation
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		validationRequest := ValidationRequest{
			KubernetesUser:   claims.KubernetesUser,
			KubernetesGroups: claims.KubernetesGroups,
			RequestedNS:      claims.AllowedNamespaces, // If empty, will check all namespaces
		}
		
		result, err := j.namespaceValidator.ValidateNamespaceAccess(ctx, validationRequest)
		if err != nil {
			return nil, fmt.Errorf("namespace validation failed during token generation: %w", err)
		}
		
		// Update claims with validated namespace information
		claims.AllowedNamespaces = result.AllowedNamespaces
		claims.DefaultNamespace = result.DefaultNamespace
		claims.ClusterAccess = result.ClusterAccess
		claims.LastPermissionCheck = result.ValidationTime
	}
	
	return j.GenerateTokenWithClaims(claims)
}

// ValidateTokenWithRefresh validates a token and optionally refreshes permission information
func (j *JWTService) ValidateTokenWithRefresh(tokenString string, refreshPermissions bool) (*JWTClaims, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return nil, err
	}
	
	// Check if permissions need refreshing based on age
	if refreshPermissions && j.namespaceValidator != nil && claims.KubernetesUser != "" {
		permissionAge := time.Since(claims.LastPermissionCheck)
		
		// Refresh permissions if they're older than 5 minutes
		if permissionAge > 5*time.Minute {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			
			validationRequest := ValidationRequest{
				KubernetesUser:   claims.KubernetesUser,
				KubernetesGroups: claims.KubernetesGroups,
			}
			
			result, err := j.namespaceValidator.ValidateNamespaceAccess(ctx, validationRequest)
			if err != nil {
				// Log error but don't fail validation - use cached permissions
				fmt.Printf("Warning: Failed to refresh permissions for user %s: %v\n", claims.KubernetesUser, err)
				return claims, nil
			}
			
			// Update claims with refreshed namespace information
			claims.AllowedNamespaces = result.AllowedNamespaces
			claims.DefaultNamespace = result.DefaultNamespace
			claims.ClusterAccess = result.ClusterAccess
			claims.LastPermissionCheck = result.ValidationTime
			
			// Store updated claims in Redis session if available
			if j.redisClient != nil {
				j.updateSessionClaims(claims)
			}
		}
	}
	
	return claims, nil
}

// RefreshTokenWithNamespaceValidation refreshes a token with optional namespace validation
func (j *JWTService) RefreshTokenWithNamespaceValidation(refreshToken string, validateNamespaces bool) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, &TokenValidationError{
			Code:    "INVALID_REFRESH_TOKEN",
			Message: "Refresh token cannot be empty",
		}
	}

	if j.redisClient == nil {
		return nil, &TokenValidationError{
			Code:    "SERVICE_UNAVAILABLE",
			Message: "Redis client not available for refresh tokens",
		}
	}

	ctx := context.Background()

	// Get session ID from refresh token
	sessionID, err := j.redisClient.Get(ctx, j.refreshKey(refreshToken)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, &TokenValidationError{
				Code:    "INVALID_REFRESH_TOKEN",
				Message: "Refresh token not found or expired",
			}
		}
		return nil, fmt.Errorf("failed to lookup refresh token: %w", err)
	}

	// Get session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, &TokenValidationError{
				Code:    "SESSION_NOT_FOUND",
				Message: "Session not found or expired",
			}
		}
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Extract enhanced user information from session
	userID, _ := session["user_id"].(string)
	email, _ := session["email"].(string)
	name, _ := session["name"].(string)
	role, _ := session["role"].(string)
	kubernetesUser, _ := session["kubernetes_user"].(string)
	clusterAccess, _ := session["cluster_access"].(bool)
	claimsVersion, _ := session["claims_version"].(float64)
	
	// Handle potentially nil session values
	defaultNamespace := "default"
	serviceAccount := ""
	if val, ok := session["default_namespace"].(string); ok {
		defaultNamespace = val
	}
	if val, ok := session["service_account"].(string); ok {
		serviceAccount = val
	}

	// Extract groups and namespaces from session
	var groups []string
	var kubernetesGroups []string
	var allowedNamespaces []string
	
	if groupsInterface, ok := session["groups"].([]interface{}); ok {
		for _, g := range groupsInterface {
			if groupStr, ok := g.(string); ok {
				groups = append(groups, groupStr)
			}
		}
	}
	
	if k8sGroupsInterface, ok := session["kubernetes_groups"].([]interface{}); ok {
		for _, g := range k8sGroupsInterface {
			if groupStr, ok := g.(string); ok {
				kubernetesGroups = append(kubernetesGroups, groupStr)
			}
		}
	}
	
	if nsInterface, ok := session["allowed_namespaces"].([]interface{}); ok {
		for _, ns := range nsInterface {
			if nsStr, ok := ns.(string); ok {
				allowedNamespaces = append(allowedNamespaces, nsStr)
			}
		}
	}

	if userID == "" {
		return nil, &TokenValidationError{
			Code:    "INVALID_SESSION",
			Message: "Invalid session data",
		}
	}

	// Create enhanced JWT claims from session data
	now := time.Now()
	claims := &JWTClaims{
		UserID:              userID,
		Email:               email,
		Name:                name,
		SessionID:           sessionID,
		IssuedAt:            now,
		ExpiresAt:           now.Add(j.tokenDuration),
		Role:                role,
		Groups:              groups,
		KubernetesUser:      kubernetesUser,
		KubernetesGroups:    kubernetesGroups,
		DefaultNamespace:    defaultNamespace,
		AllowedNamespaces:   allowedNamespaces,
		ClusterAccess:       clusterAccess,
		ServiceAccountName:  serviceAccount,
		ClaimsVersion:       int(claimsVersion),
		LastPermissionCheck: now,
		
		// MFA fields (Story 2.4)
		MFACompleted:        getBoolFromSession(session, "mfa_completed"),
		MFAMethod:           getStringFromSession(session, "mfa_method"),
		MFATimestamp:        time.Unix(int64(getFloatFromSession(session, "mfa_timestamp")), 0),
		MFAValidityDuration: time.Duration(getFloatFromSession(session, "mfa_validity_duration")) * time.Second,
		RequiresMFAStepUp:   getBoolFromSession(session, "requires_mfa_stepup"),
	}

	// Invalidate old refresh token
	if err := j.redisClient.Del(ctx, j.refreshKey(refreshToken)).Err(); err != nil {
		return nil, fmt.Errorf("failed to invalidate old refresh token: %w", err)
	}

	// Generate new token pair with optional namespace validation
	return j.GenerateTokenWithNamespaceValidation(claims, validateNamespaces)
}

// updateSessionClaims updates the session data with new claims information
func (j *JWTService) updateSessionClaims(claims *JWTClaims) error {
	if j.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}
	
	ctx := context.Background()
	
	// Get existing session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(claims.SessionID)).Result()
	if err != nil {
		return fmt.Errorf("failed to get session data: %w", err)
	}
	
	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("failed to parse session data: %w", err)
	}
	
	// Update session with new claims data
	session["kubernetes_user"] = claims.KubernetesUser
	session["kubernetes_groups"] = claims.KubernetesGroups
	session["default_namespace"] = claims.DefaultNamespace
	session["allowed_namespaces"] = claims.AllowedNamespaces
	session["cluster_access"] = claims.ClusterAccess
	session["last_permission_check"] = claims.LastPermissionCheck.Unix()
	
	// Update MFA fields (Story 2.4)
	session["mfa_completed"] = claims.MFACompleted
	session["mfa_method"] = claims.MFAMethod
	session["mfa_timestamp"] = claims.MFATimestamp.Unix()
	session["mfa_expires_at"] = claims.MFATimestamp.Add(claims.MFAValidityDuration).Unix()
	session["mfa_validity_duration"] = claims.MFAValidityDuration.Seconds()
	session["requires_mfa_stepup"] = claims.RequiresMFAStepUp
	
	// Save updated session
	updatedSessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}
	
	return j.redisClient.Set(ctx, j.sessionKey(claims.SessionID), updatedSessionJSON, j.refreshDuration).Err()
}

// Helper functions

func (j *JWTService) sessionKey(sessionID string) string {
	return fmt.Sprintf("kubechat:session:%s", sessionID)
}

func (j *JWTService) refreshKey(refreshToken string) string {
	return fmt.Sprintf("kubechat:refresh:%s", refreshToken)
}

func parsePrivateKey(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		keyInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		key, ok = keyInterface.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}

	return key, nil
}

func generateKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// EncodePrivateKeyToPEM encodes an RSA private key to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) string {
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyDER,
	})
	return string(privateKeyPEM)
}

// GenerateSecretKey generates a base64-encoded secret key for HMAC
func GenerateSecretKey() (string, error) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// Enhanced Session Lifecycle Management Methods (Story 2.3 Task 1)

// UpdateSessionActivity updates the last activity timestamp for a session
func (j *JWTService) UpdateSessionActivity(sessionID string) error {
	if j.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	// Get existing session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("failed to parse session data: %w", err)
	}

	// Check if session is still active
	if active, ok := session["active"].(bool); !ok || !active {
		return fmt.Errorf("session is inactive: %s", sessionID)
	}

	// Check for idle timeout if enabled
	if j.timeoutPolicy.EnableIdleCheck {
		lastActivity, _ := session["last_activity"].(float64)
		idleTimeout, _ := session["idle_timeout"].(float64)
		
		if time.Since(time.Unix(int64(lastActivity), 0)) > time.Duration(idleTimeout)*time.Second {
			// Session has exceeded idle timeout - mark as inactive
			session["active"] = false
			session["termination_reason"] = "idle_timeout"
			
			updatedData, _ := json.Marshal(session)
			j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedData, time.Hour) // Keep for audit
			
			j.sessionMetrics.SessionTimeouts++
			return fmt.Errorf("session exceeded idle timeout: %s", sessionID)
		}
	}

	// Update last activity
	session["last_activity"] = time.Now().Unix()

	// Save updated session
	updatedSessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	return j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedSessionJSON, j.refreshDuration).Err()
}

// GetSessionInfo retrieves comprehensive session information
func (j *JWTService) GetSessionInfo(sessionID string) (*SessionInfo, error) {
	if j.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Extract Kubernetes groups
	var kubernetesGroups []string
	if k8sGroupsInterface, ok := session["kubernetes_groups"].([]interface{}); ok {
		for _, g := range k8sGroupsInterface {
			if groupStr, ok := g.(string); ok {
				kubernetesGroups = append(kubernetesGroups, groupStr)
			}
		}
	}

	sessionInfo := &SessionInfo{
		SessionID:         sessionID,
		UserID:            getStringFromSession(session, "user_id"),
		Email:             getStringFromSession(session, "email"),
		Name:              getStringFromSession(session, "name"),
		KubernetesUser:    getStringFromSession(session, "kubernetes_user"),
		KubernetesGroups:  kubernetesGroups,
		CreatedAt:         time.Unix(int64(getFloatFromSession(session, "created_at")), 0),
		LastActivity:      time.Unix(int64(getFloatFromSession(session, "last_activity")), 0),
		ExpiresAt:         time.Unix(int64(getFloatFromSession(session, "expires_at")), 0),
		RefreshExpiresAt:  time.Unix(int64(getFloatFromSession(session, "refresh_expires_at")), 0),
		Active:            getBoolFromSession(session, "active"),
		IPAddress:         getStringFromSession(session, "ip_address"),
		UserAgent:         getStringFromSession(session, "user_agent"),
		DeviceFingerprint: getStringFromSession(session, "device_fingerprint"),
		SessionType:       getStringFromSession(session, "session_type"),
		IdleTimeout:       time.Duration(getFloatFromSession(session, "idle_timeout")) * time.Second,
		AbsoluteTimeout:   time.Duration(getFloatFromSession(session, "absolute_timeout")) * time.Second,
		TerminationReason: getStringFromSession(session, "termination_reason"),
		ConcurrentSessions: int(getFloatFromSession(session, "concurrent_sessions")),
		// MFA fields (Story 2.4)
		MFACompleted:      getBoolFromSession(session, "mfa_completed"),
		MFAMethod:         getStringFromSession(session, "mfa_method"),
		MFATimestamp:      time.Unix(int64(getFloatFromSession(session, "mfa_timestamp")), 0),
		MFAExpiresAt:      time.Unix(int64(getFloatFromSession(session, "mfa_expires_at")), 0),
		RequiresMFAStepUp: getBoolFromSession(session, "requires_mfa_stepup"),
	}

	return sessionInfo, nil
}

// GetAllActiveSessions retrieves all active sessions for a user
func (j *JWTService) GetAllActiveSessions(userID string) ([]*SessionInfo, error) {
	if j.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	// Get all session keys
	keys, err := j.redisClient.Keys(ctx, "kubechat:session:*").Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get session keys: %w", err)
	}

	var sessions []*SessionInfo
	for _, key := range keys {
		sessionData, err := j.redisClient.Get(ctx, key).Result()
		if err != nil {
			continue // Skip sessions we can't read
		}

		var session map[string]interface{}
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			continue // Skip sessions we can't parse
		}

		// Filter by user ID and active status
		sessionUserID, _ := session["user_id"].(string)
		active, _ := session["active"].(bool)
		
		if sessionUserID == userID && active {
			sessionID := extractSessionIDFromKey(key)
			sessionInfo, err := j.GetSessionInfo(sessionID)
			if err == nil {
				sessions = append(sessions, sessionInfo)
			}
		}
	}

	return sessions, nil
}

// TerminateSession terminates a specific session with a reason
func (j *JWTService) TerminateSession(sessionID string, reason string) error {
	if j.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	// Get session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("failed to parse session data: %w", err)
	}

	// Mark session as inactive
	session["active"] = false
	session["termination_reason"] = reason
	session["terminated_at"] = time.Now().Unix()

	updatedData, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	// Keep session for audit trail (1 hour)
	if err := j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedData, time.Hour).Err(); err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	// Remove refresh token if it exists
	if refreshToken, ok := session["refresh_token"].(string); ok {
		j.redisClient.Del(ctx, j.refreshKey(refreshToken))
	}

	// Update metrics
	j.sessionMetrics.TotalTerminatedSessions++

	return nil
}

// TerminateAllUserSessions terminates all active sessions for a user
func (j *JWTService) TerminateAllUserSessions(userID string, reason string) error {
	sessions, err := j.GetAllActiveSessions(userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	for _, session := range sessions {
		if err := j.TerminateSession(session.SessionID, reason); err != nil {
			// Log error but continue with other sessions
			fmt.Printf("Warning: Failed to terminate session %s: %v\n", session.SessionID, err)
		}
	}

	return nil
}

// SetSessionTimeoutPolicies updates session timeout policies
func (j *JWTService) SetSessionTimeoutPolicies(idle, absolute time.Duration) error {
	if idle <= 0 || absolute <= 0 {
		return fmt.Errorf("timeout values must be positive")
	}

	j.timeoutPolicy.IdleTimeout = idle
	j.timeoutPolicy.AbsoluteTimeout = absolute
	j.timeoutPolicy.EnableIdleCheck = true

	return nil
}

// GetSessionMetrics returns current session metrics
func (j *JWTService) GetSessionMetrics() *SessionMetrics {
	if j.redisClient == nil {
		return j.sessionMetrics
	}

	// Update active session count from Redis
	ctx := context.Background()
	keys, err := j.redisClient.Keys(ctx, "kubechat:session:*").Result()
	if err != nil {
		return j.sessionMetrics
	}

	activeCount := int64(0)
	sessionTypes := make(map[string]int64)

	for _, key := range keys {
		sessionData, err := j.redisClient.Get(ctx, key).Result()
		if err != nil {
			continue
		}

		var session map[string]interface{}
		if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
			continue
		}

		if active, ok := session["active"].(bool); ok && active {
			activeCount++
			
			if sessionType, ok := session["session_type"].(string); ok {
				sessionTypes[sessionType]++
			}
		}
	}

	j.sessionMetrics.TotalActiveSessions = activeCount
	j.sessionMetrics.ActiveSessionsByType = sessionTypes

	return j.sessionMetrics
}

// Helper functions for session data extraction

func getStringFromSession(session map[string]interface{}, key string) string {
	if value, ok := session[key].(string); ok {
		return value
	}
	return ""
}

func getFloatFromSession(session map[string]interface{}, key string) float64 {
	if value, ok := session[key].(float64); ok {
		return value
	}
	return 0
}

func getBoolFromSession(session map[string]interface{}, key string) bool {
	if value, ok := session[key].(bool); ok {
		return value
	}
	return false
}

func extractSessionIDFromKey(key string) string {
	parts := strings.Split(key, ":")
	if len(parts) >= 3 {
		return parts[2]
	}
	return ""
}

// MFA Session State Management Methods (Story 2.4 Task 4)

// UpdateMFAStatus updates the MFA status for a session
func (j *JWTService) UpdateMFAStatus(sessionID string, mfaCompleted bool, method string, validity time.Duration) error {
	if j.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	// Get existing session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("failed to parse session data: %w", err)
	}

	// Check if session is still active
	if active, ok := session["active"].(bool); !ok || !active {
		return fmt.Errorf("session is inactive: %s", sessionID)
	}

	// Update MFA status
	now := time.Now()
	session["mfa_completed"] = mfaCompleted
	session["mfa_method"] = method
	session["mfa_timestamp"] = now.Unix()
	session["mfa_expires_at"] = now.Add(validity).Unix()
	session["mfa_validity_duration"] = validity.Seconds()
	session["requires_mfa_stepup"] = false // Reset step-up requirement

	// Save updated session
	updatedSessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	return j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedSessionJSON, j.refreshDuration).Err()
}

// GetMFAStatus retrieves the MFA status for a session
func (j *JWTService) GetMFAStatus(sessionID string) (*MFASessionStatus, error) {
	if j.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("session not found: %s", sessionID)
		}
		return nil, fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return nil, fmt.Errorf("failed to parse session data: %w", err)
	}

	// Extract MFA fields with defaults
	mfaCompleted := getBoolFromSession(session, "mfa_completed")
	mfaMethod := getStringFromSession(session, "mfa_method")
	mfaTimestamp := time.Unix(int64(getFloatFromSession(session, "mfa_timestamp")), 0)
	mfaExpiresAt := time.Unix(int64(getFloatFromSession(session, "mfa_expires_at")), 0)
	mfaValidity := time.Duration(getFloatFromSession(session, "mfa_validity_duration")) * time.Second
	requiresStepUp := getBoolFromSession(session, "requires_mfa_stepup")

	// Extract step-up operations list
	var stepUpOps []string
	if opsInterface, ok := session["stepup_operations"].([]interface{}); ok {
		for _, op := range opsInterface {
			if opStr, ok := op.(string); ok {
				stepUpOps = append(stepUpOps, opStr)
			}
		}
	}

	status := &MFASessionStatus{
		SessionID:           sessionID,
		UserID:              getStringFromSession(session, "user_id"),
		MFACompleted:        mfaCompleted,
		MFAMethod:           mfaMethod,
		MFATimestamp:        mfaTimestamp,
		MFAValidityDuration: mfaValidity,
		MFAExpiresAt:        mfaExpiresAt,
		RequiresMFAStepUp:   requiresStepUp,
		StepUpOperations:    stepUpOps,
		LastMFAValidation:   mfaTimestamp,
		MFAFailureCount:     int(getFloatFromSession(session, "mfa_failure_count")),
		MFALockedUntil:      time.Unix(int64(getFloatFromSession(session, "mfa_locked_until")), 0),
	}

	return status, nil
}

// RequiresMFAStepUp checks if a session requires MFA step-up for a specific operation
func (j *JWTService) RequiresMFAStepUp(sessionID string, operation string) (bool, error) {
	if j.mfaHandler == nil {
		return false, fmt.Errorf("MFA handler not configured")
	}

	// Get current MFA status
	mfaStatus, err := j.GetMFAStatus(sessionID)
	if err != nil {
		return false, fmt.Errorf("failed to get MFA status: %w", err)
	}

	// Check if MFA is completed and still valid
	if !mfaStatus.MFACompleted || time.Now().After(mfaStatus.MFAExpiresAt) {
		return true, nil // MFA required
	}

	// Check if this specific operation requires step-up
	if j.mfaHandler.IsHighRiskOperation(operation) {
		// High-risk operations always require fresh MFA
		stepUpAge := time.Since(mfaStatus.MFATimestamp)
		if stepUpAge > 15*time.Minute { // Step-up required after 15 minutes for high-risk ops
			return true, nil
		}
	}

	// Check if step-up is explicitly required
	if mfaStatus.RequiresMFAStepUp {
		// Check if this operation is in the step-up list
		for _, op := range mfaStatus.StepUpOperations {
			if op == operation {
				return true, nil
			}
		}
	}

	return false, nil
}

// SetMFAStepUpRequirement sets the MFA step-up requirement for a session
func (j *JWTService) SetMFAStepUpRequirement(sessionID string, required bool, operation string) error {
	if j.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	// Get existing session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("failed to parse session data: %w", err)
	}

	// Update step-up requirement
	session["requires_mfa_stepup"] = required

	// Update operations list
	var stepUpOps []string
	if opsInterface, ok := session["stepup_operations"].([]interface{}); ok {
		for _, op := range opsInterface {
			if opStr, ok := op.(string); ok {
				stepUpOps = append(stepUpOps, opStr)
			}
		}
	}

	if required && operation != "" {
		// Add operation to step-up list if not already present
		found := false
		for _, op := range stepUpOps {
			if op == operation {
				found = true
				break
			}
		}
		if !found {
			stepUpOps = append(stepUpOps, operation)
		}
	} else if !required && operation != "" {
		// Remove operation from step-up list
		var newStepUpOps []string
		for _, op := range stepUpOps {
			if op != operation {
				newStepUpOps = append(newStepUpOps, op)
			}
		}
		stepUpOps = newStepUpOps
	}

	session["stepup_operations"] = stepUpOps

	// Save updated session
	updatedSessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	return j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedSessionJSON, j.refreshDuration).Err()
}

// ValidateMFAForOperation validates MFA status for a specific operation
func (j *JWTService) ValidateMFAForOperation(sessionID string, operation string) (bool, error) {
	// Check if MFA step-up is required
	requiresStepUp, err := j.RequiresMFAStepUp(sessionID, operation)
	if err != nil {
		return false, fmt.Errorf("failed to check MFA step-up requirement: %w", err)
	}

	if requiresStepUp {
		return false, fmt.Errorf("MFA step-up required for operation: %s", operation)
	}

	// Get current MFA status
	mfaStatus, err := j.GetMFAStatus(sessionID)
	if err != nil {
		return false, fmt.Errorf("failed to get MFA status: %w", err)
	}

	// Validate MFA is completed and still valid
	if !mfaStatus.MFACompleted {
		return false, fmt.Errorf("MFA not completed for session: %s", sessionID)
	}

	if time.Now().After(mfaStatus.MFAExpiresAt) {
		return false, fmt.Errorf("MFA expired for session: %s", sessionID)
	}

	// Update last MFA validation timestamp
	if j.redisClient != nil {
		ctx := context.Background()
		sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
		if err == nil {
			var session map[string]interface{}
			if json.Unmarshal([]byte(sessionData), &session) == nil {
				session["last_mfa_validation"] = time.Now().Unix()
				if updatedData, err := json.Marshal(session); err == nil {
					j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedData, j.refreshDuration)
				}
			}
		}
	}

	return true, nil
}

// InvalidateMFAForSessions invalidates MFA for all sessions of a user
func (j *JWTService) InvalidateMFAForSessions(userID string) error {
	sessions, err := j.GetAllActiveSessions(userID)
	if err != nil {
		return fmt.Errorf("failed to get user sessions: %w", err)
	}

	for _, session := range sessions {
		if err := j.invalidateMFAForSession(session.SessionID); err != nil {
			// Log error but continue with other sessions
			fmt.Printf("Warning: Failed to invalidate MFA for session %s: %v\n", session.SessionID, err)
		}
	}

	return nil
}

// invalidateMFAForSession invalidates MFA for a specific session
func (j *JWTService) invalidateMFAForSession(sessionID string) error {
	if j.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	ctx := context.Background()
	
	// Get existing session data
	sessionData, err := j.redisClient.Get(ctx, j.sessionKey(sessionID)).Result()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found: %s", sessionID)
		}
		return fmt.Errorf("failed to get session data: %w", err)
	}

	var session map[string]interface{}
	if err := json.Unmarshal([]byte(sessionData), &session); err != nil {
		return fmt.Errorf("failed to parse session data: %w", err)
	}

	// Invalidate MFA status
	session["mfa_completed"] = false
	session["mfa_method"] = ""
	session["mfa_timestamp"] = time.Time{}.Unix()
	session["mfa_expires_at"] = time.Time{}.Unix()
	session["requires_mfa_stepup"] = true
	session["stepup_operations"] = []string{}

	// Save updated session
	updatedSessionJSON, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal updated session data: %w", err)
	}

	return j.redisClient.Set(ctx, j.sessionKey(sessionID), updatedSessionJSON, j.refreshDuration).Err()
}