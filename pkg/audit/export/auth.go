package export

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ExportAuthService handles authentication and authorization for export operations
type ExportAuthService struct {
	config ExportAuthConfig
}

// ExportAuthConfig configures authentication and authorization
type ExportAuthConfig struct {
	RequireAuthentication  bool                   `json:"require_authentication"`
	JWTSecret             string                 `json:"jwt_secret,omitempty"`
	RequiredPermissions    []ExportPermission     `json:"required_permissions"`
	AllowedUsers          []string               `json:"allowed_users,omitempty"`
	AllowedRoles          []string               `json:"allowed_roles,omitempty"`
	RateLimit             ExportRateLimit        `json:"rate_limit"`
	SessionTimeout        time.Duration          `json:"session_timeout"`
	MaxExportsPerUser     int                    `json:"max_exports_per_user"`
	MaxExportsPerHour     int                    `json:"max_exports_per_hour"`
	AuditPermissionChecks bool                   `json:"audit_permission_checks"`
}

// ExportPermission represents a required permission for export operations
type ExportPermission struct {
	Resource string   `json:"resource"` // audit, export, admin
	Actions  []string `json:"actions"`  // read, export, manage
	Scope    string   `json:"scope"`    // global, cluster, namespace
}

// ExportRateLimit configures rate limiting for export operations
type ExportRateLimit struct {
	Enabled           bool          `json:"enabled"`
	RequestsPerMinute int           `json:"requests_per_minute"`
	RequestsPerHour   int           `json:"requests_per_hour"`
	RequestsPerDay    int           `json:"requests_per_day"`
	BurstSize         int           `json:"burst_size"`
	WindowSize        time.Duration `json:"window_size"`
}

// AuthContext provides authentication and authorization context
type AuthContext struct {
	UserID       string                 `json:"user_id"`
	Email        string                 `json:"email"`
	Name         string                 `json:"name"`
	Roles        []string               `json:"roles"`
	Groups       []string               `json:"groups"`
	Permissions  []ExportPermission     `json:"permissions"`
	SessionID    string                 `json:"session_id"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	AuthProvider string                 `json:"auth_provider"`
	AuthenticatedAt time.Time           `json:"authenticated_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ExportAuthResult represents the result of an authorization check
type ExportAuthResult struct {
	Authorized       bool                   `json:"authorized"`
	UserID          string                 `json:"user_id"`
	Permissions     []ExportPermission     `json:"permissions"`
	Restrictions    ExportRestrictions     `json:"restrictions"`
	RateLimitStatus RateLimitStatus        `json:"rate_limit_status"`
	Reason          string                 `json:"reason,omitempty"`
	AuditEvent      *models.AuditEvent     `json:"audit_event,omitempty"`
}

// ExportRestrictions defines what restrictions apply to the user's export operations
type ExportRestrictions struct {
	AllowedFormats      []string  `json:"allowed_formats,omitempty"`
	AllowedClusters     []string  `json:"allowed_clusters,omitempty"`
	AllowedNamespaces   []string  `json:"allowed_namespaces,omitempty"`
	MaxExportSize       int64     `json:"max_export_size,omitempty"`
	MaxTimeRange        time.Duration `json:"max_time_range,omitempty"`
	RequireApproval     bool      `json:"require_approval"`
	DataFiltering       bool      `json:"data_filtering"` // Whether to filter sensitive data
}

// RateLimitStatus represents the current rate limit status for a user
type RateLimitStatus struct {
	Allowed           bool      `json:"allowed"`
	RemainingRequests int       `json:"remaining_requests"`
	ResetAt          time.Time  `json:"reset_at"`
	RetryAfter       time.Duration `json:"retry_after"`
}

// DefaultExportAuthConfig returns default authentication configuration
func DefaultExportAuthConfig() ExportAuthConfig {
	return ExportAuthConfig{
		RequireAuthentication: true,
		JWTSecret:            "", // Must be configured via environment variable
		RequiredPermissions: []ExportPermission{
			{
				Resource: "audit",
				Actions:  []string{"read", "export"},
				Scope:    "global",
			},
		},
		RateLimit: ExportRateLimit{
			Enabled:           true,
			RequestsPerMinute: 10,
			RequestsPerHour:   100,
			RequestsPerDay:    1000,
			BurstSize:         5,
			WindowSize:        time.Minute,
		},
		SessionTimeout:        time.Hour * 8,
		MaxExportsPerUser:     10,
		MaxExportsPerHour:     50,
		AuditPermissionChecks: true,
	}
}

// NewExportAuthService creates a new export authentication service
func NewExportAuthService(config ExportAuthConfig) *ExportAuthService {
	return &ExportAuthService{
		config: config,
	}
}

// RequireAuthentication returns whether authentication is required
func (eas *ExportAuthService) RequireAuthentication() bool {
	return eas.config.RequireAuthentication
}

// HasRequiredPermissions checks if the auth context has required permissions
func (eas *ExportAuthService) HasRequiredPermissions(authContext *AuthContext) bool {
	if !eas.config.RequireAuthentication {
		return true
	}
	
	// Check if user is in allowed users list (if specified)
	if len(eas.config.AllowedUsers) > 0 {
		found := false
		for _, allowedUser := range eas.config.AllowedUsers {
			if authContext.UserID == allowedUser {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Check if user has required roles (if specified)
	if len(eas.config.AllowedRoles) > 0 {
		hasRequiredRole := false
		for _, userRole := range authContext.Roles {
			for _, requiredRole := range eas.config.AllowedRoles {
				if userRole == requiredRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}
		if !hasRequiredRole {
			return false
		}
	}
	
	// Check specific permissions
	for _, requiredPerm := range eas.config.RequiredPermissions {
		hasPermission := false
		for _, userPerm := range authContext.Permissions {
			if userPerm.Resource == requiredPerm.Resource &&
			   userPerm.Scope == requiredPerm.Scope {
				// Check if user has all required actions
				hasAllActions := true
				for _, reqAction := range requiredPerm.Actions {
					hasAction := false
					for _, userAction := range userPerm.Actions {
						if userAction == reqAction {
							hasAction = true
							break
						}
					}
					if !hasAction {
						hasAllActions = false
						break
					}
				}
				if hasAllActions {
					hasPermission = true
					break
				}
			}
		}
		if !hasPermission {
			return false
		}
	}
	
	return true
}

// AuthorizeExportRequest validates and authorizes an export request
func (eas *ExportAuthService) AuthorizeExportRequest(ctx context.Context, authCtx *AuthContext, request *ExportRequest) (*ExportAuthResult, error) {
	result := &ExportAuthResult{
		UserID: authCtx.UserID,
	}
	
	// Skip authentication if not required
	if !eas.config.RequireAuthentication {
		result.Authorized = true
		return result, nil
	}
	
	// Validate authentication context
	if err := eas.validateAuthContext(authCtx); err != nil {
		result.Authorized = false
		result.Reason = fmt.Sprintf("Authentication validation failed: %v", err)
		return result, nil
	}
	
	// Check rate limits
	rateLimitStatus := eas.checkRateLimit(authCtx.UserID)
	result.RateLimitStatus = rateLimitStatus
	if !rateLimitStatus.Allowed {
		result.Authorized = false
		result.Reason = "Rate limit exceeded"
		return result, nil
	}
	
	// Check permissions
	hasPermission, permissions := eas.checkPermissions(authCtx, request)
	result.Permissions = permissions
	if !hasPermission {
		result.Authorized = false
		result.Reason = "Insufficient permissions"
		eas.auditPermissionDenied(authCtx, request, result)
		return result, nil
	}
	
	// Apply user restrictions
	restrictions := eas.getExportRestrictions(authCtx)
	result.Restrictions = restrictions
	
	// Validate request against restrictions
	if err := eas.validateRequestAgainstRestrictions(request, restrictions); err != nil {
		result.Authorized = false
		result.Reason = fmt.Sprintf("Request violates restrictions: %v", err)
		return result, nil
	}
	
	// Check user-specific limits
	if err := eas.checkUserLimits(authCtx.UserID); err != nil {
		result.Authorized = false
		result.Reason = err.Error()
		return result, nil
	}
	
	// Authorization successful
	result.Authorized = true
	eas.auditPermissionGranted(authCtx, request, result)
	
	return result, nil
}

// ValidateSessionToken validates a session token and returns auth context
func (eas *ExportAuthService) ValidateSessionToken(ctx context.Context, token string) (*AuthContext, error) {
	if !eas.config.RequireAuthentication {
		// Return a default context for testing/development
		return &AuthContext{
			UserID:          "anonymous",
			Email:           "anonymous@localhost",
			Name:            "Anonymous User",
			Roles:           []string{"user"},
			Groups:          []string{"default"},
			SessionID:       "anonymous-session",
			AuthProvider:    "none",
			AuthenticatedAt: time.Now(),
			ExpiresAt:       time.Now().Add(eas.config.SessionTimeout),
		}, nil
	}
	
	// Parse and validate JWT token
	jwtToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		
		// Return the secret key for validation
		// In production, this should be loaded from secure configuration
		secretKey := eas.config.JWTSecret
		if secretKey == "" {
			return nil, fmt.Errorf("JWT secret not configured")
		}
		return []byte(secretKey), nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("invalid JWT token: %w", err)
	}
	
	// Extract and validate claims
	if claims, ok := jwtToken.Claims.(jwt.MapClaims); ok && jwtToken.Valid {
		// Check expiration
		if exp, ok := claims["exp"]; ok {
			if expFloat, ok := exp.(float64); ok {
				expTime := time.Unix(int64(expFloat), 0)
				if time.Now().After(expTime) {
					return nil, fmt.Errorf("JWT token has expired")
				}
			}
		}
		
		// Extract user information from claims
		userID, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
		name, _ := claims["name"].(string)
		sessionID, _ := claims["sid"].(string)
		authProvider, _ := claims["iss"].(string)
		
		// Extract roles and groups
		var roles []string
		if rolesInterface, ok := claims["roles"]; ok {
			if rolesList, ok := rolesInterface.([]interface{}); ok {
				for _, role := range rolesList {
					if roleStr, ok := role.(string); ok {
						roles = append(roles, roleStr)
					}
				}
			}
		}
		
		var groups []string
		if groupsInterface, ok := claims["groups"]; ok {
			if groupsList, ok := groupsInterface.([]interface{}); ok {
				for _, group := range groupsList {
					if groupStr, ok := group.(string); ok {
						groups = append(groups, groupStr)
					}
				}
			}
		}
		
		// Set defaults if missing
		if userID == "" {
			return nil, fmt.Errorf("JWT token missing required 'sub' claim")
		}
		if sessionID == "" {
			sessionID = fmt.Sprintf("jwt-%s-%d", userID, time.Now().Unix())
		}
		if len(roles) == 0 {
			roles = []string{"user"}
		}
		if len(groups) == 0 {
			groups = []string{"default"}
		}
		
		// Create auth context
		authTime := time.Now()
		if iat, ok := claims["iat"]; ok {
			if iatFloat, ok := iat.(float64); ok {
				authTime = time.Unix(int64(iatFloat), 0)
			}
		}
		
		expiresAt := time.Now().Add(eas.config.SessionTimeout)
		if exp, ok := claims["exp"]; ok {
			if expFloat, ok := exp.(float64); ok {
				expiresAt = time.Unix(int64(expFloat), 0)
			}
		}
		
		return &AuthContext{
			UserID:          userID,
			Email:           email,
			Name:            name,
			Roles:           roles,
			Groups:          groups,
			SessionID:       sessionID,
			AuthProvider:    authProvider,
			AuthenticatedAt: authTime,
			ExpiresAt:       expiresAt,
		}, nil
	}
	
	return nil, fmt.Errorf("invalid JWT token claims")
}

// CreateAuthContextFromUser creates an auth context from a user model
func (eas *ExportAuthService) CreateAuthContextFromUser(user *models.User, sessionID, ipAddress, userAgent string) *AuthContext {
	return &AuthContext{
		UserID:          user.ID,
		Email:           user.Email,
		Name:            user.Name,
		Roles:           user.GetKubernetesGroups(), // Reuse groups as roles
		Groups:          user.GetKubernetesGroups(),
		Permissions:     eas.getUserPermissions(user),
		SessionID:       sessionID,
		IPAddress:       ipAddress,
		UserAgent:       userAgent,
		AuthProvider:    user.OIDCAttributes.Provider,
		AuthenticatedAt: time.Now(),
		ExpiresAt:       time.Now().Add(eas.config.SessionTimeout),
		Metadata:        make(map[string]interface{}),
	}
}

// Helper methods

func (eas *ExportAuthService) validateAuthContext(authCtx *AuthContext) error {
	if authCtx.UserID == "" {
		return fmt.Errorf("user ID is required")
	}
	
	if time.Now().After(authCtx.ExpiresAt) {
		return fmt.Errorf("authentication context has expired")
	}
	
	// Check if user is in allowed users list (if configured)
	if len(eas.config.AllowedUsers) > 0 {
		allowed := false
		for _, allowedUser := range eas.config.AllowedUsers {
			if authCtx.UserID == allowedUser || authCtx.Email == allowedUser {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("user not in allowed users list")
		}
	}
	
	// Check if user has required roles (if configured)
	if len(eas.config.AllowedRoles) > 0 {
		hasRequiredRole := false
		for _, userRole := range authCtx.Roles {
			for _, allowedRole := range eas.config.AllowedRoles {
				if userRole == allowedRole {
					hasRequiredRole = true
					break
				}
			}
			if hasRequiredRole {
				break
			}
		}
		if !hasRequiredRole {
			return fmt.Errorf("user does not have required roles")
		}
	}
	
	return nil
}

func (eas *ExportAuthService) checkPermissions(authCtx *AuthContext, request *ExportRequest) (bool, []ExportPermission) {
	userPermissions := authCtx.Permissions
	
	// Check each required permission
	for _, requiredPerm := range eas.config.RequiredPermissions {
		hasPermission := false
		
		for _, userPerm := range userPermissions {
			if eas.permissionMatches(userPerm, requiredPerm) {
				hasPermission = true
				break
			}
		}
		
		if !hasPermission {
			return false, userPermissions
		}
	}
	
	return true, userPermissions
}

func (eas *ExportAuthService) permissionMatches(userPerm, requiredPerm ExportPermission) bool {
	// Check resource match
	if userPerm.Resource != requiredPerm.Resource && userPerm.Resource != "*" {
		return false
	}
	
	// Check action match
	for _, requiredAction := range requiredPerm.Actions {
		hasAction := false
		for _, userAction := range userPerm.Actions {
			if userAction == requiredAction || userAction == "*" {
				hasAction = true
				break
			}
		}
		if !hasAction {
			return false
		}
	}
	
	// Check scope match (simplified)
	if userPerm.Scope != requiredPerm.Scope && userPerm.Scope != "*" && requiredPerm.Scope != "*" {
		return false
	}
	
	return true
}

func (eas *ExportAuthService) checkRateLimit(userID string) RateLimitStatus {
	if !eas.config.RateLimit.Enabled {
		return RateLimitStatus{
			Allowed:           true,
			RemainingRequests: 999999,
		}
	}
	
	// TODO: Implement actual rate limiting
	// This would typically use Redis or in-memory store to track request counts
	
	return RateLimitStatus{
		Allowed:           true,
		RemainingRequests: eas.config.RateLimit.RequestsPerMinute,
		ResetAt:          time.Now().Add(eas.config.RateLimit.WindowSize),
	}
}

func (eas *ExportAuthService) getExportRestrictions(authCtx *AuthContext) ExportRestrictions {
	restrictions := ExportRestrictions{
		AllowedFormats: []string{"JSON", "CEF", "LEEF"}, // Default: all formats
		MaxExportSize:  1024 * 1024 * 100,              // 100MB default
		MaxTimeRange:   time.Hour * 24 * 30,            // 30 days default
	}
	
	// Apply role-based restrictions
	for _, role := range authCtx.Roles {
		switch strings.ToLower(role) {
		case "admin", "security-admin":
			// Admins have no restrictions
			restrictions.MaxExportSize = 1024 * 1024 * 1024 // 1GB
			restrictions.MaxTimeRange = time.Hour * 24 * 365 // 1 year
			
		case "security-analyst":
			// Analysts can export all formats but with size limits
			restrictions.MaxExportSize = 1024 * 1024 * 500 // 500MB
			restrictions.MaxTimeRange = time.Hour * 24 * 90 // 90 days
			
		case "developer":
			// Developers have more limited access
			restrictions.AllowedFormats = []string{"JSON"}
			restrictions.MaxExportSize = 1024 * 1024 * 50 // 50MB
			restrictions.MaxTimeRange = time.Hour * 24 * 7 // 7 days
			restrictions.DataFiltering = true // Filter sensitive data
			
		case "auditor":
			// Auditors can access all data but may require approval for large exports
			restrictions.RequireApproval = true
			restrictions.MaxExportSize = 1024 * 1024 * 200 // 200MB
			restrictions.MaxTimeRange = time.Hour * 24 * 180 // 180 days
		}
	}
	
	// Apply cluster-based restrictions if user has limited cluster access
	if len(authCtx.Groups) > 0 {
		// Use groups to determine allowed clusters/namespaces
		for _, group := range authCtx.Groups {
			if strings.HasPrefix(group, "cluster:") {
				clusterName := strings.TrimPrefix(group, "cluster:")
				restrictions.AllowedClusters = append(restrictions.AllowedClusters, clusterName)
			}
			if strings.HasPrefix(group, "namespace:") {
				namespace := strings.TrimPrefix(group, "namespace:")
				restrictions.AllowedNamespaces = append(restrictions.AllowedNamespaces, namespace)
			}
		}
	}
	
	return restrictions
}

func (eas *ExportAuthService) validateRequestAgainstRestrictions(request *ExportRequest, restrictions ExportRestrictions) error {
	// Check allowed formats
	if len(restrictions.AllowedFormats) > 0 {
		formatAllowed := false
		for _, allowedFormat := range restrictions.AllowedFormats {
			if request.Format == allowedFormat {
				formatAllowed = true
				break
			}
		}
		if !formatAllowed {
			return fmt.Errorf("format %s is not allowed", request.Format)
		}
	}
	
	// Check time range restrictions
	if !request.Filter.StartTime.IsZero() && !request.Filter.EndTime.IsZero() {
		requestedRange := request.Filter.EndTime.Sub(request.Filter.StartTime)
		if requestedRange > restrictions.MaxTimeRange {
			return fmt.Errorf("requested time range exceeds maximum allowed: %v", restrictions.MaxTimeRange)
		}
	}
	
	// Check cluster restrictions
	if len(restrictions.AllowedClusters) > 0 && len(request.Filter.ClusterNames) > 0 {
		for _, requestedCluster := range request.Filter.ClusterNames {
			clusterAllowed := false
			for _, allowedCluster := range restrictions.AllowedClusters {
				if requestedCluster == allowedCluster {
					clusterAllowed = true
					break
				}
			}
			if !clusterAllowed {
				return fmt.Errorf("access to cluster %s is not allowed", requestedCluster)
			}
		}
	}
	
	// Check namespace restrictions
	if len(restrictions.AllowedNamespaces) > 0 && len(request.Filter.Namespaces) > 0 {
		for _, requestedNamespace := range request.Filter.Namespaces {
			namespaceAllowed := false
			for _, allowedNamespace := range restrictions.AllowedNamespaces {
				if requestedNamespace == allowedNamespace {
					namespaceAllowed = true
					break
				}
			}
			if !namespaceAllowed {
				return fmt.Errorf("access to namespace %s is not allowed", requestedNamespace)
			}
		}
	}
	
	return nil
}

func (eas *ExportAuthService) checkUserLimits(userID string) error {
	// TODO: Check current export count for user
	// This would typically query the job tracker
	
	return nil
}

func (eas *ExportAuthService) getUserPermissions(user *models.User) []ExportPermission {
	// Default permissions based on user groups
	var permissions []ExportPermission
	
	groups := user.GetKubernetesGroups()
	for _, group := range groups {
		switch strings.ToLower(group) {
		case "admin", "security-admin":
			permissions = append(permissions, ExportPermission{
				Resource: "*",
				Actions:  []string{"*"},
				Scope:    "*",
			})
			
		case "security-analyst", "auditor":
			permissions = append(permissions, ExportPermission{
				Resource: "audit",
				Actions:  []string{"read", "export"},
				Scope:    "global",
			})
			
		case "developer":
			permissions = append(permissions, ExportPermission{
				Resource: "audit",
				Actions:  []string{"read"},
				Scope:    "namespace",
			})
		}
	}
	
	// If no specific permissions, give basic read access
	if len(permissions) == 0 {
		permissions = append(permissions, ExportPermission{
			Resource: "audit",
			Actions:  []string{"read"},
			Scope:    "namespace",
		})
	}
	
	return permissions
}

func (eas *ExportAuthService) auditPermissionGranted(authCtx *AuthContext, request *ExportRequest, result *ExportAuthResult) {
	if !eas.config.AuditPermissionChecks {
		return
	}
	
	// Create audit event for granted permission
	auditEvent, _ := models.NewAuditEventBuilder().
		WithEventType(models.AuditEventTypePermissionGrant).
		WithSeverity(models.AuditSeverityInfo).
		WithMessage("Export permission granted").
		WithUserContextFromUser(&models.User{
			ID:    authCtx.UserID,
			Email: authCtx.Email,
			Name:  authCtx.Name,
		}, authCtx.SessionID, authCtx.IPAddress, authCtx.UserAgent).
		WithService("export-service", "1.0").
		WithCorrelationID(request.ExportID).
		WithMetadata("export_format", request.Format).
		WithMetadata("export_platform", request.Platform).
		WithMetadata("permissions_checked", len(result.Permissions)).
		Build()
	
	result.AuditEvent = auditEvent
}

func (eas *ExportAuthService) auditPermissionDenied(authCtx *AuthContext, request *ExportRequest, result *ExportAuthResult) {
	if !eas.config.AuditPermissionChecks {
		return
	}
	
	// Create audit event for denied permission
	auditEvent, _ := models.NewAuditEventBuilder().
		WithEventType(models.AuditEventTypeRBACDenied).
		WithSeverity(models.AuditSeverityWarning).
		WithMessage("Export permission denied").
		WithUserContextFromUser(&models.User{
			ID:    authCtx.UserID,
			Email: authCtx.Email,
			Name:  authCtx.Name,
		}, authCtx.SessionID, authCtx.IPAddress, authCtx.UserAgent).
		WithService("export-service", "1.0").
		WithCorrelationID(request.ExportID).
		WithMetadata("denial_reason", result.Reason).
		WithMetadata("export_format", request.Format).
		WithMetadata("export_platform", request.Platform).
		Build()
	
	result.AuditEvent = auditEvent
}