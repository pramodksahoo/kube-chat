// Package models provides data models for the KubeChat application
package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// UserRole represents the role of a user in the system
type UserRole string

const (
	UserRoleViewer   UserRole = "viewer"
	UserRoleOperator UserRole = "operator"
	UserRoleAdmin    UserRole = "admin"
)

// UserPreferences holds user-specific preferences and settings
type UserPreferences struct {
	Theme              string            `json:"theme,omitempty"`              // light, dark, auto
	Language           string            `json:"language,omitempty"`           // en, es, fr, etc.
	DefaultNamespace   string            `json:"defaultNamespace,omitempty"`   // Default Kubernetes namespace
	DefaultContext     string            `json:"defaultContext,omitempty"`     // Default Kubernetes context
	SessionTimeout     int               `json:"sessionTimeout,omitempty"`     // Session timeout in minutes
	NotificationsEnabled bool            `json:"notificationsEnabled"`         // Enable notifications
	CustomSettings     map[string]string `json:"customSettings,omitempty"`     // Additional custom settings
}

// OIDCAttributes holds OIDC-specific user attributes
type OIDCAttributes struct {
	Provider          string            `json:"provider"`                    // OIDC provider name (okta, auth0, etc.)
	Subject           string            `json:"subject"`                     // OIDC subject identifier
	Issuer            string            `json:"issuer"`                      // OIDC issuer URL
	Email             string            `json:"email"`                       // User email from OIDC
	EmailVerified     bool              `json:"emailVerified"`               // Email verification status
	Name              string            `json:"name,omitempty"`              // Full name from OIDC
	GivenName         string            `json:"givenName,omitempty"`         // First name
	FamilyName        string            `json:"familyName,omitempty"`        // Last name
	Picture           string            `json:"picture,omitempty"`           // Profile picture URL
	Groups            []string          `json:"groups,omitempty"`            // OIDC groups
	CustomClaims      map[string]interface{} `json:"customClaims,omitempty"`  // Additional OIDC claims
	LastTokenRefresh  time.Time         `json:"lastTokenRefresh,omitempty"`  // Last token refresh timestamp
	TokenExpiry       time.Time         `json:"tokenExpiry,omitempty"`       // Token expiry timestamp
}

// User represents a KubeChat user with OIDC integration
type User struct {
	ID                string          `json:"id"`                          // Unique user identifier
	Email             string          `json:"email"`                       // User email address
	Name              string          `json:"name"`                        // Display name
	Role              UserRole        `json:"role"`                        // User role in the system
	KubernetesGroups  []string        `json:"kubernetesGroups"`           // Kubernetes RBAC groups
	LastLogin         time.Time       `json:"lastLogin"`                   // Last successful login
	Preferences       UserPreferences `json:"preferences"`                 // User preferences
	CreatedAt         time.Time       `json:"createdAt"`                   // Account creation timestamp
	UpdatedAt         time.Time       `json:"updatedAt"`                   // Last update timestamp
	
	// OIDC Integration Fields
	OIDCAttributes    OIDCAttributes  `json:"oidcAttributes"`              // OIDC-specific attributes
	ActiveSessions    []string        `json:"activeSessions,omitempty"`    // List of active session IDs
	LoginHistory      []LoginRecord   `json:"loginHistory,omitempty"`      // Recent login history
	
	// Security and Audit Fields
	IsActive          bool            `json:"isActive"`                    // Account active status
	IsLocked          bool            `json:"isLocked"`                    // Account locked status
	FailedLoginCount  int             `json:"failedLoginCount"`            // Failed login attempts
	LastFailedLogin   time.Time       `json:"lastFailedLogin,omitempty"`   // Last failed login attempt
	MFAEnabled        bool            `json:"mfaEnabled"`                  // MFA status from OIDC provider
}

// LoginRecord represents a single login event
type LoginRecord struct {
	SessionID     string    `json:"sessionId"`         // Session identifier
	LoginTime     time.Time `json:"loginTime"`         // Login timestamp
	IPAddress     string    `json:"ipAddress"`         // Client IP address
	UserAgent     string    `json:"userAgent"`         // User agent string
	Provider      string    `json:"provider"`          // Authentication provider used
	MFAUsed       bool      `json:"mfaUsed"`          // Whether MFA was used
	Success       bool      `json:"success"`           // Login success status
	FailureReason string    `json:"failureReason,omitempty"` // Reason for failure if applicable
}

// SessionAuthContext holds authentication context for a session
type SessionAuthContext struct {
	UserID           string            `json:"userId"`              // User identifier
	SessionID        string            `json:"sessionId"`           // Session identifier
	AuthProvider     string            `json:"authProvider"`        // OIDC provider used
	AuthenticatedAt  time.Time         `json:"authenticatedAt"`     // Authentication timestamp
	TokenIssuedAt    time.Time         `json:"tokenIssuedAt"`       // JWT token issued timestamp
	TokenExpiresAt   time.Time         `json:"tokenExpiresAt"`      // JWT token expiry
	RefreshTokenID   string            `json:"refreshTokenId"`      // Refresh token identifier
	IPAddress        string            `json:"ipAddress"`           // Client IP address
	UserAgent        string            `json:"userAgent"`           // User agent string
	Permissions      []string          `json:"permissions"`         // Session-specific permissions
	KubernetesContext string           `json:"kubernetesContext"`   // Current Kubernetes context
	LastActivity     time.Time         `json:"lastActivity"`        // Last session activity
	IsValid          bool              `json:"isValid"`             // Session validity status
}

// NewUser creates a new user with default values
func NewUser(email, name string, role UserRole) *User {
	now := time.Now()
	return &User{
		Email:     email,
		Name:      name,
		Role:      role,
		IsActive:  true,
		IsLocked:  false,
		CreatedAt: now,
		UpdatedAt: now,
		Preferences: UserPreferences{
			Theme:                "light",
			Language:             "en",
			SessionTimeout:       480, // 8 hours in minutes
			NotificationsEnabled: true,
			CustomSettings:       make(map[string]string),
		},
		KubernetesGroups: make([]string, 0),
		ActiveSessions:   make([]string, 0),
		LoginHistory:     make([]LoginRecord, 0),
	}
}

// UpdateFromOIDC updates user information from OIDC claims
func (u *User) UpdateFromOIDC(claims map[string]interface{}, provider string) error {
	now := time.Now()
	
	// Update basic information
	if email, ok := claims["email"].(string); ok && email != "" {
		u.Email = email
	}
	
	if name, ok := claims["name"].(string); ok && name != "" {
		u.Name = name
	}
	
	// Update OIDC attributes
	u.OIDCAttributes.Provider = provider
	
	if sub, ok := claims["sub"].(string); ok {
		u.OIDCAttributes.Subject = sub
	}
	
	if iss, ok := claims["iss"].(string); ok {
		u.OIDCAttributes.Issuer = iss
	}
	
	if emailVerified, ok := claims["email_verified"].(bool); ok {
		u.OIDCAttributes.EmailVerified = emailVerified
	}
	
	if givenName, ok := claims["given_name"].(string); ok {
		u.OIDCAttributes.GivenName = givenName
	}
	
	if familyName, ok := claims["family_name"].(string); ok {
		u.OIDCAttributes.FamilyName = familyName
	}
	
	if picture, ok := claims["picture"].(string); ok {
		u.OIDCAttributes.Picture = picture
	}
	
	// Handle groups - can be array of strings or single string
	// Always initialize Groups slice
	u.OIDCAttributes.Groups = make([]string, 0)
	if groupsClaim, ok := claims["groups"]; ok {
		switch groups := groupsClaim.(type) {
		case []interface{}:
			u.OIDCAttributes.Groups = make([]string, 0, len(groups))
			for _, group := range groups {
				if groupStr, ok := group.(string); ok {
					u.OIDCAttributes.Groups = append(u.OIDCAttributes.Groups, groupStr)
				}
			}
		case []string:
			u.OIDCAttributes.Groups = groups
		case string:
			u.OIDCAttributes.Groups = []string{groups}
		}
	}
	
	// Store custom claims
	u.OIDCAttributes.CustomClaims = make(map[string]interface{})
	for key, value := range claims {
		// Skip standard claims
		if !isStandardClaim(key) {
			u.OIDCAttributes.CustomClaims[key] = value
		}
	}
	
	u.OIDCAttributes.LastTokenRefresh = now
	u.UpdatedAt = now
	
	return nil
}

// AddLoginRecord adds a new login record to the user's history
func (u *User) AddLoginRecord(record LoginRecord) {
	// Keep only the last 50 login records
	const maxLoginRecords = 50
	
	u.LoginHistory = append([]LoginRecord{record}, u.LoginHistory...)
	
	if len(u.LoginHistory) > maxLoginRecords {
		u.LoginHistory = u.LoginHistory[:maxLoginRecords]
	}
	
	// Update login statistics
	if record.Success {
		u.LastLogin = record.LoginTime
		u.FailedLoginCount = 0 // Reset failed login count on successful login
	} else {
		u.LastFailedLogin = record.LoginTime
		u.FailedLoginCount++
		
		// Lock account after 5 failed attempts
		if u.FailedLoginCount >= 5 {
			u.IsLocked = true
		}
	}
	
	u.UpdatedAt = time.Now()
}

// AddActiveSession adds a session ID to the user's active sessions
func (u *User) AddActiveSession(sessionID string) {
	// Check if session already exists
	for _, id := range u.ActiveSessions {
		if id == sessionID {
			return
		}
	}
	
	u.ActiveSessions = append(u.ActiveSessions, sessionID)
	u.UpdatedAt = time.Now()
}

// RemoveActiveSession removes a session ID from the user's active sessions
func (u *User) RemoveActiveSession(sessionID string) {
	for i, id := range u.ActiveSessions {
		if id == sessionID {
			u.ActiveSessions = append(u.ActiveSessions[:i], u.ActiveSessions[i+1:]...)
			break
		}
	}
	u.UpdatedAt = time.Now()
}

// HasPermission checks if the user has a specific permission based on role
func (u *User) HasPermission(permission string) bool {
	switch u.Role {
	case UserRoleAdmin:
		return true // Admin has all permissions
	case UserRoleOperator:
		// Operators can read and execute safe operations
		return permission == "read" || permission == "execute-safe" || permission == "create-session"
	case UserRoleViewer:
		// Viewers can only read
		return permission == "read" || permission == "create-session"
	default:
		return false
	}
}

// IsSessionValid checks if a specific session is still valid for the user
func (u *User) IsSessionValid(sessionID string) bool {
	if u.IsLocked || !u.IsActive {
		return false
	}
	
	// Check if session is in active sessions list
	for _, id := range u.ActiveSessions {
		if id == sessionID {
			return true
		}
	}
	
	return false
}

// GetKubernetesGroups returns the Kubernetes groups for RBAC
func (u *User) GetKubernetesGroups() []string {
	groups := make([]string, 0, len(u.KubernetesGroups)+len(u.OIDCAttributes.Groups))
	
	// Add configured Kubernetes groups
	groups = append(groups, u.KubernetesGroups...)
	
	// Add OIDC groups if they exist
	groups = append(groups, u.OIDCAttributes.Groups...)
	
	// Remove duplicates
	return removeDuplicates(groups)
}

// Validate checks if the user data is valid
func (u *User) Validate() error {
	if u.Email == "" {
		return fmt.Errorf("email is required")
	}
	
	if u.Name == "" {
		return fmt.Errorf("name is required")
	}
	
	if u.Role != UserRoleViewer && u.Role != UserRoleOperator && u.Role != UserRoleAdmin {
		return fmt.Errorf("invalid role: %s", u.Role)
	}
	
	// Validate OIDC attributes if present
	if u.OIDCAttributes.Provider != "" {
		if u.OIDCAttributes.Subject == "" {
			return fmt.Errorf("OIDC subject is required when provider is set")
		}
		if u.OIDCAttributes.Issuer == "" {
			return fmt.Errorf("OIDC issuer is required when provider is set")
		}
	}
	
	return nil
}

// ToJSON serializes the user to JSON
func (u *User) ToJSON() ([]byte, error) {
	return json.Marshal(u)
}

// FromJSON deserializes a user from JSON
func (u *User) FromJSON(data []byte) error {
	return json.Unmarshal(data, u)
}

// Helper functions

func isStandardClaim(claim string) bool {
	standardClaims := map[string]bool{
		"iss":            true,
		"sub":            true,
		"aud":            true,
		"exp":            true,
		"nbf":            true,
		"iat":            true,
		"jti":            true,
		"email":          true,
		"email_verified": true,
		"name":           true,
		"given_name":     true,
		"family_name":    true,
		"picture":        true,
		"groups":         true,
	}
	
	return standardClaims[claim]
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

// UserService interface defines operations for user management
type UserService interface {
	CreateUser(user *User) error
	GetUser(id string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUser(user *User) error
	DeleteUser(id string) error
	ListUsers() ([]*User, error)
	AuthenticateUser(email, password string) (*User, error)
	UpdateUserFromOIDC(userID string, claims map[string]interface{}, provider string) error
}

// MemoryUserService is a simple in-memory implementation of UserService
type MemoryUserService struct {
	users map[string]*User
}

// NewMemoryUserService creates a new in-memory user service
func NewMemoryUserService() *MemoryUserService {
	return &MemoryUserService{
		users: make(map[string]*User),
	}
}

// CreateUser creates a new user
func (s *MemoryUserService) CreateUser(user *User) error {
	if err := user.Validate(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}
	
	if user.ID == "" {
		user.ID = generateUserID()
	}
	
	// Check if user already exists
	if _, exists := s.users[user.ID]; exists {
		return fmt.Errorf("user with ID %s already exists", user.ID)
	}
	
	// Check if email already exists
	for _, existingUser := range s.users {
		if existingUser.Email == user.Email {
			return fmt.Errorf("user with email %s already exists", user.Email)
		}
	}
	
	s.users[user.ID] = user
	return nil
}

// GetUser retrieves a user by ID
func (s *MemoryUserService) GetUser(id string) (*User, error) {
	user, exists := s.users[id]
	if !exists {
		return nil, fmt.Errorf("user with ID %s not found", id)
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email address
func (s *MemoryUserService) GetUserByEmail(email string) (*User, error) {
	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user with email %s not found", email)
}

// UpdateUser updates an existing user
func (s *MemoryUserService) UpdateUser(user *User) error {
	if err := user.Validate(); err != nil {
		return fmt.Errorf("user validation failed: %w", err)
	}
	
	if _, exists := s.users[user.ID]; !exists {
		return fmt.Errorf("user with ID %s not found", user.ID)
	}
	
	user.UpdatedAt = time.Now()
	s.users[user.ID] = user
	return nil
}

// DeleteUser deletes a user by ID
func (s *MemoryUserService) DeleteUser(id string) error {
	if _, exists := s.users[id]; !exists {
		return fmt.Errorf("user with ID %s not found", id)
	}
	
	delete(s.users, id)
	return nil
}

// ListUsers returns all users
func (s *MemoryUserService) ListUsers() ([]*User, error) {
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users, nil
}

// AuthenticateUser authenticates a user (placeholder - not used with OIDC)
func (s *MemoryUserService) AuthenticateUser(email, password string) (*User, error) {
	return nil, fmt.Errorf("password authentication not supported - use OIDC")
}

// UpdateUserFromOIDC updates user information from OIDC claims
func (s *MemoryUserService) UpdateUserFromOIDC(userID string, claims map[string]interface{}, provider string) error {
	user, exists := s.users[userID]
	if !exists {
		return fmt.Errorf("user with ID %s not found", userID)
	}
	
	return user.UpdateFromOIDC(claims, provider)
}

// Helper function to generate user IDs
func generateUserID() string {
	return fmt.Sprintf("user-%d", time.Now().UnixNano())
}