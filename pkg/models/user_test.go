package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUser(t *testing.T) {
	email := "test@example.com"
	name := "Test User"
	role := UserRoleOperator

	user := NewUser(email, name, role)

	assert.Equal(t, email, user.Email)
	assert.Equal(t, name, user.Name)
	assert.Equal(t, role, user.Role)
	assert.True(t, user.IsActive)
	assert.False(t, user.IsLocked)
	assert.NotZero(t, user.CreatedAt)
	assert.NotZero(t, user.UpdatedAt)
	assert.Equal(t, "light", user.Preferences.Theme)
	assert.Equal(t, "en", user.Preferences.Language)
	assert.Equal(t, 480, user.Preferences.SessionTimeout) // 8 hours in minutes
	assert.True(t, user.Preferences.NotificationsEnabled)
	assert.NotNil(t, user.KubernetesGroups)
	assert.NotNil(t, user.ActiveSessions)
	assert.NotNil(t, user.LoginHistory)
}

func TestUserValidation(t *testing.T) {
	tests := []struct {
		name        string
		user        User
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid user",
			user: User{
				Email: "test@example.com",
				Name:  "Test User",
				Role:  UserRoleOperator,
			},
			expectError: false,
		},
		{
			name: "missing email",
			user: User{
				Name: "Test User",
				Role: UserRoleOperator,
			},
			expectError: true,
			errorMsg:    "email is required",
		},
		{
			name: "missing name",
			user: User{
				Email: "test@example.com",
				Role:  UserRoleOperator,
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "invalid role",
			user: User{
				Email: "test@example.com",
				Name:  "Test User",
				Role:  UserRole("invalid"),
			},
			expectError: true,
			errorMsg:    "invalid role",
		},
		{
			name: "OIDC attributes with missing subject",
			user: User{
				Email: "test@example.com",
				Name:  "Test User",
				Role:  UserRoleOperator,
				OIDCAttributes: OIDCAttributes{
					Provider: "google",
					Issuer:   "https://accounts.google.com",
					// Missing Subject
				},
			},
			expectError: true,
			errorMsg:    "OIDC subject is required",
		},
		{
			name: "OIDC attributes with missing issuer",
			user: User{
				Email: "test@example.com",
				Name:  "Test User",
				Role:  UserRoleOperator,
				OIDCAttributes: OIDCAttributes{
					Provider: "google",
					Subject:  "user123",
					// Missing Issuer
				},
			},
			expectError: true,
			errorMsg:    "OIDC issuer is required",
		},
		{
			name: "complete OIDC attributes",
			user: User{
				Email: "test@example.com",
				Name:  "Test User",
				Role:  UserRoleOperator,
				OIDCAttributes: OIDCAttributes{
					Provider: "google",
					Subject:  "user123",
					Issuer:   "https://accounts.google.com",
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.user.Validate()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUpdateFromOIDC(t *testing.T) {
	user := NewUser("old@example.com", "Old Name", UserRoleViewer)
	
	claims := map[string]interface{}{
		"sub":            "user-123",
		"iss":            "https://accounts.google.com",
		"email":          "new@example.com",
		"email_verified": true,
		"name":           "New Name",
		"given_name":     "New",
		"family_name":    "Name",
		"picture":        "https://example.com/photo.jpg",
		"groups":         []string{"admin", "users"},
		"custom_claim":   "custom_value",
	}

	err := user.UpdateFromOIDC(claims, "google")
	require.NoError(t, err)

	// Test updated basic info
	assert.Equal(t, "new@example.com", user.Email)
	assert.Equal(t, "New Name", user.Name)

	// Test OIDC attributes
	assert.Equal(t, "google", user.OIDCAttributes.Provider)
	assert.Equal(t, "user-123", user.OIDCAttributes.Subject)
	assert.Equal(t, "https://accounts.google.com", user.OIDCAttributes.Issuer)
	assert.True(t, user.OIDCAttributes.EmailVerified)
	assert.Equal(t, "New", user.OIDCAttributes.GivenName)
	assert.Equal(t, "Name", user.OIDCAttributes.FamilyName)
	assert.Equal(t, "https://example.com/photo.jpg", user.OIDCAttributes.Picture)
	assert.Equal(t, []string{"admin", "users"}, user.OIDCAttributes.Groups)
	assert.Equal(t, "custom_value", user.OIDCAttributes.CustomClaims["custom_claim"])

	// Test that standard claims are not in custom claims
	_, exists := user.OIDCAttributes.CustomClaims["email"]
	assert.False(t, exists)
}

func TestUpdateFromOIDCGroupsHandling(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleViewer)

	tests := []struct {
		name     string
		groups   interface{}
		expected []string
	}{
		{
			name:     "string array groups",
			groups:   []string{"admin", "users"},
			expected: []string{"admin", "users"},
		},
		{
			name:     "interface array groups",
			groups:   []interface{}{"admin", "users", "developers"},
			expected: []string{"admin", "users", "developers"},
		},
		{
			name:     "single string group",
			groups:   "admin",
			expected: []string{"admin"},
		},
		{
			name:     "no groups",
			groups:   nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]interface{}{
				"sub":   "user-123",
				"iss":   "https://accounts.google.com",
				"email": "test@example.com",
			}

			if tt.groups != nil {
				claims["groups"] = tt.groups
			}

			err := user.UpdateFromOIDC(claims, "google")
			require.NoError(t, err)

			if tt.expected == nil {
				assert.Empty(t, user.OIDCAttributes.Groups)
			} else {
				assert.Equal(t, tt.expected, user.OIDCAttributes.Groups)
			}
		})
	}
}

func TestAddLoginRecord(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	initialTime := time.Now()

	// Add successful login
	successRecord := LoginRecord{
		SessionID:   "session-1",
		LoginTime:   initialTime,
		IPAddress:   "192.168.1.1",
		UserAgent:   "Mozilla/5.0",
		Provider:    "google",
		MFAUsed:     true,
		Success:     true,
	}
	user.AddLoginRecord(successRecord)

	assert.Len(t, user.LoginHistory, 1)
	assert.Equal(t, successRecord, user.LoginHistory[0])
	assert.Equal(t, initialTime, user.LastLogin)
	assert.Equal(t, 0, user.FailedLoginCount)

	// Add failed login
	failedRecord := LoginRecord{
		SessionID:     "session-2",
		LoginTime:     initialTime.Add(time.Minute),
		IPAddress:     "192.168.1.1",
		UserAgent:     "Mozilla/5.0",
		Provider:      "google",
		Success:       false,
		FailureReason: "Invalid credentials",
	}
	user.AddLoginRecord(failedRecord)

	assert.Len(t, user.LoginHistory, 2)
	assert.Equal(t, failedRecord, user.LoginHistory[0]) // Latest first
	assert.Equal(t, successRecord, user.LoginHistory[1])
	assert.Equal(t, initialTime, user.LastLogin) // Should not change for failed login
	assert.Equal(t, 1, user.FailedLoginCount)
	assert.Equal(t, initialTime.Add(time.Minute), user.LastFailedLogin)
}

func TestAddLoginRecordAccountLocking(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)

	// Add 5 failed login attempts
	for i := 0; i < 5; i++ {
		failedRecord := LoginRecord{
			SessionID:     "session-" + string(rune(i)),
			LoginTime:     time.Now().Add(time.Duration(i) * time.Minute),
			Success:       false,
			FailureReason: "Invalid credentials",
		}
		user.AddLoginRecord(failedRecord)
	}

	assert.Equal(t, 5, user.FailedLoginCount)
	assert.True(t, user.IsLocked)

	// Add successful login should unlock and reset counter
	successRecord := LoginRecord{
		SessionID: "session-success",
		LoginTime: time.Now().Add(10 * time.Minute),
		Success:   true,
	}
	user.AddLoginRecord(successRecord)

	assert.Equal(t, 0, user.FailedLoginCount)
	// Note: IsLocked doesn't automatically unlock on successful login in this implementation
}

func TestAddActiveSession(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)

	sessionID1 := "session-1"
	sessionID2 := "session-2"

	// Add first session
	user.AddActiveSession(sessionID1)
	assert.Contains(t, user.ActiveSessions, sessionID1)
	assert.Len(t, user.ActiveSessions, 1)

	// Add second session
	user.AddActiveSession(sessionID2)
	assert.Contains(t, user.ActiveSessions, sessionID1)
	assert.Contains(t, user.ActiveSessions, sessionID2)
	assert.Len(t, user.ActiveSessions, 2)

	// Try to add duplicate session
	user.AddActiveSession(sessionID1)
	assert.Len(t, user.ActiveSessions, 2) // Should not increase

	// Remove session
	user.RemoveActiveSession(sessionID1)
	assert.NotContains(t, user.ActiveSessions, sessionID1)
	assert.Contains(t, user.ActiveSessions, sessionID2)
	assert.Len(t, user.ActiveSessions, 1)
}

func TestHasPermission(t *testing.T) {
	tests := []struct {
		name       string
		role       UserRole
		permission string
		expected   bool
	}{
		{"admin can read", UserRoleAdmin, "read", true},
		{"admin can execute", UserRoleAdmin, "execute-safe", true},
		{"admin can do anything", UserRoleAdmin, "dangerous-operation", true},
		
		{"operator can read", UserRoleOperator, "read", true},
		{"operator can execute safe", UserRoleOperator, "execute-safe", true},
		{"operator can create session", UserRoleOperator, "create-session", true},
		{"operator cannot do dangerous", UserRoleOperator, "dangerous-operation", false},
		
		{"viewer can read", UserRoleViewer, "read", true},
		{"viewer can create session", UserRoleViewer, "create-session", true},
		{"viewer cannot execute", UserRoleViewer, "execute-safe", false},
		
		{"invalid role has no permissions", UserRole("invalid"), "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := NewUser("test@example.com", "Test User", tt.role)
			result := user.HasPermission(tt.permission)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSessionValid(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	sessionID := "session-123"

	// User is active and unlocked, but session not added
	assert.False(t, user.IsSessionValid(sessionID))

	// Add session
	user.AddActiveSession(sessionID)
	assert.True(t, user.IsSessionValid(sessionID))

	// Lock user
	user.IsLocked = true
	assert.False(t, user.IsSessionValid(sessionID))

	// Unlock but deactivate user
	user.IsLocked = false
	user.IsActive = false
	assert.False(t, user.IsSessionValid(sessionID))

	// Reactivate user
	user.IsActive = true
	assert.True(t, user.IsSessionValid(sessionID))
}

func TestGetKubernetesGroups(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	
	// Set Kubernetes groups
	user.KubernetesGroups = []string{"k8s-admin", "developers"}
	
	// Set OIDC groups
	user.OIDCAttributes.Groups = []string{"oidc-users", "developers"} // "developers" is duplicate
	
	groups := user.GetKubernetesGroups()
	
	// Should contain all groups with duplicates removed
	expectedGroups := []string{"k8s-admin", "developers", "oidc-users"}
	assert.ElementsMatch(t, expectedGroups, groups)
}

func TestUserJSONSerialization(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	user.OIDCAttributes = OIDCAttributes{
		Provider: "google",
		Subject:  "user-123",
		Issuer:   "https://accounts.google.com",
		Groups:   []string{"admin", "users"},
	}

	// Test ToJSON
	jsonData, err := user.ToJSON()
	require.NoError(t, err)
	require.NotEmpty(t, jsonData)

	// Verify JSON structure
	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)

	assert.Equal(t, "test@example.com", jsonMap["email"])
	assert.Equal(t, "Test User", jsonMap["name"])
	assert.Equal(t, string(UserRoleOperator), jsonMap["role"])

	// Test FromJSON
	var newUser User
	err = newUser.FromJSON(jsonData)
	require.NoError(t, err)

	assert.Equal(t, user.Email, newUser.Email)
	assert.Equal(t, user.Name, newUser.Name)
	assert.Equal(t, user.Role, newUser.Role)
	assert.Equal(t, user.OIDCAttributes.Provider, newUser.OIDCAttributes.Provider)
	assert.Equal(t, user.OIDCAttributes.Subject, newUser.OIDCAttributes.Subject)
}

func TestMemoryUserService(t *testing.T) {
	service := NewMemoryUserService()
	
	// Test CreateUser
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	err := service.CreateUser(user)
	require.NoError(t, err)
	assert.NotEmpty(t, user.ID)

	// Test duplicate email
	duplicateUser := NewUser("test@example.com", "Another User", UserRoleViewer)
	err = service.CreateUser(duplicateUser)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Test GetUser
	retrievedUser, err := service.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, retrievedUser.Email)

	// Test GetUserByEmail
	retrievedUser, err = service.GetUserByEmail("test@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID, retrievedUser.ID)

	// Test UpdateUser
	user.Name = "Updated Name"
	err = service.UpdateUser(user)
	require.NoError(t, err)

	retrievedUser, err = service.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", retrievedUser.Name)

	// Test ListUsers
	users, err := service.ListUsers()
	require.NoError(t, err)
	assert.Len(t, users, 1)

	// Test DeleteUser
	err = service.DeleteUser(user.ID)
	require.NoError(t, err)

	_, err = service.GetUser(user.ID)
	assert.Error(t, err)
}

func TestMemoryUserServiceErrors(t *testing.T) {
	service := NewMemoryUserService()

	// Test get non-existent user
	_, err := service.GetUser("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test get user by non-existent email
	_, err = service.GetUserByEmail("nonexistent@example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test update non-existent user
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	user.ID = "non-existent"
	err = service.UpdateUser(user)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test delete non-existent user
	err = service.DeleteUser("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test authenticate user (should fail - not supported)
	_, err = service.AuthenticateUser("test@example.com", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported")
}

func TestUpdateUserFromOIDC(t *testing.T) {
	service := NewMemoryUserService()
	
	// Create user
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	err := service.CreateUser(user)
	require.NoError(t, err)

	// Test UpdateUserFromOIDC
	claims := map[string]interface{}{
		"sub":   "user-123",
		"iss":   "https://accounts.google.com",
		"email": "updated@example.com",
		"name":  "Updated Name",
	}

	err = service.UpdateUserFromOIDC(user.ID, claims, "google")
	require.NoError(t, err)

	// Verify updates
	updatedUser, err := service.GetUser(user.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated@example.com", updatedUser.Email)
	assert.Equal(t, "Updated Name", updatedUser.Name)
	assert.Equal(t, "google", updatedUser.OIDCAttributes.Provider)

	// Test with non-existent user
	err = service.UpdateUserFromOIDC("non-existent", claims, "google")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestLoginHistoryLimit(t *testing.T) {
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	
	// Add 60 login records (more than the limit of 50)
	for i := 0; i < 60; i++ {
		record := LoginRecord{
			SessionID: "session-" + string(rune(i)),
			LoginTime: time.Now().Add(time.Duration(i) * time.Minute),
			Success:   true,
		}
		user.AddLoginRecord(record)
	}
	
	// Should only keep the last 50 records
	assert.Len(t, user.LoginHistory, 50)
	
	// The most recent record should be first
	assert.Equal(t, "session-"+string(rune(59)), user.LoginHistory[0].SessionID)
}

func TestUserPreferences(t *testing.T) {
	preferences := UserPreferences{
		Theme:                "dark",
		Language:             "es",
		DefaultNamespace:     "production",
		DefaultContext:       "prod-cluster",
		SessionTimeout:       240, // 4 hours
		NotificationsEnabled: false,
		CustomSettings: map[string]string{
			"editor_theme": "monokai",
			"font_size":    "14",
		},
	}
	
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	user.Preferences = preferences
	
	assert.Equal(t, "dark", user.Preferences.Theme)
	assert.Equal(t, "es", user.Preferences.Language)
	assert.Equal(t, "production", user.Preferences.DefaultNamespace)
	assert.Equal(t, "prod-cluster", user.Preferences.DefaultContext)
	assert.Equal(t, 240, user.Preferences.SessionTimeout)
	assert.False(t, user.Preferences.NotificationsEnabled)
	assert.Equal(t, "monokai", user.Preferences.CustomSettings["editor_theme"])
	assert.Equal(t, "14", user.Preferences.CustomSettings["font_size"])
}

func TestOIDCAttributes(t *testing.T) {
	now := time.Now()
	attributes := OIDCAttributes{
		Provider:         "okta",
		Subject:          "user-12345",
		Issuer:           "https://company.okta.com",
		Email:            "user@company.com",
		EmailVerified:    true,
		Name:             "John Doe",
		GivenName:        "John",
		FamilyName:       "Doe",
		Picture:          "https://company.okta.com/photo.jpg",
		Groups:           []string{"admin", "engineering", "full-time"},
		CustomClaims: map[string]interface{}{
			"employee_id": "EMP-12345",
			"department":  "Engineering",
			"title":       "Senior Software Engineer",
		},
		LastTokenRefresh: now,
		TokenExpiry:      now.Add(8 * time.Hour),
	}
	
	user := NewUser("test@example.com", "Test User", UserRoleOperator)
	user.OIDCAttributes = attributes
	
	assert.Equal(t, "okta", user.OIDCAttributes.Provider)
	assert.Equal(t, "user-12345", user.OIDCAttributes.Subject)
	assert.Equal(t, "https://company.okta.com", user.OIDCAttributes.Issuer)
	assert.True(t, user.OIDCAttributes.EmailVerified)
	assert.Contains(t, user.OIDCAttributes.Groups, "admin")
	assert.Equal(t, "EMP-12345", user.OIDCAttributes.CustomClaims["employee_id"])
	assert.Equal(t, "Engineering", user.OIDCAttributes.CustomClaims["department"])
}