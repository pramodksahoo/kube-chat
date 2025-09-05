package models

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChatSession(t *testing.T) {
	userID := "user-123"
	clusterContext := "prod-cluster"
	namespace := "default"

	session := NewChatSession(userID, clusterContext, namespace)

	assert.NotEmpty(t, session.ID)
	assert.Equal(t, userID, session.UserID)
	assert.Equal(t, clusterContext, session.ClusterContext)
	assert.Equal(t, namespace, session.Namespace)
	assert.Equal(t, SessionStatusActive, session.Status)
	assert.NotZero(t, session.CreatedAt)
	assert.NotZero(t, session.LastActivity)
	assert.True(t, session.ExpiresAt.After(session.CreatedAt))
	assert.NotNil(t, session.Messages)
	assert.NotNil(t, session.Commands)
	assert.Len(t, session.Messages, 0)
	assert.Len(t, session.Commands, 0)
}

func TestNewChatSessionWithAuth(t *testing.T) {
	userID := "user-123"
	clusterContext := "prod-cluster"
	namespace := "default"
	
	authContext := &SessionAuthContext{
		UserID:           userID,
		SessionID:        "session-456",
		AuthProvider:     "google",
		AuthenticatedAt:  time.Now(),
		TokenIssuedAt:    time.Now(),
		TokenExpiresAt:   time.Now().Add(4 * time.Hour), // Shorter than default session
		IPAddress:        "192.168.1.1",
		UserAgent:        "Mozilla/5.0",
		Permissions:      []string{"read", "execute"},
		IsValid:          true,
	}

	session := NewChatSessionWithAuth(userID, clusterContext, namespace, authContext)

	assert.NotEmpty(t, session.ID)
	assert.Equal(t, userID, session.UserID)
	assert.Equal(t, authContext, session.AuthContext)
	
	// Session expiry should be limited by auth token expiry
	assert.Equal(t, authContext.TokenExpiresAt, session.ExpiresAt)
}

func TestChatSessionAddMessage(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	initialActivity := session.LastActivity

	time.Sleep(time.Millisecond) // Ensure time difference

	message := ChatMessage{
		ID:        "msg-1",
		Role:      "user",
		Content:   "Hello, KubeChat!",
		Timestamp: time.Now(),
	}

	session.AddMessage(message)

	assert.Len(t, session.Messages, 1)
	assert.Equal(t, message, session.Messages[0])
	assert.True(t, session.LastActivity.After(initialActivity))
}

func TestChatSessionAddCommand(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	initialActivity := session.LastActivity

	time.Sleep(time.Millisecond)

	commandID := "cmd-123"
	session.AddCommand(commandID)

	assert.Len(t, session.Commands, 1)
	assert.Equal(t, commandID, session.Commands[0])
	assert.True(t, session.LastActivity.After(initialActivity))

	// Test execution history
	history := session.GetExecutionHistory()
	assert.Equal(t, []string{commandID}, history)
}

func TestChatSessionExpiration(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	
	// New session should not be expired
	assert.False(t, session.IsExpired())

	// Manually set expiration to past
	session.ExpiresAt = time.Now().Add(-time.Hour)
	assert.True(t, session.IsExpired())
}

func TestChatSessionTerminate(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	initialActivity := session.LastActivity

	time.Sleep(time.Millisecond)

	session.Terminate()

	assert.Equal(t, SessionStatusTerminated, session.Status)
	assert.True(t, session.LastActivity.After(initialActivity))
}

func TestChatSessionJSONSerialization(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	session.AddMessage(ChatMessage{
		ID:      "msg-1",
		Role:    "user",
		Content: "Test message",
	})

	// Test ToJSON
	jsonData, err := session.ToJSON()
	require.NoError(t, err)
	require.NotEmpty(t, jsonData)

	// Verify JSON structure
	var jsonMap map[string]interface{}
	err = json.Unmarshal(jsonData, &jsonMap)
	require.NoError(t, err)

	assert.Equal(t, session.UserID, jsonMap["userId"])
	assert.Equal(t, session.ClusterContext, jsonMap["clusterContext"])
	assert.Equal(t, session.Namespace, jsonMap["namespace"])

	// Test FromJSON
	var newSession ChatSession
	err = newSession.FromJSON(jsonData)
	require.NoError(t, err)

	assert.Equal(t, session.ID, newSession.ID)
	assert.Equal(t, session.UserID, newSession.UserID)
	assert.Equal(t, session.ClusterContext, newSession.ClusterContext)
	assert.Len(t, newSession.Messages, 1)
}

func TestSessionAuthContext(t *testing.T) {
	now := time.Now()
	authContext := &SessionAuthContext{
		UserID:           "user-123",
		SessionID:        "session-456",
		AuthProvider:     "okta",
		AuthenticatedAt:  now,
		TokenIssuedAt:    now,
		TokenExpiresAt:   now.Add(8 * time.Hour),
		RefreshTokenID:   "refresh-789",
		IPAddress:        "10.0.0.1",
		UserAgent:        "KubeChat-CLI/1.0",
		Permissions:      []string{"read", "execute-safe", "create-session"},
		KubernetesContext: "production",
		LastActivity:     now,
		IsValid:          true,
	}

	session := NewChatSession("user-123", "cluster", "default")
	session.SetAuthContext(authContext)

	assert.Equal(t, authContext, session.GetAuthContext())
	assert.True(t, session.IsAuthenticated())
	assert.Equal(t, []string{"read", "execute-safe", "create-session"}, session.GetUserPermissions())
	assert.True(t, session.HasPermission("read"))
	assert.True(t, session.HasPermission("execute-safe"))
	assert.False(t, session.HasPermission("admin"))
}

func TestSessionAuthentication(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	
	// Session without auth context should not be authenticated
	assert.False(t, session.IsAuthenticated())

	// Add auth context
	authContext := &SessionAuthContext{
		UserID:         "user-123",
		TokenExpiresAt: time.Now().Add(time.Hour),
		IsValid:        true,
	}
	session.SetAuthContext(authContext)
	assert.True(t, session.IsAuthenticated())

	// Invalid auth context
	authContext.IsValid = false
	assert.False(t, session.IsAuthenticated())

	// Expired token
	authContext.IsValid = true
	authContext.TokenExpiresAt = time.Now().Add(-time.Hour)
	assert.False(t, session.IsAuthenticated())
}

func TestSessionAuthPermissions(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	authContext := &SessionAuthContext{
		UserID:         "user-123",
		TokenExpiresAt: time.Now().Add(time.Hour),
		IsValid:        true,
		Permissions:    []string{"read", "execute-safe"},
	}
	session.SetAuthContext(authContext)

	assert.True(t, session.HasPermission("read"))
	assert.True(t, session.HasPermission("execute-safe"))
	assert.False(t, session.HasPermission("admin"))
	assert.False(t, session.HasPermission("delete"))

	// Without authentication, should have no permissions
	session.InvalidateAuth()
	assert.False(t, session.HasPermission("read"))
}

func TestSessionKubernetesContext(t *testing.T) {
	session := NewChatSession("user-123", "original-cluster", "default")
	
	// Without auth context, should return cluster context
	assert.Equal(t, "original-cluster", session.GetKubernetesContext())

	// With auth context
	authContext := &SessionAuthContext{
		KubernetesContext: "auth-cluster",
		IsValid:           true,
		TokenExpiresAt:    time.Now().Add(time.Hour),
	}
	session.SetAuthContext(authContext)
	assert.Equal(t, "auth-cluster", session.GetKubernetesContext())

	// Update Kubernetes context
	session.SetKubernetesContext("new-cluster")
	assert.Equal(t, "new-cluster", session.GetKubernetesContext())
	assert.Equal(t, "new-cluster", session.ClusterContext)
	assert.Equal(t, "new-cluster", session.AuthContext.KubernetesContext)
}

func TestSessionLifetime(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	
	// Without auth context, should return session expiry
	sessionLifetime := session.GetSessionLifetime()
	expectedLifetime := time.Until(session.ExpiresAt)
	assert.InDelta(t, expectedLifetime.Seconds(), sessionLifetime.Seconds(), 1.0)

	// With auth context that expires sooner
	authContext := &SessionAuthContext{
		TokenExpiresAt: time.Now().Add(2 * time.Hour),
		IsValid:        true,
	}
	session.SetAuthContext(authContext)
	
	authLifetime := session.GetSessionLifetime()
	expectedAuthLifetime := time.Until(authContext.TokenExpiresAt)
	assert.InDelta(t, expectedAuthLifetime.Seconds(), authLifetime.Seconds(), 1.0)
}

func TestRefreshAuthToken(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	authContext := &SessionAuthContext{
		TokenExpiresAt: time.Now().Add(time.Hour),
		RefreshTokenID: "old-refresh",
		IsValid:        true,
	}
	session.SetAuthContext(authContext)

	newExpiry := time.Now().Add(8 * time.Hour)
	newRefreshToken := "new-refresh"

	session.RefreshAuthToken(newExpiry, newRefreshToken)

	assert.Equal(t, newExpiry, session.AuthContext.TokenExpiresAt)
	assert.Equal(t, newRefreshToken, session.AuthContext.RefreshTokenID)
}

func TestChatSessionManager(t *testing.T) {
	manager := NewChatSessionManager()

	// Test CreateSession
	session := manager.CreateSession("user-123", "cluster", "default")
	assert.NotNil(t, session)
	assert.NotEmpty(t, session.ID)

	// Test GetSession
	retrievedSession, err := manager.GetSession(session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrievedSession.ID)

	// Test UpdateSession
	session.Namespace = "updated-namespace"
	err = manager.UpdateSession(session)
	require.NoError(t, err)

	retrievedSession, err = manager.GetSession(session.ID)
	require.NoError(t, err)
	assert.Equal(t, "updated-namespace", retrievedSession.Namespace)

	// Test GetActiveSessions
	activeSessions := manager.GetActiveSessions("user-123")
	assert.Len(t, activeSessions, 1)

	// Create another session for different user
	manager.CreateSession("user-456", "cluster", "default")
	activeSessions = manager.GetActiveSessions("user-123")
	assert.Len(t, activeSessions, 1) // Should still be 1

	activeSessions = manager.GetActiveSessions("user-456")
	assert.Len(t, activeSessions, 1)

	// Test DeleteSession
	err = manager.DeleteSession(session.ID)
	require.NoError(t, err)

	_, err = manager.GetSession(session.ID)
	assert.Error(t, err)
}

func TestChatSessionManagerErrors(t *testing.T) {
	manager := NewChatSessionManager()

	// Test get non-existent session
	_, err := manager.GetSession("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test update nil session
	err = manager.UpdateSession(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be nil")
}

func TestCleanupExpiredSessions(t *testing.T) {
	manager := NewChatSessionManager()

	// Create sessions with different expiration times
	activeSession := manager.CreateSession("user-1", "cluster", "default")
	expiredSession := manager.CreateSession("user-2", "cluster", "default")
	
	// Manually expire one session
	expiredSession.ExpiresAt = time.Now().Add(-time.Hour)
	manager.UpdateSession(expiredSession)

	// Cleanup expired sessions
	cleaned := manager.CleanupExpiredSessions()
	assert.Equal(t, 1, cleaned)

	// Active session should still exist
	_, err := manager.GetSession(activeSession.ID)
	assert.NoError(t, err)

	// Expired session should be removed
	_, err = manager.GetSession(expiredSession.ID)
	assert.Error(t, err)
}

func TestExtendedChatSessionManager(t *testing.T) {
	manager := NewExtendedChatSessionManager()

	authContext := &SessionAuthContext{
		UserID:         "user-123",
		SessionID:      "session-456",
		AuthProvider:   "google",
		TokenExpiresAt: time.Now().Add(8 * time.Hour),
		IsValid:        true,
		Permissions:    []string{"read", "execute"},
	}

	// Test CreateAuthenticatedSession
	session := manager.CreateAuthenticatedSession("user-123", "cluster", "default", authContext)
	assert.NotNil(t, session)
	assert.True(t, session.IsAuthenticated())

	// Test GetAuthenticatedSession
	retrievedSession, err := manager.GetAuthenticatedSession(session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrievedSession.ID)

	// Test GetUserAuthenticatedSessions
	authSessions := manager.GetUserAuthenticatedSessions("user-123")
	assert.Len(t, authSessions, 1)

	// Invalidate authentication
	session.InvalidateAuth()
	manager.UpdateSession(session)

	// Should no longer be returned as authenticated
	_, err = manager.GetAuthenticatedSession(session.ID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not authenticated")

	authSessions = manager.GetUserAuthenticatedSessions("user-123")
	assert.Len(t, authSessions, 0)
}

func TestCleanupUnauthenticatedSessions(t *testing.T) {
	manager := NewExtendedChatSessionManager()

	// Create authenticated session
	authContext := &SessionAuthContext{
		UserID:         "user-123",
		TokenExpiresAt: time.Now().Add(8 * time.Hour),
		IsValid:        true,
	}
	authSession := manager.CreateAuthenticatedSession("user-123", "cluster", "default", authContext)

	// Create unauthenticated session
	unauthSession := manager.CreateSession("user-456", "cluster", "default")

	// Cleanup unauthenticated sessions
	cleaned := manager.CleanupUnauthenticatedSessions()
	assert.Equal(t, 1, cleaned)

	// Authenticated session should still exist
	_, err := manager.GetAuthenticatedSession(authSession.ID)
	assert.NoError(t, err)

	// Unauthenticated session should be removed
	_, err = manager.GetSession(unauthSession.ID)
	assert.Error(t, err)
}

func TestSessionWithExpiredAuth(t *testing.T) {
	manager := NewExtendedChatSessionManager()

	// Create session with expired auth
	authContext := &SessionAuthContext{
		UserID:         "user-123",
		TokenExpiresAt: time.Now().Add(-time.Hour), // Expired
		IsValid:        true,
	}
	session := manager.CreateAuthenticatedSession("user-123", "cluster", "default", authContext)

	// Should not be considered authenticated
	assert.False(t, session.IsAuthenticated())

	// Should be cleaned up as unauthenticated
	cleaned := manager.CleanupUnauthenticatedSessions()
	assert.Equal(t, 1, cleaned)
}

func TestUpdateAuthActivity(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	authContext := &SessionAuthContext{
		UserID:         "user-123",
		TokenExpiresAt: time.Now().Add(time.Hour),
		IsValid:        true,
		LastActivity:   time.Now().Add(-time.Hour),
	}
	session.SetAuthContext(authContext)

	initialActivity := authContext.LastActivity
	time.Sleep(time.Millisecond)

	session.UpdateAuthActivity()

	assert.True(t, session.AuthContext.LastActivity.After(initialActivity))
}

func TestChatMessageWithExecution(t *testing.T) {
	message := ChatMessage{
		ID:        "msg-1",
		Role:      "user",
		Content:   "Get all pods",
		Timestamp: time.Now(),
		CommandGenerated: &KubernetesCommand{
			ID:               "cmd-1",
			GeneratedCommand: "kubectl get pods",
			RiskLevel:        "safe",
		},
	}

	session := NewChatSession("user-123", "cluster", "default")
	session.AddMessage(message)

	assert.Len(t, session.Messages, 1)
	assert.NotNil(t, session.Messages[0].CommandGenerated)
	assert.Equal(t, "kubectl get pods", session.Messages[0].CommandGenerated.GeneratedCommand)
}

func TestSessionStatusTransitions(t *testing.T) {
	session := NewChatSession("user-123", "cluster", "default")
	
	// Initial status
	assert.Equal(t, SessionStatusActive, session.Status)

	// Set to processing
	session.Status = SessionStatusProcessing
	assert.Equal(t, SessionStatusProcessing, session.Status)

	// Terminate
	session.Terminate()
	assert.Equal(t, SessionStatusTerminated, session.Status)

	// Check expired session status is set by manager
	expiredSession := NewChatSession("user-456", "cluster", "default")
	expiredSession.ExpiresAt = time.Now().Add(-time.Hour)
	
	manager := NewChatSessionManager()
	manager.sessions[expiredSession.ID] = expiredSession
	
	retrieved, err := manager.GetSession(expiredSession.ID)
	require.NoError(t, err)
	assert.Equal(t, SessionStatusExpired, retrieved.Status)
}