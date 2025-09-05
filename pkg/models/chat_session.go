package models

import (
	"encoding/json"
	"fmt"
	"time"
)

// SessionStatus represents the status of a chat session
type SessionStatus string

const (
	SessionStatusActive     SessionStatus = "active"
	SessionStatusProcessing SessionStatus = "processing"
	SessionStatusExpired    SessionStatus = "expired"
	SessionStatusTerminated SessionStatus = "terminated"
)

// ChatMessage represents a message in a chat session
type ChatMessage struct {
	ID                string                  `json:"id"`
	Role              string                  `json:"role"` // 'user', 'assistant', 'system'
	Content           string                  `json:"content"`
	Timestamp         time.Time               `json:"timestamp"`
	CommandGenerated  *KubernetesCommand      `json:"commandGenerated,omitempty"`
	ExecutionResult   *CommandExecutionResult `json:"executionResult,omitempty"`
}

// ChatSession represents a conversational chat session with command execution history
type ChatSession struct {
	ID             string               `json:"id"`
	UserID         string               `json:"userId"`
	ClusterContext string               `json:"clusterContext"`
	Namespace      string               `json:"namespace"`
	Messages       []ChatMessage        `json:"messages"`
	Commands       []string             `json:"commands"`       // Command IDs for execution history
	Status         SessionStatus        `json:"status"`
	CreatedAt      time.Time            `json:"createdAt"`
	LastActivity   time.Time            `json:"lastActivity"`
	ExpiresAt      time.Time            `json:"expiresAt"`
	ContextData    *SessionContext      `json:"contextData,omitempty"`    // Conversational context
	AuthContext    *SessionAuthContext  `json:"authContext,omitempty"`    // NEW: Authentication context
}

// NewChatSession creates a new chat session with default values
func NewChatSession(userID, clusterContext, namespace string) *ChatSession {
	now := time.Now()
	return &ChatSession{
		ID:             generateSessionID(),
		UserID:         userID,
		ClusterContext: clusterContext,
		Namespace:      namespace,
		Messages:       make([]ChatMessage, 0),
		Commands:       make([]string, 0),
		Status:         SessionStatusActive,
		CreatedAt:      now,
		LastActivity:   now,
		ExpiresAt:      now.Add(24 * time.Hour), // Sessions expire after 24 hours
	}
}

// AddMessage adds a message to the chat session
func (cs *ChatSession) AddMessage(message ChatMessage) {
	cs.Messages = append(cs.Messages, message)
	cs.LastActivity = time.Now()
}

// AddCommand adds a command ID to the session's execution history
func (cs *ChatSession) AddCommand(commandID string) {
	cs.Commands = append(cs.Commands, commandID)
	cs.LastActivity = time.Now()
}

// GetExecutionHistory returns command IDs from this session
func (cs *ChatSession) GetExecutionHistory() []string {
	return cs.Commands
}

// IsExpired checks if the session has expired
func (cs *ChatSession) IsExpired() bool {
	return time.Now().After(cs.ExpiresAt)
}

// UpdateActivity updates the last activity timestamp
func (cs *ChatSession) UpdateActivity() {
	cs.LastActivity = time.Now()
}

// Terminate marks the session as terminated
func (cs *ChatSession) Terminate() {
	cs.Status = SessionStatusTerminated
	cs.LastActivity = time.Now()
}

// ToJSON serializes the ChatSession to JSON bytes
func (cs *ChatSession) ToJSON() ([]byte, error) {
	return json.Marshal(cs)
}

// FromJSON deserializes JSON bytes to ChatSession
func (cs *ChatSession) FromJSON(data []byte) error {
	return json.Unmarshal(data, cs)
}

// generateSessionID generates a unique session ID
func generateSessionID() string {
	// Use UUID for session ID generation
	return "session-" + time.Now().Format("20060102-150405") + "-" + generateRandomString(8)
}

// generateRandomString generates a random string of specified length
func generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(result)
}

// ChatSessionManager manages chat sessions
type ChatSessionManager struct {
	sessions map[string]*ChatSession
}

// NewChatSessionManager creates a new chat session manager
func NewChatSessionManager() *ChatSessionManager {
	return &ChatSessionManager{
		sessions: make(map[string]*ChatSession),
	}
}

// CreateSession creates a new chat session
func (csm *ChatSessionManager) CreateSession(userID, clusterContext, namespace string) *ChatSession {
	session := NewChatSession(userID, clusterContext, namespace)
	csm.sessions[session.ID] = session
	return session
}

// GetSession retrieves a chat session by ID
func (csm *ChatSessionManager) GetSession(sessionID string) (*ChatSession, error) {
	session, exists := csm.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}
	
	if session.IsExpired() {
		session.Status = SessionStatusExpired
	}
	
	return session, nil
}

// UpdateSession updates a chat session
func (csm *ChatSessionManager) UpdateSession(session *ChatSession) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	csm.sessions[session.ID] = session
	return nil
}

// DeleteSession removes a chat session
func (csm *ChatSessionManager) DeleteSession(sessionID string) error {
	delete(csm.sessions, sessionID)
	return nil
}

// GetActiveSessions returns all active sessions for a user
func (csm *ChatSessionManager) GetActiveSessions(userID string) []*ChatSession {
	var activeSessions []*ChatSession
	
	for _, session := range csm.sessions {
		if session.UserID == userID && session.Status == SessionStatusActive && !session.IsExpired() {
			activeSessions = append(activeSessions, session)
		}
	}
	
	return activeSessions
}

// CleanupExpiredSessions removes expired sessions
func (csm *ChatSessionManager) CleanupExpiredSessions() int {
	expiredCount := 0
	var expiredSessions []string
	
	for sessionID, session := range csm.sessions {
		if session.IsExpired() {
			expiredSessions = append(expiredSessions, sessionID)
			expiredCount++
		}
	}
	
	for _, sessionID := range expiredSessions {
		delete(csm.sessions, sessionID)
	}
	
	return expiredCount
}

// Context-related methods for ChatSession

// InitializeContext initializes the session context if not already present
func (cs *ChatSession) InitializeContext() {
	if cs.ContextData == nil {
		cs.ContextData = NewSessionContext()
	}
}

// GetContext returns the session context, initializing if necessary
func (cs *ChatSession) GetContext() *SessionContext {
	cs.InitializeContext()
	return cs.ContextData
}

// UpdateContextFromCommandResult updates session context from a command execution result
func (cs *ChatSession) UpdateContextFromCommandResult(commandID string, result *CommandExecutionResult) error {
	if result == nil {
		return fmt.Errorf("command execution result cannot be nil")
	}
	
	cs.InitializeContext()
	cs.ContextData.LastCommandID = commandID
	cs.ContextData.ExtendExpiry(30 * time.Minute) // Extend context expiry
	
	// Parse command output and extract entities would be implemented here
	// This is a placeholder for the entity extraction logic
	// The actual extraction will be implemented in the entity extractor service
	
	cs.UpdateActivity()
	return nil
}

// AddContextEntity adds a context entity to the session
func (cs *ChatSession) AddContextEntity(entity ContextEntity) {
	cs.InitializeContext()
	cs.ContextData.AddEntity(entity)
	cs.UpdateActivity()
}

// AddContextReference adds a referenceable item to the session context
func (cs *ChatSession) AddContextReference(item ReferenceItem) {
	cs.InitializeContext()
	cs.ContextData.AddReferenceItem(item)
	cs.UpdateActivity()
}

// ResolveReference resolves a conversational reference to a resource
func (cs *ChatSession) ResolveReference(reference string) (*ReferenceItem, error) {
	if cs.ContextData == nil || cs.ContextData.IsExpired() {
		return nil, fmt.Errorf("no active context available for reference resolution")
	}
	
	return cs.ContextData.GetEntityByReference(reference)
}

// ClearContext clears the session context
func (cs *ChatSession) ClearContext() {
	if cs.ContextData != nil {
		cs.ContextData.Clear()
	}
	cs.UpdateActivity()
}

// HasActiveContext checks if the session has active, non-expired context
func (cs *ChatSession) HasActiveContext() bool {
	return cs.ContextData != nil && !cs.ContextData.IsExpired()
}

// GetContextSummary returns a summary of available references for user feedback
func (cs *ChatSession) GetContextSummary() map[string][]string {
	if cs.ContextData == nil || cs.ContextData.IsExpired() {
		return make(map[string][]string)
	}
	
	return cs.ContextData.GetAvailableReferences()
}

// Authentication context methods

// SetAuthContext sets the authentication context for the session
func (cs *ChatSession) SetAuthContext(authContext *SessionAuthContext) {
	cs.AuthContext = authContext
	cs.UpdateActivity()
}

// GetAuthContext returns the authentication context
func (cs *ChatSession) GetAuthContext() *SessionAuthContext {
	return cs.AuthContext
}

// IsAuthenticated checks if the session has valid authentication
func (cs *ChatSession) IsAuthenticated() bool {
	if cs.AuthContext == nil {
		return false
	}
	
	// Check if auth context is valid
	if !cs.AuthContext.IsValid {
		return false
	}
	
	// Check if token is still valid
	if time.Now().After(cs.AuthContext.TokenExpiresAt) {
		cs.AuthContext.IsValid = false
		return false
	}
	
	return true
}

// UpdateAuthActivity updates the authentication last activity timestamp
func (cs *ChatSession) UpdateAuthActivity() {
	if cs.AuthContext != nil {
		cs.AuthContext.LastActivity = time.Now()
	}
	cs.UpdateActivity()
}

// InvalidateAuth invalidates the authentication context
func (cs *ChatSession) InvalidateAuth() {
	if cs.AuthContext != nil {
		cs.AuthContext.IsValid = false
	}
	cs.UpdateActivity()
}

// GetUserPermissions returns the user permissions for this session
func (cs *ChatSession) GetUserPermissions() []string {
	if cs.AuthContext == nil {
		return []string{}
	}
	return cs.AuthContext.Permissions
}

// HasPermission checks if the session has a specific permission
func (cs *ChatSession) HasPermission(permission string) bool {
	if !cs.IsAuthenticated() {
		return false
	}
	
	for _, perm := range cs.AuthContext.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// GetKubernetesContext returns the current Kubernetes context
func (cs *ChatSession) GetKubernetesContext() string {
	if cs.AuthContext != nil && cs.AuthContext.KubernetesContext != "" {
		return cs.AuthContext.KubernetesContext
	}
	return cs.ClusterContext
}

// SetKubernetesContext updates the Kubernetes context for the session
func (cs *ChatSession) SetKubernetesContext(context string) {
	if cs.AuthContext != nil {
		cs.AuthContext.KubernetesContext = context
	}
	cs.ClusterContext = context
	cs.UpdateActivity()
}

// GetSessionLifetime returns the remaining session lifetime
func (cs *ChatSession) GetSessionLifetime() time.Duration {
	if cs.AuthContext != nil {
		tokenLifetime := time.Until(cs.AuthContext.TokenExpiresAt)
		sessionLifetime := time.Until(cs.ExpiresAt)
		
		// Return the shorter of the two
		if tokenLifetime < sessionLifetime {
			return tokenLifetime
		}
		return sessionLifetime
	}
	return time.Until(cs.ExpiresAt)
}

// RefreshAuthToken updates the authentication token information
func (cs *ChatSession) RefreshAuthToken(newTokenExpiresAt time.Time, newRefreshTokenID string) {
	if cs.AuthContext != nil {
		cs.AuthContext.TokenExpiresAt = newTokenExpiresAt
		cs.AuthContext.RefreshTokenID = newRefreshTokenID
		cs.AuthContext.LastActivity = time.Now()
	}
	cs.UpdateActivity()
}

// CreateSessionWithAuth creates a new chat session with authentication context
func NewChatSessionWithAuth(userID, clusterContext, namespace string, authContext *SessionAuthContext) *ChatSession {
	session := NewChatSession(userID, clusterContext, namespace)
	session.AuthContext = authContext
	
	// If auth context has shorter expiry, use that for session
	if authContext != nil && authContext.TokenExpiresAt.Before(session.ExpiresAt) {
		session.ExpiresAt = authContext.TokenExpiresAt
	}
	
	return session
}

// ExtendedChatSessionManager includes authentication-aware session management
type ExtendedChatSessionManager struct {
	*ChatSessionManager
}

// NewExtendedChatSessionManager creates a new extended chat session manager
func NewExtendedChatSessionManager() *ExtendedChatSessionManager {
	return &ExtendedChatSessionManager{
		ChatSessionManager: NewChatSessionManager(),
	}
}

// CreateAuthenticatedSession creates a new chat session with authentication context
func (ecsm *ExtendedChatSessionManager) CreateAuthenticatedSession(userID, clusterContext, namespace string, authContext *SessionAuthContext) *ChatSession {
	session := NewChatSessionWithAuth(userID, clusterContext, namespace, authContext)
	ecsm.sessions[session.ID] = session
	return session
}

// GetAuthenticatedSession retrieves and validates an authenticated session
func (ecsm *ExtendedChatSessionManager) GetAuthenticatedSession(sessionID string) (*ChatSession, error) {
	session, err := ecsm.GetSession(sessionID)
	if err != nil {
		return nil, err
	}
	
	if !session.IsAuthenticated() {
		return nil, fmt.Errorf("session %s is not authenticated or has expired authentication", sessionID)
	}
	
	return session, nil
}

// GetUserAuthenticatedSessions returns all authenticated sessions for a user
func (ecsm *ExtendedChatSessionManager) GetUserAuthenticatedSessions(userID string) []*ChatSession {
	var authenticatedSessions []*ChatSession
	
	for _, session := range ecsm.sessions {
		if session.UserID == userID && session.IsAuthenticated() {
			authenticatedSessions = append(authenticatedSessions, session)
		}
	}
	
	return authenticatedSessions
}

// CleanupUnauthenticatedSessions removes sessions with invalid authentication
func (ecsm *ExtendedChatSessionManager) CleanupUnauthenticatedSessions() int {
	unauthenticatedCount := 0
	var unauthenticatedSessions []string
	
	for sessionID, session := range ecsm.sessions {
		if !session.IsAuthenticated() {
			unauthenticatedSessions = append(unauthenticatedSessions, sessionID)
			unauthenticatedCount++
		}
	}
	
	for _, sessionID := range unauthenticatedSessions {
		delete(ecsm.sessions, sessionID)
	}
	
	return unauthenticatedCount
}