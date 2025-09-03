package models

import (
	"fmt"
	"sync"
	"time"
)

// SessionContextManager manages the lifecycle of session contexts
type SessionContextManager struct {
	contexts map[string]*SessionContext
	mutex    sync.RWMutex
	
	// Configuration
	defaultExpiry   time.Duration
	cleanupInterval time.Duration
	maxContexts     int
	
	// Cleanup goroutine control
	stopCleanup chan struct{}
	cleanupDone chan struct{}
}

// ContextState represents the current state of a session context
type ContextState struct {
	SessionID        string            `json:"sessionId"`
	IsActive         bool              `json:"isActive"`
	IsExpired        bool              `json:"isExpired"`
	CreatedAt        time.Time         `json:"createdAt"`
	LastActivity     time.Time         `json:"lastActivity"`
	ExpiresAt        time.Time         `json:"expiresAt"`
	ItemCount        int               `json:"itemCount"`
	EntityCount      int               `json:"entityCount"`
	LastCommandID    string            `json:"lastCommandId"`
	AvailableTypes   []string          `json:"availableTypes"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// NewSessionContextManager creates a new session context manager
func NewSessionContextManager() *SessionContextManager {
	manager := &SessionContextManager{
		contexts:        make(map[string]*SessionContext),
		defaultExpiry:   30 * time.Minute, // 30 minutes default
		cleanupInterval: 5 * time.Minute,  // Clean up every 5 minutes
		maxContexts:     100,               // Max 100 active contexts
		stopCleanup:     make(chan struct{}),
		cleanupDone:     make(chan struct{}),
	}
	
	// Start cleanup goroutine
	go manager.cleanupWorker()
	
	return manager
}

// GetContext retrieves a session context by ID
func (scm *SessionContextManager) GetContext(sessionID string) (*SessionContext, bool) {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()
	
	context, exists := scm.contexts[sessionID]
	if !exists {
		return nil, false
	}
	
	// Check if expired
	if context.IsExpired() {
		return nil, false
	}
	
	return context, true
}

// CreateContext creates a new session context
func (scm *SessionContextManager) CreateContext(sessionID string) *SessionContext {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	// Clean up existing context if it exists
	if existing, exists := scm.contexts[sessionID]; exists {
		existing.Clear()
	}
	
	// Create new context
	context := NewSessionContext()
	context.ContextExpiry = time.Now().Add(scm.defaultExpiry)
	
	// Enforce max contexts limit
	if len(scm.contexts) >= scm.maxContexts {
		scm.evictOldestContext()
	}
	
	scm.contexts[sessionID] = context
	return context
}

// UpdateContext updates an existing context or creates a new one
func (scm *SessionContextManager) UpdateContext(sessionID string, context *SessionContext) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	// Update last activity
	context.ContextExpiry = time.Now().Add(scm.defaultExpiry)
	scm.contexts[sessionID] = context
}

// ExtendContext extends the expiry time of a session context
func (scm *SessionContextManager) ExtendContext(sessionID string, duration time.Duration) error {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	context, exists := scm.contexts[sessionID]
	if !exists {
		return fmt.Errorf("session context not found: %s", sessionID)
	}
	
	if context.IsExpired() {
		return fmt.Errorf("session context has expired: %s", sessionID)
	}
	
	context.ExtendExpiry(duration)
	return nil
}

// RefreshContext refreshes the expiry time of a session context to default duration
func (scm *SessionContextManager) RefreshContext(sessionID string) error {
	return scm.ExtendContext(sessionID, scm.defaultExpiry)
}

// ClearContext clears all data from a session context but keeps it active
func (scm *SessionContextManager) ClearContext(sessionID string) error {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	context, exists := scm.contexts[sessionID]
	if !exists {
		return fmt.Errorf("session context not found: %s", sessionID)
	}
	
	context.Clear()
	context.ContextExpiry = time.Now().Add(scm.defaultExpiry)
	return nil
}

// RemoveContext completely removes a session context
func (scm *SessionContextManager) RemoveContext(sessionID string) error {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	context, exists := scm.contexts[sessionID]
	if !exists {
		return fmt.Errorf("session context not found: %s", sessionID)
	}
	
	context.Clear()
	delete(scm.contexts, sessionID)
	return nil
}

// GetContextState returns the current state of a session context
func (scm *SessionContextManager) GetContextState(sessionID string) (*ContextState, error) {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()
	
	context, exists := scm.contexts[sessionID]
	if !exists {
		return &ContextState{
			SessionID: sessionID,
			IsActive:  false,
			IsExpired: true,
		}, nil
	}
	
	// Determine available resource types
	availableTypes := make([]string, 0)
	typeMap := make(map[string]bool)
	for _, item := range context.ReferenceableItems {
		if !typeMap[item.Type] {
			availableTypes = append(availableTypes, item.Type)
			typeMap[item.Type] = true
		}
	}
	
	return &ContextState{
		SessionID:      sessionID,
		IsActive:       !context.IsExpired(),
		IsExpired:      context.IsExpired(),
		CreatedAt:      time.Now().Add(-scm.defaultExpiry), // Approximate
		LastActivity:   context.ContextExpiry.Add(-scm.defaultExpiry),
		ExpiresAt:      context.ContextExpiry,
		ItemCount:      len(context.ReferenceableItems),
		EntityCount:    len(context.NamedEntities),
		LastCommandID:  context.LastCommandID,
		AvailableTypes: availableTypes,
		Metadata: map[string]interface{}{
			"outputItems": len(context.LastCommandOutput),
		},
	}, nil
}

// ListActiveSessions returns a list of all active session IDs
func (scm *SessionContextManager) ListActiveSessions() []string {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()
	
	activeSessions := make([]string, 0)
	for sessionID, context := range scm.contexts {
		if !context.IsExpired() {
			activeSessions = append(activeSessions, sessionID)
		}
	}
	
	return activeSessions
}

// GetStats returns statistics about the context manager
func (scm *SessionContextManager) GetStats() map[string]interface{} {
	scm.mutex.RLock()
	defer scm.mutex.RUnlock()
	
	totalContexts := len(scm.contexts)
	activeContexts := 0
	expiredContexts := 0
	totalItems := 0
	totalEntities := 0
	
	for _, context := range scm.contexts {
		if context.IsExpired() {
			expiredContexts++
		} else {
			activeContexts++
		}
		totalItems += len(context.ReferenceableItems)
		totalEntities += len(context.NamedEntities)
	}
	
	return map[string]interface{}{
		"totalContexts":     totalContexts,
		"activeContexts":    activeContexts,
		"expiredContexts":   expiredContexts,
		"totalItems":        totalItems,
		"totalEntities":     totalEntities,
		"defaultExpiry":     scm.defaultExpiry.String(),
		"cleanupInterval":   scm.cleanupInterval.String(),
		"maxContexts":       scm.maxContexts,
	}
}

// CleanupExpiredContexts removes all expired contexts
func (scm *SessionContextManager) CleanupExpiredContexts() int {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	cleanedCount := 0
	for sessionID, context := range scm.contexts {
		if context.IsExpired() {
			context.Clear()
			delete(scm.contexts, sessionID)
			cleanedCount++
		}
	}
	
	return cleanedCount
}

// SetConfiguration updates the manager configuration
func (scm *SessionContextManager) SetConfiguration(defaultExpiry, cleanupInterval time.Duration, maxContexts int) {
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	if defaultExpiry > 0 {
		scm.defaultExpiry = defaultExpiry
	}
	if cleanupInterval > 0 {
		scm.cleanupInterval = cleanupInterval
	}
	if maxContexts > 0 {
		scm.maxContexts = maxContexts
	}
}

// Shutdown gracefully shuts down the context manager
func (scm *SessionContextManager) Shutdown() {
	close(scm.stopCleanup)
	<-scm.cleanupDone
	
	// Clean up all contexts
	scm.mutex.Lock()
	defer scm.mutex.Unlock()
	
	for _, context := range scm.contexts {
		context.Clear()
	}
	scm.contexts = make(map[string]*SessionContext)
}

// cleanupWorker runs periodic cleanup of expired contexts
func (scm *SessionContextManager) cleanupWorker() {
	defer close(scm.cleanupDone)
	
	ticker := time.NewTicker(scm.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cleaned := scm.CleanupExpiredContexts()
			if cleaned > 0 {
				// Log cleanup activity (in a real implementation, this would use proper logging)
				fmt.Printf("Context manager cleaned up %d expired contexts\n", cleaned)
			}
		case <-scm.stopCleanup:
			return
		}
	}
}

// evictOldestContext removes the oldest context to make room for a new one
func (scm *SessionContextManager) evictOldestContext() {
	var oldestSessionID string
	var oldestExpiry time.Time = time.Now().Add(24 * time.Hour) // Future time
	
	for sessionID, context := range scm.contexts {
		if context.ContextExpiry.Before(oldestExpiry) {
			oldestExpiry = context.ContextExpiry
			oldestSessionID = sessionID
		}
	}
	
	if oldestSessionID != "" {
		if context, exists := scm.contexts[oldestSessionID]; exists {
			context.Clear()
		}
		delete(scm.contexts, oldestSessionID)
	}
}

// ValidateContextHealth checks if a context is healthy and provides recommendations
func (scm *SessionContextManager) ValidateContextHealth(sessionID string) map[string]interface{} {
	scm.mutex.RLock()
	context, exists := scm.contexts[sessionID]
	scm.mutex.RUnlock()
	
	health := map[string]interface{}{
		"sessionId": sessionID,
		"healthy":   false,
		"issues":    []string{},
		"recommendations": []string{},
	}
	
	if !exists {
		health["issues"] = append(health["issues"].([]string), "Context does not exist")
		health["recommendations"] = append(health["recommendations"].([]string), "Create a new context by running a kubectl command")
		return health
	}
	
	issues := make([]string, 0)
	recommendations := make([]string, 0)
	
	// Check expiry
	if context.IsExpired() {
		issues = append(issues, "Context has expired")
		recommendations = append(recommendations, "Run a new command to refresh context")
	}
	
	// Check if context has items
	if len(context.ReferenceableItems) == 0 {
		issues = append(issues, "No referenceable items in context")
		recommendations = append(recommendations, "Run commands like 'get pods' to populate context")
	}
	
	// Check for stale data
	if len(context.ReferenceableItems) > 0 {
		oldestItem := context.ReferenceableItems[0]
		for _, item := range context.ReferenceableItems {
			if item.LastSeen.Before(oldestItem.LastSeen) {
				oldestItem = item
			}
		}
		
		if time.Since(oldestItem.LastSeen) > 10*time.Minute {
			issues = append(issues, "Context contains stale data (>10 minutes old)")
			recommendations = append(recommendations, "Refresh context by running recent commands")
		}
	}
	
	health["healthy"] = len(issues) == 0
	health["issues"] = issues
	health["recommendations"] = recommendations
	
	return health
}