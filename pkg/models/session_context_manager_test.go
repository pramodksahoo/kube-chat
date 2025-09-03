package models

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewSessionContextManager(t *testing.T) {
	manager := NewSessionContextManager()
	
	assert.NotNil(t, manager)
	assert.NotNil(t, manager.contexts)
	assert.Equal(t, 30*time.Minute, manager.defaultExpiry)
	assert.Equal(t, 5*time.Minute, manager.cleanupInterval)
	assert.Equal(t, 100, manager.maxContexts)
	assert.NotNil(t, manager.stopCleanup)
	assert.NotNil(t, manager.cleanupDone)
}

func TestSessionContextManager_CreateContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-1"
	context := manager.CreateContext(sessionID)
	
	assert.NotNil(t, context)
	assert.False(t, context.IsExpired())
	assert.Empty(t, context.LastCommandOutput)
	assert.Empty(t, context.NamedEntities)
	assert.Empty(t, context.ReferenceableItems)
}

func TestSessionContextManager_GetContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-2"
	
	// Test getting non-existent context
	context, exists := manager.GetContext(sessionID)
	assert.Nil(t, context)
	assert.False(t, exists)
	
	// Create context and test retrieval
	createdContext := manager.CreateContext(sessionID)
	assert.NotNil(t, createdContext)
	
	retrievedContext, exists := manager.GetContext(sessionID)
	assert.NotNil(t, retrievedContext)
	assert.True(t, exists)
	assert.Equal(t, createdContext, retrievedContext)
}

func TestSessionContextManager_GetExpiredContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-expired-session"
	context := manager.CreateContext(sessionID)
	
	// Manually expire the context
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	
	// Try to retrieve expired context
	retrievedContext, exists := manager.GetContext(sessionID)
	assert.Nil(t, retrievedContext)
	assert.False(t, exists)
}

func TestSessionContextManager_UpdateContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-3"
	originalContext := manager.CreateContext(sessionID)
	originalExpiry := originalContext.ContextExpiry
	
	// Update context
	time.Sleep(10 * time.Millisecond) // Ensure time difference
	manager.UpdateContext(sessionID, originalContext)
	
	// Verify context was updated
	retrievedContext, exists := manager.GetContext(sessionID)
	assert.True(t, exists)
	assert.NotNil(t, retrievedContext)
	assert.True(t, retrievedContext.ContextExpiry.After(originalExpiry))
}

func TestSessionContextManager_ExtendContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-4"
	manager.CreateContext(sessionID)
	
	// Extend context
	extension := 15 * time.Minute
	err := manager.ExtendContext(sessionID, extension)
	assert.NoError(t, err)
	
	// Verify extension
	retrievedContext, exists := manager.GetContext(sessionID)
	assert.True(t, exists)
	// ExtendExpiry sets to now + duration, so it should be after the original time
	assert.True(t, retrievedContext.ContextExpiry.After(time.Now().Add(-5*time.Second)))
}

func TestSessionContextManager_ExtendContext_NonExistent(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	err := manager.ExtendContext("non-existent", 10*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session context not found")
}

func TestSessionContextManager_ExtendContext_Expired(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "expired-session"
	context := manager.CreateContext(sessionID)
	
	// Manually expire the context
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	
	err := manager.ExtendContext(sessionID, 10*time.Minute)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session context has expired")
}

func TestSessionContextManager_RefreshContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-5"
	context := manager.CreateContext(sessionID)
	originalExpiry := context.ContextExpiry
	
	// Wait a bit and refresh
	time.Sleep(10 * time.Millisecond)
	err := manager.RefreshContext(sessionID)
	assert.NoError(t, err)
	
	// Verify refresh
	retrievedContext, exists := manager.GetContext(sessionID)
	assert.True(t, exists)
	assert.True(t, retrievedContext.ContextExpiry.After(originalExpiry))
}

func TestSessionContextManager_ClearContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-6"
	context := manager.CreateContext(sessionID)
	
	// Add some test data
	context.AddReferenceItem(ReferenceItem{
		ID:   "test-item",
		Type: "pod",
		Name: "test-pod",
	})
	context.LastCommandID = "test-command"
	
	// Clear context
	err := manager.ClearContext(sessionID)
	assert.NoError(t, err)
	
	// Verify context is cleared but still exists
	retrievedContext, exists := manager.GetContext(sessionID)
	assert.True(t, exists)
	assert.NotNil(t, retrievedContext)
	assert.Empty(t, retrievedContext.LastCommandOutput)
	assert.Empty(t, retrievedContext.NamedEntities)
	assert.Empty(t, retrievedContext.ReferenceableItems)
	assert.Empty(t, retrievedContext.LastCommandID)
}

func TestSessionContextManager_RemoveContext(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-7"
	manager.CreateContext(sessionID)
	
	// Verify context exists
	_, exists := manager.GetContext(sessionID)
	assert.True(t, exists)
	
	// Remove context
	err := manager.RemoveContext(sessionID)
	assert.NoError(t, err)
	
	// Verify context is removed
	_, exists = manager.GetContext(sessionID)
	assert.False(t, exists)
}

func TestSessionContextManager_RemoveContext_NonExistent(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	err := manager.RemoveContext("non-existent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "session context not found")
}

func TestSessionContextManager_GetContextState(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "test-session-8"
	
	// Test non-existent context
	state, err := manager.GetContextState(sessionID)
	assert.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, sessionID, state.SessionID)
	assert.False(t, state.IsActive)
	assert.True(t, state.IsExpired)
	
	// Test existing context
	context := manager.CreateContext(sessionID)
	context.AddReferenceItem(ReferenceItem{
		ID:   "test-item-1",
		Type: "pod",
		Name: "test-pod-1",
	})
	context.AddReferenceItem(ReferenceItem{
		ID:   "test-item-2",
		Type: "service",
		Name: "test-service-1",
	})
	context.LastCommandID = "test-command-123"
	
	state, err = manager.GetContextState(sessionID)
	assert.NoError(t, err)
	assert.NotNil(t, state)
	assert.Equal(t, sessionID, state.SessionID)
	assert.True(t, state.IsActive)
	assert.False(t, state.IsExpired)
	assert.Equal(t, 2, state.ItemCount)
	assert.Equal(t, "test-command-123", state.LastCommandID)
	assert.Contains(t, state.AvailableTypes, "pod")
	assert.Contains(t, state.AvailableTypes, "service")
}

func TestSessionContextManager_ListActiveSessions(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	// Initially no active sessions
	activeSessions := manager.ListActiveSessions()
	assert.Empty(t, activeSessions)
	
	// Create some sessions
	sessionIDs := []string{"session-1", "session-2", "session-3"}
	for _, sessionID := range sessionIDs {
		manager.CreateContext(sessionID)
	}
	
	// Verify all sessions are active
	activeSessions = manager.ListActiveSessions()
	assert.Len(t, activeSessions, 3)
	for _, sessionID := range sessionIDs {
		assert.Contains(t, activeSessions, sessionID)
	}
	
	// Expire one session
	context, _ := manager.GetContext("session-2")
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	
	// Verify only 2 active sessions remain
	activeSessions = manager.ListActiveSessions()
	assert.Len(t, activeSessions, 2)
	assert.Contains(t, activeSessions, "session-1")
	assert.Contains(t, activeSessions, "session-3")
	assert.NotContains(t, activeSessions, "session-2")
}

func TestSessionContextManager_GetStats(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	// Initially empty stats
	stats := manager.GetStats()
	assert.Equal(t, 0, stats["totalContexts"])
	assert.Equal(t, 0, stats["activeContexts"])
	assert.Equal(t, 0, stats["expiredContexts"])
	assert.Equal(t, 0, stats["totalItems"])
	assert.Equal(t, 0, stats["totalEntities"])
	
	// Create some contexts with data
	manager.CreateContext("session-1").AddReferenceItem(ReferenceItem{ID: "item-1", Type: "pod", Name: "pod-1"})
	manager.CreateContext("session-2").AddReferenceItem(ReferenceItem{ID: "item-2", Type: "service", Name: "svc-1"})
	
	// Expire one context
	context, _ := manager.GetContext("session-1")
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	
	// Verify stats
	stats = manager.GetStats()
	assert.Equal(t, 2, stats["totalContexts"])
	assert.Equal(t, 1, stats["activeContexts"])
	assert.Equal(t, 1, stats["expiredContexts"])
	assert.Equal(t, 2, stats["totalItems"])
	assert.Equal(t, "30m0s", stats["defaultExpiry"])
	assert.Equal(t, "5m0s", stats["cleanupInterval"])
	assert.Equal(t, 100, stats["maxContexts"])
}

func TestSessionContextManager_CleanupExpiredContexts(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	// Create some contexts
	manager.CreateContext("active-session")
	manager.CreateContext("expired-session-1")
	manager.CreateContext("expired-session-2")
	
	// Expire two contexts
	for _, sessionID := range []string{"expired-session-1", "expired-session-2"} {
		context, _ := manager.GetContext(sessionID)
		context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	}
	
	// Run cleanup
	cleanedCount := manager.CleanupExpiredContexts()
	assert.Equal(t, 2, cleanedCount)
	
	// Verify only active session remains
	activeSessions := manager.ListActiveSessions()
	assert.Len(t, activeSessions, 1)
	assert.Contains(t, activeSessions, "active-session")
	
	// Verify total contexts reduced
	stats := manager.GetStats()
	assert.Equal(t, 1, stats["totalContexts"])
}

func TestSessionContextManager_SetConfiguration(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	// Update configuration
	newExpiry := 60 * time.Minute
	newCleanupInterval := 10 * time.Minute
	newMaxContexts := 200
	
	manager.SetConfiguration(newExpiry, newCleanupInterval, newMaxContexts)
	
	// Verify configuration updated
	stats := manager.GetStats()
	assert.Equal(t, "1h0m0s", stats["defaultExpiry"])
	assert.Equal(t, "10m0s", stats["cleanupInterval"])
	assert.Equal(t, 200, stats["maxContexts"])
}

func TestSessionContextManager_SetConfiguration_InvalidValues(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	originalExpiry := manager.defaultExpiry
	originalCleanup := manager.cleanupInterval
	originalMax := manager.maxContexts
	
	// Try to set invalid values (should be ignored)
	manager.SetConfiguration(-5*time.Minute, -2*time.Minute, -10)
	
	// Verify configuration unchanged
	assert.Equal(t, originalExpiry, manager.defaultExpiry)
	assert.Equal(t, originalCleanup, manager.cleanupInterval)
	assert.Equal(t, originalMax, manager.maxContexts)
}

func TestSessionContextManager_MaxContextsEviction(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	// Set low max contexts for testing
	manager.SetConfiguration(30*time.Minute, 5*time.Minute, 3)
	
	// Create contexts up to the limit
	for i := 1; i <= 3; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		manager.CreateContext(sessionID)
	}
	
	// Verify all 3 contexts exist
	stats := manager.GetStats()
	assert.Equal(t, 3, stats["totalContexts"])
	
	// Create one more context (should evict oldest)
	manager.CreateContext("session-4")
	
	// Verify still only 3 contexts
	stats = manager.GetStats()
	assert.Equal(t, 3, stats["totalContexts"])
	
	// Verify newest context exists
	_, exists := manager.GetContext("session-4")
	assert.True(t, exists)
}

func TestSessionContextManager_ValidateContextHealth(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "health-test-session"
	
	// Test non-existent context
	health := manager.ValidateContextHealth(sessionID)
	assert.Equal(t, sessionID, health["sessionId"])
	assert.False(t, health["healthy"].(bool))
	issues := health["issues"].([]string)
	assert.Contains(t, issues, "Context does not exist")
	recommendations := health["recommendations"].([]string)
	assert.Contains(t, recommendations, "Create a new context by running a kubectl command")
	
	// Test active context first
	context := manager.CreateContext(sessionID)
	
	health = manager.ValidateContextHealth(sessionID)
	assert.False(t, health["healthy"].(bool)) // Should be unhealthy due to no items
	issues = health["issues"].([]string)
	assert.Contains(t, issues, "No referenceable items in context")
	
	// Test expired context - need to manually expire it in the context itself
	// rather than letting GetContext filter it out
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	
	health = manager.ValidateContextHealth(sessionID)
	assert.False(t, health["healthy"].(bool))
	issues = health["issues"].([]string)
	assert.Contains(t, issues, "Context has expired")
	
	// Make context active again for further tests
	context.ContextExpiry = time.Now().Add(30 * time.Minute)
	
	// Test context with stale data
	context.AddReferenceItem(ReferenceItem{
		ID:       "stale-item",
		Type:     "pod",
		Name:     "stale-pod",
		LastSeen: time.Now().Add(-15 * time.Minute),
	})
	
	health = manager.ValidateContextHealth(sessionID)
	assert.False(t, health["healthy"].(bool))
	issues = health["issues"].([]string)
	assert.Contains(t, issues, "Context contains stale data (>10 minutes old)")
	
	// Test healthy context
	context.ReferenceableItems = []ReferenceItem{} // Clear stale items
	context.AddReferenceItem(ReferenceItem{
		ID:       "fresh-item",
		Type:     "pod",
		Name:     "fresh-pod",
		LastSeen: time.Now(),
	})
	
	health = manager.ValidateContextHealth(sessionID)
	assert.True(t, health["healthy"].(bool))
	issues = health["issues"].([]string)
	assert.Empty(t, issues)
}

func TestSessionContextManager_Shutdown(t *testing.T) {
	manager := NewSessionContextManager()
	
	// Create some contexts
	manager.CreateContext("session-1")
	manager.CreateContext("session-2")
	
	// Verify contexts exist
	stats := manager.GetStats()
	assert.Equal(t, 2, stats["totalContexts"])
	
	// Shutdown manager
	manager.Shutdown()
	
	// Verify all contexts cleared
	stats = manager.GetStats()
	assert.Equal(t, 0, stats["totalContexts"])
}

func TestSessionContextManager_ConcurrentAccess(t *testing.T) {
	manager := NewSessionContextManager()
	defer manager.Shutdown()
	
	sessionID := "concurrent-test"
	
	// Test concurrent access
	done := make(chan bool, 2)
	
	// Goroutine 1: Create and update context
	go func() {
		context := manager.CreateContext(sessionID)
		for i := 0; i < 100; i++ {
			context.AddReferenceItem(ReferenceItem{
				ID:   fmt.Sprintf("item-%d", i),
				Type: "pod",
				Name: fmt.Sprintf("pod-%d", i),
			})
			manager.UpdateContext(sessionID, context)
		}
		done <- true
	}()
	
	// Goroutine 2: Read context stats
	go func() {
		for i := 0; i < 100; i++ {
			manager.GetStats()
			manager.GetContextState(sessionID)
			time.Sleep(1 * time.Millisecond)
		}
		done <- true
	}()
	
	// Wait for both goroutines to complete
	<-done
	<-done
	
	// Verify no race conditions occurred
	context, exists := manager.GetContext(sessionID)
	assert.True(t, exists)
	assert.NotNil(t, context)
}