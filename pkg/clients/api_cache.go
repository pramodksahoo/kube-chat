package clients

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// CacheEntry represents a cached API response
type CacheEntry struct {
	Key        string                           `json:"key"`
	Result     *models.CommandExecutionResult   `json:"result"`
	Timestamp  time.Time                       `json:"timestamp"`
	TTL        time.Duration                   `json:"ttl"`
	Command    string                          `json:"command"`
}

// APICache provides caching for read-only Kubernetes API operations
type APICache struct {
	entries    map[string]*CacheEntry
	mutex      sync.RWMutex
	defaultTTL time.Duration
	maxSize    int
}

// NewAPICache creates a new API cache
func NewAPICache() *APICache {
	return &APICache{
		entries:    make(map[string]*CacheEntry),
		defaultTTL: 5 * time.Minute, // Default 5 minute TTL
		maxSize:    1000,            // Maximum 1000 cached entries
	}
}

// SetDefaultTTL sets the default time-to-live for cache entries
func (c *APICache) SetDefaultTTL(ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.defaultTTL = ttl
}

// SetMaxSize sets the maximum number of cache entries
func (c *APICache) SetMaxSize(maxSize int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.maxSize = maxSize
}

// generateCacheKey creates a cache key for a command
func (c *APICache) generateCacheKey(command *models.KubernetesCommand) string {
	var keyParts []string
	
	// Include the generated command as the primary key component
	keyParts = append(keyParts, command.GeneratedCommand)
	
	// Include any resource-specific context
	for _, resource := range command.Resources {
		if resource.Namespace != "" {
			keyParts = append(keyParts, "ns:"+resource.Namespace)
		}
		if resource.Name != "" {
			keyParts = append(keyParts, "res:"+resource.Name)
		}
	}
	
	return strings.Join(keyParts, "|")
}

// isReadOnlyCommand determines if a command is read-only and cacheable
func (c *APICache) isReadOnlyCommand(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	
	// Remove kubectl prefix if present
	if strings.HasPrefix(command, "kubectl ") {
		command = strings.TrimPrefix(command, "kubectl ")
	}
	
	readOnlyCommands := []string{
		"get", "describe", "logs", "version", "cluster-info",
		"config view", "auth can-i", "top", "explain",
	}
	
	for _, readOnlyCmd := range readOnlyCommands {
		if strings.HasPrefix(command, readOnlyCmd) {
			return true
		}
	}
	
	return false
}

// Get retrieves a cached result if available and not expired
func (c *APICache) Get(command *models.KubernetesCommand) (*models.CommandExecutionResult, bool) {
	if !c.isReadOnlyCommand(command.GeneratedCommand) {
		return nil, false
	}
	
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	key := c.generateCacheKey(command)
	entry, exists := c.entries[key]
	
	if !exists {
		return nil, false
	}
	
	// Check if entry has expired
	if time.Since(entry.Timestamp) > entry.TTL {
		// Entry is expired, but don't remove it here (read lock)
		// It will be cleaned up by the cleanup process
		return nil, false
	}
	
	// Return a copy of the result with cache metadata
	result := *entry.Result
	result.FormattedOutput = c.addCacheMetadata(result.FormattedOutput, entry)
	
	return &result, true
}

// Put stores a result in the cache
func (c *APICache) Put(command *models.KubernetesCommand, result *models.CommandExecutionResult) {
	if !c.isReadOnlyCommand(command.GeneratedCommand) {
		return
	}
	
	// Only cache successful results
	if !result.Success {
		return
	}
	
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Check if we need to make room (simple LRU-style cleanup)
	if len(c.entries) >= c.maxSize {
		c.evictOldest()
	}
	
	key := c.generateCacheKey(command)
	entry := &CacheEntry{
		Key:       key,
		Result:    result,
		Timestamp: time.Now(),
		TTL:       c.getTTLForCommand(command.GeneratedCommand),
		Command:   command.GeneratedCommand,
	}
	
	c.entries[key] = entry
}

// getTTLForCommand returns appropriate TTL based on command type
func (c *APICache) getTTLForCommand(command string) time.Duration {
	command = strings.ToLower(command)
	
	// Different TTLs for different types of data
	if strings.Contains(command, "get pods") || strings.Contains(command, "get services") {
		return 2 * time.Minute // Pod/service status changes frequently
	}
	if strings.Contains(command, "get nodes") || strings.Contains(command, "cluster-info") {
		return 10 * time.Minute // Cluster info changes less frequently
	}
	if strings.Contains(command, "describe") {
		return 3 * time.Minute // Resource descriptions change moderately
	}
	if strings.Contains(command, "get namespaces") || strings.Contains(command, "explain") {
		return 15 * time.Minute // Relatively static information
	}
	
	return c.defaultTTL
}

// addCacheMetadata adds cache information to the formatted output
func (c *APICache) addCacheMetadata(output string, entry *CacheEntry) string {
	age := time.Since(entry.Timestamp)
	remaining := entry.TTL - age
	
	metadata := fmt.Sprintf("\n\n💾 **Cached Result** (retrieved from cache)\n")
	metadata += fmt.Sprintf("**Cached:** %s ago\n", c.formatDuration(age))
	metadata += fmt.Sprintf("**Expires in:** %s\n", c.formatDuration(remaining))
	metadata += "*This result was cached during API connectivity issues. Data may not reflect current state.*"
	
	return output + metadata
}

// formatDuration formats a duration in a human-readable way
func (c *APICache) formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("%.1f hours", d.Hours())
}

// evictOldest removes the oldest cache entries to make room for new ones
func (c *APICache) evictOldest() {
	if len(c.entries) == 0 {
		return
	}
	
	// Find the oldest entry
	var oldestKey string
	var oldestTime time.Time
	
	for key, entry := range c.entries {
		if oldestKey == "" || entry.Timestamp.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.Timestamp
		}
	}
	
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}

// CleanupExpired removes expired entries from the cache
func (c *APICache) CleanupExpired() int {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	now := time.Now()
	expiredCount := 0
	
	for key, entry := range c.entries {
		if now.Sub(entry.Timestamp) > entry.TTL {
			delete(c.entries, key)
			expiredCount++
		}
	}
	
	return expiredCount
}

// GetStats returns cache statistics
func (c *APICache) GetStats() map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	now := time.Now()
	validEntries := 0
	expiredEntries := 0
	
	for _, entry := range c.entries {
		if now.Sub(entry.Timestamp) <= entry.TTL {
			validEntries++
		} else {
			expiredEntries++
		}
	}
	
	return map[string]interface{}{
		"total_entries":   len(c.entries),
		"valid_entries":   validEntries,
		"expired_entries": expiredEntries,
		"max_size":        c.maxSize,
		"default_ttl":     c.defaultTTL.String(),
	}
}

// Clear removes all entries from the cache
func (c *APICache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// GetCachedCommands returns a list of currently cached commands
func (c *APICache) GetCachedCommands() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var commands []string
	for _, entry := range c.entries {
		if time.Since(entry.Timestamp) <= entry.TTL {
			commands = append(commands, entry.Command)
		}
	}
	
	return commands
}

// HasValidCache checks if there's a valid cache entry for a command
func (c *APICache) HasValidCache(command *models.KubernetesCommand) bool {
	_, exists := c.Get(command)
	return exists
}

// StartCleanupRoutine starts a background routine to clean up expired entries
func (c *APICache) StartCleanupRoutine(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.CleanupExpired()
			}
		}
	}()
}