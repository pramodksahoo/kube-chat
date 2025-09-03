package clients

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAPICache(t *testing.T) {
	cache := NewAPICache()
	
	assert.NotNil(t, cache)
	assert.Equal(t, 5*time.Minute, cache.defaultTTL)
	assert.Equal(t, 1000, cache.maxSize)
	assert.Empty(t, cache.entries)
}

func TestAPICacheConfiguration(t *testing.T) {
	cache := NewAPICache()
	
	// Test setting default TTL
	cache.SetDefaultTTL(10 * time.Minute)
	assert.Equal(t, 10*time.Minute, cache.defaultTTL)
	
	// Test setting max size
	cache.SetMaxSize(500)
	assert.Equal(t, 500, cache.maxSize)
}

func TestAPICacheIsReadOnlyCommand(t *testing.T) {
	cache := NewAPICache()
	
	readOnlyCommands := []string{
		"get pods",
		"describe service nginx",
		"kubectl logs pod-name",
		"version",
		"cluster-info",
		"explain deployment",
		"top nodes",
	}
	
	writeCommands := []string{
		"create deployment nginx",
		"delete pod nginx",
		"apply -f deployment.yaml",
		"patch deployment nginx",
		"scale deployment nginx --replicas=3",
	}
	
	for _, cmd := range readOnlyCommands {
		t.Run("readonly: "+cmd, func(t *testing.T) {
			assert.True(t, cache.isReadOnlyCommand(cmd), "should be read-only: %s", cmd)
		})
	}
	
	for _, cmd := range writeCommands {
		t.Run("write: "+cmd, func(t *testing.T) {
			assert.False(t, cache.isReadOnlyCommand(cmd), "should not be read-only: %s", cmd)
		})
	}
}

func TestAPICacheGenerateCacheKey(t *testing.T) {
	cache := NewAPICache()
	
	tests := []struct {
		name     string
		command  *models.KubernetesCommand
		expected string
	}{
		{
			name: "simple command",
			command: &models.KubernetesCommand{
				GeneratedCommand: "kubectl get pods",
			},
			expected: "kubectl get pods",
		},
		{
			name: "command with resources",
			command: &models.KubernetesCommand{
				GeneratedCommand: "kubectl get pod nginx",
				Resources: []models.KubernetesResource{
					{Kind: "pod", Name: "nginx", Namespace: "default"},
				},
			},
			expected: "kubectl get pod nginx|ns:default|res:nginx",
		},
		{
			name: "command with multiple resources",
			command: &models.KubernetesCommand{
				GeneratedCommand: "kubectl get pods",
				Resources: []models.KubernetesResource{
					{Kind: "pod", Namespace: "kube-system"},
					{Kind: "pod", Name: "nginx", Namespace: "default"},
				},
			},
			expected: "kubectl get pods|ns:kube-system|ns:default|res:nginx",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := cache.generateCacheKey(tt.command)
			assert.Equal(t, tt.expected, key)
		})
	}
}

func TestAPICacheGetTTLForCommand(t *testing.T) {
	cache := NewAPICache()
	
	tests := []struct {
		command     string
		expectedTTL time.Duration
	}{
		{"get pods", 2 * time.Minute},
		{"get services", 2 * time.Minute},
		{"get nodes", 10 * time.Minute},
		{"cluster-info", 10 * time.Minute},
		{"describe pod nginx", 3 * time.Minute},
		{"get namespaces", 15 * time.Minute},
		{"explain deployment", 15 * time.Minute},
		{"get deployments", 5 * time.Minute}, // default TTL
	}
	
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			ttl := cache.getTTLForCommand(tt.command)
			assert.Equal(t, tt.expectedTTL, ttl)
		})
	}
}

func TestAPICachePutAndGet(t *testing.T) {
	cache := NewAPICache()
	
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "nginx-pod Running",
		FormattedOutput: "Pod: nginx-pod Status: Running",
	}
	
	// Test put
	cache.Put(command, result)
	
	// Test get
	cachedResult, found := cache.Get(command)
	require.True(t, found, "should find cached result")
	assert.Equal(t, result.Output, cachedResult.Output)
	assert.Contains(t, cachedResult.FormattedOutput, "cached")
}

func TestAPICacheExpiration(t *testing.T) {
	cache := NewAPICache()
	cache.SetDefaultTTL(50 * time.Millisecond) // Very short TTL for testing
	
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "nginx-pod Running",
		FormattedOutput: "Pod: nginx-pod Status: Running",
	}
	
	// Cache the result
	cache.Put(command, result)
	
	// Should be available immediately
	_, found := cache.Get(command)
	assert.True(t, found, "should find fresh cached result")
	
	// Wait for expiration with extra buffer
	time.Sleep(100 * time.Millisecond)
	
	// Should be expired
	_, found = cache.Get(command)
	assert.False(t, found, "should not find expired cached result")
}

func TestAPICacheWriteCommandsNotCached(t *testing.T) {
	cache := NewAPICache()
	
	writeCommand := &models.KubernetesCommand{
		GeneratedCommand: "kubectl delete pod nginx",
	}
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "pod nginx deleted",
		FormattedOutput: "Successfully deleted pod nginx",
	}
	
	// Try to cache a write command
	cache.Put(writeCommand, result)
	
	// Should not be cached
	_, found := cache.Get(writeCommand)
	assert.False(t, found, "write commands should not be cached")
}

func TestAPICacheFailedResultsNotCached(t *testing.T) {
	cache := NewAPICache()
	
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	
	failedResult := &models.CommandExecutionResult{
		Success:         false,
		Output:          "",
		Error:           "connection refused",
		FormattedOutput: "Error: connection refused",
	}
	
	// Try to cache a failed result
	cache.Put(command, failedResult)
	
	// Should not be cached
	_, found := cache.Get(command)
	assert.False(t, found, "failed results should not be cached")
}

func TestAPICacheEviction(t *testing.T) {
	cache := NewAPICache()
	cache.SetMaxSize(2) // Very small cache for testing
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	
	// Fill cache to capacity
	for i := 0; i < 3; i++ {
		command := &models.KubernetesCommand{
			GeneratedCommand: fmt.Sprintf("kubectl get pods-%d", i),
		}
		cache.Put(command, result)
		time.Sleep(1 * time.Millisecond) // Ensure different timestamps
	}
	
	// Should have evicted the oldest entry
	assert.LessOrEqual(t, len(cache.entries), 2, "cache should not exceed max size")
	
	// First command should be evicted
	firstCommand := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods-0",
	}
	_, found := cache.Get(firstCommand)
	assert.False(t, found, "oldest entry should be evicted")
}

func TestAPICacheCleanupExpired(t *testing.T) {
	cache := NewAPICache()
	cache.SetDefaultTTL(50 * time.Millisecond)
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	
	// Add several entries
	for i := 0; i < 5; i++ {
		command := &models.KubernetesCommand{
			GeneratedCommand: fmt.Sprintf("kubectl get pods-%d", i),
		}
		cache.Put(command, result)
	}
	
	assert.Equal(t, 5, len(cache.entries))
	
	// Wait for expiration with extra buffer
	time.Sleep(100 * time.Millisecond)
	
	// Clean up expired entries
	expiredCount := cache.CleanupExpired()
	assert.Equal(t, 5, expiredCount)
	assert.Equal(t, 0, len(cache.entries))
}

func TestAPICacheStats(t *testing.T) {
	cache := NewAPICache()
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	
	// Add some entries
	for i := 0; i < 3; i++ {
		command := &models.KubernetesCommand{
			GeneratedCommand: fmt.Sprintf("kubectl get pods-%d", i),
		}
		cache.Put(command, result)
	}
	
	stats := cache.GetStats()
	assert.Equal(t, 3, stats["total_entries"])
	assert.Equal(t, 3, stats["valid_entries"])
	assert.Equal(t, 0, stats["expired_entries"])
	assert.Equal(t, 1000, stats["max_size"])
}

func TestAPICacheClear(t *testing.T) {
	cache := NewAPICache()
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	
	// Add some entries
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	cache.Put(command, result)
	
	assert.Equal(t, 1, len(cache.entries))
	
	// Clear cache
	cache.Clear()
	assert.Equal(t, 0, len(cache.entries))
}

func TestAPICacheGetCachedCommands(t *testing.T) {
	cache := NewAPICache()
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	
	expectedCommands := []string{
		"kubectl get pods",
		"kubectl get services",
		"kubectl describe pod nginx",
	}
	
	// Add entries
	for _, cmdStr := range expectedCommands {
		command := &models.KubernetesCommand{
			GeneratedCommand: cmdStr,
		}
		cache.Put(command, result)
	}
	
	// Get cached commands
	cachedCommands := cache.GetCachedCommands()
	assert.Len(t, cachedCommands, 3)
	
	// Check all expected commands are present
	for _, expected := range expectedCommands {
		assert.Contains(t, cachedCommands, expected)
	}
}

func TestAPICacheHasValidCache(t *testing.T) {
	cache := NewAPICache()
	
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	
	// Initially no cache
	assert.False(t, cache.HasValidCache(command))
	
	// Add to cache
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	cache.Put(command, result)
	
	// Should have valid cache now
	assert.True(t, cache.HasValidCache(command))
}

func TestAPICacheStartCleanupRoutine(t *testing.T) {
	cache := NewAPICache()
	cache.SetDefaultTTL(30 * time.Millisecond)
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "test output",
		FormattedOutput: "test formatted",
	}
	
	// Add entry
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	cache.Put(command, result)
	
	// Start cleanup routine
	ctx, cancel := context.WithCancel(context.Background())
	cache.StartCleanupRoutine(ctx, 20*time.Millisecond) // Cleanup every 20ms
	
	// Wait for cleanup to run multiple times
	time.Sleep(120 * time.Millisecond)
	cancel()
	
	// Entry should be cleaned up
	assert.Equal(t, 0, len(cache.entries))
}

func TestAPICacheMetadata(t *testing.T) {
	cache := NewAPICache()
	
	command := &models.KubernetesCommand{
		GeneratedCommand: "kubectl get pods",
	}
	
	result := &models.CommandExecutionResult{
		Success:         true,
		Output:          "nginx-pod Running",
		FormattedOutput: "Pod: nginx-pod Status: Running",
	}
	
	// Cache the result
	cache.Put(command, result)
	
	// Get with metadata
	cachedResult, found := cache.Get(command)
	require.True(t, found)
	
	// Should contain cache metadata
	assert.Contains(t, cachedResult.FormattedOutput, "Cached Result")
	assert.Contains(t, cachedResult.FormattedOutput, "Cached:")
	assert.Contains(t, cachedResult.FormattedOutput, "Expires in:")
	
	// Original output should still be present
	assert.Contains(t, cachedResult.FormattedOutput, "Pod: nginx-pod Status: Running")
}

func TestAPICacheFormatDuration(t *testing.T) {
	cache := NewAPICache()
	
	tests := []struct {
		duration time.Duration
		expected string
	}{
		{30 * time.Second, "30 seconds"},
		{90 * time.Second, "1 minutes"},
		{2 * time.Hour, "2.0 hours"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := cache.formatDuration(tt.duration)
			assert.Equal(t, tt.expected, result)
		})
	}
}