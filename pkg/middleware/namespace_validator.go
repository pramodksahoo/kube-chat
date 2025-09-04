// Package middleware provides namespace access validation for Kubernetes RBAC integration
package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis/v8"
	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// NamespaceValidator handles namespace access validation for users
type NamespaceValidator struct {
	kubeClient      kubernetes.Interface
	redisClient     redis.UniversalClient
	cacheTTL        time.Duration
	cachePrefix     string
	enableCaching   bool
	mutex           sync.RWMutex
	
	// Performance optimization
	batchSize       int
	maxConcurrency  int
	
	// Performance monitoring
	metrics         *ValidationMetrics
}

// NamespaceValidatorConfig holds configuration for the namespace validator
type NamespaceValidatorConfig struct {
	// Kubernetes client configuration
	KubeConfig      *rest.Config
	
	// Redis configuration for caching
	RedisClient     redis.UniversalClient
	CacheTTL        time.Duration
	EnableCaching   bool
	CachePrefix     string
	
	// Performance tuning
	BatchSize       int
	MaxConcurrency  int
}

// NamespaceAccessResult represents the result of namespace access validation
type NamespaceAccessResult struct {
	AllowedNamespaces []string          `json:"allowed_namespaces"`
	DefaultNamespace  string            `json:"default_namespace"`
	ClusterAccess     bool              `json:"cluster_access"`
	AccessMap         map[string]bool   `json:"access_map"` // namespace -> has access
	ValidationTime    time.Time         `json:"validation_time"`
	CacheHit          bool              `json:"cache_hit"`
}

// ValidationRequest represents a request to validate namespace access
type ValidationRequest struct {
	KubernetesUser   string   `json:"kubernetes_user"`
	KubernetesGroups []string `json:"kubernetes_groups"`
	RequestedNS      []string `json:"requested_namespaces,omitempty"` // If empty, validate all
}

// ValidationMetrics tracks performance metrics for namespace validation
type ValidationMetrics struct {
	mutex              sync.RWMutex
	CacheHits          int64         `json:"cache_hits"`
	CacheMisses        int64         `json:"cache_misses"`
	ValidationCount    int64         `json:"validation_count"`
	AverageLatency     time.Duration `json:"average_latency"`
	MaxLatency         time.Duration `json:"max_latency"`
	MinLatency         time.Duration `json:"min_latency"`
	TotalLatency       time.Duration `json:"total_latency"`
	K8sAPICallCount    int64         `json:"k8s_api_call_count"`
	FailureCount       int64         `json:"failure_count"`
	LastValidationTime time.Time     `json:"last_validation_time"`
}

// NewNamespaceValidator creates a new namespace validator
func NewNamespaceValidator(config NamespaceValidatorConfig) (*NamespaceValidator, error) {
	if config.KubeConfig == nil {
		return nil, fmt.Errorf("kubernetes configuration is required")
	}
	
	// Create Kubernetes client
	kubeClient, err := kubernetes.NewForConfig(config.KubeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}
	
	// Set defaults
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute // Default 5 minute cache
	}
	if config.CachePrefix == "" {
		config.CachePrefix = "kubechat:namespace_access"
	}
	if config.BatchSize == 0 {
		config.BatchSize = 10 // Default batch size
	}
	if config.MaxConcurrency == 0 {
		config.MaxConcurrency = 5 // Default concurrency limit
	}
	
	return &NamespaceValidator{
		kubeClient:      kubeClient,
		redisClient:     config.RedisClient,
		cacheTTL:        config.CacheTTL,
		cachePrefix:     config.CachePrefix,
		enableCaching:   config.EnableCaching && config.RedisClient != nil,
		batchSize:       config.BatchSize,
		maxConcurrency:  config.MaxConcurrency,
		metrics:         &ValidationMetrics{
			MinLatency: time.Duration(^uint64(0) >> 1), // Max time.Duration value initially
		},
	}, nil
}

// ValidateNamespaceAccess validates which namespaces a user can access
func (nv *NamespaceValidator) ValidateNamespaceAccess(ctx context.Context, request ValidationRequest) (*NamespaceAccessResult, error) {
	startTime := time.Now()
	defer func() {
		nv.updateMetrics(time.Since(startTime))
	}()

	if request.KubernetesUser == "" {
		nv.recordFailure()
		return nil, fmt.Errorf("kubernetes user is required")
	}
	
	// Check cache first
	if nv.enableCaching {
		if cached, err := nv.getCachedResult(ctx, request); err == nil && cached != nil {
			nv.recordCacheHit()
			cached.CacheHit = true
			return cached, nil
		}
		nv.recordCacheMiss()
	}
	
	result := &NamespaceAccessResult{
		AllowedNamespaces: []string{},
		DefaultNamespace:  "default",
		ClusterAccess:     false,
		AccessMap:         make(map[string]bool),
		ValidationTime:    time.Now(),
		CacheHit:          false,
	}
	
	// Check cluster-level access first
	clusterAccess, err := nv.checkClusterAccess(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to check cluster access: %w", err)
	}
	result.ClusterAccess = clusterAccess
	
	// If user has cluster access, they can access all namespaces
	if clusterAccess {
		namespaces, err := nv.getAllNamespaces(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get all namespaces: %w", err)
		}
		result.AllowedNamespaces = namespaces
		for _, ns := range namespaces {
			result.AccessMap[ns] = true
		}
	} else {
		// Validate specific namespace access
		namespacesToCheck := request.RequestedNS
		if len(namespacesToCheck) == 0 {
			// Get all namespaces if none specified
			allNamespaces, err := nv.getAllNamespaces(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to get all namespaces: %w", err)
			}
			namespacesToCheck = allNamespaces
		}
		
		// Validate access to each namespace
		accessMap, err := nv.validateNamespaceList(ctx, request, namespacesToCheck)
		if err != nil {
			return nil, fmt.Errorf("failed to validate namespace list: %w", err)
		}
		
		result.AccessMap = accessMap
		for ns, hasAccess := range accessMap {
			if hasAccess {
				result.AllowedNamespaces = append(result.AllowedNamespaces, ns)
			}
		}
	}
	
	// Set default namespace (first allowed, or "default" if accessible)
	result.DefaultNamespace = nv.determineDefaultNamespace(result.AllowedNamespaces)
	
	// Cache the result
	if nv.enableCaching {
		if err := nv.cacheResult(ctx, request, result); err != nil {
			// Log error but don't fail the request
			fmt.Printf("Failed to cache namespace validation result: %v\n", err)
		}
	}
	
	return result, nil
}

// checkClusterAccess checks if user has cluster-level access
func (nv *NamespaceValidator) checkClusterAccess(ctx context.Context, request ValidationRequest) (bool, error) {
	// Check for system:masters group (always has cluster access)
	for _, group := range request.KubernetesGroups {
		if group == "system:masters" {
			return true, nil
		}
	}
	
	// Use SubjectAccessReview to check cluster-level permissions for the specified user
	review := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:     "list",
				Resource: "namespaces",
			},
			User:   request.KubernetesUser,
			Groups: request.KubernetesGroups,
		},
	}
	
	nv.recordK8sAPICall()
	result, err := nv.kubeClient.AuthorizationV1().SubjectAccessReviews().Create(
		ctx, review, metav1.CreateOptions{},
	)
	if err != nil {
		nv.recordFailure()
		return false, fmt.Errorf("failed to check cluster access: %w", err)
	}
	
	return result.Status.Allowed, nil
}

// validateNamespaceList validates access to a list of namespaces efficiently
func (nv *NamespaceValidator) validateNamespaceList(ctx context.Context, request ValidationRequest, namespaces []string) (map[string]bool, error) {
	accessMap := make(map[string]bool)
	
	// Process namespaces in batches to avoid overwhelming the API server
	for i := 0; i < len(namespaces); i += nv.batchSize {
		end := i + nv.batchSize
		if end > len(namespaces) {
			end = len(namespaces)
		}
		
		batch := namespaces[i:end]
		batchResult, err := nv.validateNamespaceBatch(ctx, request, batch)
		if err != nil {
			return nil, fmt.Errorf("failed to validate namespace batch: %w", err)
		}
		
		// Merge batch results
		for ns, hasAccess := range batchResult {
			accessMap[ns] = hasAccess
		}
	}
	
	return accessMap, nil
}

// validateNamespaceBatch validates access to a batch of namespaces concurrently
func (nv *NamespaceValidator) validateNamespaceBatch(ctx context.Context, request ValidationRequest, namespaces []string) (map[string]bool, error) {
	accessMap := make(map[string]bool)
	mutex := sync.Mutex{}
	
	// Use semaphore to limit concurrency
	semaphore := make(chan struct{}, nv.maxConcurrency)
	var wg sync.WaitGroup
	var validationError error
	
	for _, namespace := range namespaces {
		wg.Add(1)
		go func(ns string) {
			defer wg.Done()
			semaphore <- struct{}{} // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore
			
			hasAccess, err := nv.checkNamespaceAccess(ctx, request, ns)
			if err != nil && validationError == nil {
				validationError = err
				return
			}
			
			mutex.Lock()
			accessMap[ns] = hasAccess
			mutex.Unlock()
		}(namespace)
	}
	
	wg.Wait()
	
	if validationError != nil {
		return nil, validationError
	}
	
	return accessMap, nil
}

// checkNamespaceAccess checks if user has access to a specific namespace
func (nv *NamespaceValidator) checkNamespaceAccess(ctx context.Context, request ValidationRequest, namespace string) (bool, error) {
	// Use SubjectAccessReview to check namespace access for the specified user
	review := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace: namespace,
				Verb:      "list",
				Resource:  "pods", // Use pods as a standard resource to check access
			},
			User:   request.KubernetesUser,
			Groups: request.KubernetesGroups,
		},
	}
	
	nv.recordK8sAPICall()
	result, err := nv.kubeClient.AuthorizationV1().SubjectAccessReviews().Create(
		ctx, review, metav1.CreateOptions{},
	)
	if err != nil {
		nv.recordFailure()
		return false, fmt.Errorf("failed to check access to namespace %s: %w", namespace, err)
	}
	
	return result.Status.Allowed, nil
}

// getAllNamespaces gets all namespaces in the cluster
func (nv *NamespaceValidator) getAllNamespaces(ctx context.Context) ([]string, error) {
	nv.recordK8sAPICall()
	namespaceList, err := nv.kubeClient.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		nv.recordFailure()
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}
	
	namespaces := make([]string, len(namespaceList.Items))
	for i, ns := range namespaceList.Items {
		namespaces[i] = ns.Name
	}
	
	return namespaces, nil
}

// determineDefaultNamespace determines the best default namespace for the user
func (nv *NamespaceValidator) determineDefaultNamespace(allowedNamespaces []string) string {
	if len(allowedNamespaces) == 0 {
		return "default" // Fallback even if not accessible
	}
	
	// Prefer "default" namespace if accessible
	for _, ns := range allowedNamespaces {
		if ns == "default" {
			return "default"
		}
	}
	
	// Prefer user-related namespaces
	for _, ns := range allowedNamespaces {
		if strings.Contains(ns, "user") || strings.Contains(ns, "dev") {
			return ns
		}
	}
	
	// Return the first allowed namespace
	return allowedNamespaces[0]
}

// Cache-related methods

// getCachedResult retrieves cached namespace validation result
func (nv *NamespaceValidator) getCachedResult(ctx context.Context, request ValidationRequest) (*NamespaceAccessResult, error) {
	if nv.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}
	
	cacheKey := nv.buildCacheKey(request)
	
	cached, err := nv.redisClient.Get(ctx, cacheKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Not found
		}
		return nil, err
	}
	
	// Parse cached result using JSON unmarshaling
	result := &NamespaceAccessResult{}
	if err := json.Unmarshal([]byte(cached), result); err != nil {
		// Cache entry is corrupted, delete it
		nv.redisClient.Del(ctx, cacheKey)
		return nil, fmt.Errorf("failed to unmarshal cached result: %w", err)
	}
	
	// Check if cached result is still fresh
	cacheAge := time.Since(result.ValidationTime)
	if cacheAge > nv.cacheTTL {
		// Entry is expired, delete it
		nv.redisClient.Del(ctx, cacheKey)
		return nil, nil
	}
	
	return result, nil
}

// cacheResult stores namespace validation result in cache
func (nv *NamespaceValidator) cacheResult(ctx context.Context, request ValidationRequest, result *NamespaceAccessResult) error {
	if nv.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}
	
	cacheKey := nv.buildCacheKey(request)
	
	// Serialize result using JSON marshaling
	serialized, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result for caching: %w", err)
	}
	
	return nv.redisClient.Set(ctx, cacheKey, serialized, nv.cacheTTL).Err()
}

// buildCacheKey builds cache key for the validation request
func (nv *NamespaceValidator) buildCacheKey(request ValidationRequest) string {
	// Create deterministic cache key based on user and groups
	groupsStr := strings.Join(request.KubernetesGroups, ",")
	return fmt.Sprintf("%s:%s:%s", nv.cachePrefix, request.KubernetesUser, groupsStr)
}

// InvalidateUserCache invalidates cached results for a user
func (nv *NamespaceValidator) InvalidateUserCache(ctx context.Context, kubernetesUser string) error {
	if nv.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}
	
	pattern := fmt.Sprintf("%s:%s:*", nv.cachePrefix, kubernetesUser)
	keys, err := nv.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	
	if len(keys) > 0 {
		return nv.redisClient.Del(ctx, keys...).Err()
	}
	
	return nil
}

// InvalidateAllCache clears all namespace validation cache
func (nv *NamespaceValidator) InvalidateAllCache(ctx context.Context) error {
	if nv.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}
	
	pattern := fmt.Sprintf("%s:*", nv.cachePrefix)
	keys, err := nv.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}
	
	if len(keys) > 0 {
		return nv.redisClient.Del(ctx, keys...).Err()
	}
	
	return nil
}

// GetCacheStats returns cache statistics
func (nv *NamespaceValidator) GetCacheStats(ctx context.Context) (map[string]interface{}, error) {
	if nv.redisClient == nil {
		return map[string]interface{}{
			"cache_enabled": false,
		}, nil
	}
	
	pattern := fmt.Sprintf("%s:*", nv.cachePrefix)
	keys, err := nv.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return nil, err
	}
	
	return map[string]interface{}{
		"cache_enabled":    nv.enableCaching,
		"cache_ttl":        nv.cacheTTL.String(),
		"cached_entries":   len(keys),
		"cache_prefix":     nv.cachePrefix,
	}, nil
}

// Performance monitoring methods

// updateMetrics updates validation metrics
func (nv *NamespaceValidator) updateMetrics(duration time.Duration) {
	nv.metrics.mutex.Lock()
	defer nv.metrics.mutex.Unlock()
	
	nv.metrics.ValidationCount++
	nv.metrics.TotalLatency += duration
	nv.metrics.AverageLatency = nv.metrics.TotalLatency / time.Duration(nv.metrics.ValidationCount)
	nv.metrics.LastValidationTime = time.Now()
	
	if duration > nv.metrics.MaxLatency {
		nv.metrics.MaxLatency = duration
	}
	
	if duration < nv.metrics.MinLatency {
		nv.metrics.MinLatency = duration
	}
}

// recordCacheHit records a cache hit
func (nv *NamespaceValidator) recordCacheHit() {
	nv.metrics.mutex.Lock()
	defer nv.metrics.mutex.Unlock()
	nv.metrics.CacheHits++
}

// recordCacheMiss records a cache miss
func (nv *NamespaceValidator) recordCacheMiss() {
	nv.metrics.mutex.Lock()
	defer nv.metrics.mutex.Unlock()
	nv.metrics.CacheMisses++
}

// recordK8sAPICall records a Kubernetes API call
func (nv *NamespaceValidator) recordK8sAPICall() {
	nv.metrics.mutex.Lock()
	defer nv.metrics.mutex.Unlock()
	nv.metrics.K8sAPICallCount++
}

// recordFailure records a validation failure
func (nv *NamespaceValidator) recordFailure() {
	nv.metrics.mutex.Lock()
	defer nv.metrics.mutex.Unlock()
	nv.metrics.FailureCount++
}

// GetMetrics returns current validation metrics
func (nv *NamespaceValidator) GetMetrics() *ValidationMetrics {
	nv.metrics.mutex.RLock()
	defer nv.metrics.mutex.RUnlock()
	
	// Return a copy to avoid race conditions
	return &ValidationMetrics{
		CacheHits:          nv.metrics.CacheHits,
		CacheMisses:        nv.metrics.CacheMisses,
		ValidationCount:    nv.metrics.ValidationCount,
		AverageLatency:     nv.metrics.AverageLatency,
		MaxLatency:         nv.metrics.MaxLatency,
		MinLatency:         nv.metrics.MinLatency,
		TotalLatency:       nv.metrics.TotalLatency,
		K8sAPICallCount:    nv.metrics.K8sAPICallCount,
		FailureCount:       nv.metrics.FailureCount,
		LastValidationTime: nv.metrics.LastValidationTime,
	}
}

// ResetMetrics resets all metrics
func (nv *NamespaceValidator) ResetMetrics() {
	nv.metrics.mutex.Lock()
	defer nv.metrics.mutex.Unlock()
	
	*nv.metrics = ValidationMetrics{
		MinLatency: time.Duration(^uint64(0) >> 1),
	}
}

// GetCacheHitRatio returns the cache hit ratio
func (nv *NamespaceValidator) GetCacheHitRatio() float64 {
	nv.metrics.mutex.RLock()
	defer nv.metrics.mutex.RUnlock()
	
	total := nv.metrics.CacheHits + nv.metrics.CacheMisses
	if total == 0 {
		return 0.0
	}
	
	return float64(nv.metrics.CacheHits) / float64(total)
}

// IsPerformanceTarget checks if performance targets are being met
func (nv *NamespaceValidator) IsPerformanceTarget() map[string]bool {
	metrics := nv.GetMetrics()
	cacheHitRatio := nv.GetCacheHitRatio()
	
	return map[string]bool{
		"token_generation_under_200ms": metrics.AverageLatency < 200*time.Millisecond,
		"claims_validation_under_50ms": metrics.AverageLatency < 50*time.Millisecond, // For cached results
		"cache_hit_ratio_above_90":     cacheHitRatio >= 0.9,
		"low_failure_rate":             metrics.FailureCount < metrics.ValidationCount/100, // Less than 1% failures
	}
}