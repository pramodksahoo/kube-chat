// Package middleware provides RBAC permission validation for secure Kubernetes operations
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

// RBACValidator handles Kubernetes RBAC permission validation
type RBACValidator struct {
	kubeClient     kubernetes.Interface
	redisClient    redis.UniversalClient
	cacheTTL       time.Duration
	cachePrefix    string
	enableCaching  bool
	circuitBreaker *CircuitBreaker
	metrics        *RBACValidationMetrics
	mutex          sync.RWMutex
}

// RBACValidatorConfig holds configuration for the RBAC validator
type RBACValidatorConfig struct {
	// Kubernetes client configuration
	KubeConfig *rest.Config

	// Redis configuration for caching
	RedisClient   redis.UniversalClient
	CacheTTL      time.Duration
	EnableCaching bool
	CachePrefix   string

	// Circuit breaker configuration for K8s API reliability
	CircuitBreakerConfig CircuitBreakerConfig
}

// PermissionRequest represents a request to validate Kubernetes permissions
type PermissionRequest struct {
	// User context from JWT claims
	KubernetesUser   string   `json:"kubernetes_user"`   // From JWT claims
	KubernetesGroups []string `json:"kubernetes_groups"` // From JWT claims
	SessionID        string   `json:"session_id"`        // From JWT claims

	// Resource details to check
	Namespace      string   `json:"namespace"`       // Target namespace
	Verb           string   `json:"verb"`            // K8s verb (get, list, create, etc.)
	Resource       string   `json:"resource"`        // K8s resource type (pods, deployments, etc.)
	ResourceName   string   `json:"resource_name"`   // Specific resource name (optional)
	APIGroup       string   `json:"api_group"`       // K8s API group (optional)
	Subresource    string   `json:"subresource"`     // K8s subresource (optional)
	
	// Additional context
	CommandContext string   `json:"command_context"` // Natural language context
	AllowedActions []string `json:"allowed_actions"` // Pre-validated actions from JWT
}

// PermissionResponse represents the result of permission validation
type PermissionResponse struct {
	Allowed         bool      `json:"allowed"`
	Reason          string    `json:"reason"`
	EvaluatedAt     time.Time `json:"evaluated_at"`
	CacheHit        bool      `json:"cache_hit"`
	ResponseTime    time.Duration `json:"response_time"`
	
	// Detailed permission information
	UserInfo        UserPermissionInfo `json:"user_info"`
	ResourceAccess  ResourceAccess     `json:"resource_access"`
	Suggestions     []string          `json:"suggestions,omitempty"`
	
	// Audit trail
	ValidationID    string `json:"validation_id"`
	AuditTrail      AuditEntry `json:"audit_trail"`
}

// UserPermissionInfo contains user permission details
type UserPermissionInfo struct {
	User              string   `json:"user"`
	Groups            []string `json:"groups"`
	ServiceAccount    string   `json:"service_account,omitempty"`
	ClusterRoleBindings []string `json:"cluster_role_bindings,omitempty"`
	RoleBindings      []string `json:"role_bindings,omitempty"`
}

// ResourceAccess contains detailed resource access information
type ResourceAccess struct {
	Namespace     string `json:"namespace"`
	Resource      string `json:"resource"`
	Verb          string `json:"verb"`
	AllowedVerbs  []string `json:"allowed_verbs,omitempty"`
	DeniedReason  string `json:"denied_reason,omitempty"`
}

// AuditEntry represents an audit log entry for permission validation
type AuditEntry struct {
	Timestamp       time.Time `json:"timestamp"`
	User            string    `json:"user"`
	SessionID       string    `json:"session_id"`
	ValidationID    string    `json:"validation_id"`
	Resource        string    `json:"resource"`
	Verb            string    `json:"verb"`
	Namespace       string    `json:"namespace"`
	Allowed         bool      `json:"allowed"`
	Reason          string    `json:"reason"`
	ClientIP        string    `json:"client_ip,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	CommandContext  string    `json:"command_context,omitempty"`
}

// RBACValidationMetrics tracks RBAC validation performance metrics
type RBACValidationMetrics struct {
	mutex                sync.RWMutex
	TotalValidations     int64         `json:"total_validations"`
	AllowedValidations   int64         `json:"allowed_validations"`
	DeniedValidations    int64         `json:"denied_validations"`
	CacheHits           int64         `json:"cache_hits"`
	CacheMisses         int64         `json:"cache_misses"`
	AverageLatency      time.Duration `json:"average_latency"`
	MaxLatency          time.Duration `json:"max_latency"`
	MinLatency          time.Duration `json:"min_latency"`
	TotalLatency        time.Duration `json:"total_latency"`
	K8sAPICallCount     int64         `json:"k8s_api_call_count"`
	CircuitBreakerTrips int64         `json:"circuit_breaker_trips"`
	ErrorCount          int64         `json:"error_count"`
	LastValidationTime  time.Time     `json:"last_validation_time"`
}

// NewRBACValidator creates a new RBAC validator with Kubernetes client integration
func NewRBACValidator(config RBACValidatorConfig) (*RBACValidator, error) {
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
		config.CachePrefix = "kubechat:rbac_validation"
	}

	// Initialize circuit breaker for K8s API reliability
	circuitBreaker := NewCircuitBreaker(config.CircuitBreakerConfig)

	return &RBACValidator{
		kubeClient:     kubeClient,
		redisClient:    config.RedisClient,
		cacheTTL:       config.CacheTTL,
		cachePrefix:    config.CachePrefix,
		enableCaching:  config.EnableCaching && config.RedisClient != nil,
		circuitBreaker: circuitBreaker,
		metrics: &RBACValidationMetrics{
			MinLatency: time.Duration(^uint64(0) >> 1), // Max time.Duration value initially
		},
	}, nil
}

// ValidatePermission validates user permissions against Kubernetes RBAC
func (r *RBACValidator) ValidatePermission(ctx context.Context, request PermissionRequest) (*PermissionResponse, error) {
	startTime := time.Now()
	
	// Generate validation ID for audit trail
	validationID := r.generateValidationID()
	
	defer func() {
		responseTime := time.Since(startTime)
		r.updateMetrics(responseTime)
		r.recordAuditEntry(ctx, request, validationID, responseTime)
	}()

	// Input validation
	if err := r.validateRequest(request); err != nil {
		r.recordError()
		return nil, fmt.Errorf("invalid permission request: %w", err)
	}

	// Check cache first for performance optimization
	if r.enableCaching {
		if cached, err := r.getCachedResult(ctx, request); err == nil && cached != nil {
			r.recordCacheHit()
			cached.ValidationID = validationID
			cached.ResponseTime = time.Since(startTime)
			return cached, nil
		}
		r.recordCacheMiss()
	}

	// Perform RBAC validation using SubjectAccessReview
	response, err := r.performRBACValidation(ctx, request, validationID, startTime)
	if err != nil {
		r.recordError()
		return nil, fmt.Errorf("RBAC validation failed: %w", err)
	}

	// Cache the result for performance optimization
	if r.enableCaching && response.Allowed {
		if err := r.cacheResult(ctx, request, response); err != nil {
			// Log error but don't fail the request
			fmt.Printf("Failed to cache RBAC validation result: %v\n", err)
		}
	}

	return response, nil
}

// performRBACValidation performs the actual RBAC validation using Kubernetes API
func (r *RBACValidator) performRBACValidation(ctx context.Context, request PermissionRequest, validationID string, startTime time.Time) (*PermissionResponse, error) {
	response := &PermissionResponse{
		Allowed:        false,
		EvaluatedAt:    time.Now(),
		CacheHit:       false,
		ValidationID:   validationID,
		UserInfo: UserPermissionInfo{
			User:   request.KubernetesUser,
			Groups: request.KubernetesGroups,
		},
		ResourceAccess: ResourceAccess{
			Namespace: request.Namespace,
			Resource:  request.Resource,
			Verb:      request.Verb,
		},
		AuditTrail: AuditEntry{
			Timestamp:      time.Now(),
			User:           request.KubernetesUser,
			SessionID:      request.SessionID,
			ValidationID:   validationID,
			Resource:       request.Resource,
			Verb:           request.Verb,
			Namespace:      request.Namespace,
			CommandContext: request.CommandContext,
		},
	}

	// Use circuit breaker to protect against K8s API failures
	var sarResult *authv1.SubjectAccessReview
	err := r.circuitBreaker.Execute(func() error {
		var execErr error
		sarResult, execErr = r.executeSubjectAccessReview(ctx, request)
		return execErr
	})

	if err != nil {
		r.recordCircuitBreakerTrip()
		response.Reason = fmt.Sprintf("Kubernetes API unavailable: %v", err)
		response.Suggestions = []string{
			"Please try again in a few moments",
			"Contact your cluster administrator if the issue persists",
		}
		return response, nil // Return response with denied access, don't error
	}
	
	// Process the SubjectAccessReview result
	response.Allowed = sarResult.Status.Allowed
	response.ResponseTime = time.Since(startTime)
	
	if sarResult.Status.Allowed {
		response.Reason = "Permission granted by Kubernetes RBAC"
		r.recordAllowedValidation()
	} else {
		response.Reason = sarResult.Status.Reason
		if response.Reason == "" {
			response.Reason = "Permission denied by Kubernetes RBAC"
		}
		r.recordDeniedValidation()
		
		// Generate helpful suggestions for denied permissions
		response.Suggestions = r.generatePermissionSuggestions(request, sarResult.Status)
	}

	response.AuditTrail.Allowed = response.Allowed
	response.AuditTrail.Reason = response.Reason

	return response, nil
}

// executeSubjectAccessReview performs the actual SubjectAccessReview API call
func (r *RBACValidator) executeSubjectAccessReview(ctx context.Context, request PermissionRequest) (*authv1.SubjectAccessReview, error) {
	// Create SubjectAccessReview for user impersonation (NOT SelfSubjectAccessReview)
	sar := &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Namespace:   request.Namespace,
				Verb:        request.Verb,
				Resource:    request.Resource,
				Name:        request.ResourceName,
				Group:       request.APIGroup,
				Subresource: request.Subresource,
			},
			User:   request.KubernetesUser,
			Groups: request.KubernetesGroups,
		},
	}

	r.recordK8sAPICall()
	result, err := r.kubeClient.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("SubjectAccessReview API call failed: %w", err)
	}

	return result, nil
}

// validateRequest validates the incoming permission request
func (r *RBACValidator) validateRequest(request PermissionRequest) error {
	if request.KubernetesUser == "" {
		return fmt.Errorf("kubernetes_user is required")
	}
	if request.Verb == "" {
		return fmt.Errorf("verb is required")
	}
	if request.Resource == "" {
		return fmt.Errorf("resource is required")
	}
	if request.SessionID == "" {
		return fmt.Errorf("session_id is required for audit trail")
	}
	
	// Validate verb is a known Kubernetes verb
	validVerbs := []string{"get", "list", "create", "update", "patch", "delete", "deletecollection", "watch"}
	verbValid := false
	for _, validVerb := range validVerbs {
		if request.Verb == validVerb {
			verbValid = true
			break
		}
	}
	if !verbValid {
		return fmt.Errorf("invalid verb '%s', must be one of: %s", request.Verb, strings.Join(validVerbs, ", "))
	}

	return nil
}

// generatePermissionSuggestions generates helpful suggestions for denied permissions
func (r *RBACValidator) generatePermissionSuggestions(request PermissionRequest, status authv1.SubjectAccessReviewStatus) []string {
	suggestions := []string{}

	// Basic suggestions based on the denied operation
	switch request.Verb {
	case "get", "list":
		suggestions = append(suggestions, fmt.Sprintf("You need 'get' or 'list' permission for %s in namespace '%s'", request.Resource, request.Namespace))
		suggestions = append(suggestions, "Ask your cluster administrator to grant you a Role or ClusterRole with read permissions")
	case "create":
		suggestions = append(suggestions, fmt.Sprintf("You need 'create' permission for %s in namespace '%s'", request.Resource, request.Namespace))
		suggestions = append(suggestions, "Consider using a namespace where you have write permissions")
	case "update", "patch":
		suggestions = append(suggestions, fmt.Sprintf("You need 'update' permission for %s in namespace '%s'", request.Resource, request.Namespace))
	case "delete":
		suggestions = append(suggestions, fmt.Sprintf("You need 'delete' permission for %s in namespace '%s'", request.Resource, request.Namespace))
		suggestions = append(suggestions, "Deletion operations require elevated permissions for safety")
	}

	// Namespace-specific suggestions
	if request.Namespace != "" {
		suggestions = append(suggestions, fmt.Sprintf("Try using a different namespace where you have %s permissions", request.Verb))
		suggestions = append(suggestions, "Use 'kubectl auth can-i' to check your permissions in other namespaces")
	} else {
		suggestions = append(suggestions, "This operation requires cluster-level permissions")
		suggestions = append(suggestions, "Contact your cluster administrator for ClusterRole permissions")
	}

	return suggestions
}

// Cache-related methods

// getCachedResult retrieves cached permission validation result
func (r *RBACValidator) getCachedResult(ctx context.Context, request PermissionRequest) (*PermissionResponse, error) {
	if r.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	cacheKey := r.buildCacheKey(request)
	
	cached, err := r.redisClient.Get(ctx, cacheKey).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Not found
		}
		return nil, err
	}

	// Parse cached result
	result := &PermissionResponse{}
	if err := json.Unmarshal([]byte(cached), result); err != nil {
		// Cache entry is corrupted, delete it
		r.redisClient.Del(ctx, cacheKey)
		return nil, fmt.Errorf("failed to unmarshal cached result: %w", err)
	}

	// Check if cached result is still fresh
	cacheAge := time.Since(result.EvaluatedAt)
	if cacheAge > r.cacheTTL {
		// Entry is expired, delete it
		r.redisClient.Del(ctx, cacheKey)
		return nil, nil
	}

	result.CacheHit = true
	return result, nil
}

// cacheResult stores permission validation result in cache
func (r *RBACValidator) cacheResult(ctx context.Context, request PermissionRequest, response *PermissionResponse) error {
	if r.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	cacheKey := r.buildCacheKey(request)
	
	// Serialize result
	serialized, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal result for caching: %w", err)
	}

	return r.redisClient.Set(ctx, cacheKey, serialized, r.cacheTTL).Err()
}

// buildCacheKey builds cache key for the validation request
func (r *RBACValidator) buildCacheKey(request PermissionRequest) string {
	// Create deterministic cache key based on user, groups, and resource details
	groupsStr := strings.Join(request.KubernetesGroups, ",")
	return fmt.Sprintf("%s:%s:%s:%s:%s:%s:%s", 
		r.cachePrefix, 
		request.KubernetesUser, 
		groupsStr,
		request.Namespace,
		request.Verb,
		request.Resource,
		request.ResourceName,
	)
}

// InvalidateUserCache invalidates all cached results for a user
func (r *RBACValidator) InvalidateUserCache(ctx context.Context, kubernetesUser string) error {
	if r.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	pattern := fmt.Sprintf("%s:%s:*", r.cachePrefix, kubernetesUser)
	keys, err := r.redisClient.Keys(ctx, pattern).Result()
	if err != nil {
		return err
	}

	if len(keys) > 0 {
		return r.redisClient.Del(ctx, keys...).Err()
	}

	return nil
}

// Utility methods

// generateValidationID generates a unique validation ID for audit trail
func (r *RBACValidator) generateValidationID() string {
	return fmt.Sprintf("rbac_%d", time.Now().UnixNano())
}

// recordAuditEntry records an audit entry for the validation request
func (r *RBACValidator) recordAuditEntry(ctx context.Context, request PermissionRequest, validationID string, responseTime time.Duration) {
	// In a real implementation, this would write to an audit log service
	// For now, we'll just log structured audit information
	auditEntry := AuditEntry{
		Timestamp:      time.Now(),
		User:           request.KubernetesUser,
		SessionID:      request.SessionID,
		ValidationID:   validationID,
		Resource:       request.Resource,
		Verb:           request.Verb,
		Namespace:      request.Namespace,
		CommandContext: request.CommandContext,
	}
	
	// TODO: Integrate with actual audit logging service
	_ = auditEntry
}

// Performance monitoring methods

// updateMetrics updates validation metrics
func (r *RBACValidator) updateMetrics(duration time.Duration) {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()

	r.metrics.TotalValidations++
	r.metrics.TotalLatency += duration
	r.metrics.AverageLatency = r.metrics.TotalLatency / time.Duration(r.metrics.TotalValidations)
	r.metrics.LastValidationTime = time.Now()

	if duration > r.metrics.MaxLatency {
		r.metrics.MaxLatency = duration
	}

	if duration < r.metrics.MinLatency {
		r.metrics.MinLatency = duration
	}
}

// Performance tracking methods
func (r *RBACValidator) recordCacheHit() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.CacheHits++
}

func (r *RBACValidator) recordCacheMiss() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.CacheMisses++
}

func (r *RBACValidator) recordK8sAPICall() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.K8sAPICallCount++
}

func (r *RBACValidator) recordAllowedValidation() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.AllowedValidations++
}

func (r *RBACValidator) recordDeniedValidation() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.DeniedValidations++
}

func (r *RBACValidator) recordCircuitBreakerTrip() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.CircuitBreakerTrips++
}

func (r *RBACValidator) recordError() {
	r.metrics.mutex.Lock()
	defer r.metrics.mutex.Unlock()
	r.metrics.ErrorCount++
}

// GetMetrics returns current validation metrics
func (r *RBACValidator) GetMetrics() *RBACValidationMetrics {
	r.metrics.mutex.RLock()
	defer r.metrics.mutex.RUnlock()

	// Return a copy to avoid race conditions
	return &RBACValidationMetrics{
		TotalValidations:     r.metrics.TotalValidations,
		AllowedValidations:   r.metrics.AllowedValidations,
		DeniedValidations:    r.metrics.DeniedValidations,
		CacheHits:           r.metrics.CacheHits,
		CacheMisses:         r.metrics.CacheMisses,
		AverageLatency:      r.metrics.AverageLatency,
		MaxLatency:          r.metrics.MaxLatency,
		MinLatency:          r.metrics.MinLatency,
		TotalLatency:        r.metrics.TotalLatency,
		K8sAPICallCount:     r.metrics.K8sAPICallCount,
		CircuitBreakerTrips: r.metrics.CircuitBreakerTrips,
		ErrorCount:          r.metrics.ErrorCount,
		LastValidationTime:  r.metrics.LastValidationTime,
	}
}

// GetCacheHitRatio returns the cache hit ratio for performance monitoring
func (r *RBACValidator) GetCacheHitRatio() float64 {
	r.metrics.mutex.RLock()
	defer r.metrics.mutex.RUnlock()

	total := r.metrics.CacheHits + r.metrics.CacheMisses
	if total == 0 {
		return 0.0
	}

	return float64(r.metrics.CacheHits) / float64(total)
}

// IsPerformanceTarget checks if performance targets are being met
func (r *RBACValidator) IsPerformanceTarget() map[string]bool {
	metrics := r.GetMetrics()
	cacheHitRatio := r.GetCacheHitRatio()

	return map[string]bool{
		"rbac_validation_under_100ms": metrics.AverageLatency < 100*time.Millisecond,
		"cache_hit_ratio_above_70":    cacheHitRatio >= 0.7,
		"low_error_rate":              metrics.ErrorCount < metrics.TotalValidations/100, // Less than 1% errors
		"api_availability":            metrics.CircuitBreakerTrips < metrics.TotalValidations/20, // Less than 5% circuit breaker trips
	}
}