// Package audit provides comprehensive audit trail search capabilities
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lib/pq"
	"github.com/pramodksahoo/kube-chat/pkg/middleware"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// SearchService provides comprehensive audit search capabilities
type SearchService struct {
	storage       AuditStorage
	db            *sql.DB
	ftsConfig     string // Full-text search configuration
	rbacValidator *middleware.RBACValidator

	// Rate limiting
	rateLimiter map[string]*UserRateLimit
	rateMutex   sync.RWMutex
	rateConfig  RateLimitConfig
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	RequestsPerMinute int           `json:"requests_per_minute"`
	BurstLimit        int           `json:"burst_limit"`
	WindowSize        time.Duration `json:"window_size"`
	CleanupInterval   time.Duration `json:"cleanup_interval"`
}

// UserRateLimit tracks rate limiting for a specific user
type UserRateLimit struct {
	UserID      string      `json:"user_id"`
	Requests    []time.Time `json:"requests"`
	LastRequest time.Time   `json:"last_request"`
	mutex       sync.Mutex
}

// DefaultRateLimitConfig returns sensible defaults for rate limiting
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerMinute: 60,              // 60 requests per minute
		BurstLimit:        10,              // Allow bursts of up to 10 requests
		WindowSize:        time.Minute,     // 1 minute window
		CleanupInterval:   5 * time.Minute, // Cleanup old entries every 5 minutes
	}
}

// SearchRequest represents a comprehensive audit search request
type SearchRequest struct {
	// User context for RBAC validation
	UserContext models.UserContext `json:"user_context"`

	// Text search parameters
	Query        string   `json:"query,omitempty"`         // Full-text search query
	SearchFields []string `json:"search_fields,omitempty"` // Specific fields to search

	// Filter parameters
	UserID        string                  `json:"user_id,omitempty"`
	EventTypes    []models.AuditEventType `json:"event_types,omitempty"`
	Severities    []models.AuditSeverity  `json:"severities,omitempty"`
	ClusterName   string                  `json:"cluster_name,omitempty"`
	Namespace     string                  `json:"namespace,omitempty"`
	ServiceName   string                  `json:"service_name,omitempty"`
	CorrelationID string                  `json:"correlation_id,omitempty"`
	TraceID       string                  `json:"trace_id,omitempty"`

	// Time range filtering with timezone support
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Timezone  string    `json:"timezone,omitempty"` // IANA timezone name

	// Command-specific filters
	NaturalLanguageQuery string   `json:"natural_language_query,omitempty"`
	GeneratedCommand     string   `json:"generated_command,omitempty"`
	RiskLevels           []string `json:"risk_levels,omitempty"`
	ExecutionStatus      []string `json:"execution_status,omitempty"`

	// Security investigation filters
	IPAddress          string   `json:"ip_address,omitempty"`
	UserAgent          string   `json:"user_agent,omitempty"`
	SuspiciousPatterns []string `json:"suspicious_patterns,omitempty"`

	// Pagination and sorting
	Limit     int    `json:"limit,omitempty"`
	Offset    int    `json:"offset,omitempty"`
	SortBy    string `json:"sort_by,omitempty"`    // Field to sort by
	SortOrder string `json:"sort_order,omitempty"` // asc, desc

	// Advanced options
	IncludeIntegrityCheck bool `json:"include_integrity_check,omitempty"`
	HighlightMatches      bool `json:"highlight_matches,omitempty"`
	RankResults           bool `json:"rank_results,omitempty"` // Use FTS ranking
}

// SearchResult represents a search result with metadata
type SearchResult struct {
	Event           *models.AuditEvent `json:"event"`
	Rank            float64            `json:"rank,omitempty"`             // FTS relevance rank
	HighlightedText string             `json:"highlighted_text,omitempty"` // Highlighted search matches
	IntegrityValid  *bool              `json:"integrity_valid,omitempty"`  // Integrity check result
}

// SearchResponse represents a comprehensive search response
type SearchResponse struct {
	Results     []*SearchResult `json:"results"`
	TotalCount  int64           `json:"total_count"`
	TotalPages  int             `json:"total_pages"`
	CurrentPage int             `json:"current_page"`
	SearchTime  time.Duration   `json:"search_time"`
	Query       SearchRequest   `json:"query"`

	// Search metadata
	QueryInfo struct {
		ProcessedQuery      string            `json:"processed_query"`
		UsedIndexes         []string          `json:"used_indexes"`
		OptimizationApplied bool              `json:"optimization_applied"`
		Filters             map[string]string `json:"filters"`
	} `json:"query_info"`
}

// NewSearchService creates a new audit search service
func NewSearchService(storage AuditStorage, db *sql.DB, rbacValidator *middleware.RBACValidator) (*SearchService, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage cannot be nil")
	}
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}
	if rbacValidator == nil {
		return nil, fmt.Errorf("RBAC validator cannot be nil")
	}

	service := &SearchService{
		storage:       storage,
		db:            db,
		ftsConfig:     "english", // Default to English FTS configuration
		rbacValidator: rbacValidator,
		rateLimiter:   make(map[string]*UserRateLimit),
		rateConfig:    DefaultRateLimitConfig(),
	}

	// Initialize search indexes
	if err := service.initializeSearchIndexes(); err != nil {
		return nil, fmt.Errorf("failed to initialize search indexes: %w", err)
	}

	// Start rate limiter cleanup routine
	go service.startRateLimitCleanup()

	return service, nil
}

// SearchEvents performs comprehensive audit event search
func (s *SearchService) SearchEvents(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	startTime := time.Now()

	// Apply rate limiting
	if err := s.checkRateLimit(req.UserContext.UserID); err != nil {
		return nil, fmt.Errorf("rate limit exceeded: %w", err)
	}

	// Validate RBAC permissions for audit search
	if err := s.validateSearchPermissions(ctx, req); err != nil {
		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// Validate search request
	if err := s.validateSearchRequest(&req); err != nil {
		return nil, fmt.Errorf("invalid search request: %w", err)
	}

	// Apply default values
	s.applyDefaultSearchParams(&req)

	// Build SQL query
	query, args, err := s.buildSearchQuery(req)
	if err != nil {
		return nil, fmt.Errorf("failed to build search query: %w", err)
	}

	// Execute count query for pagination
	countQuery, countArgs := s.buildCountQuery(req)
	var totalCount int64
	if err := s.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("failed to get total count: %w", err)
	}

	// Execute main search query
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to execute search query: %w", err)
	}
	defer rows.Close()

	var results []*SearchResult
	for rows.Next() {
		result, err := s.scanSearchResult(rows, req)
		if err != nil {
			return nil, fmt.Errorf("failed to scan search result: %w", err)
		}

		// Perform integrity check if requested
		if req.IncludeIntegrityCheck {
			valid, err := result.Event.VerifyIntegrity()
			if err == nil {
				result.IntegrityValid = &valid
			}
		}

		results = append(results, result)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error reading search results: %w", err)
	}

	// Calculate pagination metadata
	currentPage := (req.Offset / req.Limit) + 1
	totalPages := int((totalCount + int64(req.Limit) - 1) / int64(req.Limit))

	response := &SearchResponse{
		Results:     results,
		TotalCount:  totalCount,
		TotalPages:  totalPages,
		CurrentPage: currentPage,
		SearchTime:  time.Since(startTime),
		Query:       req,
	}

	// Add query info metadata
	response.QueryInfo.ProcessedQuery = query
	response.QueryInfo.UsedIndexes = s.getUsedIndexes(req)
	response.QueryInfo.OptimizationApplied = s.isOptimizationApplied(req)
	response.QueryInfo.Filters = s.getActiveFilters(req)

	return response, nil
}

// AdvancedSearch performs advanced security investigation queries
func (s *SearchService) AdvancedSearch(ctx context.Context, req SearchRequest) (*SearchResponse, error) {
	// Apply advanced search optimizations
	req.RankResults = true
	req.HighlightMatches = true
	req.IncludeIntegrityCheck = true

	// Add suspicious pattern detection if patterns are specified
	if len(req.SuspiciousPatterns) > 0 {
		req.Query = s.buildSuspiciousPatternQuery(req.SuspiciousPatterns, req.Query)
	}

	return s.SearchEvents(ctx, req)
}

// SearchEventsByDateRange performs optimized date range searches
func (s *SearchService) SearchEventsByDateRange(ctx context.Context, start, end time.Time, timezone string, filters map[string]interface{}) (*SearchResponse, error) {
	req := SearchRequest{
		StartTime: start,
		EndTime:   end,
		Timezone:  timezone,
		Limit:     1000,
		SortBy:    "timestamp",
		SortOrder: "desc",
	}

	// Apply additional filters
	if userID, ok := filters["user_id"].(string); ok {
		req.UserID = userID
	}
	if clusterName, ok := filters["cluster_name"].(string); ok {
		req.ClusterName = clusterName
	}
	if namespace, ok := filters["namespace"].(string); ok {
		req.Namespace = namespace
	}

	return s.SearchEvents(ctx, req)
}

// GetSearchSuggestions returns search suggestions based on historical queries
func (s *SearchService) GetSearchSuggestions(ctx context.Context, partial string, limit int) ([]string, error) {
	query := `
		SELECT DISTINCT 
			CASE 
				WHEN message ILIKE $1 THEN message
				WHEN user_context->>'user_id' ILIKE $1 THEN user_context->>'user_id'
				WHEN cluster_context->>'cluster_name' ILIKE $1 THEN cluster_context->>'cluster_name'
				WHEN cluster_context->>'namespace' ILIKE $1 THEN cluster_context->>'namespace'
				WHEN command_context->>'natural_language_input' ILIKE $1 THEN command_context->>'natural_language_input'
			END as suggestion
		FROM audit_events 
		WHERE 
			message ILIKE $1 
			OR user_context->>'user_id' ILIKE $1
			OR cluster_context->>'cluster_name' ILIKE $1
			OR cluster_context->>'namespace' ILIKE $1
			OR command_context->>'natural_language_input' ILIKE $1
		ORDER BY suggestion
		LIMIT $2
	`

	pattern := "%" + partial + "%"
	rows, err := s.db.QueryContext(ctx, query, pattern, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get search suggestions: %w", err)
	}
	defer rows.Close()

	var suggestions []string
	for rows.Next() {
		var suggestion sql.NullString
		if err := rows.Scan(&suggestion); err != nil {
			return nil, fmt.Errorf("failed to scan suggestion: %w", err)
		}
		if suggestion.Valid && suggestion.String != "" {
			suggestions = append(suggestions, suggestion.String)
		}
	}

	return suggestions, nil
}

// validateSearchRequest validates the search request parameters
func (s *SearchService) validateSearchRequest(req *SearchRequest) error {
	if req.Limit < 0 || req.Limit > 10000 {
		return fmt.Errorf("limit must be between 0 and 10000")
	}
	if req.Offset < 0 {
		return fmt.Errorf("offset cannot be negative")
	}
	if req.SortOrder != "" && req.SortOrder != "asc" && req.SortOrder != "desc" {
		return fmt.Errorf("sort_order must be 'asc' or 'desc'")
	}
	if !req.StartTime.IsZero() && !req.EndTime.IsZero() && req.StartTime.After(req.EndTime) {
		return fmt.Errorf("start_time cannot be after end_time")
	}

	// Validate sortable fields to prevent SQL injection
	if err := s.validateSortField(req.SortBy); err != nil {
		return fmt.Errorf("invalid sort field: %w", err)
	}

	// Validate timezone format
	if req.Timezone != "" {
		if _, err := time.LoadLocation(req.Timezone); err != nil {
			return fmt.Errorf("invalid timezone: %w", err)
		}
	}

	// Validate search fields if specified
	if len(req.SearchFields) > 0 {
		if err := s.validateSearchFields(req.SearchFields); err != nil {
			return fmt.Errorf("invalid search fields: %w", err)
		}
	}

	return nil
}

// applyDefaultSearchParams applies default values to search request
func (s *SearchService) applyDefaultSearchParams(req *SearchRequest) {
	if req.Limit == 0 {
		req.Limit = 50
	}
	if req.SortBy == "" {
		req.SortBy = "timestamp"
	}
	if req.SortOrder == "" {
		req.SortOrder = "desc"
	}
	if req.SearchFields == nil {
		req.SearchFields = []string{"message", "user_context", "command_context", "metadata"}
	}
}

// buildSearchQuery constructs the SQL query for audit search
func (s *SearchService) buildSearchQuery(req SearchRequest) (string, []interface{}, error) {
	var conditions []string
	var args []interface{}
	argIndex := 1

	// Build base query with FTS if text query is provided
	baseQuery := `
		SELECT 
			id, timestamp, event_type, severity, message,
			user_context, cluster_context, command_context,
			correlation_id, trace_id, service_name, service_version,
			metadata, checksum, checksum_at, created_at, processed_at
			%s
		FROM audit_events
	`

	var ftsSelect, ftsJoin string
	if req.Query != "" {
		if req.RankResults {
			ftsSelect = ", ts_rank(search_vector, plainto_tsquery($" + fmt.Sprintf("%d", argIndex) + ")) as rank"
			conditions = append(conditions, "search_vector @@ plainto_tsquery($"+fmt.Sprintf("%d", argIndex)+")")
		} else {
			conditions = append(conditions, "search_vector @@ plainto_tsquery($"+fmt.Sprintf("%d", argIndex)+")")
		}
		args = append(args, req.Query)
		argIndex++
	}

	// Add filter conditions
	if req.UserID != "" {
		conditions = append(conditions, "user_context->>'user_id' = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.UserID)
		argIndex++
	}

	if len(req.EventTypes) > 0 {
		eventTypes := make([]string, len(req.EventTypes))
		for i, et := range req.EventTypes {
			eventTypes[i] = string(et)
		}
		conditions = append(conditions, "event_type = ANY($"+fmt.Sprintf("%d", argIndex)+")")
		args = append(args, pq.Array(eventTypes))
		argIndex++
	}

	if len(req.Severities) > 0 {
		severities := make([]string, len(req.Severities))
		for i, sev := range req.Severities {
			severities[i] = string(sev)
		}
		conditions = append(conditions, "severity = ANY($"+fmt.Sprintf("%d", argIndex)+")")
		args = append(args, pq.Array(severities))
		argIndex++
	}

	if req.ClusterName != "" {
		conditions = append(conditions, "cluster_context->>'cluster_name' = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.ClusterName)
		argIndex++
	}

	if req.Namespace != "" {
		conditions = append(conditions, "cluster_context->>'namespace' = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.Namespace)
		argIndex++
	}

	if req.ServiceName != "" {
		conditions = append(conditions, "service_name = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.ServiceName)
		argIndex++
	}

	if req.CorrelationID != "" {
		conditions = append(conditions, "correlation_id = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.CorrelationID)
		argIndex++
	}

	if req.TraceID != "" {
		conditions = append(conditions, "trace_id = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.TraceID)
		argIndex++
	}

	// Time range filtering with timezone support
	if !req.StartTime.IsZero() {
		if req.Timezone != "" {
			conditions = append(conditions, "timestamp AT TIME ZONE $"+fmt.Sprintf("%d", argIndex+1)+" >= $"+fmt.Sprintf("%d", argIndex))
			args = append(args, req.StartTime, req.Timezone)
			argIndex += 2
		} else {
			conditions = append(conditions, "timestamp >= $"+fmt.Sprintf("%d", argIndex))
			args = append(args, req.StartTime)
			argIndex++
		}
	}

	if !req.EndTime.IsZero() {
		if req.Timezone != "" {
			conditions = append(conditions, "timestamp AT TIME ZONE $"+fmt.Sprintf("%d", argIndex+1)+" <= $"+fmt.Sprintf("%d", argIndex))
			args = append(args, req.EndTime, req.Timezone)
			argIndex += 2
		} else {
			conditions = append(conditions, "timestamp <= $"+fmt.Sprintf("%d", argIndex))
			args = append(args, req.EndTime)
			argIndex++
		}
	}

	// Command-specific filters
	if req.NaturalLanguageQuery != "" {
		conditions = append(conditions, "command_context->>'natural_language_input' ILIKE $"+fmt.Sprintf("%d", argIndex))
		args = append(args, "%"+req.NaturalLanguageQuery+"%")
		argIndex++
	}

	if req.GeneratedCommand != "" {
		conditions = append(conditions, "command_context->>'generated_command' ILIKE $"+fmt.Sprintf("%d", argIndex))
		args = append(args, "%"+req.GeneratedCommand+"%")
		argIndex++
	}

	if len(req.RiskLevels) > 0 {
		conditions = append(conditions, "command_context->>'risk_level' = ANY($"+fmt.Sprintf("%d", argIndex)+")")
		args = append(args, pq.Array(req.RiskLevels))
		argIndex++
	}

	if len(req.ExecutionStatus) > 0 {
		conditions = append(conditions, "command_context->>'execution_status' = ANY($"+fmt.Sprintf("%d", argIndex)+")")
		args = append(args, pq.Array(req.ExecutionStatus))
		argIndex++
	}

	// Security investigation filters
	if req.IPAddress != "" {
		conditions = append(conditions, "user_context->>'ip_address' = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.IPAddress)
		argIndex++
	}

	if req.UserAgent != "" {
		conditions = append(conditions, "user_context->>'user_agent' ILIKE $"+fmt.Sprintf("%d", argIndex))
		args = append(args, "%"+req.UserAgent+"%")
		argIndex++
	}

	// Build WHERE clause
	var whereClause string
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Build ORDER BY clause with validation to prevent SQL injection
	orderBy, err := s.buildOrderByClause(req)
	if err != nil {
		return "", nil, fmt.Errorf("invalid sort parameters: %w", err)
	}

	// Build LIMIT and OFFSET
	limitOffset := fmt.Sprintf("LIMIT $%d OFFSET $%d", argIndex, argIndex+1)
	args = append(args, req.Limit, req.Offset)

	// Construct final query
	query := fmt.Sprintf(baseQuery, ftsSelect) + ftsJoin + " " + whereClause + " " + orderBy + " " + limitOffset

	return query, args, nil
}

// buildCountQuery builds the count query for pagination
func (s *SearchService) buildCountQuery(req SearchRequest) (string, []interface{}) {
	query := "SELECT COUNT(*) FROM audit_events"
	var conditions []string
	var args []interface{}
	argIndex := 1

	// Apply same filter conditions as main query (excluding FTS ranking)
	if req.Query != "" {
		conditions = append(conditions, "search_vector @@ plainto_tsquery($"+fmt.Sprintf("%d", argIndex)+")")
		args = append(args, req.Query)
		argIndex++
	}

	if req.UserID != "" {
		conditions = append(conditions, "user_context->>'user_id' = $"+fmt.Sprintf("%d", argIndex))
		args = append(args, req.UserID)
		argIndex++
	}

	// Add other filter conditions (same logic as buildSearchQuery but without SELECT fields)
	// ... (implement remaining filters similarly)

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	return query, args
}

// scanSearchResult scans a database row into a SearchResult
func (s *SearchService) scanSearchResult(rows *sql.Rows, req SearchRequest) (*SearchResult, error) {
	var event models.AuditEvent
	var userContextJSON, clusterContextJSON, commandContextJSON, metadataJSON []byte
	var rank sql.NullFloat64

	scanArgs := []interface{}{
		&event.ID, &event.Timestamp, &event.EventType, &event.Severity,
		&event.Message, &userContextJSON, &clusterContextJSON,
		&commandContextJSON, &event.CorrelationID, &event.TraceID,
		&event.ServiceName, &event.ServiceVersion, &metadataJSON,
		&event.Checksum, &event.ChecksumAt, &event.CreatedAt, &event.ProcessedAt,
	}

	if req.RankResults && req.Query != "" {
		scanArgs = append(scanArgs, &rank)
	}

	if err := rows.Scan(scanArgs...); err != nil {
		return nil, fmt.Errorf("failed to scan row: %w", err)
	}

	// Unmarshal JSON fields
	if err := s.unmarshalJSONFields(&event, userContextJSON, clusterContextJSON, commandContextJSON, metadataJSON); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON fields: %w", err)
	}

	result := &SearchResult{
		Event: &event,
	}

	if rank.Valid {
		result.Rank = rank.Float64
	}

	// Generate highlighted text if requested
	if req.HighlightMatches && req.Query != "" {
		result.HighlightedText = s.generateHighlightedText(&event, req.Query)
	}

	return result, nil
}

// unmarshalJSONFields unmarshals JSON fields from database
func (s *SearchService) unmarshalJSONFields(event *models.AuditEvent, userContextJSON, clusterContextJSON, commandContextJSON, metadataJSON []byte) error {
	if userContextJSON != nil {
		if err := json.Unmarshal(userContextJSON, &event.UserContext); err != nil {
			return fmt.Errorf("failed to unmarshal user context: %w", err)
		}
	}

	if clusterContextJSON != nil {
		if err := json.Unmarshal(clusterContextJSON, &event.ClusterContext); err != nil {
			return fmt.Errorf("failed to unmarshal cluster context: %w", err)
		}
	}

	if commandContextJSON != nil {
		if err := json.Unmarshal(commandContextJSON, &event.CommandContext); err != nil {
			return fmt.Errorf("failed to unmarshal command context: %w", err)
		}
	}

	if metadataJSON != nil {
		if err := json.Unmarshal(metadataJSON, &event.Metadata); err != nil {
			return fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return nil
}

// generateHighlightedText generates highlighted text for search matches
func (s *SearchService) generateHighlightedText(event *models.AuditEvent, query string) string {
	text := event.Message
	// Simple highlighting - replace with more sophisticated implementation if needed
	highlightedText := strings.ReplaceAll(text, query, "<mark>"+query+"</mark>")
	return highlightedText
}

// buildSuspiciousPatternQuery builds a query for suspicious pattern detection
func (s *SearchService) buildSuspiciousPatternQuery(patterns []string, baseQuery string) string {
	patternQuery := strings.Join(patterns, " | ")
	if baseQuery != "" {
		return baseQuery + " & (" + patternQuery + ")"
	}
	return patternQuery
}

// getUsedIndexes returns information about indexes used in the query
func (s *SearchService) getUsedIndexes(req SearchRequest) []string {
	var indexes []string

	if req.Query != "" {
		indexes = append(indexes, "audit_events_search_vector_idx")
	}
	if req.UserID != "" {
		indexes = append(indexes, "audit_events_user_id_idx")
	}
	if !req.StartTime.IsZero() || !req.EndTime.IsZero() {
		indexes = append(indexes, "audit_events_timestamp_idx")
	}
	if req.ClusterName != "" {
		indexes = append(indexes, "audit_events_cluster_name_idx")
	}

	return indexes
}

// isOptimizationApplied checks if query optimization was applied
func (s *SearchService) isOptimizationApplied(req SearchRequest) bool {
	// Return true if any optimization techniques are used
	return req.RankResults || len(req.SearchFields) < 10 || req.Limit <= 1000
}

// getActiveFilters returns a map of active filters
func (s *SearchService) getActiveFilters(req SearchRequest) map[string]string {
	filters := make(map[string]string)

	if req.UserID != "" {
		filters["user_id"] = req.UserID
	}
	if req.ClusterName != "" {
		filters["cluster_name"] = req.ClusterName
	}
	if req.Namespace != "" {
		filters["namespace"] = req.Namespace
	}
	if !req.StartTime.IsZero() {
		filters["start_time"] = req.StartTime.Format(time.RFC3339)
	}
	if !req.EndTime.IsZero() {
		filters["end_time"] = req.EndTime.Format(time.RFC3339)
	}

	return filters
}

// validateSearchPermissions validates user permissions for audit search operations
func (s *SearchService) validateSearchPermissions(ctx context.Context, req SearchRequest) error {
	// Check if user has general audit read permissions
	permissionReq := middleware.PermissionRequest{
		KubernetesUser:   req.UserContext.KubernetesUser,
		KubernetesGroups: req.UserContext.KubernetesGroups,
		SessionID:        req.UserContext.SessionID,
		Namespace:        "kube-chat-system", // System namespace for audit logs
		Verb:             "get",
		Resource:         "audit-events",
		CommandContext:   fmt.Sprintf("Search audit events: %s", req.Query),
	}

	response, err := s.rbacValidator.ValidatePermission(ctx, permissionReq)
	if err != nil {
		return fmt.Errorf("RBAC validation failed: %w", err)
	}

	if !response.Allowed {
		return &models.RBACPermissionError{
			User:         req.UserContext.KubernetesUser,
			Groups:       req.UserContext.KubernetesGroups,
			Resource:     "audit-events",
			Verb:         "get",
			Namespace:    "kube-chat-system",
			Reason:       response.Reason,
			Type:         models.ErrorTypePermissionDenied,
			Timestamp:    time.Now(),
			ValidationID: response.ValidationID,
		}
	}

	// Additional namespace-scoped permission checks
	if req.Namespace != "" && req.Namespace != "*" {
		namespacePermReq := middleware.PermissionRequest{
			KubernetesUser:   req.UserContext.KubernetesUser,
			KubernetesGroups: req.UserContext.KubernetesGroups,
			SessionID:        req.UserContext.SessionID,
			Namespace:        req.Namespace,
			Verb:             "get",
			Resource:         "events",
			CommandContext:   fmt.Sprintf("Search audit events in namespace: %s", req.Namespace),
		}

		nsResponse, err := s.rbacValidator.ValidatePermission(ctx, namespacePermReq)
		if err != nil {
			return fmt.Errorf("namespace RBAC validation failed: %w", err)
		}

		if !nsResponse.Allowed {
			return &models.RBACPermissionError{
				User:         req.UserContext.KubernetesUser,
				Groups:       req.UserContext.KubernetesGroups,
				Resource:     "events",
				Verb:         "get",
				Namespace:    req.Namespace,
				Reason:       nsResponse.Reason,
				Type:         models.ErrorTypePermissionDenied,
				Timestamp:    time.Now(),
				ValidationID: nsResponse.ValidationID,
			}
		}
	}

	return nil
}

// checkRateLimit validates that the user hasn't exceeded rate limits
func (s *SearchService) checkRateLimit(userID string) error {
	if userID == "" {
		return fmt.Errorf("user ID required for rate limiting")
	}

	s.rateMutex.Lock()
	defer s.rateMutex.Unlock()

	now := time.Now()

	// Get or create user rate limit tracker
	userLimit, exists := s.rateLimiter[userID]
	if !exists {
		userLimit = &UserRateLimit{
			UserID:   userID,
			Requests: make([]time.Time, 0),
		}
		s.rateLimiter[userID] = userLimit
	}

	userLimit.mutex.Lock()
	defer userLimit.mutex.Unlock()

	// Clean old requests outside the window
	windowStart := now.Add(-s.rateConfig.WindowSize)
	validRequests := make([]time.Time, 0)
	for _, requestTime := range userLimit.Requests {
		if requestTime.After(windowStart) {
			validRequests = append(validRequests, requestTime)
		}
	}
	userLimit.Requests = validRequests

	// Check if user has exceeded rate limit
	if len(userLimit.Requests) >= s.rateConfig.RequestsPerMinute {
		return fmt.Errorf("rate limit exceeded: %d requests per minute allowed, try again in %v",
			s.rateConfig.RequestsPerMinute,
			s.rateConfig.WindowSize-now.Sub(userLimit.Requests[0]))
	}

	// Check burst limit (requests in last 10 seconds)
	burstStart := now.Add(-10 * time.Second)
	burstCount := 0
	for _, requestTime := range userLimit.Requests {
		if requestTime.After(burstStart) {
			burstCount++
		}
	}

	if burstCount >= s.rateConfig.BurstLimit {
		return fmt.Errorf("burst limit exceeded: %d requests per 10 seconds allowed", s.rateConfig.BurstLimit)
	}

	// Record this request
	userLimit.Requests = append(userLimit.Requests, now)
	userLimit.LastRequest = now

	return nil
}

// startRateLimitCleanup starts a background routine to clean up old rate limit entries
func (s *SearchService) startRateLimitCleanup() {
	ticker := time.NewTicker(s.rateConfig.CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		s.cleanupRateLimitEntries()
	}
}

// cleanupRateLimitEntries removes old rate limit entries to prevent memory leaks
func (s *SearchService) cleanupRateLimitEntries() {
	s.rateMutex.Lock()
	defer s.rateMutex.Unlock()

	cutoff := time.Now().Add(-2 * s.rateConfig.WindowSize)

	for userID, userLimit := range s.rateLimiter {
		userLimit.mutex.Lock()

		// Remove users who haven't made requests recently
		if userLimit.LastRequest.Before(cutoff) {
			delete(s.rateLimiter, userID)
		}

		userLimit.mutex.Unlock()
	}
}

// validateSortField validates that the sort field is safe and allowed
func (s *SearchService) validateSortField(sortBy string) error {
	allowedSortFields := map[string]bool{
		"timestamp":      true,
		"event_type":     true,
		"severity":       true,
		"user_id":        true,
		"cluster_name":   true,
		"namespace":      true,
		"service_name":   true,
		"correlation_id": true,
		"trace_id":       true,
		"created_at":     true,
		"processed_at":   true,
		"rank":           true, // Only valid when RankResults is true
	}

	if sortBy == "" {
		return nil // Will use default
	}

	if !allowedSortFields[sortBy] {
		return fmt.Errorf("sort field '%s' is not allowed", sortBy)
	}

	return nil
}

// validateSearchFields validates that search fields are safe and allowed
func (s *SearchService) validateSearchFields(searchFields []string) error {
	allowedSearchFields := map[string]bool{
		"message":         true,
		"user_context":    true,
		"cluster_context": true,
		"command_context": true,
		"metadata":        true,
	}

	for _, field := range searchFields {
		if !allowedSearchFields[field] {
			return fmt.Errorf("search field '%s' is not allowed", field)
		}
	}

	return nil
}

// buildOrderByClause safely constructs the ORDER BY clause
func (s *SearchService) buildOrderByClause(req SearchRequest) (string, error) {
	// Default sorting
	sortBy := req.SortBy
	if sortBy == "" {
		sortBy = "timestamp"
	}

	sortOrder := strings.ToUpper(req.SortOrder)
	if sortOrder == "" {
		sortOrder = "DESC"
	}

	// Special case for FTS ranking
	if req.RankResults && req.Query != "" {
		return "ORDER BY rank DESC, timestamp DESC", nil
	}

	// Map internal field names to actual database column names
	columnMap := map[string]string{
		"timestamp":      "timestamp",
		"event_type":     "event_type",
		"severity":       "severity",
		"user_id":        "(user_context->>'user_id')",
		"cluster_name":   "(cluster_context->>'cluster_name')",
		"namespace":      "(cluster_context->>'namespace')",
		"service_name":   "service_name",
		"correlation_id": "correlation_id",
		"trace_id":       "trace_id",
		"created_at":     "created_at",
		"processed_at":   "processed_at",
		"rank":           "rank",
	}

	columnName, exists := columnMap[sortBy]
	if !exists {
		return "", fmt.Errorf("invalid sort field: %s", sortBy)
	}

	return fmt.Sprintf("ORDER BY %s %s", columnName, sortOrder), nil
}

// initializeSearchIndexes creates necessary database indexes for optimal search performance
func (s *SearchService) initializeSearchIndexes() error {
	indexes := []string{
		// Full-text search vector index (GIN)
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_search_vector_idx 
		 ON audit_events USING gin(search_vector)`,

		// Composite index for timestamp + user queries
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_timestamp_user_idx 
		 ON audit_events (timestamp DESC, (user_context->>'user_id'))`,

		// GIN index for user_context JSON
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_user_context_gin_idx 
		 ON audit_events USING gin(user_context)`,

		// GIN index for cluster_context JSON
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_cluster_context_gin_idx 
		 ON audit_events USING gin(cluster_context)`,

		// GIN index for command_context JSON
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_command_context_gin_idx 
		 ON audit_events USING gin(command_context)`,

		// Index for event_type filtering
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_event_type_idx 
		 ON audit_events (event_type)`,

		// Index for severity filtering
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_severity_idx 
		 ON audit_events (severity)`,

		// Composite index for correlation tracking
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_correlation_idx 
		 ON audit_events (correlation_id, trace_id)`,

		// Index for service filtering
		`CREATE INDEX CONCURRENTLY IF NOT EXISTS audit_events_service_idx 
		 ON audit_events (service_name, timestamp DESC)`,
	}

	for _, indexSQL := range indexes {
		if _, err := s.db.Exec(indexSQL); err != nil {
			// Log warning but don't fail - indexes might already exist
			fmt.Printf("Warning: failed to create index: %v\n", err)
		}
	}

	return nil
}
