// Package audit provides comprehensive audit trail search capabilities tests
package audit

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/pramodksahoo/kube-chat/pkg/middleware"
)


// Test data helpers
func createTestAuditEvent(eventType models.AuditEventType, userID string, message string) *models.AuditEvent {
	now := time.Now().UTC()
	return &models.AuditEvent{
		ID:        "test-event-001",
		Timestamp: now,
		EventType: eventType,
		Severity:  models.AuditSeverityInfo,
		Message:   message,
		UserContext: models.UserContext{
			UserID:    userID,
			Email:     "test@example.com",
			SessionID: "session-123",
		},
		ClusterContext: models.ClusterContext{
			ClusterName: "test-cluster",
			Namespace:   "default",
		},
		CommandContext: models.CommandContext{
			NaturalLanguageInput: "get all pods",
			GeneratedCommand:     "kubectl get pods",
			RiskLevel:           "safe",
		},
		CreatedAt: now,
	}
}

func TestNewSearchService(t *testing.T) {
	tests := []struct {
		name        string
		storage     AuditStorage
		db          *sql.DB
		wantError   bool
		expectedErr string
	}{
		{
			name:        "nil storage",
			storage:     nil,
			db:          &sql.DB{},
			wantError:   true,
			expectedErr: "storage cannot be nil",
		},
		{
			name:        "nil database",
			storage:     &MockAuditStorage{},
			db:          nil,
			wantError:   true,
			expectedErr: "database connection cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewSearchService(tt.storage, tt.db, nil) // Pass nil for RBAC validator in tests

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestSearchService_validateSearchRequest(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name        string
		request     SearchRequest
		wantError   bool
		expectedErr string
	}{
		{
			name: "valid request",
			request: SearchRequest{
				Limit:     100,
				Offset:    0,
				SortOrder: "asc",
			},
			wantError: false,
		},
		{
			name: "invalid limit - too high",
			request: SearchRequest{
				Limit: 20000,
			},
			wantError:   true,
			expectedErr: "limit must be between 0 and 10000",
		},
		{
			name: "invalid limit - negative",
			request: SearchRequest{
				Limit: -1,
			},
			wantError:   true,
			expectedErr: "limit must be between 0 and 10000",
		},
		{
			name: "invalid offset - negative",
			request: SearchRequest{
				Offset: -10,
			},
			wantError:   true,
			expectedErr: "offset cannot be negative",
		},
		{
			name: "invalid sort order",
			request: SearchRequest{
				SortOrder: "invalid",
			},
			wantError:   true,
			expectedErr: "sort_order must be 'asc' or 'desc'",
		},
		{
			name: "invalid time range - start after end",
			request: SearchRequest{
				StartTime: time.Now(),
				EndTime:   time.Now().Add(-1 * time.Hour),
			},
			wantError:   true,
			expectedErr: "start_time cannot be after end_time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateSearchRequest(&tt.request)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSearchService_applyDefaultSearchParams(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name     string
		request  SearchRequest
		expected SearchRequest
	}{
		{
			name:    "empty request gets defaults",
			request: SearchRequest{},
			expected: SearchRequest{
				Limit:        50,
				SortBy:       "timestamp",
				SortOrder:    "desc",
				SearchFields: []string{"message", "user_context", "command_context", "metadata"},
			},
		},
		{
			name: "partial request preserves existing values",
			request: SearchRequest{
				Limit:     100,
				SortBy:    "event_type",
				SortOrder: "asc",
			},
			expected: SearchRequest{
				Limit:        100,
				SortBy:       "event_type",
				SortOrder:    "asc",
				SearchFields: []string{"message", "user_context", "command_context", "metadata"},
			},
		},
		{
			name: "request with custom search fields preserves them",
			request: SearchRequest{
				SearchFields: []string{"message", "user_context"},
			},
			expected: SearchRequest{
				Limit:        50,
				SortBy:       "timestamp",
				SortOrder:    "desc",
				SearchFields: []string{"message", "user_context"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service.applyDefaultSearchParams(&tt.request)

			assert.Equal(t, tt.expected.Limit, tt.request.Limit)
			assert.Equal(t, tt.expected.SortBy, tt.request.SortBy)
			assert.Equal(t, tt.expected.SortOrder, tt.request.SortOrder)
			assert.Equal(t, tt.expected.SearchFields, tt.request.SearchFields)
		})
	}
}

func TestSearchService_buildSearchQuery(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name          string
		request       SearchRequest
		expectedQuery string
		expectedArgs  int
		wantError     bool
	}{
		{
			name: "basic query with text search",
			request: SearchRequest{
				Query:     "test query",
				Limit:     10,
				Offset:    0,
				SortBy:    "timestamp",
				SortOrder: "desc",
			},
			expectedArgs: 3, // query, limit, offset
			wantError:    false,
		},
		{
			name: "query with user filter",
			request: SearchRequest{
				UserID:    "user123",
				Limit:     10,
				Offset:    0,
				SortBy:    "timestamp",
				SortOrder: "desc",
			},
			expectedArgs: 3, // user_id, limit, offset
			wantError:    false,
		},
		{
			name: "query with time range",
			request: SearchRequest{
				StartTime: time.Now().Add(-24 * time.Hour),
				EndTime:   time.Now(),
				Limit:     10,
				Offset:    0,
				SortBy:    "timestamp",
				SortOrder: "desc",
			},
			expectedArgs: 4, // start_time, end_time, limit, offset
			wantError:    false,
		},
		{
			name: "complex query with multiple filters",
			request: SearchRequest{
				Query:         "error",
				UserID:        "user123",
				ClusterName:   "prod-cluster",
				Namespace:     "kube-system",
				EventTypes:    []models.AuditEventType{models.AuditEventTypeCommand},
				Severities:    []models.AuditSeverity{models.AuditSeverityError},
				StartTime:     time.Now().Add(-24 * time.Hour),
				EndTime:       time.Now(),
				RankResults:   true,
				Limit:         50,
				Offset:        0,
				SortBy:        "timestamp",
				SortOrder:     "desc",
			},
			expectedArgs: 10, // Many parameters
			wantError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query, args, err := service.buildSearchQuery(tt.request)

			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, query)
				assert.Contains(t, query, "SELECT")
				assert.Contains(t, query, "FROM audit_events")
				assert.Len(t, args, tt.expectedArgs)
			}
		})
	}
}

func TestSearchService_buildSuspiciousPatternQuery(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name      string
		patterns  []string
		baseQuery string
		expected  string
	}{
		{
			name:      "single pattern with empty base query",
			patterns:  []string{"suspicious"},
			baseQuery: "",
			expected:  "suspicious",
		},
		{
			name:      "multiple patterns with empty base query",
			patterns:  []string{"malware", "intrusion", "attack"},
			baseQuery: "",
			expected:  "malware | intrusion | attack",
		},
		{
			name:      "single pattern with existing base query",
			patterns:  []string{"suspicious"},
			baseQuery: "error",
			expected:  "error & (suspicious)",
		},
		{
			name:      "multiple patterns with existing base query",
			patterns:  []string{"malware", "intrusion"},
			baseQuery: "security alert",
			expected:  "security alert & (malware | intrusion)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.buildSuspiciousPatternQuery(tt.patterns, tt.baseQuery)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSearchService_getUsedIndexes(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name     string
		request  SearchRequest
		expected []string
	}{
		{
			name: "text search uses FTS index",
			request: SearchRequest{
				Query: "test query",
			},
			expected: []string{"audit_events_search_vector_idx"},
		},
		{
			name: "user filter uses user index",
			request: SearchRequest{
				UserID: "user123",
			},
			expected: []string{"audit_events_user_id_idx"},
		},
		{
			name: "time range uses timestamp index",
			request: SearchRequest{
				StartTime: time.Now().Add(-1 * time.Hour),
				EndTime:   time.Now(),
			},
			expected: []string{"audit_events_timestamp_idx"},
		},
		{
			name: "cluster filter uses cluster index",
			request: SearchRequest{
				ClusterName: "prod-cluster",
			},
			expected: []string{"audit_events_cluster_name_idx"},
		},
		{
			name: "multiple filters use multiple indexes",
			request: SearchRequest{
				Query:       "error",
				UserID:      "user123",
				ClusterName: "prod-cluster",
				StartTime:   time.Now().Add(-1 * time.Hour),
			},
			expected: []string{
				"audit_events_search_vector_idx",
				"audit_events_user_id_idx",
				"audit_events_timestamp_idx",
				"audit_events_cluster_name_idx",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.getUsedIndexes(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSearchService_isOptimizationApplied(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name     string
		request  SearchRequest
		expected bool
	}{
		{
			name: "rank results enables optimization",
			request: SearchRequest{
				RankResults: true,
			},
			expected: true,
		},
		{
			name: "small search fields enables optimization",
			request: SearchRequest{
				SearchFields: []string{"message", "user_context"},
			},
			expected: true,
		},
		{
			name: "small limit enables optimization",
			request: SearchRequest{
				Limit: 100,
			},
			expected: true,
		},
		{
			name: "large search fields and limit disables optimization",
			request: SearchRequest{
				SearchFields: make([]string, 20), // Large number of fields
				Limit:        5000,               // Large limit
				RankResults:  false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isOptimizationApplied(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSearchService_getActiveFilters(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()

	tests := []struct {
		name     string
		request  SearchRequest
		expected map[string]string
	}{
		{
			name:     "empty request returns empty filters",
			request:  SearchRequest{},
			expected: map[string]string{},
		},
		{
			name: "user filter",
			request: SearchRequest{
				UserID: "user123",
			},
			expected: map[string]string{
				"user_id": "user123",
			},
		},
		{
			name: "cluster and namespace filters",
			request: SearchRequest{
				ClusterName: "prod-cluster",
				Namespace:   "kube-system",
			},
			expected: map[string]string{
				"cluster_name": "prod-cluster",
				"namespace":    "kube-system",
			},
		},
		{
			name: "time range filters",
			request: SearchRequest{
				StartTime: startTime,
				EndTime:   endTime,
			},
			expected: map[string]string{
				"start_time": startTime.Format(time.RFC3339),
				"end_time":   endTime.Format(time.RFC3339),
			},
		},
		{
			name: "multiple filters",
			request: SearchRequest{
				UserID:      "user123",
				ClusterName: "prod-cluster",
				Namespace:   "default",
				StartTime:   startTime,
				EndTime:     endTime,
			},
			expected: map[string]string{
				"user_id":      "user123",
				"cluster_name": "prod-cluster",
				"namespace":    "default",
				"start_time":   startTime.Format(time.RFC3339),
				"end_time":     endTime.Format(time.RFC3339),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.getActiveFilters(tt.request)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSearchService_generateHighlightedText(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	tests := []struct {
		name     string
		event    *models.AuditEvent
		query    string
		expected string
	}{
		{
			name: "single match highlighting",
			event: &models.AuditEvent{
				Message: "This is an error message",
			},
			query:    "error",
			expected: "This is an <mark>error</mark> message",
		},
		{
			name: "multiple matches highlighting",
			event: &models.AuditEvent{
				Message: "Error: command error occurred",
			},
			query:    "error",
			expected: "Error: command <mark>error</mark> occurred",
		},
		{
			name: "no matches",
			event: &models.AuditEvent{
				Message: "This is a normal message",
			},
			query:    "error",
			expected: "This is a normal message",
		},
		{
			name: "case sensitive matching",
			event: &models.AuditEvent{
				Message: "This is an Error message",
			},
			query:    "error",
			expected: "This is an Error message", // No match due to case
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.generateHighlightedText(tt.event, tt.query)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkSearchService_buildSearchQuery(b *testing.B) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	request := SearchRequest{
		Query:       "test query",
		UserID:      "user123",
		ClusterName: "prod-cluster",
		EventTypes:  []models.AuditEventType{models.AuditEventTypeCommand},
		StartTime:   time.Now().Add(-24 * time.Hour),
		EndTime:     time.Now(),
		Limit:       100,
		Offset:      0,
		SortBy:      "timestamp",
		SortOrder:   "desc",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := service.buildSearchQuery(request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSearchService_validateSearchRequest(b *testing.B) {
	mockStorage := &MockAuditStorage{}
	service := &SearchService{storage: mockStorage}

	request := SearchRequest{
		Query:     "test query",
		Limit:     100,
		Offset:    0,
		SortOrder: "desc",
		StartTime: time.Now().Add(-1 * time.Hour),
		EndTime:   time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := service.validateSearchRequest(&request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// MockRBACValidator provides a mock implementation for testing
type MockRBACValidator struct {
	mock.Mock
}

func (m *MockRBACValidator) ValidatePermissions(ctx context.Context, req middleware.PermissionRequest) (*middleware.PermissionResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*middleware.PermissionResponse), args.Error(1)
}

// Security Tests - SQL Injection Prevention

func TestSearchService_validateSortField_SQLInjectionPrevention(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	mockRBAC := &MockRBACValidator{}
	service := &SearchService{storage: mockStorage, rbacValidator: mockRBAC}

	maliciousInputs := []string{
		"timestamp; DROP TABLE audit_events; --",
		"timestamp' OR '1'='1",
		"timestamp UNION SELECT * FROM users", 
		"timestamp; DELETE FROM audit_events WHERE 1=1",
		"timestamp' AND (SELECT COUNT(*) FROM users) > 0 --",
		"(SELECT password FROM users LIMIT 1)",
	}

	for _, maliciousInput := range maliciousInputs {
		t.Run("malicious_input_"+maliciousInput[:min(20, len(maliciousInput))], func(t *testing.T) {
			err := service.validateSortField(maliciousInput)
			assert.Error(t, err, "Should reject malicious sort field: %s", maliciousInput)
			assert.Contains(t, err.Error(), "is not allowed", "Should indicate field is not allowed")
		})
	}
}

// Security Tests - Rate Limiting

func TestSearchService_checkRateLimit(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	mockRBAC := &MockRBACValidator{}
	
	service := &SearchService{
		storage:      mockStorage,
		rbacValidator: mockRBAC,
		rateLimiter:  make(map[string]*UserRateLimit),
		rateConfig: RateLimitConfig{
			RequestsPerMinute: 10,
			BurstLimit:       3,
			WindowSize:       time.Minute,
		},
	}

	tests := []struct {
		name         string
		userID       string
		setupFunc    func()
		expectError  bool
		expectedErr  string
	}{
		{
			name:        "first request allowed",
			userID:      "user1",
			setupFunc:   func() {},
			expectError: false,
		},
		{
			name:   "burst limit exceeded",
			userID: "user2", 
			setupFunc: func() {
				// Pre-populate with burst limit requests
				service.rateLimiter["user2"] = &UserRateLimit{
					UserID:   "user2",
					Requests: []time.Time{
						time.Now().Add(-5 * time.Second),
						time.Now().Add(-3 * time.Second), 
						time.Now().Add(-1 * time.Second),
					},
					LastRequest: time.Now(),
				}
			},
			expectError: true,
			expectedErr: "burst limit exceeded",
		},
		{
			name:        "empty user ID",
			userID:      "",
			setupFunc:   func() {},
			expectError: true,
			expectedErr: "user ID required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test conditions  
			tt.setupFunc()

			// Execute test
			err := service.checkRateLimit(tt.userID)

			// Validate results
			if tt.expectError {
				assert.Error(t, err)
				if tt.expectedErr != "" {
					assert.Contains(t, err.Error(), tt.expectedErr)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function for test
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}