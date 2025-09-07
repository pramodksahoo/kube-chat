package export

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestExportService tests the main export service functionality
func TestExportService(t *testing.T) {
	storage := &audit.MockAuditStorage{}
	config := DefaultExportServiceConfig()
	service, err := NewExportService(storage, config)
	require.NoError(t, err)
	
	t.Run("successful_export", func(t *testing.T) {
		// Setup mock expectations
		testEvents := createTestAuditEvents(10)
		storage.On("CountEvents", mock.Anything, mock.Anything).Return(int64(10), nil)
		storage.On("QueryEvents", mock.Anything, mock.Anything).Return(testEvents, nil)
		
		request := ExportRequest{
			RequestedBy: "test-user",
			Format:      "JSON",
			Filter: ExportFilter{
				StartTime: time.Now().Add(-time.Hour),
				EndTime:   time.Now(),
			},
		}
		
		job, err := service.ExportEvents(context.Background(), request)
		require.NoError(t, err)
		require.NotNil(t, job)
		assert.Equal(t, ExportJobStatusPending, job.Status)
		
		// Wait for export to complete (with timeout)
		timeout := time.After(time.Second * 10)
		ticker := time.NewTicker(time.Millisecond * 100)
		defer ticker.Stop()
		
		for {
			select {
			case <-timeout:
				t.Fatal("Export job did not complete in time")
			case <-ticker.C:
				currentJob, err := service.GetExportJob(job.ID)
				require.NoError(t, err)
				
				if currentJob.Status == ExportJobStatusCompleted {
					assert.NotNil(t, currentJob.Result)
					assert.Equal(t, int64(10), currentJob.Result.ExportedEvents)
					assert.Equal(t, "JSON", currentJob.Result.Format)
					assert.NotEmpty(t, currentJob.Result.Files)
					return
				} else if currentJob.Status == ExportJobStatusFailed {
					t.Fatalf("Export job failed: %s", currentJob.Error)
				}
			}
		}
	})
	
	t.Run("export_with_filtering", func(t *testing.T) {
		// Test specific event type filtering
		filteredEvents := createTestAuditEventsWithType(5, models.AuditEventTypeCommandExecute)
		storage.On("CountEvents", mock.Anything, mock.MatchedBy(func(filter models.AuditEventFilter) bool {
			return len(filter.EventTypes) > 0 && filter.EventTypes[0] == models.AuditEventTypeCommandExecute
		})).Return(int64(5), nil)
		storage.On("QueryEvents", mock.Anything, mock.MatchedBy(func(filter models.AuditEventFilter) bool {
			return len(filter.EventTypes) > 0 && filter.EventTypes[0] == models.AuditEventTypeCommandExecute
		})).Return(filteredEvents, nil)
		
		request := ExportRequest{
			RequestedBy: "test-user",
			Format:      "CEF",
			Filter: ExportFilter{
				EventTypes: []models.AuditEventType{models.AuditEventTypeCommandExecute},
				StartTime:  time.Now().Add(-time.Hour),
				EndTime:    time.Now(),
			},
		}
		
		job, err := service.ExportEvents(context.Background(), request)
		require.NoError(t, err)
		assert.Equal(t, "CEF", job.Request.Format)
		assert.Contains(t, job.Request.Filter.EventTypes, models.AuditEventTypeCommandExecute)
	})
	
	t.Run("export_pagination", func(t *testing.T) {
		// Test large dataset pagination
		largeEventSet := createTestAuditEvents(1500)
		storage.On("CountEvents", mock.Anything, mock.Anything).Return(int64(1500), nil)
		
		// Mock paginated queries
		pageSize := config.DefaultPageSize
		for i := 0; i < 1500; i += pageSize {
			end := i + pageSize
			if end > 1500 {
				end = 1500
			}
			pageEvents := largeEventSet[i:end]
			
			storage.On("QueryEvents", mock.Anything, mock.MatchedBy(func(filter models.AuditEventFilter) bool {
				return filter.Offset == i && filter.Limit == pageSize
			})).Return(pageEvents, nil)
		}
		
		request := ExportRequest{
			RequestedBy: "test-user",
			Format:      "JSON",
			PageSize:    pageSize,
		}
		
		job, err := service.ExportEvents(context.Background(), request)
		require.NoError(t, err)
		
		// Wait for completion and verify all events were processed
		waitForJobCompletion(t, service, job.ID, time.Second*30)
		
		finalJob, err := service.GetExportJob(job.ID)
		require.NoError(t, err)
		assert.Equal(t, ExportJobStatusCompleted, finalJob.Status)
		assert.Equal(t, int64(1500), finalJob.Result.ExportedEvents)
	})
	
	t.Run("concurrent_export_limit", func(t *testing.T) {
		// Fill up to the maximum concurrent exports
		for i := 0; i < config.MaxConcurrentExports; i++ {
			storage.On("CountEvents", mock.Anything, mock.Anything).Return(int64(1), nil)
			storage.On("QueryEvents", mock.Anything, mock.Anything).Return(createTestAuditEvents(1), nil)
			
			request := ExportRequest{
				RequestedBy: "test-user",
				Format:      "JSON",
				ExportID:    fmt.Sprintf("concurrent-test-%d", i),
			}
			
			_, err := service.ExportEvents(context.Background(), request)
			require.NoError(t, err)
		}
		
		// This one should fail due to concurrent limit
		request := ExportRequest{
			RequestedBy: "test-user",
			Format:      "JSON",
			ExportID:    "should-fail",
		}
		
		_, err = service.ExportEvents(context.Background(), request)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "maximum concurrent exports reached")
	})
	
	// Clear all mock expectations
	storage.ExpectedCalls = nil
}

// TestExportJobTracker tests the job tracking functionality
func TestExportJobTracker(t *testing.T) {
	tracker := NewExportJobTracker(time.Hour * 24)
	defer tracker.Stop()
	
	t.Run("job_lifecycle", func(t *testing.T) {
		job := &ExportJob{
			ID: "test-job-1",
			Request: ExportRequest{
				RequestedBy: "test-user",
				Format:      "JSON",
			},
			Status:    ExportJobStatusPending,
			CreatedAt: time.Now().UTC(),
			ExpiresAt: time.Now().UTC().Add(time.Hour * 24),
		}
		
		// Add job
		tracker.AddJob(job)
		
		// Retrieve job
		retrievedJob := tracker.GetJob("test-job-1")
		require.NotNil(t, retrievedJob)
		assert.Equal(t, "test-job-1", retrievedJob.ID)
		assert.Equal(t, ExportJobStatusPending, retrievedJob.Status)
		
		// Update status
		tracker.UpdateJobStatus("test-job-1", ExportJobStatusRunning, "")
		updatedJob := tracker.GetJob("test-job-1")
		assert.Equal(t, ExportJobStatusRunning, updatedJob.Status)
		
		// Complete job
		tracker.UpdateJobStatus("test-job-1", ExportJobStatusCompleted, "")
		completedJob := tracker.GetJob("test-job-1")
		assert.Equal(t, ExportJobStatusCompleted, completedJob.Status)
		assert.False(t, completedJob.CompletedAt.IsZero())
		
		// Verify metrics
		assert.Equal(t, int64(1), tracker.GetTotalJobCount())
		assert.Equal(t, int64(1), tracker.GetCompletedJobCount())
		assert.Equal(t, 0, tracker.GetActiveJobCount())
	})
	
	t.Run("job_search_and_filtering", func(t *testing.T) {
		// Add multiple test jobs
		for i := 0; i < 10; i++ {
			job := &ExportJob{
				ID: fmt.Sprintf("search-job-%d", i),
				Request: ExportRequest{
					RequestedBy: fmt.Sprintf("user-%d", i%3), // 3 different users
					Format:      "JSON",
				},
				Status:    ExportJobStatusCompleted,
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(time.Hour * 24),
			}
			tracker.AddJob(job)
		}
		
		// Test user filtering
		userJobs := tracker.GetJobsByUser("user-0", 10, 0)
		assert.Len(t, userJobs, 4) // Jobs 0, 3, 6, 9
		
		// Test status filtering
		completedJobs := tracker.ListJobs(ExportJobStatusCompleted, "", 10, 0)
		assert.Len(t, completedJobs, 10) // All jobs are completed
		
		// Test combined filtering
		userCompletedJobs := tracker.ListJobs(ExportJobStatusCompleted, "user-1", 10, 0)
		assert.Len(t, userCompletedJobs, 3) // Jobs 1, 4, 7
	})
	
	t.Run("job_cleanup", func(t *testing.T) {
		// Add an expired job
		expiredJob := &ExportJob{
			ID: "expired-job",
			Request: ExportRequest{
				RequestedBy: "test-user",
				Format:      "JSON",
			},
			Status:    ExportJobStatusCompleted,
			CreatedAt: time.Now().UTC().Add(-time.Hour * 48), // 48 hours ago
			ExpiresAt: time.Now().UTC().Add(-time.Hour * 24), // Expired 24 hours ago
		}
		tracker.AddJob(expiredJob)
		
		// Trigger cleanup
		cleared := tracker.ClearCompletedJobs(time.Hour * 36) // Clear jobs older than 36 hours
		assert.Greater(t, cleared, 0)
		
		// Verify expired job is removed
		retrievedJob := tracker.GetJob("expired-job")
		assert.Nil(t, retrievedJob)
	})
}

// TestExportAuthentication tests the export authentication functionality
func TestExportAuthentication(t *testing.T) {
	config := DefaultExportAuthConfig()
	authService := NewExportAuthService(config)
	
	t.Run("successful_authorization", func(t *testing.T) {
		authCtx := &AuthContext{
			UserID:          "admin-user",
			Email:           "admin@company.com",
			Name:            "Admin User",
			Roles:           []string{"admin"},
			Groups:          []string{"admin"},
			SessionID:       "admin-session",
			AuthenticatedAt: time.Now(),
			ExpiresAt:       time.Now().Add(time.Hour * 8),
		}
		
		// Add required permissions
		authCtx.Permissions = []ExportPermission{
			{
				Resource: "audit",
				Actions:  []string{"read", "export"},
				Scope:    "global",
			},
		}
		
		request := &ExportRequest{
			RequestedBy: "admin-user",
			Format:      "JSON",
		}
		
		result, err := authService.AuthorizeExportRequest(context.Background(), authCtx, request)
		require.NoError(t, err)
		assert.True(t, result.Authorized)
		assert.Equal(t, "admin-user", result.UserID)
		assert.NotEmpty(t, result.Permissions)
	})
	
	t.Run("insufficient_permissions", func(t *testing.T) {
		authCtx := &AuthContext{
			UserID:          "regular-user",
			Email:           "user@company.com",
			Name:            "Regular User",
			Roles:           []string{"user"},
			Groups:          []string{"default"},
			SessionID:       "user-session",
			AuthenticatedAt: time.Now(),
			ExpiresAt:       time.Now().Add(time.Hour * 8),
		}
		
		// User has limited permissions
		authCtx.Permissions = []ExportPermission{
			{
				Resource: "audit",
				Actions:  []string{"read"}, // Missing "export" action
				Scope:    "namespace",
			},
		}
		
		request := &ExportRequest{
			RequestedBy: "regular-user",
			Format:      "JSON",
		}
		
		result, err := authService.AuthorizeExportRequest(context.Background(), authCtx, request)
		require.NoError(t, err)
		assert.False(t, result.Authorized)
		assert.Contains(t, result.Reason, "Insufficient permissions")
	})
	
	t.Run("rate_limiting", func(t *testing.T) {
		// Configure strict rate limiting
		strictConfig := DefaultExportAuthConfig()
		strictConfig.RateLimit.Enabled = true
		strictConfig.RateLimit.RequestsPerMinute = 1
		strictAuthService := NewExportAuthService(strictConfig)
		
		authCtx := &AuthContext{
			UserID:          "test-user",
			Email:           "test@company.com",
			SessionID:       "test-session",
			AuthenticatedAt: time.Now(),
			ExpiresAt:       time.Now().Add(time.Hour),
			Permissions: []ExportPermission{
				{
					Resource: "audit",
					Actions:  []string{"read", "export"},
					Scope:    "global",
				},
			},
		}
		
		request := &ExportRequest{
			RequestedBy: "test-user",
			Format:      "JSON",
		}
		
		// First request should succeed
		result1, err := strictAuthService.AuthorizeExportRequest(context.Background(), authCtx, request)
		require.NoError(t, err)
		assert.True(t, result1.Authorized)
		
		// Note: Actual rate limiting implementation would track requests
		// This is a placeholder test structure
	})
}

// Helper functions

func createTestAuditEvents(count int) []*models.AuditEvent {
	events := make([]*models.AuditEvent, count)
	for i := 0; i < count; i++ {
		event, _ := models.NewAuditEventBuilder().
			WithEventType(models.AuditEventTypeCommandExecute).
			WithSeverity(models.AuditSeverityInfo).
			WithMessage(fmt.Sprintf("Test event %d", i)).
			WithUserContextFromUser(&models.User{
				ID:    fmt.Sprintf("user-%d", i),
				Email: fmt.Sprintf("user%d@example.com", i),
				Name:  fmt.Sprintf("User %d", i),
			}, fmt.Sprintf("session-%d", i), "192.168.1.1", "test-agent").
			WithService("test-service", "1.0.0").
			Build()
		events[i] = event
	}
	return events
}

func createTestAuditEventsWithType(count int, eventType models.AuditEventType) []*models.AuditEvent {
	events := createTestAuditEvents(count)
	for _, event := range events {
		event.EventType = eventType
	}
	return events
}

func waitForJobCompletion(t *testing.T, service *ExportService, jobID string, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	
	for time.Now().Before(deadline) {
		select {
		case <-ticker.C:
			job, err := service.GetExportJob(jobID)
			require.NoError(t, err)
			
			switch job.Status {
			case ExportJobStatusCompleted:
				return
			case ExportJobStatusFailed:
				t.Fatalf("Export job failed: %s", job.Error)
			case ExportJobStatusCancelled:
				t.Fatalf("Export job was cancelled")
			}
		}
	}
	
	t.Fatalf("Export job did not complete within timeout %v", timeout)
}

// Benchmark tests for performance validation

func BenchmarkExportService(b *testing.B) {
	storage := &audit.MockAuditStorage{}
	config := DefaultExportServiceConfig()
	service, err := NewExportService(storage, config)
	require.NoError(b, err)
	
	// Setup mock expectations
	testEvents := createTestAuditEvents(1000)
	storage.On("CountEvents", mock.Anything, mock.Anything).Return(int64(1000), nil)
	storage.On("QueryEvents", mock.Anything, mock.Anything).Return(testEvents, nil)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		request := ExportRequest{
			ExportID:    fmt.Sprintf("bench-export-%d", i),
			RequestedBy: "bench-user",
			Format:      "JSON",
		}
		
		_, err := service.ExportEvents(context.Background(), request)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJobTracker(b *testing.B) {
	tracker := NewExportJobTracker(time.Hour * 24)
	defer tracker.Stop()
	
	b.ResetTimer()
	
	b.Run("AddJob", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			job := &ExportJob{
				ID: fmt.Sprintf("bench-job-%d", i),
				Request: ExportRequest{
					RequestedBy: "bench-user",
					Format:      "JSON",
				},
				Status:    ExportJobStatusPending,
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(time.Hour * 24),
			}
			tracker.AddJob(job)
		}
	})
	
	b.Run("GetJob", func(b *testing.B) {
		// Pre-populate with jobs
		for i := 0; i < 1000; i++ {
			job := &ExportJob{
				ID: fmt.Sprintf("get-bench-job-%d", i),
				Request: ExportRequest{
					RequestedBy: "bench-user",
					Format:      "JSON",
				},
				Status:    ExportJobStatusPending,
				CreatedAt: time.Now().UTC(),
				ExpiresAt: time.Now().UTC().Add(time.Hour * 24),
			}
			tracker.AddJob(job)
		}
		
		b.ResetTimer()
		
		for i := 0; i < b.N; i++ {
			jobID := fmt.Sprintf("get-bench-job-%d", i%1000)
			job := tracker.GetJob(jobID)
			if job == nil {
				b.Fatal("Job not found")
			}
		}
	})
}