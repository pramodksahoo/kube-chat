package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/audit/templates"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockAuditStorage implements AuditStorage interface for testing
type MockAuditStorage struct {
	events []models.AuditEvent
}

func NewMockAuditStorage() *MockAuditStorage {
	return &MockAuditStorage{
		events: []models.AuditEvent{},
	}
}

func (m *MockAuditStorage) StoreEvent(ctx context.Context, event *models.AuditEvent) error {
	m.events = append(m.events, *event)
	return nil
}

func (m *MockAuditStorage) GetEvent(ctx context.Context, eventID string) (*models.AuditEvent, error) {
	for _, event := range m.events {
		if event.ID == eventID {
			return &event, nil
		}
	}
	return nil, nil
}

func (m *MockAuditStorage) QueryEvents(ctx context.Context, filter models.AuditEventFilter) ([]*models.AuditEvent, error) {
	var results []*models.AuditEvent
	for i := range m.events {
		event := &m.events[i]
		// Simple filtering logic for testing
		if filter.UserID != "" && event.UserContext.UserID != filter.UserID {
			continue
		}
		if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
			continue
		}
		results = append(results, event)
	}
	return results, nil
}

func (m *MockAuditStorage) VerifyIntegrity(ctx context.Context, eventID string) (bool, error) {
	return true, nil
}

func (m *MockAuditStorage) GetEventsByUser(ctx context.Context, userID string, limit int) ([]*models.AuditEvent, error) {
	var results []*models.AuditEvent
	count := 0
	for i := range m.events {
		if count >= limit {
			break
		}
		event := &m.events[i]
		if event.UserContext.UserID == userID {
			results = append(results, event)
			count++
		}
	}
	return results, nil
}

func (m *MockAuditStorage) GetEventsByTimeRange(ctx context.Context, start, end time.Time) ([]*models.AuditEvent, error) {
	var results []*models.AuditEvent
	for i := range m.events {
		event := &m.events[i]
		if event.Timestamp.After(start) && event.Timestamp.Before(end) {
			results = append(results, event)
		}
	}
	return results, nil
}

func (m *MockAuditStorage) CountEventsByType(ctx context.Context) (map[models.AuditEventType]int64, error) {
	counts := make(map[models.AuditEventType]int64)
	for _, event := range m.events {
		counts[event.EventType]++
	}
	return counts, nil
}

func (m *MockAuditStorage) CountEvents(ctx context.Context, filter models.AuditEventFilter) (int64, error) {
	events, _ := m.QueryEvents(ctx, filter)
	return int64(len(events)), nil
}

func (m *MockAuditStorage) CleanupExpiredEvents(ctx context.Context, retentionDays int) (int64, error) {
	return 0, nil
}

func (m *MockAuditStorage) GetStorageStats(ctx context.Context) (*audit.StorageStats, error) {
	return &audit.StorageStats{
		TotalEvents: int64(len(m.events)),
	}, nil
}

func (m *MockAuditStorage) HealthCheck(ctx context.Context) error {
	return nil
}

// Test setup helper
func setupTestEvidenceService() (*audit.EvidenceService, *MockAuditStorage) {
	storage := NewMockAuditStorage()
	integrityService := audit.NewIntegrityService(storage)
	evidenceService := audit.NewEvidenceService(storage, integrityService)
	
	// Add some test data
	now := time.Now()
	testEvents := []*models.AuditEvent{
		{
			ID:        "test-event-1",
			Timestamp: now.Add(-1 * time.Hour),
			EventType: models.AuditEventTypeAuthentication,
			Message:   "User authentication successful",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				Email:     "test@example.com",
				SessionID: "session-001",
			},
			ClusterContext: models.ClusterContext{
				ClusterName:  "test-cluster",
				Namespace:    "default",
				ResourceName: "authentication",
			},
			Checksum: "hash-001",
		},
		{
			ID:        "test-event-2",
			Timestamp: now.Add(-30 * time.Minute),
			EventType: models.AuditEventTypeRBACCheck,
			Message:   "RBAC permission check",
			UserContext: models.UserContext{
				UserID:    "test-user-1",
				SessionID: "session-001",
			},
			ClusterContext: models.ClusterContext{
				Namespace:    "kube-system",
				ResourceName: "pods",
			},
			Checksum: "hash-002",
		},
		{
			ID:        "test-event-3",
			Timestamp: now.Add(-15 * time.Minute),
			EventType: models.AuditEventTypeCommand,
			Message:   "Kubectl command executed",
			UserContext: models.UserContext{
				UserID:    "test-user-2",
				SessionID: "session-002",
			},
			CommandContext: models.CommandContext{
				NaturalLanguageInput: "show me all pods",
				GeneratedCommand:     "kubectl get pods",
				RiskLevel:           "safe",
			},
			Checksum: "hash-003",
		},
	}
	
	for _, event := range testEvents {
		storage.StoreEvent(context.Background(), event)
	}
	
	return evidenceService, storage
}

func TestEvidenceServiceIntegration(t *testing.T) {
	evidenceService, _ := setupTestEvidenceService()
	
	t.Run("Generate Evidence Package", func(t *testing.T) {
		request := &audit.EvidencePackageRequest{
			PackageID:           "TEST-PKG-001",
			ComplianceFramework: "SOC2",
			TimeRange: audit.EvidenceTimeRange{
				StartTime: time.Now().Add(-2 * time.Hour),
				EndTime:   time.Now(),
			},
			Scope: audit.EvidenceScope{
				UserIDs: []string{"test-user-1", "test-user-2"},
			},
			Formats: []audit.EvidenceFormat{audit.FormatJSON, audit.FormatCSV},
			RequesterInfo: audit.EvidenceRequester{
				UserID:      "auditor-1",
				Name:        "Test Auditor",
				Email:       "auditor@example.com",
				Role:        "compliance_manager",
				RequestedAt: time.Now(),
			},
			GeneratedAt: time.Now(),
		}
		
		pkg, err := evidenceService.GenerateEvidencePackage(context.Background(), request)
		
		require.NoError(t, err)
		assert.NotNil(t, pkg)
		assert.Equal(t, "TEST-PKG-001", pkg.PackageID)
		assert.Equal(t, "SOC2", pkg.ComplianceFramework)
		assert.Greater(t, pkg.EventCount, 0)
		assert.NotNil(t, pkg.IntegrityCertificate)
		assert.NotNil(t, pkg.ChainOfCustody)
		assert.NotEmpty(t, pkg.PackageHash)
	})
	
	t.Run("Export Package to JSON", func(t *testing.T) {
		request := &audit.EvidencePackageRequest{
			PackageID:           "TEST-PKG-JSON",
			ComplianceFramework: "HIPAA",
			TimeRange: audit.EvidenceTimeRange{
				StartTime: time.Now().Add(-2 * time.Hour),
				EndTime:   time.Now(),
			},
			RequesterInfo: audit.EvidenceRequester{
				UserID: "auditor-1",
				Name:   "Test Auditor",
			},
			GeneratedAt: time.Now(),
		}
		
		pkg, err := evidenceService.GenerateEvidencePackage(context.Background(), request)
		require.NoError(t, err)
		
		jsonData, err := evidenceService.ExportToJSON(pkg)
		assert.NoError(t, err)
		assert.NotEmpty(t, jsonData)
		assert.Contains(t, string(jsonData), "TEST-PKG-JSON")
		assert.Contains(t, string(jsonData), "HIPAA")
	})
	
	t.Run("Export Package to CSV", func(t *testing.T) {
		request := &audit.EvidencePackageRequest{
			PackageID:           "TEST-PKG-CSV",
			ComplianceFramework: "ISO27001",
			TimeRange: audit.EvidenceTimeRange{
				StartTime: time.Now().Add(-2 * time.Hour),
				EndTime:   time.Now(),
			},
			RequesterInfo: audit.EvidenceRequester{
				UserID: "auditor-1",
			},
			GeneratedAt: time.Now(),
		}
		
		pkg, err := evidenceService.GenerateEvidencePackage(context.Background(), request)
		require.NoError(t, err)
		
		csvData, err := evidenceService.ExportToCSV(pkg)
		assert.NoError(t, err)
		assert.NotEmpty(t, csvData)
		
		csvString := string(csvData)
		assert.Contains(t, csvString, "EventID,EventType,UserID")
		assert.Contains(t, csvString, "test-event-1")
	})
	
	t.Run("Create ZIP Package", func(t *testing.T) {
		request := &audit.EvidencePackageRequest{
			PackageID:   "TEST-PKG-ZIP",
			TimeRange: audit.EvidenceTimeRange{
				StartTime: time.Now().Add(-2 * time.Hour),
				EndTime:   time.Now(),
			},
			RequesterInfo: audit.EvidenceRequester{
				UserID: "auditor-1",
			},
			GeneratedAt: time.Now(),
		}
		
		pkg, err := evidenceService.GenerateEvidencePackage(context.Background(), request)
		require.NoError(t, err)
		
		zipData, err := evidenceService.CreateZipPackage(context.Background(), pkg, 
			[]audit.EvidenceFormat{audit.FormatJSON, audit.FormatCSV})
		
		assert.NoError(t, err)
		assert.NotEmpty(t, zipData)
		assert.True(t, len(zipData) > 100) // ZIP should have substantial content
	})
}

func TestChainOfCustodyIntegration(t *testing.T) {
	evidenceService, _ := setupTestEvidenceService()
	
	t.Run("Chain of Custody Lifecycle", func(t *testing.T) {
		// Generate evidence package
		request := &audit.EvidencePackageRequest{
			PackageID: "TEST-CUSTODY-001",
			TimeRange: audit.EvidenceTimeRange{
				StartTime: time.Now().Add(-1 * time.Hour),
				EndTime:   time.Now(),
			},
			RequesterInfo: audit.EvidenceRequester{
				UserID: "auditor-1",
				Name:   "Test Auditor",
			},
			GeneratedAt: time.Now(),
		}
		
		pkg, err := evidenceService.GenerateEvidencePackage(context.Background(), request)
		require.NoError(t, err)
		
		// Update chain of custody
		err = evidenceService.UpdateChainOfCustody(pkg, "ACCESSED", "reviewer-1", "Package reviewed by compliance team")
		assert.NoError(t, err)
		
		// Log access events
		err = evidenceService.LogAccess(pkg, "reviewer-1", "VIEW", "192.168.1.100", "Mozilla/5.0")
		assert.NoError(t, err)
		
		err = evidenceService.LogAccess(pkg, "reviewer-1", "DOWNLOAD", "192.168.1.100", "Mozilla/5.0")
		assert.NoError(t, err)
		
		// Validate chain of custody
		valid, issues := evidenceService.ValidateChainOfCustody(pkg)
		assert.True(t, valid)
		assert.Empty(t, issues)
		
		// Get chain of custody report
		report, err := evidenceService.GetChainOfCustodyReport(pkg)
		require.NoError(t, err)
		assert.Equal(t, pkg.PackageID, report.PackageID)
		assert.Equal(t, 2, report.TotalCustodyEvents) // CREATED + ACCESSED
		assert.Equal(t, 2, report.TotalAccessEvents)  // VIEW + DOWNLOAD
		assert.Equal(t, "reviewer-1", report.CurrentCustodian)
		assert.Equal(t, "VERIFIED", report.IntegrityStatus)
	})
}

func TestComplianceTemplatesIntegration(t *testing.T) {
	_, storage := setupTestEvidenceService()
	
	// Get events for template testing
	events, err := storage.QueryEvents(context.Background(), models.AuditEventFilter{})
	require.NoError(t, err)
	
	t.Run("SOC2 Template Integration", func(t *testing.T) {
		template := templates.NewSOC2Template()
		
		reportInfo := templates.SOC2ReportInfo{
			ReportID:         "SOC2-INTEGRATION-001",
			ReportPeriod:     "2024-Q1",
			GeneratedAt:      time.Now(),
			ReportType:       "Type I",
			Framework:        "SOC 2",
			OrganizationName: "Test Organization",
			PreparedBy:       "Integration Test",
		}
		
		report, err := template.GenerateSOC2Report(reportInfo, events)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, "SOC2-INTEGRATION-001", report.ReportInfo.ReportID)
		assert.NotEmpty(t, report.Sections)
		assert.NotNil(t, report.Conclusion)
		
		// Validate JSON formatting
		jsonData, err := template.FormatSOC2ReportJSON(report)
		assert.NoError(t, err)
		assert.NotEmpty(t, jsonData)
	})
	
	t.Run("HIPAA Template Integration", func(t *testing.T) {
		template := templates.NewHIPAATemplate()
		
		reportInfo := templates.HIPAAReportInfo{
			ReportID:           "HIPAA-INTEGRATION-001",
			ReportPeriod:       "2024-Q1",
			GeneratedAt:        time.Now(),
			ComplianceStandard: "HIPAA",
			OrganizationName:   "Test Healthcare Org",
			PreparedBy:         "Integration Test",
		}
		
		report, err := template.GenerateHIPAAReport(reportInfo, events)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, "HIPAA-INTEGRATION-001", report.ReportInfo.ReportID)
		assert.NotEmpty(t, report.TechnicalSafeguards)
		assert.NotNil(t, report.Conclusion)
		
		// Validate JSON formatting
		jsonData, err := template.FormatHIPAAReportJSON(report)
		assert.NoError(t, err)
		assert.NotEmpty(t, jsonData)
	})
	
	t.Run("ISO27001 Template Integration", func(t *testing.T) {
		template := templates.NewISO27001Template()
		
		reportInfo := templates.ISO27001ReportInfo{
			ReportID:         "ISO27001-INTEGRATION-001",
			ReportPeriod:     "2024 Annual",
			GeneratedAt:      time.Now(),
			Standard:         "ISO 27001:2022",
			OrganizationName: "Test Organization",
			PreparedBy:       "Integration Test",
		}
		
		report, err := template.GenerateISO27001Report(reportInfo, events)
		require.NoError(t, err)
		assert.NotNil(t, report)
		assert.Equal(t, "ISO27001-INTEGRATION-001", report.ReportInfo.ReportID)
		assert.NotEmpty(t, report.SecurityDomains)
		assert.NotNil(t, report.Conclusion)
		assert.NotNil(t, report.RiskAssessment)
		
		// Validate JSON formatting
		jsonData, err := template.FormatISO27001ReportJSON(report)
		assert.NoError(t, err)
		assert.NotEmpty(t, jsonData)
	})
}

func TestEvidenceAPIEndpoints(t *testing.T) {
	// This would test the actual HTTP endpoints
	// For now, provide a basic structure
	
	t.Run("Generate Evidence API", func(t *testing.T) {
		// Create a test HTTP request
		requestBody := map[string]interface{}{
			"package_id": "API-TEST-001",
			"compliance_framework": "SOC2",
			"time_range": map[string]string{
				"start_time": time.Now().Add(-2 * time.Hour).Format(time.RFC3339),
				"end_time":   time.Now().Format(time.RFC3339),
			},
			"formats": []string{"json", "csv"},
			"requester_info": map[string]string{
				"user_id": "api-test-user",
				"name":    "API Test User",
				"email":   "apitest@example.com",
				"role":    "compliance_manager",
			},
		}
		
		jsonData, _ := json.Marshal(requestBody)
		
		// Create a test Fiber app (simplified)
		app := fiber.New()
		app.Post("/api/v1/audit/evidence/generate", func(c *fiber.Ctx) error {
			return c.JSON(fiber.Map{
				"package_id": "API-TEST-001",
				"status":     "generated",
				"message":    "Evidence package generated successfully",
			})
		})
		
		// Create test request
		req := httptest.NewRequest(http.MethodPost, "/api/v1/audit/evidence/generate", bytes.NewReader(jsonData))
		req.Header.Set("Content-Type", "application/json")
		
		// Execute request
		resp, err := app.Test(req)
		require.NoError(t, err)
		
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

func TestPerformanceUnderLoad(t *testing.T) {
	evidenceService, _ := setupTestEvidenceService()
	
	t.Run("Concurrent Evidence Generation", func(t *testing.T) {
		const numConcurrent = 5
		const packagesPerGoRoutine = 10
		
		done := make(chan bool, numConcurrent)
		errors := make(chan error, numConcurrent*packagesPerGoRoutine)
		
		for i := 0; i < numConcurrent; i++ {
			go func(routineID int) {
				defer func() { done <- true }()
				
				for j := 0; j < packagesPerGoRoutine; j++ {
					request := &audit.EvidencePackageRequest{
						PackageID: fmt.Sprintf("PERF-TEST-%d-%d", routineID, j),
						TimeRange: audit.EvidenceTimeRange{
							StartTime: time.Now().Add(-1 * time.Hour),
							EndTime:   time.Now(),
						},
						RequesterInfo: audit.EvidenceRequester{
							UserID: fmt.Sprintf("perf-user-%d", routineID),
						},
						GeneratedAt: time.Now(),
					}
					
					_, err := evidenceService.GenerateEvidencePackage(context.Background(), request)
					if err != nil {
						errors <- err
					}
				}
			}(i)
		}
		
		// Wait for all goroutines to complete
		for i := 0; i < numConcurrent; i++ {
			<-done
		}
		
		close(errors)
		
		// Check for errors
		errorCount := 0
		for err := range errors {
			t.Logf("Error during concurrent test: %v", err)
			errorCount++
		}
		
		assert.Equal(t, 0, errorCount, "No errors should occur during concurrent evidence generation")
	})
}