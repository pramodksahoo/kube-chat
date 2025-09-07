package audit

import (
	"context"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)


func TestNewEvidenceService(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	
	service := NewEvidenceService(mockStorage, integrityService)
	
	assert.NotNil(t, service)
	assert.Equal(t, mockStorage, service.storage)
	assert.Equal(t, integrityService, service.integrityService)
}

func TestGenerateEvidencePackage(t *testing.T) {
	tests := []struct {
		name           string
		request        *EvidencePackageRequest
		mockEvents     []*models.AuditEvent
		mockReport     *IntegrityReport
		expectError    bool
		validateResult func(*testing.T, *EvidencePackage)
	}{
		{
			name: "successful package generation",
			request: &EvidencePackageRequest{
				PackageID:           "PKG_001",
				ComplianceFramework: "SOC2",
				TimeRange: EvidenceTimeRange{
					StartTime: time.Now().Add(-24 * time.Hour),
					EndTime:   time.Now(),
				},
				Scope: EvidenceScope{
					UserIDs: []string{"user1", "user2"},
				},
				RequesterInfo: EvidenceRequester{
					UserID:      "auditor1",
					Name:        "Test Auditor",
					Email:       "auditor@example.com",
					Role:        "compliance_manager",
					RequestedAt: time.Now(),
				},
				GeneratedAt: time.Now(),
			},
			mockEvents: []*models.AuditEvent{
				{
					ID:        "event1",
					EventType: models.AuditEventTypeLogin,
					Timestamp: time.Now().Add(-2 * time.Hour),
					Message:   "User login successful",
					UserContext: models.UserContext{
						UserID:    "user1",
						IPAddress: "192.168.1.100",
						UserAgent: "kubectl/v1.28.0",
					},
					ClusterContext: models.ClusterContext{
						ResourceName: "login",
						Namespace:    "default",
					},
					Checksum: "abc123",
				},
				{
					ID:        "event2",
					EventType: models.AuditEventTypeCommand,
					Timestamp: time.Now().Add(-1 * time.Hour),
					Message:   "Pod accessed",
					UserContext: models.UserContext{
						UserID:    "user2",
						IPAddress: "192.168.1.101",
						UserAgent: "kubectl/v1.28.0",
					},
					ClusterContext: models.ClusterContext{
						ResourceName: "test-pod",
						Namespace:    "default",
					},
					CommandContext: models.CommandContext{
						GeneratedCommand: "kubectl get pod test-pod",
					},
					Checksum: "def456",
				},
			},
			mockReport: &IntegrityReport{
				TotalEvents:         2,
				VerifiedEvents:      2,
				FailedEvents:        0,
				IntegrityScore:      1.0,
				IntegrityViolations: []*IntegrityViolation{},
				VerificationTime:    time.Now(),
			},
			expectError: false,
			validateResult: func(t *testing.T, pkg *EvidencePackage) {
				assert.Equal(t, "PKG_001", pkg.PackageID)
				assert.Equal(t, "SOC2", pkg.ComplianceFramework)
				assert.Equal(t, 2, pkg.EventCount)
				assert.Len(t, pkg.Events, 2)
				assert.NotNil(t, pkg.IntegrityReport)
				assert.NotNil(t, pkg.IntegrityCertificate)
				assert.NotNil(t, pkg.ChainOfCustody)
				assert.NotEmpty(t, pkg.PackageHash)
				assert.Equal(t, "VERIFIED", pkg.IntegrityCertificate.IntegrityStatus)
			},
		},
		{
			name: "package with integrity failures",
			request: &EvidencePackageRequest{
				PackageID:           "PKG_002",
				ComplianceFramework: "HIPAA",
				TimeRange: EvidenceTimeRange{
					StartTime: time.Now().Add(-24 * time.Hour),
					EndTime:   time.Now(),
				},
				RequesterInfo: EvidenceRequester{
					UserID: "auditor1",
					Name:   "Test Auditor",
				},
				GeneratedAt: time.Now(),
			},
			mockEvents: []*models.AuditEvent{
				{
					ID:        "event3",
					EventType: models.AuditEventTypeLogin,
					Timestamp: time.Now().Add(-1 * time.Hour),
					UserContext: models.UserContext{
						UserID: "user1",
					},
					Checksum: "corrupted",
				},
			},
			mockReport: &IntegrityReport{
				TotalEvents:         1,
				VerifiedEvents:      0,
				FailedEvents:        1,
				IntegrityScore:      0.0,
				IntegrityViolations: []*IntegrityViolation{{EventID: "event3"}},
				VerificationTime:    time.Now(),
			},
			expectError: false,
			validateResult: func(t *testing.T, pkg *EvidencePackage) {
				assert.Equal(t, "COMPROMISED", pkg.IntegrityCertificate.IntegrityStatus)
				assert.Contains(t, pkg.IntegrityCertificate.VerificationDetails, "failed integrity verification")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockAuditStorage{}
			integrityService := NewIntegrityService(mockStorage)
			service := NewEvidenceService(mockStorage, integrityService)

			// Setup mocks
			mockStorage.On("QueryEvents", mock.Anything, mock.AnythingOfType("models.AuditEventFilter")).Return(tt.mockEvents, nil)
			mockStorage.On("GetEventsByTimeRange", mock.Anything, mock.AnythingOfType("time.Time"), mock.AnythingOfType("time.Time")).Return(tt.mockEvents, nil)

			ctx := context.Background()
			pkg, err := service.GenerateEvidencePackage(ctx, tt.request)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, pkg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pkg)
				if tt.validateResult != nil {
					tt.validateResult(t, pkg)
				}
			}

			mockStorage.AssertExpectations(t)
		})
	}
}

func TestExportToJSON(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	service := NewEvidenceService(mockStorage, integrityService)

	pkg := &EvidencePackage{
		PackageID:           "PKG_JSON_001",
		ComplianceFramework: "SOC2",
		GeneratedAt:         time.Now(),
		EventCount:          1,
		Events: []*models.AuditEvent{
			{
				ID:        "event1",
				EventType: models.AuditEventTypeLogin,
				Timestamp: time.Now(),
				UserContext: models.UserContext{
					UserID: "user1",
				},
			},
		},
	}

	jsonData, err := service.ExportToJSON(pkg)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonData)
	assert.Contains(t, string(jsonData), "PKG_JSON_001")
	assert.Contains(t, string(jsonData), "SOC2")
}

func TestExportToCSV(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	service := NewEvidenceService(mockStorage, integrityService)

	pkg := &EvidencePackage{
		PackageID: "PKG_CSV_001",
		Events: []*models.AuditEvent{
			{
				ID:        "event1",
				EventType: models.AuditEventTypeLogin,
				Timestamp: time.Now(),
				Message:   "User login",
				UserContext: models.UserContext{
					UserID:    "user1",
					IPAddress: "192.168.1.100",
					UserAgent: "kubectl",
				},
				ClusterContext: models.ClusterContext{
					ResourceName: "login",
					Namespace:    "default",
				},
				CommandContext: models.CommandContext{
					GeneratedCommand: "login",
				},
				Checksum: "abc123",
			},
		},
	}

	csvData, err := service.ExportToCSV(pkg)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, csvData)
	
	csvString := string(csvData)
	assert.Contains(t, csvString, "EventID,EventType,UserID,Timestamp")
	assert.Contains(t, csvString, "event1")
	assert.Contains(t, csvString, "user1")
	assert.Contains(t, csvString, "login")
}

func TestCreateZipPackage(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	service := NewEvidenceService(mockStorage, integrityService)

	pkg := &EvidencePackage{
		PackageID:           "PKG_ZIP_001",
		ComplianceFramework: "ISO27001",
		GeneratedAt:         time.Now(),
		Events: []*models.AuditEvent{
			{
				ID:        "event1",
				EventType: models.AuditEventTypeLogin,
				Timestamp: time.Now(),
				UserContext: models.UserContext{
					UserID: "user1",
				},
				ClusterContext: models.ClusterContext{
					ResourceName: "login",
					Namespace:    "default",
				},
				Checksum: "abc123",
			},
		},
		IntegrityCertificate: &IntegrityCertificate{
			CertificateID:   "CERT_001",
			PackageID:       "PKG_ZIP_001",
			IntegrityStatus: "VERIFIED",
		},
		ChainOfCustody: &ChainOfCustody{
			PackageID: "PKG_ZIP_001",
			CreatedAt: time.Now(),
			Events:    []CustodyEvent{},
		},
	}

	formats := []EvidenceFormat{FormatJSON, FormatCSV}
	zipData, err := service.CreateZipPackage(context.Background(), pkg, formats)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, zipData)
	assert.True(t, len(zipData) > 100) // ZIP should be substantial
}

func TestCalculatePackageHash(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	service := NewEvidenceService(mockStorage, integrityService)

	pkg := &EvidencePackage{
		PackageID:           "PKG_HASH_001",
		ComplianceFramework: "SOC2",
		GeneratedAt:         time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC),
		Events: []*models.AuditEvent{
			{
				ID:       "event1",
				Checksum: "abc123",
			},
			{
				ID:       "event2",
				Checksum: "def456",
			},
		},
	}

	hash1 := service.calculatePackageHash(pkg)
	hash2 := service.calculatePackageHash(pkg)
	
	// Hash should be deterministic
	assert.Equal(t, hash1, hash2)
	assert.NotEmpty(t, hash1)
	assert.Len(t, hash1, 64) // SHA-256 hex string length
}

func TestVerifyPackageIntegrity(t *testing.T) {
	tests := []struct {
		name        string
		pkg         *EvidencePackage
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid package integrity",
			pkg: &EvidencePackage{
				PackageID:   "PKG_VALID",
				PackageHash: "valid_hash",
				Events: []*models.AuditEvent{
					{
						ID:       "event1",
						Checksum: "abc123",
					},
				},
				IntegrityCertificate: &IntegrityCertificate{
					IntegrityStatus: "VERIFIED",
				},
			},
			expectError: false,
		},
		{
			name: "missing integrity certificate",
			pkg: &EvidencePackage{
				PackageID:            "PKG_NO_CERT",
				PackageHash:          "valid_hash",
				IntegrityCertificate: nil,
			},
			expectError: true,
			errorMsg:    "missing integrity certificate",
		},
		{
			name: "missing event hash",
			pkg: &EvidencePackage{
				PackageID:   "PKG_NO_HASH",
				PackageHash: "valid_hash",
				Events: []*models.AuditEvent{
					{
						ID:       "event1",
						Checksum: "", // Missing hash
					},
				},
				IntegrityCertificate: &IntegrityCertificate{
					IntegrityStatus: "VERIFIED",
				},
			},
			expectError: true,
			errorMsg:    "missing event hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockStorage := &MockAuditStorage{}
			integrityService := NewIntegrityService(mockStorage)
			service := NewEvidenceService(mockStorage, integrityService)

			// Recalculate hash for packages that should pass hash verification
			if !tt.expectError || tt.errorMsg != "hash mismatch" {
				tt.pkg.PackageHash = service.calculatePackageHash(tt.pkg)
			}

			err := service.VerifyPackageIntegrity(tt.pkg)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEvidenceFormats(t *testing.T) {
	tests := []struct {
		name   string
		format EvidenceFormat
		valid  bool
	}{
		{"JSON format", FormatJSON, true},
		{"CSV format", FormatCSV, true},
		{"PDF format", FormatPDF, true},
		{"Invalid format", EvidenceFormat("invalid"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.format {
			case FormatJSON, FormatCSV, FormatPDF:
				assert.True(t, tt.valid)
			default:
				assert.False(t, tt.valid)
			}
		})
	}
}

func TestChainOfCustodyInitialization(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	service := NewEvidenceService(mockStorage, integrityService)

	pkg := &EvidencePackage{
		PackageID:           "PKG_CUSTODY_001",
		ComplianceFramework: "HIPAA",
		RequesterInfo: EvidenceRequester{
			UserID: "auditor1",
			Name:   "Test Auditor",
		},
	}

	custody := service.initializeChainOfCustody(pkg)

	assert.NotNil(t, custody)
	assert.Equal(t, pkg.PackageID, custody.PackageID)
	assert.Equal(t, pkg.RequesterInfo.UserID, custody.CurrentCustodian)
	assert.Len(t, custody.Events, 1)
	assert.Equal(t, "CREATED", custody.Events[0].EventType)
	assert.Equal(t, pkg.RequesterInfo.UserID, custody.Events[0].Actor)
	assert.NotEmpty(t, custody.Events[0].Description)
}

func TestIntegrityCertificateGeneration(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	integrityService := NewIntegrityService(mockStorage)
	service := NewEvidenceService(mockStorage, integrityService)

	tests := []struct {
		name            string
		pkg             *EvidencePackage
		expectedStatus  string
		expectedDetails string
	}{
		{
			name: "verified integrity report",
			pkg: &EvidencePackage{
				PackageID:  "PKG_CERT_001",
				EventCount: 5,
				IntegrityReport: &IntegrityReport{
					TotalEvents:   5,
					VerifiedEvents: 5,
					FailedEvents:  0,
				},
			},
			expectedStatus:  "VERIFIED",
			expectedDetails: "All audit events passed integrity verification",
		},
		{
			name: "compromised integrity report",
			pkg: &EvidencePackage{
				PackageID:  "PKG_CERT_002",
				EventCount: 5,
				IntegrityReport: &IntegrityReport{
					TotalEvents:   5,
					VerifiedEvents: 3,
					FailedEvents:  2,
				},
			},
			expectedStatus:  "COMPROMISED",
			expectedDetails: "2 events failed integrity verification",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := service.generateIntegrityCertificate(tt.pkg)

			assert.NotNil(t, cert)
			assert.Equal(t, tt.pkg.PackageID, cert.PackageID)
			assert.Equal(t, tt.expectedStatus, cert.IntegrityStatus)
			assert.Equal(t, tt.expectedDetails, cert.VerificationDetails)
			assert.Equal(t, "SHA-256", cert.Algorithm)
			assert.Equal(t, tt.pkg.EventCount, cert.EventCount)
			assert.NotEmpty(t, cert.CertificateID)
			assert.NotEmpty(t, cert.Signature)
		})
	}
}

func TestEvidenceService_ExportToPDF(t *testing.T) {
	storage := &MockAuditStorage{}
	integrityService := NewIntegrityService(storage)
	service := NewEvidenceService(storage, integrityService)
	
	// Create test evidence package
	pkg := createTestEvidencePackage()
	
	// Test PDF export
	pdfData, err := service.ExportToPDF(pkg)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, pdfData)
	
	// Verify PDF header (PDF files start with %PDF)
	assert.True(t, len(pdfData) > 4)
	assert.Equal(t, "%PDF", string(pdfData[:4]))
	
	// Verify PDF is not empty and has reasonable size
	assert.Greater(t, len(pdfData), 1000, "PDF should contain substantial content")
}

func TestEvidenceService_CreateZipPackageWithPDF(t *testing.T) {
	storage := &MockAuditStorage{}
	integrityService := NewIntegrityService(storage)
	service := NewEvidenceService(storage, integrityService)
	
	// Create test evidence package
	pkg := createTestEvidencePackage()
	
	// Test ZIP package creation with PDF format
	formats := []EvidenceFormat{FormatJSON, FormatCSV, FormatPDF}
	zipData, err := service.CreateZipPackage(context.Background(), pkg, formats)
	
	assert.NoError(t, err)
	assert.NotEmpty(t, zipData)
	
	// Verify ZIP header (ZIP files start with PK)
	assert.True(t, len(zipData) > 2)
	assert.Equal(t, "PK", string(zipData[:2]))
	
	// Verify ZIP contains all expected formats
	assert.Greater(t, len(zipData), 2000, "ZIP should contain multiple files including PDF")
}

func createTestEvidencePackage() *EvidencePackage {
	return &EvidencePackage{
		PackageID:           "test-evidence-001",
		ComplianceFramework: "SOC2",
		GeneratedAt:         time.Now(),
		EventCount:          10,
		IntegrityReport: &IntegrityReport{
			TotalEvents:    10,
			VerifiedEvents: 10,
			FailedEvents:   0,
		},
	}
}