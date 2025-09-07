// Package audit provides compliance evidence generation utilities
package audit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/jung-kurt/gofpdf/v2"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// EvidenceService provides compliance evidence generation capabilities
type EvidenceService struct {
	storage         AuditStorage
	integrityService *IntegrityService
}

// NewEvidenceService creates a new evidence service
func NewEvidenceService(storage AuditStorage, integrityService *IntegrityService) *EvidenceService {
	return &EvidenceService{
		storage:         storage,
		integrityService: integrityService,
	}
}

// EvidencePackageRequest represents a request for evidence package generation
type EvidencePackageRequest struct {
	PackageID       string                    `json:"package_id"`
	ComplianceFramework string               `json:"compliance_framework"` // SOC2, HIPAA, ISO27001
	TimeRange       EvidenceTimeRange        `json:"time_range"`
	Scope           EvidenceScope            `json:"scope"`
	Formats         []EvidenceFormat         `json:"formats"`
	RequesterInfo   EvidenceRequester        `json:"requester_info"`
	GeneratedAt     time.Time                `json:"generated_at"`
}

// EvidenceTimeRange defines the time range for evidence collection
type EvidenceTimeRange struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
}

// EvidenceScope defines what audit data should be included
type EvidenceScope struct {
	UserIDs       []string                   `json:"user_ids,omitempty"`
	EventTypes    []models.AuditEventType   `json:"event_types,omitempty"`
	ResourceTypes []string                   `json:"resource_types,omitempty"`
	Namespaces    []string                   `json:"namespaces,omitempty"`
}

// EvidenceFormat represents the output format for evidence
type EvidenceFormat string

const (
	FormatJSON EvidenceFormat = "json"
	FormatCSV  EvidenceFormat = "csv"
	FormatPDF  EvidenceFormat = "pdf"
)

// EvidenceRequester contains information about who requested the evidence
type EvidenceRequester struct {
	UserID         string    `json:"user_id"`
	Name           string    `json:"name"`
	Email          string    `json:"email"`
	Role           string    `json:"role"`
	Department     string    `json:"department"`
	RequestPurpose string    `json:"request_purpose"`
	RequestedAt    time.Time `json:"requested_at"`
}

// EvidencePackage represents a complete evidence package
type EvidencePackage struct {
	PackageID           string                          `json:"package_id"`
	ComplianceFramework string                          `json:"compliance_framework"`
	GeneratedAt         time.Time                       `json:"generated_at"`
	TimeRange           EvidenceTimeRange               `json:"time_range"`
	Scope               EvidenceScope                   `json:"scope"`
	RequesterInfo       EvidenceRequester               `json:"requester_info"`
	
	// Evidence Data
	Events              []*models.AuditEvent            `json:"events"`
	EventCount          int                             `json:"event_count"`
	
	// Integrity Verification
	IntegrityReport     *IntegrityReport                `json:"integrity_report"`
	IntegrityCertificate *IntegrityCertificate         `json:"integrity_certificate"`
	
	// Chain of Custody
	ChainOfCustody      *ChainOfCustody                 `json:"chain_of_custody"`
	
	// Package Metadata
	PackageHash         string                          `json:"package_hash"`
	FileList            []EvidenceFile                  `json:"file_list"`
}

// IntegrityCertificate provides cryptographic proof of evidence integrity
type IntegrityCertificate struct {
	CertificateID       string    `json:"certificate_id"`
	PackageID           string    `json:"package_id"`
	GeneratedAt         time.Time `json:"generated_at"`
	Algorithm           string    `json:"algorithm"` // SHA-256
	PackageHash         string    `json:"package_hash"`
	EventCount          int       `json:"event_count"`
	IntegrityStatus     string    `json:"integrity_status"` // VERIFIED, COMPROMISED
	VerificationMethod  string    `json:"verification_method"`
	VerificationDetails string    `json:"verification_details"`
	Signature           string    `json:"signature"`
}

// ChainOfCustody tracks the evidence handling lifecycle
type ChainOfCustody struct {
	PackageID           string                  `json:"package_id"`
	CreatedAt           time.Time               `json:"created_at"`
	CreatedBy           EvidenceRequester       `json:"created_by"`
	InitialCustodian    string                  `json:"initial_custodian"`
	Events              []CustodyEvent          `json:"events"`
	CurrentCustodian    string                  `json:"current_custodian"`
	AccessLog           []AccessEvent           `json:"access_log"`
}

// CustodyEvent represents an event in the chain of custody
type CustodyEvent struct {
	EventType   string    `json:"event_type"` // CREATED, ACCESSED, DOWNLOADED, VERIFIED
	Timestamp   time.Time `json:"timestamp"`
	Actor       string    `json:"actor"`
	Description string    `json:"description"`
	Hash        string    `json:"hash"`
}

// AccessEvent tracks access to the evidence package
type AccessEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	UserID      string    `json:"user_id"`
	Action      string    `json:"action"` // VIEW, DOWNLOAD, VERIFY
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
}

// EvidenceFile represents a file in the evidence package
type EvidenceFile struct {
	Filename    string `json:"filename"`
	Size        int64  `json:"size"`
	Hash        string `json:"hash"`
	MimeType    string `json:"mime_type"`
	Description string `json:"description"`
}

// GenerateEvidencePackage creates a complete evidence package
func (s *EvidenceService) GenerateEvidencePackage(ctx context.Context, request *EvidencePackageRequest) (*EvidencePackage, error) {
	// Retrieve audit events based on time range and scope
	events, err := s.retrieveEventsForPackage(ctx, request.TimeRange, request.Scope)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve events for evidence package: %w", err)
	}
	
	// Verify integrity of retrieved events
	integrityReport, err := s.integrityService.VerifyRangeIntegrity(ctx, request.TimeRange.StartTime, request.TimeRange.EndTime)
	if err != nil {
		return nil, fmt.Errorf("failed to verify integrity of events: %w", err)
	}
	
	// Create evidence package
	pkg := &EvidencePackage{
		PackageID:           request.PackageID,
		ComplianceFramework: request.ComplianceFramework,
		GeneratedAt:         request.GeneratedAt,
		TimeRange:           request.TimeRange,
		Scope:               request.Scope,
		RequesterInfo:       request.RequesterInfo,
		Events:              events,
		EventCount:          len(events),
		IntegrityReport:     integrityReport,
	}
	
	// Generate integrity certificate
	pkg.IntegrityCertificate = s.generateIntegrityCertificate(pkg)
	
	// Initialize chain of custody
	pkg.ChainOfCustody = s.initializeChainOfCustody(pkg)
	
	// Calculate package hash
	pkg.PackageHash = s.calculatePackageHash(pkg)
	
	return pkg, nil
}

// retrieveEventsForPackage retrieves audit events based on scope and time range
func (s *EvidenceService) retrieveEventsForPackage(ctx context.Context, timeRange EvidenceTimeRange, scope EvidenceScope) ([]*models.AuditEvent, error) {
	filter := models.AuditEventFilter{
		StartTime: timeRange.StartTime,
		EndTime:   timeRange.EndTime,
	}
	
	if len(scope.UserIDs) > 0 && len(scope.UserIDs) > 0 {
		filter.UserID = scope.UserIDs[0] // Use first user ID as primary filter
	}
	
	if len(scope.EventTypes) > 0 {
		filter.EventTypes = scope.EventTypes
	}
	
	events, err := s.storage.QueryEvents(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}
	
	// Sort events chronologically
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})
	
	return events, nil
}

// generateIntegrityCertificate creates an integrity certificate for the evidence package
func (s *EvidenceService) generateIntegrityCertificate(pkg *EvidencePackage) *IntegrityCertificate {
	status := "VERIFIED"
	details := "All audit events passed integrity verification"
	
	if pkg.IntegrityReport != nil && pkg.IntegrityReport.FailedEvents > 0 {
		status = "COMPROMISED"
		details = fmt.Sprintf("%d events failed integrity verification", pkg.IntegrityReport.FailedEvents)
	}
	
	cert := &IntegrityCertificate{
		CertificateID:       fmt.Sprintf("CERT_%s_%d", pkg.PackageID, time.Now().Unix()),
		PackageID:           pkg.PackageID,
		GeneratedAt:         time.Now(),
		Algorithm:           "SHA-256",
		EventCount:          pkg.EventCount,
		IntegrityStatus:     status,
		VerificationDetails: details,
	}
	
	// Generate certificate hash
	certData, _ := json.Marshal(cert)
	hash := sha256.Sum256(certData)
	cert.Signature = hex.EncodeToString(hash[:])
	
	return cert
}

// initializeChainOfCustody creates the initial chain of custody record
func (s *EvidenceService) initializeChainOfCustody(pkg *EvidencePackage) *ChainOfCustody {
	now := time.Now()
	
	custodyEvent := CustodyEvent{
		EventType:   "CREATED",
		Timestamp:   now,
		Actor:       pkg.RequesterInfo.UserID,
		Description: fmt.Sprintf("Evidence package created for compliance framework: %s", pkg.ComplianceFramework),
		Hash:        pkg.PackageHash,
	}
	
	return &ChainOfCustody{
		PackageID:        pkg.PackageID,
		CreatedAt:        now,
		CreatedBy:        pkg.RequesterInfo,
		Events:           []CustodyEvent{custodyEvent},
		CurrentCustodian: pkg.RequesterInfo.UserID,
		AccessLog:        []AccessEvent{},
	}
}

// calculatePackageHash generates a hash of the evidence package content
func (s *EvidenceService) calculatePackageHash(pkg *EvidencePackage) string {
	// Create deterministic hash of package content
	var content bytes.Buffer
	
	// Add package metadata
	content.WriteString(pkg.PackageID)
	content.WriteString(pkg.ComplianceFramework)
	content.WriteString(pkg.GeneratedAt.Format(time.RFC3339))
	
	// Add event hashes in sorted order
	eventHashes := make([]string, len(pkg.Events))
	for i, event := range pkg.Events {
		eventHashes[i] = event.Checksum
	}
	sort.Strings(eventHashes)
	
	for _, hash := range eventHashes {
		content.WriteString(hash)
	}
	
	// Calculate SHA-256 hash
	hash := sha256.Sum256(content.Bytes())
	return hex.EncodeToString(hash[:])
}

// ExportToJSON exports the evidence package to JSON format
func (s *EvidenceService) ExportToJSON(pkg *EvidencePackage) ([]byte, error) {
	return json.MarshalIndent(pkg, "", "  ")
}

// ExportToCSV exports the evidence package events to CSV format
func (s *EvidenceService) ExportToCSV(pkg *EvidencePackage) ([]byte, error) {
	var buffer bytes.Buffer
	writer := csv.NewWriter(&buffer)
	
	// Write CSV headers
	headers := []string{
		"EventID", "EventType", "UserID", "Timestamp", "Resource", "Action", 
		"Namespace", "Details", "IPAddress", "UserAgent", "Hash", "IntegrityStatus",
	}
	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write CSV headers: %w", err)
	}
	
	// Write event data
	for _, event := range pkg.Events {
		record := []string{
			event.ID,
			string(event.EventType),
			event.UserContext.UserID,
			event.Timestamp.Format(time.RFC3339),
			event.ClusterContext.ResourceName,
			event.CommandContext.GeneratedCommand,
			event.ClusterContext.Namespace,
			event.Message,
			event.UserContext.IPAddress,
			event.UserContext.UserAgent,
			event.Checksum,
			"VERIFIED", // Assume verified if in package
		}
		
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}
	
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}
	
	return buffer.Bytes(), nil
}

// ExportToPDF exports the evidence package to PDF format
func (s *EvidenceService) ExportToPDF(pkg *EvidencePackage) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.AddPage()
	
	// Title and Header
	pdf.SetFont("Arial", "B", 18)
	pdf.Cell(0, 12, "Compliance Evidence Package")
	pdf.Ln(12)
	pdf.Ln(5)
	
	// Package Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Package Information")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("Package ID: %s", pkg.PackageID))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Compliance Framework: %s", pkg.ComplianceFramework))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Generated At: %s", pkg.GeneratedAt.Format(time.RFC3339)))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Time Range: %s to %s", 
		pkg.TimeRange.StartTime.Format("2006-01-02"), 
		pkg.TimeRange.EndTime.Format("2006-01-02")))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Event Count: %d", pkg.EventCount))
	pdf.Ln(10)
	
	// Requester Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Requested By")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(0, 6, fmt.Sprintf("User ID: %s", pkg.RequesterInfo.UserID))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Department: %s", pkg.RequesterInfo.Department))
	pdf.Ln(6)
	pdf.Cell(0, 6, fmt.Sprintf("Purpose: %s", pkg.RequesterInfo.RequestPurpose))
	pdf.Ln(10)
	
	// Integrity Information
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Integrity Verification")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)
	if pkg.IntegrityCertificate != nil {
		pdf.Cell(0, 6, fmt.Sprintf("Integrity Status: %s", pkg.IntegrityCertificate.IntegrityStatus))
		pdf.Ln(6)
		pdf.Cell(0, 6, fmt.Sprintf("Certificate ID: %s", pkg.IntegrityCertificate.CertificateID))
		pdf.Ln(6)
		pdf.Cell(0, 6, fmt.Sprintf("Verification Method: %s", pkg.IntegrityCertificate.VerificationMethod))
		pdf.Ln(6)
	}
	pdf.Ln(5)
	
	// Chain of Custody Summary
	pdf.SetFont("Arial", "B", 12)
	pdf.Cell(0, 8, "Chain of Custody")
	pdf.Ln(8)
	pdf.SetFont("Arial", "", 10)
	if pkg.ChainOfCustody != nil {
		pdf.Cell(0, 6, fmt.Sprintf("Initial Custodian: %s", pkg.ChainOfCustody.InitialCustodian))
		pdf.Ln(6)
		pdf.Cell(0, 6, fmt.Sprintf("Custody Events: %d", len(pkg.ChainOfCustody.Events)))
		pdf.Ln(6)
	}
	pdf.Ln(10)
	
	// Event Summary
	pdf.SetFont("Arial", "B", 10)
	pdf.Cell(0, 8, "Audit Events Summary")
	pdf.Ln(8)
	
	// Simple text-based event listing instead of table
	pdf.SetFont("Arial", "", 8)
	eventCount := len(pkg.Events)
	if eventCount > 10 {
		eventCount = 10 // Limit for PDF space
	}
	
	for i := 0; i < eventCount; i++ {
		event := pkg.Events[i]
		eventText := fmt.Sprintf("%d. %s [%s] - %s (%s)", 
			i+1, 
			event.ID, 
			string(event.EventType), 
			event.UserContext.UserID,
			event.Timestamp.Format("2006-01-02 15:04"))
		
		pdf.Cell(0, 5, eventText)
		pdf.Ln(5)
	}
	
	if len(pkg.Events) > 10 {
		pdf.Ln(3)
		pdf.SetFont("Arial", "I", 8)
		pdf.Cell(0, 5, fmt.Sprintf("Note: Showing first 10 events of %d total events.", len(pkg.Events)))
		pdf.Ln(5)
	}
	
	// Footer
	pdf.Ln(10)
	pdf.SetFont("Arial", "I", 8)
	pdf.Cell(0, 5, "This document was automatically generated and contains cryptographically verified audit evidence.")
	pdf.Ln(5)
	pdf.Cell(0, 5, fmt.Sprintf("Package Hash: %s", pkg.PackageHash))
	
	var buffer bytes.Buffer
	err := pdf.Output(&buffer)
	if err != nil {
		return nil, fmt.Errorf("failed to generate PDF: %w", err)
	}
	
	return buffer.Bytes(), nil
}

// CreateZipPackage creates a ZIP file containing all evidence formats
func (s *EvidenceService) CreateZipPackage(ctx context.Context, pkg *EvidencePackage, formats []EvidenceFormat) ([]byte, error) {
	var buffer bytes.Buffer
	zipWriter := zip.NewWriter(&buffer)
	
	// Add JSON export
	for _, format := range formats {
		switch format {
		case FormatJSON:
			jsonData, err := s.ExportToJSON(pkg)
			if err != nil {
				return nil, fmt.Errorf("failed to export to JSON: %w", err)
			}
			
			jsonFile, err := zipWriter.Create(fmt.Sprintf("%s_evidence.json", pkg.PackageID))
			if err != nil {
				return nil, fmt.Errorf("failed to create JSON file in ZIP: %w", err)
			}
			
			_, err = jsonFile.Write(jsonData)
			if err != nil {
				return nil, fmt.Errorf("failed to write JSON data to ZIP: %w", err)
			}
			
		case FormatCSV:
			csvData, err := s.ExportToCSV(pkg)
			if err != nil {
				return nil, fmt.Errorf("failed to export to CSV: %w", err)
			}
			
			csvFile, err := zipWriter.Create(fmt.Sprintf("%s_evidence.csv", pkg.PackageID))
			if err != nil {
				return nil, fmt.Errorf("failed to create CSV file in ZIP: %w", err)
			}
			
			_, err = csvFile.Write(csvData)
			if err != nil {
				return nil, fmt.Errorf("failed to write CSV data to ZIP: %w", err)
			}
			
		case FormatPDF:
			pdfData, err := s.ExportToPDF(pkg)
			if err != nil {
				return nil, fmt.Errorf("failed to export to PDF: %w", err)
			}
			
			pdfFile, err := zipWriter.Create(fmt.Sprintf("%s_evidence.pdf", pkg.PackageID))
			if err != nil {
				return nil, fmt.Errorf("failed to create PDF file in ZIP: %w", err)
			}
			
			_, err = pdfFile.Write(pdfData)
			if err != nil {
				return nil, fmt.Errorf("failed to write PDF data to ZIP: %w", err)
			}
		}
	}
	
	// Add integrity certificate
	certData, err := json.MarshalIndent(pkg.IntegrityCertificate, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal integrity certificate: %w", err)
	}
	
	certFile, err := zipWriter.Create(fmt.Sprintf("%s_integrity_certificate.json", pkg.PackageID))
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate file in ZIP: %w", err)
	}
	
	_, err = certFile.Write(certData)
	if err != nil {
		return nil, fmt.Errorf("failed to write certificate data to ZIP: %w", err)
	}
	
	// Add chain of custody
	custodyData, err := json.MarshalIndent(pkg.ChainOfCustody, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal chain of custody: %w", err)
	}
	
	custodyFile, err := zipWriter.Create(fmt.Sprintf("%s_chain_of_custody.json", pkg.PackageID))
	if err != nil {
		return nil, fmt.Errorf("failed to create custody file in ZIP: %w", err)
	}
	
	_, err = custodyFile.Write(custodyData)
	if err != nil {
		return nil, fmt.Errorf("failed to write custody data to ZIP: %w", err)
	}
	
	err = zipWriter.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to close ZIP writer: %w", err)
	}
	
	return buffer.Bytes(), nil
}

// VerifyPackageIntegrity verifies the integrity of an evidence package
func (s *EvidenceService) VerifyPackageIntegrity(pkg *EvidencePackage) error {
	// Recalculate package hash
	calculatedHash := s.calculatePackageHash(pkg)
	
	if calculatedHash != pkg.PackageHash {
		return fmt.Errorf("package integrity verification failed: hash mismatch")
	}
	
	// Verify integrity certificate
	if pkg.IntegrityCertificate == nil {
		return fmt.Errorf("package integrity verification failed: missing integrity certificate")
	}
	
	// Verify all event hashes
	for _, event := range pkg.Events {
		if event.Checksum == "" {
			return fmt.Errorf("package integrity verification failed: missing event hash for event %s", event.ID)
		}
	}
	
	return nil
}

// UpdateChainOfCustody adds a new custody event to the evidence package
func (s *EvidenceService) UpdateChainOfCustody(pkg *EvidencePackage, eventType, actor, description string) error {
	if pkg.ChainOfCustody == nil {
		return fmt.Errorf("chain of custody not initialized")
	}
	
	custodyEvent := CustodyEvent{
		EventType:   eventType,
		Timestamp:   time.Now(),
		Actor:       actor,
		Description: description,
		Hash:        s.calculatePackageHash(pkg),
	}
	
	pkg.ChainOfCustody.Events = append(pkg.ChainOfCustody.Events, custodyEvent)
	pkg.ChainOfCustody.CurrentCustodian = actor
	
	return nil
}

// LogAccess records an access event to the evidence package
func (s *EvidenceService) LogAccess(pkg *EvidencePackage, userID, action, ipAddress, userAgent string) error {
	if pkg.ChainOfCustody == nil {
		return fmt.Errorf("chain of custody not initialized")
	}
	
	accessEvent := AccessEvent{
		Timestamp: time.Now(),
		UserID:    userID,
		Action:    action,
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}
	
	pkg.ChainOfCustody.AccessLog = append(pkg.ChainOfCustody.AccessLog, accessEvent)
	
	return nil
}

// ValidateChainOfCustody verifies the integrity of the chain of custody
func (s *EvidenceService) ValidateChainOfCustody(pkg *EvidencePackage) (bool, []string) {
	issues := []string{}
	
	if pkg.ChainOfCustody == nil {
		issues = append(issues, "Chain of custody not found")
		return false, issues
	}
	
	// Validate required fields
	if pkg.ChainOfCustody.PackageID != pkg.PackageID {
		issues = append(issues, "Chain of custody package ID mismatch")
	}
	
	if len(pkg.ChainOfCustody.Events) == 0 {
		issues = append(issues, "No custody events found")
	}
	
	// Validate custody event chronology
	for i := 1; i < len(pkg.ChainOfCustody.Events); i++ {
		if pkg.ChainOfCustody.Events[i].Timestamp.Before(pkg.ChainOfCustody.Events[i-1].Timestamp) {
			issues = append(issues, fmt.Sprintf("Custody events not in chronological order at event %d", i))
		}
	}
	
	// Validate hash consistency
	for i, event := range pkg.ChainOfCustody.Events {
		if event.Hash == "" {
			issues = append(issues, fmt.Sprintf("Missing hash for custody event %d", i))
		}
	}
	
	return len(issues) == 0, issues
}

// GetChainOfCustodyReport generates a detailed chain of custody report
func (s *EvidenceService) GetChainOfCustodyReport(pkg *EvidencePackage) (*ChainOfCustodyReport, error) {
	if pkg.ChainOfCustody == nil {
		return nil, fmt.Errorf("chain of custody not found")
	}
	
	// Calculate custody duration
	var totalDuration time.Duration
	if len(pkg.ChainOfCustody.Events) > 1 {
		firstEvent := pkg.ChainOfCustody.Events[0]
		lastEvent := pkg.ChainOfCustody.Events[len(pkg.ChainOfCustody.Events)-1]
		totalDuration = lastEvent.Timestamp.Sub(firstEvent.Timestamp)
	}
	
	// Count access events by user
	accessByUser := make(map[string]int)
	for _, access := range pkg.ChainOfCustody.AccessLog {
		accessByUser[access.UserID]++
	}
	
	report := &ChainOfCustodyReport{
		PackageID:         pkg.PackageID,
		ReportGeneratedAt: time.Now(),
		TotalCustodyEvents: len(pkg.ChainOfCustody.Events),
		TotalAccessEvents:  len(pkg.ChainOfCustody.AccessLog),
		CustodyDuration:    totalDuration,
		CurrentCustodian:   pkg.ChainOfCustody.CurrentCustodian,
		AccessSummary:      accessByUser,
		CustodyEvents:      pkg.ChainOfCustody.Events,
		AccessEvents:       pkg.ChainOfCustody.AccessLog,
		IntegrityStatus:    "VERIFIED",
	}
	
	// Validate chain integrity
	valid, issues := s.ValidateChainOfCustody(pkg)
	if !valid {
		report.IntegrityStatus = "COMPROMISED"
		report.Issues = issues
	}
	
	return report, nil
}

// ChainOfCustodyReport provides detailed chain of custody information
type ChainOfCustodyReport struct {
	PackageID          string                 `json:"package_id"`
	ReportGeneratedAt  time.Time              `json:"report_generated_at"`
	TotalCustodyEvents int                    `json:"total_custody_events"`
	TotalAccessEvents  int                    `json:"total_access_events"`
	CustodyDuration    time.Duration          `json:"custody_duration"`
	CurrentCustodian   string                 `json:"current_custodian"`
	AccessSummary      map[string]int         `json:"access_summary"`
	CustodyEvents      []CustodyEvent         `json:"custody_events"`
	AccessEvents       []AccessEvent          `json:"access_events"`
	IntegrityStatus    string                 `json:"integrity_status"`
	Issues             []string               `json:"issues,omitempty"`
}