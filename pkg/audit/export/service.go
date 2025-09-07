package export

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/audit/formats"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ExportService handles SIEM export operations for audit events
type ExportService struct {
	storage          audit.AuditStorage
	formatters       map[string]formats.SIEMFormatExporter
	integrityVerifier *formats.ExportIntegrityVerifier
	jobTracker       *ExportJobTracker
	config           ExportServiceConfig
	mu               sync.RWMutex
}

// ExportServiceConfig configures the export service behavior
type ExportServiceConfig struct {
	MaxConcurrentExports  int           `json:"max_concurrent_exports"`
	DefaultPageSize       int           `json:"default_page_size"`
	MaxPageSize           int           `json:"max_page_size"`
	ExportTimeout         time.Duration `json:"export_timeout"`
	JobRetentionPeriod    time.Duration `json:"job_retention_period"`
	EnableIntegrityChecks bool          `json:"enable_integrity_checks"`
	MaxExportSize         int64         `json:"max_export_size"` // in bytes
	TempDirectory         string        `json:"temp_directory"`
}

// ExportRequest defines parameters for audit event export
type ExportRequest struct {
	// Export identification
	ExportID    string `json:"export_id,omitempty"`
	RequestedBy string `json:"requested_by"`
	
	// Format and destination
	Format   string `json:"format"`   // JSON, CEF, LEEF
	Platform string `json:"platform"` // splunk, qradar, sentinel, etc.
	
	// Filtering parameters
	Filter ExportFilter `json:"filter"`
	
	// Pagination and limits
	PageSize int `json:"page_size,omitempty"`
	Offset   int `json:"offset,omitempty"`
	Limit    int `json:"limit,omitempty"`
	
	// Export options
	IncludeIntegrityData bool `json:"include_integrity_data"`
	CompressOutput      bool `json:"compress_output"`
	SplitLargeExports   bool `json:"split_large_exports"`
	
	// Metadata
	Description string                 `json:"description,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ExportFilter defines filtering criteria for audit event exports
type ExportFilter struct {
	// Time range
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	
	// User filtering
	UserIDs    []string `json:"user_ids,omitempty"`
	UserEmails []string `json:"user_emails,omitempty"`
	
	// Event filtering
	EventTypes []models.AuditEventType `json:"event_types,omitempty"`
	Severities []models.AuditSeverity  `json:"severities,omitempty"`
	
	// Context filtering
	ClusterNames     []string `json:"cluster_names,omitempty"`
	Namespaces       []string `json:"namespaces,omitempty"`
	ResourceTypes    []string `json:"resource_types,omitempty"`
	ServiceNames     []string `json:"service_names,omitempty"`
	
	// Command filtering
	RiskLevels         []string `json:"risk_levels,omitempty"`
	ExecutionStatuses  []string `json:"execution_statuses,omitempty"`
	
	// Advanced filtering
	CorrelationIDs []string `json:"correlation_ids,omitempty"`
	TraceIDs       []string `json:"trace_ids,omitempty"`
	
	// Text search
	SearchTerm string `json:"search_term,omitempty"`
	
	// Sampling
	SampleRate float64 `json:"sample_rate,omitempty"` // 0.0-1.0
}

// ExportJob tracks the status of an export operation
type ExportJob struct {
	ID          string                 `json:"id"`
	Request     ExportRequest          `json:"request"`
	Status      ExportJobStatus        `json:"status"`
	Progress    ExportProgress         `json:"progress"`
	Result      *ExportResult          `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   time.Time              `json:"started_at,omitempty"`
	CompletedAt time.Time              `json:"completed_at,omitempty"`
	ExpiresAt   time.Time              `json:"expires_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ExportJobStatus represents the status of an export job
type ExportJobStatus string

const (
	ExportJobStatusPending    ExportJobStatus = "pending"
	ExportJobStatusRunning    ExportJobStatus = "running"
	ExportJobStatusCompleted  ExportJobStatus = "completed"
	ExportJobStatusFailed     ExportJobStatus = "failed"
	ExportJobStatusCancelled  ExportJobStatus = "cancelled"
	ExportJobStatusExpired    ExportJobStatus = "expired"
)

// ExportProgress tracks the progress of an export operation
type ExportProgress struct {
	TotalEvents    int64     `json:"total_events"`
	ProcessedEvents int64    `json:"processed_events"`
	ExportedEvents int64     `json:"exported_events"`
	FailedEvents   int64     `json:"failed_events"`
	CurrentPage    int       `json:"current_page"`
	TotalPages     int       `json:"total_pages"`
	PercentComplete float64  `json:"percent_complete"`
	EstimatedTimeRemaining time.Duration `json:"estimated_time_remaining"`
	LastUpdated    time.Time `json:"last_updated"`
}

// ExportResult contains the results of a completed export
type ExportResult struct {
	ExportedEvents     int64                               `json:"exported_events"`
	TotalSize          int64                               `json:"total_size"`
	Format             string                              `json:"format"`
	Files              []ExportFile                        `json:"files"`
	IntegrityReport    *formats.BatchExportIntegrityReport `json:"integrity_report,omitempty"`
	Statistics         ExportStatistics                    `json:"statistics"`
	CompletedAt        time.Time                           `json:"completed_at"`
	ExecutionDuration  time.Duration                       `json:"execution_duration"`
}

// ExportFile represents an exported file
type ExportFile struct {
	Filename    string            `json:"filename"`
	Size        int64             `json:"size"`
	EventCount  int64             `json:"event_count"`
	Format      string            `json:"format"`
	Compressed  bool              `json:"compressed"`
	Checksum    string            `json:"checksum"`
	DownloadURL string            `json:"download_url,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// ExportStatistics provides detailed statistics about the export
type ExportStatistics struct {
	EventsByType      map[string]int64  `json:"events_by_type"`
	EventsBySeverity  map[string]int64  `json:"events_by_severity"`
	EventsByUser      map[string]int64  `json:"events_by_user"`
	EventsByCluster   map[string]int64  `json:"events_by_cluster"`
	TimeRange         TimeRange         `json:"time_range"`
	ProcessingTime    time.Duration     `json:"processing_time"`
	AverageEventSize  int64             `json:"average_event_size"`
}

// TimeRange represents a time range in the export statistics
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// DefaultExportServiceConfig returns sensible default configuration
func DefaultExportServiceConfig() ExportServiceConfig {
	return ExportServiceConfig{
		MaxConcurrentExports:  5,
		DefaultPageSize:       1000,
		MaxPageSize:          10000,
		ExportTimeout:        time.Hour,
		JobRetentionPeriod:   time.Hour * 24 * 7, // 7 days
		EnableIntegrityChecks: true,
		MaxExportSize:        1024 * 1024 * 1024, // 1GB
		TempDirectory:        "/tmp/kubechat-exports",
	}
}

// NewExportService creates a new export service instance
func NewExportService(storage audit.AuditStorage, config ExportServiceConfig) (*ExportService, error) {
	if config.MaxConcurrentExports == 0 {
		config = DefaultExportServiceConfig()
	}
	
	service := &ExportService{
		storage: storage,
		formatters: map[string]formats.SIEMFormatExporter{
			"JSON": formats.NewJSONExporter(formats.JSONExporterConfig{IncludeIntegrityFields: config.EnableIntegrityChecks}),
			"CEF":  formats.NewCEFExporter(formats.DefaultCEFConfig()),
			"LEEF": formats.NewLEEFExporter(formats.DefaultLEEFConfig()),
		},
		integrityVerifier: formats.NewExportIntegrityVerifier(formats.IntegrityConfig{
			VerifyOriginalChecksum: config.EnableIntegrityChecks,
			GenerateExportChecksum: config.EnableIntegrityChecks,
		}),
		jobTracker: NewExportJobTracker(config.JobRetentionPeriod),
		config:     config,
	}
	
	return service, nil
}

// ExportEvents initiates an export operation for audit events
func (es *ExportService) ExportEvents(ctx context.Context, request ExportRequest) (*ExportJob, error) {
	// Validate request
	if err := es.validateExportRequest(&request); err != nil {
		return nil, fmt.Errorf("invalid export request: %w", err)
	}
	
	// Check concurrent export limits
	if es.jobTracker.GetActiveJobCount() >= es.config.MaxConcurrentExports {
		return nil, fmt.Errorf("maximum concurrent exports reached (%d)", es.config.MaxConcurrentExports)
	}
	
	// Generate export ID if not provided
	if request.ExportID == "" {
		request.ExportID = fmt.Sprintf("export_%d_%d", time.Now().Unix(), time.Now().Nanosecond())
	}
	
	// Create export job
	job := &ExportJob{
		ID:        request.ExportID,
		Request:   request,
		Status:    ExportJobStatusPending,
		Progress:  ExportProgress{LastUpdated: time.Now().UTC()},
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(es.config.JobRetentionPeriod),
		Metadata:  make(map[string]interface{}),
	}
	
	// Register job with tracker
	es.jobTracker.AddJob(job)
	
	// Start export operation asynchronously
	go es.performExport(ctx, job)
	
	return job, nil
}

// GetExportJob retrieves information about an export job
func (es *ExportService) GetExportJob(jobID string) (*ExportJob, error) {
	job := es.jobTracker.GetJob(jobID)
	if job == nil {
		return nil, fmt.Errorf("export job %s not found", jobID)
	}
	return job, nil
}

// ListExportJobs lists all export jobs with optional filtering
func (es *ExportService) ListExportJobs(status ExportJobStatus, requestedBy string, limit, offset int) ([]*ExportJob, error) {
	return es.jobTracker.ListJobs(status, requestedBy, limit, offset), nil
}

// CancelExportJob cancels a running export job
func (es *ExportService) CancelExportJob(jobID string) error {
	job := es.jobTracker.GetJob(jobID)
	if job == nil {
		return fmt.Errorf("export job %s not found", jobID)
	}
	
	if job.Status == ExportJobStatusCompleted || job.Status == ExportJobStatusFailed {
		return fmt.Errorf("cannot cancel job in status: %s", job.Status)
	}
	
	es.jobTracker.UpdateJobStatus(jobID, ExportJobStatusCancelled, "Job cancelled by user request")
	return nil
}

// performExport executes the export operation
func (es *ExportService) performExport(ctx context.Context, job *ExportJob) {
	startTime := time.Now()
	es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusRunning, "")
	job.StartedAt = startTime
	
	// Create timeout context
	exportCtx, cancel := context.WithTimeout(ctx, es.config.ExportTimeout)
	defer cancel()
	
	// Convert export filter to audit storage filter
	storageFilter := es.convertToStorageFilter(job.Request.Filter)
	
	// Get total count for progress tracking
	totalCount, err := es.storage.CountEvents(exportCtx, storageFilter)
	if err != nil {
		es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Failed to count events: %v", err))
		return
	}
	
	if totalCount == 0 {
		// Complete with empty result
		es.completeExportWithNoEvents(job, startTime)
		return
	}
	
	// Initialize progress
	job.Progress.TotalEvents = totalCount
	pageSize := job.Request.PageSize
	if pageSize == 0 {
		pageSize = es.config.DefaultPageSize
	} else if pageSize > es.config.MaxPageSize {
		pageSize = es.config.MaxPageSize
	}
	
	job.Progress.TotalPages = int((totalCount + int64(pageSize) - 1) / int64(pageSize))
	
	// Get formatter
	formatter, exists := es.formatters[job.Request.Format]
	if !exists {
		es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Unsupported format: %s", job.Request.Format))
		return
	}
	
	// Perform paginated export
	var allEvents []*models.AuditEvent
	var exportedData []byte
	var statistics ExportStatistics
	
	currentOffset := job.Request.Offset
	processedEvents := int64(0)
	
	for currentPage := 1; currentPage <= job.Progress.TotalPages; currentPage++ {
		// Check for cancellation
		select {
		case <-exportCtx.Done():
			es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusCancelled, "Export timeout or cancellation")
			return
		default:
		}
		
		// Check job status (may have been cancelled)
		currentJob := es.jobTracker.GetJob(job.ID)
		if currentJob.Status == ExportJobStatusCancelled {
			return
		}
		
		// Update pagination in filter
		storageFilter.Offset = currentOffset
		storageFilter.Limit = pageSize
		
		// Fetch events for this page
		events, err := es.storage.QueryEvents(exportCtx, storageFilter)
		if err != nil {
			es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Failed to query events: %v", err))
			return
		}
		
		if len(events) == 0 {
			break // No more events
		}
		
		// Apply sampling if specified
		if job.Request.Filter.SampleRate > 0 && job.Request.Filter.SampleRate < 1.0 {
			events = es.applySampling(events, job.Request.Filter.SampleRate)
		}
		
		// Accumulate events
		allEvents = append(allEvents, events...)
		processedEvents += int64(len(events))
		
		// Update progress
		job.Progress.ProcessedEvents = processedEvents
		job.Progress.CurrentPage = currentPage
		job.Progress.PercentComplete = float64(processedEvents) / float64(totalCount) * 100
		job.Progress.EstimatedTimeRemaining = es.calculateEstimatedTimeRemaining(startTime, processedEvents, totalCount)
		job.Progress.LastUpdated = time.Now().UTC()
		
		// Update statistics
		es.updateStatistics(&statistics, events)
		
		// Move to next page
		currentOffset += pageSize
		
		// Check size limits
		if job.Request.Limit > 0 && processedEvents >= int64(job.Request.Limit) {
			break
		}
	}
	
	// Export all collected events
	exportedData, err = formatter.ExportBatch(allEvents)
	if err != nil {
		es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Failed to export events: %v", err))
		return
	}
	
	// Check export size limits
	if es.config.MaxExportSize > 0 && int64(len(exportedData)) > es.config.MaxExportSize {
		es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Export size exceeds limit: %d bytes", len(exportedData)))
		return
	}
	
	// Perform integrity verification if enabled
	var integrityReport *formats.BatchExportIntegrityReport
	if es.config.EnableIntegrityChecks {
		integrityReport, err = es.integrityVerifier.VerifyBatchExportIntegrity(
			allEvents,
			exportedData,
			job.Request.Format,
			job.ID,
		)
		if err != nil {
			es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Integrity verification failed: %v", err))
			return
		}
	}
	
	// Create export files
	files, err := es.createExportFiles(job, exportedData, formatter)
	if err != nil {
		es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusFailed, fmt.Sprintf("Failed to create export files: %v", err))
		return
	}
	
	// Complete statistics
	if len(allEvents) > 0 {
		statistics.TimeRange.Start = allEvents[0].Timestamp
		statistics.TimeRange.End = allEvents[len(allEvents)-1].Timestamp
	}
	statistics.ProcessingTime = time.Since(startTime)
	statistics.AverageEventSize = int64(len(exportedData)) / int64(len(allEvents))
	
	// Create final result
	result := &ExportResult{
		ExportedEvents:    int64(len(allEvents)),
		TotalSize:         int64(len(exportedData)),
		Format:            job.Request.Format,
		Files:             files,
		IntegrityReport:   integrityReport,
		Statistics:        statistics,
		CompletedAt:       time.Now().UTC(),
		ExecutionDuration: time.Since(startTime),
	}
	
	// Update job with result
	job.Result = result
	job.Progress.ExportedEvents = int64(len(allEvents))
	job.Progress.PercentComplete = 100.0
	job.CompletedAt = time.Now().UTC()
	
	es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusCompleted, "")
}

// Helper methods

func (es *ExportService) validateExportRequest(request *ExportRequest) error {
	if request.RequestedBy == "" {
		return fmt.Errorf("requested_by is required")
	}
	if request.Format == "" {
		request.Format = "JSON"
	}
	if _, exists := es.formatters[request.Format]; !exists {
		return fmt.Errorf("unsupported format: %s", request.Format)
	}
	if request.PageSize < 0 {
		return fmt.Errorf("page_size cannot be negative")
	}
	if request.PageSize > es.config.MaxPageSize {
		return fmt.Errorf("page_size exceeds maximum: %d", es.config.MaxPageSize)
	}
	if request.Filter.SampleRate < 0 || request.Filter.SampleRate > 1 {
		return fmt.Errorf("sample_rate must be between 0.0 and 1.0")
	}
	return nil
}

func (es *ExportService) convertToStorageFilter(exportFilter ExportFilter) models.AuditEventFilter {
	return models.AuditEventFilter{
		EventTypes:    exportFilter.EventTypes,
		Severities:    exportFilter.Severities,
		StartTime:     exportFilter.StartTime,
		EndTime:       exportFilter.EndTime,
		ClusterName:   es.firstOrEmpty(exportFilter.ClusterNames),
		Namespace:     es.firstOrEmpty(exportFilter.Namespaces),
		ServiceName:   es.firstOrEmpty(exportFilter.ServiceNames),
		CorrelationID: es.firstOrEmpty(exportFilter.CorrelationIDs),
		SortBy:        "timestamp",
		SortOrder:     "asc",
	}
}

func (es *ExportService) firstOrEmpty(slice []string) string {
	if len(slice) > 0 {
		return slice[0]
	}
	return ""
}

func (es *ExportService) applySampling(events []*models.AuditEvent, sampleRate float64) []*models.AuditEvent {
	if sampleRate >= 1.0 {
		return events
	}
	
	sampledEvents := make([]*models.AuditEvent, 0)
	for i, event := range events {
		// Simple deterministic sampling based on event position
		if float64(i%100)/100.0 < sampleRate {
			sampledEvents = append(sampledEvents, event)
		}
	}
	
	return sampledEvents
}

func (es *ExportService) updateStatistics(stats *ExportStatistics, events []*models.AuditEvent) {
	if stats.EventsByType == nil {
		stats.EventsByType = make(map[string]int64)
		stats.EventsBySeverity = make(map[string]int64)
		stats.EventsByUser = make(map[string]int64)
		stats.EventsByCluster = make(map[string]int64)
	}
	
	for _, event := range events {
		stats.EventsByType[string(event.EventType)]++
		stats.EventsBySeverity[string(event.Severity)]++
		stats.EventsByUser[event.UserContext.UserID]++
		if event.ClusterContext.ClusterName != "" {
			stats.EventsByCluster[event.ClusterContext.ClusterName]++
		}
	}
}

func (es *ExportService) calculateEstimatedTimeRemaining(startTime time.Time, processed, total int64) time.Duration {
	if processed == 0 {
		return 0
	}
	
	elapsed := time.Since(startTime)
	avgTimePerEvent := elapsed / time.Duration(processed)
	remaining := total - processed
	
	return avgTimePerEvent * time.Duration(remaining)
}

func (es *ExportService) completeExportWithNoEvents(job *ExportJob, startTime time.Time) {
	result := &ExportResult{
		ExportedEvents:    0,
		TotalSize:         0,
		Format:            job.Request.Format,
		Files:             []ExportFile{},
		Statistics:        ExportStatistics{},
		CompletedAt:       time.Now().UTC(),
		ExecutionDuration: time.Since(startTime),
	}
	
	job.Result = result
	job.Progress.PercentComplete = 100.0
	job.CompletedAt = time.Now().UTC()
	
	es.jobTracker.UpdateJobStatus(job.ID, ExportJobStatusCompleted, "")
}

func (es *ExportService) createExportFiles(job *ExportJob, data []byte, formatter formats.SIEMFormatExporter) ([]ExportFile, error) {
	filename := fmt.Sprintf("%s.%s", job.ID, es.getFileExtension(job.Request.Format))
	
	// TODO: Implement file creation, compression, and storage
	// This would typically involve:
	// 1. Writing data to temporary files
	// 2. Compressing if requested
	// 3. Calculating checksums
	// 4. Generating download URLs
	
	file := ExportFile{
		Filename:   filename,
		Size:       int64(len(data)),
		EventCount: job.Progress.ExportedEvents,
		Format:     job.Request.Format,
		Compressed: job.Request.CompressOutput,
		Checksum:   es.calculateChecksum(data),
		Metadata:   make(map[string]interface{}),
	}
	
	return []ExportFile{file}, nil
}

func (es *ExportService) getFileExtension(format string) string {
	switch format {
	case "JSON":
		return "json"
	case "CEF", "LEEF":
		return "txt"
	default:
		return "dat"
	}
}

func (es *ExportService) calculateChecksum(data []byte) string {
	// Simple checksum calculation - in practice, use SHA-256
	return fmt.Sprintf("sha256:%x", len(data)) // Placeholder
}

// GetExportMetrics returns export service metrics
func (es *ExportService) GetExportMetrics() map[string]interface{} {
	return map[string]interface{}{
		"active_jobs":           es.jobTracker.GetActiveJobCount(),
		"total_jobs":           es.jobTracker.GetTotalJobCount(),
		"completed_jobs":       es.jobTracker.GetCompletedJobCount(),
		"failed_jobs":          es.jobTracker.GetFailedJobCount(),
		"max_concurrent_exports": es.config.MaxConcurrentExports,
		"supported_formats":    []string{"JSON", "CEF", "LEEF"},
	}
}