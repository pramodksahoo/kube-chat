// Package main provides the KubeChat audit service entry point
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/audit/export"
	"github.com/pramodksahoo/kube-chat/pkg/audit/streaming"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// Config holds the audit service configuration
type Config struct {
	Port             string `json:"port"`
	DatabaseURL      string `json:"database_url"`
	RetentionDays    int    `json:"retention_days"`
	WorkerCount      int    `json:"worker_count"`
	BufferSize       int    `json:"buffer_size"`
	RetryAttempts    int    `json:"retry_attempts"`
	RetryDelayMs     int    `json:"retry_delay_ms"`
	HealthCheckPath  string `json:"health_check_path"`
	MetricsPath      string `json:"metrics_path"`
	EncryptionEnabled bool  `json:"encryption_enabled"`
	KeyNamespace     string `json:"key_namespace"`
	KeySecretName    string `json:"key_secret_name"`
}

// DefaultConfig returns default configuration
func DefaultConfig() Config {
	// Try to get DATABASE_URL first, if not available, construct from individual components
	databaseURL := getEnv("DATABASE_URL", "")
	if databaseURL == "" {
		// Construct DATABASE_URL from individual environment variables
		host := getEnv("DATABASE_HOST", "postgres-postgresql")
		port := getEnv("DATABASE_PORT", "5432")
		dbname := getEnv("DATABASE_NAME", "kubechat_audit")
		user := getEnv("DATABASE_USER", "postgres")
		password := getEnv("DATABASE_PASSWORD", "password")
		databaseURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, host, port, dbname)
	}
	
	return Config{
		Port:              getEnv("AUDIT_PORT", "8081"),
		DatabaseURL:       databaseURL,
		RetentionDays:     getEnvInt("AUDIT_RETENTION_DAYS", 365*7), // 7 years default
		WorkerCount:       getEnvInt("AUDIT_WORKER_COUNT", 4),
		BufferSize:        getEnvInt("AUDIT_BUFFER_SIZE", 10000),
		RetryAttempts:     getEnvInt("AUDIT_RETRY_ATTEMPTS", 3),
		RetryDelayMs:      getEnvInt("AUDIT_RETRY_DELAY_MS", 2000),
		HealthCheckPath:   getEnv("AUDIT_HEALTH_PATH", "/health"),
		MetricsPath:       getEnv("AUDIT_METRICS_PATH", "/metrics"),
		EncryptionEnabled: getEnv("AUDIT_ENCRYPTION_ENABLED", "true") == "true",
		KeyNamespace:      getEnv("AUDIT_KEY_NAMESPACE", "kube-chat"),
		KeySecretName:     getEnv("AUDIT_KEY_SECRET_NAME", "audit-encryption-key"),
	}
}

// AuditService provides the main audit service
type AuditService struct {
	config            Config
	storage           audit.AuditStorage
	collector         *audit.EventCollector
	verifier          *audit.IntegrityVerifier
	integrityService  *audit.IntegrityService
	evidenceService   *audit.EvidenceService
	exportService     *export.ExportService
	streamingService  *streaming.WebhookStreamingService
	authService       *export.ExportAuthService
	encryptedStorage  *audit.EncryptedAuditStorage
	app               *fiber.App
}

// NewAuditService creates a new audit service instance
func NewAuditService(config Config) (*AuditService, error) {
	// Initialize storage
	baseStorage, err := audit.NewPostgreSQLAuditStorage(config.DatabaseURL, config.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	
	var storage audit.AuditStorage = baseStorage

	// Initialize encryption if enabled
	var encryptedStorage *audit.EncryptedAuditStorage
	if config.EncryptionEnabled {
		// Create encryption key manager
		keyManager := audit.NewExternalSecretsKeyManager(config.KeyNamespace, config.KeySecretName)
		
		// Create encryption service
		encryptionService, err := audit.NewEncryptionService(keyManager)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
		}
		
		// Wrap storage with encryption
		encryptedStorage = audit.NewEncryptedAuditStorage(baseStorage, encryptionService)
		storage = encryptedStorage // Use encrypted storage
		
		log.Printf("Audit encryption enabled with key namespace: %s", config.KeyNamespace)
	}

	// Initialize collector
	collectorConfig := audit.CollectorConfig{
		Workers:       config.WorkerCount,
		BufferSize:    config.BufferSize,
		RetryAttempts: config.RetryAttempts,
		RetryDelay:    time.Duration(config.RetryDelayMs) * time.Millisecond,
	}
	collector := audit.NewEventCollector(storage, collectorConfig)

	// Initialize integrity verifier
	verifier := audit.NewIntegrityVerifier()
	
	// Initialize integrity service
	integrityService := audit.NewIntegrityService(storage)
	
	// Initialize evidence service
	evidenceService := audit.NewEvidenceService(storage, integrityService)

	// Initialize authentication service
	authConfig := export.DefaultExportAuthConfig()
	authConfig.JWTSecret = getEnv("JWT_SECRET", "")
	if authConfig.JWTSecret == "" {
		log.Println("Warning: JWT_SECRET not configured - authentication will be disabled")
		authConfig.RequireAuthentication = false
	}
	authService := export.NewExportAuthService(authConfig)

	// Initialize export service
	exportConfig := export.ExportServiceConfig{
		MaxConcurrentExports:  getEnvInt("EXPORT_MAX_CONCURRENT", 5),
		DefaultPageSize:       getEnvInt("EXPORT_DEFAULT_PAGE_SIZE", 1000),
		MaxPageSize:          getEnvInt("EXPORT_MAX_PAGE_SIZE", 10000),
		ExportTimeout:        time.Duration(getEnvInt("EXPORT_TIMEOUT_MINUTES", 30)) * time.Minute,
		JobRetentionPeriod:   time.Duration(getEnvInt("EXPORT_JOB_RETENTION_HOURS", 24)) * time.Hour,
		EnableIntegrityChecks: getEnv("EXPORT_ENABLE_INTEGRITY", "true") == "true",
		MaxExportSize:        int64(getEnvInt("EXPORT_MAX_SIZE_MB", 100)) * 1024 * 1024,
		TempDirectory:        getEnv("EXPORT_TEMP_DIR", "/tmp/kubechat-exports"),
	}
	exportService, err := export.NewExportService(storage, exportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize export service: %w", err)
	}

	// Initialize streaming service  
	bufferConfig := streaming.LocalBufferConfig{
		MaxBufferSize:      getEnvInt("STREAM_BUFFER_SIZE", 10000),
		MaxBufferAge:       time.Duration(getEnvInt("STREAM_BUFFER_MAX_AGE_MINUTES", 60)) * time.Minute,
		BufferDirectory:    getEnv("STREAM_BUFFER_PATH", "/tmp/kubechat-stream-buffer"),
		FlushInterval:      time.Duration(getEnvInt("STREAM_BUFFER_FLUSH_SECONDS", 30)) * time.Second,
		PersistToDisk:      getEnv("STREAM_BUFFER_PERSIST", "true") == "true",
		MaxDiskUsage:       int64(getEnvInt("STREAM_BUFFER_MAX_DISK_MB", 100)) * 1024 * 1024,
		CompressionEnabled: getEnv("STREAM_BUFFER_COMPRESSION", "true") == "true",
		RetryPolicy: streaming.RetryPolicy{
			MaxRetries:         getEnvInt("STREAM_BUFFER_MAX_RETRIES", 3),
			InitialBackoff:     time.Duration(getEnvInt("STREAM_BUFFER_RETRY_BACKOFF_SECONDS", 30)) * time.Second,
			MaxBackoff:         time.Duration(getEnvInt("STREAM_BUFFER_MAX_BACKOFF_SECONDS", 300)) * time.Second,
			BackoffMultiplier:  2.0,
			RetryJitter:        true,
			ExponentialBackoff: true,
		},
	}
	streamingService := streaming.NewWebhookStreamingService(bufferConfig)

	// Initialize Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "KubeChat Audit Service",
		ServerHeader: "KubeChat-Audit/1.0",
	})

	service := &AuditService{
		config:           config,
		storage:          storage,
		collector:        collector,
		verifier:         verifier,
		integrityService: integrityService,
		evidenceService:  evidenceService,
		exportService:    exportService,
		streamingService: streamingService,
		authService:      authService,
		encryptedStorage: encryptedStorage,
		app:              app,
	}

	service.setupRoutes()
	return service, nil
}

// setupRoutes configures the HTTP routes
func (s *AuditService) setupRoutes() {
	// Middleware
	s.app.Use(recover.New())
	s.app.Use(logger.New())
	s.app.Use(cors.New())

	// Health check endpoint
	s.app.Get(s.config.HealthCheckPath, s.healthCheckHandler)

	// Ready endpoint
	s.app.Get("/ready", s.readinessHandler)

	// Metrics endpoint
	s.app.Get(s.config.MetricsPath, s.metricsHandler)

	// Audit API endpoints
	api := s.app.Group("/api/v1/audit")
	
	// Event ingestion
	api.Post("/log", s.logEventHandler)
	
	// Event retrieval
	api.Get("/events", s.queryEventsHandler)
	api.Get("/events/:id", s.getEventHandler)
	
	// User-specific queries
	api.Get("/users/:userID/events", s.getUserEventsHandler)
	
	// Integrity verification
	api.Post("/verify", s.verifyIntegrityHandler)
	api.Get("/events/:id/verify", s.verifyEventIntegrityHandler)
	
	// Enhanced integrity verification endpoints
	api.Post("/integrity/verify", s.integrityVerificationHandler)
	api.Get("/integrity/report", s.integrityReportHandler)
	api.Get("/integrity/status", s.integrityStatusHandler)
	api.Post("/integrity/repair", s.integrityRepairHandler)
	
	// Encryption management endpoints (if encryption enabled)
	if s.encryptedStorage != nil {
		api.Get("/encryption/metrics", s.encryptionMetricsHandler)
		api.Post("/encryption/rotate-key", s.rotateEncryptionKeyHandler)
	}
	
	// Statistics
	api.Get("/stats", s.getStatsHandler)
	api.Get("/stats/types", s.getEventTypeStatsHandler)
	
	// SIEM Export API endpoints (with authentication middleware)
	siemAPI := api.Group("/export", s.authMiddleware)
	siemAPI.Post("/", s.createExportHandler)
	siemAPI.Get("/jobs", s.listExportJobsHandler)
	siemAPI.Get("/jobs/:jobID", s.getExportJobHandler)
	siemAPI.Get("/jobs/:jobID/download", s.downloadExportHandler)
	siemAPI.Delete("/jobs/:jobID", s.cancelExportJobHandler)
	
	// SIEM Streaming API endpoints (with authentication middleware)
	streamAPI := api.Group("/stream", s.authMiddleware)
	streamAPI.Get("/status", s.getStreamingStatusHandler)
	streamAPI.Post("/webhook", s.configureWebhookHandler)
	streamAPI.Get("/webhooks", s.listWebhooksHandler)
	streamAPI.Put("/webhooks/:webhookID", s.updateWebhookHandler)
	streamAPI.Delete("/webhooks/:webhookID", s.deleteWebhookHandler)
	streamAPI.Post("/test/:webhookID", s.testWebhookHandler)
	
	// Evidence Generation API endpoints (with authentication middleware)
	evidenceAPI := api.Group("/evidence", s.authMiddleware)
	evidenceAPI.Post("/generate", s.generateEvidenceHandler)
	evidenceAPI.Get("/packages", s.listEvidencePackagesHandler)
	evidenceAPI.Get("/download/:id", s.downloadEvidenceHandler)
	evidenceAPI.Get("/verify/:id", s.verifyEvidenceHandler)
}

// Start starts the audit service
func (s *AuditService) Start() error {
	// Start the event collector
	if err := s.collector.Start(); err != nil {
		return fmt.Errorf("failed to start event collector: %w", err)
	}

	log.Printf("Starting KubeChat Audit Service on port %s", s.config.Port)
	log.Printf("Database: %s", s.config.DatabaseURL)
	log.Printf("Worker Count: %d", s.config.WorkerCount)
	log.Printf("Buffer Size: %d", s.config.BufferSize)

	// Start HTTP server
	return s.app.Listen(":" + s.config.Port)
}

// Stop gracefully stops the audit service
func (s *AuditService) Stop() error {
	log.Println("Shutting down KubeChat Audit Service...")

	// Stop the event collector
	if err := s.collector.Stop(); err != nil {
		log.Printf("Error stopping event collector: %v", err)
	}

	// Shutdown HTTP server
	if err := s.app.Shutdown(); err != nil {
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}

	log.Println("Audit service stopped")
	return nil
}

// HTTP Handlers

func (s *AuditService) healthCheckHandler(c *fiber.Ctx) error {
	// Check collector health
	if err := s.collector.HealthCheck(); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		})
	}

	// Check storage health
	if err := s.storage.HealthCheck(c.Context()); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"status": "unhealthy",
			"error":  err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"status": "healthy",
		"service": "audit-service",
		"version": "1.0.0",
	})
}

func (s *AuditService) readinessHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ready",
		"service": "audit-service",
		"version": "1.0.0",
	})
}

func (s *AuditService) metricsHandler(c *fiber.Ctx) error {
	stats := s.collector.GetStats()
	
	return c.JSON(fiber.Map{
		"collector_stats": stats,
		"service_info": fiber.Map{
			"uptime": time.Since(stats.StartedAt).String(),
			"config": fiber.Map{
				"worker_count": s.config.WorkerCount,
				"buffer_size":  s.config.BufferSize,
			},
		},
	})
}

func (s *AuditService) logEventHandler(c *fiber.Ctx) error {
	var event models.AuditEvent
	if err := c.BodyParser(&event); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	// Collect the event asynchronously
	if err := s.collector.CollectEventWithTimeout(&event, time.Second*5); err != nil {
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
			"error": "Failed to queue audit event",
			"details": err.Error(),
		})
	}

	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"message": "Audit event queued for processing",
		"event_id": event.ID,
	})
}

func (s *AuditService) queryEventsHandler(c *fiber.Ctx) error {
	// Parse query parameters into filter
	filter := models.AuditEventFilter{
		UserID:        c.Query("user_id"),
		ClusterName:   c.Query("cluster_name"),
		Namespace:     c.Query("namespace"),
		ServiceName:   c.Query("service_name"),
		CorrelationID: c.Query("correlation_id"),
		Limit:         c.QueryInt("limit", 50),
		Offset:        c.QueryInt("offset", 0),
		SortBy:        c.Query("sort_by", "timestamp"),
		SortOrder:     c.Query("sort_order", "desc"),
	}

	// Parse time range if provided
	if startTime := c.Query("start_time"); startTime != "" {
		if t, err := time.Parse(time.RFC3339, startTime); err == nil {
			filter.StartTime = t
		}
	}
	if endTime := c.Query("end_time"); endTime != "" {
		if t, err := time.Parse(time.RFC3339, endTime); err == nil {
			filter.EndTime = t
		}
	}

	events, err := s.storage.QueryEvents(c.Context(), filter)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to query audit events",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"events": events,
		"count":  len(events),
		"filter": filter,
	})
}

func (s *AuditService) getEventHandler(c *fiber.Ctx) error {
	eventID := c.Params("id")
	if eventID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Event ID is required",
		})
	}

	event, err := s.storage.GetEvent(c.Context(), eventID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Audit event not found",
			"details": err.Error(),
		})
	}

	return c.JSON(event)
}

func (s *AuditService) getUserEventsHandler(c *fiber.Ctx) error {
	userID := c.Params("userID")
	limit := c.QueryInt("limit", 100)

	events, err := s.storage.GetEventsByUser(c.Context(), userID, limit)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get user events",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"user_id": userID,
		"events":  events,
		"count":   len(events),
	})
}

func (s *AuditService) verifyIntegrityHandler(c *fiber.Ctx) error {
	var request struct {
		EventIDs []string `json:"event_ids"`
	}
	
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	var events []*models.AuditEvent
	for _, eventID := range request.EventIDs {
		event, err := s.storage.GetEvent(c.Context(), eventID)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
				"error": fmt.Sprintf("Event %s not found", eventID),
			})
		}
		events = append(events, event)
	}

	report, err := s.verifier.VerifyBatchIntegrity(events)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify integrity",
			"details": err.Error(),
		})
	}

	return c.JSON(report)
}

func (s *AuditService) verifyEventIntegrityHandler(c *fiber.Ctx) error {
	eventID := c.Params("id")
	
	valid, err := s.storage.VerifyIntegrity(c.Context(), eventID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify event integrity",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"event_id": eventID,
		"valid":    valid,
	})
}

func (s *AuditService) getStatsHandler(c *fiber.Ctx) error {
	stats, err := s.storage.GetStorageStats(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get storage statistics",
			"details": err.Error(),
		})
	}

	return c.JSON(stats)
}

func (s *AuditService) getEventTypeStatsHandler(c *fiber.Ctx) error {
	counts, err := s.storage.CountEventsByType(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to get event type statistics",
			"details": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"event_type_counts": counts,
	})
}

// Utility functions

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// Authentication middleware for SIEM API endpoints
func (s *AuditService) authMiddleware(c *fiber.Ctx) error {
	// Skip authentication if not required (development mode)
	if !s.authService.RequireAuthentication() {
		return c.Next()
	}
	
	// Extract JWT token from Authorization header
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Authorization header required",
		})
	}
	
	// Check for Bearer token format
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid authorization header format",
		})
	}
	
	token := authHeader[7:] // Remove "Bearer " prefix
	
	// Validate token
	authContext, err := s.authService.ValidateSessionToken(c.Context(), token)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid or expired token",
			"details": err.Error(),
		})
	}
	
	// Check permissions
	if !s.authService.HasRequiredPermissions(authContext) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "Insufficient permissions for audit export operations",
		})
	}
	
	// Store auth context in request locals for handlers to use
	c.Locals("authContext", authContext)
	
	return c.Next()
}

// SIEM Export Handler - Create Export Job
func (s *AuditService) createExportHandler(c *fiber.Ctx) error {
	authContext := c.Locals("authContext").(*export.AuthContext)
	
	var request export.ExportRequest
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
			"details": err.Error(),
		})
	}
	
	// Set the requesting user
	request.RequestedBy = authContext.UserID
	
	// Create export job
	job, err := s.exportService.ExportEvents(c.Context(), request)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create export job",
			"details": err.Error(),
		})
	}
	
	return c.Status(fiber.StatusCreated).JSON(job)
}

// SIEM Export Handler - List Export Jobs
func (s *AuditService) listExportJobsHandler(c *fiber.Ctx) error {
	authContext := c.Locals("authContext").(*export.AuthContext)
	
	// Get query parameters
	status := c.Query("status")
	limit := c.QueryInt("limit", 20)
	offset := c.QueryInt("offset", 0)
	
	jobs, err := s.exportService.ListExportJobs(export.ExportJobStatus(status), authContext.UserID, limit, offset)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to list export jobs",
			"details": err.Error(),
		})
	}
	
	return c.JSON(fiber.Map{
		"jobs": jobs,
		"count": len(jobs),
	})
}

// SIEM Export Handler - Get Export Job
func (s *AuditService) getExportJobHandler(c *fiber.Ctx) error {
	_ = c.Locals("authContext").(*export.AuthContext) // For future authorization checks
	jobID := c.Params("jobID")
	
	job, err := s.exportService.GetExportJob(jobID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Export job not found",
			"details": err.Error(),
		})
	}
	
	return c.JSON(job)
}

// SIEM Export Handler - Download Export
func (s *AuditService) downloadExportHandler(c *fiber.Ctx) error {
	_ = c.Locals("authContext").(*export.AuthContext) // For future authorization checks
	jobID := c.Params("jobID")
	
	// Get job details
	job, err := s.exportService.GetExportJob(jobID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Export job not found",
		})
	}
	
	// Check if job is completed
	if job.Status != "completed" {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "Export job not completed",
			"status": job.Status,
		})
	}
	
	// Check if there are export files
	if job.Result == nil || len(job.Result.Files) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Export files not found",
		})
	}
	
	// Stream the first export file (for now)
	exportFile := job.Result.Files[0]
	return c.Download(exportFile.Filename, fmt.Sprintf("audit-export-%s.%s", jobID, exportFile.Format))
}

// SIEM Export Handler - Cancel Export Job
func (s *AuditService) cancelExportJobHandler(c *fiber.Ctx) error {
	_ = c.Locals("authContext").(*export.AuthContext) // For future authorization checks
	jobID := c.Params("jobID")
	
	err := s.exportService.CancelExportJob(jobID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to cancel export job",
			"details": err.Error(),
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Export job cancelled",
		"jobID": jobID,
	})
}

// SIEM Streaming Handler - Get Status
func (s *AuditService) getStreamingStatusHandler(c *fiber.Ctx) error {
	status := s.streamingService.GetServiceStatus()
	return c.JSON(status)
}

// SIEM Streaming Handler - Configure Webhook
func (s *AuditService) configureWebhookHandler(c *fiber.Ctx) error {
	authContext := c.Locals("authContext").(*export.AuthContext)
	
	var webhook streaming.WebhookEndpoint
	if err := c.BodyParser(&webhook); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid webhook configuration",
			"details": err.Error(),
		})
	}
	
	// Add webhook
	err := s.streamingService.AddEndpoint(&webhook)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to configure webhook",
			"details": err.Error(),
		})
	}
	
	log.Printf("User %s configured webhook %s for platform %s", 
		authContext.UserID, webhook.ID, webhook.Platform)
	
	return c.Status(fiber.StatusCreated).JSON(webhook)
}

// SIEM Streaming Handler - List Webhooks
func (s *AuditService) listWebhooksHandler(c *fiber.Ctx) error {
	webhooks := s.streamingService.ListEndpoints()
	return c.JSON(fiber.Map{
		"webhooks": webhooks,
		"count": len(webhooks),
	})
}

// SIEM Streaming Handler - Update Webhook
func (s *AuditService) updateWebhookHandler(c *fiber.Ctx) error {
	webhookID := c.Params("webhookID")
	
	var webhook streaming.WebhookEndpoint
	if err := c.BodyParser(&webhook); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid webhook configuration",
		})
	}
	
	webhook.ID = webhookID
	
	err := s.streamingService.UpdateEndpoint(&webhook)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update webhook",
			"details": err.Error(),
		})
	}
	
	return c.JSON(webhook)
}

// SIEM Streaming Handler - Delete Webhook
func (s *AuditService) deleteWebhookHandler(c *fiber.Ctx) error {
	webhookID := c.Params("webhookID")
	
	err := s.streamingService.RemoveEndpoint(webhookID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Webhook not found",
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Webhook deleted",
		"webhookID": webhookID,
	})
}

// SIEM Streaming Handler - Test Webhook
func (s *AuditService) testWebhookHandler(c *fiber.Ctx) error {
	webhookID := c.Params("webhookID")
	
	err := s.streamingService.TestEndpoint(webhookID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Webhook test failed",
			"details": err.Error(),
		})
	}
	
	return c.JSON(fiber.Map{
		"message": "Webhook test successful",
		"webhookID": webhookID,
	})
}

// Enhanced Integrity Verification Handlers

func (s *AuditService) integrityVerificationHandler(c *fiber.Ctx) error {
	var request struct {
		StartSequence *int64    `json:"start_sequence,omitempty"`
		EndSequence   *int64    `json:"end_sequence,omitempty"`
		StartTime     *time.Time `json:"start_time,omitempty"`
		EndTime       *time.Time `json:"end_time,omitempty"`
		EventIDs      []string  `json:"event_ids,omitempty"`
	}
	
	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
			"details": err.Error(),
		})
	}
	
	// Perform integrity verification based on request parameters
	var report *audit.IntegrityReport
	var err error
	
	if len(request.EventIDs) > 0 {
		// Verify specific events
		report, err = s.integrityService.VerifyEventsByID(c.Context(), request.EventIDs)
	} else if request.StartTime != nil && request.EndTime != nil {
		// Verify time range
		report, err = s.integrityService.VerifyRangeIntegrity(c.Context(), *request.StartTime, *request.EndTime)
	} else {
		// Verify recent events (default behavior)
		endTime := time.Now()
		startTime := endTime.Add(-24 * time.Hour) // Last 24 hours
		report, err = s.integrityService.VerifyRangeIntegrity(c.Context(), startTime, endTime)
	}
	
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to verify integrity",
			"details": err.Error(),
		})
	}
	
	return c.JSON(report)
}

func (s *AuditService) integrityReportHandler(c *fiber.Ctx) error {
	format := c.Query("format", "json")
	reportType := c.Query("type", "compliance")
	
	// Generate comprehensive integrity report
	report, err := s.integrityService.GenerateComplianceReport(c.Context(), reportType)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate integrity report",
			"details": err.Error(),
		})
	}
	
	switch format {
	case "pdf":
		// In a real implementation, this would generate a PDF
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
			"error": "PDF format not yet implemented",
			"available_formats": []string{"json"},
		})
	default:
		return c.JSON(report)
	}
}

func (s *AuditService) integrityStatusHandler(c *fiber.Ctx) error {
	status := s.integrityService.GetIntegrityStatus()
	return c.JSON(status)
}

func (s *AuditService) integrityRepairHandler(c *fiber.Ctx) error {
	report, err := s.integrityService.DetectAndReportViolations(c.Context())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to detect integrity violations",
			"details": err.Error(),
		})
	}
	
	return c.JSON(fiber.Map{
		"violations_detected": len(report.IntegrityViolations) > 0,
		"violations_count": len(report.IntegrityViolations),
		"report": report,
		"note": "Tamper-proof storage prevents automatic repair. This endpoint only detects and reports violations.",
	})
}

// Encryption Management Handlers

func (s *AuditService) encryptionMetricsHandler(c *fiber.Ctx) error {
	if s.encryptedStorage == nil {
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
			"error": "Encryption not enabled",
		})
	}
	
	metrics := s.encryptedStorage.GetEncryptionMetrics()
	return c.JSON(metrics)
}

func (s *AuditService) rotateEncryptionKeyHandler(c *fiber.Ctx) error {
	if s.encryptedStorage == nil {
		return c.Status(fiber.StatusNotImplemented).JSON(fiber.Map{
			"error": "Encryption not enabled",
		})
	}
	
	// Get old key info
	oldMetrics := s.encryptedStorage.GetEncryptionMetrics()
	oldKeyID := oldMetrics.CurrentKeyID
	
	// Rotate key
	err := s.encryptedStorage.RotateEncryptionKey()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to rotate encryption key",
			"details": err.Error(),
		})
	}
	
	// Get new key info
	newMetrics := s.encryptedStorage.GetEncryptionMetrics()
	newKeyID := newMetrics.CurrentKeyID
	
	log.Printf("Encryption key rotated: %s -> %s", oldKeyID, newKeyID)
	
	return c.JSON(fiber.Map{
		"message": "Encryption key rotated successfully",
		"old_key_id": oldKeyID,
		"new_key_id": newKeyID,
		"rotation_time": time.Now().UTC(),
	})
}

// Evidence Generation Handlers

func (s *AuditService) generateEvidenceHandler(c *fiber.Ctx) error {
	var request struct {
		PackageID           string                    `json:"package_id"`
		ComplianceFramework string                   `json:"compliance_framework"`
		TimeRange          struct {
			StartTime string `json:"start_time"`
			EndTime   string `json:"end_time"`
		} `json:"time_range"`
		Scope struct {
			UserIDs       []string `json:"user_ids,omitempty"`
			EventTypes    []string `json:"event_types,omitempty"`
			ResourceTypes []string `json:"resource_types,omitempty"`
			Namespaces    []string `json:"namespaces,omitempty"`
		} `json:"scope,omitempty"`
		Formats []string `json:"formats"`
		RequesterInfo struct {
			UserID string `json:"user_id"`
			Name   string `json:"name"`
			Email  string `json:"email"`
			Role   string `json:"role"`
		} `json:"requester_info"`
	}

	if err := c.BodyParser(&request); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
			"details": err.Error(),
		})
	}

	// Parse time range
	startTime, err := time.Parse(time.RFC3339, request.TimeRange.StartTime)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid start_time format, expected RFC3339",
		})
	}

	endTime, err := time.Parse(time.RFC3339, request.TimeRange.EndTime)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid end_time format, expected RFC3339",
		})
	}

	// Create evidence package request
	packageRequest := &audit.EvidencePackageRequest{
		PackageID:           request.PackageID,
		ComplianceFramework: request.ComplianceFramework,
		TimeRange: audit.EvidenceTimeRange{
			StartTime: startTime,
			EndTime:   endTime,
		},
		Scope: audit.EvidenceScope{
			UserIDs:       request.Scope.UserIDs,
			ResourceTypes: request.Scope.ResourceTypes,
			Namespaces:    request.Scope.Namespaces,
		},
		Formats: convertToEvidenceFormats(request.Formats),
		RequesterInfo: audit.EvidenceRequester{
			UserID:      request.RequesterInfo.UserID,
			Name:        request.RequesterInfo.Name,
			Email:       request.RequesterInfo.Email,
			Role:        request.RequesterInfo.Role,
			RequestedAt: time.Now(),
		},
		GeneratedAt: time.Now(),
	}

	// Generate evidence package
	evidencePackage, err := s.evidenceService.GenerateEvidencePackage(c.Context(), packageRequest)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to generate evidence package",
			"details": err.Error(),
		})
	}

	// Log access event
	_ = s.evidenceService.LogAccess(evidencePackage, 
		request.RequesterInfo.UserID, "GENERATE", c.IP(), c.Get("User-Agent"))

	return c.JSON(fiber.Map{
		"package_id": evidencePackage.PackageID,
		"status": "generated",
		"generated_at": evidencePackage.GeneratedAt,
		"event_count": evidencePackage.EventCount,
		"compliance_framework": evidencePackage.ComplianceFramework,
		"integrity_status": evidencePackage.IntegrityCertificate.IntegrityStatus,
	})
}

func (s *AuditService) listEvidencePackagesHandler(c *fiber.Ctx) error {
	// This would typically store evidence packages in a database
	// For now, return a placeholder response
	return c.JSON(fiber.Map{
		"packages": []map[string]interface{}{},
		"message": "Evidence packages listing not yet implemented - packages are generated on demand",
	})
}

func (s *AuditService) downloadEvidenceHandler(c *fiber.Ctx) error {
	packageID := c.Params("id")
	if packageID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Package ID is required",
		})
	}

	// For a full implementation, this would retrieve the package from storage
	// For now, return an error indicating the package needs to be regenerated
	return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
		"error": "Evidence package not found",
		"message": "Evidence packages are generated on demand. Please use the /generate endpoint to create a new package.",
		"package_id": packageID,
	})
}

func (s *AuditService) verifyEvidenceHandler(c *fiber.Ctx) error {
	packageID := c.Params("id")
	if packageID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Package ID is required",
		})
	}

	// For a full implementation, this would retrieve and verify the package
	// For now, return a placeholder response
	return c.JSON(fiber.Map{
		"package_id": packageID,
		"verification_status": "not_implemented",
		"message": "Evidence package verification requires retrieving the package from storage",
	})
}

// Helper function to convert string formats to EvidenceFormat types
func convertToEvidenceFormats(formats []string) []audit.EvidenceFormat {
	evidenceFormats := make([]audit.EvidenceFormat, len(formats))
	for i, format := range formats {
		switch format {
		case "json":
			evidenceFormats[i] = audit.FormatJSON
		case "csv":
			evidenceFormats[i] = audit.FormatCSV
		case "pdf":
			evidenceFormats[i] = audit.FormatPDF
		default:
			evidenceFormats[i] = audit.FormatJSON // Default fallback
		}
	}
	return evidenceFormats
}

func main() {
	config := DefaultConfig()
	
	service, err := NewAuditService(config)
	if err != nil {
		log.Fatalf("Failed to create audit service: %v", err)
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Received shutdown signal")
		if err := service.Stop(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
		os.Exit(0)
	}()

	// Start the service
	if err := service.Start(); err != nil {
		log.Fatalf("Failed to start audit service: %v", err)
	}
}