// Package middleware provides HTTP middleware for audit logging
package middleware

import (
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// AuditConfig holds configuration for audit middleware
type AuditConfig struct {
	// Collector is the audit event collector
	Collector EventCollectorInterface
	
	// ServiceName identifies the service generating audit events
	ServiceName string
	
	// ServiceVersion identifies the service version
	ServiceVersion string
	
	// SkipPaths are paths to skip auditing (e.g., health checks)
	SkipPaths []string
	
	// SkipMethods are HTTP methods to skip auditing
	SkipMethods []string
	
	// LogRequestBody enables request body logging
	LogRequestBody bool
	
	// LogResponseBody enables response body logging
	LogResponseBody bool
	
	// MaxBodySize limits the size of request/response bodies to log
	MaxBodySize int64
	
	// UserContextExtractor extracts user context from the request
	UserContextExtractor func(c *fiber.Ctx) (*models.User, *models.SessionAuthContext, error)
	
	// CorrelationIDExtractor extracts correlation ID from request
	CorrelationIDExtractor func(c *fiber.Ctx) string
	
	// TraceIDExtractor extracts trace ID from request
	TraceIDExtractor func(c *fiber.Ctx) string
}

// EventCollectorInterface defines the interface for audit event collection
type EventCollectorInterface interface {
	CollectEvent(event *models.AuditEvent) error
	CollectEventWithTimeout(event *models.AuditEvent, timeout time.Duration) error
}

// DefaultAuditConfig returns default audit middleware configuration
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		ServiceName:     "api-gateway",
		ServiceVersion:  "1.0.0",
		SkipPaths:       []string{"/health", "/metrics", "/favicon.ico"},
		SkipMethods:     []string{"OPTIONS"},
		LogRequestBody:  false,
		LogResponseBody: false,
		MaxBodySize:     4096, // 4KB default
		UserContextExtractor: defaultUserContextExtractor,
		CorrelationIDExtractor: defaultCorrelationIDExtractor,
		TraceIDExtractor: defaultTraceIDExtractor,
	}
}

// NewAuditMiddleware creates a new audit middleware with the provided configuration
func NewAuditMiddleware(config AuditConfig) fiber.Handler {
	if config.Collector == nil {
		log.Println("Warning: Audit middleware configured without collector - events will be ignored")
	}
	
	return func(c *fiber.Ctx) error {
		// Skip audit for certain paths and methods
		if shouldSkipAudit(c, config) {
			return c.Next()
		}
		
		// Record start time
		startTime := time.Now()
		
		// Capture request information
		requestInfo := captureRequestInfo(c, config)
		
		// Continue processing
		err := c.Next()
		
		// Record end time and calculate duration
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		
		// Capture response information
		responseInfo := captureResponseInfo(c, config)
		
		// Create and send audit event
		auditEvent := createAuditEvent(c, config, requestInfo, responseInfo, startTime, duration, err)
		if auditEvent != nil {
			sendAuditEvent(config.Collector, auditEvent)
		}
		
		return err
	}
}

// RequestInfo holds captured request information
type RequestInfo struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`
	QueryParams map[string]string `json:"query_params"`
	Body        string            `json:"body,omitempty"`
	BodySize    int64             `json:"body_size"`
	IPAddress   string            `json:"ip_address"`
	UserAgent   string            `json:"user_agent"`
}

// ResponseInfo holds captured response information  
type ResponseInfo struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body,omitempty"`
	BodySize   int64             `json:"body_size"`
}

// shouldSkipAudit determines if the request should be skipped for auditing
func shouldSkipAudit(c *fiber.Ctx, config AuditConfig) bool {
	// Skip configured paths
	path := c.Path()
	for _, skipPath := range config.SkipPaths {
		if path == skipPath || strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	
	// Skip configured methods
	method := c.Method()
	for _, skipMethod := range config.SkipMethods {
		if method == skipMethod {
			return true
		}
	}
	
	return false
}

// captureRequestInfo captures relevant request information for auditing
func captureRequestInfo(c *fiber.Ctx, config AuditConfig) *RequestInfo {
	info := &RequestInfo{
		Method:      c.Method(),
		URL:         c.OriginalURL(),
		Path:        c.Path(),
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		IPAddress:   c.IP(),
		UserAgent:   c.Get("User-Agent"),
	}
	
	// Capture relevant headers
	relevantHeaders := []string{
		"Authorization", "X-User-ID", "X-Session-ID", "X-Correlation-ID", 
		"X-Trace-ID", "Content-Type", "Accept", "X-Forwarded-For",
	}
	
	for _, header := range relevantHeaders {
		if value := c.Get(header); value != "" {
			info.Headers[header] = value
		}
	}
	
	// Capture query parameters
	c.Request().URI().QueryArgs().VisitAll(func(key, value []byte) {
		info.QueryParams[string(key)] = string(value)
	})
	
	// Capture request body if enabled
	if config.LogRequestBody && c.Method() != "GET" && c.Method() != "HEAD" {
		if bodyBytes := c.Body(); len(bodyBytes) > 0 && int64(len(bodyBytes)) <= config.MaxBodySize {
			info.Body = string(bodyBytes)
			info.BodySize = int64(len(bodyBytes))
		} else {
			info.BodySize = int64(len(bodyBytes))
		}
	}
	
	return info
}

// captureResponseInfo captures relevant response information for auditing
func captureResponseInfo(c *fiber.Ctx, config AuditConfig) *ResponseInfo {
	info := &ResponseInfo{
		StatusCode: c.Response().StatusCode(),
		Headers:    make(map[string]string),
	}
	
	// Capture response headers
	c.Response().Header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		if keyStr == "Content-Type" || keyStr == "Content-Length" || strings.HasPrefix(keyStr, "X-") {
			info.Headers[keyStr] = string(value)
		}
	})
	
	// Capture response body if enabled
	if config.LogResponseBody {
		if bodyBytes := c.Response().Body(); len(bodyBytes) > 0 && int64(len(bodyBytes)) <= config.MaxBodySize {
			info.Body = string(bodyBytes)
			info.BodySize = int64(len(bodyBytes))
		} else {
			info.BodySize = int64(len(bodyBytes))
		}
	}
	
	return info
}

// createAuditEvent creates an audit event from the request/response information
func createAuditEvent(c *fiber.Ctx, config AuditConfig, reqInfo *RequestInfo, respInfo *ResponseInfo, startTime time.Time, duration time.Duration, err error) *models.AuditEvent {
	// Extract user context
	_, sessionCtx, userErr := config.UserContextExtractor(c)
	if userErr != nil {
		log.Printf("Warning: Failed to extract user context for audit: %v", userErr)
		// Create a minimal user context for anonymous/system requests
		sessionCtx = &models.SessionAuthContext{
			UserID:    "system",
			SessionID: "anonymous",
			IPAddress: reqInfo.IPAddress,
			UserAgent: reqInfo.UserAgent,
		}
	}
	
	// Determine event type based on request
	eventType := determineEventType(reqInfo.Method, reqInfo.Path, respInfo.StatusCode)
	
	// Determine severity based on response status
	severity := determineSeverity(respInfo.StatusCode, err)
	
	// Create audit event
	builder := models.NewAuditEventBuilder()
	auditEvent, buildErr := builder.
		WithEventType(eventType).
		WithSeverity(severity).
		WithMessage(createAuditMessage(reqInfo, respInfo, err)).
		WithUserContext(sessionCtx).
		WithCorrelationID(config.CorrelationIDExtractor(c)).
		WithTraceID(config.TraceIDExtractor(c)).
		WithService(config.ServiceName, config.ServiceVersion).
		WithMetadata("request", reqInfo).
		WithMetadata("response", respInfo).
		WithMetadata("duration_ms", duration.Milliseconds()).
		WithMetadata("error", getErrorString(err)).
		Build()
	
	if buildErr != nil {
		log.Printf("Error creating audit event: %v", buildErr)
		return nil
	}
	
	return auditEvent
}

// determineEventType determines the audit event type based on request characteristics
func determineEventType(method, path string, statusCode int) models.AuditEventType {
	// Authentication endpoints
	if strings.Contains(path, "/auth/") || strings.Contains(path, "/login") {
		if statusCode >= 200 && statusCode < 300 {
			return models.AuditEventTypeLogin
		}
		return models.AuditEventTypeAuthentication
	}
	
	if strings.Contains(path, "/logout") {
		return models.AuditEventTypeLogout
	}
	
	// NLP endpoints  
	if strings.Contains(path, "/nlp/") || strings.Contains(path, "/translate") {
		return models.AuditEventTypeNLPInput
	}
	
	// Command execution endpoints
	if strings.Contains(path, "/execute") || strings.Contains(path, "/command") {
		return models.AuditEventTypeCommandExecute
	}
	
	// RBAC endpoints
	if strings.Contains(path, "/rbac/") || strings.Contains(path, "/permissions") {
		if statusCode == 403 {
			return models.AuditEventTypeRBACDenied
		}
		return models.AuditEventTypeRBACCheck
	}
	
	// Default to command for API calls
	return models.AuditEventTypeCommand
}

// determineSeverity determines audit event severity based on response status
func determineSeverity(statusCode int, err error) models.AuditSeverity {
	if err != nil {
		return models.AuditSeverityError
	}
	
	switch {
	case statusCode >= 500:
		return models.AuditSeverityError
	case statusCode >= 400:
		if statusCode == 403 || statusCode == 401 {
			return models.AuditSeverityCritical // Security-related errors
		}
		return models.AuditSeverityWarning
	case statusCode >= 300:
		return models.AuditSeverityInfo
	default:
		return models.AuditSeverityInfo
	}
}

// createAuditMessage creates a human-readable audit message
func createAuditMessage(reqInfo *RequestInfo, respInfo *ResponseInfo, err error) string {
	if err != nil {
		return fmt.Sprintf("%s %s failed with error: %v", reqInfo.Method, reqInfo.Path, err)
	}
	
	return fmt.Sprintf("%s %s completed with status %d", reqInfo.Method, reqInfo.Path, respInfo.StatusCode)
}

// sendAuditEvent sends the audit event to the collector
func sendAuditEvent(collector EventCollectorInterface, event *models.AuditEvent) {
	if collector == nil {
		return
	}
	
	// Try to send with a short timeout
	if err := collector.CollectEventWithTimeout(event, time.Millisecond*500); err != nil {
		log.Printf("Warning: Failed to collect audit event %s: %v", event.ID, err)
	}
}

// getErrorString safely extracts error string
func getErrorString(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// Default extractor functions

func defaultUserContextExtractor(c *fiber.Ctx) (*models.User, *models.SessionAuthContext, error) {
	// Extract user information from headers/context
	userID := c.Get("X-User-ID")
	sessionID := c.Get("X-Session-ID")
	
	if userID == "" {
		return nil, nil, fmt.Errorf("no user context found")
	}
	
	sessionCtx := &models.SessionAuthContext{
		UserID:    userID,
		SessionID: sessionID,
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
	}
	
	// Create a minimal user object
	user := &models.User{
		ID:    userID,
		Email: c.Get("X-User-Email"),
		Name:  c.Get("X-User-Name"),
	}
	
	return user, sessionCtx, nil
}

func defaultCorrelationIDExtractor(c *fiber.Ctx) string {
	// Check multiple possible header names
	correlationID := c.Get("X-Correlation-ID")
	if correlationID == "" {
		correlationID = c.Get("X-Request-ID")
	}
	if correlationID == "" {
		correlationID = c.Get("Request-ID")
	}
	return correlationID
}

func defaultTraceIDExtractor(c *fiber.Ctx) string {
	// Check multiple possible header names
	traceID := c.Get("X-Trace-ID")
	if traceID == "" {
		traceID = c.Get("X-B3-TraceId")
	}
	if traceID == "" {
		traceID = c.Get("Trace-ID")
	}
	return traceID
}

// SessionLifecycleAuditMiddleware provides middleware for session lifecycle events
func SessionLifecycleAuditMiddleware(collector EventCollectorInterface, serviceName, serviceVersion string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Check for session events in the request context
		if sessionEvent := c.Locals("session_event"); sessionEvent != nil {
			sendSessionAuditEvent(collector, c, sessionEvent.(string), serviceName, serviceVersion)
		}
		
		return c.Next()
	}
}

// sendSessionAuditEvent sends session lifecycle audit events
func sendSessionAuditEvent(collector EventCollectorInterface, c *fiber.Ctx, eventType, serviceName, serviceVersion string) {
	if collector == nil {
		return
	}
	
	var auditEventType models.AuditEventType
	var message string
	
	switch eventType {
	case "session_created":
		auditEventType = models.AuditEventTypeLogin
		message = "User session created"
	case "session_expired":
		auditEventType = models.AuditEventTypeSessionExpiry
		message = "User session expired"
	case "session_terminated":
		auditEventType = models.AuditEventTypeLogout
		message = "User session terminated"
	default:
		return
	}
	
	// Extract user context
	userID := c.Get("X-User-ID")
	sessionID := c.Get("X-Session-ID")
	
	if userID == "" {
		return
	}
	
	sessionCtx := &models.SessionAuthContext{
		UserID:    userID,
		SessionID: sessionID,
		IPAddress: c.IP(),
		UserAgent: c.Get("User-Agent"),
	}
	
	// Create audit event
	builder := models.NewAuditEventBuilder()
	auditEvent, err := builder.
		WithEventType(auditEventType).
		WithSeverity(models.AuditSeverityInfo).
		WithMessage(message).
		WithUserContext(sessionCtx).
		WithService(serviceName, serviceVersion).
		WithMetadata("session_event", eventType).
		Build()
	
	if err != nil {
		log.Printf("Error creating session audit event: %v", err)
		return
	}
	
	sendAuditEvent(collector, auditEvent)
}