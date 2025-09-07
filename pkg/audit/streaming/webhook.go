package streaming

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/audit/formats"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// WebhookStreamingService handles real-time webhook delivery of audit events
type WebhookStreamingService struct {
	endpoints   map[string]*WebhookEndpoint
	client      *http.Client
	formatters  map[string]formats.SIEMFormatExporter
	buffer      *LocalBuffer
	metrics     *WebhookMetrics
	mu          sync.RWMutex
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// WebhookEndpoint represents a configured SIEM webhook endpoint
type WebhookEndpoint struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	URL         string                 `json:"url"`
	Method      string                 `json:"method"`
	Format      string                 `json:"format"`      // JSON, CEF, LEEF
	Platform    string                 `json:"platform"`    // splunk, qradar, sentinel, etc.
	Headers     map[string]string      `json:"headers"`
	Secret      string                 `json:"secret,omitempty"` // For HMAC signature
	Timeout     time.Duration          `json:"timeout"`
	RetryConfig WebhookRetryConfig     `json:"retry_config"`
	FilterConfig WebhookFilterConfig   `json:"filter_config"`
	Active      bool                   `json:"active"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// WebhookRetryConfig configures retry behavior for failed webhook deliveries
type WebhookRetryConfig struct {
	MaxAttempts       int           `json:"max_attempts"`
	InitialDelay      time.Duration `json:"initial_delay"`
	MaxDelay          time.Duration `json:"max_delay"`
	ExponentialBase   float64       `json:"exponential_base"`
	RetryableStatuses []int         `json:"retryable_statuses"`
}

// WebhookFilterConfig configures event filtering for webhooks
type WebhookFilterConfig struct {
	EventTypes     []models.AuditEventType `json:"event_types,omitempty"`
	Severities     []models.AuditSeverity  `json:"severities,omitempty"`
	UserIDs        []string                `json:"user_ids,omitempty"`
	ClusterNames   []string                `json:"cluster_names,omitempty"`
	Namespaces     []string                `json:"namespaces,omitempty"`
	RiskLevels     []string                `json:"risk_levels,omitempty"`
	SampleRate     float64                 `json:"sample_rate"` // 0.0-1.0 for event sampling
}

// WebhookMetrics tracks webhook delivery statistics
type WebhookMetrics struct {
	TotalDeliveries    int64                    `json:"total_deliveries"`
	SuccessfulDeliveries int64                  `json:"successful_deliveries"`
	FailedDeliveries   int64                    `json:"failed_deliveries"`
	RetryAttempts      int64                    `json:"retry_attempts"`
	AverageLatency     time.Duration            `json:"average_latency"`
	EndpointMetrics    map[string]*EndpointMetrics `json:"endpoint_metrics"`
	LastUpdated        time.Time                `json:"last_updated"`
	mu                 sync.RWMutex
}

// EndpointMetrics tracks metrics for individual endpoints
type EndpointMetrics struct {
	EndpointID         string        `json:"endpoint_id"`
	DeliveryCount      int64         `json:"delivery_count"`
	SuccessCount       int64         `json:"success_count"`
	FailureCount       int64         `json:"failure_count"`
	AverageLatency     time.Duration `json:"average_latency"`
	LastDeliveryAt     time.Time     `json:"last_delivery_at,omitempty"`
	LastSuccessAt      time.Time     `json:"last_success_at,omitempty"`
	LastFailureAt      time.Time     `json:"last_failure_at,omitempty"`
	ConsecutiveFailures int          `json:"consecutive_failures"`
}

// WebhookDeliveryResult represents the result of a webhook delivery attempt
type WebhookDeliveryResult struct {
	EndpointID     string        `json:"endpoint_id"`
	EventID        string        `json:"event_id"`
	Success        bool          `json:"success"`
	StatusCode     int           `json:"status_code,omitempty"`
	ResponseBody   string        `json:"response_body,omitempty"`
	Error          string        `json:"error,omitempty"`
	Latency        time.Duration `json:"latency"`
	AttemptNumber  int           `json:"attempt_number"`
	DeliveredAt    time.Time     `json:"delivered_at"`
}

// DefaultWebhookRetryConfig returns sensible default retry configuration
func DefaultWebhookRetryConfig() WebhookRetryConfig {
	return WebhookRetryConfig{
		MaxAttempts:       3,
		InitialDelay:      time.Second * 2,
		MaxDelay:          time.Second * 30,
		ExponentialBase:   2.0,
		RetryableStatuses: []int{500, 502, 503, 504, 408, 429},
	}
}

// NewWebhookStreamingService creates a new webhook streaming service
func NewWebhookStreamingService(bufferConfig LocalBufferConfig) *WebhookStreamingService {
	ctx, cancel := context.WithCancel(context.Background())
	
	service := &WebhookStreamingService{
		endpoints: make(map[string]*WebhookEndpoint),
		client: &http.Client{
			Timeout: time.Second * 30,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     time.Second * 90,
			},
		},
		formatters: map[string]formats.SIEMFormatExporter{
			"JSON": formats.NewJSONExporter(formats.JSONExporterConfig{IncludeIntegrityFields: true}),
			"CEF":  formats.NewCEFExporter(formats.DefaultCEFConfig()),
			"LEEF": formats.NewLEEFExporter(formats.DefaultLEEFConfig()),
		},
		buffer: NewLocalBuffer(bufferConfig),
		metrics: &WebhookMetrics{
			EndpointMetrics: make(map[string]*EndpointMetrics),
		},
		ctx:        ctx,
		cancelFunc: cancel,
	}
	
	return service
}

// AddEndpoint adds a new webhook endpoint
func (ws *WebhookStreamingService) AddEndpoint(endpoint *WebhookEndpoint) error {
	if endpoint.ID == "" {
		endpoint.ID = fmt.Sprintf("webhook_%d", time.Now().Unix())
	}
	
	// Set defaults
	if endpoint.Method == "" {
		endpoint.Method = "POST"
	}
	if endpoint.Format == "" {
		endpoint.Format = "JSON"
	}
	if endpoint.Timeout == 0 {
		endpoint.Timeout = time.Second * 30
	}
	if endpoint.RetryConfig.MaxAttempts == 0 {
		endpoint.RetryConfig = DefaultWebhookRetryConfig()
	}
	
	// Validate endpoint
	if err := ws.validateEndpoint(endpoint); err != nil {
		return fmt.Errorf("invalid webhook endpoint: %w", err)
	}
	
	now := time.Now().UTC()
	endpoint.CreatedAt = now
	endpoint.UpdatedAt = now
	
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	ws.endpoints[endpoint.ID] = endpoint
	
	// Initialize metrics for this endpoint
	ws.metrics.mu.Lock()
	ws.metrics.EndpointMetrics[endpoint.ID] = &EndpointMetrics{
		EndpointID: endpoint.ID,
	}
	ws.metrics.mu.Unlock()
	
	return nil
}

// RemoveEndpoint removes a webhook endpoint
func (ws *WebhookStreamingService) RemoveEndpoint(endpointID string) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	if _, exists := ws.endpoints[endpointID]; !exists {
		return fmt.Errorf("endpoint %s not found", endpointID)
	}
	
	delete(ws.endpoints, endpointID)
	
	ws.metrics.mu.Lock()
	delete(ws.metrics.EndpointMetrics, endpointID)
	ws.metrics.mu.Unlock()
	
	return nil
}

// UpdateEndpoint updates an existing webhook endpoint
func (ws *WebhookStreamingService) UpdateEndpoint(endpoint *WebhookEndpoint) error {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	
	if _, exists := ws.endpoints[endpoint.ID]; !exists {
		return fmt.Errorf("endpoint %s not found", endpoint.ID)
	}
	
	if err := ws.validateEndpoint(endpoint); err != nil {
		return fmt.Errorf("invalid webhook endpoint update: %w", err)
	}
	
	endpoint.UpdatedAt = time.Now().UTC()
	ws.endpoints[endpoint.ID] = endpoint
	
	return nil
}

// StreamEvent streams an audit event to all configured webhooks
func (ws *WebhookStreamingService) StreamEvent(event *models.AuditEvent) error {
	ws.mu.RLock()
	activeEndpoints := make([]*WebhookEndpoint, 0, len(ws.endpoints))
	for _, endpoint := range ws.endpoints {
		if endpoint.Active && ws.shouldForwardEvent(event, endpoint.FilterConfig) {
			activeEndpoints = append(activeEndpoints, endpoint)
		}
	}
	ws.mu.RUnlock()
	
	if len(activeEndpoints) == 0 {
		return nil // No active endpoints or event filtered out
	}
	
	// Stream to all matching endpoints concurrently
	var wg sync.WaitGroup
	resultsChan := make(chan *WebhookDeliveryResult, len(activeEndpoints))
	
	for _, endpoint := range activeEndpoints {
		wg.Add(1)
		go func(ep *WebhookEndpoint) {
			defer wg.Done()
			result := ws.deliverToEndpoint(event, ep)
			resultsChan <- result
		}(endpoint)
	}
	
	// Wait for all deliveries to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()
	
	// Collect results and update metrics
	var deliveryErrors []string
	for result := range resultsChan {
		ws.updateMetrics(result)
		
		if !result.Success {
			deliveryErrors = append(deliveryErrors, fmt.Sprintf("endpoint %s: %s", result.EndpointID, result.Error))
			
			// Buffer failed events for retry
			ws.buffer.BufferEvent(event, result.EndpointID)
		}
	}
	
	// Return error if any deliveries failed
	if len(deliveryErrors) > 0 {
		return fmt.Errorf("webhook delivery failures: %v", deliveryErrors)
	}
	
	return nil
}

// deliverToEndpoint delivers an event to a specific endpoint with retry logic
func (ws *WebhookStreamingService) deliverToEndpoint(event *models.AuditEvent, endpoint *WebhookEndpoint) *WebhookDeliveryResult {
	startTime := time.Now()
	
	// Format the event for the endpoint
	formatter, exists := ws.formatters[endpoint.Format]
	if !exists {
		return &WebhookDeliveryResult{
			EndpointID:    endpoint.ID,
			EventID:       event.ID,
			Success:       false,
			Error:         fmt.Sprintf("unsupported format: %s", endpoint.Format),
			Latency:       time.Since(startTime),
			AttemptNumber: 1,
			DeliveredAt:   time.Now().UTC(),
		}
	}
	
	exportedData, err := formatter.Export(event)
	if err != nil {
		return &WebhookDeliveryResult{
			EndpointID:    endpoint.ID,
			EventID:       event.ID,
			Success:       false,
			Error:         fmt.Sprintf("export failed: %v", err),
			Latency:       time.Since(startTime),
			AttemptNumber: 1,
			DeliveredAt:   time.Now().UTC(),
		}
	}
	
	// Attempt delivery with retry logic
	for attempt := 1; attempt <= endpoint.RetryConfig.MaxAttempts; attempt++ {
		result := ws.attemptDelivery(event.ID, endpoint, exportedData, attempt, startTime)
		
		// Return success immediately
		if result.Success {
			return result
		}
		
		// Check if this error is retryable
		if !ws.isRetryableError(result.StatusCode, endpoint.RetryConfig) {
			result.AttemptNumber = attempt
			return result
		}
		
		// If this is not the last attempt, wait before retrying
		if attempt < endpoint.RetryConfig.MaxAttempts {
			delay := ws.calculateRetryDelay(attempt, endpoint.RetryConfig)
			select {
			case <-time.After(delay):
				// Continue to next attempt
			case <-ws.ctx.Done():
				result.Error = "streaming service stopped during retry"
				result.AttemptNumber = attempt
				return result
			}
		} else {
			// Last attempt failed
			result.AttemptNumber = attempt
			return result
		}
	}
	
	// This should never be reached, but included for completeness
	return &WebhookDeliveryResult{
		EndpointID:    endpoint.ID,
		EventID:       event.ID,
		Success:       false,
		Error:         "maximum retry attempts exceeded",
		Latency:       time.Since(startTime),
		AttemptNumber: endpoint.RetryConfig.MaxAttempts,
		DeliveredAt:   time.Now().UTC(),
	}
}

// attemptDelivery makes a single delivery attempt to an endpoint
func (ws *WebhookStreamingService) attemptDelivery(eventID string, endpoint *WebhookEndpoint, data []byte, attempt int, startTime time.Time) *WebhookDeliveryResult {
	// Create HTTP request
	req, err := http.NewRequestWithContext(ws.ctx, endpoint.Method, endpoint.URL, bytes.NewBuffer(data))
	if err != nil {
		return &WebhookDeliveryResult{
			EndpointID:    endpoint.ID,
			EventID:       eventID,
			Success:       false,
			Error:         fmt.Sprintf("request creation failed: %v", err),
			Latency:       time.Since(startTime),
			AttemptNumber: attempt,
			DeliveredAt:   time.Now().UTC(),
		}
	}
	
	// Set headers
	for key, value := range endpoint.Headers {
		req.Header.Set(key, value)
	}
	
	// Set content type based on format
	formatter := ws.formatters[endpoint.Format]
	req.Header.Set("Content-Type", formatter.GetContentType())
	
	// Add HMAC signature if secret is configured
	if endpoint.Secret != "" {
		signature := ws.generateHMACSignature(data, endpoint.Secret)
		req.Header.Set("X-Webhook-Signature", "sha256="+signature)
	}
	
	// Add custom headers for audit context
	req.Header.Set("X-Audit-Event-ID", eventID)
	req.Header.Set("X-Audit-Format", endpoint.Format)
	req.Header.Set("X-Audit-Platform", endpoint.Platform)
	req.Header.Set("X-Delivery-Attempt", fmt.Sprintf("%d", attempt))
	
	// Make the request
	client := &http.Client{Timeout: endpoint.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return &WebhookDeliveryResult{
			EndpointID:    endpoint.ID,
			EventID:       eventID,
			Success:       false,
			Error:         fmt.Sprintf("HTTP request failed: %v", err),
			Latency:       time.Since(startTime),
			AttemptNumber: attempt,
			DeliveredAt:   time.Now().UTC(),
		}
	}
	defer resp.Body.Close()
	
	// Read response body
	responseBody, _ := io.ReadAll(resp.Body)
	
	// Determine success based on status code
	success := resp.StatusCode >= 200 && resp.StatusCode < 300
	
	result := &WebhookDeliveryResult{
		EndpointID:    endpoint.ID,
		EventID:       eventID,
		Success:       success,
		StatusCode:    resp.StatusCode,
		ResponseBody:  string(responseBody),
		Latency:       time.Since(startTime),
		AttemptNumber: attempt,
		DeliveredAt:   time.Now().UTC(),
	}
	
	if !success {
		result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(responseBody))
	}
	
	return result
}

// Helper methods
func (ws *WebhookStreamingService) validateEndpoint(endpoint *WebhookEndpoint) error {
	if endpoint.URL == "" {
		return fmt.Errorf("URL is required")
	}
	if endpoint.Format != "" {
		if _, exists := ws.formatters[endpoint.Format]; !exists {
			return fmt.Errorf("unsupported format: %s", endpoint.Format)
		}
	}
	return nil
}

func (ws *WebhookStreamingService) shouldForwardEvent(event *models.AuditEvent, filter WebhookFilterConfig) bool {
	// Apply sampling if configured
	if filter.SampleRate > 0 && filter.SampleRate < 1.0 {
		// Simple hash-based sampling for consistency
		hash := sha256.Sum256([]byte(event.ID))
		hashValue := float64(hash[0]) / 255.0
		if hashValue > filter.SampleRate {
			return false
		}
	}
	
	// Filter by event types
	if len(filter.EventTypes) > 0 {
		found := false
		for _, eventType := range filter.EventTypes {
			if event.EventType == eventType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Filter by severities
	if len(filter.Severities) > 0 {
		found := false
		for _, severity := range filter.Severities {
			if event.Severity == severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Filter by user IDs
	if len(filter.UserIDs) > 0 {
		found := false
		for _, userID := range filter.UserIDs {
			if event.UserContext.UserID == userID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Filter by cluster names
	if len(filter.ClusterNames) > 0 {
		found := false
		for _, clusterName := range filter.ClusterNames {
			if event.ClusterContext.ClusterName == clusterName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Filter by namespaces
	if len(filter.Namespaces) > 0 {
		found := false
		for _, namespace := range filter.Namespaces {
			if event.ClusterContext.Namespace == namespace {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	// Filter by risk levels
	if len(filter.RiskLevels) > 0 {
		found := false
		for _, riskLevel := range filter.RiskLevels {
			if event.CommandContext.RiskLevel == riskLevel {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	
	return true
}

func (ws *WebhookStreamingService) generateHMACSignature(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (ws *WebhookStreamingService) isRetryableError(statusCode int, config WebhookRetryConfig) bool {
	for _, retryableStatus := range config.RetryableStatuses {
		if statusCode == retryableStatus {
			return true
		}
	}
	return false
}

func (ws *WebhookStreamingService) calculateRetryDelay(attempt int, config WebhookRetryConfig) time.Duration {
	delay := time.Duration(float64(config.InitialDelay) * 
		(config.ExponentialBase * float64(attempt-1)))
	
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}
	
	return delay
}

// GetServiceStatus returns the current status of the streaming service
func (ws *WebhookStreamingService) GetServiceStatus() map[string]interface{} {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	
	activeEndpoints := 0
	for _, endpoint := range ws.endpoints {
		if endpoint.Active {
			activeEndpoints++
		}
	}
	
	return map[string]interface{}{
		"status":             "running",
		"total_endpoints":    len(ws.endpoints),
		"active_endpoints":   activeEndpoints,
		"buffer_size":        ws.buffer.GetCurrentSize(),
		"service_start_time": time.Now().Format(time.RFC3339), // Placeholder
	}
}

// ListEndpoints returns all configured webhook endpoints
func (ws *WebhookStreamingService) ListEndpoints() []*WebhookEndpoint {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	
	endpoints := make([]*WebhookEndpoint, 0, len(ws.endpoints))
	for _, endpoint := range ws.endpoints {
		endpoints = append(endpoints, endpoint)
	}
	
	return endpoints
}

// TestEndpoint tests a webhook endpoint with a sample event
func (ws *WebhookStreamingService) TestEndpoint(endpointID string) error {
	ws.mu.RLock()
	endpoint, exists := ws.endpoints[endpointID]
	ws.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("webhook endpoint %s not found", endpointID)
	}
	
	// Create a test event
	testEvent := &models.AuditEvent{
		ID:        fmt.Sprintf("test-%d", time.Now().Unix()),
		EventType: models.AuditEventTypeHealthCheck,
		Timestamp: time.Now(),
		Severity:  models.AuditSeverityInfo,
		Message:   "Webhook endpoint test event",
		UserContext: models.UserContext{
			UserID:    "test-user",
			SessionID: "test-session",
		},
		ClusterContext: models.ClusterContext{
			ClusterName: "test-cluster",
		},
		ServiceName:   "audit-service",
		CorrelationID: fmt.Sprintf("test-corr-%d", time.Now().Unix()),
		Checksum:      "test-checksum",
	}
	
	// Try to deliver the test event
	result := ws.deliverToEndpoint(testEvent, endpoint)
	if result.Success {
		return nil
	}
	
	return fmt.Errorf("webhook test failed: %s", result.Error)
}

func (ws *WebhookStreamingService) updateMetrics(result *WebhookDeliveryResult) {
	ws.metrics.mu.Lock()
	defer ws.metrics.mu.Unlock()
	
	ws.metrics.TotalDeliveries++
	if result.Success {
		ws.metrics.SuccessfulDeliveries++
	} else {
		ws.metrics.FailedDeliveries++
	}
	
	if result.AttemptNumber > 1 {
		ws.metrics.RetryAttempts += int64(result.AttemptNumber - 1)
	}
	
	// Update endpoint-specific metrics
	endpointMetrics := ws.metrics.EndpointMetrics[result.EndpointID]
	if endpointMetrics == nil {
		endpointMetrics = &EndpointMetrics{EndpointID: result.EndpointID}
		ws.metrics.EndpointMetrics[result.EndpointID] = endpointMetrics
	}
	
	endpointMetrics.DeliveryCount++
	endpointMetrics.LastDeliveryAt = result.DeliveredAt
	
	if result.Success {
		endpointMetrics.SuccessCount++
		endpointMetrics.LastSuccessAt = result.DeliveredAt
		endpointMetrics.ConsecutiveFailures = 0
	} else {
		endpointMetrics.FailureCount++
		endpointMetrics.LastFailureAt = result.DeliveredAt
		endpointMetrics.ConsecutiveFailures++
	}
	
	// Update average latency (simple moving average)
	if endpointMetrics.DeliveryCount == 1 {
		endpointMetrics.AverageLatency = result.Latency
	} else {
		endpointMetrics.AverageLatency = time.Duration(
			(int64(endpointMetrics.AverageLatency) + int64(result.Latency)) / 2)
	}
	
	ws.metrics.LastUpdated = time.Now().UTC()
}

// GetMetrics returns current webhook streaming metrics
func (ws *WebhookStreamingService) GetMetrics() *WebhookMetrics {
	ws.metrics.mu.RLock()
	defer ws.metrics.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := &WebhookMetrics{
		TotalDeliveries:      ws.metrics.TotalDeliveries,
		SuccessfulDeliveries: ws.metrics.SuccessfulDeliveries,
		FailedDeliveries:     ws.metrics.FailedDeliveries,
		RetryAttempts:        ws.metrics.RetryAttempts,
		AverageLatency:       ws.metrics.AverageLatency,
		EndpointMetrics:      make(map[string]*EndpointMetrics),
		LastUpdated:          ws.metrics.LastUpdated,
	}
	
	// Copy endpoint metrics
	for id, em := range ws.metrics.EndpointMetrics {
		metrics.EndpointMetrics[id] = &EndpointMetrics{
			EndpointID:          em.EndpointID,
			DeliveryCount:       em.DeliveryCount,
			SuccessCount:        em.SuccessCount,
			FailureCount:        em.FailureCount,
			AverageLatency:      em.AverageLatency,
			LastDeliveryAt:      em.LastDeliveryAt,
			LastSuccessAt:       em.LastSuccessAt,
			LastFailureAt:       em.LastFailureAt,
			ConsecutiveFailures: em.ConsecutiveFailures,
		}
	}
	
	return metrics
}

// GetEndpoints returns all configured webhook endpoints
func (ws *WebhookStreamingService) GetEndpoints() map[string]*WebhookEndpoint {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	
	endpoints := make(map[string]*WebhookEndpoint)
	for id, endpoint := range ws.endpoints {
		// Create a copy to avoid mutation
		endpointCopy := *endpoint
		endpoints[id] = &endpointCopy
	}
	
	return endpoints
}

// Stop gracefully stops the webhook streaming service
func (ws *WebhookStreamingService) Stop() error {
	ws.cancelFunc()
	return nil
}