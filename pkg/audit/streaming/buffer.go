package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// LocalBuffer provides local buffering for failed SIEM deliveries
type LocalBuffer struct {
	config        LocalBufferConfig
	bufferedEvents map[string][]*BufferedEvent
	metrics       *BufferMetrics
	mu            sync.RWMutex
	ctx           context.Context
	cancelFunc    context.CancelFunc
	retryWorker   *RetryWorker
}

// LocalBufferConfig configures the local buffering behavior
type LocalBufferConfig struct {
	MaxBufferSize       int           `json:"max_buffer_size"`        // Maximum events to buffer
	MaxBufferAge        time.Duration `json:"max_buffer_age"`         // Maximum age before discarding
	BufferDirectory     string        `json:"buffer_directory"`       // Directory for persistent storage
	FlushInterval       time.Duration `json:"flush_interval"`         // How often to attempt retry
	PersistToDisk       bool          `json:"persist_to_disk"`        // Whether to persist buffer to disk
	MaxDiskUsage        int64         `json:"max_disk_usage"`         // Maximum disk usage in bytes
	CompressionEnabled  bool          `json:"compression_enabled"`    // Enable compression for disk storage
	RetryPolicy         RetryPolicy   `json:"retry_policy"`           // Retry policy configuration
}

// BufferedEvent represents an event stored in the local buffer
type BufferedEvent struct {
	Event        *models.AuditEvent `json:"event"`
	EndpointID   string             `json:"endpoint_id,omitempty"`
	StreamName   string             `json:"stream_name,omitempty"`
	Format       string             `json:"format"`
	FirstFailed  time.Time          `json:"first_failed"`
	LastAttempt  time.Time          `json:"last_attempt"`
	AttemptCount int                `json:"attempt_count"`
	Reason       string             `json:"reason"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// BufferMetrics tracks buffer statistics
type BufferMetrics struct {
	TotalBuffered       int64     `json:"total_buffered"`
	CurrentlyBuffered   int64     `json:"currently_buffered"`
	TotalRetried        int64     `json:"total_retried"`
	SuccessfulRetries   int64     `json:"successful_retries"`
	FailedRetries       int64     `json:"failed_retries"`
	ExpiredEvents       int64     `json:"expired_events"`
	DiskUsage           int64     `json:"disk_usage"`
	LastFlushAt         time.Time `json:"last_flush_at"`
	LastCleanupAt       time.Time `json:"last_cleanup_at"`
	BuffersByEndpoint   map[string]int64 `json:"buffers_by_endpoint"`
	mu                  sync.RWMutex
}

// RetryPolicy defines the retry behavior for buffered events
type RetryPolicy struct {
	MaxRetries          int           `json:"max_retries"`
	InitialBackoff      time.Duration `json:"initial_backoff"`
	MaxBackoff          time.Duration `json:"max_backoff"`
	BackoffMultiplier   float64       `json:"backoff_multiplier"`
	RetryJitter         bool          `json:"retry_jitter"`
	ExponentialBackoff  bool          `json:"exponential_backoff"`
}

// RetryWorker handles periodic retry of buffered events
type RetryWorker struct {
	buffer          *LocalBuffer
	webhookService  *WebhookStreamingService
	natsService     *NATSStreamingService
	ticker          *time.Ticker
	isRunning       bool
	mu              sync.Mutex
}

// DefaultLocalBufferConfig returns sensible default buffer configuration
func DefaultLocalBufferConfig() LocalBufferConfig {
	return LocalBufferConfig{
		MaxBufferSize:      10000,
		MaxBufferAge:       time.Hour * 24, // 24 hours
		BufferDirectory:    "/tmp/kubechat-audit-buffer",
		FlushInterval:      time.Minute * 5,
		PersistToDisk:      true,
		MaxDiskUsage:       100 * 1024 * 1024, // 100MB
		CompressionEnabled: true,
		RetryPolicy: RetryPolicy{
			MaxRetries:         10,
			InitialBackoff:     time.Second * 30,
			MaxBackoff:         time.Hour,
			BackoffMultiplier:  2.0,
			RetryJitter:        true,
			ExponentialBackoff: true,
		},
	}
}

// NewLocalBuffer creates a new local buffer instance
func NewLocalBuffer(config LocalBufferConfig) *LocalBuffer {
	if config.MaxBufferSize == 0 {
		config = DefaultLocalBufferConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	buffer := &LocalBuffer{
		config:         config,
		bufferedEvents: make(map[string][]*BufferedEvent),
		metrics: &BufferMetrics{
			BuffersByEndpoint: make(map[string]int64),
		},
		ctx:        ctx,
		cancelFunc: cancel,
	}
	
	// Create buffer directory if it doesn't exist
	if config.PersistToDisk {
		if err := os.MkdirAll(config.BufferDirectory, 0755); err != nil {
			// Log error but continue without disk persistence
			config.PersistToDisk = false
		}
	}
	
	// Load persisted events if disk persistence is enabled
	if config.PersistToDisk {
		buffer.loadPersistedEvents()
	}
	
	// Start cleanup routine
	go buffer.cleanupRoutine()
	
	return buffer
}

// BufferEvent adds an event to the buffer for later retry
func (lb *LocalBuffer) BufferEvent(event *models.AuditEvent, targetID string) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	// Check buffer size limits
	currentSize := lb.getCurrentBufferSize()
	if currentSize >= lb.config.MaxBufferSize {
		// Remove oldest events to make room
		lb.evictOldestEvents(1)
	}
	
	bufferedEvent := &BufferedEvent{
		Event:        event,
		EndpointID:   targetID,
		Format:       "JSON", // Default format, can be configured
		FirstFailed:  time.Now().UTC(),
		LastAttempt:  time.Now().UTC(),
		AttemptCount: 1,
		Reason:       "Initial delivery failure",
		Metadata:     make(map[string]interface{}),
	}
	
	// Add to buffer
	if lb.bufferedEvents[targetID] == nil {
		lb.bufferedEvents[targetID] = make([]*BufferedEvent, 0)
	}
	lb.bufferedEvents[targetID] = append(lb.bufferedEvents[targetID], bufferedEvent)
	
	// Update metrics
	lb.updateMetrics(targetID, 1, "buffered")
	
	// Persist to disk if enabled
	if lb.config.PersistToDisk {
		go lb.persistEvent(bufferedEvent, targetID)
	}
	
	return nil
}

// RetryBufferedEvents attempts to retry all buffered events
func (lb *LocalBuffer) RetryBufferedEvents(webhookService *WebhookStreamingService, natsService *NATSStreamingService) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	var retryErrors []string
	totalRetried := 0
	successfulRetries := 0
	
	for targetID, events := range lb.bufferedEvents {
		remainingEvents := make([]*BufferedEvent, 0)
		
		for _, bufferedEvent := range events {
			// Check if event has expired
			if time.Since(bufferedEvent.FirstFailed) > lb.config.MaxBufferAge {
				lb.updateMetrics(targetID, -1, "expired")
				continue
			}
			
			// Check if we've exceeded max retries
			if bufferedEvent.AttemptCount > lb.config.RetryPolicy.MaxRetries {
				lb.updateMetrics(targetID, -1, "max_retries_exceeded")
				continue
			}
			
			// Calculate backoff delay
			if !lb.shouldRetryNow(bufferedEvent) {
				remainingEvents = append(remainingEvents, bufferedEvent)
				continue
			}
			
			totalRetried++
			
			// Attempt retry
			var success bool
			var err error
			
			if bufferedEvent.EndpointID != "" && webhookService != nil {
				// Retry webhook delivery
				success, err = lb.retryWebhookDelivery(bufferedEvent, webhookService)
			} else if bufferedEvent.StreamName != "" && natsService != nil {
				// Retry NATS streaming
				success, err = lb.retryNATSDelivery(bufferedEvent, natsService)
			}
			
			// Update attempt count and timestamp
			bufferedEvent.AttemptCount++
			bufferedEvent.LastAttempt = time.Now().UTC()
			
			if success {
				successfulRetries++
				lb.updateMetrics(targetID, -1, "retry_success")
				
				// Remove from persistent storage if enabled
				if lb.config.PersistToDisk {
					go lb.removePersistedEvent(bufferedEvent, targetID)
				}
			} else {
				if err != nil {
					bufferedEvent.Reason = err.Error()
					retryErrors = append(retryErrors, fmt.Sprintf("%s: %v", targetID, err))
				}
				remainingEvents = append(remainingEvents, bufferedEvent)
			}
		}
		
		// Update buffered events list
		if len(remainingEvents) > 0 {
			lb.bufferedEvents[targetID] = remainingEvents
		} else {
			delete(lb.bufferedEvents, targetID)
		}
	}
	
	// Update retry metrics
	lb.metrics.mu.Lock()
	lb.metrics.TotalRetried += int64(totalRetried)
	lb.metrics.SuccessfulRetries += int64(successfulRetries)
	lb.metrics.FailedRetries += int64(totalRetried - successfulRetries)
	lb.metrics.LastFlushAt = time.Now().UTC()
	lb.metrics.mu.Unlock()
	
	if len(retryErrors) > 0 {
		return fmt.Errorf("retry failures: %v", retryErrors)
	}
	
	return nil
}

// retryWebhookDelivery retries delivery to a webhook endpoint
func (lb *LocalBuffer) retryWebhookDelivery(bufferedEvent *BufferedEvent, webhookService *WebhookStreamingService) (bool, error) {
	endpoints := webhookService.GetEndpoints()
	endpoint, exists := endpoints[bufferedEvent.EndpointID]
	if !exists {
		return false, fmt.Errorf("endpoint %s no longer exists", bufferedEvent.EndpointID)
	}
	
	// Attempt delivery
	result := webhookService.deliverToEndpoint(bufferedEvent.Event, endpoint)
	if result.Error != "" {
		return result.Success, fmt.Errorf("%s", result.Error)
	}
	return result.Success, nil
}

// retryNATSDelivery retries delivery to a NATS stream
func (lb *LocalBuffer) retryNATSDelivery(bufferedEvent *BufferedEvent, natsService *NATSStreamingService) (bool, error) {
	streams := natsService.GetStreams()
	stream, exists := streams[bufferedEvent.StreamName]
	if !exists {
		return false, fmt.Errorf("stream %s no longer exists", bufferedEvent.StreamName)
	}
	
	// Attempt delivery
	err := natsService.publishToStream(bufferedEvent.Event, stream)
	return err == nil, err
}

// shouldRetryNow determines if an event should be retried based on backoff policy
func (lb *LocalBuffer) shouldRetryNow(bufferedEvent *BufferedEvent) bool {
	if bufferedEvent.AttemptCount == 1 {
		return true // First retry
	}
	
	var backoffDelay time.Duration
	
	if lb.config.RetryPolicy.ExponentialBackoff {
		// Exponential backoff
		backoffDelay = time.Duration(float64(lb.config.RetryPolicy.InitialBackoff) * 
			(lb.config.RetryPolicy.BackoffMultiplier * float64(bufferedEvent.AttemptCount-1)))
	} else {
		// Linear backoff
		backoffDelay = lb.config.RetryPolicy.InitialBackoff * time.Duration(bufferedEvent.AttemptCount)
	}
	
	// Cap at max backoff
	if backoffDelay > lb.config.RetryPolicy.MaxBackoff {
		backoffDelay = lb.config.RetryPolicy.MaxBackoff
	}
	
	// Add jitter if enabled
	if lb.config.RetryPolicy.RetryJitter {
		jitter := time.Duration(float64(backoffDelay) * 0.1) // 10% jitter
		backoffDelay += time.Duration(float64(jitter) * (2.0*float64(time.Now().UnixNano()%1000)/1000.0 - 1.0))
	}
	
	return time.Since(bufferedEvent.LastAttempt) >= backoffDelay
}

// getCurrentBufferSize returns the current total number of buffered events
func (lb *LocalBuffer) getCurrentBufferSize() int {
	totalSize := 0
	for _, events := range lb.bufferedEvents {
		totalSize += len(events)
	}
	return totalSize
}

// evictOldestEvents removes the oldest events to make room for new ones
func (lb *LocalBuffer) evictOldestEvents(count int) {
	evicted := 0
	
	for targetID, events := range lb.bufferedEvents {
		if evicted >= count {
			break
		}
		
		if len(events) > 0 {
			// Remove the oldest event
			lb.bufferedEvents[targetID] = events[1:]
			evicted++
			lb.updateMetrics(targetID, -1, "evicted")
			
			// Clean up empty slices
			if len(lb.bufferedEvents[targetID]) == 0 {
				delete(lb.bufferedEvents, targetID)
			}
		}
	}
}

// cleanupRoutine periodically cleans up expired events
func (lb *LocalBuffer) cleanupRoutine() {
	ticker := time.NewTicker(lb.config.FlushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			lb.cleanupExpiredEvents()
		case <-lb.ctx.Done():
			return
		}
	}
}

// cleanupExpiredEvents removes events that have exceeded the maximum age
func (lb *LocalBuffer) cleanupExpiredEvents() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	now := time.Now().UTC()
	totalCleaned := 0
	
	for targetID, events := range lb.bufferedEvents {
		remainingEvents := make([]*BufferedEvent, 0)
		
		for _, event := range events {
			if now.Sub(event.FirstFailed) <= lb.config.MaxBufferAge {
				remainingEvents = append(remainingEvents, event)
			} else {
				totalCleaned++
				lb.updateMetrics(targetID, -1, "expired")
				
				// Remove from persistent storage
				if lb.config.PersistToDisk {
					go lb.removePersistedEvent(event, targetID)
				}
			}
		}
		
		if len(remainingEvents) > 0 {
			lb.bufferedEvents[targetID] = remainingEvents
		} else {
			delete(lb.bufferedEvents, targetID)
		}
	}
	
	lb.metrics.mu.Lock()
	lb.metrics.ExpiredEvents += int64(totalCleaned)
	lb.metrics.LastCleanupAt = now
	lb.metrics.mu.Unlock()
}

// persistEvent saves an event to disk for persistence across restarts
func (lb *LocalBuffer) persistEvent(event *BufferedEvent, targetID string) error {
	if !lb.config.PersistToDisk {
		return nil
	}
	
	filename := fmt.Sprintf("%s_%s_%d.json", event.Event.ID, targetID, event.FirstFailed.Unix())
	filepath := filepath.Join(lb.config.BufferDirectory, filename)
	
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal buffered event: %w", err)
	}
	
	// TODO: Add compression if enabled
	if lb.config.CompressionEnabled {
		// Implement compression here
	}
	
	err = os.WriteFile(filepath, data, 0644)
	if err != nil {
		return fmt.Errorf("failed to persist event to disk: %w", err)
	}
	
	// Update disk usage metrics
	lb.metrics.mu.Lock()
	lb.metrics.DiskUsage += int64(len(data))
	lb.metrics.mu.Unlock()
	
	return nil
}

// removePersistedEvent removes a persisted event from disk
func (lb *LocalBuffer) removePersistedEvent(event *BufferedEvent, targetID string) error {
	if !lb.config.PersistToDisk {
		return nil
	}
	
	filename := fmt.Sprintf("%s_%s_%d.json", event.Event.ID, targetID, event.FirstFailed.Unix())
	filepath := filepath.Join(lb.config.BufferDirectory, filename)
	
	// Get file size before deletion
	if info, err := os.Stat(filepath); err == nil {
		lb.metrics.mu.Lock()
		lb.metrics.DiskUsage -= info.Size()
		lb.metrics.mu.Unlock()
	}
	
	return os.Remove(filepath)
}

// loadPersistedEvents loads previously persisted events from disk
func (lb *LocalBuffer) loadPersistedEvents() error {
	if !lb.config.PersistToDisk {
		return nil
	}
	
	files, err := filepath.Glob(filepath.Join(lb.config.BufferDirectory, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob buffer files: %w", err)
	}
	
	loadedCount := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip corrupted files
		}
		
		var bufferedEvent BufferedEvent
		if err := json.Unmarshal(data, &bufferedEvent); err != nil {
			continue // Skip corrupted events
		}
		
		// Check if event is still within age limits
		if time.Since(bufferedEvent.FirstFailed) > lb.config.MaxBufferAge {
			os.Remove(file) // Clean up expired file
			continue
		}
		
		// Add to buffer
		targetID := bufferedEvent.EndpointID
		if targetID == "" {
			targetID = bufferedEvent.StreamName
		}
		
		if lb.bufferedEvents[targetID] == nil {
			lb.bufferedEvents[targetID] = make([]*BufferedEvent, 0)
		}
		lb.bufferedEvents[targetID] = append(lb.bufferedEvents[targetID], &bufferedEvent)
		loadedCount++
		
		// Update disk usage metrics
		lb.metrics.mu.Lock()
		lb.metrics.DiskUsage += int64(len(data))
		lb.metrics.mu.Unlock()
	}
	
	return nil
}

// updateMetrics updates buffer metrics
func (lb *LocalBuffer) updateMetrics(targetID string, delta int64, operation string) {
	lb.metrics.mu.Lock()
	defer lb.metrics.mu.Unlock()
	
	switch operation {
	case "buffered":
		lb.metrics.TotalBuffered += delta
		lb.metrics.CurrentlyBuffered += delta
	case "retry_success", "expired", "max_retries_exceeded", "evicted":
		lb.metrics.CurrentlyBuffered += delta // delta should be negative
	}
	
	// Update endpoint-specific metrics
	if lb.metrics.BuffersByEndpoint[targetID] == 0 && delta < 0 {
		// Avoid negative counts
		lb.metrics.BuffersByEndpoint[targetID] = 0
	} else {
		lb.metrics.BuffersByEndpoint[targetID] += delta
	}
	
	// Clean up zero counts
	if lb.metrics.BuffersByEndpoint[targetID] <= 0 {
		delete(lb.metrics.BuffersByEndpoint, targetID)
	}
}

// GetMetrics returns current buffer metrics
func (lb *LocalBuffer) GetMetrics() *BufferMetrics {
	lb.metrics.mu.RLock()
	defer lb.metrics.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := &BufferMetrics{
		TotalBuffered:     lb.metrics.TotalBuffered,
		CurrentlyBuffered: lb.metrics.CurrentlyBuffered,
		TotalRetried:      lb.metrics.TotalRetried,
		SuccessfulRetries: lb.metrics.SuccessfulRetries,
		FailedRetries:     lb.metrics.FailedRetries,
		ExpiredEvents:     lb.metrics.ExpiredEvents,
		DiskUsage:         lb.metrics.DiskUsage,
		LastFlushAt:       lb.metrics.LastFlushAt,
		LastCleanupAt:     lb.metrics.LastCleanupAt,
		BuffersByEndpoint: make(map[string]int64),
	}
	
	// Copy endpoint-specific metrics
	for endpoint, count := range lb.metrics.BuffersByEndpoint {
		metrics.BuffersByEndpoint[endpoint] = count
	}
	
	return metrics
}

// GetBufferedEvents returns the currently buffered events for a specific target
func (lb *LocalBuffer) GetBufferedEvents(targetID string) []*BufferedEvent {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	events, exists := lb.bufferedEvents[targetID]
	if !exists {
		return nil
	}
	
	// Return a copy to avoid mutations
	eventsCopy := make([]*BufferedEvent, len(events))
	copy(eventsCopy, events)
	return eventsCopy
}

// ClearBuffer clears all buffered events (useful for testing)
func (lb *LocalBuffer) ClearBuffer() {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	
	// Clear in-memory buffer
	lb.bufferedEvents = make(map[string][]*BufferedEvent)
	
	// Clear disk storage if enabled
	if lb.config.PersistToDisk {
		files, _ := filepath.Glob(filepath.Join(lb.config.BufferDirectory, "*.json"))
		for _, file := range files {
			os.Remove(file)
		}
	}
	
	// Reset metrics
	lb.metrics.mu.Lock()
	lb.metrics.CurrentlyBuffered = 0
	lb.metrics.DiskUsage = 0
	lb.metrics.BuffersByEndpoint = make(map[string]int64)
	lb.metrics.mu.Unlock()
}

// Stop gracefully stops the local buffer
func (lb *LocalBuffer) Stop() error {
	lb.cancelFunc()
	
	// Persist any remaining events if disk persistence is enabled
	if lb.config.PersistToDisk {
		lb.mu.RLock()
		for targetID, events := range lb.bufferedEvents {
			for _, event := range events {
				lb.persistEvent(event, targetID)
			}
		}
		lb.mu.RUnlock()
	}
	
	return nil
}

// StartRetryWorker starts the retry worker for automatic retry processing
func (lb *LocalBuffer) StartRetryWorker(webhookService *WebhookStreamingService, natsService *NATSStreamingService) *RetryWorker {
	worker := &RetryWorker{
		buffer:         lb,
		webhookService: webhookService,
		natsService:    natsService,
		ticker:         time.NewTicker(lb.config.FlushInterval),
	}
	
	go worker.run()
	
	worker.mu.Lock()
	worker.isRunning = true
	worker.mu.Unlock()
	
	return worker
}

// run executes the retry worker loop
func (rw *RetryWorker) run() {
	defer rw.ticker.Stop()
	
	for {
		select {
		case <-rw.ticker.C:
			rw.buffer.RetryBufferedEvents(rw.webhookService, rw.natsService)
		case <-rw.buffer.ctx.Done():
			return
		}
	}
}

// Stop stops the retry worker
func (rw *RetryWorker) Stop() {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	
	if rw.isRunning {
		rw.ticker.Stop()
		rw.isRunning = false
	}
}

// IsRunning returns whether the retry worker is currently running
func (rw *RetryWorker) IsRunning() bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.isRunning
}

// GetCurrentSize returns the current number of buffered events across all targets
func (lb *LocalBuffer) GetCurrentSize() int {
	lb.mu.RLock()
	defer lb.mu.RUnlock()
	
	total := 0
	for _, events := range lb.bufferedEvents {
		total += len(events)
	}
	
	return total
}