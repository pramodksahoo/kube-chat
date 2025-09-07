// Package audit provides event collection and processing capabilities
package audit

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// EventCollector handles asynchronous audit event collection and processing
type EventCollector struct {
	storage       AuditStorage
	eventQueue    chan *models.AuditEvent
	workers       int
	bufferSize    int
	retryAttempts int
	retryDelay    time.Duration
	
	// Processing statistics
	stats         *CollectorStats
	statsMutex    sync.RWMutex
	
	// Lifecycle management
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	started       bool
	startMutex    sync.Mutex
}

// CollectorConfig holds configuration for the event collector
type CollectorConfig struct {
	Workers       int           `json:"workers"`        // Number of worker goroutines
	BufferSize    int           `json:"buffer_size"`    // Event queue buffer size
	RetryAttempts int           `json:"retry_attempts"` // Number of retry attempts for failed events
	RetryDelay    time.Duration `json:"retry_delay"`    // Delay between retry attempts
}

// DefaultCollectorConfig returns the default collector configuration
func DefaultCollectorConfig() CollectorConfig {
	return CollectorConfig{
		Workers:       4,
		BufferSize:    10000,
		RetryAttempts: 3,
		RetryDelay:    time.Second * 2,
	}
}

// CollectorStats provides statistics about event collection performance
type CollectorStats struct {
	EventsReceived    int64     `json:"events_received"`
	EventsProcessed   int64     `json:"events_processed"`
	EventsFailed      int64     `json:"events_failed"`
	EventsDropped     int64     `json:"events_dropped"`
	ProcessingTime    int64     `json:"processing_time_ms"`
	QueueSize         int       `json:"queue_size"`
	LastProcessedAt   time.Time `json:"last_processed_at"`
	StartedAt         time.Time `json:"started_at"`
	IsRunning         bool      `json:"is_running"`
}

// NewEventCollector creates a new audit event collector
func NewEventCollector(storage AuditStorage, config CollectorConfig) *EventCollector {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &EventCollector{
		storage:       storage,
		eventQueue:    make(chan *models.AuditEvent, config.BufferSize),
		workers:       config.Workers,
		bufferSize:    config.BufferSize,
		retryAttempts: config.RetryAttempts,
		retryDelay:    config.RetryDelay,
		stats:         &CollectorStats{},
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start begins the event collection and processing
func (c *EventCollector) Start() error {
	c.startMutex.Lock()
	defer c.startMutex.Unlock()
	
	if c.started {
		return fmt.Errorf("collector is already started")
	}
	
	c.started = true
	c.updateStats(func(stats *CollectorStats) {
		stats.StartedAt = time.Now().UTC()
		stats.IsRunning = true
	})
	
	// Start worker goroutines
	for i := 0; i < c.workers; i++ {
		c.wg.Add(1)
		go c.worker(i)
	}
	
	log.Printf("Audit event collector started with %d workers and buffer size %d", c.workers, c.bufferSize)
	return nil
}

// Stop gracefully shuts down the event collector
func (c *EventCollector) Stop() error {
	c.startMutex.Lock()
	defer c.startMutex.Unlock()
	
	if !c.started {
		return fmt.Errorf("collector is not started")
	}
	
	log.Println("Stopping audit event collector...")
	
	// Close the event queue to stop accepting new events
	close(c.eventQueue)
	
	// Cancel the context to signal workers to stop
	c.cancel()
	
	// Wait for all workers to finish processing
	c.wg.Wait()
	
	c.started = false
	c.updateStats(func(stats *CollectorStats) {
		stats.IsRunning = false
	})
	
	log.Println("Audit event collector stopped")
	return nil
}

// CollectEvent asynchronously collects an audit event
func (c *EventCollector) CollectEvent(event *models.AuditEvent) error {
	c.updateStats(func(stats *CollectorStats) {
		stats.EventsReceived++
	})
	
	select {
	case c.eventQueue <- event:
		return nil
	case <-c.ctx.Done():
		return fmt.Errorf("collector is shutting down")
	default:
		// Queue is full, drop the event
		c.updateStats(func(stats *CollectorStats) {
			stats.EventsDropped++
		})
		return fmt.Errorf("event queue is full, event dropped")
	}
}

// CollectEventWithTimeout collects an event with a timeout
func (c *EventCollector) CollectEventWithTimeout(event *models.AuditEvent, timeout time.Duration) error {
	c.updateStats(func(stats *CollectorStats) {
		stats.EventsReceived++
	})
	
	ctx, cancel := context.WithTimeout(c.ctx, timeout)
	defer cancel()
	
	select {
	case c.eventQueue <- event:
		return nil
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			c.updateStats(func(stats *CollectorStats) {
				stats.EventsDropped++
			})
			return fmt.Errorf("timeout waiting to queue event")
		}
		return fmt.Errorf("collector is shutting down")
	}
}

// GetStats returns current collector statistics
func (c *EventCollector) GetStats() CollectorStats {
	c.statsMutex.RLock()
	defer c.statsMutex.RUnlock()
	
	stats := *c.stats
	stats.QueueSize = len(c.eventQueue)
	return stats
}

// HealthCheck performs a health check on the collector
func (c *EventCollector) HealthCheck() error {
	stats := c.GetStats()
	
	if !stats.IsRunning {
		return fmt.Errorf("collector is not running")
	}
	
	// Check if queue is near capacity
	queueUtilization := float64(stats.QueueSize) / float64(c.bufferSize) * 100
	if queueUtilization > 90 {
		return fmt.Errorf("event queue utilization is %0.1f%% (critical threshold)", queueUtilization)
	}
	
	// Check if events are being processed
	if stats.EventsReceived > 0 && stats.LastProcessedAt.IsZero() {
		return fmt.Errorf("events received but none processed")
	}
	
	// Check if processing is stalled
	if !stats.LastProcessedAt.IsZero() && time.Since(stats.LastProcessedAt) > time.Minute*5 {
		return fmt.Errorf("no events processed in the last 5 minutes")
	}
	
	// Check storage health
	if err := c.storage.HealthCheck(context.Background()); err != nil {
		return fmt.Errorf("storage health check failed: %w", err)
	}
	
	return nil
}

// worker processes events from the queue
func (c *EventCollector) worker(workerID int) {
	defer c.wg.Done()
	
	log.Printf("Audit collector worker %d started", workerID)
	defer log.Printf("Audit collector worker %d stopped", workerID)
	
	for {
		select {
		case event, ok := <-c.eventQueue:
			if !ok {
				// Channel closed, worker should exit
				return
			}
			
			c.processEvent(event, workerID)
			
		case <-c.ctx.Done():
			// Context cancelled, worker should exit
			return
		}
	}
}

// processEvent handles the processing of a single audit event
func (c *EventCollector) processEvent(event *models.AuditEvent, workerID int) {
	startTime := time.Now()
	
	var lastErr error
	for attempt := 0; attempt <= c.retryAttempts; attempt++ {
		err := c.storage.StoreEvent(context.Background(), event)
		if err == nil {
			// Success
			c.updateStats(func(stats *CollectorStats) {
				stats.EventsProcessed++
				stats.ProcessingTime += time.Since(startTime).Milliseconds()
				stats.LastProcessedAt = time.Now().UTC()
			})
			
			log.Printf("Worker %d processed event %s (attempt %d)", workerID, event.ID, attempt+1)
			return
		}
		
		lastErr = err
		
		if attempt < c.retryAttempts {
			log.Printf("Worker %d failed to process event %s (attempt %d): %v, retrying...", 
				workerID, event.ID, attempt+1, err)
			
			// Wait before retrying
			select {
			case <-time.After(c.retryDelay):
				// Continue with retry
			case <-c.ctx.Done():
				// Context cancelled, stop retrying
				c.updateStats(func(stats *CollectorStats) {
					stats.EventsFailed++
				})
				return
			}
		}
	}
	
	// All retry attempts failed
	log.Printf("Worker %d permanently failed to process event %s after %d attempts: %v", 
		workerID, event.ID, c.retryAttempts+1, lastErr)
	
	c.updateStats(func(stats *CollectorStats) {
		stats.EventsFailed++
	})
	
	// TODO: Implement dead letter queue for failed events
	c.handleFailedEvent(event, lastErr)
}

// handleFailedEvent handles events that could not be processed
func (c *EventCollector) handleFailedEvent(event *models.AuditEvent, err error) {
	// Log the failure for monitoring
	log.Printf("AUDIT EVENT LOST: Event %s failed processing: %v", event.ID, err)
	
	// TODO: In production, this should:
	// 1. Write to a dead letter queue
	// 2. Send alerts to monitoring systems
	// 3. Store in a backup location
	// 4. Generate incident reports
}

// updateStats safely updates collector statistics
func (c *EventCollector) updateStats(updateFunc func(*CollectorStats)) {
	c.statsMutex.Lock()
	defer c.statsMutex.Unlock()
	updateFunc(c.stats)
}

// BatchEventCollector provides batch collection capabilities
type BatchEventCollector struct {
	collector   *EventCollector
	batchSize   int
	batchBuffer []*models.AuditEvent
	bufferMutex sync.Mutex
	flushTimer  *time.Timer
	flushInterval time.Duration
}

// NewBatchEventCollector creates a new batch event collector
func NewBatchEventCollector(collector *EventCollector, batchSize int, flushInterval time.Duration) *BatchEventCollector {
	return &BatchEventCollector{
		collector:     collector,
		batchSize:     batchSize,
		batchBuffer:   make([]*models.AuditEvent, 0, batchSize),
		flushInterval: flushInterval,
	}
}

// CollectEvent adds an event to the batch buffer
func (b *BatchEventCollector) CollectEvent(event *models.AuditEvent) error {
	b.bufferMutex.Lock()
	defer b.bufferMutex.Unlock()
	
	b.batchBuffer = append(b.batchBuffer, event)
	
	// Reset flush timer
	if b.flushTimer != nil {
		b.flushTimer.Stop()
	}
	b.flushTimer = time.AfterFunc(b.flushInterval, b.flushBatch)
	
	// Flush if batch is full
	if len(b.batchBuffer) >= b.batchSize {
		b.flushBatchLocked()
	}
	
	return nil
}

// flushBatch flushes the current batch
func (b *BatchEventCollector) flushBatch() {
	b.bufferMutex.Lock()
	defer b.bufferMutex.Unlock()
	b.flushBatchLocked()
}

// flushBatchLocked flushes the current batch (requires lock)
func (b *BatchEventCollector) flushBatchLocked() {
	if len(b.batchBuffer) == 0 {
		return
	}
	
	// Send all events in the batch
	for _, event := range b.batchBuffer {
		if err := b.collector.CollectEvent(event); err != nil {
			log.Printf("Failed to collect event %s in batch: %v", event.ID, err)
		}
	}
	
	// Clear the buffer
	b.batchBuffer = b.batchBuffer[:0]
	
	// Stop the flush timer
	if b.flushTimer != nil {
		b.flushTimer.Stop()
		b.flushTimer = nil
	}
}

// Flush manually flushes any remaining events in the buffer
func (b *BatchEventCollector) Flush() {
	b.flushBatch()
}