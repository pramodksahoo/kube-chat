package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/pramodksahoo/kube-chat/pkg/audit/formats"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// NATSStreamingService handles SIEM integration via NATS JetStream
type NATSStreamingService struct {
	conn        *nats.Conn
	jetStream   nats.JetStreamContext
	config      NATSStreamingConfig
	formatters  map[string]formats.SIEMFormatExporter
	streams     map[string]*NATSStreamConfig
	metrics     *NATSMetrics
	mu          sync.RWMutex
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// NATSStreamingConfig configures NATS JetStream connectivity
type NATSStreamingConfig struct {
	URLs                []string      `json:"urls"`
	ConnectionTimeout   time.Duration `json:"connection_timeout"`
	ReconnectWait       time.Duration `json:"reconnect_wait"`
	MaxReconnectAttempts int          `json:"max_reconnect_attempts"`
	ClusterName         string        `json:"cluster_name"`
	UserCredentials     string        `json:"user_credentials,omitempty"`
	TLSCertFile         string        `json:"tls_cert_file,omitempty"`
	TLSKeyFile          string        `json:"tls_key_file,omitempty"`
	TLSCAFile           string        `json:"tls_ca_file,omitempty"`
}

// NATSStreamConfig defines configuration for a NATS stream
type NATSStreamConfig struct {
	StreamName    string                     `json:"stream_name"`
	Subject       string                     `json:"subject"`
	Description   string                     `json:"description"`
	Format        string                     `json:"format"`        // JSON, CEF, LEEF
	Platform      string                     `json:"platform"`      // splunk, qradar, sentinel, etc.
	Retention     nats.RetentionPolicy       `json:"retention"`
	Storage       nats.StorageType           `json:"storage"`
	MaxMsgs       int64                      `json:"max_msgs"`
	MaxBytes      int64                      `json:"max_bytes"`
	MaxAge        time.Duration              `json:"max_age"`
	Replicas      int                        `json:"replicas"`
	FilterConfig  WebhookFilterConfig        `json:"filter_config"`
	StreamConfig  *nats.StreamConfig         `json:"-"` // Internal NATS config
	Active        bool                       `json:"active"`
	CreatedAt     time.Time                  `json:"created_at"`
	UpdatedAt     time.Time                  `json:"updated_at"`
}

// NATSMetrics tracks NATS streaming statistics
type NATSMetrics struct {
	TotalPublished       int64                        `json:"total_published"`
	SuccessfulPublished  int64                        `json:"successful_published"`
	FailedPublished      int64                        `json:"failed_published"`
	ConnectionStatus     string                       `json:"connection_status"`
	StreamMetrics        map[string]*NATSStreamMetrics `json:"stream_metrics"`
	LastUpdated          time.Time                    `json:"last_updated"`
	mu                   sync.RWMutex
}

// NATSStreamMetrics tracks metrics for individual NATS streams
type NATSStreamMetrics struct {
	StreamName      string    `json:"stream_name"`
	MessagesCount   int64     `json:"messages_count"`
	BytesCount      int64     `json:"bytes_count"`
	PublishCount    int64     `json:"publish_count"`
	SuccessCount    int64     `json:"success_count"`
	ErrorCount      int64     `json:"error_count"`
	LastPublishAt   time.Time `json:"last_publish_at,omitempty"`
	AverageLatency  time.Duration `json:"average_latency"`
}

// NATSMessage represents a NATS message with audit event data
type NATSMessage struct {
	EventID       string                 `json:"event_id"`
	Format        string                 `json:"format"`
	Platform      string                 `json:"platform"`
	Data          []byte                 `json:"data"`
	Headers       map[string]string      `json:"headers"`
	PublishedAt   time.Time              `json:"published_at"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// DefaultNATSStreamingConfig returns sensible default NATS configuration
func DefaultNATSStreamingConfig() NATSStreamingConfig {
	return NATSStreamingConfig{
		URLs:                 []string{"nats://localhost:4222"},
		ConnectionTimeout:    time.Second * 10,
		ReconnectWait:        time.Second * 2,
		MaxReconnectAttempts: 10,
		ClusterName:         "kubechat-audit",
	}
}

// DefaultNATSStreamConfig returns default stream configuration
func DefaultNATSStreamConfig(name, subject, format string) *NATSStreamConfig {
	return &NATSStreamConfig{
		StreamName:  name,
		Subject:     subject,
		Description: fmt.Sprintf("KubeChat audit events for %s format", format),
		Format:      format,
		Retention:   nats.WorkQueuePolicy,
		Storage:     nats.FileStorage,
		MaxMsgs:     1000000,
		MaxBytes:    1024 * 1024 * 1024, // 1GB
		MaxAge:      time.Hour * 24 * 7,  // 7 days
		Replicas:    1,
		Active:      true,
	}
}

// NewNATSStreamingService creates a new NATS streaming service
func NewNATSStreamingService(config NATSStreamingConfig) (*NATSStreamingService, error) {
	if len(config.URLs) == 0 {
		config = DefaultNATSStreamingConfig()
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	service := &NATSStreamingService{
		config:     config,
		formatters: map[string]formats.SIEMFormatExporter{
			"JSON": formats.NewJSONExporter(formats.JSONExporterConfig{IncludeIntegrityFields: true}),
			"CEF":  formats.NewCEFExporter(formats.DefaultCEFConfig()),
			"LEEF": formats.NewLEEFExporter(formats.DefaultLEEFConfig()),
		},
		streams: make(map[string]*NATSStreamConfig),
		metrics: &NATSMetrics{
			StreamMetrics: make(map[string]*NATSStreamMetrics),
		},
		ctx:        ctx,
		cancelFunc: cancel,
	}
	
	if err := service.connect(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}
	
	return service, nil
}

// connect establishes connection to NATS JetStream
func (ns *NATSStreamingService) connect() error {
	// Configure NATS connection options
	opts := []nats.Option{
		nats.Timeout(ns.config.ConnectionTimeout),
		nats.ReconnectWait(ns.config.ReconnectWait),
		nats.MaxReconnects(ns.config.MaxReconnectAttempts),
		nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
			ns.updateConnectionStatus("disconnected")
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			ns.updateConnectionStatus("reconnected")
		}),
		nats.ClosedHandler(func(nc *nats.Conn) {
			ns.updateConnectionStatus("closed")
		}),
	}
	
	// Add TLS configuration if provided
	if ns.config.TLSCertFile != "" && ns.config.TLSKeyFile != "" {
		opts = append(opts, nats.ClientCert(ns.config.TLSCertFile, ns.config.TLSKeyFile))
	}
	if ns.config.TLSCAFile != "" {
		opts = append(opts, nats.RootCAs(ns.config.TLSCAFile))
	}
	
	// Add user credentials if provided
	if ns.config.UserCredentials != "" {
		opts = append(opts, nats.UserCredentials(ns.config.UserCredentials))
	}
	
	// Connect to NATS
	conn, err := nats.Connect(nats.DefaultURL, opts...)
	if err != nil {
		return fmt.Errorf("failed to connect to NATS: %w", err)
	}
	
	// Create JetStream context
	jetStream, err := conn.JetStream()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create JetStream context: %w", err)
	}
	
	ns.conn = conn
	ns.jetStream = jetStream
	ns.updateConnectionStatus("connected")
	
	return nil
}

// AddStream adds a new NATS stream configuration
func (ns *NATSStreamingService) AddStream(streamConfig *NATSStreamConfig) error {
	if streamConfig.StreamName == "" {
		return fmt.Errorf("stream name is required")
	}
	if streamConfig.Subject == "" {
		return fmt.Errorf("subject is required")
	}
	
	// Validate formatter exists
	if _, exists := ns.formatters[streamConfig.Format]; !exists {
		return fmt.Errorf("unsupported format: %s", streamConfig.Format)
	}
	
	// Create NATS stream configuration
	natsStreamConfig := &nats.StreamConfig{
		Name:        streamConfig.StreamName,
		Subjects:    []string{streamConfig.Subject},
		Description: streamConfig.Description,
		Retention:   streamConfig.Retention,
		Storage:     streamConfig.Storage,
		MaxMsgs:     streamConfig.MaxMsgs,
		MaxBytes:    streamConfig.MaxBytes,
		MaxAge:      streamConfig.MaxAge,
		Replicas:    streamConfig.Replicas,
	}
	
	// Create or update the stream
	_, err := ns.jetStream.AddStream(natsStreamConfig)
	if err != nil {
		return fmt.Errorf("failed to create NATS stream: %w", err)
	}
	
	streamConfig.StreamConfig = natsStreamConfig
	streamConfig.CreatedAt = time.Now().UTC()
	streamConfig.UpdatedAt = time.Now().UTC()
	
	ns.mu.Lock()
	ns.streams[streamConfig.StreamName] = streamConfig
	ns.mu.Unlock()
	
	// Initialize metrics for this stream
	ns.metrics.mu.Lock()
	ns.metrics.StreamMetrics[streamConfig.StreamName] = &NATSStreamMetrics{
		StreamName: streamConfig.StreamName,
	}
	ns.metrics.mu.Unlock()
	
	return nil
}

// RemoveStream removes a NATS stream
func (ns *NATSStreamingService) RemoveStream(streamName string) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	
	if _, exists := ns.streams[streamName]; !exists {
		return fmt.Errorf("stream %s not found", streamName)
	}
	
	// Delete the NATS stream
	if err := ns.jetStream.DeleteStream(streamName); err != nil {
		return fmt.Errorf("failed to delete NATS stream: %w", err)
	}
	
	delete(ns.streams, streamName)
	
	ns.metrics.mu.Lock()
	delete(ns.metrics.StreamMetrics, streamName)
	ns.metrics.mu.Unlock()
	
	return nil
}

// StreamEvent streams an audit event to all configured NATS streams
func (ns *NATSStreamingService) StreamEvent(event *models.AuditEvent) error {
	ns.mu.RLock()
	activeStreams := make([]*NATSStreamConfig, 0, len(ns.streams))
	for _, stream := range ns.streams {
		if stream.Active && ns.shouldStreamEvent(event, stream.FilterConfig) {
			activeStreams = append(activeStreams, stream)
		}
	}
	ns.mu.RUnlock()
	
	if len(activeStreams) == 0 {
		return nil // No active streams or event filtered out
	}
	
	// Publish to all matching streams concurrently
	var wg sync.WaitGroup
	errorChan := make(chan error, len(activeStreams))
	
	for _, stream := range activeStreams {
		wg.Add(1)
		go func(s *NATSStreamConfig) {
			defer wg.Done()
			if err := ns.publishToStream(event, s); err != nil {
				errorChan <- fmt.Errorf("stream %s: %w", s.StreamName, err)
			}
		}(stream)
	}
	
	// Wait for all publications to complete
	go func() {
		wg.Wait()
		close(errorChan)
	}()
	
	// Collect any errors
	var publishErrors []string
	for err := range errorChan {
		publishErrors = append(publishErrors, err.Error())
	}
	
	// Return error if any publications failed
	if len(publishErrors) > 0 {
		return fmt.Errorf("NATS publish failures: %v", publishErrors)
	}
	
	return nil
}

// publishToStream publishes an event to a specific NATS stream
func (ns *NATSStreamingService) publishToStream(event *models.AuditEvent, stream *NATSStreamConfig) error {
	startTime := time.Now()
	
	// Format the event for the stream
	formatter, exists := ns.formatters[stream.Format]
	if !exists {
		return fmt.Errorf("unsupported format: %s", stream.Format)
	}
	
	exportedData, err := formatter.Export(event)
	if err != nil {
		ns.updateStreamMetrics(stream.StreamName, false, 0, time.Since(startTime))
		return fmt.Errorf("export failed: %w", err)
	}
	
	// Create NATS message
	natsMsg := &NATSMessage{
		EventID:     event.ID,
		Format:      stream.Format,
		Platform:    stream.Platform,
		Data:        exportedData,
		Headers: map[string]string{
			"Content-Type":    formatter.GetContentType(),
			"Event-Type":      string(event.EventType),
			"Event-Severity":  string(event.Severity),
			"User-ID":         event.UserContext.UserID,
			"Cluster-Name":    event.ClusterContext.ClusterName,
			"Correlation-ID":  event.CorrelationID,
		},
		PublishedAt: time.Now().UTC(),
		Metadata: map[string]interface{}{
			"stream_name": stream.StreamName,
			"subject":     stream.Subject,
			"format":      stream.Format,
			"platform":    stream.Platform,
		},
	}
	
	// Serialize the message
	msgData, err := json.Marshal(natsMsg)
	if err != nil {
		ns.updateStreamMetrics(stream.StreamName, false, 0, time.Since(startTime))
		return fmt.Errorf("message serialization failed: %w", err)
	}
	
	// Create NATS message with headers
	msg := &nats.Msg{
		Subject: stream.Subject,
		Data:    msgData,
		Header:  make(nats.Header),
	}
	
	// Add headers
	for key, value := range natsMsg.Headers {
		msg.Header.Set(key, value)
	}
	
	// Publish the message
	_, err = ns.jetStream.PublishMsg(msg)
	if err != nil {
		ns.updateStreamMetrics(stream.StreamName, false, len(msgData), time.Since(startTime))
		return fmt.Errorf("NATS publish failed: %w", err)
	}
	
	ns.updateStreamMetrics(stream.StreamName, true, len(msgData), time.Since(startTime))
	return nil
}

// shouldStreamEvent determines if an event should be streamed based on filter configuration
func (ns *NATSStreamingService) shouldStreamEvent(event *models.AuditEvent, filter WebhookFilterConfig) bool {
	// Reuse the same filtering logic from webhook service
	ws := &WebhookStreamingService{}
	return ws.shouldForwardEvent(event, filter)
}

// updateStreamMetrics updates metrics for a specific stream
func (ns *NATSStreamingService) updateStreamMetrics(streamName string, success bool, msgSize int, latency time.Duration) {
	ns.metrics.mu.Lock()
	defer ns.metrics.mu.Unlock()
	
	ns.metrics.TotalPublished++
	if success {
		ns.metrics.SuccessfulPublished++
	} else {
		ns.metrics.FailedPublished++
	}
	
	// Update stream-specific metrics
	streamMetrics := ns.metrics.StreamMetrics[streamName]
	if streamMetrics == nil {
		streamMetrics = &NATSStreamMetrics{StreamName: streamName}
		ns.metrics.StreamMetrics[streamName] = streamMetrics
	}
	
	streamMetrics.PublishCount++
	streamMetrics.BytesCount += int64(msgSize)
	streamMetrics.LastPublishAt = time.Now().UTC()
	
	if success {
		streamMetrics.SuccessCount++
		streamMetrics.MessagesCount++
	} else {
		streamMetrics.ErrorCount++
	}
	
	// Update average latency (simple moving average)
	if streamMetrics.PublishCount == 1 {
		streamMetrics.AverageLatency = latency
	} else {
		streamMetrics.AverageLatency = time.Duration(
			(int64(streamMetrics.AverageLatency) + int64(latency)) / 2)
	}
	
	ns.metrics.LastUpdated = time.Now().UTC()
}

// updateConnectionStatus updates the connection status in metrics
func (ns *NATSStreamingService) updateConnectionStatus(status string) {
	ns.metrics.mu.Lock()
	defer ns.metrics.mu.Unlock()
	ns.metrics.ConnectionStatus = status
	ns.metrics.LastUpdated = time.Now().UTC()
}

// GetMetrics returns current NATS streaming metrics
func (ns *NATSStreamingService) GetMetrics() *NATSMetrics {
	ns.metrics.mu.RLock()
	defer ns.metrics.mu.RUnlock()
	
	// Create a copy to avoid race conditions
	metrics := &NATSMetrics{
		TotalPublished:      ns.metrics.TotalPublished,
		SuccessfulPublished: ns.metrics.SuccessfulPublished,
		FailedPublished:     ns.metrics.FailedPublished,
		ConnectionStatus:    ns.metrics.ConnectionStatus,
		StreamMetrics:       make(map[string]*NATSStreamMetrics),
		LastUpdated:         ns.metrics.LastUpdated,
	}
	
	// Copy stream metrics
	for name, sm := range ns.metrics.StreamMetrics {
		metrics.StreamMetrics[name] = &NATSStreamMetrics{
			StreamName:     sm.StreamName,
			MessagesCount:  sm.MessagesCount,
			BytesCount:     sm.BytesCount,
			PublishCount:   sm.PublishCount,
			SuccessCount:   sm.SuccessCount,
			ErrorCount:     sm.ErrorCount,
			LastPublishAt:  sm.LastPublishAt,
			AverageLatency: sm.AverageLatency,
		}
	}
	
	return metrics
}

// GetStreams returns all configured NATS streams
func (ns *NATSStreamingService) GetStreams() map[string]*NATSStreamConfig {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	
	streams := make(map[string]*NATSStreamConfig)
	for name, stream := range ns.streams {
		// Create a copy to avoid mutation
		streamCopy := *stream
		streams[name] = &streamCopy
	}
	
	return streams
}

// GetStreamInfo returns NATS stream information
func (ns *NATSStreamingService) GetStreamInfo(streamName string) (*nats.StreamInfo, error) {
	return ns.jetStream.StreamInfo(streamName)
}

// HealthCheck performs a health check on the NATS connection and streams
func (ns *NATSStreamingService) HealthCheck() error {
	if ns.conn == nil || ns.conn.Status() != nats.CONNECTED {
		return fmt.Errorf("NATS connection is not established")
	}
	
	// Check JetStream availability
	_, err := ns.jetStream.AccountInfo()
	if err != nil {
		return fmt.Errorf("JetStream is not available: %w", err)
	}
	
	return nil
}

// Stop gracefully stops the NATS streaming service
func (ns *NATSStreamingService) Stop() error {
	ns.cancelFunc()
	
	if ns.conn != nil {
		ns.conn.Close()
	}
	
	ns.updateConnectionStatus("stopped")
	return nil
}

// CreateDefaultStreams creates default NATS streams for common SIEM platforms
func (ns *NATSStreamingService) CreateDefaultStreams() error {
	defaultStreams := []*NATSStreamConfig{
		DefaultNATSStreamConfig("kubechat-audit-json", "kubechat.audit.json", "JSON"),
		DefaultNATSStreamConfig("kubechat-audit-cef", "kubechat.audit.cef", "CEF"),
		DefaultNATSStreamConfig("kubechat-audit-leef", "kubechat.audit.leef", "LEEF"),
	}
	
	for _, stream := range defaultStreams {
		if err := ns.AddStream(stream); err != nil {
			return fmt.Errorf("failed to create default stream %s: %w", stream.StreamName, err)
		}
	}
	
	return nil
}