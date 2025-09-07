package streaming

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/audit/formats"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWebhookStreamingService tests the webhook streaming functionality
func TestWebhookStreamingService(t *testing.T) {
	tests := []struct {
		name        string
		setupMocks  func() (*httptest.Server, *WebhookEndpoint)
		expectError bool
	}{
		{
			name: "successful_webhook_delivery",
			setupMocks: func() (*httptest.Server, *WebhookEndpoint) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"status": "success"}`))
				}))
				
				endpoint := &WebhookEndpoint{
					ID:      "test-endpoint",
					Name:    "Test Endpoint",
					URL:     server.URL,
					Method:  "POST",
					Format:  "JSON",
					Active:  true,
					Timeout: time.Second * 5,
					RetryConfig: DefaultWebhookRetryConfig(),
				}
				
				return server, endpoint
			},
			expectError: false,
		},
		{
			name: "webhook_retry_on_failure",
			setupMocks: func() (*httptest.Server, *WebhookEndpoint) {
				attempts := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					attempts++
					if attempts <= 2 {
						w.WriteHeader(http.StatusInternalServerError)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"status": "success"}`))
				}))
				
				endpoint := &WebhookEndpoint{
					ID:      "retry-endpoint",
					Name:    "Retry Test Endpoint",
					URL:     server.URL,
					Method:  "POST",
					Format:  "JSON",
					Active:  true,
					Timeout: time.Second * 5,
					RetryConfig: WebhookRetryConfig{
						MaxAttempts:       3,
						InitialDelay:      time.Millisecond * 100,
						MaxDelay:          time.Second,
						ExponentialBase:   2.0,
						RetryableStatuses: []int{500, 502, 503, 504},
					},
				}
				
				return server, endpoint
			},
			expectError: false,
		},
		{
			name: "webhook_authentication_with_hmac",
			setupMocks: func() (*httptest.Server, *WebhookEndpoint) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Verify HMAC signature header
					signature := r.Header.Get("X-Webhook-Signature")
					if signature == "" || !strings.HasPrefix(signature, "sha256=") {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.WriteHeader(http.StatusOK)
					w.Write([]byte(`{"status": "authenticated"}`))
				}))
				
				endpoint := &WebhookEndpoint{
					ID:      "auth-endpoint",
					Name:    "Authenticated Endpoint",
					URL:     server.URL,
					Method:  "POST",
					Format:  "JSON",
					Secret:  "test-secret-key",
					Active:  true,
					Timeout: time.Second * 5,
					RetryConfig: DefaultWebhookRetryConfig(),
				}
				
				return server, endpoint
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, endpoint := tt.setupMocks()
			defer server.Close()
			
			// Create webhook streaming service
			bufferConfig := DefaultLocalBufferConfig()
			service := NewWebhookStreamingService(bufferConfig)
			
			// Add test endpoint
			err := service.AddEndpoint(endpoint)
			require.NoError(t, err)
			
			// Create test audit event
			event := createTestAuditEvent(t)
			
			// Stream the event
			err = service.StreamEvent(event)
			
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				
				// Verify metrics were updated
				metrics := service.GetMetrics()
				assert.Greater(t, metrics.TotalDeliveries, int64(0))
			}
		})
	}
}

// TestNATSStreamingService tests NATS streaming functionality
func TestNATSStreamingService(t *testing.T) {
	// Skip this test if NATS is not available
	t.Skip("NATS integration test requires running NATS server")
	
	config := DefaultNATSStreamingConfig()
	service, err := NewNATSStreamingService(config)
	require.NoError(t, err)
	defer service.Stop()
	
	// Create test stream
	streamConfig := DefaultNATSStreamConfig("test-stream", "test.audit.json", "JSON")
	err = service.AddStream(streamConfig)
	require.NoError(t, err)
	
	// Create test event
	event := createTestAuditEvent(t)
	
	// Stream the event
	err = service.StreamEvent(event)
	assert.NoError(t, err)
	
	// Verify metrics
	metrics := service.GetMetrics()
	assert.Greater(t, metrics.TotalPublished, int64(0))
	assert.Equal(t, "connected", metrics.ConnectionStatus)
}

// TestLocalBuffer tests the local buffering functionality
func TestLocalBuffer(t *testing.T) {
	tests := []struct {
		name           string
		bufferConfig   LocalBufferConfig
		eventsToBuffer int
		expectSuccess  bool
	}{
		{
			name: "basic_buffering",
			bufferConfig: LocalBufferConfig{
				MaxBufferSize: 100,
				MaxBufferAge:  time.Hour,
				FlushInterval: time.Second,
				PersistToDisk: false,
				RetryPolicy:   RetryPolicy{MaxRetries: 3},
			},
			eventsToBuffer: 10,
			expectSuccess:  true,
		},
		{
			name: "buffer_size_limit",
			bufferConfig: LocalBufferConfig{
				MaxBufferSize: 5,
				MaxBufferAge:  time.Hour,
				FlushInterval: time.Second,
				PersistToDisk: false,
				RetryPolicy:   RetryPolicy{MaxRetries: 3},
			},
			eventsToBuffer: 10,
			expectSuccess:  true, // Should evict oldest events
		},
		{
			name: "persistent_buffering",
			bufferConfig: LocalBufferConfig{
				MaxBufferSize: 100,
				MaxBufferAge:  time.Hour,
				FlushInterval: time.Second,
				PersistToDisk: true,
				BufferDirectory: t.TempDir(),
				RetryPolicy:     RetryPolicy{MaxRetries: 3},
			},
			eventsToBuffer: 5,
			expectSuccess:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := NewLocalBuffer(tt.bufferConfig)
			defer buffer.Stop()
			
			// Buffer multiple events
			for i := 0; i < tt.eventsToBuffer; i++ {
				event := createTestAuditEvent(t)
				event.ID = fmt.Sprintf("test-event-%d", i)
				
				err := buffer.BufferEvent(event, "test-endpoint")
				if tt.expectSuccess {
					assert.NoError(t, err)
				}
			}
			
			// Check buffer metrics
			metrics := buffer.GetMetrics()
			if tt.expectSuccess {
				assert.Greater(t, metrics.TotalBuffered, int64(0))
				
				// Check buffer size doesn't exceed limit
				assert.LessOrEqual(t, metrics.CurrentlyBuffered, int64(tt.bufferConfig.MaxBufferSize))
			}
			
			// Test buffered event retrieval
			bufferedEvents := buffer.GetBufferedEvents("test-endpoint")
			if tt.expectSuccess {
				assert.NotEmpty(t, bufferedEvents)
			}
		})
	}
}

// TestEventFiltering tests event filtering functionality
func TestEventFiltering(t *testing.T) {
	service := &WebhookStreamingService{}
	
	tests := []struct {
		name         string
		event        *models.AuditEvent
		filter       WebhookFilterConfig
		shouldForward bool
	}{
		{
			name:  "no_filtering",
			event: createTestAuditEvent(t),
			filter: WebhookFilterConfig{
				SampleRate: 1.0,
			},
			shouldForward: true,
		},
		{
			name:  "event_type_filtering",
			event: createTestAuditEventWithType(t, models.AuditEventTypeCommandExecute),
			filter: WebhookFilterConfig{
				EventTypes: []models.AuditEventType{models.AuditEventTypeCommandExecute},
				SampleRate: 1.0,
			},
			shouldForward: true,
		},
		{
			name:  "event_type_filtering_exclude",
			event: createTestAuditEventWithType(t, models.AuditEventTypeHealthCheck),
			filter: WebhookFilterConfig{
				EventTypes: []models.AuditEventType{models.AuditEventTypeCommandExecute},
				SampleRate: 1.0,
			},
			shouldForward: false,
		},
		{
			name:  "severity_filtering",
			event: createTestAuditEventWithSeverity(t, models.AuditSeverityError),
			filter: WebhookFilterConfig{
				Severities: []models.AuditSeverity{models.AuditSeverityError, models.AuditSeverityCritical},
				SampleRate: 1.0,
			},
			shouldForward: true,
		},
		{
			name:  "user_filtering",
			event: createTestAuditEventWithUser(t, "admin-user"),
			filter: WebhookFilterConfig{
				UserIDs:    []string{"admin-user", "super-admin"},
				SampleRate: 1.0,
			},
			shouldForward: true,
		},
		{
			name:  "sampling_rate_zero",
			event: createTestAuditEvent(t),
			filter: WebhookFilterConfig{
				SampleRate: 0.0,
			},
			shouldForward: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.shouldForwardEvent(tt.event, tt.filter)
			assert.Equal(t, tt.shouldForward, result)
		})
	}
}

// TestFormatCompatibility tests compatibility with different SIEM formats
func TestFormatCompatibility(t *testing.T) {
	event := createTestAuditEvent(t)
	
	tests := []struct {
		name   string
		format formats.SIEMFormatExporter
	}{
		{
			name:   "json_format",
			format: formats.NewJSONExporter(formats.JSONExporterConfig{}),
		},
		{
			name:   "cef_format",
			format: formats.NewCEFExporter(formats.DefaultCEFConfig()),
		},
		{
			name:   "leef_format",
			format: formats.NewLEEFExporter(formats.DefaultLEEFConfig()),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test single event export
			data, err := tt.format.Export(event)
			require.NoError(t, err)
			require.NotEmpty(t, data)
			
			// Test batch export
			events := []*models.AuditEvent{event, event}
			batchData, err := tt.format.ExportBatch(events)
			require.NoError(t, err)
			require.NotEmpty(t, batchData)
			
			// Test validation
			err = tt.format.ValidateEvent(event)
			assert.NoError(t, err)
		})
	}
}

// TestConcurrentStreaming tests concurrent streaming to multiple endpoints
func TestConcurrentStreaming(t *testing.T) {
	const numEndpoints = 5
	const numEvents = 100
	
	// Create multiple mock endpoints
	var servers []*httptest.Server
	var endpoints []*WebhookEndpoint
	var receivedCounts []int
	var mutexes []sync.Mutex
	
	for i := 0; i < numEndpoints; i++ {
		receivedCounts = append(receivedCounts, 0)
		mutexes = append(mutexes, sync.Mutex{})
		
		idx := i // Capture loop variable
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mutexes[idx].Lock()
			receivedCounts[idx]++
			mutexes[idx].Unlock()
			
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": "success"}`))
		}))
		
		servers = append(servers, server)
		
		endpoint := &WebhookEndpoint{
			ID:      fmt.Sprintf("endpoint-%d", i),
			Name:    fmt.Sprintf("Test Endpoint %d", i),
			URL:     server.URL,
			Method:  "POST",
			Format:  "JSON",
			Active:  true,
			Timeout: time.Second * 5,
			RetryConfig: DefaultWebhookRetryConfig(),
		}
		
		endpoints = append(endpoints, endpoint)
	}
	
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()
	
	// Create webhook streaming service
	bufferConfig := DefaultLocalBufferConfig()
	service := NewWebhookStreamingService(bufferConfig)
	
	// Add all endpoints
	for _, endpoint := range endpoints {
		err := service.AddEndpoint(endpoint)
		require.NoError(t, err)
	}
	
	// Stream events concurrently
	var wg sync.WaitGroup
	for i := 0; i < numEvents; i++ {
		wg.Add(1)
		go func(eventNum int) {
			defer wg.Done()
			
			event := createTestAuditEvent(t)
			event.ID = fmt.Sprintf("concurrent-event-%d", eventNum)
			
			err := service.StreamEvent(event)
			assert.NoError(t, err)
		}(i)
	}
	
	wg.Wait()
	
	// Verify all endpoints received all events
	for i, count := range receivedCounts {
		assert.Equal(t, numEvents, count, "Endpoint %d should have received %d events", i, numEvents)
	}
	
	// Verify metrics
	metrics := service.GetMetrics()
	assert.Equal(t, int64(numEvents*numEndpoints), metrics.TotalDeliveries)
	assert.Equal(t, int64(numEvents*numEndpoints), metrics.SuccessfulDeliveries)
}

// TestFailureScenarios tests various failure scenarios
func TestFailureScenarios(t *testing.T) {
	tests := []struct {
		name         string
		setupServer  func() *httptest.Server
		expectError  bool
		expectRetry  bool
	}{
		{
			name: "server_unavailable",
			setupServer: func() *httptest.Server {
				// Return a server that's immediately closed
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusOK)
				}))
				server.Close() // Close immediately to simulate unavailable server
				return server
			},
			expectError: true,
			expectRetry: false, // Connection errors are not retryable by default
		},
		{
			name: "internal_server_error",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte(`{"error": "internal server error"}`))
				}))
			},
			expectError: true,
			expectRetry: true,
		},
		{
			name: "bad_request_not_retryable",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(`{"error": "bad request"}`))
				}))
			},
			expectError: true,
			expectRetry: false,
		},
		{
			name: "timeout_scenario",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					// Simulate slow server
					time.Sleep(time.Second * 2)
					w.WriteHeader(http.StatusOK)
				}))
			},
			expectError: true,
			expectRetry: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer func() {
				if server != nil && server.URL != "" {
					server.Close()
				}
			}()
			
			endpoint := &WebhookEndpoint{
				ID:      "failure-test",
				Name:    "Failure Test Endpoint",
				URL:     server.URL,
				Method:  "POST",
				Format:  "JSON",
				Active:  true,
				Timeout: time.Millisecond * 500, // Short timeout for timeout test
				RetryConfig: WebhookRetryConfig{
					MaxAttempts:       3,
					InitialDelay:      time.Millisecond * 100,
					MaxDelay:          time.Second,
					ExponentialBase:   2.0,
					RetryableStatuses: []int{500, 502, 503, 504},
				},
			}
			
			bufferConfig := DefaultLocalBufferConfig()
			service := NewWebhookStreamingService(bufferConfig)
			
			err := service.AddEndpoint(endpoint)
			require.NoError(t, err)
			
			event := createTestAuditEvent(t)
			
			err = service.StreamEvent(event)
			if tt.expectError {
				assert.Error(t, err)
				
				// Check if event was buffered for retry
				bufferedEvents := service.buffer.GetBufferedEvents("failure-test")
				if tt.expectRetry {
					assert.NotEmpty(t, bufferedEvents, "Event should be buffered for retry")
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPerformanceUnderLoad tests performance under high load
func TestPerformanceUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}
	
	const numEvents = 1000
	const concurrency = 10
	
	// Create a fast mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status": "ok"}`))
	}))
	defer server.Close()
	
	endpoint := &WebhookEndpoint{
		ID:      "performance-test",
		Name:    "Performance Test Endpoint",
		URL:     server.URL,
		Method:  "POST",
		Format:  "JSON",
		Active:  true,
		Timeout: time.Second * 30,
		RetryConfig: DefaultWebhookRetryConfig(),
	}
	
	bufferConfig := DefaultLocalBufferConfig()
	service := NewWebhookStreamingService(bufferConfig)
	
	err := service.AddEndpoint(endpoint)
	require.NoError(t, err)
	
	startTime := time.Now()
	
	// Stream events with controlled concurrency
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	
	for i := 0; i < numEvents; i++ {
		wg.Add(1)
		go func(eventNum int) {
			defer wg.Done()
			
			semaphore <- struct{}{} // Acquire
			defer func() { <-semaphore }() // Release
			
			event := createTestAuditEvent(t)
			event.ID = fmt.Sprintf("perf-event-%d", eventNum)
			
			err := service.StreamEvent(event)
			assert.NoError(t, err)
		}(i)
	}
	
	wg.Wait()
	duration := time.Since(startTime)
	
	// Calculate performance metrics
	eventsPerSecond := float64(numEvents) / duration.Seconds()
	
	t.Logf("Processed %d events in %v (%.2f events/second)", 
		numEvents, duration, eventsPerSecond)
	
	// Verify all events were processed successfully
	metrics := service.GetMetrics()
	assert.Equal(t, int64(numEvents), metrics.TotalDeliveries)
	assert.Equal(t, int64(numEvents), metrics.SuccessfulDeliveries)
	assert.Equal(t, int64(0), metrics.FailedDeliveries)
	
	// Performance assertion (adjust based on your requirements)
	assert.Greater(t, eventsPerSecond, 50.0, "Should process at least 50 events per second")
}

// Helper functions for creating test data

func createTestAuditEvent(t *testing.T) *models.AuditEvent {
	event, err := models.NewAuditEventBuilder().
		WithEventType(models.AuditEventTypeCommandExecute).
		WithSeverity(models.AuditSeverityInfo).
		WithMessage("Test audit event").
		WithUserContextFromUser(&models.User{
			ID:    "test-user",
			Email: "test@example.com",
			Name:  "Test User",
		}, "test-session", "192.168.1.1", "test-agent").
		WithClusterContext("test-cluster", "default", "pod", "test-pod", "test-context").
		WithCommandContext("get pods", "kubectl get pods", "safe", "success", "3 pods", "", 100).
		WithCorrelationID("test-correlation").
		WithService("test-service", "1.0.0").
		Build()
	
	require.NoError(t, err)
	return event
}

func createTestAuditEventWithType(t *testing.T, eventType models.AuditEventType) *models.AuditEvent {
	event := createTestAuditEvent(t)
	event.EventType = eventType
	return event
}

func createTestAuditEventWithSeverity(t *testing.T, severity models.AuditSeverity) *models.AuditEvent {
	event := createTestAuditEvent(t)
	event.Severity = severity
	return event
}

func createTestAuditEventWithUser(t *testing.T, userID string) *models.AuditEvent {
	event := createTestAuditEvent(t)
	event.UserContext.UserID = userID
	return event
}