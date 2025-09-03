package clients

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// APIHealthStatus represents the health status of the Kubernetes API
type APIHealthStatus struct {
	IsHealthy        bool      `json:"isHealthy"`
	LastCheck        time.Time `json:"lastCheck"`
	LastSuccessful   time.Time `json:"lastSuccessful"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	ResponseTime     time.Duration `json:"responseTime"`
	ErrorMessage     string    `json:"errorMessage,omitempty"`
	Version          string    `json:"version,omitempty"`
}

// APIHealthMonitor monitors the health of the Kubernetes API server
type APIHealthMonitor struct {
	client          KubernetesClient
	status          *APIHealthStatus
	statusMutex     sync.RWMutex
	checkInterval   time.Duration
	timeout         time.Duration
	maxFailures     int
	stopChan        chan struct{}
	notificationChan chan APIHealthNotification
	isRunning       bool
	runningMutex    sync.Mutex
}

// APIHealthNotification represents a health status change notification
type APIHealthNotification struct {
	PreviousStatus APIHealthStatus `json:"previousStatus"`
	CurrentStatus  APIHealthStatus `json:"currentStatus"`
	Timestamp      time.Time       `json:"timestamp"`
	Severity       models.EscalationLevel `json:"severity"`
	Message        string          `json:"message"`
}

// NewAPIHealthMonitor creates a new API health monitor
func NewAPIHealthMonitor(client KubernetesClient) *APIHealthMonitor {
	return &APIHealthMonitor{
		client:        client,
		status:        &APIHealthStatus{IsHealthy: true},
		checkInterval: 30 * time.Second,  // Check every 30 seconds
		timeout:       10 * time.Second,  // 10 second timeout per check
		maxFailures:   3,                 // Consider unhealthy after 3 consecutive failures
		stopChan:      make(chan struct{}),
		notificationChan: make(chan APIHealthNotification, 100),
	}
}

// SetCheckInterval configures the health check interval
func (hm *APIHealthMonitor) SetCheckInterval(interval time.Duration) {
	hm.checkInterval = interval
}

// SetTimeout configures the health check timeout
func (hm *APIHealthMonitor) SetTimeout(timeout time.Duration) {
	hm.timeout = timeout
}

// SetMaxFailures configures the maximum consecutive failures before marking as unhealthy
func (hm *APIHealthMonitor) SetMaxFailures(maxFailures int) {
	hm.maxFailures = maxFailures
}

// GetStatus returns the current API health status
func (hm *APIHealthMonitor) GetStatus() APIHealthStatus {
	hm.statusMutex.RLock()
	defer hm.statusMutex.RUnlock()
	return *hm.status
}

// IsHealthy returns whether the API is currently healthy
func (hm *APIHealthMonitor) IsHealthy() bool {
	hm.statusMutex.RLock()
	defer hm.statusMutex.RUnlock()
	return hm.status.IsHealthy
}

// Start begins continuous health monitoring
func (hm *APIHealthMonitor) Start(ctx context.Context) error {
	hm.runningMutex.Lock()
	defer hm.runningMutex.Unlock()
	
	if hm.isRunning {
		return fmt.Errorf("health monitor is already running")
	}
	
	hm.isRunning = true
	
	// Perform initial health check
	hm.performHealthCheck(ctx)
	
	// Start background monitoring
	go hm.monitoringLoop(ctx)
	
	return nil
}

// Stop stops the health monitoring
func (hm *APIHealthMonitor) Stop() {
	hm.runningMutex.Lock()
	defer hm.runningMutex.Unlock()
	
	if !hm.isRunning {
		return
	}
	
	close(hm.stopChan)
	hm.isRunning = false
}

// GetNotificationChannel returns the channel for health status notifications
func (hm *APIHealthMonitor) GetNotificationChannel() <-chan APIHealthNotification {
	return hm.notificationChan
}

// monitoringLoop runs the continuous health monitoring
func (hm *APIHealthMonitor) monitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(hm.checkInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-hm.stopChan:
			return
		case <-ticker.C:
			hm.performHealthCheck(ctx)
		}
	}
}

// performHealthCheck executes a health check against the Kubernetes API
func (hm *APIHealthMonitor) performHealthCheck(ctx context.Context) {
	hm.statusMutex.Lock()
	defer hm.statusMutex.Unlock()
	
	previousStatus := *hm.status
	now := time.Now()
	hm.status.LastCheck = now
	
	// Create timeout context for the health check
	checkCtx, cancel := context.WithTimeout(ctx, hm.timeout)
	defer cancel()
	
	// Perform the health check by calling kubectl version
	startTime := time.Now()
	version, err := hm.client.GetVersion(checkCtx)
	responseTime := time.Since(startTime)
	
	hm.status.ResponseTime = responseTime
	
	if err != nil {
		// Health check failed
		hm.status.ConsecutiveFailures++
		hm.status.ErrorMessage = err.Error()
		
		// Mark as unhealthy if we've exceeded max failures
		if hm.status.ConsecutiveFailures >= hm.maxFailures {
			hm.status.IsHealthy = false
		}
	} else {
		// Health check succeeded
		hm.status.ConsecutiveFailures = 0
		hm.status.ErrorMessage = ""
		hm.status.LastSuccessful = now
		hm.status.Version = version
		hm.status.IsHealthy = true
	}
	
	// Send notification if status changed
	if previousStatus.IsHealthy != hm.status.IsHealthy {
		hm.sendNotification(previousStatus, *hm.status)
	}
}

// sendNotification sends a health status change notification
func (hm *APIHealthMonitor) sendNotification(previousStatus, currentStatus APIHealthStatus) {
	var severity models.EscalationLevel
	var message string
	
	if currentStatus.IsHealthy && !previousStatus.IsHealthy {
		// Recovered
		severity = models.EscalationLevelLow
		message = "Kubernetes API has recovered and is now healthy"
	} else if !currentStatus.IsHealthy && previousStatus.IsHealthy {
		// Became unhealthy
		if currentStatus.ConsecutiveFailures >= hm.maxFailures {
			severity = models.EscalationLevelHigh
			message = fmt.Sprintf("Kubernetes API is unhealthy - %d consecutive failures", currentStatus.ConsecutiveFailures)
		} else {
			severity = models.EscalationLevelMedium
			message = fmt.Sprintf("Kubernetes API connectivity issues detected - %d failures", currentStatus.ConsecutiveFailures)
		}
	}
	
	notification := APIHealthNotification{
		PreviousStatus: previousStatus,
		CurrentStatus:  currentStatus,
		Timestamp:      time.Now(),
		Severity:       severity,
		Message:        message,
	}
	
	// Non-blocking send to notification channel
	select {
	case hm.notificationChan <- notification:
	default:
		// Channel is full, skip this notification
	}
}

// GetHealthReport returns a formatted health report
func (hm *APIHealthMonitor) GetHealthReport() string {
	status := hm.GetStatus()
	
	var report string
	if status.IsHealthy {
		report = fmt.Sprintf("✅ **Kubernetes API Health: HEALTHY**\n\n")
		report += fmt.Sprintf("**Last Check:** %s\n", status.LastCheck.Format(time.RFC3339))
		report += fmt.Sprintf("**Response Time:** %v\n", status.ResponseTime)
		if status.Version != "" {
			report += fmt.Sprintf("**Version:** %s\n", status.Version)
		}
	} else {
		report = fmt.Sprintf("❌ **Kubernetes API Health: UNHEALTHY**\n\n")
		report += fmt.Sprintf("**Last Check:** %s\n", status.LastCheck.Format(time.RFC3339))
		report += fmt.Sprintf("**Last Successful:** %s\n", status.LastSuccessful.Format(time.RFC3339))
		report += fmt.Sprintf("**Consecutive Failures:** %d\n", status.ConsecutiveFailures)
		if status.ErrorMessage != "" {
			report += fmt.Sprintf("**Error:** %s\n", status.ErrorMessage)
		}
		
		// Add troubleshooting suggestions
		report += "\n🔧 **Troubleshooting Steps:**\n"
		report += "1. Check network connectivity to the cluster\n"
		report += "2. Verify kubeconfig settings\n"
		report += "3. Check cluster status with your cloud provider\n"
		report += "4. Confirm authentication credentials are valid\n"
	}
	
	return report
}

// GetDegradedModeRecommendations returns recommendations for operating in degraded mode
func (hm *APIHealthMonitor) GetDegradedModeRecommendations() []string {
	if hm.IsHealthy() {
		return []string{}
	}
	
	recommendations := []string{
		"Use cached results when possible for read-only operations",
		"Defer write operations until API connectivity is restored",
		"Check local kubeconfig and authentication settings",
		"Consider switching to a backup cluster if available",
		"Monitor health status and retry periodically",
	}
	
	return recommendations
}

// WaitForHealthy waits until the API becomes healthy or the context is cancelled
func (hm *APIHealthMonitor) WaitForHealthy(ctx context.Context, maxWait time.Duration) error {
	if hm.IsHealthy() {
		return nil
	}
	
	waitCtx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timed out waiting for API to become healthy")
		case <-ticker.C:
			if hm.IsHealthy() {
				return nil
			}
		case notification := <-hm.notificationChan:
			if notification.CurrentStatus.IsHealthy {
				return nil
			}
		}
	}
}