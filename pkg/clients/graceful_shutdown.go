package clients

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// ShutdownHook represents a function to call during graceful shutdown
type ShutdownHook func(context.Context) error

// ShutdownManager manages graceful shutdown of services
type ShutdownManager struct {
	hooks        []ShutdownHook
	hookNames    []string
	timeout      time.Duration
	mutex        sync.RWMutex
	isShuttingDown bool
}

// NewShutdownManager creates a new graceful shutdown manager
func NewShutdownManager() *ShutdownManager {
	return &ShutdownManager{
		hooks:     make([]ShutdownHook, 0),
		hookNames: make([]string, 0),
		timeout:   30 * time.Second, // Default 30 second timeout
	}
}

// SetTimeout sets the shutdown timeout
func (sm *ShutdownManager) SetTimeout(timeout time.Duration) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	sm.timeout = timeout
}

// RegisterHook registers a shutdown hook with a descriptive name
func (sm *ShutdownManager) RegisterHook(name string, hook ShutdownHook) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	sm.hooks = append(sm.hooks, hook)
	sm.hookNames = append(sm.hookNames, name)
}

// IsShuttingDown returns whether the shutdown process has started
func (sm *ShutdownManager) IsShuttingDown() bool {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return sm.isShuttingDown
}

// Shutdown executes all registered shutdown hooks
func (sm *ShutdownManager) Shutdown(ctx context.Context) error {
	sm.mutex.Lock()
	if sm.isShuttingDown {
		sm.mutex.Unlock()
		return fmt.Errorf("shutdown already in progress")
	}
	sm.isShuttingDown = true
	
	hooks := make([]ShutdownHook, len(sm.hooks))
	names := make([]string, len(sm.hookNames))
	copy(hooks, sm.hooks)
	copy(names, sm.hookNames)
	sm.mutex.Unlock()
	
	fmt.Printf("Graceful shutdown initiated with %d hooks\n", len(hooks))
	
	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, sm.timeout)
	defer cancel()
	
	// Execute hooks in reverse order (LIFO)
	var errors []error
	for i := len(hooks) - 1; i >= 0; i-- {
		hookName := names[i]
		hook := hooks[i]
		
		fmt.Printf("Executing shutdown hook: %s\n", hookName)
		
		hookErr := make(chan error, 1)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					hookErr <- fmt.Errorf("panic in shutdown hook %s: %v", hookName, r)
				}
			}()
			hookErr <- hook(timeoutCtx)
		}()
		
		select {
		case err := <-hookErr:
			if err != nil {
				fmt.Printf("Shutdown hook %s failed: %v\n", hookName, err)
				errors = append(errors, fmt.Errorf("hook %s: %w", hookName, err))
			} else {
				fmt.Printf("Shutdown hook %s completed successfully\n", hookName)
			}
		case <-timeoutCtx.Done():
			fmt.Printf("Shutdown hook %s timed out\n", hookName)
			errors = append(errors, fmt.Errorf("hook %s: timeout", hookName))
		}
	}
	
	if len(errors) > 0 {
		return fmt.Errorf("shutdown completed with %d errors: %v", len(errors), errors)
	}
	
	fmt.Printf("Graceful shutdown completed successfully\n")
	return nil
}

// WaitForSignal waits for shutdown signals and executes graceful shutdown
func (sm *ShutdownManager) WaitForSignal() error {
	// Create signal channel
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	
	// Wait for signal
	sig := <-signalChan
	fmt.Printf("Received signal: %v\n", sig)
	
	// Execute graceful shutdown
	ctx := context.Background()
	return sm.Shutdown(ctx)
}

// ServiceHealthMonitor monitors service health and triggers shutdown if needed
type ServiceHealthMonitor struct {
	services        map[string]HealthChecker
	checkInterval   time.Duration
	unhealthyThreshold int
	shutdownManager *ShutdownManager
	ctx            context.Context
	cancel         context.CancelFunc
	isRunning      bool
	mutex          sync.RWMutex
}

// HealthChecker interface for services that can be health checked
type HealthChecker interface {
	IsHealthy() bool
	GetHealthReport() string
}

// NewServiceHealthMonitor creates a new service health monitor
func NewServiceHealthMonitor(shutdownManager *ShutdownManager) *ServiceHealthMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &ServiceHealthMonitor{
		services:           make(map[string]HealthChecker),
		checkInterval:      30 * time.Second, // Check every 30 seconds
		unhealthyThreshold: 3,                // Shutdown after 3 consecutive unhealthy checks
		shutdownManager:    shutdownManager,
		ctx:               ctx,
		cancel:            cancel,
	}
}

// RegisterService registers a service for health monitoring
func (shm *ServiceHealthMonitor) RegisterService(name string, service HealthChecker) {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()
	shm.services[name] = service
}

// Start starts the health monitoring
func (shm *ServiceHealthMonitor) Start() error {
	shm.mutex.Lock()
	if shm.isRunning {
		shm.mutex.Unlock()
		return fmt.Errorf("health monitor is already running")
	}
	shm.isRunning = true
	shm.mutex.Unlock()
	
	go shm.monitorLoop()
	return nil
}

// Stop stops the health monitoring
func (shm *ServiceHealthMonitor) Stop() {
	shm.mutex.Lock()
	defer shm.mutex.Unlock()
	
	if !shm.isRunning {
		return
	}
	
	shm.cancel()
	shm.isRunning = false
}

// monitorLoop runs the continuous health monitoring
func (shm *ServiceHealthMonitor) monitorLoop() {
	ticker := time.NewTicker(shm.checkInterval)
	defer ticker.Stop()
	
	unhealthyCounts := make(map[string]int)
	
	for {
		select {
		case <-shm.ctx.Done():
			return
		case <-ticker.C:
			shm.mutex.RLock()
			services := make(map[string]HealthChecker)
			for name, service := range shm.services {
				services[name] = service
			}
			shm.mutex.RUnlock()
			
			criticalFailures := false
			
			for name, service := range services {
				if service.IsHealthy() {
					unhealthyCounts[name] = 0
				} else {
					unhealthyCounts[name]++
					fmt.Printf("Service %s is unhealthy (count: %d)\n", name, unhealthyCounts[name])
					
					if unhealthyCounts[name] >= shm.unhealthyThreshold {
						fmt.Printf("Service %s has been unhealthy for %d consecutive checks - triggering shutdown\n", name, unhealthyCounts[name])
						criticalFailures = true
					}
				}
			}
			
			if criticalFailures {
				fmt.Printf("Critical service failures detected - initiating graceful shutdown\n")
				go func() {
					if err := shm.shutdownManager.Shutdown(context.Background()); err != nil {
						fmt.Printf("Shutdown failed: %v\n", err)
						os.Exit(1)
					}
					os.Exit(0)
				}()
				return
			}
		}
	}
}

// GetHealthReport returns a comprehensive health report for all monitored services
func (shm *ServiceHealthMonitor) GetHealthReport() string {
	shm.mutex.RLock()
	defer shm.mutex.RUnlock()
	
	if len(shm.services) == 0 {
		return "No services registered for health monitoring\n"
	}
	
	var report string
	healthyCount := 0
	
	report += "🔍 **Service Health Monitor Report**\n\n"
	
	for name, service := range shm.services {
		if service.IsHealthy() {
			report += fmt.Sprintf("✅ **%s:** HEALTHY\n", name)
			healthyCount++
		} else {
			report += fmt.Sprintf("❌ **%s:** UNHEALTHY\n", name)
		}
		
		// Add detailed health report if available
		if healthReport := service.GetHealthReport(); healthReport != "" {
			// Indent the health report
			indentedReport := ""
			for _, line := range []string{healthReport} {
				indentedReport += "    " + line + "\n"
			}
			report += indentedReport + "\n"
		}
	}
	
	report += fmt.Sprintf("**Summary:** %d/%d services healthy\n", healthyCount, len(shm.services))
	
	if healthyCount < len(shm.services) {
		report += "⚠️ **Some services are unhealthy - monitoring for shutdown conditions**\n"
	}
	
	return report
}

// CreateDefaultShutdownManager creates a shutdown manager with common hooks
func CreateDefaultShutdownManager(kubernetesClient KubernetesClient, healthMonitor *APIHealthMonitor) *ShutdownManager {
	sm := NewShutdownManager()
	
	// Register health monitor shutdown hook
	if healthMonitor != nil {
		sm.RegisterHook("api-health-monitor", func(ctx context.Context) error {
			fmt.Println("Stopping API health monitor...")
			healthMonitor.Stop()
			return nil
		})
	}
	
	// Register kubernetes client cleanup hook
	if kubectlClient, ok := kubernetesClient.(*kubectlClient); ok {
		sm.RegisterHook("kubernetes-client-cleanup", func(ctx context.Context) error {
			fmt.Println("Cleaning up Kubernetes client...")
			kubectlClient.StopHealthMonitoring()
			kubectlClient.ClearCache()
			return nil
		})
	}
	
	// Register final cleanup hook
	sm.RegisterHook("final-cleanup", func(ctx context.Context) error {
		fmt.Println("Performing final cleanup...")
		// Any final cleanup operations
		return nil
	})
	
	return sm
}