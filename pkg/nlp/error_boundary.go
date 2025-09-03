package nlp

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ErrorBoundaryStats tracks error boundary statistics
type ErrorBoundaryStats struct {
	TotalCalls    int64     `json:"totalCalls"`
	PanicsRecovered int64   `json:"panicsRecovered"`
	ErrorsCaught  int64     `json:"errorsCaught"`
	LastPanic     time.Time `json:"lastPanic,omitempty"`
	LastError     time.Time `json:"lastError,omitempty"`
}

// ErrorBoundary provides panic recovery and error handling for critical functions
type ErrorBoundary struct {
	name  string
	stats ErrorBoundaryStats
}

// NewErrorBoundary creates a new error boundary
func NewErrorBoundary(name string) *ErrorBoundary {
	return &ErrorBoundary{
		name: name,
	}
}

// SafeExecute executes a function with panic recovery and error boundary protection
func (eb *ErrorBoundary) SafeExecute(fn func() error) error {
	atomic.AddInt64(&eb.stats.TotalCalls, 1)
	
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&eb.stats.PanicsRecovered, 1)
			eb.stats.LastPanic = time.Now()
			
			// Log the panic with stack trace
			stackTrace := debug.Stack()
			fmt.Printf("PANIC RECOVERED in %s: %v\nStack trace:\n%s\n", eb.name, r, stackTrace)
			
			// You could add more sophisticated logging here
			// For now, we just print to stdout
		}
	}()
	
	err := fn()
	if err != nil {
		atomic.AddInt64(&eb.stats.ErrorsCaught, 1)
		eb.stats.LastError = time.Now()
	}
	
	return err
}

// SafeExecuteWithResult executes a function with panic recovery and returns both result and error
func (eb *ErrorBoundary) SafeExecuteWithResult(fn func() (interface{}, error)) (result interface{}, err error) {
	atomic.AddInt64(&eb.stats.TotalCalls, 1)
	
	defer func() {
		if r := recover(); r != nil {
			atomic.AddInt64(&eb.stats.PanicsRecovered, 1)
			eb.stats.LastPanic = time.Now()
			
			// Log the panic with stack trace
			stackTrace := debug.Stack()
			fmt.Printf("PANIC RECOVERED in %s: %v\nStack trace:\n%s\n", eb.name, r, stackTrace)
			
			// Override result and error for panic case
			result = nil
			err = fmt.Errorf("panic recovered in %s: %v", eb.name, r)
		}
	}()
	
	result, err = fn()
	if err != nil {
		atomic.AddInt64(&eb.stats.ErrorsCaught, 1)
		eb.stats.LastError = time.Now()
	}
	
	return result, err
}

// GetStats returns error boundary statistics
func (eb *ErrorBoundary) GetStats() ErrorBoundaryStats {
	return ErrorBoundaryStats{
		TotalCalls:      atomic.LoadInt64(&eb.stats.TotalCalls),
		PanicsRecovered: atomic.LoadInt64(&eb.stats.PanicsRecovered),
		ErrorsCaught:    atomic.LoadInt64(&eb.stats.ErrorsCaught),
		LastPanic:       eb.stats.LastPanic,
		LastError:       eb.stats.LastError,
	}
}

// GetHealthReport returns a formatted health report
func (eb *ErrorBoundary) GetHealthReport() string {
	stats := eb.GetStats()
	
	var healthIcon string
	if stats.PanicsRecovered == 0 {
		healthIcon = "✅"
	} else if stats.PanicsRecovered < 5 {
		healthIcon = "⚠️"
	} else {
		healthIcon = "❌"
	}
	
	report := fmt.Sprintf("%s **Error Boundary '%s'**\n", healthIcon, eb.name)
	report += fmt.Sprintf("**Total Calls:** %d\n", stats.TotalCalls)
	report += fmt.Sprintf("**Panics Recovered:** %d\n", stats.PanicsRecovered)
	report += fmt.Sprintf("**Errors Caught:** %d\n", stats.ErrorsCaught)
	
	if !stats.LastPanic.IsZero() {
		report += fmt.Sprintf("**Last Panic:** %s\n", stats.LastPanic.Format(time.RFC3339))
	}
	
	if !stats.LastError.IsZero() {
		report += fmt.Sprintf("**Last Error:** %s\n", stats.LastError.Format(time.RFC3339))
	}
	
	return report
}

// SafeNLPProcessor provides safe wrappers for NLP operations
type SafeNLPProcessor struct {
	contextResolver *ContextResolver
	suggestionEngine *SuggestionEngine
	errorHandler    *ErrorHandler
	
	// Error boundaries for different operations
	translationBoundary  *ErrorBoundary
	contextBoundary      *ErrorBoundary
	suggestionBoundary   *ErrorBoundary
	errorHandlingBoundary *ErrorBoundary
}

// NewSafeNLPProcessor creates a new safe NLP processor with error boundaries
func NewSafeNLPProcessor() *SafeNLPProcessor {
	return &SafeNLPProcessor{
		contextResolver:       NewContextResolver(),
		suggestionEngine:      NewSuggestionEngine(),
		errorHandler:         NewErrorHandler(),
		translationBoundary:  NewErrorBoundary("nlp-translation"),
		contextBoundary:      NewErrorBoundary("nlp-context"),
		suggestionBoundary:   NewErrorBoundary("nlp-suggestion"),
		errorHandlingBoundary: NewErrorBoundary("nlp-error-handling"),
	}
}

// SafeTranslateCommand safely translates natural language to kubectl command
func (snp *SafeNLPProcessor) SafeTranslateCommand(ctx context.Context, input string, sessionContext *models.SessionContext) (*models.KubernetesCommand, error) {
	result, err := snp.translationBoundary.SafeExecuteWithResult(func() (interface{}, error) {
		// This would call your actual translation logic
		// For now, we'll create a mock implementation
		if input == "" {
			return nil, fmt.Errorf("empty input provided")
		}
		
		// Mock translation logic - in real implementation this would call your translator
		command := models.NewKubernetesCommand(
			"default-session",
			input,
			fmt.Sprintf("kubectl get pods # translated from: %s", input),
			models.RiskLevelSafe,
		)
		
		return command, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("translation error boundary caught: %w", err)
	}
	
	if command, ok := result.(*models.KubernetesCommand); ok {
		return command, nil
	}
	
	return nil, fmt.Errorf("unexpected result type from translation")
}

// SafeResolveContext safely resolves context references
func (snp *SafeNLPProcessor) SafeResolveContext(ctx context.Context, input string, sessionContext *models.SessionContext) (*models.SessionContext, error) {
	result, err := snp.contextBoundary.SafeExecuteWithResult(func() (interface{}, error) {
		if sessionContext == nil {
			return &models.SessionContext{
				ReferenceableItems: []models.ReferenceItem{},
				LastCommandOutput:  []models.ContextKubernetesResource{},
				NamedEntities:     []models.ContextEntity{},
				ContextExpiry:     time.Now().Add(24 * time.Hour),
				LastCommandID:     "safe-default",
			}, nil
		}
		
		// Use the context resolver safely
		resolved, _, resolveErr := snp.contextResolver.ResolveReferences(input, sessionContext)
		if resolveErr != nil {
			return nil, resolveErr
		}
		return resolved, nil
	})
	
	if err != nil {
		return nil, fmt.Errorf("context resolution error boundary caught: %w", err)
	}
	
	if context, ok := result.(*models.SessionContext); ok {
		return context, nil
	}
	
	return nil, fmt.Errorf("unexpected result type from context resolution")
}

// SafeGetSuggestions safely generates command suggestions
func (snp *SafeNLPProcessor) SafeGetSuggestions(input string, errorType models.ErrorType, sessionContext *models.SessionContext) []string {
	result, err := snp.suggestionBoundary.SafeExecuteWithResult(func() (interface{}, error) {
		suggestions := snp.suggestionEngine.SuggestCorrections(input, errorType)
		return suggestions, nil
	})
	
	if err != nil {
		// Return fallback suggestions
		return []string{
			"get pods",
			"get services", 
			"get deployments",
		}
	}
	
	if suggestions, ok := result.([]string); ok {
		return suggestions
	}
	
	// Return fallback suggestions if type assertion fails
	return []string{
		"get pods",
		"get services",
		"get deployments",
	}
}

// SafeFormatError safely formats error messages
func (snp *SafeNLPProcessor) SafeFormatError(kubectlError *models.KubectlError, sessionContext *models.SessionContext) string {
	result, err := snp.errorHandlingBoundary.SafeExecuteWithResult(func() (interface{}, error) {
		formatted := snp.errorHandler.FormatError(kubectlError, sessionContext)
		return formatted, nil
	})
	
	if err != nil {
		// Return a safe fallback error message
		if kubectlError != nil {
			return fmt.Sprintf("❌ **Error:** %s\n\n💡 **Suggestion:** Try rephrasing your command or check the resource name.", kubectlError.Message)
		}
		return "❌ **An unexpected error occurred.** Please try again with a simpler command."
	}
	
	if formatted, ok := result.(string); ok {
		return formatted
	}
	
	// Return fallback if type assertion fails
	return "❌ **Error formatting failed.** Please try again."
}

// GetAllStats returns statistics for all error boundaries
func (snp *SafeNLPProcessor) GetAllStats() map[string]ErrorBoundaryStats {
	return map[string]ErrorBoundaryStats{
		"translation":    snp.translationBoundary.GetStats(),
		"context":        snp.contextBoundary.GetStats(),
		"suggestion":     snp.suggestionBoundary.GetStats(),
		"error-handling": snp.errorHandlingBoundary.GetStats(),
	}
}

// GetHealthReport returns a comprehensive health report for all error boundaries
func (snp *SafeNLPProcessor) GetHealthReport() string {
	var report string
	
	report += "🛡️ **NLP Error Boundaries Health Report**\n\n"
	report += snp.translationBoundary.GetHealthReport() + "\n"
	report += snp.contextBoundary.GetHealthReport() + "\n"
	report += snp.suggestionBoundary.GetHealthReport() + "\n"
	report += snp.errorHandlingBoundary.GetHealthReport() + "\n"
	
	// Calculate overall health
	stats := snp.GetAllStats()
	totalPanics := int64(0)
	totalCalls := int64(0)
	
	for _, stat := range stats {
		totalPanics += stat.PanicsRecovered
		totalCalls += stat.TotalCalls
	}
	
	var healthStatus string
	if totalPanics == 0 {
		healthStatus = "✅ HEALTHY"
	} else if totalPanics < 10 {
		healthStatus = "⚠️ DEGRADED"
	} else {
		healthStatus = "❌ CRITICAL"
	}
	
	report += fmt.Sprintf("**Overall Status:** %s\n", healthStatus)
	report += fmt.Sprintf("**Total Operations:** %d\n", totalCalls)
	report += fmt.Sprintf("**Total Panics Recovered:** %d\n", totalPanics)
	
	if totalCalls > 0 {
		successRate := float64(totalCalls-totalPanics) / float64(totalCalls) * 100
		report += fmt.Sprintf("**Success Rate:** %.2f%%\n", successRate)
	}
	
	return report
}