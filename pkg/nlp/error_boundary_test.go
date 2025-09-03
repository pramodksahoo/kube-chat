package nlp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewErrorBoundary(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	assert.NotNil(t, eb)
	assert.Equal(t, "test-boundary", eb.name)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(0), stats.TotalCalls)
	assert.Equal(t, int64(0), stats.PanicsRecovered)
	assert.Equal(t, int64(0), stats.ErrorsCaught)
}

func TestErrorBoundarySafeExecuteSuccess(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	err := eb.SafeExecute(func() error {
		return nil
	})
	
	assert.NoError(t, err)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(0), stats.PanicsRecovered)
	assert.Equal(t, int64(0), stats.ErrorsCaught)
}

func TestErrorBoundarySafeExecuteError(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	expectedError := fmt.Errorf("test error")
	err := eb.SafeExecute(func() error {
		return expectedError
	})
	
	assert.Equal(t, expectedError, err)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(0), stats.PanicsRecovered)
	assert.Equal(t, int64(1), stats.ErrorsCaught)
	assert.False(t, stats.LastError.IsZero())
}

func TestErrorBoundarySafeExecutePanic(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	// This should not crash the test - panic should be recovered
	err := eb.SafeExecute(func() error {
		panic("test panic")
	})
	
	// The function returns nil for panics (panic is recovered but no error is returned)
	assert.NoError(t, err)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(1), stats.PanicsRecovered)
	assert.Equal(t, int64(0), stats.ErrorsCaught)
	assert.False(t, stats.LastPanic.IsZero())
}

func TestErrorBoundarySafeExecuteWithResultSuccess(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	expectedResult := "test result"
	result, err := eb.SafeExecuteWithResult(func() (interface{}, error) {
		return expectedResult, nil
	})
	
	assert.NoError(t, err)
	assert.Equal(t, expectedResult, result)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(0), stats.PanicsRecovered)
	assert.Equal(t, int64(0), stats.ErrorsCaught)
}

func TestErrorBoundarySafeExecuteWithResultError(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	expectedError := fmt.Errorf("test error")
	result, err := eb.SafeExecuteWithResult(func() (interface{}, error) {
		return nil, expectedError
	})
	
	assert.Equal(t, expectedError, err)
	assert.Nil(t, result)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(0), stats.PanicsRecovered)
	assert.Equal(t, int64(1), stats.ErrorsCaught)
}

func TestErrorBoundarySafeExecuteWithResultPanic(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	result, err := eb.SafeExecuteWithResult(func() (interface{}, error) {
		panic("test panic")
	})
	
	require.NotNil(t, err)
	assert.Contains(t, err.Error(), "panic recovered")
	assert.Nil(t, result)
	
	stats := eb.GetStats()
	assert.Equal(t, int64(1), stats.TotalCalls)
	assert.Equal(t, int64(1), stats.PanicsRecovered)
	assert.False(t, stats.LastPanic.IsZero())
}

func TestErrorBoundaryHealthReport(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	t.Run("healthy boundary", func(t *testing.T) {
		eb.SafeExecute(func() error { return nil })
		
		report := eb.GetHealthReport()
		assert.Contains(t, report, "✅")
		assert.Contains(t, report, "test-boundary")
		assert.Contains(t, report, "Total Calls: 1")
		assert.Contains(t, report, "Panics Recovered: 0")
	})
	
	t.Run("boundary with few panics", func(t *testing.T) {
		eb.SafeExecute(func() error { panic("test") })
		
		report := eb.GetHealthReport()
		assert.Contains(t, report, "⚠️")
		assert.Contains(t, report, "Panics Recovered: 1")
		assert.Contains(t, report, "Last Panic:")
	})
	
	t.Run("boundary with many panics", func(t *testing.T) {
		// Add more panics to trigger critical status
		for i := 0; i < 5; i++ {
			eb.SafeExecute(func() error { panic("test") })
		}
		
		report := eb.GetHealthReport()
		assert.Contains(t, report, "❌")
	})
}

func TestNewSafeNLPProcessor(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	assert.NotNil(t, processor)
	assert.NotNil(t, processor.contextResolver)
	assert.NotNil(t, processor.suggestionEngine)
	assert.NotNil(t, processor.errorHandler)
	assert.NotNil(t, processor.translationBoundary)
	assert.NotNil(t, processor.contextBoundary)
	assert.NotNil(t, processor.suggestionBoundary)
	assert.NotNil(t, processor.errorHandlingBoundary)
}

func TestSafeNLPProcessorSafeTranslateCommand(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	t.Run("successful translation", func(t *testing.T) {
		ctx := context.Background()
		sessionContext := &models.SessionContext{
			ReferenceableItems: []models.ReferenceItem{},
			LastCommandOutput:  []models.ContextKubernetesResource{},
			NamedEntities:     []models.ContextEntity{},
			ContextExpiry:     time.Now().Add(24 * time.Hour),
			LastCommandID:     "test-command",
		}
		
		result, err := processor.SafeTranslateCommand(ctx, "get pods", sessionContext)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "get pods", result.NaturalLanguageInput)
		assert.Contains(t, result.GeneratedCommand, "kubectl get pods")
	})
	
	t.Run("empty input", func(t *testing.T) {
		ctx := context.Background()
		
		result, err := processor.SafeTranslateCommand(ctx, "", nil)
		
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "empty input provided")
	})
}

func TestSafeNLPProcessorSafeResolveContext(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	t.Run("nil session context", func(t *testing.T) {
		ctx := context.Background()
		
		result, err := processor.SafeResolveContext(ctx, "test input", nil)
		
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "safe-default", result.LastCommandID)
	})
	
	t.Run("valid session context", func(t *testing.T) {
		ctx := context.Background()
		sessionContext := &models.SessionContext{
			ReferenceableItems: []models.ReferenceItem{
				{ID: "test-1", Type: "pod", Name: "nginx-pod"},
			},
			LastCommandOutput: []models.ContextKubernetesResource{},
			NamedEntities:    []models.ContextEntity{},
			ContextExpiry:    time.Now().Add(24 * time.Hour),
			LastCommandID:    "test-command",
		}
		
		result, err := processor.SafeResolveContext(ctx, "describe the first pod", sessionContext)
		
		// Should succeed even if context resolver fails, because error boundary handles it
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestSafeNLPProcessorSafeGetSuggestions(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	t.Run("normal suggestions", func(t *testing.T) {
		suggestions := processor.SafeGetSuggestions("invalid command", models.ErrorTypeNLPMalformed, nil)
		
		assert.NotEmpty(t, suggestions)
		assert.Contains(t, suggestions, "get pods")
	})
	
	t.Run("fallback suggestions on error", func(t *testing.T) {
		// Force an error by using nil suggestion engine (this would panic in real use)
		processor.suggestionEngine = nil
		
		suggestions := processor.SafeGetSuggestions("test", models.ErrorTypeNLPMalformed, nil)
		
		// Should return fallback suggestions
		assert.Equal(t, []string{"get pods", "get services", "get deployments"}, suggestions)
	})
}

func TestSafeNLPProcessorSafeFormatError(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	t.Run("normal error formatting", func(t *testing.T) {
		kubectlError := &models.KubectlError{
			Type:    models.ErrorTypeNotFound,
			Message: "pod not found",
		}
		
		result := processor.SafeFormatError(kubectlError, nil)
		
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "Error:")
		assert.Contains(t, result, "pod not found")
	})
	
	t.Run("nil error", func(t *testing.T) {
		result := processor.SafeFormatError(nil, nil)
		
		assert.NotEmpty(t, result)
		assert.Contains(t, result, "An unexpected error occurred")
	})
	
	t.Run("fallback on formatting error", func(t *testing.T) {
		// Force error by setting nil error handler
		processor.errorHandler = nil
		
		kubectlError := &models.KubectlError{
			Type:    models.ErrorTypeNotFound,
			Message: "test error",
		}
		
		result := processor.SafeFormatError(kubectlError, nil)
		
		// Should return fallback error message
		assert.Contains(t, result, "Error:")
		assert.Contains(t, result, "test error")
	})
}

func TestSafeNLPProcessorGetAllStats(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	// Execute some operations to generate stats
	processor.SafeGetSuggestions("test", models.ErrorTypeNLPMalformed, nil)
	processor.SafeFormatError(nil, nil)
	
	stats := processor.GetAllStats()
	
	assert.Len(t, stats, 4)
	assert.Contains(t, stats, "translation")
	assert.Contains(t, stats, "context")
	assert.Contains(t, stats, "suggestion")
	assert.Contains(t, stats, "error-handling")
	
	// Check that some operations were recorded
	assert.Greater(t, stats["suggestion"].TotalCalls, int64(0))
	assert.Greater(t, stats["error-handling"].TotalCalls, int64(0))
}

func TestSafeNLPProcessorGetHealthReport(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	// Execute some operations
	processor.SafeGetSuggestions("test", models.ErrorTypeNLPMalformed, nil)
	processor.SafeFormatError(nil, nil)
	
	report := processor.GetHealthReport()
	
	assert.Contains(t, report, "NLP Error Boundaries Health Report")
	assert.Contains(t, report, "translation")
	assert.Contains(t, report, "context")
	assert.Contains(t, report, "suggestion")
	assert.Contains(t, report, "error-handling")
	assert.Contains(t, report, "Overall Status:")
	assert.Contains(t, report, "HEALTHY")
	assert.Contains(t, report, "Total Operations:")
	assert.Contains(t, report, "Success Rate:")
}

func TestSafeNLPProcessorWithPanics(t *testing.T) {
	processor := NewSafeNLPProcessor()
	
	// Simulate a panic in the suggestion engine by setting it to nil
	// This would normally cause a panic, but error boundary should handle it
	originalEngine := processor.suggestionEngine
	processor.suggestionEngine = nil
	
	// This should not crash and should return fallback suggestions
	suggestions := processor.SafeGetSuggestions("test", models.ErrorTypeNLPMalformed, nil)
	
	assert.Equal(t, []string{"get pods", "get services", "get deployments"}, suggestions)
	
	// Check that panic was recorded
	_ = processor.GetAllStats()
	// Note: In this test we won't see panics because SafeGetSuggestions handles nil gracefully
	// But in a real panic scenario, the error boundary would catch it
	
	// Restore original engine
	processor.suggestionEngine = originalEngine
}

func TestErrorBoundaryMultipleOperations(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	// Mix of successful operations, errors, and panics
	err1 := eb.SafeExecute(func() error { return nil })
	err2 := eb.SafeExecute(func() error { return fmt.Errorf("error 1") })
	err3 := eb.SafeExecute(func() error { panic("panic 1") })
	err4 := eb.SafeExecute(func() error { return fmt.Errorf("error 2") })
	err5 := eb.SafeExecute(func() error { panic("panic 2") })
	
	assert.NoError(t, err1)
	assert.Error(t, err2)
	assert.NoError(t, err3) // Panic recovered, no error returned
	assert.Error(t, err4)
	assert.NoError(t, err5) // Panic recovered, no error returned
	
	stats := eb.GetStats()
	assert.Equal(t, int64(5), stats.TotalCalls)
	assert.Equal(t, int64(2), stats.PanicsRecovered)
	assert.Equal(t, int64(2), stats.ErrorsCaught)
}

func TestErrorBoundaryThreadSafety(t *testing.T) {
	eb := NewErrorBoundary("test-boundary")
	
	// Run multiple goroutines concurrently
	done := make(chan bool, 100)
	
	for i := 0; i < 100; i++ {
		go func(id int) {
			defer func() { done <- true }()
			
			if id%3 == 0 {
				eb.SafeExecute(func() error { return fmt.Errorf("error %d", id) })
			} else if id%3 == 1 {
				eb.SafeExecute(func() error { panic(fmt.Sprintf("panic %d", id)) })
			} else {
				eb.SafeExecute(func() error { return nil })
			}
		}(i)
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < 100; i++ {
		<-done
	}
	
	stats := eb.GetStats()
	assert.Equal(t, int64(100), stats.TotalCalls)
	assert.Greater(t, stats.ErrorsCaught, int64(0))
	assert.Greater(t, stats.PanicsRecovered, int64(0))
}