package nlp

import (
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewContextResolver(t *testing.T) {
	resolver := NewContextResolver()
	
	assert.NotNil(t, resolver)
	assert.NotNil(t, resolver.ordinalPattern)
	assert.NotNil(t, resolver.demonstrativePattern)
	assert.NotNil(t, resolver.pronounPattern)
	assert.NotNil(t, resolver.entityExtractor)
}

func TestContextResolver_ResolveReferences(t *testing.T) {
	resolver := NewContextResolver()
	now := time.Now()
	
	// Create test session context
	sessionContext := models.NewSessionContext()
	
	// Add test reference items
	testItems := []models.ReferenceItem{
		{
			ID:        "pod-1",
			Type:      "pod",
			Name:      "nginx-deployment-1",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
		{
			ID:        "pod-2",
			Type:      "pod",
			Name:      "nginx-deployment-2",
			Namespace: "default",
			Position:  2,
			LastSeen:  now.Add(1 * time.Minute),
		},
		{
			ID:        "svc-1",
			Type:      "service",
			Name:      "nginx-service",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name                 string
		input               string
		sessionContext      *models.SessionContext
		wantResolvedInput   string
		wantReferencesCount int
		wantError           bool
		errorContains       string
	}{
		{
			name:                 "ordinal reference - first pod",
			input:               "describe the first pod",
			sessionContext:      sessionContext,
			wantResolvedInput:   "describe the nginx-deployment-1",
			wantReferencesCount: 1,
			wantError:           false,
		},
		{
			name:                 "ordinal reference - second pod",
			input:               "delete the second pod",
			sessionContext:      sessionContext,
			wantResolvedInput:   "delete the nginx-deployment-2",
			wantReferencesCount: 1,
			wantError:           false,
		},
		{
			name:                 "demonstrative reference - that service",
			input:               "scale that service",
			sessionContext:      sessionContext,
			wantResolvedInput:   "scale nginx-service",
			wantReferencesCount: 1,
			wantError:           false,
		},
		{
			name:                 "pronoun reference - it",
			input:               "describe it",
			sessionContext:      sessionContext,
			wantResolvedInput:   "describe nginx-service", // Most recent item
			wantReferencesCount: 1,
			wantError:           false,
		},
		{
			name:                 "multiple references",
			input:               "compare the first pod with that service",
			sessionContext:      sessionContext,
			wantResolvedInput:   "compare the nginx-deployment-1 with nginx-service",
			wantReferencesCount: 2,
			wantError:           false,
		},
		{
			name:                 "no references",
			input:               "get pods",
			sessionContext:      sessionContext,
			wantResolvedInput:   "get pods",
			wantReferencesCount: 0,
			wantError:           false,
		},
		{
			name:           "nil session context",
			input:          "describe the first pod",
			sessionContext: nil,
			wantError:      true,
			errorContains:  "no active context available",
		},
		{
			name:           "expired session context",
			input:          "describe the first pod",
			sessionContext: createExpiredContext(),
			wantError:      true,
			errorContains:  "no active context available",
		},
		{
			name:                 "invalid ordinal reference",
			input:               "describe the fifth pod",
			sessionContext:      sessionContext,
			wantError:           true,
			errorContains:       "failed to resolve reference",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvedInput, references, err := resolver.ResolveReferences(tt.input, tt.sessionContext)
			
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantResolvedInput, resolvedInput)
				assert.Len(t, references, tt.wantReferencesCount)
			}
		})
	}
}

func TestContextResolver_ValidateReference(t *testing.T) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test reference item
	sessionContext.AddReferenceItem(models.ReferenceItem{
		ID:        "pod-1",
		Type:      "pod",
		Name:      "test-pod",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	})
	
	tests := []struct {
		name           string
		reference      string
		sessionContext *models.SessionContext
		wantValid      bool
		wantReason     string
	}{
		{
			name:           "valid ordinal reference",
			reference:      "first pod",
			sessionContext: sessionContext,
			wantValid:      true,
			wantReason:     "Reference is valid",
		},
		{
			name:           "valid direct name reference",
			reference:      "test-pod",
			sessionContext: sessionContext,
			wantValid:      true,
			wantReason:     "Reference is valid",
		},
		{
			name:           "invalid reference",
			reference:      "nonexistent pod",
			sessionContext: sessionContext,
			wantValid:      false,
		},
		{
			name:           "nil context",
			reference:      "first pod",
			sessionContext: nil,
			wantValid:      false,
			wantReason:     "No active context available",
		},
		{
			name:           "expired context",
			reference:      "first pod",
			sessionContext: createExpiredContext(),
			wantValid:      false,
			wantReason:     "No active context available",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, reason, item := resolver.ValidateReference(tt.reference, tt.sessionContext)
			
			assert.Equal(t, tt.wantValid, valid)
			if tt.wantReason != "" {
				assert.Equal(t, tt.wantReason, reason)
			}
			
			if tt.wantValid {
				assert.NotNil(t, item)
			} else {
				assert.Nil(t, item)
			}
		})
	}
}

func TestContextResolver_GetAvailableReferences(t *testing.T) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test reference items
	testItems := []models.ReferenceItem{
		{ID: "pod-1", Type: "pod", Name: "nginx-1", Position: 1, LastSeen: now},
		{ID: "pod-2", Type: "pod", Name: "nginx-2", Position: 2, LastSeen: now},
		{ID: "svc-1", Type: "service", Name: "nginx-svc", Position: 1, LastSeen: now},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	result := resolver.GetAvailableReferences(sessionContext)
	
	assert.True(t, result["available"].(bool))
	
	byType, ok := result["by_type"].(map[string][]string)
	require.True(t, ok)
	assert.Len(t, byType["pod"], 2)
	assert.Len(t, byType["service"], 1)
	assert.Contains(t, byType["pod"], "nginx-1")
	assert.Contains(t, byType["pod"], "nginx-2")
	assert.Contains(t, byType["service"], "nginx-svc")
	
	ordinalRefs, ok := result["ordinal_references"].([]string)
	require.True(t, ok)
	assert.Len(t, ordinalRefs, 3)
	assert.Contains(t, ordinalRefs[0], "first pod")
	assert.Contains(t, ordinalRefs[1], "second pod")
	assert.Contains(t, ordinalRefs[2], "third service")
	
	demonstrativeExamples, ok := result["demonstrative_examples"].([]string)
	require.True(t, ok)
	assert.Contains(t, demonstrativeExamples, "that pod")
	assert.Contains(t, demonstrativeExamples, "this service")
	assert.Contains(t, demonstrativeExamples, "the deployment")
	
	pronounExamples, ok := result["pronoun_examples"].([]string)
	require.True(t, ok)
	assert.Contains(t, pronounExamples, "describe it")
	assert.Contains(t, pronounExamples, "delete them")
	assert.Contains(t, pronounExamples, "scale those")
}

func TestContextResolver_GetAvailableReferences_NoContext(t *testing.T) {
	resolver := NewContextResolver()
	
	tests := []struct {
		name           string
		sessionContext *models.SessionContext
	}{
		{
			name:           "nil context",
			sessionContext: nil,
		},
		{
			name:           "expired context",
			sessionContext: createExpiredContext(),
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.GetAvailableReferences(tt.sessionContext)
			
			assert.False(t, result["available"].(bool))
			assert.Equal(t, "No active context", result["reason"].(string))
			
			references, ok := result["references"].([]string)
			require.True(t, ok)
			assert.Empty(t, references)
		})
	}
}

func TestContextResolver_DetectAmbiguousReferences(t *testing.T) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test reference items - multiple pods to create ambiguity
	testItems := []models.ReferenceItem{
		{ID: "pod-1", Type: "pod", Name: "nginx-1", Position: 1, LastSeen: now},
		{ID: "pod-2", Type: "pod", Name: "nginx-2", Position: 2, LastSeen: now},
		{ID: "svc-1", Type: "service", Name: "nginx-svc", Position: 1, LastSeen: now},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name           string
		input          string
		sessionContext *models.SessionContext
		wantAmbiguous  []string
	}{
		{
			name:           "ambiguous demonstrative - multiple pods",
			input:          "describe that pod",
			sessionContext: sessionContext,
			wantAmbiguous:  []string{"'that pod' could refer to 2 different pods"},
		},
		{
			name:           "no ambiguity - single service",
			input:          "describe that service",
			sessionContext: sessionContext,
			wantAmbiguous:  []string{},
		},
		{
			name:           "pronoun without context",
			input:          "describe it",
			sessionContext: models.NewSessionContext(), // Empty context
			wantAmbiguous:  []string{"Pronouns used but no previous context available"},
		},
		{
			name:           "no references to check",
			input:          "get pods",
			sessionContext: sessionContext,
			wantAmbiguous:  []string{},
		},
		{
			name:           "reference to non-existent type",
			input:          "describe that deployment",
			sessionContext: sessionContext,
			wantAmbiguous:  []string{"No deployment found in current context"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ambiguous := resolver.DetectAmbiguousReferences(tt.input, tt.sessionContext)
			
			assert.Equal(t, len(tt.wantAmbiguous), len(ambiguous))
			for i, expected := range tt.wantAmbiguous {
				if i < len(ambiguous) {
					assert.Contains(t, ambiguous[i], expected)
				}
			}
		})
	}
}

func TestContextResolver_SuggestClarifications(t *testing.T) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test reference items
	testItems := []models.ReferenceItem{
		{ID: "pod-1", Type: "pod", Name: "nginx-1", Position: 1, LastSeen: now},
		{ID: "svc-1", Type: "service", Name: "nginx-svc", Position: 1, LastSeen: now},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name             string
		input            string
		sessionContext   *models.SessionContext
		wantSuggestions  int
		containsKeywords []string
	}{
		{
			name:             "with active context",
			input:            "describe something",
			sessionContext:   sessionContext,
			wantSuggestions:  1,
			containsKeywords: []string{"reference items by name", "ordinal", "demonstrative"},
		},
		{
			name:             "no context available",
			input:            "describe the first pod",
			sessionContext:   nil,
			wantSuggestions:  1,
			containsKeywords: []string{"run a command first", "establish context"},
		},
		{
			name:             "expired context",
			input:            "describe that pod",
			sessionContext:   createExpiredContext(),
			wantSuggestions:  1,
			containsKeywords: []string{"run a command first", "establish context"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := resolver.SuggestClarifications(tt.input, tt.sessionContext)
			
			assert.Len(t, suggestions, tt.wantSuggestions)
			
			if len(suggestions) > 0 {
				suggestionText := suggestions[0]
				for _, keyword := range tt.containsKeywords {
					// At least one keyword should be present
					found := false
					for _, suggestion := range suggestions {
						if assert.Contains(t, suggestion, keyword) {
							found = true
							break
						}
					}
					if !found {
						// Check if any keyword is in the suggestion text
						for _, keyword := range tt.containsKeywords {
							if assert.Contains(t, suggestionText, keyword) {
								break
							}
						}
					}
				}
			}
		})
	}
}

func TestContextResolver_EnhanceCommandWithContext(t *testing.T) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test reference item with non-default namespace
	sessionContext.AddReferenceItem(models.ReferenceItem{
		ID:        "pod-1",
		Type:      "pod",
		Name:      "nginx-1",
		Namespace: "production",
		Position:  1,
		LastSeen:  now,
	})
	
	tests := []struct {
		name              string
		originalCommand   string
		resolvedInput     string
		references        []string
		sessionContext    *models.SessionContext
		wantNamespaceCtx  string
		wantResolvedCmd   string
		wantContextUsed   bool
	}{
		{
			name:             "command with context and namespace enhancement",
			originalCommand:  "kubectl get pods nginx-1",
			resolvedInput:    "kubectl get pods nginx-1",
			references:       []string{"first pod -> nginx-1"},
			sessionContext:   sessionContext,
			wantNamespaceCtx: "production",
			wantResolvedCmd:  "kubectl get pods nginx-1 -n production",
			wantContextUsed:  true,
		},
		{
			name:             "command already has namespace",
			originalCommand:  "kubectl get pods nginx-1 -n production",
			resolvedInput:    "kubectl get pods nginx-1 -n production",
			references:       []string{"first pod -> nginx-1"},
			sessionContext:   sessionContext,
			wantNamespaceCtx: "production",
			wantResolvedCmd:  "kubectl get pods nginx-1 -n production",
			wantContextUsed:  true,
		},
		{
			name:             "no context",
			originalCommand:  "kubectl get pods",
			resolvedInput:    "kubectl get pods",
			references:       []string{},
			sessionContext:   nil,
			wantNamespaceCtx: "",
			wantResolvedCmd:  "kubectl get pods",
			wantContextUsed:  false,
		},
		{
			name:             "no references used",
			originalCommand:  "kubectl get pods",
			resolvedInput:    "kubectl get pods",
			references:       []string{},
			sessionContext:   sessionContext,
			wantNamespaceCtx: "production",
			wantResolvedCmd:  "kubectl get pods -n production",
			wantContextUsed:  false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enhancement := resolver.EnhanceCommandWithContext(
				tt.originalCommand,
				tt.resolvedInput,
				tt.references,
				tt.sessionContext,
			)
			
			assert.Equal(t, tt.originalCommand, enhancement["original_command"])
			assert.Equal(t, tt.wantResolvedCmd, enhancement["resolved_command"])
			assert.Equal(t, tt.references, enhancement["resolved_references"])
			assert.Equal(t, tt.wantContextUsed, enhancement["context_used"])
			assert.Equal(t, tt.wantNamespaceCtx, enhancement["namespace_context"])
			
			additionalContext, ok := enhancement["additional_context"].(map[string]interface{})
			require.True(t, ok)
			
			if tt.sessionContext != nil {
				assert.Contains(t, additionalContext, "context_items_count")
				assert.Contains(t, additionalContext, "context_expired")
				assert.Contains(t, additionalContext, "last_command_id")
			}
		})
	}
}

func TestContextResolver_NumberToOrdinal(t *testing.T) {
	resolver := NewContextResolver()
	
	tests := []struct {
		number   int
		expected string
	}{
		{1, "first"},
		{2, "second"},
		{3, "third"},
		{4, "fourth"},
		{5, "fifth"},
		{10, "tenth"},
		{11, "11th"},
		{12, "12th"},
		{13, "13th"},
		{21, "21st"},
		{22, "22nd"},
		{23, "23rd"},
		{24, "24th"},
		{0, "0th"},
		{-1, "0th"},
	}
	
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := resolver.numberToOrdinal(tt.number)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContextResolver_ContainsReferences(t *testing.T) {
	resolver := NewContextResolver()
	
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"ordinal reference", "describe the first pod", true},
		{"demonstrative reference", "delete that service", true},
		{"pronoun reference", "scale it", true},
		{"multiple references", "compare the first pod with that service", true},
		{"no references", "kubectl get pods", false},
		{"similar but not reference", "get all pods", false},
		{"empty string", "", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.ContainsReferences(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestContextResolver_ExtractReferences(t *testing.T) {
	resolver := NewContextResolver()
	
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "multiple reference types",
			input:    "compare the first pod with that service and describe it",
			expected: []string{"first pod", "that service", "it"},
		},
		{
			name:     "ordinal only",
			input:    "delete the second deployment",
			expected: []string{"second deployment"},
		},
		{
			name:     "demonstrative only",
			input:    "scale that pod",
			expected: []string{"that pod"},
		},
		{
			name:     "pronoun only",
			input:    "restart them",
			expected: []string{"them"},
		},
		{
			name:     "no references",
			input:    "kubectl get all pods",
			expected: []string{},
		},
		{
			name:     "empty input",
			input:    "",
			expected: []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.ExtractReferences(tt.input)
			assert.ElementsMatch(t, tt.expected, result)
		})
	}
}

// Helper function to create an expired context for testing
func createExpiredContext() *models.SessionContext {
	context := models.NewSessionContext()
	context.ContextExpiry = time.Now().Add(-1 * time.Hour) // Expired
	return context
}

// Benchmark tests for performance validation
func BenchmarkContextResolver_ResolveReferences(b *testing.B) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	
	// Setup test data
	for i := 1; i <= 100; i++ {
		sessionContext.AddReferenceItem(models.ReferenceItem{
			ID:       fmt.Sprintf("pod-%d", i),
			Type:     "pod",
			Name:     fmt.Sprintf("test-pod-%d", i),
			Position: i,
			LastSeen: time.Now(),
		})
	}
	
	input := "describe the first pod"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := resolver.ResolveReferences(input, sessionContext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContextResolver_DetectAmbiguousReferences(b *testing.B) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	
	// Setup test data with ambiguous references
	for i := 1; i <= 50; i++ {
		sessionContext.AddReferenceItem(models.ReferenceItem{
			ID:       fmt.Sprintf("pod-%d", i),
			Type:     "pod",
			Name:     fmt.Sprintf("test-pod-%d", i),
			Position: i,
			LastSeen: time.Now(),
		})
	}
	
	input := "describe that pod"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.DetectAmbiguousReferences(input, sessionContext)
	}
}