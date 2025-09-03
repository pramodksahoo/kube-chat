package nlp

import (
	"testing"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNewSuggestionEngine(t *testing.T) {
	se := NewSuggestionEngine()
	assert.NotNil(t, se)
	assert.NotEmpty(t, se.commonPatterns)
	assert.NotEmpty(t, se.typoCorrections)
	assert.NotEmpty(t, se.resourceAliases)
}

func TestSuggestCorrections(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name      string
		input     string
		errorType models.ErrorType
		wantCount int
		wantContains []string
	}{
		{
			name:      "malformed input",
			input:     "xyz",
			errorType: models.ErrorTypeNLPMalformed,
			wantCount: 4,
			wantContains: []string{"get pods", "get services"},
		},
		{
			name:      "ambiguous input with list pattern",
			input:     "show me something",
			errorType: models.ErrorTypeNLPAmbiguous,
			wantCount: 5,
			wantContains: []string{"get pods", "get services", "get deployments"},
		},
		{
			name:      "unsupported migration",
			input:     "migrate database",
			errorType: models.ErrorTypeNLPUnsupported,
			wantCount: 2,
			wantContains: []string{"get pods", "describe"},
		},
		{
			name:      "general unknown error",
			input:     "some random command",
			errorType: models.ErrorTypeUnknown,
			wantCount: 5,
			wantContains: []string{"get pods", "get services"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := se.SuggestCorrections(tt.input, tt.errorType)
			
			assert.LessOrEqual(t, len(suggestions), tt.wantCount)
			
			for _, want := range tt.wantContains {
				found := false
				for _, suggestion := range suggestions {
					if suggestion == want {
						found = true
						break
					}
				}
				assert.True(t, found, "Should contain suggestion: %s", want)
			}
		})
	}
}

func TestCorrectTypos(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "kubectl typo",
			input:    "kubctl get pod",
			expected: "kubectl get pods",
		},
		{
			name:     "resource typo",
			input:    "get pod",
			expected: "get pods",
		},
		{
			name:     "action typo",
			input:    "gt pods",
			expected: "get pods",
		},
		{
			name:     "multiple corrections",
			input:    "kubctl gt pod",
			expected: "kubectl get pods",
		},
		{
			name:     "resource alias",
			input:    "get po",
			expected: "get pods",
		},
		{
			name:     "service alias",
			input:    "describe svc nginx",
			expected: "describe services nginx",
		},
		{
			name:     "no correction needed",
			input:    "get pods",
			expected: "get pods",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := se.correctTypos(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetContextualSuggestions(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name       string
		input      string
		sessionCtx *models.SessionContext
		wantCount  int
		wantContains []string
	}{
		{
			name:       "no context",
			input:      "help me",
			sessionCtx: nil,
			wantCount:  5,
			wantContains: []string{"get pods", "get services"},
		},
		{
			name:  "context with pods",
			input: "what now",
			sessionCtx: &models.SessionContext{
				ReferenceableItems: []models.ReferenceItem{
					{ID: "pod-1", Type: "pod", Name: "nginx-123"},
					{ID: "pod-2", Type: "pod", Name: "app-456"},
				},
			},
			wantCount:  5,
			wantContains: []string{"describe pod", "get pod", "describe the first one"},
		},
		{
			name:  "context with services and deployments",
			input: "show me more",
			sessionCtx: &models.SessionContext{
				ReferenceableItems: []models.ReferenceItem{
					{ID: "svc-1", Type: "service", Name: "web-service"},
					{ID: "deploy-1", Type: "deployment", Name: "api-deployment"},
				},
			},
			wantCount:  5,
			wantContains: []string{"describe service", "describe deployment"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := se.GetContextualSuggestions(tt.input, tt.sessionCtx)
			
			assert.LessOrEqual(t, len(suggestions), tt.wantCount)
			
			for _, want := range tt.wantContains {
				found := false
				for _, suggestion := range suggestions {
					if suggestion == want || 
					   (want == "describe pod" && suggestion == "describe pod <name>") ||
					   (want == "get pod" && suggestion == "get pod") {
						found = true
						break
					}
				}
				assert.True(t, found, "Should contain suggestion like: %s, got: %v", want, suggestions)
			}
		})
	}
}

func TestFallbackSuggestions(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name       string
		input      string
		sessionCtx *models.SessionContext
		wantCount  int
		wantContains []string
	}{
		{
			name:       "empty input",
			input:      "",
			sessionCtx: nil,
			wantCount:  5,
			wantContains: []string{"get pods", "get services"},
		},
		{
			name:       "input with pod keyword",
			input:      "something about pods please",
			sessionCtx: nil,
			wantCount:  5,
			wantContains: []string{"get pods", "describe pod"},
		},
		{
			name:       "input with deployment keyword",
			input:      "deployment status check",
			sessionCtx: nil,
			wantCount:  5,
			wantContains: []string{"get deployments", "describe deployment"},
		},
		{
			name:  "input with context",
			input: "gibberish input",
			sessionCtx: &models.SessionContext{
				ReferenceableItems: []models.ReferenceItem{
					{ID: "pod-1", Type: "pod", Name: "nginx-123"},
				},
			},
			wantCount:  5,
			wantContains: []string{"describe the first pod"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := se.FallbackSuggestions(tt.input, tt.sessionCtx)
			
			assert.LessOrEqual(t, len(suggestions), tt.wantCount)
			assert.Greater(t, len(suggestions), 0)
			
			for _, want := range tt.wantContains {
				found := false
				for _, suggestion := range suggestions {
					if suggestion == want {
						found = true
						break
					}
				}
				assert.True(t, found, "Should contain suggestion: %s, got: %v", want, suggestions)
			}
		})
	}
}

func TestExtractKeywords(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "pod keyword",
			input:    "show me all pods",
			expected: []string{"pods"},
		},
		{
			name:     "multiple keywords",
			input:    "get deployment status",
			expected: []string{"deployment", "get", "status"},
		},
		{
			name:     "service and describe",
			input:    "describe the service details",
			expected: []string{"service", "describe"},
		},
		{
			name:     "operational keywords",
			input:    "check health and restart failed pods",
			expected: []string{"pods", "health", "failed"},
		},
		{
			name:     "no kubernetes keywords",
			input:    "hello world example",
			expected: []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keywords := se.extractKeywords(tt.input)
			
			assert.Equal(t, len(tt.expected), len(keywords))
			
			for _, expectedKeyword := range tt.expected {
				assert.Contains(t, keywords, expectedKeyword)
			}
		})
	}
}

func TestGetSmartSuggestions(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name           string
		input          string
		sessionCtx     *models.SessionContext
		previousErrors []string
		wantCount      int
		wantExclude    []string
	}{
		{
			name:           "no previous errors",
			input:          "help me",
			sessionCtx:     nil,
			previousErrors: []string{},
			wantCount:      4,
			wantExclude:    []string{},
		},
		{
			name:           "previous describe errors",
			input:          "show details",
			sessionCtx:     nil,
			previousErrors: []string{"describe command failed", "describe pod error"},
			wantCount:      4,
			wantExclude:    []string{"describe"},
		},
		{
			name:           "all suggestions filtered",
			input:          "delete everything",
			sessionCtx:     nil,
			previousErrors: []string{"get failed", "delete failed", "create failed"},
			wantCount:      3, // Should fallback to basic commands
			wantExclude:    []string{},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestions := se.GetSmartSuggestions(tt.input, tt.sessionCtx, tt.previousErrors)
			
			assert.LessOrEqual(t, len(suggestions), tt.wantCount)
			assert.Greater(t, len(suggestions), 0)
			
			for _, exclude := range tt.wantExclude {
				for _, suggestion := range suggestions {
					assert.NotContains(t, suggestion, exclude, "Should not contain excluded pattern: %s", exclude)
				}
			}
		})
	}
}

func TestFormatSuggestionsForDisplay(t *testing.T) {
	se := NewSuggestionEngine()
	
	tests := []struct {
		name        string
		suggestions []string
		wantContains []string
	}{
		{
			name:        "empty suggestions",
			suggestions: []string{},
			wantContains: []string{"💡", "Try these common commands:", "get pods"},
		},
		{
			name:        "normal suggestions",
			suggestions: []string{"get pods", "get services", "describe pod nginx"},
			wantContains: []string{"💡", "Suggestions:", "• get pods", "• get services", "• describe pod nginx"},
		},
		{
			name:        "many suggestions - should limit",
			suggestions: []string{"cmd1", "cmd2", "cmd3", "cmd4", "cmd5", "cmd6"},
			wantContains: []string{"💡", "• cmd1", "• cmd2", "• cmd3", "• cmd4", "• cmd5"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := se.FormatSuggestionsForDisplay(tt.suggestions)
			
			for _, want := range tt.wantContains {
				assert.Contains(t, result, want)
			}
			
			// Should not contain cmd6 if there were 6+ suggestions (limited to 5)
			if len(tt.suggestions) > 5 {
				assert.NotContains(t, result, "• cmd6")
			}
		})
	}
}