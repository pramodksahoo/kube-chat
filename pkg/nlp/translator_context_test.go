package nlp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestTranslatorService_TranslateCommandWithContext(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	now := time.Now()
	
	// Create test session context
	sessionContext := models.NewSessionContext()
	
	// Add test reference items
	testItems := []models.ReferenceItem{
		{
			ID:        "pod-1",
			Type:      "pod",
			Name:      "nginx-deployment-1",
			Namespace: "production",
			Position:  1,
			LastSeen:  now,
		},
		{
			ID:        "pod-2",
			Type:      "pod",
			Name:      "nginx-deployment-2",
			Namespace: "production",
			Position:  2,
			LastSeen:  now.Add(1 * time.Minute),
		},
		{
			ID:        "svc-1",
			Type:      "service",
			Name:      "nginx-service",
			Namespace: "production",
			Position:  1,
			LastSeen:  now,
		},
		{
			ID:        "deploy-1",
			Type:      "deployment",
			Name:      "nginx-deployment",
			Namespace: "production",
			Position:  1,
			LastSeen:  now,
		},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name              string
		input             string
		sessionContext    *models.SessionContext
		wantCommand       string
		wantRiskLevel     models.RiskLevel
		wantError         bool
		errorContains     string
		wantStatus        models.CommandStatus
		contextEnhanced   bool
	}{
		{
			name:            "ordinal reference - describe first pod",
			input:           "describe the first pod",
			sessionContext:  sessionContext,
			wantCommand:     "kubectl describe pod nginx-deployment-1 -n production",
			wantRiskLevel:   models.RiskLevelSafe,
			wantError:       false,
			wantStatus:      models.CommandStatusApproved,
			contextEnhanced: true,
		},
		{
			name:            "demonstrative reference - delete that service",
			input:           "delete that service",
			sessionContext:  sessionContext,
			wantCommand:     "kubectl delete service nginx-service -n production",
			wantRiskLevel:   models.RiskLevelDestructive,
			wantError:       false,
			wantStatus:      models.CommandStatusPendingApproval,
			contextEnhanced: true,
		},
		{
			name:            "pronoun reference - describe it",
			input:           "describe it",
			sessionContext:  sessionContext,
			wantCommand:     "kubectl describe deployment nginx-deployment -n production", // Most recent item resolved by context
			wantRiskLevel:   models.RiskLevelSafe,
			wantError:       false,
			wantStatus:      models.CommandStatusApproved,
			contextEnhanced: true,
		},
		{
			name:            "scale with ordinal reference",
			input:           "scale the first deployment to 3 replicas",
			sessionContext:  sessionContext,
			wantCommand:     "kubectl scale deployment nginx-deployment --replicas=3 -n production",
			wantRiskLevel:   models.RiskLevelCaution,
			wantError:       false,
			wantStatus:      models.CommandStatusPendingApproval,
			contextEnhanced: true,
		},
		{
			name:            "logs with demonstrative reference",
			input:           "logs from that service",
			sessionContext:  sessionContext,
			wantCommand:     "kubectl logs nginx-service -n production", // Service logs
			wantRiskLevel:   models.RiskLevelSafe,
			wantError:       false,
			wantStatus:      models.CommandStatusApproved,
			contextEnhanced: true,
		},
		{
			name:           "no context - should work without references",
			input:          "get pods",
			sessionContext: nil,
			wantCommand:    "kubectl get pods",
			wantRiskLevel:  models.RiskLevelSafe,
			wantError:      false,
			wantStatus:     models.CommandStatusApproved,
		},
		{
			name:           "expired context - should fail with context references",
			input:          "describe the first pod",
			sessionContext: createExpiredContext(),
			wantError:      true,
			errorContains:  "no active session context available",
		},
		{
			name:           "ambiguous reference - multiple pods",
			input:          "describe that pod",
			sessionContext: sessionContext,
			wantError:      true,
			errorContains:  "ambiguous reference",
		},
		{
			name:           "invalid ordinal reference",
			input:          "describe the fifth pod",
			sessionContext: sessionContext,
			wantError:      true,
			errorContains:  "failed to resolve references",
		},
		{
			name:           "unsupported command with context",
			input:          "do something with the first pod",
			sessionContext: sessionContext,
			wantError:      true,
			errorContains:  "unable to translate input",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.TranslateCommandWithContext(ctx, tt.input, tt.sessionContext)
			
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				
				assert.Equal(t, tt.input, result.NaturalLanguageInput)
				assert.Equal(t, tt.wantCommand, result.GeneratedCommand)
				assert.Equal(t, tt.wantRiskLevel, result.RiskLevel)
				assert.Equal(t, tt.wantStatus, result.Status)
				
				// Check that approval token is set for risky commands
				if tt.wantRiskLevel != models.RiskLevelSafe {
					assert.NotNil(t, result.ApprovalToken)
					assert.NotNil(t, result.ApprovalExpiresAt)
				}
				
				// Verify resource information
				assert.NotEmpty(t, result.Resources)
				assert.NotEmpty(t, result.Resources[0].Kind)
				assert.NotEmpty(t, result.Resources[0].Action)
			}
		})
	}
}

func TestTranslatorService_ContextAwarePatterns(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	// Create a session context with test data
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	sessionContext.AddReferenceItem(models.ReferenceItem{
		ID:        "pod-1",
		Type:      "pod",
		Name:      "test-pod-1",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	})
	
	sessionContext.AddReferenceItem(models.ReferenceItem{
		ID:        "svc-1",
		Type:      "service",
		Name:      "test-service",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	})
	
	tests := []struct {
		name          string
		input         string
		wantError     bool
		wantRiskLevel models.RiskLevel
		wantAction    string
	}{
		{
			name:          "describe with ordinal - first pod",
			input:         "describe the first pod",
			wantError:     false,
			wantRiskLevel: models.RiskLevelSafe,
			wantAction:    "read",
		},
		{
			name:          "describe with demonstrative - that service",
			input:         "describe that service",
			wantError:     false,
			wantRiskLevel: models.RiskLevelSafe,
			wantAction:    "read",
		},
		{
			name:          "delete with ordinal - first pod",
			input:         "delete the first pod",
			wantError:     false,
			wantRiskLevel: models.RiskLevelDestructive,
			wantAction:    "delete",
		},
		{
			name:          "delete with demonstrative - that service",
			input:         "delete that service",
			wantError:     false,
			wantRiskLevel: models.RiskLevelDestructive,
			wantAction:    "delete",
		},
		{
			name:          "pronoun - describe it",
			input:         "describe it",
			wantError:     false,
			wantRiskLevel: models.RiskLevelSafe,
			wantAction:    "read",
		},
		{
			name:          "pronoun - delete them",
			input:         "delete them",
			wantError:     false,
			wantRiskLevel: models.RiskLevelDestructive,
			wantAction:    "delete",
		},
		{
			name:          "logs with ordinal reference",
			input:         "logs from the first pod",
			wantError:     false,
			wantRiskLevel: models.RiskLevelSafe,
			wantAction:    "read",
		},
		{
			name:          "logs with demonstrative reference",
			input:         "logs from that pod",
			wantError:     false,
			wantRiskLevel: models.RiskLevelSafe,
			wantAction:    "read",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.TranslateCommandWithContext(ctx, tt.input, sessionContext)
			
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantRiskLevel, result.RiskLevel)
				
				if len(result.Resources) > 0 {
					assert.Equal(t, tt.wantAction, result.Resources[0].Action)
				}
			}
		})
	}
}

func TestTranslatorService_ContextValidation(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	tests := []struct {
		name           string
		input          string
		sessionContext *models.SessionContext
		wantError      bool
		errorContains  string
	}{
		{
			name:           "empty input",
			input:          "",
			sessionContext: models.NewSessionContext(),
			wantError:      true,
			errorContains:  "input cannot be empty",
		},
		{
			name:           "nil context with references",
			input:          "describe the first pod",
			sessionContext: nil,
			wantError:      true,
			errorContains:  "context references detected",
		},
		{
			name:           "context reference with no context data",
			input:          "describe the first pod",
			sessionContext: models.NewSessionContext(), // Empty context
			wantError:      true,
			errorContains:  "failed to resolve references",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.TranslateCommandWithContext(ctx, tt.input, tt.sessionContext)
			
			if tt.wantError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

func TestTranslatorService_NamespaceEnhancement(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	// Create session context with non-default namespace
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	sessionContext.AddReferenceItem(models.ReferenceItem{
		ID:        "pod-1",
		Type:      "pod",
		Name:      "test-pod",
		Namespace: "production",
		Position:  1,
		LastSeen:  now,
	})
	
	tests := []struct {
		name                string
		input               string
		wantCommandContains string
	}{
		{
			name:                "ordinal reference with namespace enhancement",
			input:               "describe the first pod",
			wantCommandContains: "-n production",
		},
		{
			name:                "demonstrative reference with namespace enhancement",
			input:               "describe that pod",
			wantCommandContains: "-n production",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.TranslateCommandWithContext(ctx, tt.input, sessionContext)
			
			assert.NoError(t, err)
			assert.NotNil(t, result)
			assert.Contains(t, result.GeneratedCommand, tt.wantCommandContains)
		})
	}
}

func TestTranslatorService_FallbackToBasicTranslation(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	// Test that basic translation still works without context
	result, err := translator.TranslateCommand(ctx, "get pods")
	
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "kubectl get pods", result.GeneratedCommand)
	assert.Equal(t, models.RiskLevelSafe, result.RiskLevel)
	assert.Equal(t, models.CommandStatusApproved, result.Status)
}

func TestTranslatorService_ContextSuggestions(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	// Create session context with available references
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	sessionContext.AddReferenceItem(models.ReferenceItem{
		ID:       "pod-1",
		Type:     "pod",
		Name:     "available-pod",
		Position: 1,
		LastSeen: now,
	})
	
	tests := []struct {
		name            string
		input           string
		sessionContext  *models.SessionContext
		wantError       bool
		wantSuggestions bool
	}{
		{
			name:            "unknown command with context - should show available references",
			input:           "do something unknown",
			sessionContext:  sessionContext,
			wantError:       true,
			wantSuggestions: true,
		},
		{
			name:            "unknown command without context - basic error",
			input:           "do something unknown",
			sessionContext:  nil,
			wantError:       true,
			wantSuggestions: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.TranslateCommandWithContext(ctx, tt.input, tt.sessionContext)
			
			assert.Error(t, err)
			assert.Nil(t, result)
			
			if tt.wantSuggestions {
				// Error message should contain reference information
				assert.Contains(t, err.Error(), "Available references")
			}
		})
	}
}

// Benchmark tests for performance validation
func BenchmarkTranslatorService_ContextTranslation(b *testing.B) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	// Setup test context
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	for i := 1; i <= 10; i++ {
		sessionContext.AddReferenceItem(models.ReferenceItem{
			ID:       fmt.Sprintf("pod-%d", i),
			Type:     "pod",
			Name:     fmt.Sprintf("test-pod-%d", i),
			Position: i,
			LastSeen: now,
		})
	}
	
	input := "describe the first pod"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := translator.TranslateCommandWithContext(ctx, input, sessionContext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTranslatorService_BasicTranslation(b *testing.B) {
	translator := NewTranslatorService()
	ctx := context.Background()
	
	input := "get pods"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := translator.TranslateCommand(ctx, input)
		if err != nil {
			b.Fatal(err)
		}
	}
}