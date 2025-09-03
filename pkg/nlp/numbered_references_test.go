package nlp

import (
	"context"
	"testing"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestNumberedReferences(t *testing.T) {
	translator := NewTranslatorService()
	ctx := context.Background()
	now := time.Now()
	
	// Create test session context with multiple pods and services
	sessionContext := models.NewSessionContext()
	
	testItems := []models.ReferenceItem{
		{
			ID:        "pod-1",
			Type:      "pod",
			Name:      "nginx-pod-alpha",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
		{
			ID:        "pod-2",
			Type:      "pod",
			Name:      "nginx-pod-beta",
			Namespace: "default",
			Position:  2,
			LastSeen:  now,
		},
		{
			ID:        "svc-1",
			Type:      "service",
			Name:      "nginx-service-alpha",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
		{
			ID:        "svc-2",
			Type:      "service",
			Name:      "nginx-service-beta",
			Namespace: "default",
			Position:  2,
			LastSeen:  now,
		},
		{
			ID:        "deploy-1",
			Type:      "deployment",
			Name:      "nginx-deployment",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name        string
		input       string
		wantCommand string
		wantError   bool
	}{
		{
			name:        "describe pod 1",
			input:       "describe pod 1",
			wantCommand: "kubectl describe pod nginx-pod-alpha",
			wantError:   false,
		},
		{
			name:        "describe pod 2",
			input:       "describe pod 2", 
			wantCommand: "kubectl describe pod nginx-pod-beta",
			wantError:   false,
		},
		{
			name:        "delete service 1",
			input:       "delete service 1",
			wantCommand: "kubectl delete service nginx-service-alpha",
			wantError:   false,
		},
		{
			name:        "get service 2",
			input:       "get service 2",
			wantCommand: "kubectl get service nginx-service-beta",
			wantError:   false,
		},
		{
			name:        "scale deployment 1 to 5",
			input:       "scale deployment 1 to 5",
			wantCommand: "kubectl scale deployment nginx-deployment --replicas=5",
			wantError:   false,
		},
		{
			name:        "logs from pod 1",
			input:       "logs from pod 1",
			wantCommand: "kubectl logs nginx-pod-alpha",
			wantError:   false,
		},
		{
			name:        "invalid number - pod 10",
			input:       "describe pod 10",
			wantError:   true,
		},
		{
			name:        "invalid number - service 0",
			input:       "describe service 0",
			wantError:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := translator.TranslateCommandWithContext(ctx, tt.input, sessionContext)
			
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantCommand, result.GeneratedCommand)
			}
		})
	}
}

func TestContextResolver_NumberedReferences(t *testing.T) {
	resolver := NewContextResolver()
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test reference items
	testItems := []models.ReferenceItem{
		{ID: "pod-1", Type: "pod", Name: "test-pod-1", Position: 1, LastSeen: now},
		{ID: "pod-2", Type: "pod", Name: "test-pod-2", Position: 2, LastSeen: now},
		{ID: "svc-1", Type: "service", Name: "test-service-1", Position: 1, LastSeen: now},
		{ID: "svc-2", Type: "service", Name: "test-service-2", Position: 2, LastSeen: now},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name              string
		input             string
		wantResolvedInput string
		wantReferences    []string
		wantError         bool
	}{
		{
			name:              "numbered pod reference",
			input:             "describe pod 1",
			wantResolvedInput: "describe test-pod-1",
			wantReferences:    []string{"pod 1 -> test-pod-1"},
			wantError:         false,
		},
		{
			name:              "numbered service reference",
			input:             "delete service 2",
			wantResolvedInput: "delete test-service-2", 
			wantReferences:    []string{"service 2 -> test-service-2"},
			wantError:         false,
		},
		{
			name:      "invalid numbered reference",
			input:     "describe pod 5",
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolvedInput, references, err := resolver.ResolveReferences(tt.input, sessionContext)
			
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantResolvedInput, resolvedInput)
				assert.Equal(t, tt.wantReferences, references)
			}
		})
	}
}

func TestContextResolver_ContainsNumberedReferences(t *testing.T) {
	resolver := NewContextResolver()
	
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"numbered pod reference", "describe pod 1", true},
		{"numbered service reference", "delete service 2", true},
		{"numbered deployment reference", "get deployment 3", true},
		{"ordinal reference", "describe the first pod", true},
		{"demonstrative reference", "delete that service", true},
		{"no references", "kubectl get pods", false},
		{"regular command with number", "scale nginx to 5", false}, // This shouldn't match
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolver.ContainsReferences(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGetEntityByNumberedReference(t *testing.T) {
	sessionContext := models.NewSessionContext()
	now := time.Now()
	
	// Add test items
	testItems := []models.ReferenceItem{
		{ID: "pod-1", Type: "pod", Name: "alpha-pod", Position: 1, LastSeen: now},
		{ID: "pod-2", Type: "pod", Name: "beta-pod", Position: 2, LastSeen: now},
		{ID: "svc-1", Type: "service", Name: "alpha-service", Position: 1, LastSeen: now},
		{ID: "deploy-1", Type: "deployment", Name: "alpha-deployment", Position: 1, LastSeen: now},
	}
	
	for _, item := range testItems {
		sessionContext.AddReferenceItem(item)
	}
	
	tests := []struct {
		name         string
		resourceType string
		number       int
		wantName     string
		wantError    bool
	}{
		{
			name:         "pod 1",
			resourceType: "pod",
			number:       1,
			wantName:     "alpha-pod",
			wantError:    false,
		},
		{
			name:         "pod 2",
			resourceType: "pod", 
			number:       2,
			wantName:     "beta-pod",
			wantError:    false,
		},
		{
			name:         "service 1",
			resourceType: "service",
			number:       1,
			wantName:     "alpha-service",
			wantError:    false,
		},
		{
			name:         "deployment 1",
			resourceType: "deployment",
			number:       1,
			wantName:     "alpha-deployment",
			wantError:    false,
		},
		{
			name:         "invalid - pod 5",
			resourceType: "pod",
			number:       5,
			wantError:    true,
		},
		{
			name:         "invalid - pod 0",
			resourceType: "pod",
			number:       0,
			wantError:    true,
		},
		{
			name:         "invalid - service 3",
			resourceType: "service",
			number:       3,
			wantError:    true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sessionContext.GetEntityByNumberedReference(tt.resourceType, tt.number)
			
			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.wantName, result.Name)
			}
		})
	}
}