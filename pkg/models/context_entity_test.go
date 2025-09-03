package models

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSessionContext(t *testing.T) {
	context := NewSessionContext()
	
	assert.NotNil(t, context)
	assert.Empty(t, context.LastCommandOutput)
	assert.Empty(t, context.NamedEntities)
	assert.Empty(t, context.ReferenceableItems)
	assert.True(t, context.ContextExpiry.After(time.Now()))
}

func TestSessionContext_AddEntity(t *testing.T) {
	context := NewSessionContext()
	now := time.Now()
	
	entity1 := ContextEntity{
		Type:      "pod",
		Name:      "test-pod-1",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	}
	
	// Add new entity
	context.AddEntity(entity1)
	assert.Len(t, context.NamedEntities, 1)
	assert.Equal(t, "test-pod-1", context.NamedEntities[0].Name)
	
	// Update existing entity
	laterTime := now.Add(1 * time.Minute)
	entity1Updated := ContextEntity{
		Type:      "pod",
		Name:      "test-pod-1",
		Namespace: "default",
		Position:  2, // Different position
		LastSeen:  laterTime,
	}
	
	context.AddEntity(entity1Updated)
	assert.Len(t, context.NamedEntities, 1) // Should still be 1
	assert.Equal(t, 2, context.NamedEntities[0].Position)
	assert.Equal(t, laterTime, context.NamedEntities[0].LastSeen)
}

func TestSessionContext_AddReferenceItem(t *testing.T) {
	context := NewSessionContext()
	now := time.Now()
	
	item1 := ReferenceItem{
		ID:        "pod-1",
		Type:      "pod",
		Name:      "test-pod-1",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	}
	
	// Add new item
	context.AddReferenceItem(item1)
	assert.Len(t, context.ReferenceableItems, 1)
	
	// Update existing item
	item1Updated := item1
	item1Updated.Position = 2
	item1Updated.LastSeen = now.Add(1 * time.Minute)
	
	context.AddReferenceItem(item1Updated)
	assert.Len(t, context.ReferenceableItems, 1) // Should still be 1
	assert.Equal(t, 2, context.ReferenceableItems[0].Position)
}

func TestSessionContext_GetEntityByReference(t *testing.T) {
	context := NewSessionContext()
	now := time.Now()
	
	// Setup test data
	items := []ReferenceItem{
		{
			ID:        "pod-1",
			Type:      "pod",
			Name:      "test-pod-1",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
		{
			ID:        "pod-2",
			Type:      "pod",
			Name:      "test-pod-2",
			Namespace: "default",
			Position:  2,
			LastSeen:  now.Add(1 * time.Minute),
		},
		{
			ID:        "svc-1",
			Type:      "service",
			Name:      "test-service",
			Namespace: "default",
			Position:  1,
			LastSeen:  now,
		},
	}
	
	for _, item := range items {
		context.AddReferenceItem(item)
	}
	
	tests := []struct {
		name      string
		reference string
		wantName  string
		wantError bool
	}{
		{
			name:      "ordinal reference - first pod",
			reference: "first pod",
			wantName:  "test-pod-1",
			wantError: false,
		},
		{
			name:      "ordinal reference - second pod",
			reference: "second pod",
			wantName:  "test-pod-2",
			wantError: false,
		},
		{
			name:      "ordinal reference - first one",
			reference: "first one",
			wantName:  "test-pod-1",
			wantError: false,
		},
		{
			name:      "demonstrative reference - that pod",
			reference: "that pod",
			wantName:  "test-pod-2", // Most recent pod
			wantError: false,
		},
		{
			name:      "demonstrative reference - that service",
			reference: "that service",
			wantName:  "test-service",
			wantError: false,
		},
		{
			name:      "direct name reference",
			reference: "test-pod-1",
			wantName:  "test-pod-1",
			wantError: false,
		},
		{
			name:      "invalid reference",
			reference: "nonexistent pod",
			wantError: true,
		},
		{
			name:      "ordinal out of range",
			reference: "fifth pod",
			wantError: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := context.GetEntityByReference(tt.reference)
			
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

func TestSessionContext_IsExpired(t *testing.T) {
	context := NewSessionContext()
	
	// Should not be expired initially
	assert.False(t, context.IsExpired())
	
	// Set expiry to past
	context.ContextExpiry = time.Now().Add(-1 * time.Minute)
	assert.True(t, context.IsExpired())
	
	// Set expiry to future
	context.ContextExpiry = time.Now().Add(1 * time.Hour)
	assert.False(t, context.IsExpired())
}

func TestSessionContext_ExtendExpiry(t *testing.T) {
	context := NewSessionContext()
	originalExpiry := context.ContextExpiry
	
	context.ExtendExpiry(1 * time.Hour)
	
	assert.True(t, context.ContextExpiry.After(originalExpiry))
}

func TestSessionContext_Clear(t *testing.T) {
	context := NewSessionContext()
	
	// Add some data
	context.AddEntity(ContextEntity{
		Type: "pod",
		Name: "test-pod",
	})
	context.AddReferenceItem(ReferenceItem{
		ID:   "pod-1",
		Type: "pod",
		Name: "test-pod",
	})
	context.LastCommandID = "cmd-123"
	
	// Clear context
	context.Clear()
	
	assert.Empty(t, context.LastCommandOutput)
	assert.Empty(t, context.NamedEntities)
	assert.Empty(t, context.ReferenceableItems)
	assert.Empty(t, context.LastCommandID)
	assert.True(t, context.ContextExpiry.After(time.Now()))
}

func TestSessionContext_GetAvailableReferences(t *testing.T) {
	context := NewSessionContext()
	
	// Add reference items
	items := []ReferenceItem{
		{ID: "pod-1", Type: "pod", Name: "test-pod-1"},
		{ID: "pod-2", Type: "pod", Name: "test-pod-2"},
		{ID: "svc-1", Type: "service", Name: "test-service"},
	}
	
	for _, item := range items {
		context.AddReferenceItem(item)
	}
	
	references := context.GetAvailableReferences()
	
	assert.Len(t, references, 2) // pod and service types
	assert.Len(t, references["pod"], 2)
	assert.Len(t, references["service"], 1)
	assert.Contains(t, references["pod"], "test-pod-1")
	assert.Contains(t, references["pod"], "test-pod-2")
	assert.Contains(t, references["service"], "test-service")
}

func TestSessionContext_JSONSerialization(t *testing.T) {
	context := NewSessionContext()
	now := time.Now()
	
	// Add test data
	context.AddEntity(ContextEntity{
		Type:      "pod",
		Name:      "test-pod",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	})
	
	context.AddReferenceItem(ReferenceItem{
		ID:        "pod-1",
		Type:      "pod",
		Name:      "test-pod",
		Namespace: "default",
		Position:  1,
		LastSeen:  now,
	})
	
	// Serialize to JSON
	jsonData, err := context.ToJSON()
	require.NoError(t, err)
	assert.NotEmpty(t, jsonData)
	
	// Deserialize from JSON
	newContext := &SessionContext{}
	err = newContext.FromJSON(jsonData)
	require.NoError(t, err)
	
	assert.Len(t, newContext.NamedEntities, 1)
	assert.Len(t, newContext.ReferenceableItems, 1)
	assert.Equal(t, "test-pod", newContext.NamedEntities[0].Name)
	assert.Equal(t, "test-pod", newContext.ReferenceableItems[0].Name)
}

func TestExtractOrdinalReference(t *testing.T) {
	tests := []struct {
		name         string
		reference    string
		wantPosition int
		wantType     string
		wantNil      bool
	}{
		{
			name:         "first pod",
			reference:    "first pod",
			wantPosition: 1,
			wantType:     "pod",
		},
		{
			name:         "second service",
			reference:    "second service",
			wantPosition: 2,
			wantType:     "service",
		},
		{
			name:         "third one",
			reference:    "third one",
			wantPosition: 3,
			wantType:     "one",
		},
		{
			name:         "1st deployment",
			reference:    "1st deployment",
			wantPosition: 1,
			wantType:     "deployment",
		},
		{
			name:      "invalid reference",
			reference: "invalid reference",
			wantNil:   true,
		},
		{
			name:      "empty reference",
			reference: "",
			wantNil:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractOrdinalReference(tt.reference)
			
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantPosition, result.position)
				assert.Equal(t, tt.wantType, result.resourceType)
			}
		})
	}
}

func TestExtractDemonstrativeReference(t *testing.T) {
	tests := []struct {
		name     string
		reference string
		wantType string
		wantNil  bool
	}{
		{
			name:      "that pod",
			reference: "that pod",
			wantType:  "pod",
		},
		{
			name:      "this service",
			reference: "this service",
			wantType:  "service",
		},
		{
			name:      "the deployment",
			reference: "the deployment",
			wantType:  "deployment",
		},
		{
			name:      "invalid - too many words",
			reference: "that big pod",
			wantNil:   true,
		},
		{
			name:      "invalid - one word",
			reference: "pod",
			wantNil:   true,
		},
		{
			name:      "invalid demonstrative",
			reference: "some pod",
			wantNil:   true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractDemonstrativeReference(tt.reference)
			
			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				require.NotNil(t, result)
				assert.Equal(t, tt.wantType, result.resourceType)
			}
		})
	}
}

func TestContextKubernetesResource(t *testing.T) {
	resource := ContextKubernetesResource{
		KubernetesResource: KubernetesResource{
			Kind:      "Pod",
			Name:      "test-pod",
			Namespace: "default",
			Action:    "read",
		},
		Status:   "Running",
		Age:      "5m",
		Labels:   map[string]string{"app": "test"},
		Position: 1,
	}
	
	assert.Equal(t, "Pod", resource.Kind)
	assert.Equal(t, "test-pod", resource.Name)
	assert.Equal(t, "default", resource.Namespace)
	assert.Equal(t, "Running", resource.Status)
	assert.Equal(t, "5m", resource.Age)
	assert.Equal(t, "test", resource.Labels["app"])
	assert.Equal(t, 1, resource.Position)
}