package nlp

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewEntityExtractor(t *testing.T) {
	extractor := NewEntityExtractor()
	
	assert.NotNil(t, extractor)
	assert.NotNil(t, extractor.tableHeaderRegex)
	assert.NotNil(t, extractor.podRegex)
	assert.NotNil(t, extractor.serviceRegex)
	assert.NotNil(t, extractor.deploymentRegex)
	assert.NotNil(t, extractor.namespaceRegex)
}

func TestEntityExtractor_DetermineResourceType(t *testing.T) {
	extractor := NewEntityExtractor()
	
	tests := []struct {
		name     string
		command  string
		expected string
	}{
		{
			name:     "kubectl get pods",
			command:  "kubectl get pods",
			expected: "pod",
		},
		{
			name:     "get services",
			command:  "get services",
			expected: "service",
		},
		{
			name:     "kubectl get svc",
			command:  "kubectl get svc",
			expected: "service",
		},
		{
			name:     "get deployments",
			command:  "get deployments",
			expected: "deployment",
		},
		{
			name:     "kubectl get deploy",
			command:  "kubectl get deploy",
			expected: "deployment",
		},
		{
			name:     "get namespaces",
			command:  "get namespaces",
			expected: "namespace",
		},
		{
			name:     "kubectl get ns",
			command:  "kubectl get ns",
			expected: "namespace",
		},
		{
			name:     "get nodes",
			command:  "get nodes",
			expected: "node",
		},
		{
			name:     "unknown command",
			command:  "some random command",
			expected: "",
		},
		{
			name:     "empty command",
			command:  "",
			expected: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.determineResourceType(tt.command)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEntityExtractor_FormatDetection(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("table format detection", func(t *testing.T) {
		tableOutput := `NAME                     READY   STATUS    RESTARTS   AGE
test-pod-1               1/1     Running   0          5m
test-pod-2               0/1     Pending   0          2m`
		
		assert.True(t, extractor.isTableFormat(tableOutput))
		assert.False(t, extractor.isJSONFormat(tableOutput))
		assert.False(t, extractor.isYAMLFormat(tableOutput))
	})
	
	t.Run("JSON format detection", func(t *testing.T) {
		jsonOutput := `{
  "apiVersion": "v1",
  "items": []
}`
		
		assert.False(t, extractor.isTableFormat(jsonOutput))
		assert.True(t, extractor.isJSONFormat(jsonOutput))
		assert.False(t, extractor.isYAMLFormat(jsonOutput))
	})
	
	t.Run("YAML format detection", func(t *testing.T) {
		yamlOutput := `apiVersion: v1
kind: Pod
metadata:
  name: test-pod`
		
		assert.False(t, extractor.isTableFormat(yamlOutput))
		assert.False(t, extractor.isJSONFormat(yamlOutput))
		assert.True(t, extractor.isYAMLFormat(yamlOutput))
	})
}

func TestEntityExtractor_ParseTableFormat(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("parse pod output", func(t *testing.T) {
		podOutput := `NAME                     READY   STATUS    RESTARTS   AGE
test-pod-1               1/1     Running   0          5m
test-pod-2               0/1     Pending   0          2m
test-pod-3               1/1     Failed    1          1h`
		
		entities, refItems, err := extractor.parseTableFormat(podOutput, "pod")
		
		require.NoError(t, err)
		assert.Len(t, entities, 3)
		assert.Len(t, refItems, 3)
		
		// Check first pod
		assert.Equal(t, "pod", entities[0].Type)
		assert.Equal(t, "test-pod-1", entities[0].Name)
		assert.Equal(t, 1, entities[0].Position)
		
		// Check reference items
		assert.Equal(t, "test-pod-1", refItems[0].Name)
		assert.Equal(t, "pod", refItems[0].Type)
		assert.Equal(t, 1, refItems[0].Position)
		
		// Check metadata
		metadata := refItems[0].Metadata.(map[string]interface{})
		assert.Equal(t, "1/1", metadata["ready"])
		assert.Equal(t, "Running", metadata["status"])
		assert.Equal(t, "0", metadata["restarts"])
		assert.Equal(t, "5m", metadata["age"])
	})
	
	t.Run("parse service output", func(t *testing.T) {
		serviceOutput := `NAME           TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
kubernetes     ClusterIP   10.96.0.1       <none>        443/TCP   5d
test-service   NodePort    10.96.100.1     <none>        80:30080/TCP   1h`
		
		entities, refItems, err := extractor.parseTableFormat(serviceOutput, "service")
		
		require.NoError(t, err)
		assert.Len(t, entities, 2)
		assert.Len(t, refItems, 2)
		
		// Check first service
		assert.Equal(t, "service", entities[0].Type)
		assert.Equal(t, "kubernetes", entities[0].Name)
		assert.Equal(t, 1, entities[0].Position)
	})
	
	t.Run("parse deployment output", func(t *testing.T) {
		deploymentOutput := `NAME               READY   UP-TO-DATE   AVAILABLE   AGE
test-deployment    2/2     2            2           1h
another-deploy     0/1     1            0           5m`
		
		entities, refItems, err := extractor.parseTableFormat(deploymentOutput, "deployment")
		
		require.NoError(t, err)
		assert.Len(t, entities, 2)
		assert.Len(t, refItems, 2)
		
		// Check first deployment
		assert.Equal(t, "deployment", entities[0].Type)
		assert.Equal(t, "test-deployment", entities[0].Name)
		assert.Equal(t, 1, entities[0].Position)
	})
}

func TestEntityExtractor_ParseGenericTableLine(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("generic parsing", func(t *testing.T) {
		line := "custom-resource-name   Active   Ready   5m"
		now := time.Now()
		
		entity, refItem, err := extractor.parseGenericTableLine(line, "customresource", 1, now)
		
		require.NoError(t, err)
		assert.NotNil(t, entity)
		assert.NotNil(t, refItem)
		
		assert.Equal(t, "customresource", entity.Type)
		assert.Equal(t, "custom-resource-name", entity.Name)
		assert.Equal(t, 1, entity.Position)
	})
	
	t.Run("empty line", func(t *testing.T) {
		line := ""
		now := time.Now()
		
		entity, refItem, err := extractor.parseGenericTableLine(line, "test", 1, now)
		
		assert.Error(t, err)
		assert.Nil(t, entity)
		assert.Nil(t, refItem)
	})
}

func TestEntityExtractor_LooksLikeResourceName(t *testing.T) {
	extractor := NewEntityExtractor()
	
	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "valid kubernetes name",
			input:    "test-pod-123",
			expected: true,
		},
		{
			name:     "valid simple name",
			input:    "nginx",
			expected: true,
		},
		{
			name:     "name with numbers",
			input:    "app-v1-2-3",
			expected: true,
		},
		{
			name:     "invalid - uppercase",
			input:    "Test-Pod",
			expected: false,
		},
		{
			name:     "invalid - special chars",
			input:    "test_pod",
			expected: false,
		},
		{
			name:     "invalid - too short",
			input:    "ab",
			expected: false,
		},
		{
			name:     "invalid - starts with hyphen",
			input:    "-test-pod",
			expected: false,
		},
		{
			name:     "invalid - ends with hyphen",
			input:    "test-pod-",
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractor.looksLikeResourceName(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEntityExtractor_ExtractEntitiesFromOutput(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("successful extraction", func(t *testing.T) {
		output := `NAME                     READY   STATUS    RESTARTS   AGE
test-pod-1               1/1     Running   0          5m
test-pod-2               0/1     Pending   0          2m`
		
		command := "kubectl get pods"
		
		entities, refItems, err := extractor.ExtractEntitiesFromOutput(output, command)
		
		require.NoError(t, err)
		assert.Len(t, entities, 2)
		assert.Len(t, refItems, 2)
		
		assert.Equal(t, "test-pod-1", entities[0].Name)
		assert.Equal(t, "test-pod-2", entities[1].Name)
	})
	
	t.Run("empty output", func(t *testing.T) {
		output := ""
		command := "kubectl get pods"
		
		entities, refItems, err := extractor.ExtractEntitiesFromOutput(output, command)
		
		assert.Error(t, err)
		assert.Nil(t, entities)
		assert.Nil(t, refItems)
	})
	
	t.Run("unknown command", func(t *testing.T) {
		output := "some output"
		command := "unknown command"
		
		entities, refItems, err := extractor.ExtractEntitiesFromOutput(output, command)
		
		assert.Error(t, err)
		assert.Nil(t, entities)
		assert.Nil(t, refItems)
	})
}

func TestEntityExtractor_ExtractFromCommandAndOutput(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("successful context creation", func(t *testing.T) {
		output := `NAME                     READY   STATUS    RESTARTS   AGE
test-pod-1               1/1     Running   0          5m
test-pod-2               0/1     Pending   0          2m`
		
		command := "kubectl get pods"
		namespace := "test-namespace"
		
		context, err := extractor.ExtractFromCommandAndOutput(command, output, namespace)
		
		require.NoError(t, err)
		assert.NotNil(t, context)
		assert.Len(t, context.NamedEntities, 2)
		assert.Len(t, context.ReferenceableItems, 2)
		
		// Check namespace was set
		for _, entity := range context.NamedEntities {
			assert.Equal(t, namespace, entity.Namespace)
		}
		
		for _, item := range context.ReferenceableItems {
			assert.Equal(t, namespace, item.Namespace)
		}
	})
	
	t.Run("failed extraction", func(t *testing.T) {
		output := ""
		command := "kubectl get pods"
		
		context, err := extractor.ExtractFromCommandAndOutput(command, output, "default")
		
		assert.Error(t, err)
		assert.Nil(t, context)
	})
}

func TestEntityExtractor_ValidateReference(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("valid reference", func(t *testing.T) {
		// Create a context with test data
		context := models.NewSessionContext()
		context.AddReferenceItem(models.ReferenceItem{
			ID:       "pod-1",
			Type:     "pod",
			Name:     "test-pod-1",
			Position: 1,
		})
		
		valid, message := extractor.ValidateReference("first pod", context)
		
		assert.True(t, valid)
		assert.Equal(t, "Reference is valid", message)
	})
	
	t.Run("invalid reference", func(t *testing.T) {
		context := models.NewSessionContext()
		
		valid, message := extractor.ValidateReference("first pod", context)
		
		assert.False(t, valid)
		assert.Contains(t, message, "no pod item found at position")
	})
	
	t.Run("nil context", func(t *testing.T) {
		valid, message := extractor.ValidateReference("first pod", nil)
		
		assert.False(t, valid)
		assert.Equal(t, "No active context available", message)
	})
	
	t.Run("expired context", func(t *testing.T) {
		context := models.NewSessionContext()
		context.ContextExpiry = context.ContextExpiry.Add(-1 * time.Hour) // Make it expired
		
		valid, message := extractor.ValidateReference("first pod", context)
		
		assert.False(t, valid)
		assert.Equal(t, "No active context available", message)
	})
}

func TestEntityExtractor_ParsePlainTextFormat(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("extract from plain text", func(t *testing.T) {
		output := `pod/test-pod-1 created
pod/another-pod configured
deployment test-deployment scaled`
		
		entities, refItems, err := extractor.parsePlainTextFormat(output, "pod")
		
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(entities), 1)
		assert.GreaterOrEqual(t, len(refItems), 1)
		
		// Should find kubernetes-style names
		found := false
		for _, entity := range entities {
			if strings.Contains(entity.Name, "test-pod") || strings.Contains(entity.Name, "another-pod") {
				found = true
				break
			}
		}
		assert.True(t, found, "Should find resource names in plain text")
	})
	
	t.Run("empty plain text", func(t *testing.T) {
		output := ""
		
		entities, refItems, err := extractor.parsePlainTextFormat(output, "pod")
		
		require.NoError(t, err)
		assert.Empty(t, entities)
		assert.Empty(t, refItems)
	})
}

func TestEntityExtractor_ExtractMetadataFromMatches(t *testing.T) {
	extractor := NewEntityExtractor()
	
	t.Run("pod metadata", func(t *testing.T) {
		matches := []string{"full_match", "pod-name", "1/1", "Running", "0", "5m"}
		
		metadata := extractor.extractMetadataFromMatches(matches, "pod")
		
		assert.Equal(t, "1/1", metadata["ready"])
		assert.Equal(t, "Running", metadata["status"])
		assert.Equal(t, "0", metadata["restarts"])
		assert.Equal(t, "5m", metadata["age"])
	})
	
	t.Run("service metadata", func(t *testing.T) {
		matches := []string{"full_match", "svc-name", "ClusterIP", "10.96.0.1", "<none>", "5m"}
		
		metadata := extractor.extractMetadataFromMatches(matches, "service")
		
		assert.Equal(t, "ClusterIP", metadata["type"])
		assert.Equal(t, "10.96.0.1", metadata["clusterIP"])
		assert.Equal(t, "<none>", metadata["externalIP"])
		assert.Equal(t, "5m", metadata["age"])
	})
	
	t.Run("insufficient matches", func(t *testing.T) {
		matches := []string{"full_match", "name"}
		
		metadata := extractor.extractMetadataFromMatches(matches, "pod")
		
		// Should not panic and return empty metadata
		assert.NotNil(t, metadata)
	})
}