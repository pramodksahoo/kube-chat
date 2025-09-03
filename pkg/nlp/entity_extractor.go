package nlp

import (
	"bufio"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// EntityExtractor extracts named entities from kubectl command outputs
type EntityExtractor struct {
	// Regular expressions for parsing different kubectl output formats
	tableHeaderRegex *regexp.Regexp
	podRegex         *regexp.Regexp
	serviceRegex     *regexp.Regexp
	deploymentRegex  *regexp.Regexp
	namespaceRegex   *regexp.Regexp
}

// NewEntityExtractor creates a new entity extractor
func NewEntityExtractor() *EntityExtractor {
	return &EntityExtractor{
		// Regex for identifying table headers (NAME, READY, STATUS, etc.)
		tableHeaderRegex: regexp.MustCompile(`^NAME\s+`),
		
		// Regex patterns for different resource types in kubectl output
		podRegex:        regexp.MustCompile(`^([a-z0-9\-]+)\s+(\d+/\d+|\d+)\s+(Running|Pending|Failed|Succeeded|CrashLoopBackOff|ContainerCreating|Terminating)\s+(\d+)\s+([0-9]+[smhd]|[0-9]+[smhd][0-9]+[smhd]?)`),
		serviceRegex:    regexp.MustCompile(`^([a-z0-9\-]+)\s+(ClusterIP|NodePort|LoadBalancer|ExternalName)\s+([0-9\.]+|<none>)\s+([0-9\.\:\,\/<>a-zA-Z\-]+)\s+([0-9]+[smhd]|[0-9]+[smhd][0-9]+[smhd]?)`),
		deploymentRegex: regexp.MustCompile(`^([a-z0-9\-]+)\s+(\d+/\d+)\s+(\d+)\s+(\d+)\s+([0-9]+[smhd]|[0-9]+[smhd][0-9]+[smhd]?)`),
		namespaceRegex:  regexp.MustCompile(`^([a-z0-9\-]+)\s+(Active|Terminating)\s+([0-9]+[smhd]|[0-9]+[smhd][0-9]+[smhd]?)`),
	}
}

// ExtractEntitiesFromOutput extracts entities from kubectl command output
func (ee *EntityExtractor) ExtractEntitiesFromOutput(output string, command string) ([]models.ContextEntity, []models.ReferenceItem, error) {
	if strings.TrimSpace(output) == "" {
		return nil, nil, fmt.Errorf("empty output provided")
	}

	// Determine command type and resource type
	resourceType := ee.determineResourceType(command)
	if resourceType == "" {
		return nil, nil, fmt.Errorf("unable to determine resource type from command: %s", command)
	}

	// Parse the output based on detected format
	if ee.isTableFormat(output) {
		return ee.parseTableFormat(output, resourceType)
	} else if ee.isJSONFormat(output) {
		return ee.parseJSONFormat(output, resourceType)
	} else if ee.isYAMLFormat(output) {
		return ee.parseYAMLFormat(output, resourceType)
	} else {
		// Try parsing as plain text
		return ee.parsePlainTextFormat(output, resourceType)
	}
}

// determineResourceType determines the resource type from the kubectl command
func (ee *EntityExtractor) determineResourceType(command string) string {
	command = strings.ToLower(command)
	
	// Remove kubectl prefix if present
	if strings.HasPrefix(command, "kubectl ") {
		command = strings.TrimPrefix(command, "kubectl ")
	}
	
	// Check for resource type keywords
	resourceMappings := map[string]string{
		"pods":        "pod",
		"pod":         "pod",
		"po":          "pod",
		"services":    "service",
		"service":     "service",
		"svc":         "service",
		"deployments": "deployment",
		"deployment":  "deployment",
		"deploy":      "deployment",
		"namespaces":  "namespace",
		"namespace":   "namespace",
		"ns":          "namespace",
		"nodes":       "node",
		"node":        "node",
		"configmaps":  "configmap",
		"configmap":   "configmap",
		"cm":          "configmap",
		"secrets":     "secret",
		"secret":      "secret",
	}
	
	words := strings.Fields(command)
	for _, word := range words {
		if resourceType, found := resourceMappings[word]; found {
			return resourceType
		}
	}
	
	return ""
}

// isTableFormat checks if output is in table format
func (ee *EntityExtractor) isTableFormat(output string) bool {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return false
	}
	
	// Check if first line looks like a header
	firstLine := strings.TrimSpace(lines[0])
	return ee.tableHeaderRegex.MatchString(firstLine)
}

// isJSONFormat checks if output is in JSON format
func (ee *EntityExtractor) isJSONFormat(output string) bool {
	trimmed := strings.TrimSpace(output)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

// isYAMLFormat checks if output is in YAML format
func (ee *EntityExtractor) isYAMLFormat(output string) bool {
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && strings.Contains(trimmed, ":") && 
			(strings.HasPrefix(trimmed, "apiVersion:") || strings.HasPrefix(trimmed, "kind:")) {
			return true
		}
	}
	return false
}

// parseTableFormat parses kubectl table format output
func (ee *EntityExtractor) parseTableFormat(output, resourceType string) ([]models.ContextEntity, []models.ReferenceItem, error) {
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return nil, nil, fmt.Errorf("insufficient lines in table output")
	}

	var entities []models.ContextEntity
	var referenceItems []models.ReferenceItem
	position := 1
	now := time.Now()

	// Skip header line and process data lines
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		entity, refItem, err := ee.parseTableLine(line, resourceType, position, now)
		if err != nil {
			// Log error but continue processing other lines
			continue
		}

		if entity != nil {
			entities = append(entities, *entity)
		}
		if refItem != nil {
			referenceItems = append(referenceItems, *refItem)
		}
		position++
	}

	return entities, referenceItems, nil
}

// parseTableLine parses a single line from kubectl table output
func (ee *EntityExtractor) parseTableLine(line, resourceType string, position int, timestamp time.Time) (*models.ContextEntity, *models.ReferenceItem, error) {
	var regex *regexp.Regexp
	
	switch resourceType {
	case "pod":
		regex = ee.podRegex
	case "service":
		regex = ee.serviceRegex
	case "deployment":
		regex = ee.deploymentRegex
	case "namespace":
		regex = ee.namespaceRegex
	default:
		// Generic parsing for unknown resource types
		return ee.parseGenericTableLine(line, resourceType, position, timestamp)
	}

	matches := regex.FindStringSubmatch(line)
	if len(matches) < 2 {
		return ee.parseGenericTableLine(line, resourceType, position, timestamp)
	}

	name := matches[1]
	
	// Extract namespace from context if available (this would be passed in from session)
	namespace := "default" // Default assumption, should be derived from session context

	entity := &models.ContextEntity{
		Type:      resourceType,
		Name:      name,
		Namespace: namespace,
		Position:  position,
		LastSeen:  timestamp,
	}

	refItem := &models.ReferenceItem{
		ID:        fmt.Sprintf("%s-%d", resourceType, position),
		Type:      resourceType,
		Name:      name,
		Namespace: namespace,
		Position:  position,
		LastSeen:  timestamp,
		Metadata:  ee.extractMetadataFromMatches(matches, resourceType),
	}

	return entity, refItem, nil
}

// parseGenericTableLine parses a generic table line when specific regex doesn't match
func (ee *EntityExtractor) parseGenericTableLine(line, resourceType string, position int, timestamp time.Time) (*models.ContextEntity, *models.ReferenceItem, error) {
	// Generic parsing: assume first field is the name
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("no fields found in line: %s", line)
	}

	name := fields[0]
	namespace := "default"

	entity := &models.ContextEntity{
		Type:      resourceType,
		Name:      name,
		Namespace: namespace,
		Position:  position,
		LastSeen:  timestamp,
	}

	refItem := &models.ReferenceItem{
		ID:        fmt.Sprintf("%s-%d", resourceType, position),
		Type:      resourceType,
		Name:      name,
		Namespace: namespace,
		Position:  position,
		LastSeen:  timestamp,
		Metadata:  map[string]interface{}{"rawFields": fields},
	}

	return entity, refItem, nil
}

// extractMetadataFromMatches extracts metadata from regex matches
func (ee *EntityExtractor) extractMetadataFromMatches(matches []string, resourceType string) map[string]interface{} {
	metadata := make(map[string]interface{})
	
	switch resourceType {
	case "pod":
		if len(matches) >= 6 {
			metadata["ready"] = matches[2]
			metadata["status"] = matches[3]
			metadata["restarts"] = matches[4]
			metadata["age"] = matches[5]
		}
	case "service":
		if len(matches) >= 6 {
			metadata["type"] = matches[2]
			metadata["clusterIP"] = matches[3]
			metadata["externalIP"] = matches[4]
			metadata["age"] = matches[5]
		}
	case "deployment":
		if len(matches) >= 6 {
			metadata["ready"] = matches[2]
			metadata["upToDate"] = matches[3]
			metadata["available"] = matches[4]
			metadata["age"] = matches[5]
		}
	case "namespace":
		if len(matches) >= 4 {
			metadata["status"] = matches[2]
			metadata["age"] = matches[3]
		}
	}
	
	return metadata
}

// parseJSONFormat parses JSON format output (placeholder implementation)
func (ee *EntityExtractor) parseJSONFormat(output, resourceType string) ([]models.ContextEntity, []models.ReferenceItem, error) {
	// This would implement JSON parsing logic
	// For now, return error indicating it's not implemented
	return nil, nil, fmt.Errorf("JSON format parsing not yet implemented")
}

// parseYAMLFormat parses YAML format output (placeholder implementation)
func (ee *EntityExtractor) parseYAMLFormat(output, resourceType string) ([]models.ContextEntity, []models.ReferenceItem, error) {
	// This would implement YAML parsing logic
	// For now, return error indicating it's not implemented
	return nil, nil, fmt.Errorf("YAML format parsing not yet implemented")
}

// parsePlainTextFormat parses plain text output
func (ee *EntityExtractor) parsePlainTextFormat(output, resourceType string) ([]models.ContextEntity, []models.ReferenceItem, error) {
	var entities []models.ContextEntity
	var referenceItems []models.ReferenceItem
	
	scanner := bufio.NewScanner(strings.NewReader(output))
	position := 1
	now := time.Now()
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		// Try to extract resource names from plain text
		words := strings.Fields(line)
		for _, word := range words {
			var resourceName string
			
			// Check if it's in format "resource/name"
			if strings.Contains(word, "/") {
				parts := strings.Split(word, "/")
				if len(parts) == 2 {
					resourceName = parts[1]
				}
			} else {
				resourceName = word
			}
			
			// Simple heuristic: if it looks like a kubernetes resource name
			if ee.looksLikeResourceName(resourceName) {
				entity := models.ContextEntity{
					Type:      resourceType,
					Name:      resourceName,
					Namespace: "default",
					Position:  position,
					LastSeen:  now,
				}
				
				refItem := models.ReferenceItem{
					ID:        fmt.Sprintf("%s-%d", resourceType, position),
					Type:      resourceType,
					Name:      resourceName,
					Namespace: "default",
					Position:  position,
					LastSeen:  now,
					Metadata:  map[string]interface{}{"source": "plaintext"},
				}
				
				entities = append(entities, entity)
				referenceItems = append(referenceItems, refItem)
				position++
			}
		}
	}
	
	return entities, referenceItems, nil
}

// looksLikeResourceName checks if a string looks like a Kubernetes resource name
func (ee *EntityExtractor) looksLikeResourceName(name string) bool {
	// Kubernetes resource names are typically lowercase with hyphens
	matched, _ := regexp.MatchString(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`, name)
	return matched && len(name) > 3 // Minimum reasonable length
}

// ExtractFromCommandAndOutput is a convenience method that combines command analysis and output parsing
func (ee *EntityExtractor) ExtractFromCommandAndOutput(command, output, namespace string) (*models.SessionContext, error) {
	entities, refItems, err := ee.ExtractEntitiesFromOutput(output, command)
	if err != nil {
		return nil, fmt.Errorf("failed to extract entities: %w", err)
	}
	
	// Create a session context with the extracted data
	context := models.NewSessionContext()
	
	// Set namespace for all entities if provided
	for i := range entities {
		if namespace != "" {
			entities[i].Namespace = namespace
		}
		context.AddEntity(entities[i])
	}
	
	for i := range refItems {
		if namespace != "" {
			refItems[i].Namespace = namespace
		}
		context.AddReferenceItem(refItems[i])
	}
	
	return context, nil
}

// ValidateReference validates if a reference can be resolved in the given context
func (ee *EntityExtractor) ValidateReference(reference string, context *models.SessionContext) (bool, string) {
	if context == nil || context.IsExpired() {
		return false, "No active context available"
	}
	
	_, err := context.GetEntityByReference(reference)
	if err != nil {
		return false, err.Error()
	}
	
	return true, "Reference is valid"
}