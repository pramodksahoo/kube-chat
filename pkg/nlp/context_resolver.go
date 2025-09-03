package nlp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ContextResolver resolves conversational references using session context
type ContextResolver struct {
	// Patterns for detecting referential expressions
	ordinalPattern      *regexp.Regexp
	demonstrativePattern *regexp.Regexp
	pronounPattern      *regexp.Regexp
	numberedPattern     *regexp.Regexp // NEW: For "pod 1", "service 2" style references
	
	// Entity extractor for context processing
	entityExtractor *EntityExtractor
}

// NewContextResolver creates a new context resolver
func NewContextResolver() *ContextResolver {
	return &ContextResolver{
		// Patterns for detecting referential expressions in natural language
		ordinalPattern:       regexp.MustCompile(`(?i)\b(first|second|third|fourth|fifth|1st|2nd|3rd|4th|5th|\d+st|\d+nd|\d+rd|\d+th)\s+(one|pod|service|deployment|namespace|node|secret|configmap|ingress)\b`),
		demonstrativePattern: regexp.MustCompile(`(?i)\b(that|this|the)\s+(pod|service|deployment|namespace|node|secret|configmap|ingress)\b`),
		pronounPattern:       regexp.MustCompile(`(?i)\b(it|them|they|those|these)\b`),
		numberedPattern:      regexp.MustCompile(`(?i)\b(pod|service|deployment|namespace|node|secret|configmap|ingress)\s+(\d+)\b`),
		
		entityExtractor: NewEntityExtractor(),
	}
}

// ResolveReferences analyzes input for referential expressions and resolves them using session context
func (cr *ContextResolver) ResolveReferences(input string, sessionContext *models.SessionContext) (string, []string, error) {
	if sessionContext == nil || sessionContext.IsExpired() {
		return input, nil, fmt.Errorf("no active context available for reference resolution")
	}
	
	resolvedInput := input
	var resolvedReferences []string
	
	// First, check for ordinal references ("first pod", "second service")
	ordinalMatches := cr.ordinalPattern.FindAllStringSubmatch(input, -1)
	for _, match := range ordinalMatches {
		if len(match) >= 3 {
			ordinal := match[1]
			resourceType := match[2]
			reference := fmt.Sprintf("%s %s", ordinal, resourceType)
			
			resolvedItem, err := sessionContext.GetEntityByReference(reference)
			if err != nil {
				return input, nil, fmt.Errorf("failed to resolve reference '%s': %w", reference, err)
			}
			
			// Replace the reference with the actual resource name
			replacement := resolvedItem.Name
			resolvedInput = strings.Replace(resolvedInput, match[0], replacement, 1)
			resolvedReferences = append(resolvedReferences, fmt.Sprintf("%s -> %s", reference, resolvedItem.Name))
		}
	}
	
	// Check for demonstrative references ("that pod", "this service")
	demonstrativeMatches := cr.demonstrativePattern.FindAllStringSubmatch(resolvedInput, -1)
	for _, match := range demonstrativeMatches {
		if len(match) >= 3 {
			demonstrative := match[1]
			resourceType := match[2]
			reference := fmt.Sprintf("%s %s", demonstrative, resourceType)
			
			resolvedItem, err := sessionContext.GetEntityByReference(reference)
			if err != nil {
				return input, nil, fmt.Errorf("failed to resolve reference '%s': %w", reference, err)
			}
			
			// Replace the reference with the actual resource name
			replacement := resolvedItem.Name
			resolvedInput = strings.Replace(resolvedInput, match[0], replacement, 1)
			resolvedReferences = append(resolvedReferences, fmt.Sprintf("%s -> %s", reference, resolvedItem.Name))
		}
	}
	
	// Check for pronoun references ("it", "them") - these are more complex and context-dependent
	pronounMatches := cr.pronounPattern.FindAllStringSubmatch(resolvedInput, -1)
	for _, match := range pronounMatches {
		pronoun := match[1]
		
		// For pronouns, we need to infer what they refer to based on the command context
		// This is a simplified implementation - in practice, this would be more sophisticated
		if len(sessionContext.ReferenceableItems) > 0 {
			// Default to the most recently referenced item
			mostRecent := sessionContext.ReferenceableItems[len(sessionContext.ReferenceableItems)-1]
			
			replacement := mostRecent.Name
			resolvedInput = strings.Replace(resolvedInput, match[0], replacement, 1)
			resolvedReferences = append(resolvedReferences, fmt.Sprintf("%s -> %s", pronoun, mostRecent.Name))
		}
	}
	
	// Check for numbered references ("pod 1", "service 2")
	numberedMatches := cr.numberedPattern.FindAllStringSubmatch(resolvedInput, -1)
	for _, match := range numberedMatches {
		if len(match) >= 3 {
			resourceType := match[1]
			numberStr := match[2]
			reference := fmt.Sprintf("%s %s", resourceType, numberStr)
			
			// Convert number string to position
			var position int
			if _, err := fmt.Sscanf(numberStr, "%d", &position); err != nil {
				continue
			}
			
			// Find item by position and type
			resolvedItem, err := sessionContext.GetEntityByNumberedReference(resourceType, position)
			if err != nil {
				return input, nil, fmt.Errorf("failed to resolve numbered reference '%s': %w", reference, err)
			}
			
			// Replace the reference with the actual resource name
			replacement := resolvedItem.Name
			resolvedInput = strings.Replace(resolvedInput, match[0], replacement, 1)
			resolvedReferences = append(resolvedReferences, fmt.Sprintf("%s -> %s", reference, resolvedItem.Name))
		}
	}
	
	return resolvedInput, resolvedReferences, nil
}

// ValidateReference checks if a reference can be resolved in the current context
func (cr *ContextResolver) ValidateReference(reference string, sessionContext *models.SessionContext) (bool, string, *models.ReferenceItem) {
	if sessionContext == nil || sessionContext.IsExpired() {
		return false, "No active context available", nil
	}
	
	resolvedItem, err := sessionContext.GetEntityByReference(reference)
	if err != nil {
		return false, err.Error(), nil
	}
	
	return true, "Reference is valid", resolvedItem
}

// GetAvailableReferences returns a formatted list of what can be referenced
func (cr *ContextResolver) GetAvailableReferences(sessionContext *models.SessionContext) map[string]interface{} {
	if sessionContext == nil || sessionContext.IsExpired() {
		return map[string]interface{}{
			"available": false,
			"reason":    "No active context",
			"references": []string{},
		}
	}
	
	references := sessionContext.GetAvailableReferences()
	
	// Format for user-friendly display
	formattedReferences := make(map[string][]string)
	ordinalReferences := make([]string, 0)
	
	position := 1
	for resourceType, items := range references {
		formattedItems := make([]string, 0)
		
		for _, itemName := range items {
			// Add both name and ordinal reference options
			formattedItems = append(formattedItems, itemName)
			ordinalReferences = append(ordinalReferences, fmt.Sprintf("%s %s (%s)", 
				cr.numberToOrdinal(position), resourceType, itemName))
			position++
		}
		
		formattedReferences[resourceType] = formattedItems
	}
	
	return map[string]interface{}{
		"available": true,
		"by_type": formattedReferences,
		"ordinal_references": ordinalReferences,
		"demonstrative_examples": []string{
			"that pod", "this service", "the deployment",
		},
		"pronoun_examples": []string{
			"describe it", "delete them", "scale those",
		},
	}
}

// DetectAmbiguousReferences identifies potentially ambiguous references that need clarification
func (cr *ContextResolver) DetectAmbiguousReferences(input string, sessionContext *models.SessionContext) []string {
	var ambiguous []string
	
	if sessionContext == nil || sessionContext.IsExpired() {
		return ambiguous
	}
	
	// Check for pronouns without clear antecedents
	pronounMatches := cr.pronounPattern.FindAllString(input, -1)
	if len(pronounMatches) > 0 && len(sessionContext.ReferenceableItems) == 0 {
		ambiguous = append(ambiguous, "Pronouns used but no previous context available")
	}
	
	// Check for demonstratives that might match multiple items
	demonstrativeMatches := cr.demonstrativePattern.FindAllStringSubmatch(input, -1)
	for _, match := range demonstrativeMatches {
		if len(match) >= 3 {
			resourceType := match[2]
			
			// Count items of this type in context
			count := 0
			for _, item := range sessionContext.ReferenceableItems {
				if strings.Contains(strings.ToLower(item.Type), resourceType) {
					count++
				}
			}
			
			if count > 1 {
				ambiguous = append(ambiguous, fmt.Sprintf("'%s' could refer to %d different %ss", 
					match[0], count, resourceType))
			} else if count == 0 {
				ambiguous = append(ambiguous, fmt.Sprintf("No %s found in current context", resourceType))
			}
		}
	}
	
	return ambiguous
}

// SuggestClarifications suggests clarifications for ambiguous references
func (cr *ContextResolver) SuggestClarifications(input string, sessionContext *models.SessionContext) []string {
	var suggestions []string
	
	if sessionContext == nil || sessionContext.IsExpired() {
		suggestions = append(suggestions, "Please run a command first to establish context (e.g., 'get pods')")
		return suggestions
	}
	
	// Suggest specific names instead of ambiguous references
	ambiguousRefs := cr.DetectAmbiguousReferences(input, sessionContext)
	for _, ambiguous := range ambiguousRefs {
		if strings.Contains(ambiguous, "could refer to") {
			suggestions = append(suggestions, "Use specific names or ordinal references like 'first pod', 'second service'")
		} else if strings.Contains(ambiguous, "not found in current context") {
			// Suggest available alternatives
			available := cr.GetAvailableReferences(sessionContext)
			if byType, ok := available["by_type"].(map[string][]string); ok {
				var availableTypes []string
				for resourceType := range byType {
					availableTypes = append(availableTypes, resourceType)
				}
				if len(availableTypes) > 0 {
					suggestions = append(suggestions, fmt.Sprintf("Available resources: %s", 
						strings.Join(availableTypes, ", ")))
				}
			}
		}
	}
	
	if len(suggestions) == 0 {
		// General suggestions when context is available
		suggestions = append(suggestions, 
			"You can reference items by name, ordinal (first, second), or demonstrative (that, this)")
	}
	
	return suggestions
}

// EnhanceCommandWithContext enhances a kubectl command by resolving references and adding context
func (cr *ContextResolver) EnhanceCommandWithContext(originalCommand string, resolvedInput string, references []string, sessionContext *models.SessionContext) map[string]interface{} {
	enhancement := map[string]interface{}{
		"original_command":     originalCommand,
		"resolved_command":     originalCommand, // Will be updated if changes needed
		"resolved_references":  references,
		"context_used":         len(references) > 0,
		"namespace_context":    "",
		"additional_context":   map[string]interface{}{},
	}
	
	if sessionContext == nil {
		return enhancement
	}
	
	// Add namespace context if available from session
	if len(sessionContext.ReferenceableItems) > 0 {
		// Use namespace from most recent item
		latestItem := sessionContext.ReferenceableItems[len(sessionContext.ReferenceableItems)-1]
		if latestItem.Namespace != "" && latestItem.Namespace != "default" {
			enhancement["namespace_context"] = latestItem.Namespace
			
			// If command doesn't already specify namespace, suggest adding it
			if !strings.Contains(originalCommand, "-n ") && !strings.Contains(originalCommand, "--namespace") {
				enhancedCommand := originalCommand + fmt.Sprintf(" -n %s", latestItem.Namespace)
				enhancement["resolved_command"] = enhancedCommand
			}
		}
	}
	
	// Add context metadata for debugging/logging
	enhancement["additional_context"] = map[string]interface{}{
		"context_items_count": len(sessionContext.ReferenceableItems),
		"context_expired":     sessionContext.IsExpired(),
		"last_command_id":     sessionContext.LastCommandID,
	}
	
	return enhancement
}

// numberToOrdinal converts a number to its ordinal representation
func (cr *ContextResolver) numberToOrdinal(n int) string {
	if n <= 0 {
		return "0th"
	}
	
	ordinals := map[int]string{
		1: "first", 2: "second", 3: "third", 4: "fourth", 5: "fifth",
		6: "sixth", 7: "seventh", 8: "eighth", 9: "ninth", 10: "tenth",
	}
	
	if ordinal, exists := ordinals[n]; exists {
		return ordinal
	}
	
	// For numbers > 10, use numeric ordinals
	// Special cases for 11, 12, 13 (always "th")
	if n%100 >= 11 && n%100 <= 13 {
		return fmt.Sprintf("%dth", n)
	}
	
	switch n % 10 {
	case 1:
		return fmt.Sprintf("%dst", n)
	case 2:
		return fmt.Sprintf("%dnd", n)
	case 3:
		return fmt.Sprintf("%drd", n)
	default:
		return fmt.Sprintf("%dth", n)
	}
}

// ContainsReferences checks if input contains any referential expressions
func (cr *ContextResolver) ContainsReferences(input string) bool {
	return cr.ordinalPattern.MatchString(input) || 
		   cr.demonstrativePattern.MatchString(input) || 
		   cr.pronounPattern.MatchString(input) ||
		   cr.numberedPattern.MatchString(input)
}

// ExtractReferences extracts all referential expressions from input without resolving them
func (cr *ContextResolver) ExtractReferences(input string) []string {
	var references []string
	
	// Extract ordinal references
	ordinalMatches := cr.ordinalPattern.FindAllString(input, -1)
	references = append(references, ordinalMatches...)
	
	// Extract demonstrative references
	demonstrativeMatches := cr.demonstrativePattern.FindAllString(input, -1)
	references = append(references, demonstrativeMatches...)
	
	// Extract pronoun references
	pronounMatches := cr.pronounPattern.FindAllString(input, -1)
	references = append(references, pronounMatches...)
	
	// Extract numbered references
	numberedMatches := cr.numberedPattern.FindAllString(input, -1)
	references = append(references, numberedMatches...)
	
	return references
}

// GetErrorSuggestions integrates with error handling to provide context-aware suggestions
func (cr *ContextResolver) GetErrorSuggestions(input string, sessionContext *models.SessionContext, errorType models.ErrorType) []string {
	var suggestions []string
	
	// Check if the error is related to ambiguous references
	if errorType == models.ErrorTypeNLPAmbiguous {
		ambiguous := cr.DetectAmbiguousReferences(input, sessionContext)
		if len(ambiguous) > 0 {
			// Provide specific suggestions based on available context
			if sessionContext != nil && len(sessionContext.ReferenceableItems) > 0 {
				// Suggest using specific names
				for i, item := range sessionContext.ReferenceableItems {
					if i >= 3 { // Limit to first 3 items
						break
					}
					suggestions = append(suggestions, fmt.Sprintf("describe %s %s", item.Type, item.Name))
				}
				
				// Suggest ordinal references
				if len(sessionContext.ReferenceableItems) > 1 {
					suggestions = append(suggestions, "Use ordinal references like 'first pod', 'second service'")
				}
			}
		}
	}
	
	// For malformed references, suggest proper format
	if errorType == models.ErrorTypeNLPMalformed && cr.ContainsReferences(input) {
		suggestions = append(suggestions, []string{
			"Use proper references like 'the first pod' or 'that service'",
			"Specify resource names explicitly instead of using pronouns",
		}...)
	}
	
	// For context-dependent operations without context
	if sessionContext == nil || len(sessionContext.ReferenceableItems) == 0 {
		suggestions = append(suggestions, []string{
			"First run a command to get resources: 'get pods'",
			"Then you can reference them: 'describe the first pod'",
		}...)
	}
	
	return suggestions
}

// ValidateContextReference checks if a reference can be resolved with current context
func (cr *ContextResolver) ValidateContextReference(input string, sessionContext *models.SessionContext) (bool, []string) {
	if sessionContext == nil || sessionContext.IsExpired() {
		return false, []string{"No active context available"}
	}
	
	var issues []string
	valid := true
	
	// Check ordinal references
	ordinalMatches := cr.ordinalPattern.FindAllStringSubmatch(input, -1)
	for _, match := range ordinalMatches {
		if len(match) >= 3 {
			resourceType := match[2]
			// Count matching resources
			count := 0
			for _, item := range sessionContext.ReferenceableItems {
				if strings.Contains(strings.ToLower(item.Type), resourceType) {
					count++
				}
			}
			if count == 0 {
				issues = append(issues, fmt.Sprintf("No %s found in current context", resourceType))
				valid = false
			}
		}
	}
	
	// Check demonstrative references
	demonstrativeMatches := cr.demonstrativePattern.FindAllStringSubmatch(input, -1)
	for _, match := range demonstrativeMatches {
		if len(match) >= 3 {
			resourceType := match[2]
			count := 0
			for _, item := range sessionContext.ReferenceableItems {
				if strings.Contains(strings.ToLower(item.Type), resourceType) {
					count++
				}
			}
			if count == 0 {
				issues = append(issues, fmt.Sprintf("No %s found for 'that %s' reference", resourceType, resourceType))
				valid = false
			} else if count > 1 {
				issues = append(issues, fmt.Sprintf("'that %s' is ambiguous - %d %ss found", resourceType, count, resourceType))
				valid = false
			}
		}
	}
	
	// Check pronoun references
	if cr.pronounPattern.MatchString(input) && len(sessionContext.ReferenceableItems) == 0 {
		issues = append(issues, "Pronoun used but no resources available in context")
		valid = false
	}
	
	return valid, issues
}

// SuggestContextualCommands suggests commands based on current session context
func (cr *ContextResolver) SuggestContextualCommands(sessionContext *models.SessionContext) []string {
	var suggestions []string
	
	if sessionContext == nil || len(sessionContext.ReferenceableItems) == 0 {
		// No context, suggest basic commands
		return []string{
			"get pods",
			"get services",
			"get deployments",
		}
	}
	
	// Group items by type
	resourceCounts := make(map[string]int)
	for _, item := range sessionContext.ReferenceableItems {
		resourceCounts[item.Type]++
	}
	
	// Suggest operations based on available resources
	for resourceType, count := range resourceCounts {
		if count == 1 {
			suggestions = append(suggestions, fmt.Sprintf("describe that %s", resourceType))
		} else {
			suggestions = append(suggestions, fmt.Sprintf("describe the first %s", resourceType))
		}
		
		// Suggest other operations
		if strings.Contains(resourceType, "pod") {
			suggestions = append(suggestions, "logs from the first pod")
		}
		if strings.Contains(resourceType, "deployment") {
			suggestions = append(suggestions, "scale that deployment")
		}
	}
	
	// Add numbered reference suggestions
	if len(sessionContext.ReferenceableItems) > 1 {
		firstItem := sessionContext.ReferenceableItems[0]
		suggestions = append(suggestions, fmt.Sprintf("%s 1", firstItem.Type))
		if len(sessionContext.ReferenceableItems) > 2 {
			suggestions = append(suggestions, fmt.Sprintf("%s 2", firstItem.Type))
		}
	}
	
	// Limit suggestions
	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}
	
	return suggestions
}