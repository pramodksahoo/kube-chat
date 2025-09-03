package nlp

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// SuggestionEngine provides intelligent suggestions for failed or ambiguous NLP commands
type SuggestionEngine struct {
	// Command patterns and their suggestions
	commonPatterns map[string][]string
	
	// Typo correction mappings
	typoCorrections map[string]string
	
	// Resource type mappings
	resourceAliases map[string]string
}

// NewSuggestionEngine creates a new suggestion engine with predefined patterns
func NewSuggestionEngine() *SuggestionEngine {
	return &SuggestionEngine{
		commonPatterns: map[string][]string{
			// List/show operations
			"list|show|display|view": {
				"get pods",
				"get services", 
				"get deployments",
				"get namespaces",
				"get nodes",
			},
			// Describe operations
			"describe|details|info|information": {
				"describe pod <pod-name>",
				"describe service <service-name>",
				"describe deployment <deployment-name>",
				"describe node <node-name>",
			},
			// Delete operations
			"delete|remove|destroy": {
				"delete pod <pod-name>",
				"delete service <service-name>",
				"delete deployment <deployment-name>",
			},
			// Create operations
			"create|make|add|new": {
				"create deployment <name> --image=<image>",
				"create service <name> --tcp=80:80",
				"create namespace <namespace-name>",
			},
			// Scale operations
			"scale|resize": {
				"scale deployment <deployment-name> --replicas=<number>",
			},
			// Status/health operations
			"status|health|check": {
				"get pods --all-namespaces",
				"get nodes",
				"describe pod <pod-name>",
			},
		},
		typoCorrections: map[string]string{
			// Common kubectl typos
			"kubctl":     "kubectl",
			"kubectrl":   "kubectl", 
			"kubeclt":    "kubectl",
			// Resource type typos
			"pod":        "pods",
			"service":    "services",
			"deployment": "deployments",
			"namespace":  "namespaces",
			"node":       "nodes",
			// Action typos
			"gt":         "get",
			"gte":        "get",
			"delte":      "delete",
			"deleet":     "delete",
			"creat":      "create",
			"describ":    "describe",
		},
		resourceAliases: map[string]string{
			// Common aliases
			"po":     "pods",
			"svc":    "services", 
			"deploy": "deployments",
			"ns":     "namespaces",
			"no":     "nodes",
			// Plural/singular mappings
			"pod":        "pods",
			"service":    "services",
			"deployment": "deployments",
			"namespace":  "namespaces",
			"node":       "nodes",
		},
	}
}

// SuggestCorrections analyzes failed input and provides correction suggestions
func (se *SuggestionEngine) SuggestCorrections(input string, errorType models.ErrorType) []string {
	input = strings.ToLower(strings.TrimSpace(input))
	var suggestions []string
	
	switch errorType {
	case models.ErrorTypeNLPMalformed:
		suggestions = se.suggestForMalformed(input)
	case models.ErrorTypeNLPAmbiguous:
		suggestions = se.suggestForAmbiguous(input)
	case models.ErrorTypeNLPUnsupported:
		suggestions = se.suggestForUnsupported(input)
	default:
		suggestions = se.suggestGeneral(input)
	}
	
	// Remove duplicates and limit to top 5 suggestions
	suggestions = se.deduplicateAndLimit(suggestions, 5)
	
	return suggestions
}

// suggestForMalformed provides suggestions for malformed input
func (se *SuggestionEngine) suggestForMalformed(input string) []string {
	var suggestions []string
	
	// Try typo correction first
	corrected := se.correctTypos(input)
	if corrected != input {
		suggestions = append(suggestions, fmt.Sprintf("Did you mean: %s", corrected))
	}
	
	// If input is too short or unclear, suggest common commands
	if len(input) < 5 {
		suggestions = append(suggestions, []string{
			"get pods",
			"get services",
			"get deployments", 
			"describe pod <name>",
		}...)
	}
	
	return suggestions
}

// suggestForAmbiguous provides suggestions for ambiguous input 
func (se *SuggestionEngine) suggestForAmbiguous(input string) []string {
	var suggestions []string
	
	// Look for action patterns and suggest specific alternatives
	for pattern, patternSuggestions := range se.commonPatterns {
		if matched, _ := regexp.MatchString(pattern, input); matched {
			suggestions = append(suggestions, patternSuggestions...)
			break
		}
	}
	
	// If we found pronouns, suggest being more specific
	if regexp.MustCompile(`\b(it|that|this|those|these)\b`).MatchString(input) {
		suggestions = append(suggestions, []string{
			"Use specific resource names instead of 'it', 'that', etc.",
			"Example: 'describe pod nginx-123' instead of 'describe that'",
		}...)
	}
	
	return suggestions
}

// suggestForUnsupported provides suggestions for unsupported operations
func (se *SuggestionEngine) suggestForUnsupported(input string) []string {
	var suggestions []string
	
	// For complex operations, suggest simpler alternatives
	if regexp.MustCompile(`\bmigrate|migration\b`).MatchString(input) {
		suggestions = append(suggestions, []string{
			"Try: get pods (to see current state)",
			"Try: describe deployment <name> (for deployment details)",
		}...)
	}
	
	if regexp.MustCompile(`\bbackup|restore\b`).MatchString(input) {
		suggestions = append(suggestions, []string{
			"Try: get persistentvolumes (to see storage)",
			"Try: describe pvc <name> (for volume details)",
		}...)
	}
	
	// For non-k8s requests, suggest k8s alternatives
	if regexp.MustCompile(`\b(file system|ls|cd)\b`).MatchString(input) {
		suggestions = append(suggestions, []string{
			"Try: get pods (to list kubernetes pods)",
			"Try: get namespaces (to see available namespaces)",
		}...)
	}
	
	return suggestions
}

// suggestGeneral provides general suggestions when specific type is unknown
func (se *SuggestionEngine) suggestGeneral(input string) []string {
	var suggestions []string
	
	// Try to find the best matching pattern
	bestScore := 0
	var bestSuggestions []string
	
	for pattern, patternSuggestions := range se.commonPatterns {
		score := se.calculateSimilarity(input, pattern)
		if score > bestScore {
			bestScore = score
			bestSuggestions = patternSuggestions
		}
	}
	
	if bestScore > 0 {
		suggestions = append(suggestions, bestSuggestions...)
	} else {
		// Fallback to most common commands
		suggestions = append(suggestions, []string{
			"get pods",
			"get services", 
			"get deployments",
			"describe pod <name>",
			"get namespaces",
		}...)
	}
	
	return suggestions
}

// correctTypos attempts to correct common typos in the input
func (se *SuggestionEngine) correctTypos(input string) string {
	words := strings.Fields(input)
	corrected := make([]string, len(words))
	
	for i, word := range words {
		if correction, exists := se.typoCorrections[word]; exists {
			corrected[i] = correction
		} else if alias, exists := se.resourceAliases[word]; exists {
			corrected[i] = alias
		} else {
			corrected[i] = word
		}
	}
	
	return strings.Join(corrected, " ")
}

// calculateSimilarity calculates a simple similarity score between input and pattern
func (se *SuggestionEngine) calculateSimilarity(input, pattern string) int {
	input = strings.ToLower(input)
	pattern = strings.ToLower(pattern)
	
	// Split patterns by | and find best match
	patterns := strings.Split(pattern, "|")
	maxScore := 0
	
	for _, p := range patterns {
		score := 0
		if strings.Contains(input, p) {
			score = len(p) // Longer matches get higher scores
		}
		if score > maxScore {
			maxScore = score
		}
	}
	
	return maxScore
}

// deduplicateAndLimit removes duplicates and limits suggestions to specified count
func (se *SuggestionEngine) deduplicateAndLimit(suggestions []string, limit int) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, suggestion := range suggestions {
		if !seen[suggestion] && len(result) < limit {
			seen[suggestion] = true
			result = append(result, suggestion)
		}
	}
	
	return result
}

// GetContextualSuggestions provides suggestions based on current session context
func (se *SuggestionEngine) GetContextualSuggestions(input string, sessionContext *models.SessionContext) []string {
	var suggestions []string
	
	if sessionContext == nil || len(sessionContext.ReferenceableItems) == 0 {
		// No context available, provide general suggestions
		return se.SuggestCorrections(input, models.ErrorTypeNLPUnsupported)
	}
	
	// Analyze available resources in context
	resourceTypes := make(map[string]int)
	for _, item := range sessionContext.ReferenceableItems {
		resourceTypes[item.Type]++
	}
	
	// Sort resource types by count
	type resourceCount struct {
		resourceType string
		count       int
	}
	
	var sortedResources []resourceCount
	for resourceType, count := range resourceTypes {
		sortedResources = append(sortedResources, resourceCount{resourceType, count})
	}
	
	sort.Slice(sortedResources, func(i, j int) bool {
		return sortedResources[i].count > sortedResources[j].count
	})
	
	// Generate contextual suggestions
	for _, rc := range sortedResources {
		if len(suggestions) >= 3 {
			break
		}
		
		suggestions = append(suggestions, []string{
			fmt.Sprintf("describe %s <name>", rc.resourceType),
			fmt.Sprintf("get %s", rc.resourceType),
		}...)
	}
	
	// Add reference-based suggestions
	if len(sessionContext.ReferenceableItems) > 0 {
		suggestions = append(suggestions, []string{
			"describe the first one",
			"delete that " + sessionContext.ReferenceableItems[0].Type,
			"get details for " + sessionContext.ReferenceableItems[0].Name,
		}...)
	}
	
	return se.deduplicateAndLimit(suggestions, 5)
}

// FormatSuggestionsForDisplay formats suggestions for user-friendly display
func (se *SuggestionEngine) FormatSuggestionsForDisplay(suggestions []string) string {
	if len(suggestions) == 0 {
		return "💡 **Try these common commands:**\n• get pods\n• get services\n• describe pod <name>"
	}
	
	result := "💡 **Suggestions:**\n"
	for i, suggestion := range suggestions {
		result += fmt.Sprintf("• %s\n", suggestion)
		if i >= 4 { // Limit display to 5 suggestions
			break
		}
	}
	
	return strings.TrimSpace(result)
}

// FallbackSuggestions provides comprehensive fallback suggestions when NLP completely fails
func (se *SuggestionEngine) FallbackSuggestions(input string, sessionContext *models.SessionContext) []string {
	var suggestions []string
	
	// Try to salvage something from the input
	input = strings.ToLower(strings.TrimSpace(input))
	
	// Look for any recognizable keywords
	keywords := se.extractKeywords(input)
	
	// Generate suggestions based on keywords
	if len(keywords) > 0 {
		suggestions = se.generateKeywordBasedSuggestions(keywords, sessionContext)
	}
	
	// If still no suggestions, provide most common commands
	if len(suggestions) == 0 {
		suggestions = se.getCommonCommands(sessionContext)
	}
	
	// Ensure we have at least basic commands
	if len(suggestions) == 0 {
		suggestions = []string{
			"get pods",
			"get services", 
			"get deployments",
			"get namespaces",
			"describe pod <name>",
		}
	}
	
	return se.deduplicateAndLimit(suggestions, 5)
}

// extractKeywords attempts to find recognizable kubernetes-related keywords from input
func (se *SuggestionEngine) extractKeywords(input string) []string {
	var keywords []string
	
	// Kubernetes resource types
	resourceTypes := []string{
		"pod", "pods", "service", "services", "deployment", "deployments",
		"namespace", "namespaces", "node", "nodes", "configmap", "configmaps",
		"secret", "secrets", "ingress", "pvc", "persistentvolumeclaim",
	}
	
	// Kubernetes actions
	actions := []string{
		"get", "describe", "delete", "create", "apply", "edit", "scale",
		"logs", "exec", "port-forward", "top", "rollout",
	}
	
	// Check for resource types
	for _, resource := range resourceTypes {
		if strings.Contains(input, resource) {
			keywords = append(keywords, resource)
		}
	}
	
	// Check for actions
	for _, action := range actions {
		if strings.Contains(input, action) {
			keywords = append(keywords, action)
		}
	}
	
	// Look for common operational keywords
	operationalKeywords := []string{
		"status", "health", "running", "failed", "error", "log", "restart",
		"scale", "increase", "decrease", "update", "change", "modify",
	}
	
	for _, keyword := range operationalKeywords {
		if strings.Contains(input, keyword) {
			keywords = append(keywords, keyword)
		}
	}
	
	return keywords
}

// generateKeywordBasedSuggestions creates suggestions based on found keywords
func (se *SuggestionEngine) generateKeywordBasedSuggestions(keywords []string, sessionContext *models.SessionContext) []string {
	var suggestions []string
	
	// Keyword-based suggestion mappings
	keywordSuggestions := map[string][]string{
		// Resource types
		"pod":        {"get pods", "describe pod <name>", "logs <pod-name>"},
		"pods":       {"get pods", "describe pod <name>", "logs <pod-name>"},
		"service":    {"get services", "describe service <name>"},
		"services":   {"get services", "describe service <name>"},
		"deployment": {"get deployments", "describe deployment <name>", "scale deployment <name> --replicas=3"},
		"deployments": {"get deployments", "describe deployment <name>"},
		"namespace":  {"get namespaces", "describe namespace <name>"},
		"node":       {"get nodes", "describe node <name>", "top node"},
		
		// Actions
		"get":        {"get pods", "get services", "get deployments"},
		"describe":   {"describe pod <name>", "describe service <name>", "describe deployment <name>"},
		"delete":     {"delete pod <name>", "delete service <name>", "delete deployment <name>"},
		"create":     {"create deployment <name> --image=<image>", "create service <name>"},
		"logs":       {"logs <pod-name>", "logs -f <pod-name>"},
		"scale":      {"scale deployment <name> --replicas=<number>"},
		
		// Operational
		"status":     {"get pods", "get nodes", "describe pod <name>"},
		"health":     {"get pods", "top nodes", "describe node <name>"},
		"running":    {"get pods --field-selector=status.phase=Running"},
		"failed":     {"get pods --field-selector=status.phase=Failed"},
		"error":      {"describe pod <name>", "logs <pod-name>"},
		"restart":    {"delete pod <name>", "rollout restart deployment <name>"},
	}
	
	// Generate suggestions based on found keywords
	for _, keyword := range keywords {
		if keywordSuggs, exists := keywordSuggestions[keyword]; exists {
			suggestions = append(suggestions, keywordSuggs...)
		}
	}
	
	// If we have session context, make suggestions more specific
	if sessionContext != nil && len(sessionContext.ReferenceableItems) > 0 {
		contextSuggestions := se.makeContextSpecific(suggestions, sessionContext)
		suggestions = append(suggestions, contextSuggestions...)
	}
	
	return suggestions
}

// makeContextSpecific makes generic suggestions more specific based on session context
func (se *SuggestionEngine) makeContextSpecific(genericSuggestions []string, sessionContext *models.SessionContext) []string {
	var contextSuggestions []string
	
	// Replace generic placeholders with actual names from context
	for _, generic := range genericSuggestions {
		if strings.Contains(generic, "<name>") || strings.Contains(generic, "<pod-name>") {
			for i, item := range sessionContext.ReferenceableItems {
				if i >= 2 { // Limit to first 2 items
					break
				}
				
				// Replace placeholders with actual names
				specific := strings.ReplaceAll(generic, "<name>", item.Name)
				specific = strings.ReplaceAll(specific, "<pod-name>", item.Name)
				contextSuggestions = append(contextSuggestions, specific)
			}
		}
	}
	
	return contextSuggestions
}

// getCommonCommands returns the most commonly used kubernetes commands
func (se *SuggestionEngine) getCommonCommands(sessionContext *models.SessionContext) []string {
	commonCommands := []string{
		"get pods",
		"get services",
		"get deployments", 
		"get namespaces",
		"get nodes",
	}
	
	// If we have context, add context-aware commands
	if sessionContext != nil && len(sessionContext.ReferenceableItems) > 0 {
		// Add "describe the first X" type commands
		resourceTypes := make(map[string]bool)
		for _, item := range sessionContext.ReferenceableItems {
			resourceTypes[item.Type] = true
		}
		
		for resourceType := range resourceTypes {
			commonCommands = append(commonCommands, fmt.Sprintf("describe the first %s", resourceType))
		}
	}
	
	return commonCommands
}

// GetSmartSuggestions provides intelligent suggestions based on input analysis and context
func (se *SuggestionEngine) GetSmartSuggestions(input string, sessionContext *models.SessionContext, previousErrors []string) []string {
	var suggestions []string
	
	// Analyze previous errors to avoid repeating failed patterns
	failedPatterns := se.analyzeFailedPatterns(previousErrors)
	
	// Start with fallback suggestions
	fallbackSuggestions := se.FallbackSuggestions(input, sessionContext)
	
	// Filter out suggestions that match failed patterns
	for _, suggestion := range fallbackSuggestions {
		if !se.matchesFailedPattern(suggestion, failedPatterns) {
			suggestions = append(suggestions, suggestion)
		}
	}
	
	// If all suggestions were filtered out, provide basic safe commands
	if len(suggestions) == 0 {
		suggestions = []string{
			"get pods",
			"get services",
			"help", // Ultimate fallback
		}
	}
	
	return se.deduplicateAndLimit(suggestions, 4)
}

// analyzeFailedPatterns identifies patterns from previous error attempts
func (se *SuggestionEngine) analyzeFailedPatterns(previousErrors []string) []string {
	var patterns []string
	
	for _, error := range previousErrors {
		// Extract failed command patterns
		if strings.Contains(error, "describe") {
			patterns = append(patterns, "describe")
		}
		if strings.Contains(error, "delete") {
			patterns = append(patterns, "delete")
		}
		if strings.Contains(error, "create") {
			patterns = append(patterns, "create")
		}
		// Add more pattern analysis as needed
	}
	
	return patterns
}

// matchesFailedPattern checks if a suggestion matches a previously failed pattern
func (se *SuggestionEngine) matchesFailedPattern(suggestion string, failedPatterns []string) bool {
	for _, pattern := range failedPatterns {
		if strings.Contains(suggestion, pattern) {
			return true
		}
	}
	return false
}