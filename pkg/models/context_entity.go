package models

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ContextEntity represents a named entity extracted from command output for context references
type ContextEntity struct {
	Type      string    `json:"type"`      // pod, deployment, service, etc.
	Name      string    `json:"name"`      // resource name
	Namespace string    `json:"namespace"` // kubernetes namespace
	Position  int       `json:"position"`  // position in list (for "first one", "second one" references)
	LastSeen  time.Time `json:"lastSeen"`  // when this entity was last referenced
}

// ReferenceItem represents an item that can be referenced in conversation
type ReferenceItem struct {
	ID          string      `json:"id"`          // unique identifier
	Type        string      `json:"type"`        // resource type
	Name        string      `json:"name"`        // display name
	Namespace   string      `json:"namespace"`   // namespace
	Position    int         `json:"position"`    // ordinal position
	CommandID   string      `json:"commandId"`   // command that generated this item
	LastSeen    time.Time   `json:"lastSeen"`    // last time referenced
	Metadata    interface{} `json:"metadata"`    // additional context data
}

// SessionContext represents conversational context for a session
type SessionContext struct {
	LastCommandOutput []ContextKubernetesResource `json:"lastCommandOutput"` // parsed output from last command
	NamedEntities     []ContextEntity             `json:"namedEntities"`     // extracted entities
	ReferenceableItems []ReferenceItem            `json:"referenceableItems"` // items that can be referenced
	ContextExpiry     time.Time                  `json:"contextExpiry"`     // when context expires
	LastCommandID     string                     `json:"lastCommandId"`     // ID of command that created context
}

// ContextKubernetesResource extends KubernetesResource with context-specific fields
type ContextKubernetesResource struct {
	KubernetesResource        // Embed existing KubernetesResource
	Status                    string            `json:"status"`    // current status
	Age                       string            `json:"age"`       // resource age
	Labels                    map[string]string `json:"labels"`    // resource labels
	Position                  int               `json:"position"`  // position in command output
}

// NewSessionContext creates a new session context
func NewSessionContext() *SessionContext {
	return &SessionContext{
		LastCommandOutput:  make([]ContextKubernetesResource, 0),
		NamedEntities:      make([]ContextEntity, 0),
		ReferenceableItems: make([]ReferenceItem, 0),
		ContextExpiry:      time.Now().Add(30 * time.Minute), // 30 minute default expiry
	}
}

// AddEntity adds a named entity to the context
func (sc *SessionContext) AddEntity(entity ContextEntity) {
	// Update lastSeen if entity already exists, otherwise add new
	for i, existing := range sc.NamedEntities {
		if existing.Type == entity.Type && existing.Name == entity.Name && existing.Namespace == entity.Namespace {
			sc.NamedEntities[i].LastSeen = entity.LastSeen
			sc.NamedEntities[i].Position = entity.Position
			return
		}
	}
	
	sc.NamedEntities = append(sc.NamedEntities, entity)
}

// AddReferenceItem adds a referenceable item to the context
func (sc *SessionContext) AddReferenceItem(item ReferenceItem) {
	// Update if exists, otherwise add new
	for i, existing := range sc.ReferenceableItems {
		if existing.ID == item.ID {
			sc.ReferenceableItems[i] = item
			return
		}
	}
	
	sc.ReferenceableItems = append(sc.ReferenceableItems, item)
}

// GetEntityByReference resolves a reference like "the first pod" or "that deployment"
func (sc *SessionContext) GetEntityByReference(reference string) (*ReferenceItem, error) {
	reference = strings.ToLower(strings.TrimSpace(reference))
	
	// Handle ordinal references ("first one", "second pod", etc.)
	if ordinalMatch := extractOrdinalReference(reference); ordinalMatch != nil {
		return sc.findByOrdinal(ordinalMatch.position, ordinalMatch.resourceType)
	}
	
	// Handle demonstrative references ("that pod", "this deployment")
	if demonstrativeMatch := extractDemonstrativeReference(reference); demonstrativeMatch != nil {
		return sc.findByDemonstrative(demonstrativeMatch.resourceType)
	}
	
	// Handle direct name references
	if nameMatch := extractNameReference(reference); nameMatch != "" {
		return sc.findByName(nameMatch)
	}
	
	return nil, fmt.Errorf("could not resolve reference: %s", reference)
}

// GetEntityByNumberedReference resolves numbered references like "pod 1", "service 2"
func (sc *SessionContext) GetEntityByNumberedReference(resourceType string, number int) (*ReferenceItem, error) {
	// Filter items by resource type
	var candidates []ReferenceItem
	for _, item := range sc.ReferenceableItems {
		if strings.Contains(strings.ToLower(item.Type), strings.ToLower(resourceType)) {
			candidates = append(candidates, item)
		}
	}
	
	// Return the nth item (1-based indexing)
	if number <= len(candidates) && number > 0 {
		return &candidates[number-1], nil
	}
	
	return nil, fmt.Errorf("no %s item found at position %d", resourceType, number)
}

// IsExpired checks if the context has expired
func (sc *SessionContext) IsExpired() bool {
	return time.Now().After(sc.ContextExpiry)
}

// ExtendExpiry extends the context expiry time
func (sc *SessionContext) ExtendExpiry(duration time.Duration) {
	sc.ContextExpiry = time.Now().Add(duration)
}

// Clear clears all context data
func (sc *SessionContext) Clear() {
	sc.LastCommandOutput = make([]ContextKubernetesResource, 0)
	sc.NamedEntities = make([]ContextEntity, 0)
	sc.ReferenceableItems = make([]ReferenceItem, 0)
	sc.LastCommandID = ""
	sc.ContextExpiry = time.Now().Add(30 * time.Minute)
}

// GetAvailableReferences returns a summary of what can be referenced
func (sc *SessionContext) GetAvailableReferences() map[string][]string {
	references := make(map[string][]string)
	
	for _, item := range sc.ReferenceableItems {
		if items, exists := references[item.Type]; exists {
			references[item.Type] = append(items, item.Name)
		} else {
			references[item.Type] = []string{item.Name}
		}
	}
	
	return references
}

// ToJSON serializes SessionContext to JSON
func (sc *SessionContext) ToJSON() ([]byte, error) {
	return json.Marshal(sc)
}

// FromJSON deserializes JSON to SessionContext
func (sc *SessionContext) FromJSON(data []byte) error {
	return json.Unmarshal(data, sc)
}

// Helper structures for reference parsing
type ordinalReference struct {
	position     int
	resourceType string
}

type demonstrativeReference struct {
	resourceType string
}

// extractOrdinalReference extracts ordinal references like "first pod", "second one"
func extractOrdinalReference(reference string) *ordinalReference {
	ordinals := map[string]int{
		"first":   1,
		"second":  2,
		"third":   3,
		"fourth":  4,
		"fifth":   5,
		"1st":     1,
		"2nd":     2,
		"3rd":     3,
		"4th":     4,
		"5th":     5,
	}
	
	words := strings.Fields(reference)
	if len(words) == 0 {
		return nil
	}
	
	var position int
	var resourceType string
	
	// Look for ordinal in first word
	if pos, found := ordinals[words[0]]; found {
		position = pos
		if len(words) > 1 {
			resourceType = words[1]
		} else {
			resourceType = "" // "first one" case
		}
		return &ordinalReference{position: position, resourceType: resourceType}
	}
	
	return nil
}

// extractDemonstrativeReference extracts demonstrative references like "that pod", "this service"
func extractDemonstrativeReference(reference string) *demonstrativeReference {
	words := strings.Fields(reference)
	if len(words) != 2 {
		return nil
	}
	
	demonstratives := []string{"that", "this", "the"}
	for _, dem := range demonstratives {
		if words[0] == dem {
			return &demonstrativeReference{resourceType: words[1]}
		}
	}
	
	return nil
}

// extractNameReference extracts direct name references
func extractNameReference(reference string) string {
	// For now, return the reference as-is for direct name lookup
	return reference
}

// findByOrdinal finds reference item by ordinal position
func (sc *SessionContext) findByOrdinal(position int, resourceType string) (*ReferenceItem, error) {
	var candidates []ReferenceItem
	
	// If resourceType is specified, filter by type
	if resourceType != "" && resourceType != "one" {
		for _, item := range sc.ReferenceableItems {
			if strings.Contains(strings.ToLower(item.Type), resourceType) {
				candidates = append(candidates, item)
			}
		}
	} else {
		// Use all items if no specific type
		candidates = sc.ReferenceableItems
	}
	
	// Sort by position and return the nth item
	if position <= len(candidates) && position > 0 {
		return &candidates[position-1], nil
	}
	
	return nil, fmt.Errorf("no %s item found at position %d", resourceType, position)
}

// findByDemonstrative finds reference item by demonstrative reference
func (sc *SessionContext) findByDemonstrative(resourceType string) (*ReferenceItem, error) {
	// Find the most recently seen item of the specified type
	var mostRecent *ReferenceItem
	var latestTime time.Time
	
	for i, item := range sc.ReferenceableItems {
		if strings.Contains(strings.ToLower(item.Type), resourceType) {
			if mostRecent == nil || item.LastSeen.After(latestTime) {
				mostRecent = &sc.ReferenceableItems[i]
				latestTime = item.LastSeen
			}
		}
	}
	
	if mostRecent == nil {
		return nil, fmt.Errorf("no %s found in current context", resourceType)
	}
	
	return mostRecent, nil
}

// findByName finds reference item by name
func (sc *SessionContext) findByName(name string) (*ReferenceItem, error) {
	for i, item := range sc.ReferenceableItems {
		if strings.EqualFold(item.Name, name) {
			return &sc.ReferenceableItems[i], nil
		}
	}
	
	return nil, fmt.Errorf("no resource named '%s' found in current context", name)
}