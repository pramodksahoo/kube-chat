// Package audit provides comprehensive command traceability capabilities
package audit

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// TraceabilityService provides command-to-cluster-change traceability
type TraceabilityService struct {
	storage AuditStorage
	db      *sql.DB
}

// CommandTrace represents a complete audit trail from natural language to cluster impact
type CommandTrace struct {
	TraceID           string                `json:"trace_id"`
	CorrelationID     string                `json:"correlation_id"`
	SessionID         string                `json:"session_id"`
	UserContext       models.UserContext    `json:"user_context"`
	
	// Workflow stages
	NaturalLanguageStage *TraceStage `json:"natural_language_stage,omitempty"`
	TranslationStage     *TraceStage `json:"translation_stage,omitempty"`
	ValidationStage      *TraceStage `json:"validation_stage,omitempty"`
	ExecutionStage       *TraceStage `json:"execution_stage,omitempty"`
	ResultStage          *TraceStage `json:"result_stage,omitempty"`
	ClusterImpactStage   *TraceStage `json:"cluster_impact_stage,omitempty"`
	
	// Summary information
	WorkflowStatus    string                 `json:"workflow_status"`     // pending, in_progress, completed, failed
	TotalDuration     time.Duration          `json:"total_duration"`
	AffectedResources []AffectedResource     `json:"affected_resources"`
	RiskAssessment    RiskAssessment         `json:"risk_assessment"`
	ComplianceInfo    ComplianceInformation  `json:"compliance_info"`
	
	CreatedAt         time.Time              `json:"created_at"`
	CompletedAt       *time.Time             `json:"completed_at,omitempty"`
}

// TraceStage represents a single stage in the command workflow
type TraceStage struct {
	StageName     string                 `json:"stage_name"`
	EventID       string                 `json:"event_id"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       *time.Time             `json:"end_time,omitempty"`
	Duration      *time.Duration         `json:"duration,omitempty"`
	Status        string                 `json:"status"`        // pending, in_progress, completed, failed
	Input         map[string]interface{} `json:"input"`
	Output        map[string]interface{} `json:"output"`
	ErrorDetails  string                 `json:"error_details,omitempty"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// AffectedResource represents a Kubernetes resource affected by the command
type AffectedResource struct {
	ResourceType   string                 `json:"resource_type"`   // pod, service, deployment, etc.
	ResourceName   string                 `json:"resource_name"`
	Namespace      string                 `json:"namespace"`
	ClusterName    string                 `json:"cluster_name"`
	Action         string                 `json:"action"`         // created, updated, deleted, viewed
	
	// Before and after states for change tracking
	BeforeState    map[string]interface{} `json:"before_state,omitempty"`
	AfterState     map[string]interface{} `json:"after_state,omitempty"`
	ChangeSummary  string                 `json:"change_summary,omitempty"`
	
	Timestamp      time.Time              `json:"timestamp"`
}

// RiskAssessment contains security risk analysis for the command workflow
type RiskAssessment struct {
	OverallRiskLevel  string   `json:"overall_risk_level"`  // safe, caution, destructive
	RiskFactors       []string `json:"risk_factors"`
	SecurityWarnings  []string `json:"security_warnings"`
	RequiredApprovals []string `json:"required_approvals,omitempty"`
	ComplianceFlags   []string `json:"compliance_flags,omitempty"`
}

// ComplianceInformation contains compliance-related metadata
type ComplianceInformation struct {
	RequiresApproval     bool     `json:"requires_approval"`
	ApprovalStatus       string   `json:"approval_status,omitempty"`   // pending, approved, denied
	ApprovedBy           string   `json:"approved_by,omitempty"`
	ApprovalTimestamp    *time.Time `json:"approval_timestamp,omitempty"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`       // SOC2, HIPAA, PCI-DSS, etc.
	RetentionPeriod      int      `json:"retention_period"`            // Days to retain this trace
}

// TraceSearchRequest represents search parameters for command traces
type TraceSearchRequest struct {
	TraceID           string    `json:"trace_id,omitempty"`
	CorrelationID     string    `json:"correlation_id,omitempty"`
	SessionID         string    `json:"session_id,omitempty"`
	UserID            string    `json:"user_id,omitempty"`
	WorkflowStatus    []string  `json:"workflow_status,omitempty"`
	StartTime         time.Time `json:"start_time,omitempty"`
	EndTime           time.Time `json:"end_time,omitempty"`
	ClusterName       string    `json:"cluster_name,omitempty"`
	Namespace         string    `json:"namespace,omitempty"`
	ResourceType      string    `json:"resource_type,omitempty"`
	RiskLevel         string    `json:"risk_level,omitempty"`
	IncludeDetails    bool      `json:"include_details,omitempty"`
	Limit             int       `json:"limit,omitempty"`
	Offset            int       `json:"offset,omitempty"`
}

// WorkflowVisualization contains data for timeline visualization
type WorkflowVisualization struct {
	TraceID      string                    `json:"trace_id"`
	Timeline     []TimelineEvent           `json:"timeline"`
	FlowDiagram  FlowDiagramData          `json:"flow_diagram"`
	ImpactGraph  ResourceImpactGraph      `json:"impact_graph"`
	Metrics      WorkflowMetrics          `json:"metrics"`
}

// TimelineEvent represents an event in the workflow timeline
type TimelineEvent struct {
	Timestamp   time.Time              `json:"timestamp"`
	StageName   string                 `json:"stage_name"`
	EventType   string                 `json:"event_type"`
	Description string                 `json:"description"`
	Status      string                 `json:"status"`
	Duration    *time.Duration         `json:"duration,omitempty"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// FlowDiagramData contains data for workflow flow diagram
type FlowDiagramData struct {
	Nodes []FlowNode `json:"nodes"`
	Edges []FlowEdge `json:"edges"`
}

// FlowNode represents a node in the workflow diagram
type FlowNode struct {
	ID          string                 `json:"id"`
	Label       string                 `json:"label"`
	Type        string                 `json:"type"`        // stage, decision, resource
	Status      string                 `json:"status"`
	Metadata    map[string]interface{} `json:"metadata"`
	Position    Position               `json:"position"`
}

// FlowEdge represents a connection between workflow nodes
type FlowEdge struct {
	ID          string                 `json:"id"`
	Source      string                 `json:"source"`
	Target      string                 `json:"target"`
	Label       string                 `json:"label,omitempty"`
	Type        string                 `json:"type"`        // flow, dependency, impact
	Metadata    map[string]interface{} `json:"metadata"`
}

// Position represents X,Y coordinates for visualization
type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// ResourceImpactGraph shows the relationship between commands and affected resources
type ResourceImpactGraph struct {
	Nodes []ResourceNode `json:"nodes"`
	Edges []ImpactEdge   `json:"edges"`
}

// ResourceNode represents a resource in the impact graph
type ResourceNode struct {
	ID             string                 `json:"id"`
	ResourceType   string                 `json:"resource_type"`
	ResourceName   string                 `json:"resource_name"`
	Namespace      string                 `json:"namespace"`
	ImpactLevel    string                 `json:"impact_level"`    // high, medium, low
	ChangesSummary []string               `json:"changes_summary"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// ImpactEdge represents the impact relationship between command and resource
type ImpactEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Action   string `json:"action"`
	Severity string `json:"severity"`
}

// WorkflowMetrics contains performance and compliance metrics
type WorkflowMetrics struct {
	TotalStages         int           `json:"total_stages"`
	CompletedStages     int           `json:"completed_stages"`
	FailedStages        int           `json:"failed_stages"`
	AverageStageTime    time.Duration `json:"average_stage_time"`
	TotalExecutionTime  time.Duration `json:"total_execution_time"`
	ResourcesAffected   int           `json:"resources_affected"`
	SecurityViolations  int           `json:"security_violations"`
	ComplianceWarnings  int           `json:"compliance_warnings"`
}

// NewTraceabilityService creates a new command traceability service
func NewTraceabilityService(storage AuditStorage, db *sql.DB) (*TraceabilityService, error) {
	if storage == nil {
		return nil, fmt.Errorf("storage cannot be nil")
	}
	if db == nil {
		return nil, fmt.Errorf("database connection cannot be nil")
	}

	service := &TraceabilityService{
		storage: storage,
		db:      db,
	}

	return service, nil
}

// TraceCommandWorkflow creates a comprehensive trace of a command workflow
func (t *TraceabilityService) TraceCommandWorkflow(ctx context.Context, traceID string) (*CommandTrace, error) {
	if traceID == "" {
		return nil, fmt.Errorf("trace ID cannot be empty")
	}

	// Query all events related to this trace
	filter := models.AuditEventFilter{
		TraceID:   traceID,
		SortBy:    "timestamp",
		SortOrder: "asc",
		Limit:     1000,
	}

	events, err := t.storage.QueryEvents(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query trace events: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no events found for trace ID: %s", traceID)
	}

	// Build the command trace from events
	trace, err := t.buildCommandTrace(events)
	if err != nil {
		return nil, fmt.Errorf("failed to build command trace: %w", err)
	}

	return trace, nil
}

// TraceCommandByCorrelation traces a command using correlation ID
func (t *TraceabilityService) TraceCommandByCorrelation(ctx context.Context, correlationID string) (*CommandTrace, error) {
	if correlationID == "" {
		return nil, fmt.Errorf("correlation ID cannot be empty")
	}

	// Query events by correlation ID
	filter := models.AuditEventFilter{
		CorrelationID: correlationID,
		SortBy:        "timestamp",
		SortOrder:     "asc",
		Limit:         1000,
	}

	events, err := t.storage.QueryEvents(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query correlation events: %w", err)
	}

	if len(events) == 0 {
		return nil, fmt.Errorf("no events found for correlation ID: %s", correlationID)
	}

	// Build the command trace from events
	trace, err := t.buildCommandTrace(events)
	if err != nil {
		return nil, fmt.Errorf("failed to build command trace: %w", err)
	}

	return trace, nil
}

// SearchCommandTraces searches for command traces based on criteria
func (t *TraceabilityService) SearchCommandTraces(ctx context.Context, req TraceSearchRequest) ([]*CommandTrace, error) {
	// Build audit event filter from trace search request
	eventFilter := models.AuditEventFilter{
		UserID:        req.UserID,
		StartTime:     req.StartTime,
		EndTime:       req.EndTime,
		ClusterName:   req.ClusterName,
		Namespace:     req.Namespace,
		CorrelationID: req.CorrelationID,
		TraceID:       req.TraceID,
		SortBy:        "timestamp",
		SortOrder:     "desc",
		Limit:         req.Limit,
		Offset:        req.Offset,
	}

	if eventFilter.Limit == 0 {
		eventFilter.Limit = 100
	}

	events, err := t.storage.QueryEvents(ctx, eventFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to search trace events: %w", err)
	}

	// Group events by trace ID or correlation ID
	traceGroups := t.groupEventsByTrace(events)

	var traces []*CommandTrace
	for _, eventGroup := range traceGroups {
		trace, err := t.buildCommandTrace(eventGroup)
		if err != nil {
			// Log error but continue with other traces
			continue
		}

		// Apply trace-level filtering
		if t.matchesTraceFilter(trace, req) {
			traces = append(traces, trace)
		}
	}

	return traces, nil
}

// GetWorkflowVisualization creates visualization data for a command workflow
func (t *TraceabilityService) GetWorkflowVisualization(ctx context.Context, traceID string) (*WorkflowVisualization, error) {
	trace, err := t.TraceCommandWorkflow(ctx, traceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get command trace: %w", err)
	}

	visualization := &WorkflowVisualization{
		TraceID:     traceID,
		Timeline:    t.buildTimeline(trace),
		FlowDiagram: t.buildFlowDiagram(trace),
		ImpactGraph: t.buildImpactGraph(trace),
		Metrics:     t.calculateMetrics(trace),
	}

	return visualization, nil
}

// AnalyzeCommandImpact analyzes the impact of a command on cluster resources
func (t *TraceabilityService) AnalyzeCommandImpact(ctx context.Context, traceID string) ([]AffectedResource, error) {
	trace, err := t.TraceCommandWorkflow(ctx, traceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get command trace: %w", err)
	}

	return trace.AffectedResources, nil
}

// buildCommandTrace constructs a CommandTrace from audit events
func (t *TraceabilityService) buildCommandTrace(events []*models.AuditEvent) (*CommandTrace, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("no events provided")
	}

	// Sort events by timestamp
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.Before(events[j].Timestamp)
	})

	firstEvent := events[0]
	trace := &CommandTrace{
		TraceID:       firstEvent.TraceID,
		CorrelationID: firstEvent.CorrelationID,
		SessionID:     firstEvent.UserContext.SessionID,
		UserContext:   firstEvent.UserContext,
		CreatedAt:     firstEvent.Timestamp,
	}

	// Process events and build stages
	stageMap := make(map[string]*TraceStage)
	var affectedResources []AffectedResource

	for _, event := range events {
		stageName := t.mapEventToStage(event.EventType)
		
		// Create or update stage
		if stage, exists := stageMap[stageName]; exists {
			t.updateStage(stage, event)
		} else {
			stageMap[stageName] = t.createStage(stageName, event)
		}

		// Extract affected resources
		if resource := t.extractAffectedResource(event); resource != nil {
			affectedResources = append(affectedResources, *resource)
		}
	}

	// Assign stages to trace
	trace.NaturalLanguageStage = stageMap["natural_language"]
	trace.TranslationStage = stageMap["translation"]
	trace.ValidationStage = stageMap["validation"]
	trace.ExecutionStage = stageMap["execution"]
	trace.ResultStage = stageMap["result"]
	trace.ClusterImpactStage = stageMap["cluster_impact"]

	trace.AffectedResources = affectedResources
	trace.WorkflowStatus = t.determineWorkflowStatus(stageMap)
	trace.RiskAssessment = t.calculateRiskAssessment(events, affectedResources)
	trace.ComplianceInfo = t.buildComplianceInfo(events)

	// Calculate total duration
	if trace.WorkflowStatus == "completed" && len(events) > 0 {
		lastEvent := events[len(events)-1]
		trace.CompletedAt = &lastEvent.Timestamp
		trace.TotalDuration = lastEvent.Timestamp.Sub(firstEvent.Timestamp)
	}

	return trace, nil
}

// mapEventToStage maps audit event types to workflow stages
func (t *TraceabilityService) mapEventToStage(eventType models.AuditEventType) string {
	switch eventType {
	case models.AuditEventTypeNLPInput:
		return "natural_language"
	case models.AuditEventTypeNLPTranslation:
		return "translation"
	case models.AuditEventTypeRBACCheck:
		return "validation"
	case models.AuditEventTypeCommandExecute:
		return "execution"
	case models.AuditEventTypeCommandResult:
		return "result"
	default:
		return "cluster_impact"
	}
}

// createStage creates a new trace stage from an audit event
func (t *TraceabilityService) createStage(stageName string, event *models.AuditEvent) *TraceStage {
	stage := &TraceStage{
		StageName: stageName,
		EventID:   event.ID,
		StartTime: event.Timestamp,
		Status:    "in_progress",
		Input:     make(map[string]interface{}),
		Output:    make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
	}

	// Populate stage-specific data
	switch stageName {
	case "natural_language":
		stage.Input["natural_language_query"] = event.CommandContext.NaturalLanguageInput
	case "translation":
		stage.Input["natural_language_input"] = event.CommandContext.NaturalLanguageInput
		stage.Output["generated_command"] = event.CommandContext.GeneratedCommand
	case "execution":
		stage.Input["command"] = event.CommandContext.GeneratedCommand
		stage.Output["execution_status"] = event.CommandContext.ExecutionStatus
		stage.Output["execution_result"] = event.CommandContext.ExecutionResult
		if event.CommandContext.ExecutionError != "" {
			stage.ErrorDetails = event.CommandContext.ExecutionError
		}
	}

	// Add event metadata
	if event.Metadata != nil {
		stage.Metadata = event.Metadata
	}

	return stage
}

// updateStage updates an existing stage with information from a new event
func (t *TraceabilityService) updateStage(stage *TraceStage, event *models.AuditEvent) {
	// Update end time and calculate duration
	stage.EndTime = &event.Timestamp
	duration := event.Timestamp.Sub(stage.StartTime)
	stage.Duration = &duration

	// Update status based on event severity
	if event.Severity == models.AuditSeverityError || event.Severity == models.AuditSeverityCritical {
		stage.Status = "failed"
		stage.ErrorDetails = event.Message
	} else {
		stage.Status = "completed"
	}

	// Update output information
	if event.CommandContext.ExecutionResult != "" {
		stage.Output["execution_result"] = event.CommandContext.ExecutionResult
	}
	if event.CommandContext.ExecutionStatus != "" {
		stage.Output["execution_status"] = event.CommandContext.ExecutionStatus
	}
}

// extractAffectedResource extracts resource information from an audit event
func (t *TraceabilityService) extractAffectedResource(event *models.AuditEvent) *AffectedResource {
	if event.ClusterContext.ResourceType == "" {
		return nil
	}

	resource := &AffectedResource{
		ResourceType: event.ClusterContext.ResourceType,
		ResourceName: event.ClusterContext.ResourceName,
		Namespace:    event.ClusterContext.Namespace,
		ClusterName:  event.ClusterContext.ClusterName,
		Action:       t.determineResourceAction(event.EventType),
		Timestamp:    event.Timestamp,
	}

	// Extract before/after states from metadata if available
	if event.Metadata != nil {
		if beforeState, exists := event.Metadata["before_state"]; exists {
			if beforeStateMap, ok := beforeState.(map[string]interface{}); ok {
				resource.BeforeState = beforeStateMap
			}
		}
		if afterState, exists := event.Metadata["after_state"]; exists {
			if afterStateMap, ok := afterState.(map[string]interface{}); ok {
				resource.AfterState = afterStateMap
			}
		}
		if changeSummary, exists := event.Metadata["change_summary"]; exists {
			if changeSummaryStr, ok := changeSummary.(string); ok {
				resource.ChangeSummary = changeSummaryStr
			}
		}
	}

	return resource
}

// determineResourceAction determines the action performed on a resource
func (t *TraceabilityService) determineResourceAction(eventType models.AuditEventType) string {
	switch eventType {
	case models.AuditEventTypeCommandExecute:
		return "modified"
	case models.AuditEventTypeCommand:
		return "viewed"
	default:
		return "accessed"
	}
}

// groupEventsByTrace groups events by trace ID or correlation ID
func (t *TraceabilityService) groupEventsByTrace(events []*models.AuditEvent) map[string][]*models.AuditEvent {
	groups := make(map[string][]*models.AuditEvent)

	for _, event := range events {
		key := event.TraceID
		if key == "" {
			key = event.CorrelationID
		}
		if key == "" {
			key = event.UserContext.SessionID + "_" + event.Timestamp.Format("2006-01-02T15:04:05")
		}

		groups[key] = append(groups[key], event)
	}

	return groups
}

// matchesTraceFilter checks if a trace matches the search criteria
func (t *TraceabilityService) matchesTraceFilter(trace *CommandTrace, req TraceSearchRequest) bool {
	if len(req.WorkflowStatus) > 0 {
		matched := false
		for _, status := range req.WorkflowStatus {
			if trace.WorkflowStatus == status {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	if req.RiskLevel != "" && trace.RiskAssessment.OverallRiskLevel != req.RiskLevel {
		return false
	}

	return true
}

// determineWorkflowStatus determines the overall status of the workflow
func (t *TraceabilityService) determineWorkflowStatus(stages map[string]*TraceStage) string {
	hasFailedStage := false
	allCompleted := true

	for _, stage := range stages {
		if stage == nil {
			continue
		}

		if stage.Status == "failed" {
			hasFailedStage = true
		}
		if stage.Status != "completed" {
			allCompleted = false
		}
	}

	if hasFailedStage {
		return "failed"
	}
	if allCompleted && len(stages) > 0 {
		return "completed"
	}
	return "in_progress"
}

// calculateRiskAssessment analyzes the security risk of the command workflow
func (t *TraceabilityService) calculateRiskAssessment(events []*models.AuditEvent, resources []AffectedResource) RiskAssessment {
	assessment := RiskAssessment{
		OverallRiskLevel: "safe",
		RiskFactors:      []string{},
		SecurityWarnings: []string{},
	}

	// Analyze command risk levels
	for _, event := range events {
		if event.CommandContext.RiskLevel != "" {
			switch event.CommandContext.RiskLevel {
			case "destructive":
				assessment.OverallRiskLevel = "destructive"
				assessment.RiskFactors = append(assessment.RiskFactors, "destructive command detected")
			case "caution":
				if assessment.OverallRiskLevel == "safe" {
					assessment.OverallRiskLevel = "caution"
				}
				assessment.RiskFactors = append(assessment.RiskFactors, "potentially dangerous command")
			}
		}

		// Check for security events
		if event.EventType == models.AuditEventTypeRBACDenied {
			assessment.SecurityWarnings = append(assessment.SecurityWarnings, "RBAC permission denied")
		}
	}

	// Analyze resource impact
	for _, resource := range resources {
		if resource.Action == "deleted" {
			assessment.RiskFactors = append(assessment.RiskFactors, "resource deletion detected")
		}
		if resource.Namespace == "kube-system" {
			assessment.RiskFactors = append(assessment.RiskFactors, "system namespace modification")
		}
	}

	return assessment
}

// buildComplianceInfo builds compliance information for the trace
func (t *TraceabilityService) buildComplianceInfo(events []*models.AuditEvent) ComplianceInformation {
	info := ComplianceInformation{
		ComplianceFrameworks: []string{"SOC2", "HIPAA", "PCI-DSS"},
		RetentionPeriod:      2555, // 7 years in days
	}

	// Determine if approval is required based on risk level
	for _, event := range events {
		if event.CommandContext.RiskLevel == "destructive" {
			info.RequiresApproval = true
			info.ApprovalStatus = "pending"
			break
		}
	}

	return info
}

// Helper methods for visualization

func (t *TraceabilityService) buildTimeline(trace *CommandTrace) []TimelineEvent {
	var timeline []TimelineEvent

	stages := []*TraceStage{
		trace.NaturalLanguageStage,
		trace.TranslationStage,
		trace.ValidationStage,
		trace.ExecutionStage,
		trace.ResultStage,
		trace.ClusterImpactStage,
	}

	for _, stage := range stages {
		if stage == nil {
			continue
		}

		event := TimelineEvent{
			Timestamp:   stage.StartTime,
			StageName:   stage.StageName,
			EventType:   "stage_start",
			Description: fmt.Sprintf("Started %s stage", stage.StageName),
			Status:      stage.Status,
			Duration:    stage.Duration,
			Metadata:    stage.Metadata,
		}
		timeline = append(timeline, event)
	}

	return timeline
}

func (t *TraceabilityService) buildFlowDiagram(trace *CommandTrace) FlowDiagramData {
	var nodes []FlowNode
	var edges []FlowEdge

	// Create nodes for each stage
	stageNames := []string{"natural_language", "translation", "validation", "execution", "result", "cluster_impact"}
	for i, stageName := range stageNames {
		node := FlowNode{
			ID:       stageName,
			Label:    stageName,
			Type:     "stage",
			Status:   "pending",
			Metadata: make(map[string]interface{}),
			Position: Position{X: float64(i * 100), Y: 50},
		}
		nodes = append(nodes, node)

		// Create edges between consecutive stages
		if i > 0 {
			edge := FlowEdge{
				ID:     fmt.Sprintf("%s_to_%s", stageNames[i-1], stageName),
				Source: stageNames[i-1],
				Target: stageName,
				Type:   "flow",
			}
			edges = append(edges, edge)
		}
	}

	return FlowDiagramData{
		Nodes: nodes,
		Edges: edges,
	}
}

func (t *TraceabilityService) buildImpactGraph(trace *CommandTrace) ResourceImpactGraph {
	var nodes []ResourceNode
	var edges []ImpactEdge

	// Create nodes for affected resources
	for i, resource := range trace.AffectedResources {
		node := ResourceNode{
			ID:           fmt.Sprintf("resource_%d", i),
			ResourceType: resource.ResourceType,
			ResourceName: resource.ResourceName,
			Namespace:    resource.Namespace,
			ImpactLevel:  t.determineImpactLevel(resource),
			Metadata:     make(map[string]interface{}),
		}
		nodes = append(nodes, node)

		// Create edge from command to resource
		edge := ImpactEdge{
			ID:       fmt.Sprintf("command_to_resource_%d", i),
			Source:   "command",
			Target:   node.ID,
			Action:   resource.Action,
			Severity: t.determineImpactSeverity(resource),
		}
		edges = append(edges, edge)
	}

	return ResourceImpactGraph{
		Nodes: nodes,
		Edges: edges,
	}
}

func (t *TraceabilityService) calculateMetrics(trace *CommandTrace) WorkflowMetrics {
	metrics := WorkflowMetrics{
		ResourcesAffected: len(trace.AffectedResources),
	}

	stages := []*TraceStage{
		trace.NaturalLanguageStage,
		trace.TranslationStage,
		trace.ValidationStage,
		trace.ExecutionStage,
		trace.ResultStage,
		trace.ClusterImpactStage,
	}

	var totalDuration time.Duration
	for _, stage := range stages {
		if stage == nil {
			continue
		}

		metrics.TotalStages++
		if stage.Status == "completed" {
			metrics.CompletedStages++
		} else if stage.Status == "failed" {
			metrics.FailedStages++
		}

		if stage.Duration != nil {
			totalDuration += *stage.Duration
		}
	}

	if metrics.TotalStages > 0 {
		metrics.AverageStageTime = totalDuration / time.Duration(metrics.TotalStages)
	}
	metrics.TotalExecutionTime = trace.TotalDuration

	return metrics
}

func (t *TraceabilityService) determineImpactLevel(resource AffectedResource) string {
	if resource.Action == "deleted" {
		return "high"
	}
	if resource.Namespace == "kube-system" {
		return "high"
	}
	if resource.Action == "modified" {
		return "medium"
	}
	return "low"
}

func (t *TraceabilityService) determineImpactSeverity(resource AffectedResource) string {
	if resource.Action == "deleted" || resource.Namespace == "kube-system" {
		return "high"
	}
	return "medium"
}