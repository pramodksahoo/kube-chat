// Package audit provides comprehensive command traceability capabilities tests
package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

func TestNewTraceabilityService(t *testing.T) {
	tests := []struct {
		name        string
		storage     AuditStorage
		db          *sql.DB
		wantError   bool
		expectedErr string
	}{
		{
			name:        "nil storage",
			storage:     nil,
			db:          &sql.DB{},
			wantError:   true,
			expectedErr: "storage cannot be nil",
		},
		{
			name:        "nil database",
			storage:     &MockAuditStorage{},
			db:          nil,
			wantError:   true,
			expectedErr: "database connection cannot be nil",
		},
		{
			name:      "valid parameters",
			storage:   &MockAuditStorage{},
			db:        &sql.DB{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewTraceabilityService(tt.storage, tt.db)

			if tt.wantError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, service)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, service)
			}
		})
	}
}

func TestTraceabilityService_buildCommandTrace(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name      string
		events    []*models.AuditEvent
		wantError bool
	}{
		{
			name:      "empty events",
			events:    []*models.AuditEvent{},
			wantError: true,
		},
		{
			name: "single event trace",
			events: []*models.AuditEvent{
				createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPInput, "get pods"),
			},
			wantError: false,
		},
		{
			name: "complete workflow trace",
			events: []*models.AuditEvent{
				createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPInput, "get pods"),
				createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPTranslation, "kubectl get pods"),
				createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeRBACCheck, "RBAC check passed"),
				createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeCommandExecute, "command executed"),
				createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeCommandResult, "pods listed successfully"),
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			trace, err := service.buildCommandTrace(tt.events)

			if tt.wantError {
				assert.Error(t, err)
				assert.Nil(t, trace)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, trace)
				
				if len(tt.events) > 0 {
					assert.Equal(t, tt.events[0].TraceID, trace.TraceID)
					assert.Equal(t, tt.events[0].CorrelationID, trace.CorrelationID)
					assert.Equal(t, tt.events[0].UserContext, trace.UserContext)
				}
			}
		})
	}
}

func TestTraceabilityService_mapEventToStage(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name         string
		eventType    models.AuditEventType
		expectedStage string
	}{
		{
			name:         "NLP input maps to natural language",
			eventType:    models.AuditEventTypeNLPInput,
			expectedStage: "natural_language",
		},
		{
			name:         "NLP translation maps to translation",
			eventType:    models.AuditEventTypeNLPTranslation,
			expectedStage: "translation",
		},
		{
			name:         "RBAC check maps to validation",
			eventType:    models.AuditEventTypeRBACCheck,
			expectedStage: "validation",
		},
		{
			name:         "Command execute maps to execution",
			eventType:    models.AuditEventTypeCommandExecute,
			expectedStage: "execution",
		},
		{
			name:         "Command result maps to result",
			eventType:    models.AuditEventTypeCommandResult,
			expectedStage: "result",
		},
		{
			name:         "Other events map to cluster impact",
			eventType:    models.AuditEventTypeAuthentication,
			expectedStage: "cluster_impact",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stage := service.mapEventToStage(tt.eventType)
			assert.Equal(t, tt.expectedStage, stage)
		})
	}
}

func TestTraceabilityService_createStage(t *testing.T) {
	service := &TraceabilityService{}

	event := createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPInput, "get pods")
	event.CommandContext.NaturalLanguageInput = "show me all pods"

	stage := service.createStage("natural_language", event)

	assert.NotNil(t, stage)
	assert.Equal(t, "natural_language", stage.StageName)
	assert.Equal(t, event.ID, stage.EventID)
	assert.Equal(t, event.Timestamp, stage.StartTime)
	assert.Equal(t, "in_progress", stage.Status)
	assert.Equal(t, "show me all pods", stage.Input["natural_language_query"])
}

func TestTraceabilityService_updateStage(t *testing.T) {
	service := &TraceabilityService{}

	// Create initial stage
	initialEvent := createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPInput, "get pods")
	stage := service.createStage("natural_language", initialEvent)

	// Create update event
	updateEvent := createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPTranslation, "translation complete")
	updateEvent.Timestamp = initialEvent.Timestamp.Add(2 * time.Second)
	updateEvent.CommandContext.ExecutionResult = "translation successful"

	// Update stage
	service.updateStage(stage, updateEvent)

	assert.NotNil(t, stage.EndTime)
	assert.Equal(t, updateEvent.Timestamp, *stage.EndTime)
	assert.NotNil(t, stage.Duration)
	assert.Equal(t, 2*time.Second, *stage.Duration)
	assert.Equal(t, "completed", stage.Status)
	assert.Equal(t, "translation successful", stage.Output["execution_result"])
}

func TestTraceabilityService_extractAffectedResource(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name     string
		event    *models.AuditEvent
		expected *AffectedResource
	}{
		{
			name: "event with no resource context",
			event: &models.AuditEvent{
				ClusterContext: models.ClusterContext{},
			},
			expected: nil,
		},
		{
			name: "event with resource context",
			event: &models.AuditEvent{
				Timestamp: time.Now(),
				EventType: models.AuditEventTypeCommandExecute,
				ClusterContext: models.ClusterContext{
					ResourceType: "pod",
					ResourceName: "test-pod",
					Namespace:    "default",
					ClusterName:  "test-cluster",
				},
				Metadata: map[string]interface{}{
					"before_state":   map[string]interface{}{"status": "running"},
					"after_state":    map[string]interface{}{"status": "terminated"},
					"change_summary": "Pod was terminated",
				},
			},
			expected: &AffectedResource{
				ResourceType:  "pod",
				ResourceName:  "test-pod",
				Namespace:     "default",
				ClusterName:   "test-cluster",
				Action:        "modified",
				BeforeState:   map[string]interface{}{"status": "running"},
				AfterState:    map[string]interface{}{"status": "terminated"},
				ChangeSummary: "Pod was terminated",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.extractAffectedResource(tt.event)

			if tt.expected == nil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
				assert.Equal(t, tt.expected.ResourceType, result.ResourceType)
				assert.Equal(t, tt.expected.ResourceName, result.ResourceName)
				assert.Equal(t, tt.expected.Namespace, result.Namespace)
				assert.Equal(t, tt.expected.ClusterName, result.ClusterName)
				assert.Equal(t, tt.expected.Action, result.Action)
				assert.Equal(t, tt.expected.BeforeState, result.BeforeState)
				assert.Equal(t, tt.expected.AfterState, result.AfterState)
				assert.Equal(t, tt.expected.ChangeSummary, result.ChangeSummary)
			}
		})
	}
}

func TestTraceabilityService_determineResourceAction(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name         string
		eventType    models.AuditEventType
		expectedAction string
	}{
		{
			name:         "command execute is modified",
			eventType:    models.AuditEventTypeCommandExecute,
			expectedAction: "modified",
		},
		{
			name:         "command is viewed",
			eventType:    models.AuditEventTypeCommand,
			expectedAction: "viewed",
		},
		{
			name:         "other events are accessed",
			eventType:    models.AuditEventTypeAuthentication,
			expectedAction: "accessed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := service.determineResourceAction(tt.eventType)
			assert.Equal(t, tt.expectedAction, action)
		})
	}
}

func TestTraceabilityService_groupEventsByTrace(t *testing.T) {
	service := &TraceabilityService{}

	events := []*models.AuditEvent{
		createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPInput, "event 1"),
		createTestTraceEvent("trace-001", "corr-001", models.AuditEventTypeNLPTranslation, "event 2"),
		createTestTraceEvent("trace-002", "corr-002", models.AuditEventTypeNLPInput, "event 3"),
		{
			ID:            "event-4",
			Timestamp:     time.Now(),
			TraceID:       "",
			CorrelationID: "corr-003",
			UserContext:   models.UserContext{SessionID: "session-123"},
		},
	}

	groups := service.groupEventsByTrace(events)

	assert.Len(t, groups, 3)
	assert.Len(t, groups["trace-001"], 2)
	assert.Len(t, groups["trace-002"], 1)
	assert.Len(t, groups["corr-003"], 1)
}

func TestTraceabilityService_determineWorkflowStatus(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name     string
		stages   map[string]*TraceStage
		expected string
	}{
		{
			name:     "empty stages",
			stages:   map[string]*TraceStage{},
			expected: "in_progress",
		},
		{
			name: "all completed stages",
			stages: map[string]*TraceStage{
				"stage1": {Status: "completed"},
				"stage2": {Status: "completed"},
			},
			expected: "completed",
		},
		{
			name: "has failed stage",
			stages: map[string]*TraceStage{
				"stage1": {Status: "completed"},
				"stage2": {Status: "failed"},
			},
			expected: "failed",
		},
		{
			name: "mixed stages in progress",
			stages: map[string]*TraceStage{
				"stage1": {Status: "completed"},
				"stage2": {Status: "in_progress"},
			},
			expected: "in_progress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := service.determineWorkflowStatus(tt.stages)
			assert.Equal(t, tt.expected, status)
		})
	}
}

func TestTraceabilityService_calculateRiskAssessment(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name        string
		events      []*models.AuditEvent
		resources   []AffectedResource
		expectedRisk string
	}{
		{
			name: "safe command",
			events: []*models.AuditEvent{
				{
					CommandContext: models.CommandContext{
						RiskLevel: "safe",
					},
				},
			},
			resources:   []AffectedResource{},
			expectedRisk: "safe",
		},
		{
			name: "destructive command",
			events: []*models.AuditEvent{
				{
					CommandContext: models.CommandContext{
						RiskLevel: "destructive",
					},
				},
			},
			resources:   []AffectedResource{},
			expectedRisk: "destructive",
		},
		{
			name: "caution command",
			events: []*models.AuditEvent{
				{
					CommandContext: models.CommandContext{
						RiskLevel: "caution",
					},
				},
			},
			resources:   []AffectedResource{},
			expectedRisk: "caution",
		},
		{
			name:   "resource deletion increases risk",
			events: []*models.AuditEvent{},
			resources: []AffectedResource{
				{Action: "deleted"},
			},
			expectedRisk: "safe", // Risk factors added but overall level remains safe without command risk
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assessment := service.calculateRiskAssessment(tt.events, tt.resources)
			assert.Equal(t, tt.expectedRisk, assessment.OverallRiskLevel)
			
			// Check that risk factors are populated appropriately
			if len(tt.events) > 0 && tt.events[0].CommandContext.RiskLevel == "destructive" {
				assert.Contains(t, assessment.RiskFactors, "destructive command detected")
			}
		})
	}
}

func TestTraceabilityService_buildComplianceInfo(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name            string
		events          []*models.AuditEvent
		expectedApproval bool
	}{
		{
			name: "safe command doesn't require approval",
			events: []*models.AuditEvent{
				{
					CommandContext: models.CommandContext{
						RiskLevel: "safe",
					},
				},
			},
			expectedApproval: false,
		},
		{
			name: "destructive command requires approval",
			events: []*models.AuditEvent{
				{
					CommandContext: models.CommandContext{
						RiskLevel: "destructive",
					},
				},
			},
			expectedApproval: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := service.buildComplianceInfo(tt.events)
			
			assert.Equal(t, tt.expectedApproval, info.RequiresApproval)
			assert.Contains(t, info.ComplianceFrameworks, "SOC2")
			assert.Contains(t, info.ComplianceFrameworks, "HIPAA")
			assert.Equal(t, 2555, info.RetentionPeriod) // 7 years
			
			if tt.expectedApproval {
				assert.Equal(t, "pending", info.ApprovalStatus)
			}
		})
	}
}

func TestTraceabilityService_determineImpactLevel(t *testing.T) {
	service := &TraceabilityService{}

	tests := []struct {
		name     string
		resource AffectedResource
		expected string
	}{
		{
			name: "deleted resource is high impact",
			resource: AffectedResource{
				Action: "deleted",
			},
			expected: "high",
		},
		{
			name: "kube-system namespace is high impact",
			resource: AffectedResource{
				Action:    "modified",
				Namespace: "kube-system",
			},
			expected: "high",
		},
		{
			name: "modified resource is medium impact",
			resource: AffectedResource{
				Action:    "modified",
				Namespace: "default",
			},
			expected: "medium",
		},
		{
			name: "viewed resource is low impact",
			resource: AffectedResource{
				Action:    "viewed",
				Namespace: "default",
			},
			expected: "low",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level := service.determineImpactLevel(tt.resource)
			assert.Equal(t, tt.expected, level)
		})
	}
}

func TestTraceabilityService_buildTimeline(t *testing.T) {
	service := &TraceabilityService{}

	trace := &CommandTrace{
		NaturalLanguageStage: &TraceStage{
			StageName: "natural_language",
			StartTime: time.Now(),
			Status:    "completed",
			Metadata:  map[string]interface{}{"test": "data"},
		},
		TranslationStage: &TraceStage{
			StageName: "translation",
			StartTime: time.Now().Add(1 * time.Second),
			Status:    "completed",
		},
	}

	timeline := service.buildTimeline(trace)

	assert.Len(t, timeline, 2)
	assert.Equal(t, "natural_language", timeline[0].StageName)
	assert.Equal(t, "stage_start", timeline[0].EventType)
	assert.Equal(t, "completed", timeline[0].Status)
	assert.Equal(t, map[string]interface{}{"test": "data"}, timeline[0].Metadata)
}

// Helper function to create test audit events for tracing
func createTestTraceEvent(traceID, correlationID string, eventType models.AuditEventType, message string) *models.AuditEvent {
	now := time.Now().UTC()
	return &models.AuditEvent{
		ID:            fmt.Sprintf("event-%s-%d", traceID, now.Unix()),
		Timestamp:     now,
		TraceID:       traceID,
		CorrelationID: correlationID,
		EventType:     eventType,
		Severity:      models.AuditSeverityInfo,
		Message:       message,
		UserContext: models.UserContext{
			UserID:    "test-user",
			SessionID: "test-session",
		},
		ClusterContext: models.ClusterContext{
			ClusterName: "test-cluster",
		},
		CommandContext: models.CommandContext{},
		CreatedAt:      now,
	}
}

// Mock implementation for testing TraceCommandWorkflow
func TestTraceabilityService_TraceCommandWorkflow(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &TraceabilityService{storage: mockStorage}

	ctx := context.Background()
	traceID := "trace-001"

	// Setup mock expectations
	expectedEvents := []*models.AuditEvent{
		createTestTraceEvent(traceID, "corr-001", models.AuditEventTypeNLPInput, "get pods"),
		createTestTraceEvent(traceID, "corr-001", models.AuditEventTypeNLPTranslation, "kubectl get pods"),
	}

	expectedFilter := models.AuditEventFilter{
		TraceID:   traceID,
		SortBy:    "timestamp",
		SortOrder: "asc",
		Limit:     1000,
	}

	mockStorage.On("QueryEvents", ctx, expectedFilter).Return(expectedEvents, nil)

	// Test the method
	trace, err := service.TraceCommandWorkflow(ctx, traceID)

	// Assertions
	require.NoError(t, err)
	assert.NotNil(t, trace)
	assert.Equal(t, traceID, trace.TraceID)
	assert.Equal(t, "corr-001", trace.CorrelationID)
	mockStorage.AssertExpectations(t)
}

func TestTraceabilityService_TraceCommandWorkflow_EmptyTraceID(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &TraceabilityService{storage: mockStorage}

	ctx := context.Background()

	trace, err := service.TraceCommandWorkflow(ctx, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trace ID cannot be empty")
	assert.Nil(t, trace)
}

func TestTraceabilityService_TraceCommandWorkflow_NoEvents(t *testing.T) {
	mockStorage := &MockAuditStorage{}
	service := &TraceabilityService{storage: mockStorage}

	ctx := context.Background()
	traceID := "trace-001"

	expectedFilter := models.AuditEventFilter{
		TraceID:   traceID,
		SortBy:    "timestamp",
		SortOrder: "asc",
		Limit:     1000,
	}

	mockStorage.On("QueryEvents", ctx, expectedFilter).Return([]*models.AuditEvent{}, nil)

	trace, err := service.TraceCommandWorkflow(ctx, traceID)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no events found for trace ID")
	assert.Nil(t, trace)
	mockStorage.AssertExpectations(t)
}