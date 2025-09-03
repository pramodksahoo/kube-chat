package models

import (
	"time"

	"github.com/google/uuid"
)

// RiskLevel represents the risk assessment for a kubectl command
type RiskLevel string

const (
	RiskLevelSafe        RiskLevel = "safe"        // Read operations (Story 1.1 focus)
	RiskLevelCaution     RiskLevel = "caution"     // Write operations (future stories)
	RiskLevelDestructive RiskLevel = "destructive" // Delete operations (future stories)
)

// CommandStatus represents the execution status of a command
type CommandStatus string

const (
	CommandStatusPending         CommandStatus = "pending"
	CommandStatusPendingApproval CommandStatus = "pending_approval" // NEW: Required for confirmation workflow
	CommandStatusApproved        CommandStatus = "approved"
	CommandStatusExecuting       CommandStatus = "executing"
	CommandStatusCompleted       CommandStatus = "completed"
	CommandStatusFailed          CommandStatus = "failed"
	CommandStatusCancelled       CommandStatus = "cancelled"
)

// KubernetesResource represents a Kubernetes resource affected by a command
type KubernetesResource struct {
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	Action    string `json:"action"` // Used for risk assessment: create, read, update, delete
}

// CommandExecutionResult represents the result of command execution
type CommandExecutionResult struct {
	ExitCode int    `json:"exitCode"`
	Output   string `json:"output"`
	Error    string `json:"error,omitempty"`
}

// KubernetesCommand represents a kubectl command with metadata and safety analysis
type KubernetesCommand struct {
	ID                   string                  `json:"id"`
	SessionID            string                  `json:"sessionId"`
	NaturalLanguageInput string                  `json:"naturalLanguageInput"`
	GeneratedCommand     string                  `json:"generatedCommand"`
	RiskLevel            RiskLevel               `json:"riskLevel"`
	Resources            []KubernetesResource    `json:"resources"`
	Status               CommandStatus           `json:"status"`
	ExecutedAt           *time.Time              `json:"executedAt,omitempty"`
	ExecutionResult      *CommandExecutionResult `json:"executionResult,omitempty"`
	RollbackCommand      *string                 `json:"rollbackCommand,omitempty"`
	ApprovalToken        *string                 `json:"approvalToken,omitempty"`     // NEW: Required for confirmation
	ApprovalExpiresAt    *time.Time              `json:"approvalExpiresAt,omitempty"` // NEW: Auto-cancel timeout
	CreatedAt            time.Time               `json:"createdAt"`
	UpdatedAt            time.Time               `json:"updatedAt"`
}

// NewKubernetesCommand creates a new KubernetesCommand with default values
func NewKubernetesCommand(sessionID, naturalInput, generatedCommand string, riskLevel RiskLevel) *KubernetesCommand {
	now := time.Now()
	return &KubernetesCommand{
		ID:                   uuid.New().String(),
		SessionID:            sessionID,
		NaturalLanguageInput: naturalInput,
		GeneratedCommand:     generatedCommand,
		RiskLevel:            riskLevel,
		Resources:            make([]KubernetesResource, 0),
		Status:               CommandStatusPending,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
}

// IsReadOnly returns true if the command is a read-only operation (Story 1.1 focus)
func (kc *KubernetesCommand) IsReadOnly() bool {
	return kc.RiskLevel == RiskLevelSafe
}

// CanExecuteDirectly returns true if the command can be executed without additional approval
func (kc *KubernetesCommand) CanExecuteDirectly() bool {
	return kc.IsReadOnly() && kc.Status == CommandStatusApproved
}

// UpdateStatus updates the command status and timestamp
func (kc *KubernetesCommand) UpdateStatus(status CommandStatus) {
	kc.Status = status
	kc.UpdatedAt = time.Now()
	if status == CommandStatusExecuting {
		now := time.Now()
		kc.ExecutedAt = &now
	}
}
