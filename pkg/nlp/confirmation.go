package nlp

import (
	"fmt"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// ConfirmationManager manages pending commands awaiting user approval
type ConfirmationManager struct {
	pendingCommands map[string]*models.KubernetesCommand
	mutex           sync.RWMutex
}

// NewConfirmationManager creates a new confirmation manager
func NewConfirmationManager() *ConfirmationManager {
	cm := &ConfirmationManager{
		pendingCommands: make(map[string]*models.KubernetesCommand),
	}

	// Start cleanup goroutine for expired approvals
	go cm.cleanupExpiredApprovals()

	return cm
}

// AddPendingCommand adds a command to the pending approval queue
func (cm *ConfirmationManager) AddPendingCommand(command *models.KubernetesCommand) error {
	if command.ApprovalToken == nil {
		return fmt.Errorf("command must have approval token")
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	cm.pendingCommands[command.ID] = command
	return nil
}

// ConfirmCommand confirms a pending command with the provided token
func (cm *ConfirmationManager) ConfirmCommand(commandID, token string) (*models.KubernetesCommand, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	command, exists := cm.pendingCommands[commandID]
	if !exists {
		return nil, fmt.Errorf("command %s not found or already processed", commandID)
	}

	// Check if command has expired
	if command.IsExpired() {
		delete(cm.pendingCommands, commandID)
		command.UpdateStatus(models.CommandStatusCancelled)
		return nil, fmt.Errorf("command %s has expired", commandID)
	}

	// Validate approval token
	if command.ApprovalToken == nil || *command.ApprovalToken != token {
		return nil, fmt.Errorf("invalid approval token for command %s", commandID)
	}

	// Confirm the command
	command.UpdateStatus(models.CommandStatusApproved)
	command.ClearApprovalToken()
	delete(cm.pendingCommands, commandID)

	return command, nil
}

// CancelCommand cancels a pending command
func (cm *ConfirmationManager) CancelCommand(commandID string) (*models.KubernetesCommand, error) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	command, exists := cm.pendingCommands[commandID]
	if !exists {
		return nil, fmt.Errorf("command %s not found or already processed", commandID)
	}

	command.UpdateStatus(models.CommandStatusCancelled)
	command.ClearApprovalToken()
	delete(cm.pendingCommands, commandID)

	return command, nil
}

// GetCommandStatus returns the current status of a command
func (cm *ConfirmationManager) GetCommandStatus(commandID string) (*models.KubernetesCommand, error) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	command, exists := cm.pendingCommands[commandID]
	if !exists {
		return nil, fmt.Errorf("command %s not found in pending queue", commandID)
	}

	// Check if expired and update status
	if command.IsExpired() {
		command.UpdateStatus(models.CommandStatusCancelled)
		delete(cm.pendingCommands, commandID)
		return command, nil
	}

	return command, nil
}

// cleanupExpiredApprovals runs periodically to clean up expired approvals
func (cm *ConfirmationManager) cleanupExpiredApprovals() {
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()

	for range ticker.C {
		cm.mutex.Lock()

		var expiredCommands []string
		for commandID, command := range cm.pendingCommands {
			if command.IsExpired() {
				expiredCommands = append(expiredCommands, commandID)
				command.UpdateStatus(models.CommandStatusCancelled)
				command.ClearApprovalToken()
			}
		}

		// Remove expired commands
		for _, commandID := range expiredCommands {
			delete(cm.pendingCommands, commandID)
		}

		cm.mutex.Unlock()

		if len(expiredCommands) > 0 {
			fmt.Printf("Cleaned up %d expired approval commands\n", len(expiredCommands))
		}
	}
}

// GetPendingCommandsCount returns the number of commands awaiting approval
func (cm *ConfirmationManager) GetPendingCommandsCount() int {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()

	return len(cm.pendingCommands)
}

// UpdateCommand updates a command in the manager (Story 1.3)
func (cm *ConfirmationManager) UpdateCommand(command *models.KubernetesCommand) error {
	if command == nil {
		return fmt.Errorf("command cannot be nil")
	}

	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	// If command is completed or failed, we can remove it from pending
	if command.Status == models.CommandStatusCompleted || command.Status == models.CommandStatusFailed {
		delete(cm.pendingCommands, command.ID)
	} else {
		// Keep it in pending for status tracking
		cm.pendingCommands[command.ID] = command
	}

	return nil
}
