package models

import "time"

// ConfirmRequest represents a command confirmation request
type ConfirmRequest struct {
	CommandID string `json:"commandId" validate:"required"`
	Token     string `json:"token" validate:"required"`
}

// ConfirmResponse represents the response after command confirmation
type ConfirmResponse struct {
	Success   bool               `json:"success"`
	CommandID string             `json:"commandId"`
	Status    CommandStatus      `json:"status"`
	Command   *KubernetesCommand `json:"command,omitempty"`
	Error     string             `json:"error,omitempty"`
}

// CancelRequest represents a command cancellation request
type CancelRequest struct {
	CommandID string `json:"commandId" validate:"required"`
	Reason    string `json:"reason,omitempty"`
}

// CancelResponse represents the response after command cancellation
type CancelResponse struct {
	Success   bool          `json:"success"`
	CommandID string        `json:"commandId"`
	Status    CommandStatus `json:"status"`
	Error     string        `json:"error,omitempty"`
}

// StatusRequest represents a command status request
type StatusRequest struct {
	CommandID string `json:"commandId" validate:"required"`
}

// StatusResponse represents the command status response
type StatusResponse struct {
	Success   bool               `json:"success"`
	CommandID string             `json:"commandId"`
	Status    CommandStatus      `json:"status"`
	Command   *KubernetesCommand `json:"command,omitempty"`
	Error     string             `json:"error,omitempty"`
}

// RequiresApproval returns true if the command requires user approval
func (kc *KubernetesCommand) RequiresApproval() bool {
	return kc.RiskLevel == RiskLevelCaution || kc.RiskLevel == RiskLevelDestructive
}

// IsExpired returns true if the approval token has expired
func (kc *KubernetesCommand) IsExpired() bool {
	if kc.ApprovalExpiresAt == nil {
		return false
	}
	return time.Now().After(*kc.ApprovalExpiresAt)
}

// SetApprovalToken sets the approval token with 5-minute expiry
func (kc *KubernetesCommand) SetApprovalToken(token string) {
	kc.ApprovalToken = &token
	expiry := time.Now().Add(5 * time.Minute)
	kc.ApprovalExpiresAt = &expiry
	kc.UpdatedAt = time.Now()
}

// ClearApprovalToken clears the approval token and expiry
func (kc *KubernetesCommand) ClearApprovalToken() {
	kc.ApprovalToken = nil
	kc.ApprovalExpiresAt = nil
	kc.UpdatedAt = time.Now()
}
