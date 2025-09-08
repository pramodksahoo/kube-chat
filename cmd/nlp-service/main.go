package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/pramodksahoo/kube-chat/pkg/audit"
	"github.com/pramodksahoo/kube-chat/pkg/clients"
	"github.com/pramodksahoo/kube-chat/pkg/middleware"
	"github.com/pramodksahoo/kube-chat/pkg/models"
	"github.com/pramodksahoo/kube-chat/pkg/nlp"
)

func main() {
	// Create Fiber v3 app with configuration for Story 1.2
	app := fiber.New(fiber.Config{
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
		AppName:      "KubeChat NLP Service v1.3 - Command Execution Results",
	})

	// Create NLP translator service (Story 1.1 + 1.2 implementation)
	translator := nlp.NewTranslatorService()

	// Create confirmation manager for write operations (Story 1.2)
	confirmationManager := nlp.NewConfirmationManager()

	// Create Kubernetes client for command execution (Story 1.3)
	kubernetesClient, err := clients.NewKubernetesClient(nil)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes client: %v", err)
	}

	// Create session manager for command history (Story 1.3)
	sessionManager := NewSessionManager()

	// Create session context manager for conversational context (Story 1.4)
	contextManager := models.NewSessionContextManager()
	defer contextManager.Shutdown()

	// Initialize audit collector for audit logging
	var auditCollector middleware.EventCollectorInterface
	if os.Getenv("ENABLE_AUDIT") != "false" {
		auditStorage, err := audit.NewPostgreSQLAuditStorage(
			os.Getenv("AUDIT_DATABASE_URL"),
			365*7, // 7 years retention
		)
		if err != nil {
			log.Printf("Warning: Failed to initialize audit storage: %v", err)
		} else {
			collectorConfig := audit.DefaultCollectorConfig()
			auditCollector = audit.NewEventCollector(auditStorage, collectorConfig)
			
			if err := auditCollector.(*audit.EventCollector).Start(); err != nil {
				log.Printf("Warning: Failed to start audit collector: %v", err)
				auditCollector = nil
			}
		}
	}

	// Setup routes for Story 1.1 + 1.2 + 1.3 + 1.4
	setupRoutes(app, translator, confirmationManager, kubernetesClient, sessionManager, contextManager, auditCollector)

	// Handle graceful shutdown
	go func() {
		sigterm := make(chan os.Signal, 1)
		signal.Notify(sigterm, syscall.SIGINT, syscall.SIGTERM)
		<-sigterm

		log.Println("Shutting down NLP service...")
		if err := app.ShutdownWithTimeout(30 * time.Second); err != nil {
			log.Fatalf("Server shutdown error: %v", err)
		}
	}()

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
	}

	log.Printf("Starting KubeChat NLP Service (Story 1.3) on port %s", port)
	log.Printf("Supported operations: get pods, create deployment, scale deployment, delete pod, describe services")
	log.Printf("New features: Command execution, results formatting, session history")
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// setupRoutes configures the API endpoints for Story 1.1 + 1.2 + 1.3 + 1.4
func setupRoutes(app *fiber.App, translator nlp.TranslatorService, confirmationManager *nlp.ConfirmationManager, kubernetesClient clients.KubernetesClient, sessionManager *SessionManager, contextManager *models.SessionContextManager, auditCollector middleware.EventCollectorInterface) {
	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"service": "nlp-service",
			"version": "1.3",
			"story":   "Story 1.3 - Command Execution Results",
		})
	})

	// NLP processing endpoints group
	nlpGroup := app.Group("/nlp")

	// POST /nlp/process - Natural language to kubectl translation (Story 1.1 + 1.2 + 1.4)
	nlpGroup.Post("/process", func(c *fiber.Ctx) error {
		return handleNLPProcess(c, translator, confirmationManager, contextManager, auditCollector)
	})

	// PUT /nlp/confirm/{commandId} - User confirms pending command execution (Story 1.2)
	nlpGroup.Put("/confirm/:commandId", func(c *fiber.Ctx) error {
		return handleConfirmCommand(c, confirmationManager)
	})

	// DELETE /nlp/cancel/{commandId} - User cancels pending command (Story 1.2)
	nlpGroup.Delete("/cancel/:commandId", func(c *fiber.Ctx) error {
		return handleCancelCommand(c, confirmationManager)
	})

	// GET /nlp/commands/{commandId}/status - Check command execution status (Story 1.2)
	nlpGroup.Get("/commands/:commandId/status", func(c *fiber.Ctx) error {
		return handleGetCommandStatus(c, confirmationManager)
	})

	// POST /nlp/execute/{commandId} - Execute approved command (Story 1.3 + 1.4)
	nlpGroup.Post("/execute/:commandId", func(c *fiber.Ctx) error {
		return handleExecuteCommand(c, confirmationManager, kubernetesClient, sessionManager, contextManager, auditCollector)
	})

	// GET /nlp/sessions/{sessionId}/history - Retrieve command history (Story 1.3)
	nlpGroup.Get("/sessions/:sessionId/history", func(c *fiber.Ctx) error {
		return handleGetSessionHistory(c, sessionManager)
	})

	// Story 1.4: Context-related endpoints
	// GET /nlp/sessions/{sessionId}/context - Retrieve current context (Task 4.1)
	nlpGroup.Get("/sessions/:sessionId/context", func(c *fiber.Ctx) error {
		return handleGetSessionContext(c, contextManager)
	})

	// DELETE /nlp/sessions/{sessionId}/context - Reset session context (Task 4.1)
	nlpGroup.Delete("/sessions/:sessionId/context", func(c *fiber.Ctx) error {
		return handleResetSessionContext(c, contextManager)
	})

	// POST /nlp/sessions/{sessionId}/validate-reference - Validate context references (Task 4.1)
	nlpGroup.Post("/sessions/:sessionId/validate-reference", func(c *fiber.Ctx) error {
		return handleValidateReference(c, contextManager, translator)
	})

	// GET /nlp/sessions/{sessionId}/context/state - Get context state for debugging (Task 4.2)
	nlpGroup.Get("/sessions/:sessionId/context/state", func(c *fiber.Ctx) error {
		return handleGetContextState(c, contextManager)
	})

	// GET /nlp/sessions/{sessionId}/context/health - Validate context health (Task 4.2)
	nlpGroup.Get("/sessions/:sessionId/context/health", func(c *fiber.Ctx) error {
		return handleValidateContextHealth(c, contextManager)
	})

	// GET /nlp/sessions/active - List all active sessions (Task 4.2)
	nlpGroup.Get("/sessions/active", func(c *fiber.Ctx) error {
		return handleListActiveSessions(c, contextManager)
	})

	// GET /nlp/sessions/stats - Get context manager statistics (Task 4.2)
	nlpGroup.Get("/sessions/stats", func(c *fiber.Ctx) error {
		return handleGetContextStats(c, contextManager)
	})
}

// ProcessRequest represents the request payload for NLP processing (Story 1.1)
type ProcessRequest struct {
	Input     string `json:"input" validate:"required"`
	SessionID string `json:"sessionId,omitempty"`
}

// ProcessResponse represents the response from NLP processing (Story 1.1 + 1.2)
type ProcessResponse struct {
	Success           bool    `json:"success"`
	GeneratedCommand  string  `json:"generatedCommand,omitempty"`
	RiskLevel         string  `json:"riskLevel,omitempty"`
	Explanation       string  `json:"explanation,omitempty"`
	Error             string  `json:"error,omitempty"`
	CommandID         string  `json:"commandId,omitempty"`
	Status            string  `json:"status,omitempty"`            // NEW: Command status
	ApprovalToken     *string `json:"approvalToken,omitempty"`     // NEW: For confirmation workflow
	ApprovalExpiresAt *string `json:"approvalExpiresAt,omitempty"` // NEW: Auto-cancel timeout
	RequiresApproval  bool    `json:"requiresApproval"`            // NEW: Indicates if confirmation needed
}

// handleNLPProcess processes natural language input and returns kubectl command (Story 1.1 + 1.2 + 1.4 implementation)
func handleNLPProcess(c *fiber.Ctx, translator nlp.TranslatorService, confirmationManager *nlp.ConfirmationManager, contextManager *models.SessionContextManager, auditCollector middleware.EventCollectorInterface) error {
	var req ProcessRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ProcessResponse{
			Success: false,
			Error:   "Invalid request format - expected JSON with 'input' field",
		})
	}

	// Story 1.2 AC4: Handle basic error cases with helpful error messages
	if req.Input == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ProcessResponse{
			Success: false,
			Error:   "Input cannot be empty. Supported commands: show pods, create deployment, scale deployment, delete pod",
		})
	}

	// Process with timeout for user verification
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Story 1.4: Use context-aware translation when session context exists
	var result *models.KubernetesCommand
	var err error
	
	if req.SessionID != "" {
		if sessionContext, exists := contextManager.GetContext(req.SessionID); exists {
			// Use context-aware translation
			result, err = translator.TranslateCommandWithContext(ctx, req.Input, sessionContext)
		} else {
			// Create new context for this session
			sessionContext = contextManager.CreateContext(req.SessionID)
			result, err = translator.TranslateCommand(ctx, req.Input)
		}
	} else {
		// Use regular translation without context
		result, err = translator.TranslateCommand(ctx, req.Input)
	}
	
	if err != nil {
		log.Printf("Translation error for input %q: %v", req.Input, err)
		return c.Status(fiber.StatusBadRequest).JSON(ProcessResponse{
			Success: false,
			Error:   err.Error(),
		})
	}
	
	// Store session ID in command for later use
	if req.SessionID != "" {
		result.SessionID = req.SessionID
	}

	// Audit log: NLP command generation
	if auditCollector != nil {
		auditEvent, auditErr := models.NewAuditEventBuilder().
			WithEventType(models.AuditEventTypeNLPInput).
			WithMessage(fmt.Sprintf("NLP command generated: %s → %s", req.Input, result.GeneratedCommand)).
			WithSeverity(models.AuditSeverityInfo).
			WithUserContextFromUser(
				&models.User{ID: c.Get("X-User-ID"), Name: c.Get("X-User-Name")}, 
				c.Get("X-Session-ID"), 
				c.IP(), 
				c.Get("User-Agent"),
			).
			WithService("nlp-service", "1.3").
			WithMetadata("natural_language_input", req.Input).
			WithMetadata("generated_command", result.GeneratedCommand).
			WithMetadata("risk_level", string(result.RiskLevel)).
			WithMetadata("session_id", req.SessionID).
			Build()
		
		if auditErr == nil {
			auditCollector.CollectEvent(auditEvent)
		}
	}

	// Story 1.2 AC2: Display the generated kubectl command for user verification
	var explanation string
	var requiresApproval bool
	var approvalExpiresAt *string

	switch result.RiskLevel {
	case models.RiskLevelSafe:
		explanation = fmt.Sprintf("Translated '%s' to kubectl command. This is a SAFE read operation.", req.Input)
		requiresApproval = false
		// Add to confirmation manager even for safe commands to enable execution flow
		result.UpdateStatus(models.CommandStatusApproved) // Auto-approve safe commands
		confirmationManager.AddPendingCommand(result)
	case models.RiskLevelCaution:
		explanation = fmt.Sprintf("Translated '%s' to kubectl command. This is a CAUTION write operation that requires approval.", req.Input)
		requiresApproval = true
		// Add to confirmation manager for approval workflow
		confirmationManager.AddPendingCommand(result)
		if result.ApprovalExpiresAt != nil {
			expiryStr := result.ApprovalExpiresAt.Format(time.RFC3339)
			approvalExpiresAt = &expiryStr
		}
	case models.RiskLevelDestructive:
		explanation = fmt.Sprintf("Translated '%s' to kubectl command. This is a DESTRUCTIVE operation that requires explicit approval.", req.Input)
		requiresApproval = true
		// Add to confirmation manager for approval workflow
		confirmationManager.AddPendingCommand(result)
		if result.ApprovalExpiresAt != nil {
			expiryStr := result.ApprovalExpiresAt.Format(time.RFC3339)
			approvalExpiresAt = &expiryStr
		}
	}

	return c.JSON(ProcessResponse{
		Success:           true,
		GeneratedCommand:  result.GeneratedCommand,
		RiskLevel:         string(result.RiskLevel),
		Explanation:       explanation,
		CommandID:         result.ID,
		Status:            string(result.Status),
		ApprovalToken:     result.ApprovalToken,
		ApprovalExpiresAt: approvalExpiresAt,
		RequiresApproval:  requiresApproval,
	})
}

// handleConfirmCommand handles command confirmation (Story 1.2 AC3)
func handleConfirmCommand(c *fiber.Ctx, confirmationManager *nlp.ConfirmationManager) error {
	commandID := c.Params("commandId")
	if commandID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.ConfirmResponse{
			Success: false,
			Error:   "Command ID is required",
		})
	}

	var req models.ConfirmRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(models.ConfirmResponse{
			Success: false,
			Error:   "Invalid request format - expected JSON with 'token' field",
		})
	}

	req.CommandID = commandID

	// Confirm the command
	command, err := confirmationManager.ConfirmCommand(req.CommandID, req.Token)
	if err != nil {
		log.Printf("Confirmation error for command %q: %v", req.CommandID, err)
		return c.Status(fiber.StatusBadRequest).JSON(models.ConfirmResponse{
			Success:   false,
			CommandID: req.CommandID,
			Error:     err.Error(),
		})
	}

	return c.JSON(models.ConfirmResponse{
		Success:   true,
		CommandID: command.ID,
		Status:    command.Status,
		Command:   command,
	})
}

// handleCancelCommand handles command cancellation (Story 1.2 AC4)
func handleCancelCommand(c *fiber.Ctx, confirmationManager *nlp.ConfirmationManager) error {
	commandID := c.Params("commandId")
	if commandID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.CancelResponse{
			Success: false,
			Error:   "Command ID is required",
		})
	}

	// Cancel the command
	command, err := confirmationManager.CancelCommand(commandID)
	if err != nil {
		log.Printf("Cancellation error for command %q: %v", commandID, err)
		return c.Status(fiber.StatusBadRequest).JSON(models.CancelResponse{
			Success:   false,
			CommandID: commandID,
			Error:     err.Error(),
		})
	}

	return c.JSON(models.CancelResponse{
		Success:   true,
		CommandID: command.ID,
		Status:    command.Status,
	})
}

// handleGetCommandStatus handles command status requests (Story 1.2)
func handleGetCommandStatus(c *fiber.Ctx, confirmationManager *nlp.ConfirmationManager) error {
	commandID := c.Params("commandId")
	if commandID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(models.StatusResponse{
			Success: false,
			Error:   "Command ID is required",
		})
	}

	// Get command status
	command, err := confirmationManager.GetCommandStatus(commandID)
	if err != nil {
		log.Printf("Status query error for command %q: %v", commandID, err)
		return c.Status(fiber.StatusNotFound).JSON(models.StatusResponse{
			Success:   false,
			CommandID: commandID,
			Error:     err.Error(),
		})
	}

	return c.JSON(models.StatusResponse{
		Success:   true,
		CommandID: command.ID,
		Status:    command.Status,
		Command:   command,
	})
}

// ExecuteRequest represents the request payload for command execution (Story 1.3)
type ExecuteRequest struct {
	Confirmed bool `json:"confirmed,omitempty"`
}

// ExecuteResponse represents the response from command execution (Story 1.3)
type ExecuteResponse struct {
	Success         bool                            `json:"success"`
	CommandID       string                          `json:"commandId"`
	Status          string                          `json:"status"`
	ExecutionResult *models.CommandExecutionResult `json:"executionResult,omitempty"`
	Error           string                          `json:"error,omitempty"`
}

// HistoryResponse represents the response for session history (Story 1.3)
type HistoryResponse struct {
	Success   bool                     `json:"success"`
	SessionID string                   `json:"sessionId"`
	Commands  []*models.KubernetesCommand `json:"commands"`
	Total     int                      `json:"total"`
	Error     string                   `json:"error,omitempty"`
}

// Context-related request/response types (Story 1.4)
// ContextResponse represents the response for context operations
type ContextResponse struct {
	Success        bool                    `json:"success"`
	SessionID      string                  `json:"sessionId"`
	Context        *models.SessionContext  `json:"context,omitempty"`
	ContextState   *models.ContextState    `json:"contextState,omitempty"`
	Error          string                  `json:"error,omitempty"`
}

// ValidateReferenceRequest represents the request for reference validation
type ValidateReferenceRequest struct {
	Reference string `json:"reference" validate:"required"`
}

// ValidateReferenceResponse represents the response for reference validation
type ValidateReferenceResponse struct {
	Success         bool     `json:"success"`
	SessionID       string   `json:"sessionId"`
	Reference       string   `json:"reference"`
	IsValid         bool     `json:"isValid"`
	ResolvedEntity  *models.ReferenceItem `json:"resolvedEntity,omitempty"`
	Error           string   `json:"error,omitempty"`
	Suggestions     []string `json:"suggestions,omitempty"`
}

// ActiveSessionsResponse represents the response for active sessions list
type ActiveSessionsResponse struct {
	Success        bool     `json:"success"`
	ActiveSessions []string `json:"activeSessions"`
	Total          int      `json:"total"`
	Error          string   `json:"error,omitempty"`
}

// StatsResponse represents the response for context manager statistics
type StatsResponse struct {
	Success bool                   `json:"success"`
	Stats   map[string]interface{} `json:"stats"`
	Error   string                 `json:"error,omitempty"`
}

// HealthResponse represents the response for context health validation
type HealthResponse struct {
	Success bool                   `json:"success"`
	SessionID string               `json:"sessionId"`
	Health  map[string]interface{} `json:"health"`
	Error   string                 `json:"error,omitempty"`
}

// SessionManager manages session-based command history (Story 1.3)
type SessionManager struct {
	sessions map[string]*SessionData
}

// SessionData holds the command history for a session
type SessionData struct {
	ID       string                     `json:"id"`
	Commands []*models.KubernetesCommand `json:"commands"`
	Created  time.Time                  `json:"created"`
	Updated  time.Time                  `json:"updated"`
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SessionData),
	}
}

// AddCommandToSession adds a command to a session's history
func (sm *SessionManager) AddCommandToSession(sessionID string, command *models.KubernetesCommand) {
	if sessionID == "" {
		sessionID = "default"
	}

	session, exists := sm.sessions[sessionID]
	if !exists {
		session = &SessionData{
			ID:       sessionID,
			Commands: make([]*models.KubernetesCommand, 0),
			Created:  time.Now(),
		}
		sm.sessions[sessionID] = session
	}

	session.Commands = append(session.Commands, command)
	session.Updated = time.Now()
}

// GetSessionHistory retrieves command history for a session
func (sm *SessionManager) GetSessionHistory(sessionID string) ([]*models.KubernetesCommand, error) {
	if sessionID == "" {
		sessionID = "default"
	}

	session, exists := sm.sessions[sessionID]
	if !exists {
		return []*models.KubernetesCommand{}, nil
	}

	return session.Commands, nil
}

// handleExecuteCommand handles command execution (Story 1.3 + 1.4 AC1)
func handleExecuteCommand(c *fiber.Ctx, confirmationManager *nlp.ConfirmationManager, kubernetesClient clients.KubernetesClient, sessionManager *SessionManager, contextManager *models.SessionContextManager, auditCollector middleware.EventCollectorInterface) error {
	commandID := c.Params("commandId")
	if commandID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ExecuteResponse{
			Success: false,
			Error:   "Command ID is required",
		})
	}

	var req ExecuteRequest
	if err := c.BodyParser(&req); err != nil {
		// Allow empty body for simple execution requests
		req = ExecuteRequest{Confirmed: true}
	}

	// Get the command from confirmation manager
	command, err := confirmationManager.GetCommandStatus(commandID)
	if err != nil {
		log.Printf("Command retrieval error for %q: %v", commandID, err)
		return c.Status(fiber.StatusNotFound).JSON(ExecuteResponse{
			Success:   false,
			CommandID: commandID,
			Error:     fmt.Sprintf("Command not found: %v", err),
		})
	}

	// Verify command is approved
	if command.Status != models.CommandStatusApproved {
		return c.Status(fiber.StatusBadRequest).JSON(ExecuteResponse{
			Success:   false,
			CommandID: commandID,
			Status:    string(command.Status),
			Error:     fmt.Sprintf("Command must be approved before execution, current status: %s", command.Status),
		})
	}

	// Update command status to EXECUTING
	command.UpdateStatus(models.CommandStatusExecuting)
	confirmationManager.UpdateCommand(command)

	// Execute the command with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	result, err := kubernetesClient.ExecuteCommand(ctx, command)
	if err != nil {
		log.Printf("Command execution error for %q: %v", commandID, err)
		
		// Update command status to FAILED
		command.UpdateStatus(models.CommandStatusFailed)
		command.ExecutionResult = &models.CommandExecutionResult{
			Success:         false,
			Output:          "",
			Error:           err.Error(),
			ExitCode:        1,
			ExecutionTime:   0,
			FormattedOutput: fmt.Sprintf("❌ Execution failed: %v", err),
		}
		confirmationManager.UpdateCommand(command)

		return c.Status(fiber.StatusInternalServerError).JSON(ExecuteResponse{
			Success:         false,
			CommandID:       commandID,
			Status:          string(command.Status),
			ExecutionResult: command.ExecutionResult,
			Error:           err.Error(),
		})
	}

	// Apply output formatting
	formatter := models.NewOutputFormatter()
	formatter.FormatOutput(result, command.GeneratedCommand)

	// Update command with execution result
	if result.Success {
		command.UpdateStatus(models.CommandStatusCompleted)
	} else {
		command.UpdateStatus(models.CommandStatusFailed)
	}
	command.ExecutionResult = result
	confirmationManager.UpdateCommand(command)

	// Audit log: Command execution result
	if auditCollector != nil {
		eventType := models.AuditEventTypeCommandExecute
		severity := models.AuditSeverityInfo
		message := fmt.Sprintf("Command executed: %s", command.GeneratedCommand)
		
		if !result.Success {
			severity = models.AuditSeverityError
			message = fmt.Sprintf("Command execution failed: %s", command.GeneratedCommand)
		}
		
		auditEvent, auditErr := models.NewAuditEventBuilder().
			WithEventType(eventType).
			WithMessage(message).
			WithSeverity(severity).
			WithUserContextFromUser(
				&models.User{ID: c.Get("X-User-ID"), Name: c.Get("X-User-Name")}, 
				c.Get("X-Session-ID"), 
				c.IP(), 
				c.Get("User-Agent"),
			).
			WithService("nlp-service", "1.3").
			WithMetadata("command_id", commandID).
			WithMetadata("kubectl_command", command.GeneratedCommand).
			WithMetadata("execution_success", result.Success).
			WithMetadata("exit_code", result.ExitCode).
			WithMetadata("session_id", command.SessionID).
			WithMetadata("risk_level", string(command.RiskLevel)).
			Build()
		
		if auditErr == nil {
			auditCollector.CollectEvent(auditEvent)
		}
	}

	// Story 1.4: Extract context from command results and store in session context
	if command.SessionID != "" && result.Success {
		// Get or create session context
		sessionContext, exists := contextManager.GetContext(command.SessionID)
		if !exists {
			sessionContext = contextManager.CreateContext(command.SessionID)
		}
		
		// Extract entities and reference items from the command output
		entityExtractor := nlp.NewEntityExtractor()
		entities, referenceItems, err := entityExtractor.ExtractEntitiesFromOutput(result.Output, command.GeneratedCommand)
		if err != nil {
			log.Printf("Entity extraction error for session %q: %v", command.SessionID, err)
		} else {
			// Add extracted entities to context
			for _, entity := range entities {
				sessionContext.AddEntity(entity)
			}
			
			// Add reference items to context
			for _, item := range referenceItems {
				item.CommandID = command.ID
				sessionContext.AddReferenceItem(item)
			}
			
			// Update last command ID
			sessionContext.LastCommandID = command.ID
			
			// Update context in manager
			contextManager.UpdateContext(command.SessionID, sessionContext)
		}
		
		// Add to session history
		sessionManager.AddCommandToSession(command.SessionID, command)
	}

	return c.JSON(ExecuteResponse{
		Success:         true,
		CommandID:       commandID,
		Status:          string(command.Status),
		ExecutionResult: result,
	})
}

// handleGetSessionHistory handles session history retrieval (Story 1.3 AC4)
func handleGetSessionHistory(c *fiber.Ctx, sessionManager *SessionManager) error {
	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(HistoryResponse{
			Success: false,
			Error:   "Session ID is required",
		})
	}

	commands, err := sessionManager.GetSessionHistory(sessionID)
	if err != nil {
		log.Printf("History retrieval error for session %q: %v", sessionID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(HistoryResponse{
			Success:   false,
			SessionID: sessionID,
			Error:     err.Error(),
		})
	}

	return c.JSON(HistoryResponse{
		Success:   true,
		SessionID: sessionID,
		Commands:  commands,
		Total:     len(commands),
	})
}

// Context-related handlers (Story 1.4 - Task 4)

// handleGetSessionContext retrieves the current session context (Task 4.1)
func handleGetSessionContext(c *fiber.Ctx, contextManager *models.SessionContextManager) error {
	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ContextResponse{
			Success: false,
			Error:   "Session ID is required",
		})
	}

	context, exists := contextManager.GetContext(sessionID)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(ContextResponse{
			Success:   false,
			SessionID: sessionID,
			Error:     "Session context not found",
		})
	}

	return c.JSON(ContextResponse{
		Success:   true,
		SessionID: sessionID,
		Context:   context,
	})
}

// handleResetSessionContext resets/clears a session context (Task 4.1)
func handleResetSessionContext(c *fiber.Ctx, contextManager *models.SessionContextManager) error {
	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ContextResponse{
			Success: false,
			Error:   "Session ID is required",
		})
	}

	err := contextManager.ClearContext(sessionID)
	if err != nil {
		log.Printf("Context reset error for session %q: %v", sessionID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(ContextResponse{
			Success:   false,
			SessionID: sessionID,
			Error:     err.Error(),
		})
	}

	return c.JSON(ContextResponse{
		Success:   true,
		SessionID: sessionID,
	})
}

// handleValidateReference validates context references (Task 4.1)
func handleValidateReference(c *fiber.Ctx, contextManager *models.SessionContextManager, translator nlp.TranslatorService) error {
	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ValidateReferenceResponse{
			Success: false,
			Error:   "Session ID is required",
		})
	}

	var req ValidateReferenceRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ValidateReferenceResponse{
			Success:   false,
			SessionID: sessionID,
			Error:     "Invalid request format - expected JSON with 'reference' field",
		})
	}

	if req.Reference == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ValidateReferenceResponse{
			Success:   false,
			SessionID: sessionID,
			Error:     "Reference cannot be empty",
		})
	}

	context, exists := contextManager.GetContext(sessionID)
	if !exists {
		return c.Status(fiber.StatusNotFound).JSON(ValidateReferenceResponse{
			Success:   false,
			SessionID: sessionID,
			Reference: req.Reference,
			IsValid:   false,
			Error:     "Session context not found",
			Suggestions: []string{"Create a context by running a kubectl command first"},
		})
	}

	// Try to resolve the reference
	resolvedEntity, err := context.GetEntityByReference(req.Reference)
	if err != nil {
		// Check if we can provide helpful suggestions
		availableRefs := context.GetAvailableReferences()
		suggestions := make([]string, 0)
		
		for resourceType, names := range availableRefs {
			if len(names) > 0 {
				suggestions = append(suggestions, fmt.Sprintf("Try '%s 1' or 'the first %s'", resourceType, resourceType))
			}
		}
		
		if len(suggestions) == 0 {
			suggestions = []string{"No referenceable items in context. Run commands like 'get pods' first."}
		}

		return c.JSON(ValidateReferenceResponse{
			Success:     false,
			SessionID:   sessionID,
			Reference:   req.Reference,
			IsValid:     false,
			Error:       err.Error(),
			Suggestions: suggestions,
		})
	}

	return c.JSON(ValidateReferenceResponse{
		Success:        true,
		SessionID:      sessionID,
		Reference:      req.Reference,
		IsValid:        true,
		ResolvedEntity: resolvedEntity,
	})
}

// handleGetContextState retrieves context state for debugging (Task 4.2)
func handleGetContextState(c *fiber.Ctx, contextManager *models.SessionContextManager) error {
	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ContextResponse{
			Success: false,
			Error:   "Session ID is required",
		})
	}

	contextState, err := contextManager.GetContextState(sessionID)
	if err != nil {
		log.Printf("Context state retrieval error for session %q: %v", sessionID, err)
		return c.Status(fiber.StatusInternalServerError).JSON(ContextResponse{
			Success:   false,
			SessionID: sessionID,
			Error:     err.Error(),
		})
	}

	return c.JSON(ContextResponse{
		Success:      true,
		SessionID:    sessionID,
		ContextState: contextState,
	})
}

// handleValidateContextHealth validates context health (Task 4.2)
func handleValidateContextHealth(c *fiber.Ctx, contextManager *models.SessionContextManager) error {
	sessionID := c.Params("sessionId")
	if sessionID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(HealthResponse{
			Success: false,
			Error:   "Session ID is required",
		})
	}

	health := contextManager.ValidateContextHealth(sessionID)
	
	return c.JSON(HealthResponse{
		Success:   true,
		SessionID: sessionID,
		Health:    health,
	})
}

// handleListActiveSessions lists all active sessions (Task 4.2)
func handleListActiveSessions(c *fiber.Ctx, contextManager *models.SessionContextManager) error {
	activeSessions := contextManager.ListActiveSessions()
	
	return c.JSON(ActiveSessionsResponse{
		Success:        true,
		ActiveSessions: activeSessions,
		Total:          len(activeSessions),
	})
}

// handleGetContextStats retrieves context manager statistics (Task 4.2)
func handleGetContextStats(c *fiber.Ctx, contextManager *models.SessionContextManager) error {
	stats := contextManager.GetStats()
	
	return c.JSON(StatsResponse{
		Success: true,
		Stats:   stats,
	})
}
