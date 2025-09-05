// Package main provides the API Gateway service for KubeChat with enterprise authentication
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/healthcheck"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/gofiber/fiber/v3/middleware/requestid"

	"github.com/pramodksahoo/kube-chat/pkg/middleware"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// Config holds the API Gateway configuration
type Config struct {
	Port            string                        `json:"port"`
	Host            string                        `json:"host"`
	Environment     string                        `json:"environment"`
	JWTConfig       middleware.JWTConfig          `json:"jwt_config"`
	OIDCProviders   []middleware.OIDCProvider     `json:"oidc_providers"`
	SAMLConfig      middleware.SAMLConfig         `json:"saml_config"`
	CORSOrigins     []string                     `json:"cors_origins"`
	EnableSAML      bool                         `json:"enable_saml"`
	SessionTimeout  time.Duration                 `json:"session_timeout"`
	EnableWebSocket bool                         `json:"enable_websocket"`
}

// APIGateway represents the main API Gateway service
type APIGateway struct {
	app            *fiber.App
	config         Config
	authMiddleware *middleware.AuthMiddleware
	jwtService     middleware.JWTServiceInterface
	samlProvider   *middleware.SAMLProvider
	userService    models.UserService
	sessionManager *models.ExtendedChatSessionManager
}

// NewAPIGateway creates a new API Gateway instance
func NewAPIGateway(config Config) (*APIGateway, error) {
	// Create Fiber app with configuration
	app := fiber.New(fiber.Config{
		AppName:           "KubeChat API Gateway",
		EnablePrintRoutes: config.Environment == "development",
		ErrorHandler:      customErrorHandler,
		IdleTimeout:       30 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	})

	// Initialize JWT service
	jwtService, err := middleware.NewJWTService(config.JWTConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT service: %w", err)
	}

	// Initialize authentication middleware
	authMiddleware, err := middleware.NewAuthMiddleware(config.OIDCProviders, jwtService)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth middleware: %w", err)
	}

	// Initialize SAML provider if enabled
	var samlProvider *middleware.SAMLProvider
	if config.EnableSAML {
		samlProvider, err = middleware.NewSAMLProvider(config.SAMLConfig, jwtService)
		if err != nil {
			log.Printf("Warning: SAML provider initialization failed: %v", err)
			// Don't fail startup, just disable SAML
			config.EnableSAML = false
		}
	}

	// Initialize user service (in-memory for now)
	userService := models.NewMemoryUserService()

	// Initialize session manager
	sessionManager := models.NewExtendedChatSessionManager()

	return &APIGateway{
		app:            app,
		config:         config,
		authMiddleware: authMiddleware,
		jwtService:     jwtService,
		samlProvider:   samlProvider,
		userService:    userService,
		sessionManager: sessionManager,
	}, nil
}

// setupMiddleware configures global middleware
func (gw *APIGateway) setupMiddleware() {
	// Recovery middleware
	gw.app.Use(recover.New())

	// Request ID middleware
	gw.app.Use(requestid.New())

	// Logger middleware
	gw.app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${method} ${path} ${latency}\n",
	}))

	// CORS middleware
	gw.app.Use(cors.New(cors.Config{
		AllowOrigins: strings.Join(gw.config.CORSOrigins, ","),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS",
		AllowCredentials: true,
	}))

	// Health check middleware
	gw.app.Use(healthcheck.New(healthcheck.Config{
		LivenessEndpoint:  "/health/live",
		ReadinessEndpoint: "/health/ready",
		LivenessProbe: func(c fiber.Ctx) bool {
			return true // API Gateway is alive
		},
		ReadinessProbe: func(c fiber.Ctx) bool {
			// Check if critical services are ready
			return gw.jwtService != nil && gw.authMiddleware != nil
		},
	}))
}

// setupAuthRoutes configures authentication-related routes
func (gw *APIGateway) setupAuthRoutes() {
	auth := gw.app.Group("/auth")

	// Authentication providers list
	auth.Get("/providers", gw.authMiddleware.ListProviders())

	// OIDC authentication routes
	auth.Post("/login", gw.handleLogin)
	auth.Get("/callback/:provider", gw.handleCallback)
	auth.Post("/logout", gw.authMiddleware.RequireAuthentication(), gw.handleLogout)
	auth.Post("/refresh", gw.handleRefresh)

	// SAML routes (if enabled)
	if gw.config.EnableSAML && gw.samlProvider != nil {
		middleware.CreateSAMLRoutes(auth, gw.samlProvider)
		
		// Fallback authentication route
		auth.Get("/fallback", gw.handleAuthFallback)
	}

	// User profile routes
	profile := auth.Group("/profile", gw.authMiddleware.RequireAuthentication())
	profile.Get("/", gw.handleGetProfile)
	profile.Put("/", gw.handleUpdateProfile)
}

// setupAPIRoutes configures main API routes
func (gw *APIGateway) setupAPIRoutes() {
	api := gw.app.Group("/api/v1", gw.authMiddleware.RequireAuthentication())

	// Chat session routes
	sessions := api.Group("/sessions")
	sessions.Post("/", gw.handleCreateSession)
	sessions.Get("/", gw.handleListSessions)
	sessions.Get("/:sessionId", gw.handleGetSession)
	sessions.Put("/:sessionId", gw.handleUpdateSession)
	sessions.Delete("/:sessionId", gw.handleDeleteSession)
	sessions.Post("/:sessionId/messages", gw.handleSendMessage)

	// WebSocket route for real-time chat (if enabled)
	if gw.config.EnableWebSocket {
		api.Get("/chat/:sessionId", gw.handleWebSocketUpgrade)
	}

	// Admin routes (admin role required)
	admin := api.Group("/admin", gw.requireRole("admin"))
	admin.Get("/users", gw.handleListUsers)
	admin.Get("/users/:userId", gw.handleGetUser)
	admin.Put("/users/:userId", gw.handleUpdateUser)
	admin.Delete("/users/:userId", gw.handleDeleteUser)
	admin.Post("/cleanup", gw.handleCleanupSessions)
}

// Authentication handlers

func (gw *APIGateway) handleLogin(c fiber.Ctx) error {
	var req struct {
		Provider    string `json:"provider"`
		RedirectURL string `json:"redirect_url,omitempty"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	if req.Provider == "" {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Provider is required",
		})
	}

	// Generate state for CSRF protection
	state := fmt.Sprintf("state-%d", time.Now().UnixNano())

	// Get authentication URL from provider
	authURL, err := gw.authMiddleware.GetAuthURL(req.Provider, state)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"auth_url": authURL,
		"state":    state,
		"provider": req.Provider,
	})
}

func (gw *APIGateway) handleCallback(c fiber.Ctx) error {
	// Forward to auth middleware callback handler
	return gw.authMiddleware.HandleCallback(c)
}

func (gw *APIGateway) handleLogout(c fiber.Ctx) error {
	// Get user from context
	userClaims := c.Locals("user").(*middleware.JWTClaims)
	if userClaims == nil {
		return c.Status(401).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid authentication",
		})
	}

	// Blacklist the token
	if err := gw.jwtService.BlacklistToken(userClaims.SessionID); err != nil {
		log.Printf("Failed to blacklist token: %v", err)
	}

	// Remove user from active sessions
	user, err := gw.userService.GetUser(userClaims.UserID)
	if err == nil {
		user.RemoveActiveSession(userClaims.SessionID)
		gw.userService.UpdateUser(user)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Logged out successfully",
	})
}

func (gw *APIGateway) handleRefresh(c fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	tokenPair, err := gw.jwtService.RefreshToken(req.RefreshToken)
	if err != nil {
		return c.Status(401).JSON(fiber.Map{
			"error":   true,
			"message": "Token refresh failed",
		})
	}

	return c.JSON(fiber.Map{
		"access_token":  tokenPair.AccessToken,
		"refresh_token": tokenPair.RefreshToken,
		"expires_at":    tokenPair.ExpiresAt.Unix(),
		"token_type":    tokenPair.TokenType,
	})
}

func (gw *APIGateway) handleAuthFallback(c fiber.Ctx) error {
	if !gw.config.EnableSAML || gw.samlProvider == nil {
		return c.Status(503).JSON(fiber.Map{
			"error":   true,
			"message": "SAML fallback not available",
		})
	}

	return middleware.CreateFallbackHandler(gw.authMiddleware, gw.samlProvider)(c)
}

// Profile handlers

func (gw *APIGateway) handleGetProfile(c fiber.Ctx) error {
	userClaims := c.Locals("user").(*middleware.JWTClaims)
	user, err := gw.userService.GetUser(userClaims.UserID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": "User not found",
		})
	}

	return c.JSON(user)
}

func (gw *APIGateway) handleUpdateProfile(c fiber.Ctx) error {
	userClaims := c.Locals("user").(*middleware.JWTClaims)
	user, err := gw.userService.GetUser(userClaims.UserID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": "User not found",
		})
	}

	var updates struct {
		Name        string                  `json:"name,omitempty"`
		Preferences models.UserPreferences  `json:"preferences,omitempty"`
	}

	if err := c.Bind().JSON(&updates); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	// Update allowed fields
	if updates.Name != "" {
		user.Name = updates.Name
	}
	if updates.Preferences.Theme != "" {
		user.Preferences = updates.Preferences
	}

	if err := gw.userService.UpdateUser(user); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to update profile",
		})
	}

	return c.JSON(user)
}

// Session handlers (simplified - full implementation would be more complex)

func (gw *APIGateway) handleCreateSession(c fiber.Ctx) error {
	userClaims := c.Locals("user").(*middleware.JWTClaims)
	
	var req struct {
		ClusterContext string `json:"cluster_context"`
		Namespace      string `json:"namespace"`
	}

	if err := c.Bind().JSON(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{
			"error":   true,
			"message": "Invalid request body",
		})
	}

	// Create authentication context
	authContext := &models.SessionAuthContext{
		UserID:           userClaims.UserID,
		SessionID:        userClaims.SessionID,
		AuthProvider:     "oidc", // This would be determined from the actual provider
		AuthenticatedAt:  time.Now(),
		TokenIssuedAt:    userClaims.IssuedAt,
		TokenExpiresAt:   userClaims.ExpiresAt,
		IPAddress:        c.IP(),
		UserAgent:        c.Get("User-Agent"),
		Permissions:      []string{"read", "create-session"},
		KubernetesContext: req.ClusterContext,
		LastActivity:     time.Now(),
		IsValid:          true,
	}

	// Create chat session
	session := gw.sessionManager.CreateAuthenticatedSession(
		userClaims.UserID,
		req.ClusterContext,
		req.Namespace,
		authContext,
	)

	return c.Status(201).JSON(session)
}

func (gw *APIGateway) handleListSessions(c fiber.Ctx) error {
	userClaims := c.Locals("user").(*middleware.JWTClaims)
	sessions := gw.sessionManager.GetUserAuthenticatedSessions(userClaims.UserID)
	
	return c.JSON(fiber.Map{
		"sessions": sessions,
		"count":    len(sessions),
	})
}

func (gw *APIGateway) handleGetSession(c fiber.Ctx) error {
	sessionID := c.Params("sessionId")
	session, err := gw.sessionManager.GetAuthenticatedSession(sessionID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": err.Error(),
		})
	}

	// Verify user owns the session
	userClaims := c.Locals("user").(*middleware.JWTClaims)
	if session.UserID != userClaims.UserID {
		return c.Status(403).JSON(fiber.Map{
			"error":   true,
			"message": "Access denied",
		})
	}

	return c.JSON(session)
}

func (gw *APIGateway) handleUpdateSession(c fiber.Ctx) error {
	// Implementation for updating session (namespace, context, etc.)
	return c.JSON(fiber.Map{"message": "Update session not implemented"})
}

func (gw *APIGateway) handleDeleteSession(c fiber.Ctx) error {
	sessionID := c.Params("sessionId")
	if err := gw.sessionManager.DeleteSession(sessionID); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to delete session",
		})
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Session deleted",
	})
}

func (gw *APIGateway) handleSendMessage(c fiber.Ctx) error {
	// Implementation for sending messages to chat session
	return c.JSON(fiber.Map{"message": "Send message not implemented"})
}

func (gw *APIGateway) handleWebSocketUpgrade(c fiber.Ctx) error {
	// Implementation for WebSocket upgrade with authentication
	return c.JSON(fiber.Map{"message": "WebSocket not implemented"})
}

// Admin handlers

func (gw *APIGateway) handleListUsers(c fiber.Ctx) error {
	users, err := gw.userService.ListUsers()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   true,
			"message": "Failed to list users",
		})
	}

	return c.JSON(fiber.Map{
		"users": users,
		"count": len(users),
	})
}

func (gw *APIGateway) handleGetUser(c fiber.Ctx) error {
	userID := c.Params("userId")
	user, err := gw.userService.GetUser(userID)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"error":   true,
			"message": "User not found",
		})
	}

	return c.JSON(user)
}

func (gw *APIGateway) handleUpdateUser(c fiber.Ctx) error {
	// Implementation for admin user updates
	return c.JSON(fiber.Map{"message": "Update user not implemented"})
}

func (gw *APIGateway) handleDeleteUser(c fiber.Ctx) error {
	// Implementation for admin user deletion
	return c.JSON(fiber.Map{"message": "Delete user not implemented"})
}

func (gw *APIGateway) handleCleanupSessions(c fiber.Ctx) error {
	expired := gw.sessionManager.CleanupExpiredSessions()
	unauthenticated := gw.sessionManager.CleanupUnauthenticatedSessions()

	return c.JSON(fiber.Map{
		"success":        true,
		"expired_removed": expired,
		"unauth_removed":  unauthenticated,
	})
}

// Middleware helpers

func (gw *APIGateway) requireRole(role string) fiber.Handler {
	return func(c fiber.Ctx) error {
		userClaims := c.Locals("user").(*middleware.JWTClaims)
		if userClaims == nil {
			return c.Status(401).JSON(fiber.Map{
				"error":   true,
				"message": "Authentication required",
			})
		}

		// Get user and check role
		user, err := gw.userService.GetUser(userClaims.UserID)
		if err != nil || string(user.Role) != role {
			return c.Status(403).JSON(fiber.Map{
				"error":   true,
				"message": "Insufficient permissions",
			})
		}

		return c.Next()
	}
}

// Error handler
func customErrorHandler(c fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}

	return c.Status(code).JSON(fiber.Map{
		"error":   true,
		"message": err.Error(),
	})
}

// Start starts the API Gateway server
func (gw *APIGateway) Start() error {
	// Setup middleware and routes
	gw.setupMiddleware()
	gw.setupAuthRoutes()
	gw.setupAPIRoutes()

	// Start server
	address := fmt.Sprintf("%s:%s", gw.config.Host, gw.config.Port)
	log.Printf("Starting API Gateway on %s", address)
	
	return gw.app.Listen(address)
}

// Shutdown gracefully shuts down the API Gateway
func (gw *APIGateway) Shutdown() error {
	return gw.app.Shutdown()
}

// main function
func main() {
	// Load configuration (in production, this would come from environment variables or config files)
	config := Config{
		Port:        getEnv("PORT", "8080"),
		Host:        getEnv("HOST", "0.0.0.0"),
		Environment: getEnv("ENVIRONMENT", "development"),
		JWTConfig: middleware.JWTConfig{
			RedisAddr:       getEnv("REDIS_ADDR", "localhost:6379"),
			RedisPassword:   getEnv("REDIS_PASSWORD", ""),
			RedisDB:         0,
			TokenDuration:   8 * time.Hour,
			RefreshDuration: 24 * 7 * time.Hour,
			Issuer:          "kubechat-api-gateway",
		},
		OIDCProviders: []middleware.OIDCProvider{
			{
				Name:         "google",
				Issuer:       "https://accounts.google.com",
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				RedirectURL:  getEnv("GOOGLE_REDIRECT_URL", "http://localhost:8080/auth/callback/google"),
				Scopes:       []string{"email", "profile"},
			},
		},
		SAMLConfig: middleware.SAMLConfig{
			EntityID:       getEnv("SAML_ENTITY_ID", "http://localhost:8080/saml/metadata"),
			ACSURL:         getEnv("SAML_ACS_URL", "http://localhost:8080/saml/acs"),
			SLOUrl:         getEnv("SAML_SLO_URL", "http://localhost:8080/saml/sls"),
			IDPMetadataURL: getEnv("SAML_IDP_METADATA_URL", ""),
			SignRequests:   true,
			ForceAuthn:     false,
			AllowIDPInit:   true,
		},
		CORSOrigins:     []string{"http://localhost:3000", "https://kubechat.example.com"},
		EnableSAML:      getEnv("ENABLE_SAML", "false") == "true",
		SessionTimeout:  8 * time.Hour,
		EnableWebSocket: true,
	}

	// Create API Gateway
	gateway, err := NewAPIGateway(config)
	if err != nil {
		log.Fatalf("Failed to create API Gateway: %v", err)
	}

	// Setup graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		log.Println("Shutting down API Gateway...")
		if err := gateway.Shutdown(); err != nil {
			log.Printf("Error during shutdown: %v", err)
		}
	}()

	// Start server
	if err := gateway.Start(); err != nil {
		log.Fatalf("Failed to start API Gateway: %v", err)
	}
}

// Helper function to get environment variables with defaults
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}