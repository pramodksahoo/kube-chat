package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/audit/streaming"
)

// SIEMConfigManager handles SIEM integration configuration
type SIEMConfigManager struct {
	configs       map[string]*SIEMConfig
	templates     map[string]*SIEMTemplate
	configDir     string
	autoReload    bool
	watchInterval time.Duration
	mu            sync.RWMutex
	onChange      []func(string, *SIEMConfig) // Change callbacks
}

// SIEMConfig represents configuration for a specific SIEM integration
type SIEMConfig struct {
	ID             string                   `json:"id"`
	Name           string                   `json:"name"`
	Platform       SIEMPlatform             `json:"platform"`
	Description    string                   `json:"description"`
	Enabled        bool                     `json:"enabled"`
	
	// Connection configuration
	WebhookConfig  *WebhookSIEMConfig       `json:"webhook_config,omitempty"`
	NATSConfig     *NATSSIEMConfig          `json:"nats_config,omitempty"`
	
	// Format configuration
	Format         string                   `json:"format"`         // JSON, CEF, LEEF
	FieldMappings  map[string]string        `json:"field_mappings,omitempty"`
	CustomHeaders  map[string]string        `json:"custom_headers,omitempty"`
	
	// Filtering and routing
	EventFilters   streaming.WebhookFilterConfig `json:"event_filters"`
	
	// Security and authentication
	Authentication AuthConfig              `json:"authentication"`
	TLSConfig      TLSConfig               `json:"tls_config,omitempty"`
	
	// Reliability and performance
	RetryConfig    streaming.WebhookRetryConfig `json:"retry_config"`
	BufferConfig   streaming.LocalBufferConfig  `json:"buffer_config"`
	
	// Metadata
	Tags           []string                `json:"tags,omitempty"`
	CreatedAt      time.Time               `json:"created_at"`
	UpdatedAt      time.Time               `json:"updated_at"`
	CreatedBy      string                  `json:"created_by"`
	Version        int                     `json:"version"`
	Metadata       map[string]interface{}  `json:"metadata,omitempty"`
}

// WebhookSIEMConfig configures webhook-based SIEM integration
type WebhookSIEMConfig struct {
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers,omitempty"`
	Timeout        time.Duration     `json:"timeout"`
	MaxRetries     int               `json:"max_retries"`
	VerifySSL      bool              `json:"verify_ssl"`
	ProxyURL       string            `json:"proxy_url,omitempty"`
}

// NATSSIEMConfig configures NATS-based SIEM integration
type NATSSIEMConfig struct {
	URLs           []string          `json:"urls"`
	Subject        string            `json:"subject"`
	StreamName     string            `json:"stream_name"`
	Credentials    string            `json:"credentials,omitempty"`
	ClusterName    string            `json:"cluster_name,omitempty"`
}

// AuthConfig defines authentication configuration
type AuthConfig struct {
	Type           AuthType          `json:"type"`           // none, basic, bearer, apikey, oauth2, hmac
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	Token          string            `json:"token,omitempty"`
	APIKey         string            `json:"api_key,omitempty"`
	APIKeyHeader   string            `json:"api_key_header,omitempty"`
	OAuth2Config   *OAuth2Config     `json:"oauth2_config,omitempty"`
	HMACSecret     string            `json:"hmac_secret,omitempty"`
}

// TLSConfig defines TLS configuration
type TLSConfig struct {
	Enabled            bool   `json:"enabled"`
	CertFile           string `json:"cert_file,omitempty"`
	KeyFile            string `json:"key_file,omitempty"`
	CAFile             string `json:"ca_file,omitempty"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

// OAuth2Config defines OAuth2 authentication configuration
type OAuth2Config struct {
	TokenURL     string            `json:"token_url"`
	ClientID     string            `json:"client_id"`
	ClientSecret string            `json:"client_secret"`
	Scopes       []string          `json:"scopes,omitempty"`
	ExtraParams  map[string]string `json:"extra_params,omitempty"`
}

// SIEMTemplate provides pre-configured templates for common SIEM platforms
type SIEMTemplate struct {
	ID                 string                       `json:"id"`
	Name               string                       `json:"name"`
	Platform           SIEMPlatform                 `json:"platform"`
	Description        string                       `json:"description"`
	Version            string                       `json:"version"`
	RecommendedFormat  string                       `json:"recommended_format"`
	DefaultConfig      SIEMConfig                   `json:"default_config"`
	FieldMappings      map[string]string            `json:"field_mappings"`
	ValidationRules    []ValidationRule             `json:"validation_rules"`
	Documentation      SIEMTemplateDocumentation    `json:"documentation"`
	Examples           []SIEMConfigExample          `json:"examples"`
}

// ValidationRule defines validation rules for SIEM configuration
type ValidationRule struct {
	Field       string `json:"field"`
	Required    bool   `json:"required"`
	Type        string `json:"type"`        // string, int, bool, url, duration
	Pattern     string `json:"pattern,omitempty"`
	MinValue    *int   `json:"min_value,omitempty"`
	MaxValue    *int   `json:"max_value,omitempty"`
	Description string `json:"description"`
}

// SIEMTemplateDocumentation provides documentation for SIEM templates
type SIEMTemplateDocumentation struct {
	SetupInstructions []string          `json:"setup_instructions"`
	ConfigurationTips []string          `json:"configuration_tips"`
	TroubleshootingTips []string        `json:"troubleshooting_tips"`
	References        []DocumentReference `json:"references"`
}

// DocumentReference provides links to external documentation
type DocumentReference struct {
	Title string `json:"title"`
	URL   string `json:"url"`
	Type  string `json:"type"` // official, guide, tutorial, forum
}

// SIEMConfigExample provides example configurations
type SIEMConfigExample struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Config      SIEMConfig `json:"config"`
	UseCase     string     `json:"use_case"`
}

// SIEMPlatform represents supported SIEM platforms
type SIEMPlatform string

const (
	SIEMPlatformSplunk        SIEMPlatform = "splunk"
	SIEMPlatformQRadar        SIEMPlatform = "qradar"
	SIEMPlatformSentinel      SIEMPlatform = "sentinel"
	SIEMPlatformElastic       SIEMPlatform = "elastic"
	SIEMPlatformSumoLogic     SIEMPlatform = "sumologic"
	SIEMPlatformLogRhythm     SIEMPlatform = "logrhythm"
	SIEMPlatformArcSight      SIEMPlatform = "arcsight"
	SIEMPlatformGeneric       SIEMPlatform = "generic"
)

// AuthType represents authentication types
type AuthType string

const (
	AuthTypeNone   AuthType = "none"
	AuthTypeBasic  AuthType = "basic"
	AuthTypeBearer AuthType = "bearer"
	AuthTypeAPIKey AuthType = "apikey"
	AuthTypeOAuth2 AuthType = "oauth2"
	AuthTypeHMAC   AuthType = "hmac"
)

// ConfigurationStatus represents the status of SIEM configuration
type ConfigurationStatus struct {
	ConfigID    string                 `json:"config_id"`
	Status      string                 `json:"status"`      // valid, invalid, warning
	LastTested  time.Time              `json:"last_tested"`
	TestResult  *ConnectionTestResult  `json:"test_result,omitempty"`
	Issues      []ConfigurationIssue   `json:"issues,omitempty"`
}

// ConnectionTestResult represents the result of testing SIEM connectivity
type ConnectionTestResult struct {
	Success       bool          `json:"success"`
	ResponseTime  time.Duration `json:"response_time"`
	StatusCode    int           `json:"status_code,omitempty"`
	ErrorMessage  string        `json:"error_message,omitempty"`
	TestedAt      time.Time     `json:"tested_at"`
}

// ConfigurationIssue represents configuration validation issues
type ConfigurationIssue struct {
	Field       string `json:"field"`
	Severity    string `json:"severity"`    // error, warning, info
	Message     string `json:"message"`
	Suggestion  string `json:"suggestion,omitempty"`
}

// NewSIEMConfigManager creates a new SIEM configuration manager
func NewSIEMConfigManager(configDir string, autoReload bool) *SIEMConfigManager {
	manager := &SIEMConfigManager{
		configs:       make(map[string]*SIEMConfig),
		templates:     make(map[string]*SIEMTemplate),
		configDir:     configDir,
		autoReload:    autoReload,
		watchInterval: time.Minute * 5,
		onChange:      make([]func(string, *SIEMConfig), 0),
	}
	
	// Create config directory if it doesn't exist
	os.MkdirAll(configDir, 0755)
	
	// Load built-in templates
	manager.loadBuiltinTemplates()
	
	// Load existing configurations
	manager.LoadConfigurations()
	
	// Start auto-reload if enabled
	if autoReload {
		go manager.watchConfigDirectory()
	}
	
	return manager
}

// LoadConfigurations loads all SIEM configurations from the config directory
func (scm *SIEMConfigManager) LoadConfigurations() error {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	
	configFiles, err := filepath.Glob(filepath.Join(scm.configDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to glob config files: %w", err)
	}
	
	for _, configFile := range configFiles {
		if err := scm.loadConfigurationFile(configFile); err != nil {
			// Log error but continue loading other configs
			continue
		}
	}
	
	return nil
}

// SaveConfiguration saves a SIEM configuration to disk
func (scm *SIEMConfigManager) SaveConfiguration(config *SIEMConfig) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	
	// Update metadata
	config.UpdatedAt = time.Now().UTC()
	config.Version++
	
	// Validate configuration
	if err := scm.validateConfiguration(config); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}
	
	// Save to disk
	configFile := filepath.Join(scm.configDir, fmt.Sprintf("%s.json", config.ID))
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal configuration: %w", err)
	}
	
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write configuration file: %w", err)
	}
	
	// Update in-memory configuration
	scm.configs[config.ID] = config
	
	// Notify change callbacks
	for _, callback := range scm.onChange {
		callback(config.ID, config)
	}
	
	return nil
}

// GetConfiguration retrieves a SIEM configuration by ID
func (scm *SIEMConfigManager) GetConfiguration(configID string) (*SIEMConfig, error) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	
	config, exists := scm.configs[configID]
	if !exists {
		return nil, fmt.Errorf("SIEM configuration %s not found", configID)
	}
	
	// Return a copy to prevent external mutations
	configCopy := *config
	return &configCopy, nil
}

// ListConfigurations returns all SIEM configurations
func (scm *SIEMConfigManager) ListConfigurations() []*SIEMConfig {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	
	configs := make([]*SIEMConfig, 0, len(scm.configs))
	for _, config := range scm.configs {
		configCopy := *config
		configs = append(configs, &configCopy)
	}
	
	return configs
}

// DeleteConfiguration removes a SIEM configuration
func (scm *SIEMConfigManager) DeleteConfiguration(configID string) error {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	
	config, exists := scm.configs[configID]
	if !exists {
		return fmt.Errorf("SIEM configuration %s not found", configID)
	}
	
	// Remove from disk
	configFile := filepath.Join(scm.configDir, fmt.Sprintf("%s.json", configID))
	if err := os.Remove(configFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove configuration file: %w", err)
	}
	
	// Remove from memory
	delete(scm.configs, configID)
	
	// Notify change callbacks
	for _, callback := range scm.onChange {
		callback(configID, config)
	}
	
	return nil
}

// GetTemplate retrieves a SIEM template by ID
func (scm *SIEMConfigManager) GetTemplate(templateID string) (*SIEMTemplate, error) {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	
	template, exists := scm.templates[templateID]
	if !exists {
		return nil, fmt.Errorf("SIEM template %s not found", templateID)
	}
	
	return template, nil
}

// ListTemplates returns all available SIEM templates
func (scm *SIEMConfigManager) ListTemplates() []*SIEMTemplate {
	scm.mu.RLock()
	defer scm.mu.RUnlock()
	
	templates := make([]*SIEMTemplate, 0, len(scm.templates))
	for _, template := range scm.templates {
		templates = append(templates, template)
	}
	
	return templates
}

// CreateFromTemplate creates a SIEM configuration from a template
func (scm *SIEMConfigManager) CreateFromTemplate(templateID, configID, configName string, overrides map[string]interface{}) (*SIEMConfig, error) {
	template, err := scm.GetTemplate(templateID)
	if err != nil {
		return nil, err
	}
	
	// Start with template's default configuration
	config := template.DefaultConfig
	config.ID = configID
	config.Name = configName
	config.CreatedAt = time.Now().UTC()
	config.UpdatedAt = config.CreatedAt
	config.Version = 1
	
	// Apply field mappings from template
	if config.FieldMappings == nil {
		config.FieldMappings = make(map[string]string)
	}
	for k, v := range template.FieldMappings {
		config.FieldMappings[k] = v
	}
	
	// Apply overrides
	if err := scm.applyConfigurationOverrides(&config, overrides); err != nil {
		return nil, fmt.Errorf("failed to apply configuration overrides: %w", err)
	}
	
	// Validate the configuration
	if err := scm.validateConfiguration(&config); err != nil {
		return nil, fmt.Errorf("generated configuration is invalid: %w", err)
	}
	
	return &config, nil
}

// TestConfiguration tests connectivity to a SIEM system
func (scm *SIEMConfigManager) TestConfiguration(configID string) (*ConnectionTestResult, error) {
	config, err := scm.GetConfiguration(configID)
	if err != nil {
		return nil, err
	}
	
	result := &ConnectionTestResult{
		TestedAt: time.Now().UTC(),
	}
	
	startTime := time.Now()
	
	if config.WebhookConfig != nil {
		// Test webhook connectivity
		result.Success, result.StatusCode, result.ErrorMessage = scm.testWebhookConnection(config.WebhookConfig)
	} else if config.NATSConfig != nil {
		// Test NATS connectivity
		result.Success, result.ErrorMessage = scm.testNATSConnection(config.NATSConfig)
	} else {
		result.Success = false
		result.ErrorMessage = "No connection configuration found"
	}
	
	result.ResponseTime = time.Since(startTime)
	
	return result, nil
}

// ValidateConfiguration validates a SIEM configuration
func (scm *SIEMConfigManager) ValidateConfiguration(config *SIEMConfig) []ConfigurationIssue {
	return scm.validateConfigurationDetailed(config)
}

// OnConfigurationChange registers a callback for configuration changes
func (scm *SIEMConfigManager) OnConfigurationChange(callback func(string, *SIEMConfig)) {
	scm.mu.Lock()
	defer scm.mu.Unlock()
	scm.onChange = append(scm.onChange, callback)
}

// Helper methods

func (scm *SIEMConfigManager) loadConfigurationFile(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", configFile, err)
	}
	
	var config SIEMConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config file %s: %w", configFile, err)
	}
	
	scm.configs[config.ID] = &config
	return nil
}

func (scm *SIEMConfigManager) validateConfiguration(config *SIEMConfig) error {
	issues := scm.validateConfigurationDetailed(config)
	
	// Check for error-level issues
	for _, issue := range issues {
		if issue.Severity == "error" {
			return fmt.Errorf("validation error in field %s: %s", issue.Field, issue.Message)
		}
	}
	
	return nil
}

func (scm *SIEMConfigManager) validateConfigurationDetailed(config *SIEMConfig) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Basic validation
	if config.ID == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "id",
			Severity: "error",
			Message:  "Configuration ID is required",
		})
	}
	
	if config.Name == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "name",
			Severity: "error",
			Message:  "Configuration name is required",
		})
	}
	
	if config.Platform == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "platform",
			Severity: "error",
			Message:  "SIEM platform is required",
		})
	}
	
	// Format validation
	validFormats := []string{"JSON", "CEF", "LEEF"}
	formatValid := false
	for _, validFormat := range validFormats {
		if config.Format == validFormat {
			formatValid = true
			break
		}
	}
	if !formatValid {
		issues = append(issues, ConfigurationIssue{
			Field:    "format",
			Severity: "error",
			Message:  "Invalid format. Must be one of: JSON, CEF, LEEF",
		})
	}
	
	// Connection configuration validation
	if config.WebhookConfig == nil && config.NATSConfig == nil {
		issues = append(issues, ConfigurationIssue{
			Field:    "connection",
			Severity: "error",
			Message:  "Either webhook_config or nats_config must be specified",
		})
	}
	
	// Webhook configuration validation
	if config.WebhookConfig != nil {
		if config.WebhookConfig.URL == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "webhook_config.url",
				Severity: "error",
				Message:  "Webhook URL is required",
			})
		}
		
		if config.WebhookConfig.Method == "" {
			config.WebhookConfig.Method = "POST"
		}
		
		if config.WebhookConfig.Timeout == 0 {
			config.WebhookConfig.Timeout = 30 * time.Second
		}
	}
	
	// NATS configuration validation
	if config.NATSConfig != nil {
		if len(config.NATSConfig.URLs) == 0 {
			issues = append(issues, ConfigurationIssue{
				Field:    "nats_config.urls",
				Severity: "error",
				Message:  "NATS URLs are required",
			})
		}
		
		if config.NATSConfig.Subject == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "nats_config.subject",
				Severity: "error",
				Message:  "NATS subject is required",
			})
		}
	}
	
	return issues
}

func (scm *SIEMConfigManager) applyConfigurationOverrides(config *SIEMConfig, overrides map[string]interface{}) error {
	// Simple override implementation
	// In a real implementation, this would be more sophisticated
	if name, ok := overrides["name"].(string); ok {
		config.Name = name
	}
	if enabled, ok := overrides["enabled"].(bool); ok {
		config.Enabled = enabled
	}
	if url, ok := overrides["webhook_url"].(string); ok && config.WebhookConfig != nil {
		config.WebhookConfig.URL = url
	}
	
	return nil
}

func (scm *SIEMConfigManager) testWebhookConnection(webhookConfig *WebhookSIEMConfig) (bool, int, string) {
	// TODO: Implement actual webhook connectivity test
	// This would make an HTTP request to the webhook URL
	return true, 200, ""
}

func (scm *SIEMConfigManager) testNATSConnection(natsConfig *NATSSIEMConfig) (bool, string) {
	// TODO: Implement actual NATS connectivity test
	// This would connect to NATS and verify the stream exists
	return true, ""
}

func (scm *SIEMConfigManager) watchConfigDirectory() {
	ticker := time.NewTicker(scm.watchInterval)
	defer ticker.Stop()
	
	for range ticker.C {
		scm.LoadConfigurations()
	}
}

func (scm *SIEMConfigManager) loadBuiltinTemplates() {
	// Load built-in templates for common SIEM platforms
	templates := []*SIEMTemplate{
		scm.createSplunkTemplate(),
		scm.createQRadarTemplate(),
		scm.createSentinelTemplate(),
		scm.createElasticTemplate(),
		scm.createGenericTemplate(),
	}
	
	for _, template := range templates {
		scm.templates[template.ID] = template
	}
}

// Individual template creation methods will be implemented in the next file...
// This file is getting quite long, so I'll continue with the template implementations