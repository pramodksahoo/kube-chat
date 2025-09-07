package config

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ConfigurationValidator provides comprehensive validation for SIEM configurations
type ConfigurationValidator struct {
	validPlatforms map[SIEMPlatform]bool
	validFormats   map[string]bool
	validAuthTypes map[AuthType]bool
}

// EnvironmentConfigLoader loads SIEM configuration from environment variables
type EnvironmentConfigLoader struct {
	prefix string
}

// ValidationContext provides context for configuration validation
type ValidationContext struct {
	ConfigID    string
	Platform    SIEMPlatform
	Environment string // development, staging, production
	Strict      bool   // Whether to enforce strict validation
}

// NewConfigurationValidator creates a new configuration validator
func NewConfigurationValidator() *ConfigurationValidator {
	return &ConfigurationValidator{
		validPlatforms: map[SIEMPlatform]bool{
			SIEMPlatformSplunk:    true,
			SIEMPlatformQRadar:    true,
			SIEMPlatformSentinel:  true,
			SIEMPlatformElastic:   true,
			SIEMPlatformSumoLogic: true,
			SIEMPlatformLogRhythm: true,
			SIEMPlatformArcSight:  true,
			SIEMPlatformGeneric:   true,
		},
		validFormats: map[string]bool{
			"JSON": true,
			"CEF":  true,
			"LEEF": true,
		},
		validAuthTypes: map[AuthType]bool{
			AuthTypeNone:   true,
			AuthTypeBasic:  true,
			AuthTypeBearer: true,
			AuthTypeAPIKey: true,
			AuthTypeOAuth2: true,
			AuthTypeHMAC:   true,
		},
	}
}

// ValidateConfiguration performs comprehensive validation of a SIEM configuration
func (cv *ConfigurationValidator) ValidateConfiguration(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Basic field validation
	issues = append(issues, cv.validateBasicFields(config, context)...)
	
	// Platform-specific validation
	issues = append(issues, cv.validatePlatformSpecific(config, context)...)
	
	// Connection configuration validation
	issues = append(issues, cv.validateConnectionConfig(config, context)...)
	
	// Authentication validation
	issues = append(issues, cv.validateAuthentication(config, context)...)
	
	// Security validation
	issues = append(issues, cv.validateSecurity(config, context)...)
	
	// Performance validation
	issues = append(issues, cv.validatePerformance(config, context)...)
	
	// Environment-specific validation
	issues = append(issues, cv.validateEnvironmentSpecific(config, context)...)
	
	return issues
}

// validateBasicFields validates required and basic fields
func (cv *ConfigurationValidator) validateBasicFields(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Required fields
	if config.ID == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "id",
			Severity: "error",
			Message:  "Configuration ID is required",
		})
	} else if !cv.isValidID(config.ID) {
		issues = append(issues, ConfigurationIssue{
			Field:    "id",
			Severity: "error",
			Message:  "Configuration ID must contain only alphanumeric characters, hyphens, and underscores",
		})
	}
	
	if config.Name == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "name",
			Severity: "error",
			Message:  "Configuration name is required",
		})
	}
	
	// Platform validation
	if !cv.validPlatforms[config.Platform] {
		issues = append(issues, ConfigurationIssue{
			Field:    "platform",
			Severity: "error",
			Message:  fmt.Sprintf("Unsupported SIEM platform: %s", config.Platform),
		})
	}
	
	// Format validation
	if !cv.validFormats[config.Format] {
		issues = append(issues, ConfigurationIssue{
			Field:    "format",
			Severity: "error",
			Message:  fmt.Sprintf("Unsupported format: %s. Valid formats: JSON, CEF, LEEF", config.Format),
		})
	}
	
	return issues
}

// validatePlatformSpecific performs platform-specific validation
func (cv *ConfigurationValidator) validatePlatformSpecific(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	switch config.Platform {
	case SIEMPlatformSplunk:
		issues = append(issues, cv.validateSplunkConfig(config, context)...)
	case SIEMPlatformQRadar:
		issues = append(issues, cv.validateQRadarConfig(config, context)...)
	case SIEMPlatformSentinel:
		issues = append(issues, cv.validateSentinelConfig(config, context)...)
	case SIEMPlatformElastic:
		issues = append(issues, cv.validateElasticConfig(config, context)...)
	}
	
	return issues
}

// validateSplunkConfig validates Splunk-specific configuration
func (cv *ConfigurationValidator) validateSplunkConfig(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	if config.WebhookConfig != nil {
		// Validate HEC endpoint URL
		if !strings.Contains(config.WebhookConfig.URL, "/services/collector") {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.url",
				Severity:   "warning",
				Message:    "URL should contain '/services/collector' for Splunk HEC",
				Suggestion: "Use the full HEC endpoint URL (e.g., https://splunk.company.com:8088/services/collector)",
			})
		}
		
		// Check for common port 8088
		if !strings.Contains(config.WebhookConfig.URL, ":8088") {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.url",
				Severity:   "info",
				Message:    "Splunk HEC typically uses port 8088",
				Suggestion: "Verify that the port in the URL matches your Splunk HEC configuration",
			})
		}
	}
	
	// Validate authentication token format for HEC
	if config.Authentication.Type == AuthTypeBearer {
		token := config.Authentication.Token
		if token != "" && !cv.isValidUUID(token) {
			issues = append(issues, ConfigurationIssue{
				Field:      "authentication.token",
				Severity:   "warning",
				Message:    "Splunk HEC tokens are typically in UUID format",
				Suggestion: "Verify that the token is a valid HEC token from Splunk",
			})
		}
	}
	
	// Recommend JSON format for Splunk
	if config.Format != "JSON" {
		issues = append(issues, ConfigurationIssue{
			Field:      "format",
			Severity:   "info",
			Message:    "JSON format is recommended for Splunk integration",
			Suggestion: "Consider using JSON format for better Splunk compatibility",
		})
	}
	
	return issues
}

// validateQRadarConfig validates QRadar-specific configuration
func (cv *ConfigurationValidator) validateQRadarConfig(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Recommend LEEF format for QRadar
	if config.Format != "LEEF" {
		issues = append(issues, ConfigurationIssue{
			Field:      "format",
			Severity:   "warning",
			Message:    "LEEF format is recommended for QRadar integration",
			Suggestion: "QRadar has native support for LEEF format parsing",
		})
	}
	
	// Check authentication
	if config.Authentication.Type == AuthTypeNone {
		issues = append(issues, ConfigurationIssue{
			Field:      "authentication.type",
			Severity:   "warning",
			Message:    "QRadar typically requires authentication",
			Suggestion: "Configure basic authentication or API key authentication",
		})
	}
	
	return issues
}

// validateSentinelConfig validates Microsoft Sentinel-specific configuration
func (cv *ConfigurationValidator) validateSentinelConfig(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	if config.WebhookConfig != nil {
		// Validate Azure Log Analytics URL format
		if !strings.Contains(config.WebhookConfig.URL, ".ods.opinsights.azure.com") {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.url",
				Severity:   "error",
				Message:    "URL should be Azure Log Analytics Data Collector API endpoint",
				Suggestion: "Use format: https://{workspace-id}.ods.opinsights.azure.com/api/logs",
			})
		}
		
		// Check for required API version
		if !strings.Contains(config.WebhookConfig.URL, "api-version=") {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.url",
				Severity:   "warning",
				Message:    "API version parameter is recommended for Azure Log Analytics",
				Suggestion: "Add ?api-version=2016-04-01 to the URL",
			})
		}
	}
	
	// Validate custom headers for Log-Type
	if config.WebhookConfig != nil && config.WebhookConfig.Headers != nil {
		if _, hasLogType := config.WebhookConfig.Headers["Log-Type"]; !hasLogType {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.headers",
				Severity:   "warning",
				Message:    "Log-Type header is recommended for Sentinel",
				Suggestion: "Add Log-Type header to specify custom log table name",
			})
		}
	}
	
	// Recommend JSON format
	if config.Format != "JSON" {
		issues = append(issues, ConfigurationIssue{
			Field:      "format",
			Severity:   "info",
			Message:    "JSON format is recommended for Microsoft Sentinel",
			Suggestion: "Sentinel works best with JSON format and ECS-compatible field names",
		})
	}
	
	return issues
}

// validateElasticConfig validates Elastic Stack-specific configuration
func (cv *ConfigurationValidator) validateElasticConfig(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	if config.WebhookConfig != nil {
		// Validate Elasticsearch URL format
		if !strings.Contains(config.WebhookConfig.URL, "/_doc") && !strings.Contains(config.WebhookConfig.URL, "/_bulk") {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.url",
				Severity:   "warning",
				Message:    "URL should target Elasticsearch document or bulk API",
				Suggestion: "Use format: https://elasticsearch.company.com:9200/index-name/_doc",
			})
		}
	}
	
	// Recommend JSON format
	if config.Format != "JSON" {
		issues = append(issues, ConfigurationIssue{
			Field:      "format",
			Severity:   "info",
			Message:    "JSON format is recommended for Elastic Stack",
			Suggestion: "Elasticsearch works best with JSON format and ECS field mappings",
		})
	}
	
	return issues
}

// validateConnectionConfig validates connection configuration
func (cv *ConfigurationValidator) validateConnectionConfig(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Must have either webhook or NATS config
	if config.WebhookConfig == nil && config.NATSConfig == nil {
		issues = append(issues, ConfigurationIssue{
			Field:    "connection",
			Severity: "error",
			Message:  "Either webhook_config or nats_config must be specified",
		})
		return issues
	}
	
	// Validate webhook configuration
	if config.WebhookConfig != nil {
		issues = append(issues, cv.validateWebhookConfig(config.WebhookConfig, context)...)
	}
	
	// Validate NATS configuration
	if config.NATSConfig != nil {
		issues = append(issues, cv.validateNATSConfig(config.NATSConfig, context)...)
	}
	
	return issues
}

// validateWebhookConfig validates webhook-specific configuration
func (cv *ConfigurationValidator) validateWebhookConfig(webhookConfig *WebhookSIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// URL validation
	if webhookConfig.URL == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "webhook_config.url",
			Severity: "error",
			Message:  "Webhook URL is required",
		})
	} else {
		if _, err := url.Parse(webhookConfig.URL); err != nil {
			issues = append(issues, ConfigurationIssue{
				Field:    "webhook_config.url",
				Severity: "error",
				Message:  fmt.Sprintf("Invalid URL format: %v", err),
			})
		} else {
			// Security check for HTTPS in production
			if context.Environment == "production" && !strings.HasPrefix(webhookConfig.URL, "https://") {
				issues = append(issues, ConfigurationIssue{
					Field:      "webhook_config.url",
					Severity:   "warning",
					Message:    "HTTPS is recommended for production environments",
					Suggestion: "Use HTTPS URLs to ensure data security in transit",
				})
			}
		}
	}
	
	// Method validation
	validMethods := []string{"POST", "PUT", "PATCH"}
	methodValid := false
	for _, method := range validMethods {
		if webhookConfig.Method == method {
			methodValid = true
			break
		}
	}
	if !methodValid {
		issues = append(issues, ConfigurationIssue{
			Field:    "webhook_config.method",
			Severity: "warning",
			Message:  "Unusual HTTP method for webhook",
			Suggestion: "POST is the most common method for webhook integrations",
		})
	}
	
	// Timeout validation
	if webhookConfig.Timeout < time.Second {
		issues = append(issues, ConfigurationIssue{
			Field:    "webhook_config.timeout",
			Severity: "warning",
			Message:  "Very short timeout may cause delivery failures",
			Suggestion: "Consider using at least 5 seconds timeout",
		})
	} else if webhookConfig.Timeout > time.Minute*5 {
		issues = append(issues, ConfigurationIssue{
			Field:    "webhook_config.timeout",
			Severity: "warning",
			Message:  "Very long timeout may impact performance",
			Suggestion: "Consider using timeout of 30-60 seconds maximum",
		})
	}
	
	return issues
}

// validateNATSConfig validates NATS-specific configuration
func (cv *ConfigurationValidator) validateNATSConfig(natsConfig *NATSSIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// URLs validation
	if len(natsConfig.URLs) == 0 {
		issues = append(issues, ConfigurationIssue{
			Field:    "nats_config.urls",
			Severity: "error",
			Message:  "At least one NATS URL is required",
		})
	}
	
	for i, natsURL := range natsConfig.URLs {
		if _, err := url.Parse(natsURL); err != nil {
			issues = append(issues, ConfigurationIssue{
				Field:    fmt.Sprintf("nats_config.urls[%d]", i),
				Severity: "error",
				Message:  fmt.Sprintf("Invalid NATS URL format: %v", err),
			})
		}
	}
	
	// Subject validation
	if natsConfig.Subject == "" {
		issues = append(issues, ConfigurationIssue{
			Field:    "nats_config.subject",
			Severity: "error",
			Message:  "NATS subject is required",
		})
	} else if !cv.isValidNATSSubject(natsConfig.Subject) {
		issues = append(issues, ConfigurationIssue{
			Field:    "nats_config.subject",
			Severity: "warning",
			Message:  "NATS subject contains unusual characters",
			Suggestion: "Use alphanumeric characters, dots, and hyphens in NATS subjects",
		})
	}
	
	return issues
}

// validateAuthentication validates authentication configuration
func (cv *ConfigurationValidator) validateAuthentication(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	auth := config.Authentication
	
	// Validate authentication type
	if !cv.validAuthTypes[auth.Type] {
		issues = append(issues, ConfigurationIssue{
			Field:    "authentication.type",
			Severity: "error",
			Message:  fmt.Sprintf("Invalid authentication type: %s", auth.Type),
		})
		return issues
	}
	
	// Type-specific validation
	switch auth.Type {
	case AuthTypeBasic:
		if auth.Username == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "authentication.username",
				Severity: "error",
				Message:  "Username is required for basic authentication",
			})
		}
		if auth.Password == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "authentication.password",
				Severity: "error",
				Message:  "Password is required for basic authentication",
			})
		}
		
	case AuthTypeBearer, AuthTypeAPIKey:
		if auth.Token == "" && auth.APIKey == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "authentication",
				Severity: "error",
				Message:  "Token or API key is required for token-based authentication",
			})
		}
		
	case AuthTypeOAuth2:
		if auth.OAuth2Config == nil {
			issues = append(issues, ConfigurationIssue{
				Field:    "authentication.oauth2_config",
				Severity: "error",
				Message:  "OAuth2 configuration is required for OAuth2 authentication",
			})
		} else {
			if auth.OAuth2Config.TokenURL == "" {
				issues = append(issues, ConfigurationIssue{
					Field:    "authentication.oauth2_config.token_url",
					Severity: "error",
					Message:  "Token URL is required for OAuth2",
				})
			}
			if auth.OAuth2Config.ClientID == "" {
				issues = append(issues, ConfigurationIssue{
					Field:    "authentication.oauth2_config.client_id",
					Severity: "error",
					Message:  "Client ID is required for OAuth2",
				})
			}
			if auth.OAuth2Config.ClientSecret == "" {
				issues = append(issues, ConfigurationIssue{
					Field:    "authentication.oauth2_config.client_secret",
					Severity: "error",
					Message:  "Client secret is required for OAuth2",
				})
			}
		}
		
	case AuthTypeHMAC:
		if auth.HMACSecret == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "authentication.hmac_secret",
				Severity: "error",
				Message:  "HMAC secret is required for HMAC authentication",
			})
		}
	}
	
	return issues
}

// validateSecurity validates security-related configuration
func (cv *ConfigurationValidator) validateSecurity(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Production environment security checks
	if context.Environment == "production" {
		if config.Authentication.Type == AuthTypeNone {
			issues = append(issues, ConfigurationIssue{
				Field:      "authentication.type",
				Severity:   "warning",
				Message:    "No authentication configured for production environment",
				Suggestion: "Configure appropriate authentication for security",
			})
		}
		
		if config.WebhookConfig != nil && !config.WebhookConfig.VerifySSL {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.verify_ssl",
				Severity:   "warning",
				Message:    "SSL verification is disabled in production",
				Suggestion: "Enable SSL verification for production security",
			})
		}
	}
	
	// TLS configuration validation
	if config.TLSConfig.Enabled {
		if config.TLSConfig.CertFile == "" || config.TLSConfig.KeyFile == "" {
			issues = append(issues, ConfigurationIssue{
				Field:    "tls_config",
				Severity: "error",
				Message:  "Certificate and key files are required when TLS is enabled",
			})
		}
	}
	
	return issues
}

// validatePerformance validates performance-related configuration
func (cv *ConfigurationValidator) validatePerformance(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	// Retry configuration validation
	retryConfig := config.RetryConfig
	if retryConfig.MaxAttempts > 10 {
		issues = append(issues, ConfigurationIssue{
			Field:      "retry_config.max_attempts",
			Severity:   "warning",
			Message:    "High number of retry attempts may impact performance",
			Suggestion: "Consider using 3-5 retry attempts maximum",
		})
	}
	
	if retryConfig.MaxDelay > time.Minute*10 {
		issues = append(issues, ConfigurationIssue{
			Field:      "retry_config.max_delay",
			Severity:   "warning",
			Message:    "Very long retry delay may cause event buildup",
			Suggestion: "Consider using maximum delay of 1-2 minutes",
		})
	}
	
	// Buffer configuration validation
	bufferConfig := config.BufferConfig
	if bufferConfig.MaxBufferSize > 100000 {
		issues = append(issues, ConfigurationIssue{
			Field:      "buffer_config.max_buffer_size",
			Severity:   "warning",
			Message:    "Large buffer size may consume significant memory",
			Suggestion: "Consider using smaller buffer size with faster retry intervals",
		})
	}
	
	return issues
}

// validateEnvironmentSpecific performs environment-specific validation
func (cv *ConfigurationValidator) validateEnvironmentSpecific(config *SIEMConfig, context ValidationContext) []ConfigurationIssue {
	var issues []ConfigurationIssue
	
	switch context.Environment {
	case "development":
		// More lenient validation for development
		if config.Authentication.Type == AuthTypeNone {
			issues = append(issues, ConfigurationIssue{
				Field:    "authentication.type",
				Severity: "info",
				Message:  "No authentication configured (acceptable for development)",
			})
		}
		
	case "staging":
		// Staging should be similar to production but with warnings
		if config.WebhookConfig != nil && !strings.HasPrefix(config.WebhookConfig.URL, "https://") {
			issues = append(issues, ConfigurationIssue{
				Field:      "webhook_config.url",
				Severity:   "info",
				Message:    "Consider using HTTPS for staging environment",
				Suggestion: "Test with HTTPS to match production configuration",
			})
		}
		
	case "production":
		// Strict validation for production
		if context.Strict {
			// Additional strict checks for production
			if config.EventFilters.SampleRate < 1.0 {
				issues = append(issues, ConfigurationIssue{
					Field:      "event_filters.sample_rate",
					Severity:   "warning",
					Message:    "Event sampling is enabled, some events will be lost",
					Suggestion: "Verify that sampling is intentional for compliance requirements",
				})
			}
		}
	}
	
	return issues
}

// Helper functions

func (cv *ConfigurationValidator) isValidID(id string) bool {
	pattern := regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	return pattern.MatchString(id)
}

func (cv *ConfigurationValidator) isValidUUID(s string) bool {
	pattern := regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	return pattern.MatchString(s)
}

func (cv *ConfigurationValidator) isValidNATSSubject(subject string) bool {
	// NATS subjects can contain alphanumeric chars, dots, hyphens, and wildcards
	pattern := regexp.MustCompile(`^[a-zA-Z0-9\.\-\*>]+$`)
	return pattern.MatchString(subject)
}

// Environment Configuration Loader

// NewEnvironmentConfigLoader creates a new environment config loader
func NewEnvironmentConfigLoader(prefix string) *EnvironmentConfigLoader {
	if prefix == "" {
		prefix = "KUBECHAT_SIEM"
	}
	return &EnvironmentConfigLoader{prefix: prefix}
}

// LoadFromEnvironment loads SIEM configuration from environment variables
func (ecl *EnvironmentConfigLoader) LoadFromEnvironment(configID string) (*SIEMConfig, error) {
	config := &SIEMConfig{
		ID:        configID,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
		Version:   1,
		Metadata:  make(map[string]interface{}),
	}
	
	// Load basic configuration
	config.Name = ecl.getEnvWithDefault(fmt.Sprintf("%s_%s_NAME", ecl.prefix, strings.ToUpper(configID)), configID)
	config.Platform = SIEMPlatform(ecl.getEnvWithDefault(fmt.Sprintf("%s_%s_PLATFORM", ecl.prefix, strings.ToUpper(configID)), "generic"))
	config.Format = ecl.getEnvWithDefault(fmt.Sprintf("%s_%s_FORMAT", ecl.prefix, strings.ToUpper(configID)), "JSON")
	config.Enabled = ecl.getEnvBool(fmt.Sprintf("%s_%s_ENABLED", ecl.prefix, strings.ToUpper(configID)), true)
	
	// Load webhook configuration
	if webhookURL := os.Getenv(fmt.Sprintf("%s_%s_WEBHOOK_URL", ecl.prefix, strings.ToUpper(configID))); webhookURL != "" {
		config.WebhookConfig = &WebhookSIEMConfig{
			URL:       webhookURL,
			Method:    ecl.getEnvWithDefault(fmt.Sprintf("%s_%s_WEBHOOK_METHOD", ecl.prefix, strings.ToUpper(configID)), "POST"),
			Timeout:   ecl.getEnvDuration(fmt.Sprintf("%s_%s_WEBHOOK_TIMEOUT", ecl.prefix, strings.ToUpper(configID)), 30*time.Second),
			VerifySSL: ecl.getEnvBool(fmt.Sprintf("%s_%s_WEBHOOK_VERIFY_SSL", ecl.prefix, strings.ToUpper(configID)), true),
		}
		
		// Load webhook headers
		config.WebhookConfig.Headers = make(map[string]string)
		if contentType := os.Getenv(fmt.Sprintf("%s_%s_WEBHOOK_CONTENT_TYPE", ecl.prefix, strings.ToUpper(configID))); contentType != "" {
			config.WebhookConfig.Headers["Content-Type"] = contentType
		}
	}
	
	// Load authentication configuration
	authType := ecl.getEnvWithDefault(fmt.Sprintf("%s_%s_AUTH_TYPE", ecl.prefix, strings.ToUpper(configID)), "none")
	config.Authentication = AuthConfig{
		Type: AuthType(authType),
	}
	
	switch AuthType(authType) {
	case AuthTypeBasic:
		config.Authentication.Username = os.Getenv(fmt.Sprintf("%s_%s_AUTH_USERNAME", ecl.prefix, strings.ToUpper(configID)))
		config.Authentication.Password = os.Getenv(fmt.Sprintf("%s_%s_AUTH_PASSWORD", ecl.prefix, strings.ToUpper(configID)))
	case AuthTypeBearer:
		config.Authentication.Token = os.Getenv(fmt.Sprintf("%s_%s_AUTH_TOKEN", ecl.prefix, strings.ToUpper(configID)))
	case AuthTypeAPIKey:
		config.Authentication.APIKey = os.Getenv(fmt.Sprintf("%s_%s_AUTH_API_KEY", ecl.prefix, strings.ToUpper(configID)))
		config.Authentication.APIKeyHeader = ecl.getEnvWithDefault(fmt.Sprintf("%s_%s_AUTH_API_KEY_HEADER", ecl.prefix, strings.ToUpper(configID)), "X-API-Key")
	}
	
	return config, nil
}

// Helper methods for environment loading
func (ecl *EnvironmentConfigLoader) getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func (ecl *EnvironmentConfigLoader) getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if parsed, err := strconv.ParseBool(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}

func (ecl *EnvironmentConfigLoader) getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if parsed, err := time.ParseDuration(value); err == nil {
			return parsed
		}
	}
	return defaultValue
}