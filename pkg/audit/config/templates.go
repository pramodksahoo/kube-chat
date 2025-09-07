package config

import (
	"time"

	"github.com/pramodksahoo/kube-chat/pkg/audit/formats"
	"github.com/pramodksahoo/kube-chat/pkg/audit/streaming"
	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// createSplunkTemplate creates the built-in Splunk template
func (scm *SIEMConfigManager) createSplunkTemplate() *SIEMTemplate {
	return &SIEMTemplate{
		ID:                "splunk",
		Name:              "Splunk Enterprise/Cloud",
		Platform:          SIEMPlatformSplunk,
		Description:       "Integration template for Splunk Enterprise and Splunk Cloud with HTTP Event Collector (HEC)",
		Version:           "1.0.0",
		RecommendedFormat: "JSON",
		DefaultConfig: SIEMConfig{
			Platform:      SIEMPlatformSplunk,
			Format:        "JSON",
			Enabled:       false,
			WebhookConfig: &WebhookSIEMConfig{
				Method:    "POST",
				Timeout:   30 * time.Second,
				VerifySSL: true,
			},
			Authentication: AuthConfig{
				Type:         AuthTypeBearer,
				APIKeyHeader: "Authorization",
			},
			EventFilters: streaming.WebhookFilterConfig{
				SampleRate: 1.0, // No sampling by default
			},
			RetryConfig: streaming.DefaultWebhookRetryConfig(),
		},
		FieldMappings: formats.GetSplunkMappings(),
		ValidationRules: []ValidationRule{
			{
				Field:       "webhook_config.url",
				Required:    true,
				Type:        "url",
				Pattern:     `^https?://.*:8088/services/collector`,
				Description: "Splunk HEC endpoint URL (typically ends with :8088/services/collector)",
			},
			{
				Field:       "authentication.token",
				Required:    true,
				Type:        "string",
				Pattern:     `^[0-9a-fA-F-]{36}$`,
				Description: "Splunk HEC token (36-character UUID format)",
			},
		},
		Documentation: SIEMTemplateDocumentation{
			SetupInstructions: []string{
				"1. Configure HTTP Event Collector (HEC) in Splunk",
				"2. Create a new HEC token with appropriate permissions",
				"3. Configure the HEC endpoint URL (e.g., https://splunk.company.com:8088/services/collector)",
				"4. Set the HEC token in the authentication configuration",
				"5. Configure index and sourcetype settings in custom headers",
				"6. Test the connection to verify data ingestion",
			},
			ConfigurationTips: []string{
				"Use JSON format for best Splunk compatibility",
				"Configure appropriate index and sourcetype in custom headers",
				"Enable SSL verification in production environments",
				"Set up index-time field extraction rules in Splunk for better performance",
				"Consider using index clustering for high availability",
			},
			TroubleshootingTips: []string{
				"Verify HEC is enabled and accessible from KubeChat",
				"Check HEC token permissions and expiration",
				"Verify SSL certificate if using HTTPS",
				"Check Splunk indexer queues if events are not appearing",
				"Review splunkd.log for HEC-related errors",
			},
			References: []DocumentReference{
				{
					Title: "Splunk HTTP Event Collector Documentation",
					URL:   "https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector",
					Type:  "official",
				},
				{
					Title: "HEC Configuration Best Practices",
					URL:   "https://docs.splunk.com/Documentation/Splunk/latest/Data/HECExamples",
					Type:  "guide",
				},
			},
		},
		Examples: []SIEMConfigExample{
			{
				Name:        "Splunk Enterprise HEC",
				Description: "Basic configuration for Splunk Enterprise with HEC",
				UseCase:     "On-premises Splunk Enterprise deployment",
				Config: SIEMConfig{
					ID:       "splunk-enterprise",
					Name:     "Splunk Enterprise",
					Platform: SIEMPlatformSplunk,
					Format:   "JSON",
					Enabled:  true,
					WebhookConfig: &WebhookSIEMConfig{
						URL:       "https://splunk.company.com:8088/services/collector/event",
						Method:    "POST",
						Headers:   map[string]string{
							"Content-Type": "application/json",
						},
						Timeout:   30 * time.Second,
						VerifySSL: true,
					},
					Authentication: AuthConfig{
						Type:         AuthTypeBearer,
						Token:        "your-hec-token-here",
						APIKeyHeader: "Authorization",
					},
					CustomHeaders: map[string]string{
						"X-Splunk-Request-Channel": "kubechat-audit",
					},
				},
			},
			{
				Name:        "Splunk Cloud",
				Description: "Configuration for Splunk Cloud with custom index",
				UseCase:     "Splunk Cloud deployment with dedicated audit index",
				Config: SIEMConfig{
					ID:       "splunk-cloud",
					Name:     "Splunk Cloud",
					Platform: SIEMPlatformSplunk,
					Format:   "JSON",
					Enabled:  true,
					WebhookConfig: &WebhookSIEMConfig{
						URL:       "https://http-inputs-company.splunkcloud.com:443/services/collector",
						Method:    "POST",
						Timeout:   30 * time.Second,
						VerifySSL: true,
					},
					Authentication: AuthConfig{
						Type:  AuthTypeBearer,
						Token: "your-cloud-hec-token",
					},
					CustomHeaders: map[string]string{
						"X-Splunk-Request-Channel": "kubechat-audit-cloud",
					},
				},
			},
		},
	}
}

// createQRadarTemplate creates the built-in IBM QRadar template
func (scm *SIEMConfigManager) createQRadarTemplate() *SIEMTemplate {
	return &SIEMTemplate{
		ID:                "qradar",
		Name:              "IBM QRadar",
		Platform:          SIEMPlatformQRadar,
		Description:       "Integration template for IBM QRadar SIEM using LEEF format and syslog/HTTP forwarder",
		Version:           "1.0.0",
		RecommendedFormat: "LEEF",
		DefaultConfig: SIEMConfig{
			Platform: SIEMPlatformQRadar,
			Format:   "LEEF",
			Enabled:  false,
			WebhookConfig: &WebhookSIEMConfig{
				Method:    "POST",
				Timeout:   30 * time.Second,
				VerifySSL: true,
			},
			Authentication: AuthConfig{
				Type: AuthTypeBasic,
			},
			EventFilters: streaming.WebhookFilterConfig{
				SampleRate: 1.0,
			},
			RetryConfig: streaming.DefaultWebhookRetryConfig(),
		},
		FieldMappings: formats.GetQRadarMappings(),
		ValidationRules: []ValidationRule{
			{
				Field:       "webhook_config.url",
				Required:    true,
				Type:        "url",
				Description: "QRadar log receiver endpoint URL",
			},
			{
				Field:       "authentication.username",
				Required:    true,
				Type:        "string",
				Description: "QRadar service account username",
			},
			{
				Field:       "authentication.password",
				Required:    true,
				Type:        "string",
				Description: "QRadar service account password",
			},
		},
		Documentation: SIEMTemplateDocumentation{
			SetupInstructions: []string{
				"1. Configure QRadar to receive external log sources",
				"2. Create a dedicated log source identifier for KubeChat",
				"3. Set up HTTP/HTTPS log receiver or syslog receiver",
				"4. Configure authentication credentials for the log receiver",
				"5. Test log ingestion with sample LEEF events",
				"6. Configure QRadar rules for KubeChat audit events",
			},
			ConfigurationTips: []string{
				"Use LEEF 2.0 format for best QRadar compatibility",
				"Configure appropriate QRadar log source type",
				"Set up custom properties for Kubernetes-specific fields",
				"Use QRadar's built-in parsing rules for LEEF format",
				"Configure proper timezone handling",
			},
			TroubleshootingTips: []string{
				"Verify QRadar log receiver is running and accessible",
				"Check QRadar System Notifications for ingestion errors",
				"Verify LEEF format compliance using QRadar's format validator",
				"Check QRadar log source configuration",
				"Review QRadar error logs for parsing issues",
			},
			References: []DocumentReference{
				{
					Title: "QRadar Log Sources Configuration",
					URL:   "https://www.ibm.com/docs/en/qradar-common",
					Type:  "official",
				},
				{
					Title: "LEEF Format Reference",
					URL:   "https://www.ibm.com/docs/en/qradar-common?topic=format-log-event-extended-leef",
					Type:  "official",
				},
			},
		},
		Examples: []SIEMConfigExample{
			{
				Name:        "QRadar HTTP Receiver",
				Description: "QRadar configuration using HTTP log receiver",
				UseCase:     "Direct HTTP integration with QRadar log receiver",
				Config: SIEMConfig{
					ID:       "qradar-http",
					Name:     "QRadar HTTP",
					Platform: SIEMPlatformQRadar,
					Format:   "LEEF",
					Enabled:  true,
					WebhookConfig: &WebhookSIEMConfig{
						URL:       "https://qradar.company.com:443/api/siem/external_log_ingestion",
						Method:    "POST",
						Headers:   map[string]string{
							"Content-Type": "text/plain",
							"X-Log-Source": "KubeChat-Audit",
						},
						Timeout:   30 * time.Second,
						VerifySSL: true,
					},
					Authentication: AuthConfig{
						Type:     AuthTypeBasic,
						Username: "qradar-service",
						Password: "your-service-password",
					},
				},
			},
		},
	}
}

// createSentinelTemplate creates the built-in Microsoft Sentinel template
func (scm *SIEMConfigManager) createSentinelTemplate() *SIEMTemplate {
	return &SIEMTemplate{
		ID:                "sentinel",
		Name:              "Microsoft Sentinel",
		Platform:          SIEMPlatformSentinel,
		Description:       "Integration template for Microsoft Sentinel using Log Analytics Workspace Data Collector API",
		Version:           "1.0.0",
		RecommendedFormat: "JSON",
		DefaultConfig: SIEMConfig{
			Platform: SIEMPlatformSentinel,
			Format:   "JSON",
			Enabled:  false,
			WebhookConfig: &WebhookSIEMConfig{
				Method:    "POST",
				Timeout:   30 * time.Second,
				VerifySSL: true,
			},
			Authentication: AuthConfig{
				Type: AuthTypeAPIKey,
			},
			EventFilters: streaming.WebhookFilterConfig{
				SampleRate: 1.0,
			},
			RetryConfig: streaming.DefaultWebhookRetryConfig(),
		},
		FieldMappings: formats.GetSentinelMappings(),
		ValidationRules: []ValidationRule{
			{
				Field:       "webhook_config.url",
				Required:    true,
				Type:        "url",
				Pattern:     `^https://.*\.ods\.opinsights\.azure\.com/api/logs`,
				Description: "Azure Log Analytics Data Collector API endpoint",
			},
			{
				Field:       "authentication.api_key",
				Required:    true,
				Type:        "string",
				Description: "Log Analytics Workspace shared key",
			},
		},
		Documentation: SIEMTemplateDocumentation{
			SetupInstructions: []string{
				"1. Create or use existing Log Analytics Workspace in Azure",
				"2. Obtain the Workspace ID and Primary/Secondary Key",
				"3. Configure Data Collector API endpoint URL",
				"4. Set up custom log table for KubeChat audit events",
				"5. Create Sentinel Analytics rules for audit events",
				"6. Configure appropriate retention and data export policies",
			},
			ConfigurationTips: []string{
				"Use JSON format with TimeGenerated field for best Sentinel compatibility",
				"Configure custom log table name (e.g., KubeChatAudit_CL)",
				"Set up appropriate data retention policies",
				"Create custom workbooks for audit event visualization",
				"Use Sentinel's built-in KQL queries for analysis",
			},
			TroubleshootingTips: []string{
				"Verify Log Analytics Workspace is accessible",
				"Check workspace key validity and permissions",
				"Verify JSON format compliance with Sentinel requirements",
				"Check Azure resource limits and quotas",
				"Review Log Analytics ingestion logs for errors",
			},
			References: []DocumentReference{
				{
					Title: "Azure Log Analytics Data Collector API",
					URL:   "https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api",
					Type:  "official",
				},
				{
					Title: "Microsoft Sentinel Custom Logs",
					URL:   "https://docs.microsoft.com/en-us/azure/sentinel/connect-custom-logs",
					Type:  "official",
				},
			},
		},
		Examples: []SIEMConfigExample{
			{
				Name:        "Sentinel Data Collector API",
				Description: "Direct integration with Azure Log Analytics using Data Collector API",
				UseCase:     "Azure cloud-native deployment with Sentinel",
				Config: SIEMConfig{
					ID:       "sentinel-datacollector",
					Name:     "Microsoft Sentinel",
					Platform: SIEMPlatformSentinel,
					Format:   "JSON",
					Enabled:  true,
					WebhookConfig: &WebhookSIEMConfig{
						URL:    "https://your-workspace-id.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
						Method: "POST",
						Headers: map[string]string{
							"Content-Type": "application/json",
							"Log-Type":     "KubeChatAudit",
						},
						Timeout:   30 * time.Second,
						VerifySSL: true,
					},
					Authentication: AuthConfig{
						Type:         AuthTypeAPIKey,
						APIKey:       "your-workspace-shared-key",
						APIKeyHeader: "Authorization",
					},
				},
			},
		},
	}
}

// createElasticTemplate creates the built-in Elastic Stack template
func (scm *SIEMConfigManager) createElasticTemplate() *SIEMTemplate {
	return &SIEMTemplate{
		ID:                "elastic",
		Name:              "Elastic Stack (ELK)",
		Platform:          SIEMPlatformElastic,
		Description:       "Integration template for Elastic Stack using Elasticsearch HTTP API with ECS format",
		Version:           "1.0.0",
		RecommendedFormat: "JSON",
		DefaultConfig: SIEMConfig{
			Platform: SIEMPlatformElastic,
			Format:   "JSON",
			Enabled:  false,
			WebhookConfig: &WebhookSIEMConfig{
				Method:    "POST",
				Timeout:   30 * time.Second,
				VerifySSL: true,
			},
			Authentication: AuthConfig{
				Type: AuthTypeBasic,
			},
			EventFilters: streaming.WebhookFilterConfig{
				SampleRate: 1.0,
			},
			RetryConfig: streaming.DefaultWebhookRetryConfig(),
		},
		FieldMappings: formats.GetElasticMappings(),
		ValidationRules: []ValidationRule{
			{
				Field:       "webhook_config.url",
				Required:    true,
				Type:        "url",
				Pattern:     `^https?://.*:\d+/[^/]+/_doc`,
				Description: "Elasticsearch index endpoint URL",
			},
			{
				Field:       "authentication.username",
				Required:    false,
				Type:        "string",
				Description: "Elasticsearch username (if authentication is enabled)",
			},
		},
		Documentation: SIEMTemplateDocumentation{
			SetupInstructions: []string{
				"1. Set up Elasticsearch cluster with appropriate security",
				"2. Create dedicated index for KubeChat audit events",
				"3. Configure index template with ECS field mappings",
				"4. Set up Kibana for visualization and analysis",
				"5. Configure Elastic Security rules for audit events",
				"6. Set up appropriate index lifecycle policies",
			},
			ConfigurationTips: []string{
				"Use ECS-compliant field mappings for best compatibility",
				"Configure appropriate index naming strategy",
				"Set up index templates with proper field types",
				"Use Elasticsearch ingest pipelines for data processing",
				"Configure appropriate shard and replica settings",
			},
			TroubleshootingTips: []string{
				"Verify Elasticsearch cluster health and accessibility",
				"Check authentication credentials and permissions",
				"Verify index template and mapping compatibility",
				"Check Elasticsearch logs for ingestion errors",
				"Verify JSON format compliance with ECS schema",
			},
			References: []DocumentReference{
				{
					Title: "Elasticsearch Index API",
					URL:   "https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html",
					Type:  "official",
				},
				{
					Title: "Elastic Common Schema (ECS)",
					URL:   "https://www.elastic.co/guide/en/ecs/current/index.html",
					Type:  "official",
				},
			},
		},
		Examples: []SIEMConfigExample{
			{
				Name:        "Elasticsearch Direct Indexing",
				Description: "Direct indexing to Elasticsearch with ECS schema",
				UseCase:     "Self-hosted Elastic Stack deployment",
				Config: SIEMConfig{
					ID:       "elastic-direct",
					Name:     "Elastic Stack",
					Platform: SIEMPlatformElastic,
					Format:   "JSON",
					Enabled:  true,
					WebhookConfig: &WebhookSIEMConfig{
						URL:    "https://elasticsearch.company.com:9200/kubechat-audit/_doc",
						Method: "POST",
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Timeout:   30 * time.Second,
						VerifySSL: true,
					},
					Authentication: AuthConfig{
						Type:     AuthTypeBasic,
						Username: "elastic-user",
						Password: "your-elastic-password",
					},
				},
			},
		},
	}
}

// createGenericTemplate creates a generic template for custom SIEM integrations
func (scm *SIEMConfigManager) createGenericTemplate() *SIEMTemplate {
	return &SIEMTemplate{
		ID:                "generic",
		Name:              "Generic SIEM/Log System",
		Platform:          SIEMPlatformGeneric,
		Description:       "Generic template for custom SIEM systems or log aggregators with HTTP webhook support",
		Version:           "1.0.0",
		RecommendedFormat: "JSON",
		DefaultConfig: SIEMConfig{
			Platform: SIEMPlatformGeneric,
			Format:   "JSON",
			Enabled:  false,
			WebhookConfig: &WebhookSIEMConfig{
				Method:    "POST",
				Timeout:   30 * time.Second,
				VerifySSL: true,
			},
			Authentication: AuthConfig{
				Type: AuthTypeNone,
			},
			EventFilters: streaming.WebhookFilterConfig{
				SampleRate: 1.0,
			},
			RetryConfig: streaming.DefaultWebhookRetryConfig(),
		},
		FieldMappings: make(map[string]string), // No default mappings for generic
		ValidationRules: []ValidationRule{
			{
				Field:       "webhook_config.url",
				Required:    true,
				Type:        "url",
				Description: "HTTP endpoint URL for receiving audit events",
			},
		},
		Documentation: SIEMTemplateDocumentation{
			SetupInstructions: []string{
				"1. Configure your SIEM or log system to accept HTTP webhooks",
				"2. Set up the webhook endpoint URL and authentication",
				"3. Choose appropriate data format (JSON, CEF, or LEEF)",
				"4. Configure field mappings if needed for your system",
				"5. Test connectivity and data ingestion",
				"6. Set up parsing and analysis rules in your SIEM",
			},
			ConfigurationTips: []string{
				"Use JSON format for maximum flexibility",
				"Configure appropriate timeout and retry settings",
				"Set up proper authentication for security",
				"Consider using field mappings to match your schema",
				"Configure filtering to reduce data volume if needed",
			},
			TroubleshootingTips: []string{
				"Verify webhook endpoint is accessible and responsive",
				"Check authentication configuration",
				"Verify data format compatibility with your system",
				"Check network connectivity and firewall rules",
				"Review webhook logs for error messages",
			},
			References: []DocumentReference{
				{
					Title: "HTTP Webhook Best Practices",
					URL:   "https://webhook.site/webhook-best-practices",
					Type:  "guide",
				},
			},
		},
		Examples: []SIEMConfigExample{
			{
				Name:        "Generic HTTP Webhook",
				Description: "Basic HTTP webhook configuration for custom systems",
				UseCase:     "Custom log aggregation system with HTTP API",
				Config: SIEMConfig{
					ID:       "generic-webhook",
					Name:     "Custom SIEM",
					Platform: SIEMPlatformGeneric,
					Format:   "JSON",
					Enabled:  true,
					WebhookConfig: &WebhookSIEMConfig{
						URL:    "https://logs.company.com/api/webhooks/kubechat",
						Method: "POST",
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Timeout:   30 * time.Second,
						VerifySSL: true,
					},
					Authentication: AuthConfig{
						Type:         AuthTypeAPIKey,
						APIKey:       "your-api-key",
						APIKeyHeader: "X-API-Key",
					},
				},
			},
		},
	}
}

// GetPlatformSpecificEventFilters returns platform-specific event filters
func GetPlatformSpecificEventFilters(platform SIEMPlatform) streaming.WebhookFilterConfig {
	switch platform {
	case SIEMPlatformSplunk:
		// Splunk can handle all event types efficiently
		return streaming.WebhookFilterConfig{
			SampleRate: 1.0,
		}
		
	case SIEMPlatformQRadar:
		// QRadar benefits from filtering out low-value events
		return streaming.WebhookFilterConfig{
			EventTypes: []models.AuditEventType{
				models.AuditEventTypeAuthentication,
				models.AuditEventTypeLogin,
				models.AuditEventTypeLogout,
				models.AuditEventTypeCommandExecute,
				models.AuditEventTypeRBACDenied,
				models.AuditEventTypeSystemError,
			},
			Severities: []models.AuditSeverity{
				models.AuditSeverityWarning,
				models.AuditSeverityError,
				models.AuditSeverityCritical,
			},
			SampleRate: 1.0,
		}
		
	case SIEMPlatformSentinel:
		// Sentinel can handle high volumes but focus on security events
		return streaming.WebhookFilterConfig{
			EventTypes: []models.AuditEventType{
				models.AuditEventTypeAuthentication,
				models.AuditEventTypeLogin,
				models.AuditEventTypeLogout,
				models.AuditEventTypeCommandExecute,
				models.AuditEventTypeRBACCheck,
				models.AuditEventTypeRBACDenied,
			},
			SampleRate: 1.0,
		}
		
	case SIEMPlatformElastic:
		// Elastic Stack can handle all events with good performance
		return streaming.WebhookFilterConfig{
			SampleRate: 1.0,
		}
		
	default:
		// Generic configuration - minimal filtering
		return streaming.WebhookFilterConfig{
			SampleRate: 1.0,
		}
	}
}

// GetPlatformSpecificRetryConfig returns platform-specific retry configuration
func GetPlatformSpecificRetryConfig(platform SIEMPlatform) streaming.WebhookRetryConfig {
	baseConfig := streaming.DefaultWebhookRetryConfig()
	
	switch platform {
	case SIEMPlatformSplunk:
		// Splunk HEC is generally reliable, moderate retries
		baseConfig.MaxAttempts = 3
		baseConfig.InitialDelay = time.Second * 2
		
	case SIEMPlatformQRadar:
		// QRadar may be less tolerant of high volume, more conservative retries
		baseConfig.MaxAttempts = 5
		baseConfig.InitialDelay = time.Second * 5
		baseConfig.MaxDelay = time.Minute * 2
		
	case SIEMPlatformSentinel:
		// Azure services are generally reliable
		baseConfig.MaxAttempts = 3
		baseConfig.InitialDelay = time.Second * 1
		
	case SIEMPlatformElastic:
		// Elasticsearch can handle retries well
		baseConfig.MaxAttempts = 4
		baseConfig.InitialDelay = time.Second * 1
	}
	
	return baseConfig
}