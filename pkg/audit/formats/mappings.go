package formats

import (
	"fmt"

	"github.com/pramodksahoo/kube-chat/pkg/models"
)

// FieldMapping defines custom field name mappings for specific SIEM platforms
type FieldMapping struct {
	SourceField string `json:"source_field"`
	TargetField string `json:"target_field"`
	Transform   string `json:"transform,omitempty"` // Optional transformation function
}

// PlatformMappings defines field mappings for different SIEM platforms
type PlatformMappings struct {
	Platform string         `json:"platform"`
	Mappings []FieldMapping `json:"mappings"`
}

// GetSplunkMappings returns optimized field mappings for Splunk
func GetSplunkMappings() map[string]string {
	return map[string]string{
		// Splunk CIM (Common Information Model) mappings
		"timestamp":      "index_time",
		"event_type":     "eventtype",
		"user_id":        "user",
		"user_email":     "user_email",
		"session_id":     "session_id",
		"client_ip":      "src_ip",
		"user_agent":     "http_user_agent",
		"cluster_name":   "dest_host",
		"namespace":      "kubernetes_namespace",
		"resource_type":  "kubernetes_resource_type",
		"resource_name":  "kubernetes_resource_name",
		"generated_command": "command",
		"risk_level":     "risk_score",
		"execution_status": "action",
		"execution_result": "result",
		"execution_error": "error",
		"correlation_id": "transaction_id",
		"trace_id":       "trace_id",
		"service_name":   "source_service",
		"severity":       "severity",
		"message":        "signature",
	}
}

// GetQRadarMappings returns optimized field mappings for IBM QRadar
func GetQRadarMappings() map[string]string {
	return map[string]string{
		// QRadar DSM (Device Support Module) standard fields
		"timestamp":      "EventTime",
		"event_type":     "EventCategory",
		"user_id":        "UserName", 
		"user_email":     "SourceUserEmail",
		"session_id":     "SourceSessionID",
		"client_ip":      "SourceIP",
		"user_agent":     "SourceUserAgent",
		"cluster_name":   "DestinationHostName",
		"namespace":      "SourceZone",
		"resource_type":  "DestinationResourceType",
		"resource_name":  "DestinationResourceName",
		"generated_command": "CommandLine",
		"risk_level":     "ThreatLevel",
		"execution_status": "ActionTaken",
		"execution_result": "ProcessOutput",
		"execution_error": "ErrorMessage",
		"correlation_id": "CorrelationID",
		"trace_id":       "TraceID",
		"service_name":   "SourceService",
		"severity":       "Magnitude",
		"message":        "EventDescription",
	}
}

// GetSentinelMappings returns optimized field mappings for Microsoft Sentinel
func GetSentinelMappings() map[string]string {
	return map[string]string{
		// Microsoft Sentinel KQL query optimized fields
		"timestamp":      "TimeGenerated",
		"event_type":     "ActivityType",
		"user_id":        "AccountName",
		"user_email":     "AccountUPN",
		"session_id":     "SessionId",
		"client_ip":      "SourceIPAddress",
		"user_agent":     "UserAgent",
		"cluster_name":   "TargetResource",
		"namespace":      "ResourceGroup",
		"resource_type":  "ResourceType",
		"resource_name":  "ResourceName",
		"generated_command": "CommandLine",
		"risk_level":     "RiskLevel",
		"execution_status": "OperationResult",
		"execution_result": "Result",
		"execution_error": "ErrorMessage",
		"correlation_id": "CorrelationId",
		"trace_id":       "TraceId",
		"service_name":   "SourceSystem",
		"severity":       "AlertSeverity",
		"message":        "AlertName",
	}
}

// GetElasticMappings returns optimized field mappings for Elastic SIEM
func GetElasticMappings() map[string]string {
	return map[string]string{
		// Elastic Common Schema (ECS) mappings
		"timestamp":      "@timestamp",
		"event_type":     "event.category",
		"user_id":        "user.name",
		"user_email":     "user.email",
		"session_id":     "user.session.id",
		"client_ip":      "source.ip",
		"user_agent":     "user_agent.original",
		"cluster_name":   "host.name",
		"namespace":      "kubernetes.namespace",
		"resource_type":  "kubernetes.resource.type",
		"resource_name":  "kubernetes.resource.name",
		"generated_command": "process.command_line",
		"risk_level":     "event.risk_score",
		"execution_status": "event.outcome",
		"execution_result": "process.result",
		"execution_error": "error.message",
		"correlation_id": "trace.id",
		"trace_id":       "trace.id",
		"service_name":   "service.name",
		"severity":       "log.level",
		"message":        "message",
	}
}

// SIEMPlatform represents supported SIEM platforms
type SIEMPlatform string

const (
	SIEMPlatformSplunk   SIEMPlatform = "splunk"
	SIEMPlatformQRadar   SIEMPlatform = "qradar"
	SIEMPlatformSentinel SIEMPlatform = "sentinel"
	SIEMPlatformElastic  SIEMPlatform = "elastic"
	SIEMPlatformGeneric  SIEMPlatform = "generic"
)

// GetPlatformMappings returns the appropriate field mappings for a SIEM platform
func GetPlatformMappings(platform SIEMPlatform) (map[string]string, error) {
	switch platform {
	case SIEMPlatformSplunk:
		return GetSplunkMappings(), nil
	case SIEMPlatformQRadar:
		return GetQRadarMappings(), nil
	case SIEMPlatformSentinel:
		return GetSentinelMappings(), nil
	case SIEMPlatformElastic:
		return GetElasticMappings(), nil
	case SIEMPlatformGeneric:
		return make(map[string]string), nil // No mappings for generic
	default:
		return nil, fmt.Errorf("unsupported SIEM platform: %s", platform)
	}
}

// EventTypeMapping provides event type translations for different SIEM platforms
type EventTypeMapping struct {
	KubeChatEventType models.AuditEventType `json:"kubechat_event_type"`
	SplunkEventType   string                 `json:"splunk_event_type"`
	QRadarEventType   string                 `json:"qradar_event_type"`
	SentinelEventType string                 `json:"sentinel_event_type"`
	ElasticEventType  string                 `json:"elastic_event_type"`
}

// GetEventTypeMappings returns event type mappings for SIEM platforms
func GetEventTypeMappings() []EventTypeMapping {
	return []EventTypeMapping{
		{
			KubeChatEventType: models.AuditEventTypeAuthentication,
			SplunkEventType:   "authentication",
			QRadarEventType:   "Authentication",
			SentinelEventType: "SigninActivity",
			ElasticEventType:  "authentication",
		},
		{
			KubeChatEventType: models.AuditEventTypeLogin,
			SplunkEventType:   "successful_login",
			QRadarEventType:   "User Login Success",
			SentinelEventType: "SigninSuccess",
			ElasticEventType:  "authentication",
		},
		{
			KubeChatEventType: models.AuditEventTypeLogout,
			SplunkEventType:   "logout",
			QRadarEventType:   "User Logout",
			SentinelEventType: "SigninActivity",
			ElasticEventType:  "authentication",
		},
		{
			KubeChatEventType: models.AuditEventTypeCommand,
			SplunkEventType:   "command_execution",
			QRadarEventType:   "Command Execution",
			SentinelEventType: "ProcessCreated",
			ElasticEventType:  "process",
		},
		{
			KubeChatEventType: models.AuditEventTypeCommandExecute,
			SplunkEventType:   "command_execution",
			QRadarEventType:   "Administrative Command",
			SentinelEventType: "ProcessCreated",
			ElasticEventType:  "process",
		},
		{
			KubeChatEventType: models.AuditEventTypeNLPInput,
			SplunkEventType:   "user_input",
			QRadarEventType:   "User Input",
			SentinelEventType: "UserActivity",
			ElasticEventType:  "user",
		},
		{
			KubeChatEventType: models.AuditEventTypeNLPTranslation,
			SplunkEventType:   "translation",
			QRadarEventType:   "Command Translation",
			SentinelEventType: "AIProcessing",
			ElasticEventType:  "process",
		},
		{
			KubeChatEventType: models.AuditEventTypeRBACCheck,
			SplunkEventType:   "authorization_check",
			QRadarEventType:   "Authorization Check",
			SentinelEventType: "AuthorizationActivity",
			ElasticEventType:  "authentication",
		},
		{
			KubeChatEventType: models.AuditEventTypeRBACDenied,
			SplunkEventType:   "authorization_failure",
			QRadarEventType:   "Authorization Failure",
			SentinelEventType: "AuthorizationFailure",
			ElasticEventType:  "authentication",
		},
		{
			KubeChatEventType: models.AuditEventTypeSystemError,
			SplunkEventType:   "system_error",
			QRadarEventType:   "System Error",
			SentinelEventType: "SystemError",
			ElasticEventType:  "error",
		},
	}
}

// GetEventTypeForPlatform returns the appropriate event type for a specific SIEM platform
func GetEventTypeForPlatform(kubeChatEventType models.AuditEventType, platform SIEMPlatform) string {
	mappings := GetEventTypeMappings()
	
	for _, mapping := range mappings {
		if mapping.KubeChatEventType == kubeChatEventType {
			switch platform {
			case SIEMPlatformSplunk:
				return mapping.SplunkEventType
			case SIEMPlatformQRadar:
				return mapping.QRadarEventType
			case SIEMPlatformSentinel:
				return mapping.SentinelEventType
			case SIEMPlatformElastic:
				return mapping.ElasticEventType
			}
		}
	}
	
	// Return original event type if no mapping found
	return string(kubeChatEventType)
}

// RiskLevelMapping provides risk level translations for different SIEM platforms
type RiskLevelMapping struct {
	KubeChatRisk  string `json:"kubechat_risk"`
	SplunkRisk    string `json:"splunk_risk"`
	QRadarRisk    int    `json:"qradar_risk"`
	SentinelRisk  string `json:"sentinel_risk"`
	ElasticRisk   int    `json:"elastic_risk"`
}

// GetRiskLevelMappings returns risk level mappings for SIEM platforms
func GetRiskLevelMappings() []RiskLevelMapping {
	return []RiskLevelMapping{
		{
			KubeChatRisk: "safe",
			SplunkRisk:   "low",
			QRadarRisk:   2,
			SentinelRisk: "Low",
			ElasticRisk:  25,
		},
		{
			KubeChatRisk: "caution",
			SplunkRisk:   "medium",
			QRadarRisk:   5,
			SentinelRisk: "Medium",
			ElasticRisk:  50,
		},
		{
			KubeChatRisk: "destructive",
			SplunkRisk:   "high",
			QRadarRisk:   9,
			SentinelRisk: "High",
			ElasticRisk:  90,
		},
	}
}

// GetRiskLevelForPlatform returns the appropriate risk level for a specific SIEM platform
func GetRiskLevelForPlatform(kubeChatRisk string, platform SIEMPlatform) interface{} {
	mappings := GetRiskLevelMappings()
	
	for _, mapping := range mappings {
		if mapping.KubeChatRisk == kubeChatRisk {
			switch platform {
			case SIEMPlatformSplunk:
				return mapping.SplunkRisk
			case SIEMPlatformQRadar:
				return mapping.QRadarRisk
			case SIEMPlatformSentinel:
				return mapping.SentinelRisk
			case SIEMPlatformElastic:
				return mapping.ElasticRisk
			}
		}
	}
	
	// Return original risk level if no mapping found
	return kubeChatRisk
}

// ValidateMappings validates that field mappings are properly configured
func ValidateMappings(mappings map[string]string) error {
	if mappings == nil {
		return fmt.Errorf("mappings cannot be nil")
	}
	
	// Check for empty source or target fields
	for source, target := range mappings {
		if source == "" {
			return fmt.Errorf("source field cannot be empty")
		}
		if target == "" {
			return fmt.Errorf("target field cannot be empty for source: %s", source)
		}
	}
	
	return nil
}

// ApplyFieldMappings applies field mappings to a generic event map
func ApplyFieldMappings(eventMap map[string]interface{}, mappings map[string]string) map[string]interface{} {
	if mappings == nil || len(mappings) == 0 {
		return eventMap
	}
	
	mappedEvent := make(map[string]interface{})
	
	// Apply mappings
	for originalField, mappedField := range mappings {
		if value, exists := eventMap[originalField]; exists {
			mappedEvent[mappedField] = value
		}
	}
	
	// Include fields that don't have mappings
	for field, value := range eventMap {
		if _, haMapping := mappings[field]; !haMapping {
			mappedEvent[field] = value
		}
	}
	
	return mappedEvent
}