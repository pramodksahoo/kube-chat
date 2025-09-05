package middleware

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
)

// SIEM Integration Types
type SIEMProvider string

const (
	SIEMSplunk     SIEMProvider = "splunk"
	SIEMElastic    SIEMProvider = "elastic"
	SIEMArcSight   SIEMProvider = "arcsight"
	SIEMQRadar     SIEMProvider = "qradar"
	SIEMSentinel   SIEMProvider = "sentinel"
)

// Compliance Framework Types
type ComplianceFramework string

const (
	ComplianceSOX     ComplianceFramework = "sox"
	ComplianceHIPAA   ComplianceFramework = "hipaa"
	CompliancePCI     ComplianceFramework = "pci"
	ComplianceSOC2    ComplianceFramework = "soc2"
	ComplianceGDPR    ComplianceFramework = "gdpr"
	ComplianceISO27001 ComplianceFramework = "iso27001"
)

// SIEM Configuration
type SIEMConfig struct {
	Provider        SIEMProvider          `json:"provider"`
	Endpoint        string               `json:"endpoint"`
	APIKey          string               `json:"api_key,omitempty"`
	Username        string               `json:"username,omitempty"`
	Password        string               `json:"password,omitempty"`
	Index           string               `json:"index,omitempty"`
	CustomHeaders   map[string]string    `json:"custom_headers,omitempty"`
	TLSConfig       *tls.Config          `json:"-"`
	BatchSize       int                  `json:"batch_size"`
	FlushInterval   time.Duration        `json:"flush_interval"`
	RetryAttempts   int                  `json:"retry_attempts"`
	TimeoutSeconds  int                  `json:"timeout_seconds"`
}

// Compliance Configuration
type ComplianceConfig struct {
	Frameworks      []ComplianceFramework `json:"frameworks"`
	ReportingPeriod string               `json:"reporting_period"` // daily, weekly, monthly
	RetentionDays   int                  `json:"retention_days"`
	AlertThresholds map[string]int       `json:"alert_thresholds"`
	NotificationURL string               `json:"notification_url,omitempty"`
}

// SIEM Event Formats
type SIEMEvent struct {
	Timestamp    time.Time         `json:"timestamp"`
	EventID      string           `json:"event_id"`
	Source       string           `json:"source"`
	EventType    string           `json:"event_type"`
	Severity     string           `json:"severity"`
	UserID       string           `json:"user_id,omitempty"`
	SessionID    string           `json:"session_id,omitempty"`
	IPAddress    string           `json:"ip_address,omitempty"`
	UserAgent    string           `json:"user_agent,omitempty"`
	Description  string           `json:"description"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	ComplianceContext *ComplianceContext `json:"compliance_context,omitempty"`
}

// Compliance Context
type ComplianceContext struct {
	Framework    ComplianceFramework `json:"framework"`
	ControlID    string             `json:"control_id"`
	Requirement  string             `json:"requirement"`
	RiskLevel    string             `json:"risk_level"`
	Evidence     map[string]string  `json:"evidence,omitempty"`
}

// Compliance Report
type ComplianceReport struct {
	ID              string                    `json:"id"`
	Framework       ComplianceFramework       `json:"framework"`
	Period          string                   `json:"period"`
	GeneratedAt     time.Time                `json:"generated_at"`
	TotalEvents     int64                    `json:"total_events"`
	SecurityEvents  int64                    `json:"security_events"`
	ComplianceScore float64                  `json:"compliance_score"`
	Violations      []ComplianceViolation    `json:"violations"`
	Recommendations []string                 `json:"recommendations"`
	Controls        map[string]ControlStatus `json:"controls"`
}

type ComplianceViolation struct {
	ID          string    `json:"id"`
	ControlID   string    `json:"control_id"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Count       int       `json:"count"`
	Evidence    []string  `json:"evidence"`
}

type ControlStatus struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Status      string  `json:"status"` // compliant, non-compliant, partial
	Score       float64 `json:"score"`
	LastChecked time.Time `json:"last_checked"`
}

// SIEM Integration Manager
type SIEMIntegrationManager struct {
	config      SIEMConfig
	compliance  ComplianceConfig
	redisClient redis.Cmdable
	httpClient  *http.Client
	eventBuffer chan SIEMEvent
	stopCh      chan struct{}
}

// Create new SIEM Integration Manager
func NewSIEMIntegrationManager(siemConfig SIEMConfig, complianceConfig ComplianceConfig, redisClient redis.Cmdable) *SIEMIntegrationManager {
	// Set defaults
	if siemConfig.BatchSize == 0 {
		siemConfig.BatchSize = 100
	}
	if siemConfig.FlushInterval == 0 {
		siemConfig.FlushInterval = 30 * time.Second
	}
	if siemConfig.RetryAttempts == 0 {
		siemConfig.RetryAttempts = 3
	}
	if siemConfig.TimeoutSeconds == 0 {
		siemConfig.TimeoutSeconds = 30
	}

	httpClient := &http.Client{
		Timeout: time.Duration(siemConfig.TimeoutSeconds) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: siemConfig.TLSConfig,
		},
	}

	manager := &SIEMIntegrationManager{
		config:      siemConfig,
		compliance:  complianceConfig,
		redisClient: redisClient,
		httpClient:  httpClient,
		eventBuffer: make(chan SIEMEvent, siemConfig.BatchSize*2),
		stopCh:      make(chan struct{}),
	}

	// Start background event processor
	go manager.processEvents()

	return manager
}

// Send Authentication Event to SIEM
func (s *SIEMIntegrationManager) SendAuthEvent(entry AuthAuditEntry) error {
	event := SIEMEvent{
		Timestamp:   entry.EventTime,
		EventID:     entry.EventID,
		Source:      "kubechat-auth",
		EventType:   string(entry.EventType),
		Severity:    s.mapAuditSeverityToSIEM(entry.Severity),
		UserID:      entry.UserID,
		SessionID:   entry.SessionID,
		IPAddress:   entry.IPAddress,
		UserAgent:   entry.UserAgent,
		Description: entry.Message,
		Metadata: map[string]interface{}{
			"kubernetes_command":       entry.KubernetesCommand,
			"natural_language_input":   entry.NaturalLanguageInput,
			"success":                  entry.Success,
			"failure_reason":           entry.FailureReason,
			"error_code":               entry.ErrorCode,
			"signature":                entry.Signature,
			"risk_score":               entry.RiskScore,
			"compliance_flags":         entry.ComplianceFlags,
		},
		ComplianceContext: s.getComplianceContext(entry),
	}

	select {
	case s.eventBuffer <- event:
		return nil
	default:
		return fmt.Errorf("event buffer full, dropping event")
	}
}

// Send Security Event to SIEM
func (s *SIEMIntegrationManager) SendSecurityEvent(eventType, description, userID, sessionID, ipAddress string, severity AuditSeverity, metadata map[string]string) error {
	metadataInterface := make(map[string]interface{})
	for k, v := range metadata {
		metadataInterface[k] = v
	}

	event := SIEMEvent{
		Timestamp:   time.Now(),
		EventID:     fmt.Sprintf("sec-%d", time.Now().UnixNano()),
		Source:      "kubechat-security",
		EventType:   eventType,
		Severity:    s.mapAuditSeverityToSIEM(severity),
		UserID:      userID,
		SessionID:   sessionID,
		IPAddress:   ipAddress,
		Description: description,
		Metadata:    metadataInterface,
	}

	select {
	case s.eventBuffer <- event:
		return nil
	default:
		return fmt.Errorf("event buffer full, dropping event")
	}
}

// Process Events in Background
func (s *SIEMIntegrationManager) processEvents() {
	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()

	var eventBatch []SIEMEvent

	for {
		select {
		case event := <-s.eventBuffer:
			eventBatch = append(eventBatch, event)
			if len(eventBatch) >= s.config.BatchSize {
				s.flushEvents(eventBatch)
				eventBatch = nil
			}

		case <-ticker.C:
			if len(eventBatch) > 0 {
				s.flushEvents(eventBatch)
				eventBatch = nil
			}

		case <-s.stopCh:
			if len(eventBatch) > 0 {
				s.flushEvents(eventBatch)
			}
			return
		}
	}
}

// Flush Events to SIEM
func (s *SIEMIntegrationManager) flushEvents(events []SIEMEvent) {
	for attempt := 1; attempt <= s.config.RetryAttempts; attempt++ {
		if err := s.sendToSIEM(events); err != nil {
			if attempt == s.config.RetryAttempts {
				// Log final failure
				fmt.Printf("Failed to send events to SIEM after %d attempts: %v\n", s.config.RetryAttempts, err)
				// Store failed events for retry later
				s.storeFailedEvents(events)
			} else {
				// Exponential backoff
				time.Sleep(time.Duration(attempt*attempt) * time.Second)
			}
		} else {
			return
		}
	}
}

// Send Events to SIEM System
func (s *SIEMIntegrationManager) sendToSIEM(events []SIEMEvent) error {
	switch s.config.Provider {
	case SIEMSplunk:
		return s.sendToSplunk(events)
	case SIEMElastic:
		return s.sendToElastic(events)
	case SIEMArcSight:
		return s.sendToArcSight(events)
	case SIEMQRadar:
		return s.sendToQRadar(events)
	case SIEMSentinel:
		return s.sendToSentinel(events)
	default:
		return fmt.Errorf("unsupported SIEM provider: %s", s.config.Provider)
	}
}

// Send to Splunk
func (s *SIEMIntegrationManager) sendToSplunk(events []SIEMEvent) error {
	var payload bytes.Buffer
	
	for _, event := range events {
		eventData, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		payload.Write(eventData)
		payload.WriteString("\n")
	}

	req, err := http.NewRequest("POST", s.config.Endpoint, &payload)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Splunk "+s.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SIEM returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Send to Elasticsearch
func (s *SIEMIntegrationManager) sendToElastic(events []SIEMEvent) error {
	var payload bytes.Buffer
	
	for _, event := range events {
		// Elasticsearch bulk API format
		indexLine := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": s.config.Index,
			},
		}
		indexData, _ := json.Marshal(indexLine)
		payload.Write(indexData)
		payload.WriteString("\n")
		
		eventData, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("failed to marshal event: %w", err)
		}
		payload.Write(eventData)
		payload.WriteString("\n")
	}

	req, err := http.NewRequest("POST", s.config.Endpoint+"/_bulk", &payload)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "ApiKey "+s.config.APIKey)
	} else if s.config.Username != "" && s.config.Password != "" {
		req.SetBasicAuth(s.config.Username, s.config.Password)
	}
	
	req.Header.Set("Content-Type", "application/json")
	
	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SIEM returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Send to ArcSight (CEF format)
func (s *SIEMIntegrationManager) sendToArcSight(events []SIEMEvent) error {
	var payload bytes.Buffer
	
	for _, event := range events {
		cefEvent := s.convertToCEF(event)
		payload.WriteString(cefEvent)
		payload.WriteString("\n")
	}

	req, err := http.NewRequest("POST", s.config.Endpoint, &payload)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	if s.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.config.APIKey)
	}
	
	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SIEM returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Send to QRadar
func (s *SIEMIntegrationManager) sendToQRadar(events []SIEMEvent) error {
	// QRadar uses LEEF format
	var payload bytes.Buffer
	
	for _, event := range events {
		leefEvent := s.convertToLEEF(event)
		payload.WriteString(leefEvent)
		payload.WriteString("\n")
	}

	req, err := http.NewRequest("POST", s.config.Endpoint, &payload)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("SEC", s.config.APIKey)
	req.Header.Set("Content-Type", "text/plain")
	
	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SIEM returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Send to Microsoft Sentinel
func (s *SIEMIntegrationManager) sendToSentinel(events []SIEMEvent) error {
	payload, err := json.Marshal(events)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	req, err := http.NewRequest("POST", s.config.Endpoint, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "SharedKey "+s.config.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Log-Type", "KubeChatSecurityEvents")
	
	for key, value := range s.config.CustomHeaders {
		req.Header.Set(key, value)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SIEM returned error status: %d", resp.StatusCode)
	}

	return nil
}

// Convert to CEF Format
func (s *SIEMIntegrationManager) convertToCEF(event SIEMEvent) string {
	// CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
	extensions := fmt.Sprintf("rt=%d src=%s suser=%s cs1=%s cs1Label=SessionID msg=%s",
		event.Timestamp.Unix()*1000,
		event.IPAddress,
		event.UserID,
		event.SessionID,
		event.Description,
	)

	return fmt.Sprintf("CEF:0|Anthropic|KubeChat|1.0|%s|%s|%s|%s",
		event.EventType,
		event.Description,
		event.Severity,
		extensions,
	)
}

// Convert to LEEF Format
func (s *SIEMIntegrationManager) convertToLEEF(event SIEMEvent) string {
	// LEEF:2.0|Vendor|Product|Version|EventID|delim|key1=value1|key2=value2
	return fmt.Sprintf("LEEF:2.0|Anthropic|KubeChat|1.0|%s|^|devTime=%d^src=%s^usrName=%s^cat=%s^msg=%s",
		event.EventType,
		event.Timestamp.Unix(),
		event.IPAddress,
		event.UserID,
		event.EventType,
		event.Description,
	)
}

// Map Audit Severity to SIEM Severity
func (s *SIEMIntegrationManager) mapAuditSeverityToSIEM(severity AuditSeverity) string {
	switch severity {
	case AuditSeverityInfo:
		return "Low"
	case AuditSeverityWarning:
		return "Medium"
	case AuditSeverityError:
		return "High"
	case AuditSeverityCritical:
		return "Critical"
	default:
		return "Medium"
	}
}

// Get Compliance Context
func (s *SIEMIntegrationManager) getComplianceContext(entry AuthAuditEntry) *ComplianceContext {
	// Map event types to compliance controls
	controlMappings := map[AuthEvent]map[ComplianceFramework]string{
		AuthEventLogin: {
			ComplianceSOX:     "IT-AC-01",
			ComplianceSOC2:    "CC6.1",
			ComplianceISO27001: "A.9.2.1",
		},
		AuthEventLoginFailure: {
			ComplianceSOX:     "IT-AC-02",
			ComplianceSOC2:    "CC6.2",
			ComplianceISO27001: "A.9.2.4",
		},
		AuthEventPermissionDenied: {
			ComplianceSOX:     "IT-AC-03",
			ComplianceSOC2:    "CC6.3",
			ComplianceISO27001: "A.9.2.3",
		},
	}

	// Use the first configured framework
	if len(s.compliance.Frameworks) > 0 {
		framework := s.compliance.Frameworks[0]
		if controls, ok := controlMappings[entry.EventType]; ok {
			if controlID, ok := controls[framework]; ok {
				return &ComplianceContext{
					Framework: framework,
					ControlID: controlID,
					Requirement: s.getControlRequirement(framework, controlID),
					RiskLevel:   s.mapSeverityToRisk(entry.Severity),
				}
			}
		}
	}

	return nil
}

// Get Control Requirement
func (s *SIEMIntegrationManager) getControlRequirement(framework ComplianceFramework, controlID string) string {
	requirements := map[ComplianceFramework]map[string]string{
		ComplianceSOX: {
			"IT-AC-01": "Access controls must be properly configured and monitored",
			"IT-AC-02": "Failed access attempts must be logged and monitored",
			"IT-AC-03": "Privileged access must be restricted and monitored",
		},
		ComplianceSOC2: {
			"CC6.1": "Logical access security measures protect information assets",
			"CC6.2": "System access is monitored and unauthorized access is prevented",
			"CC6.3": "Privileged access is restricted to appropriate personnel",
		},
	}

	if frameworkReqs, ok := requirements[framework]; ok {
		if req, ok := frameworkReqs[controlID]; ok {
			return req
		}
	}

	return "Access control and monitoring requirement"
}

// Map Severity to Risk Level
func (s *SIEMIntegrationManager) mapSeverityToRisk(severity AuditSeverity) string {
	switch severity {
	case AuditSeverityInfo:
		return "Low"
	case AuditSeverityWarning:
		return "Medium"
	case AuditSeverityError:
		return "High"
	case AuditSeverityCritical:
		return "Critical"
	default:
		return "Medium"
	}
}

// Store Failed Events for Retry
func (s *SIEMIntegrationManager) storeFailedEvents(events []SIEMEvent) {
	// Store in Redis for retry later
	for _, event := range events {
		eventData, err := json.Marshal(event)
		if err != nil {
			continue
		}
		
		key := fmt.Sprintf("failed_siem_events:%s", event.EventID)
		s.redisClient.Set(context.Background(), key, eventData, 24*time.Hour)
	}
}

// Generate Compliance Report
func (s *SIEMIntegrationManager) GenerateComplianceReport(framework ComplianceFramework, period string) (*ComplianceReport, error) {
	report := &ComplianceReport{
		ID:          fmt.Sprintf("compliance-%s-%s-%d", framework, period, time.Now().Unix()),
		Framework:   framework,
		Period:      period,
		GeneratedAt: time.Now(),
		Controls:    make(map[string]ControlStatus),
	}

	// Calculate compliance metrics
	if err := s.calculateComplianceMetrics(report); err != nil {
		return nil, fmt.Errorf("failed to calculate compliance metrics: %w", err)
	}

	// Identify violations
	if err := s.identifyViolations(report); err != nil {
		return nil, fmt.Errorf("failed to identify violations: %w", err)
	}

	// Generate recommendations
	report.Recommendations = s.generateRecommendations(report)

	return report, nil
}

// Calculate Compliance Metrics
func (s *SIEMIntegrationManager) calculateComplianceMetrics(report *ComplianceReport) error {
	// This would typically query your audit data
	// For now, we'll use mock data
	report.TotalEvents = 1000
	report.SecurityEvents = 150
	report.ComplianceScore = 85.5

	// Mock control statuses
	report.Controls = map[string]ControlStatus{
		"IT-AC-01": {
			ID:          "IT-AC-01",
			Name:        "Access Control Configuration",
			Status:      "compliant",
			Score:       95.0,
			LastChecked: time.Now(),
		},
		"IT-AC-02": {
			ID:          "IT-AC-02",
			Name:        "Failed Access Monitoring",
			Status:      "partial",
			Score:       75.0,
			LastChecked: time.Now(),
		},
	}

	return nil
}

// Identify Violations
func (s *SIEMIntegrationManager) identifyViolations(report *ComplianceReport) error {
	// Mock violations
	report.Violations = []ComplianceViolation{
		{
			ID:          "violation-001",
			ControlID:   "IT-AC-02",
			Severity:    "Medium",
			Description: "Multiple failed login attempts detected without proper response",
			FirstSeen:   time.Now().Add(-24 * time.Hour),
			LastSeen:    time.Now().Add(-1 * time.Hour),
			Count:       5,
			Evidence:    []string{"Failed login attempts from IP 203.0.113.1", "No account lockout triggered"},
		},
	}

	return nil
}

// Generate Recommendations
func (s *SIEMIntegrationManager) generateRecommendations(report *ComplianceReport) []string {
	recommendations := []string{}

	for _, violation := range report.Violations {
		switch violation.ControlID {
		case "IT-AC-02":
			recommendations = append(recommendations, "Implement automated account lockout after multiple failed attempts")
		}
	}

	if report.ComplianceScore < 80 {
		recommendations = append(recommendations, "Review and enhance security monitoring procedures")
	}

	return recommendations
}

// Close SIEM Integration
func (s *SIEMIntegrationManager) Close() error {
	close(s.stopCh)
	return nil
}