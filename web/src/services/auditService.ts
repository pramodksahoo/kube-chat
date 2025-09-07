/**
 * Audit Service - Client-side audit logging for compliance
 * Tracks user interactions, resource access, and system events
 */

export interface AuditEvent {
  id: string;
  timestamp: Date;
  userId: string;
  sessionId: string;
  action: string;
  resource?: {
    kind: string;
    name: string;
    namespace?: string;
  };
  metadata: {
    userAgent: string;
    ipAddress: string;
    component: 'web-ui';
    source: string;
    level: 'info' | 'warn' | 'error';
    requestId?: string;
    parentRequestId?: string;
  };
  outcome: 'success' | 'failure' | 'error';
  details: Record<string, any>;
  tags: string[];
  sensitive?: boolean; // Flag for events containing sensitive data
}

export interface AuditFilter {
  startTime?: Date;
  endTime?: Date;
  userId?: string;
  action?: string;
  resource?: string;
  outcome?: 'success' | 'failure' | 'error';
  level?: 'info' | 'warn' | 'error';
  tags?: string[];
  limit?: number;
  offset?: number;
}

export interface AuditSearchResult {
  events: AuditEvent[];
  total: number;
  hasMore: boolean;
}

export interface ComplianceReport {
  period: {
    start: Date;
    end: Date;
  };
  summary: {
    totalEvents: number;
    successfulActions: number;
    failedActions: number;
    errorEvents: number;
    uniqueUsers: number;
    resourcesAccessed: number;
  };
  topActions: Array<{ action: string; count: number }>;
  topUsers: Array<{ userId: string; count: number }>;
  topResources: Array<{ resource: string; count: number }>;
  securityEvents: AuditEvent[];
  complianceViolations: Array<{
    type: string;
    description: string;
    events: AuditEvent[];
    severity: 'low' | 'medium' | 'high' | 'critical';
  }>;
}

export class AuditService {
  private baseUrl: string;
  private userId: string = '';
  private sessionId: string = '';
  private requestIdCounter: number = 0;
  private eventQueue: AuditEvent[] = [];
  private batchTimer: NodeJS.Timeout | null = null;
  private batchSize: number = 10;
  private batchInterval: number = 5000; // 5 seconds

  constructor(baseUrl: string = '/api/v1', isTestMode: boolean = false) {
    this.baseUrl = baseUrl;
    this.sessionId = this.generateSessionId();
    if (!isTestMode) {
      this.startBatchProcessor();
    }
  }

  // Initialize audit service with user context
  initialize(userId: string): void {
    this.userId = userId;
    this.logEvent('audit.session.start', {
      details: {
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
      },
      level: 'info',
    });
  }

  // Core audit logging method
  logEvent(
    action: string,
    options: {
      resource?: { kind: string; name: string; namespace?: string };
      outcome?: 'success' | 'failure' | 'error';
      details?: Record<string, any>;
      level?: 'info' | 'warn' | 'error';
      tags?: string[];
      sensitive?: boolean;
      requestId?: string;
      parentRequestId?: string;
    } = {}
  ): string {
    const requestId = options.requestId || this.generateRequestId();
    
    const event: AuditEvent = {
      id: this.generateEventId(),
      timestamp: new Date(),
      userId: this.userId,
      sessionId: this.sessionId,
      action,
      resource: options.resource,
      metadata: {
        userAgent: navigator.userAgent,
        ipAddress: this.getClientIP(),
        component: 'web-ui',
        source: 'kubernetes-dashboard',
        level: options.level || 'info',
        requestId,
        parentRequestId: options.parentRequestId,
      },
      outcome: options.outcome || 'success',
      details: this.sanitizeDetails(options.details || {}),
      tags: options.tags || [],
      sensitive: options.sensitive || false,
    };

    // Add to queue for batch processing
    this.eventQueue.push(event);

    // Immediate flush for critical events
    if (options.level === 'error' || event.sensitive) {
      void this.flushEvents();
    }

    return requestId;
  }

  // Resource access logging
  logResourceAccess(
    action: 'view' | 'edit' | 'delete' | 'create',
    resource: { kind: string; name: string; namespace?: string },
    outcome: 'success' | 'failure' | 'error' = 'success',
    details?: Record<string, any>
  ): void {
    this.logEvent(`resource.${action}`, {
      resource,
      outcome,
      details,
      level: outcome === 'success' ? 'info' : outcome === 'failure' ? 'warn' : 'error',
      tags: ['resource-access', action, resource.kind.toLowerCase()],
    });
  }

  // Dashboard interaction logging
  logDashboardInteraction(
    interaction: 'view' | 'filter' | 'sort' | 'search' | 'export',
    details?: Record<string, any>
  ): void {
    this.logEvent(`dashboard.${interaction}`, {
      outcome: 'success',
      details,
      level: 'info',
      tags: ['dashboard', interaction],
    });
  }

  // Permission check logging
  logPermissionCheck(
    resource: string,
    action: string,
    allowed: boolean,
    reason?: string,
    namespace?: string
  ): void {
    this.logEvent('permission.check', {
      resource: namespace ? { kind: resource, name: action, namespace } : { kind: resource, name: action },
      outcome: allowed ? 'success' : 'failure',
      details: {
        permission: `${action}:${resource}`,
        allowed,
        reason,
        namespace,
      },
      level: allowed ? 'info' : 'warn',
      tags: ['permission', 'rbac', allowed ? 'allowed' : 'denied'],
    });
  }

  // Error and security event logging
  logError(
    error: Error,
    context: {
      action?: string;
      resource?: { kind: string; name: string; namespace?: string };
      details?: Record<string, any>;
    } = {}
  ): void {
    this.logEvent(context.action || 'error.unhandled', {
      resource: context.resource,
      outcome: 'error',
      details: {
        error: {
          name: error.name,
          message: error.message,
          stack: error.stack,
        },
        ...context.details,
      },
      level: 'error',
      tags: ['error', 'exception'],
    });
  }

  logSecurityEvent(
    eventType: 'authentication' | 'authorization' | 'access_violation' | 'suspicious_activity',
    details: Record<string, any>,
    severity: 'low' | 'medium' | 'high' | 'critical' = 'medium'
  ): void {
    this.logEvent(`security.${eventType}`, {
      outcome: 'success',
      details: {
        securityEventType: eventType,
        severity,
        ...details,
      },
      level: severity === 'low' ? 'info' : severity === 'medium' ? 'warn' : 'error',
      tags: ['security', eventType, severity],
      sensitive: severity === 'high' || severity === 'critical',
    });
  }

  // Data export logging (compliance requirement)
  logDataExport(
    exportType: 'resource_list' | 'resource_details' | 'logs' | 'events',
    resourceCount: number,
    format: 'json' | 'csv' | 'yaml',
    details?: Record<string, any>
  ): void {
    this.logEvent('data.export', {
      outcome: 'success',
      details: {
        exportType,
        resourceCount,
        format,
        ...details,
      },
      level: 'info',
      tags: ['data-export', exportType, format],
      sensitive: true, // Data exports are always sensitive
    });
  }

  // Search and retrieve audit events
  async searchEvents(filter: AuditFilter): Promise<AuditSearchResult> {
    try {
      const queryParams = new URLSearchParams();
      
      if (filter.startTime) queryParams.append('startTime', filter.startTime.toISOString());
      if (filter.endTime) queryParams.append('endTime', filter.endTime.toISOString());
      if (filter.userId) queryParams.append('userId', filter.userId);
      if (filter.action) queryParams.append('action', filter.action);
      if (filter.resource) queryParams.append('resource', filter.resource);
      if (filter.outcome) queryParams.append('outcome', filter.outcome);
      if (filter.level) queryParams.append('level', filter.level);
      if (filter.tags) queryParams.append('tags', filter.tags.join(','));
      if (filter.limit) queryParams.append('limit', filter.limit.toString());
      if (filter.offset) queryParams.append('offset', filter.offset.toString());

      const response = await fetch(`${this.baseUrl}/audit/events?${queryParams}`, {
        headers: this.getAuthHeaders(),
      });

      if (!response.ok) {
        throw new Error(`Audit search failed: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Failed to search audit events:', error);
      throw error;
    }
  }

  // Generate compliance report
  async generateComplianceReport(
    startDate: Date,
    endDate: Date,
    includeDetails: boolean = false
  ): Promise<ComplianceReport> {
    try {
      const response = await fetch(`${this.baseUrl}/audit/compliance-report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...this.getAuthHeaders(),
        },
        body: JSON.stringify({
          startDate: startDate.toISOString(),
          endDate: endDate.toISOString(),
          includeDetails,
        }),
      });

      if (!response.ok) {
        throw new Error(`Compliance report generation failed: ${response.statusText}`);
      }

      const report = await response.json();
      
      // Log the report generation
      this.logEvent('compliance.report.generated', {
        outcome: 'success',
        details: {
          period: {
            start: startDate.toISOString(),
            end: endDate.toISOString(),
          },
          totalEvents: report.summary.totalEvents,
          includeDetails,
        },
        level: 'info',
        tags: ['compliance', 'report'],
        sensitive: true,
      });

      return report;
    } catch (error) {
      this.logError(error as Error, {
        action: 'compliance.report.generation',
        details: { startDate, endDate, includeDetails },
      });
      throw error;
    }
  }

  // Batch processing methods
  private startBatchProcessor(): void {
    this.batchTimer = setInterval(() => {
      if (this.eventQueue.length > 0) {
        void this.flushEvents();
      }
    }, this.batchInterval);
  }

  private async flushEvents(): Promise<void> {
    if (this.eventQueue.length === 0) return;

    const eventsToSend = this.eventQueue.splice(0, this.batchSize);

    try {
      await this.sendEvents(eventsToSend);
    } catch (error) {
      console.error('Failed to send audit events:', error);
      // Re-queue failed events (with backoff logic in production)
      this.eventQueue.unshift(...eventsToSend);
    }
  }

  private async sendEvents(events: AuditEvent[]): Promise<void> {
    const response = await fetch(`${this.baseUrl}/audit/events`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        ...this.getAuthHeaders(),
      },
      body: JSON.stringify({ events }),
    });

    if (!response.ok) {
      throw new Error(`Failed to send audit events: ${response.statusText}`);
    }
  }

  // Utility methods
  private generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private generateRequestId(): string {
    return `req_${Date.now()}_${++this.requestIdCounter}`;
  }

  private generateSessionId(): string {
    return `sess_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private getClientIP(): string {
    // In a real implementation, this would be determined server-side
    return 'client-side';
  }

  private sanitizeDetails(details: Record<string, any>): Record<string, any> {
    const sensitiveKeys = ['password', 'token', 'secret', 'auth'];
    const sanitized = { ...details };

    const sanitizeValue = (obj: any, path: string = ''): any => {
      if (obj === null || obj === undefined) return obj;

      if (typeof obj === 'string') {
        // Check if key or path contains sensitive terms
        if (sensitiveKeys.some(key => path.toLowerCase().includes(key))) {
          return '[REDACTED]';
        }
        return obj;
      }

      if (Array.isArray(obj)) {
        return obj.map((item, index) => sanitizeValue(item, `${path}[${index}]`));
      }

      if (typeof obj === 'object') {
        const result: any = {};
        for (const [key, value] of Object.entries(obj)) {
          const newPath = path ? `${path}.${key}` : key;
          result[key] = sanitizeValue(value, newPath);
        }
        return result;
      }

      return obj;
    };

    return sanitizeValue(sanitized);
  }

  private getAuthHeaders(): Record<string, string> {
    const token = localStorage.getItem('auth-token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
  }

  // Cleanup
  destroy(): void {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }

    // Flush remaining events
    if (this.eventQueue.length > 0) {
      void this.flushEvents();
    }
  }
}

// Default instance
export const auditService = new AuditService('/api');

// React hook for audit logging
import { useEffect, useRef } from 'react';

export function useAuditLogging(userId?: string) {
  const auditRef = useRef(auditService);

  useEffect(() => {
    if (userId) {
      auditRef.current.initialize(userId);
    }
  }, [userId]);

  const logResourceAccess = useRef(auditRef.current.logResourceAccess.bind(auditRef.current));
  const logDashboardInteraction = useRef(auditRef.current.logDashboardInteraction.bind(auditRef.current));
  const logError = useRef(auditRef.current.logError.bind(auditRef.current));
  const logSecurityEvent = useRef(auditRef.current.logSecurityEvent.bind(auditRef.current));

  return {
    logResourceAccess: logResourceAccess.current,
    logDashboardInteraction: logDashboardInteraction.current,
    logError: logError.current,
    logSecurityEvent: logSecurityEvent.current,
    searchEvents: auditRef.current.searchEvents.bind(auditRef.current),
    generateComplianceReport: auditRef.current.generateComplianceReport.bind(auditRef.current),
  };
}