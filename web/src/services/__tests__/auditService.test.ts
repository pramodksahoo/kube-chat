/**
 * Tests for Audit Service
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuditService, auditService } from '../auditService';

// Mock fetch
global.fetch = vi.fn();

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(window, 'localStorage', { value: mockLocalStorage });

// Mock navigator
Object.defineProperty(window, 'navigator', {
  value: {
    userAgent: 'Mozilla/5.0 (Test Browser)',
  },
});

describe('Audit Service', () => {
  let service: AuditService;

  beforeEach(() => {
    vi.clearAllMocks();
    service = new AuditService('/api', true); // Enable test mode to prevent timers
    mockLocalStorage.getItem.mockReturnValue('mock-token');
    
    // Mock successful fetch responses
    vi.mocked(fetch).mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ success: true }),
    } as Response);
  });

  afterEach(() => {
    service.destroy();
  });

  describe('Initialization', () => {
    it('should initialize with user context', () => {
      const consoleSpy = vi.spyOn(console, 'log').mockImplementation(() => {});
      
      service.initialize('test-user');
      
      // Should not throw errors during initialization
      expect(() => service.initialize('test-user')).not.toThrow();
      
      consoleSpy.mockRestore();
    });

    it('should generate unique session ID', () => {
      const service1 = new AuditService('/api');
      const service2 = new AuditService('/api');
      
      expect(service1['sessionId']).not.toBe(service2['sessionId']);
      
      service1.destroy();
      service2.destroy();
    });
  });

  describe('Event Logging', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should log basic events', () => {
      const requestId = service.logEvent('test.action', {
        outcome: 'success',
        details: { key: 'value' },
        level: 'info',
      });

      expect(requestId).toMatch(/^req_/);
      expect(service['eventQueue']).toHaveLength(1);
      
      const event = service['eventQueue'][0];
      expect(event.action).toBe('test.action');
      expect(event.userId).toBe('test-user');
      expect(event.outcome).toBe('success');
      expect(event.details).toEqual({ key: 'value' });
    });

    it('should generate unique event IDs', () => {
      service.logEvent('action1');
      service.logEvent('action2');

      const events = service['eventQueue'];
      expect(events[0].id).not.toBe(events[1].id);
    });

    it('should handle sensitive events', () => {
      service.logEvent('sensitive.action', {
        sensitive: true,
        details: { password: 'secret123' },
      });

      const event = service['eventQueue'][0];
      expect(event.sensitive).toBe(true);
      expect(event.details.password).toBe('[REDACTED]');
    });

    it('should sanitize sensitive data in details', () => {
      service.logEvent('test.action', {
        details: {
          username: 'john',
          password: 'secret123',
          token: 'abc123',
          data: { secret: 'hidden', public: 'visible' },
        },
      });

      const event = service['eventQueue'][0];
      expect(event.details.username).toBe('john');
      expect(event.details.password).toBe('[REDACTED]');
      expect(event.details.token).toBe('[REDACTED]');
      expect(event.details.data.secret).toBe('[REDACTED]');
      expect(event.details.data.public).toBe('visible');
    });

    it('should add metadata to events', () => {
      service.logEvent('test.action');

      const event = service['eventQueue'][0];
      expect(event.metadata.userAgent).toBe('Mozilla/5.0 (Test Browser)');
      expect(event.metadata.component).toBe('web-ui');
      expect(event.metadata.source).toBe('kubernetes-dashboard');
      expect(event.timestamp).toBeInstanceOf(Date);
    });
  });

  describe('Resource Access Logging', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should log resource view events', () => {
      const resource = { kind: 'Pod', name: 'test-pod', namespace: 'default' };
      
      service.logResourceAccess('view', resource, 'success', { source: 'dashboard' });

      const event = service['eventQueue'][0];
      expect(event.action).toBe('resource.view');
      expect(event.resource).toEqual(resource);
      expect(event.outcome).toBe('success');
      expect(event.tags).toContain('resource-access');
      expect(event.tags).toContain('view');
      expect(event.tags).toContain('pod');
    });

    it('should log resource modification events', () => {
      const resource = { kind: 'Deployment', name: 'web-app' };
      
      service.logResourceAccess('delete', resource, 'failure', { reason: 'permission denied' });

      const event = service['eventQueue'][0];
      expect(event.action).toBe('resource.delete');
      expect(event.outcome).toBe('failure');
      expect(event.metadata.level).toBe('warn');
    });
  });

  describe('Dashboard Interaction Logging', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should log dashboard interactions', () => {
      service.logDashboardInteraction('filter', {
        filterType: 'namespace',
        filterValue: 'production',
      });

      const event = service['eventQueue'][0];
      expect(event.action).toBe('dashboard.filter');
      expect(event.tags).toContain('dashboard');
      expect(event.tags).toContain('filter');
      expect(event.details.filterType).toBe('namespace');
    });
  });

  describe('Permission Check Logging', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should log successful permission checks', () => {
      service.logPermissionCheck('pods', 'get', true, 'RBAC allowed', 'default');

      const event = service['eventQueue'][0];
      expect(event.action).toBe('permission.check');
      expect(event.outcome).toBe('success');
      expect(event.metadata.level).toBe('info');
      expect(event.details.allowed).toBe(true);
      expect(event.details.reason).toBe('RBAC allowed');
    });

    it('should log failed permission checks', () => {
      service.logPermissionCheck('secrets', 'list', false, 'Forbidden');

      const event = service['eventQueue'][0];
      expect(event.outcome).toBe('failure');
      expect(event.metadata.level).toBe('warn');
      expect(event.details.allowed).toBe(false);
    });
  });

  describe('Error and Security Logging', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should log errors with context', () => {
      const error = new Error('Test error');
      const context = {
        action: 'test.operation',
        resource: { kind: 'Pod', name: 'test-pod' },
        details: { context: 'additional info' },
      };

      service.logError(error, context);

      const event = service['eventQueue'][0];
      expect(event.action).toBe('test.operation');
      expect(event.outcome).toBe('error');
      expect(event.metadata.level).toBe('error');
      expect(event.details.error.message).toBe('Test error');
      expect(event.details.error.name).toBe('Error');
      expect(event.details.context).toBe('additional info');
    });

    it('should log security events', () => {
      service.logSecurityEvent('authorization', {
        attemptedAction: 'admin access',
        reason: 'privilege escalation attempt',
      }, 'high');

      const event = service['eventQueue'][0];
      expect(event.action).toBe('security.authorization');
      expect(event.metadata.level).toBe('error');
      expect(event.tags).toContain('security');
      expect(event.tags).toContain('authorization');
      expect(event.tags).toContain('high');
      expect(event.sensitive).toBe(true);
    });
  });

  describe('Data Export Logging', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should log data exports', () => {
      service.logDataExport('resource_list', 50, 'json', {
        namespace: 'production',
        resourceType: 'pods',
      });

      const event = service['eventQueue'][0];
      expect(event.action).toBe('data.export');
      expect(event.sensitive).toBe(true);
      expect(event.details.exportType).toBe('resource_list');
      expect(event.details.resourceCount).toBe(50);
      expect(event.details.format).toBe('json');
      expect(event.tags).toContain('data-export');
    });
  });

  describe('Event Search', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should search events with filters', async () => {
      const mockResponse = {
        events: [
          { id: 'event1', action: 'test.action1' },
          { id: 'event2', action: 'test.action2' },
        ],
        total: 2,
        hasMore: false,
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      } as Response);

      const filter = {
        startTime: new Date('2023-01-01'),
        endTime: new Date('2023-01-02'),
        userId: 'test-user',
        action: 'test.action',
        limit: 10,
      };

      const result = await service.searchEvents(filter);

      expect(result).toEqual(mockResponse);
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/audit/events?'),
        expect.objectContaining({
          headers: expect.objectContaining({
            'Authorization': 'Bearer mock-token',
          }),
        })
      );
    });

    it('should handle search errors', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Network error'));

      const filter = { limit: 10 };

      await expect(service.searchEvents(filter)).rejects.toThrow('Network error');
    });
  });

  describe('Compliance Report Generation', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
    });

    it('should generate compliance reports', async () => {
      const mockReport = {
        period: { start: '2023-01-01', end: '2023-01-02' },
        summary: { totalEvents: 100, successfulActions: 90, failedActions: 10 },
        topActions: [{ action: 'resource.view', count: 50 }],
        complianceViolations: [],
        securityEvents: [],
      };

      vi.mocked(fetch).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockReport),
      } as Response);

      const startDate = new Date('2023-01-01');
      const endDate = new Date('2023-01-02');

      const report = await service.generateComplianceReport(startDate, endDate, true);

      expect(report).toEqual(mockReport);
      expect(fetch).toHaveBeenCalledWith(
        '/api/audit/compliance-report',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Authorization': 'Bearer mock-token',
          }),
          body: JSON.stringify({
            startDate: startDate.toISOString(),
            endDate: endDate.toISOString(),
            includeDetails: true,
          }),
        })
      );

      // Should log report generation and send to server immediately (sensitive event)
      expect(fetch).toHaveBeenCalledTimes(2); // One for compliance report, one for audit event
      
      // Check that the audit event was sent
      const auditEventCall = vi.mocked(fetch).mock.calls.find(call =>
        call[0] === '/api/audit/events' && call[1]?.method === 'POST'
      );
      expect(auditEventCall).toBeDefined();
      
      const auditEventBody = JSON.parse(auditEventCall![1]!.body as string);
      expect(auditEventBody.events).toHaveLength(1);
      expect(auditEventBody.events[0].action).toBe('compliance.report.generated');
      expect(auditEventBody.events[0].sensitive).toBe(true);
    });

    it('should handle report generation errors', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Server error'));

      const startDate = new Date('2023-01-01');
      const endDate = new Date('2023-01-02');

      await expect(
        service.generateComplianceReport(startDate, endDate)
      ).rejects.toThrow('Server error');

      // Should log the error
      const event = service['eventQueue'][0];
      expect(event.outcome).toBe('error');
    });
  });

  describe('Batch Processing', () => {
    beforeEach(() => {
      service.initialize('test-user');
      // Clear the session start event from initialization
      service['eventQueue'] = [];
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it('should batch process events', async () => {
      // Add events to queue
      service.logEvent('action1');
      service.logEvent('action2');
      service.logEvent('action3');

      expect(service['eventQueue']).toHaveLength(3);

      // Trigger batch processing
      vi.advanceTimersByTime(5000);
      
      await vi.runAllTimersAsync();

      // Events should be sent and queue cleared
      expect(fetch).toHaveBeenCalledWith(
        '/api/audit/events',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('action1'),
        })
      );
    });

    it('should immediately flush sensitive events', () => {
      service.logEvent('sensitive.action', { sensitive: true });

      // Should trigger immediate flush
      expect(fetch).toHaveBeenCalled();
    });

    it('should handle batch send failures', async () => {
      vi.mocked(fetch).mockRejectedValueOnce(new Error('Send failed'));

      service.logEvent('test.action');
      
      // Trigger batch processing
      vi.advanceTimersByTime(5000);
      await vi.runAllTimersAsync();

      // Events should be re-queued on failure
      expect(service['eventQueue']).toHaveLength(1);
    });
  });

  describe('Utility Methods', () => {
    it('should generate unique IDs', () => {
      const id1 = service['generateEventId']();
      const id2 = service['generateEventId']();
      const reqId1 = service['generateRequestId']();
      const reqId2 = service['generateRequestId']();

      expect(id1).toMatch(/^evt_/);
      expect(id2).toMatch(/^evt_/);
      expect(id1).not.toBe(id2);

      expect(reqId1).toMatch(/^req_/);
      expect(reqId2).toMatch(/^req_/);
      expect(reqId1).not.toBe(reqId2);
    });

    it('should get auth headers', () => {
      const headers = service['getAuthHeaders']();
      expect(headers).toEqual({
        'Authorization': 'Bearer mock-token',
      });
    });

    it('should handle missing auth token', () => {
      mockLocalStorage.getItem.mockReturnValue(null);
      
      const headers = service['getAuthHeaders']();
      expect(headers).toEqual({});
    });
  });

  describe('Cleanup', () => {
    it('should cleanup resources on destroy', () => {
      service.logEvent('test.action');
      expect(service['eventQueue']).toHaveLength(1);

      service.destroy();

      // Should flush remaining events and clear timer
      expect(service['batchTimer']).toBeNull();
    });
  });

  describe('Default Instance', () => {
    it('should provide default auditService instance', () => {
      expect(auditService).toBeInstanceOf(AuditService);
    });
  });
});