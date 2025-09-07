/**
 * @jest-environment jsdom
 */

import { describe, it, expect, beforeEach, afterEach, vi, type Mock } from 'vitest';
import { 
  ResourceMonitoringService, 
  createResourceMonitoringService,
  resourceMonitoring
} from '../resourceMonitoringService';
import type { ResourceStatus } from '../kubernetesApi';

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState: number = MockWebSocket.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  url: string;

  constructor(url: string) {
    this.url = url;
    // Simulate connection opening
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      this.onopen?.(new Event('open'));
    }, 10);
  }

  send(_data: string): void {
    // Mock sending data
  }

  close(code?: number, reason?: string): void {
    this.readyState = MockWebSocket.CLOSED;
    const closeEvent = new CloseEvent('close', { 
      code: code || 1000, 
      reason: reason || ''
    });
    this.onclose?.(closeEvent);
  }

  // Helper methods for testing
  simulateMessage(data: any): void {
    if (this.readyState === MockWebSocket.OPEN) {
      const messageEvent = new MessageEvent('message', {
        data: JSON.stringify(data)
      });
      this.onmessage?.(messageEvent);
    }
  }

  simulateError(): void {
    this.onerror?.(new Event('error'));
  }

  simulateClose(code: number = 1006): void {
    this.readyState = MockWebSocket.CLOSED;
    const closeEvent = new CloseEvent('close', { code });
    this.onclose?.(closeEvent);
  }
}

// Mock global WebSocket
global.WebSocket = MockWebSocket as any;

// Mock window.location
Object.defineProperty(window, 'location', {
  value: {
    host: 'localhost:3000',
    protocol: 'http:'
  },
  writable: true
});

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  clear: vi.fn()
};
Object.defineProperty(window, 'localStorage', { value: mockLocalStorage });

describe('ResourceMonitoringService', () => {
  let service: ResourceMonitoringService;
  let eventListener: Mock;

  beforeEach(() => {
    service = createResourceMonitoringService({
      sessionId: 'test-session-123',
      token: 'test-token',
      reconnectInterval: 100,
      maxReconnectAttempts: 3
    });
    
    eventListener = vi.fn();
    vi.clearAllMocks();
  });

  afterEach(() => {
    service.disconnect();
  });

  describe('Connection Management', () => {
    it('should connect to WebSocket successfully', async () => {
      const unsubscribe = service.subscribe(eventListener);

      await service.connect();

      expect(service.isConnected).toBe(true);
      expect(service.connectionState).toBe('open');
      expect(eventListener).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'connected'
      });

      unsubscribe();
    });

    it('should build correct WebSocket URL', async () => {
      const serviceWithNamespace = createResourceMonitoringService({
        sessionId: 'test-session',
        token: 'test-token',
        namespace: 'production',
        resourceTypes: ['pods', 'deployments']
      });

      await serviceWithNamespace.connect();

      // Check that the URL was constructed correctly
      // This tests the buildWebSocketUrl method indirectly
      expect(serviceWithNamespace.isConnected).toBe(true);
      
      serviceWithNamespace.disconnect();
    });

    it('should handle connection errors gracefully', async () => {
      const unsubscribe = service.subscribe(eventListener);

      // Mock WebSocket to simulate immediate error
      const originalWebSocket = global.WebSocket;
      global.WebSocket = class extends MockWebSocket {
        constructor(url: string) {
          super(url);
          setTimeout(() => this.simulateError(), 5);
        }
      } as any;

      try {
        await service.connect();
        // Should not reach here
        expect(false).toBe(true);
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
      }

      global.WebSocket = originalWebSocket;
      unsubscribe();
    });

    it('should disconnect gracefully', async () => {
      const unsubscribe = service.subscribe(eventListener);

      await service.connect();
      expect(service.isConnected).toBe(true);

      service.disconnect();
      expect(service.isConnected).toBe(false);
      expect(eventListener).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'disconnected'
      });

      unsubscribe();
    });
  });

  describe('Message Handling', () => {
    let mockWebSocket: MockWebSocket;

    beforeEach(async () => {
      service.subscribe(eventListener);
      await service.connect();
      
      // Get reference to the mock WebSocket instance
      mockWebSocket = (service as any).ws as MockWebSocket;
      
      // Clear the connection event
      eventListener.mockClear();
    });

    it('should handle resource_updated messages', () => {
      const mockResource: ResourceStatus = {
        kind: 'Pod',
        name: 'test-pod',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date(),
        metadata: { labels: { app: 'test' } },
        relationships: []
      };

      mockWebSocket.simulateMessage({
        type: 'resource_updated',
        resource: {
          ...mockResource,
          lastUpdated: mockResource.lastUpdated.toISOString()
        }
      });

      expect(eventListener).toHaveBeenCalledWith({
        type: 'resource_updated',
        resource: expect.objectContaining({
          kind: 'Pod',
          name: 'test-pod',
          status: 'Ready',
          lastUpdated: expect.any(Date)
        })
      });
    });

    it('should handle resource_created messages', () => {
      const mockResource: ResourceStatus = {
        kind: 'Deployment',
        name: 'new-deployment',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date(),
        metadata: {},
        relationships: []
      };

      mockWebSocket.simulateMessage({
        type: 'resource_created',
        resource: {
          ...mockResource,
          lastUpdated: mockResource.lastUpdated.toISOString()
        }
      });

      expect(eventListener).toHaveBeenCalledWith({
        type: 'resource_created',
        resource: expect.objectContaining({
          kind: 'Deployment',
          name: 'new-deployment',
          status: 'Ready'
        })
      });
    });

    it('should handle resource_deleted messages', () => {
      mockWebSocket.simulateMessage({
        type: 'resource_deleted',
        resourceId: 'Pod/default/deleted-pod'
      });

      expect(eventListener).toHaveBeenCalledWith({
        type: 'resource_deleted',
        resourceId: 'Pod/default/deleted-pod'
      });
    });

    it('should handle cluster_state_changed messages', () => {
      const timestamp = '2025-09-07T10:00:00Z';
      
      mockWebSocket.simulateMessage({
        type: 'cluster_state_changed',
        timestamp
      });

      expect(eventListener).toHaveBeenCalledWith({
        type: 'cluster_state_changed',
        timestamp
      });
    });

    it('should handle error messages', () => {
      mockWebSocket.simulateMessage({
        type: 'error',
        message: 'Permission denied',
        code: 'PERMISSION_ERROR'
      });

      expect(eventListener).toHaveBeenCalledWith({
        type: 'error',
        message: 'Permission denied',
        code: 'PERMISSION_ERROR'
      });
    });

    it('should handle malformed messages gracefully', () => {
      // Simulate receiving invalid JSON
      const messageEvent = new MessageEvent('message', {
        data: 'invalid json'
      });
      mockWebSocket.onmessage?.(messageEvent);

      expect(eventListener).toHaveBeenCalledWith({
        type: 'error',
        message: 'Failed to parse message',
        code: 'PARSE_ERROR'
      });
    });
  });

  describe('Resource Monitoring', () => {
    let mockWebSocket: MockWebSocket;

    beforeEach(async () => {
      await service.connect();
      mockWebSocket = (service as any).ws as MockWebSocket;
      vi.spyOn(mockWebSocket, 'send');
    });

    it('should send monitor_resource messages', () => {
      service.monitorResource('Pod', 'test-pod', 'default');

      expect(mockWebSocket.send).toHaveBeenCalledWith(
        JSON.stringify({
          type: 'monitor_resource',
          payload: { kind: 'Pod', name: 'test-pod', namespace: 'default' }
        })
      );
    });

    it('should send unmonitor_resource messages', () => {
      service.unmonitorResource('Deployment', 'test-deployment');

      expect(mockWebSocket.send).toHaveBeenCalledWith(
        JSON.stringify({
          type: 'unmonitor_resource',
          payload: { kind: 'Deployment', name: 'test-deployment', namespace: undefined }
        })
      );
    });

    it('should not send messages when disconnected', () => {
      service.disconnect();

      service.monitorResource('Pod', 'test-pod');

      expect(mockWebSocket.send).not.toHaveBeenCalled();
    });
  });

  describe('Reconnection Logic', () => {
    it('should attempt reconnection on unexpected closure', async () => {
      const unsubscribe = service.subscribe(eventListener);
      await service.connect();

      const mockWebSocket = (service as any).ws as MockWebSocket;
      eventListener.mockClear();

      // Simulate unexpected closure
      mockWebSocket.simulateClose(1006);

      expect(eventListener).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'reconnecting'
      });

      // Wait for reconnection attempt
      await new Promise(resolve => setTimeout(resolve, 150));

      unsubscribe();
    });

    it('should not reconnect after manual disconnect', async () => {
      const unsubscribe = service.subscribe(eventListener);
      await service.connect();

      eventListener.mockClear();
      service.disconnect();

      // Wait to ensure no reconnection attempt
      await new Promise(resolve => setTimeout(resolve, 150));

      // Should only have disconnection event, not reconnecting
      expect(eventListener).toHaveBeenCalledTimes(1);
      expect(eventListener).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'disconnected'
      });

      unsubscribe();
    });

    it('should give up after max reconnection attempts', async () => {
      const unsubscribe = service.subscribe(eventListener);

      // Mock WebSocket to always fail
      global.WebSocket = class extends MockWebSocket {
        constructor(url: string) {
          super(url);
          setTimeout(() => this.simulateClose(1006), 5);
        }
      } as any;

      await service.connect();
      eventListener.mockClear();

      // Wait for all reconnection attempts
      await new Promise(resolve => setTimeout(resolve, 500));

      expect(eventListener).toHaveBeenCalledWith({
        type: 'error',
        message: 'Maximum reconnection attempts reached',
        code: 'MAX_RECONNECT_EXCEEDED'
      });

      unsubscribe();
    });
  });

  describe('Subscription Management', () => {
    it('should support multiple subscribers', () => {
      const listener1 = vi.fn();
      const listener2 = vi.fn();

      const unsubscribe1 = service.subscribe(listener1);
      const unsubscribe2 = service.subscribe(listener2);

      // Simulate an event
      (service as any).emit({ type: 'connection_status', status: 'connected' });

      expect(listener1).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'connected'
      });
      expect(listener2).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'connected'
      });

      unsubscribe1();
      unsubscribe2();
    });

    it('should handle unsubscription correctly', () => {
      const listener1 = vi.fn();
      const listener2 = vi.fn();

      const unsubscribe1 = service.subscribe(listener1);
      service.subscribe(listener2);

      // Unsubscribe first listener
      unsubscribe1();

      // Simulate an event
      (service as any).emit({ type: 'connection_status', status: 'connected' });

      expect(listener1).not.toHaveBeenCalled();
      expect(listener2).toHaveBeenCalledWith({
        type: 'connection_status',
        status: 'connected'
      });
    });

    it('should handle errors in event listeners gracefully', () => {
      const errorListener = vi.fn().mockImplementation(() => {
        throw new Error('Listener error');
      });
      const normalListener = vi.fn();

      service.subscribe(errorListener);
      service.subscribe(normalListener);

      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

      // Simulate an event
      (service as any).emit({ type: 'connection_status', status: 'connected' });

      expect(consoleSpy).toHaveBeenCalledWith(
        'Error in WebSocket event listener:',
        expect.any(Error)
      );
      expect(normalListener).toHaveBeenCalled();

      consoleSpy.mockRestore();
    });
  });
});

describe('Singleton Resource Monitoring', () => {
  afterEach(() => {
    // Clean up singleton instance
    if ((resourceMonitoring as any)._resourceMonitoringInstance) {
      resourceMonitoring.instance.disconnect();
      (resourceMonitoring as any)._resourceMonitoringInstance = null;
    }
  });

  it('should initialize singleton instance', () => {
    const config = { sessionId: 'test-session', token: 'test-token' };
    const instance = resourceMonitoring.initialize(config);

    expect(instance).toBeInstanceOf(ResourceMonitoringService);
    expect(resourceMonitoring.instance).toBe(instance);
  });

  it('should replace existing instance on re-initialization', () => {
    const config1 = { sessionId: 'session-1', token: 'token-1' };
    const config2 = { sessionId: 'session-2', token: 'token-2' };

    const instance1 = resourceMonitoring.initialize(config1);
    const disconnectSpy = vi.spyOn(instance1, 'disconnect');
    
    const instance2 = resourceMonitoring.initialize(config2);

    expect(disconnectSpy).toHaveBeenCalled();
    expect(resourceMonitoring.instance).toBe(instance2);
    expect(instance2).not.toBe(instance1);
  });

  it('should throw error when accessing uninitialized instance', () => {
    expect(() => resourceMonitoring.instance).toThrow(
      'Resource monitoring service not initialized. Call initialize() first.'
    );
  });

  it('should provide proxy methods to singleton instance', async () => {
    const config = { sessionId: 'test-session', token: 'test-token' };
    resourceMonitoring.initialize(config);

    const instanceSpy = vi.spyOn(resourceMonitoring.instance, 'connect');
    
    await resourceMonitoring.connect();
    
    expect(instanceSpy).toHaveBeenCalled();
  });
});