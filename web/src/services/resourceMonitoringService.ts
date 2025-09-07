/**
 * Resource Monitoring WebSocket Service
 * Provides real-time updates for Kubernetes resource status changes
 */

import type { ResourceStatus } from './kubernetesApi';

export type ResourceUpdateEvent = 
  | { type: 'resource_updated'; resource: ResourceStatus }
  | { type: 'resource_created'; resource: ResourceStatus }  
  | { type: 'resource_deleted'; resourceId: string }
  | { type: 'cluster_state_changed'; timestamp: string }
  | { type: 'connection_status'; status: 'connected' | 'disconnected' | 'reconnecting' }
  | { type: 'error'; message: string; code?: string };

export interface ResourceMonitoringConfig {
  sessionId: string;
  token?: string;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
  namespace?: string;
  resourceTypes?: string[];
}

export class ResourceMonitoringService {
  private ws: WebSocket | null = null;
  private config: ResourceMonitoringConfig;
  private listeners: ((event: ResourceUpdateEvent) => void)[] = [];
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private isManuallyDisconnected = false;
  private heartbeatInterval: NodeJS.Timeout | null = null;

  constructor(config: ResourceMonitoringConfig) {
    this.config = {
      reconnectInterval: 5000,
      maxReconnectAttempts: 10,
      ...config
    };
  }

  /**
   * Connect to resource monitoring WebSocket
   */
  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.isManuallyDisconnected = false;
        const wsUrl = this.buildWebSocketUrl();
        
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
          this.reconnectAttempts = 0;
          this.startHeartbeat();
          this.emit({ type: 'connection_status', status: 'connected' });
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            this.handleMessage(data);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
            this.emit({ 
              type: 'error', 
              message: 'Failed to parse message',
              code: 'PARSE_ERROR'
            });
          }
        };

        this.ws.onclose = (event) => {
          this.stopHeartbeat();
          
          if (event.code === 1000) {
            // Normal closure
            this.emit({ type: 'connection_status', status: 'disconnected' });
            return;
          }

          if (!this.isManuallyDisconnected) {
            this.handleReconnection();
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.emit({ 
            type: 'error', 
            message: 'WebSocket connection error',
            code: 'CONNECTION_ERROR'
          });
          
          if (this.ws?.readyState === WebSocket.CONNECTING) {
            reject(new Error('Failed to establish WebSocket connection'));
          }
        };

      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  /**
   * Disconnect from WebSocket
   */
  disconnect(): void {
    this.isManuallyDisconnected = true;
    this.clearReconnectTimer();
    this.stopHeartbeat();

    if (this.ws) {
      this.ws.close(1000, 'Manual disconnect');
      this.ws = null;
    }

    this.emit({ type: 'connection_status', status: 'disconnected' });
  }

  /**
   * Subscribe to resource update events
   */
  subscribe(listener: (event: ResourceUpdateEvent) => void): () => void {
    this.listeners.push(listener);
    
    // Return unsubscribe function
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  /**
   * Request specific resource monitoring
   */
  monitorResource(kind: string, name: string, namespace?: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'monitor_resource',
        payload: { kind, name, namespace }
      }));
    }
  }

  /**
   * Stop monitoring specific resource
   */
  unmonitorResource(kind: string, name: string, namespace?: string): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify({
        type: 'unmonitor_resource', 
        payload: { kind, name, namespace }
      }));
    }
  }

  /**
   * Get current connection status
   */
  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Get connection state
   */
  get connectionState(): 'connecting' | 'open' | 'closing' | 'closed' {
    if (!this.ws) return 'closed';
    
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING: return 'connecting';
      case WebSocket.OPEN: return 'open';
      case WebSocket.CLOSING: return 'closing';
      case WebSocket.CLOSED: return 'closed';
      default: return 'closed';
    }
  }

  private buildWebSocketUrl(): string {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    
    let url = `${protocol}//${host}/api/v1/resources/ws/${this.config.sessionId}`;
    
    const params = new URLSearchParams();
    if (this.config.token) {
      params.set('token', this.config.token);
    }
    if (this.config.namespace) {
      params.set('namespace', this.config.namespace);
    }
    if (this.config.resourceTypes?.length) {
      params.set('types', this.config.resourceTypes.join(','));
    }

    const queryString = params.toString();
    if (queryString) {
      url += `?${queryString}`;
    }

    return url;
  }

  private handleMessage(data: any): void {
    switch (data.type) {
      case 'resource_updated':
      case 'resource_created':
        if (data.resource) {
          // Convert timestamp strings back to Date objects
          const resource: ResourceStatus = {
            ...data.resource,
            lastUpdated: new Date(data.resource.lastUpdated)
          };
          this.emit({ type: data.type, resource });
        }
        break;

      case 'resource_deleted':
        if (data.resourceId) {
          this.emit({ type: 'resource_deleted', resourceId: data.resourceId });
        }
        break;

      case 'cluster_state_changed':
        this.emit({ 
          type: 'cluster_state_changed', 
          timestamp: data.timestamp || new Date().toISOString() 
        });
        break;

      case 'pong':
        // Heartbeat response - no action needed
        break;

      case 'error':
        this.emit({
          type: 'error',
          message: data.message || 'Unknown error',
          code: data.code
        });
        break;

      default:
        console.warn('Unknown WebSocket message type:', data.type);
    }
  }

  private emit(event: ResourceUpdateEvent): void {
    this.listeners.forEach(listener => {
      try {
        listener(event);
      } catch (error) {
        console.error('Error in WebSocket event listener:', error);
      }
    });
  }

  private handleReconnection(): void {
    if (this.reconnectAttempts >= (this.config.maxReconnectAttempts || 10)) {
      this.emit({ 
        type: 'error', 
        message: 'Maximum reconnection attempts reached',
        code: 'MAX_RECONNECT_EXCEEDED'
      });
      return;
    }

    this.emit({ type: 'connection_status', status: 'reconnecting' });
    
    this.reconnectTimer = setTimeout(() => {
      this.reconnectAttempts++;
      this.connect().catch((error) => {
        console.error('Reconnection failed:', error);
      });
    }, this.config.reconnectInterval);
  }

  private clearReconnectTimer(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  private startHeartbeat(): void {
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: 'ping' }));
      }
    }, 30000); // Send ping every 30 seconds
  }

  private stopHeartbeat(): void {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }
}

/**
 * Factory function for creating resource monitoring service
 */
export function createResourceMonitoringService(
  config: ResourceMonitoringConfig
): ResourceMonitoringService {
  return new ResourceMonitoringService(config);
}

/**
 * Singleton instance for application use
 */
let _resourceMonitoringInstance: ResourceMonitoringService | null = null;

export const resourceMonitoring = {
  initialize(config: ResourceMonitoringConfig) {
    if (_resourceMonitoringInstance) {
      _resourceMonitoringInstance.disconnect();
    }
    _resourceMonitoringInstance = createResourceMonitoringService(config);
    return _resourceMonitoringInstance;
  },

  get instance() {
    if (!_resourceMonitoringInstance) {
      throw new Error('Resource monitoring service not initialized. Call initialize() first.');
    }
    return _resourceMonitoringInstance;
  },

  connect: () => resourceMonitoring.instance.connect(),
  disconnect: () => resourceMonitoring.instance.disconnect(),
  subscribe: (listener: (event: ResourceUpdateEvent) => void) => 
    resourceMonitoring.instance.subscribe(listener),
  monitorResource: (kind: string, name: string, namespace?: string) => 
    resourceMonitoring.instance.monitorResource(kind, name, namespace),
  unmonitorResource: (kind: string, name: string, namespace?: string) => 
    resourceMonitoring.instance.unmonitorResource(kind, name, namespace),
  isConnected: () => resourceMonitoring.instance.isConnected,
  connectionState: () => resourceMonitoring.instance.connectionState,
};