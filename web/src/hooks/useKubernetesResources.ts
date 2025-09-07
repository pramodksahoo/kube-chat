/**
 * Custom hook for Kubernetes resource monitoring with WebSocket real-time updates
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { kubernetesApi, resourceChangeDetector, type ResourceStatus } from '../services/kubernetesApi';

export interface UseKubernetesResourcesOptions {
  namespace?: string;
  kind?: string;
  labelSelector?: string;
  autoRefresh?: boolean;
  refreshInterval?: number;
  sessionId?: string;
}

export interface UseKubernetesResourcesReturn {
  resources: ResourceStatus[];
  loading: boolean;
  error: string | null;
  refreshResources: () => Promise<void>;
  isConnected: boolean;
  connectionError: string | null;
}

/**
 * Hook for managing Kubernetes resources with real-time WebSocket updates
 */
export function useKubernetesResources(
  options: UseKubernetesResourcesOptions = {}
): UseKubernetesResourcesReturn {
  const [resources, setResources] = useState<ResourceStatus[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const refreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  const {
    namespace,
    kind,
    labelSelector,
    autoRefresh = true,
    refreshInterval = 30000, // 30 seconds
    sessionId = 'default',
  } = options;

  /**
   * Fetch resources from API
   */
  const refreshResources = useCallback(async (): Promise<void> => {
    try {
      setError(null);
      const response = await kubernetesApi.listResources({
        namespace,
        kind,
        labelSelector,
      });

      // Process resources and detect changes
      const processedResources = response.resources.map(resource => ({
        ...resource,
        lastUpdated: new Date(resource.lastUpdated),
      }));

      // Detect changes for notifications
      const changes = resourceChangeDetector.detectChanges(processedResources);
      
      // Log changes for debugging
      if (changes.added.length > 0 || changes.updated.length > 0 || changes.removed.length > 0) {
        console.log('Resource changes detected:', changes);
      }

      setResources(processedResources);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch resources';
      setError(errorMessage);
      console.error('Failed to fetch resources:', err);
    } finally {
      setLoading(false);
    }
  }, [namespace, kind, labelSelector]);

  /**
   * Handle WebSocket message
   */
  const handleWebSocketMessage = useCallback((event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data);
      
      switch (data.type) {
        case 'resource_updated':
          // Update specific resource in the list
          setResources(prev => {
            const updated = [...prev];
            const index = updated.findIndex(r => 
              r.kind === data.payload.kind &&
              r.name === data.payload.name &&
              r.namespace === data.payload.namespace
            );
            
            if (index !== -1) {
              updated[index] = {
                ...data.payload,
                lastUpdated: new Date(data.payload.lastUpdated),
              };
            }
            
            return updated;
          });
          break;

        case 'resource_created':
          // Add new resource to the list
          setResources(prev => [...prev, {
            ...data.payload,
            lastUpdated: new Date(data.payload.lastUpdated),
          }]);
          break;

        case 'resource_deleted':
          // Remove resource from the list
          setResources(prev => prev.filter(r =>
            !(r.kind === data.payload.kind &&
              r.name === data.payload.name &&
              r.namespace === data.payload.namespace)
          ));
          break;

        case 'cluster_state_changed':
          // Refresh all resources
          void refreshResources();
          break;

        default:
          console.log('Unknown WebSocket message type:', data.type);
      }
    } catch (err) {
      console.error('Failed to parse WebSocket message:', err);
    }
  }, [refreshResources]);

  /**
   * Setup WebSocket connection for real-time updates
   */
  const setupWebSocket = useCallback(() => {
    try {
      const token = localStorage.getItem('authToken');
      if (!token) {
        setConnectionError('Authentication token not found');
        return;
      }

      const wsUrl = `wss://${window.location.host}/api/v1/resources/${sessionId}?token=${token}`;
      const ws = new WebSocket(wsUrl);

      ws.onopen = () => {
        console.log('Resource WebSocket connected');
        setIsConnected(true);
        setConnectionError(null);
        
        // Clear any pending reconnect
        if (reconnectTimeoutRef.current) {
          clearTimeout(reconnectTimeoutRef.current);
          reconnectTimeoutRef.current = null;
        }
      };

      ws.onmessage = handleWebSocketMessage;

      ws.onclose = (event) => {
        console.log('Resource WebSocket disconnected:', event.code, event.reason);
        setIsConnected(false);
        
        // Attempt to reconnect after 3 seconds
        if (!reconnectTimeoutRef.current) {
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log('Attempting to reconnect WebSocket...');
            setupWebSocket();
          }, 3000);
        }
      };

      ws.onerror = (event) => {
        console.error('Resource WebSocket error:', event);
        setConnectionError('WebSocket connection error');
        setIsConnected(false);
      };

      wsRef.current = ws;
    } catch (err) {
      console.error('Failed to setup WebSocket:', err);
      setConnectionError(err instanceof Error ? err.message : 'WebSocket setup failed');
    }
  }, [sessionId, handleWebSocketMessage]);

  /**
   * Setup auto-refresh interval
   */
  const setupAutoRefresh = useCallback(() => {
    if (autoRefresh && refreshInterval > 0) {
      refreshIntervalRef.current = setInterval(() => void refreshResources(), refreshInterval);
    }
  }, [autoRefresh, refreshInterval, refreshResources]);

  /**
   * Initial data fetch and WebSocket setup
   */
  useEffect(() => {
    // Initial fetch
    void refreshResources();

    // Setup WebSocket for real-time updates
    setupWebSocket();

    // Setup auto-refresh
    setupAutoRefresh();

    return () => {
      // Cleanup WebSocket
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      // Cleanup timeouts and intervals
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }

      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
        refreshIntervalRef.current = null;
      }
    };
  }, [refreshResources, setupWebSocket, setupAutoRefresh]);

  // Refresh when filter options change
  useEffect(() => {
    if (!loading) {
      setLoading(true);
      void refreshResources();
    }
  }, [namespace, kind, labelSelector]);

  return {
    resources,
    loading,
    error,
    refreshResources,
    isConnected,
    connectionError,
  };
}

/**
 * Hook for monitoring a single resource
 */
export function useKubernetesResource(
  kind: string,
  name: string,
  namespace?: string,
  _sessionId?: string
) {
  const [resource, setResource] = useState<ResourceStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshResource = useCallback(async () => {
    try {
      setError(null);
      setLoading(true);
      
      const resourceData = await kubernetesApi.getResource(kind, name, namespace);
      setResource({
        ...resourceData,
        lastUpdated: new Date(resourceData.lastUpdated),
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch resource';
      setError(errorMessage);
      console.error('Failed to fetch resource:', err);
    } finally {
      setLoading(false);
    }
  }, [kind, name, namespace]);

  useEffect(() => {
    void refreshResource();
  }, [refreshResource]);

  return {
    resource,
    loading,
    error,
    refreshResource,
  };
}