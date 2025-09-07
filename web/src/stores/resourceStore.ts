/**
 * Resource Dashboard Store - Zustand state management
 * Manages resource data, filters, selections, and WebSocket connection state
 */

import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { ResourceStatus } from '../services/kubernetesApi';
import { 
  resourceMonitoring,
  ResourceMonitoringService,
  type ResourceUpdateEvent
} from '../services/resourceMonitoringService';

export interface ResourceFilters {
  namespace?: string;
  kind?: string;
  labelSelector?: string;
  status?: 'all' | 'ready' | 'warning' | 'error' | 'unknown';
  searchQuery?: string;
}

export interface ResourceSelection {
  resource: ResourceStatus | null;
  previousResource?: ResourceStatus | null;
  selectedAt?: Date;
}

export interface ConnectionState {
  isConnected: boolean;
  connectionError: string | null;
  reconnectAttempts: number;
  lastConnectedAt?: Date;
  lastDisconnectedAt?: Date;
}

export interface ResourceCache {
  data: ResourceStatus[];
  lastUpdated: Date;
  version: number;
  pendingUpdates: Record<string, ResourceStatus>;
}

export interface DashboardPreferences {
  autoRefresh: boolean;
  refreshInterval: number;
  defaultView: 'grid' | 'list' | 'topology';
  showNamespaces: boolean;
  compactView: boolean;
  groupByKind: boolean;
}

export interface ResourceStore {
  // Core resource data
  cache: ResourceCache;
  filters: ResourceFilters;
  selection: ResourceSelection;
  
  // Connection state
  connection: ConnectionState;
  
  // UI preferences
  preferences: DashboardPreferences;
  loading: boolean;
  error: string | null;
  
  // Monitoring service instance
  monitoringService: ResourceMonitoringService | null;
  
  // Actions - Resource Management
  setResources: (resources: ResourceStatus[]) => void;
  updateResource: (resource: ResourceStatus) => void;
  removeResource: (resourceId: string) => void;
  clearResources: () => void;
  refreshResources: () => Promise<void>;
  
  // Actions - Filtering and Search
  setFilters: (filters: Partial<ResourceFilters>) => void;
  clearFilters: () => void;
  setSearchQuery: (query: string) => void;
  
  // Actions - Selection Management
  selectResource: (resource: ResourceStatus | null) => void;
  clearSelection: () => void;
  
  // Actions - Connection Management
  initializeMonitoring: (sessionId: string, token?: string) => void;
  connectToMonitoring: () => Promise<void>;
  disconnectFromMonitoring: () => void;
  setConnectionState: (state: Partial<ConnectionState>) => void;
  
  // Actions - Preferences
  setPreferences: (preferences: Partial<DashboardPreferences>) => void;
  resetPreferences: () => void;
  
  // Actions - Error Management
  setError: (error: string | null) => void;
  setLoading: (loading: boolean) => void;
  
  // Computed getters
  getFilteredResources: () => ResourceStatus[];
  getResourceById: (id: string) => ResourceStatus | undefined;
  getResourcesByKind: () => Record<string, ResourceStatus[]>;
  getConnectionStatus: () => 'connected' | 'connecting' | 'disconnected' | 'error';
  getSummaryStatistics: () => {
    total: number;
    ready: number;
    warning: number;
    error: number;
    unknown: number;
  };
}

const defaultPreferences: DashboardPreferences = {
  autoRefresh: true,
  refreshInterval: 30000,
  defaultView: 'grid',
  showNamespaces: true,
  compactView: false,
  groupByKind: true,
};

const defaultConnectionState: ConnectionState = {
  isConnected: false,
  connectionError: null,
  reconnectAttempts: 0,
};

const defaultCache: ResourceCache = {
  data: [],
  lastUpdated: new Date(),
  version: 0,
  pendingUpdates: {},
};

export const useResourceStore = create<ResourceStore>()(
  subscribeWithSelector((set, get) => ({
    // Initial state
    cache: defaultCache,
    filters: {},
    selection: { resource: null },
    connection: defaultConnectionState,
    preferences: defaultPreferences,
    loading: false,
    error: null,
    monitoringService: null,

    // Resource Management Actions
    setResources: (resources: ResourceStatus[]) => {
      set((state) => ({
        cache: {
          ...state.cache,
          data: resources,
          lastUpdated: new Date(),
          version: state.cache.version + 1,
        },
        loading: false,
        error: null,
      }));
    },

    updateResource: (resource: ResourceStatus) => {
      set((state) => {
        const resourceId = `${resource.kind}/${resource.namespace || 'default'}/${resource.name}`;
        const updatedData = state.cache.data.map(r => {
          const rId = `${r.kind}/${r.namespace || 'default'}/${r.name}`;
          return rId === resourceId ? resource : r;
        });

        // If resource doesn't exist, add it
        if (!state.cache.data.find(r => {
          const rId = `${r.kind}/${r.namespace || 'default'}/${r.name}`;
          return rId === resourceId;
        })) {
          updatedData.push(resource);
        }

        return {
          cache: {
            ...state.cache,
            data: updatedData,
            lastUpdated: new Date(),
            version: state.cache.version + 1,
          },
        };
      });
    },

    removeResource: (resourceId: string) => {
      set((state) => ({
        cache: {
          ...state.cache,
          data: state.cache.data.filter(r => {
            const rId = `${r.kind}/${r.namespace || 'default'}/${r.name}`;
            return rId !== resourceId;
          }),
          lastUpdated: new Date(),
          version: state.cache.version + 1,
        },
      }));
    },

    clearResources: () => {
      set((state) => ({
        cache: {
          ...defaultCache,
          version: state.cache.version + 1,
        },
        selection: { resource: null },
      }));
    },

    refreshResources: async () => {
      const { kubernetesApi } = await import('../services/kubernetesApi');
      const { filters, setResources, setError, setLoading } = get();
      
      try {
        setLoading(true);
        const response = await kubernetesApi.listResources(filters);
        setResources(response.resources);
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Failed to refresh resources';
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    },

    // Filtering Actions
    setFilters: (newFilters: Partial<ResourceFilters>) => {
      set((state) => ({
        filters: { ...state.filters, ...newFilters },
      }));
    },

    clearFilters: () => {
      set(() => ({
        filters: {},
      }));
    },

    setSearchQuery: (query: string) => {
      set((state) => ({
        filters: { ...state.filters, searchQuery: query },
      }));
    },

    // Selection Management
    selectResource: (resource: ResourceStatus | null) => {
      set((state) => ({
        selection: {
          previousResource: state.selection.resource,
          resource,
          selectedAt: resource ? new Date() : undefined,
        },
      }));
    },

    clearSelection: () => {
      set(() => ({
        selection: { resource: null },
      }));
    },

    // Connection Management
    initializeMonitoring: (sessionId: string, token?: string) => {
      const service = resourceMonitoring.initialize({
        sessionId,
        token,
        reconnectInterval: 3000,
        maxReconnectAttempts: 10,
      });

      // Subscribe to monitoring events
      service.subscribe((event: ResourceUpdateEvent) => {
        const { updateResource, removeResource, setConnectionState, refreshResources } = get();

        switch (event.type) {
          case 'resource_updated':
          case 'resource_created':
            updateResource(event.resource);
            break;

          case 'resource_deleted':
            removeResource(event.resourceId);
            break;

          case 'cluster_state_changed':
            void refreshResources();
            break;

          case 'connection_status':
            setConnectionState({
              isConnected: event.status === 'connected',
              reconnectAttempts: event.status === 'connected' ? 0 : get().connection.reconnectAttempts + 1,
              lastConnectedAt: event.status === 'connected' ? new Date() : undefined,
              lastDisconnectedAt: event.status === 'disconnected' ? new Date() : undefined,
            });
            break;

          case 'error':
            setConnectionState({
              connectionError: event.message,
            });
            break;
        }
      });

      set(() => ({
        monitoringService: service,
      }));
    },

    connectToMonitoring: async () => {
      const { monitoringService } = get();
      if (!monitoringService) {
        throw new Error('Monitoring service not initialized');
      }

      try {
        await monitoringService.connect();
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Failed to connect to monitoring';
        set((state) => ({
          connection: {
            ...state.connection,
            connectionError: errorMessage,
            isConnected: false,
          },
        }));
        throw error;
      }
    },

    disconnectFromMonitoring: () => {
      const { monitoringService } = get();
      if (monitoringService) {
        monitoringService.disconnect();
      }
      set((state) => ({
        connection: {
          ...state.connection,
          isConnected: false,
          lastDisconnectedAt: new Date(),
        },
      }));
    },

    setConnectionState: (newState: Partial<ConnectionState>) => {
      set((state) => ({
        connection: { ...state.connection, ...newState },
      }));
    },

    // Preferences Management
    setPreferences: (newPreferences: Partial<DashboardPreferences>) => {
      set((state) => ({
        preferences: { ...state.preferences, ...newPreferences },
      }));
    },

    resetPreferences: () => {
      set(() => ({
        preferences: { ...defaultPreferences },
      }));
    },

    // Error Management
    setError: (error: string | null) => {
      set(() => ({ error }));
    },

    setLoading: (loading: boolean) => {
      set(() => ({ loading }));
    },

    // Computed Getters
    getFilteredResources: () => {
      const { cache, filters } = get();
      let filtered = cache.data;

      // Filter by status
      if (filters.status && filters.status !== 'all') {
        filtered = filtered.filter(r => 
          r.status.toLowerCase() === filters.status?.toLowerCase()
        );
      }

      // Filter by kind
      if (filters.kind) {
        filtered = filtered.filter(r => 
          r.kind.toLowerCase() === filters.kind?.toLowerCase()
        );
      }

      // Filter by namespace
      if (filters.namespace) {
        filtered = filtered.filter(r => r.namespace === filters.namespace);
      }

      // Filter by search query
      if (filters.searchQuery?.trim()) {
        const query = filters.searchQuery.toLowerCase().trim();
        filtered = filtered.filter(r =>
          r.name.toLowerCase().includes(query) ||
          r.kind.toLowerCase().includes(query) ||
          (r.namespace && r.namespace.toLowerCase().includes(query))
        );
      }

      return filtered;
    },

    getResourceById: (id: string) => {
      const { cache } = get();
      return cache.data.find(r => {
        const rId = `${r.kind}/${r.namespace || 'default'}/${r.name}`;
        return rId === id;
      });
    },

    getResourcesByKind: () => {
      const { getFilteredResources } = get();
      const resources = getFilteredResources();
      const grouped: Record<string, ResourceStatus[]> = {};

      resources.forEach(resource => {
        if (!grouped[resource.kind]) {
          grouped[resource.kind] = [];
        }
        grouped[resource.kind].push(resource);
      });

      return grouped;
    },

    getConnectionStatus: () => {
      const { connection, monitoringService } = get();
      
      if (!monitoringService) return 'disconnected';
      if (connection.connectionError) return 'error';
      if (connection.isConnected) return 'connected';
      if (connection.reconnectAttempts > 0) return 'connecting';
      return 'disconnected';
    },

    getSummaryStatistics: () => {
      const { getFilteredResources } = get();
      const resources = getFilteredResources();

      return {
        total: resources.length,
        ready: resources.filter(r => r.status === 'Ready').length,
        warning: resources.filter(r => r.status === 'Warning').length,
        error: resources.filter(r => r.status === 'Error').length,
        unknown: resources.filter(r => r.status === 'Unknown').length,
      };
    },
  }))
);

// Selectors for optimized component subscriptions
export const useResourceData = () => useResourceStore(state => state.cache.data);
export const useResourceFilters = () => useResourceStore(state => state.filters);
export const useResourceSelection = () => useResourceStore(state => state.selection);
export const useConnectionState = () => useResourceStore(state => state.connection);
export const useResourcePreferences = () => useResourceStore(state => state.preferences);
export const useResourceLoading = () => useResourceStore(state => state.loading);
export const useResourceError = () => useResourceStore(state => state.error);

// Computed selectors
export const useFilteredResources = () => useResourceStore(state => state.getFilteredResources());
export const useResourcesByKind = () => useResourceStore(state => state.getResourcesByKind());
export const useResourceSummary = () => useResourceStore(state => state.getSummaryStatistics());
export const useConnectionStatus = () => useResourceStore(state => state.getConnectionStatus());