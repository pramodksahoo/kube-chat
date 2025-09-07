/**
 * Dashboard Store - Zustand store for dashboard state management
 * Manages resource data, filters, caching, and performance optimization
 */

import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import { createJSONStorage, persist } from 'zustand/middleware';
import { enableMapSet } from 'immer';

// Enable MapSet plugin for Immer
enableMapSet();
import type { ResourceStatus } from '../services/kubernetesApi';

export interface DashboardFilters {
  namespace: string;
  status: string;
  kind: string;
  labelSelector: string;
  searchTerm: string;
}

export interface ViewSettings {
  viewMode: 'cards' | 'table' | 'topology';
  groupBy: 'namespace' | 'kind' | 'status' | 'none';
  sortBy: 'name' | 'status' | 'lastUpdated' | 'kind';
  sortOrder: 'asc' | 'desc';
  density: 'comfortable' | 'compact' | 'spacious';
  showMetadata: boolean;
  autoRefresh: boolean;
  refreshInterval: number;
}

export interface ResourceCache {
  data: ResourceStatus[];
  lastUpdated: Date;
  etag?: string;
}

export interface PerformanceMetrics {
  lastFetchDuration: number;
  lastRenderDuration: number;
  totalResources: number;
  filteredResources: number;
  websocketConnected: boolean;
  lastError?: string;
}

export interface SelectedResource {
  resource: ResourceStatus;
  tab: 'describe' | 'logs' | 'events';
}

export interface DashboardState {
  // Resource data
  resources: ResourceStatus[];
  selectedResource: SelectedResource | null;
  loading: boolean;
  error: string | null;
  
  // Cache management
  cache: Map<string, ResourceCache>;
  cacheExpiry: number; // milliseconds
  
  // Filters and view settings
  filters: DashboardFilters;
  viewSettings: ViewSettings;
  
  // Performance tracking
  metrics: PerformanceMetrics;
  
  // UI state
  sidebarCollapsed: boolean;
  modalOpen: boolean;
  
  // Computed derived state
  filteredResources: ResourceStatus[];
  groupedResources: Record<string, ResourceStatus[]>;
  namespaces: string[];
  resourceKinds: string[];
  statusCounts: Record<string, number>;
}

export interface DashboardActions {
  // Resource management
  setResources: (resources: ResourceStatus[]) => void;
  updateResource: (resource: ResourceStatus) => void;
  removeResource: (kind: string, name: string, namespace?: string) => void;
  selectResource: (resource: ResourceStatus | null, tab?: 'describe' | 'logs' | 'events') => void;
  
  // Filter management
  setFilter: <K extends keyof DashboardFilters>(key: K, value: DashboardFilters[K]) => void;
  resetFilters: () => void;
  
  // View settings
  setViewSetting: <K extends keyof ViewSettings>(key: K, value: ViewSettings[K]) => void;
  resetViewSettings: () => void;
  
  // Cache management
  setCacheData: (key: string, data: ResourceStatus[], etag?: string) => void;
  getCacheData: (key: string) => ResourceCache | null;
  clearCache: () => void;
  
  // Performance tracking
  updateMetrics: (metrics: Partial<PerformanceMetrics>) => void;
  
  // UI state
  toggleSidebar: () => void;
  setModalOpen: (open: boolean) => void;
  
  // Loading and error states
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  
  // Bulk operations
  refreshAll: () => Promise<void>;
  exportData: () => string;
}

// Default state values
const defaultFilters: DashboardFilters = {
  namespace: '',
  status: '',
  kind: '',
  labelSelector: '',
  searchTerm: '',
};

const defaultViewSettings: ViewSettings = {
  viewMode: 'cards',
  groupBy: 'namespace',
  sortBy: 'name',
  sortOrder: 'asc',
  density: 'comfortable',
  showMetadata: true,
  autoRefresh: true,
  refreshInterval: 30000, // 30 seconds
};

const defaultMetrics: PerformanceMetrics = {
  lastFetchDuration: 0,
  lastRenderDuration: 0,
  totalResources: 0,
  filteredResources: 0,
  websocketConnected: false,
};

// Utility functions
const filterResources = (resources: ResourceStatus[], filters: DashboardFilters): ResourceStatus[] => {
  return resources.filter(resource => {
    // Namespace filter
    if (filters.namespace && resource.namespace !== filters.namespace) {
      return false;
    }
    
    // Status filter
    if (filters.status && resource.status !== filters.status) {
      return false;
    }
    
    // Kind filter
    if (filters.kind && resource.kind !== filters.kind) {
      return false;
    }
    
    // Search term (matches name, kind, namespace, or labels)
    if (filters.searchTerm) {
      const searchLower = filters.searchTerm.toLowerCase();
      const matchesName = resource.name.toLowerCase().includes(searchLower);
      const matchesKind = resource.kind.toLowerCase().includes(searchLower);
      const matchesNamespace = resource.namespace?.toLowerCase().includes(searchLower);
      const matchesLabels = Object.entries(resource.metadata?.labels || {})
        .some(([key, value]) => 
          key.toLowerCase().includes(searchLower) || 
          String(value).toLowerCase().includes(searchLower)
        );
      
      if (!matchesName && !matchesKind && !matchesNamespace && !matchesLabels) {
        return false;
      }
    }
    
    // Label selector (basic key=value format)
    if (filters.labelSelector) {
      const labels = resource.metadata?.labels || {};
      const selectors = filters.labelSelector.split(',');
      
      for (const selector of selectors) {
        const [key, value] = selector.trim().split('=');
        if (!labels[key] || (value && String(labels[key]) !== value)) {
          return false;
        }
      }
    }
    
    return true;
  });
};

const sortResources = (resources: ResourceStatus[], sortBy: ViewSettings['sortBy'], sortOrder: ViewSettings['sortOrder']): ResourceStatus[] => {
  return [...resources].sort((a, b) => {
    let comparison = 0;
    
    switch (sortBy) {
      case 'name':
        comparison = a.name.localeCompare(b.name);
        break;
      case 'kind':
        comparison = a.kind.localeCompare(b.kind);
        break;
      case 'status':
        comparison = a.status.localeCompare(b.status);
        break;
      case 'lastUpdated':
        comparison = a.lastUpdated.getTime() - b.lastUpdated.getTime();
        break;
      default:
        comparison = 0;
    }
    
    return sortOrder === 'asc' ? comparison : -comparison;
  });
};

const groupResources = (resources: ResourceStatus[], groupBy: ViewSettings['groupBy']): Record<string, ResourceStatus[]> => {
  if (groupBy === 'none') {
    return { all: resources };
  }
  
  return resources.reduce((groups, resource) => {
    let key: string;
    
    switch (groupBy) {
      case 'namespace':
        key = resource.namespace || 'cluster-scoped';
        break;
      case 'kind':
        key = resource.kind;
        break;
      case 'status':
        key = resource.status;
        break;
      default:
        key = 'all';
    }
    
    if (!groups[key]) {
      groups[key] = [];
    }
    groups[key].push(resource);
    
    return groups;
  }, {} as Record<string, ResourceStatus[]>);
};

const getUniqueNamespaces = (resources: ResourceStatus[]): string[] => {
  const namespaces = new Set<string>();
  resources.forEach(resource => {
    if (resource.namespace) {
      namespaces.add(resource.namespace);
    }
  });
  return Array.from(namespaces).sort();
};

const getUniqueKinds = (resources: ResourceStatus[]): string[] => {
  const kinds = new Set<string>();
  resources.forEach(resource => {
    kinds.add(resource.kind);
  });
  return Array.from(kinds).sort();
};

const getStatusCounts = (resources: ResourceStatus[]): Record<string, number> => {
  return resources.reduce((counts, resource) => {
    counts[resource.status] = (counts[resource.status] || 0) + 1;
    return counts;
  }, {} as Record<string, number>);
};

// Zustand store with middleware
export const useDashboardStore = create<DashboardState & DashboardActions>()(
  persist(
    subscribeWithSelector(
      immer((set, get) => ({
        // Initial state
        resources: [],
        selectedResource: null,
        loading: false,
        error: null,
        cache: new Map(),
        cacheExpiry: 5 * 60 * 1000, // 5 minutes
        filters: defaultFilters,
        viewSettings: defaultViewSettings,
        metrics: defaultMetrics,
        sidebarCollapsed: false,
        modalOpen: false,
        
        // Computed derived state (will be updated by selectors)
        filteredResources: [],
        groupedResources: {},
        namespaces: [],
        resourceKinds: [],
        statusCounts: {},
        
        // Actions
        setResources: (resources) => set((state) => {
          state.resources = resources;
          
          // Update derived state
          const filtered = filterResources(resources, state.filters);
          const sorted = sortResources(filtered, state.viewSettings.sortBy, state.viewSettings.sortOrder);
          
          state.filteredResources = sorted;
          state.groupedResources = groupResources(sorted, state.viewSettings.groupBy);
          state.namespaces = getUniqueNamespaces(resources);
          state.resourceKinds = getUniqueKinds(resources);
          state.statusCounts = getStatusCounts(resources);
          
          // Update metrics
          state.metrics.totalResources = resources.length;
          state.metrics.filteredResources = filtered.length;
        }),
        
        updateResource: (resource) => set((state) => {
          const index = state.resources.findIndex(r => 
            r.kind === resource.kind && 
            r.name === resource.name && 
            r.namespace === resource.namespace
          );
          
          if (index >= 0) {
            state.resources[index] = resource;
          } else {
            state.resources.push(resource);
          }
          
          // Recompute derived state
          const filtered = filterResources(state.resources, state.filters);
          const sorted = sortResources(filtered, state.viewSettings.sortBy, state.viewSettings.sortOrder);
          
          state.filteredResources = sorted;
          state.groupedResources = groupResources(sorted, state.viewSettings.groupBy);
          state.namespaces = getUniqueNamespaces(state.resources);
          state.resourceKinds = getUniqueKinds(state.resources);
          state.statusCounts = getStatusCounts(state.resources);
        }),
        
        removeResource: (kind, name, namespace) => set((state) => {
          state.resources = state.resources.filter(r => 
            !(r.kind === kind && r.name === name && r.namespace === namespace)
          );
          
          // Clear selection if removed resource was selected
          if (state.selectedResource && 
              state.selectedResource.resource.kind === kind &&
              state.selectedResource.resource.name === name &&
              state.selectedResource.resource.namespace === namespace) {
            state.selectedResource = null;
            state.modalOpen = false;
          }
          
          // Recompute derived state
          const filtered = filterResources(state.resources, state.filters);
          const sorted = sortResources(filtered, state.viewSettings.sortBy, state.viewSettings.sortOrder);
          
          state.filteredResources = sorted;
          state.groupedResources = groupResources(sorted, state.viewSettings.groupBy);
          state.namespaces = getUniqueNamespaces(state.resources);
          state.resourceKinds = getUniqueKinds(state.resources);
          state.statusCounts = getStatusCounts(state.resources);
        }),
        
        selectResource: (resource, tab = 'describe') => set((state) => {
          state.selectedResource = resource ? { resource, tab } : null;
          state.modalOpen = !!resource;
        }),
        
        setFilter: (key, value) => set((state) => {
          state.filters[key] = value;
          
          // Recompute filtered results
          const filtered = filterResources(state.resources, state.filters);
          const sorted = sortResources(filtered, state.viewSettings.sortBy, state.viewSettings.sortOrder);
          
          state.filteredResources = sorted;
          state.groupedResources = groupResources(sorted, state.viewSettings.groupBy);
          state.metrics.filteredResources = filtered.length;
        }),
        
        resetFilters: () => set((state) => {
          state.filters = { ...defaultFilters };
          
          // Recompute with no filters
          const sorted = sortResources(state.resources, state.viewSettings.sortBy, state.viewSettings.sortOrder);
          
          state.filteredResources = sorted;
          state.groupedResources = groupResources(sorted, state.viewSettings.groupBy);
          state.metrics.filteredResources = state.resources.length;
        }),
        
        setViewSetting: (key, value) => set((state) => {
          state.viewSettings[key] = value;
          
          // Recompute if sort or group settings changed
          if (key === 'sortBy' || key === 'sortOrder') {
            const sorted = sortResources(state.filteredResources, state.viewSettings.sortBy, state.viewSettings.sortOrder);
            state.filteredResources = sorted;
            state.groupedResources = groupResources(sorted, state.viewSettings.groupBy);
          } else if (key === 'groupBy') {
            state.groupedResources = groupResources(state.filteredResources, state.viewSettings.groupBy);
          }
        }),
        
        resetViewSettings: () => set((state) => {
          state.viewSettings = { ...defaultViewSettings };
          
          // Recompute with default settings
          const sorted = sortResources(state.filteredResources, defaultViewSettings.sortBy, defaultViewSettings.sortOrder);
          state.filteredResources = sorted;
          state.groupedResources = groupResources(sorted, defaultViewSettings.groupBy);
        }),
        
        setCacheData: (key, data, etag) => set((state) => {
          state.cache.set(key, {
            data,
            lastUpdated: new Date(),
            etag,
          });
        }),
        
        getCacheData: (key) => {
          const state = get();
          const cached = state.cache.get(key);
          
          if (!cached) return null;
          
          // Check if cache is expired
          const age = Date.now() - cached.lastUpdated.getTime();
          if (age > state.cacheExpiry) {
            state.cache.delete(key);
            return null;
          }
          
          return cached;
        },
        
        clearCache: () => set((state) => {
          state.cache.clear();
        }),
        
        updateMetrics: (metrics) => set((state) => {
          state.metrics = { ...state.metrics, ...metrics };
        }),
        
        toggleSidebar: () => set((state) => {
          state.sidebarCollapsed = !state.sidebarCollapsed;
        }),
        
        setModalOpen: (open) => set((state) => {
          state.modalOpen = open;
          if (!open) {
            state.selectedResource = null;
          }
        }),
        
        setLoading: (loading) => set((state) => {
          state.loading = loading;
        }),
        
        setError: (error) => set((state) => {
          state.error = error;
        }),
        
        refreshAll: async () => {
          const state = get();
          state.setLoading(true);
          state.setError(null);
          
          try {
            // Clear cache to force fresh data
            state.clearCache();
            
            // This would be implemented by the consuming component
            // to trigger a fresh API call
            // Dashboard refresh triggered
          } catch (error) {
            state.setError(error instanceof Error ? error.message : 'Failed to refresh');
          } finally {
            state.setLoading(false);
          }
        },
        
        exportData: () => {
          const state = get();
          const exportData = {
            resources: state.resources,
            filters: state.filters,
            viewSettings: state.viewSettings,
            exportedAt: new Date().toISOString(),
          };
          
          return JSON.stringify(exportData, null, 2);
        },
      }))
    ),
    {
      name: 'dashboard-storage',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        filters: state.filters,
        viewSettings: state.viewSettings,
        sidebarCollapsed: state.sidebarCollapsed,
      }),
    }
  )
);

// Selector hooks for optimized subscriptions
export const useResources = () => useDashboardStore(state => state.resources);
export const useFilteredResources = () => useDashboardStore(state => state.filteredResources);
export const useGroupedResources = () => useDashboardStore(state => state.groupedResources);
export const useSelectedResource = () => useDashboardStore(state => state.selectedResource);
export const useDashboardFilters = () => useDashboardStore(state => state.filters);
export const useViewSettings = () => useDashboardStore(state => state.viewSettings);
export const useDashboardMetrics = () => useDashboardStore(state => state.metrics);
export const useDashboardLoading = () => useDashboardStore(state => state.loading);
export const useDashboardError = () => useDashboardStore(state => state.error);