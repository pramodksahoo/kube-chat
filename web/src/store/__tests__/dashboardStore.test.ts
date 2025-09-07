/**
 * Tests for Dashboard Store
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { useDashboardStore } from '../dashboardStore';
import type { ResourceStatus } from '../../services/kubernetesApi';

// Mock localStorage
const mockLocalStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};
Object.defineProperty(window, 'localStorage', { value: mockLocalStorage });

describe('Dashboard Store', () => {
  const mockResources: ResourceStatus[] = [
    {
      kind: 'Pod',
      name: 'web-pod-1',
      namespace: 'production',
      status: 'Ready',
      lastUpdated: new Date('2023-01-01T10:00:00Z'),
      metadata: { labels: { app: 'web' } },
      relationships: [],
    },
    {
      kind: 'Service',
      name: 'web-service',
      namespace: 'production',
      status: 'Warning',
      lastUpdated: new Date('2023-01-01T09:00:00Z'),
      metadata: { labels: { app: 'web' } },
      relationships: [],
    },
    {
      kind: 'Pod',
      name: 'api-pod-1',
      namespace: 'staging',
      status: 'Ready',
      lastUpdated: new Date('2023-01-01T11:00:00Z'),
      metadata: { labels: { app: 'api' } },
      relationships: [],
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    // Reset store state
    useDashboardStore.setState({
      resources: [],
      selectedResource: null,
      loading: false,
      error: null,
      cache: new Map(),
      filters: {
        namespace: '',
        status: '',
        kind: '',
        labelSelector: '',
        searchTerm: '',
      },
      viewSettings: {
        viewMode: 'cards',
        groupBy: 'namespace',
        sortBy: 'name',
        sortOrder: 'asc',
        density: 'comfortable',
        showMetadata: true,
        autoRefresh: true,
        refreshInterval: 30000,
      },
      metrics: {
        lastFetchDuration: 0,
        lastRenderDuration: 0,
        totalResources: 0,
        filteredResources: 0,
        websocketConnected: false,
      },
      sidebarCollapsed: false,
      modalOpen: false,
      filteredResources: [],
      groupedResources: {},
      namespaces: [],
      resourceKinds: [],
      statusCounts: {},
    });
  });

  describe('Resource Management', () => {
    it('should set resources and update derived state', () => {
      const { setResources } = useDashboardStore.getState();
      
      setResources(mockResources);
      
      const state = useDashboardStore.getState();
      expect(state.resources).toEqual(mockResources);
      expect(state.filteredResources).toHaveLength(3);
      expect(state.namespaces).toEqual(['production', 'staging']);
      expect(state.resourceKinds).toEqual(['Pod', 'Service']);
      expect(state.statusCounts).toEqual({ Ready: 2, Warning: 1 });
      expect(state.metrics.totalResources).toBe(3);
    });

    it('should update individual resources', () => {
      const { setResources, updateResource } = useDashboardStore.getState();
      
      setResources(mockResources);
      
      const updatedResource = {
        ...mockResources[0],
        status: 'Error' as const,
        lastUpdated: new Date('2023-01-01T12:00:00Z'),
      };
      
      updateResource(updatedResource);
      
      const state = useDashboardStore.getState();
      expect(state.resources[0]).toEqual(updatedResource);
      expect(state.statusCounts).toEqual({ Ready: 1, Warning: 1, Error: 1 });
    });

    it('should add new resource when updating non-existent resource', () => {
      const { setResources, updateResource } = useDashboardStore.getState();
      
      setResources(mockResources);
      
      const newResource: ResourceStatus = {
        kind: 'Deployment',
        name: 'new-deployment',
        namespace: 'default',
        status: 'Ready',
        lastUpdated: new Date('2023-01-01T12:00:00Z'),
        metadata: {},
        relationships: [],
      };
      
      updateResource(newResource);
      
      const state = useDashboardStore.getState();
      expect(state.resources).toHaveLength(4);
      expect(state.resources[3]).toEqual(newResource);
    });

    it('should remove resources', () => {
      const { setResources, removeResource } = useDashboardStore.getState();
      
      setResources(mockResources);
      
      removeResource('Pod', 'web-pod-1', 'production');
      
      const state = useDashboardStore.getState();
      expect(state.resources).toHaveLength(2);
      expect(state.resources.find(r => r.name === 'web-pod-1')).toBeUndefined();
    });

    it('should clear selected resource when removing it', () => {
      const { setResources, selectResource, removeResource } = useDashboardStore.getState();
      
      setResources(mockResources);
      selectResource(mockResources[0]);
      
      expect(useDashboardStore.getState().selectedResource?.resource).toEqual(mockResources[0]);
      
      removeResource('Pod', 'web-pod-1', 'production');
      
      const state = useDashboardStore.getState();
      expect(state.selectedResource).toBeNull();
      expect(state.modalOpen).toBe(false);
    });
  });

  describe('Resource Selection', () => {
    it('should select resource and open modal', () => {
      const { selectResource } = useDashboardStore.getState();
      
      selectResource(mockResources[0], 'logs');
      
      const state = useDashboardStore.getState();
      expect(state.selectedResource?.resource).toEqual(mockResources[0]);
      expect(state.selectedResource?.tab).toBe('logs');
      expect(state.modalOpen).toBe(true);
    });

    it('should clear selection and close modal', () => {
      const { selectResource } = useDashboardStore.getState();
      
      selectResource(mockResources[0]);
      expect(useDashboardStore.getState().selectedResource).toBeTruthy();
      
      selectResource(null);
      
      const state = useDashboardStore.getState();
      expect(state.selectedResource).toBeNull();
      expect(state.modalOpen).toBe(false);
    });

    it('should default to describe tab', () => {
      const { selectResource } = useDashboardStore.getState();
      
      selectResource(mockResources[0]);
      
      const state = useDashboardStore.getState();
      expect(state.selectedResource?.tab).toBe('describe');
    });
  });

  describe('Filtering', () => {
    beforeEach(() => {
      const { setResources } = useDashboardStore.getState();
      setResources(mockResources);
    });

    it('should filter by namespace', () => {
      const { setFilter } = useDashboardStore.getState();
      
      setFilter('namespace', 'production');
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(2);
      expect(state.filteredResources.every(r => r.namespace === 'production')).toBe(true);
    });

    it('should filter by status', () => {
      const { setFilter } = useDashboardStore.getState();
      
      setFilter('status', 'Ready');
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(2);
      expect(state.filteredResources.every(r => r.status === 'Ready')).toBe(true);
    });

    it('should filter by kind', () => {
      const { setFilter } = useDashboardStore.getState();
      
      setFilter('kind', 'Pod');
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(2);
      expect(state.filteredResources.every(r => r.kind === 'Pod')).toBe(true);
    });

    it('should filter by search term', () => {
      const { setFilter } = useDashboardStore.getState();
      
      setFilter('searchTerm', 'web');
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(2);
      expect(state.filteredResources.every(r => 
        r.name.includes('web') || r.metadata.labels?.app === 'web'
      )).toBe(true);
    });

    it('should filter by label selector', () => {
      const { setFilter } = useDashboardStore.getState();
      
      setFilter('labelSelector', 'app=web');
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(2);
      expect(state.filteredResources.every(r => r.metadata.labels?.app === 'web')).toBe(true);
    });

    it('should reset all filters', () => {
      const { setFilter, resetFilters } = useDashboardStore.getState();
      
      setFilter('namespace', 'production');
      setFilter('status', 'Ready');
      expect(useDashboardStore.getState().filteredResources).toHaveLength(1);
      
      resetFilters();
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(3);
      expect(state.filters).toEqual({
        namespace: '',
        status: '',
        kind: '',
        labelSelector: '',
        searchTerm: '',
      });
    });

    it('should combine multiple filters', () => {
      const { setFilter } = useDashboardStore.getState();
      
      setFilter('namespace', 'production');
      setFilter('status', 'Ready');
      
      const state = useDashboardStore.getState();
      expect(state.filteredResources).toHaveLength(1);
      expect(state.filteredResources[0].name).toBe('web-pod-1');
    });
  });

  describe('View Settings', () => {
    beforeEach(() => {
      const { setResources } = useDashboardStore.getState();
      setResources(mockResources);
    });

    it('should change view mode', () => {
      const { setViewSetting } = useDashboardStore.getState();
      
      setViewSetting('viewMode', 'table');
      
      const state = useDashboardStore.getState();
      expect(state.viewSettings.viewMode).toBe('table');
    });

    it('should change sort order and update resources', () => {
      const { setViewSetting } = useDashboardStore.getState();
      
      setViewSetting('sortBy', 'lastUpdated');
      setViewSetting('sortOrder', 'desc');
      
      const state = useDashboardStore.getState();
      expect(state.viewSettings.sortBy).toBe('lastUpdated');
      expect(state.viewSettings.sortOrder).toBe('desc');
      
      // Should be sorted by lastUpdated desc (newest first)
      expect(state.filteredResources[0].name).toBe('api-pod-1');
      expect(state.filteredResources[2].name).toBe('web-service');
    });

    it('should change grouping and update grouped resources', () => {
      const { setViewSetting } = useDashboardStore.getState();
      
      setViewSetting('groupBy', 'kind');
      
      const state = useDashboardStore.getState();
      expect(state.viewSettings.groupBy).toBe('kind');
      expect(state.groupedResources).toHaveProperty('Pod');
      expect(state.groupedResources).toHaveProperty('Service');
      expect(state.groupedResources.Pod).toHaveLength(2);
      expect(state.groupedResources.Service).toHaveLength(1);
    });

    it('should reset view settings', () => {
      const { setViewSetting, resetViewSettings } = useDashboardStore.getState();
      
      setViewSetting('viewMode', 'table');
      setViewSetting('sortBy', 'status');
      
      resetViewSettings();
      
      const state = useDashboardStore.getState();
      expect(state.viewSettings.viewMode).toBe('cards');
      expect(state.viewSettings.sortBy).toBe('name');
    });
  });

  describe('Cache Management', () => {
    it('should set and get cache data', () => {
      const { setCacheData, getCacheData } = useDashboardStore.getState();
      
      setCacheData('test-key', mockResources, 'etag-123');
      
      const cached = getCacheData('test-key');
      expect(cached).toBeTruthy();
      expect(cached?.data).toEqual(mockResources);
      expect(cached?.etag).toBe('etag-123');
    });

    it('should return null for expired cache', () => {
      const { setCacheData, getCacheData } = useDashboardStore.getState();
      
      // Set cache expiry to 0 to make it immediately expired
      useDashboardStore.setState({ cacheExpiry: 0 });
      
      setCacheData('test-key', mockResources);
      
      // Wait a bit to ensure expiry
      setTimeout(() => {
        const cached = getCacheData('test-key');
        expect(cached).toBeNull();
      }, 10);
    });

    it('should clear cache', () => {
      const { setCacheData, getCacheData, clearCache } = useDashboardStore.getState();
      
      setCacheData('test-key', mockResources);
      expect(getCacheData('test-key')).toBeTruthy();
      
      clearCache();
      expect(getCacheData('test-key')).toBeNull();
    });
  });

  describe('UI State Management', () => {
    it('should toggle sidebar', () => {
      const { toggleSidebar } = useDashboardStore.getState();
      
      expect(useDashboardStore.getState().sidebarCollapsed).toBe(false);
      
      toggleSidebar();
      expect(useDashboardStore.getState().sidebarCollapsed).toBe(true);
      
      toggleSidebar();
      expect(useDashboardStore.getState().sidebarCollapsed).toBe(false);
    });

    it('should set modal open state', () => {
      const { setModalOpen, selectResource } = useDashboardStore.getState();
      
      // Select resource first
      selectResource(mockResources[0]);
      expect(useDashboardStore.getState().modalOpen).toBe(true);
      
      setModalOpen(false);
      
      const state = useDashboardStore.getState();
      expect(state.modalOpen).toBe(false);
      expect(state.selectedResource).toBeNull();
    });

    it('should set loading state', () => {
      const { setLoading } = useDashboardStore.getState();
      
      setLoading(true);
      expect(useDashboardStore.getState().loading).toBe(true);
      
      setLoading(false);
      expect(useDashboardStore.getState().loading).toBe(false);
    });

    it('should set error state', () => {
      const { setError } = useDashboardStore.getState();
      
      setError('Test error');
      expect(useDashboardStore.getState().error).toBe('Test error');
      
      setError(null);
      expect(useDashboardStore.getState().error).toBeNull();
    });
  });

  describe('Performance Metrics', () => {
    it('should update metrics', () => {
      const { updateMetrics } = useDashboardStore.getState();
      
      updateMetrics({
        lastFetchDuration: 150,
        websocketConnected: true,
        lastError: 'Connection timeout',
      });
      
      const state = useDashboardStore.getState();
      expect(state.metrics.lastFetchDuration).toBe(150);
      expect(state.metrics.websocketConnected).toBe(true);
      expect(state.metrics.lastError).toBe('Connection timeout');
    });
  });

  describe('Data Export', () => {
    it('should export data as JSON', () => {
      const { setResources, setFilter, exportData } = useDashboardStore.getState();
      
      setResources(mockResources);
      setFilter('namespace', 'production');
      
      const exported = exportData();
      const data = JSON.parse(exported);
      
      expect(data.resources.length).toBe(mockResources.length);
      expect(data.resources[0].name).toBe(mockResources[0].name);
      expect(data.filters.namespace).toBe('production');
      expect(data.viewSettings).toBeTruthy();
      expect(data.exportedAt).toBeTruthy();
    });
  });

  describe('Selector Hooks', () => {
    it('should provide selector hooks', async () => {
      // Test that all selector hooks are exported and callable
      const module = await import('../dashboardStore');
      
      expect(typeof module.useResources).toBe('function');
      expect(typeof module.useFilteredResources).toBe('function');
      expect(typeof module.useSelectedResource).toBe('function');
    });
  });

  describe('Grouping Logic', () => {
    beforeEach(() => {
      const { setResources } = useDashboardStore.getState();
      setResources(mockResources);
    });

    it('should group by namespace', () => {
      const { setViewSetting } = useDashboardStore.getState();
      
      setViewSetting('groupBy', 'namespace');
      
      const state = useDashboardStore.getState();
      expect(state.groupedResources).toHaveProperty('production');
      expect(state.groupedResources).toHaveProperty('staging');
      expect(state.groupedResources.production).toHaveLength(2);
      expect(state.groupedResources.staging).toHaveLength(1);
    });

    it('should group by status', () => {
      const { setViewSetting } = useDashboardStore.getState();
      
      setViewSetting('groupBy', 'status');
      
      const state = useDashboardStore.getState();
      expect(state.groupedResources).toHaveProperty('Ready');
      expect(state.groupedResources).toHaveProperty('Warning');
      expect(state.groupedResources.Ready).toHaveLength(2);
      expect(state.groupedResources.Warning).toHaveLength(1);
    });

    it('should group by none', () => {
      const { setViewSetting } = useDashboardStore.getState();
      
      setViewSetting('groupBy', 'none');
      
      const state = useDashboardStore.getState();
      expect(state.groupedResources).toHaveProperty('all');
      expect(state.groupedResources.all).toHaveLength(3);
    });
  });
});