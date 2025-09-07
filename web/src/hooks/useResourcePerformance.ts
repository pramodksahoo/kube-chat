/**
 * Performance optimization hook for resource rendering
 * Provides virtualization, memoization, and batch processing utilities
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useDashboardStore } from '../store/dashboardStore';
import type { ResourceStatus } from '../services/kubernetesApi';

export interface VirtualizedRange {
  startIndex: number;
  endIndex: number;
  visibleItems: ResourceStatus[];
}

export interface PerformanceHookOptions {
  itemHeight?: number;
  containerHeight?: number;
  overscan?: number;
  batchSize?: number;
  debounceMs?: number;
}

export interface PerformanceMetrics {
  renderTime: number;
  itemsRendered: number;
  totalItems: number;
  virtualizedEnabled: boolean;
}

export function useResourcePerformance(options: PerformanceHookOptions = {}) {
  const {
    itemHeight = 120,
    containerHeight = 600,
    overscan = 5,
    batchSize = 50,
    debounceMs = 100,
  } = options;

  const filteredResources = useDashboardStore(state => state.filteredResources);
  const updateMetrics = useDashboardStore(state => state.updateMetrics);
  
  const [scrollTop, setScrollTop] = useState(0);
  const [isScrolling, setIsScrolling] = useState(false);
  const [renderMetrics, setRenderMetrics] = useState<PerformanceMetrics>({
    renderTime: 0,
    itemsRendered: 0,
    totalItems: 0,
    virtualizedEnabled: false,
  });

  const scrollTimeoutRef = useRef<NodeJS.Timeout | undefined>(undefined);
  const renderStartTime = useRef<number | undefined>(undefined);

  // Determine if virtualization should be enabled
  const shouldVirtualize = filteredResources.length > 100;

  // Calculate visible range for virtualization
  const virtualizedRange = useMemo((): VirtualizedRange => {
    if (!shouldVirtualize) {
      return {
        startIndex: 0,
        endIndex: filteredResources.length - 1,
        visibleItems: filteredResources,
      };
    }

    const visibleCount = Math.ceil(containerHeight / itemHeight);
    const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
    const endIndex = Math.min(
      filteredResources.length - 1,
      startIndex + visibleCount + overscan * 2
    );

    const visibleItems = filteredResources.slice(startIndex, endIndex + 1);

    return {
      startIndex,
      endIndex,
      visibleItems,
    };
  }, [filteredResources, containerHeight, itemHeight, scrollTop, overscan, shouldVirtualize]);

  // Batch processing for large datasets
  const [processedBatches, setProcessedBatches] = useState<Set<number>>(new Set());
  const [currentBatch, setCurrentBatch] = useState(0);

  const processBatch = useCallback((batchIndex: number) => {
    if (processedBatches.has(batchIndex)) return;

    // Simulate batch processing (e.g., enriching data, computing derived values)
    setTimeout(() => {
      setProcessedBatches(prev => new Set(prev).add(batchIndex));
    }, 10);
  }, [processedBatches]);

  useEffect(() => {
    if (shouldVirtualize) {
      const batchIndex = Math.floor(virtualizedRange.startIndex / batchSize);
      if (batchIndex !== currentBatch) {
        setCurrentBatch(batchIndex);
        processBatch(batchIndex);
        
        // Preload next batch
        processBatch(batchIndex + 1);
      }
    }
  }, [virtualizedRange.startIndex, batchSize, currentBatch, processBatch, shouldVirtualize]);

  // Scroll handling with debouncing
  const handleScroll = useCallback((event: React.UIEvent<HTMLDivElement>) => {
    const element = event.currentTarget;
    const newScrollTop = element.scrollTop;

    setScrollTop(newScrollTop);
    setIsScrolling(true);

    // Clear existing timeout
    if (scrollTimeoutRef.current) {
      clearTimeout(scrollTimeoutRef.current);
    }

    // Debounce scroll end detection
    scrollTimeoutRef.current = setTimeout(() => {
      setIsScrolling(false);
    }, debounceMs);
  }, [debounceMs]);

  // Performance tracking
  const startRender = useCallback(() => {
    renderStartTime.current = performance.now();
  }, []);

  const endRender = useCallback(() => {
    if (renderStartTime.current) {
      const renderTime = performance.now() - renderStartTime.current;
      
      const metrics: PerformanceMetrics = {
        renderTime,
        itemsRendered: virtualizedRange.visibleItems.length,
        totalItems: filteredResources.length,
        virtualizedEnabled: shouldVirtualize,
      };

      setRenderMetrics(metrics);
      
      // Update global metrics
      updateMetrics({
        lastRenderDuration: renderTime,
        totalResources: filteredResources.length,
        filteredResources: filteredResources.length,
      });
    }
  }, [virtualizedRange.visibleItems.length, filteredResources.length, shouldVirtualize, updateMetrics]);

  // Memoized resource processing
  const memoizedResources = useMemo(() => {
    startRender();
    
    const processed = virtualizedRange.visibleItems.map(resource => ({
      ...resource,
      // Add computed properties for performance
      displayName: `${resource.kind}/${resource.name}`,
      sortKey: `${resource.namespace || 'cluster'}-${resource.kind}-${resource.name}`,
      statusColor: getStatusColor(resource.status),
      lastUpdatedFormatted: formatRelativeTime(resource.lastUpdated),
    }));

    // Defer end render to next tick
    setTimeout(endRender, 0);

    return processed;
  }, [virtualizedRange.visibleItems, startRender, endRender]);

  // Cleanup
  useEffect(() => {
    return () => {
      if (scrollTimeoutRef.current) {
        clearTimeout(scrollTimeoutRef.current);
      }
    };
  }, []);

  // Virtual scroll container props
  const containerProps = {
    onScroll: handleScroll,
    style: {
      height: containerHeight,
      overflowY: 'auto' as const,
      position: 'relative' as const,
    },
  };

  // Virtual content props
  const contentProps = shouldVirtualize ? {
    style: {
      height: filteredResources.length * itemHeight,
      paddingTop: virtualizedRange.startIndex * itemHeight,
    },
  } : {};

  return {
    // Virtualized data
    virtualizedRange,
    resources: memoizedResources,
    shouldVirtualize,
    
    // Scroll handling
    containerProps,
    contentProps,
    isScrolling,
    
    // Performance metrics
    metrics: renderMetrics,
    
    // Batch processing status
    currentBatch,
    processedBatches: processedBatches.size,
    totalBatches: Math.ceil(filteredResources.length / batchSize),
  };
}

// Utility functions
function getStatusColor(status: string): string {
  const colorMap: Record<string, string> = {
    'Ready': '#10B981', // green-500
    'Warning': '#F59E0B', // amber-500
    'Error': '#EF4444', // red-500
    'Pending': '#8B5CF6', // violet-500
    'Unknown': '#6B7280', // gray-500
  };
  return colorMap[status] || '#6B7280';
}

function formatRelativeTime(date: Date): string {
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMinutes = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  if (diffMinutes < 1) return 'just now';
  if (diffMinutes < 60) return `${diffMinutes}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  return `${diffDays}d ago`;
}

// Hook for optimized resource filtering
export function useOptimizedFiltering(resources: ResourceStatus[]) {
  const filters = useDashboardStore(state => state.filters);
  const viewSettings = useDashboardStore(state => state.viewSettings);

  return useMemo(() => {
    const startTime = performance.now();
    
    // Apply filters
    const filtered = resources.filter(resource => {
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
      
      // Search term
      if (filters.searchTerm) {
        const searchLower = filters.searchTerm.toLowerCase();
        const matchesName = resource.name.toLowerCase().includes(searchLower);
        const matchesKind = resource.kind.toLowerCase().includes(searchLower);
        const matchesNamespace = resource.namespace?.toLowerCase().includes(searchLower);
        
        if (!matchesName && !matchesKind && !matchesNamespace) {
          return false;
        }
      }
      
      return true;
    });

    // Apply sorting
    filtered.sort((a, b) => {
      let comparison = 0;
      
      switch (viewSettings.sortBy) {
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
      }
      
      return viewSettings.sortOrder === 'asc' ? comparison : -comparison;
    });

    const filterTime = performance.now() - startTime;
    
    console.debug(`Filtered ${filtered.length}/${resources.length} resources in ${filterTime.toFixed(2)}ms`);

    return filtered;
  }, [resources, filters, viewSettings]);
}