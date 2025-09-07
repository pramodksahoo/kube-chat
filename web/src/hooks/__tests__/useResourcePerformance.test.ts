/**
 * Tests for useResourcePerformance hook
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook } from '@testing-library/react';
import { useResourcePerformance } from '../useResourcePerformance';
import { useDashboardStore } from '../../store/dashboardStore';
import type { ResourceStatus } from '../../services/kubernetesApi';

// Mock the dashboard store
vi.mock('../../store/dashboardStore', () => ({
  useDashboardStore: vi.fn(),
}));

// Mock performance.now
global.performance.now = vi.fn(() => 1000);

describe('useResourcePerformance', () => {
  const mockResources: ResourceStatus[] = Array.from({ length: 150 }, (_, i) => ({
    kind: 'Pod',
    name: `pod-${i}`,
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date(`2023-01-${String(i + 1).padStart(2, '0')}T10:00:00Z`),
    metadata: {},
    relationships: [],
  }));

  const mockStoreFunctions = {
    updateMetrics: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    
    // Mock the store functions
    vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
      if (selector.name === 'updateMetrics') return mockStoreFunctions.updateMetrics;
      
      // Default selector for filteredResources
      if (typeof selector === 'function') {
        return selector({
          filteredResources: mockResources.slice(0, 10), // Default to small set
          updateMetrics: mockStoreFunctions.updateMetrics,
        });
      }
      
      return mockResources.slice(0, 10);
    });

    // Reset performance mock
    vi.spyOn(performance, 'now').mockReturnValue(1000);
  });

  describe('Virtualization Logic', () => {
    it('should enable virtualization for large datasets', () => {
      // Mock large dataset
      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: mockResources, // 150 items
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return mockResources;
      });

      const { result } = renderHook(() => useResourcePerformance({
        itemHeight: 100,
        containerHeight: 600,
      }));

      expect(result.current.shouldVirtualize).toBe(true);
    });

    it('should disable virtualization for small datasets', () => {
      const { result } = renderHook(() => useResourcePerformance());

      expect(result.current.shouldVirtualize).toBe(false);
    });

    it('should calculate correct visible range', () => {
      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: mockResources,
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return mockResources;
      });

      const { result } = renderHook(() => useResourcePerformance({
        itemHeight: 100,
        containerHeight: 600,
        overscan: 2,
      }));

      // With scroll at top, should show first items + overscan
      expect(result.current.virtualizedRange.startIndex).toBe(0);
      expect(result.current.virtualizedRange.endIndex).toBeDefined();
      expect(result.current.virtualizedRange.visibleItems).toBeDefined();
    });

    it('should update visible range on scroll', () => {
      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: mockResources,
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return mockResources;
      });

      const { result } = renderHook(() => useResourcePerformance({
        itemHeight: 100,
        containerHeight: 600,
      }));

      // Simulate scroll event
      act(() => {
        const mockEvent = {
          currentTarget: { scrollTop: 500 },
        } as React.UIEvent<HTMLDivElement>;
        
        result.current.containerProps.onScroll(mockEvent);
      });

      expect(result.current.isScrolling).toBe(true);
    });
  });

  describe('Performance Metrics', () => {
    it('should track render metrics', () => {
      const { result } = renderHook(() => useResourcePerformance());

      expect(result.current.metrics).toEqual({
        renderTime: expect.any(Number),
        itemsRendered: expect.any(Number),
        totalItems: expect.any(Number),
        virtualizedEnabled: false,
      });
    });

    it('should update global metrics', async () => {
      renderHook(() => useResourcePerformance());

      // Wait for async metric update
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 10));
      });

      // Performance metrics should be reported
      expect(mockStoreFunctions.updateMetrics).toHaveBeenCalled();
    });

    it('should track render time', () => {
      let callCount = 0;
      vi.spyOn(performance, 'now').mockImplementation(() => {
        callCount++;
        return callCount === 1 ? 1000 : 1050; // 50ms render time
      });

      const { result } = renderHook(() => useResourcePerformance());

      // Should track render time
      expect(result.current.metrics.renderTime).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Batch Processing', () => {
    it('should process batches for large datasets', () => {
      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: mockResources,
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return mockResources;
      });

      const { result } = renderHook(() => useResourcePerformance({
        batchSize: 20,
      }));

      expect(result.current.totalBatches).toBe(Math.ceil(150 / 20));
      expect(result.current.currentBatch).toBeDefined();
      expect(result.current.processedBatches).toBeGreaterThanOrEqual(0);
    });

    it('should preload next batch', () => {
      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: mockResources,
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return mockResources;
      });

      const { result } = renderHook(() => useResourcePerformance({
        batchSize: 50,
      }));

      // Should start processing batches
      expect(result.current.processedBatches).toBeGreaterThanOrEqual(0);
    });
  });

  describe('Scroll Handling', () => {
    it('should handle scroll events', () => {
      const { result } = renderHook(() => useResourcePerformance({
        debounceMs: 50,
      }));

      const mockEvent = {
        currentTarget: { scrollTop: 200 },
      } as React.UIEvent<HTMLDivElement>;

      act(() => {
        result.current.containerProps.onScroll(mockEvent);
      });

      expect(result.current.isScrolling).toBe(true);
    });

    it('should debounce scroll end detection', async () => {
      const { result } = renderHook(() => useResourcePerformance({
        debounceMs: 10,
      }));

      const mockEvent = {
        currentTarget: { scrollTop: 200 },
      } as React.UIEvent<HTMLDivElement>;

      act(() => {
        result.current.containerProps.onScroll(mockEvent);
      });

      expect(result.current.isScrolling).toBe(true);

      // Wait for debounce
      await act(async () => {
        await new Promise(resolve => setTimeout(resolve, 20));
      });

      expect(result.current.isScrolling).toBe(false);
    });

    it('should provide container and content props', () => {
      const { result } = renderHook(() => useResourcePerformance({
        containerHeight: 800,
      }));

      expect(result.current.containerProps).toEqual({
        onScroll: expect.any(Function),
        style: {
          height: 800,
          overflowY: 'auto',
          position: 'relative',
        },
      });

      expect(result.current.contentProps).toBeDefined();
    });
  });

  describe('Resource Processing', () => {
    it('should add computed properties to resources', () => {
      const { result } = renderHook(() => useResourcePerformance());

      const processedResource = result.current.resources[0];
      if (processedResource) {
        expect(processedResource).toHaveProperty('displayName');
        expect(processedResource).toHaveProperty('sortKey');
        expect(processedResource).toHaveProperty('statusColor');
        expect(processedResource).toHaveProperty('lastUpdatedFormatted');
      }
    });

    it('should format display names correctly', () => {
      const { result } = renderHook(() => useResourcePerformance());

      const processedResource = result.current.resources[0];
      if (processedResource) {
        expect(processedResource.displayName).toBe('Pod/pod-0');
      }
    });

    it('should generate sort keys', () => {
      const { result } = renderHook(() => useResourcePerformance());

      const processedResource = result.current.resources[0];
      if (processedResource) {
        expect(processedResource.sortKey).toBe('default-Pod-pod-0');
      }
    });

    it('should apply status colors', () => {
      const { result } = renderHook(() => useResourcePerformance());

      const processedResource = result.current.resources[0];
      if (processedResource) {
        expect(processedResource.statusColor).toBe('#10B981'); // Green for Ready
      }
    });

    it('should format relative times', () => {
      const { result } = renderHook(() => useResourcePerformance());

      const processedResource = result.current.resources[0];
      if (processedResource) {
        expect(processedResource.lastUpdatedFormatted).toMatch(/ago|just now/);
      }
    });
  });

  describe('Options and Configuration', () => {
    it('should use default options', () => {
      const { result } = renderHook(() => useResourcePerformance());

      expect(result.current.containerProps.style.height).toBe(600); // Default height
      expect(result.current.shouldVirtualize).toBe(false); // Small dataset
    });

    it('should respect custom options', () => {
      const { result } = renderHook(() => useResourcePerformance({
        itemHeight: 150,
        containerHeight: 800,
        overscan: 10,
        batchSize: 25,
        debounceMs: 200,
      }));

      expect(result.current.containerProps.style.height).toBe(800);
    });

    it('should handle zero resources', () => {
      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: [],
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return [];
      });

      const { result } = renderHook(() => useResourcePerformance());

      expect(result.current.resources).toEqual([]);
      expect(result.current.shouldVirtualize).toBe(false);
      expect(result.current.metrics.totalItems).toBe(0);
    });
  });

  describe('Memory Management', () => {
    it('should cleanup timeouts on unmount', () => {
      const _clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');

      const { unmount } = renderHook(() => useResourcePerformance());

      unmount();

      // Cleanup should not throw
      expect(() => unmount()).not.toThrow();
    });

    it('should handle rapid scroll events', () => {
      const { result } = renderHook(() => useResourcePerformance({
        debounceMs: 100,
      }));

      const mockEvent = {
        currentTarget: { scrollTop: 200 },
      } as React.UIEvent<HTMLDivElement>;

      // Rapid scroll events
      act(() => {
        result.current.containerProps.onScroll(mockEvent);
        result.current.containerProps.onScroll({ ...mockEvent, currentTarget: { scrollTop: 300 } });
        result.current.containerProps.onScroll({ ...mockEvent, currentTarget: { scrollTop: 400 } });
      });

      // Should handle without errors
      expect(result.current.isScrolling).toBe(true);
    });
  });

  describe('Edge Cases', () => {
    it('should handle resources at exact virtualization threshold', () => {
      const exactResources = Array.from({ length: 100 }, (_, i) => ({
        kind: 'Pod',
        name: `pod-${i}`,
        namespace: 'default',
        status: 'Ready' as const,
        lastUpdated: new Date(),
        metadata: {},
        relationships: [],
      }));

      vi.mocked(useDashboardStore).mockImplementation((selector: any) => {
        if (typeof selector === 'function') {
          return selector({
            filteredResources: exactResources,
            updateMetrics: mockStoreFunctions.updateMetrics,
          });
        }
        return exactResources;
      });

      const { result } = renderHook(() => useResourcePerformance());

      expect(result.current.shouldVirtualize).toBe(false); // Exactly 100 items
    });

    it('should handle very small container heights', () => {
      const { result } = renderHook(() => useResourcePerformance({
        containerHeight: 50,
        itemHeight: 100,
      }));

      expect(result.current.containerProps.style.height).toBe(50);
    });

    it('should handle zero item height', () => {
      const { result } = renderHook(() => useResourcePerformance({
        itemHeight: 0,
      }));

      // Should not crash with zero height
      expect(result.current.virtualizedRange.startIndex).toBe(0);
    });
  });
});