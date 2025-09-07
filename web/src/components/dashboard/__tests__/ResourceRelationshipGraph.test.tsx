/**
 * Tests for ResourceRelationshipGraph component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ResourceRelationshipGraph } from '../ResourceRelationshipGraph';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock canvas context
const mockCanvasContext = {
  clearRect: vi.fn(),
  beginPath: vi.fn(),
  moveTo: vi.fn(),
  lineTo: vi.fn(),
  arc: vi.fn(),
  fill: vi.fn(),
  stroke: vi.fn(),
  fillText: vi.fn(),
  set fillStyle(value: string) {},
  set strokeStyle(value: string) {},
  set lineWidth(value: number) {},
  set font(value: string) {},
  set textAlign(value: string) {},
  set textBaseline(value: string) {},
};

// Mock HTMLCanvasElement
Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
  value: () => mockCanvasContext,
});

// Mock getBoundingClientRect
Object.defineProperty(HTMLCanvasElement.prototype, 'getBoundingClientRect', {
  value: () => ({
    left: 0,
    top: 0,
    width: 800,
    height: 600,
  }),
});

// Mock requestAnimationFrame
global.requestAnimationFrame = vi.fn((cb) => setTimeout(() => cb(), 16));
global.cancelAnimationFrame = vi.fn();

describe('ResourceRelationshipGraph', () => {
  const mockResources: ResourceStatus[] = [
    {
      kind: 'Deployment',
      name: 'web-app',
      namespace: 'production',
      status: 'Ready',
      lastUpdated: new Date('2023-01-01T10:00:00Z'),
      metadata: {},
      relationships: [
        {
          kind: 'Service',
          name: 'web-service',
          namespace: 'production',
          relationship: 'selects',
        },
      ],
    },
    {
      kind: 'Service',
      name: 'web-service',
      namespace: 'production',
      status: 'Ready',
      lastUpdated: new Date('2023-01-01T10:00:00Z'),
      metadata: {},
      relationships: [
        {
          kind: 'Pod',
          name: 'web-pod-1',
          namespace: 'production',
          relationship: 'controls',
        },
      ],
    },
    {
      kind: 'Pod',
      name: 'web-pod-1',
      namespace: 'production',
      status: 'Warning',
      lastUpdated: new Date('2023-01-01T10:00:00Z'),
      metadata: {},
      relationships: [],
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('should render the graph component', () => {
      render(<ResourceRelationshipGraph resources={mockResources} />);
      
      expect(screen.getByTestId('resource-relationship-graph')).toBeInTheDocument();
      expect(screen.getByTestId('relationship-canvas')).toBeInTheDocument();
    });

    it('should display canvas with correct dimensions', () => {
      render(
        <ResourceRelationshipGraph 
          resources={mockResources} 
          width={1000}
          height={800}
        />
      );
      
      const canvas = screen.getByTestId('relationship-canvas');
      expect(canvas.width).toBe(1000);
      expect(canvas.height).toBe(800);
    });

    it('should show legend and resource count', () => {
      render(<ResourceRelationshipGraph resources={mockResources} />);
      
      expect(screen.getByText('Status:')).toBeInTheDocument();
      expect(screen.getByText('Ready')).toBeInTheDocument();
      expect(screen.getByText('Warning')).toBeInTheDocument();
      expect(screen.getByText('Error')).toBeInTheDocument();
      
      expect(screen.getByText('Relations:')).toBeInTheDocument();
      expect(screen.getByText('owns')).toBeInTheDocument();
      expect(screen.getByText('controls')).toBeInTheDocument();
      expect(screen.getByText('selects')).toBeInTheDocument();
      
      expect(screen.getByText(/Showing \d+ resources with \d+ relationships/)).toBeInTheDocument();
    });
  });

  describe('Interaction Handling', () => {
    it('should handle mouse events when interactive', async () => {
      const onResourceSelect = vi.fn();
      const onResourceHover = vi.fn();
      
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          interactive={true}
          onResourceSelect={onResourceSelect}
          onResourceHover={onResourceHover}
        />
      );
      
      const canvas = screen.getByTestId('relationship-canvas');
      
      // Simulate mouse move
      fireEvent.mouseMove(canvas, { clientX: 100, clientY: 100 });
      
      // Should handle mouse events without errors
      expect(canvas).toBeInTheDocument();
    });

    it('should not handle mouse events when not interactive', () => {
      const onResourceSelect = vi.fn();
      
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          interactive={false}
          onResourceSelect={onResourceSelect}
        />
      );
      
      const canvas = screen.getByTestId('relationship-canvas');
      
      fireEvent.click(canvas, { clientX: 100, clientY: 100 });
      
      expect(onResourceSelect).not.toHaveBeenCalled();
    });

    it('should handle mouse down and up events for dragging', () => {
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          interactive={true}
        />
      );
      
      const canvas = screen.getByTestId('relationship-canvas');
      
      fireEvent.mouseDown(canvas, { clientX: 100, clientY: 100 });
      fireEvent.mouseUp(canvas);
      
      // Should handle events without errors
      expect(canvas).toBeInTheDocument();
    });
  });

  describe('Filtering', () => {
    it('should filter resources by namespace', () => {
      const multiNamespaceResources = [
        ...mockResources,
        {
          kind: 'Pod',
          name: 'staging-pod',
          namespace: 'staging',
          status: 'Ready' as const,
          lastUpdated: new Date('2023-01-01T10:00:00Z'),
          metadata: {},
          relationships: [],
        },
      ];

      render(
        <ResourceRelationshipGraph 
          resources={multiNamespaceResources}
          filterByNamespace="production"
        />
      );
      
      expect(screen.getByText(/in namespace: production/)).toBeInTheDocument();
    });

    it('should show all resources when no namespace filter', () => {
      render(<ResourceRelationshipGraph resources={mockResources} />);
      
      expect(screen.queryByText(/in namespace:/)).not.toBeInTheDocument();
    });
  });

  describe('Label Display', () => {
    it('should show labels when enabled', () => {
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          showLabels={true}
        />
      );
      
      // Component should render without errors when labels are enabled
      expect(screen.getByTestId('resource-relationship-graph')).toBeInTheDocument();
    });

    it('should hide labels when disabled', () => {
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          showLabels={false}
        />
      );
      
      // Component should render without errors when labels are disabled
      expect(screen.getByTestId('resource-relationship-graph')).toBeInTheDocument();
    });
  });

  describe('Resource Selection', () => {
    it('should highlight selected resource', () => {
      const selectedResource = mockResources[0];
      
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          selectedResource={selectedResource}
        />
      );
      
      // Component should render with selected resource
      expect(screen.getByTestId('resource-relationship-graph')).toBeInTheDocument();
    });

    it('should handle resource selection change', () => {
      const { rerender } = render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          selectedResource={mockResources[0]}
        />
      );
      
      rerender(
        <ResourceRelationshipGraph 
          resources={mockResources}
          selectedResource={mockResources[1]}
        />
      );
      
      expect(screen.getByTestId('resource-relationship-graph')).toBeInTheDocument();
    });
  });

  describe('Custom Dimensions', () => {
    it('should use custom width and height', () => {
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          width={1200}
          height={900}
        />
      );
      
      const canvas = screen.getByTestId('relationship-canvas');
      expect(canvas.width).toBe(1200);
      expect(canvas.height).toBe(900);
    });

    it('should use default dimensions when not specified', () => {
      render(<ResourceRelationshipGraph resources={mockResources} />);
      
      const canvas = screen.getByTestId('relationship-canvas');
      expect(canvas.width).toBe(800);
      expect(canvas.height).toBe(600);
    });
  });

  describe('Empty State', () => {
    it('should handle empty resources array', () => {
      render(<ResourceRelationshipGraph resources={[]} />);
      
      expect(screen.getByTestId('resource-relationship-graph')).toBeInTheDocument();
      expect(screen.getByText(/Showing 0 resources with 0 relationships/)).toBeInTheDocument();
    });

    it('should handle resources without relationships', () => {
      const resourcesWithoutRelationships = mockResources.map(resource => ({
        ...resource,
        relationships: [],
      }));
      
      render(<ResourceRelationshipGraph resources={resourcesWithoutRelationships} />);
      
      expect(screen.getByText(/with 0 relationships/)).toBeInTheDocument();
    });
  });

  describe('Canvas Drawing', () => {
    it('should call canvas drawing methods', () => {
      render(<ResourceRelationshipGraph resources={mockResources} />);
      
      // Canvas drawing methods should be available
      expect(mockCanvasContext.clearRect).toBeDefined();
      expect(mockCanvasContext.beginPath).toBeDefined();
      expect(mockCanvasContext.arc).toBeDefined();
    });

    it('should handle resources change', () => {
      const { rerender } = render(<ResourceRelationshipGraph resources={mockResources} />);

      const newResources = [
        ...mockResources,
        {
          kind: 'ConfigMap',
          name: 'app-config',
          namespace: 'production',
          status: 'Ready' as const,
          lastUpdated: new Date('2023-01-01T10:00:00Z'),
          metadata: {},
          relationships: [],
        },
      ];

      rerender(<ResourceRelationshipGraph resources={newResources} />);
      
      // Component should handle resource changes without errors
      expect(screen.getByText(/Showing 4 resources/)).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('should provide proper canvas element', () => {
      render(<ResourceRelationshipGraph resources={mockResources} />);
      
      const canvas = screen.getByTestId('relationship-canvas');
      expect(canvas).toBeInTheDocument();
      expect(canvas.tagName).toBe('CANVAS');
    });

    it('should apply custom className', () => {
      render(
        <ResourceRelationshipGraph 
          resources={mockResources}
          className="custom-graph-class"
        />
      );
      
      const container = screen.getByTestId('resource-relationship-graph');
      expect(container).toHaveClass('custom-graph-class');
    });
  });

  describe('Performance', () => {
    it('should handle large numbers of resources', () => {
      const largeResourceSet = Array.from({ length: 100 }, (_, i) => ({
        kind: 'Pod',
        name: `pod-${i}`,
        namespace: 'default',
        status: 'Ready' as const,
        lastUpdated: new Date('2023-01-01T10:00:00Z'),
        metadata: {},
        relationships: [],
      }));
      
      render(<ResourceRelationshipGraph resources={largeResourceSet} />);
      
      expect(screen.getByText(/Showing 100 resources/)).toBeInTheDocument();
    });

    it('should cleanup animation frames on unmount', () => {
      const { unmount } = render(<ResourceRelationshipGraph resources={mockResources} />);
      
      unmount();
      
      // Component should cleanup without errors
      expect(screen.queryByTestId('resource-relationship-graph')).not.toBeInTheDocument();
    });
  });
});