/**
 * Tests for ResourceTopology component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ResourceTopology } from '../ResourceTopology';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock the ResourceRelationshipGraph component
vi.mock('../ResourceRelationshipGraph', () => ({
  ResourceRelationshipGraph: ({ resources, selectedResource }: any) => (
    <div data-testid="mock-relationship-graph">
      <div>Graph with {resources.length} resources</div>
      {selectedResource && <div>Selected: {selectedResource.name}</div>}
    </div>
  ),
}));

// Mock canvas for graph component
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

Object.defineProperty(HTMLCanvasElement.prototype, 'getContext', {
  value: () => mockCanvasContext,
});

describe('ResourceTopology', () => {
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
      relationships: [],
    },
    {
      kind: 'Pod',
      name: 'staging-pod',
      namespace: 'staging',
      status: 'Warning',
      lastUpdated: new Date('2023-01-01T10:00:00Z'),
      metadata: {},
      relationships: [],
    },
    {
      kind: 'ClusterRole',
      name: 'admin-role',
      namespace: undefined, // cluster-scoped
      status: 'Ready',
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
    it('should render the topology component', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      expect(screen.getByTestId('resource-topology')).toBeInTheDocument();
      expect(screen.getByText('Resource Topology')).toBeInTheDocument();
    });

    it('should show statistics in header', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      expect(screen.getByText('Resources:')).toBeInTheDocument();
      expect(screen.getByText('4')).toBeInTheDocument(); // 4 resources
      expect(screen.getByText('Namespaces:')).toBeInTheDocument();
      expect(screen.getByText('2')).toBeInTheDocument(); // production + staging
      expect(screen.getByText('Relationships:')).toBeInTheDocument();
      expect(screen.getByText('Status:')).toBeInTheDocument();
    });

    it('should display status distribution', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      // Should show status counts (3 Ready, 1 Warning)
      const statusSection = screen.getByText('Status:').parentElement;
      expect(statusSection).toBeInTheDocument();
    });
  });

  describe('Layout Switching', () => {
    it('should default to graph layout', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="graph" />);
      
      expect(screen.getByTestId('mock-relationship-graph')).toBeInTheDocument();
      expect(screen.getByTestId('layout-graph-button')).toHaveClass('bg-blue-600');
    });

    it('should switch to tree layout when button clicked', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      const treeButton = screen.getByTestId('layout-tree-button');
      fireEvent.click(treeButton);
      
      expect(screen.getByTestId('tree-layout')).toBeInTheDocument();
      expect(screen.getByText('Tree Layout')).toBeInTheDocument();
      expect(screen.getByText('Hierarchical tree view coming soon')).toBeInTheDocument();
      expect(treeButton).toHaveClass('bg-blue-600');
    });

    it('should switch to namespace layout when button clicked', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      const namespaceButton = screen.getByTestId('layout-namespace-button');
      fireEvent.click(namespaceButton);
      
      expect(screen.getByTestId('namespace-layout')).toBeInTheDocument();
      expect(namespaceButton).toHaveClass('bg-blue-600');
    });

    it('should use default layout prop', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      expect(screen.getByTestId('namespace-layout')).toBeInTheDocument();
      expect(screen.getByTestId('layout-namespace-button')).toHaveClass('bg-blue-600');
    });
  });

  describe('Graph Layout Controls', () => {
    it('should show labels checkbox for graph layout', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="graph" />);
      
      expect(screen.getByTestId('show-labels-checkbox')).toBeInTheDocument();
      expect(screen.getByText('Show Labels')).toBeInTheDocument();
    });

    it('should handle labels checkbox toggle', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="graph" />);
      
      const checkbox = screen.getByTestId('show-labels-checkbox');
      expect(checkbox.checked).toBe(true); // Default true
      
      fireEvent.click(checkbox);
      expect(checkbox.checked).toBe(false);
    });

    it('should show namespace filter for graph layout', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="graph" />);
      
      expect(screen.getByTestId('topology-namespace-filter')).toBeInTheDocument();
      expect(screen.getByText('All Namespaces')).toBeInTheDocument();
    });

    it('should handle namespace filter change', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="graph" />);
      
      const select = screen.getByTestId('topology-namespace-filter');
      fireEvent.change(select, { target: { value: 'production' } });
      
      expect((select as HTMLSelectElement).value).toBe('production');
    });

    it('should not show graph-specific controls for other layouts', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="tree" />);
      
      expect(screen.queryByTestId('show-labels-checkbox')).not.toBeInTheDocument();
    });
  });

  describe('Namespace Layout', () => {
    it('should group resources by namespace', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      // Check for namespace headers (more specific than just text)
      expect(screen.getByRole('heading', { level: 3, name: /production/ })).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 3, name: /staging/ })).toBeInTheDocument();
      expect(screen.getByRole('heading', { level: 3, name: /cluster-scoped/ })).toBeInTheDocument();
    });

    it('should show resource counts per namespace', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      expect(screen.getByText('(2 resources)')).toBeInTheDocument(); // production
      expect(screen.getAllByText('(1 resources)')).toHaveLength(2); // staging and cluster-scoped
    });

    it('should display resource items in namespace groups', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      const resourceItems = screen.getAllByTestId('namespace-resource-item');
      expect(resourceItems).toHaveLength(4);
    });

    it('should handle resource selection in namespace layout', () => {
      const onResourceSelect = vi.fn();
      render(
        <ResourceTopology 
          resources={mockResources} 
          defaultLayout="namespace"
          onResourceSelect={onResourceSelect}
        />
      );
      
      const resourceItems = screen.getAllByTestId('namespace-resource-item');
      fireEvent.click(resourceItems[0]);
      
      expect(onResourceSelect).toHaveBeenCalledWith(mockResources[0]);
    });

    it('should show namespace selector', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      expect(screen.getByTestId('namespace-selector')).toBeInTheDocument();
      expect(screen.getAllByText('All Namespaces')).toHaveLength(2); // Header filter + namespace selector
    });

    it('should filter by selected namespace', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      const _selector = screen.getByTestId('namespace-selector');
      fireEvent.change(selector, { target: { value: 'production' } });
      
      expect(screen.getByRole('heading', { level: 3, name: /production/ })).toBeInTheDocument();
      expect(screen.queryByRole('heading', { level: 3, name: /staging/ })).not.toBeInTheDocument();
    });

    it('should highlight selected resource', () => {
      render(
        <ResourceTopology 
          resources={mockResources} 
          defaultLayout="namespace"
          selectedResource={mockResources[0]}
        />
      );
      
      const resourceItems = screen.getAllByTestId('namespace-resource-item');
      expect(resourceItems[0]).toHaveClass('border-blue-500');
    });
  });

  describe('Resource Information Display', () => {
    it('should show resource relationships count', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      expect(screen.getByText('1 relationship')).toBeInTheDocument();
    });

    it('should handle resource without relationships', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      // Resources without relationships should not show relationship text
      const resourceItems = screen.getAllByTestId('namespace-resource-item');
      expect(resourceItems.length).toBeGreaterThan(0);
    });

    it('should display resource status indicators', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      const statusIndicators = screen.getAllByTestId('namespace-resource-item')
        .map(item => item.querySelector('[class*="rounded-full"]'))
        .filter(Boolean);
      
      expect(statusIndicators.length).toBeGreaterThan(0);
    });
  });

  describe('Tree Layout', () => {
    it('should show coming soon message for tree layout', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="tree" />);
      
      expect(screen.getByText('🌳')).toBeInTheDocument();
      expect(screen.getByText('Tree Layout')).toBeInTheDocument();
      expect(screen.getByText('Hierarchical tree view coming soon')).toBeInTheDocument();
    });
  });

  describe('Event Handling', () => {
    it('should handle resource selection', () => {
      const onResourceSelect = vi.fn();
      render(
        <ResourceTopology 
          resources={mockResources}
          onResourceSelect={onResourceSelect}
          defaultLayout="graph"
        />
      );
      
      // Graph component should receive the callback
      expect(screen.getByTestId('mock-relationship-graph')).toBeInTheDocument();
    });

    it('should handle resource hover', () => {
      const onResourceHover = vi.fn();
      render(
        <ResourceTopology 
          resources={mockResources}
          onResourceHover={onResourceHover}
          defaultLayout="graph"
        />
      );
      
      // Graph component should receive the callback
      expect(screen.getByTestId('mock-relationship-graph')).toBeInTheDocument();
    });

    it('should pass selected resource to child components', () => {
      const selectedResource = mockResources[0];
      render(
        <ResourceTopology 
          resources={mockResources}
          selectedResource={selectedResource}
          defaultLayout="graph"
        />
      );
      
      expect(screen.getByText(`Selected: ${selectedResource.name}`)).toBeInTheDocument();
    });
  });

  describe('Namespace Management', () => {
    it('should list unique namespaces', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      const _selector = screen.getByTestId('namespace-selector');
      
      // Should have production and staging options in select
      expect(screen.getAllByText('production')).toHaveLength(2); // Header + option
      expect(screen.getAllByText('staging')).toHaveLength(2); // Header + option
    });

    it('should handle resources without namespace', () => {
      render(<ResourceTopology resources={mockResources} defaultLayout="namespace" />);
      
      // Cluster-scoped resources should be grouped under 'cluster-scoped'
      expect(screen.getByRole('heading', { level: 3, name: /cluster-scoped/ })).toBeInTheDocument();
    });
  });

  describe('Custom Props', () => {
    it('should apply custom className', () => {
      render(
        <ResourceTopology 
          resources={mockResources} 
          className="custom-topology-class"
        />
      );
      
      const container = screen.getByTestId('resource-topology');
      expect(container).toHaveClass('custom-topology-class');
    });
  });

  describe('Empty State', () => {
    it('should handle empty resources array', () => {
      render(<ResourceTopology resources={[]} />);
      
      expect(screen.getByTestId('resource-topology')).toBeInTheDocument();
      expect(screen.getByText('0')).toBeInTheDocument(); // Resource count
    });

    it('should show empty namespace layout', () => {
      render(<ResourceTopology resources={[]} defaultLayout="namespace" />);
      
      expect(screen.getByTestId('namespace-layout')).toBeInTheDocument();
    });
  });

  describe('Statistics Calculation', () => {
    it('should calculate correct resource statistics', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      expect(screen.getByText('Resources:')).toBeInTheDocument();
      expect(screen.getByText('4')).toBeInTheDocument();
      expect(screen.getByText('Namespaces:')).toBeInTheDocument();
      expect(screen.getByText('2')).toBeInTheDocument(); // production, staging (cluster-scoped doesn't count)
    });

    it('should calculate relationships count', () => {
      render(<ResourceTopology resources={mockResources} />);
      
      expect(screen.getByText('Relationships:')).toBeInTheDocument();
      expect(screen.getByText('1')).toBeInTheDocument(); // Only 1 relationship in mock data
    });
  });
});