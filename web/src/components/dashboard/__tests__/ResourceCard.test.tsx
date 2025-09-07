/**
 * Tests for ResourceCard component
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ResourceCard } from '../ResourceCard';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock ResourceStatusIndicator
vi.mock('../ResourceStatusIndicator', () => ({
  ResourceStatusIndicator: vi.fn(({ status, size, showLabel }) => (
    <div 
      data-testid={`status-indicator-${status.toLowerCase()}`}
      data-size={size}
      data-show-label={showLabel}
    >
      {status}
    </div>
  )),
}));

describe('ResourceCard', () => {
  const mockResource: ResourceStatus = {
    kind: 'Pod',
    name: 'test-pod',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date('2023-01-01T10:00:00Z'),
    metadata: {
      version: '1.0',
      app: 'test-app',
    },
    relationships: [
      {
        kind: 'Service',
        name: 'test-service',
        namespace: 'default',
        relationship: 'owns',
      },
    ],
  };

  const mockOnClick = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Rendering', () => {
    it('should render basic resource information', () => {
      render(<ResourceCard resource={mockResource} />);

      expect(screen.getByTestId('resource-card')).toBeInTheDocument();
      expect(screen.getByText('test-pod')).toBeInTheDocument();
      expect(screen.getByText('Pod')).toBeInTheDocument();
      expect(screen.getByText('default')).toBeInTheDocument();
      expect(screen.getByTestId('status-indicator-ready')).toBeInTheDocument();
    });

    it('should display resource icon based on kind', () => {
      render(<ResourceCard resource={mockResource} />);

      // Pod should show green circle emoji
      expect(screen.getByText('🟢')).toBeInTheDocument();
    });

    it('should show different icons for different resource kinds', () => {
      const deploymentResource = { ...mockResource, kind: 'Deployment' };
      const { rerender } = render(<ResourceCard resource={deploymentResource} />);
      expect(screen.getByText('🚀')).toBeInTheDocument();

      const serviceResource = { ...mockResource, kind: 'Service' };
      rerender(<ResourceCard resource={serviceResource} />);
      expect(screen.getByText('🌐')).toBeInTheDocument();

      const unknownResource = { ...mockResource, kind: 'UnknownKind' };
      rerender(<ResourceCard resource={unknownResource} />);
      expect(screen.getByText('📦')).toBeInTheDocument();
    });

    it('should format last updated time correctly', () => {
      // Create a resource updated 2 hours ago
      const twoHoursAgo = new Date(Date.now() - 2 * 60 * 60 * 1000);
      const recentResource = { ...mockResource, lastUpdated: twoHoursAgo };

      render(<ResourceCard resource={recentResource} />);

      expect(screen.getByText(/\d+h ago/)).toBeInTheDocument();
    });

    it('should show relationships count', () => {
      render(<ResourceCard resource={mockResource} />);

      expect(screen.getByText('1 relationship')).toBeInTheDocument();
    });

    it('should show multiple relationships count', () => {
      const resourceWithMultipleRels = {
        ...mockResource,
        relationships: [
          { kind: 'Service', name: 'svc1', relationship: 'owns' as const },
          { kind: 'ConfigMap', name: 'cm1', relationship: 'references' as const },
        ],
      };

      render(<ResourceCard resource={resourceWithMultipleRels} />);

      expect(screen.getByText('2 relationships')).toBeInTheDocument();
    });

    it('should display metadata tags', () => {
      render(<ResourceCard resource={mockResource} />);

      expect(screen.getByText('version: 1.0')).toBeInTheDocument();
      expect(screen.getByText('app: test-app')).toBeInTheDocument();
    });

    it('should limit metadata display to 3 items', () => {
      const resourceWithManyMetadata = {
        ...mockResource,
        metadata: {
          version: '1.0',
          app: 'test-app',
          env: 'prod',
          team: 'backend',
          region: 'us-east-1',
        },
      };

      render(<ResourceCard resource={resourceWithManyMetadata} />);

      // Should show first 3 metadata items
      expect(screen.getByText('version: 1.0')).toBeInTheDocument();
      expect(screen.getByText('app: test-app')).toBeInTheDocument();
      expect(screen.getByText('env: prod')).toBeInTheDocument();
      
      // Should not show 4th and 5th items
      expect(screen.queryByText('team: backend')).not.toBeInTheDocument();
      expect(screen.queryByText('region: us-east-1')).not.toBeInTheDocument();
    });

    it('should not show namespace when showNamespace is false', () => {
      render(<ResourceCard resource={mockResource} showNamespace={false} />);

      expect(screen.queryByText('default')).not.toBeInTheDocument();
    });

    it('should handle resource without namespace', () => {
      const clusterResource = { ...mockResource, namespace: undefined };
      render(<ResourceCard resource={clusterResource} />);

      expect(screen.getByText('test-pod')).toBeInTheDocument();
      expect(screen.getByText('Pod')).toBeInTheDocument();
    });
  });

  describe('Compact Mode', () => {
    it('should render in compact mode', () => {
      render(<ResourceCard resource={mockResource} compact={true} />);

      expect(screen.getByTestId('resource-card')).toBeInTheDocument();
      expect(screen.getByText('test-pod')).toBeInTheDocument();
      
      // In compact mode, should not show metadata or relationships
      expect(screen.queryByText('1 relationship')).not.toBeInTheDocument();
      expect(screen.queryByText('version: 1.0')).not.toBeInTheDocument();
    });
  });

  describe('Status Styling', () => {
    it('should apply correct styling for Ready status', () => {
      render(<ResourceCard resource={mockResource} />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveClass('border-green-200', 'bg-green-50', 'hover:bg-green-100');
    });

    it('should apply correct styling for Warning status', () => {
      const warningResource = { ...mockResource, status: 'Warning' as const };
      render(<ResourceCard resource={warningResource} />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveClass('border-yellow-200', 'bg-yellow-50', 'hover:bg-yellow-100');
    });

    it('should apply correct styling for Error status', () => {
      const errorResource = { ...mockResource, status: 'Error' as const };
      render(<ResourceCard resource={errorResource} />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveClass('border-red-200', 'bg-red-50', 'hover:bg-red-100');
    });

    it('should apply correct styling for Unknown status', () => {
      const unknownResource = { ...mockResource, status: 'Unknown' as const };
      render(<ResourceCard resource={unknownResource} />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveClass('border-gray-200', 'bg-gray-50', 'hover:bg-gray-100');
    });
  });

  describe('Interactions', () => {
    it('should call onClick when card is clicked', () => {
      render(<ResourceCard resource={mockResource} onClick={mockOnClick} />);

      const card = screen.getByTestId('resource-card');
      fireEvent.click(card);

      expect(mockOnClick).toHaveBeenCalledWith(mockResource);
    });

    it('should call onClick when Enter key is pressed', () => {
      render(<ResourceCard resource={mockResource} onClick={mockOnClick} />);

      const card = screen.getByTestId('resource-card');
      fireEvent.keyDown(card, { key: 'Enter' });

      expect(mockOnClick).toHaveBeenCalledWith(mockResource);
    });

    it('should call onClick when Space key is pressed', () => {
      render(<ResourceCard resource={mockResource} onClick={mockOnClick} />);

      const card = screen.getByTestId('resource-card');
      fireEvent.keyDown(card, { key: ' ' });

      expect(mockOnClick).toHaveBeenCalledWith(mockResource);
    });

    it('should not call onClick for other keys', () => {
      render(<ResourceCard resource={mockResource} onClick={mockOnClick} />);

      const card = screen.getByTestId('resource-card');
      fireEvent.keyDown(card, { key: 'Tab' });

      expect(mockOnClick).not.toHaveBeenCalled();
    });

    it('should work without onClick handler', () => {
      render(<ResourceCard resource={mockResource} />);

      const card = screen.getByTestId('resource-card');
      
      // Should not throw error
      expect(() => {
        fireEvent.click(card);
        fireEvent.keyDown(card, { key: 'Enter' });
      }).not.toThrow();
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA attributes', () => {
      render(<ResourceCard resource={mockResource} />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveAttribute('role', 'button');
      expect(card).toHaveAttribute('tabIndex', '0');
      expect(card).toHaveAttribute('aria-label', 'Pod test-pod - Status: Ready');
    });

    it('should have correct data attributes', () => {
      render(<ResourceCard resource={mockResource} />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveAttribute('data-resource-kind', 'Pod');
      expect(card).toHaveAttribute('data-resource-name', 'test-pod');
      expect(card).toHaveAttribute('data-resource-status', 'Ready');
    });
  });

  describe('Props', () => {
    it('should apply custom className', () => {
      render(<ResourceCard resource={mockResource} className="custom-class" />);

      const card = screen.getByTestId('resource-card');
      expect(card).toHaveClass('custom-class');
    });

    it('should pass correct props to ResourceStatusIndicator', () => {
      render(<ResourceCard resource={mockResource} compact={true} />);

      const statusIndicator = screen.getByTestId('status-indicator-ready');
      expect(statusIndicator).toHaveAttribute('data-size', 'sm'); // compact mode uses small size
      expect(statusIndicator).toHaveAttribute('data-show-label', 'false'); // card doesn't show label on status
    });

    it('should use medium size for status indicator in normal mode', () => {
      render(<ResourceCard resource={mockResource} compact={false} />);

      const statusIndicator = screen.getByTestId('status-indicator-ready');
      expect(statusIndicator).toHaveAttribute('data-size', 'md');
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long resource names', () => {
      const longNameResource = {
        ...mockResource,
        name: 'very-long-resource-name-that-should-be-truncated-in-the-ui',
      };

      render(<ResourceCard resource={longNameResource} />);

      expect(screen.getByText(longNameResource.name)).toBeInTheDocument();
    });

    it('should handle missing metadata', () => {
      const resourceWithoutMetadata = {
        ...mockResource,
        metadata: {},
      };

      render(<ResourceCard resource={resourceWithoutMetadata} />);

      expect(screen.getByText('test-pod')).toBeInTheDocument();
      // Should not show any metadata tags
      expect(screen.queryByText(/:/)).not.toBeInTheDocument();
    });

    it('should handle missing relationships', () => {
      const resourceWithoutRelationships = {
        ...mockResource,
        relationships: [],
      };

      render(<ResourceCard resource={resourceWithoutRelationships} />);

      expect(screen.getByText('test-pod')).toBeInTheDocument();
      expect(screen.queryByText('relationship')).not.toBeInTheDocument();
    });

    it('should filter out long metadata values', () => {
      const resourceWithLongMetadata = {
        ...mockResource,
        metadata: {
          shortKey: 'short',
          longKey: 'this-is-a-very-long-value-that-should-be-filtered-out-because-it-is-too-long',
        },
      };

      render(<ResourceCard resource={resourceWithLongMetadata} />);

      expect(screen.getByText('shortKey: short')).toBeInTheDocument();
      expect(screen.queryByText(/longKey:/)).not.toBeInTheDocument();
    });
  });
});