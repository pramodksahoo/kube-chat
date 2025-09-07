/**
 * Tests for ResourceDashboard component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ResourceDashboard } from '../ResourceDashboard';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock the useKubernetesResources hook
vi.mock('../../../hooks/useKubernetesResources', () => ({
  useKubernetesResources: vi.fn(),
}));

// Mock the child components
vi.mock('../ResourceCard', () => ({
  ResourceCard: vi.fn(({ resource, onClick }) => (
    <div 
      data-testid="resource-card" 
      data-resource-name={resource.name}
      data-resource-kind={resource.kind}
      onClick={() => onClick?.(resource)}
    >
      {resource.name} - {resource.status}
    </div>
  )),
}));

vi.mock('../ResourceDetailModal', () => ({
  ResourceDetailModal: vi.fn(({ resource, isOpen, onClose }) => 
    isOpen ? (
      <div data-testid="resource-detail-modal">
        Modal for {resource.name}
        <button onClick={onClose} data-testid="close-modal">Close</button>
      </div>
    ) : null
  ),
}));

import { useKubernetesResources } from '../../../hooks/useKubernetesResources';

const mockUseKubernetesResources = vi.mocked(useKubernetesResources);

describe('ResourceDashboard', () => {
  const mockResources: ResourceStatus[] = [
    {
      kind: 'Pod',
      name: 'test-pod-1',
      namespace: 'default',
      status: 'Ready',
      lastUpdated: new Date('2023-01-01'),
      metadata: {},
      relationships: [],
    },
    {
      kind: 'Pod',
      name: 'test-pod-2',
      namespace: 'default', 
      status: 'Warning',
      lastUpdated: new Date('2023-01-01'),
      metadata: {},
      relationships: [],
    },
    {
      kind: 'Deployment',
      name: 'test-deployment',
      namespace: 'default',
      status: 'Ready',
      lastUpdated: new Date('2023-01-01'),
      metadata: {},
      relationships: [],
    },
    {
      kind: 'Service',
      name: 'test-service',
      namespace: 'kube-system',
      status: 'Error',
      lastUpdated: new Date('2023-01-01'),
      metadata: {},
      relationships: [],
    },
  ];

  const defaultHookReturn = {
    resources: mockResources,
    loading: false,
    error: null,
    refreshResources: vi.fn(),
    isConnected: true,
    connectionError: null,
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockUseKubernetesResources.mockReturnValue(defaultHookReturn);
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  describe('Rendering', () => {
    it('should render dashboard with resources', () => {
      render(<ResourceDashboard />);

      expect(screen.getByTestId('resource-dashboard')).toBeInTheDocument();
      expect(screen.getByText('Resource Dashboard')).toBeInTheDocument();
      expect(screen.getByText('Live')).toBeInTheDocument();
    });

    it('should display resource summary statistics correctly', () => {
      render(<ResourceDashboard />);

      // Check summary counts using the summary section
      const summarySection = screen.getByTestId('resource-dashboard').querySelector('.dashboard-summary');
      expect(summarySection).toBeInTheDocument();
      
      // Verify the summary cards are present - text appears in summary and filter dropdown
      expect(screen.getByText('Total')).toBeInTheDocument();
      expect(screen.getAllByText('Ready')).toHaveLength(2); // Appears in summary and filter dropdown
      expect(screen.getAllByText('Warning')).toHaveLength(2); // Appears in summary and filter dropdown  
      expect(screen.getAllByText('Error')).toHaveLength(2); // Appears in summary and filter dropdown
      expect(screen.getAllByText('Unknown')).toHaveLength(2); // Appears in summary and filter dropdown
    });

    it('should group resources by kind', () => {
      render(<ResourceDashboard />);

      expect(screen.getByText('Pod')).toBeInTheDocument();
      expect(screen.getByText('Deployment')).toBeInTheDocument();  
      expect(screen.getByText('Service')).toBeInTheDocument();

      // Check resource counts for each kind - should be in spans next to headings
      const resourceGroups = screen.getAllByText(/^(Pod|Deployment|Service)$/);
      expect(resourceGroups).toHaveLength(3);
    });

    it('should render resource cards', () => {
      render(<ResourceDashboard />);

      const cards = screen.getAllByTestId('resource-card');
      expect(cards).toHaveLength(4);

      expect(cards[0].getAttribute('data-resource-name')).toBe('test-pod-1');
    });
  });

  describe('Loading and Error States', () => {
    it('should show loading state when loading and no resources', () => {
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        resources: [],
        loading: true,
      });

      render(<ResourceDashboard />);

      expect(screen.getByTestId('loading-state')).toBeInTheDocument();
      expect(screen.getByText('Loading resources...')).toBeInTheDocument();
    });

    it('should show error state when there is an error', () => {
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        error: 'API Error',
        resources: [],
      });

      render(<ResourceDashboard />);

      expect(screen.getByTestId('resource-dashboard-error')).toBeInTheDocument();
      expect(screen.getByText('Failed to load resources')).toBeInTheDocument();
      expect(screen.getByText('API Error')).toBeInTheDocument();
    });

    it('should show empty state when no resources match filters', () => {
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        resources: [],
      });

      render(<ResourceDashboard />);

      expect(screen.getByTestId('empty-state')).toBeInTheDocument();
      expect(screen.getByText('No resources found')).toBeInTheDocument();
    });

    it('should show connection warning when there is a connection error', () => {
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        connectionError: 'WebSocket connection failed',
        isConnected: false,
      });

      render(<ResourceDashboard />);

      expect(screen.getByText('Connection Warning:')).toBeInTheDocument();
      expect(screen.getByText('WebSocket connection failed')).toBeInTheDocument();
      expect(screen.getByText('Offline')).toBeInTheDocument();
    });
  });

  describe('Filtering', () => {
    it('should filter resources by status', async () => {
      render(<ResourceDashboard />);

      const statusFilter = screen.getByLabelText('Filter resources by status');
      fireEvent.change(statusFilter, { target: { value: 'ready' } });

      await waitFor(() => {
        const cards = screen.getAllByTestId('resource-card');
        expect(cards).toHaveLength(2); // Only Ready resources
      });
    });

    it('should filter resources by search query', async () => {
      render(<ResourceDashboard />);

      const searchInput = screen.getByLabelText('Search resources by name, kind, or namespace');
      fireEvent.change(searchInput, { target: { value: 'pod' } });

      await waitFor(() => {
        const cards = screen.getAllByTestId('resource-card');
        expect(cards).toHaveLength(2); // Only pods
      });
    });

    it('should show empty state when filters match nothing', async () => {
      render(<ResourceDashboard />);

      const searchInput = screen.getByLabelText('Search resources by name, kind, or namespace');
      fireEvent.change(searchInput, { target: { value: 'nonexistent' } });

      await waitFor(() => {
        expect(screen.getByTestId('empty-state')).toBeInTheDocument();
        expect(screen.getByText('Try adjusting your filters')).toBeInTheDocument();
      });
    });

    it('should combine status and search filters', async () => {
      render(<ResourceDashboard />);

      const statusFilter = screen.getByLabelText('Filter resources by status');
      const searchInput = screen.getByLabelText('Search resources by name, kind, or namespace');

      fireEvent.change(statusFilter, { target: { value: 'ready' } });
      fireEvent.change(searchInput, { target: { value: 'pod' } });

      await waitFor(() => {
        const cards = screen.getAllByTestId('resource-card');
        expect(cards).toHaveLength(1); // Only ready pods
      });
    });
  });

  describe('Interactions', () => {
    it('should refresh resources when refresh button is clicked', async () => {
      const mockRefresh = vi.fn();
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        refreshResources: mockRefresh,
      });

      render(<ResourceDashboard />);

      const refreshButton = screen.getByLabelText('Refresh resources');
      fireEvent.click(refreshButton);

      expect(mockRefresh).toHaveBeenCalledTimes(1);
    });

    it('should open resource detail modal when resource is clicked', async () => {
      render(<ResourceDashboard />);

      const firstCard = screen.getAllByTestId('resource-card')[0];
      fireEvent.click(firstCard);

      await waitFor(() => {
        expect(screen.getByTestId('resource-detail-modal')).toBeInTheDocument();
      });
    });

    it('should close resource detail modal', async () => {
      render(<ResourceDashboard />);

      // Open modal
      const firstCard = screen.getAllByTestId('resource-card')[0];
      fireEvent.click(firstCard);

      await waitFor(() => {
        expect(screen.getByTestId('resource-detail-modal')).toBeInTheDocument();
      });

      // Close modal
      const closeButton = screen.getByTestId('close-modal');
      fireEvent.click(closeButton);

      await waitFor(() => {
        expect(screen.queryByTestId('resource-detail-modal')).not.toBeInTheDocument();
      });
    });

    it('should call onResourceSelect when resource is selected', async () => {
      const mockOnResourceSelect = vi.fn();
      render(<ResourceDashboard onResourceSelect={mockOnResourceSelect} />);

      const firstCard = screen.getAllByTestId('resource-card')[0];
      fireEvent.click(firstCard);

      expect(mockOnResourceSelect).toHaveBeenCalledWith(mockResources[0]);
    });

    it('should retry when retry button is clicked in error state', async () => {
      const mockRefresh = vi.fn();
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        error: 'API Error',
        resources: [],
        refreshResources: mockRefresh,
      });

      render(<ResourceDashboard />);

      const retryButton = screen.getByLabelText('Retry loading resources');
      fireEvent.click(retryButton);

      expect(mockRefresh).toHaveBeenCalledTimes(1);
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels and roles', () => {
      render(<ResourceDashboard />);

      expect(screen.getByRole('button', { name: 'Refresh resources' })).toBeInTheDocument();
      expect(screen.getByLabelText('Search resources by name, kind, or namespace')).toBeInTheDocument();
      expect(screen.getByLabelText('Filter resources by status')).toBeInTheDocument();
    });

    it('should show proper connection status accessibility label', () => {
      render(<ResourceDashboard />);

      expect(screen.getByLabelText('Connected')).toBeInTheDocument();
    });

    it('should show proper disconnected status', () => {
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        isConnected: false,
      });

      render(<ResourceDashboard />);

      expect(screen.getByLabelText('Disconnected')).toBeInTheDocument();
    });

    it('should have proper error state accessibility', () => {
      mockUseKubernetesResources.mockReturnValue({
        ...defaultHookReturn,
        error: 'API Error',
        resources: [],
      });

      render(<ResourceDashboard />);

      expect(screen.getByRole('alert')).toBeInTheDocument();
    });
  });

  describe('Props', () => {
    it('should pass filtering props to useKubernetesResources hook', () => {
      const props = {
        namespace: 'test-namespace',
        kind: 'Pod', 
        labelSelector: 'app=test',
        sessionId: 'test-session',
        autoRefresh: false,
      };

      render(<ResourceDashboard {...props} />);

      expect(mockUseKubernetesResources).toHaveBeenCalledWith({
        namespace: 'test-namespace',
        kind: 'Pod',
        labelSelector: 'app=test',
        sessionId: 'test-session',
        autoRefresh: false,
      });
    });

    it('should apply custom className', () => {
      render(<ResourceDashboard className="custom-class" />);

      const dashboard = screen.getByTestId('resource-dashboard');
      expect(dashboard).toHaveClass('custom-class');
    });

    it('should work without showNamespace prop on ResourceCard', () => {
      render(<ResourceDashboard />);

      expect(screen.getByTestId('resource-dashboard')).toBeInTheDocument();
      // ResourceCard should render normally (mocked)
      expect(screen.getAllByTestId('resource-card')).toHaveLength(4);
    });
  });
});