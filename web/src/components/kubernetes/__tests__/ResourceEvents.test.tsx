/**
 * Tests for ResourceEvents component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { ResourceEvents } from '../ResourceEvents';
import { kubernetesApi } from '../../../services/kubernetesApi';
import type { KubernetesEvent, ResourceStatus } from '../../../services/kubernetesApi';

// Mock the kubernetesApi
vi.mock('../../../services/kubernetesApi', () => ({
  kubernetesApi: {
    getResourceEvents: vi.fn(),
  },
}));

describe('ResourceEvents', () => {
  const mockResource: ResourceStatus = {
    kind: 'Pod',
    name: 'test-pod',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date('2023-01-01T10:00:00Z'),
    metadata: {},
    relationships: [],
  };

  const mockEvents: KubernetesEvent[] = [
    {
      name: 'event-1',
      namespace: 'default',
      reason: 'Created',
      message: 'Pod created successfully',
      type: 'Normal',
      count: 1,
      firstTimestamp: new Date('2023-01-01T10:00:00Z'),
      lastTimestamp: new Date('2023-01-01T10:00:00Z'),
      source: { component: 'kubelet', host: 'node-1' },
    },
    {
      name: 'event-2',
      namespace: 'default',
      reason: 'FailedMount',
      message: 'Unable to mount volumes for pod',
      type: 'Warning',
      count: 3,
      firstTimestamp: new Date('2023-01-01T10:01:00Z'),
      lastTimestamp: new Date('2023-01-01T10:03:00Z'),
      source: { component: 'kubelet', host: 'node-1' },
    },
    {
      name: 'event-3',
      namespace: 'default',
      reason: 'Started',
      message: 'Container started',
      type: 'Normal',
      count: 1,
      firstTimestamp: new Date('2023-01-01T10:05:00Z'),
      lastTimestamp: new Date('2023-01-01T10:05:00Z'),
      source: { component: 'kubelet', host: 'node-2' },
    },
  ];

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2023-01-01T11:00:00Z')); // Set current time for relative time calculations
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.resetAllMocks();
  });

  describe('Loading State', () => {
    it('should show loading state initially', () => {
      vi.mocked(kubernetesApi.getResourceEvents).mockImplementation(() => new Promise(() => {}));

      render(<ResourceEvents resource={mockResource} />);

      expect(screen.getByTestId('resource-events-loading')).toBeInTheDocument();
      expect(screen.getByText('Loading events...')).toBeInTheDocument();
    });
  });

  describe('Success State', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should load and display events', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-events')).toBeInTheDocument();
      });

      expect(kubernetesApi.getResourceEvents).toHaveBeenCalledWith('Pod', 'test-pod', 'default', 100);
    });

    it('should display events in timeline format', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('events-timeline')).toBeInTheDocument();
      });

      const eventItems = screen.getAllByTestId('event-item');
      expect(eventItems).toHaveLength(3);

      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Pod created successfully')).toBeInTheDocument();
      expect(screen.getByText('FailedMount')).toBeInTheDocument();
      expect(screen.getByText('Unable to mount volumes for pod')).toBeInTheDocument();
      expect(screen.getByText('Started')).toBeInTheDocument();
      expect(screen.getByText('Container started')).toBeInTheDocument();
    });

    it('should show event metadata', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('kubelet')).toBeInTheDocument();
      });

      expect(screen.getByText('on node-1')).toBeInTheDocument();
      expect(screen.getByText('on node-2')).toBeInTheDocument();
      expect(screen.getByText('3 times')).toBeInTheDocument(); // Event count for repeated event
    });

    it('should show relative timestamps', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('55m ago')).toBeInTheDocument(); // Latest event (10:05 -> 11:00)
      });

      expect(screen.getByText('57m ago')).toBeInTheDocument(); // Warning event (10:03 -> 11:00)
      expect(screen.getByText('60m ago')).toBeInTheDocument(); // First event (10:00 -> 11:00)
    });

    it('should display controls with default values', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('refresh-events-button')).toBeInTheDocument();
      });

      expect(screen.getByDisplayValue('All Events')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Newest First')).toBeInTheDocument();
      expect(screen.getByText('Refresh')).toBeInTheDocument();
    });

    it('should show event type icons and styling', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        const eventItems = screen.getAllByTestId('event-item');
        expect(eventItems).toHaveLength(3);
      });

      // Check that Normal and Warning events are displayed with proper styling
      expect(screen.getByText('✓')).toBeInTheDocument(); // Normal event icons
      expect(screen.getByText('⚠')).toBeInTheDocument(); // Warning event icon
    });
  });

  describe('Filtering', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should filter events by type', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      // Filter to only Normal events
      const typeFilter = screen.getByDisplayValue('All Events');
      fireEvent.change(typeFilter, { target: { value: 'Normal' } });

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(2);
      });

      expect(screen.getByText('Created')).toBeInTheDocument();
      expect(screen.getByText('Started')).toBeInTheDocument();
      expect(screen.queryByText('FailedMount')).not.toBeInTheDocument();
    });

    it('should filter events by search term', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      const searchInput = screen.getByPlaceholderText(/Search events/);
      fireEvent.change(searchInput, { target: { value: 'mount' } });

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(1);
      });

      expect(screen.getByText('FailedMount')).toBeInTheDocument();
      expect(screen.getByText('1 of 3 events')).toBeInTheDocument();
    });

    it('should search across reason, message, and component', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      // Search by component name
      const searchInput = screen.getByPlaceholderText(/Search events/);
      fireEvent.change(searchInput, { target: { value: 'kubelet' } });

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      // Search by reason
      fireEvent.change(searchInput, { target: { value: 'Created' } });

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(1);
      });
    });
  });

  describe('Sorting', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should sort events newest first by default', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        const eventItems = screen.getAllByTestId('event-item');
        expect(eventItems).toHaveLength(3);
      });

      // First event should be the newest (Started - 10:05)
      const firstEvent = screen.getAllByTestId('event-item')[0];
      expect(firstEvent).toHaveTextContent('Started');
    });

    it('should sort events oldest first when changed', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      const sortSelect = screen.getByDisplayValue('Newest First');
      fireEvent.change(sortSelect, { target: { value: 'asc' } });

      await waitFor(() => {
        const firstEvent = screen.getAllByTestId('event-item')[0];
        expect(firstEvent).toHaveTextContent('Created');
      });
    });
  });

  describe('Auto-refresh', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should auto-refresh events when enabled', async () => {
      render(<ResourceEvents resource={mockResource} autoRefresh={true} refreshInterval={5000} />);

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
      });

      // Advance time to trigger auto-refresh
      act(() => {
        vi.advanceTimersByTime(5000);
      });

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(2);
      });

      expect(screen.getByText('Auto-refreshing every 5s')).toBeInTheDocument();
    });

    it('should not auto-refresh when disabled', async () => {
      render(<ResourceEvents resource={mockResource} autoRefresh={false} />);

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
      });

      // Advance time
      act(() => {
        vi.advanceTimersByTime(30000);
      });

      // Should not make additional calls
      expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
    });

    it('should manually refresh when refresh button is clicked', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
      });

      fireEvent.click(screen.getByTestId('refresh-events-button'));

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('Error State', () => {
    it('should show error state when API call fails', async () => {
      const errorMessage = 'Failed to fetch events';
      vi.mocked(kubernetesApi.getResourceEvents).mockRejectedValue(new Error(errorMessage));

      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-events-error')).toBeInTheDocument();
      });

      expect(screen.getByText('Failed to load events')).toBeInTheDocument();
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });

    it('should allow retry when error occurs', async () => {
      vi.mocked(kubernetesApi.getResourceEvents)
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({ events: mockEvents });

      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Retry')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Retry'));

      await waitFor(() => {
        expect(screen.getByTestId('resource-events')).toBeInTheDocument();
      });

      expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(2);
    });

    it('should handle non-Error exceptions', async () => {
      vi.mocked(kubernetesApi.getResourceEvents).mockRejectedValue('String error');

      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Failed to fetch events')).toBeInTheDocument();
      });
    });
  });

  describe('Empty Events', () => {
    it('should show empty state when no events available', async () => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: [] });

      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('No events found')).toBeInTheDocument();
      });
    });

    it('should show filtered empty state when filters match nothing', async () => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });

      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      const searchInput = screen.getByPlaceholderText(/Search events/);
      fireEvent.change(searchInput, { target: { value: 'nonexistent' } });

      await waitFor(() => {
        expect(screen.getByText('No events match the filters')).toBeInTheDocument();
      });
    });
  });

  describe('Event Timestamps', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should show both first and last timestamps for repeated events', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('First seen:')).toBeInTheDocument();
      });

      expect(screen.getByText('Last seen:')).toBeInTheDocument();
      expect(screen.getByText('1/1/2023, 10:01:00 AM')).toBeInTheDocument(); // First timestamp
      expect(screen.getByText('1/1/2023, 10:03:00 AM')).toBeInTheDocument(); // Last timestamp
    });

    it('should only show first timestamp for single occurrence events', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        const eventItems = screen.getAllByTestId('event-item');
        expect(eventItems).toHaveLength(3);
      });

      // Single occurrence events should have first seen timestamp
      expect(screen.getByText('1/1/2023, 10:00:00 AM')).toBeInTheDocument();
      expect(screen.getByText('1/1/2023, 10:05:00 AM')).toBeInTheDocument();
    });
  });

  describe('Status Bar', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should display correct status information', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('3 events')).toBeInTheDocument();
      });

      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
    });

    it('should show filtered count when search is active', async () => {
      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('event-item')).toHaveLength(3);
      });

      const searchInput = screen.getByPlaceholderText(/Search events/);
      fireEvent.change(searchInput, { target: { value: 'Created' } });

      await waitFor(() => {
        expect(screen.getByText('1 events (filtered from 3)')).toBeInTheDocument();
      });
    });

    it('should show auto-refresh status when enabled', async () => {
      render(<ResourceEvents resource={mockResource} autoRefresh={true} refreshInterval={15000} />);

      await waitFor(() => {
        expect(screen.getByText('Auto-refreshing every 15s')).toBeInTheDocument();
      });
    });
  });

  describe('Custom Props', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should apply custom className', async () => {
      render(<ResourceEvents resource={mockResource} className="custom-class" />);

      await waitFor(() => {
        const container = screen.getByTestId('resource-events');
        expect(container).toHaveClass('custom-class');
      });
    });

    it('should use custom refresh interval', async () => {
      render(<ResourceEvents resource={mockResource} autoRefresh={true} refreshInterval={1000} />);

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
      });

      act(() => {
        vi.advanceTimersByTime(1000);
      });

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('Cleanup', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should cleanup intervals on unmount', async () => {
      const { unmount } = render(<ResourceEvents resource={mockResource} autoRefresh={true} />);

      await waitFor(() => {
        expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
      });

      unmount();

      // Advance time to ensure intervals are cleared
      act(() => {
        vi.advanceTimersByTime(60000);
      });

      // Should not make additional API calls after unmount
      expect(kubernetesApi.getResourceEvents).toHaveBeenCalledTimes(1);
    });
  });

  describe('Event Source Display', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: mockEvents });
    });

    it('should handle source component same as host', async () => {
      const eventsWithSameHost = [
        {
          ...mockEvents[0],
          source: { component: 'kubelet', host: 'kubelet' },
        },
      ];
      vi.mocked(kubernetesApi.getResourceEvents).mockResolvedValue({ events: eventsWithSameHost });

      render(<ResourceEvents resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('kubelet')).toBeInTheDocument();
      });

      // Should not show "on kubelet" when host is same as component
      expect(screen.queryByText('on kubelet')).not.toBeInTheDocument();
    });
  });
});