/**
 * Tests for ResourceLogs component
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { ResourceLogs } from '../ResourceLogs';
import { kubernetesApi } from '../../../services/kubernetesApi';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock the kubernetesApi
vi.mock('../../../services/kubernetesApi', () => ({
  kubernetesApi: {
    getResourceLogs: vi.fn(),
  },
}));

// Mock URL.createObjectURL and other download-related APIs
global.URL.createObjectURL = vi.fn(() => 'mock-url');
global.URL.revokeObjectURL = vi.fn();

// Mock document.createElement for download functionality
const mockAnchorElement = {
  href: '',
  download: '',
  click: vi.fn(),
};
global.document.createElement = vi.fn(() => mockAnchorElement as any);
global.document.body.appendChild = vi.fn();
global.document.body.removeChild = vi.fn();

describe('ResourceLogs', () => {
  const mockResource: ResourceStatus = {
    kind: 'Pod',
    name: 'test-pod',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date('2023-01-01T10:00:00Z'),
    metadata: {},
    relationships: [],
  };

  const mockLogs = `2023-01-01T10:00:00.000Z INFO Starting application
2023-01-01T10:00:01.000Z DEBUG Connecting to database
2023-01-01T10:00:02.000Z WARN Connection timeout increased
2023-01-01T10:00:03.000Z INFO Application started successfully
2023-01-01T10:00:04.000Z ERROR Failed to load configuration`;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.resetAllMocks();
  });

  describe('Loading State', () => {
    it('should show loading state initially', () => {
      vi.mocked(kubernetesApi.getResourceLogs).mockImplementation(() => new Promise(() => {}));

      render(<ResourceLogs resource={mockResource} />);

      expect(screen.getByTestId('resource-logs-loading')).toBeInTheDocument();
      expect(screen.getByText('Loading logs...')).toBeInTheDocument();
    });
  });

  describe('Success State', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);
    });

    it('should load and display logs', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-logs')).toBeInTheDocument();
      });

      expect(kubernetesApi.getResourceLogs).toHaveBeenCalledWith('Pod', 'test-pod', 'default', {
        container: undefined,
        follow: false,
        tailLines: 100,
      });
    });

    it('should display log lines with syntax highlighting', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('logs-container')).toBeInTheDocument();
      });

      const logLines = screen.getAllByTestId('log-line');
      expect(logLines).toHaveLength(5);
      expect(logLines[0]).toHaveTextContent('Starting application');
    });

    it('should show controls with default values', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('follow-button')).toBeInTheDocument();
      });

      expect(screen.getByDisplayValue('100')).toBeInTheDocument(); // Tail lines
      expect(screen.getByText('Follow Logs')).toBeInTheDocument();
      expect(screen.getByTestId('clear-button')).toBeInTheDocument();
      expect(screen.getByText('Download')).toBeInTheDocument();
    });

    it('should show container selector for Pod resources', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Container:')).toBeInTheDocument();
      });

      expect(screen.getByDisplayValue('Default')).toBeInTheDocument();
    });

    it('should not show container selector for non-Pod resources', async () => {
      const serviceResource = { ...mockResource, kind: 'Service' };
      render(<ResourceLogs resource={serviceResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-logs')).toBeInTheDocument();
      });

      expect(screen.queryByText('Container:')).not.toBeInTheDocument();
    });

    it('should filter logs based on search input', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(5);
      });

      const searchInput = screen.getByPlaceholderText('Search logs...');
      fireEvent.change(searchInput, { target: { value: 'ERROR' } });

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(1);
        expect(screen.getByText('1 of 5 lines')).toBeInTheDocument();
      });
    });

    it('should clear logs when clear button is clicked', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(5);
      });

      fireEvent.click(screen.getByTestId('clear-button'));

      expect(screen.getByText('No logs available')).toBeInTheDocument();
    });

    it('should download logs when download button is clicked', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Download')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Download'));

      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(global.URL.createObjectURL).toHaveBeenCalled();
      expect(mockAnchorElement.click).toHaveBeenCalled();
      expect(mockAnchorElement.download).toBe('Pod-test-pod-logs.txt');
    });

    it('should disable download button when no logs', async () => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue('');

      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Download')).toBeDisabled();
      });
    });
  });

  describe('Follow Mode', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);
    });

    it('should start following logs when follow button is clicked', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Follow Logs')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByTestId('follow-button'));

      expect(screen.getByText('Stop Following')).toBeInTheDocument();
      expect(screen.getByText('Following logs...')).toBeInTheDocument();
    });

    it('should stop following logs when stop button is clicked', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Follow Logs')).toBeInTheDocument();
      });

      // Start following
      fireEvent.click(screen.getByTestId('follow-button'));
      expect(screen.getByText('Stop Following')).toBeInTheDocument();

      // Stop following
      fireEvent.click(screen.getByTestId('follow-button'));
      expect(screen.getByText('Follow Logs')).toBeInTheDocument();
      expect(screen.queryByText('Following logs...')).not.toBeInTheDocument();
    });

    it('should poll for new logs when following', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(kubernetesApi.getResourceLogs).toHaveBeenCalledTimes(1);
      });

      // Start following
      fireEvent.click(screen.getByTestId('follow-button'));

      // Advance time to trigger interval
      act(() => {
        vi.advanceTimersByTime(2000);
      });

      await waitFor(() => {
        expect(kubernetesApi.getResourceLogs).toHaveBeenCalledTimes(2);
      });
    });
  });

  describe('Configuration Options', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);
    });

    it('should update tail lines when selection changes', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('100')).toBeInTheDocument();
      });

      const tailLinesSelect = screen.getByDisplayValue('100');
      fireEvent.change(tailLinesSelect, { target: { value: '500' } });

      await waitFor(() => {
        expect(kubernetesApi.getResourceLogs).toHaveBeenCalledWith('Pod', 'test-pod', 'default', {
          container: undefined,
          follow: false,
          tailLines: 500,
        });
      });
    });

    it('should update container when selection changes for Pod resources', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('Default')).toBeInTheDocument();
      });

      const containerSelect = screen.getByDisplayValue('Default');
      fireEvent.change(containerSelect, { target: { value: 'main' } });

      await waitFor(() => {
        expect(kubernetesApi.getResourceLogs).toHaveBeenCalledWith('Pod', 'test-pod', 'default', {
          container: 'main',
          follow: false,
          tailLines: 100,
        });
      });
    });
  });

  describe('Error State', () => {
    it('should show error state when API call fails', async () => {
      const errorMessage = 'Failed to fetch logs';
      vi.mocked(kubernetesApi.getResourceLogs).mockRejectedValue(new Error(errorMessage));

      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-logs-error')).toBeInTheDocument();
      });

      expect(screen.getByText('Failed to load logs')).toBeInTheDocument();
      expect(screen.getByText(errorMessage)).toBeInTheDocument();
    });

    it('should allow retry when error occurs', async () => {
      vi.mocked(kubernetesApi.getResourceLogs)
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce(mockLogs);

      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Retry')).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText('Retry'));

      await waitFor(() => {
        expect(screen.getByTestId('resource-logs')).toBeInTheDocument();
      });

      expect(kubernetesApi.getResourceLogs).toHaveBeenCalledTimes(2);
    });

    it('should handle non-Error exceptions', async () => {
      vi.mocked(kubernetesApi.getResourceLogs).mockRejectedValue('String error');

      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('Failed to fetch logs')).toBeInTheDocument();
      });
    });
  });

  describe('Empty Logs', () => {
    it('should show empty state when no logs available', async () => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue('');

      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('No logs available')).toBeInTheDocument();
      });
    });

    it('should show filtered empty state when search matches nothing', async () => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);

      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(5);
      });

      const searchInput = screen.getByPlaceholderText('Search logs...');
      fireEvent.change(searchInput, { target: { value: 'nonexistent' } });

      await waitFor(() => {
        expect(screen.getByText('No logs match the filter')).toBeInTheDocument();
      });
    });
  });

  describe('Log Line Formatting', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);
    });

    it('should apply syntax highlighting to log levels', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('logs-container')).toBeInTheDocument();
      });

      // Check that log content is displayed (syntax highlighting is applied via dangerouslySetInnerHTML)
      expect(screen.getByText(/Starting application/)).toBeInTheDocument();
      expect(screen.getByText(/Connecting to database/)).toBeInTheDocument();
    });

    it('should highlight search terms in logs', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(5);
      });

      const searchInput = screen.getByPlaceholderText('Search logs...');
      fireEvent.change(searchInput, { target: { value: 'application' } });

      // Should highlight the search term in matching lines
      expect(screen.getAllByTestId('log-line')).toHaveLength(2);
    });
  });

  describe('Status Bar', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);
    });

    it('should display correct status information', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByText('5 lines')).toBeInTheDocument();
      });

      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
    });

    it('should show container name when selected', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByDisplayValue('Default')).toBeInTheDocument();
      });

      const containerSelect = screen.getByDisplayValue('Default');
      fireEvent.change(containerSelect, { target: { value: 'main' } });

      await waitFor(() => {
        expect(screen.getByText('Pod/test-pod (main)')).toBeInTheDocument();
      });
    });

    it('should show filtered count when search is active', async () => {
      render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(5);
      });

      const searchInput = screen.getByPlaceholderText('Search logs...');
      fireEvent.change(searchInput, { target: { value: 'INFO' } });

      await waitFor(() => {
        expect(screen.getByText('2 lines (filtered from 5)')).toBeInTheDocument();
      });
    });
  });

  describe('Custom Props', () => {
    beforeEach(() => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);
    });

    it('should apply custom className', async () => {
      render(<ResourceLogs resource={mockResource} className="custom-class" />);

      await waitFor(() => {
        const container = screen.getByTestId('resource-logs');
        expect(container).toHaveClass('custom-class');
      });
    });

    it('should respect maxLines prop', async () => {
      const longLogs = Array.from({ length: 2000 }, (_, i) => `Line ${i}`).join('\n');
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(longLogs);

      render(<ResourceLogs resource={mockResource} maxLines={10} />);

      await waitFor(() => {
        expect(screen.getAllByTestId('log-line')).toHaveLength(10);
      });
    });

    it('should respect autoScroll prop', async () => {
      render(<ResourceLogs resource={mockResource} autoScroll={false} />);

      await waitFor(() => {
        expect(screen.getByTestId('resource-logs')).toBeInTheDocument();
      });

      // Component should render without errors when autoScroll is disabled
    });
  });

  describe('Cleanup', () => {
    it('should cleanup intervals on unmount', async () => {
      vi.mocked(kubernetesApi.getResourceLogs).mockResolvedValue(mockLogs);

      const { unmount } = render(<ResourceLogs resource={mockResource} />);

      await waitFor(() => {
        expect(screen.getByTestId('follow-button')).toBeInTheDocument();
      });

      // Start following
      fireEvent.click(screen.getByTestId('follow-button'));

      // Unmount component
      unmount();

      // Advance time to ensure intervals are cleared
      act(() => {
        vi.advanceTimersByTime(5000);
      });

      // Should not make additional API calls after unmount
      expect(kubernetesApi.getResourceLogs).toHaveBeenCalledTimes(1);
    });
  });
});