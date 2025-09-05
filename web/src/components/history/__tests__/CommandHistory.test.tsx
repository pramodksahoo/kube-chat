import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import CommandHistory from '../CommandHistory';
import type { HistoryEntry } from '../CommandHistory';

expect.extend(toHaveNoViolations);

const mockEntries: HistoryEntry[] = [
  {
    id: 'cmd-1',
    command: 'kubectl get pods',
    timestamp: '2024-01-01T10:00:00Z',
    status: 'completed',
    duration: 1250,
    safetyLevel: 'safe',
    exitCode: 0,
    tags: ['query', 'pods'],
  },
  {
    id: 'cmd-2',
    command: 'kubectl delete pod nginx-pod',
    timestamp: '2024-01-01T09:30:00Z',
    status: 'failed',
    duration: 500,
    safetyLevel: 'destructive',
    exitCode: 1,
    error: 'pod "nginx-pod" not found',
    tags: ['delete'],
  },
  {
    id: 'cmd-3',
    command: 'kubectl describe pod test-pod',
    timestamp: '2024-01-01T09:00:00Z',
    status: 'completed',
    duration: 800,
    safetyLevel: 'safe',
    exitCode: 0,
    output: 'Pod details...',
    tags: ['describe', 'pods'],
  },
];

const defaultProps = {
  entries: mockEntries,
};

describe('CommandHistory', () => {
  const mockOnRerun = vi.fn();
  const mockOnDelete = vi.fn();
  const mockOnExport = vi.fn();
  const mockOnClearAll = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('renders command history with entries', () => {
      render(<CommandHistory {...defaultProps} />);

      expect(screen.getByText('Command History')).toBeInTheDocument();
      expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
      expect(screen.getByText('kubectl delete pod nginx-pod')).toBeInTheDocument();
      expect(screen.getByText('kubectl describe pod test-pod')).toBeInTheDocument();
    });

    it('displays empty state when no entries', () => {
      render(<CommandHistory entries={[]} />);

      expect(screen.getByText('No command history')).toBeInTheDocument();
      expect(screen.getByText('Your executed commands will appear here')).toBeInTheDocument();
    });

    it('shows entry details correctly', () => {
      render(<CommandHistory {...defaultProps} />);

      expect(screen.getByText('Exit: 0')).toBeInTheDocument();
      expect(screen.getByText('Exit: 1')).toBeInTheDocument();
      expect(screen.getByText('pod "nginx-pod" not found')).toBeInTheDocument();
      expect(screen.getAllByText('safe')).toHaveLength(2);
      expect(screen.getByText('destructive')).toBeInTheDocument();
    });
  });

  describe('Filtering', () => {
    it('filters by status', async () => {
      render(<CommandHistory {...defaultProps} />);

      // All entries should be visible initially
      expect(screen.getAllByText(/kubectl/)).toHaveLength(3);

      // Click on "Success" filter
      fireEvent.click(screen.getByText('Success (2)'));

      await waitFor(() => {
        expect(screen.getAllByText(/kubectl/)).toHaveLength(2);
        expect(screen.queryByText('kubectl delete pod nginx-pod')).not.toBeInTheDocument();
      });

      // Click on "Failed" filter
      fireEvent.click(screen.getByText('Failed (1)'));

      await waitFor(() => {
        expect(screen.getAllByText(/kubectl/)).toHaveLength(1);
        expect(screen.getByText('kubectl delete pod nginx-pod')).toBeInTheDocument();
      });
    });

    it('filters by search term', async () => {
      render(<CommandHistory {...defaultProps} />);

      const searchInput = screen.getByPlaceholderText('Search commands, output, or tags...');
      
      fireEvent.change(searchInput, { target: { value: 'delete' } });

      await waitFor(() => {
        expect(screen.getAllByText(/kubectl/)).toHaveLength(1);
        expect(screen.getByText('kubectl delete pod nginx-pod')).toBeInTheDocument();
      });

      // Search by tag
      fireEvent.change(searchInput, { target: { value: 'pods' } });

      await waitFor(() => {
        expect(screen.getAllByText(/kubectl/)).toHaveLength(2); // Two entries have 'pods' tag
      });
    });

    it('clears filters', async () => {
      render(<CommandHistory {...defaultProps} />);

      // Apply filters
      fireEvent.click(screen.getByText('Failed (1)'));
      const searchInput = screen.getByPlaceholderText('Search commands, output, or tags...');
      fireEvent.change(searchInput, { target: { value: 'test' } });

      await waitFor(() => {
        expect(screen.getByText('No commands match your current filters')).toBeInTheDocument();
      });

      // Clear filters
      fireEvent.click(screen.getByText('Clear filters'));

      await waitFor(() => {
        expect(screen.getAllByText(/kubectl/)).toHaveLength(3);
      });
    });
  });

  describe('Sorting', () => {
    it('sorts by different criteria', async () => {
      render(<CommandHistory {...defaultProps} />);

      const sortSelect = screen.getByDisplayValue('Newest First');

      // Sort by command alphabetically
      fireEvent.change(sortSelect, { target: { value: 'command-asc' } });

      await waitFor(() => {
        const commands = screen.getAllByText(/kubectl/);
        expect(commands[0]).toHaveTextContent('kubectl delete pod nginx-pod');
        expect(commands[1]).toHaveTextContent('kubectl describe pod test-pod');
        expect(commands[2]).toHaveTextContent('kubectl get pods');
      });

      // Sort by duration
      fireEvent.change(sortSelect, { target: { value: 'duration-desc' } });

      await waitFor(() => {
        const commands = screen.getAllByText(/kubectl/);
        expect(commands[0]).toHaveTextContent('kubectl get pods'); // Longest duration
      });
    });
  });

  describe('Selection and Bulk Actions', () => {
    it('selects individual entries', () => {
      render(<CommandHistory {...defaultProps} onDelete={mockOnDelete} />);

      const checkboxes = screen.getAllByRole('checkbox');
      const firstEntryCheckbox = checkboxes[1]; // Skip "Select All" checkbox

      fireEvent.click(firstEntryCheckbox);

      expect(screen.getByText('Select All (1 selected)')).toBeInTheDocument();
    });

    it('selects all entries', () => {
      render(<CommandHistory {...defaultProps} onDelete={mockOnDelete} />);

      const selectAllCheckbox = screen.getByText('Select All (0 selected)').previousElementSibling as HTMLInputElement;
      fireEvent.click(selectAllCheckbox);

      expect(screen.getByText('Select All (3 selected)')).toBeInTheDocument();
      expect(screen.getByText('Delete Selected')).toBeInTheDocument();
    });

    it('deletes selected entries', () => {
      render(<CommandHistory {...defaultProps} onDelete={mockOnDelete} />);

      // Select first entry
      const checkboxes = screen.getAllByRole('checkbox');
      fireEvent.click(checkboxes[1]);

      // Delete selected
      fireEvent.click(screen.getByText('Delete Selected'));

      expect(mockOnDelete).toHaveBeenCalledWith('cmd-1');
    });

    it('exports selected entries', () => {
      render(<CommandHistory {...defaultProps} onExport={mockOnExport} />);

      // Select first entry
      const checkboxes = screen.getAllByRole('checkbox');
      fireEvent.click(checkboxes[1]);

      // Export selected
      fireEvent.click(screen.getByText('Export Selected'));

      expect(mockOnExport).toHaveBeenCalledWith([mockEntries[0]]);
    });
  });

  describe('Individual Entry Actions', () => {
    it('reruns command when rerun button is clicked', () => {
      render(<CommandHistory {...defaultProps} onRerun={mockOnRerun} />);

      const rerunButtons = screen.getAllByText('Rerun');
      fireEvent.click(rerunButtons[0]);

      expect(mockOnRerun).toHaveBeenCalledWith(mockEntries[0]);
    });

    it('deletes individual entry', () => {
      render(<CommandHistory {...defaultProps} onDelete={mockOnDelete} />);

      const deleteButtons = screen.getAllByText('Delete');
      fireEvent.click(deleteButtons[0]);

      expect(mockOnDelete).toHaveBeenCalledWith('cmd-1');
    });

    it('hides action buttons when callbacks not provided', () => {
      render(<CommandHistory {...defaultProps} />);

      expect(screen.queryByText('Rerun')).not.toBeInTheDocument();
      expect(screen.queryByText('Delete')).not.toBeInTheDocument();
    });
  });

  describe('Global Actions', () => {
    it('exports all entries', () => {
      render(<CommandHistory {...defaultProps} onExport={mockOnExport} />);

      fireEvent.click(screen.getByText('Export All'));

      expect(mockOnExport).toHaveBeenCalledWith(mockEntries);
    });

    it('clears all entries', () => {
      render(<CommandHistory {...defaultProps} onClearAll={mockOnClearAll} />);

      fireEvent.click(screen.getByText('Clear All'));

      expect(mockOnClearAll).toHaveBeenCalled();
    });

    it('hides global action buttons when callbacks not provided', () => {
      render(<CommandHistory {...defaultProps} />);

      expect(screen.queryByText('Export All')).not.toBeInTheDocument();
      expect(screen.queryByText('Clear All')).not.toBeInTheDocument();
    });
  });

  describe('Status Icons', () => {
    it('displays correct status icons', () => {
      render(<CommandHistory {...defaultProps} />);

      // Should have green checkmarks for completed and red X for failed
      const successIcons = document.querySelectorAll('.bg-green-500');
      const failureIcons = document.querySelectorAll('.bg-red-500');

      expect(successIcons).toHaveLength(2); // Two completed commands
      expect(failureIcons).toHaveLength(1); // One failed command
    });
  });

  describe('Time and Duration Formatting', () => {
    it('formats relative timestamps', () => {
      // Mock current time for consistent testing
      const mockNow = new Date('2024-01-01T10:01:00Z');
      vi.setSystemTime(mockNow);

      render(<CommandHistory {...defaultProps} />);

      expect(screen.getByText('1m ago')).toBeInTheDocument(); // Latest command

      vi.useRealTimers();
    });

    it('formats durations correctly', () => {
      render(<CommandHistory {...defaultProps} />);

      expect(screen.getByText('1.3s')).toBeInTheDocument(); // 1250ms
      expect(screen.getByText('500ms')).toBeInTheDocument(); // 500ms
      expect(screen.getByText('800ms')).toBeInTheDocument(); // 800ms
    });
  });

  describe('Tags Display', () => {
    it('displays tags for entries', () => {
      render(<CommandHistory {...defaultProps} />);

      expect(screen.getByText('query')).toBeInTheDocument();
      expect(screen.getAllByText('pods')).toHaveLength(2);
      expect(screen.getByText('delete')).toBeInTheDocument();
      expect(screen.getByText('describe')).toBeInTheDocument();
    });
  });

  describe('Max Entries Limit', () => {
    it('respects maxEntries limit', () => {
      const manyEntries = Array.from({ length: 10 }, (_, i) => ({
        ...mockEntries[0],
        id: `cmd-${i}`,
        command: `kubectl get pods-${i}`,
      }));

      render(<CommandHistory entries={manyEntries} maxEntries={5} />);

      expect(screen.getAllByText(/kubectl get pods-/)).toHaveLength(5);
      expect(screen.getByText('Showing 5 of 10 commands')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('meets WCAG AA accessibility standards', async () => {
      const { container } = render(<CommandHistory {...defaultProps} />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('provides proper form controls accessibility', () => {
      render(<CommandHistory {...defaultProps} onDelete={mockOnDelete} />);

      const searchInput = screen.getByPlaceholderText('Search commands, output, or tags...');
      const sortSelect = screen.getByDisplayValue('Newest First');
      const checkboxes = screen.getAllByRole('checkbox');

      expect(searchInput).toBeInTheDocument();
      expect(sortSelect).toBeInTheDocument();
      expect(checkboxes.length).toBeGreaterThan(0);
    });

    it('provides proper button accessibility', () => {
      render(
        <CommandHistory 
          {...defaultProps}
          onRerun={mockOnRerun}
          onDelete={mockOnDelete}
          onExport={mockOnExport}
          onClearAll={mockOnClearAll}
        />
      );

      const buttons = screen.getAllByRole('button');
      expect(buttons.length).toBeGreaterThan(0);

      buttons.forEach(button => {
        expect(button).toBeInTheDocument();
      });
    });
  });

  describe('Edge Cases', () => {
    it('handles entries without optional fields', () => {
      const minimalEntries = [{
        id: 'minimal-1',
        command: 'kubectl version',
        timestamp: '2024-01-01T10:00:00Z',
        status: 'completed' as const,
        duration: 100,
        safetyLevel: 'safe' as const,
      }];

      render(<CommandHistory entries={minimalEntries} />);

      expect(screen.getByText('kubectl version')).toBeInTheDocument();
      expect(screen.queryByText('Exit:')).not.toBeInTheDocument();
    });

    it('handles very long commands gracefully', () => {
      const longCommandEntry = {
        ...mockEntries[0],
        command: 'kubectl get pods --all-namespaces --field-selector=status.phase=Running --output=wide --sort-by=.metadata.creationTimestamp --show-labels',
      };

      render(<CommandHistory entries={[longCommandEntry]} />);

      expect(screen.getByText(/kubectl get pods --all-namespaces/)).toBeInTheDocument();
    });
  });
});