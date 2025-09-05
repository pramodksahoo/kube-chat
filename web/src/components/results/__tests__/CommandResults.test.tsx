import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import CommandResults from '../CommandResults';
import type { CommandOutput } from '../CommandResults';

expect.extend(toHaveNoViolations);

const mockTableOutput = `NAME                READY   STATUS    RESTARTS   AGE
nginx-deployment    1/1     Running   0          10m
redis-pod           1/1     Running   1          5m`;

const mockJsonOutput = JSON.stringify({
  apiVersion: 'v1',
  kind: 'Pod',
  metadata: {
    name: 'test-pod',
    namespace: 'default',
  },
  spec: {
    containers: [
      {
        name: 'nginx',
        image: 'nginx:1.21',
      },
    ],
  },
}, null, 2);

const mockYamlOutput = `apiVersion: v1
kind: Pod
metadata:
  name: test-pod
  namespace: default
spec:
  containers:
  - name: nginx
    image: nginx:1.21`;

const successfulOutput: CommandOutput = {
  stdout: mockTableOutput,
  exitCode: 0,
  duration: 1250,
  timestamp: '2024-01-01T10:00:00Z',
};

const failedOutput: CommandOutput = {
  stdout: '',
  stderr: 'Error: pods "nonexistent-pod" not found',
  exitCode: 1,
  duration: 500,
  timestamp: '2024-01-01T10:01:00Z',
};

const jsonOutput: CommandOutput = {
  stdout: mockJsonOutput,
  exitCode: 0,
  duration: 800,
  timestamp: '2024-01-01T10:02:00Z',
};

const yamlOutput: CommandOutput = {
  stdout: mockYamlOutput,
  exitCode: 0,
  duration: 950,
  timestamp: '2024-01-01T10:03:00Z',
};

const defaultProps = {
  executionId: 'exec-123',
  command: 'kubectl get pods',
  output: successfulOutput,
};

describe('CommandResults', () => {
  const mockOnRerun = vi.fn();
  const mockOnExport = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('renders successful command results', () => {
      render(<CommandResults {...defaultProps} />);

      expect(screen.getByText('Command Executed Successfully')).toBeInTheDocument();
      expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
      expect(screen.getByText('Exit code: 0')).toBeInTheDocument();
      expect(screen.getByText(/Completed in 1\.[0-9]s/)).toBeInTheDocument();
      expect(screen.getByText('ID: exec-123')).toBeInTheDocument();
    });

    it('renders failed command results', () => {
      render(
        <CommandResults 
          {...defaultProps}
          output={failedOutput}
        />
      );

      expect(screen.getByText('Command Failed')).toBeInTheDocument();
      expect(screen.getByText('Exit code: 1')).toBeInTheDocument();
      expect(screen.getByText('Error Output')).toBeInTheDocument();
      expect(screen.getByText('Error: pods "nonexistent-pod" not found')).toBeInTheDocument();
    });

    it('displays correct status icons', () => {
      const { rerender } = render(<CommandResults {...defaultProps} />);
      
      // Check for green checkmark icon (success)
      let statusIcon = document.querySelector('.bg-green-500');
      expect(statusIcon).toBeInTheDocument();
      
      rerender(<CommandResults {...defaultProps} output={failedOutput} />);
      
      // Check for red X icon (failure)
      statusIcon = document.querySelector('.bg-red-500');
      expect(statusIcon).toBeInTheDocument();
    });
  });

  describe('Output Format Detection', () => {
    it('detects and formats table output', () => {
      render(<CommandResults {...defaultProps} />);

      expect(screen.getByText('TABLE')).toBeInTheDocument();
      expect(screen.getByText('NAME')).toBeInTheDocument();
      expect(screen.getByText('READY')).toBeInTheDocument();
      expect(screen.getByText('nginx-deployment')).toBeInTheDocument();
      expect(screen.getByText('redis-pod')).toBeInTheDocument();
    });

    it('detects and formats JSON output', () => {
      render(
        <CommandResults 
          {...defaultProps}
          output={jsonOutput}
        />
      );

      expect(screen.getByText('JSON')).toBeInTheDocument();
      expect(screen.getByText('"apiVersion": "v1",')).toBeInTheDocument();
      expect(screen.getByText('"kind": "Pod",')).toBeInTheDocument();
    });

    it('detects and formats YAML output', () => {
      render(
        <CommandResults 
          {...defaultProps}
          output={yamlOutput}
        />
      );

      expect(screen.getByText('YAML')).toBeInTheDocument();
      expect(screen.getByText('apiVersion: v1')).toBeInTheDocument();
      expect(screen.getByText('kind: Pod')).toBeInTheDocument();
    });

    it('handles plain text output', () => {
      const textOutput = {
        ...successfulOutput,
        stdout: 'Simple text output without special formatting',
      };

      render(
        <CommandResults 
          {...defaultProps}
          output={textOutput}
        />
      );

      expect(screen.getByText('TEXT')).toBeInTheDocument();
      expect(screen.getByText('Simple text output without special formatting')).toBeInTheDocument();
    });
  });

  describe('View Mode Toggle', () => {
    it('switches between formatted and raw view', () => {
      render(<CommandResults {...defaultProps} />);

      // Should start in formatted view
      expect(screen.getByText('nginx-deployment')).toBeInTheDocument();
      
      // Switch to raw view
      fireEvent.click(screen.getByText('Raw'));
      
      // Should show raw output
      expect(screen.getByText(mockTableOutput)).toBeInTheDocument();
      
      // Switch back to formatted view
      fireEvent.click(screen.getByText('Formatted'));
      
      // Should show formatted table again
      expect(screen.getByText('NAME')).toBeInTheDocument();
    });

    it('applies correct styling to active view mode button', () => {
      render(<CommandResults {...defaultProps} />);

      const formattedButton = screen.getByText('Formatted');
      const rawButton = screen.getByText('Raw');

      expect(formattedButton).toHaveClass('bg-blue-50', 'text-blue-700');
      expect(rawButton).not.toHaveClass('bg-blue-50', 'text-blue-700');

      fireEvent.click(rawButton);

      expect(rawButton).toHaveClass('bg-blue-50', 'text-blue-700');
      expect(formattedButton).not.toHaveClass('bg-blue-50', 'text-blue-700');
    });
  });

  describe('Action Buttons', () => {
    it('calls onRerun when rerun button is clicked', () => {
      render(
        <CommandResults 
          {...defaultProps}
          onRerun={mockOnRerun}
        />
      );

      fireEvent.click(screen.getByText('Rerun'));
      expect(mockOnRerun).toHaveBeenCalled();
    });

    it('hides rerun button when onRerun is not provided', () => {
      render(<CommandResults {...defaultProps} />);
      
      expect(screen.queryByText('Rerun')).not.toBeInTheDocument();
    });

    it('shows export controls when onExport is provided', () => {
      render(
        <CommandResults 
          {...defaultProps}
          onExport={mockOnExport}
        />
      );

      expect(screen.getByText('Export')).toBeInTheDocument();
      expect(screen.getByDisplayValue('Text')).toBeInTheDocument();
    });

    it('calls onExport with selected format', () => {
      render(
        <CommandResults 
          {...defaultProps}
          onExport={mockOnExport}
        />
      );

      // Change format to JSON
      const formatSelect = screen.getByDisplayValue('Text');
      fireEvent.change(formatSelect, { target: { value: 'json' } });
      
      // Click export
      fireEvent.click(screen.getByText('Export'));
      
      expect(mockOnExport).toHaveBeenCalledWith('json');
    });
  });

  describe('Duration and Timestamp Formatting', () => {
    it('formats duration correctly', () => {
      const testCases = [
        { duration: 500, expected: '500ms' },
        { duration: 1500, expected: '1.5s' },
        { duration: 65000, expected: '1.1m' },
      ];

      testCases.forEach(({ duration, expected }) => {
        const output = { ...successfulOutput, duration };
        const { unmount } = render(
          <CommandResults {...defaultProps} output={output} />
        );
        
        expect(screen.getByText(`Completed in ${expected}`)).toBeInTheDocument();
        unmount();
      });
    });

    it('formats timestamps correctly', () => {
      render(<CommandResults {...defaultProps} />);
      
      // Should format the timestamp (exact format depends on locale)
      const timestampElement = screen.getByText(/•/);
      expect(timestampElement.textContent).toContain('2024');
    });
  });

  describe('Table Rendering', () => {
    it('renders table with proper structure', () => {
      render(<CommandResults {...defaultProps} />);

      // Check table structure
      const table = document.querySelector('table');
      expect(table).toBeInTheDocument();
      
      const headers = table?.querySelectorAll('th');
      expect(headers).toHaveLength(4); // NAME, READY, STATUS, RESTARTS, AGE minus empty ones
      
      const rows = table?.querySelectorAll('tbody tr');
      expect(rows).toHaveLength(2); // nginx-deployment and redis-pod
    });

    it('handles malformed table data gracefully', () => {
      const malformedOutput = {
        ...successfulOutput,
        stdout: 'NAME\nnginx-deployment    incomplete-row',
      };

      render(
        <CommandResults 
          {...defaultProps}
          output={malformedOutput}
        />
      );

      // Should still render without crashing
      expect(screen.getByText('TABLE')).toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('handles empty output gracefully', () => {
      const emptyOutput = {
        stdout: '',
        stderr: '',
        exitCode: 0,
        duration: 100,
        timestamp: '2024-01-01T10:00:00Z',
      };

      render(
        <CommandResults 
          {...defaultProps}
          output={emptyOutput}
        />
      );

      expect(screen.getByText('(no output)')).toBeInTheDocument();
    });

    it('handles invalid JSON gracefully', () => {
      const invalidJsonOutput = {
        ...successfulOutput,
        stdout: '{ invalid json }',
      };

      render(
        <CommandResults 
          {...defaultProps}
          output={invalidJsonOutput}
        />
      );

      // Should fallback to text formatting
      expect(screen.getByText('TEXT')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('meets WCAG AA accessibility standards', async () => {
      const { container } = render(<CommandResults {...defaultProps} />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('provides proper button accessibility', () => {
      render(
        <CommandResults 
          {...defaultProps}
          onRerun={mockOnRerun}
          onExport={mockOnExport}
        />
      );

      const rerunButton = screen.getByRole('button', { name: /rerun/i });
      const exportButton = screen.getByRole('button', { name: /export/i });
      
      expect(rerunButton).toBeInTheDocument();
      expect(exportButton).toBeInTheDocument();
    });

    it('provides proper form accessibility', () => {
      render(
        <CommandResults 
          {...defaultProps}
          onExport={mockOnExport}
        />
      );

      const formatSelect = screen.getByDisplayValue('Text');
      expect(formatSelect).toHaveAttribute('value', 'text');
    });
  });
});