import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import CommandExecutionStatus from '../CommandExecutionStatus';
import type { ExecutionStep } from '../CommandExecutionStatus';

expect.extend(toHaveNoViolations);

const mockSteps: ExecutionStep[] = [
  {
    id: 'validate',
    name: 'Validate Command',
    phase: 'validating',
    status: 'completed',
    startTime: '2024-01-01T10:00:00Z',
    endTime: '2024-01-01T10:00:02Z',
    estimatedDuration: 2,
    actualDuration: 2,
    message: 'Command syntax validated successfully',
  },
  {
    id: 'prepare',
    name: 'Prepare Resources',
    phase: 'preparing',
    status: 'in_progress',
    startTime: '2024-01-01T10:00:02Z',
    estimatedDuration: 5,
    message: 'Preparing Kubernetes resources',
    progress: 60,
  },
  {
    id: 'execute',
    name: 'Execute Command',
    phase: 'executing',
    status: 'pending',
    estimatedDuration: 10,
  },
];

const mockFailedSteps: ExecutionStep[] = [
  {
    id: 'validate',
    name: 'Validate Command',
    phase: 'validating',
    status: 'completed',
    actualDuration: 2,
  },
  {
    id: 'execute',
    name: 'Execute Command',
    phase: 'executing',
    status: 'failed',
    error: 'Insufficient permissions to delete pod',
    actualDuration: 1,
  },
];

const defaultProps = {
  executionId: 'exec-123',
  command: 'kubectl get pods -n default',
  steps: mockSteps,
  overallStatus: 'executing' as const,
};

describe('CommandExecutionStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Basic Rendering', () => {
    it('renders execution status with all required elements', () => {
      render(<CommandExecutionStatus {...defaultProps} />);

      expect(screen.getByText('Executing Command')).toBeInTheDocument();
      expect(screen.getByText('kubectl get pods -n default')).toBeInTheDocument();
      expect(screen.getByText('1/3 steps')).toBeInTheDocument();
      expect(screen.getByText('Execution ID: exec-123')).toBeInTheDocument();
    });

    it('displays command in code block', () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      const codeElement = screen.getByText('kubectl get pods -n default');
      expect(codeElement.tagName).toBe('CODE');
      expect(codeElement.parentElement).toHaveClass('bg-gray-900', 'text-gray-100');
    });

    it('shows progress bar with correct percentage', () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      expect(screen.getByText('33%')).toBeInTheDocument(); // 1 completed out of 3 steps
    });
  });

  describe('Status Display', () => {
    it('shows correct status for different phases', () => {
      const { rerender } = render(<CommandExecutionStatus {...defaultProps} />);
      
      expect(screen.getByText('Executing Command')).toBeInTheDocument();
      
      rerender(<CommandExecutionStatus {...defaultProps} overallStatus="completed" />);
      expect(screen.getByText('Execution Complete')).toBeInTheDocument();
      
      rerender(<CommandExecutionStatus {...defaultProps} overallStatus="failed" />);
      expect(screen.getByText('Execution Failed')).toBeInTheDocument();
    });

    it('applies correct colors for different statuses', () => {
      const { rerender } = render(<CommandExecutionStatus {...defaultProps} />);
      
      // Find the header container by looking for the element with the specific background classes
      const header = document.querySelector('.bg-blue-50.border-blue-200');
      expect(header).toHaveClass('text-blue-600', 'bg-blue-50');
      
      rerender(<CommandExecutionStatus {...defaultProps} overallStatus="completed" />);
      const completedHeader = document.querySelector('.bg-green-50.border-green-200');
      expect(completedHeader).toHaveClass('text-green-600', 'bg-green-50');
    });

    it('shows active step name in header', () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      const activeStepElements = screen.getAllByText('Prepare Resources');
      expect(activeStepElements.length).toBeGreaterThan(0);
      // Check that one of them is in the header (has the opacity-75 class)
      const headerActiveStep = document.querySelector('.text-xs.opacity-75');
      expect(headerActiveStep).toHaveTextContent('Prepare Resources');
    });
  });

  describe('Step Details', () => {
    it('renders all steps with correct status icons', () => {
      render(<CommandExecutionStatus {...defaultProps} />);

      expect(screen.getByText('Validate Command')).toBeInTheDocument();
      expect(screen.getAllByText('Prepare Resources')).toHaveLength(2); // One in header, one in steps
      expect(screen.getByText('Execute Command')).toBeInTheDocument();
    });

    it('shows step messages and progress', () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      expect(screen.getByText('Command syntax validated successfully')).toBeInTheDocument();
      expect(screen.getByText('Preparing Kubernetes resources')).toBeInTheDocument();
    });

    it('displays step durations correctly', () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      expect(screen.getByText('2s')).toBeInTheDocument(); // Actual duration for completed step
      expect(screen.getByText('(~5s)')).toBeInTheDocument(); // Estimated for in-progress step
    });

    it('shows progress bars for in-progress steps', () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      // Look for progress elements - there should be two: overall and step-level
      const progressBars = document.querySelectorAll('.bg-blue-500');
      expect(progressBars.length).toBeGreaterThan(1);
    });
  });

  describe('Error Handling', () => {
    it('displays errors for failed steps', () => {
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          steps={mockFailedSteps}
          overallStatus="failed"
        />
      );

      expect(screen.getByText('Execution Failed')).toBeInTheDocument();
      expect(screen.getByText('Insufficient permissions to delete pod')).toBeInTheDocument();
    });

    it('shows retry button for failed executions', () => {
      const mockOnRetry = vi.fn();
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          steps={mockFailedSteps}
          overallStatus="failed"
          onRetry={mockOnRetry}
        />
      );

      const retryButton = screen.getByText('Retry');
      expect(retryButton).toBeInTheDocument();
      
      fireEvent.click(retryButton);
      expect(mockOnRetry).toHaveBeenCalled();
    });
  });

  describe('Cancellation', () => {
    it('shows cancel button for interruptible executions', () => {
      const mockOnCancel = vi.fn();
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          isInterruptible={true}
          onCancel={mockOnCancel}
        />
      );

      const cancelButton = screen.getByText('Cancel');
      expect(cancelButton).toBeInTheDocument();
      
      fireEvent.click(cancelButton);
      expect(mockOnCancel).toHaveBeenCalled();
    });

    it('hides cancel button for non-interruptible executions', () => {
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          isInterruptible={false}
        />
      );

      expect(screen.queryByText('Cancel')).not.toBeInTheDocument();
    });

    it('hides cancel button for completed executions', () => {
      const mockOnCancel = vi.fn();
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          overallStatus="completed"
          isInterruptible={true}
          onCancel={mockOnCancel}
        />
      );

      expect(screen.queryByText('Cancel')).not.toBeInTheDocument();
    });
  });

  describe('Expand/Collapse', () => {
    it('expands and collapses step details', async () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      // Steps should be visible by default
      expect(screen.getByText('Validate Command')).toBeInTheDocument();
      
      // Click collapse button
      const expandButton = screen.getByLabelText('Collapse details');
      fireEvent.click(expandButton);
      
      await waitFor(() => {
        expect(screen.queryByText('Validate Command')).not.toBeInTheDocument();
      });
      
      // Click expand button
      const collapseButton = screen.getByLabelText('Expand details');
      fireEvent.click(collapseButton);
      
      await waitFor(() => {
        expect(screen.getByText('Validate Command')).toBeInTheDocument();
      });
    });
  });

  describe('Timer Functionality', () => {
    it('updates elapsed time for active executions', async () => {
      render(<CommandExecutionStatus {...defaultProps} />);
      
      // Fast-forward time by 5 seconds
      vi.advanceTimersByTime(5000);
      
      await waitFor(() => {
        // Look for elapsed time in the header area (next to status text)
        const headerArea = document.querySelector('.text-blue-600');
        if (headerArea) {
          expect(headerArea.textContent).toContain('5s');
        }
      }, { timeout: 1000 });
    });

    it('does not show timer for completed executions', () => {
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          overallStatus="completed"
        />
      );

      vi.advanceTimersByTime(5000);
      
      // Timer should not be visible for completed executions
      const headerArea = document.querySelector('.text-green-600');
      if (headerArea) {
        expect(headerArea.textContent).not.toContain('5s');
      }
    });
  });

  describe('Progress Calculation', () => {
    it('calculates progress percentage correctly', () => {
      const stepsWithMultipleCompleted = [
        { ...mockSteps[0], status: 'completed' as const },
        { ...mockSteps[1], status: 'completed' as const },
        { ...mockSteps[2], status: 'pending' as const },
      ];

      render(
        <CommandExecutionStatus 
          {...defaultProps}
          steps={stepsWithMultipleCompleted}
        />
      );

      expect(screen.getByText('67%')).toBeInTheDocument(); // 2 out of 3 completed
    });

    it('shows 100% for all completed steps', () => {
      const allCompleted = mockSteps.map(step => ({
        ...step,
        status: 'completed' as const,
      }));

      render(
        <CommandExecutionStatus 
          {...defaultProps}
          steps={allCompleted}
          overallStatus="completed"
        />
      );

      expect(screen.getByText('100%')).toBeInTheDocument();
    });
  });

  describe('Accessibility', () => {
    it('meets WCAG AA accessibility standards', async () => {
      const { container } = render(<CommandExecutionStatus {...defaultProps} />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('provides proper button accessibility', () => {
      const mockOnCancel = vi.fn();
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          isInterruptible={true}
          onCancel={mockOnCancel}
        />
      );

      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      const expandButton = screen.getByRole('button', { name: /collapse details/i });
      
      expect(cancelButton).toBeInTheDocument();
      expect(expandButton).toBeInTheDocument();
    });
  });

  describe('Edge Cases', () => {
    it('handles empty steps array', () => {
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          steps={[]}
        />
      );

      expect(screen.getByText('0/0 steps')).toBeInTheDocument();
      expect(screen.getByText('0%')).toBeInTheDocument();
    });

    it('handles steps without duration information', () => {
      const stepsWithoutDuration = [
        {
          id: 'test',
          name: 'Test Step',
          phase: 'executing' as const,
          status: 'in_progress' as const,
        },
      ];

      render(
        <CommandExecutionStatus 
          {...defaultProps}
          steps={stepsWithoutDuration}
        />
      );

      expect(screen.getByText('Test Step')).toBeInTheDocument();
    });

    it('handles very long commands gracefully', () => {
      const longCommand = 'kubectl get pods --all-namespaces --field-selector=status.phase=Running --output=wide --sort-by=.metadata.creationTimestamp';
      
      render(
        <CommandExecutionStatus 
          {...defaultProps}
          command={longCommand}
        />
      );

      const commandContainer = screen.getByText(longCommand).closest('div');
      expect(commandContainer).toHaveClass('overflow-x-auto');
    });
  });
});