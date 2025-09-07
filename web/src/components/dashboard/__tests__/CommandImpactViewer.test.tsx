/**
 * Tests for CommandImpactViewer component
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { type CommandImpact, CommandImpactViewer } from '../CommandImpactViewer';
import type { ResourceStatus } from '../../../services/kubernetesApi';

// Mock ResourceStatusIndicator
vi.mock('../ResourceStatusIndicator', () => ({
  ResourceStatusIndicator: vi.fn(({ status, size, showLabel, showIcon }) => (
    <div 
      data-testid={`status-indicator-${status.toLowerCase()}`}
      data-size={size}
      data-show-label={showLabel}
      data-show-icon={showIcon}
    >
      Status: {status}
    </div>
  )),
}));

describe('CommandImpactViewer', () => {
  const baseResource: ResourceStatus = {
    kind: 'Pod',
    name: 'test-pod',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date('2023-01-01T12:00:00Z'),
    metadata: { version: '1.0' },
    relationships: [],
  };

  const mockCreatedImpact: CommandImpact = {
    commandId: 'cmd-123',
    sessionId: 'session-456',
    naturalLanguageInput: 'Create a pod named test-pod',
    generatedCommand: 'kubectl create pod test-pod --image=nginx',
    executedAt: new Date('2023-01-01T12:00:00Z'),
    executedBy: 'user@example.com',
    afterState: baseResource,
    changeType: 'created',
    riskLevel: 'safe',
  };

  const mockUpdatedImpact: CommandImpact = {
    commandId: 'cmd-124',
    sessionId: 'session-456',
    naturalLanguageInput: 'Scale the pod to 3 replicas',
    generatedCommand: 'kubectl scale deployment test-pod --replicas=3',
    executedAt: new Date('2023-01-01T12:30:00Z'),
    executedBy: 'user@example.com',
    beforeState: baseResource,
    afterState: {
      ...baseResource,
      status: 'Warning',
      lastUpdated: new Date('2023-01-01T12:30:00Z'),
      metadata: { version: '1.1', replicas: '3' },
    },
    changeType: 'updated',
    riskLevel: 'caution',
  };

  const mockDeletedImpact: CommandImpact = {
    commandId: 'cmd-125',
    sessionId: 'session-456',
    naturalLanguageInput: 'Delete the test pod',
    generatedCommand: 'kubectl delete pod test-pod',
    executedAt: new Date('2023-01-01T13:00:00Z'),
    executedBy: 'admin@example.com',
    beforeState: baseResource,
    afterState: baseResource, // For deleted resources, afterState might be the last known state
    changeType: 'deleted',
    riskLevel: 'destructive',
  };

  const mockOnViewDetails = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    // Mock current time for consistent time formatting tests
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2023-01-01T14:00:00Z')); // 2 hours after execution
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('Created Impact', () => {
    it('should render created resource impact correctly', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} />);

      expect(screen.getByTestId('command-impact-viewer')).toBeInTheDocument();
      expect(screen.getByTestId('command-impact-viewer')).toHaveAttribute('data-change-type', 'created');
      
      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      expect(screen.getByText('Resource created')).toBeInTheDocument();
      expect(screen.getByText('➕')).toBeInTheDocument();
      expect(screen.getByText('2h ago')).toBeInTheDocument();
      expect(screen.getByText('by user@example.com')).toBeInTheDocument();
    });

    it('should show before/after states for created resource', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} />);

      expect(screen.getByText('Before')).toBeInTheDocument();
      expect(screen.getByText('Resource did not exist')).toBeInTheDocument();
      expect(screen.getByText('After')).toBeInTheDocument();
      expect(screen.getByTestId('status-indicator-ready')).toBeInTheDocument();
    });
  });

  describe('Updated Impact', () => {
    it('should render updated resource impact correctly', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} />);

      expect(screen.getByTestId('command-impact-viewer')).toHaveAttribute('data-change-type', 'updated');
      
      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      expect(screen.getByText('2 changes')).toBeInTheDocument(); // Status + metadata changes
      expect(screen.getByText('✏️')).toBeInTheDocument();
    });

    it('should show before and after states for updated resource', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} />);

      const beforeSection = screen.getByText('Before').closest('div');
      const afterSection = screen.getByText('After').closest('div');

      expect(beforeSection).toBeInTheDocument();
      expect(afterSection).toBeInTheDocument();
      
      // Should have two status indicators (before and after)
      expect(screen.getAllByText(/Status:/)).toHaveLength(2);
    });
  });

  describe('Deleted Impact', () => {
    it('should render deleted resource impact correctly', () => {
      render(<CommandImpactViewer impact={mockDeletedImpact} />);

      expect(screen.getByTestId('command-impact-viewer')).toHaveAttribute('data-change-type', 'deleted');
      
      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      expect(screen.getAllByText('Resource deleted')).toHaveLength(2); // Appears in summary and after section
      expect(screen.getByText('🗑️')).toBeInTheDocument();
      expect(screen.getByText('1h ago')).toBeInTheDocument();
      expect(screen.getByText('by admin@example.com')).toBeInTheDocument();
    });

    it('should show deleted state in after section', () => {
      render(<CommandImpactViewer impact={mockDeletedImpact} />);

      expect(screen.getByText('Before')).toBeInTheDocument();
      expect(screen.getByText('After')).toBeInTheDocument();
      expect(screen.getAllByText('Resource deleted')).toHaveLength(2); // Appears in summary and after section
    });
  });

  describe('Risk Level Styling', () => {
    it('should apply safe risk level styling', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} />);

      const riskText = screen.getByText('Resource created');
      expect(riskText).toHaveClass('text-green-700');
    });

    it('should apply caution risk level styling', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} />);

      const riskText = screen.getByText('2 changes');
      expect(riskText).toHaveClass('text-yellow-700');
    });

    it('should apply destructive risk level styling', () => {
      render(<CommandImpactViewer impact={mockDeletedImpact} />);

      const riskTexts = screen.getAllByText('Resource deleted');
      expect(riskTexts[0]).toHaveClass('text-red-700'); // Check the first occurrence (in summary)
    });

    it('should show risk level indicator', () => {
      render(<CommandImpactViewer impact={mockDeletedImpact} />);

      expect(screen.getByText('Risk Level:')).toBeInTheDocument();
      expect(screen.getByText('Destructive')).toBeInTheDocument();
      
      const riskLevel = screen.getByText('Destructive');
      expect(riskLevel).toHaveClass('text-red-700');
    });
  });

  describe('Details View', () => {
    it('should show command details when showDetails=true', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} showDetails={true} />);

      expect(screen.getByText('Command Request')).toBeInTheDocument();
      expect(screen.getByText('Scale the pod to 3 replicas')).toBeInTheDocument();
      
      expect(screen.getByText('Generated Command')).toBeInTheDocument();
      expect(screen.getByText('kubectl scale deployment test-pod --replicas=3')).toBeInTheDocument();
      
      expect(screen.getByText('Changes')).toBeInTheDocument();
    });

    it('should not show command details by default', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} />);

      expect(screen.queryByText('Command Request')).not.toBeInTheDocument();
      expect(screen.queryByText('Generated Command')).not.toBeInTheDocument();
    });

    it('should show change details for updated resources', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} showDetails={true} />);

      expect(screen.getByText('Changes')).toBeInTheDocument();
      // Should show status change from Ready to Warning
      expect(screen.getByText('Status:')).toBeInTheDocument();
    });
  });

  describe('Compact Mode', () => {
    it('should render in compact mode', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} compact={true} />);

      expect(screen.getByTestId('command-impact-viewer')).toBeInTheDocument();
      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      
      // Should not show before/after comparison in compact mode
      expect(screen.queryByText('Before')).not.toBeInTheDocument();
      expect(screen.queryByText('After')).not.toBeInTheDocument();
    });
  });

  describe('Time Formatting', () => {
    it('should format recent time as "just now"', () => {
      const recentImpact = {
        ...mockCreatedImpact,
        executedAt: new Date('2023-01-01T13:59:30Z'), // 30 seconds ago
      };

      render(<CommandImpactViewer impact={recentImpact} />);
      expect(screen.getByText('just now')).toBeInTheDocument();
      expect(screen.getByText('by user@example.com')).toBeInTheDocument();
    });

    it('should format minutes ago correctly', () => {
      const minutesAgo = {
        ...mockCreatedImpact,
        executedAt: new Date('2023-01-01T13:45:00Z'), // 15 minutes ago
      };

      render(<CommandImpactViewer impact={minutesAgo} />);
      expect(screen.getByText('15m ago')).toBeInTheDocument();
      expect(screen.getByText('by user@example.com')).toBeInTheDocument();
    });

    it('should format days ago correctly', () => {
      const daysAgo = {
        ...mockCreatedImpact,
        executedAt: new Date('2022-12-30T14:00:00Z'), // 2 days ago
      };

      render(<CommandImpactViewer impact={daysAgo} />);
      expect(screen.getByText('2d ago')).toBeInTheDocument();
      expect(screen.getByText('by user@example.com')).toBeInTheDocument();
    });

    it('should handle missing executedBy', () => {
      const impactWithoutUser = {
        ...mockCreatedImpact,
        executedBy: undefined,
      };

      render(<CommandImpactViewer impact={impactWithoutUser} />);
      expect(screen.getByText('2h ago')).toBeInTheDocument();
      expect(screen.queryByText('by')).not.toBeInTheDocument();
    });
  });

  describe('Interactions', () => {
    it('should call onViewDetails when Details button is clicked', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} onViewDetails={mockOnViewDetails} />);

      const detailsButton = screen.getByText('Details');
      fireEvent.click(detailsButton);

      expect(mockOnViewDetails).toHaveBeenCalledWith('cmd-123');
    });

    it('should not render Details button without onViewDetails handler', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} />);

      expect(screen.queryByText('Details')).not.toBeInTheDocument();
    });
  });

  describe('Change Type Icons', () => {
    it('should show correct icons for different change types', () => {
      const { rerender } = render(<CommandImpactViewer impact={mockCreatedImpact} />);
      expect(screen.getByText('➕')).toBeInTheDocument();

      rerender(<CommandImpactViewer impact={mockUpdatedImpact} />);
      expect(screen.getByText('✏️')).toBeInTheDocument();

      rerender(<CommandImpactViewer impact={mockDeletedImpact} />);
      expect(screen.getByText('🗑️')).toBeInTheDocument();
    });
  });

  describe('Styling', () => {
    it('should apply correct background styling for different change types', () => {
      const { rerender } = render(<CommandImpactViewer impact={mockCreatedImpact} />);
      expect(screen.getByTestId('command-impact-viewer')).toHaveClass('bg-green-50', 'border-green-200');

      rerender(<CommandImpactViewer impact={mockUpdatedImpact} />);
      expect(screen.getByTestId('command-impact-viewer')).toHaveClass('bg-blue-50', 'border-blue-200');

      rerender(<CommandImpactViewer impact={mockDeletedImpact} />);
      expect(screen.getByTestId('command-impact-viewer')).toHaveClass('bg-red-50', 'border-red-200');
    });

    it('should apply custom className', () => {
      render(<CommandImpactViewer impact={mockCreatedImpact} className="custom-class" />);

      expect(screen.getByTestId('command-impact-viewer')).toHaveClass('custom-class');
    });
  });

  describe('Status Indicator Integration', () => {
    it('should pass correct props to ResourceStatusIndicator', () => {
      render(<CommandImpactViewer impact={mockUpdatedImpact} />);

      const statusIndicators = screen.getAllByTestId(/status-indicator-/);
      expect(statusIndicators).toHaveLength(2); // Before and after states

      // Check that indicators are rendered with correct props
      statusIndicators.forEach(indicator => {
        expect(indicator).toHaveAttribute('data-size', 'sm');
        expect(indicator).toHaveAttribute('data-show-label', 'true');
        expect(indicator).toHaveAttribute('data-show-icon', 'true');
      });
    });
  });

  describe('Edge Cases', () => {
    it('should handle impact without beforeState', () => {
      const impactWithoutBefore = {
        ...mockCreatedImpact,
        beforeState: undefined,
      };

      render(<CommandImpactViewer impact={impactWithoutBefore} />);

      expect(screen.getByText('Resource created')).toBeInTheDocument();
      expect(screen.getByText('Resource did not exist')).toBeInTheDocument();
    });

    it('should handle impact without risk level', () => {
      const impactWithoutRisk = {
        ...mockCreatedImpact,
        riskLevel: undefined,
      };

      render(<CommandImpactViewer impact={impactWithoutRisk} />);

      expect(screen.getByText('Pod/test-pod')).toBeInTheDocument();
      expect(screen.queryByText('Risk Level:')).not.toBeInTheDocument();
    });

    it('should handle very long command text', () => {
      const longCommandImpact = {
        ...mockCreatedImpact,
        naturalLanguageInput: 'This is a very long natural language command that should be handled gracefully in the UI without breaking the layout',
        generatedCommand: 'kubectl create deployment very-long-name-with-many-parameters --image=nginx:latest --replicas=3 --port=80',
      };

      render(<CommandImpactViewer impact={longCommandImpact} showDetails={true} />);

      expect(screen.getByText(longCommandImpact.naturalLanguageInput)).toBeInTheDocument();
      expect(screen.getByText(longCommandImpact.generatedCommand)).toBeInTheDocument();
    });
  });
});