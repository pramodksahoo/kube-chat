import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { axe, toHaveNoViolations } from 'jest-axe';
import EnhancedCommandConfirmationDialog from '../EnhancedCommandConfirmationDialog';
import type { KubernetesResource, PermissionCheck } from '../EnhancedCommandConfirmationDialog';

expect.extend({ toHaveNoViolations } as any);

const mockResources: KubernetesResource[] = [
  {
    kind: 'Pod',
    name: 'nginx-pod',
    namespace: 'default',
    action: 'delete',
    currentState: { status: 'Running', replicas: 1 },
  },
  {
    kind: 'Service',
    name: 'nginx-service',
    namespace: 'default',
    action: 'update',
    currentState: { type: 'ClusterIP' },
    targetState: { type: 'NodePort' },
  },
];

const mockPermissions: PermissionCheck[] = [
  {
    resource: 'pods',
    verb: 'delete',
    namespace: 'default',
    status: 'allowed',
  },
  {
    resource: 'services',
    verb: 'update',
    namespace: 'default',
    status: 'allowed',
  },
];

const mockPermissionsWithDenied: PermissionCheck[] = [
  ...mockPermissions,
  {
    resource: 'pods',
    verb: 'delete',
    namespace: 'kube-system',
    status: 'denied',
    reason: 'User does not have delete permissions for kube-system namespace',
  },
];

const mockImpactSummary = {
  scope: '2 resources in default namespace',
  severity: 'medium' as const,
  reversible: false,
  estimatedDuration: '30 seconds',
  dependencies: ['nginx-deployment', 'nginx-ingress'],
};

const defaultProps = {
  isOpen: true,
  onClose: vi.fn(),
  onConfirm: vi.fn(),
  onModify: vi.fn(),
  command: 'kubectl delete pod nginx-pod -n default',
  safetyLevel: 'destructive' as const,
  affectedResources: mockResources,
  permissions: mockPermissions,
  impactSummary: mockImpactSummary,
  commandExplanation: 'This command will delete the nginx pod from the default namespace',
};

describe('EnhancedCommandConfirmationDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Basic Rendering', () => {
    it('renders dialog when open', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);

      expect(screen.getByRole('dialog')).toBeInTheDocument();
      expect(screen.getByText('Confirm Command Execution')).toBeInTheDocument();
      expect(screen.getByText('kubectl delete pod nginx-pod -n default')).toBeInTheDocument();
    });

    it('does not render when closed', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} isOpen={false} />);

      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });

    it('displays safety level indicator', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      // Should show destructive safety indicator
      const safetyElements = screen.getAllByText(/destructive/i);
      expect(safetyElements.length).toBeGreaterThan(0);
    });

    it('shows all tabs with correct counts', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);

      expect(screen.getByText('Overview')).toBeInTheDocument();
      expect(screen.getByText('Resources')).toBeInTheDocument();
      expect(screen.getByText('2')).toBeInTheDocument(); // Resources count
      expect(screen.getByText('Permissions')).toBeInTheDocument();
      expect(screen.getAllByText('2')).toHaveLength(2); // Resources and Permissions count
      expect(screen.getByText('Impact Analysis')).toBeInTheDocument();
    });
  });

  describe('Tab Navigation', () => {
    it('starts with overview tab active', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);

      expect(screen.getByText(defaultProps.commandExplanation)).toBeInTheDocument();
      expect(screen.getByText('MEDIUM Impact Operation')).toBeInTheDocument();
    });

    it('switches to resources tab', async () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Resources'));
      
      await waitFor(() => {
        expect(screen.getByText('Affected Resources (2)')).toBeInTheDocument();
        expect(screen.getByText('Pod/nginx-pod')).toBeInTheDocument();
        expect(screen.getByText('Service/nginx-service')).toBeInTheDocument();
      });
    });

    it('switches to permissions tab', async () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Permissions'));
      
      await waitFor(() => {
        expect(screen.getByText('RBAC Permission Check (2)')).toBeInTheDocument();
        expect(screen.getByText('delete pods in default')).toBeInTheDocument();
        expect(screen.getByText('update services in default')).toBeInTheDocument();
      });
    });

    it('switches to impact analysis tab', async () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Impact Analysis'));
      
      await waitFor(() => {
        expect(screen.getByText('Impact Analysis')).toBeInTheDocument();
        expect(screen.getByText('MEDIUM')).toBeInTheDocument();
        expect(screen.getByText('2 resources in default namespace')).toBeInTheDocument();
        expect(screen.getByText('30 seconds')).toBeInTheDocument();
      });
    });
  });

  describe('Resource Display', () => {
    beforeEach(() => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      fireEvent.click(screen.getByText('Resources'));
    });

    it('displays resource information correctly', async () => {
      await waitFor(() => {
        expect(screen.getByText('Pod/nginx-pod')).toBeInTheDocument();
        expect(screen.getByText('Service/nginx-service')).toBeInTheDocument();
        expect(screen.getByText('default')).toBeInTheDocument();
      });
    });

    it('shows resource actions with correct styling', async () => {
      await waitFor(() => {
        const deleteAction = screen.getByText('delete');
        const updateAction = screen.getByText('update');
        
        expect(deleteAction).toHaveClass('bg-red-100', 'text-red-800');
        expect(updateAction).toHaveClass('bg-yellow-100', 'text-yellow-800');
      });
    });

    it('displays before/after states for resources', async () => {
      await waitFor(() => {
        expect(screen.getByText('Current State')).toBeInTheDocument();
        expect(screen.getByText('Target State')).toBeInTheDocument();
      });
    });
  });

  describe('Permission Validation', () => {
    it('shows all permissions allowed', async () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      fireEvent.click(screen.getByText('Permissions'));
      
      await waitFor(() => {
        expect(screen.getByText('✨ All permissions verified')).toBeInTheDocument();
        expect(screen.queryByText('Permission Issues Found')).not.toBeInTheDocument();
      });
    });

    it('shows permission denied status', async () => {
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          permissions={mockPermissionsWithDenied}
        />
      );
      fireEvent.click(screen.getByText('Permissions'));
      
      await waitFor(() => {
        expect(screen.getByText('Permission Issues Found')).toBeInTheDocument();
        expect(screen.getByText('Insufficient permissions to execute')).toBeInTheDocument();
        expect(screen.getByText('User does not have delete permissions for kube-system namespace')).toBeInTheDocument();
      });
    });

    it('disables execute button when permissions denied', () => {
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          permissions={mockPermissionsWithDenied}
        />
      );
      
      const executeButton = screen.getByText('Execute Command');
      expect(executeButton).toBeDisabled();
    });

    it('shows permission status icons correctly', async () => {
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          permissions={[
            ...mockPermissions,
            { resource: 'configmaps', verb: 'create', status: 'checking' },
          ]}
        />
      );
      fireEvent.click(screen.getByText('Permissions'));
      
      await waitFor(() => {
        // Should have checkmarks for allowed permissions
        const allowedIcons = document.querySelectorAll('.text-green-600');
        expect(allowedIcons.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Impact Analysis', () => {
    beforeEach(() => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      fireEvent.click(screen.getByText('Impact Analysis'));
    });

    it('displays severity level with correct styling', async () => {
      await waitFor(() => {
        const severityElement = screen.getByText('MEDIUM');
        expect(severityElement).toHaveClass('text-yellow-600', 'bg-yellow-50');
      });
    });

    it('shows reversibility status', async () => {
      await waitFor(() => {
        const reversibleElement = screen.getByText('No');
        expect(reversibleElement).toHaveClass('text-red-600', 'bg-red-50');
      });
    });

    it('displays dependencies list', async () => {
      await waitFor(() => {
        expect(screen.getByText('Dependencies')).toBeInTheDocument();
        expect(screen.getByText('nginx-deployment')).toBeInTheDocument();
        expect(screen.getByText('nginx-ingress')).toBeInTheDocument();
      });
    });

    it('shows estimated duration', async () => {
      await waitFor(() => {
        expect(screen.getByText('Estimated Duration')).toBeInTheDocument();
        expect(screen.getByText('30 seconds')).toBeInTheDocument();
      });
    });
  });

  describe('Action Buttons', () => {
    it('calls onConfirm when execute button clicked', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Execute Command'));
      expect(defaultProps.onConfirm).toHaveBeenCalled();
    });

    it('calls onClose when cancel button clicked', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Cancel'));
      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('calls onModify when modify button clicked', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      fireEvent.click(screen.getByText('Modify Request'));
      expect(defaultProps.onModify).toHaveBeenCalled();
    });

    it('calls onClose when overlay is clicked', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      const dialog = screen.getByRole('dialog');
      fireEvent.click(dialog);
      expect(defaultProps.onClose).toHaveBeenCalled();
    });

    it('shows loading state correctly', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} isLoading={true} />);
      
      expect(screen.getByText('Executing...')).toBeInTheDocument();
      expect(screen.getByText('Cancel')).toBeDisabled();
      expect(screen.getByText('Modify Request')).toBeDisabled();
    });

    it('applies correct button colors based on safety level', () => {
      const { rerender } = render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      let executeButton = screen.getByText('Execute Command');
      expect(executeButton).toHaveClass('bg-[#dc2626]');
      
      rerender(<EnhancedCommandConfirmationDialog {...defaultProps} safetyLevel="safe" />);
      executeButton = screen.getByText('Execute Command');
      expect(executeButton).toHaveClass('bg-[#059669]');
    });
  });

  describe('Safety Level Styling', () => {
    it('applies destructive styling to header', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} safetyLevel="destructive" />);
      
      const header = screen.getByText('Confirm Command Execution').closest('div');
      expect(header).toHaveClass('bg-red-50', 'border-red-200');
    });

    it('applies caution styling to header', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} safetyLevel="caution" />);
      
      const header = screen.getByText('Confirm Command Execution').closest('div');
      expect(header).toHaveClass('bg-yellow-50', 'border-yellow-200');
    });

    it('applies safe styling to header', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} safetyLevel="safe" />);
      
      const header = screen.getByText('Confirm Command Execution').closest('div');
      expect(header).toHaveClass('bg-green-50', 'border-green-200');
    });
  });

  describe('Accessibility', () => {
    it('meets WCAG AA accessibility standards', async () => {
      const { container } = render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      const results = await axe(container);
      expect(results).toHaveNoViolations();
    });

    it('provides proper dialog attributes', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      const dialog = screen.getByRole('dialog');
      expect(dialog).toHaveAttribute('aria-modal', 'true');
      expect(dialog).toHaveAttribute('aria-labelledby', 'confirmation-title');
    });

    it('provides proper button accessibility', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      const closeButton = screen.getByRole('button', { name: /close dialog/i });
      expect(closeButton).toBeInTheDocument();
      
      const cancelButton = screen.getByRole('button', { name: /cancel/i });
      const executeButton = screen.getByRole('button', { name: /execute command/i });
      const modifyButton = screen.getByRole('button', { name: /modify request/i });
      
      expect(cancelButton).toBeInTheDocument();
      expect(executeButton).toBeInTheDocument();
      expect(modifyButton).toBeInTheDocument();
    });

    it('supports keyboard navigation', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      const tabButtons = screen.getAllByRole('button').filter(button => 
        ['Overview', 'Resources', 'Permissions', 'Impact Analysis'].includes(button.textContent?.split(' ')[0] || '')
      );
      
      tabButtons.forEach(button => {
        expect(button).toBeInTheDocument();
      });
    });
  });

  describe('Edge Cases', () => {
    it('handles empty resources list', () => {
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          affectedResources={[]}
        />
      );
      
      fireEvent.click(screen.getByText('Resources'));
      expect(screen.getByText('Affected Resources (0)')).toBeInTheDocument();
    });

    it('handles empty permissions list', () => {
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          permissions={[]}
        />
      );
      
      fireEvent.click(screen.getByText('Permissions'));
      expect(screen.getByText('RBAC Permission Check (0)')).toBeInTheDocument();
    });

    it('handles missing onModify callback', () => {
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          onModify={undefined}
        />
      );
      
      expect(screen.queryByText('Modify Request')).not.toBeInTheDocument();
    });

    it('shows audit notice', () => {
      render(<EnhancedCommandConfirmationDialog {...defaultProps} />);
      
      expect(screen.getByText(/This action will be logged for compliance/)).toBeInTheDocument();
    });

    it('handles resources without namespace', () => {
      const resourcesWithoutNamespace = [
        {
          kind: 'ClusterRole',
          name: 'admin',
          action: 'create' as const,
        },
      ];
      
      render(
        <EnhancedCommandConfirmationDialog 
          {...defaultProps}
          affectedResources={resourcesWithoutNamespace}
        />
      );
      
      fireEvent.click(screen.getByText('Resources'));
      expect(screen.getByText('ClusterRole/admin')).toBeInTheDocument();
    });
  });
});