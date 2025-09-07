/**
 * Tests for CommandHistoryPanel component
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import CommandHistoryPanel from '../CommandHistoryPanel';
import { useCommandHistory, useCommandTracking } from '../../../services/commandHistoryService';
import { usePermissions } from '../../auth/PermissionProvider';
import { useAuditLogging } from '../../../services/auditService';
import type { CommandRecord } from '../../../services/commandHistoryService';

// Mock dependencies
vi.mock('../../../services/commandHistoryService', () => ({
  useCommandHistory: vi.fn(),
  useCommandTracking: vi.fn(),
}));

vi.mock('../../auth/PermissionProvider', () => ({
  usePermissions: vi.fn(),
}));

vi.mock('../../../services/auditService', () => ({
  useAuditLogging: vi.fn(),
}));

describe('CommandHistoryPanel', () => {
  const mockSearchCommands = vi.fn();
  const mockGenerateRollbackCommand = vi.fn();
  const mockGetCommandStatistics = vi.fn();
  const mockLogDashboardInteraction = vi.fn();
  const mockActiveCommands: CommandRecord[] = [];
  const mockClearCompletedCommands = vi.fn();

  const mockCommands: CommandRecord[] = [
    {
      id: 'cmd_1',
      timestamp: new Date('2023-01-01T10:00:00Z'),
      userId: 'user1',
      sessionId: 'session1',
      command: 'kubectl get pods',
      intent: 'list_pods',
      parameters: {},
      status: 'completed',
      executionTime: 1500,
      affectedResources: [
        { kind: 'Pod', name: 'test-pod', namespace: 'default' }
      ],
      resourceChanges: [],
      impactSummary: {
        resourcesAffected: 1,
        namespacesCovered: ['default'],
        changeTypes: ['list'],
        potentialImpact: 'low',
        impactDescription: 'Listed pods in default namespace',
        dependentResources: [],
        rollbackComplexity: 'simple',
      },
      rollbackAvailable: false,
    },
    {
      id: 'cmd_2',
      timestamp: new Date('2023-01-01T11:00:00Z'),
      userId: 'user1',
      sessionId: 'session1',
      command: 'kubectl delete pod bad-pod',
      intent: 'delete_pod',
      parameters: {},
      status: 'failed',
      errorMessage: 'Pod not found',
      affectedResources: [
        { kind: 'Pod', name: 'bad-pod', namespace: 'default' }
      ],
      resourceChanges: [],
      impactSummary: {
        resourcesAffected: 1,
        namespacesCovered: ['default'],
        changeTypes: ['delete'],
        potentialImpact: 'high',
        impactDescription: 'Attempted to delete pod',
        dependentResources: [],
        rollbackComplexity: 'complex',
      },
      rollbackAvailable: false,
    },
    {
      id: 'cmd_3',
      timestamp: new Date('2023-01-01T12:00:00Z'),
      userId: 'user1',
      sessionId: 'session1',
      command: 'kubectl scale deployment web --replicas=3',
      intent: 'scale_deployment',
      parameters: {},
      status: 'completed',
      executionTime: 2000,
      affectedResources: [
        { kind: 'Deployment', name: 'web', namespace: 'default' }
      ],
      resourceChanges: [{
        resource: { kind: 'Deployment', name: 'web', namespace: 'default' },
        changeType: 'scaled',
        fieldChanges: [{
          path: 'spec.replicas',
          oldValue: 1,
          newValue: 3,
          changeType: 'modified',
        }],
        timestamp: new Date('2023-01-01T12:00:00Z'),
        metadata: {
          source: 'command',
          relatedCommandId: 'cmd_3',
        },
      }],
      impactSummary: {
        resourcesAffected: 1,
        namespacesCovered: ['default'],
        changeTypes: ['scale'],
        potentialImpact: 'medium',
        impactDescription: 'Scaled deployment replicas',
        dependentResources: [],
        rollbackComplexity: 'moderate',
      },
      rollbackAvailable: true,
    },
  ];

  const mockStatistics = {
    totalCommands: 10,
    successRate: 80,
    averageExecutionTime: 1750,
    topCommands: [
      { command: 'list_pods', count: 5 },
      { command: 'scale_deployment', count: 3 },
    ],
    topUsers: [
      { userId: 'user1', count: 7 },
      { userId: 'user2', count: 3 },
    ],
    impactDistribution: {
      low: 6,
      medium: 2,
      high: 1,
      critical: 1,
    },
    resourceTypesAffected: {
      Pod: 5,
      Deployment: 3,
      Service: 2,
    },
  };

  beforeEach(() => {
    vi.clearAllMocks();

    vi.mocked(useCommandHistory).mockReturnValue({
      searchCommands: mockSearchCommands,
      generateRollbackCommand: mockGenerateRollbackCommand,
      getCommandStatistics: mockGetCommandStatistics,
      recordCommand: vi.fn(),
      updateCommandStatus: vi.fn(),
      getResourceHistory: vi.fn(),
      getCommandById: vi.fn(),
    });

    vi.mocked(useCommandTracking).mockReturnValue({
      trackCommand: vi.fn(),
      updateCommand: vi.fn(),
      getActiveCommands: vi.fn(() => mockActiveCommands),
      clearCompletedCommands: mockClearCompletedCommands,
      activeCommands: mockActiveCommands,
    });

    vi.mocked(usePermissions).mockReturnValue({
      permissions: {
        canView: { pods: true },
        canEdit: { pods: true },
        canDelete: { pods: true },
        canCreate: { pods: true },
        accessibleNamespaces: ['default'],
        accessibleResources: ['pods'],
      },
      user: 'test-user',
      loading: false,
      error: null,
      refreshPermissions: vi.fn(),
    });

    vi.mocked(useAuditLogging).mockReturnValue({
      logDashboardInteraction: mockLogDashboardInteraction,
      logResourceAccess: vi.fn(),
      logError: vi.fn(),
      logSecurityEvent: vi.fn(),
      searchEvents: vi.fn(),
      generateComplianceReport: vi.fn(),
    });

    // Setup default mock responses
    mockSearchCommands.mockResolvedValue({
      commands: mockCommands,
      total: mockCommands.length,
      hasMore: false,
    });

    mockGetCommandStatistics.mockResolvedValue(mockStatistics);
  });

  describe('Basic Rendering', () => {
    it('should render the command history panel', async () => {
      render(<CommandHistoryPanel />);

      expect(screen.getByText('Command History')).toBeInTheDocument();
      
      await waitFor(() => {
        expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
      });
    });

    it('should render statistics when enabled', async () => {
      render(<CommandHistoryPanel showStatistics={true} />);

      await waitFor(() => {
        expect(screen.getByText('Command Statistics (Last 7 Days)')).toBeInTheDocument();
        expect(screen.getByText('10')).toBeInTheDocument(); // Total commands
        expect(screen.getByText('80.0%')).toBeInTheDocument(); // Success rate
      });
    });

    it('should not render statistics when disabled', () => {
      render(<CommandHistoryPanel showStatistics={false} />);

      expect(screen.queryByText('Command Statistics (Last 7 Days)')).not.toBeInTheDocument();
    });

    it('should show loading state', () => {
      mockSearchCommands.mockImplementation(() => new Promise(() => {})); // Never resolves
      
      render(<CommandHistoryPanel />);
      
      expect(screen.getByText('Loading commands...')).toBeInTheDocument();
    });

    it('should show empty state', async () => {
      mockSearchCommands.mockResolvedValue({
        commands: [],
        total: 0,
        hasMore: false,
      });

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('No command history found')).toBeInTheDocument();
        expect(screen.getByText('Commands will appear here as they are executed')).toBeInTheDocument();
      });
    });

    it('should show error state', async () => {
      mockSearchCommands.mockRejectedValue(new Error('Failed to load commands'));

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('Failed to load commands')).toBeInTheDocument();
      });
    });
  });

  describe('Command Display', () => {
    it('should display command information correctly', async () => {
      render(<CommandHistoryPanel />);

      await waitFor(() => {
        // Check command text
        expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
        expect(screen.getByText('kubectl delete pod bad-pod')).toBeInTheDocument();
        
        // Check status indicators
        expect(screen.getByText('Completed')).toBeInTheDocument();
        expect(screen.getByText('Failed')).toBeInTheDocument();
        
        // Check impact levels
        expect(screen.getByText('Low')).toBeInTheDocument();
        expect(screen.getByText('High')).toBeInTheDocument();
        expect(screen.getByText('Medium')).toBeInTheDocument();
      });
    });

    it('should show execution times', async () => {
      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('1500ms')).toBeInTheDocument();
        expect(screen.getByText('2000ms')).toBeInTheDocument();
      });
    });

    it('should show error messages for failed commands', async () => {
      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('Pod not found')).toBeInTheDocument();
      });
    });

    it('should show resource changes', async () => {
      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText(/scaled: Deployment\/web/)).toBeInTheDocument();
      });
    });
  });

  describe('Filtering', () => {
    it('should toggle filter panel', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      const filterButton = screen.getByLabelText('Toggle filters');
      await user.click(filterButton);

      expect(screen.getByPlaceholderText('Search commands...')).toBeInTheDocument();
    });

    it('should handle search input', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      // Open filters
      const filterButton = screen.getByLabelText('Toggle filters');
      await user.click(filterButton);

      // Type in search
      const searchInput = screen.getByPlaceholderText('Search commands...');
      await user.type(searchInput, 'kubectl get');

      await waitFor(() => {
        expect(mockSearchCommands).toHaveBeenCalledWith(
          expect.objectContaining({
            command: 'kubectl get',
          })
        );
      });
    });

    it('should handle status filter', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      // Open filters
      const filterButton = screen.getByLabelText('Toggle filters');
      await user.click(filterButton);

      // Select status filter
      const statusSelect = screen.getByDisplayValue('All Status');
      await user.selectOptions(statusSelect, 'completed');

      await waitFor(() => {
        expect(mockSearchCommands).toHaveBeenCalledWith(
          expect.objectContaining({
            status: 'completed',
          })
        );
      });
    });

    it('should handle impact filter', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      // Open filters
      const filterButton = screen.getByLabelText('Toggle filters');
      await user.click(filterButton);

      // Select impact filter
      const impactSelect = screen.getByDisplayValue('All Impact');
      await user.selectOptions(impactSelect, 'high');

      await waitFor(() => {
        expect(mockSearchCommands).toHaveBeenCalledWith(
          expect.objectContaining({
            impactLevel: 'high',
          })
        );
      });
    });

    it('should log search interactions', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      // Open filters and search
      const filterButton = screen.getByLabelText('Toggle filters');
      await user.click(filterButton);

      const searchInput = screen.getByPlaceholderText('Search commands...');
      await user.type(searchInput, 'test');

      await waitFor(() => {
        expect(mockLogDashboardInteraction).toHaveBeenCalledWith(
          'search',
          expect.objectContaining({
            searchType: 'command_history',
          })
        );
      });
    });
  });

  describe('Actions', () => {
    it('should handle rollback generation', async () => {
      const user = userEvent.setup();
      mockGenerateRollbackCommand.mockResolvedValue('kubectl scale deployment web --replicas=1');

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('kubectl scale deployment web --replicas=3')).toBeInTheDocument();
      });

      // Find and click rollback button for the scalable command
      const rollbackButtons = screen.getAllByLabelText(/Generate rollback for/);
      await user.click(rollbackButtons[0]);

      await waitFor(() => {
        expect(mockGenerateRollbackCommand).toHaveBeenCalledWith('cmd_3');
      });
    });

    it('should handle view details', async () => {
      const user = userEvent.setup();
      const mockOnCommandSelect = vi.fn();

      render(<CommandHistoryPanel onCommandSelect={mockOnCommandSelect} />);

      await waitFor(() => {
        expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
      });

      // Click on a command card
      const commandCard = screen.getByText('kubectl get pods').closest('.border');
      expect(commandCard).toBeInTheDocument();
      
      if (commandCard) {
        await user.click(commandCard);
        expect(mockOnCommandSelect).toHaveBeenCalledWith(mockCommands[0]);
      }
    });

    it('should handle view details button', async () => {
      const user = userEvent.setup();
      const mockOnCommandSelect = vi.fn();

      render(<CommandHistoryPanel onCommandSelect={mockOnCommandSelect} />);

      await waitFor(() => {
        expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
      });

      // Click on view details button
      const detailsButtons = screen.getAllByLabelText(/View details for/);
      await user.click(detailsButtons[0]);

      expect(mockOnCommandSelect).toHaveBeenCalledWith(mockCommands[0]);
    });

    it('should handle clear completed commands', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      const clearButton = screen.getByText('Clear Completed');
      await user.click(clearButton);

      expect(mockClearCompletedCommands).toHaveBeenCalled();
    });
  });

  describe('Active Commands Integration', () => {
    it('should merge active commands with history', async () => {
      const activeCommand: CommandRecord = {
        id: 'cmd_active',
        timestamp: new Date(),
        userId: 'user1',
        sessionId: 'session1',
        command: 'kubectl apply -f deployment.yaml',
        intent: 'apply_manifest',
        parameters: {},
        status: 'executing',
        affectedResources: [],
        resourceChanges: [],
        impactSummary: {
          resourcesAffected: 1,
          namespacesCovered: ['default'],
          changeTypes: ['create'],
          potentialImpact: 'low',
          impactDescription: 'Applying manifest',
          dependentResources: [],
          rollbackComplexity: 'simple',
        },
        rollbackAvailable: false,
      };

      vi.mocked(useCommandTracking).mockReturnValue({
        trackCommand: vi.fn(),
        updateCommand: vi.fn(),
        getActiveCommands: vi.fn(() => [activeCommand]),
        clearCompletedCommands: mockClearCompletedCommands,
        activeCommands: [activeCommand],
      });

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('kubectl apply -f deployment.yaml')).toBeInTheDocument();
        expect(screen.getByText('Executing')).toBeInTheDocument();
      });
    });

    it('should prioritize active commands in display order', async () => {
      const recentActiveCommand: CommandRecord = {
        id: 'cmd_recent',
        timestamp: new Date(Date.now() + 10000), // Future timestamp
        userId: 'user1',
        sessionId: 'session1',
        command: 'kubectl create secret',
        intent: 'create_secret',
        parameters: {},
        status: 'pending',
        affectedResources: [],
        resourceChanges: [],
        impactSummary: {
          resourcesAffected: 1,
          namespacesCovered: ['default'],
          changeTypes: ['create'],
          potentialImpact: 'low',
          impactDescription: 'Creating secret',
          dependentResources: [],
          rollbackComplexity: 'simple',
        },
        rollbackAvailable: false,
      };

      vi.mocked(useCommandTracking).mockReturnValue({
        trackCommand: vi.fn(),
        updateCommand: vi.fn(),
        getActiveCommands: vi.fn(() => [recentActiveCommand]),
        clearCompletedCommands: mockClearCompletedCommands,
        activeCommands: [recentActiveCommand],
      });

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        const commandElements = screen.getAllByText(/kubectl/);
        // The most recent (active) command should be first
        expect(commandElements[0]).toHaveTextContent('kubectl create secret');
      });
    });
  });

  describe('Statistics Panel', () => {
    it('should display comprehensive statistics', async () => {
      render(<CommandHistoryPanel showStatistics={true} />);

      await waitFor(() => {
        // Main metrics
        expect(screen.getByText('10')).toBeInTheDocument(); // Total commands
        expect(screen.getByText('80.0%')).toBeInTheDocument(); // Success rate
        expect(screen.getByText('1750ms')).toBeInTheDocument(); // Avg execution time
        expect(screen.getByText('3')).toBeInTheDocument(); // Resource types

        // Top commands
        expect(screen.getByText('list_pods')).toBeInTheDocument();
        expect(screen.getByText('scale_deployment')).toBeInTheDocument();

        // Impact distribution
        expect(screen.getByText('6')).toBeInTheDocument(); // Low impact count
      });
    });

    it('should handle statistics loading errors gracefully', async () => {
      mockGetCommandStatistics.mockRejectedValue(new Error('Statistics error'));

      render(<CommandHistoryPanel showStatistics={true} />);

      // Should still render the main panel even if statistics fail
      await waitFor(() => {
        expect(screen.getByText('Command History')).toBeInTheDocument();
      });

      // Statistics section should not appear
      expect(screen.queryByText('Command Statistics (Last 7 Days)')).not.toBeInTheDocument();
    });
  });

  describe('Error Handling', () => {
    it('should handle search errors', async () => {
      mockSearchCommands.mockRejectedValue(new Error('Network error'));

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('Network error')).toBeInTheDocument();
      });
    });

    it('should handle rollback generation errors', async () => {
      const user = userEvent.setup();
      mockGenerateRollbackCommand.mockRejectedValue(new Error('Rollback failed'));

      render(<CommandHistoryPanel />);

      await waitFor(() => {
        expect(screen.getByText('kubectl scale deployment web --replicas=3')).toBeInTheDocument();
      });

      const rollbackButtons = screen.getAllByLabelText(/Generate rollback for/);
      await user.click(rollbackButtons[0]);

      await waitFor(() => {
        expect(screen.getByText('Rollback failed')).toBeInTheDocument();
      });
    });
  });

  describe('Accessibility', () => {
    it('should have proper ARIA labels', async () => {
      render(<CommandHistoryPanel />);

      expect(screen.getByLabelText('Toggle filters')).toBeInTheDocument();
      
      await waitFor(() => {
        expect(screen.getByLabelText(/Generate rollback for/)).toBeInTheDocument();
        expect(screen.getByLabelText(/View details for/)).toBeInTheDocument();
      });
    });

    it('should support keyboard navigation', async () => {
      const user = userEvent.setup();
      render(<CommandHistoryPanel />);

      // Tab through elements
      await user.tab();
      expect(screen.getByText('Clear Completed')).toHaveFocus();

      await user.tab();
      expect(screen.getByLabelText('Toggle filters')).toHaveFocus();
    });
  });

  describe('Props and Configuration', () => {
    it('should use provided userId and sessionId', () => {
      render(<CommandHistoryPanel userId="custom-user" sessionId="custom-session" />);

      expect(useCommandTracking).toHaveBeenCalledWith('custom-user', 'custom-session');
    });

    it('should apply custom className', () => {
      const { container } = render(<CommandHistoryPanel className="custom-class" />);
      
      expect(container.firstChild).toHaveClass('custom-class');
    });

    it('should call onCommandSelect when provided', async () => {
      const user = userEvent.setup();
      const mockOnCommandSelect = vi.fn();

      render(<CommandHistoryPanel onCommandSelect={mockOnCommandSelect} />);

      await waitFor(() => {
        expect(screen.getByText('kubectl get pods')).toBeInTheDocument();
      });

      const commandCard = screen.getByText('kubectl get pods').closest('.border');
      if (commandCard) {
        await user.click(commandCard);
        expect(mockOnCommandSelect).toHaveBeenCalled();
      }
    });
  });
});