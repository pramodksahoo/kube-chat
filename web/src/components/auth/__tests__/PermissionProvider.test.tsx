/**
 * Tests for PermissionProvider component
 */

import { beforeEach, describe, expect, it, vi, type MockedFunction } from 'vitest';
import { act, render, screen, waitFor } from '@testing-library/react';
import { Can, Cannot, PermissionProvider, Restricted, usePermissions } from '../PermissionProvider';
import { rbacService } from '../../../services/rbacService';

// Mock RBAC service
vi.mock('../../../services/rbacService', () => ({
  rbacService: {
    getPermissionsForUI: vi.fn(),
    clearUserCache: vi.fn(),
  },
}));

describe('PermissionProvider', () => {
  const mockPermissions = {
    canView: { pods: true, services: false },
    canEdit: { pods: false, services: true },
    canDelete: { pods: false, services: false },
    canCreate: { pods: true, services: true },
    accessibleNamespaces: ['default', 'kube-system'],
    accessibleResources: ['pods', 'services'],
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Provider Functionality', () => {
    it('should provide permissions context', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      const TestComponent = () => {
        const { permissions, loading } = usePermissions();
        
        if (loading) return <div>Loading...</div>;
        
        return (
          <div>
            <div data-testid="can-view-pods">{permissions.canView.pods.toString()}</div>
            <div data-testid="accessible-namespaces">{permissions.accessibleNamespaces.join(',')}</div>
          </div>
        );
      };

      render(
        <PermissionProvider user="test-user">
          <TestComponent />
        </PermissionProvider>
      );

      expect(screen.getByText('Loading...')).toBeInTheDocument();

      await waitFor(() => {
        expect(screen.getByTestId('can-view-pods')).toHaveTextContent('true');
        expect(screen.getByTestId('accessible-namespaces')).toHaveTextContent('default,kube-system');
      });
    });

    it('should handle permission loading errors', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockRejectedValue(new Error('Permission error'));

      const TestComponent = () => {
        const { error, permissions } = usePermissions();
        
        return (
          <div>
            <div data-testid="error">{error || 'No error'}</div>
            <div data-testid="has-permissions">{Object.keys(permissions.canView).length > 0 ? 'true' : 'false'}</div>
          </div>
        );
      };

      render(
        <PermissionProvider user="test-user">
          <TestComponent />
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('error')).toHaveTextContent('Permission error');
        expect(screen.getByTestId('has-permissions')).toHaveTextContent('false');
      });
    });

    it('should refresh permissions on demand', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      const TestComponent = () => {
        const { refreshPermissions, loading } = usePermissions();
        
        return (
          <div>
            <button onClick={() => void refreshPermissions()} disabled={loading}>
              Refresh
            </button>
            <div data-testid="loading">{loading.toString()}</div>
          </div>
        );
      };

      render(
        <PermissionProvider user="test-user">
          <TestComponent />
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('loading')).toHaveTextContent('false');
      });

      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.getPermissionsForUI as jest.MockedFunction<typeof rbacService.getPermissionsForUI>).toHaveBeenCalledTimes(1);

      // Trigger refresh
      const refreshButton = screen.getByRole('button', { name: 'Refresh' });
      await act(async () => {
        refreshButton.click();
      });

      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.getPermissionsForUI as jest.MockedFunction<typeof rbacService.getPermissionsForUI>).toHaveBeenCalledTimes(2);
    });

    it('should clear cache when user changes', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      const TestComponent = () => {
        const { user } = usePermissions();
        return <div data-testid="user">{user || 'No user'}</div>;
      };

      const { rerender } = render(
        <PermissionProvider user="user1">
          <TestComponent />
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('user')).toHaveTextContent('user1');
      });

      // Change user
      rerender(
        <PermissionProvider user="user2">
          <TestComponent />
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('user')).toHaveTextContent('user2');
      });

      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.clearUserCache).toHaveBeenCalledWith('user2');
    });

    it('should handle refresh interval', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);
      vi.useFakeTimers();

      render(
        <PermissionProvider user="test-user" refreshInterval={1000}>
          <div>Test</div>
        </PermissionProvider>
      );

      await waitFor(() => {
        // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.getPermissionsForUI as jest.MockedFunction<typeof rbacService.getPermissionsForUI>).toHaveBeenCalledTimes(1);
      });

      // Fast-forward time
      act(() => {
        vi.advanceTimersByTime(1000);
      });

      await waitFor(() => {
        // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.getPermissionsForUI as jest.MockedFunction<typeof rbacService.getPermissionsForUI>).toHaveBeenCalledTimes(2);
      });

      vi.useRealTimers();
    });

    it('should disable refresh interval when set to 0', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);
      vi.useFakeTimers();

      render(
        <PermissionProvider user="test-user" refreshInterval={0}>
          <div>Test</div>
        </PermissionProvider>
      );

      await waitFor(() => {
        // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.getPermissionsForUI as jest.MockedFunction<typeof rbacService.getPermissionsForUI>).toHaveBeenCalledTimes(1);
      });

      // Fast-forward time - should not trigger refresh
      act(() => {
        vi.advanceTimersByTime(10000);
      });

      // eslint-disable-next-line @typescript-eslint/unbound-method
      expect(rbacService.getPermissionsForUI as jest.MockedFunction<typeof rbacService.getPermissionsForUI>).toHaveBeenCalledTimes(1);

      vi.useRealTimers();
    });
  });

  describe('Can Component', () => {
    it('should render children when permission is granted', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      render(
        <PermissionProvider user="test-user">
          <Can resource="pods" action="view">
            <div data-testid="allowed-content">Can view pods</div>
          </Can>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('allowed-content')).toBeInTheDocument();
      });
    });

    it('should render fallback when permission is denied', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      render(
        <PermissionProvider user="test-user">
          <Can resource="services" action="view" fallback={<div data-testid="fallback">Access denied</div>}>
            <div data-testid="allowed-content">Can view services</div>
          </Can>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('fallback')).toBeInTheDocument();
        expect(screen.queryByTestId('allowed-content')).not.toBeInTheDocument();
      });
    });

    it('should check namespace access', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue({
        ...mockPermissions,
        canView: { pods: true },
        accessibleNamespaces: ['default'],
      });

      render(
        <PermissionProvider user="test-user">
          <Can resource="pods" action="view" namespace="default">
            <div data-testid="namespace-allowed">Allowed namespace</div>
          </Can>
          <Can resource="pods" action="view" namespace="restricted" fallback={<div data-testid="namespace-denied">Denied namespace</div>}>
            <div data-testid="namespace-content">Content</div>
          </Can>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('namespace-allowed')).toBeInTheDocument();
        expect(screen.getByTestId('namespace-denied')).toBeInTheDocument();
        expect(screen.queryByTestId('namespace-content')).not.toBeInTheDocument();
      });
    });

    it('should handle wildcard namespace access', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue({
        ...mockPermissions,
        canView: { pods: true },
        accessibleNamespaces: ['*'],
      });

      render(
        <PermissionProvider user="test-user">
          <Can resource="pods" action="view" namespace="any-namespace">
            <div data-testid="wildcard-access">Wildcard access</div>
          </Can>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('wildcard-access')).toBeInTheDocument();
      });
    });
  });

  describe('Cannot Component', () => {
    it('should render children when permission is denied', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      render(
        <PermissionProvider user="test-user">
          <Cannot resource="services" action="view">
            <div data-testid="cannot-content">Cannot view services</div>
          </Cannot>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('cannot-content')).toBeInTheDocument();
      });
    });

    it('should not render children when permission is granted', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      render(
        <PermissionProvider user="test-user">
          <Cannot resource="pods" action="view">
            <div data-testid="cannot-content">Cannot view pods</div>
          </Cannot>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.queryByTestId('cannot-content')).not.toBeInTheDocument();
      });
    });
  });

  describe('Restricted Component', () => {
    it('should render children when user has permissions', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      render(
        <PermissionProvider user="test-user">
          <Restricted>
            <div data-testid="restricted-content">Restricted content</div>
          </Restricted>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('restricted-content')).toBeInTheDocument();
      });
    });

    it('should render no permissions message when user has no permissions', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue({
        canView: {},
        canEdit: {},
        canDelete: {},
        canCreate: {},
        accessibleNamespaces: [],
        accessibleResources: [],
      });

      render(
        <PermissionProvider user="test-user">
          <Restricted>
            <div data-testid="restricted-content">Restricted content</div>
          </Restricted>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByText("Access denied. You don't have permission to view this content.")).toBeInTheDocument();
        expect(screen.queryByTestId('restricted-content')).not.toBeInTheDocument();
      });
    });

    it('should render loading state', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockImplementation(() => new Promise(() => {})); // Never resolves

      render(
        <PermissionProvider user="test-user">
          <Restricted>
            <div data-testid="restricted-content">Restricted content</div>
          </Restricted>
        </PermissionProvider>
      );

      expect(screen.getByText('Loading permissions...')).toBeInTheDocument();
    });

    it('should render custom loading component', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockImplementation(() => new Promise(() => {}));

      render(
        <PermissionProvider user="test-user">
          <Restricted loading={<div data-testid="custom-loading">Custom loading</div>}>
            <div data-testid="restricted-content">Restricted content</div>
          </Restricted>
        </PermissionProvider>
      );

      expect(screen.getByTestId('custom-loading')).toBeInTheDocument();
    });

    it('should render custom no permissions component', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue({
        canView: {},
        canEdit: {},
        canDelete: {},
        canCreate: {},
        accessibleNamespaces: [],
        accessibleResources: [],
      });

      render(
        <PermissionProvider user="test-user">
          <Restricted noPermissions={<div data-testid="custom-no-permissions">Custom no permissions</div>}>
            <div data-testid="restricted-content">Restricted content</div>
          </Restricted>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('custom-no-permissions')).toBeInTheDocument();
        expect(screen.queryByTestId('restricted-content')).not.toBeInTheDocument();
      });
    });

    it('should render custom error component', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockRejectedValue(new Error('Permission error'));

      render(
        <PermissionProvider user="test-user">
          <Restricted error={<div data-testid="custom-error">Custom error</div>}>
            <div data-testid="restricted-content">Restricted content</div>
          </Restricted>
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('custom-error')).toBeInTheDocument();
      });
    });
  });

  describe('Permission Hooks', () => {
    it('should provide specific permission hooks', async () => {
      vi.spyOn(rbacService, 'getPermissionsForUI').mockResolvedValue(mockPermissions);

      const TestComponent = () => {
        const canViewPods = usePermissions().permissions.canView.pods;
        const canEditServices = usePermissions().permissions.canEdit.services;
        const accessibleNamespaces = usePermissions().permissions.accessibleNamespaces;
        
        return (
          <div>
            <div data-testid="can-view-pods">{canViewPods.toString()}</div>
            <div data-testid="can-edit-services">{canEditServices.toString()}</div>
            <div data-testid="namespaces">{accessibleNamespaces.length.toString()}</div>
          </div>
        );
      };

      render(
        <PermissionProvider user="test-user">
          <TestComponent />
        </PermissionProvider>
      );

      await waitFor(() => {
        expect(screen.getByTestId('can-view-pods')).toHaveTextContent('true');
        expect(screen.getByTestId('can-edit-services')).toHaveTextContent('true');
        expect(screen.getByTestId('namespaces')).toHaveTextContent('2');
      });
    });

    it('should throw error when used outside provider', () => {
      const TestComponent = () => {
        usePermissions();
        return <div>Test</div>;
      };

      expect(() => {
        render(<TestComponent />);
      }).toThrow('usePermissions must be used within a PermissionProvider');
    });
  });
});