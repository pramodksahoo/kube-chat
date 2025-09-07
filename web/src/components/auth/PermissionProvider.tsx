/**
 * PermissionProvider - Context provider for RBAC permissions
 * Manages user permissions and provides them to child components
 */

import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react';
import { type PermissionContextValue, rbacService } from '../../services/rbacService';

export interface PermissionProviderProps {
  children: React.ReactNode;
  user?: string | null;
  refreshInterval?: number;
}

// Create context with default values
export const PermissionContext = createContext<PermissionContextValue>({
  permissions: {
    canView: {},
    canEdit: {},
    canDelete: {},
    canCreate: {},
    accessibleNamespaces: [],
    accessibleResources: [],
  },
  loading: false,
  error: null,
  user: null,
  refreshPermissions: async () => {},
});

export const PermissionProvider: React.FC<PermissionProviderProps> = ({
  children,
  user = null,
  refreshInterval = 5 * 60 * 1000, // 5 minutes
}) => {
  const userRef = useRef(user);
  userRef.current = user;

  const [permissions, setPermissions] = useState<{
    canView: Record<string, boolean>;
    canEdit: Record<string, boolean>;
    canDelete: Record<string, boolean>;
    canCreate: Record<string, boolean>;
    accessibleNamespaces: string[];
    accessibleResources: string[];
  }>({
    canView: {},
    canEdit: {},
    canDelete: {},
    canCreate: {},
    accessibleNamespaces: [],
    accessibleResources: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshPermissions = useCallback(async () => {
    const currentUser = userRef.current;
    if (!currentUser) return;
    
    try {
      setLoading(true);
      setError(null);

      const uiPermissions = await rbacService.getPermissionsForUI(currentUser);
      setPermissions(uiPermissions);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load permissions';
      setError(errorMessage);
      console.error('Permission refresh failed:', err);
      
      // Set empty permissions on error
      setPermissions({
        canView: {},
        canEdit: {},
        canDelete: {},
        canCreate: {},
        accessibleNamespaces: [],
        accessibleResources: [],
      });
    } finally {
      setLoading(false);
    }
  }, []); // No dependencies - uses ref for current user

  // Initial permissions load
  useEffect(() => {
    void refreshPermissions();
  }, [refreshPermissions]);

  // Set up periodic refresh
  useEffect(() => {
    if (!refreshInterval || refreshInterval <= 0) return;

    const interval = setInterval(() => void refreshPermissions(), refreshInterval);
    return () => clearInterval(interval);
  }, [refreshPermissions, refreshInterval]);

  // Clear cache when user changes
  useEffect(() => {
    if (user) {
      rbacService.clearUserCache(user);
      void refreshPermissions();
    }
  }, [user, refreshPermissions]);

  const contextValue: PermissionContextValue = {
    permissions,
    loading,
    error,
    user,
    refreshPermissions,
  };

  return (
    <PermissionContext.Provider value={contextValue}>
      {children}
    </PermissionContext.Provider>
  );
};

export function usePermissions() {
  const context = useContext(PermissionContext);
  if (!context) {
    throw new Error('usePermissions must be used within a PermissionProvider');
  }
  return context;
}

// Specific permission hooks
export function useCanView(resource: string): boolean {
  const { permissions } = usePermissions();
  return permissions.canView[resource] || false;
}

export function useCanEdit(resource: string): boolean {
  const { permissions } = usePermissions();
  return permissions.canEdit[resource] || false;
}

export function useCanDelete(resource: string): boolean {
  const { permissions } = usePermissions();
  return permissions.canDelete[resource] || false;
}

export function useCanCreate(resource: string): boolean {
  const { permissions } = usePermissions();
  return permissions.canCreate[resource] || false;
}

export function useAccessibleNamespaces(): string[] {
  const { permissions } = usePermissions();
  return permissions.accessibleNamespaces;
}

export function useAccessibleResources(): string[] {
  const { permissions } = usePermissions();
  return permissions.accessibleResources;
}

// Conditional rendering components
export interface CanProps {
  resource: string;
  action: 'view' | 'edit' | 'delete' | 'create';
  children: React.ReactNode;
  fallback?: React.ReactNode;
  namespace?: string;
}

export const Can: React.FC<CanProps> = ({
  resource,
  action,
  children,
  fallback = null,
  namespace,
}) => {
  const { permissions } = usePermissions();
  
  const hasPermission = (() => {
    switch (action) {
      case 'view':
        return permissions.canView[resource] || false;
      case 'edit':
        return permissions.canEdit[resource] || false;
      case 'delete':
        return permissions.canDelete[resource] || false;
      case 'create':
        return permissions.canCreate[resource] || false;
      default:
        return false;
    }
  })();

  // Additional namespace check if specified
  const hasNamespaceAccess = namespace 
    ? permissions.accessibleNamespaces.includes(namespace) || permissions.accessibleNamespaces.includes('*')
    : true;

  return hasPermission && hasNamespaceAccess ? <>{children}</> : <>{fallback}</>;
};

export interface CannotProps {
  resource: string;
  action: 'view' | 'edit' | 'delete' | 'create';
  children: React.ReactNode;
  namespace?: string;
}

export const Cannot: React.FC<CannotProps> = ({
  resource,
  action,
  children,
  namespace,
}) => {
  const { permissions } = usePermissions();
  
  const hasPermission = (() => {
    switch (action) {
      case 'view':
        return permissions.canView[resource] || false;
      case 'edit':
        return permissions.canEdit[resource] || false;
      case 'delete':
        return permissions.canDelete[resource] || false;
      case 'create':
        return permissions.canCreate[resource] || false;
      default:
        return false;
    }
  })();

  const hasNamespaceAccess = namespace 
    ? permissions.accessibleNamespaces.includes(namespace) || permissions.accessibleNamespaces.includes('*')
    : true;

  return (!hasPermission || !hasNamespaceAccess) ? <>{children}</> : null;
};

// Permission-aware wrapper components
export interface RestrictedProps {
  children: React.ReactNode;
  loading?: React.ReactNode;
  error?: React.ReactNode;
  noPermissions?: React.ReactNode;
}

export const Restricted: React.FC<RestrictedProps> = ({
  children,
  loading: loadingComponent = <div>Loading permissions...</div>,
  error: errorComponent,
  noPermissions = <div>Access denied. You don't have permission to view this content.</div>,
}) => {
  const { loading, error, permissions } = usePermissions();

  if (loading) {
    return <>{loadingComponent}</>;
  }

  if (error && errorComponent) {
    return <>{errorComponent}</>;
  }

  // Check if user has any permissions
  const hasAnyPermissions = [
    ...Object.values(permissions.canView),
    ...Object.values(permissions.canEdit),
    ...Object.values(permissions.canDelete),
    ...Object.values(permissions.canCreate),
  ].some(Boolean);

  if (!hasAnyPermissions) {
    return <>{noPermissions}</>;
  }

  return <>{children}</>;
};

// Permission debugging component (development only)
export const PermissionDebugger: React.FC = () => {
  const { permissions, loading, error, user } = usePermissions();

  if (process.env.NODE_ENV !== 'development') {
    return null;
  }

  return (
    <div className="fixed bottom-4 right-4 bg-gray-800 text-white p-4 rounded-lg shadow-lg max-w-md text-xs">
      <h3 className="font-bold mb-2">Permission Debug</h3>
      
      <div className="mb-2">
        <strong>User:</strong> {user || 'Anonymous'}
      </div>
      
      <div className="mb-2">
        <strong>Status:</strong> {loading ? 'Loading...' : error ? `Error: ${error}` : 'Ready'}
      </div>
      
      <div className="mb-2">
        <strong>Namespaces:</strong> {permissions.accessibleNamespaces.join(', ') || 'None'}
      </div>
      
      <div className="mb-2">
        <strong>Resources:</strong> {permissions.accessibleResources.join(', ') || 'None'}
      </div>
      
      <details className="mt-2">
        <summary className="cursor-pointer">View Permissions</summary>
        <pre className="mt-2 text-xs bg-gray-700 p-2 rounded overflow-auto max-h-40">
          {JSON.stringify(permissions, null, 2)}
        </pre>
      </details>
    </div>
  );
};