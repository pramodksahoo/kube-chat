/**
 * PermissionGuard - HOC and component for permission-based rendering
 * Provides fine-grained access control for UI components
 */

import React, { type ComponentType } from 'react';
import { Can, usePermissions } from './PermissionProvider';
import { rbacService } from '../../services/rbacService';

export interface PermissionGuardProps {
  resource: string;
  action: 'view' | 'edit' | 'delete' | 'create';
  namespace?: string;
  resourceName?: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
  loadingComponent?: React.ReactNode;
  errorComponent?: React.ReactNode;
}

export const PermissionGuard: React.FC<PermissionGuardProps> = ({
  resource,
  action,
  namespace,
  resourceName: _resourceName,
  children,
  fallback = <div className="text-gray-500 text-sm">Access denied</div>,
  loadingComponent = <div className="text-gray-500 text-sm">Checking permissions...</div>,
  errorComponent,
}) => {
  const { loading, error } = usePermissions();

  if (loading) {
    return <>{loadingComponent}</>;
  }

  if (error && errorComponent) {
    return <>{errorComponent}</>;
  }

  return (
    <Can resource={resource} action={action} namespace={namespace} fallback={fallback}>
      {children}
    </Can>
  );
};

// HOC for wrapping components with permission checks
export function withPermissions<P extends object>(
  WrappedComponent: ComponentType<P>,
  requiredPermissions: {
    resource: string;
    action: 'view' | 'edit' | 'delete' | 'create';
    namespace?: string;
  }
) {
  const PermissionWrappedComponent = (props: P) => (
    <PermissionGuard
      resource={requiredPermissions.resource}
      action={requiredPermissions.action}
      namespace={requiredPermissions.namespace}
      fallback={
        <div className="p-4 text-center text-gray-500 bg-gray-50 rounded-lg border">
          <div className="text-lg mb-2">🔒</div>
          <div className="font-medium">Access Restricted</div>
          <div className="text-sm">
            You don't have permission to {requiredPermissions.action} {requiredPermissions.resource}
            {requiredPermissions.namespace && ` in namespace ${requiredPermissions.namespace}`}
          </div>
        </div>
      }
    >
      <WrappedComponent {...props} />
    </PermissionGuard>
  );

  PermissionWrappedComponent.displayName = `withPermissions(${WrappedComponent.displayName || WrappedComponent.name})`;

  return PermissionWrappedComponent;
}

// Batch permission checker component
export interface BatchPermissionGuardProps {
  checks: Array<{
    resource: string;
    action: 'view' | 'edit' | 'delete' | 'create';
    namespace?: string;
  }>;
  mode: 'any' | 'all'; // 'any' = at least one permission, 'all' = all permissions required
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const BatchPermissionGuard: React.FC<BatchPermissionGuardProps> = ({
  checks,
  mode,
  children,
  fallback = <div className="text-gray-500 text-sm">Insufficient permissions</div>,
}) => {
  const { permissions } = usePermissions();

  const hasPermissions = checks.map(check => {
    switch (check.action) {
      case 'view':
        return permissions.canView[check.resource] || false;
      case 'edit':
        return permissions.canEdit[check.resource] || false;
      case 'delete':
        return permissions.canDelete[check.resource] || false;
      case 'create':
        return permissions.canCreate[check.resource] || false;
      default:
        return false;
    }
  });

  const shouldRender = mode === 'any' 
    ? hasPermissions.some(Boolean)
    : hasPermissions.every(Boolean);

  return shouldRender ? <>{children}</> : <>{fallback}</>;
};

// Resource-specific permission guards
export const CanViewPods: React.FC<{ children: React.ReactNode; namespace?: string; fallback?: React.ReactNode }> = ({
  children,
  namespace,
  fallback,
}) => (
  <Can resource="pods" action="view" namespace={namespace} fallback={fallback}>
    {children}
  </Can>
);

export const CanEditPods: React.FC<{ children: React.ReactNode; namespace?: string; fallback?: React.ReactNode }> = ({
  children,
  namespace,
  fallback,
}) => (
  <Can resource="pods" action="edit" namespace={namespace} fallback={fallback}>
    {children}
  </Can>
);

export const CanDeletePods: React.FC<{ children: React.ReactNode; namespace?: string; fallback?: React.ReactNode }> = ({
  children,
  namespace,
  fallback,
}) => (
  <Can resource="pods" action="delete" namespace={namespace} fallback={fallback}>
    {children}
  </Can>
);

export const CanCreatePods: React.FC<{ children: React.ReactNode; namespace?: string; fallback?: React.ReactNode }> = ({
  children,
  namespace,
  fallback,
}) => (
  <Can resource="pods" action="create" namespace={namespace} fallback={fallback}>
    {children}
  </Can>
);

// Advanced permission checker with async validation
export interface AsyncPermissionGuardProps {
  resource: string;
  action: string;
  namespace?: string;
  resourceName?: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
  loadingComponent?: React.ReactNode;
}

export const AsyncPermissionGuard: React.FC<AsyncPermissionGuardProps> = ({
  resource,
  action,
  namespace,
  resourceName,
  children,
  fallback = <div className="text-gray-500 text-sm">Access denied</div>,
  loadingComponent = <div className="text-gray-500 text-sm animate-pulse">Validating permissions...</div>,
}) => {
  const [loading, setLoading] = React.useState(true);
  const [allowed, setAllowed] = React.useState(false);
  const { user } = usePermissions();

  React.useEffect(() => {
    let cancelled = false;

    const checkPermission = async () => {
      try {
        setLoading(true);
        
        const result = await rbacService.canI({
          resource,
          verb: action,
          namespace,
          resourceName,
        }, user || undefined);

        if (!cancelled) {
          setAllowed(result.allowed);
        }
      } catch (error) {
        console.error('Permission check failed:', error);
        if (!cancelled) {
          setAllowed(false);
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void checkPermission();

    return () => {
      cancelled = true;
    };
  }, [resource, action, namespace, resourceName, user]);

  if (loading) {
    return <>{loadingComponent}</>;
  }

  return allowed ? <>{children}</> : <>{fallback}</>;
};

// Namespace-aware component wrapper
export interface NamespaceGuardProps {
  namespace: string;
  children: React.ReactNode;
  fallback?: React.ReactNode;
}

export const NamespaceGuard: React.FC<NamespaceGuardProps> = ({
  namespace,
  children,
  fallback = <div className="text-gray-500 text-sm">Access denied for namespace: {namespace}</div>,
}) => {
  const { permissions } = usePermissions();
  
  const hasAccess = permissions.accessibleNamespaces.includes(namespace) || 
                   permissions.accessibleNamespaces.includes('*');

  return hasAccess ? <>{children}</> : <>{fallback}</>;
};

// Permission-aware button component
export interface PermissionButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  resource: string;
  action: 'view' | 'edit' | 'delete' | 'create';
  namespace?: string;
  children: React.ReactNode;
  disabledText?: string;
}

export const PermissionButton: React.FC<PermissionButtonProps> = ({
  resource,
  action,
  namespace,
  children,
  disabledText = 'No permission',
  className = '',
  ...buttonProps
}) => {
  const { permissions, loading } = usePermissions();

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

  const isAllowed = hasPermission && hasNamespaceAccess;
  const isDisabled = loading || !isAllowed || buttonProps.disabled;

  return (
    <button
      {...buttonProps}
      disabled={isDisabled}
      className={`${className} ${isDisabled ? 'opacity-50 cursor-not-allowed' : ''}`}
      title={!isAllowed ? disabledText : buttonProps.title}
    >
      {children}
    </button>
  );
};

// Error boundary for permission-related errors
interface PermissionErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class PermissionErrorBoundary extends React.Component<
  { children: React.ReactNode; fallback?: React.ReactNode },
  PermissionErrorBoundaryState
> {
  constructor(props: { children: React.ReactNode; fallback?: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): PermissionErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('Permission error boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return this.props.fallback || (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
          <div className="font-medium">Permission Error</div>
          <div className="text-sm mt-1">
            {this.state.error?.message || 'An error occurred while checking permissions.'}
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}