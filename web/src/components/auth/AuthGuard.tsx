import React, { useEffect, useState } from 'react';
import { useAuthentication } from '../../hooks/useAuthentication';
import { LoginPage } from './LoginPage';

interface AuthGuardProps {
  children: React.ReactNode;
  fallback?: React.ReactNode;
  requiredRoles?: string[];
  requiredGroups?: string[];
  requireAnyRole?: boolean; // If true, user needs ANY of the required roles, not all
  requireAnyGroup?: boolean; // If true, user needs ANY of the required groups, not all
  redirectTo?: string;
  showLogin?: boolean;
}

export function AuthGuard({
  children,
  fallback,
  requiredRoles = [],
  requiredGroups = [],
  requireAnyRole = true,
  requireAnyGroup = true,
  redirectTo,
  showLogin = true,
}: AuthGuardProps) {
  const {
    isAuthenticated,
    user,
    isLoading,
    mfaRequired,
    hasRole,
    hasGroup,
    hasAnyRole,
    hasAnyGroup,
    checkSession,
  } = useAuthentication();

  const [initialCheckComplete, setInitialCheckComplete] = useState(false);

  // Perform initial authentication check
  useEffect(() => {
    if (!initialCheckComplete && !isLoading) {
      void checkSession().finally(() => {
        setInitialCheckComplete(true);
      });
    }
  }, [checkSession, initialCheckComplete, isLoading]);

  // Handle redirect if specified
  useEffect(() => {
    if (initialCheckComplete && !isAuthenticated && !mfaRequired && redirectTo) {
      // Store the intended destination
      if (typeof window !== 'undefined') {
        sessionStorage.setItem('kubechat_auth_redirect', redirectTo);
      }
    }
  }, [initialCheckComplete, isAuthenticated, mfaRequired, redirectTo]);

  // Check if user has required permissions
  const hasRequiredPermissions = (): boolean => {
    if (!user) return false;

    // Check roles if specified
    if (requiredRoles.length > 0) {
      if (requireAnyRole) {
        if (!hasAnyRole(requiredRoles)) return false;
      } else {
        // Require ALL roles
        if (!requiredRoles.every(role => hasRole(role))) return false;
      }
    }

    // Check groups if specified
    if (requiredGroups.length > 0) {
      if (requireAnyGroup) {
        if (!hasAnyGroup(requiredGroups)) return false;
      } else {
        // Require ALL groups
        if (!requiredGroups.every(group => hasGroup(group))) return false;
      }
    }

    return true;
  };

  // Show loading spinner while checking authentication
  if (isLoading || !initialCheckComplete) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Checking authentication...</p>
        </div>
      </div>
    );
  }

  // Show login page if not authenticated
  if (!isAuthenticated || mfaRequired) {
    if (showLogin) {
      return (
        <LoginPage
          redirectPath={redirectTo || window.location.pathname}
          onLoginSuccess={() => {
            // Handle successful login
            const storedRedirect = sessionStorage.getItem('kubechat_auth_redirect');
            if (storedRedirect) {
              sessionStorage.removeItem('kubechat_auth_redirect');
              window.location.href = storedRedirect;
            }
          }}
        />
      );
    }

    // Show custom fallback or default unauthorized message
    if (fallback) {
      return <>{fallback}</>;
    }

    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <svg className="mx-auto h-12 w-12 text-gray-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
            <path d="M34 40h10v-4a6 6 0 00-10.712-3.714M34 40H14m20 0v-4a9.971 9.971 0 00-.712-3.714M14 40H4v-4a6 6 0 0110.713-3.714M14 40v-4c0-1.313.253-2.566.713-3.714m0 0A10.003 10.003 0 0124 26c4.21 0 7.813 2.602 9.288 6.286M30 14a6 6 0 11-12 0 6 6 0 0112 0zm12 6a4 4 0 11-8 0 4 4 0 018 0zm-28 0a4 4 0 11-8 0 4 4 0 018 0z" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <h2 className="mt-2 text-lg font-medium text-gray-900">Authentication Required</h2>
          <p className="mt-1 text-sm text-gray-500">Please sign in to access this page.</p>
          <div className="mt-6">
            <a
              href="/login"
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500"
            >
              Sign In
            </a>
          </div>
        </div>
      </div>
    );
  }

  // Check permissions if user is authenticated
  if (!hasRequiredPermissions()) {
    if (fallback) {
      return <>{fallback}</>;
    }

    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <svg className="mx-auto h-12 w-12 text-red-400" stroke="currentColor" fill="none" viewBox="0 0 48 48">
            <path d="M12 9v3m0 0v3m0-3h3m-3 0h-3m6 0a9 9 0 11-18 0 9 9 0 0118 0z" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <h2 className="mt-2 text-lg font-medium text-gray-900">Access Denied</h2>
          <p className="mt-1 text-sm text-gray-500">You don't have permission to access this page.</p>
          
          {(requiredRoles.length > 0 || requiredGroups.length > 0) && (
            <div className="mt-4 text-xs text-gray-400">
              {requiredRoles.length > 0 && (
                <p>Required roles: {requiredRoles.join(requireAnyRole ? ' OR ' : ' AND ')}</p>
              )}
              {requiredGroups.length > 0 && (
                <p>Required groups: {requiredGroups.join(requireAnyGroup ? ' OR ' : ' AND ')}</p>
              )}
            </div>
          )}
          
          <div className="mt-6">
            <button
              onClick={() => window.history.back()}
              className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-gray-600 hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500"
            >
              Go Back
            </button>
          </div>
        </div>
      </div>
    );
  }

  // User is authenticated and has required permissions
  return <>{children}</>;
}

// Higher-order component version for easier usage
export function withAuthGuard<P extends object>(
  Component: React.ComponentType<P>,
  guardOptions?: Omit<AuthGuardProps, 'children'>
) {
  const WrappedComponent = (props: P) => (
    <AuthGuard {...guardOptions}>
      <Component {...props} />
    </AuthGuard>
  );
  
  WrappedComponent.displayName = `withAuthGuard(${Component.displayName || Component.name})`;
  
  return WrappedComponent;
}

export default AuthGuard;