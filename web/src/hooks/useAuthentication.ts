import { useCallback, useEffect } from 'react';
import { useAuthStore } from '../stores/authStore';
import type { LoginFormData, User } from '../types/auth';

/**
 * Custom hook for authentication state and actions
 */
export function useAuthentication() {
  const {
    // State
    isAuthenticated,
    user,
    token,
    tokenExpiry,
    provider,
    mfaRequired,
    sessionId,
    isLoading,
    error,
    lastActivity,
    
    // Actions
    login,
    logout,
    refreshToken,
    checkSession,
    setError,
    clearError,
    updateLastActivity,
    updateUser,
  } = useAuthStore();

  // Auto-check session on mount
  useEffect(() => {
    if (!isAuthenticated && !isLoading) {
      void checkSession();
    }
  }, [isAuthenticated, isLoading, checkSession]);

  // Handle authentication with comprehensive error handling
  const handleLogin = useCallback(async (loginData: LoginFormData) => {
    try {
      clearError();
      await login(loginData);
    } catch (error) {
      console.error('Authentication failed:', error);
      // Error is handled by the auth store
    }
  }, [login, clearError]);

  // Handle logout with cleanup
  const handleLogout = useCallback(async () => {
    try {
      clearError();
      await logout();
      
      // Additional cleanup if needed
      if (typeof window !== 'undefined') {
        // Clear any remaining authentication-related data
        sessionStorage.clear();
      }
    } catch (error) {
      console.error('Logout failed:', error);
      // Even if logout fails on server, clear local state
    }
  }, [logout, clearError]);

  // Force token refresh
  const handleRefreshToken = useCallback(async () => {
    try {
      clearError();
      await refreshToken();
    } catch (error) {
      console.error('Token refresh failed:', error);
      // Error is handled by the auth store
    }
  }, [refreshToken, clearError]);

  // Update user activity timestamp
  const recordActivity = useCallback(() => {
    if (isAuthenticated) {
      updateLastActivity();
    }
  }, [isAuthenticated, updateLastActivity]);

  // Check if token is near expiry (within 5 minutes)
  const isTokenNearExpiry = useCallback((): boolean => {
    if (!tokenExpiry) return false;
    
    const now = new Date().getTime();
    const expiry = new Date(tokenExpiry).getTime();
    const fiveMinutesInMs = 5 * 60 * 1000;
    
    return (expiry - now) <= fiveMinutesInMs;
  }, [tokenExpiry]);

  // Check if token has expired
  const isTokenExpired = useCallback((): boolean => {
    if (!tokenExpiry) return false;
    
    const now = new Date().getTime();
    const expiry = new Date(tokenExpiry).getTime();
    
    return now >= expiry;
  }, [tokenExpiry]);

  // Get time remaining until token expires
  const getTokenTimeRemaining = useCallback((): number => {
    if (!tokenExpiry) return 0;
    
    const now = new Date().getTime();
    const expiry = new Date(tokenExpiry).getTime();
    
    return Math.max(0, expiry - now);
  }, [tokenExpiry]);

  // Update user profile information
  const updateUserProfile = useCallback((updates: Partial<User>) => {
    if (isAuthenticated) {
      updateUser(updates);
    }
  }, [isAuthenticated, updateUser]);

  // Check if user has specific role
  const hasRole = useCallback((role: string): boolean => {
    return user?.roles?.includes(role) || false;
  }, [user?.roles]);

  // Check if user belongs to specific group
  const hasGroup = useCallback((group: string): boolean => {
    return user?.groups?.includes(group) || false;
  }, [user?.groups]);

  // Check if user has any of the specified roles
  const hasAnyRole = useCallback((roles: string[]): boolean => {
    if (!user?.roles) return false;
    return roles.some(role => user.roles.includes(role));
  }, [user?.roles]);

  // Check if user belongs to any of the specified groups
  const hasAnyGroup = useCallback((groups: string[]): boolean => {
    if (!user?.groups) return false;
    return groups.some(group => user.groups.includes(group));
  }, [user?.groups]);

  // Format last activity for display
  const getLastActivityDisplay = useCallback((): string => {
    if (!lastActivity) return 'Never';
    
    const now = new Date().getTime();
    const lastActivityTime = lastActivity.getTime();
    const diffInMs = now - lastActivityTime;
    
    const diffInMinutes = Math.floor(diffInMs / (1000 * 60));
    const diffInHours = Math.floor(diffInMinutes / 60);
    const diffInDays = Math.floor(diffInHours / 24);
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes} minute${diffInMinutes > 1 ? 's' : ''} ago`;
    if (diffInHours < 24) return `${diffInHours} hour${diffInHours > 1 ? 's' : ''} ago`;
    return `${diffInDays} day${diffInDays > 1 ? 's' : ''} ago`;
  }, [lastActivity]);

  // Authentication state object
  const authState = {
    isAuthenticated,
    user,
    token,
    tokenExpiry,
    provider,
    mfaRequired,
    sessionId,
    isLoading,
    error,
    lastActivity,
  };

  // Authentication actions object
  const authActions = {
    login: handleLogin,
    logout: handleLogout,
    refreshToken: handleRefreshToken,
    checkSession,
    recordActivity,
    updateUserProfile,
    clearError,
    setError,
  };

  // Utility functions object
  const authUtils = {
    isTokenNearExpiry,
    isTokenExpired,
    getTokenTimeRemaining,
    hasRole,
    hasGroup,
    hasAnyRole,
    hasAnyGroup,
    getLastActivityDisplay,
  };

  return {
    ...authState,
    ...authActions,
    ...authUtils,
  };
}

export default useAuthentication;