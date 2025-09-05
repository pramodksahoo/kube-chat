import { useCallback, useEffect, useState } from 'react';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
}

export interface AuthState {
  user: AuthUser | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}

interface LoginResponse {
  user: AuthUser;
  token: string;
}

interface RefreshTokenResponse {
  token: string;
}

export const useAuth = () => {
  const [authState, setAuthState] = useState<AuthState>({
    user: null,
    token: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
  });

  // Load token from localStorage on mount
  useEffect(() => {
    const token = localStorage.getItem('auth_token');
    const userString = localStorage.getItem('auth_user');
    
    if (token && userString) {
      try {
        const user = JSON.parse(userString) as AuthUser;
        setAuthState({
          user,
          token,
          isAuthenticated: true,
          isLoading: false,
          error: null,
        });
      } catch (error) {
        console.error('Failed to parse stored user data:', error);
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_user');
        setAuthState(prev => ({ ...prev, isLoading: false }));
      }
    } else {
      setAuthState(prev => ({ ...prev, isLoading: false }));
    }
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setAuthState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      // Mock authentication - replace with actual API call
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        throw new Error('Authentication failed');
      }

      const data = await response.json() as LoginResponse;
      const { user, token } = data;

      // Store in localStorage
      localStorage.setItem('auth_token', token);
      localStorage.setItem('auth_user', JSON.stringify(user));

      setAuthState({
        user,
        token,
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      return { success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Login failed';
      setAuthState(prev => ({
        ...prev,
        isLoading: false,
        error: errorMessage,
      }));
      return { success: false, error: errorMessage };
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_user');
    setAuthState({
      user: null,
      token: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  }, []);

  const validateToken = useCallback(async (): Promise<boolean> => {
    if (!authState.token) {
      return false;
    }

    try {
      const response = await fetch('/api/v1/auth/validate', {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${authState.token}`,
        },
      });

      if (!response.ok) {
        logout();
        return false;
      }

      return true;
    } catch (error) {
      console.error('Token validation failed:', error);
      logout();
      return false;
    }
  }, [authState.token, logout]);

  const refreshToken = useCallback(async (): Promise<boolean> => {
    if (!authState.token) {
      return false;
    }

    try {
      const response = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${authState.token}`,
        },
      });

      if (!response.ok) {
        logout();
        return false;
      }

      const data = await response.json() as RefreshTokenResponse;
      const { token: newToken } = data;

      localStorage.setItem('auth_token', newToken);
      setAuthState(prev => ({
        ...prev,
        token: newToken,
      }));

      return true;
    } catch (error) {
      console.error('Token refresh failed:', error);
      logout();
      return false;
    }
  }, [authState.token, logout]);

  const hasPermission = useCallback(
    (permission: string): boolean => {
      return authState.user?.permissions.includes(permission) || false;
    },
    [authState.user]
  );

  const hasRole = useCallback(
    (role: string): boolean => {
      return authState.user?.roles.includes(role) || false;
    },
    [authState.user]
  );

  return {
    ...authState,
    login,
    logout,
    validateToken,
    refreshToken,
    hasPermission,
    hasRole,
  };
};