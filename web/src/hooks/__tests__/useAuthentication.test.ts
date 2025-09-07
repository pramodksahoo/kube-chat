import { renderHook, act } from '@testing-library/react';
import { useAuthentication } from '../useAuthentication';
import { useAuthStore } from '../../stores/authStore';
import type { User, LoginFormData } from '../../types/auth';

// Mock the auth store
jest.mock('../../stores/authStore');
const mockUseAuthStore = jest.mocked(useAuthStore);

describe('useAuthentication', () => {
  const mockAuthState = {
    isAuthenticated: false,
    user: null,
    token: null,
    tokenExpiry: null,
    provider: null,
    mfaRequired: false,
    sessionId: null,
    isLoading: false,
    error: null,
    lastActivity: null,
    login: jest.fn(),
    logout: jest.fn(),
    refreshToken: jest.fn(),
    checkSession: jest.fn(),
    setError: jest.fn(),
    clearError: jest.fn(),
    updateLastActivity: jest.fn(),
    updateUser: jest.fn(),
    setAuthenticated: jest.fn(),
    setMFARequired: jest.fn(),
    setLoading: jest.fn(),
  };

  beforeEach(() => {
    jest.clearAllMocks();
    mockUseAuthStore.mockReturnValue(mockAuthState);
  });

  it('should return authentication state and actions', () => {
    const { result } = renderHook(() => useAuthentication());

    expect(result.current.isAuthenticated).toBe(false);
    expect(result.current.user).toBeNull();
    expect(result.current.login).toBeDefined();
    expect(result.current.logout).toBeDefined();
    expect(result.current.refreshToken).toBeDefined();
    expect(result.current.checkSession).toBeDefined();
    expect(result.current.clearError).toBeDefined();
    expect(result.current.recordActivity).toBeDefined();
  });

  it('should check session on mount when not authenticated and not loading', () => {
    renderHook(() => useAuthentication());

    expect(mockAuthState.checkSession).toHaveBeenCalled();
  });

  it('should not check session when already authenticated', () => {
    mockUseAuthStore.mockReturnValue({
      ...mockAuthState,
      isAuthenticated: true,
    });

    renderHook(() => useAuthentication());

    expect(mockAuthState.checkSession).not.toHaveBeenCalled();
  });

  it('should not check session when loading', () => {
    mockUseAuthStore.mockReturnValue({
      ...mockAuthState,
      isLoading: true,
    });

    renderHook(() => useAuthentication());

    expect(mockAuthState.checkSession).not.toHaveBeenCalled();
  });

  describe('handleLogin', () => {
    it('should handle login successfully', async () => {
      const { result } = renderHook(() => useAuthentication());

      const loginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      await act(async () => {
        await result.current.login(loginData);
      });

      expect(mockAuthState.clearError).toHaveBeenCalled();
      expect(mockAuthState.login).toHaveBeenCalledWith(loginData);
    });

    it('should handle login errors gracefully', async () => {
      const loginError = new Error('Login failed');
      const mockLoginWithError = jest.fn().mockRejectedValue(loginError);
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        login: mockLoginWithError,
      });

      const { result } = renderHook(() => useAuthentication());

      const loginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      // Should not throw error
      await act(async () => {
        await result.current.login(loginData);
      });

      expect(mockAuthState.clearError).toHaveBeenCalled();
      expect(mockLoginWithError).toHaveBeenCalledWith(loginData);
    });
  });

  describe('handleLogout', () => {
    it('should handle logout successfully', async () => {
      const { result } = renderHook(() => useAuthentication());

      await act(async () => {
        await result.current.logout();
      });

      expect(mockAuthState.clearError).toHaveBeenCalled();
      expect(mockAuthState.logout).toHaveBeenCalled();
    });

    it('should handle logout errors gracefully', async () => {
      const logoutError = new Error('Logout failed');
      const mockLogoutWithError = jest.fn().mockRejectedValue(logoutError);
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        logout: mockLogoutWithError,
      });

      const { result } = renderHook(() => useAuthentication());

      // Should not throw error
      await act(async () => {
        await result.current.logout();
      });

      expect(mockAuthState.clearError).toHaveBeenCalled();
      expect(mockLogoutWithError).toHaveBeenCalled();
    });
  });

  describe('handleRefreshToken', () => {
    it('should handle token refresh successfully', async () => {
      const { result } = renderHook(() => useAuthentication());

      await act(async () => {
        await result.current.refreshToken();
      });

      expect(mockAuthState.clearError).toHaveBeenCalled();
      expect(mockAuthState.refreshToken).toHaveBeenCalled();
    });
  });

  describe('recordActivity', () => {
    it('should update activity when authenticated', () => {
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        isAuthenticated: true,
      });

      const { result } = renderHook(() => useAuthentication());

      act(() => {
        result.current.recordActivity();
      });

      expect(mockAuthState.updateLastActivity).toHaveBeenCalled();
    });

    it('should not update activity when not authenticated', () => {
      const { result } = renderHook(() => useAuthentication());

      act(() => {
        result.current.recordActivity();
      });

      expect(mockAuthState.updateLastActivity).not.toHaveBeenCalled();
    });
  });

  describe('token expiry checks', () => {
    it('should detect token near expiry', () => {
      const nearExpiryTime = new Date(Date.now() + 3 * 60 * 1000); // 3 minutes from now
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        tokenExpiry: nearExpiryTime,
      });

      const { result } = renderHook(() => useAuthentication());

      expect(result.current.isTokenNearExpiry()).toBe(true);
    });

    it('should not flag token with plenty of time', () => {
      const futureTime = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes from now
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        tokenExpiry: futureTime,
      });

      const { result } = renderHook(() => useAuthentication());

      expect(result.current.isTokenNearExpiry()).toBe(false);
    });

    it('should detect expired token', () => {
      const pastTime = new Date(Date.now() - 60 * 1000); // 1 minute ago
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        tokenExpiry: pastTime,
      });

      const { result } = renderHook(() => useAuthentication());

      expect(result.current.isTokenExpired()).toBe(true);
    });

    it('should calculate time remaining correctly', () => {
      const futureTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        tokenExpiry: futureTime,
      });

      const { result } = renderHook(() => useAuthentication());

      const timeRemaining = result.current.getTokenTimeRemaining();
      expect(timeRemaining).toBeGreaterThan(9 * 60 * 1000);
      expect(timeRemaining).toBeLessThanOrEqual(10 * 60 * 1000);
    });
  });

  describe('role and group checks', () => {
    const mockUser: User = {
      id: 'user-1',
      email: 'test@example.com',
      name: 'Test User',
      roles: ['user', 'admin'],
      groups: ['developers', 'testers'],
      preferences: {} as any,
    };

    beforeEach(() => {
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        user: mockUser,
      });
    });

    it('should check if user has specific role', () => {
      const { result } = renderHook(() => useAuthentication());

      expect(result.current.hasRole('admin')).toBe(true);
      expect(result.current.hasRole('superadmin')).toBe(false);
    });

    it('should check if user belongs to specific group', () => {
      const { result } = renderHook(() => useAuthentication());

      expect(result.current.hasGroup('developers')).toBe(true);
      expect(result.current.hasGroup('managers')).toBe(false);
    });

    it('should check if user has any of specified roles', () => {
      const { result } = renderHook(() => useAuthentication());

      expect(result.current.hasAnyRole(['admin', 'superadmin'])).toBe(true);
      expect(result.current.hasAnyRole(['superadmin', 'owner'])).toBe(false);
    });

    it('should check if user belongs to any of specified groups', () => {
      const { result } = renderHook(() => useAuthentication());

      expect(result.current.hasAnyGroup(['developers', 'managers'])).toBe(true);
      expect(result.current.hasAnyGroup(['managers', 'executives'])).toBe(false);
    });

    it('should handle missing user roles and groups', () => {
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        user: { ...mockUser, roles: undefined, groups: undefined } as any,
      });

      const { result } = renderHook(() => useAuthentication());

      expect(result.current.hasRole('admin')).toBe(false);
      expect(result.current.hasGroup('developers')).toBe(false);
      expect(result.current.hasAnyRole(['admin'])).toBe(false);
      expect(result.current.hasAnyGroup(['developers'])).toBe(false);
    });
  });

  describe('updateUserProfile', () => {
    it('should update user profile when authenticated', () => {
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        isAuthenticated: true,
      });

      const { result } = renderHook(() => useAuthentication());

      const updates = { name: 'Updated Name' };

      act(() => {
        result.current.updateUserProfile(updates);
      });

      expect(mockAuthState.updateUser).toHaveBeenCalledWith(updates);
    });

    it('should not update user profile when not authenticated', () => {
      const { result } = renderHook(() => useAuthentication());

      const updates = { name: 'Updated Name' };

      act(() => {
        result.current.updateUserProfile(updates);
      });

      expect(mockAuthState.updateUser).not.toHaveBeenCalled();
    });
  });

  describe('getLastActivityDisplay', () => {
    it('should format last activity display correctly', () => {
      const lastActivity = new Date(Date.now() - 2 * 60 * 1000); // 2 minutes ago
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        lastActivity,
      });

      const { result } = renderHook(() => useAuthentication());

      expect(result.current.getLastActivityDisplay()).toBe('2 minutes ago');
    });

    it('should show "Never" when no last activity', () => {
      const { result } = renderHook(() => useAuthentication());

      expect(result.current.getLastActivityDisplay()).toBe('Never');
    });

    it('should show "Just now" for very recent activity', () => {
      const lastActivity = new Date(Date.now() - 30000); // 30 seconds ago
      
      mockUseAuthStore.mockReturnValue({
        ...mockAuthState,
        lastActivity,
      });

      const { result } = renderHook(() => useAuthentication());

      expect(result.current.getLastActivityDisplay()).toBe('Just now');
    });
  });
});