import { renderHook, act } from '@testing-library/react';
import { useAuthStore } from '../authStore';
import AuthenticationService from '../../services/authenticationService';
import type { LoginFormData, AuthError, User } from '../../types/auth';

// Mock the authentication service
jest.mock('../../services/authenticationService');
const mockAuthService = jest.mocked(AuthenticationService);

describe('authStore', () => {
  beforeEach(() => {
    useAuthStore.setState({
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
    });
    jest.clearAllMocks();
  });

  describe('initial state', () => {
    it('should have correct initial state', () => {
      const { result } = renderHook(() => useAuthStore());
      
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBeNull();
      expect(result.current.token).toBeNull();
      expect(result.current.tokenExpiry).toBeNull();
      expect(result.current.provider).toBeNull();
      expect(result.current.mfaRequired).toBe(false);
      expect(result.current.sessionId).toBeNull();
      expect(result.current.isLoading).toBe(false);
      expect(result.current.error).toBeNull();
      expect(result.current.lastActivity).toBeNull();
    });
  });

  describe('login', () => {
    it('should handle OIDC login successfully', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      const mockInstance = {
        initiateOIDCLogin: jest.fn().mockResolvedValue('https://auth.example.com/authorize'),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.login(mockLoginData);
      });

      expect(mockInstance.initiateOIDCLogin).toHaveBeenCalledWith({
        name: 'test-provider',
        issuer: '',
        clientId: '',
        scopes: [],
        redirectUri: '',
      });
    });

    it('should handle SAML login successfully', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'saml',
        providerId: 'saml-provider',
        remember: true,
      };

      const mockInstance = {
        initiateSAMLSSO: jest.fn().mockResolvedValue('saml-request-data'),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.login(mockLoginData);
      });

      expect(mockInstance.initiateSAMLSSO).toHaveBeenCalledWith({
        name: 'saml-provider',
        ssoUrl: '',
        certificate: '',
        entityId: '',
      });
    });

    it('should handle login errors', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      const mockInstance = {
        initiateOIDCLogin: jest.fn().mockRejectedValue(new Error('Login failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.login(mockLoginData);
      });

      expect(result.current.error).toEqual({
        code: 'LOGIN_FAILED',
        message: 'Login failed',
        timestamp: expect.any(String),
        retryable: true,
      });
      expect(result.current.isLoading).toBe(false);
    });

    it('should set loading state during login', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      let resolveLogin: () => void;
      const loginPromise = new Promise<string>((resolve) => {
        resolveLogin = () => resolve('https://auth.example.com/authorize');
      });

      const mockInstance = {
        initiateOIDCLogin: jest.fn().mockReturnValue(loginPromise),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      const loginPromiseResult = act(async () => {
        return result.current.login(mockLoginData);
      });

      // Should be loading
      expect(result.current.isLoading).toBe(true);

      resolveLogin!();
      await loginPromiseResult;

      expect(result.current.isLoading).toBe(false);
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      const mockInstance = {
        logout: jest.fn().mockResolvedValue(undefined),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      // Set some initial authenticated state
      const { result } = renderHook(() => useAuthStore());
      act(() => {
        result.current.setAuthenticated(
          { id: 'user-1', email: 'test@example.com', name: 'Test', roles: [], groups: [], preferences: {} as any },
          'token',
          new Date(),
          'session-1',
          'oidc'
        );
      });

      await act(async () => {
        await result.current.logout();
      });

      expect(mockInstance.logout).toHaveBeenCalled();
      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.user).toBeNull();
      expect(result.current.token).toBeNull();
      expect(result.current.sessionId).toBeNull();
    });

    it('should handle logout errors', async () => {
      const mockInstance = {
        logout: jest.fn().mockRejectedValue(new Error('Logout failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.logout();
      });

      expect(result.current.error).toEqual({
        code: 'LOGOUT_FAILED',
        message: 'Logout failed',
        timestamp: expect.any(String),
        retryable: true,
      });
    });
  });

  describe('refreshToken', () => {
    it('should refresh token successfully', async () => {
      const mockUser: User = {
        id: 'user-1',
        email: 'test@example.com',
        name: 'Test User',
        roles: ['user'],
        groups: ['default'],
        preferences: {} as any,
      };

      const mockAuthState = {
        user: mockUser,
        token: 'new-token',
        tokenExpiry: new Date(Date.now() + 3600000),
        sessionId: 'session-1',
        provider: 'oidc' as const,
      };

      const mockInstance = {
        refreshToken: jest.fn().mockResolvedValue(mockAuthState),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.refreshToken();
      });

      expect(mockInstance.refreshToken).toHaveBeenCalled();
      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.token).toBe('new-token');
      expect(result.current.user).toEqual(mockUser);
    });

    it('should handle token refresh failure', async () => {
      const mockInstance = {
        refreshToken: jest.fn().mockRejectedValue(new Error('Token refresh failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.refreshToken();
      });

      expect(result.current.isAuthenticated).toBe(false);
      expect(result.current.error).toEqual({
        code: 'TOKEN_REFRESH_FAILED',
        message: 'Session expired. Please sign in again.',
        timestamp: expect.any(String),
        retryable: false,
      });
    });
  });

  describe('checkSession', () => {
    it('should check session successfully', async () => {
      const mockUser: User = {
        id: 'user-1',
        email: 'test@example.com',
        name: 'Test User',
        roles: ['user'],
        groups: ['default'],
        preferences: {} as any,
      };

      const mockAuthState = {
        user: mockUser,
        token: 'current-token',
        tokenExpiry: new Date(Date.now() + 1800000),
        sessionId: 'session-1',
        provider: 'oidc' as const,
        mfaRequired: false,
      };

      const mockInstance = {
        getSessionStatus: jest.fn().mockResolvedValue(mockAuthState),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.checkSession();
      });

      expect(mockInstance.getSessionStatus).toHaveBeenCalled();
      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.user).toEqual(mockUser);
    });

    it('should handle MFA required state', async () => {
      const mockAuthState = {
        mfaRequired: true,
      };

      const mockInstance = {
        getSessionStatus: jest.fn().mockResolvedValue(mockAuthState),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.checkSession();
      });

      expect(result.current.mfaRequired).toBe(true);
      expect(result.current.isAuthenticated).toBe(false);
    });

    it('should handle session check failure', async () => {
      const mockInstance = {
        getSessionStatus: jest.fn().mockRejectedValue(new Error('Session check failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.checkSession();
      });

      expect(result.current.isAuthenticated).toBe(false);
    });
  });

  describe('setAuthenticated', () => {
    it('should set authenticated state correctly', () => {
      const mockUser: User = {
        id: 'user-1',
        email: 'test@example.com',
        name: 'Test User',
        roles: ['admin'],
        groups: ['admins'],
        preferences: {} as any,
      };

      const tokenExpiry = new Date(Date.now() + 3600000);

      const { result } = renderHook(() => useAuthStore());

      act(() => {
        result.current.setAuthenticated(mockUser, 'jwt-token', tokenExpiry, 'session-123', 'saml');
      });

      expect(result.current.isAuthenticated).toBe(true);
      expect(result.current.user).toEqual(mockUser);
      expect(result.current.token).toBe('jwt-token');
      expect(result.current.tokenExpiry).toEqual(tokenExpiry);
      expect(result.current.sessionId).toBe('session-123');
      expect(result.current.provider).toBe('saml');
      expect(result.current.mfaRequired).toBe(false);
      expect(result.current.error).toBeNull();
      expect(result.current.lastActivity).toBeInstanceOf(Date);
    });
  });

  describe('updateLastActivity', () => {
    it('should update last activity timestamp', () => {
      const { result } = renderHook(() => useAuthStore());

      const beforeUpdate = result.current.lastActivity;
      
      act(() => {
        result.current.updateLastActivity();
      });

      expect(result.current.lastActivity).toBeInstanceOf(Date);
      expect(result.current.lastActivity).not.toEqual(beforeUpdate);
    });
  });

  describe('updateUser', () => {
    it('should update user information', () => {
      const mockUser: User = {
        id: 'user-1',
        email: 'test@example.com',
        name: 'Test User',
        roles: ['user'],
        groups: ['default'],
        preferences: {} as any,
      };

      const { result } = renderHook(() => useAuthStore());

      // Set initial authenticated state
      act(() => {
        result.current.setAuthenticated(mockUser, 'token', new Date(), 'session-1', 'oidc');
      });

      // Update user
      act(() => {
        result.current.updateUser({ name: 'Updated User', roles: ['admin'] });
      });

      expect(result.current.user?.name).toBe('Updated User');
      expect(result.current.user?.roles).toEqual(['admin']);
      expect(result.current.user?.email).toBe('test@example.com'); // Should preserve other fields
    });

    it('should not update user when not authenticated', () => {
      const { result } = renderHook(() => useAuthStore());

      act(() => {
        result.current.updateUser({ name: 'Should Not Update' });
      });

      expect(result.current.user).toBeNull();
    });
  });

  describe('error handling', () => {
    it('should set and clear errors', () => {
      const { result } = renderHook(() => useAuthStore());

      const mockError: AuthError = {
        code: 'TEST_ERROR',
        message: 'Test error message',
        timestamp: new Date().toISOString(),
        retryable: true,
      };

      act(() => {
        result.current.setError(mockError);
      });

      expect(result.current.error).toEqual(mockError);

      act(() => {
        result.current.clearError();
      });

      expect(result.current.error).toBeNull();
    });
  });
});