import { renderHook, act } from '@testing-library/react';
import { useAuthStore } from '../authStore';
import AuthenticationService from '../../services/authenticationService';
import type { LoginFormData } from '../../types/auth';
import { vi } from 'vitest';

// Mock the authentication service
vi.mock('../../services/authenticationService');
const mockAuthService = vi.mocked(AuthenticationService);

describe('authStore rate limiting', () => {
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
      _rateLimiting: {
        attempts: 0,
        lastAttempt: null,
        lockoutUntil: null,
      },
    });
    vi.clearAllMocks();
  });

  describe('rate limiting behavior', () => {
    it('should allow login attempts initially', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      const mockInstance = {
        initiateOIDCLogin: vi.fn().mockRejectedValue(new Error('Login failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      await act(async () => {
        await result.current.login(mockLoginData);
      });

      // First attempt should be allowed
      expect(mockInstance.initiateOIDCLogin).toHaveBeenCalled();
      expect(result.current.error?.code).toBe('LOGIN_FAILED');
    });

    it('should implement exponential backoff after 3 failed attempts', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      const mockInstance = {
        initiateOIDCLogin: vi.fn().mockRejectedValue(new Error('Login failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      // Simulate 3 failed attempts
      for (let i = 0; i < 3; i++) {
        await act(async () => {
          await result.current.login(mockLoginData);
        });
      }

      // 4th attempt should be rate limited
      await act(async () => {
        await result.current.login(mockLoginData);
      });

      expect(result.current.error?.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(result.current.error?.message).toContain('Too many failed login attempts');
    });

    it('should reset rate limiting on successful logout', async () => {
      const mockInstance = {
        logout: vi.fn().mockResolvedValue(undefined),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      // Set some failed attempts
      act(() => {
        useAuthStore.setState({
          _rateLimiting: {
            attempts: 3,
            lastAttempt: new Date(),
            lockoutUntil: new Date(Date.now() + 60000),
          },
        });
      });

      await act(async () => {
        await result.current.logout();
      });

      const state = useAuthStore.getState();
      expect(state._rateLimiting.attempts).toBe(0);
      expect(state._rateLimiting.lockoutUntil).toBeNull();
    });

    it('should calculate lockout duration exponentially', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      const mockInstance = {
        initiateOIDCLogin: vi.fn().mockRejectedValue(new Error('Login failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      // Simulate multiple failed attempts and check lockout duration
      const startTime = Date.now();
      
      // First 3 attempts should not cause lockout
      for (let i = 0; i < 3; i++) {
        await act(async () => {
          await result.current.login(mockLoginData);
        });
      }

      const state = useAuthStore.getState();
      
      // Check that lockout is set (after 3rd attempt)
      expect(state._rateLimiting.lockoutUntil).toBeTruthy();
      
      // Lockout should be roughly 2^3 = 8 seconds (for 3rd attempt)
      const lockoutDuration = state._rateLimiting.lockoutUntil!.getTime() - startTime;
      expect(lockoutDuration).toBeGreaterThan(7000); // At least 7 seconds
      expect(lockoutDuration).toBeLessThan(10000); // Less than 10 seconds
    });

    it('should enforce maximum lockout duration of 5 minutes', async () => {
      const mockLoginData: LoginFormData = {
        provider: 'oidc',
        providerId: 'test-provider',
        remember: false,
      };

      const mockInstance = {
        initiateOIDCLogin: vi.fn().mockRejectedValue(new Error('Login failed')),
      };
      mockAuthService.getInstance.mockReturnValue(mockInstance as any);

      const { result } = renderHook(() => useAuthStore());

      // Set initial state with many failed attempts
      act(() => {
        useAuthStore.setState({
          _rateLimiting: {
            attempts: 10, // This would normally cause 2^10 = 1024 seconds
            lastAttempt: new Date(),
            lockoutUntil: null,
          },
        });
      });

      const startTime = Date.now();

      // One more failed attempt
      await act(async () => {
        await result.current.login(mockLoginData);
      });

      const state = useAuthStore.getState();
      const lockoutDuration = state._rateLimiting.lockoutUntil!.getTime() - startTime;
      
      // Should be capped at 5 minutes (300 seconds) + small tolerance for execution time
      expect(lockoutDuration).toBeLessThanOrEqual(300100); // 5 minutes max + 100ms tolerance
    });
  });
});