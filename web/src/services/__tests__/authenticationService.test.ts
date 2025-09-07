import { AuthenticationService } from '../authenticationService';
import type { OIDCProvider, SAMLProvider } from '../../types/auth';
import { vi } from 'vitest';

// Mock fetch globally
global.fetch = vi.fn();

describe('AuthenticationService', () => {
  let service: AuthenticationService;
  
  beforeEach(() => {
    service = AuthenticationService.getInstance();
    // Clear cached CSRF token
    (service as any).csrfToken = null;
    vi.clearAllMocks();
    // Clear localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: vi.fn(),
        setItem: vi.fn(),
        removeItem: vi.fn(),
        clear: vi.fn(),
      },
      writable: true,
    });
    // Mock window.location
    Object.defineProperty(window, 'location', {
      value: { href: 'http://localhost:3000' },
      writable: true,
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getInstance', () => {
    it('should return singleton instance', () => {
      const instance1 = AuthenticationService.getInstance();
      const instance2 = AuthenticationService.getInstance();
      expect(instance1).toBe(instance2);
    });
  });

  describe('getCSRFToken', () => {
    it('should retrieve and cache CSRF token', async () => {
      const mockToken = 'csrf-token-123';
      
      (fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: mockToken }),
      });

      // Access private method via type assertion for testing
      const token = await (service as any).getCSRFToken();
      
      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/csrf', {
        method: 'GET',
        credentials: 'include',
      });
      expect(token).toBe(mockToken);
    });

    it('should return cached CSRF token on subsequent calls', async () => {
      const mockToken = 'csrf-token-456';
      
      (fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => ({ token: mockToken }),
      });

      // First call should fetch
      const firstToken = await (service as any).getCSRFToken();
      
      // Second call should use cache (no additional fetch calls)
      const cachedToken = await (service as any).getCSRFToken();
      
      expect(fetch).toHaveBeenCalledTimes(1);
      expect(firstToken).toBe(mockToken);
      expect(cachedToken).toBe(mockToken);
    });
  });

  describe('initiateOIDCLogin', () => {
    it('should redirect to OIDC authorization URL with CSRF protection', async () => {
      const mockProvider: OIDCProvider = {
        name: 'Test Provider',
        issuer: 'https://auth.example.com',
        clientId: 'test-client',
        scopes: ['openid', 'profile'],
        redirectUri: 'http://localhost:3000/auth/callback'
      };

      const mockCSRFToken = 'csrf-token-123';
      const mockResponse = {
        authorizationUrl: 'https://auth.example.com/authorize?client_id=test-client&response_type=code&scope=openid%20profile&redirect_uri=http://localhost:3000/auth/callback&state=test-state'
      };

      // Mock CSRF token fetch
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: mockCSRFToken }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse,
        });

      const result = await service.initiateOIDCLogin(mockProvider);

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/oidc/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 
          'Content-Type': 'application/json',
          'X-CSRF-Token': mockCSRFToken,
        },
        body: JSON.stringify({
          providerId: mockProvider.name,
          clientId: mockProvider.clientId,
          scopes: mockProvider.scopes,
          redirectUri: mockProvider.redirectUri,
        }),
      });
      expect(result).toBe(mockResponse.authorizationUrl);
    });

    it('should handle OIDC login errors', async () => {
      const mockProvider: OIDCProvider = {
        name: 'Test Provider',
        issuer: 'https://auth.example.com',
        clientId: 'test-client',
        scopes: ['openid'],
        redirectUri: 'http://localhost:3000/auth/callback'
      };

      // Mock CSRF token fetch
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: 'csrf-token-123' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          statusText: 'Bad Request',
        });

      await expect(service.initiateOIDCLogin(mockProvider)).rejects.toThrow('Failed to initiate OIDC login');
    });
  });

  describe('handleOIDCCallback', () => {
    it('should handle OIDC callback successfully', async () => {
      const mockAuthState = {
        isAuthenticated: true,
        user: {
          id: 'user-1',
          email: 'test@example.com',
          name: 'Test User',
          roles: ['user'],
          groups: ['default'],
          preferences: {
            theme: 'system' as const,
            language: 'en-US',
            timezone: 'UTC',
            dashboardLayout: {
              sidebar: { collapsed: false, width: 280 },
              panels: {
                chat: { visible: true, position: 'center' as const },
                resources: { visible: true, position: 'right' as const },
                commands: { visible: true, position: 'bottom' as const },
              },
            },
            notifications: {
              enabled: true,
              email: false,
              push: true,
              sound: true,
              sessionWarnings: true,
              commandResults: true,
              systemAlerts: true,
            },
          },
        },
        token: 'mock-jwt-token',
        tokenExpiry: new Date(Date.now() + 3600000),
        provider: 'oidc' as const,
        sessionId: 'session-1',
        mfaRequired: false,
      };

      // Mock CSRF token fetch first, then the callback response
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: 'csrf-token-123' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockAuthState,
        });

      const result = await service.handleOIDCCallback('auth-code', 'test-state');

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/oidc/callback', {
        method: 'POST',
        credentials: 'include',
        headers: { 
          'Content-Type': 'application/json',
          'X-CSRF-Token': expect.any(String)
        },
        body: JSON.stringify({ code: 'auth-code', state: 'test-state' }),
      });
      expect(result).toEqual(mockAuthState);
    });

    it('should handle OIDC callback errors', async () => {
      // Mock CSRF token fetch first, then the error response
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: 'csrf-token-123' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          statusText: 'Unauthorized',
        });

      await expect(service.handleOIDCCallback('invalid-code', 'invalid-state')).rejects.toThrow('Failed to handle OIDC callback');
    });
  });

  describe('initiateSAMLSSO', () => {
    it('should initiate SAML SSO flow', async () => {
      const mockProvider: SAMLProvider = {
        name: 'Corporate SAML',
        ssoUrl: 'https://sso.company.com/saml/login',
        certificate: 'mock-certificate',
        entityId: 'kubechat-app'
      };

      const mockResponse = {
        ssoUrl: 'https://sso.company.com/saml/login?SAMLRequest=...'
      };

      // Mock CSRF token fetch first, then the SSO response
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: 'csrf-token-123' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => mockResponse,
        });

      const result = await service.initiateSAMLSSO(mockProvider);

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/saml/sso', {
        method: 'POST',
        credentials: 'include',
        headers: { 
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'csrf-token-123'
        },
        body: JSON.stringify({
          providerId: mockProvider.name,
          entityId: mockProvider.entityId,
          ssoUrl: mockProvider.ssoUrl,
        }),
      });
      expect(result).toBe(mockResponse.ssoUrl);
    });
  });

  describe('refreshToken', () => {
    it('should refresh authentication token', async () => {
      const mockAuthState = {
        isAuthenticated: true,
        user: { id: 'user-1', email: 'test@example.com', name: 'Test User', roles: [], groups: [] },
        token: 'new-jwt-token',
        tokenExpiry: new Date(Date.now() + 3600000),
        provider: 'oidc' as const,
        sessionId: 'session-1',
        mfaRequired: false,
      };

      (fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockAuthState,
      });

      const result = await service.refreshToken();

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/refresh', {
        method: 'POST',
        credentials: 'include',
      });
      expect(result).toEqual(mockAuthState);
    });

    it('should handle token refresh errors', async () => {
      (fetch as any).mockResolvedValueOnce({
        ok: false,
        statusText: 'Forbidden',
      });

      await expect(service.refreshToken()).rejects.toThrow('Failed to refresh token');
    });
  });

  describe('logout', () => {
    it('should logout successfully', async () => {
      // Mock CSRF token fetch first, then logout response
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: 'csrf-token-123' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ success: true }),
        });

      await service.logout();

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRF-Token': 'csrf-token-123',
        },
      });
    });

    it('should handle logout errors gracefully', async () => {
      // Mock CSRF token fetch first, then error response
      (fetch as any)
        .mockResolvedValueOnce({
          ok: true,
          json: async () => ({ token: 'csrf-token-123' }),
        })
        .mockResolvedValueOnce({
          ok: false,
          statusText: 'Internal Server Error',
        });

      await expect(service.logout()).rejects.toThrow('Failed to logout');
    });
  });

  describe('getSessionStatus', () => {
    it('should get current session status', async () => {
      const mockAuthState = {
        isAuthenticated: true,
        user: { id: 'user-1', email: 'test@example.com', name: 'Test User', roles: [], groups: [] },
        token: 'current-token',
        tokenExpiry: new Date(Date.now() + 1800000),
        provider: 'oidc' as const,
        sessionId: 'session-1',
        mfaRequired: false,
      };

      (fetch as any).mockResolvedValueOnce({
        ok: true,
        json: async () => mockAuthState,
      });

      const result = await service.getSessionStatus();

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/session', {
        method: 'GET',
        credentials: 'include',
      });
      expect(result).toEqual(mockAuthState);
    });

    it('should return null for unauthenticated session', async () => {
      (fetch as any).mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      const result = await service.getSessionStatus();
      expect(result).toBeNull();
    });
  });

});