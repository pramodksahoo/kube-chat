import type { AuthenticationState, OIDCProvider, SAMLProvider } from '../types/auth';

export class AuthenticationService {
  private static instance: AuthenticationService;
  private csrfToken: string | null = null;
  
  private constructor() {}
  
  public static getInstance(): AuthenticationService {
    if (!AuthenticationService.instance) {
      AuthenticationService.instance = new AuthenticationService();
    }
    return AuthenticationService.instance;
  }

  /**
   * Get CSRF token from server
   */
  private async getCSRFToken(): Promise<string> {
    if (this.csrfToken) {
      return this.csrfToken;
    }

    try {
      const response = await fetch('/api/v1/auth/csrf', {
        method: 'GET',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to get CSRF token: ${response.statusText}`);
      }

      const data = await response.json();
      this.csrfToken = data.token;
      return this.csrfToken || '';
    } catch (error) {
      throw new Error(`Failed to retrieve CSRF token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Create authenticated request headers with CSRF protection
   */
  private async createAuthHeaders(): Promise<Record<string, string>> {
    const csrfToken = await this.getCSRFToken();
    return {
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    };
  }

  /**
   * Initiate OIDC login flow
   */
  public async initiateOIDCLogin(provider: OIDCProvider): Promise<string> {
    try {
      const headers = await this.createAuthHeaders();
      const response = await fetch('/api/v1/auth/oidc/login', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({
          providerId: provider.name,
          clientId: provider.clientId,
          scopes: provider.scopes,
          redirectUri: provider.redirectUri,
        }),
      });

      if (!response.ok) {
        throw new Error(`OIDC login initiation failed: ${response.statusText}`);
      }

      const data = await response.json();
      return data.authorizationUrl;
    } catch (error) {
      throw new Error(`Failed to initiate OIDC login: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Handle OIDC callback with authorization code
   */
  public async handleOIDCCallback(code: string, state: string): Promise<AuthenticationState> {
    try {
      const headers = await this.createAuthHeaders();
      const response = await fetch('/api/v1/auth/oidc/callback', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({
          code,
          state,
        }),
      });

      if (!response.ok) {
        throw new Error(`OIDC callback handling failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        isAuthenticated: true,
        user: data.user,
        token: data.token,
        tokenExpiry: new Date(data.tokenExpiry),
        provider: 'oidc',
        mfaRequired: data.mfaRequired || false,
        sessionId: data.sessionId,
      };
    } catch (error) {
      throw new Error(`Failed to handle OIDC callback: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Initiate SAML SSO flow
   */
  public async initiateSAMLSSO(provider: SAMLProvider): Promise<string> {
    try {
      const headers = await this.createAuthHeaders();
      const response = await fetch('/api/v1/auth/saml/sso', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({
          providerId: provider.name,
          entityId: provider.entityId,
          ssoUrl: provider.ssoUrl,
        }),
      });

      if (!response.ok) {
        throw new Error(`SAML SSO initiation failed: ${response.statusText}`);
      }

      const data = await response.json();
      return data.ssoUrl;
    } catch (error) {
      throw new Error(`Failed to initiate SAML SSO: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Handle SAML assertion consumer service callback
   */
  public async handleSAMLAssertion(samlResponse: string): Promise<AuthenticationState> {
    try {
      const headers = await this.createAuthHeaders();
      const response = await fetch('/api/v1/auth/saml/acs', {
        method: 'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({
          SAMLResponse: samlResponse,
        }),
      });

      if (!response.ok) {
        throw new Error(`SAML assertion handling failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        isAuthenticated: true,
        user: data.user,
        token: data.token,
        tokenExpiry: new Date(data.tokenExpiry),
        provider: 'saml',
        mfaRequired: data.mfaRequired || false,
        sessionId: data.sessionId,
      };
    } catch (error) {
      throw new Error(`Failed to handle SAML assertion: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Get current session status
   */
  public async getSessionStatus(): Promise<AuthenticationState | null> {
    try {
      const response = await fetch('/api/v1/auth/session', {
        method: 'GET',
        credentials: 'include',
      });

      if (response.status === 401) {
        return null; // Not authenticated
      }

      if (!response.ok) {
        throw new Error(`Session status check failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        isAuthenticated: true,
        user: data.user,
        token: data.token,
        tokenExpiry: new Date(data.tokenExpiry),
        provider: data.provider,
        mfaRequired: data.mfaRequired || false,
        sessionId: data.sessionId,
      };
    } catch (error) {
      throw new Error(`Failed to check session status: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Refresh authentication token
   */
  public async refreshToken(): Promise<AuthenticationState> {
    try {
      const response = await fetch('/api/v1/auth/refresh', {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Token refresh failed: ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        isAuthenticated: true,
        user: data.user,
        token: data.token,
        tokenExpiry: new Date(data.tokenExpiry),
        provider: data.provider,
        mfaRequired: data.mfaRequired || false,
        sessionId: data.sessionId,
      };
    } catch (error) {
      throw new Error(`Failed to refresh token: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Logout and cleanup session
   */
  public async logout(): Promise<void> {
    try {
      const headers = await this.createAuthHeaders();
      const response = await fetch('/api/v1/auth/logout', {
        method: 'POST',
        credentials: 'include',
        headers,
      });

      if (!response.ok) {
        throw new Error(`Logout failed: ${response.statusText}`);
      }

      // Clear CSRF token on successful logout
      this.csrfToken = null;
    } catch (error) {
      // Clear CSRF token even on logout failure for security
      this.csrfToken = null;
      throw new Error(`Failed to logout: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Validate and sanitize authentication inputs
   */
  public validateAuthInput(input: string): string {
    if (typeof input !== 'string') {
      throw new Error('Authentication input must be a string');
    }
    
    const sanitized = input.trim();
    
    if (sanitized.length === 0) {
      throw new Error('Authentication input cannot be empty');
    }
    
    if (sanitized.length > 1000) {
      throw new Error('Authentication input exceeds maximum length');
    }
    
    return sanitized;
  }
}

export default AuthenticationService;