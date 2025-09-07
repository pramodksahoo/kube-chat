import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { AuthError, AuthStoreState, LoginFormData, OIDCLoginData, SAMLLoginData, User } from '../types/auth';
import AuthenticationService from '../services/authenticationService';
import TokenStorageService from '../services/tokenStorageService';

interface AuthStoreActions {
  // Authentication actions
  login: (data: LoginFormData) => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
  checkSession: () => Promise<void>;
  
  // State management actions
  setAuthenticated: (user: User, token: string, tokenExpiry: Date, sessionId: string, provider: 'oidc' | 'saml') => void;
  setMFARequired: (required: boolean) => void;
  setError: (error: AuthError | null) => void;
  setLoading: (loading: boolean) => void;
  clearError: () => void;
  updateLastActivity: () => void;
  
  // User profile actions
  updateUser: (user: Partial<User>) => void;
}

type AuthStore = AuthStoreState & AuthStoreActions;

export const useAuthStore = create<AuthStore>()(
  subscribeWithSelector((set, get) => ({
    // Initial state
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
    
    // Rate limiting state (not in interface to avoid exposing)
    _rateLimiting: {
      attempts: 0,
      lastAttempt: null as Date | null,
      lockoutUntil: null as Date | null,
    },

    // Authentication actions
    login: async (data: LoginFormData) => {
      const { setLoading, setError, _rateLimiting } = get();
      
      // Check rate limiting
      const now = new Date();
      if (_rateLimiting.lockoutUntil && now < _rateLimiting.lockoutUntil) {
        const remainingMs = _rateLimiting.lockoutUntil.getTime() - now.getTime();
        const remainingSeconds = Math.ceil(remainingMs / 1000);
        setError({
          code: 'RATE_LIMIT_EXCEEDED',
          message: `Too many failed login attempts. Please wait ${remainingSeconds} seconds before trying again.`,
          timestamp: new Date().toISOString(),
          retryable: true,
        });
        return;
      }
      
      try {
        setLoading(true);
        setError(null);
        
        const authService = AuthenticationService.getInstance();
        
        if (data.provider === 'oidc') {
          // OIDC flow - initiate authorization
          const oidcData = data as OIDCLoginData;
          const provider = {
            name: oidcData.providerId,
            issuer: '', // Will be filled by service
            clientId: '',
            scopes: [],
            redirectUri: '',
          };
          
          await authService.initiateOIDCLogin(provider);
          
          // Redirect will happen, so we don't continue here
          return;
        } else if (data.provider === 'saml') {
          // SAML flow - initiate SSO
          const samlData = data as SAMLLoginData;
          const provider = {
            name: samlData.providerId,
            ssoUrl: '',
            certificate: '',
            entityId: '',
          };
          
          await authService.initiateSAMLSSO(provider);
          
          // Redirect will happen, so we don't continue here
          return;
        } else {
          throw new Error('Unsupported authentication provider');
        }
        // Reset rate limiting on successful login attempt
        set((state) => ({
          ...state,
          _rateLimiting: {
            attempts: 0,
            lastAttempt: null,
            lockoutUntil: null,
          }
        }));
      } catch (error) {
        // Implement exponential backoff on failed attempts
        const now = new Date();
        const newAttempts = _rateLimiting.attempts + 1;
        
        // Calculate lockout duration: 2^attempts seconds, max 5 minutes
        const lockoutSeconds = Math.min(Math.pow(2, newAttempts), 300);
        const lockoutUntil = new Date(now.getTime() + lockoutSeconds * 1000);
        
        set((state) => ({
          ...state,
          _rateLimiting: {
            attempts: newAttempts,
            lastAttempt: now,
            lockoutUntil: newAttempts >= 3 ? lockoutUntil : null, // Start lockout after 3 failed attempts
          }
        }));
        
        const authError: AuthError = {
          code: 'LOGIN_FAILED',
          message: error instanceof Error ? error.message : 'Login failed',
          timestamp: new Date().toISOString(),
          retryable: true,
        };
        setError(authError);
      } finally {
        setLoading(false);
      }
    },

    logout: async () => {
      const { setLoading, setError } = get();
      
      try {
        setLoading(true);
        setError(null);
        
        const authService = AuthenticationService.getInstance();
        await authService.logout();
        
        // Clear all authentication state
        set({
          isAuthenticated: false,
          user: null,
          token: null,
          tokenExpiry: null,
          provider: null,
          mfaRequired: false,
          sessionId: null,
          lastActivity: null,
        });
        
        // Reset rate limiting on successful logout
        set((state) => ({
          ...state,
          _rateLimiting: {
            attempts: 0,
            lastAttempt: null,
            lockoutUntil: null,
          }
        }));
        
        // Clear token storage using consistent strategy
        const tokenStorage = TokenStorageService.getInstance();
        tokenStorage.clearToken();
        
        // Clear other localStorage/sessionStorage
        if (typeof window !== 'undefined') {
          Object.keys(localStorage).forEach(key => {
            if (key.startsWith('kubechat_') && key !== 'kubechat_auth_token') {
              localStorage.removeItem(key);
            }
          });
          
          Object.keys(sessionStorage).forEach(key => {
            if (key.startsWith('kubechat_')) {
              sessionStorage.removeItem(key);
            }
          });
        }
        
      } catch (error) {
        const authError: AuthError = {
          code: 'LOGOUT_FAILED',
          message: error instanceof Error ? error.message : 'Logout failed',
          timestamp: new Date().toISOString(),
          retryable: true,
        };
        setError(authError);
      } finally {
        setLoading(false);
      }
    },

    refreshToken: async () => {
      const { setLoading, setError, setAuthenticated } = get();
      
      try {
        setLoading(true);
        setError(null);
        
        const authService = AuthenticationService.getInstance();
        const authState = await authService.refreshToken();
        
        if (authState && authState.user) {
          setAuthenticated(
            authState.user,
            authState.token!,
            authState.tokenExpiry!,
            authState.sessionId!,
            authState.provider!
          );
        }
      } catch {
        // Token refresh failed - user needs to re-authenticate
        set({
          isAuthenticated: false,
          user: null,
          token: null,
          tokenExpiry: null,
          provider: null,
          mfaRequired: false,
          sessionId: null,
        });
        
        const authError: AuthError = {
          code: 'TOKEN_REFRESH_FAILED',
          message: 'Session expired. Please sign in again.',
          timestamp: new Date().toISOString(),
          retryable: false,
        };
        setError(authError);
      } finally {
        setLoading(false);
      }
    },

    checkSession: async () => {
      const { setLoading, setError, setAuthenticated, setMFARequired } = get();
      
      try {
        setLoading(true);
        setError(null);
        
        const authService = AuthenticationService.getInstance();
        const authState = await authService.getSessionStatus();
        
        if (authState) {
          if (authState.mfaRequired) {
            setMFARequired(true);
          } else if (authState.user) {
            setAuthenticated(
              authState.user,
              authState.token!,
              authState.tokenExpiry!,
              authState.sessionId!,
              authState.provider!
            );
          }
        }
      } catch {
        // Session check failed - user is not authenticated
        set({
          isAuthenticated: false,
          user: null,
          token: null,
          tokenExpiry: null,
          provider: null,
          mfaRequired: false,
          sessionId: null,
        });
      } finally {
        setLoading(false);
      }
    },

    // State management actions
    setAuthenticated: (user, token, tokenExpiry, sessionId, provider) => {
      // Store token using consistent strategy
      const tokenStorage = TokenStorageService.getInstance();
      tokenStorage.storeToken(token, tokenExpiry);
      
      set({
        isAuthenticated: true,
        user,
        token, // Keep in state for performance, but primary storage is via TokenStorageService
        tokenExpiry,
        sessionId,
        provider,
        mfaRequired: false,
        lastActivity: new Date(),
        error: null,
      });
    },

    setMFARequired: (required) => {
      set({ mfaRequired: required });
    },

    setError: (error) => {
      set({ error });
    },

    setLoading: (loading) => {
      set({ isLoading: loading });
    },

    clearError: () => {
      set({ error: null });
    },

    updateLastActivity: () => {
      set({ lastActivity: new Date() });
    },

    updateUser: (updates) => {
      set((state) => ({
        user: state.user ? { ...state.user, ...updates } : null,
      }));
    },
  }))
);

// Automatic token refresh setup
if (typeof window !== 'undefined') {
  // Check session on page load
  void useAuthStore.getState().checkSession();
  
  // Set up automatic token refresh
  useAuthStore.subscribe(
    (state) => state.tokenExpiry,
    (tokenExpiry) => {
      if (!tokenExpiry) return;
      
      const refreshTime = new Date(tokenExpiry).getTime() - Date.now() - (5 * 60 * 1000); // Refresh 5 minutes before expiry
      
      if (refreshTime > 0) {
        setTimeout(() => {
          void (async () => {
            const currentState = useAuthStore.getState();
            if (currentState.isAuthenticated) {
              await currentState.refreshToken();
            }
          })();
        }, refreshTime);
      }
    }
  );
  
  // Update last activity on user interactions
  const updateActivity = () => {
    const state = useAuthStore.getState();
    if (state.isAuthenticated) {
      state.updateLastActivity();
    }
  };
  
  ['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
    window.addEventListener(event, updateActivity, { passive: true });
  });
}

export default useAuthStore;