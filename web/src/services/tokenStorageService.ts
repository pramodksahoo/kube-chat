/**
 * Token Storage Service - Centralized token management
 * 
 * Strategy: Use httpOnly cookies as primary storage with Zustand state as cache
 * This provides:
 * - Security: httpOnly cookies prevent XSS token theft
 * - Performance: In-memory cache for fast access
 * - Consistency: Single source of truth with fallback strategy
 */

interface StoredTokenData {
  token: string;
  expiry: string;
  stored: string;
}

export class TokenStorageService {
  private static instance: TokenStorageService;
  
  private constructor() {}
  
  public static getInstance(): TokenStorageService {
    if (!TokenStorageService.instance) {
      TokenStorageService.instance = new TokenStorageService();
    }
    return TokenStorageService.instance;
  }

  /**
   * Store authentication token
   * Primary: Server sets httpOnly cookie
   * Fallback: Secure localStorage for development/testing
   */
  public storeToken(token: string, expiryDate: Date): void {
    // In production, tokens should be stored in httpOnly cookies by the server
    // This method handles the fallback case for development or when httpOnly isn't available
    
    if (this.isHttpOnlySupported()) {
      // Tokens are stored in httpOnly cookies by server - no client-side storage needed
      return;
    }
    
    // Fallback to secure localStorage for development
    this.storeInSecureLocalStorage(token, expiryDate);
  }

  /**
   * Retrieve authentication token
   * Primary: From server session validation
   * Fallback: From secure localStorage
   */
  public getToken(): string | null {
    if (this.isHttpOnlySupported()) {
      // With httpOnly cookies, we validate token existence via server session check
      // The actual token value is not accessible to JavaScript (by design)
      return null; // Return null - token access happens server-side
    }
    
    // Fallback: retrieve from localStorage for development
    return this.getFromSecureLocalStorage();
  }

  /**
   * Clear stored token
   */
  public clearToken(): void {
    if (this.isHttpOnlySupported()) {
      // httpOnly cookies are cleared by server on logout
      return;
    }
    
    // Fallback: clear localStorage
    this.clearSecureLocalStorage();
  }

  /**
   * Check if httpOnly cookie support is available
   * In production with proper backend, this should return true
   */
  private isHttpOnlySupported(): boolean {
    // Check if we're in production environment with httpOnly cookie support
    // For development, we fallback to localStorage
    return process.env.NODE_ENV === 'production' && 
           typeof document !== 'undefined' &&
           document.cookie.includes('kubechat_session=');
  }

  /**
   * Store token in secure localStorage (development fallback)
   */
  private storeInSecureLocalStorage(token: string, expiryDate: Date): void {
    if (typeof window === 'undefined') return;
    
    try {
      const tokenData = {
        token,
        expiry: expiryDate.toISOString(),
        stored: new Date().toISOString(),
      };
      
      // In a production app, you might want to encrypt this data
      localStorage.setItem('kubechat_auth_token', JSON.stringify(tokenData));
      
      // Note: For production, use httpOnly cookies instead of localStorage
    } catch {
      // Storage error - tokens will not persist across sessions
    }
  }

  /**
   * Retrieve token from secure localStorage (development fallback)
   */
  private getFromSecureLocalStorage(): string | null {
    if (typeof window === 'undefined') return null;
    
    try {
      const stored = localStorage.getItem('kubechat_auth_token');
      if (!stored) return null;
      
      const tokenData = JSON.parse(stored) as StoredTokenData;
      const expiry = new Date(tokenData.expiry);
      
      // Check if token is expired
      if (new Date() > expiry) {
        this.clearSecureLocalStorage();
        return null;
      }
      
      return tokenData.token;
    } catch {
      // Token retrieval error - treat as no token available
      this.clearSecureLocalStorage();
      return null;
    }
  }

  /**
   * Clear token from secure localStorage
   */
  private clearSecureLocalStorage(): void {
    if (typeof window === 'undefined') return;
    
    try {
      localStorage.removeItem('kubechat_auth_token');
    } catch {
      // Clear operation failed - token may persist
    }
  }

  /**
   * Get token storage strategy information for debugging
   */
  public getStorageStrategy(): { 
    strategy: 'httpOnly' | 'localStorage'; 
    secure: boolean; 
    recommendation: string 
  } {
    if (this.isHttpOnlySupported()) {
      return {
        strategy: 'httpOnly',
        secure: true,
        recommendation: 'Production-ready: Tokens stored in httpOnly cookies'
      };
    }
    
    return {
      strategy: 'localStorage',
      secure: false,
      recommendation: 'Development only: Use httpOnly cookies in production'
    };
  }
}

export default TokenStorageService;