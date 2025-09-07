import type { SessionInfo } from '../types/auth';

export class SessionService {
  private static instance: SessionService;
  private sessionCheckInterval: NodeJS.Timeout | null = null;
  
  private constructor() {}
  
  public static getInstance(): SessionService {
    if (!SessionService.instance) {
      SessionService.instance = new SessionService();
    }
    return SessionService.instance;
  }

  /**
   * Get current session information
   */
  public async getCurrentSession(): Promise<SessionInfo | null> {
    try {
      const response = await fetch('/api/v1/auth/session', {
        method: 'GET',
        credentials: 'include',
      });

      if (response.status === 401) {
        return null; // No active session
      }

      if (!response.ok) {
        throw new Error(`Failed to get session info: ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        id: data.sessionId,
        userId: data.userId,
        createdAt: new Date(data.createdAt),
        expiresAt: new Date(data.expiresAt),
        lastActivity: new Date(data.lastActivity),
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      };
    } catch (error) {
      throw new Error(`Failed to get current session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Calculate time remaining until session expires
   */
  public getSessionTimeRemaining(session: SessionInfo): number {
    const now = new Date().getTime();
    const expiry = session.expiresAt.getTime();
    return Math.max(0, expiry - now);
  }

  /**
   * Check if session is about to expire (within 5 minutes)
   */
  public isSessionNearExpiry(session: SessionInfo): boolean {
    const timeRemaining = this.getSessionTimeRemaining(session);
    const fiveMinutesInMs = 5 * 60 * 1000;
    return timeRemaining <= fiveMinutesInMs && timeRemaining > 0;
  }

  /**
   * Check if session has expired
   */
  public isSessionExpired(session: SessionInfo): boolean {
    return this.getSessionTimeRemaining(session) === 0;
  }

  /**
   * Start periodic session monitoring
   */
  public startSessionMonitoring(
    onSessionWarning: (timeRemaining: number) => void,
    onSessionExpired: () => void,
    checkIntervalMs: number = 60000 // Check every minute
  ): void {
    this.stopSessionMonitoring(); // Clear any existing interval
    
    this.sessionCheckInterval = setInterval(() => {
      void (async () => {
        try {
          const session = await this.getCurrentSession();
          
          if (!session) {
            onSessionExpired();
            return;
          }

          if (this.isSessionExpired(session)) {
            onSessionExpired();
          } else if (this.isSessionNearExpiry(session)) {
            const timeRemaining = this.getSessionTimeRemaining(session);
            onSessionWarning(timeRemaining);
          }
        } catch (error) {
          console.error('Session monitoring error:', error);
        }
      })();
    }, checkIntervalMs);
  }

  /**
   * Stop session monitoring
   */
  public stopSessionMonitoring(): void {
    if (this.sessionCheckInterval) {
      clearInterval(this.sessionCheckInterval);
      this.sessionCheckInterval = null;
    }
  }

  /**
   * Extend session activity
   */
  public async extendSession(): Promise<SessionInfo> {
    try {
      const response = await fetch('/api/v1/auth/session/extend', {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error(`Failed to extend session: ${response.statusText}`);
      }

      const data = await response.json();
      
      return {
        id: data.sessionId,
        userId: data.userId,
        createdAt: new Date(data.createdAt),
        expiresAt: new Date(data.expiresAt),
        lastActivity: new Date(data.lastActivity),
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      };
    } catch (error) {
      throw new Error(`Failed to extend session: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  }

  /**
   * Cleanup session-related data on logout
   */
  public cleanup(): void {
    this.stopSessionMonitoring();
    
    // Clear any session-related localStorage/sessionStorage
    if (typeof window !== 'undefined') {
      // Clear any authentication-related storage
      Object.keys(localStorage).forEach(key => {
        if (key.startsWith('kubechat_auth_') || key.startsWith('kubechat_session_')) {
          localStorage.removeItem(key);
        }
      });
      
      Object.keys(sessionStorage).forEach(key => {
        if (key.startsWith('kubechat_auth_') || key.startsWith('kubechat_session_')) {
          sessionStorage.removeItem(key);
        }
      });
    }
  }

  /**
   * Format time remaining for display
   */
  public formatTimeRemaining(milliseconds: number): string {
    const totalSeconds = Math.floor(milliseconds / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    
    if (minutes > 0) {
      return `${minutes}m ${seconds}s`;
    } else {
      return `${seconds}s`;
    }
  }

  /**
   * Store session state securely in localStorage
   */
  public storeSessionState(sessionId: string, encrypted: boolean = false): void {
    if (typeof window === 'undefined') return;
    
    try {
      const sessionData = {
        sessionId,
        timestamp: new Date().toISOString(),
        encrypted,
      };
      
      localStorage.setItem('kubechat_session_state', JSON.stringify(sessionData));
    } catch (error) {
      console.error('Failed to store session state:', error);
    }
  }

  /**
   * Retrieve stored session state
   */
  public getStoredSessionState(): { sessionId: string; timestamp: string; encrypted: boolean } | null {
    if (typeof window === 'undefined') return null;
    
    try {
      const stored = localStorage.getItem('kubechat_session_state');
      if (!stored) return null;
      
      return JSON.parse(stored);
    } catch (error) {
      console.error('Failed to retrieve session state:', error);
      return null;
    }
  }
}

export default SessionService;