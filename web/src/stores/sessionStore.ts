import { create } from 'zustand';
import { subscribeWithSelector } from 'zustand/middleware';
import type { SessionInfo, SessionStoreState } from '../types/auth';
import SessionService from '../services/sessionService';

interface SessionStoreActions {
  // Session management actions
  startMonitoring: () => void;
  stopMonitoring: () => void;
  extendSession: () => Promise<void>;
  
  // State management actions
  setCurrentSession: (session: SessionInfo | null) => void;
  setTimeRemaining: (time: number | null) => void;
  setWarningShown: (shown: boolean) => void;
  setError: (error: string | null) => void;
  clearError: () => void;
  
  // Session event handlers
  handleSessionWarning: (timeRemaining: number) => void;
  handleSessionExpired: () => void;
}

type SessionStore = SessionStoreState & SessionStoreActions;

export const useSessionStore = create<SessionStore>()(
  subscribeWithSelector((set, get) => ({
    // Initial state
    currentSession: null,
    isMonitoring: false,
    warningShown: false,
    timeRemaining: null,
    error: null,

    // Session management actions
    startMonitoring: () => {
      const { handleSessionWarning, handleSessionExpired, isMonitoring } = get();
      
      if (isMonitoring) return; // Already monitoring
      
      const sessionService = SessionService.getInstance();
      
      sessionService.startSessionMonitoring(
        handleSessionWarning,
        handleSessionExpired,
        30000 // Check every 30 seconds
      );
      
      set({ isMonitoring: true });
    },

    stopMonitoring: () => {
      const sessionService = SessionService.getInstance();
      sessionService.stopSessionMonitoring();
      
      set({ 
        isMonitoring: false,
        warningShown: false,
        timeRemaining: null,
      });
    },

    extendSession: async () => {
      const { setError, setCurrentSession } = get();
      
      try {
        setError(null);
        
        const sessionService = SessionService.getInstance();
        const updatedSession = await sessionService.extendSession();
        
        setCurrentSession(updatedSession);
        set({ warningShown: false }); // Reset warning state
        
      } catch (error) {
        setError(error instanceof Error ? error.message : 'Failed to extend session');
      }
    },

    // State management actions
    setCurrentSession: (session) => {
      set({ currentSession: session });
    },

    setTimeRemaining: (time) => {
      set({ timeRemaining: time });
    },

    setWarningShown: (shown) => {
      set({ warningShown: shown });
    },

    setError: (error) => {
      set({ error });
    },

    clearError: () => {
      set({ error: null });
    },

    // Session event handlers
    handleSessionWarning: (timeRemaining) => {
      const { warningShown, setTimeRemaining, setWarningShown } = get();
      
      setTimeRemaining(timeRemaining);
      
      if (!warningShown) {
        setWarningShown(true);
        
        // Show browser notification if supported and permitted
        if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
          const minutes = Math.floor(timeRemaining / (1000 * 60));
          new Notification('Session Expiring Soon', {
            body: `Your session will expire in ${minutes} minutes. Click to extend.`,
            icon: '/kubechat-icon.png',
            requireInteraction: true,
          });
        }
        
        // Dispatch custom event for UI components to handle
        if (typeof window !== 'undefined') {
          window.dispatchEvent(new CustomEvent('session-warning', {
            detail: { timeRemaining }
          }));
        }
      }
    },

    handleSessionExpired: () => {
      const { stopMonitoring } = get();
      
      stopMonitoring();
      
      set({
        currentSession: null,
        timeRemaining: null,
        warningShown: false,
        error: 'Session expired',
      });
      
      // Show browser notification
      if (typeof window !== 'undefined' && 'Notification' in window && Notification.permission === 'granted') {
        new Notification('Session Expired', {
          body: 'Your session has expired. Please sign in again.',
          icon: '/kubechat-icon.png',
          requireInteraction: true,
        });
      }
      
      // Dispatch custom event for UI components to handle
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('session-expired'));
      }
      
      // Auto-redirect to login page after a short delay
      setTimeout(() => {
        if (typeof window !== 'undefined') {
          window.location.href = '/login';
        }
      }, 2000);
    },
  }))
);

// Session monitoring integration with auth store
if (typeof window !== 'undefined') {
  // Subscribe to auth state changes to start/stop session monitoring
  const { useAuthStore } = await import('./authStore');
  
  useAuthStore.subscribe(
    (state) => state.isAuthenticated,
    (isAuthenticated) => {
      const sessionStore = useSessionStore.getState();
      
      if (isAuthenticated) {
        sessionStore.startMonitoring();
      } else {
        sessionStore.stopMonitoring();
      }
    }
  );
  
  // Load initial session if authenticated
  useAuthStore.subscribe(
    (state) => ({ isAuthenticated: state.isAuthenticated, sessionId: state.sessionId }),
    ({ isAuthenticated, sessionId }) => {
      if (isAuthenticated && sessionId) {
        const loadSessionInfo = async () => {
          try {
            const sessionService = SessionService.getInstance();
            const session = await sessionService.getCurrentSession();
            
            if (session) {
              useSessionStore.getState().setCurrentSession(session);
            }
          } catch (sessionError) {
            // eslint-disable-next-line no-console
            console.error('Failed to load session info:', sessionError);
          }
        };
        
        void loadSessionInfo();
      }
    }
  );
  
  // Handle browser visibility changes to extend session when user returns
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) {
      const authState = useAuthStore.getState();
      const sessionState = useSessionStore.getState();
      
      if (authState.isAuthenticated && sessionState.currentSession) {
        // Update last activity when user returns to tab
        authState.updateLastActivity();
        
        // Check if session needs extending
        const sessionService = SessionService.getInstance();
        if (sessionService.isSessionNearExpiry(sessionState.currentSession)) {
          void sessionState.extendSession();
        }
      }
    }
  });
  
  // Request notification permission on first load
  if ('Notification' in window && Notification.permission === 'default') {
    void Notification.requestPermission().then(permission => {
      // eslint-disable-next-line no-console
      console.log('Notification permission:', permission);
    });
  }
}

export default useSessionStore;