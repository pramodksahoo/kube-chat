import { useCallback, useEffect, useState } from 'react';
import { useSessionStore } from '../stores/sessionStore';

/**
 * Custom hook for session management and monitoring
 */
export function useSession() {
  const {
    // State
    currentSession,
    isMonitoring,
    warningShown,
    timeRemaining,
    error,
    
    // Actions
    startMonitoring,
    stopMonitoring,
    extendSession,
    setWarningShown,
    clearError,
  } = useSessionStore();

  const [showExpiryModal, setShowExpiryModal] = useState(false);

  // Handle session warning events
  useEffect(() => {
    const handleSessionWarning = (_event: CustomEvent) => {
      setShowExpiryModal(true);
    };

    const handleSessionExpired = () => {
      setShowExpiryModal(false);
    };

    if (typeof window !== 'undefined') {
      window.addEventListener('session-warning', handleSessionWarning as EventListener);
      window.addEventListener('session-expired', handleSessionExpired);

      return () => {
        window.removeEventListener('session-warning', handleSessionWarning as EventListener);
        window.removeEventListener('session-expired', handleSessionExpired);
      };
    }
  }, []);

  // Auto-dismiss warning after session extension
  useEffect(() => {
    if (!warningShown && showExpiryModal) {
      setShowExpiryModal(false);
    }
  }, [warningShown, showExpiryModal]);

  // Start monitoring when component mounts
  useEffect(() => {
    if (!isMonitoring) {
      startMonitoring();
    }

    return () => {
      // Don't stop monitoring on unmount - let other components use it
    };
  }, [isMonitoring, startMonitoring]);

  // Handle session extension
  const handleExtendSession = useCallback(async () => {
    try {
      clearError();
      await extendSession();
      setShowExpiryModal(false);
      setWarningShown(false);
    } catch (error) {
      console.error('Failed to extend session:', error);
    }
  }, [extendSession, clearError, setWarningShown]);

  // Handle session dismissal (accept expiry)
  const handleDismissWarning = useCallback(() => {
    setShowExpiryModal(false);
    setWarningShown(false);
  }, [setWarningShown]);


  // Check if session is near expiry (within 5 minutes)
  const isSessionNearExpiry = useCallback((): boolean => {
    if (!currentSession) return false;
    
    const now = new Date().getTime();
    const expiry = new Date(currentSession.expiresAt).getTime();
    const fiveMinutesInMs = 5 * 60 * 1000;
    
    return (expiry - now) <= fiveMinutesInMs && (expiry - now) > 0;
  }, [currentSession]);

  // Check if session has expired
  const isSessionExpired = useCallback((): boolean => {
    if (!currentSession) return false;
    
    const now = new Date().getTime();
    const expiry = new Date(currentSession.expiresAt).getTime();
    
    return now >= expiry;
  }, [currentSession]);

  // Get session duration
  const getSessionDuration = useCallback((): string => {
    if (!currentSession) return 'Unknown';
    
    const startTime = new Date(currentSession.createdAt).getTime();
    const currentTime = new Date().getTime();
    const durationMs = currentTime - startTime;
    
    const hours = Math.floor(durationMs / (1000 * 60 * 60));
    const minutes = Math.floor((durationMs % (1000 * 60 * 60)) / (1000 * 60));
    
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    } else {
      return `${minutes}m`;
    }
  }, [currentSession]);

  // Get time until expiry
  const getTimeUntilExpiry = useCallback((): number => {
    if (!currentSession) return 0;
    
    const now = new Date().getTime();
    const expiry = new Date(currentSession.expiresAt).getTime();
    
    return Math.max(0, expiry - now);
  }, [currentSession]);

  // Format last activity time
  const getLastActivityDisplay = useCallback((): string => {
    if (!currentSession) return 'Unknown';
    
    const lastActivity = new Date(currentSession.lastActivity);
    const now = new Date();
    const diffInMs = now.getTime() - lastActivity.getTime();
    const diffInMinutes = Math.floor(diffInMs / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes} minute${diffInMinutes > 1 ? 's' : ''} ago`;
    
    const diffInHours = Math.floor(diffInMinutes / 60);
    if (diffInHours < 24) return `${diffInHours} hour${diffInHours > 1 ? 's' : ''} ago`;
    
    const diffInDays = Math.floor(diffInHours / 24);
    return `${diffInDays} day${diffInDays > 1 ? 's' : ''} ago`;
  }, [currentSession]);

  // Session state object
  const sessionState = {
    currentSession,
    isMonitoring,
    warningShown,
    timeRemaining,
    error,
    showExpiryModal,
  };

  // Session actions object
  const sessionActions = {
    startMonitoring,
    stopMonitoring,
    extendSession: handleExtendSession,
    dismissWarning: handleDismissWarning,
    clearError,
  };

  // Session utility functions
  const sessionUtils = {
    isSessionNearExpiry,
    isSessionExpired,
    // getFormattedTimeRemaining,
    getSessionDuration,
    getTimeUntilExpiry,
    getLastActivityDisplay,
  };

  return {
    ...sessionState,
    ...sessionActions,
    ...sessionUtils,
  };
}

export default useSession;