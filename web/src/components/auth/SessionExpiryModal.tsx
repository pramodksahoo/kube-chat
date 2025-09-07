import { useCallback, useEffect, useState } from 'react';
import { useSession } from '../../hooks/useSession';
import { useAuthentication } from '../../hooks/useAuthentication';

interface SessionExpiryModalProps {
  isOpen?: boolean;
  onClose?: () => void;
  autoShow?: boolean;
}

export function SessionExpiryModal({ 
  isOpen: controlledIsOpen, 
  onClose,
  autoShow = true 
}: SessionExpiryModalProps) {
  const [internalIsOpen, setInternalIsOpen] = useState(false);
  const [countdown, setCountdown] = useState<number>(0);
  
  const {
    showExpiryModal,
    timeRemaining,
    // getFormattedTimeRemaining, // Available for future use
    extendSession,
    dismissWarning,
  } = useSession();

  const {
    logout,
  } = useAuthentication();

  // Use controlled or internal state for modal visibility
  const isOpen = controlledIsOpen !== undefined ? controlledIsOpen : (autoShow ? showExpiryModal : internalIsOpen);

  // Update countdown based on time remaining
  useEffect(() => {
    if (timeRemaining && isOpen) {
      const seconds = Math.floor(timeRemaining / 1000);
      setCountdown(seconds);
      
      const interval = setInterval(() => {
        setCountdown(prev => {
          const newCount = prev - 1;
          if (newCount <= 0) {
            clearInterval(interval);
            void handleSessionExpired();
            return 0;
          }
          return newCount;
        });
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [timeRemaining, isOpen]);

  const handleExtendSession = useCallback(async () => {
    try {
      await extendSession();
      setInternalIsOpen(false);
      onClose?.();
    } catch (error) {
      console.error('Failed to extend session:', error);
    }
  }, [extendSession, onClose]);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
      setInternalIsOpen(false);
      onClose?.();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, [logout, onClose]);

  const handleSessionExpired = useCallback(async () => {
    // Session has expired, force logout
    await handleLogout();
  }, [handleLogout]);

  const handleDismiss = useCallback(() => {
    dismissWarning();
    setInternalIsOpen(false);
    onClose?.();
  }, [dismissWarning, onClose]);

  const formatCountdown = useCallback((seconds: number): string => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  }, []);

  if (!isOpen) {
    return null;
  }

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity z-50" />
      
      {/* Modal */}
      <div className="fixed inset-0 z-50 overflow-y-auto">
        <div className="flex min-h-full items-end justify-center p-4 text-center sm:items-center sm:p-0">
          <div className="relative transform overflow-hidden rounded-lg bg-white text-left shadow-xl transition-all sm:my-8 sm:w-full sm:max-w-lg">
            <div className="bg-white px-4 pb-4 pt-5 sm:p-6 sm:pb-4">
              <div className="sm:flex sm:items-start">
                <div className="mx-auto flex h-12 w-12 flex-shrink-0 items-center justify-center rounded-full bg-yellow-100 sm:mx-0 sm:h-10 sm:w-10">
                  <svg className="h-6 w-6 text-yellow-600" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
                  </svg>
                </div>
                <div className="mt-3 text-center sm:ml-4 sm:mt-0 sm:text-left">
                  <h3 className="text-base font-semibold leading-6 text-gray-900">
                    Session Expiring Soon
                  </h3>
                  <div className="mt-2">
                    <p className="text-sm text-gray-500">
                      Your session will expire in{' '}
                      <span className="font-mono font-semibold text-red-600">
                        {formatCountdown(countdown)}
                      </span>
                      . Would you like to extend your session or sign out?
                    </p>
                    
                    {countdown <= 60 && (
                      <div className="mt-3 p-3 bg-red-50 rounded-md">
                        <div className="flex">
                          <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor">
                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5v3a.75.75 0 001.5 0v-3A.75.75 0 009 9z" clipRule="evenodd" />
                          </svg>
                          <div className="ml-3">
                            <p className="text-sm text-red-700">
                              <strong>Warning:</strong> Your session will expire automatically in less than 1 minute.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
            
            {/* Progress bar */}
            <div className="px-4 sm:px-6">
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className={`h-2 rounded-full transition-all duration-1000 ${
                    countdown > 120 ? 'bg-green-500' :
                    countdown > 60 ? 'bg-yellow-500' :
                    'bg-red-500'
                  }`}
                  style={{
                    width: `${Math.max(0, Math.min(100, (countdown / 300) * 100))}%`
                  }}
                />
              </div>
            </div>
            
            <div className="bg-gray-50 px-4 py-3 sm:flex sm:flex-row-reverse sm:px-6">
              <button
                type="button"
                onClick={() => void handleExtendSession()}
                disabled={countdown <= 0}
                className="inline-flex w-full justify-center rounded-md bg-blue-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed sm:ml-3 sm:w-auto"
              >
                Extend Session
              </button>
              <button
                type="button"
                onClick={() => void handleLogout()}
                className="mt-3 inline-flex w-full justify-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 sm:mt-0 sm:w-auto"
              >
                Sign Out
              </button>
              {countdown > 60 && (
                <button
                  type="button"
                  onClick={handleDismiss}
                  className="mt-3 inline-flex w-full justify-center rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 hover:bg-gray-50 sm:mt-0 sm:w-auto sm:mr-3"
                >
                  Dismiss
                </button>
              )}
            </div>

            {/* Additional info */}
            <div className="bg-blue-50 px-4 py-3 sm:px-6">
              <div className="text-xs text-blue-700">
                <p><strong>Security Notice:</strong> For your security, sessions automatically expire after a period of inactivity.</p>
                <p className="mt-1">Extending your session will keep you signed in for another session period.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

export default SessionExpiryModal;