import { useCallback, useState } from 'react';
import { useSession } from '../../hooks/useSession';
import { useAuthentication } from '../../hooks/useAuthentication';

interface SessionStatusProps {
  className?: string;
  showDetails?: boolean;
}

export function SessionStatus({ className = '', showDetails = false }: SessionStatusProps) {
  const [showDropdown, setShowDropdown] = useState(false);
  
  const {
    currentSession,
    isSessionNearExpiry,
    isSessionExpired,
    getSessionDuration,
    getLastActivityDisplay,
    getTimeUntilExpiry,
    extendSession,
    error: sessionError,
  } = useSession();

  const {
    user,
    logout,
  } = useAuthentication();

  const handleExtendSession = useCallback(async () => {
    try {
      await extendSession();
    } catch (error) {
      console.error('Failed to extend session:', error);
    }
  }, [extendSession]);

  const handleLogout = useCallback(async () => {
    try {
      await logout();
    } catch (error) {
      console.error('Logout failed:', error);
    }
  }, [logout]);

  // Local function to format time remaining
  const formatTimeRemaining = useCallback((timeRemaining: number): string => {
    if (!timeRemaining) return '0:00';
    
    const totalSeconds = Math.floor(timeRemaining / 1000);
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = totalSeconds % 60;
    
    return `${minutes}:${seconds.toString().padStart(2, '0')}`;
  }, []);

  const toggleDropdown = useCallback(() => {
    setShowDropdown(prev => !prev);
  }, []);

  if (!currentSession || !user) {
    return null;
  }

  const isExpired = isSessionExpired();
  const isNearExpiry = isSessionNearExpiry();
  
  let statusColor = 'green';
  let statusText = 'Active';
  
  if (isExpired) {
    statusColor = 'red';
    statusText = 'Expired';
  } else if (isNearExpiry) {
    statusColor = 'yellow';
    statusText = 'Expiring Soon';
  }

  return (
    <div className={`relative ${className}`}>
      <button
        onClick={toggleDropdown}
        className="flex items-center space-x-2 text-sm text-gray-700 hover:text-gray-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 rounded-md p-2"
        aria-label="Session status"
      >
        {/* Status indicator */}
        <div className={`w-2 h-2 rounded-full ${
          statusColor === 'green' ? 'bg-green-500' :
          statusColor === 'yellow' ? 'bg-yellow-500' :
          'bg-red-500'
        }`} />
        
        <span className="hidden sm:inline">{user.name || user.email}</span>
        
        {isNearExpiry && !isExpired && (
          <span className="text-xs text-yellow-600">
            ({formatTimeRemaining(getTimeUntilExpiry())})
          </span>
        )}
        
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Dropdown menu */}
      {showDropdown && (
        <div className="absolute right-0 mt-2 w-80 bg-white rounded-md shadow-lg ring-1 ring-black ring-opacity-5 z-50">
          <div className="p-4">
            {/* User info */}
            <div className="flex items-center space-x-3 mb-4">
              <div className="flex-shrink-0">
                <div className="w-10 h-10 bg-blue-500 rounded-full flex items-center justify-center text-white font-medium">
                  {(user.name || user.email).charAt(0).toUpperCase()}
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 truncate">
                  {user.name || user.email}
                </p>
                <p className="text-xs text-gray-500 truncate">
                  {user.email}
                </p>
              </div>
            </div>

            {/* Session status */}
            <div className="border-t border-gray-200 pt-3 mb-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-900">Session Status</span>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                  statusColor === 'green' ? 'bg-green-100 text-green-800' :
                  statusColor === 'yellow' ? 'bg-yellow-100 text-yellow-800' :
                  'bg-red-100 text-red-800'
                }`}>
                  {statusText}
                </span>
              </div>
              
              <div className="text-xs text-gray-600 space-y-1">
                <div>Duration: {getSessionDuration()}</div>
                <div>Last activity: {getLastActivityDisplay()}</div>
                {currentSession.expiresAt && (
                  <div>
                    Expires: {new Date(currentSession.expiresAt).toLocaleString()}
                  </div>
                )}
              </div>
            </div>

            {/* Session error */}
            {sessionError && (
              <div className="mb-3 p-2 bg-red-50 border border-red-200 rounded text-xs text-red-700">
                {sessionError}
              </div>
            )}

            {/* Session actions */}
            <div className="border-t border-gray-200 pt-3 space-y-2">
              {isNearExpiry && !isExpired && (
                <button
                  onClick={() => void handleExtendSession()}
                  className="w-full text-left px-3 py-2 text-sm text-blue-600 hover:bg-blue-50 rounded-md flex items-center space-x-2"
                >
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  <span>Extend Session</span>
                </button>
              )}
              
              <button
                onClick={() => void handleLogout()}
                className="w-full text-left px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-md flex items-center space-x-2"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                <span>Sign Out</span>
              </button>
            </div>

            {showDetails && (
              <div className="border-t border-gray-200 pt-3 mt-3">
                <h4 className="text-sm font-medium text-gray-900 mb-2">Session Details</h4>
                <div className="text-xs text-gray-600 space-y-1">
                  <div>Session ID: {currentSession.id.substring(0, 8)}...</div>
                  <div>IP Address: {currentSession.ipAddress}</div>
                  <div>User Agent: {currentSession.userAgent.substring(0, 40)}...</div>
                  {user.roles.length > 0 && (
                    <div>Roles: {user.roles.join(', ')}</div>
                  )}
                  {user.groups.length > 0 && (
                    <div>Groups: {user.groups.join(', ')}</div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Click outside handler */}
      {showDropdown && (
        <div
          className="fixed inset-0 z-40"
          onClick={() => setShowDropdown(false)}
        />
      )}
    </div>
  );
}

export default SessionStatus;