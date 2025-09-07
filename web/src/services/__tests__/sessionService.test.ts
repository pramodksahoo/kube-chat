import { SessionService } from '../sessionService';
import type { SessionInfo } from '../../types/auth';

// Mock fetch globally
global.fetch = jest.fn();

describe('SessionService', () => {
  let service: SessionService;
  
  beforeEach(() => {
    service = SessionService.getInstance();
    jest.clearAllMocks();
    jest.useFakeTimers();
    
    // Mock localStorage
    Object.defineProperty(window, 'localStorage', {
      value: {
        getItem: jest.fn(),
        setItem: jest.fn(),
        removeItem: jest.fn(),
        clear: jest.fn(),
      },
      writable: true,
    });
  });

  afterEach(() => {
    service.stopSessionMonitoring();
    jest.useRealTimers();
    jest.restoreAllMocks();
  });

  describe('getInstance', () => {
    it('should return singleton instance', () => {
      const instance1 = SessionService.getInstance();
      const instance2 = SessionService.getInstance();
      expect(instance1).toBe(instance2);
    });
  });

  describe('getCurrentSession', () => {
    it('should return current session info', async () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date('2024-01-01T10:00:00Z'),
        expiresAt: new Date('2024-01-01T12:00:00Z'),
        lastActivity: new Date('2024-01-01T11:30:00Z'),
        ipAddress: '192.168.1.1',
        userAgent: 'Mozilla/5.0 Test Browser'
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          sessionId: mockSession.id,
          userId: mockSession.userId,
          createdAt: mockSession.createdAt.toISOString(),
          expiresAt: mockSession.expiresAt.toISOString(),
          lastActivity: mockSession.lastActivity.toISOString(),
          ipAddress: mockSession.ipAddress,
          userAgent: mockSession.userAgent,
        }),
      });

      const result = await service.getCurrentSession();

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/session', {
        method: 'GET',
        credentials: 'include',
      });
      expect(result).toEqual(mockSession);
    });

    it('should return null for unauthorized request', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      const result = await service.getCurrentSession();
      expect(result).toBeNull();
    });

    it('should handle session fetch errors', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        statusText: 'Internal Server Error',
      });

      await expect(service.getCurrentSession()).rejects.toThrow('Failed to get current session: Internal Server Error');
    });
  });

  describe('getSessionTimeRemaining', () => {
    it('should calculate time remaining until expiry', () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes from now
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      const timeRemaining = service.getSessionTimeRemaining(mockSession);
      expect(timeRemaining).toBeGreaterThan(29 * 60 * 1000); // Should be close to 30 minutes
      expect(timeRemaining).toBeLessThanOrEqual(30 * 60 * 1000);
    });

    it('should return 0 for expired session', () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
        expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
        lastActivity: new Date(Date.now() - 90 * 60 * 1000), // 1.5 hours ago
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      const timeRemaining = service.getSessionTimeRemaining(mockSession);
      expect(timeRemaining).toBe(0);
    });
  });

  describe('isSessionNearExpiry', () => {
    it('should detect session near expiry', () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3 * 60 * 1000), // 3 minutes from now
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      expect(service.isSessionNearExpiry(mockSession)).toBe(true);
    });

    it('should not flag session with plenty of time remaining', () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000), // 30 minutes from now
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      expect(service.isSessionNearExpiry(mockSession)).toBe(false);
    });
  });

  describe('isSessionExpired', () => {
    it('should detect expired session', () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
        expiresAt: new Date(Date.now() - 60 * 60 * 1000), // 1 hour ago
        lastActivity: new Date(Date.now() - 90 * 60 * 1000),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      expect(service.isSessionExpired(mockSession)).toBe(true);
    });

    it('should not flag valid session as expired', () => {
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      expect(service.isSessionExpired(mockSession)).toBe(false);
    });
  });

  describe('startSessionMonitoring', () => {
    it('should start monitoring and call warning callback', async () => {
      const onWarning = jest.fn();
      const onExpired = jest.fn();
      
      const mockSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3 * 60 * 1000), // 3 minutes from now
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      (fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: async () => ({
          sessionId: mockSession.id,
          userId: mockSession.userId,
          createdAt: mockSession.createdAt.toISOString(),
          expiresAt: mockSession.expiresAt.toISOString(),
          lastActivity: mockSession.lastActivity.toISOString(),
          ipAddress: mockSession.ipAddress,
          userAgent: mockSession.userAgent,
        }),
      });

      service.startSessionMonitoring(onWarning, onExpired, 1000); // Check every second

      // Fast forward time to trigger the check
      jest.advanceTimersByTime(1000);

      // Wait for async operations
      await Promise.resolve();

      expect(onWarning).toHaveBeenCalledWith(expect.any(Number));
      expect(onExpired).not.toHaveBeenCalled();
    });

    it('should call expired callback for expired session', async () => {
      const onWarning = jest.fn();
      const onExpired = jest.fn();

      (fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 401,
      });

      service.startSessionMonitoring(onWarning, onExpired, 1000);

      jest.advanceTimersByTime(1000);
      await Promise.resolve();

      expect(onExpired).toHaveBeenCalled();
      expect(onWarning).not.toHaveBeenCalled();
    });
  });

  describe('stopSessionMonitoring', () => {
    it('should stop session monitoring', () => {
      const onWarning = jest.fn();
      const onExpired = jest.fn();

      service.startSessionMonitoring(onWarning, onExpired, 1000);
      service.stopSessionMonitoring();

      jest.advanceTimersByTime(2000);
      
      expect(onWarning).not.toHaveBeenCalled();
      expect(onExpired).not.toHaveBeenCalled();
    });
  });

  describe('extendSession', () => {
    it('should extend session successfully', async () => {
      const mockExtendedSession: SessionInfo = {
        id: 'session-123',
        userId: 'user-456',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 2 * 60 * 60 * 1000), // 2 hours from now
        lastActivity: new Date(),
        ipAddress: '192.168.1.1',
        userAgent: 'Test Browser'
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          sessionId: mockExtendedSession.id,
          userId: mockExtendedSession.userId,
          createdAt: mockExtendedSession.createdAt.toISOString(),
          expiresAt: mockExtendedSession.expiresAt.toISOString(),
          lastActivity: mockExtendedSession.lastActivity.toISOString(),
          ipAddress: mockExtendedSession.ipAddress,
          userAgent: mockExtendedSession.userAgent,
        }),
      });

      const result = await service.extendSession();

      expect(fetch).toHaveBeenCalledWith('/api/v1/auth/session/extend', {
        method: 'POST',
        credentials: 'include',
      });
      expect(result).toEqual(mockExtendedSession);
    });

    it('should handle session extension errors', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        statusText: 'Forbidden',
      });

      await expect(service.extendSession()).rejects.toThrow('Failed to extend session: Forbidden');
    });
  });

  describe('formatTimeRemaining', () => {
    it('should format time remaining correctly', () => {
      expect(service.formatTimeRemaining(125000)).toBe('2m 5s'); // 2 minutes 5 seconds
      expect(service.formatTimeRemaining(45000)).toBe('45s'); // 45 seconds
      expect(service.formatTimeRemaining(0)).toBe('0s'); // No time remaining
    });
  });

  describe('storeSessionState', () => {
    it('should store session state in localStorage', () => {
      service.storeSessionState('session-123', true);

      expect(localStorage.setItem).toHaveBeenCalledWith('kubechat_session_state', expect.any(String));
    });
  });

  describe('getStoredSessionState', () => {
    it('should retrieve stored session state', () => {
      const mockData = { sessionId: 'session-123', timestamp: '2024-01-01T10:00:00Z', encrypted: false };
      (localStorage.getItem as jest.Mock).mockReturnValue(JSON.stringify(mockData));

      const result = service.getStoredSessionState();
      expect(result).toEqual(mockData);
    });

    it('should return null for missing session state', () => {
      (localStorage.getItem as jest.Mock).mockReturnValue(null);

      const result = service.getStoredSessionState();
      expect(result).toBeNull();
    });
  });
});