import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { act, renderHook, waitFor } from '@testing-library/react';
import { useExecutionStatus } from '../useExecutionStatus';
import type { ExecutionStatusUpdate } from '../useExecutionStatus';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock WebSocket
class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState: number = MockWebSocket.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(public url: string) {
    // Simulate async connection
    setTimeout(() => {
      this.readyState = MockWebSocket.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    }, 0);
  }

  send(data: string) {
    // Mock implementation
  }

  close(code?: number, reason?: string) {
    this.readyState = MockWebSocket.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code: code || 1000, reason }));
    }
  }

  // Helper method for tests to simulate receiving messages
  simulateMessage(data: any) {
    if (this.onmessage) {
      this.onmessage(new MessageEvent('message', { data: JSON.stringify(data) }));
    }
  }

  // Helper method for tests to simulate errors
  simulateError() {
    if (this.onerror) {
      this.onerror(new Event('error'));
    }
  }
}

// Store reference to mock instances for tests
let mockWsInstances: MockWebSocket[] = [];

const MockWebSocketConstructor = vi.fn().mockImplementation((url: string) => {
  const instance = new MockWebSocket(url);
  mockWsInstances.push(instance);
  return instance;
});

// Mock WebSocket globally
global.WebSocket = MockWebSocketConstructor as any;

describe('useExecutionStatus', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockWsInstances = [];
    mockFetch.mockClear();
    
    // Mock successful fetch by default
    mockFetch.mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ executionId: 'test-exec-123' }),
    });
  });

  afterEach(() => {
    // Clean up any active WebSocket instances
    mockWsInstances.forEach(ws => {
      if (ws.readyState === MockWebSocket.OPEN) {
        ws.close();
      }
    });
  });

  describe('Initial State', () => {
    it('returns correct initial values', () => {
      const { result } = renderHook(() => useExecutionStatus());

      expect(result.current.status).toBe('queued');
      expect(result.current.steps).toEqual([]);
      expect(result.current.isConnected).toBe(false);
      expect(result.current.isReconnecting).toBe(false);
      expect(result.current.error).toBe(null);
      expect(typeof result.current.startExecution).toBe('function');
      expect(typeof result.current.cancelExecution).toBe('function');
      expect(typeof result.current.retryConnection).toBe('function');
    });

    it('connects to WebSocket when executionId is provided', async () => {
      renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(mockWsInstances).toHaveLength(1);
        expect(mockWsInstances[0].url).toBe('ws://localhost:8080/ws/execution/test-123');
      });
    });
  });

  describe('Starting Execution', () => {
    it('starts execution and returns executionId', async () => {
      const { result } = renderHook(() => useExecutionStatus());

      let executionId: string;
      await act(async () => {
        executionId = await result.current.startExecution('kubectl get pods');
      });

      expect(mockFetch).toHaveBeenCalledWith('/api/execution/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'kubectl get pods' }),
      });

      expect(executionId!).toBe('test-exec-123');
      expect(result.current.error).toBe(null);
    });

    it('handles execution start errors', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      
      const { result } = renderHook(() => useExecutionStatus());

      await expect(
        act(async () => {
          await result.current.startExecution('kubectl get pods');
        })
      ).rejects.toThrow('Network error');

      expect(result.current.error).toBe('Failed to start execution: Network error');
    });

    it('handles HTTP errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 403,
        statusText: 'Forbidden',
      });
      
      const { result } = renderHook(() => useExecutionStatus());

      await expect(
        act(async () => {
          await result.current.startExecution('kubectl delete pods --all');
        })
      ).rejects.toThrow('HTTP 403: Forbidden');
    });
  });

  describe('WebSocket Connection', () => {
    it('establishes WebSocket connection on mount with executionId', async () => {
      const { result } = renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      expect(mockWsInstances).toHaveLength(1);
    });

    it('updates status when receiving messages', async () => {
      const { result } = renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      const statusUpdate: ExecutionStatusUpdate = {
        executionId: 'test-123',
        phase: 'executing',
        steps: [
          {
            id: 'validate',
            name: 'Validate Command',
            phase: 'validating',
            status: 'completed',
          },
        ],
        timestamp: '2024-01-01T10:00:00Z',
      };

      act(() => {
        mockWsInstances[0].simulateMessage(statusUpdate);
      });

      expect(result.current.status).toBe('executing');
      expect(result.current.steps).toHaveLength(1);
      expect(result.current.steps[0].name).toBe('Validate Command');
    });

    it('ignores messages for different execution IDs', async () => {
      const { result } = renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      const statusUpdate: ExecutionStatusUpdate = {
        executionId: 'different-exec-id',
        phase: 'executing',
        steps: [],
        timestamp: '2024-01-01T10:00:00Z',
      };

      act(() => {
        mockWsInstances[0].simulateMessage(statusUpdate);
      });

      expect(result.current.status).toBe('queued'); // Should remain unchanged
    });

    it('handles malformed messages gracefully', async () => {
      const { result } = renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      act(() => {
        if (mockWsInstances[0].onmessage) {
          mockWsInstances[0].onmessage(new MessageEvent('message', { data: 'invalid json' }));
        }
      });

      expect(result.current.error).toBe('Failed to parse status update');
    });
  });

  describe('Connection Management', () => {
    it('attempts to reconnect on connection loss', async () => {
      vi.useFakeTimers();
      
      const { result } = renderHook(() => useExecutionStatus({ 
        executionId: 'test-123',
        autoReconnect: true,
        retryDelay: 1000,
      }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      // Set status to executing to trigger reconnect behavior
      act(() => {
        const statusUpdate: ExecutionStatusUpdate = {
          executionId: 'test-123',
          phase: 'executing',
          steps: [],
          timestamp: '2024-01-01T10:00:00Z',
        };
        mockWsInstances[0].simulateMessage(statusUpdate);
      });

      // Simulate connection loss
      act(() => {
        mockWsInstances[0].close(1006, 'Connection lost'); // Abnormal closure
      });

      expect(result.current.isConnected).toBe(false);
      expect(result.current.isReconnecting).toBe(true);

      // Fast forward to trigger reconnection
      act(() => {
        vi.advanceTimersByTime(1000);
      });

      await waitFor(() => {
        expect(mockWsInstances).toHaveLength(2); // New connection should be created
      });

      vi.useRealTimers();
    });

    it('respects maxRetries limit', async () => {
      vi.useFakeTimers();
      
      const { result } = renderHook(() => useExecutionStatus({ 
        executionId: 'test-123',
        autoReconnect: true,
        maxRetries: 2,
        retryDelay: 1000,
      }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      // Set status to executing
      act(() => {
        const statusUpdate: ExecutionStatusUpdate = {
          executionId: 'test-123',
          phase: 'executing',
          steps: [],
          timestamp: '2024-01-01T10:00:00Z',
        };
        mockWsInstances[0].simulateMessage(statusUpdate);
      });

      // Simulate multiple connection failures
      for (let i = 0; i < 3; i++) {
        act(() => {
          mockWsInstances[mockWsInstances.length - 1].close(1006, 'Connection lost');
        });

        if (i < 2) {
          act(() => {
            vi.advanceTimersByTime(1000 * Math.pow(2, i));
          });
          
          await waitFor(() => {
            expect(mockWsInstances).toHaveLength(i + 2);
          });
        }
      }

      expect(result.current.error).toBe('Max reconnection attempts reached');
      expect(result.current.isReconnecting).toBe(false);

      vi.useRealTimers();
    });

    it('does not reconnect for normal closures', async () => {
      const { result } = renderHook(() => useExecutionStatus({ 
        executionId: 'test-123',
        autoReconnect: true,
      }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      act(() => {
        mockWsInstances[0].close(1000, 'Normal closure');
      });

      expect(result.current.isConnected).toBe(false);
      expect(result.current.isReconnecting).toBe(false);
    });
  });

  describe('Execution Cancellation', () => {
    it('sends cancel request', async () => {
      const { result } = renderHook(() => useExecutionStatus());

      await act(async () => {
        await result.current.startExecution('kubectl get pods');
      });

      act(() => {
        result.current.cancelExecution();
      });

      expect(mockFetch).toHaveBeenCalledWith('/api/execution/test-exec-123/cancel', {
        method: 'POST',
      });
    });

    it('handles cancel request errors gracefully', async () => {
      const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
      mockFetch.mockImplementationOnce((url) => {
        if (url === '/api/execution/test-exec-123/cancel') {
          return Promise.reject(new Error('Cancel failed'));
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ executionId: 'test-exec-123' }),
        });
      });

      const { result } = renderHook(() => useExecutionStatus());

      await act(async () => {
        await result.current.startExecution('kubectl get pods');
      });

      act(() => {
        result.current.cancelExecution();
      });

      await waitFor(() => {
        expect(result.current.error).toBe('Failed to cancel execution');
      });

      consoleSpy.mockRestore();
    });
  });

  describe('Cleanup', () => {
    it('cleans up WebSocket connection on unmount', async () => {
      const { result, unmount } = renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      const closeSpy = vi.spyOn(mockWsInstances[0], 'close');
      
      unmount();

      expect(closeSpy).toHaveBeenCalledWith(1000, 'Component unmounting');
    });
  });

  describe('Manual Retry', () => {
    it('allows manual retry of connection', async () => {
      const { result } = renderHook(() => useExecutionStatus({ executionId: 'test-123' }));

      await waitFor(() => {
        expect(result.current.isConnected).toBe(true);
      });

      // Simulate connection failure
      act(() => {
        mockWsInstances[0].simulateError();
        mockWsInstances[0].close(1006, 'Connection error');
      });

      expect(result.current.isConnected).toBe(false);

      act(() => {
        result.current.retryConnection();
      });

      await waitFor(() => {
        expect(mockWsInstances).toHaveLength(2);
      });
    });
  });
});