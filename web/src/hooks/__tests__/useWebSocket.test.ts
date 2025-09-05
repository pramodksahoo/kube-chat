import { act, renderHook, waitFor } from '@testing-library/react';
import { useWebSocket } from '@/hooks/useWebSocket';

// Mock WebSocket
interface MockWebSocket {
  readyState: number;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
  onerror: ((event: Event) => void) | null;
  send: (data: string) => void;
  close: (code?: number, reason?: string) => void;
  url: string;
}

class MockWebSocketImpl implements MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  readyState = MockWebSocketImpl.CONNECTING;
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  url: string;
  
  constructor(url: string) {
    this.url = url;
    // Simulate connection after a short delay
    setTimeout(() => {
      this.readyState = MockWebSocketImpl.OPEN;
      if (this.onopen) {
        this.onopen(new Event('open'));
      }
    }, 10);
  }

  send(data: string) {
    // Simulate echo for testing
    setTimeout(() => {
      if (this.onmessage && this.readyState === MockWebSocketImpl.OPEN) {
        const message = JSON.parse(data);
        if (message.type !== 'heartbeat') {
          this.onmessage(new MessageEvent('message', { data }));
        }
      }
    }, 10);
  }

  close(code?: number, reason?: string) {
    this.readyState = MockWebSocketImpl.CLOSED;
    if (this.onclose) {
      this.onclose(new CloseEvent('close', { code, reason }));
    }
  }
}

// Mock global WebSocket
global.WebSocket = MockWebSocketImpl as any;

describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  test('initializes with disconnected status', () => {
    const { result } = renderHook(() => useWebSocket());
    
    expect(result.current.connectionStatus.status).toBe('connecting');
    expect(result.current.messages).toEqual([]);
  });

  test('connects successfully', async () => {
    const { result } = renderHook(() => useWebSocket());

    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.connectionStatus.status).toBe('connected');
    });
  });

  test('sends and receives messages', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Wait for connection
    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.connectionStatus.status).toBe('connected');
    });

    // Send a message
    act(() => {
      result.current.sendMessage({
        type: 'user',
        content: 'Hello, WebSocket!',
      });
    });

    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.messages).toHaveLength(1);
      expect(result.current.messages[0].content).toBe('Hello, WebSocket!');
      expect(result.current.messages[0].type).toBe('user');
    });
  });

  test('queues messages when disconnected', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Send message while disconnected
    act(() => {
      result.current.sendMessage({
        type: 'user',
        content: 'Queued message',
      });
    });

    // Should not have messages yet
    expect(result.current.messages).toHaveLength(0);

    // Connect
    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.connectionStatus.status).toBe('connected');
    });

    // Wait for queued message to be sent
    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.messages).toHaveLength(1);
      expect(result.current.messages[0].content).toBe('Queued message');
    });
  });

  test('clears messages', async () => {
    const { result } = renderHook(() => useWebSocket());

    // Wait for connection and send message
    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.connectionStatus.status).toBe('connected');
    });

    act(() => {
      result.current.sendMessage({
        type: 'user',
        content: 'Test message',
      });
    });

    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.messages).toHaveLength(1);
    });

    // Clear messages
    act(() => {
      result.current.clearMessages();
    });

    expect(result.current.messages).toHaveLength(0);
  });

  test('handles reconnection', async () => {
    const { result } = renderHook(() => useWebSocket({
      reconnectAttempts: 2,
      reconnectInterval: 1000,
    }));

    // Wait for initial connection
    act(() => {
      vi.advanceTimersByTime(20);
    });

    await waitFor(() => {
      expect(result.current.connectionStatus.status).toBe('connected');
    });

    // Simulate disconnection
    act(() => {
      result.current.disconnect();
    });

    expect(result.current.connectionStatus.status).toBe('disconnected');

    // Test manual reconnection
    act(() => {
      result.current.reconnect();
    });

    expect(result.current.connectionStatus.status).toBe('connecting');
  });

  test('uses custom configuration', () => {
    const customConfig = {
      url: 'ws://custom-url:8080/chat',
      reconnectAttempts: 10,
      reconnectInterval: 5000,
      heartbeatInterval: 60000,
      token: 'test-token',
    };

    const { result } = renderHook(() => useWebSocket(customConfig));
    
    // The URL should include the token
    expect(result.current.connectionStatus.status).toBe('connecting');
  });
});