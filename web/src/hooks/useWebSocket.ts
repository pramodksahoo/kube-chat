import { useCallback, useEffect, useRef, useState } from 'react';
import type {
  ConnectionStatus,
  MessageQueue,
  WebSocketConfig,
  WebSocketMessage,
} from '@/types/websocket';

const DEFAULT_CONFIG: WebSocketConfig = {
  url: `${typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${typeof window !== 'undefined' ? window.location.host : 'localhost'}/ws/chat`,
  reconnectAttempts: 5,
  reconnectInterval: 3000,
  heartbeatInterval: 30000,
};

export const useWebSocket = (config: Partial<WebSocketConfig> = {}) => {
  const fullConfig = { ...DEFAULT_CONFIG, ...config };
  const websocketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const heartbeatTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptsRef = useRef(0);

  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>({
    status: 'disconnected',
    reconnectAttempts: 0,
  });

  const [messages, setMessages] = useState<WebSocketMessage[]>([]);
  const [messageQueue, setMessageQueue] = useState<MessageQueue>({
    messages: [],
    maxSize: 100,
  });

  // Generate unique message ID
  const generateMessageId = useCallback(() => {
    return `msg_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }, []);

  // Send heartbeat to keep connection alive
  const sendHeartbeat = useCallback(() => {
    if (websocketRef.current?.readyState === WebSocket.OPEN) {
      websocketRef.current.send(
        JSON.stringify({
          type: 'heartbeat',
          timestamp: new Date().toISOString(),
        })
      );
    }
  }, []);

  // Process message queue when connection is restored
  const processMessageQueue = useCallback(() => {
    if (
      websocketRef.current?.readyState === WebSocket.OPEN &&
      messageQueue.messages.length > 0
    ) {
      messageQueue.messages.forEach(message => {
        websocketRef.current?.send(JSON.stringify(message));
      });
      setMessageQueue(prev => ({ ...prev, messages: [] }));
    }
  }, [messageQueue.messages]);

  // Connect to WebSocket
  const connect = useCallback(() => {
    if (websocketRef.current?.readyState === WebSocket.OPEN) {
      return;
    }

    setConnectionStatus(prev => ({
      ...prev,
      status: reconnectAttemptsRef.current > 0 ? 'reconnecting' : 'connecting',
    }));

    try {
      const wsUrl = fullConfig.token
        ? `${fullConfig.url}?token=${fullConfig.token}`
        : fullConfig.url;

      websocketRef.current = new WebSocket(wsUrl);

      websocketRef.current.onopen = () => {
        console.log('WebSocket connected');
        reconnectAttemptsRef.current = 0;
        setConnectionStatus({
          status: 'connected',
          lastConnected: new Date(),
          reconnectAttempts: 0,
        });

        // Start heartbeat
        heartbeatTimeoutRef.current = setInterval(() => {
          sendHeartbeat();
        }, fullConfig.heartbeatInterval);

        // Process any queued messages
        processMessageQueue();
      };

      websocketRef.current.onmessage = event => {
        try {
          const data = JSON.parse(event.data as string) as WebSocketMessage;
          
          // Skip heartbeat responses
          if (data.type === 'heartbeat') {
            return;
          }

          const message: WebSocketMessage = data;
          setMessages(prev => [...prev, message]);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      websocketRef.current.onclose = event => {
        console.log('WebSocket disconnected:', event.code, event.reason);
        
        if (heartbeatTimeoutRef.current) {
          clearInterval(heartbeatTimeoutRef.current);
          heartbeatTimeoutRef.current = null;
        }

        if (event.code !== 1000 && reconnectAttemptsRef.current < fullConfig.reconnectAttempts) {
          setConnectionStatus(prev => ({
            ...prev,
            status: 'reconnecting',
            reconnectAttempts: reconnectAttemptsRef.current + 1,
          }));

          reconnectAttemptsRef.current += 1;
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, fullConfig.reconnectInterval);
        } else {
          setConnectionStatus(prev => ({
            ...prev,
            status: 'disconnected',
          }));
        }
      };

      websocketRef.current.onerror = error => {
        console.error('WebSocket error:', error);
        setConnectionStatus(prev => ({
          ...prev,
          status: 'error',
          error: 'Connection failed',
        }));
      };
    } catch (error) {
      console.error('Failed to create WebSocket connection:', error);
      setConnectionStatus(prev => ({
        ...prev,
        status: 'error',
        error: 'Failed to initialize connection',
      }));
    }
  }, [fullConfig, sendHeartbeat, processMessageQueue]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (heartbeatTimeoutRef.current) {
      clearInterval(heartbeatTimeoutRef.current);
      heartbeatTimeoutRef.current = null;
    }

    if (websocketRef.current) {
      websocketRef.current.close(1000, 'Client disconnect');
      websocketRef.current = null;
    }

    setConnectionStatus(prev => ({ ...prev, status: 'disconnected' }));
  }, []);

  // Send message
  const sendMessage = useCallback(
    (message: Omit<WebSocketMessage, 'id' | 'timestamp'>) => {
      const fullMessage: WebSocketMessage = {
        ...message,
        id: generateMessageId(),
        timestamp: new Date().toISOString(),
      };

      if (websocketRef.current?.readyState === WebSocket.OPEN) {
        websocketRef.current.send(JSON.stringify(fullMessage));
        setMessages(prev => [...prev, fullMessage]);
      } else {
        // Queue message for later delivery
        setMessageQueue(prev => ({
          ...prev,
          messages: [...prev.messages, fullMessage].slice(-prev.maxSize),
        }));
      }
    },
    [generateMessageId]
  );

  // Reconnect manually
  const reconnect = useCallback(() => {
    reconnectAttemptsRef.current = 0;
    disconnect();
    setTimeout(() => connect(), 1000);
  }, [connect, disconnect]);

  // Clear messages
  const clearMessages = useCallback(() => {
    setMessages([]);
  }, []);

  // Initialize connection
  useEffect(() => {
    connect();
    return () => disconnect();
  }, [connect, disconnect]);

  return {
    connectionStatus,
    messages,
    sendMessage,
    reconnect,
    clearMessages,
    connect,
    disconnect,
  };
};