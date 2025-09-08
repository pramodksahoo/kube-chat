import { useCallback, useEffect, useRef, useState } from 'react';
import type { ExecutionPhase, ExecutionStep } from '@/components/execution/CommandExecutionStatus';

export interface ExecutionStatusUpdate {
  executionId: string;
  phase: ExecutionPhase;
  steps: ExecutionStep[];
  timestamp: string;
  completed?: boolean;
  error?: string;
}

export interface UseExecutionStatusOptions {
  executionId?: string;
  autoReconnect?: boolean;
  maxRetries?: number;
  retryDelay?: number;
}

export interface UseExecutionStatusReturn {
  status: ExecutionPhase;
  steps: ExecutionStep[];
  isConnected: boolean;
  isReconnecting: boolean;
  error: string | null;
  startExecution: (command: string) => Promise<string>;
  cancelExecution: () => void;
  retryConnection: () => void;
}

const WS_BASE_URL = typeof window !== 'undefined'
  ? window.location.protocol === 'https:' 
    ? `wss://${window.location.host}` 
    : `ws://${window.location.host}`
  : 'ws://localhost';

export const useExecutionStatus = ({
  executionId: initialExecutionId,
  autoReconnect = true,
  maxRetries = 3,
  retryDelay = 1000,
}: UseExecutionStatusOptions = {}): UseExecutionStatusReturn => {
  const [executionId, setExecutionId] = useState<string | undefined>(initialExecutionId);
  const [status, setStatus] = useState<ExecutionPhase>('queued');
  const [steps, setSteps] = useState<ExecutionStep[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const wsRef = useRef<WebSocket | null>(null);
  const retryCountRef = useRef(0);
  const retryTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const connect = useCallback(() => {
    if (!executionId) return;

    try {
      const wsUrl = `${WS_BASE_URL}/ws/execution/${executionId}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        setIsReconnecting(false);
        setError(null);
        retryCountRef.current = 0;
      };

      ws.onmessage = (event) => {
        try {
          const update: ExecutionStatusUpdate = JSON.parse(event.data);
          
          if (update.executionId === executionId) {
            setStatus(update.phase);
            setSteps(update.steps);
            
            if (update.completed || update.phase === 'completed' || update.phase === 'failed' || update.phase === 'cancelled') {
              // Execution finished, close connection
              ws.close(1000, 'Execution completed');
            }
          }
        } catch (parseError) {
          console.error('Failed to parse execution status update:', parseError);
          setError('Failed to parse status update');
        }
      };

      ws.onerror = (wsError) => {
        console.error('WebSocket error:', wsError);
        setError('Connection error occurred');
      };

      ws.onclose = (event) => {
        setIsConnected(false);
        wsRef.current = null;

        // Only attempt to reconnect if it wasn't a normal closure and we have retries left
        if (
          autoReconnect && 
          event.code !== 1000 && 
          retryCountRef.current < maxRetries &&
          (status === 'executing' || status === 'preparing' || status === 'validating')
        ) {
          setIsReconnecting(true);
          retryCountRef.current++;
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, retryDelay * Math.pow(2, retryCountRef.current - 1)); // Exponential backoff
        } else {
          setIsReconnecting(false);
          if (event.code !== 1000 && retryCountRef.current >= maxRetries) {
            setError('Max reconnection attempts reached');
          }
        }
      };
    } catch (connectionError) {
      console.error('Failed to establish WebSocket connection:', connectionError);
      setError('Failed to establish connection');
    }
  }, [executionId, autoReconnect, maxRetries, retryDelay, status]);

  const disconnect = useCallback(() => {
    if (retryTimeoutRef.current) {
      clearTimeout(retryTimeoutRef.current);
      retryTimeoutRef.current = null;
    }
    
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    if (wsRef.current) {
      wsRef.current.close(1000, 'Component unmounting');
      wsRef.current = null;
    }
    
    setIsConnected(false);
    setIsReconnecting(false);
  }, []);

  const startExecution = useCallback(async (command: string): Promise<string> => {
    try {
      const response = await fetch('/api/execution/start', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ command }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const { executionId: newExecutionId } = await response.json();
      setExecutionId(newExecutionId);
      setStatus('queued');
      setSteps([]);
      setError(null);
      
      return newExecutionId;
    } catch (fetchError) {
      const errorMessage = fetchError instanceof Error ? fetchError.message : 'Unknown error';
      setError(`Failed to start execution: ${errorMessage}`);
      throw fetchError;
    }
  }, []);

  const cancelExecution = useCallback(() => {
    if (!executionId) return;

    fetch(`/api/execution/${executionId}/cancel`, {
      method: 'POST',
    }).catch((cancelError) => {
      console.error('Failed to cancel execution:', cancelError);
      setError('Failed to cancel execution');
    });
  }, [executionId]);

  const retryConnection = useCallback(() => {
    retryCountRef.current = 0;
    setError(null);
    connect();
  }, [connect]);

  // Connect when executionId changes
  useEffect(() => {
    if (executionId) {
      connect();
    } else {
      disconnect();
    }

    return disconnect;
  }, [executionId, connect, disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    status,
    steps,
    isConnected,
    isReconnecting,
    error,
    startExecution,
    cancelExecution,
    retryConnection,
  };
};