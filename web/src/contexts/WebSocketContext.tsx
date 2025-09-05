import React, { createContext, type ReactNode, useContext } from 'react';
import { useWebSocket } from '@/hooks/useWebSocket';
import type { WebSocketConfig, WebSocketContextType } from '@/types/websocket';

const WebSocketContext = createContext<WebSocketContextType | null>(null);

interface WebSocketProviderProps {
  children: ReactNode;
  config?: Partial<WebSocketConfig>;
}

export const WebSocketProvider: React.FC<WebSocketProviderProps> = ({
  children,
  config,
}) => {
  const webSocket = useWebSocket(config);

  const contextValue: WebSocketContextType = {
    connectionStatus: webSocket.connectionStatus,
    sendMessage: webSocket.sendMessage,
    sendStatusUpdate: (statusUpdate) => {
      // TODO: Implement status update functionality
      console.log('Status update:', statusUpdate);
    },
    messages: webSocket.messages,
    clearMessages: webSocket.clearMessages,
    reconnect: webSocket.reconnect,
    getMessageStatus: (messageId) => {
      // TODO: Implement message status retrieval
      console.log('Getting status for message:', messageId);
      return null;
    },
  };

  return (
    <WebSocketContext.Provider value={contextValue}>
      {children}
    </WebSocketContext.Provider>
  );
};

export const useWebSocketContext = (): WebSocketContextType => {
  const context = useContext(WebSocketContext);
  if (!context) {
    throw new Error(
      'useWebSocketContext must be used within a WebSocketProvider'
    );
  }
  return context;
};