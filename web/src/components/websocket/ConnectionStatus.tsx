import React from 'react';
import { useWebSocketContext } from '@/contexts/WebSocketContext';
import { cn } from '@/utils/cn';

const ConnectionStatus: React.FC = () => {
  const { connectionStatus, reconnect } = useWebSocketContext();

  const getStatusColor = () => {
    switch (connectionStatus.status) {
      case 'connected':
        return 'text-safe-600 bg-safe-50 border-safe-200';
      case 'connecting':
      case 'reconnecting':
        return 'text-caution-600 bg-caution-50 border-caution-200';
      case 'disconnected':
      case 'error':
        return 'text-destructive-600 bg-destructive-50 border-destructive-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getStatusText = () => {
    switch (connectionStatus.status) {
      case 'connected':
        return 'Connected';
      case 'connecting':
        return 'Connecting...';
      case 'reconnecting':
        return `Reconnecting (${connectionStatus.reconnectAttempts})...`;
      case 'disconnected':
        return 'Disconnected';
      case 'error':
        return `Error: ${connectionStatus.error || 'Connection failed'}`;
      default:
        return 'Unknown';
    }
  };

  const getStatusIcon = () => {
    switch (connectionStatus.status) {
      case 'connected':
        return (
          <div className="h-2 w-2 rounded-full bg-safe-500 animate-pulse" />
        );
      case 'connecting':
      case 'reconnecting':
        return (
          <div className="h-2 w-2 rounded-full bg-caution-500 animate-spin border border-caution-600" />
        );
      case 'disconnected':
      case 'error':
        return <div className="h-2 w-2 rounded-full bg-destructive-500" />;
      default:
        return <div className="h-2 w-2 rounded-full bg-gray-500" />;
    }
  };

  return (
    <div
      className={cn(
        'flex items-center gap-2 px-3 py-2 rounded-md border text-sm',
        getStatusColor()
      )}
    >
      {getStatusIcon()}
      <span className="font-medium">{getStatusText()}</span>
      
      {connectionStatus.lastConnected && (
        <span className="text-xs opacity-70">
          Last: {connectionStatus.lastConnected.toLocaleTimeString()}
        </span>
      )}

      {(connectionStatus.status === 'disconnected' ||
        connectionStatus.status === 'error') && (
        <button
          onClick={reconnect}
          className="ml-2 px-2 py-1 text-xs bg-white rounded border hover:bg-gray-50 transition-colors"
        >
          Reconnect
        </button>
      )}
    </div>
  );
};

export default ConnectionStatus;