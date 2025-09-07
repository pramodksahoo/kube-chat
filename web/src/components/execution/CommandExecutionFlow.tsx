import React, { useCallback, useState } from 'react';
import { cn } from '@/utils/cn';
import CommandExecutionStatus from './CommandExecutionStatus';
import { useExecutionStatus } from '@/hooks/useExecutionStatus';

export interface CommandExecutionFlowProps {
  command: string;
  executionId?: string;
  onExecutionComplete?: (success: boolean, output?: string) => void;
  onExecutionCancel?: () => void;
  className?: string;
}

const CommandExecutionFlow: React.FC<CommandExecutionFlowProps> = ({
  command,
  executionId: initialExecutionId,
  onExecutionComplete,
  onExecutionCancel,
  className,
}) => {
  const [localExecutionId, setLocalExecutionId] = useState<string | undefined>(initialExecutionId);
  
  const {
    status,
    steps,
    isConnected,
    isReconnecting,
    error: connectionError,
    startExecution,
    cancelExecution,
    retryConnection,
  } = useExecutionStatus({ 
    executionId: localExecutionId,
    autoReconnect: true,
    maxRetries: 3,
    retryDelay: 1000,
  });

  const handleStartExecution = useCallback(async () => {
    try {
      const newExecutionId = await startExecution(command);
      setLocalExecutionId(newExecutionId);
    } catch (error) {
      console.error('Failed to start execution:', error);
      // Error is handled by the hook
    }
  }, [command, startExecution]);

  const handleCancelExecution = useCallback(() => {
    cancelExecution();
    onExecutionCancel?.();
  }, [cancelExecution, onExecutionCancel]);

  const handleRetryExecution = useCallback(() => {
    // Reset state and start new execution
    setLocalExecutionId(undefined);
    void handleStartExecution();
  }, [handleStartExecution]);

  // Monitor execution completion
  React.useEffect(() => {
    if (status === 'completed') {
      onExecutionComplete?.(true);
    } else if (status === 'failed') {
      onExecutionComplete?.(false);
    }
  }, [status, onExecutionComplete]);

  // Auto-start execution if we have a command but no execution ID
  React.useEffect(() => {
    if (command && !localExecutionId && status === 'queued') {
      void handleStartExecution();
    }
  }, [command, localExecutionId, status, handleStartExecution]);

  if (!command) {
    return (
      <div className="bg-gray-50 rounded-lg p-4 text-center text-gray-500">
        No command provided for execution
      </div>
    );
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Connection Status */}
      {!isConnected && localExecutionId && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse" />
              <span className="text-sm text-yellow-800">
                {isReconnecting ? 'Reconnecting to execution stream...' : 'Connection lost'}
              </span>
            </div>
            {!isReconnecting && (
              <button
                onClick={retryConnection}
                className="text-sm text-yellow-700 hover:text-yellow-900 underline"
              >
                Retry
              </button>
            )}
          </div>
        </div>
      )}

      {/* Connection Error */}
      {connectionError && (
        <div className="bg-red-50 border border-red-200 rounded-lg p-3">
          <div className="flex items-start space-x-2">
            <svg className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <div>
              <p className="text-sm text-red-800 font-medium">Connection Error</p>
              <p className="text-sm text-red-600 mt-1">{connectionError}</p>
            </div>
          </div>
        </div>
      )}

      {/* Execution Status */}
      {localExecutionId ? (
        <CommandExecutionStatus
          executionId={localExecutionId}
          command={command}
          steps={steps}
          overallStatus={status}
          isInterruptible={status === 'executing' || status === 'preparing'}
          onCancel={handleCancelExecution}
          onRetry={status === 'failed' ? handleRetryExecution : undefined}
        />
      ) : (
        /* Initial State - Preparing to Start */
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
          <div className="flex items-center space-x-3">
            <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
            <div>
              <h3 className="text-sm font-medium text-blue-900">Preparing Execution</h3>
              <p className="text-sm text-blue-700 mt-1">Setting up command execution environment...</p>
            </div>
          </div>
          
          <div className="mt-3 pt-3 border-t border-blue-200">
            <div className="text-xs text-blue-600 mb-1">Command to Execute</div>
            <div className="bg-gray-900 text-gray-100 p-2 rounded font-mono text-sm">
              <code>{command}</code>
            </div>
          </div>
        </div>
      )}

      {/* Debug Information (Development Only) */}
      {process.env.NODE_ENV === 'development' && (
        <details className="bg-gray-50 border border-gray-200 rounded-lg p-3 text-xs">
          <summary className="cursor-pointer text-gray-600 hover:text-gray-800">
            Debug Info
          </summary>
          <div className="mt-2 space-y-1 font-mono">
            <div>Execution ID: {localExecutionId || 'Not started'}</div>
            <div>Status: {status}</div>
            <div>Connected: {isConnected ? 'Yes' : 'No'}</div>
            <div>Reconnecting: {isReconnecting ? 'Yes' : 'No'}</div>
            <div>Steps: {steps.length}</div>
            <div>Error: {connectionError || 'None'}</div>
          </div>
        </details>
      )}
    </div>
  );
};

export default CommandExecutionFlow;