import React from 'react';
import { cn } from '@/utils/cn';
import type { WebSocketMessage } from '@/types/websocket';
import SafetyIndicator from '@/components/safety/SafetyIndicator';
import RiskAssessment from '@/components/safety/RiskAssessment';
import ProcessingStatus from '@/components/status/ProcessingStatus';

interface MessageItemProps {
  message: WebSocketMessage;
  className?: string;
}

const MessageItem: React.FC<MessageItemProps> = ({ message, className }) => {
  const isUser = message.type === 'user';
  const isSystem = message.type === 'system';
  const isError = message.type === 'error';
  const isStatus = message.type === 'status';
  const hasCommand = Boolean(message.command);
  const hasSafetyLevel = Boolean(message.safetyLevel);
  const hasProcessingState = Boolean(message.processingState);

  const getMessageStyles = () => {
    if (isUser) {
      return 'bg-primary-100 text-primary-900 ml-8 rounded-lg';
    }
    if (isSystem) {
      return 'bg-gray-100 text-gray-700 mx-16 rounded-lg text-sm text-center';
    }
    if (isError) {
      return 'bg-destructive-50 text-destructive-900 border border-destructive-200 mr-8 rounded-lg';
    }
    if (isStatus) {
      return 'bg-blue-50 text-blue-900 border border-blue-200 mr-8 rounded-lg';
    }
    return 'bg-white border border-gray-200 mr-8 rounded-lg';
  };

  const formatTime = (timestamp: string) => {
    return new Date(timestamp).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getRoleIcon = () => {
    if (isUser) {
      return (
        <div className="w-6 h-6 bg-primary-600 rounded-full flex items-center justify-center flex-shrink-0">
          <span className="text-white text-xs font-medium">U</span>
        </div>
      );
    }
    if (isSystem) {
      return (
        <div className="w-6 h-6 bg-gray-500 rounded-full flex items-center justify-center flex-shrink-0">
          <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
            <path
              fillRule="evenodd"
              d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z"
              clipRule="evenodd"
            />
          </svg>
        </div>
      );
    }
    if (isError) {
      return (
        <div className="w-6 h-6 bg-destructive-600 rounded-full flex items-center justify-center flex-shrink-0">
          <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
            <path
              fillRule="evenodd"
              d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
              clipRule="evenodd"
            />
          </svg>
        </div>
      );
    }
    return (
      <div className="w-6 h-6 bg-safe-600 rounded-full flex items-center justify-center flex-shrink-0">
        <span className="text-white text-xs font-medium">AI</span>
      </div>
    );
  };

  return (
    <div
      className={cn(
        'flex gap-3 items-start animate-fade-in',
        isSystem && 'justify-center',
        className
      )}
    >
      {!isSystem && getRoleIcon()}
      
      <div
        className={cn(
          'p-3 max-w-[80%] break-words',
          getMessageStyles()
        )}
      >
        <div className="space-y-1">
          {!isSystem && (
            <div className="flex items-center justify-between gap-2">
              <span className="font-medium text-sm">
                {isUser ? 'You' : isError ? 'Error' : 'KubeChat'}
              </span>
              <time
                className="text-xs opacity-70"
                dateTime={message.timestamp}
              >
                {formatTime(message.timestamp)}
              </time>
            </div>
          )}
          
          {hasProcessingState && message.processingState && message.processingState !== 'idle' && (
            <ProcessingStatus
              state={message.processingState}
              progress={message.progress}
              variant="inline"
              size="sm"
              showProgress={Boolean(message.progress)}
              className="mb-2"
            />
          )}
          
          {hasSafetyLevel && !isUser && !isSystem && (
            <SafetyIndicator 
              level={message.safetyLevel!}
              variant="icon"
              showText={true}
              className="mb-2"
            />
          )}
          
          <div className={cn(
            'text-sm leading-relaxed',
            isSystem && 'text-center'
          )}>
            {message.content}
          </div>
          
          {hasCommand && (
            <div className="mt-3 p-3 bg-gray-900 text-gray-100 rounded-md font-mono text-sm overflow-x-auto">
              <div className="flex items-center justify-between mb-2">
                <span className="text-gray-400 text-xs">Generated Command:</span>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard?.writeText(message.command!);
                  }}
                  className="text-gray-400 hover:text-white text-xs px-2 py-1 rounded hover:bg-gray-800 transition-colors"
                  aria-label="Copy command to clipboard"
                >
                  Copy
                </button>
              </div>
              <code>{message.command}</code>
            </div>
          )}
          
          {hasSafetyLevel && (message.affectedResources || message.risks || message.recommendations) && (
            <div className="mt-3">
              <RiskAssessment 
                data={{
                  level: message.safetyLevel!,
                  command: message.command,
                  affectedResources: message.affectedResources,
                  risks: message.risks,
                  recommendations: message.recommendations
                }}
                variant="detailed"
              />
            </div>
          )}
          
          {message.metadata && (
            <div className="mt-2 pt-2 border-t border-current border-opacity-20">
              <details className="text-xs">
                <summary className="cursor-pointer opacity-70 hover:opacity-100">
                  Metadata
                </summary>
                <pre className="mt-1 p-2 bg-black bg-opacity-10 rounded text-xs overflow-x-auto">
                  {JSON.stringify(message.metadata, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default MessageItem;