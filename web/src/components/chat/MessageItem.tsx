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
      return 'bg-gradient-to-r from-blue-500 to-purple-600 text-white ml-8 rounded-2xl shadow-lg hover:shadow-xl transition-all duration-300';
    }
    if (isSystem) {
      return 'bg-gray-50/80 backdrop-blur-sm text-gray-600 mx-16 rounded-xl text-sm text-center border border-gray-200/50';
    }
    if (isError) {
      return 'bg-red-50/90 text-red-800 border border-red-200/80 mr-8 rounded-2xl backdrop-blur-sm shadow-lg';
    }
    if (isStatus) {
      return 'bg-blue-50/90 text-blue-800 border border-blue-200/80 mr-8 rounded-2xl backdrop-blur-sm shadow-lg';
    }
    return 'bg-white/80 backdrop-blur-xl border border-gray-200/60 mr-8 rounded-2xl shadow-lg hover:shadow-xl transition-all duration-300';
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
        <div className="w-10 h-10 bg-gradient-to-r from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center flex-shrink-0 shadow-lg ring-4 ring-blue-100">
          <div className="w-6 h-6 bg-white rounded-lg flex items-center justify-center">
            <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
            </svg>
          </div>
        </div>
      );
    }
    if (isSystem) {
      return (
        <div className="w-8 h-8 bg-gray-100 rounded-xl flex items-center justify-center flex-shrink-0 shadow-sm">
          <svg className="w-4 h-4 text-gray-600" fill="currentColor" viewBox="0 0 20 20">
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
        <div className="w-10 h-10 bg-red-100 rounded-2xl flex items-center justify-center flex-shrink-0 shadow-lg ring-4 ring-red-50">
          <div className="w-6 h-6 bg-red-500 rounded-lg flex items-center justify-center">
            <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 20 20">
              <path
                fillRule="evenodd"
                d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                clipRule="evenodd"
              />
            </svg>
          </div>
        </div>
      );
    }
    return (
      <div className="w-10 h-10 bg-gradient-to-r from-green-400 to-blue-500 rounded-2xl flex items-center justify-center flex-shrink-0 shadow-lg ring-4 ring-green-50">
        <div className="w-6 h-6 bg-white rounded-lg flex items-center justify-center">
          <img 
            src="/kubechat-icon.png" 
            alt="AI Assistant" 
            className="w-4 h-4 object-contain"
          />
        </div>
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
          'px-4 py-3 max-w-[80%] break-words transform transition-all duration-300 hover:scale-[1.02]',
          getMessageStyles()
        )}
      >
        <div className="space-y-1">
          {!isSystem && (
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className={cn(
                "font-semibold text-sm",
                isUser ? "text-white" : isError ? "text-red-800" : "text-gray-800"
              )}>
                {isUser ? 'You' : isError ? 'Error' : 'KubeChat Assistant'}
              </span>
              <time
                className={cn(
                  "text-xs font-medium",
                  isUser ? "text-white/70" : "text-gray-500"
                )}
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
            isSystem && 'text-center',
            isUser ? 'text-white font-medium' : 'text-gray-700'
          )}>
            {message.content}
          </div>
          
          {hasCommand && (
            <div className="mt-4 p-4 bg-gradient-to-r from-gray-900 to-gray-800 text-gray-100 rounded-xl font-mono text-sm overflow-x-auto shadow-inner border border-gray-700">
              <div className="flex items-center justify-between mb-3">
                <span className="text-gray-300 text-xs font-semibold flex items-center gap-2">
                  <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zm0 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V8zm0 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1v-2z" clipRule="evenodd" />
                  </svg>
                  Generated Command
                </span>
                <button
                  type="button"
                  onClick={() => {
                    void navigator.clipboard?.writeText(message.command!);
                  }}
                  className="group flex items-center gap-1.5 text-gray-400 hover:text-white text-xs px-3 py-1.5 rounded-lg hover:bg-gray-700/50 transition-all duration-200 border border-gray-600/50 hover:border-gray-500"
                  aria-label="Copy command to clipboard"
                >
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  Copy
                </button>
              </div>
              <code className="text-green-300">{message.command}</code>
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