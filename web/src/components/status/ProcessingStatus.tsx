import React from 'react';
import { cn } from '@/utils/cn';

export type ProcessingState = 'idle' | 'processing' | 'executing' | 'completed' | 'failed';

export interface ProcessingStatusProps {
  state: ProcessingState;
  message?: string;
  progress?: number;
  variant?: 'inline' | 'card' | 'minimal';
  size?: 'sm' | 'md' | 'lg';
  showProgress?: boolean;
  className?: string;
}

const ProcessingStatus: React.FC<ProcessingStatusProps> = ({
  state,
  message,
  progress,
  variant = 'inline',
  size = 'md',
  showProgress = false,
  className,
}) => {
  const getStatusStyles = (state: ProcessingState) => {
    switch (state) {
      case 'processing':
        return {
          color: 'text-blue-600',
          bg: 'bg-blue-50',
          border: 'border-blue-200',
          ring: 'ring-blue-500',
        };
      case 'executing':
        return {
          color: 'text-amber-600',
          bg: 'bg-amber-50',
          border: 'border-amber-200',
          ring: 'ring-amber-500',
        };
      case 'completed':
        return {
          color: 'text-emerald-600',
          bg: 'bg-emerald-50',
          border: 'border-emerald-200',
          ring: 'ring-emerald-500',
        };
      case 'failed':
        return {
          color: 'text-red-600',
          bg: 'bg-red-50',
          border: 'border-red-200',
          ring: 'ring-red-500',
        };
      case 'idle':
      default:
        return {
          color: 'text-gray-600',
          bg: 'bg-gray-50',
          border: 'border-gray-200',
          ring: 'ring-gray-500',
        };
    }
  };

  const getStatusIcon = (state: ProcessingState) => {
    const iconSizes = {
      sm: 'w-3 h-3',
      md: 'w-4 h-4',
      lg: 'w-5 h-5',
    };

    const iconSize = iconSizes[size];

    switch (state) {
      case 'processing':
        return (
          <div className={cn('animate-spin', iconSize)}>
            <svg viewBox="0 0 24 24" fill="none" className="animate-spin">
              <circle
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="2"
                strokeDasharray="31.416"
                strokeDashoffset="31.416"
                className="animate-pulse"
              >
                <animate
                  attributeName="stroke-dashoffset"
                  dur="2s"
                  values="0;31.416"
                  repeatCount="indefinite"
                />
              </circle>
            </svg>
          </div>
        );
      case 'executing':
        return (
          <div className={cn('flex space-x-1', iconSize)}>
            <div className="w-1 h-4 bg-current animate-pulse animation-delay-0 rounded"></div>
            <div className="w-1 h-4 bg-current animate-pulse animation-delay-200 rounded"></div>
            <div className="w-1 h-4 bg-current animate-pulse animation-delay-400 rounded"></div>
          </div>
        );
      case 'completed':
        return (
          <svg className={cn(iconSize, 'animate-bounce-once')} viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
          </svg>
        );
      case 'failed':
        return (
          <svg className={cn(iconSize, 'animate-shake')} viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        );
      case 'idle':
      default:
        return (
          <div className={cn(iconSize, 'rounded-full bg-current opacity-30')}></div>
        );
    }
  };

  const getStatusMessage = (state: ProcessingState) => {
    if (message) return message;
    
    switch (state) {
      case 'processing':
        return 'Processing your request...';
      case 'executing':
        return 'Executing command...';
      case 'completed':
        return 'Command completed successfully';
      case 'failed':
        return 'Command execution failed';
      case 'idle':
      default:
        return 'Ready';
    }
  };

  const getSizeClasses = () => {
    switch (size) {
      case 'sm':
        return 'text-xs px-2 py-1';
      case 'lg':
        return 'text-base px-4 py-3';
      case 'md':
      default:
        return 'text-sm px-3 py-2';
    }
  };

  const styles = getStatusStyles(state);
  const icon = getStatusIcon(state);
  const statusMessage = getStatusMessage(state);
  const isAnimated = state === 'processing' || state === 'executing';

  if (variant === 'minimal') {
    return (
      <div
        className={cn(
          'flex items-center space-x-2',
          styles.color,
          className
        )}
        role="status"
        aria-label={`Status: ${statusMessage}`}
      >
        {icon}
        {statusMessage && (
          <span className="text-sm font-medium">{statusMessage}</span>
        )}
      </div>
    );
  }

  if (variant === 'card') {
    return (
      <div
        className={cn(
          'rounded-lg border shadow-sm p-4 space-y-3',
          styles.bg,
          styles.border,
          isAnimated && `ring-2 ring-opacity-20 ${styles.ring}`,
          className
        )}
        role="status"
        aria-label={`Status: ${statusMessage}`}
      >
        <div className="flex items-center space-x-3">
          <div className={styles.color}>
            {icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className={cn('font-medium', styles.color)}>
              {statusMessage}
            </div>
            {showProgress && typeof progress === 'number' && (
              <div className="mt-2">
                <div className="flex justify-between text-xs text-gray-600 mb-1">
                  <span>Progress</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div
                    className={cn(
                      'h-2 rounded-full transition-all duration-300 ease-out',
                      state === 'completed' ? 'bg-emerald-500' :
                      state === 'failed' ? 'bg-red-500' :
                      state === 'executing' ? 'bg-amber-500' :
                      'bg-blue-500'
                    )}
                    style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  // Default: inline variant
  return (
    <div
      className={cn(
        'inline-flex items-center space-x-2 rounded-md border',
        styles.bg,
        styles.border,
        styles.color,
        getSizeClasses(),
        isAnimated && `ring-1 ring-opacity-20 ${styles.ring}`,
        className
      )}
      role="status"
      aria-label={`Status: ${statusMessage}`}
    >
      <div className="flex-shrink-0">
        {icon}
      </div>
      {statusMessage && (
        <span className="font-medium">{statusMessage}</span>
      )}
      {showProgress && typeof progress === 'number' && (
        <span className="text-xs opacity-75">
          ({Math.round(progress)}%)
        </span>
      )}
    </div>
  );
};

export default ProcessingStatus;