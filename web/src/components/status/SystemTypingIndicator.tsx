import React from 'react';
import { cn } from '@/utils/cn';

export interface SystemTypingIndicatorProps {
  isVisible: boolean;
  message?: string;
  variant?: 'default' | 'processing' | 'analyzing' | 'executing';
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  className?: string;
}

const SystemTypingIndicator: React.FC<SystemTypingIndicatorProps> = ({
  isVisible,
  message,
  variant = 'default',
  size = 'md',
  showIcon = true,
  className,
}) => {
  const getVariantStyles = (variant: string) => {
    switch (variant) {
      case 'processing':
        return {
          bg: 'bg-blue-50',
          border: 'border-blue-200',
          text: 'text-blue-700',
          dot: 'bg-blue-500',
        };
      case 'analyzing':
        return {
          bg: 'bg-purple-50',
          border: 'border-purple-200',
          text: 'text-purple-700',
          dot: 'bg-purple-500',
        };
      case 'executing':
        return {
          bg: 'bg-amber-50',
          border: 'border-amber-200',
          text: 'text-amber-700',
          dot: 'bg-amber-500',
        };
      case 'default':
      default:
        return {
          bg: 'bg-gray-50',
          border: 'border-gray-200',
          text: 'text-gray-700',
          dot: 'bg-gray-400',
        };
    }
  };

  const getDefaultMessage = (variant: string) => {
    switch (variant) {
      case 'processing':
        return 'KubeChat is processing your request...';
      case 'analyzing':
        return 'KubeChat is analyzing your command...';
      case 'executing':
        return 'KubeChat is executing the command...';
      case 'default':
      default:
        return 'KubeChat is typing...';
    }
  };

  const getSizeClasses = (size: string) => {
    switch (size) {
      case 'sm':
        return {
          container: 'px-3 py-2 text-sm',
          dots: 'w-1 h-1',
          icon: 'w-4 h-4',
        };
      case 'lg':
        return {
          container: 'px-4 py-3 text-base',
          dots: 'w-2 h-2',
          icon: 'w-6 h-6',
        };
      case 'md':
      default:
        return {
          container: 'px-3 py-2 text-sm',
          dots: 'w-1.5 h-1.5',
          icon: 'w-5 h-5',
        };
    }
  };

  const getVariantIcon = (variant: string) => {
    const sizeClasses = getSizeClasses(size);
    const iconSize = sizeClasses.icon;

    switch (variant) {
      case 'processing':
        return (
          <svg className={cn(iconSize, 'animate-spin')} viewBox="0 0 24 24" fill="none">
            <circle
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeDasharray="31.416"
              strokeDashoffset="31.416"
            >
              <animate
                attributeName="stroke-dashoffset"
                dur="2s"
                values="31.416;0"
                repeatCount="indefinite"
              />
            </circle>
          </svg>
        );
      case 'analyzing':
        return (
          <svg className={iconSize} viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            <animate
              attributeName="opacity"
              dur="2s"
              values="0.4;1;0.4"
              repeatCount="indefinite"
            />
          </svg>
        );
      case 'executing':
        return (
          <svg className={iconSize} viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
            <animate
              attributeName="opacity"
              dur="1.5s"
              values="0.5;1;0.5"
              repeatCount="indefinite"
            />
          </svg>
        );
      case 'default':
      default:
        return (
          <div className="w-6 h-6 bg-gray-500 rounded-full flex items-center justify-center flex-shrink-0">
            <span className="text-white text-xs font-medium">AI</span>
          </div>
        );
    }
  };

  const styles = getVariantStyles(variant);
  const sizeClasses = getSizeClasses(size);
  const displayMessage = message || getDefaultMessage(variant);
  const variantIcon = getVariantIcon(variant);

  if (!isVisible) {
    return null;
  }

  return (
    <div
      className={cn(
        'flex items-center space-x-3 rounded-lg border animate-fade-in',
        styles.bg,
        styles.border,
        sizeClasses.container,
        className
      )}
      role="status"
      aria-label={displayMessage}
      aria-live="polite"
    >
      {showIcon && (
        <div className={cn('flex-shrink-0', styles.text)}>
          {variantIcon}
        </div>
      )}
      
      <div className="flex items-center space-x-2 flex-1 min-w-0">
        <span className={cn('font-medium', styles.text)}>
          {displayMessage}
        </span>
        
        <div className="flex space-x-1">
          <div 
            className={cn(
              'rounded-full animate-pulse',
              styles.dot,
              sizeClasses.dots
            )}
            style={{ animationDelay: '0ms', animationDuration: '1.4s' }}
          />
          <div 
            className={cn(
              'rounded-full animate-pulse',
              styles.dot,
              sizeClasses.dots
            )}
            style={{ animationDelay: '200ms', animationDuration: '1.4s' }}
          />
          <div 
            className={cn(
              'rounded-full animate-pulse',
              styles.dot,
              sizeClasses.dots
            )}
            style={{ animationDelay: '400ms', animationDuration: '1.4s' }}
          />
        </div>
      </div>
    </div>
  );
};

export default SystemTypingIndicator;