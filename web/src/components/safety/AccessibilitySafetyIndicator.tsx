import React from 'react';
import { cn } from '@/utils/cn';
import type { SafetyLevel } from './SafetyIndicator';

export interface AccessibilitySafetyIndicatorProps {
  level: SafetyLevel;
  variant?: 'icon' | 'text' | 'symbol' | 'pattern';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

const AccessibilitySafetyIndicator: React.FC<AccessibilitySafetyIndicatorProps> = ({
  level,
  variant = 'icon',
  size = 'md',
  className,
}) => {
  const getSafetySymbol = (level: SafetyLevel) => {
    switch (level) {
      case 'safe':
        return '✓';
      case 'caution':
        return '⚠';
      case 'destructive':
        return '✗';
      case 'info':
        return 'ℹ';
      case 'disabled':
        return '⊘';
      default:
        return '?';
    }
  };

  const getSafetyPattern = (level: SafetyLevel) => {
    switch (level) {
      case 'safe':
        return 'repeating-linear-gradient(45deg, transparent, transparent 2px, #059669 2px, #059669 4px)';
      case 'caution':
        return 'repeating-linear-gradient(45deg, transparent, transparent 2px, #d97706 2px, #d97706 4px)';
      case 'destructive':
        return 'repeating-linear-gradient(45deg, transparent, transparent 2px, #dc2626 2px, #dc2626 4px)';
      case 'info':
        return 'repeating-linear-gradient(45deg, transparent, transparent 2px, #0ea5e9 2px, #0ea5e9 4px)';
      case 'disabled':
        return 'repeating-linear-gradient(45deg, transparent, transparent 2px, #64748b 2px, #64748b 4px)';
      default:
        return 'repeating-linear-gradient(45deg, transparent, transparent 2px, #6b7280 2px, #6b7280 4px)';
    }
  };

  const getSafetyText = (level: SafetyLevel) => {
    switch (level) {
      case 'safe':
        return 'SAFE';
      case 'caution':
        return 'CAUTION';
      case 'destructive':
        return 'DANGER';
      case 'info':
        return 'INFO';
      case 'disabled':
        return 'DISABLED';
      default:
        return 'UNKNOWN';
    }
  };

  const getSizeClasses = (size: 'sm' | 'md' | 'lg') => {
    switch (size) {
      case 'sm':
        return {
          container: 'w-4 h-4 text-xs',
          text: 'text-xs px-1 py-0.5',
        };
      case 'md':
        return {
          container: 'w-5 h-5 text-sm',
          text: 'text-sm px-2 py-1',
        };
      case 'lg':
        return {
          container: 'w-6 h-6 text-base',
          text: 'text-base px-3 py-1',
        };
      default:
        return {
          container: 'w-5 h-5 text-sm',
          text: 'text-sm px-2 py-1',
        };
    }
  };

  const getAccessibleIcon = (level: SafetyLevel) => {
    const baseClasses = "flex-shrink-0";
    
    switch (level) {
      case 'safe':
        return (
          <svg className={cn(baseClasses, getSizeClasses(size).container)} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            <circle cx="10" cy="10" r="9" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.3" />
          </svg>
        );
      case 'caution':
        return (
          <svg className={cn(baseClasses, getSizeClasses(size).container)} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            <rect x="1" y="1" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.3" rx="2" />
          </svg>
        );
      case 'destructive':
        return (
          <svg className={cn(baseClasses, getSizeClasses(size).container)} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            <polygon points="10,1 19,19 1,19" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.3" />
          </svg>
        );
      case 'info':
        return (
          <svg className={cn(baseClasses, getSizeClasses(size).container)} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
            <rect x="2" y="2" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" opacity="0.3" />
          </svg>
        );
      case 'disabled':
        return (
          <svg className={cn(baseClasses, getSizeClasses(size).container)} viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
            <path fillRule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clipRule="evenodd" />
            <line x1="2" y1="2" x2="18" y2="18" stroke="currentColor" strokeWidth="2" opacity="0.5" />
          </svg>
        );
      default:
        return (
          <div className={cn(baseClasses, getSizeClasses(size).container, 'border border-current rounded flex items-center justify-center')}>
            <span>?</span>
          </div>
        );
    }
  };

  const sizeClasses = getSizeClasses(size);
  const symbol = getSafetySymbol(level);
  const text = getSafetyText(level);
  const pattern = getSafetyPattern(level);

  if (variant === 'symbol') {
    return (
      <span
        className={cn(
          'inline-flex items-center justify-center font-mono font-bold',
          sizeClasses.container,
          className
        )}
        role="img"
        aria-label={`Safety level: ${text}`}
        title={`Safety level: ${text}`}
      >
        {symbol}
      </span>
    );
  }

  if (variant === 'text') {
    return (
      <span
        className={cn(
          'inline-flex items-center justify-center font-mono font-bold uppercase tracking-wide border rounded',
          sizeClasses.text,
          className
        )}
        role="status"
        aria-label={`Safety level: ${text}`}
      >
        {text}
      </span>
    );
  }

  if (variant === 'pattern') {
    return (
      <div
        className={cn(
          'inline-flex items-center justify-center rounded border-2 border-gray-300',
          sizeClasses.container,
          className
        )}
        style={{ 
          background: pattern,
          backgroundSize: '8px 8px'
        }}
        role="img"
        aria-label={`Safety level: ${text}`}
        title={`Safety level: ${text}`}
      >
        <span className="sr-only">{text}</span>
      </div>
    );
  }

  // Default: icon variant with enhanced accessibility
  return (
    <div
      className={cn(
        'inline-flex items-center justify-center',
        className
      )}
      role="img"
      aria-label={`Safety level: ${text}`}
      title={`Safety level: ${text}`}
    >
      {getAccessibleIcon(level)}
      <span className="sr-only">{text}</span>
    </div>
  );
};

export default AccessibilitySafetyIndicator;