import React from 'react';
import { cn } from '@/utils/cn';
import AccessibilitySafetyIndicator from './AccessibilitySafetyIndicator';

export type SafetyLevel = 'safe' | 'caution' | 'destructive' | 'info' | 'disabled';

export interface SafetyIndicatorProps {
  level: SafetyLevel;
  variant?: 'border' | 'background' | 'icon' | 'badge';
  size?: 'sm' | 'md' | 'lg';
  showText?: boolean;
  useAccessibleAlternative?: boolean;
  accessibilityVariant?: 'icon' | 'text' | 'symbol' | 'pattern';
  className?: string;
  children?: React.ReactNode;
}

const getSafetyText = (level: SafetyLevel) => {
  switch (level) {
    case 'safe':
      return 'Safe Operation';
    case 'caution':
      return 'Caution Required';
    case 'destructive':
      return 'Destructive Operation';
    case 'info':
      return 'Information';
    case 'disabled':
      return 'Disabled';
    default:
      return 'Unknown';
  }
};

const SafetyIndicator: React.FC<SafetyIndicatorProps> = ({
  level,
  variant = 'border',
  size = 'md',
  showText = false,
  useAccessibleAlternative = false,
  accessibilityVariant = 'icon',
  className,
  children,
}) => {
  // If accessibility mode is requested, use the accessible alternative
  if (useAccessibleAlternative) {
    return (
      <div className={cn('flex items-center space-x-2', className)}>
        <AccessibilitySafetyIndicator 
          level={level}
          variant={accessibilityVariant}
          size={size}
        />
        {showText && (
          <span className="text-sm font-medium">
            {getSafetyText(level)}
          </span>
        )}
        {children}
      </div>
    );
  }
  const getSafetyStyles = (level: SafetyLevel) => {
    switch (level) {
      case 'safe':
        return {
          border: 'border-l-4 border-[#059669]',
          background: 'bg-emerald-50 border border-emerald-200 text-emerald-800',
          icon: 'text-[#059669]',
          badge: 'bg-[#059669] text-white',
          textColor: 'text-emerald-800',
          bgColor: 'bg-emerald-50',
          borderColor: 'border-emerald-200',
        };
      case 'caution':
        return {
          border: 'border-l-4 border-[#d97706]',
          background: 'bg-amber-50 border border-amber-200 text-amber-800',
          icon: 'text-[#d97706]',
          badge: 'bg-[#d97706] text-white',
          textColor: 'text-amber-800',
          bgColor: 'bg-amber-50',
          borderColor: 'border-amber-200',
        };
      case 'destructive':
        return {
          border: 'border-l-4 border-[#dc2626]',
          background: 'bg-red-50 border border-red-200 text-red-800',
          icon: 'text-[#dc2626]',
          badge: 'bg-[#dc2626] text-white',
          textColor: 'text-red-800',
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
        };
      case 'info':
        return {
          border: 'border-l-4 border-[#0ea5e9]',
          background: 'bg-blue-50 border border-blue-200 text-blue-800',
          icon: 'text-[#0ea5e9]',
          badge: 'bg-[#0ea5e9] text-white',
          textColor: 'text-blue-800',
          bgColor: 'bg-blue-50',
          borderColor: 'border-blue-200',
        };
      case 'disabled':
        return {
          border: 'border-l-4 border-[#64748b]',
          background: 'bg-gray-50 border border-gray-200 text-gray-600',
          icon: 'text-[#64748b]',
          badge: 'bg-[#64748b] text-white',
          textColor: 'text-gray-600',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
        };
      default:
        return {
          border: 'border-l-4 border-gray-300',
          background: 'bg-gray-50 border border-gray-200 text-gray-700',
          icon: 'text-gray-500',
          badge: 'bg-gray-500 text-white',
          textColor: 'text-gray-700',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
        };
    }
  };

  const getSafetyIcon = (level: SafetyLevel) => {
    switch (level) {
      case 'safe':
        return (
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
          </svg>
        );
      case 'caution':
        return (
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
          </svg>
        );
      case 'destructive':
        return (
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        );
      case 'info':
        return (
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
        );
      case 'disabled':
        return (
          <svg className="w-4 h-4" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M13.477 14.89A6 6 0 015.11 6.524l8.367 8.368zm1.414-1.414L6.524 5.11a6 6 0 018.367 8.367zM18 10a8 8 0 11-16 0 8 8 0 0116 0z" clipRule="evenodd" />
          </svg>
        );
      default:
        return null;
    }
  };


  const getSizeClasses = (size: 'sm' | 'md' | 'lg') => {
    switch (size) {
      case 'sm':
        return 'px-2 py-1 text-xs';
      case 'md':
        return 'px-3 py-2 text-sm';
      case 'lg':
        return 'px-4 py-3 text-base';
      default:
        return 'px-3 py-2 text-sm';
    }
  };

  const styles = getSafetyStyles(level);
  const icon = getSafetyIcon(level);
  const text = getSafetyText(level);
  const sizeClasses = getSizeClasses(size);

  if (variant === 'icon') {
    return (
      <div 
        className={cn('inline-flex items-center justify-center', styles.icon, className)}
        role="img"
        aria-label={`Safety level: ${text}`}
      >
        {icon}
        {showText && <span className="ml-2">{text}</span>}
      </div>
    );
  }

  if (variant === 'badge') {
    return (
      <span 
        className={cn(
          'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium',
          styles.badge,
          className
        )}
        role="status"
        aria-label={`Safety level: ${text}`}
      >
        {icon && <span className="mr-1">{icon}</span>}
        {showText ? text : level.toUpperCase()}
      </span>
    );
  }

  if (variant === 'background') {
    return (
      <div 
        className={cn(
          'rounded-md',
          styles.background,
          sizeClasses,
          className
        )}
        role="status"
        aria-label={`Safety level: ${text}`}
      >
        <div className="flex items-center">
          {icon && (
            <span className={cn('flex-shrink-0', styles.icon)}>
              {icon}
            </span>
          )}
          {(showText || children) && (
            <div className={cn('ml-2', styles.textColor)}>
              {showText && <span className="font-medium">{text}</span>}
              {children && (
                <div className={showText ? 'mt-1' : ''}>{children}</div>
              )}
            </div>
          )}
        </div>
      </div>
    );
  }

  // Default: border variant
  return (
    <div 
      className={cn(
        'rounded-md',
        styles.border,
        styles.bgColor,
        styles.borderColor,
        sizeClasses,
        className
      )}
      role="status"
      aria-label={`Safety level: ${text}`}
    >
      <div className="flex items-center">
        {icon && (
          <span className={cn('flex-shrink-0', styles.icon)}>
            {icon}
          </span>
        )}
        {(showText || children) && (
          <div className={cn('ml-2', styles.textColor)}>
            {showText && <span className="font-medium">{text}</span>}
            {children && (
              <div className={showText ? 'mt-1' : ''}>{children}</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default SafetyIndicator;