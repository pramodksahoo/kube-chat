/**
 * ResourceStatusIndicator - Visual indicator for resource health status
 * Provides accessible status visualization with color and icon indicators
 */

import React, { memo } from 'react';

export type ResourceStatusType = 'Ready' | 'Warning' | 'Error' | 'Unknown';

export interface ResourceStatusIndicatorProps {
  status: ResourceStatusType;
  size?: 'sm' | 'md' | 'lg';
  showLabel?: boolean;
  showIcon?: boolean;
  className?: string;
  pulse?: boolean;
}

export const ResourceStatusIndicator: React.FC<ResourceStatusIndicatorProps> = memo(({
  status,
  size = 'md',
  showLabel = true,
  showIcon = true,
  className = '',
  pulse = false,
}) => {
  // Status configuration
  const statusConfig = {
    Ready: {
      color: 'text-green-700 bg-green-100 border-green-200',
      dotColor: 'bg-green-500',
      icon: '✓',
      label: 'Ready',
      ariaLabel: 'Status: Ready',
    },
    Warning: {
      color: 'text-yellow-700 bg-yellow-100 border-yellow-200',
      dotColor: 'bg-yellow-500',
      icon: '⚠',
      label: 'Warning',
      ariaLabel: 'Status: Warning',
    },
    Error: {
      color: 'text-red-700 bg-red-100 border-red-200',
      dotColor: 'bg-red-500',
      icon: '✗',
      label: 'Error',
      ariaLabel: 'Status: Error',
    },
    Unknown: {
      color: 'text-gray-700 bg-gray-100 border-gray-200',
      dotColor: 'bg-gray-500',
      icon: '?',
      label: 'Unknown',
      ariaLabel: 'Status: Unknown',
    },
  };

  // Size configuration
  const sizeConfig = {
    sm: {
      container: 'text-xs px-2 py-1',
      dot: 'w-2 h-2',
      icon: 'text-xs',
    },
    md: {
      container: 'text-sm px-3 py-1.5',
      dot: 'w-3 h-3',
      icon: 'text-sm',
    },
    lg: {
      container: 'text-base px-4 py-2',
      dot: 'w-4 h-4',
      icon: 'text-base',
    },
  };

  const config = statusConfig[status];
  const sizes = sizeConfig[size];

  // Simple dot indicator (most minimal)
  if (!showLabel && !showIcon) {
    return (
      <div
        className={`rounded-full ${sizes.dot} ${config.dotColor} ${
          pulse ? 'animate-pulse' : ''
        } ${className}`}
        role="img"
        aria-label={config.ariaLabel}
        data-testid={`status-dot-${status.toLowerCase()}`}
      />
    );
  }

  // Icon-only indicator
  if (!showLabel && showIcon) {
    return (
      <div
        className={`inline-flex items-center justify-center rounded-full border ${sizes.container} ${config.color} ${
          pulse ? 'animate-pulse' : ''
        } ${className}`}
        role="img"
        aria-label={config.ariaLabel}
        data-testid={`status-icon-${status.toLowerCase()}`}
      >
        <span className={sizes.icon} aria-hidden="true">
          {config.icon}
        </span>
      </div>
    );
  }

  // Full indicator with label (and optional icon)
  return (
    <div
      className={`inline-flex items-center gap-2 rounded-full border ${sizes.container} ${config.color} ${
        pulse ? 'animate-pulse' : ''
      } ${className}`}
      role="img"
      aria-label={config.ariaLabel}
      data-testid={`status-indicator-${status.toLowerCase()}`}
    >
      {showIcon && (
        <span className={sizes.icon} aria-hidden="true">
          {config.icon}
        </span>
      )}
      
      {showLabel && (
        <span className="font-medium">
          {config.label}
        </span>
      )}
    </div>
  );
});

ResourceStatusIndicator.displayName = 'ResourceStatusIndicator';

export default ResourceStatusIndicator;