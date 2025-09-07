/**
 * ResourceCard - Individual resource display component
 * Shows resource status, basic information, and provides click interaction
 */

import React, { memo } from 'react';
import { ResourceStatusIndicator } from './ResourceStatusIndicator';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceCardProps {
  resource: ResourceStatus;
  onClick?: (resource: ResourceStatus) => void;
  className?: string;
  showNamespace?: boolean;
  compact?: boolean;
}

export const ResourceCard: React.FC<ResourceCardProps> = memo(({
  resource,
  onClick,
  className = '',
  showNamespace = true,
  compact = false,
}) => {
  const handleClick = () => {
    onClick?.(resource);
  };

  const handleKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      handleClick();
    }
  };

  // Format last updated time
  const formatLastUpdated = (date: Date) => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMinutes < 1) return 'just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  };

  // Get resource icon based on kind
  const getResourceIcon = (kind: string) => {
    const icons: Record<string, string> = {
      Pod: '🟢',
      Deployment: '🚀',
      Service: '🌐',
      ConfigMap: '📋',
      Secret: '🔐',
      PersistentVolume: '💾',
      PersistentVolumeClaim: '💿',
      Ingress: '🌍',
      Namespace: '📁',
      Node: '🖥️',
      Job: '⚙️',
      CronJob: '⏰',
      StatefulSet: '📊',
      DaemonSet: '👥',
      ReplicaSet: '🔄',
    };
    return icons[kind] || '📦';
  };

  // Get status-based styling
  const getStatusStyling = (status: string) => {
    const styles = {
      Ready: 'border-green-200 bg-green-50 hover:bg-green-100',
      Warning: 'border-yellow-200 bg-yellow-50 hover:bg-yellow-100', 
      Error: 'border-red-200 bg-red-50 hover:bg-red-100',
      Unknown: 'border-gray-200 bg-gray-50 hover:bg-gray-100',
    };
    return styles[status as keyof typeof styles] || styles.Unknown;
  };

  const statusStyling = getStatusStyling(resource.status);

  return (
    <div
      className={`resource-card border rounded-lg p-4 cursor-pointer transition-all duration-200 ${statusStyling} ${
        compact ? 'p-3' : 'p-4'
      } ${className}`}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
      role="button"
      tabIndex={0}
      data-testid="resource-card"
      data-resource-kind={resource.kind}
      data-resource-name={resource.name}
      data-resource-status={resource.status}
      aria-label={`${resource.kind} ${resource.name} - Status: ${resource.status}`}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          {/* Resource icon */}
          <div className={`text-2xl ${compact ? 'text-xl' : 'text-2xl'}`} aria-hidden="true">
            {getResourceIcon(resource.kind)}
          </div>

          {/* Resource details */}
          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0 flex-1">
                <h3 className={`font-medium text-gray-900 truncate ${compact ? 'text-sm' : 'text-base'}`}>
                  {resource.name}
                </h3>
                
                <div className={`flex items-center gap-2 mt-1 ${compact ? 'text-xs' : 'text-sm'} text-gray-600`}>
                  <span className="font-mono bg-gray-100 px-2 py-0.5 rounded text-xs">
                    {resource.kind}
                  </span>
                  
                  {showNamespace && resource.namespace && (
                    <span className="truncate">
                      {resource.namespace}
                    </span>
                  )}
                </div>
              </div>

              {/* Status indicator */}
              <ResourceStatusIndicator 
                status={resource.status} 
                size={compact ? 'sm' : 'md'}
                showLabel={false}
              />
            </div>

            {/* Additional metadata */}
            {!compact && (
              <div className="mt-3 space-y-1">
                <div className="text-xs text-gray-500">
                  Updated {formatLastUpdated(resource.lastUpdated)}
                </div>
                
                {/* Show relationships count if any */}
                {resource.relationships && resource.relationships.length > 0 && (
                  <div className="text-xs text-gray-500">
                    {resource.relationships.length} relationship{resource.relationships.length !== 1 ? 's' : ''}
                  </div>
                )}

                {/* Show key metadata */}
                {resource.metadata && Object.keys(resource.metadata).length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-2">
                    {Object.entries(resource.metadata).slice(0, 3).map(([key, value]) => {
                      const displayValue = typeof value === 'string' ? value : JSON.stringify(value);
                      if (displayValue.length > 20) return null;
                      
                      return (
                        <span
                          key={key}
                          className="inline-flex items-center px-2 py-0.5 rounded-full text-xs bg-blue-100 text-blue-800"
                          title={`${key}: ${displayValue}`}
                        >
                          {key}: {displayValue}
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Hover effect overlay */}
      <div className="absolute inset-0 rounded-lg opacity-0 hover:opacity-10 bg-current transition-opacity duration-200 pointer-events-none" />
    </div>
  );
});

ResourceCard.displayName = 'ResourceCard';

export default ResourceCard;