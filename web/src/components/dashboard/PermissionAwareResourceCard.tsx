/**
 * PermissionAwareResourceCard - ResourceCard with RBAC integration
 * Shows/hides actions and information based on user permissions
 */

import React, { memo } from 'react';
import { ResourceStatusIndicator } from './ResourceStatusIndicator';
import { NamespaceGuard, PermissionButton } from '../auth/PermissionGuard';
import { Can, usePermissions } from '../auth/PermissionProvider';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface PermissionAwareResourceCardProps {
  resource: ResourceStatus;
  onView?: (resource: ResourceStatus) => void;
  onEdit?: (resource: ResourceStatus) => void;
  onDelete?: (resource: ResourceStatus) => void;
  className?: string;
  showNamespace?: boolean;
  compact?: boolean;
  showActions?: boolean;
  enforceNamespaceAccess?: boolean;
}

export const PermissionAwareResourceCard: React.FC<PermissionAwareResourceCardProps> = memo(({
  resource,
  onView,
  onEdit,
  onDelete,
  className = '',
  showNamespace = true,
  compact = false,
  showActions = true,
  enforceNamespaceAccess = true,
}) => {
  const { permissions, loading } = usePermissions();

  // Check if user can view this resource type at all
  const canViewResourceType = permissions.canView[resource.kind.toLowerCase()] || 
                             permissions.canView['*'] || 
                             false;

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
    const iconMap: Record<string, string> = {
      'Pod': '🟢',
      'Service': '🌐',
      'Deployment': '🚀',
      'ConfigMap': '⚙️',
      'Secret': '🔐',
      'Ingress': '🌍',
      'PersistentVolume': '💾',
      'PersistentVolumeClaim': '💽',
      'Namespace': '📁',
      'Node': '🖥️',
    };
    return iconMap[kind] || '📦';
  };

  // If user can't view this resource type, don't render anything
  if (!canViewResourceType) {
    return null;
  }

  const CardContent = () => (
    <div
      className={`resource-card border rounded-lg p-4 bg-white hover:shadow-md transition-shadow ${
        compact ? 'p-3' : ''
      } ${onView ? 'cursor-pointer hover:bg-gray-50' : ''} ${className}`}
      onClick={() => onView?.(resource)}
      onKeyDown={(event) => {
        if ((event.key === 'Enter' || event.key === ' ') && onView) {
          event.preventDefault();
          onView(resource);
        }
      }}
      tabIndex={onView ? 0 : undefined}
      role={onView ? 'button' : undefined}
      data-testid="permission-aware-resource-card"
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className="text-2xl flex-shrink-0">
            {getResourceIcon(resource.kind)}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className="font-medium text-gray-900 truncate">
                {resource.name}
              </h3>
              <span className="text-xs text-gray-500 bg-gray-100 px-2 py-0.5 rounded">
                {resource.kind}
              </span>
            </div>
            
            {showNamespace && resource.namespace && (
              <div className="text-sm text-gray-600">
                <span className="font-medium">Namespace:</span> {resource.namespace}
              </div>
            )}
          </div>
        </div>
        
        <ResourceStatusIndicator 
          status={resource.status}
          size="sm"
          showLabel={!compact}
        />
      </div>

      {/* Metadata */}
      {!compact && (
        <>
          <div className="text-sm text-gray-600 mb-3">
            <div>
              <span className="font-medium">Last Updated:</span> {formatLastUpdated(resource.lastUpdated)}
            </div>
            
            <Can resource={resource.kind.toLowerCase()} action="view">
              {resource.relationships.length > 0 && (
                <div>
                  <span className="font-medium">Relationships:</span> {resource.relationships.length}
                </div>
              )}
            </Can>
          </div>

          {/* Labels - only show if user can view details */}
          <Can resource={resource.kind.toLowerCase()} action="view">
            {resource.metadata.labels && Object.keys(resource.metadata.labels).length > 0 && (
              <div className="mb-3">
                <div className="text-sm font-medium text-gray-700 mb-1">Labels:</div>
                <div className="flex flex-wrap gap-1">
                  {Object.entries(resource.metadata.labels).slice(0, 3).map(([key, value]) => (
                    <span
                      key={key}
                      className="text-xs bg-blue-100 text-blue-800 px-2 py-0.5 rounded"
                    >
                      {key}: {String(value)}
                    </span>
                  ))}
                  {Object.keys(resource.metadata.labels).length > 3 && (
                    <span className="text-xs text-gray-500">
                      +{Object.keys(resource.metadata.labels).length - 3} more
                    </span>
                  )}
                </div>
              </div>
            )}
          </Can>
        </>
      )}

      {/* Action Buttons */}
      {showActions && !loading && (
        <div className="flex items-center gap-2 pt-3 border-t">
          {/* View/Details button */}
          <Can resource={resource.kind.toLowerCase()} action="view">
            <PermissionButton
              resource={resource.kind.toLowerCase()}
              action="view"
              namespace={resource.namespace}
              onClick={() => onView?.(resource)}
              className="px-3 py-1 text-sm bg-blue-600 text-white rounded hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500"
              disabledText="Cannot view details"
            >
              View
            </PermissionButton>
          </Can>

          {/* Edit button */}
          <Can resource={resource.kind.toLowerCase()} action="edit">
            <PermissionButton
              resource={resource.kind.toLowerCase()}
              action="edit"
              namespace={resource.namespace}
              onClick={() => onEdit?.(resource)}
              className="px-3 py-1 text-sm bg-gray-600 text-white rounded hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500"
              disabledText="Cannot edit resource"
              disabled={!onEdit}
            >
              Edit
            </PermissionButton>
          </Can>

          {/* Delete button */}
          <Can resource={resource.kind.toLowerCase()} action="delete">
            <PermissionButton
              resource={resource.kind.toLowerCase()}
              action="delete"
              namespace={resource.namespace}
              onClick={() => onDelete?.(resource)}
              className="px-3 py-1 text-sm bg-red-600 text-white rounded hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
              disabledText="Cannot delete resource"
              disabled={!onDelete}
            >
              Delete
            </PermissionButton>
          </Can>

          {/* Show message if no actions available */}
          <Can resource={resource.kind.toLowerCase()} action="view" fallback={
            <Can resource={resource.kind.toLowerCase()} action="edit" fallback={
              <Can resource={resource.kind.toLowerCase()} action="delete" fallback={
                <span className="text-xs text-gray-400">No actions available</span>
              }>
                {null}
              </Can>
            }>
              {null}
            </Can>
          }>
            {null}
          </Can>
        </div>
      )}

      {/* Permission loading state */}
      {loading && (
        <div className="pt-3 border-t">
          <div className="text-xs text-gray-500 animate-pulse">Loading permissions...</div>
        </div>
      )}
    </div>
  );

  // Wrap with namespace guard if enforcement is enabled
  if (enforceNamespaceAccess && resource.namespace) {
    return (
      <NamespaceGuard
        namespace={resource.namespace}
        fallback={
          <div className="resource-card border rounded-lg p-4 bg-gray-50 opacity-60">
            <div className="flex items-center gap-3">
              <div className="text-xl opacity-50">🔒</div>
              <div>
                <div className="font-medium text-gray-600">{resource.name}</div>
                <div className="text-sm text-gray-500">Access restricted to namespace: {resource.namespace}</div>
              </div>
            </div>
          </div>
        }
      >
        <CardContent />
      </NamespaceGuard>
    );
  }

  return <CardContent />;
});

PermissionAwareResourceCard.displayName = 'PermissionAwareResourceCard';

export default PermissionAwareResourceCard;