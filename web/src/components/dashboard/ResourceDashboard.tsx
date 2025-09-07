/**
 * ResourceDashboard - Main dashboard component for Kubernetes resource visualization
 * Provides real-time resource monitoring with WebSocket updates
 */

import React, { useCallback, useMemo, useState } from 'react';
import { useKubernetesResources } from '../../hooks/useKubernetesResources';
import { ResourceCard } from './ResourceCard';
import { ResourceDetailModal } from './ResourceDetailModal';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceDashboardProps {
  namespace?: string;
  kind?: string;
  labelSelector?: string;
  sessionId?: string;
  className?: string;
  autoRefresh?: boolean;
  onResourceSelect?: (resource: ResourceStatus) => void;
}

export const ResourceDashboard: React.FC<ResourceDashboardProps> = ({
  namespace,
  kind,
  labelSelector,
  sessionId,
  className = '',
  autoRefresh = true,
  onResourceSelect,
}) => {
  const [selectedResource, setSelectedResource] = useState<ResourceStatus | null>(null);
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const {
    resources,
    loading,
    error,
    refreshResources,
    isConnected,
    connectionError,
  } = useKubernetesResources({
    namespace,
    kind,
    labelSelector,
    sessionId,
    autoRefresh,
  });

  // Filter resources based on status and search
  const filteredResources = useMemo(() => {
    let filtered = resources;

    // Filter by status
    if (filterStatus !== 'all') {
      filtered = filtered.filter(resource => 
        resource.status.toLowerCase() === filterStatus.toLowerCase()
      );
    }

    // Filter by search query
    if (searchQuery.trim()) {
      const query = searchQuery.toLowerCase().trim();
      filtered = filtered.filter(resource =>
        resource.name.toLowerCase().includes(query) ||
        resource.kind.toLowerCase().includes(query) ||
        (resource.namespace && resource.namespace.toLowerCase().includes(query))
      );
    }

    return filtered;
  }, [resources, filterStatus, searchQuery]);

  // Group resources by kind for better organization
  const resourcesByKind = useMemo(() => {
    const groups: Record<string, ResourceStatus[]> = {};
    filteredResources.forEach(resource => {
      if (!groups[resource.kind]) {
        groups[resource.kind] = [];
      }
      groups[resource.kind].push(resource);
    });
    return groups;
  }, [filteredResources]);

  // Calculate summary statistics
  const summary = useMemo(() => {
    const total = resources.length;
    const ready = resources.filter(r => r.status === 'Ready').length;
    const warning = resources.filter(r => r.status === 'Warning').length;
    const error = resources.filter(r => r.status === 'Error').length;
    const unknown = resources.filter(r => r.status === 'Unknown').length;

    return { total, ready, warning, error, unknown };
  }, [resources]);

  const handleResourceClick = useCallback((resource: ResourceStatus) => {
    setSelectedResource(resource);
    onResourceSelect?.(resource);
  }, [onResourceSelect]);

  const handleCloseModal = useCallback(() => {
    setSelectedResource(null);
  }, []);

  const handleRefresh = useCallback(async () => {
    await refreshResources();
  }, [refreshResources]);

  if (error) {
    return (
      <div 
        className={`resource-dashboard error-state ${className}`}
        data-testid="resource-dashboard-error"
        role="alert"
      >
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <div className="text-red-600 text-lg font-medium mb-2">
            Failed to load resources
          </div>
          <div className="text-red-500 text-sm mb-4">{error}</div>
          <button
            onClick={() => void handleRefresh()}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
            aria-label="Retry loading resources"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div 
      className={`resource-dashboard ${className}`}
      data-testid="resource-dashboard"
    >
      {/* Header with connection status and controls */}
      <div className="dashboard-header mb-6">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-4">
            <h1 className="text-2xl font-bold text-gray-900">
              Resource Dashboard
            </h1>
            
            {/* Connection indicator */}
            <div className="flex items-center gap-2">
              <div 
                className={`w-2 h-2 rounded-full ${
                  isConnected ? 'bg-green-500' : 'bg-red-500'
                }`}
                aria-label={isConnected ? 'Connected' : 'Disconnected'}
              />
              <span className="text-sm text-gray-600">
                {isConnected ? 'Live' : 'Offline'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Refresh button */}
            <button
              onClick={() => void handleRefresh()}
              disabled={loading}
              className="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-blue-500"
              aria-label="Refresh resources"
            >
              {loading ? 'Refreshing...' : 'Refresh'}
            </button>
          </div>
        </div>

        {connectionError && (
          <div className="mt-4 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <div className="text-yellow-800 text-sm">
              <strong>Connection Warning:</strong> {connectionError}
            </div>
          </div>
        )}
      </div>

      {/* Summary statistics */}
      <div className="dashboard-summary mb-6">
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          <div className="bg-white rounded-lg border p-4 text-center">
            <div className="text-2xl font-bold text-gray-900">{summary.total}</div>
            <div className="text-sm text-gray-600">Total</div>
          </div>
          <div className="bg-white rounded-lg border p-4 text-center">
            <div className="text-2xl font-bold text-green-600">{summary.ready}</div>
            <div className="text-sm text-gray-600">Ready</div>
          </div>
          <div className="bg-white rounded-lg border p-4 text-center">
            <div className="text-2xl font-bold text-yellow-600">{summary.warning}</div>
            <div className="text-sm text-gray-600">Warning</div>
          </div>
          <div className="bg-white rounded-lg border p-4 text-center">
            <div className="text-2xl font-bold text-red-600">{summary.error}</div>
            <div className="text-sm text-gray-600">Error</div>
          </div>
          <div className="bg-white rounded-lg border p-4 text-center">
            <div className="text-2xl font-bold text-gray-600">{summary.unknown}</div>
            <div className="text-sm text-gray-600">Unknown</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="dashboard-filters mb-6">
        <div className="bg-white rounded-lg border p-4">
          <div className="flex flex-col sm:flex-row gap-4">
            {/* Search input */}
            <div className="flex-1">
              <label htmlFor="resource-search" className="sr-only">
                Search resources
              </label>
              <input
                id="resource-search"
                type="text"
                placeholder="Search resources..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Search resources by name, kind, or namespace"
              />
            </div>

            {/* Status filter */}
            <div className="sm:w-48">
              <label htmlFor="status-filter" className="sr-only">
                Filter by status
              </label>
              <select
                id="status-filter"
                value={filterStatus}
                onChange={(e) => setFilterStatus(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Filter resources by status"
              >
                <option value="all">All Status</option>
                <option value="ready">Ready</option>
                <option value="warning">Warning</option>
                <option value="error">Error</option>
                <option value="unknown">Unknown</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* Resource grid */}
      <div className="dashboard-content">
        {loading && resources.length === 0 ? (
          <div className="text-center py-12" data-testid="loading-state">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto mb-4"></div>
            <div className="text-gray-600">Loading resources...</div>
          </div>
        ) : filteredResources.length === 0 ? (
          <div className="text-center py-12" data-testid="empty-state">
            <div className="text-gray-400 text-6xl mb-4">📦</div>
            <div className="text-lg font-medium text-gray-900 mb-2">No resources found</div>
            <div className="text-gray-600">
              {searchQuery || filterStatus !== 'all' 
                ? 'Try adjusting your filters' 
                : 'No resources are currently available in this cluster'
              }
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {Object.entries(resourcesByKind).map(([kindName, kindResources]) => (
              <div key={kindName} className="resource-group">
                <h2 className="text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2">
                  {kindName}
                  <span className="bg-gray-100 text-gray-700 px-2 py-1 rounded-full text-sm">
                    {kindResources.length}
                  </span>
                </h2>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                  {kindResources.map((resource) => (
                    <ResourceCard
                      key={`${resource.kind}-${resource.namespace || 'default'}-${resource.name}`}
                      resource={resource}
                      onClick={() => handleResourceClick(resource)}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Resource detail modal */}
      {selectedResource && (
        <ResourceDetailModal
          resource={selectedResource}
          isOpen={true}
          onClose={handleCloseModal}
        />
      )}
    </div>
  );
};

export default ResourceDashboard;