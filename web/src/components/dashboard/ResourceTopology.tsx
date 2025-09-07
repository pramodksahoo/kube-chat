/**
 * ResourceTopology - Container component for different topology layouts
 * Provides switching between graph, tree, and namespace layouts
 */

import React, { memo, useState } from 'react';
import { ResourceRelationshipGraph } from './ResourceRelationshipGraph';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceTopologyProps {
  resources: ResourceStatus[];
  selectedResource?: ResourceStatus | null;
  onResourceSelect?: (resource: ResourceStatus) => void;
  onResourceHover?: (resource: ResourceStatus | null) => void;
  className?: string;
  defaultLayout?: 'graph' | 'tree' | 'namespace';
}

type LayoutType = 'graph' | 'tree' | 'namespace';

export const ResourceTopology: React.FC<ResourceTopologyProps> = memo(({
  resources,
  selectedResource,
  onResourceSelect,
  onResourceHover,
  className = '',
  defaultLayout = 'graph',
}) => {
  const [activeLayout, setActiveLayout] = useState<LayoutType>(defaultLayout);
  const [selectedNamespace, setSelectedNamespace] = useState<string>('');
  const [showLabels, setShowLabels] = useState(true);

  // Get unique namespaces from resources
  const namespaces = React.useMemo(() => {
    const namespaceSet = new Set<string>();
    resources.forEach(resource => {
      if (resource.namespace) {
        namespaceSet.add(resource.namespace);
      }
    });
    return Array.from(namespaceSet).sort();
  }, [resources]);

  // Group resources by namespace
  const resourcesByNamespace = React.useMemo(() => {
    const groups: Record<string, ResourceStatus[]> = {};
    resources.forEach(resource => {
      const namespace = resource.namespace || 'cluster-scoped';
      if (!groups[namespace]) {
        groups[namespace] = [];
      }
      groups[namespace].push(resource);
    });
    return groups;
  }, [resources]);

  // Calculate statistics
  const stats = React.useMemo(() => {
    const totalResources = resources.length;
    const totalNamespaces = namespaces.length;
    const totalRelationships = resources.reduce((sum, resource) => sum + resource.relationships.length, 0);
    
    const statusCounts = resources.reduce((counts, resource) => {
      counts[resource.status] = (counts[resource.status] || 0) + 1;
      return counts;
    }, {} as Record<string, number>);

    return {
      totalResources,
      totalNamespaces,
      totalRelationships,
      statusCounts,
    };
  }, [resources, namespaces]);

  const renderTreeLayout = () => (
    <div className="tree-layout p-4" data-testid="tree-layout">
      <div className="text-center text-gray-500 py-8">
        <div className="text-4xl mb-4">🌳</div>
        <div className="text-lg font-medium mb-2">Tree Layout</div>
        <div className="text-sm">Hierarchical tree view coming soon</div>
      </div>
    </div>
  );

  const renderNamespaceLayout = () => (
    <div className="namespace-layout" data-testid="namespace-layout">
      {/* Namespace selector */}
      <div className="border-b bg-gray-50 p-4">
        <div className="flex items-center gap-4">
          <label htmlFor="namespace-select" className="text-sm font-medium text-gray-700">
            Namespace:
          </label>
          <select
            id="namespace-select"
            value={selectedNamespace}
            onChange={(e) => setSelectedNamespace(e.target.value)}
            className="text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            data-testid="namespace-selector"
          >
            <option value="">All Namespaces</option>
            {namespaces.map(ns => (
              <option key={ns} value={ns}>{ns}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Namespace-grouped resources */}
      <div className="p-4 max-h-96 overflow-y-auto">
        {Object.entries(resourcesByNamespace)
          .filter(([ns]) => !selectedNamespace || ns === selectedNamespace)
          .map(([namespace, namespaceResources]) => (
            <div key={namespace} className="mb-6">
              <h3 className="text-lg font-semibold text-gray-800 mb-3 flex items-center gap-2">
                <span className="w-3 h-3 bg-blue-500 rounded"></span>
                {namespace}
                <span className="text-sm text-gray-500 font-normal">
                  ({namespaceResources.length} resources)
                </span>
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 ml-4">
                {namespaceResources.map(resource => (
                  <div
                    key={`${resource.kind}-${resource.name}`}
                    className={`resource-item p-3 border rounded-lg cursor-pointer transition-colors ${
                      selectedResource?.name === resource.name &&
                      selectedResource?.kind === resource.kind &&
                      selectedResource?.namespace === resource.namespace
                        ? 'border-blue-500 bg-blue-50'
                        : 'border-gray-200 hover:border-gray-300 hover:bg-gray-50'
                    }`}
                    onClick={() => onResourceSelect?.(resource)}
                    data-testid="namespace-resource-item"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-gray-900 truncate">
                          {resource.name}
                        </div>
                        <div className="text-sm text-gray-500">
                          {resource.kind}
                        </div>
                      </div>
                      <div className={`w-3 h-3 rounded-full ${
                        resource.status === 'Ready' ? 'bg-green-500' :
                        resource.status === 'Warning' ? 'bg-yellow-500' :
                        resource.status === 'Error' ? 'bg-red-500' :
                        'bg-gray-400'
                      }`} />
                    </div>
                    
                    {resource.relationships.length > 0 && (
                      <div className="mt-2 text-xs text-gray-500">
                        {resource.relationships.length} relationship{resource.relationships.length !== 1 ? 's' : ''}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))
        }
      </div>
    </div>
  );

  const renderActiveLayout = () => {
    switch (activeLayout) {
      case 'graph':
        return (
          <ResourceRelationshipGraph
            resources={resources}
            selectedResource={selectedResource}
            onResourceSelect={onResourceSelect}
            onResourceHover={onResourceHover}
            showLabels={showLabels}
            filterByNamespace={selectedNamespace || undefined}
          />
        );
      case 'tree':
        return renderTreeLayout();
      case 'namespace':
        return renderNamespaceLayout();
      default:
        return renderTreeLayout();
    }
  };

  return (
    <div className={`resource-topology ${className}`} data-testid="resource-topology">
      {/* Header with layout switcher and controls */}
      <div className="topology-header border-b bg-white p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <h3 className="text-lg font-semibold text-gray-900">
              Resource Topology
            </h3>
            
            {/* Layout switcher */}
            <div className="flex border border-gray-300 rounded-lg overflow-hidden">
              <button
                onClick={() => setActiveLayout('graph')}
                className={`px-3 py-1 text-sm font-medium transition-colors ${
                  activeLayout === 'graph'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
                data-testid="layout-graph-button"
              >
                Graph
              </button>
              <button
                onClick={() => setActiveLayout('tree')}
                className={`px-3 py-1 text-sm font-medium transition-colors border-l ${
                  activeLayout === 'tree'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
                data-testid="layout-tree-button"
              >
                Tree
              </button>
              <button
                onClick={() => setActiveLayout('namespace')}
                className={`px-3 py-1 text-sm font-medium transition-colors border-l ${
                  activeLayout === 'namespace'
                    ? 'bg-blue-600 text-white'
                    : 'bg-white text-gray-700 hover:bg-gray-50'
                }`}
                data-testid="layout-namespace-button"
              >
                Namespace
              </button>
            </div>
          </div>

          {/* Controls */}
          <div className="flex items-center gap-4">
            {activeLayout === 'graph' && (
              <label className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={showLabels}
                  onChange={(e) => setShowLabels(e.target.checked)}
                  className="rounded border-gray-300 focus:ring-2 focus:ring-blue-500"
                  data-testid="show-labels-checkbox"
                />
                Show Labels
              </label>
            )}
            
            {(activeLayout === 'graph' || activeLayout === 'namespace') && (
              <div className="flex items-center gap-2">
                <label htmlFor="topology-namespace" className="text-sm font-medium text-gray-700">
                  Filter:
                </label>
                <select
                  id="topology-namespace"
                  value={selectedNamespace}
                  onChange={(e) => setSelectedNamespace(e.target.value)}
                  className="text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                  data-testid="topology-namespace-filter"
                >
                  <option value="">All Namespaces</option>
                  {namespaces.map(ns => (
                    <option key={ns} value={ns}>{ns}</option>
                  ))}
                </select>
              </div>
            )}
          </div>
        </div>

        {/* Statistics */}
        <div className="mt-4 flex flex-wrap items-center gap-6 text-sm text-gray-600">
          <div className="flex items-center gap-1">
            <span className="font-medium">Resources:</span>
            <span>{stats.totalResources}</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="font-medium">Namespaces:</span>
            <span>{stats.totalNamespaces}</span>
          </div>
          <div className="flex items-center gap-1">
            <span className="font-medium">Relationships:</span>
            <span>{stats.totalRelationships}</span>
          </div>
          
          {/* Status distribution */}
          <div className="flex items-center gap-2">
            <span className="font-medium">Status:</span>
            {Object.entries(stats.statusCounts).map(([status, count]) => (
              <div key={status} className="flex items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${
                  status === 'Ready' ? 'bg-green-500' :
                  status === 'Warning' ? 'bg-yellow-500' :
                  status === 'Error' ? 'bg-red-500' :
                  'bg-gray-400'
                }`} />
                <span className="text-xs">{count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Layout content */}
      <div className="topology-content">
        {renderActiveLayout()}
      </div>
    </div>
  );
});

ResourceTopology.displayName = 'ResourceTopology';

export default ResourceTopology;