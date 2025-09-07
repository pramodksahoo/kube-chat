import React from 'react';
import { ResourceCard } from './ResourceCard';
import type { ResourceStatus } from '../../services/kubernetesApi';

// Demo data for the dashboard
const demoResources: ResourceStatus[] = [
  {
    kind: 'Pod',
    name: 'nginx-deployment-7d8b49ccf-abc12',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date(),
    metadata: {
      labels: { app: 'nginx', version: '1.20' },
      annotations: { 'deployment.kubernetes.io/revision': '1' }
    },
    relationships: []
  },
  {
    kind: 'Service',
    name: 'nginx-service',
    namespace: 'default', 
    status: 'Ready',
    lastUpdated: new Date(),
    metadata: {
      labels: { app: 'nginx' },
      annotations: {}
    },
    relationships: []
  },
  {
    kind: 'Deployment',
    name: 'nginx-deployment',
    namespace: 'default',
    status: 'Ready', 
    lastUpdated: new Date(),
    metadata: {
      labels: { app: 'nginx' },
      annotations: { 'deployment.kubernetes.io/revision': '1' }
    },
    relationships: []
  },
  {
    kind: 'Pod',
    name: 'redis-6b8c4c8f9-def34',
    namespace: 'default',
    status: 'Warning',
    lastUpdated: new Date(),
    metadata: {
      labels: { app: 'redis' },
      annotations: {}
    },
    relationships: []
  },
  {
    kind: 'ConfigMap',
    name: 'app-config',
    namespace: 'default',
    status: 'Ready',
    lastUpdated: new Date(),
    metadata: {
      labels: { app: 'nginx' },
      annotations: {}
    },
    relationships: []
  }
];

export interface DemoDashboardProps {
  className?: string;
}

export const DemoDashboard: React.FC<DemoDashboardProps> = ({ className = '' }) => {
  const resourceCounts = demoResources.reduce((acc, resource) => {
    acc[resource.kind] = (acc[resource.kind] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const statusCounts = demoResources.reduce((acc, resource) => {
    acc[resource.status] = (acc[resource.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Kubernetes Dashboard</h1>
          <p className="text-gray-600">Monitor your cluster resources in real-time</p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 bg-green-500 rounded-full"></div>
          <span className="text-sm text-gray-600">Cluster Connected</span>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-white p-4 rounded-lg shadow border border-gray-200">
          <div className="text-2xl font-bold text-blue-600">{demoResources.length}</div>
          <div className="text-sm text-gray-600">Total Resources</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow border border-gray-200">
          <div className="text-2xl font-bold text-green-600">{statusCounts.Ready || 0}</div>
          <div className="text-sm text-gray-600">Ready</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow border border-gray-200">
          <div className="text-2xl font-bold text-yellow-600">{statusCounts.Warning || 0}</div>
          <div className="text-sm text-gray-600">Warning</div>
        </div>
        <div className="bg-white p-4 rounded-lg shadow border border-gray-200">
          <div className="text-2xl font-bold text-red-600">{statusCounts.Error || 0}</div>
          <div className="text-sm text-gray-600">Error</div>
        </div>
      </div>

      {/* Resource Type Summary */}
      <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Resource Types</h2>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {Object.entries(resourceCounts).map(([kind, count]) => (
            <div key={kind} className="text-center">
              <div className="text-xl font-bold text-gray-900">{count}</div>
              <div className="text-sm text-gray-600">{kind}s</div>
            </div>
          ))}
        </div>
      </div>

      {/* Resource Cards */}
      <div className="space-y-4">
        <h2 className="text-lg font-semibold text-gray-900">Resources</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {demoResources.map((resource, index) => (
            <ResourceCard
              key={`${resource.kind}-${resource.name}-${index}`}
              resource={resource}
              className="h-full"
              onClick={() => console.log('Selected resource:', resource)}
            />
          ))}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-white p-6 rounded-lg shadow border border-gray-200">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Quick Actions</h2>
        <div className="flex flex-wrap gap-2">
          <button className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
            Refresh Resources
          </button>
          <button className="px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 transition-colors">
            Deploy Application
          </button>
          <button className="px-4 py-2 bg-yellow-600 text-white rounded-md hover:bg-yellow-700 transition-colors">
            View Logs
          </button>
          <button className="px-4 py-2 bg-purple-600 text-white rounded-md hover:bg-purple-700 transition-colors">
            Scale Resources
          </button>
        </div>
      </div>
    </div>
  );
};