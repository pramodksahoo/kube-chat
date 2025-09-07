/**
 * ResourceDetailModal - Detailed resource information modal
 * Provides tabbed interface for describe, logs, and events
 */

import React, { memo, useEffect, useState } from 'react';
import { ResourceStatusIndicator } from './ResourceStatusIndicator';
import { ResourceDescribe } from '../kubernetes/ResourceDescribe';
import { ResourceLogs } from '../kubernetes/ResourceLogs';
import { ResourceEvents } from '../kubernetes/ResourceEvents';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceDetailModalProps {
  resource: ResourceStatus;
  isOpen: boolean;
  onClose: () => void;
  className?: string;
  defaultTab?: 'describe' | 'logs' | 'events';
}

type TabId = 'describe' | 'logs' | 'events';

export const ResourceDetailModal: React.FC<ResourceDetailModalProps> = memo(({
  resource,
  isOpen,
  onClose,
  className = '',
  defaultTab = 'describe',
}) => {
  const [activeTab, setActiveTab] = useState<TabId>(defaultTab);

  // Handle escape key to close modal
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        onClose();
      }
    };

    if (isOpen) {
      document.addEventListener('keydown', handleEscape);
      document.body.style.overflow = 'hidden';
    }

    return () => {
      document.removeEventListener('keydown', handleEscape);
      document.body.style.overflow = '';
    };
  }, [isOpen, onClose]);

  // Reset tab when modal opens or resource changes
  useEffect(() => {
    if (isOpen) {
      setActiveTab(defaultTab);
    }
  }, [isOpen, resource, defaultTab]);

  // Tab configuration
  const tabs: Array<{ id: TabId; label: string; icon: string }> = [
    { id: 'describe', label: 'Describe', icon: '📋' },
    { id: 'logs', label: 'Logs', icon: '📄' },
    { id: 'events', label: 'Events', icon: '📅' },
  ];

  // Filter tabs based on resource type
  const availableTabs = tabs.filter(tab => {
    // Events are available for all resources
    if (tab.id === 'events') return true;
    
    // Logs are only available for pods and some other resource types
    if (tab.id === 'logs') {
      return ['Pod', 'Job', 'CronJob'].includes(resource.kind);
    }
    
    // Describe is available for all resources
    return true;
  });

  // Ensure active tab is available for this resource
  useEffect(() => {
    if (!availableTabs.find(tab => tab.id === activeTab)) {
      setActiveTab(availableTabs[0]?.id || 'describe');
    }
  }, [activeTab, availableTabs]);

  if (!isOpen) return null;

  const renderTabContent = () => {
    switch (activeTab) {
      case 'describe':
        return <ResourceDescribe resource={resource} />;
      case 'logs':
        return <ResourceLogs resource={resource} />;
      case 'events':
        return <ResourceEvents resource={resource} />;
      default:
        return <ResourceDescribe resource={resource} />;
    }
  };

  return (
    <div
      className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${className}`}
      data-testid="resource-detail-modal"
    >
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black bg-opacity-50"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Modal content */}
      <div
        className="relative bg-white rounded-lg shadow-xl max-w-6xl w-full max-h-[90vh] overflow-hidden flex flex-col"
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        {/* Modal header */}
        <div className="flex items-center justify-between p-6 border-b bg-white flex-shrink-0">
          <div className="flex items-center gap-4">
            <h2 id="modal-title" className="text-xl font-semibold text-gray-900">
              {resource.kind}/{resource.name}
            </h2>
            {resource.namespace && (
              <span className="text-sm text-gray-500 bg-gray-100 px-2 py-1 rounded">
                {resource.namespace}
              </span>
            )}
            <ResourceStatusIndicator 
              status={resource.status}
              size="md"
              showLabel={true}
              showIcon={true}
            />
          </div>
          
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 focus:outline-none focus:ring-2 focus:ring-blue-500 rounded p-1"
            aria-label="Close modal"
            data-testid="close-modal-button"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Tab navigation */}
        <div className="flex border-b bg-gray-50 flex-shrink-0">
          {availableTabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-6 py-3 text-sm font-medium border-b-2 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-inset ${
                activeTab === tab.id
                  ? 'border-blue-600 text-blue-600 bg-white'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              }`}
              data-testid={`tab-${tab.id}`}
              aria-selected={activeTab === tab.id}
              role="tab"
            >
              <span aria-hidden="true">{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        <div 
          className="flex-1 overflow-hidden"
          role="tabpanel"
          aria-labelledby={`tab-${activeTab}`}
          data-testid={`tabpanel-${activeTab}`}
        >
          {renderTabContent()}
        </div>
      </div>
    </div>
  );
});

ResourceDetailModal.displayName = 'ResourceDetailModal';

export default ResourceDetailModal;