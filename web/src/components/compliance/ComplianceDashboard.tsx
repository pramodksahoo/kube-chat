/**
 * ComplianceDashboard - Compliance monitoring and audit visualization
 * Displays audit events, compliance reports, and security metrics
 */

import React, { useCallback, useEffect, useState } from 'react';
import { type AuditEvent, type AuditFilter, auditService, type ComplianceReport } from '../../services/auditService';
import { usePermissions } from '../auth/PermissionProvider';

export interface ComplianceDashboardProps {
  className?: string;
  defaultTimeRange?: '1h' | '24h' | '7d' | '30d';
}

interface TimeRange {
  start: Date;
  end: Date;
  label: string;
}

export const ComplianceDashboard: React.FC<ComplianceDashboardProps> = ({
  className = '',
  defaultTimeRange = '24h',
}) => {
  const { user: _user } = usePermissions();
  
  const [activeTab, setActiveTab] = useState<'events' | 'compliance' | 'security'>('events');
  const [selectedTimeRange, setSelectedTimeRange] = useState(defaultTimeRange);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [complianceReport, setComplianceReport] = useState<ComplianceReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Filters
  const [eventFilter, setEventFilter] = useState<AuditFilter>({});
  const [searchTerm, setSearchTerm] = useState('');

  // Time range options
  const timeRanges: Record<string, TimeRange> = {
    '1h': {
      start: new Date(Date.now() - 60 * 60 * 1000),
      end: new Date(),
      label: 'Last Hour',
    },
    '24h': {
      start: new Date(Date.now() - 24 * 60 * 60 * 1000),
      end: new Date(),
      label: 'Last 24 Hours',
    },
    '7d': {
      start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000),
      end: new Date(),
      label: 'Last 7 Days',
    },
    '30d': {
      start: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
      end: new Date(),
      label: 'Last 30 Days',
    },
  };

  const currentTimeRange = timeRanges[selectedTimeRange];

  // Load audit events
  const loadEvents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const filter: AuditFilter = {
        ...eventFilter,
        startTime: currentTimeRange.start,
        endTime: currentTimeRange.end,
        limit: 100,
      };

      const result = await auditService.searchEvents(filter);
      setEvents(result.events);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load events');
      console.error('Failed to load audit events:', err);
    } finally {
      setLoading(false);
    }
  }, [eventFilter, currentTimeRange]);

  // Load compliance report
  const loadComplianceReport = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const report = await auditService.generateComplianceReport(
        currentTimeRange.start,
        currentTimeRange.end,
        true
      );
      setComplianceReport(report);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate compliance report');
      console.error('Failed to generate compliance report:', err);
    } finally {
      setLoading(false);
    }
  }, [currentTimeRange]);

  // Load data based on active tab
  useEffect(() => {
    switch (activeTab) {
      case 'events':
        void loadEvents();
        break;
      case 'compliance':
      case 'security':
        void loadComplianceReport();
        break;
    }
  }, [activeTab, loadEvents, loadComplianceReport]);

  // Filter events by search term
  const filteredEvents = events.filter(event => {
    if (!searchTerm) return true;
    
    const searchLower = searchTerm.toLowerCase();
    return (
      event.action.toLowerCase().includes(searchLower) ||
      event.userId.toLowerCase().includes(searchLower) ||
      event.resource?.name.toLowerCase().includes(searchLower) ||
      event.resource?.kind.toLowerCase().includes(searchLower) ||
      Object.values(event.details).some(value => 
        String(value).toLowerCase().includes(searchLower)
      )
    );
  });

  // Format timestamp for display
  const formatTimestamp = (date: Date) => {
    return new Intl.DateTimeFormat('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    }).format(new Date(date));
  };

  // Get status color for outcome
  const getOutcomeColor = (outcome: string) => {
    switch (outcome) {
      case 'success': return 'text-green-600 bg-green-100';
      case 'failure': return 'text-yellow-600 bg-yellow-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  // Get severity color
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'text-blue-600 bg-blue-100';
      case 'medium': return 'text-yellow-600 bg-yellow-100';
      case 'high': return 'text-orange-600 bg-orange-100';
      case 'critical': return 'text-red-600 bg-red-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className={`compliance-dashboard ${className}`} data-testid="compliance-dashboard">
      {/* Header */}
      <div className="border-b bg-white p-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-semibold text-gray-900">
              Compliance Dashboard
            </h1>
            <p className="text-gray-600 mt-1">
              Monitor audit events, compliance status, and security metrics
            </p>
          </div>

          {/* Time range selector */}
          <div className="flex items-center gap-4">
            <label htmlFor="time-range" className="text-sm font-medium text-gray-700">
              Time Range:
            </label>
            <select
              id="time-range"
              value={selectedTimeRange}
              onChange={(e) => setSelectedTimeRange(e.target.value as '1h' | '24h' | '7d' | '30d')}
              className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              {Object.entries(timeRanges).map(([key, range]) => (
                <option key={key} value={key}>{range.label}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="mt-6">
          <nav className="flex space-x-8">
            {[
              { key: 'events', label: 'Audit Events', icon: '📋' },
              { key: 'compliance', label: 'Compliance Report', icon: '📊' },
              { key: 'security', label: 'Security Events', icon: '🔒' },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key as any)}
                className={`flex items-center gap-2 px-3 py-2 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.key
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <span>{tab.icon}</span>
                {tab.label}
              </button>
            ))}
          </nav>
        </div>
      </div>

      {/* Content */}
      <div className="p-6">
        {loading && (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mx-auto"></div>
            <p className="text-gray-600 mt-2">Loading...</p>
          </div>
        )}

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
            <div className="text-red-800 font-medium">Error</div>
            <div className="text-red-600 text-sm mt-1">{error}</div>
          </div>
        )}

        {/* Events Tab */}
        {activeTab === 'events' && !loading && (
          <div>
            {/* Search and Filters */}
            <div className="mb-6 space-y-4">
              <div className="flex items-center gap-4">
                <input
                  type="text"
                  placeholder="Search events..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="flex-1 max-w-md border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                
                <select
                  value={eventFilter.outcome || ''}
                  onChange={(e) => setEventFilter(prev => ({ 
                    ...prev, 
                    outcome: e.target.value as any || undefined 
                  }))}
                  className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">All Outcomes</option>
                  <option value="success">Success</option>
                  <option value="failure">Failure</option>
                  <option value="error">Error</option>
                </select>

                <select
                  value={eventFilter.level || ''}
                  onChange={(e) => setEventFilter(prev => ({ 
                    ...prev, 
                    level: e.target.value as any || undefined 
                  }))}
                  className="border border-gray-300 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">All Levels</option>
                  <option value="info">Info</option>
                  <option value="warn">Warning</option>
                  <option value="error">Error</option>
                </select>
              </div>
            </div>

            {/* Events List */}
            <div className="space-y-3">
              {filteredEvents.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  No audit events found for the selected time range and filters.
                </div>
              ) : (
                filteredEvents.map((event) => (
                  <div
                    key={event.id}
                    className="bg-white border rounded-lg p-4 hover:shadow-md transition-shadow"
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <span className="font-medium text-gray-900">
                            {event.action}
                          </span>
                          <span className={`px-2 py-1 text-xs rounded-full ${getOutcomeColor(event.outcome)}`}>
                            {event.outcome}
                          </span>
                          {event.sensitive && (
                            <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-600">
                              Sensitive
                            </span>
                          )}
                        </div>

                        <div className="text-sm text-gray-600 space-y-1">
                          <div>
                            <span className="font-medium">User:</span> {event.userId}
                          </div>
                          {event.resource && (
                            <div>
                              <span className="font-medium">Resource:</span>{' '}
                              {event.resource.kind}/{event.resource.name}
                              {event.resource.namespace && ` (${event.resource.namespace})`}
                            </div>
                          )}
                          <div>
                            <span className="font-medium">Time:</span> {formatTimestamp(event.timestamp)}
                          </div>
                        </div>

                        {event.tags.length > 0 && (
                          <div className="mt-2 flex flex-wrap gap-1">
                            {event.tags.map((tag) => (
                              <span
                                key={tag}
                                className="px-2 py-1 text-xs bg-gray-100 text-gray-600 rounded"
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}

                        {Object.keys(event.details).length > 0 && (
                          <details className="mt-3">
                            <summary className="text-sm text-blue-600 cursor-pointer">
                              View Details
                            </summary>
                            <pre className="mt-2 text-xs bg-gray-50 p-3 rounded overflow-auto">
                              {JSON.stringify(event.details, null, 2)}
                            </pre>
                          </details>
                        )}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Compliance Tab */}
        {activeTab === 'compliance' && !loading && complianceReport && (
          <div className="space-y-6">
            {/* Summary Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-white border rounded-lg p-4">
                <div className="text-2xl font-bold text-gray-900">
                  {complianceReport.summary.totalEvents.toLocaleString()}
                </div>
                <div className="text-sm text-gray-600">Total Events</div>
              </div>
              
              <div className="bg-white border rounded-lg p-4">
                <div className="text-2xl font-bold text-green-600">
                  {complianceReport.summary.successfulActions.toLocaleString()}
                </div>
                <div className="text-sm text-gray-600">Successful Actions</div>
              </div>
              
              <div className="bg-white border rounded-lg p-4">
                <div className="text-2xl font-bold text-yellow-600">
                  {complianceReport.summary.failedActions.toLocaleString()}
                </div>
                <div className="text-sm text-gray-600">Failed Actions</div>
              </div>
              
              <div className="bg-white border rounded-lg p-4">
                <div className="text-2xl font-bold text-blue-600">
                  {complianceReport.summary.uniqueUsers.toLocaleString()}
                </div>
                <div className="text-sm text-gray-600">Unique Users</div>
              </div>
            </div>

            {/* Top Actions */}
            <div className="bg-white border rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Top Actions
              </h3>
              <div className="space-y-2">
                {complianceReport.topActions.map((action) => (
                  <div key={action.action} className="flex justify-between items-center">
                    <span className="text-sm text-gray-700">{action.action}</span>
                    <span className="text-sm font-medium text-gray-900">
                      {action.count.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Compliance Violations */}
            {complianceReport.complianceViolations.length > 0 && (
              <div className="bg-white border rounded-lg p-6">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Compliance Violations
                </h3>
                <div className="space-y-4">
                  {complianceReport.complianceViolations.map((violation, index) => (
                    <div key={index} className="border-l-4 border-red-400 pl-4">
                      <div className="flex items-center gap-2 mb-2">
                        <span className="font-medium text-gray-900">
                          {violation.type}
                        </span>
                        <span className={`px-2 py-1 text-xs rounded-full ${getSeverityColor(violation.severity)}`}>
                          {violation.severity}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 mb-2">
                        {violation.description}
                      </p>
                      <div className="text-sm text-gray-500">
                        {violation.events.length} related events
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Security Tab */}
        {activeTab === 'security' && !loading && complianceReport && (
          <div className="space-y-6">
            <div className="bg-white border rounded-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">
                Security Events
              </h3>
              
              {complianceReport.securityEvents.length === 0 ? (
                <div className="text-center py-8 text-gray-500">
                  No security events found for the selected time range.
                </div>
              ) : (
                <div className="space-y-3">
                  {complianceReport.securityEvents.map((event) => (
                    <div
                      key={event.id}
                      className="border rounded-lg p-4 bg-red-50 border-red-200"
                    >
                      <div className="flex items-center gap-2 mb-2">
                        <span className="font-medium text-red-900">
                          🔒 {event.action}
                        </span>
                        <span className="px-2 py-1 text-xs rounded-full bg-red-100 text-red-600">
                          Security Event
                        </span>
                      </div>
                      
                      <div className="text-sm text-red-700 space-y-1">
                        <div>
                          <span className="font-medium">User:</span> {event.userId}
                        </div>
                        <div>
                          <span className="font-medium">Time:</span> {formatTimestamp(event.timestamp)}
                        </div>
                        {event.resource && (
                          <div>
                            <span className="font-medium">Resource:</span>{' '}
                            {event.resource.kind}/{event.resource.name}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ComplianceDashboard;