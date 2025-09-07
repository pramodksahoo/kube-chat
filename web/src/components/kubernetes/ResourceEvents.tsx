/**
 * ResourceEvents - Chronological event timeline component
 * Displays Kubernetes events with timeline visualization and filtering
 */

import React, { memo, useCallback, useEffect, useState } from 'react';
import { kubernetesApi, type KubernetesEvent, type ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceEventsProps {
  resource: ResourceStatus;
  className?: string;
  autoRefresh?: boolean;
  refreshInterval?: number;
}

export const ResourceEvents: React.FC<ResourceEventsProps> = memo(({
  resource,
  className = '',
  autoRefresh = true,
  refreshInterval = 30000, // 30 seconds
}) => {
  const [events, setEvents] = useState<KubernetesEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<'all' | 'Normal' | 'Warning'>('all');
  const [searchFilter, setSearchFilter] = useState<string>('');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const refreshIntervalRef = React.useRef<NodeJS.Timeout | null>(null);

  // Fetch events from API
  const fetchEvents = useCallback(async () => {
    try {
      setError(null);
      const response = await kubernetesApi.getResourceEvents(
        resource.kind,
        resource.name,
        resource.namespace,
        100 // Limit to 100 events
      );

      // Convert date strings to Date objects and sort by timestamp
      const processedEvents = response.events.map(event => ({
        ...event,
        firstTimestamp: new Date(event.firstTimestamp),
        lastTimestamp: new Date(event.lastTimestamp),
      }));

      setEvents(processedEvents);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch events';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [resource]);

  // Filter and sort events
  const filteredEvents = React.useMemo(() => {
    let filtered = events;

    // Filter by type
    if (filterType !== 'all') {
      filtered = filtered.filter(event => event.type === filterType);
    }

    // Filter by search term
    if (searchFilter.trim()) {
      const searchTerm = searchFilter.toLowerCase();
      filtered = filtered.filter(event =>
        event.reason.toLowerCase().includes(searchTerm) ||
        event.message.toLowerCase().includes(searchTerm) ||
        event.source.component.toLowerCase().includes(searchTerm)
      );
    }

    // Sort by timestamp
    filtered.sort((a, b) => {
      const timeA = a.lastTimestamp.getTime();
      const timeB = b.lastTimestamp.getTime();
      return sortOrder === 'desc' ? timeB - timeA : timeA - timeB;
    });

    return filtered;
  }, [events, filterType, searchFilter, sortOrder]);

  // Format relative time
  const formatRelativeTime = useCallback((date: Date) => {
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMinutes < 1) return 'just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    return `${diffDays}d ago`;
  }, []);

  // Get event type styling
  const getEventTypeStyling = (type: 'Normal' | 'Warning') => {
    return {
      Normal: {
        icon: '✓',
        iconColor: 'text-green-600',
        bgColor: 'bg-green-50',
        borderColor: 'border-green-200',
        textColor: 'text-green-800',
      },
      Warning: {
        icon: '⚠',
        iconColor: 'text-yellow-600',
        bgColor: 'bg-yellow-50',
        borderColor: 'border-yellow-200',
        textColor: 'text-yellow-800',
      },
    }[type];
  };

  // Setup auto-refresh
  useEffect(() => {
    void fetchEvents();

    if (autoRefresh) {
      refreshIntervalRef.current = setInterval(() => void fetchEvents(), refreshInterval);
    }

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [fetchEvents, autoRefresh, refreshInterval]);

  if (loading) {
    return (
      <div className={`resource-events loading ${className}`} data-testid="resource-events-loading">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">Loading events...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`resource-events error ${className}`} data-testid="resource-events-error">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <div className="text-red-600 text-lg font-medium mb-2">
            Failed to load events
          </div>
          <div className="text-red-500 text-sm mb-4">{error}</div>
          <button
            onClick={() => void fetchEvents()}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`resource-events ${className}`} data-testid="resource-events">
      {/* Controls */}
      <div className="events-controls border-b bg-gray-50 p-4 space-y-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* Event type filter */}
          <div className="flex items-center gap-2">
            <label htmlFor="event-type-filter" className="text-sm font-medium text-gray-700">
              Type:
            </label>
            <select
              id="event-type-filter"
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as 'all' | 'Normal' | 'Warning')}
              className="text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">All Events</option>
              <option value="Normal">Normal</option>
              <option value="Warning">Warning</option>
            </select>
          </div>

          {/* Sort order */}
          <div className="flex items-center gap-2">
            <label htmlFor="sort-order" className="text-sm font-medium text-gray-700">
              Sort:
            </label>
            <select
              id="sort-order"
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as 'asc' | 'desc')}
              className="text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="desc">Newest First</option>
              <option value="asc">Oldest First</option>
            </select>
          </div>

          {/* Refresh button */}
          <button
            onClick={() => void fetchEvents()}
            disabled={loading}
            className="px-3 py-1 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
            data-testid="refresh-events-button"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>

        {/* Search filter */}
        <div className="flex items-center gap-2">
          <label htmlFor="event-search" className="text-sm font-medium text-gray-700">
            Search:
          </label>
          <input
            id="event-search"
            type="text"
            placeholder="Search events by reason, message, or component..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="flex-1 max-w-md text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          {searchFilter && (
            <span className="text-sm text-gray-500">
              {filteredEvents.length} of {events.length} events
            </span>
          )}
        </div>
      </div>

      {/* Events timeline */}
      <div className="events-timeline max-h-96 overflow-y-auto" data-testid="events-timeline">
        {filteredEvents.length === 0 ? (
          <div className="flex items-center justify-center py-8 text-gray-500">
            {events.length === 0 ? 'No events found' : 'No events match the filters'}
          </div>
        ) : (
          <div className="timeline-container">
            {filteredEvents.map((event, index) => {
              const styling = getEventTypeStyling(event.type);
              const isLastEvent = index === filteredEvents.length - 1;

              return (
                <div
                  key={`${event.name}-${event.lastTimestamp.getTime()}`}
                  className="timeline-item flex items-start gap-4 p-4 hover:bg-gray-50 relative"
                  data-testid="event-item"
                >
                  {/* Timeline connector */}
                  <div className="timeline-connector flex flex-col items-center">
                    <div
                      className={`timeline-icon w-8 h-8 rounded-full border-2 flex items-center justify-center text-sm font-bold ${styling.bgColor} ${styling.borderColor} ${styling.iconColor}`}
                    >
                      {styling.icon}
                    </div>
                    {!isLastEvent && (
                      <div className="timeline-line w-0.5 bg-gray-200 flex-1 mt-2 min-h-[2rem]" />
                    )}
                  </div>

                  {/* Event details */}
                  <div className="timeline-content flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <h4 className={`font-medium ${styling.textColor}`}>
                          {event.reason}
                        </h4>
                        <p className="text-gray-700 text-sm mt-1 break-words">
                          {event.message}
                        </p>
                      </div>

                      <div className="flex-shrink-0 text-right">
                        <div className="text-sm text-gray-500">
                          {formatRelativeTime(event.lastTimestamp)}
                        </div>
                        {event.count > 1 && (
                          <div className="text-xs text-gray-400">
                            {event.count} times
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Event metadata */}
                    <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-gray-500">
                      <span className="flex items-center gap-1">
                        <span className="font-medium">Source:</span>
                        {event.source.component}
                        {event.source.host !== event.source.component && (
                          <span className="text-gray-400">on {event.source.host}</span>
                        )}
                      </span>

                      <span className="flex items-center gap-1">
                        <span className="font-medium">First seen:</span>
                        {event.firstTimestamp.toLocaleString()}
                      </span>

                      {event.firstTimestamp.getTime() !== event.lastTimestamp.getTime() && (
                        <span className="flex items-center gap-1">
                          <span className="font-medium">Last seen:</span>
                          {event.lastTimestamp.toLocaleString()}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="events-status border-t bg-gray-50 p-2 text-xs text-gray-600 flex justify-between">
        <span>
          {filteredEvents.length} events
          {searchFilter && ` (filtered from ${events.length})`}
          {autoRefresh && (
            <span className="ml-2 text-green-600">
              • Auto-refreshing every {Math.floor(refreshInterval / 1000)}s
            </span>
          )}
        </span>
        <span>
          {resource.kind}/{resource.name}
        </span>
      </div>
    </div>
  );
});

ResourceEvents.displayName = 'ResourceEvents';

export default ResourceEvents;