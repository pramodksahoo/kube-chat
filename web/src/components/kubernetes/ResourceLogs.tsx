/**
 * ResourceLogs - Real-time log streaming component
 * Displays container logs with real-time updates and filtering
 */

import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import { kubernetesApi, type ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceLogsProps {
  resource: ResourceStatus;
  className?: string;
  autoScroll?: boolean;
  maxLines?: number;
}

export const ResourceLogs: React.FC<ResourceLogsProps> = memo(({
  resource,
  className = '',
  autoScroll = true,
  maxLines = 1000,
}) => {
  const [logs, setLogs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isFollowing, setIsFollowing] = useState(false);
  const [selectedContainer, setSelectedContainer] = useState<string>('');
  const [tailLines, setTailLines] = useState<number>(100);
  const [searchFilter, setSearchFilter] = useState<string>('');

  const logsEndRef = useRef<HTMLDivElement>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);
  const followIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Auto-scroll to bottom when new logs arrive
  const scrollToBottom = useCallback(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [autoScroll]);

  // Fetch logs from API
  const fetchLogs = useCallback(async (follow = false) => {
    try {
      setError(null);
      if (!follow) setLoading(true);

      const logData = await kubernetesApi.getResourceLogs(
        resource.kind,
        resource.name,
        resource.namespace,
        {
          container: selectedContainer || undefined,
          follow: false, // We handle following manually
          tailLines: tailLines,
        }
      );

      const newLogs = logData.split('\n').filter(line => line.trim() !== '');
      
      if (follow) {
        // For follow mode, append new logs
        setLogs(prevLogs => {
          const combined = [...prevLogs, ...newLogs];
          // Keep only the last maxLines
          return combined.slice(-maxLines);
        });
      } else {
        // For initial load, replace all logs
        setLogs(newLogs.slice(-maxLines));
      }

      setTimeout(scrollToBottom, 100);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to fetch logs';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  }, [resource, selectedContainer, tailLines, maxLines, scrollToBottom]);

  // Start/stop log following
  const toggleFollow = useCallback(() => {
    if (isFollowing) {
      // Stop following
      if (followIntervalRef.current) {
        clearInterval(followIntervalRef.current);
        followIntervalRef.current = null;
      }
      setIsFollowing(false);
    } else {
      // Start following
      setIsFollowing(true);
      followIntervalRef.current = setInterval(() => {
        void fetchLogs(true);
      }, 2000); // Refresh every 2 seconds
    }
  }, [isFollowing, fetchLogs]);

  // Clear logs
  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  // Download logs as file
  const downloadLogs = useCallback(() => {
    const logsText = logs.join('\n');
    const blob = new Blob([logsText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${resource.kind}-${resource.name}-logs.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [logs, resource]);

  // Filter logs based on search
  const filteredLogs = React.useMemo(() => {
    if (!searchFilter.trim()) return logs;
    const filter = searchFilter.toLowerCase();
    return logs.filter(log => log.toLowerCase().includes(filter));
  }, [logs, searchFilter]);

  // Format log line with syntax highlighting
  const formatLogLine = useCallback((line: string, index: number) => {
    // Basic log level highlighting
    let formattedLine = line;
    
    // Highlight log levels
    formattedLine = formattedLine.replace(
      /\b(ERROR|FATAL|CRITICAL)\b/gi,
      '<span class="text-red-400 font-semibold">$1</span>'
    );
    formattedLine = formattedLine.replace(
      /\b(WARN|WARNING)\b/gi,
      '<span class="text-yellow-400 font-semibold">$1</span>'
    );
    formattedLine = formattedLine.replace(
      /\b(INFO|INFORMATION)\b/gi,
      '<span class="text-blue-400 font-semibold">$1</span>'
    );
    formattedLine = formattedLine.replace(
      /\b(DEBUG|TRACE)\b/gi,
      '<span class="text-gray-400">$1</span>'
    );

    // Highlight timestamps
    formattedLine = formattedLine.replace(
      /(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:Z|[+-]\d{2}:\d{2})?)/g,
      '<span class="text-green-400">$1</span>'
    );

    // Highlight JSON structure
    formattedLine = formattedLine.replace(
      /(["{}[\],])/g,
      '<span class="text-purple-300">$1</span>'
    );

    // Highlight search terms
    if (searchFilter.trim()) {
      const regex = new RegExp(`(${searchFilter.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')})`, 'gi');
      formattedLine = formattedLine.replace(regex, '<mark class="bg-yellow-300 text-black">$1</mark>');
    }

    return (
      <div
        key={index}
        className="log-line font-mono text-sm leading-relaxed py-0.5 px-3 hover:bg-gray-800 group"
        data-testid="log-line"
      >
        <span className="text-gray-500 text-xs mr-3 opacity-0 group-hover:opacity-100">
          {index + 1}
        </span>
        <span dangerouslySetInnerHTML={{ __html: formattedLine }} />
      </div>
    );
  }, [searchFilter]);

  // Initial load
  useEffect(() => {
    void fetchLogs();
    return () => {
      if (followIntervalRef.current) {
        clearInterval(followIntervalRef.current);
      }
    };
  }, [fetchLogs]);

  // Handle container change
  useEffect(() => {
    if (selectedContainer !== '') {
      void fetchLogs();
    }
  }, [selectedContainer, fetchLogs]);

  if (loading && logs.length === 0) {
    return (
      <div className={`resource-logs loading ${className}`} data-testid="resource-logs-loading">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">Loading logs...</span>
        </div>
      </div>
    );
  }

  if (error && logs.length === 0) {
    return (
      <div className={`resource-logs error ${className}`} data-testid="resource-logs-error">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <div className="text-red-600 text-lg font-medium mb-2">
            Failed to load logs
          </div>
          <div className="text-red-500 text-sm mb-4">{error}</div>
          <button
            onClick={() => void fetchLogs()}
            className="bg-red-600 text-white px-4 py-2 rounded-md hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className={`resource-logs ${className}`} data-testid="resource-logs">
      {/* Controls */}
      <div className="logs-controls border-b bg-gray-50 p-4 space-y-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* Container selector (if applicable) */}
          {resource.kind === 'Pod' && (
            <div className="flex items-center gap-2">
              <label htmlFor="container-select" className="text-sm font-medium text-gray-700">
                Container:
              </label>
              <select
                id="container-select"
                value={selectedContainer}
                onChange={(e) => setSelectedContainer(e.target.value)}
                className="text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="">Default</option>
                <option value="main">main</option>
                <option value="sidecar">sidecar</option>
              </select>
            </div>
          )}

          {/* Tail lines */}
          <div className="flex items-center gap-2">
            <label htmlFor="tail-lines" className="text-sm font-medium text-gray-700">
              Lines:
            </label>
            <select
              id="tail-lines"
              value={tailLines}
              onChange={(e) => setTailLines(Number(e.target.value))}
              className="text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value={50}>50</option>
              <option value={100}>100</option>
              <option value={500}>500</option>
              <option value={1000}>1000</option>
            </select>
          </div>

          {/* Controls buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={toggleFollow}
              className={`px-3 py-1 text-sm rounded-md font-medium focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                isFollowing
                  ? 'bg-red-600 text-white hover:bg-red-700'
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
              data-testid="follow-button"
            >
              {isFollowing ? 'Stop Following' : 'Follow Logs'}
            </button>

            <button
              onClick={clearLogs}
              className="px-3 py-1 text-sm bg-gray-600 text-white rounded-md hover:bg-gray-700 focus:outline-none focus:ring-2 focus:ring-gray-500"
              data-testid="clear-button"
            >
              Clear
            </button>

            <button
              onClick={downloadLogs}
              className="px-3 py-1 text-sm bg-green-600 text-white rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500"
              disabled={logs.length === 0}
            >
              Download
            </button>
          </div>
        </div>

        {/* Search filter */}
        <div className="flex items-center gap-2">
          <label htmlFor="log-search" className="text-sm font-medium text-gray-700">
            Filter:
          </label>
          <input
            id="log-search"
            type="text"
            placeholder="Search logs..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            className="flex-1 max-w-md text-sm border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          {searchFilter && (
            <span className="text-sm text-gray-500">
              {filteredLogs.length} of {logs.length} lines
            </span>
          )}
        </div>
      </div>

      {/* Logs display */}
      <div 
        className="logs-container bg-gray-900 text-gray-100 overflow-auto max-h-96"
        ref={logsContainerRef}
        data-testid="logs-container"
      >
        {filteredLogs.length === 0 ? (
          <div className="flex items-center justify-center py-8 text-gray-400">
            {logs.length === 0 ? 'No logs available' : 'No logs match the filter'}
          </div>
        ) : (
          <div className="logs-content">
            {filteredLogs.map((line, index) => formatLogLine(line, index))}
            <div ref={logsEndRef} />
          </div>
        )}
        
        {/* Loading indicator for follow mode */}
        {isFollowing && (
          <div className="border-t border-gray-700 p-2 bg-gray-800 text-center text-sm text-gray-400">
            <div className="inline-flex items-center gap-2">
              <div className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></div>
              Following logs...
            </div>
          </div>
        )}
      </div>

      {/* Status bar */}
      <div className="logs-status border-t bg-gray-50 p-2 text-xs text-gray-600 flex justify-between">
        <span>
          {filteredLogs.length} lines {searchFilter && `(filtered from ${logs.length})`}
        </span>
        <span>
          {resource.kind}/{resource.name}
          {selectedContainer && ` (${selectedContainer})`}
        </span>
      </div>
    </div>
  );
});

ResourceLogs.displayName = 'ResourceLogs';

export default ResourceLogs;