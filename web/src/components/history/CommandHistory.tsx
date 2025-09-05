import React, { useMemo, useState } from 'react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/ui/button';
import SafetyIndicator from '@/components/safety/SafetyIndicator';
import type { SafetyLevel } from '@/components/safety/SafetyIndicator';

export interface HistoryEntry {
  id: string;
  command: string;
  timestamp: string;
  status: 'completed' | 'failed' | 'cancelled';
  duration: number;
  safetyLevel: SafetyLevel;
  exitCode?: number;
  output?: string;
  error?: string;
  userId?: string;
  tags?: string[];
}

export interface CommandHistoryProps {
  entries: HistoryEntry[];
  onRerun?: (entry: HistoryEntry) => void;
  onDelete?: (entryId: string) => void;
  onExport?: (entries: HistoryEntry[]) => void;
  onClearAll?: () => void;
  maxEntries?: number;
  className?: string;
}

const CommandHistory: React.FC<CommandHistoryProps> = ({
  entries,
  onRerun,
  onDelete,
  onExport,
  onClearAll,
  maxEntries = 50,
  className,
}) => {
  const [filter, setFilter] = useState<'all' | 'completed' | 'failed'>('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedEntries, setSelectedEntries] = useState<Set<string>>(new Set());
  const [sortBy, setSortBy] = useState<'timestamp' | 'duration' | 'command'>('timestamp');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  const filteredAndSortedEntries = useMemo(() => {
    let filtered = entries;

    // Apply status filter
    if (filter !== 'all') {
      filtered = filtered.filter(entry => entry.status === filter);
    }

    // Apply search filter
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      filtered = filtered.filter(entry => 
        entry.command.toLowerCase().includes(term) ||
        entry.output?.toLowerCase().includes(term) ||
        entry.error?.toLowerCase().includes(term) ||
        entry.tags?.some(tag => tag.toLowerCase().includes(term))
      );
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let comparison = 0;
      
      switch (sortBy) {
        case 'timestamp':
          comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
          break;
        case 'duration':
          comparison = a.duration - b.duration;
          break;
        case 'command':
          comparison = a.command.localeCompare(b.command);
          break;
      }

      return sortOrder === 'desc' ? -comparison : comparison;
    });

    return filtered.slice(0, maxEntries);
  }, [entries, filter, searchTerm, sortBy, sortOrder, maxEntries]);

  const formatTimestamp = (timestamp: string): string => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMinutes = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMinutes / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffMinutes < 1) return 'Just now';
    if (diffMinutes < 60) return `${diffMinutes}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString();
  };

  const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  };

  const getStatusIcon = (status: HistoryEntry['status']) => {
    switch (status) {
      case 'completed':
        return (
          <div className="w-4 h-4 bg-green-500 rounded-full flex items-center justify-center">
            <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
          </div>
        );
      case 'failed':
        return (
          <div className="w-4 h-4 bg-red-500 rounded-full flex items-center justify-center">
            <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </div>
        );
      case 'cancelled':
        return (
          <div className="w-4 h-4 bg-gray-500 rounded-full flex items-center justify-center">
            <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
          </div>
        );
    }
  };

  const toggleSelection = (entryId: string) => {
    const newSelection = new Set(selectedEntries);
    if (newSelection.has(entryId)) {
      newSelection.delete(entryId);
    } else {
      newSelection.add(entryId);
    }
    setSelectedEntries(newSelection);
  };

  const selectAll = () => {
    if (selectedEntries.size === filteredAndSortedEntries.length) {
      setSelectedEntries(new Set());
    } else {
      setSelectedEntries(new Set(filteredAndSortedEntries.map(entry => entry.id)));
    }
  };

  const deleteSelected = () => {
    if (onDelete) {
      selectedEntries.forEach(entryId => onDelete(entryId));
      setSelectedEntries(new Set());
    }
  };

  const exportSelected = () => {
    if (onExport) {
      const entriesToExport = selectedEntries.size > 0 
        ? filteredAndSortedEntries.filter(entry => selectedEntries.has(entry.id))
        : filteredAndSortedEntries;
      onExport(entriesToExport);
    }
  };

  const getFilterCount = (status: 'all' | 'completed' | 'failed') => {
    if (status === 'all') return entries.length;
    return entries.filter(entry => entry.status === status).length;
  };

  if (entries.length === 0) {
    return (
      <div className={cn('bg-gray-50 rounded-lg p-8 text-center', className)}>
        <div className="text-gray-400 mb-4">
          <svg className="w-12 h-12 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
          </svg>
        </div>
        <h3 className="text-sm font-medium text-gray-900 mb-1">No command history</h3>
        <p className="text-sm text-gray-600">Your executed commands will appear here</p>
      </div>
    );
  }

  return (
    <div className={cn('bg-white rounded-lg shadow-sm border border-gray-200', className)}>
      {/* Header */}
      <div className="px-4 py-3 border-b border-gray-200">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">Command History</h2>
          <div className="flex items-center space-x-2">
            {selectedEntries.size > 0 && (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={deleteSelected}
                  className="text-red-600 border-red-300 hover:bg-red-50"
                >
                  Delete Selected
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={exportSelected}
                >
                  Export Selected
                </Button>
              </>
            )}
            {onExport && (
              <Button
                variant="outline"
                size="sm"
                onClick={exportSelected}
              >
                Export All
              </Button>
            )}
            {onClearAll && entries.length > 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={onClearAll}
                className="text-red-600 border-red-300 hover:bg-red-50"
              >
                Clear All
              </Button>
            )}
          </div>
        </div>

        {/* Filters and Search */}
        <div className="flex items-center space-x-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Search commands, output, or tags..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-md text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
          
          <div className="flex items-center space-x-2">
            <span className="text-xs text-gray-500">Filter:</span>
            <div className="flex bg-white rounded-md border border-gray-300">
              {[
                { key: 'all', label: 'All', count: getFilterCount('all') },
                { key: 'completed', label: 'Success', count: getFilterCount('completed') },
                { key: 'failed', label: 'Failed', count: getFilterCount('failed') },
              ].map(({ key, label, count }) => (
                <button
                  key={key}
                  onClick={() => setFilter(key as typeof filter)}
                  className={cn(
                    'px-3 py-1 text-xs font-medium first:rounded-l-md last:rounded-r-md',
                    filter === key
                      ? 'bg-blue-50 text-blue-700 border-r border-blue-200'
                      : 'text-gray-600 hover:text-gray-900 border-r border-gray-300 last:border-r-0'
                  )}
                >
                  {label} ({count})
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs text-gray-500">Sort:</span>
            <select
              value={`${sortBy}-${sortOrder}`}
              onChange={(e) => {
                const [newSortBy, newSortOrder] = e.target.value.split('-');
                setSortBy(newSortBy as typeof sortBy);
                setSortOrder(newSortOrder as typeof sortOrder);
              }}
              className="text-xs border border-gray-300 rounded px-2 py-1"
            >
              <option value="timestamp-desc">Newest First</option>
              <option value="timestamp-asc">Oldest First</option>
              <option value="duration-desc">Longest First</option>
              <option value="duration-asc">Shortest First</option>
              <option value="command-asc">Command A-Z</option>
              <option value="command-desc">Command Z-A</option>
            </select>
          </div>
        </div>

        {/* Bulk Actions */}
        {filteredAndSortedEntries.length > 0 && (
          <div className="flex items-center justify-between mt-4 text-sm">
            <label className="flex items-center space-x-2">
              <input
                type="checkbox"
                checked={selectedEntries.size === filteredAndSortedEntries.length && filteredAndSortedEntries.length > 0}
                onChange={selectAll}
                className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
              />
              <span className="text-gray-600">
                Select All ({selectedEntries.size} selected)
              </span>
            </label>
            <span className="text-gray-500">
              Showing {filteredAndSortedEntries.length} of {entries.length} commands
            </span>
          </div>
        )}
      </div>

      {/* History List */}
      <div className="divide-y divide-gray-200">
        {filteredAndSortedEntries.map((entry) => (
          <div key={entry.id} className="px-4 py-4 hover:bg-gray-50">
            <div className="flex items-start space-x-3">
              <label className="flex items-center mt-1">
                <input
                  type="checkbox"
                  checked={selectedEntries.has(entry.id)}
                  onChange={() => toggleSelection(entry.id)}
                  className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                />
              </label>

              <div className="flex-shrink-0 mt-1">
                {getStatusIcon(entry.status)}
              </div>

              <div className="flex-grow min-w-0">
                <div className="flex items-start justify-between">
                  <div className="flex-grow">
                    <div className="flex items-center space-x-2 mb-1">
                      <SafetyIndicator
                        level={entry.safetyLevel}
                        variant="badge"
                        size="sm"
                      />
                      <span className="text-xs text-gray-500">
                        {formatTimestamp(entry.timestamp)}
                      </span>
                      <span className="text-xs text-gray-500">
                        {formatDuration(entry.duration)}
                      </span>
                      {entry.exitCode !== undefined && (
                        <span className={cn(
                          'text-xs px-1 py-0.5 rounded',
                          entry.exitCode === 0 
                            ? 'bg-green-100 text-green-800'
                            : 'bg-red-100 text-red-800'
                        )}>
                          Exit: {entry.exitCode}
                        </span>
                      )}
                    </div>

                    <div className="bg-gray-100 p-2 rounded font-mono text-sm mb-2 overflow-x-auto">
                      <code>{entry.command}</code>
                    </div>

                    {entry.tags && entry.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mb-2">
                        {entry.tags.map((tag) => (
                          <span
                            key={tag}
                            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}

                    {entry.error && (
                      <div className="text-xs text-red-600 bg-red-50 p-2 rounded mb-2">
                        {entry.error}
                      </div>
                    )}
                  </div>

                  <div className="flex items-center space-x-1 ml-4">
                    {onRerun && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onRerun(entry)}
                        className="text-gray-600 border-gray-300 hover:bg-gray-50"
                      >
                        Rerun
                      </Button>
                    )}
                    {onDelete && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onDelete(entry.id)}
                        className="text-red-600 border-red-300 hover:bg-red-50"
                      >
                        Delete
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {filteredAndSortedEntries.length === 0 && (
        <div className="px-4 py-8 text-center text-gray-500">
          <p>No commands match your current filters</p>
          <button
            onClick={() => {
              setFilter('all');
              setSearchTerm('');
            }}
            className="mt-2 text-sm text-blue-600 hover:text-blue-800 underline"
          >
            Clear filters
          </button>
        </div>
      )}
    </div>
  );
};

export default CommandHistory;