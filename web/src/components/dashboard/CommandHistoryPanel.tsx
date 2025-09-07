/**
 * Command History Panel - Display and manage command execution history
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertCircle, CheckCircle, Clock, Eye, Filter, RotateCcw, Search, TrendingUp, XCircle } from 'lucide-react';
import { 
  type CommandHistoryFilter, 
  type CommandRecord,
  type ImpactSummary, 
  useCommandHistory,
  useCommandTracking 
} from '../../services/commandHistoryService';
import { usePermissions } from '../auth/PermissionProvider';
import { useAuditLogging } from '../../services/auditService';

interface CommandHistoryPanelProps {
  className?: string;
  onCommandSelect?: (command: CommandRecord) => void;
  userId?: string;
  sessionId?: string;
  showStatistics?: boolean;
}

const CommandHistoryPanel: React.FC<CommandHistoryPanelProps> = ({
  className = '',
  onCommandSelect,
  userId,
  sessionId,
  showStatistics = true,
}) => {
  const { user } = usePermissions();
  const { logDashboardInteraction } = useAuditLogging(user || undefined);
  const { searchCommands, generateRollbackCommand, getCommandStatistics } = useCommandHistory();
  const { activeCommands, clearCompletedCommands } = useCommandTracking(userId, sessionId);
  
  const [commands, setCommands] = useState<CommandRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<CommandHistoryFilter>({
    limit: 50,
    offset: 0,
  });
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedStatus, setSelectedStatus] = useState<CommandRecord['status'] | 'all'>('all');
  const [selectedImpact, setSelectedImpact] = useState<ImpactSummary['potentialImpact'] | 'all'>('all');
  const [showFilters, setShowFilters] = useState(false);
  const [statistics, setStatistics] = useState<any>(null);

  // Load command history
  const loadCommands = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const searchFilter: CommandHistoryFilter = {
        ...filter,
        command: searchQuery || undefined,
        status: selectedStatus !== 'all' ? selectedStatus : undefined,
        impactLevel: selectedImpact !== 'all' ? selectedImpact : undefined,
        userId: filter.userId || userId,
      };

      const result = await searchCommands(searchFilter);
      setCommands(result.commands);

      logDashboardInteraction('search', {
        searchType: 'command_history',
        queryLength: searchQuery.length,
        filterCount: Object.keys(searchFilter).length,
        resultCount: result.commands.length,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load command history');
    } finally {
      setLoading(false);
    }
  }, [filter, searchQuery, selectedStatus, selectedImpact, userId, searchCommands, logDashboardInteraction]);

  // Load statistics
  const loadStatistics = useCallback(async () => {
    if (!showStatistics) return;

    try {
      const endTime = new Date();
      const startTime = new Date();
      startTime.setDate(startTime.getDate() - 7); // Last 7 days

      const stats = await getCommandStatistics({ start: startTime, end: endTime });
      setStatistics(stats);
    } catch (err) {
      console.warn('Failed to load command statistics:', err);
    }
  }, [showStatistics, getCommandStatistics]);

  useEffect(() => {
    void loadCommands();
  }, [loadCommands]);

  useEffect(() => {
    void loadStatistics();
  }, [loadStatistics]);

  // Handle search
  const handleSearch = (query: string) => {
    setSearchQuery(query);
    setFilter(prev => ({ ...prev, offset: 0 }));
  };

  // Handle status filter
  const handleStatusFilter = (status: CommandRecord['status'] | 'all') => {
    setSelectedStatus(status);
    setFilter(prev => ({ ...prev, offset: 0 }));
  };

  // Handle impact filter
  const handleImpactFilter = (impact: ImpactSummary['potentialImpact'] | 'all') => {
    setSelectedImpact(impact);
    setFilter(prev => ({ ...prev, offset: 0 }));
  };

  // Handle rollback
  const handleRollback = async (commandId: string) => {
    try {
      const rollbackCommand = await generateRollbackCommand(commandId);
      if (rollbackCommand) {
        // Display rollback command or execute it
        console.log('Rollback command:', rollbackCommand);
        
        logDashboardInteraction('view', {
          action: 'generate_rollback',
          commandId,
          rollbackGenerated: true,
        });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate rollback command');
    }
  };

  // Render status indicator
  const renderStatusIndicator = (status: CommandRecord['status']) => {
    const statusConfig = {
      pending: { icon: Clock, color: 'text-yellow-500', bg: 'bg-yellow-50', label: 'Pending' },
      executing: { icon: Clock, color: 'text-blue-500', bg: 'bg-blue-50', label: 'Executing' },
      completed: { icon: CheckCircle, color: 'text-green-500', bg: 'bg-green-50', label: 'Completed' },
      failed: { icon: XCircle, color: 'text-red-500', bg: 'bg-red-50', label: 'Failed' },
      cancelled: { icon: XCircle, color: 'text-gray-500', bg: 'bg-gray-50', label: 'Cancelled' },
    };

    const config = statusConfig[status];
    const IconComponent = config.icon;

    return (
      <div className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${config.bg} ${config.color}`}>
        <IconComponent className="w-3 h-3 mr-1" />
        {config.label}
      </div>
    );
  };

  // Render impact indicator
  const renderImpactIndicator = (impact: ImpactSummary['potentialImpact']) => {
    const impactConfig = {
      low: { color: 'text-green-600', bg: 'bg-green-100', label: 'Low' },
      medium: { color: 'text-yellow-600', bg: 'bg-yellow-100', label: 'Medium' },
      high: { color: 'text-orange-600', bg: 'bg-orange-100', label: 'High' },
      critical: { color: 'text-red-600', bg: 'bg-red-100', label: 'Critical' },
    };

    const config = impactConfig[impact];

    return (
      <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${config.bg} ${config.color}`}>
        {config.label}
      </span>
    );
  };

  // Statistics component
  const StatisticsPanel = () => {
    if (!statistics) return null;

    return (
      <div className="bg-white p-4 rounded-lg border border-gray-200 mb-6">
        <div className="flex items-center mb-4">
          <TrendingUp className="w-5 h-5 text-blue-500 mr-2" />
          <h3 className="text-lg font-semibold">Command Statistics (Last 7 Days)</h3>
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">{statistics.totalCommands}</div>
            <div className="text-sm text-gray-500">Total Commands</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">{statistics.successRate.toFixed(1)}%</div>
            <div className="text-sm text-gray-500">Success Rate</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{statistics.averageExecutionTime.toFixed(0)}ms</div>
            <div className="text-sm text-gray-500">Avg Execution</div>
          </div>
          
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">{Object.keys(statistics.resourceTypesAffected).length}</div>
            <div className="text-sm text-gray-500">Resource Types</div>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">Top Commands</h4>
            <div className="space-y-1">
              {statistics.topCommands.slice(0, 3).map((cmd: any, index: number) => (
                <div key={index} className="flex justify-between text-sm">
                  <span className="truncate">{cmd.command}</span>
                  <span className="text-gray-500">{cmd.count}</span>
                </div>
              ))}
            </div>
          </div>
          
          <div>
            <h4 className="text-sm font-medium text-gray-700 mb-2">Impact Distribution</h4>
            <div className="space-y-1">
              {Object.entries(statistics.impactDistribution).map(([level, count]) => (
                <div key={level} className="flex justify-between text-sm">
                  <span className="capitalize">{level}</span>
                  <span className="text-gray-500">{String(count)}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    );
  };

  // Combined commands (history + active)
  const allCommands = useMemo(() => {
    const commandMap = new Map<string, CommandRecord>();
    
    // Add history commands
    commands.forEach(cmd => commandMap.set(cmd.id, cmd));
    
    // Add/update with active commands
    activeCommands.forEach(cmd => commandMap.set(cmd.id, cmd));
    
    return Array.from(commandMap.values()).sort((a, b) => 
      b.timestamp.getTime() - a.timestamp.getTime()
    );
  }, [commands, activeCommands]);

  return (
    <div className={`bg-white rounded-lg shadow ${className}`}>
      {/* Header */}
      <div className="px-6 py-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">Command History</h2>
          <div className="flex items-center space-x-2">
            <button
              onClick={clearCompletedCommands}
              className="text-sm text-gray-500 hover:text-gray-700"
            >
              Clear Completed
            </button>
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`p-2 rounded-md ${showFilters ? 'bg-blue-100 text-blue-600' : 'text-gray-400 hover:text-gray-600'}`}
              aria-label="Toggle filters"
            >
              <Filter className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Statistics */}
      {showStatistics && <StatisticsPanel />}

      {/* Filters */}
      {showFilters && (
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Search */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search commands..."
                value={searchQuery}
                onChange={(e) => handleSearch(e.target.value)}
                className="w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Status Filter */}
            <div>
              <select
                value={selectedStatus}
                onChange={(e) => handleStatusFilter(e.target.value as any)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Status</option>
                <option value="pending">Pending</option>
                <option value="executing">Executing</option>
                <option value="completed">Completed</option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </select>
            </div>

            {/* Impact Filter */}
            <div>
              <select
                value={selectedImpact}
                onChange={(e) => handleImpactFilter(e.target.value as any)}
                className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="all">All Impact</option>
                <option value="low">Low Impact</option>
                <option value="medium">Medium Impact</option>
                <option value="high">High Impact</option>
                <option value="critical">Critical Impact</option>
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      <div className="p-6">
        {loading && (
          <div className="flex items-center justify-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
            <span className="ml-2 text-gray-600">Loading commands...</span>
          </div>
        )}

        {error && (
          <div className="flex items-center p-4 mb-4 text-red-700 bg-red-50 border border-red-200 rounded-lg">
            <AlertCircle className="w-5 h-5 mr-2" />
            <span>{error}</span>
          </div>
        )}

        {!loading && !error && (
          <div className="space-y-4">
            {allCommands.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <Clock className="w-12 h-12 mx-auto mb-4 text-gray-300" />
                <p>No command history found</p>
                <p className="text-sm">Commands will appear here as they are executed</p>
              </div>
            ) : (
              allCommands.map((command) => (
                <div
                  key={command.id}
                  className="border border-gray-200 rounded-lg p-4 hover:bg-gray-50 transition-colors cursor-pointer"
                  onClick={() => onCommandSelect?.(command)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      {/* Command and Status */}
                      <div className="flex items-center space-x-3 mb-2">
                        <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded">
                          {command.command}
                        </code>
                        {renderStatusIndicator(command.status)}
                        {renderImpactIndicator(command.impactSummary.potentialImpact)}
                      </div>

                      {/* Details */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-gray-600">
                        <div>
                          <span className="font-medium">Intent:</span> {command.intent}
                        </div>
                        <div>
                          <span className="font-medium">Resources:</span> {command.affectedResources.length}
                        </div>
                        <div>
                          <span className="font-medium">Time:</span> {
                            new Date(command.timestamp).toLocaleString()
                          }
                        </div>
                      </div>

                      {/* Execution Time */}
                      {command.executionTime && (
                        <div className="mt-2 text-sm text-gray-600">
                          <span className="font-medium">Execution Time:</span> {command.executionTime}ms
                        </div>
                      )}

                      {/* Error Message */}
                      {command.errorMessage && (
                        <div className="mt-2 p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700">
                          {command.errorMessage}
                        </div>
                      )}

                      {/* Impact Summary */}
                      {command.impactSummary.impactDescription && (
                        <div className="mt-2 text-sm text-gray-600">
                          <span className="font-medium">Impact:</span> {command.impactSummary.impactDescription}
                        </div>
                      )}

                      {/* Resource Changes */}
                      {command.resourceChanges.length > 0 && (
                        <div className="mt-3">
                          <div className="text-sm font-medium text-gray-700 mb-1">Changes:</div>
                          <div className="flex flex-wrap gap-2">
                            {command.resourceChanges.map((change, index) => (
                              <span
                                key={index}
                                className="inline-flex items-center px-2 py-1 rounded text-xs bg-blue-50 text-blue-700"
                              >
                                {change.changeType}: {change.resource.kind}/{change.resource.name}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center space-x-2 ml-4">
                      {command.rollbackAvailable && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            void handleRollback(command.id);
                          }}
                          className="p-1 text-orange-600 hover:bg-orange-50 rounded"
                          title="Generate rollback command"
                          aria-label={`Generate rollback for ${command.command}`}
                        >
                          <RotateCcw className="w-4 h-4" />
                        </button>
                      )}
                      
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onCommandSelect?.(command);
                        }}
                        className="p-1 text-blue-600 hover:bg-blue-50 rounded"
                        title="View details"
                        aria-label={`View details for ${command.command}`}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default CommandHistoryPanel;