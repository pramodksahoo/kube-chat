/**
 * CommandImpactViewer - Enhanced with command history integration
 * Shows the impact of commands on Kubernetes resources with historical context
 */

import React, { memo, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, ChevronDown, ChevronRight, Clock, ExternalLink, RotateCcw } from 'lucide-react';
import { ResourceStatusIndicator } from './ResourceStatusIndicator';
import { 
  type CommandRecord,
  useCommandHistory 
} from '../../services/commandHistoryService';
import { usePermissions } from '../auth/PermissionProvider';
import { useAuditLogging } from '../../services/auditService';
import type { ResourceStatus } from '../../services/kubernetesApi';

export interface CommandImpact {
  commandId: string;
  sessionId: string;
  naturalLanguageInput: string;
  generatedCommand: string;
  executedAt: Date;
  executedBy?: string;
  beforeState?: ResourceStatus;
  afterState: ResourceStatus;
  changeType: 'created' | 'updated' | 'deleted';
  riskLevel?: 'safe' | 'caution' | 'destructive';
}

export interface CommandImpactViewerProps {
  impact?: CommandImpact;
  command?: CommandRecord;
  commandId?: string;
  showDetails?: boolean;
  compact?: boolean;
  showHistoricalContext?: boolean;
  showRollback?: boolean;
  className?: string;
  onViewDetails?: (commandId: string) => void;
  onRollbackRequested?: (rollbackCommand: string) => void;
  onResourceClick?: (resource: { kind: string; name: string; namespace?: string }) => void;
}

export const CommandImpactViewer: React.FC<CommandImpactViewerProps> = memo(({
  impact,
  command: externalCommand,
  commandId,
  showDetails = false,
  compact = false,
  showHistoricalContext = false,
  showRollback = false,
  className = '',
  onViewDetails,
  onRollbackRequested,
  onResourceClick,
}) => {
  const { user } = usePermissions();
  const { logDashboardInteraction, logResourceAccess } = useAuditLogging(user || undefined);
  const { getCommandById, generateRollbackCommand, getResourceHistory } = useCommandHistory();
  
  const [command, setCommand] = useState<CommandRecord | null>(externalCommand || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rollbackCommand, setRollbackCommand] = useState<string | null>(null);
  const [showHistoryDetails, setShowHistoryDetails] = useState(false);
  const [resourceHistory, setResourceHistory] = useState<any>(null);

  // Load command if only ID provided
  useEffect(() => {
    const loadCommand = async () => {
      if (!commandId || externalCommand) return;

      try {
        setLoading(true);
        const cmd = await getCommandById(commandId);
        setCommand(cmd);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load command');
      } finally {
        setLoading(false);
      }
    };

    void loadCommand();
  }, [commandId, externalCommand, getCommandById]);

  // Load resource history for historical context
  useEffect(() => {
    const loadHistory = async () => {
      if (!showHistoricalContext || !command) return;

      try {
        const histories = new Map();
        for (const resource of command.affectedResources) {
          const history = await getResourceHistory({
            resource,
            limit: 5,
            startTime: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
          });
          histories.set(`${resource.kind}/${resource.name}`, history);
        }
        setResourceHistory(histories);
      } catch (err) {
        console.warn('Failed to load resource history:', err);
      }
    };

    void loadHistory();
  }, [showHistoricalContext, command, getResourceHistory]);

  // Handle rollback generation
  const handleGenerateRollback = async () => {
    if (!command) return;

    try {
      logDashboardInteraction('view', {
        action: 'generate_rollback',
        commandId: command.id,
      });

      const rollback = await generateRollbackCommand(command.id);
      if (rollback) {
        setRollbackCommand(rollback);
        onRollbackRequested?.(rollback);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to generate rollback command');
    }
  };

  // Handle resource click
  const handleResourceClick = (resource: { kind: string; name: string; namespace?: string }) => {
    logResourceAccess('view', resource, 'success', {
      source: 'command_impact_viewer',
      commandId: command?.id,
    });

    onResourceClick?.(resource);
  };
  // Calculate what changed - either from legacy impact or command
  const changes = useMemo(() => {
    // If we have a command record, use its data
    if (command) {
      const resourceChanges = command.resourceChanges;
      if (resourceChanges.length === 0) {
        return {
          type: 'pending',
          summary: 'Command pending execution',
          details: [],
        };
      }

      const changeTypes = [...new Set(resourceChanges.map(c => c.changeType))];
      const totalChanges = resourceChanges.length;

      return {
        type: changeTypes.includes('deleted') ? 'deleted' : 
              changeTypes.includes('created') ? 'created' : 'updated',
        summary: `${totalChanges} resource${totalChanges !== 1 ? 's' : ''} ${
          changeTypes.length === 1 ? changeTypes[0] : 'changed'
        }`,
        details: resourceChanges.map(change => ({
          field: `${change.resource.kind}/${change.resource.name}`,
          before: change.before?.status || 'N/A',
          after: change.after?.status || 'N/A',
          type: change.changeType,
          fieldChanges: change.fieldChanges,
        })),
      };
    }

    // Fallback to legacy impact calculation
    if (!impact) {
      return {
        type: 'unknown',
        summary: 'No impact data',
        details: [],
      };
    }

    if (!impact.beforeState || impact.changeType === 'created') {
      return {
        type: 'created',
        summary: 'Resource created',
        details: [],
      };
    }

    if (impact.changeType === 'deleted') {
      return {
        type: 'deleted',
        summary: 'Resource deleted',
        details: [],
      };
    }

    const { beforeState, afterState } = impact;
    const changeDetails = [];

    // Check status change
    if (beforeState.status !== afterState.status) {
      changeDetails.push({
        field: 'Status',
        before: beforeState.status,
        after: afterState.status,
        type: 'status-change',
      });
    }

    // Check metadata changes (simplified)
    const beforeKeys = Object.keys(beforeState.metadata || {});
    const afterKeys = Object.keys(afterState.metadata || {});
    
    if (beforeKeys.length !== afterKeys.length) {
      changeDetails.push({
        field: 'Metadata',
        before: `${beforeKeys.length} fields`,
        after: `${afterKeys.length} fields`,
        type: 'metadata-change',
      });
    }

    return {
      type: 'updated',
      summary: changeDetails.length > 0 ? `${changeDetails.length} change${changeDetails.length !== 1 ? 's' : ''}` : 'Resource updated',
      details: changeDetails,
    };
  }, [impact, command]);

  // Get change type styling
  const getChangeTypeStyling = (changeType: string) => {
    const styles = {
      created: 'bg-green-50 border-green-200',
      updated: 'bg-blue-50 border-blue-200',
      deleted: 'bg-red-50 border-red-200',
      pending: 'bg-yellow-50 border-yellow-200',
      unknown: 'bg-gray-50 border-gray-200',
    };
    return styles[changeType as keyof typeof styles] || styles.updated;
  };

  // Get risk level styling
  const getRiskLevelStyling = (riskLevel?: string) => {
    const styles = {
      safe: 'text-green-700',
      caution: 'text-yellow-700',
      destructive: 'text-red-700',
    };
    return riskLevel ? styles[riskLevel as keyof typeof styles] || styles.safe : 'text-gray-700';
  };

  // Format execution time
  const formatExecutionTime = (date: Date) => {
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

  // Get change type icon
  const getChangeTypeIcon = (changeType: string) => {
    const icons = {
      created: '➕',
      updated: '✏️',
      deleted: '🗑️',
      pending: '⏳',
      unknown: '❓',
    };
    return icons[changeType as keyof typeof icons] || '📝';
  };

  // Get display resource for the header - prefer command data over impact
  const getDisplayResource = () => {
    if (command && command.affectedResources.length > 0) {
      return command.affectedResources[0]; // Show first affected resource
    }
    if (impact) {
      return {
        kind: impact.afterState.kind,
        name: impact.afterState.name,
        namespace: impact.afterState.namespace,
      };
    }
    return null;
  };

  // Get display time - prefer command data over impact
  const getDisplayTime = () => {
    if (command) return command.timestamp;
    if (impact) return impact.executedAt;
    return new Date();
  };

  const displayResource = getDisplayResource();
  const displayTime = getDisplayTime();

  // Loading state
  if (loading) {
    return (
      <div className={`bg-white rounded-lg border border-gray-200 p-4 ${className}`}>
        <div className="flex items-center justify-center py-4">
          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
          <span className="ml-2 text-gray-600">Loading command details...</span>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className={`bg-red-50 border border-red-200 rounded-lg p-4 ${className}`}>
        <div className="flex items-center text-red-700">
          <AlertTriangle className="w-5 h-5 mr-2" />
          <span>{error}</span>
        </div>
      </div>
    );
  }

  // No data state
  if (!command && !impact) {
    return (
      <div className={`bg-gray-50 border border-gray-200 rounded-lg p-4 ${className}`}>
        <div className="text-center text-gray-500">
          <Clock className="w-8 h-8 mx-auto mb-2 text-gray-300" />
          <p>No command or impact data available</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`command-impact-viewer border rounded-lg p-4 ${getChangeTypeStyling(changes.type)} ${className}`}
      data-testid="command-impact-viewer"
      data-change-type={changes.type}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-4 mb-3">
        <div className="flex items-start gap-3 flex-1 min-w-0">
          <div className="text-lg" aria-hidden="true">
            {getChangeTypeIcon(changes.type)}
          </div>
          
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <h3 className={`font-medium text-gray-900 ${compact ? 'text-sm' : 'text-base'}`}>
                {displayResource ? (
                  <button
                    onClick={() => displayResource && handleResourceClick(displayResource)}
                    className="hover:underline text-blue-600 hover:text-blue-800"
                  >
                    {displayResource.kind}/{displayResource.name}
                  </button>
                ) : (
                  'Multiple Resources'
                )}
              </h3>
              
              <span className={`text-xs font-medium ${getRiskLevelStyling(command?.impactSummary?.potentialImpact || impact?.riskLevel)}`}>
                {changes.summary}
              </span>
            </div>
            
            <div className={`text-gray-600 ${compact ? 'text-xs' : 'text-sm'}`}>
              {formatExecutionTime(displayTime)}
              {(command?.userId || impact?.executedBy) && (
                <span className="ml-2">by {command?.userId || impact?.executedBy}</span>
              )}
              {command?.status && (
                <span className="ml-2">• {command.status}</span>
              )}
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex items-center space-x-2">
          {showRollback && command?.rollbackAvailable && (
            <button
              onClick={() => void handleGenerateRollback()}
              className="p-1 text-orange-600 hover:bg-orange-50 rounded"
              title="Generate rollback command"
              aria-label="Generate rollback command"
            >
              <RotateCcw className="w-4 h-4" />
            </button>
          )}
          
          {onViewDetails && (
            <button
              onClick={() => onViewDetails(command?.id || impact?.commandId || '')}
              className="text-blue-600 hover:text-blue-800 text-sm font-medium focus:outline-none focus:underline"
              aria-label="View command details"
            >
              Details
            </button>
          )}
        </div>
      </div>

      {/* Before/After comparison */}
      {!compact && (impact?.beforeState || changes.type === 'created') && (
        <div className="mb-3">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Before state */}
            <div className="bg-white rounded-lg border p-3">
              <div className="text-sm font-medium text-gray-700 mb-2">Before</div>
              {impact?.beforeState ? (
                <div className="flex items-center gap-2">
                  <ResourceStatusIndicator 
                    status={impact.beforeState.status}
                    size="sm"
                    showLabel={true}
                    showIcon={true}
                  />
                </div>
              ) : (
                <div className="text-sm text-gray-500 italic">
                  Resource did not exist
                </div>
              )}
            </div>

            {/* After state */}
            <div className="bg-white rounded-lg border p-3">
              <div className="text-sm font-medium text-gray-700 mb-2">After</div>
              {changes.type === 'deleted' ? (
                <div className="text-sm text-gray-500 italic">
                  Resource deleted
                </div>
              ) : (
                <div className="flex items-center gap-2">
                  <ResourceStatusIndicator 
                    status={impact?.afterState?.status || 'Unknown'}
                    size="sm"
                    showLabel={true}
                    showIcon={true}
                  />
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Command details */}
      {showDetails && (
        <div className="border-t pt-3 space-y-3">
          {/* Natural language input */}
          <div>
            <div className="text-sm font-medium text-gray-700 mb-1">Command Request</div>
            <div className="text-sm text-gray-900 bg-gray-50 rounded p-2 font-mono">
              {impact?.naturalLanguageInput || 'Not available'}
            </div>
          </div>

          {/* Generated command */}
          <div>
            <div className="text-sm font-medium text-gray-700 mb-1">Generated Command</div>
            <div className="text-sm text-gray-900 bg-gray-50 rounded p-2 font-mono">
              {impact?.generatedCommand || 'Not available'}
            </div>
          </div>

          {/* Change details */}
          {changes.details.length > 0 && (
            <div>
              <div className="text-sm font-medium text-gray-700 mb-2">Changes</div>
              <div className="space-y-2">
                {changes.details.map((change, index) => (
                  <div key={index} className="flex items-center gap-3 text-sm">
                    <span className="font-medium text-gray-900">{change.field}:</span>
                    <span className="text-gray-600">{change.before}</span>
                    <span className="text-gray-400">→</span>
                    <span className="text-gray-900 font-medium">{change.after}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Enhanced Command Information */}
      {command && showDetails && (
        <div className="border-t pt-3 space-y-3">
          {/* Command metadata */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <div>
              <div className="text-gray-600">Intent:</div>
              <div className="font-medium">{command.intent}</div>
            </div>
            <div>
              <div className="text-gray-600">Execution Time:</div>
              <div className="font-medium">
                {command.executionTime ? `${command.executionTime}ms` : 'N/A'}
              </div>
            </div>
            <div>
              <div className="text-gray-600">Impact Level:</div>
              <div className={`font-medium capitalize ${getRiskLevelStyling(command.impactSummary.potentialImpact)}`}>
                {command.impactSummary.potentialImpact}
              </div>
            </div>
          </div>

          {/* Original command */}
          <div>
            <div className="text-sm font-medium text-gray-700 mb-1">Command</div>
            <div className="text-sm bg-gray-50 rounded p-2 font-mono">
              {command.command}
            </div>
          </div>

          {/* Resource changes from command history */}
          {command.resourceChanges.length > 0 && (
            <div>
              <div className="text-sm font-medium text-gray-700 mb-2">Resource Changes</div>
              <div className="space-y-2">
                {command.resourceChanges.map((change, index) => (
                  <div key={index} className="border border-gray-200 rounded p-3">
                    <div className="flex items-center justify-between mb-2">
                      <button
                        onClick={() => handleResourceClick(change.resource)}
                        className="flex items-center text-blue-600 hover:text-blue-800 hover:underline"
                      >
                        <span className="font-mono text-sm">
                          {change.resource.kind}/{change.resource.name}
                        </span>
                        {change.resource.namespace && (
                          <span className="text-gray-500 ml-1">({change.resource.namespace})</span>
                        )}
                        <ExternalLink className="w-3 h-3 ml-1" />
                      </button>
                      
                      <span className={`px-2 py-1 rounded text-xs font-medium ${
                        change.changeType === 'created' ? 'bg-green-100 text-green-800' :
                        change.changeType === 'deleted' ? 'bg-red-100 text-red-800' :
                        'bg-blue-100 text-blue-800'
                      }`}>
                        {change.changeType}
                      </span>
                    </div>
                    
                    {change.fieldChanges.length > 0 && (
                      <div>
                        <div className="text-xs text-gray-600 mb-1">
                          {change.fieldChanges.length} field{change.fieldChanges.length !== 1 ? 's' : ''} changed
                        </div>
                        <div className="text-xs space-y-1">
                          {change.fieldChanges.slice(0, 3).map((fieldChange, fIndex) => (
                            <div key={fIndex} className="font-mono bg-gray-50 p-1 rounded">
                              {fieldChange.path}: {fieldChange.changeType}
                            </div>
                          ))}
                          {change.fieldChanges.length > 3 && (
                            <div className="text-gray-500">
                              ... {change.fieldChanges.length - 3} more changes
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Error message */}
          {command.errorMessage && (
            <div className="p-2 bg-red-50 border border-red-200 rounded text-sm text-red-700">
              <div className="font-medium">Error:</div>
              <div>{command.errorMessage}</div>
            </div>
          )}
        </div>
      )}

      {/* Historical Context */}
      {showHistoricalContext && resourceHistory && resourceHistory.size > 0 && (
        <div className="border-t pt-3">
          <button
            onClick={() => setShowHistoryDetails(!showHistoryDetails)}
            className="flex items-center justify-between w-full text-left text-sm font-medium text-gray-700 hover:text-gray-900"
          >
            <span>Historical Context (Last 24h)</span>
            {showHistoryDetails ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>
          
          {showHistoryDetails && (
            <div className="mt-2 space-y-2">
              {Array.from(resourceHistory.entries()).slice(0, 3).map((entry) => {
                const [resourceKey, history] = entry as [string, any];
                return (
                <div key={resourceKey} className="text-xs bg-gray-50 p-2 rounded">
                  <div className="font-medium">{resourceKey}</div>
                  {(history).changes.slice(0, 2).map((change: any, index: number) => (
                    <div key={index} className="text-gray-600 flex justify-between">
                      <span>{change.changeType} by {change.metadata.source}</span>
                      <span>{new Date(change.timestamp).toLocaleTimeString()}</span>
                    </div>
                  ))}
                </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Rollback Command Display */}
      {rollbackCommand && (
        <div className="border-t pt-3">
          <div className="text-sm font-medium text-gray-700 mb-2 flex items-center">
            <RotateCcw className="w-4 h-4 mr-1 text-orange-600" />
            Generated Rollback Command
          </div>
          <pre className="text-xs bg-gray-900 text-green-400 p-3 rounded overflow-x-auto font-mono">
            {rollbackCommand}
          </pre>
        </div>
      )}

      {/* Risk level indicator - legacy and enhanced */}
      {(impact?.riskLevel || command?.impactSummary?.potentialImpact) && (
        <div className="flex items-center gap-2 mt-3 pt-3 border-t">
          <div className="text-sm text-gray-600">Risk Level:</div>
          <div className={`text-sm font-medium ${getRiskLevelStyling(command?.impactSummary?.potentialImpact || impact?.riskLevel)}`}>
            {((command?.impactSummary?.potentialImpact || impact?.riskLevel) || '').charAt(0).toUpperCase() + 
             ((command?.impactSummary?.potentialImpact || impact?.riskLevel) || '').slice(1)}
          </div>
          
          {command?.impactSummary && (
            <>
              <div className="text-sm text-gray-600 ml-4">Resources Affected:</div>
              <div className="text-sm font-medium">{command.impactSummary.resourcesAffected}</div>
              
              {command.impactSummary.namespacesCovered.length > 0 && (
                <>
                  <div className="text-sm text-gray-600 ml-4">Namespaces:</div>
                  <div className="text-sm font-medium">
                    {command.impactSummary.namespacesCovered.join(', ')}
                  </div>
                </>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
});

CommandImpactViewer.displayName = 'CommandImpactViewer';

export default CommandImpactViewer;