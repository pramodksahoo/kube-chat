/**
 * Command History Service - Track resource changes and command impact
 * Provides integration with chat commands and resource change tracking
 */

import { kubernetesApi, type ResourceStatus } from './kubernetesApi';
import { auditService } from './auditService';

export interface SimpleResourceReference {
  kind: string;
  name: string;
  namespace?: string;
}

export interface CommandRecord {
  id: string;
  timestamp: Date;
  userId: string;
  sessionId: string;
  command: string;
  intent: string; // Parsed intent from NLP
  parameters: Record<string, any>;
  status: 'pending' | 'executing' | 'completed' | 'failed' | 'cancelled';
  executionTime?: number; // milliseconds
  affectedResources: SimpleResourceReference[];
  resourceSnapshot?: ResourceStatus[]; // Before state
  resourceChanges: ResourceChange[];
  impactSummary: ImpactSummary;
  errorMessage?: string;
  rollbackAvailable: boolean;
  rollbackCommandId?: string;
}

export interface ResourceChange {
  resource: SimpleResourceReference;
  changeType: 'created' | 'updated' | 'deleted' | 'scaled' | 'restarted' | 'patched';
  before?: Partial<ResourceStatus>;
  after?: Partial<ResourceStatus>;
  fieldChanges: FieldChange[];
  timestamp: Date;
  metadata: {
    source: 'command' | 'external' | 'system';
    triggeredBy?: string;
    relatedCommandId?: string;
  };
}

export interface FieldChange {
  path: string; // JSONPath to the field
  oldValue: any;
  newValue: any;
  changeType: 'added' | 'removed' | 'modified';
}

export interface ImpactSummary {
  resourcesAffected: number;
  namespacesCovered: string[];
  changeTypes: string[];
  potentialImpact: 'low' | 'medium' | 'high' | 'critical';
  impactDescription: string;
  dependentResources: SimpleResourceReference[];
  rollbackComplexity: 'simple' | 'moderate' | 'complex' | 'dangerous';
}

export interface CommandHistoryFilter {
  startTime?: Date;
  endTime?: Date;
  userId?: string;
  command?: string;
  status?: CommandRecord['status'];
  affectedResource?: SimpleResourceReference;
  namespace?: string;
  intent?: string;
  impactLevel?: ImpactSummary['potentialImpact'];
  limit?: number;
  offset?: number;
}

export interface CommandHistoryResult {
  commands: CommandRecord[];
  total: number;
  hasMore: boolean;
}

export interface ResourceHistoryFilter {
  resource: SimpleResourceReference;
  startTime?: Date;
  endTime?: Date;
  changeTypes?: ResourceChange['changeType'][];
  includeExternal?: boolean;
  limit?: number;
}

export interface ResourceHistoryResult {
  resource: SimpleResourceReference;
  changes: ResourceChange[];
  commands: CommandRecord[];
  total: number;
  hasMore: boolean;
}

export class CommandHistoryService {
  private commands: Map<string, CommandRecord> = new Map();
  private resourceChangeQueue: ResourceChange[] = [];
  private changeDetectionEnabled: boolean = true;
  private batchInterval: number = 2000; // 2 seconds
  private batchTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.startChangeDetection();
  }

  // Command lifecycle management
  async recordCommand(
    command: string,
    intent: string,
    parameters: Record<string, any> = {},
    userId: string,
    sessionId: string
  ): Promise<string> {
    const commandId = this.generateCommandId();
    const timestamp = new Date();

    // Take resource snapshot before execution
    const affectedResources = await this.predictAffectedResources(intent, parameters);
    const resourceSnapshot = await this.captureResourceSnapshot(affectedResources);

    const commandRecord: CommandRecord = {
      id: commandId,
      timestamp,
      userId,
      sessionId,
      command,
      intent,
      parameters,
      status: 'pending',
      affectedResources,
      resourceSnapshot,
      resourceChanges: [],
      impactSummary: await this.assessImpact(intent, parameters, affectedResources),
      rollbackAvailable: false,
    };

    this.commands.set(commandId, commandRecord);

    // Audit log the command
    auditService.logEvent('command.recorded', {
      details: {
        commandId,
        command,
        intent,
        affectedResourceCount: affectedResources.length,
        impactLevel: commandRecord.impactSummary.potentialImpact,
      },
      level: 'info',
      tags: ['command-history', 'command-recorded'],
    });

    return commandId;
  }

  async updateCommandStatus(
    commandId: string,
    status: CommandRecord['status'],
    error?: string
  ): Promise<void> {
    const command = this.commands.get(commandId);
    if (!command) {
      throw new Error(`Command ${commandId} not found`);
    }

    const previousStatus = command.status;
    command.status = status;

    if (status === 'executing' && previousStatus === 'pending') {
      // Start execution timer
      (command as any).executionStartTime = Date.now();
    }

    if (['completed', 'failed', 'cancelled'].includes(status)) {
      // Calculate execution time
      const executionStartTime = (command as any).executionStartTime;
      if (executionStartTime) {
        command.executionTime = Date.now() - executionStartTime;
      }

      // Detect changes after command completion
      if (status === 'completed') {
        await this.detectResourceChanges(commandId);
        command.rollbackAvailable = this.assessRollbackAvailability(command);
      }

      if (error) {
        command.errorMessage = error;
      }
    }

    // Audit log status change
    auditService.logEvent('command.status_changed', {
      details: {
        commandId,
        previousStatus,
        newStatus: status,
        executionTime: command.executionTime,
        error,
      },
      level: error ? 'error' : 'info',
      tags: ['command-history', 'status-change'],
    });
  }

  async addResourceChange(
    commandId: string | null,
    change: Omit<ResourceChange, 'timestamp' | 'metadata'>
  ): Promise<void> {
    const resourceChange: ResourceChange = {
      ...change,
      timestamp: new Date(),
      metadata: {
        source: commandId ? 'command' : 'external',
        relatedCommandId: commandId || undefined,
      },
    };

    // Add to queue for batch processing
    this.resourceChangeQueue.push(resourceChange);

    // If associated with a command, update the command record
    if (commandId) {
      const command = this.commands.get(commandId);
      if (command) {
        command.resourceChanges.push(resourceChange);
        
        // Update impact summary
        command.impactSummary = await this.recalculateImpact(command);
      }
    }

    // Audit log the resource change
    auditService.logResourceAccess(
      change.changeType === 'created' ? 'create' :
      change.changeType === 'deleted' ? 'delete' : 'edit',
      change.resource,
      'success',
      {
        changeType: change.changeType,
        fieldChanges: change.fieldChanges.length,
        commandId,
        source: resourceChange.metadata.source,
      }
    );
  }

  // Query methods
  async searchCommands(filter: CommandHistoryFilter): Promise<CommandHistoryResult> {
    let filteredCommands = Array.from(this.commands.values());

    // Apply filters
    if (filter.startTime) {
      filteredCommands = filteredCommands.filter(cmd => cmd.timestamp >= filter.startTime!);
    }
    
    if (filter.endTime) {
      filteredCommands = filteredCommands.filter(cmd => cmd.timestamp <= filter.endTime!);
    }

    if (filter.userId) {
      filteredCommands = filteredCommands.filter(cmd => cmd.userId === filter.userId);
    }

    if (filter.command) {
      filteredCommands = filteredCommands.filter(cmd => 
        cmd.command.toLowerCase().includes(filter.command!.toLowerCase()) ||
        cmd.intent.toLowerCase().includes(filter.command!.toLowerCase())
      );
    }

    if (filter.status) {
      filteredCommands = filteredCommands.filter(cmd => cmd.status === filter.status);
    }

    if (filter.namespace) {
      filteredCommands = filteredCommands.filter(cmd =>
        cmd.affectedResources.some(r => r.namespace === filter.namespace)
      );
    }

    if (filter.intent) {
      filteredCommands = filteredCommands.filter(cmd => cmd.intent === filter.intent);
    }

    if (filter.impactLevel) {
      filteredCommands = filteredCommands.filter(cmd => 
        cmd.impactSummary.potentialImpact === filter.impactLevel
      );
    }

    if (filter.affectedResource) {
      const resource = filter.affectedResource;
      filteredCommands = filteredCommands.filter(cmd =>
        cmd.affectedResources.some(r => 
          r.kind === resource.kind && 
          r.name === resource.name && 
          r.namespace === resource.namespace
        )
      );
    }

    // Sort by timestamp (newest first)
    filteredCommands.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    const total = filteredCommands.length;
    const offset = filter.offset || 0;
    const limit = filter.limit || 50;

    const paginatedCommands = filteredCommands.slice(offset, offset + limit);
    const hasMore = offset + limit < total;

    // Audit log the search
    auditService.logDashboardInteraction('search', {
      searchType: 'command_history',
      filterCount: Object.keys(filter).length,
      resultCount: paginatedCommands.length,
      totalCount: total,
    });

    return {
      commands: paginatedCommands,
      total,
      hasMore,
    };
  }

  async getResourceHistory(filter: ResourceHistoryFilter): Promise<ResourceHistoryResult> {
    // Get resource changes
    let changes = this.resourceChangeQueue.filter(change =>
      this.matchesResourceReference(change.resource, filter.resource)
    );

    // Get changes from commands
    const commandChanges = Array.from(this.commands.values())
      .flatMap(cmd => cmd.resourceChanges)
      .filter(change => this.matchesResourceReference(change.resource, filter.resource));

    changes = [...changes, ...commandChanges];

    // Apply filters
    if (filter.startTime) {
      changes = changes.filter(change => change.timestamp >= filter.startTime!);
    }

    if (filter.endTime) {
      changes = changes.filter(change => change.timestamp <= filter.endTime!);
    }

    if (filter.changeTypes) {
      changes = changes.filter(change => filter.changeTypes!.includes(change.changeType));
    }

    if (!filter.includeExternal) {
      changes = changes.filter(change => change.metadata.source !== 'external');
    }

    // Sort by timestamp (newest first)
    changes.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

    // Get related commands
    const relatedCommandIds = new Set(
      changes
        .map(change => change.metadata.relatedCommandId)
        .filter((id): id is string => !!id)
    );

    const relatedCommands = Array.from(relatedCommandIds)
      .map(id => this.commands.get(id))
      .filter((cmd): cmd is CommandRecord => !!cmd);

    const total = changes.length;
    const limit = filter.limit || 50;
    const paginatedChanges = changes.slice(0, limit);

    return {
      resource: filter.resource,
      changes: paginatedChanges,
      commands: relatedCommands,
      total,
      hasMore: limit < total,
    };
  }

  async getCommandById(commandId: string): Promise<CommandRecord | null> {
    return this.commands.get(commandId) || null;
  }

  // Rollback functionality
  async generateRollbackCommand(commandId: string): Promise<string | null> {
    const command = this.commands.get(commandId);
    if (!command || !command.rollbackAvailable) {
      return null;
    }

    // Generate rollback command based on changes
    const rollbackSteps: string[] = [];

    for (const change of command.resourceChanges) {
      switch (change.changeType) {
        case 'created':
          rollbackSteps.push(`kubectl delete ${change.resource.kind} ${change.resource.name} -n ${change.resource.namespace || 'default'}`);
          break;
        
        case 'deleted':
          if (command.resourceSnapshot) {
            const originalResource = command.resourceSnapshot.find(r =>
              this.matchesResourceReference(r, change.resource)
            );
            if (originalResource) {
              rollbackSteps.push(`# Recreate ${change.resource.kind}/${change.resource.name}`);
              rollbackSteps.push(`kubectl apply -f - <<EOF\n# Resource manifest would be here\nEOF`);
            }
          }
          break;
        
        case 'updated':
        case 'patched':
          // Restore previous field values
          for (const fieldChange of change.fieldChanges) {
            if (fieldChange.changeType === 'modified') {
              rollbackSteps.push(
                `kubectl patch ${change.resource.kind} ${change.resource.name} -n ${change.resource.namespace || 'default'} ` +
                `--type='json' -p='[{"op": "replace", "path": "${fieldChange.path}", "value": ${JSON.stringify(fieldChange.oldValue)}}]'`
              );
            }
          }
          break;
        
        case 'scaled': {
          const scaleChange = change.fieldChanges.find(fc => fc.path.includes('replicas'));
          if (scaleChange) {
            rollbackSteps.push(
              `kubectl scale ${change.resource.kind} ${change.resource.name} -n ${change.resource.namespace || 'default'} ` +
              `--replicas=${scaleChange.oldValue}`
            );
          }
          break;
        }
      }
    }

    return rollbackSteps.join('\n');
  }

  // Analytics and reporting
  async getCommandStatistics(timeRange: { start: Date; end: Date }): Promise<{
    totalCommands: number;
    successRate: number;
    averageExecutionTime: number;
    topCommands: Array<{ command: string; count: number }>;
    topUsers: Array<{ userId: string; count: number }>;
    impactDistribution: Record<ImpactSummary['potentialImpact'], number>;
    resourceTypesAffected: Record<string, number>;
  }> {
    const commands = Array.from(this.commands.values()).filter(
      cmd => cmd.timestamp >= timeRange.start && cmd.timestamp <= timeRange.end
    );

    const totalCommands = commands.length;
    const completedCommands = commands.filter(cmd => cmd.status === 'completed');
    const successRate = totalCommands > 0 ? (completedCommands.length / totalCommands) * 100 : 0;

    const executionTimes = completedCommands
      .map(cmd => cmd.executionTime)
      .filter((time): time is number => typeof time === 'number');
    const averageExecutionTime = executionTimes.length > 0 
      ? executionTimes.reduce((a, b) => a + b, 0) / executionTimes.length 
      : 0;

    // Top commands
    const commandCounts = new Map<string, number>();
    commands.forEach(cmd => {
      const key = cmd.intent || cmd.command;
      commandCounts.set(key, (commandCounts.get(key) || 0) + 1);
    });
    const topCommands = Array.from(commandCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([command, count]) => ({ command, count }));

    // Top users
    const userCounts = new Map<string, number>();
    commands.forEach(cmd => {
      userCounts.set(cmd.userId, (userCounts.get(cmd.userId) || 0) + 1);
    });
    const topUsers = Array.from(userCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([userId, count]) => ({ userId, count }));

    // Impact distribution
    const impactDistribution: Record<ImpactSummary['potentialImpact'], number> = {
      low: 0,
      medium: 0,
      high: 0,
      critical: 0,
    };
    commands.forEach(cmd => {
      impactDistribution[cmd.impactSummary.potentialImpact]++;
    });

    // Resource types affected
    const resourceTypes = new Map<string, number>();
    commands.forEach(cmd => {
      cmd.affectedResources.forEach(resource => {
        resourceTypes.set(resource.kind, (resourceTypes.get(resource.kind) || 0) + 1);
      });
    });
    const resourceTypesAffected = Object.fromEntries(resourceTypes);

    return {
      totalCommands,
      successRate,
      averageExecutionTime,
      topCommands,
      topUsers,
      impactDistribution,
      resourceTypesAffected,
    };
  }

  // Private methods
  private startChangeDetection(): void {
    if (!this.changeDetectionEnabled) return;

    this.batchTimer = setInterval(() => {
      void this.processResourceChangeQueue();
    }, this.batchInterval);
  }

  private async processResourceChangeQueue(): Promise<void> {
    if (this.resourceChangeQueue.length === 0) return;

    const changes = this.resourceChangeQueue.splice(0);
    
    // Process changes in batches
    const batchSize = 10;
    for (let i = 0; i < changes.length; i += batchSize) {
      const batch = changes.slice(i, i + batchSize);
      await this.processBatch(batch);
    }
  }

  private async processBatch(changes: ResourceChange[]): Promise<void> {
    // Group changes by resource for efficiency
    const groupedChanges = new Map<string, ResourceChange[]>();
    
    changes.forEach(change => {
      const key = `${change.resource.kind}/${change.resource.name}/${change.resource.namespace || 'default'}`;
      if (!groupedChanges.has(key)) {
        groupedChanges.set(key, []);
      }
      groupedChanges.get(key)!.push(change);
    });

    // Process each resource's changes
    for (const [, resourceChanges] of groupedChanges) {
      await this.analyzeResourceChanges(resourceChanges);
    }
  }

  private async analyzeResourceChanges(changes: ResourceChange[]): Promise<void> {
    // Detect patterns, potential issues, cascading effects
    const resource = changes[0].resource;
    
    // Check for cascading changes
    await this.findRelatedResources(resource);
    
    // Alert for critical changes
    const criticalChanges = changes.filter(change => 
      change.changeType === 'deleted' || 
      change.fieldChanges.some(fc => fc.path.includes('image') || fc.path.includes('replicas'))
    );

    if (criticalChanges.length > 0) {
      auditService.logSecurityEvent('suspicious_activity', {
        resourceChanges: criticalChanges.length,
        resource: `${resource.kind}/${resource.name}`,
        namespace: resource.namespace,
        changeTypes: criticalChanges.map(c => c.changeType),
      }, 'medium');
    }
  }

  private async predictAffectedResources(
    _intent: string, 
    _parameters: Record<string, any>
  ): Promise<SimpleResourceReference[]> {
    const resources: SimpleResourceReference[] = [];

    // Basic intent-based prediction
    if (_parameters.resource) {
      resources.push({
        kind: _parameters.resource.kind,
        name: _parameters.resource.name,
        namespace: _parameters.resource.namespace,
      });
    }

    if (_parameters.namespace) {
      // For namespace-wide operations, get current resources
      try {
        const response = await kubernetesApi.listResources({ 
          namespace: _parameters.namespace 
        });
        resources.push(...response.resources.map(r => ({
          kind: r.kind,
          name: r.name,
          namespace: r.namespace,
        })));
      } catch (error) {
        console.warn('Failed to predict affected resources:', error);
      }
    }

    return resources;
  }

  private async captureResourceSnapshot(
    resources: SimpleResourceReference[]
  ): Promise<ResourceStatus[]> {
    const snapshots: ResourceStatus[] = [];

    for (const resource of resources) {
      try {
        const status = await kubernetesApi.getResource(resource.kind, resource.name, resource.namespace);
        if (status) {
          snapshots.push(status);
        }
      } catch (error) {
        console.warn(`Failed to capture snapshot for ${resource.kind}/${resource.name}:`, error);
      }
    }

    return snapshots;
  }

  private async assessImpact(
    intent: string,
    _parameters: Record<string, any>,
    affectedResources: SimpleResourceReference[]
  ): Promise<ImpactSummary> {
    const namespaces = [...new Set(affectedResources.map(r => r.namespace).filter(Boolean))] as string[];
    // const _resourceTypes = [...new Set(affectedResources.map(r => r.kind))]; // Available for future use

    // Determine impact level based on intent and scope
    let potentialImpact: ImpactSummary['potentialImpact'] = 'low';
    let rollbackComplexity: ImpactSummary['rollbackComplexity'] = 'simple';

    if (intent.includes('delete') || intent.includes('destroy')) {
      potentialImpact = affectedResources.length > 5 ? 'critical' : 'high';
      rollbackComplexity = 'complex';
    } else if (intent.includes('scale') || intent.includes('update')) {
      potentialImpact = affectedResources.length > 10 ? 'high' : 'medium';
      rollbackComplexity = 'moderate';
    } else if (intent.includes('create') || intent.includes('deploy')) {
      potentialImpact = 'low';
      rollbackComplexity = 'simple';
    }

    // Check for system resources
    const systemResources = affectedResources.filter(r => 
      r.namespace === 'kube-system' || 
      r.namespace === 'kube-public' ||
      ['ClusterRole', 'ClusterRoleBinding', 'PersistentVolume'].includes(r.kind)
    );

    if (systemResources.length > 0) {
      potentialImpact = 'critical';
      rollbackComplexity = 'dangerous';
    }

    const dependentResources = await this.findDependentResources(affectedResources);

    return {
      resourcesAffected: affectedResources.length,
      namespacesCovered: namespaces,
      changeTypes: [intent],
      potentialImpact,
      impactDescription: this.generateImpactDescription(intent, affectedResources.length, namespaces),
      dependentResources,
      rollbackComplexity,
    };
  }

  private async recalculateImpact(command: CommandRecord): Promise<ImpactSummary> {
    const actualChanges = command.resourceChanges;
    const changeTypes = [...new Set(actualChanges.map(c => c.changeType))];
    const namespaces = [...new Set(actualChanges.map(c => c.resource.namespace).filter(Boolean))] as string[];

    // Recalculate based on actual changes
    let potentialImpact: ImpactSummary['potentialImpact'] = 'low';
    
    if (changeTypes.includes('deleted')) {
      potentialImpact = actualChanges.length > 5 ? 'critical' : 'high';
    } else if (changeTypes.includes('updated') || changeTypes.includes('scaled')) {
      potentialImpact = actualChanges.length > 10 ? 'high' : 'medium';
    }

    const dependentResources = await this.findDependentResources(
      actualChanges.map(c => c.resource)
    );

    return {
      ...command.impactSummary,
      resourcesAffected: actualChanges.length,
      namespacesCovered: namespaces,
      changeTypes,
      potentialImpact,
      dependentResources,
    };
  }

  private async detectResourceChanges(commandId: string): Promise<void> {
    const command = this.commands.get(commandId);
    if (!command || !command.resourceSnapshot) return;

    // Compare current state with snapshot
    for (const snapshotResource of command.resourceSnapshot) {
      try {
        const currentResource = await kubernetesApi.getResource(
          snapshotResource.kind,
          snapshotResource.name,
          snapshotResource.namespace
        );

        if (!currentResource) {
          // Resource was deleted
          await this.addResourceChange(commandId, {
            resource: {
              kind: snapshotResource.kind,
              name: snapshotResource.name,
              namespace: snapshotResource.namespace,
            },
            changeType: 'deleted',
            before: snapshotResource,
            fieldChanges: [],
          });
        } else {
          // Check for changes
          const fieldChanges = this.compareResourceFields(snapshotResource, currentResource);
          if (fieldChanges.length > 0) {
            await this.addResourceChange(commandId, {
              resource: {
                kind: snapshotResource.kind,
                name: snapshotResource.name,
                namespace: snapshotResource.namespace,
              },
              changeType: 'updated',
              before: snapshotResource,
              after: currentResource,
              fieldChanges,
            });
          }
        }
      } catch (error) {
        console.warn(`Failed to detect changes for ${snapshotResource.kind}/${snapshotResource.name}:`, error);
      }
    }
  }

  private compareResourceFields(before: ResourceStatus, after: ResourceStatus): FieldChange[] {
    const changes: FieldChange[] = [];

    // Compare key fields
    const fieldsToCompare = [
      'status',
      'metadata.labels',
    ];

    for (const fieldPath of fieldsToCompare) {
      const beforeValue = this.getNestedValue(before.metadata, fieldPath);
      const afterValue = this.getNestedValue(after.metadata, fieldPath);

      if (JSON.stringify(beforeValue) !== JSON.stringify(afterValue)) {
        changes.push({
          path: fieldPath,
          oldValue: beforeValue,
          newValue: afterValue,
          changeType: beforeValue === undefined ? 'added' : 
                     afterValue === undefined ? 'removed' : 'modified',
        });
      }
    }

    return changes;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => {
      if (key.includes('[') && key.includes(']')) {
        // Handle array notation like 'containers[0]'
        const [arrayKey, indexStr] = key.split(/\[|\]/);
        const index = parseInt(indexStr, 10);
        return current?.[arrayKey]?.[index];
      }
      return current?.[key];
    }, obj);
  }

  private async findDependentResources(_resources: SimpleResourceReference[]): Promise<SimpleResourceReference[]> {
    // Find resources that depend on the given resources
    const dependents: SimpleResourceReference[] = [];

    // This is a simplified implementation
    // In a real scenario, you'd analyze labels, selectors, owner references, etc.
    
    return dependents;
  }

  private async findRelatedResources(_resource: SimpleResourceReference): Promise<SimpleResourceReference[]> {
    // Find resources related to the given resource
    const related: SimpleResourceReference[] = [];
    
    // This is a simplified implementation
    // In practice, you'd look at service selectors, ingress backends, etc.
    
    return related;
  }

  private matchesResourceReference(resource: SimpleResourceReference, target: SimpleResourceReference): boolean {
    return resource.kind === target.kind &&
           resource.name === target.name &&
           (resource.namespace || 'default') === (target.namespace || 'default');
  }

  private assessRollbackAvailability(command: CommandRecord): boolean {
    // Simple rollback availability assessment
    if (command.status !== 'completed') return false;
    
    // Commands with deletions are harder to rollback
    const hasDeletes = command.resourceChanges.some(c => c.changeType === 'deleted');
    if (hasDeletes && !command.resourceSnapshot) return false;
    
    // Critical impact changes might be dangerous to rollback
    if (command.impactSummary.potentialImpact === 'critical') return false;
    
    return true;
  }

  private generateImpactDescription(
    intent: string, 
    resourceCount: number, 
    namespaces: string[]
  ): string {
    const nsText = namespaces.length === 1 ? `namespace ${namespaces[0]}` : `${namespaces.length} namespaces`;
    
    if (intent.includes('delete')) {
      return `Will delete ${resourceCount} resources across ${nsText}. This action cannot be easily undone.`;
    } else if (intent.includes('scale')) {
      return `Will scale ${resourceCount} resources in ${nsText}. May affect application availability.`;
    } else if (intent.includes('update')) {
      return `Will update ${resourceCount} resources in ${nsText}. Changes will be applied immediately.`;
    } else {
      return `Will affect ${resourceCount} resources in ${nsText}.`;
    }
  }

  private generateCommandId(): string {
    return `cmd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  // Cleanup
  destroy(): void {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }
    
    // Process remaining changes
    if (this.resourceChangeQueue.length > 0) {
      void this.processResourceChangeQueue();
    }
  }
}

// Default instance
export const commandHistoryService = new CommandHistoryService();

// React hook for command history
import { useRef, useState } from 'react';

export function useCommandHistory() {
  const serviceRef = useRef(commandHistoryService);
  
  const recordCommand = async (
    command: string,
    intent: string,
    parameters: Record<string, any> = {},
    userId: string,
    sessionId: string
  ) => {
    return await serviceRef.current.recordCommand(command, intent, parameters, userId, sessionId);
  };

  const updateCommandStatus = async (
    commandId: string,
    status: CommandRecord['status'],
    error?: string
  ) => {
    return await serviceRef.current.updateCommandStatus(commandId, status, error);
  };

  const searchCommands = async (filter: CommandHistoryFilter) => {
    return await serviceRef.current.searchCommands(filter);
  };

  const getResourceHistory = async (filter: ResourceHistoryFilter) => {
    return await serviceRef.current.getResourceHistory(filter);
  };

  const generateRollbackCommand = async (commandId: string) => {
    return await serviceRef.current.generateRollbackCommand(commandId);
  };

  const getCommandStatistics = async (timeRange: { start: Date; end: Date }) => {
    return await serviceRef.current.getCommandStatistics(timeRange);
  };

  return {
    recordCommand,
    updateCommandStatus,
    searchCommands,
    getResourceHistory,
    generateRollbackCommand,
    getCommandStatistics,
    getCommandById: serviceRef.current.getCommandById.bind(serviceRef.current),
  };
}

export function useCommandTracking(userId?: string, sessionId?: string) {
  const { recordCommand, updateCommandStatus } = useCommandHistory();
  const [activeCommands, setActiveCommands] = useState<Map<string, CommandRecord>>(new Map());

  const trackCommand = async (
    command: string,
    intent: string,
    parameters: Record<string, any> = {}
  ) => {
    if (!userId || !sessionId) {
      throw new Error('User ID and session ID required for command tracking');
    }

    const commandId = await recordCommand(command, intent, parameters, userId, sessionId);
    
    // Track command locally
    const commandRecord: CommandRecord = {
      id: commandId,
      timestamp: new Date(),
      userId,
      sessionId,
      command,
      intent,
      parameters,
      status: 'pending',
      affectedResources: [],
      resourceChanges: [],
      impactSummary: {
        resourcesAffected: 0,
        namespacesCovered: [],
        changeTypes: [],
        potentialImpact: 'low',
        impactDescription: '',
        dependentResources: [],
        rollbackComplexity: 'simple',
      },
      rollbackAvailable: false,
    };

    setActiveCommands(prev => new Map(prev).set(commandId, commandRecord));
    
    return commandId;
  };

  const updateCommand = async (
    commandId: string,
    status: CommandRecord['status'],
    error?: string
  ) => {
    await updateCommandStatus(commandId, status, error);
    
    // Update local state
    setActiveCommands(prev => {
      const updated = new Map(prev);
      const command = updated.get(commandId);
      if (command) {
        command.status = status;
        if (error) command.errorMessage = error;
        updated.set(commandId, command);
      }
      return updated;
    });
  };

  const getActiveCommands = () => {
    return Array.from(activeCommands.values());
  };

  const clearCompletedCommands = () => {
    setActiveCommands(prev => {
      const filtered = new Map();
      for (const [id, command] of prev) {
        if (!['completed', 'failed', 'cancelled'].includes(command.status)) {
          filtered.set(id, command);
        }
      }
      return filtered;
    });
  };

  return {
    trackCommand,
    updateCommand,
    getActiveCommands,
    clearCompletedCommands,
    activeCommands: Array.from(activeCommands.values()),
  };
}