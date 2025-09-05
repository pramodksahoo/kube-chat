import React, { useState } from 'react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/ui/button';
import SafetyIndicator from '@/components/safety/SafetyIndicator';
import RiskAssessment from '@/components/safety/RiskAssessment';
import SyntaxHighlighter from '@/components/command/SyntaxHighlighter';
import type { SafetyLevel } from '@/components/safety/SafetyIndicator';
import type { RiskAssessmentData } from '@/components/safety/RiskAssessment';

export interface KubernetesResource {
  kind: string;
  name: string;
  namespace?: string;
  currentState?: Record<string, unknown>;
  targetState?: Record<string, unknown>;
  action: 'create' | 'update' | 'delete' | 'read';
}

export interface PermissionCheck {
  resource: string;
  verb: string;
  namespace?: string;
  status: 'allowed' | 'denied' | 'checking';
  reason?: string;
}

export interface EnhancedCommandConfirmationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  onModify?: () => void;
  command: string;
  safetyLevel: SafetyLevel;
  riskData?: RiskAssessmentData;
  affectedResources: KubernetesResource[];
  permissions: PermissionCheck[];
  impactSummary: {
    scope: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    reversible: boolean;
    estimatedDuration?: string;
    dependencies?: string[];
  };
  commandExplanation: string;
  isLoading?: boolean;
  className?: string;
}

const EnhancedCommandConfirmationDialog: React.FC<EnhancedCommandConfirmationDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  onModify,
  command,
  safetyLevel,
  riskData,
  affectedResources,
  permissions,
  impactSummary,
  commandExplanation,
  isLoading = false,
  className,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'resources' | 'permissions' | 'impact'>('overview');

  if (!isOpen) return null;

  const getSafetyButtonColor = (level: SafetyLevel) => {
    switch (level) {
      case 'safe': return 'bg-[#059669] hover:bg-[#047857]';
      case 'caution': return 'bg-[#d97706] hover:bg-[#b45309]';
      case 'destructive': return 'bg-[#dc2626] hover:bg-[#b91c1c]';
      default: return 'bg-primary-600 hover:bg-primary-700';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'text-green-600 bg-green-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'critical': return 'text-red-600 bg-red-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const getPermissionIcon = (status: PermissionCheck['status']) => {
    switch (status) {
      case 'allowed':
        return (
          <svg className="w-4 h-4 text-green-600" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
          </svg>
        );
      case 'denied':
        return (
          <svg className="w-4 h-4 text-red-600" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        );
      case 'checking':
        return (
          <svg className="w-4 h-4 text-yellow-600 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="m4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
          </svg>
        );
    }
  };

  const hasPermissionIssues = permissions.some(p => p.status === 'denied');
  const canExecute = !hasPermissionIssues && !isLoading;

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirmation-title"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className={cn(
        'bg-white rounded-lg shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden',
        className
      )}>
        {/* Header */}
        <div className={cn(
          'px-6 py-4 border-b border-gray-200',
          safetyLevel === 'destructive' && 'bg-red-50 border-red-200',
          safetyLevel === 'caution' && 'bg-yellow-50 border-yellow-200',
          safetyLevel === 'safe' && 'bg-green-50 border-green-200'
        )}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h2 id="confirmation-title" className="text-lg font-semibold text-gray-900">
                Confirm Command Execution
              </h2>
              <SafetyIndicator 
                level={safetyLevel}
                variant="badge"
                size="md"
                showText={true}
              />
            </div>
            <button
              type="button"
              onClick={onClose}
              className="text-gray-400 hover:text-gray-600 transition-colors"
              aria-label="Close dialog"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
        </div>

        {/* Command Preview */}
        <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
          <h3 className="text-sm font-medium text-gray-700 mb-2">Command to Execute:</h3>
          <SyntaxHighlighter
            code={command}
            language="kubectl"
            showCopyButton={false}
            className="text-sm"
          />
        </div>

        {/* Tabs */}
        <div className="border-b border-gray-200">
          <nav className="flex space-x-8 px-6">
            {[
              { id: 'overview', label: 'Overview' },
              { id: 'resources', label: 'Resources', count: affectedResources.length },
              { id: 'permissions', label: 'Permissions', count: permissions.length },
              { id: 'impact', label: 'Impact Analysis' }
            ].map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as any)}
                className={cn(
                  'py-3 text-sm font-medium border-b-2 transition-colors',
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                )}
              >
                {tab.label}
                {tab.count && (
                  <span className={cn(
                    'ml-2 px-2 py-0.5 rounded-full text-xs',
                    activeTab === tab.id
                      ? 'bg-blue-100 text-blue-600'
                      : 'bg-gray-100 text-gray-600'
                  )}>
                    {tab.count}
                  </span>
                )}
              </button>
            ))}
          </nav>
        </div>

        {/* Tab Content */}
        <div className="px-6 py-6 max-h-96 overflow-y-auto">
          {activeTab === 'overview' && (
            <div className="space-y-4">
              <div>
                <h3 className="text-sm font-medium text-gray-900 mb-2">What this command will do:</h3>
                <p className="text-gray-700">{commandExplanation}</p>
              </div>

              {impactSummary.severity !== 'low' && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                  <div className="flex items-center gap-2 mb-2">
                    <svg className="w-5 h-5 text-yellow-600" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                    <h4 className="text-sm font-medium text-yellow-900">
                      {impactSummary.severity.toUpperCase()} Impact Operation
                    </h4>
                  </div>
                  <p className="text-yellow-800 text-sm">
                    This operation affects {impactSummary.scope} and {impactSummary.reversible ? 'can be' : 'cannot be'} reversed.
                  </p>
                </div>
              )}

              {riskData && (
                <div className="mt-4">
                  <RiskAssessment data={riskData} variant="detailed" />
                </div>
              )}
            </div>
          )}

          {activeTab === 'resources' && (
            <div className="space-y-4">
              <h3 className="text-sm font-medium text-gray-900">Affected Resources ({affectedResources.length})</h3>
              {affectedResources.map((resource, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-medium">{resource.kind}/{resource.name}</span>
                      {resource.namespace && (
                        <span className="text-xs bg-gray-100 text-gray-600 px-2 py-1 rounded">
                          {resource.namespace}
                        </span>
                      )}
                    </div>
                    <span className={cn(
                      'px-2 py-1 rounded-full text-xs font-medium',
                      resource.action === 'delete' && 'bg-red-100 text-red-800',
                      resource.action === 'create' && 'bg-green-100 text-green-800',
                      resource.action === 'update' && 'bg-yellow-100 text-yellow-800',
                      resource.action === 'read' && 'bg-blue-100 text-blue-800'
                    )}>
                      {resource.action}
                    </span>
                  </div>
                  
                  {resource.action !== 'read' && (resource.currentState || resource.targetState) && (
                    <div className="grid grid-cols-2 gap-4 mt-3 text-xs">
                      {resource.currentState && (
                        <div>
                          <h4 className="font-medium text-gray-700 mb-1">Current State</h4>
                          <pre className="bg-gray-100 p-2 rounded overflow-x-auto">
                            {JSON.stringify(resource.currentState, null, 2)}
                          </pre>
                        </div>
                      )}
                      {resource.targetState && (
                        <div>
                          <h4 className="font-medium text-gray-700 mb-1">Target State</h4>
                          <pre className="bg-blue-50 p-2 rounded overflow-x-auto">
                            {JSON.stringify(resource.targetState, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {activeTab === 'permissions' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium text-gray-900">RBAC Permission Check ({permissions.length})</h3>
                {hasPermissionIssues && (
                  <span className="bg-red-100 text-red-800 px-2 py-1 rounded-full text-xs font-medium">
                    Permission Issues Found
                  </span>
                )}
              </div>
              
              <div className="space-y-2">
                {permissions.map((permission, index) => (
                  <div key={index} className={cn(
                    'flex items-center justify-between p-3 border rounded-lg',
                    permission.status === 'denied' && 'border-red-200 bg-red-50',
                    permission.status === 'allowed' && 'border-green-200 bg-green-50',
                    permission.status === 'checking' && 'border-yellow-200 bg-yellow-50'
                  )}>
                    <div className="flex items-center gap-3">
                      {getPermissionIcon(permission.status)}
                      <div>
                        <div className="font-mono text-sm">
                          {permission.verb} {permission.resource}
                          {permission.namespace && <span className="text-gray-500"> in {permission.namespace}</span>}
                        </div>
                        {permission.reason && (
                          <div className="text-xs text-gray-600 mt-1">{permission.reason}</div>
                        )}
                      </div>
                    </div>
                    <span className={cn(
                      'px-2 py-1 rounded-full text-xs font-medium',
                      permission.status === 'allowed' && 'bg-green-100 text-green-800',
                      permission.status === 'denied' && 'bg-red-100 text-red-800',
                      permission.status === 'checking' && 'bg-yellow-100 text-yellow-800'
                    )}>
                      {permission.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'impact' && (
            <div className="space-y-4">
              <h3 className="text-sm font-medium text-gray-900">Impact Analysis</h3>
              
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium text-gray-700">Severity Level</label>
                    <div className={cn(
                      'mt-1 px-3 py-2 rounded-lg text-sm font-medium',
                      getSeverityColor(impactSummary.severity)
                    )}>
                      {impactSummary.severity.toUpperCase()}
                    </div>
                  </div>
                  
                  <div>
                    <label className="text-sm font-medium text-gray-700">Scope</label>
                    <div className="mt-1 text-sm text-gray-900">{impactSummary.scope}</div>
                  </div>
                </div>
                
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium text-gray-700">Reversible</label>
                    <div className={cn(
                      'mt-1 px-3 py-2 rounded-lg text-sm font-medium',
                      impactSummary.reversible ? 'text-green-600 bg-green-50' : 'text-red-600 bg-red-50'
                    )}>
                      {impactSummary.reversible ? 'Yes' : 'No'}
                    </div>
                  </div>
                  
                  {impactSummary.estimatedDuration && (
                    <div>
                      <label className="text-sm font-medium text-gray-700">Estimated Duration</label>
                      <div className="mt-1 text-sm text-gray-900">{impactSummary.estimatedDuration}</div>
                    </div>
                  )}
                </div>
              </div>

              {impactSummary.dependencies && impactSummary.dependencies.length > 0 && (
                <div>
                  <label className="text-sm font-medium text-gray-700">Dependencies</label>
                  <ul className="mt-2 space-y-1">
                    {impactSummary.dependencies.map((dependency, index) => (
                      <li key={index} className="text-sm text-gray-600 flex items-center gap-2">
                        <span className="w-1.5 h-1.5 bg-gray-400 rounded-full"></span>
                        {dependency}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-6 py-4 bg-gray-50 border-t border-gray-200 flex items-center justify-between">
          <div className="flex items-center text-sm text-gray-600">
            {hasPermissionIssues && (
              <div className="flex items-center gap-1 text-red-600">
                <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                Insufficient permissions to execute
              </div>
            )}
            {!hasPermissionIssues && (
              <span>✨ All permissions verified</span>
            )}
          </div>
          
          <div className="flex items-center gap-3">
            <Button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="bg-gray-300 text-gray-700 hover:bg-gray-400"
            >
              Cancel
            </Button>
            
            {onModify && (
              <Button
                type="button"
                onClick={onModify}
                disabled={isLoading}
                className="border border-gray-300 text-gray-700 bg-white hover:bg-gray-50"
              >
                Modify Request
              </Button>
            )}
            
            <Button
              type="button"
              onClick={onConfirm}
              disabled={!canExecute}
              className={cn(
                'text-white',
                getSafetyButtonColor(safetyLevel),
                !canExecute && 'opacity-50 cursor-not-allowed'
              )}
            >
              {isLoading ? 'Executing...' : 'Execute Command'}
            </Button>
          </div>
        </div>

        {/* Audit Notice */}
        <div className="px-6 py-2 bg-blue-50 border-t border-blue-200 text-xs text-blue-800">
          🔒 This action will be logged for compliance and security auditing purposes
        </div>
      </div>
    </div>
  );
};

export default EnhancedCommandConfirmationDialog;