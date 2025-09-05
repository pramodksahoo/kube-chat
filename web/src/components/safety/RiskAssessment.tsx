import React from 'react';
import type { SafetyLevel } from './SafetyIndicator';
import SafetyIndicator from './SafetyIndicator';
import { cn } from '@/utils/cn';

export interface RiskAssessmentData {
  level: SafetyLevel;
  command?: string;
  affectedResources?: string[];
  risks?: string[];
  recommendations?: string[];
  executionTime?: string;
}

export interface RiskAssessmentProps {
  data: RiskAssessmentData;
  variant?: 'compact' | 'detailed';
  className?: string;
}

const RiskAssessment: React.FC<RiskAssessmentProps> = ({
  data,
  variant = 'compact',
  className,
}) => {
  const { level, command, affectedResources, risks, recommendations, executionTime } = data;

  const getRiskDescription = (level: SafetyLevel) => {
    switch (level) {
      case 'safe':
        return 'This operation is safe and will not modify your cluster state.';
      case 'caution':
        return 'This operation requires attention and may modify cluster resources.';
      case 'destructive':
        return 'This operation is destructive and may cause irreversible changes.';
      case 'info':
        return 'This is an informational operation.';
      case 'disabled':
        return 'This operation is not available.';
      default:
        return 'Risk level unknown.';
    }
  };

  if (variant === 'compact') {
    return (
      <div className={cn('flex items-center space-x-2', className)}>
        <SafetyIndicator level={level} variant="icon" />
        <span className="text-sm text-gray-700">{getRiskDescription(level)}</span>
      </div>
    );
  }

  return (
    <div className={cn('space-y-4', className)}>
      {/* Risk Level Header */}
      <div className="flex items-center justify-between">
        <SafetyIndicator 
          level={level} 
          variant="badge" 
          showText={true}
          size="lg"
        />
        {executionTime && (
          <span className="text-sm text-gray-500">
            Est. execution: {executionTime}
          </span>
        )}
      </div>

      {/* Risk Description */}
      <SafetyIndicator 
        level={level} 
        variant="background" 
        size="md"
        className="w-full"
      >
        <p className="text-sm">{getRiskDescription(level)}</p>
      </SafetyIndicator>

      {/* Command Preview */}
      {command && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-900">Generated Command:</h4>
          <div className="bg-gray-900 text-gray-100 p-3 rounded-md font-mono text-sm overflow-x-auto">
            <code>{command}</code>
          </div>
        </div>
      )}

      {/* Affected Resources */}
      {affectedResources && affectedResources.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-900">Affected Resources:</h4>
          <ul className="space-y-1">
            {affectedResources.map((resource, index) => (
              <li 
                key={index} 
                className="text-sm text-gray-700 flex items-center space-x-2"
              >
                <span className="w-1.5 h-1.5 bg-gray-400 rounded-full" />
                <span>{resource}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Risk Details */}
      {risks && risks.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-900">Potential Risks:</h4>
          <ul className="space-y-1">
            {risks.map((risk, index) => (
              <li 
                key={index} 
                className="text-sm text-red-700 flex items-center space-x-2"
              >
                <svg className="w-3 h-3 text-red-500 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <span>{risk}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-gray-900">Recommendations:</h4>
          <ul className="space-y-1">
            {recommendations.map((recommendation, index) => (
              <li 
                key={index} 
                className="text-sm text-blue-700 flex items-center space-x-2"
              >
                <svg className="w-3 h-3 text-blue-500 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                </svg>
                <span>{recommendation}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default RiskAssessment;