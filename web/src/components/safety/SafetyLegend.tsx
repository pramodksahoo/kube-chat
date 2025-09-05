import React from 'react';
import { cn } from '@/utils/cn';
import SafetyIndicator from './SafetyIndicator';
import type { SafetyLevel } from './SafetyIndicator';

export interface SafetyLegendProps {
  variant?: 'horizontal' | 'vertical';
  showDescriptions?: boolean;
  className?: string;
}

const SafetyLegend: React.FC<SafetyLegendProps> = ({
  variant = 'horizontal',
  showDescriptions = true,
  className,
}) => {
  const safetyLevels: Array<{
    level: SafetyLevel;
    label: string;
    description: string;
    examples: string[];
  }> = [
    {
      level: 'safe',
      label: 'Safe Operations',
      description: 'Read operations and informational commands that do not modify cluster state.',
      examples: ['kubectl get', 'kubectl describe', 'kubectl logs'],
    },
    {
      level: 'caution',
      label: 'Caution Required',
      description: 'Operations that may modify resources and require attention.',
      examples: ['kubectl apply', 'kubectl patch', 'kubectl scale'],
    },
    {
      level: 'destructive',
      label: 'Destructive Operations',
      description: 'Operations that may cause irreversible changes or data loss.',
      examples: ['kubectl delete', 'kubectl rollback', 'kubectl drain'],
    },
    {
      level: 'info',
      label: 'Informational',
      description: 'System messages and informational content.',
      examples: ['Status updates', 'Help messages', 'Confirmations'],
    },
    {
      level: 'disabled',
      label: 'Disabled',
      description: 'Operations that are not available or accessible.',
      examples: ['Restricted commands', 'Unavailable features'],
    },
  ];

  const isVertical = variant === 'vertical';

  return (
    <div
      className={cn(
        'safety-legend rounded-lg border border-gray-200 bg-white shadow-sm',
        className
      )}
      role="region"
      aria-labelledby="safety-legend-title"
    >
      <div className="p-4 border-b border-gray-200">
        <h3 
          id="safety-legend-title"
          className="text-sm font-semibold text-gray-900"
        >
          Command Safety Levels
        </h3>
        <p className="text-xs text-gray-600 mt-1">
          Visual indicators to help you understand operation risk levels
        </p>
      </div>
      
      <div className={cn(
        'p-4 space-y-3',
        !isVertical && 'grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 space-y-0'
      )}>
        {safetyLevels.map((item) => (
          <div
            key={item.level}
            className={cn(
              'safety-legend-item',
              isVertical && 'border-b border-gray-100 last:border-b-0 pb-3 last:pb-0'
            )}
          >
            <div className="flex items-start space-x-3">
              <SafetyIndicator
                level={item.level}
                variant="badge"
                showText={false}
                className="mt-0.5 flex-shrink-0"
              />
              
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2 mb-1">
                  <h4 className="text-sm font-medium text-gray-900">
                    {item.label}
                  </h4>
                  <span 
                    className="text-xs text-gray-500 uppercase tracking-wide font-mono"
                    aria-label={`Safety level: ${item.level}`}
                  >
                    {item.level}
                  </span>
                </div>
                
                {showDescriptions && (
                  <>
                    <p className="text-xs text-gray-600 mb-2 leading-relaxed">
                      {item.description}
                    </p>
                    
                    <div className="space-y-1">
                      <span className="text-xs text-gray-500 font-medium">
                        Examples:
                      </span>
                      <ul className="text-xs text-gray-600 space-y-0.5">
                        {item.examples.map((example, index) => (
                          <li key={index} className="flex items-center space-x-1">
                            <span className="w-1 h-1 bg-gray-400 rounded-full flex-shrink-0" />
                            <code className="font-mono text-xs bg-gray-50 px-1 py-0.5 rounded">
                              {example}
                            </code>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="px-4 py-3 bg-gray-50 text-xs text-gray-600 border-t border-gray-200 rounded-b-lg">
        <div className="flex items-center space-x-2">
          <svg className="w-3 h-3 text-gray-500" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
          <span>
            All operations are logged for security and compliance. High-risk commands require additional confirmation.
          </span>
        </div>
      </div>
    </div>
  );
};

export default SafetyLegend;