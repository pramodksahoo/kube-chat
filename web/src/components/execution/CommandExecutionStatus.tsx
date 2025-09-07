import React, { useEffect, useState } from 'react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/ui/button';

export type ExecutionPhase = 
  | 'queued'
  | 'validating'
  | 'preparing'
  | 'executing'
  | 'finalizing'
  | 'completed'
  | 'failed'
  | 'cancelled';

export interface ExecutionStep {
  id: string;
  name: string;
  phase: ExecutionPhase;
  status: 'pending' | 'in_progress' | 'completed' | 'failed' | 'cancelled';
  startTime?: string;
  endTime?: string;
  estimatedDuration?: number;
  actualDuration?: number;
  message?: string;
  error?: string;
  progress?: number; // 0-100
}

export interface CommandExecutionStatusProps {
  executionId: string;
  command: string;
  steps: ExecutionStep[];
  overallStatus: ExecutionPhase;
  isInterruptible?: boolean;
  onCancel?: () => void;
  onRetry?: () => void;
  className?: string;
}

const CommandExecutionStatus: React.FC<CommandExecutionStatusProps> = ({
  executionId,
  command,
  steps,
  overallStatus,
  isInterruptible = false,
  onCancel,
  onRetry,
  className,
}) => {
  const [elapsedTime, setElapsedTime] = useState(0);
  const [isExpanded, setIsExpanded] = useState(true);

  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (overallStatus === 'executing' || overallStatus === 'preparing' || overallStatus === 'validating') {
      interval = setInterval(() => {
        setElapsedTime(prev => prev + 1);
      }, 1000);
    }
    
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [overallStatus]);

  const formatDuration = (seconds: number): string => {
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}m ${remainingSeconds}s`;
  };

  const getStatusIcon = (status: ExecutionStep['status']) => {
    switch (status) {
      case 'pending':
        return (
          <div className="w-4 h-4 rounded-full border-2 border-gray-300" />
        );
      case 'in_progress':
        return (
          <div className="w-4 h-4 rounded-full border-2 border-blue-500 animate-pulse">
            <div className="w-2 h-2 bg-blue-500 rounded-full animate-spin" />
          </div>
        );
      case 'completed':
        return (
          <div className="w-4 h-4 rounded-full bg-green-500 flex items-center justify-center">
            <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
            </svg>
          </div>
        );
      case 'failed':
        return (
          <div className="w-4 h-4 rounded-full bg-red-500 flex items-center justify-center">
            <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </div>
        );
      case 'cancelled':
        return (
          <div className="w-4 h-4 rounded-full bg-gray-500 flex items-center justify-center">
            <svg className="w-2.5 h-2.5 text-white" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
          </div>
        );
      default:
        return null;
    }
  };

  const getOverallStatusColor = () => {
    switch (overallStatus) {
      case 'queued':
      case 'preparing':
      case 'validating':
        return 'text-yellow-600 bg-yellow-50 border-yellow-200';
      case 'executing':
        return 'text-blue-600 bg-blue-50 border-blue-200';
      case 'completed':
        return 'text-green-600 bg-green-50 border-green-200';
      case 'failed':
        return 'text-red-600 bg-red-50 border-red-200';
      case 'cancelled':
        return 'text-gray-600 bg-gray-50 border-gray-200';
      default:
        return 'text-gray-600 bg-gray-50 border-gray-200';
    }
  };

  const getOverallStatusText = () => {
    switch (overallStatus) {
      case 'queued':
        return 'Queued for Execution';
      case 'validating':
        return 'Validating Command';
      case 'preparing':
        return 'Preparing Execution';
      case 'executing':
        return 'Executing Command';
      case 'finalizing':
        return 'Finalizing';
      case 'completed':
        return 'Execution Complete';
      case 'failed':
        return 'Execution Failed';
      case 'cancelled':
        return 'Execution Cancelled';
      default:
        return 'Unknown Status';
    }
  };

  const activeStep = steps.find(step => step.status === 'in_progress');
  const completedSteps = steps.filter(step => step.status === 'completed').length;
  const totalSteps = steps.length;
  const progressPercentage = totalSteps > 0 ? (completedSteps / totalSteps) * 100 : 0;

  return (
    <div className={cn('bg-white rounded-lg shadow-sm border border-gray-200', className)}>
      {/* Header */}
      <div className={cn('px-4 py-3 border-b border-gray-200 rounded-t-lg', getOverallStatusColor())}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="flex items-center space-x-2">
              <span className="text-sm font-medium">{getOverallStatusText()}</span>
              {elapsedTime > 0 && (
                <span className="text-xs opacity-75">
                  {formatDuration(elapsedTime)}
                </span>
              )}
            </div>
            {activeStep && (
              <div className="text-xs opacity-75">
                {activeStep.name}
              </div>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs">
              {completedSteps}/{totalSteps} steps
            </span>
            {isInterruptible && onCancel && overallStatus === 'executing' && (
              <Button
                variant="outline"
                size="sm"
                onClick={onCancel}
                className="text-red-600 border-red-300 hover:bg-red-50"
              >
                Cancel
              </Button>
            )}
            {overallStatus === 'failed' && onRetry && (
              <Button
                variant="outline"
                size="sm"
                onClick={onRetry}
                className="text-blue-600 border-blue-300 hover:bg-blue-50"
              >
                Retry
              </Button>
            )}
            <button
              onClick={() => setIsExpanded(!isExpanded)}
              className="text-gray-500 hover:text-gray-700"
              aria-label={isExpanded ? 'Collapse details' : 'Expand details'}
            >
              <svg
                className={cn('w-4 h-4 transition-transform', isExpanded ? 'rotate-180' : '')}
                viewBox="0 0 20 20"
                fill="currentColor"
              >
                <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd" />
              </svg>
            </button>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="mt-3">
          <div className="flex justify-between text-xs mb-1">
            <span>Progress</span>
            <span>{Math.round(progressPercentage)}%</span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-2">
            <div
              className={cn(
                'h-2 rounded-full transition-all duration-300',
                overallStatus === 'completed' ? 'bg-green-500' :
                overallStatus === 'failed' ? 'bg-red-500' :
                overallStatus === 'cancelled' ? 'bg-gray-500' :
                'bg-blue-500'
              )}
              style={{ width: `${progressPercentage}%` }}
            />
          </div>
        </div>
      </div>

      {/* Command Display */}
      <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
        <div className="text-xs text-gray-600 mb-1">Command</div>
        <div className="bg-gray-900 text-gray-100 p-2 rounded font-mono text-sm overflow-x-auto">
          <code>{command}</code>
        </div>
      </div>

      {/* Steps Details */}
      {isExpanded && (
        <div className="px-4 py-3">
          <div className="space-y-3">
            {steps.map((step, _index) => (
              <div
                key={step.id}
                className={cn(
                  'flex items-start space-x-3 p-3 rounded-lg',
                  step.status === 'in_progress' ? 'bg-blue-50' :
                  step.status === 'completed' ? 'bg-green-50' :
                  step.status === 'failed' ? 'bg-red-50' :
                  'bg-gray-50'
                )}
              >
                <div className="flex-shrink-0 mt-1">
                  {getStatusIcon(step.status)}
                </div>
                <div className="flex-grow min-w-0">
                  <div className="flex items-center justify-between">
                    <h4 className="text-sm font-medium text-gray-900">
                      {step.name}
                    </h4>
                    <div className="text-xs text-gray-500">
                      {step.actualDuration && formatDuration(step.actualDuration)}
                      {step.estimatedDuration && step.status === 'in_progress' && (
                        <span className="ml-1">
                          (~{formatDuration(step.estimatedDuration)})
                        </span>
                      )}
                    </div>
                  </div>
                  
                  {step.message && (
                    <p className="text-xs text-gray-600 mt-1">{step.message}</p>
                  )}
                  
                  {step.error && (
                    <p className="text-xs text-red-600 mt-1">{step.error}</p>
                  )}
                  
                  {step.status === 'in_progress' && step.progress !== undefined && (
                    <div className="mt-2">
                      <div className="w-full bg-gray-200 rounded-full h-1">
                        <div
                          className="bg-blue-500 h-1 rounded-full transition-all duration-300"
                          style={{ width: `${step.progress}%` }}
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Execution ID Footer */}
      <div className="px-4 py-2 bg-gray-50 text-xs text-gray-500 rounded-b-lg border-t border-gray-200">
        Execution ID: {executionId}
      </div>
    </div>
  );
};

export default CommandExecutionStatus;