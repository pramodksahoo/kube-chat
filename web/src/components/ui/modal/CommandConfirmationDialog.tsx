import React from 'react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/ui/button';
import SafetyIndicator from '@/components/safety/SafetyIndicator';
import RiskAssessment from '@/components/safety/RiskAssessment';
import type { SafetyLevel } from '@/components/safety/SafetyIndicator';
import type { RiskAssessmentData } from '@/components/safety/RiskAssessment';

export interface CommandConfirmationDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  onModify?: () => void;
  command: string;
  safetyLevel: SafetyLevel;
  riskData?: RiskAssessmentData;
  isLoading?: boolean;
  className?: string;
}

const CommandConfirmationDialog: React.FC<CommandConfirmationDialogProps> = ({
  isOpen,
  onClose,
  onConfirm,
  onModify,
  command,
  safetyLevel,
  riskData,
  isLoading = false,
  className,
}) => {
  if (!isOpen) return null;

  const getSafetyButtonColor = (level: SafetyLevel) => {
    switch (level) {
      case 'safe': return 'bg-[#059669] hover:bg-[#047857]';
      case 'caution': return 'bg-[#d97706] hover:bg-[#b45309]';
      case 'destructive': return 'bg-[#dc2626] hover:bg-[#b91c1c]';
      default: return 'bg-primary-600 hover:bg-primary-700';
    }
  };

  return (
    <div
      className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
      role="dialog"
      aria-modal="true"
      aria-labelledby="confirmation-title"
    >
      <div
        className={cn(
          'bg-white rounded-lg shadow-xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto',
          className
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <h2 id="confirmation-title" className="text-lg font-semibold text-gray-900">
              Command Execution Confirmation
            </h2>
            <SafetyIndicator
              level={safetyLevel}
              variant="badge"
              showText={true}
              size="md"
            />
          </div>
        </div>

        {/* Content */}
        <div className="px-6 py-4 space-y-4">
          {/* Risk Assessment */}
          {riskData ? (
            <RiskAssessment data={riskData} variant="detailed" />
          ) : (
            <div className="space-y-3">
              <div>
                <h3 className="text-sm font-medium text-gray-900 mb-2">Command to Execute:</h3>
                <div className="bg-gray-900 text-gray-100 p-3 rounded-md font-mono text-sm overflow-x-auto">
                  <code>{command}</code>
                </div>
              </div>
              <SafetyIndicator
                level={safetyLevel}
                variant="background"
                showText={true}
                className="w-full"
              >
                <p className="text-sm mt-1">
                  This command has been classified as {safetyLevel}. Please review carefully before proceeding.
                </p>
              </SafetyIndicator>
            </div>
          )}

          {/* Audit Notice */}
          <div className="bg-blue-50 border border-blue-200 rounded-md p-3">
            <div className="flex items-start space-x-2">
              <svg className="w-4 h-4 text-blue-500 mt-0.5 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
              </svg>
              <div className="text-sm text-blue-700">
                <span className="font-medium">Audit Notice:</span> This action will be logged for security and compliance purposes.
              </div>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="px-6 py-4 bg-gray-50 border-t border-gray-200 flex justify-end space-x-3">
          <Button
            variant="outline"
            onClick={onClose}
            disabled={isLoading}
            type="button"
          >
            Cancel
          </Button>
          
          {onModify && (
            <Button
              variant="outline"
              onClick={onModify}
              disabled={isLoading}
              type="button"
            >
              Modify Request
            </Button>
          )}
          
          <Button
            className={getSafetyButtonColor(safetyLevel)}
            onClick={onConfirm}
            disabled={isLoading}
            type="button"
          >
            {isLoading ? 'Executing...' : 'Execute Command'}
          </Button>
        </div>
      </div>
    </div>
  );
};

export default CommandConfirmationDialog;