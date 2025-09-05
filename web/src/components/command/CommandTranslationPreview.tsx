import React from 'react';
import { cn } from '@/utils/cn';
import SafetyIndicator from '@/components/safety/SafetyIndicator';
import SyntaxHighlighter from './SyntaxHighlighter';
import type { SafetyLevel } from '@/components/safety/SafetyIndicator';

export interface CommandTranslation {
  originalQuery: string;
  generatedCommand: string;
  confidence: number;
  explanation: string;
  safetyLevel: SafetyLevel;
  alternatives?: {
    command: string;
    explanation: string;
    confidence: number;
  }[];
  affectedResources?: string[];
  requiredPermissions?: string[];
}

export interface CommandTranslationPreviewProps {
  translation: CommandTranslation;
  onApprove?: (command: string) => void;
  onModify?: (command: string) => void;
  onSelectAlternative?: (alternative: { command: string; explanation: string }) => void;
  isLoading?: boolean;
  showAlternatives?: boolean;
  className?: string;
}

const getConfidenceColor = (confidence: number): string => {
  if (confidence >= 0.8) return 'text-safe-600 bg-safe-50';
  if (confidence >= 0.6) return 'text-caution-600 bg-caution-50';
  return 'text-destructive-600 bg-destructive-50';
};

const getConfidenceText = (confidence: number): string => {
  if (confidence >= 0.9) return 'High Confidence';
  if (confidence >= 0.7) return 'Good Confidence';
  if (confidence >= 0.5) return 'Medium Confidence';
  return 'Low Confidence';
};

const CommandTranslationPreview: React.FC<CommandTranslationPreviewProps> = ({
  translation,
  onApprove,
  onModify,
  onSelectAlternative,
  isLoading = false,
  showAlternatives = true,
  className,
}) => {
  const confidencePercentage = Math.round(translation.confidence * 100);

  return (
    <div className={cn('space-y-4', className)}>
      {/* Original Query Display */}
      <div className="bg-gray-50 rounded-lg p-4">
        <h3 className="text-sm font-medium text-gray-700 mb-2">Natural Language Query:</h3>
        <p className="text-gray-900 italic">"{translation.originalQuery}"</p>
      </div>

      {/* Translation Result */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="bg-gray-50 px-4 py-3 border-b border-gray-200">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <h3 className="text-sm font-medium text-gray-900">Generated Command</h3>
              <SafetyIndicator 
                level={translation.safetyLevel}
                variant="badge"
                size="sm"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className={cn(
                'px-2 py-1 rounded-full text-xs font-medium',
                getConfidenceColor(translation.confidence)
              )}>
                {getConfidenceText(translation.confidence)} ({confidencePercentage}%)
              </span>
            </div>
          </div>
        </div>

        <SyntaxHighlighter
          code={translation.generatedCommand}
          language="kubectl"
          showCopyButton={true}
          className="rounded-t-none"
        />
      </div>

      {/* Command Explanation */}
      <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
        <h4 className="text-sm font-medium text-blue-900 mb-2 flex items-center gap-2">
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
          </svg>
          What this command will do:
        </h4>
        <p className="text-blue-800">{translation.explanation}</p>
      </div>

      {/* Affected Resources */}
      {translation.affectedResources && translation.affectedResources.length > 0 && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
          <h4 className="text-sm font-medium text-yellow-900 mb-2">Affected Resources:</h4>
          <ul className="space-y-1">
            {translation.affectedResources.map((resource, index) => (
              <li key={index} className="text-sm text-yellow-800 flex items-center gap-2">
                <span className="w-1.5 h-1.5 bg-yellow-400 rounded-full"></span>
                {resource}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Required Permissions */}
      {translation.requiredPermissions && translation.requiredPermissions.length > 0 && (
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-4">
          <h4 className="text-sm font-medium text-purple-900 mb-2">Required Permissions:</h4>
          <div className="flex flex-wrap gap-2">
            {translation.requiredPermissions.map((permission, index) => (
              <span key={index} className="px-2 py-1 bg-purple-100 text-purple-800 text-xs rounded-md">
                {permission}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Alternative Suggestions */}
      {showAlternatives && translation.alternatives && translation.alternatives.length > 0 && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium text-gray-900">Alternative Commands:</h4>
          {translation.alternatives.map((alternative, index) => (
            <div key={index} className="border border-gray-200 rounded-lg p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-500">Alternative {index + 1}</span>
                <div className="flex items-center gap-2">
                  <span className={cn(
                    'px-2 py-1 rounded-full text-xs font-medium',
                    getConfidenceColor(alternative.confidence)
                  )}>
                    {Math.round(alternative.confidence * 100)}%
                  </span>
                  <button
                    type="button"
                    onClick={() => onSelectAlternative?.(alternative)}
                    className="text-xs text-blue-600 hover:text-blue-800 font-medium"
                  >
                    Use This
                  </button>
                </div>
              </div>
              <code className="text-sm font-mono bg-gray-100 px-2 py-1 rounded block mb-2">
                {alternative.command}
              </code>
              <p className="text-sm text-gray-600">{alternative.explanation}</p>
            </div>
          ))}
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex items-center gap-3 pt-4 border-t border-gray-200">
        <button
          type="button"
          onClick={() => onApprove?.(translation.generatedCommand)}
          disabled={isLoading}
          className={cn(
            'px-4 py-2 rounded-md font-medium text-sm transition-colors',
            translation.safetyLevel === 'safe' 
              ? 'bg-safe-600 hover:bg-safe-700 text-white'
              : translation.safetyLevel === 'caution'
              ? 'bg-caution-600 hover:bg-caution-700 text-white'
              : 'bg-destructive-600 hover:bg-destructive-700 text-white',
            isLoading && 'opacity-50 cursor-not-allowed'
          )}
        >
          {isLoading ? 'Processing...' : 'Execute Command'}
        </button>
        
        <button
          type="button"
          onClick={() => onModify?.(translation.generatedCommand)}
          disabled={isLoading}
          className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          Modify
        </button>

        <div className="flex-1"></div>

        {translation.confidence < 0.7 && (
          <div className="text-xs text-amber-600 flex items-center gap-1">
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            Review carefully - confidence below 70%
          </div>
        )}
      </div>
    </div>
  );
};

export default CommandTranslationPreview;