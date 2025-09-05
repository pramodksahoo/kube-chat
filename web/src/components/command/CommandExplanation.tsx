import React, { useState } from 'react';
import { cn } from '@/utils/cn';

export interface KubectlCommandPart {
  part: string;
  type: 'command' | 'verb' | 'resource' | 'name' | 'flag' | 'value' | 'namespace';
  explanation: string;
}

export interface CommandExplanationProps {
  command: string;
  fullExplanation: string;
  parts?: KubectlCommandPart[];
  examples?: {
    description: string;
    command: string;
  }[];
  relatedCommands?: {
    description: string;
    command: string;
  }[];
  className?: string;
}

const getPartColor = (type: KubectlCommandPart['type']): string => {
  switch (type) {
    case 'command': return 'text-blue-600 bg-blue-50';
    case 'verb': return 'text-green-600 bg-green-50';
    case 'resource': return 'text-purple-600 bg-purple-50';
    case 'name': return 'text-orange-600 bg-orange-50';
    case 'flag': return 'text-yellow-600 bg-yellow-50';
    case 'value': return 'text-pink-600 bg-pink-50';
    case 'namespace': return 'text-cyan-600 bg-cyan-50';
    default: return 'text-gray-600 bg-gray-50';
  }
};

const CommandExplanation: React.FC<CommandExplanationProps> = ({
  command,
  fullExplanation,
  parts = [],
  examples = [],
  relatedCommands = [],
  className,
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'breakdown' | 'examples' | 'related'>('overview');
  const [hoveredPart, setHoveredPart] = useState<string | null>(null);

  const renderCommandWithHighlight = () => {
    if (parts.length === 0) {
      return <code className="text-sm">{command}</code>;
    }

    return (
      <div className="font-mono text-sm">
        {parts.map((part, index) => (
          <span
            key={index}
            onMouseEnter={() => setHoveredPart(part.part)}
            onMouseLeave={() => setHoveredPart(null)}
            className={cn(
              'px-1 py-0.5 rounded cursor-help transition-colors',
              getPartColor(part.type),
              hoveredPart === part.part && 'ring-2 ring-blue-300'
            )}
            title={part.explanation}
          >
            {part.part}
          </span>
        ))}
      </div>
    );
  };

  const tabs = [
    { id: 'overview', label: 'Overview', count: null },
    { id: 'breakdown', label: 'Breakdown', count: parts.length > 0 ? parts.length : null },
    { id: 'examples', label: 'Examples', count: examples.length > 0 ? examples.length : null },
    { id: 'related', label: 'Related', count: relatedCommands.length > 0 ? relatedCommands.length : null },
  ] as const;

  return (
    <div className={cn('bg-white border border-gray-200 rounded-lg', className)}>
      {/* Header with Command */}
      <div className="bg-gray-50 px-4 py-3 border-b border-gray-200">
        <h3 className="text-sm font-medium text-gray-900 mb-2">Command Explanation</h3>
        <div className="bg-gray-900 text-gray-100 p-3 rounded font-mono text-sm overflow-x-auto">
          {renderCommandWithHighlight()}
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        <nav className="flex space-x-8 px-4">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              onClick={() => setActiveTab(tab.id)}
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
      <div className="p-4">
        {activeTab === 'overview' && (
          <div className="space-y-3">
            <p className="text-gray-900 leading-relaxed">{fullExplanation}</p>
            {parts.length > 0 && (
              <div className="text-xs text-gray-500">
                💡 Hover over colored parts in the command above to see detailed explanations
              </div>
            )}
          </div>
        )}

        {activeTab === 'breakdown' && parts.length > 0 && (
          <div className="space-y-3">
            {parts.map((part, index) => (
              <div key={index} className="flex items-start gap-3 p-3 bg-gray-50 rounded-lg">
                <span className={cn(
                  'px-2 py-1 rounded text-xs font-mono font-medium',
                  getPartColor(part.type)
                )}>
                  {part.part}
                </span>
                <div className="flex-1">
                  <span className="text-xs font-medium text-gray-500 uppercase tracking-wide">
                    {part.type}
                  </span>
                  <p className="text-sm text-gray-900 mt-1">{part.explanation}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'breakdown' && parts.length === 0 && (
          <div className="text-center py-6 text-gray-500">
            <p>Detailed breakdown not available for this command.</p>
          </div>
        )}

        {activeTab === 'examples' && examples.length > 0 && (
          <div className="space-y-4">
            {examples.map((example, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-3">
                <h4 className="text-sm font-medium text-gray-900 mb-2">{example.description}</h4>
                <code className="block bg-gray-900 text-gray-100 p-2 rounded text-sm font-mono">
                  {example.command}
                </code>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'examples' && examples.length === 0 && (
          <div className="text-center py-6 text-gray-500">
            <p>No examples available for this command.</p>
          </div>
        )}

        {activeTab === 'related' && relatedCommands.length > 0 && (
          <div className="space-y-3">
            {relatedCommands.map((related, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-3">
                <p className="text-sm text-gray-700 mb-2">{related.description}</p>
                <code className="block bg-gray-900 text-gray-100 p-2 rounded text-sm font-mono">
                  {related.command}
                </code>
              </div>
            ))}
          </div>
        )}

        {activeTab === 'related' && relatedCommands.length === 0 && (
          <div className="text-center py-6 text-gray-500">
            <p>No related commands available.</p>
          </div>
        )}
      </div>

      {/* Hovered Part Tooltip */}
      {hoveredPart && (
        <div className="border-t border-gray-200 bg-blue-50 px-4 py-2">
          <div className="text-xs text-blue-600 font-medium">
            {parts.find(p => p.part === hoveredPart)?.explanation}
          </div>
        </div>
      )}
    </div>
  );
};

export default CommandExplanation;