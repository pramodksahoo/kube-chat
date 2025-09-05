import React, { useMemo, useState } from 'react';
import { cn } from '@/utils/cn';
import { Button } from '@/components/ui/button';

export interface CommandOutput {
  stdout?: string;
  stderr?: string;
  exitCode: number;
  duration: number;
  timestamp: string;
}

export interface CommandResultsProps {
  executionId: string;
  command: string;
  output: CommandOutput;
  onRerun?: () => void;
  onExport?: (format: 'json' | 'yaml' | 'text') => void;
  className?: string;
}

interface ParsedKubectlOutput {
  type: 'table' | 'yaml' | 'json' | 'text';
  data: any;
  headers?: string[];
  rows?: string[][];
}

const CommandResults: React.FC<CommandResultsProps> = ({
  executionId,
  command,
  output,
  onRerun,
  onExport,
  className,
}) => {
  const [viewMode, setViewMode] = useState<'formatted' | 'raw'>('formatted');
  const [selectedFormat, setSelectedFormat] = useState<'json' | 'yaml' | 'text'>('text');

  const parsedOutput = useMemo((): ParsedKubectlOutput => {
    if (!output.stdout) {
      return { type: 'text', data: '' };
    }

    const stdout = output.stdout.trim();

    // Try to parse as JSON
    try {
      const jsonData = JSON.parse(stdout);
      return { type: 'json', data: jsonData };
    } catch {
      // Not JSON, continue
    }

    // Check if it's YAML (starts with apiVersion or kind)
    if (stdout.match(/^(apiVersion|kind):/m)) {
      return { type: 'yaml', data: stdout };
    }

    // Check if it's a kubectl table output (has headers with NAME, READY, etc.)
    const lines = stdout.split('\n').filter(line => line.trim());
    if (lines.length >= 2) {
      const firstLine = lines[0];
      // Common kubectl table headers
      const tableHeaders = ['NAME', 'READY', 'STATUS', 'RESTARTS', 'AGE', 'NAMESPACE', 'TYPE', 'CLUSTER-IP'];
      const isTableOutput = tableHeaders.some(header => firstLine.includes(header));
      
      if (isTableOutput) {
        const headers = firstLine.split(/\s{2,}/).filter(h => h.trim());
        const rows = lines.slice(1).map(line => 
          line.split(/\s{2,}/).filter(cell => cell.trim())
        ).filter(row => row.length > 0);
        
        return { type: 'table', data: { headers, rows }, headers, rows };
      }
    }

    // Default to text
    return { type: 'text', data: stdout };
  }, [output.stdout]);

  const formatDuration = (ms: number): string => {
    if (ms < 1000) return `${ms}ms`;
    if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`;
    return `${(ms / 60000).toFixed(1)}m`;
  };

  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleString();
  };

  const renderFormattedOutput = () => {
    switch (parsedOutput.type) {
      case 'table':
        return (
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  {parsedOutput.headers?.map((header, index) => (
                    <th
                      key={index}
                      className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                    >
                      {header}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {parsedOutput.rows?.map((row, rowIndex) => (
                  <tr key={rowIndex} className="hover:bg-gray-50">
                    {row.map((cell, cellIndex) => (
                      <td
                        key={cellIndex}
                        className="px-3 py-2 whitespace-nowrap text-sm text-gray-900 font-mono"
                      >
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );

      case 'json':
        return (
          <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono">
            <code>{JSON.stringify(parsedOutput.data, null, 2)}</code>
          </pre>
        );

      case 'yaml':
        return (
          <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono">
            <code>{parsedOutput.data}</code>
          </pre>
        );

      case 'text':
      default:
        return (
          <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap">
            <code>{parsedOutput.data}</code>
          </pre>
        );
    }
  };

  const renderRawOutput = () => (
    <pre className="bg-gray-900 text-gray-100 p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap">
      <code>{output.stdout || '(no output)'}</code>
    </pre>
  );

  const getStatusIcon = () => {
    if (output.exitCode === 0) {
      return (
        <div className="w-5 h-5 bg-green-500 rounded-full flex items-center justify-center">
          <svg className="w-3 h-3 text-white" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
          </svg>
        </div>
      );
    } else {
      return (
        <div className="w-5 h-5 bg-red-500 rounded-full flex items-center justify-center">
          <svg className="w-3 h-3 text-white" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
          </svg>
        </div>
      );
    }
  };

  const handleExport = () => {
    onExport?.(selectedFormat);
  };

  return (
    <div className={cn('bg-white rounded-lg shadow-sm border border-gray-200', className)}>
      {/* Header */}
      <div className={cn(
        'px-4 py-3 border-b border-gray-200 rounded-t-lg',
        output.exitCode === 0 
          ? 'bg-green-50 border-green-200 text-green-800'
          : 'bg-red-50 border-red-200 text-red-800'
      )}>
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getStatusIcon()}
            <div>
              <h3 className="text-sm font-medium">
                {output.exitCode === 0 ? 'Command Executed Successfully' : 'Command Failed'}
              </h3>
              <p className="text-xs opacity-75 mt-0.5">
                Completed in {formatDuration(output.duration)} • {formatTimestamp(output.timestamp)}
              </p>
            </div>
          </div>
          
          <div className="flex items-center space-x-2">
            <div className="text-xs">
              Exit code: {output.exitCode}
            </div>
            {onRerun && (
              <Button
                variant="outline"
                size="sm"
                onClick={onRerun}
                className="text-gray-600 border-gray-300 hover:bg-gray-50"
              >
                Rerun
              </Button>
            )}
          </div>
        </div>
      </div>

      {/* Command Display */}
      <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-gray-600">Command</span>
          <span className="text-xs text-gray-500">ID: {executionId}</span>
        </div>
        <div className="bg-gray-900 text-gray-100 p-2 rounded font-mono text-sm overflow-x-auto">
          <code>{command}</code>
        </div>
      </div>

      {/* View Controls */}
      <div className="px-4 py-3 border-b border-gray-200 bg-gray-50">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            {/* View Mode Toggle */}
            <div className="flex items-center space-x-2">
              <span className="text-xs text-gray-600">View:</span>
              <div className="flex bg-white rounded-md border border-gray-300">
                <button
                  onClick={() => setViewMode('formatted')}
                  className={cn(
                    'px-3 py-1 text-xs font-medium rounded-l-md',
                    viewMode === 'formatted'
                      ? 'bg-blue-50 text-blue-700 border-r border-blue-200'
                      : 'text-gray-600 hover:text-gray-900'
                  )}
                >
                  Formatted
                </button>
                <button
                  onClick={() => setViewMode('raw')}
                  className={cn(
                    'px-3 py-1 text-xs font-medium rounded-r-md',
                    viewMode === 'raw'
                      ? 'bg-blue-50 text-blue-700 border-l border-blue-200'
                      : 'text-gray-600 hover:text-gray-900'
                  )}
                >
                  Raw
                </button>
              </div>
            </div>

            {/* Output Type Badge */}
            <div className={cn(
              'inline-flex items-center px-2 py-1 rounded text-xs font-medium',
              parsedOutput.type === 'table' ? 'bg-blue-100 text-blue-800' :
              parsedOutput.type === 'json' ? 'bg-purple-100 text-purple-800' :
              parsedOutput.type === 'yaml' ? 'bg-orange-100 text-orange-800' :
              'bg-gray-100 text-gray-800'
            )}>
              {parsedOutput.type.toUpperCase()}
            </div>
          </div>

          {/* Export Controls */}
          {onExport && (
            <div className="flex items-center space-x-2">
              <select
                value={selectedFormat}
                onChange={(e) => setSelectedFormat(e.target.value as 'json' | 'yaml' | 'text')}
                className="text-xs border border-gray-300 rounded px-2 py-1"
              >
                <option value="text">Text</option>
                <option value="json">JSON</option>
                <option value="yaml">YAML</option>
              </select>
              <Button
                variant="outline"
                size="sm"
                onClick={handleExport}
                className="text-gray-600 border-gray-300 hover:bg-gray-50"
              >
                Export
              </Button>
            </div>
          )}
        </div>
      </div>

      {/* Output Content */}
      <div className="p-4">
        {viewMode === 'formatted' ? renderFormattedOutput() : renderRawOutput()}
        
        {/* Error Output */}
        {output.stderr && (
          <div className="mt-4">
            <h4 className="text-sm font-medium text-red-800 mb-2">Error Output</h4>
            <pre className="bg-red-900 text-red-100 p-4 rounded-lg overflow-x-auto text-sm font-mono whitespace-pre-wrap">
              <code>{output.stderr}</code>
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};

export default CommandResults;