/**
 * ResourceDescribe - YAML resource description with syntax highlighting
 * Displays kubectl describe equivalent information with formatted YAML
 */

import React, { memo, useEffect, useState } from 'react';
import { kubernetesApi, type ResourceStatus } from '../../services/kubernetesApi';

export interface ResourceDescribeProps {
  resource: ResourceStatus;
  className?: string;
}

export const ResourceDescribe: React.FC<ResourceDescribeProps> = memo(({
  resource,
  className = '',
}) => {
  const [describeData, setDescribeData] = useState<{ yaml: string; description: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDescribe = async () => {
      try {
        setLoading(true);
        setError(null);
        
        const data = await kubernetesApi.describeResource(
          resource.kind,
          resource.name,
          resource.namespace
        );
        
        setDescribeData(data);
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'Failed to fetch resource description';
        setError(errorMessage);
      } finally {
        setLoading(false);
      }
    };

    void fetchDescribe();
  }, [resource.kind, resource.name, resource.namespace]);

  const formatYaml = (yaml: string) => {
    // Simple YAML syntax highlighting using regex
    return yaml
      .split('\n')
      .map((line, index) => {
        let formattedLine = line;
        
        // Highlight keys (text before colon)
        formattedLine = formattedLine.replace(
          /^(\s*)([^:\s]+):/g, 
          '$1<span class="text-blue-600 font-medium">$2</span>:'
        );
        
        // Highlight string values (quoted text)
        formattedLine = formattedLine.replace(
          /"([^"]*)"/g,
          '"<span class="text-green-600">$1</span>"'
        );
        
        // Highlight boolean values
        formattedLine = formattedLine.replace(
          /\b(true|false|null)\b/g,
          '<span class="text-purple-600 font-medium">$1</span>'
        );
        
        // Highlight numbers
        formattedLine = formattedLine.replace(
          /\b(\d+)\b/g,
          '<span class="text-orange-600">$1</span>'
        );
        
        // Highlight comments
        formattedLine = formattedLine.replace(
          /#(.*)$/,
          '<span class="text-gray-500 italic">#$1</span>'
        );

        return (
          <div key={index} className="min-h-[1.25rem]">
            <span dangerouslySetInnerHTML={{ __html: formattedLine || ' ' }} />
          </div>
        );
      });
  };

  if (loading) {
    return (
      <div className={`resource-describe loading ${className}`} data-testid="resource-describe-loading">
        <div className="flex items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">Loading resource description...</span>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className={`resource-describe error ${className}`} data-testid="resource-describe-error">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 text-center">
          <div className="text-red-600 text-lg font-medium mb-2">
            Failed to load description
          </div>
          <div className="text-red-500 text-sm">{error}</div>
        </div>
      </div>
    );
  }

  if (!describeData) {
    return (
      <div className={`resource-describe empty ${className}`} data-testid="resource-describe-empty">
        <div className="text-center py-8 text-gray-500">
          No description available
        </div>
      </div>
    );
  }

  return (
    <div className={`resource-describe ${className}`} data-testid="resource-describe">
      <div className="space-y-6">
        {/* Description section */}
        {describeData.description && (
          <div className="describe-section">
            <h3 className="text-lg font-semibold text-gray-900 mb-3">Description</h3>
            <div className="bg-gray-50 border rounded-lg p-4">
              <pre className="text-sm text-gray-800 whitespace-pre-wrap font-mono">
                {describeData.description}
              </pre>
            </div>
          </div>
        )}

        {/* YAML section */}
        <div className="yaml-section">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-lg font-semibold text-gray-900">YAML Definition</h3>
            <button
              onClick={() => void navigator.clipboard.writeText(describeData.yaml)}
              className="text-sm bg-gray-100 hover:bg-gray-200 px-3 py-1 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
              aria-label="Copy YAML to clipboard"
            >
              Copy YAML
            </button>
          </div>
          
          <div className="bg-gray-900 rounded-lg overflow-hidden">
            <div className="bg-gray-800 px-4 py-2 text-sm text-gray-300 border-b border-gray-700">
              <code>{resource.kind}/{resource.name}</code>
              {resource.namespace && <span className="ml-2 text-gray-400">in {resource.namespace}</span>}
            </div>
            
            <div className="p-4 overflow-x-auto max-h-96">
              <pre className="text-sm font-mono text-gray-100 leading-relaxed">
                {formatYaml(describeData.yaml)}
              </pre>
            </div>
          </div>
        </div>

        {/* Resource metadata summary */}
        <div className="metadata-section">
          <h3 className="text-lg font-semibold text-gray-900 mb-3">Resource Information</h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <div className="flex justify-between py-2 px-3 bg-gray-50 rounded">
                <span className="font-medium text-gray-700">Kind:</span>
                <span className="font-mono text-gray-900">{resource.kind}</span>
              </div>
              <div className="flex justify-between py-2 px-3 bg-gray-50 rounded">
                <span className="font-medium text-gray-700">Name:</span>
                <span className="font-mono text-gray-900">{resource.name}</span>
              </div>
              {resource.namespace && (
                <div className="flex justify-between py-2 px-3 bg-gray-50 rounded">
                  <span className="font-medium text-gray-700">Namespace:</span>
                  <span className="font-mono text-gray-900">{resource.namespace}</span>
                </div>
              )}
            </div>
            
            <div className="space-y-2">
              <div className="flex justify-between py-2 px-3 bg-gray-50 rounded">
                <span className="font-medium text-gray-700">Status:</span>
                <span className={`font-medium ${
                  resource.status === 'Ready' ? 'text-green-600' :
                  resource.status === 'Warning' ? 'text-yellow-600' :
                  resource.status === 'Error' ? 'text-red-600' :
                  'text-gray-600'
                }`}>
                  {resource.status}
                </span>
              </div>
              <div className="flex justify-between py-2 px-3 bg-gray-50 rounded">
                <span className="font-medium text-gray-700">Last Updated:</span>
                <span className="text-gray-900">{resource.lastUpdated.toLocaleString()}</span>
              </div>
              {resource.relationships.length > 0 && (
                <div className="flex justify-between py-2 px-3 bg-gray-50 rounded">
                  <span className="font-medium text-gray-700">Relationships:</span>
                  <span className="text-gray-900">{resource.relationships.length}</span>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
});

ResourceDescribe.displayName = 'ResourceDescribe';

export default ResourceDescribe;