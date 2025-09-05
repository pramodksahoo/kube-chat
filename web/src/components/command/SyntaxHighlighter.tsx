import React, { useState } from 'react';
import { cn } from '@/utils/cn';

export interface SyntaxHighlighterProps {
  code: string;
  language: 'kubectl' | 'yaml' | 'bash';
  showLineNumbers?: boolean;
  collapsible?: boolean;
  collapsed?: boolean;
  showCopyButton?: boolean;
  title?: string;
  className?: string;
}

const SyntaxHighlighter: React.FC<SyntaxHighlighterProps> = ({
  code,
  language,
  showLineNumbers = false,
  collapsible = false,
  collapsed = false,
  showCopyButton = true,
  title,
  className,
}) => {
  const [isCollapsed, setIsCollapsed] = useState(collapsed);
  const [copyText, setCopyText] = useState('Copy');

  const highlightKubectlCommand = (command: string) => {
    return command
      .replace(/\b(kubectl)\b/g, '<span class="text-blue-400 font-semibold">$1</span>')
      .replace(/\b(get|apply|delete|create|describe|logs|exec|port-forward|scale|rollout)\b/g, '<span class="text-green-400">$1</span>')
      .replace(/(-[a-zA-Z-]+)/g, '<span class="text-yellow-300">$1</span>')
      .replace(/(--[a-zA-Z-]+)/g, '<span class="text-purple-300">$1</span>')
      .replace(/(['"][^'"]*['"])/g, '<span class="text-orange-300">$1</span>');
  };

  const highlightYaml = (yaml: string) => {
    return yaml
      .replace(/^(\s*[a-zA-Z_][a-zA-Z0-9_]*)\s*:/gm, '<span class="text-blue-400">$1</span>:')
      .replace(/:\s*([^\n]+)/g, ': <span class="text-green-300">$1</span>')
      .replace(/(['"][^'"]*['"])/g, '<span class="text-orange-300">$1</span>')
      .replace(/^(\s*-\s)/gm, '<span class="text-yellow-400">$1</span>');
  };

  const highlightBash = (bash: string) => {
    return bash
      .replace(/\b(if|then|else|elif|fi|for|do|done|while|until|case|esac|function)\b/g, '<span class="text-purple-400">$1</span>')
      .replace(/\b(echo|cat|grep|awk|sed|sort|uniq|head|tail|wc)\b/g, '<span class="text-green-400">$1</span>')
      .replace(/(\$[a-zA-Z_][a-zA-Z0-9_]*|\$\{[^}]+\})/g, '<span class="text-yellow-300">$1</span>')
      .replace(/(#.*$)/gm, '<span class="text-gray-400 italic">$1</span>');
  };

  const getHighlightedCode = () => {
    switch (language) {
      case 'kubectl':
        return highlightKubectlCommand(code);
      case 'yaml':
        return highlightYaml(code);
      case 'bash':
        return highlightBash(code);
      default:
        return code;
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopyText('Copied!');
      setTimeout(() => setCopyText('Copy'), 2000);
    } catch {
      setCopyText('Failed');
      setTimeout(() => setCopyText('Copy'), 2000);
    }
  };

  const lines = code.split('\n');
  const highlightedCode = getHighlightedCode();

  return (
    <div className={cn('syntax-highlighter', className)}>
      {(title || collapsible || showCopyButton) && (
        <div className="flex items-center justify-between bg-gray-800 px-4 py-2 rounded-t-md">
          <div className="flex items-center space-x-2">
            {collapsible && (
              <button
                type="button"
                onClick={() => setIsCollapsed(!isCollapsed)}
                className="text-gray-400 hover:text-white transition-colors"
                aria-label={isCollapsed ? 'Expand code' : 'Collapse code'}
              >
                <svg className={cn('w-4 h-4 transform transition-transform', isCollapsed ? 'rotate-0' : 'rotate-90')} viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z" clipRule="evenodd" />
                </svg>
              </button>
            )}
            {title && (
              <h3 className="text-sm font-medium text-gray-300">{title}</h3>
            )}
            <span className="text-xs text-gray-500 uppercase tracking-wide">{language}</span>
          </div>
          
          {showCopyButton && (
            <button
              type="button"
              onClick={() => {
                void handleCopy();
              }}
              className="text-gray-400 hover:text-white text-xs px-2 py-1 rounded hover:bg-gray-700 transition-colors"
              aria-label="Copy code to clipboard"
            >
              {copyText}
            </button>
          )}
        </div>
      )}

      <div className={cn(
        'bg-gray-900 text-gray-100 overflow-x-auto',
        title || collapsible || showCopyButton ? 'rounded-b-md' : 'rounded-md',
        isCollapsed && 'hidden'
      )}>
        <div className="p-4">
          {showLineNumbers ? (
            <div className="flex">
              <div className="text-gray-500 text-xs pr-4 select-none">
                {lines.map((_, index) => (
                  <div key={index} className="leading-6">
                    {index + 1}
                  </div>
                ))}
              </div>
              <div className="flex-1 font-mono text-sm">
                <pre
                  className="leading-6"
                  dangerouslySetInnerHTML={{ __html: highlightedCode }}
                />
              </div>
            </div>
          ) : (
            <pre
              className="font-mono text-sm leading-6"
              dangerouslySetInnerHTML={{ __html: highlightedCode }}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default SyntaxHighlighter;