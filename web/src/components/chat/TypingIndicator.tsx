import React from 'react';
import { cn } from '@/utils/cn';
import SystemTypingIndicator from '@/components/status/SystemTypingIndicator';

interface TypingIndicatorProps {
  variant?: 'default' | 'processing' | 'analyzing' | 'executing';
  message?: string;
  className?: string;
}

const TypingIndicator: React.FC<TypingIndicatorProps> = ({ 
  variant = 'default', 
  message,
  className 
}) => {
  return (
    <div
      className={cn(
        'flex gap-3 items-start animate-fade-in',
        className
      )}
    >
      <div className="w-6 h-6 bg-safe-600 rounded-full flex items-center justify-center flex-shrink-0">
        <span className="text-white text-xs font-medium">AI</span>
      </div>
      
      <div className="mr-8">
        <SystemTypingIndicator
          isVisible={true}
          variant={variant}
          message={message}
          size="md"
          showIcon={false}
        />
      </div>
    </div>
  );
};

export default TypingIndicator;