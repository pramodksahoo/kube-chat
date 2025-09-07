import React, { useCallback, useEffect, useRef, useState } from 'react';
import { cn } from '@/utils/cn';
import { useWebSocketContext } from '@/contexts/WebSocketContext';

interface MessageInputProps {
  className?: string;
  onTypingStart?: () => void;
  onTypingStop?: () => void;
  maxLength?: number;
  placeholder?: string;
}

const MessageInput: React.FC<MessageInputProps> = ({
  className,
  onTypingStart,
  onTypingStop,
  maxLength = 1000,
  placeholder = "Ask me about your Kubernetes cluster...",
}) => {
  const [message, setMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const typingTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  
  const { sendMessage, connectionStatus } = useWebSocketContext();
  const isConnected = connectionStatus.status === 'connected';

  // Auto-resize textarea
  const adjustTextareaHeight = useCallback(() => {
    const textarea = textareaRef.current;
    if (textarea) {
      textarea.style.height = 'auto';
      textarea.style.height = `${Math.min(textarea.scrollHeight, 120)}px`;
    }
  }, []);

  // Handle typing indicators
  const handleTypingStart = useCallback(() => {
    if (!isTyping) {
      setIsTyping(true);
      onTypingStart?.();
    }

    // Reset typing timeout
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }

    typingTimeoutRef.current = setTimeout(() => {
      setIsTyping(false);
      onTypingStop?.();
    }, 2000);
  }, [isTyping, onTypingStart, onTypingStop]);

  const handleTypingStop = useCallback(() => {
    if (typingTimeoutRef.current) {
      clearTimeout(typingTimeoutRef.current);
    }
    setIsTyping(false);
    onTypingStop?.();
  }, [onTypingStop]);

  // Handle input change
  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      const value = e.target.value;
      if (value.length <= maxLength) {
        setMessage(value);
        handleTypingStart();
      }
      adjustTextareaHeight();
    },
    [maxLength, handleTypingStart, adjustTextareaHeight]
  );

  // Handle form submission
  const handleSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      
      if (!message.trim() || !isConnected) {
        return;
      }

      // Send message
      sendMessage({
        type: 'user',
        content: message.trim(),
        userId: 'current-user', // Replace with actual user ID
        sessionId: 'current-session', // Replace with actual session ID
      });

      // Reset form
      setMessage('');
      handleTypingStop();
      
      // Reset textarea height
      if (textareaRef.current) {
        textareaRef.current.style.height = 'auto';
      }
    },
    [message, isConnected, sendMessage, handleTypingStop]
  );

  // Handle keyboard shortcuts
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        handleSubmit(e);
      }
    },
    [handleSubmit]
  );

  // Clean up timeout on unmount
  useEffect(() => {
    return () => {
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }
    };
  }, []);

  return (
    <div
      className={cn(
        'relative bg-white/80 backdrop-blur-xl rounded-2xl shadow-xl shadow-gray-900/10',
        'border border-white/50 p-4',
        'before:absolute before:inset-0 before:bg-gradient-to-br before:from-blue-50/50 before:to-purple-50/30 before:rounded-2xl before:-z-10',
        className
      )}
    >
      <form onSubmit={handleSubmit} className="space-y-4">
        {/* Status Bar */}
        <div className="flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <div className={cn(
              "flex items-center gap-1.5 px-2 py-1 rounded-full font-medium",
              isConnected
                ? "bg-green-50 text-green-700 border border-green-200"
                : "bg-red-50 text-red-600 border border-red-200"
            )}>
              <div className={cn(
                "w-1.5 h-1.5 rounded-full",
                isConnected ? "bg-green-500 animate-pulse" : "bg-red-500"
              )} />
              {isConnected ? "Connected" : "Disconnected"}
            </div>
            {isTyping && (
              <div className="flex items-center gap-1.5 px-2 py-1 bg-blue-50 text-blue-600 border border-blue-200 rounded-full">
                <div className="flex gap-0.5">
                  <div className="w-1 h-1 bg-blue-500 rounded-full animate-pulse" />
                  <div className="w-1 h-1 bg-blue-500 rounded-full animate-pulse" style={{animationDelay: '0.1s'}} />
                  <div className="w-1 h-1 bg-blue-500 rounded-full animate-pulse" style={{animationDelay: '0.2s'}} />
                </div>
                Typing...
              </div>
            )}
          </div>
          
          <div className="text-gray-400">
            {message.length}/{maxLength}
          </div>
        </div>

        {/* Message Input */}
        <div className="relative">
          <textarea
            ref={textareaRef}
            value={message}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            disabled={!isConnected}
            rows={1}
            className={cn(
              'w-full resize-none bg-white/70 backdrop-blur-sm rounded-xl',
              'border-2 border-gray-200/60 hover:border-gray-300/80 focus:border-blue-400/80',
              'px-4 py-4 pr-16 text-gray-900 placeholder-gray-400',
              'focus:outline-none focus:ring-0 focus:bg-white/90',
              'disabled:bg-gray-50 disabled:text-gray-400 disabled:cursor-not-allowed',
              'transition-all duration-300 shadow-sm',
              'font-medium leading-relaxed'
            )}
            style={{ minHeight: '56px' }}
            aria-label="Message input"
            maxLength={maxLength}
          />
          
          {/* Send Button */}
          <button
            type="submit"
            disabled={!message.trim() || !isConnected}
            className={cn(
              'absolute right-2 top-1/2 -translate-y-1/2',
              'w-10 h-10 rounded-xl transition-all duration-300',
              'flex items-center justify-center',
              'shadow-lg hover:shadow-xl',
              message.trim() && isConnected
                ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white hover:from-blue-600 hover:to-purple-700 transform hover:scale-105'
                : 'bg-gray-100 text-gray-400 cursor-not-allowed'
            )}
            aria-label="Send message"
          >
            <svg
              className={cn(
                'w-5 h-5 transition-transform duration-300',
                message.trim() && isConnected ? 'translate-x-0.5' : ''
              )}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"
              />
            </svg>
          </button>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between text-xs text-gray-500">
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 bg-gray-100 rounded text-gray-600 font-mono text-xs">Enter</kbd>
              to send
            </span>
            <span className="flex items-center gap-1.5">
              <kbd className="px-1.5 py-0.5 bg-gray-100 rounded text-gray-600 font-mono text-xs">⇧Enter</kbd>
              for new line
            </span>
          </div>
          
          {/* Quick Actions */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
              title="Attach file"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
              </svg>
            </button>
            <button
              type="button"
              className="p-1.5 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors"
              title="Voice input"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11a7 7 0 01-7 7m0 0a7 7 0 01-7-7m7 7v4m0 0H8m4 0h4m-4-8a3 3 0 01-3-3V5a3 3 0 116 0v6a3 3 0 01-3 3z" />
              </svg>
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};

export default MessageInput;