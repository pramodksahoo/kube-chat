import React, { useEffect, useRef } from 'react';
import { cn } from '@/utils/cn';
import { useWebSocketContext } from '@/contexts/WebSocketContext';
import MessageItem from './MessageItem';
import TypingIndicator from './TypingIndicator';

interface MessageListProps {
  className?: string;
  isTyping?: boolean;
}

const MessageList: React.FC<MessageListProps> = ({
  className,
  isTyping = false,
}) => {
  const { messages } = useWebSocketContext();
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, isTyping]);

  return (
    <div
      ref={scrollRef}
      className={cn(
        'flex-1 overflow-y-auto p-4 space-y-4',
        'scrollbar-thin scrollbar-thumb-gray-300 scrollbar-track-gray-100',
        className
      )}
      role="log"
      aria-label="Chat messages"
    >
      {messages.length === 0 ? (
        <div className="flex items-center justify-center h-full">
          <div className="text-center space-y-3">
            <div className="w-16 h-16 bg-gray-100 rounded-full mx-auto flex items-center justify-center">
              <svg
                className="w-8 h-8 text-gray-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"
                />
              </svg>
            </div>
            <div>
              <h3 className="text-lg font-semibold text-gray-900">
                Welcome to KubeChat
              </h3>
              <p className="text-sm text-gray-500 max-w-md mx-auto">
                Start a conversation by asking about your Kubernetes cluster.
                I can help you manage pods, deployments, services, and more.
              </p>
            </div>
            <div className="flex flex-wrap gap-2 justify-center">
              <span className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-xs">
                "Show me all pods"
              </span>
              <span className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-xs">
                "List deployments"
              </span>
              <span className="px-3 py-1 bg-gray-100 text-gray-700 rounded-full text-xs">
                "Check cluster status"
              </span>
            </div>
          </div>
        </div>
      ) : (
        <>
          {messages.map(message => (
            <MessageItem
              key={message.id}
              message={message}
            />
          ))}
          
          {isTyping && (
            <TypingIndicator />
          )}
        </>
      )}
    </div>
  );
};

export default MessageList;