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
        'flex-1 overflow-y-auto px-6 py-4',
        'scrollbar-thin scrollbar-thumb-gray-300/60 scrollbar-track-transparent hover:scrollbar-thumb-gray-400/80',
        'scroll-smooth',
        className
      )}
      role="log"
      aria-label="Chat messages"
    >
      {messages.length === 0 ? (
        <div className="flex items-center justify-center h-full">
          <div className="text-center space-y-6 max-w-lg mx-auto">
            {/* Welcome Animation */}
            <div className="relative">
              <div className="w-20 h-20 mx-auto mb-4">
                <div className="w-full h-full bg-gradient-to-br from-blue-500/20 to-purple-600/20 rounded-3xl flex items-center justify-center backdrop-blur-sm border border-white/30 shadow-xl">
                  <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center shadow-lg">
                    <svg
                      className="w-6 h-6 text-white"
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
                </div>
                {/* Floating particles */}
                <div className="absolute inset-0 -z-10">
                  <div className="absolute top-0 right-4 w-2 h-2 bg-blue-400/40 rounded-full animate-pulse delay-0"></div>
                  <div className="absolute top-8 left-2 w-1.5 h-1.5 bg-purple-400/40 rounded-full animate-pulse delay-300"></div>
                  <div className="absolute bottom-4 right-0 w-1 h-1 bg-blue-300/40 rounded-full animate-pulse delay-700"></div>
                </div>
              </div>
            </div>
            
            {/* Welcome Text */}
            <div className="space-y-3">
              <h3 className="text-2xl font-bold bg-gradient-to-r from-gray-800 to-gray-600 bg-clip-text text-transparent">
                Welcome to KubeChat
              </h3>
              <p className="text-gray-500 leading-relaxed">
                Your AI-powered Kubernetes assistant is ready to help! Start a conversation 
                by asking about your cluster, deployments, pods, and more.
              </p>
            </div>
            
            {/* Suggested Actions */}
            <div className="space-y-3">
              <p className="text-sm font-medium text-gray-700">Try asking:</p>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {[
                  { text: "Show me all pods", icon: "🚀" },
                  { text: "List deployments", icon: "📦" },
                  { text: "Check cluster status", icon: "⚡" },
                  { text: "Get node information", icon: "🔧" }
                ].map((suggestion, index) => (
                  <button
                    key={index}
                    className="group flex items-center gap-2 px-4 py-3 bg-white/60 hover:bg-white/80 backdrop-blur-sm rounded-xl border border-gray-200/60 hover:border-gray-300/80 text-left transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5"
                    onClick={() => {
                      // You could implement auto-fill functionality here
                      console.log('Suggested query:', suggestion.text);
                    }}
                  >
                    <span className="text-lg">{suggestion.icon}</span>
                    <span className="text-sm text-gray-700 group-hover:text-gray-900 font-medium">
                      "{suggestion.text}"
                    </span>
                    <svg 
                      className="w-4 h-4 text-gray-400 group-hover:text-gray-600 ml-auto transform group-hover:translate-x-1 transition-transform duration-300" 
                      fill="none" 
                      stroke="currentColor" 
                      viewBox="0 0 24 24"
                    >
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {messages.map((message, index) => (
            <div 
              key={message.id} 
              className="animate-in fade-in slide-in-from-bottom-4 duration-500"
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <MessageItem message={message} />
            </div>
          ))}
          
          {isTyping && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-300">
              <TypingIndicator />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default MessageList;