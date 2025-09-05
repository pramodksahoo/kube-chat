import React, { useState } from 'react';
import { cn } from '@/utils/cn';
import ConnectionStatus from '@/components/websocket/ConnectionStatus';
import MessageList from './MessageList';
import MessageInput from './MessageInput';
import ChatHeader from './ChatHeader';

interface ChatLayoutProps {
  className?: string;
}

const ChatLayout: React.FC<ChatLayoutProps> = ({ className }) => {
  const [isTyping, setIsTyping] = useState(false);

  return (
    <div
      className={cn(
        'flex flex-col h-screen bg-gray-50',
        'max-w-6xl mx-auto border border-gray-200 rounded-lg shadow-sm',
        'md:h-[calc(100vh-2rem)] md:my-4', // Desktop spacing
        className
      )}
    >
      {/* Header */}
      <ChatHeader />

      {/* Connection Status */}
      <div className="px-4 py-2 border-b border-gray-200 bg-white">
        <ConnectionStatus />
      </div>

      {/* Messages Container */}
      <div className="flex-1 flex flex-col min-h-0">
        <MessageList
          className="flex-1"
          isTyping={isTyping}
        />
        
        {/* Input Area */}
        <div className="border-t border-gray-200 bg-white">
          <MessageInput
            onTypingStart={() => setIsTyping(true)}
            onTypingStop={() => setIsTyping(false)}
            className="p-4"
          />
        </div>
      </div>
    </div>
  );
};

export default ChatLayout;