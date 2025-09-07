import React, { useState } from 'react';
import { cn } from '@/utils/cn';
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
        'flex flex-col h-screen relative',
        'bg-gradient-to-br from-blue-50/50 via-white to-purple-50/30',
        'max-w-6xl mx-auto shadow-2xl shadow-gray-900/10',
        'md:h-[calc(100vh-2rem)] md:my-4 md:rounded-3xl',
        'overflow-hidden border border-white/50',
        'before:absolute before:inset-0 before:bg-gradient-to-br before:from-white/40 before:via-white/20 before:to-white/10 before:backdrop-blur-3xl before:-z-10',
        className
      )}
    >
      {/* Animated background particles */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none -z-20">
        <div className="absolute top-10 left-10 w-32 h-32 bg-blue-400/10 rounded-full blur-2xl animate-pulse"></div>
        <div className="absolute top-32 right-16 w-24 h-24 bg-purple-400/10 rounded-full blur-2xl animate-pulse delay-300"></div>
        <div className="absolute bottom-20 left-20 w-40 h-40 bg-indigo-400/10 rounded-full blur-2xl animate-pulse delay-700"></div>
        <div className="absolute bottom-32 right-8 w-28 h-28 bg-pink-400/10 rounded-full blur-2xl animate-pulse delay-1000"></div>
      </div>

      {/* Header */}
      <ChatHeader />

      {/* Messages Container */}
      <div className="flex-1 flex flex-col min-h-0 relative">
        {/* Messages */}
        <MessageList
          className="flex-1"
          isTyping={isTyping}
        />
        
        {/* Input Area */}
        <div className="p-4 bg-gradient-to-t from-white/60 to-transparent backdrop-blur-sm">
          <MessageInput
            onTypingStart={() => setIsTyping(true)}
            onTypingStop={() => setIsTyping(false)}
          />
        </div>
      </div>
    </div>
  );
};

export default ChatLayout;