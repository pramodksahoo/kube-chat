import React from 'react';
import { cn } from '@/utils/cn';

interface ChatHeaderProps {
  className?: string;
  isOnline?: boolean;
}

const ChatHeader: React.FC<ChatHeaderProps> = ({ className, isOnline = true }) => {
  return (
    <div
      className={cn(
        'relative flex items-center justify-between px-6 py-4',
        'bg-gradient-to-r from-white/95 via-white/90 to-white/95',
        'backdrop-blur-xl border-b border-white/20',
        'shadow-sm shadow-gray-900/5',
        'rounded-t-2xl',
        'before:absolute before:inset-0 before:bg-gradient-to-r before:from-blue-50/30 before:to-purple-50/20 before:rounded-t-2xl before:-z-10',
        className
      )}
    >
      {/* Assistant Info */}
      <div className="flex items-center gap-4">
        <div className="relative">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 p-0.5 shadow-lg">
            <div className="w-full h-full rounded-[14px] bg-white flex items-center justify-center">
              <img 
                src="/kubechat-icon.png" 
                alt="KubeChat Assistant" 
                className="w-7 h-7 object-contain"
              />
            </div>
          </div>
          {/* Status indicator */}
          <div className={cn(
            "absolute -bottom-1 -right-1 w-4 h-4 rounded-full border-2 border-white shadow-sm transition-all duration-300",
            isOnline 
              ? "bg-green-500 shadow-green-500/20" 
              : "bg-gray-400"
          )}>
            {isOnline && (
              <div className="absolute inset-0.5 bg-green-400 rounded-full animate-pulse" />
            )}
          </div>
        </div>

        <div className="flex flex-col">
          <h2 className="text-lg font-bold bg-gradient-to-r from-gray-900 to-gray-700 bg-clip-text text-transparent">
            KubeChat Assistant
          </h2>
          <div className="flex items-center gap-2">
            <div className={cn(
              "flex items-center gap-1.5 px-2 py-1 rounded-full text-xs font-medium transition-all duration-300",
              isOnline 
                ? "bg-green-50 text-green-700 border border-green-200" 
                : "bg-gray-50 text-gray-500 border border-gray-200"
            )}>
              <div className={cn(
                "w-1.5 h-1.5 rounded-full",
                isOnline ? "bg-green-500" : "bg-gray-400"
              )} />
              {isOnline ? "Ready to help" : "Connecting..."}
            </div>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="flex items-center gap-1">
        <button
          className={cn(
            "group relative p-2.5 rounded-xl transition-all duration-300",
            "bg-white/60 hover:bg-white/80 backdrop-blur-sm",
            "border border-gray-200/60 hover:border-gray-300/80",
            "shadow-sm hover:shadow-md",
            "text-gray-500 hover:text-gray-700"
          )}
          aria-label="Settings"
        >
          <svg
            className="w-5 h-5 transition-transform duration-300 group-hover:rotate-90"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
            />
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
            />
          </svg>
          
          {/* Tooltip */}
          <div className="absolute bottom-full right-0 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-nowrap">
            Settings
          </div>
        </button>
        
        <button
          className={cn(
            "group relative p-2.5 rounded-xl transition-all duration-300",
            "bg-white/60 hover:bg-white/80 backdrop-blur-sm",
            "border border-gray-200/60 hover:border-gray-300/80",
            "shadow-sm hover:shadow-md",
            "text-gray-500 hover:text-gray-700"
          )}
          aria-label="Help"
        >
          <svg
            className="w-5 h-5 transition-transform duration-300 group-hover:scale-110"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
            />
          </svg>
          
          {/* Tooltip */}
          <div className="absolute bottom-full right-0 mb-2 px-2 py-1 bg-gray-900 text-white text-xs rounded-lg opacity-0 group-hover:opacity-100 transition-opacity duration-200 pointer-events-none whitespace-nowrap">
            Help & Support
          </div>
        </button>
      </div>
    </div>
  );
};

export default ChatHeader;