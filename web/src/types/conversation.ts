import type { WebSocketMessage } from './websocket';

export interface Conversation {
  id: string;
  title: string;
  messages: WebSocketMessage[];
  createdAt: Date;
  updatedAt: Date;
  userId: string;
  metadata?: {
    tags?: string[];
    archived?: boolean;
    pinned?: boolean;
    summary?: string;
  };
}

export interface ConversationFilter {
  query?: string;
  userId?: string;
  dateRange?: {
    from?: Date;
    to?: Date;
  };
  tags?: string[];
  archived?: boolean;
  pinned?: boolean;
}

export interface ConversationSearchResult {
  conversation: Conversation;
  matchingMessages: WebSocketMessage[];
  relevanceScore: number;
}

export interface ConversationStore {
  conversations: Conversation[];
  currentConversation: Conversation | null;
  isLoading: boolean;
  error: string | null;
  
  // Actions
  createConversation: (title: string, userId: string) => Conversation;
  updateConversation: (id: string, updates: Partial<Conversation>) => void;
  deleteConversation: (id: string) => void;
  addMessage: (conversationId: string, message: WebSocketMessage) => void;
  setCurrentConversation: (id: string | null) => void;
  
  // Search and filter
  searchConversations: (filter: ConversationFilter) => ConversationSearchResult[];
  getConversationsByDateRange: (from: Date, to: Date) => Conversation[];
  
  // Persistence
  saveToStorage: () => void;
  loadFromStorage: () => void;
  clearStorage: () => void;
  
  // Export
  exportConversation: (id: string, format: 'json' | 'csv' | 'txt') => string;
  exportAllConversations: (format: 'json' | 'csv' | 'txt') => string;
}