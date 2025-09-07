import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type {
  Conversation,
  ConversationFilter,
  ConversationSearchResult,
  ConversationStore,
} from '@/types/conversation';
import type { WebSocketMessage } from '@/types/websocket';

const STORAGE_KEY = 'kubechat-conversations';

// Generate unique conversation ID
const generateConversationId = (): string => {
  return `conv_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
};

// Generate conversation title from first message
const generateConversationTitle = (firstMessage?: WebSocketMessage): string => {
  if (!firstMessage || !firstMessage.content) {
    return `New Conversation - ${new Date().toLocaleString()}`;
  }
  
  const content = firstMessage.content.trim();
  if (content.length <= 50) {
    return content;
  }
  
  return `${content.substring(0, 47)}...`;
};

// Search messages within conversations
const searchInConversation = (
  conversation: Conversation,
  query: string
): { matchingMessages: WebSocketMessage[]; score: number } => {
  const lowerQuery = query.toLowerCase();
  const matchingMessages: WebSocketMessage[] = [];
  let totalScore = 0;

  conversation.messages.forEach(message => {
    const contentMatch = message.content.toLowerCase().includes(lowerQuery);
    const metadataMatch = message.metadata
      ? JSON.stringify(message.metadata).toLowerCase().includes(lowerQuery)
      : false;

    if (contentMatch || metadataMatch) {
      matchingMessages.push(message);
      // Score based on relevance
      const titleMatch = conversation.title.toLowerCase().includes(lowerQuery);
      const messageScore = contentMatch ? 2 : 1;
      totalScore += messageScore + (titleMatch ? 1 : 0);
    }
  });

  return { matchingMessages, score: totalScore };
};

export const useConversationStore = create<ConversationStore>()(
  persist(
    (set, get) => ({
      conversations: [],
      currentConversation: null,
      isLoading: false,
      error: null,

      createConversation: (title: string, userId: string): Conversation => {
        const newConversation: Conversation = {
          id: generateConversationId(),
          title,
          messages: [],
          createdAt: new Date(),
          updatedAt: new Date(),
          userId,
        };

        set(state => ({
          conversations: [...state.conversations, newConversation],
          currentConversation: newConversation,
        }));

        return newConversation;
      },

      updateConversation: (id: string, updates: Partial<Conversation>) => {
        set(state => ({
          conversations: state.conversations.map(conv =>
            conv.id === id
              ? { ...conv, ...updates, updatedAt: new Date() }
              : conv
          ),
          currentConversation:
            state.currentConversation?.id === id
              ? { ...state.currentConversation, ...updates, updatedAt: new Date() }
              : state.currentConversation,
        }));
      },

      deleteConversation: (id: string) => {
        set(state => ({
          conversations: state.conversations.filter(conv => conv.id !== id),
          currentConversation:
            state.currentConversation?.id === id
              ? null
              : state.currentConversation,
        }));
      },

      addMessage: (conversationId: string, message: WebSocketMessage) => {
        set(state => {
          const updatedConversations = state.conversations.map(conv => {
            if (conv.id === conversationId) {
              const updatedConv = {
                ...conv,
                messages: [...conv.messages, message],
                updatedAt: new Date(),
              };

              // Update title if this is the first user message
              if (conv.messages.length === 0 && message.type === 'user') {
                updatedConv.title = generateConversationTitle(message);
              }

              return updatedConv;
            }
            return conv;
          });

          return {
            conversations: updatedConversations,
            currentConversation:
              state.currentConversation?.id === conversationId
                ? updatedConversations.find(c => c.id === conversationId) || null
                : state.currentConversation,
          };
        });
      },

      setCurrentConversation: (id: string | null) => {
        const conversation = id
          ? get().conversations.find(conv => conv.id === id) || null
          : null;
        
        set({ currentConversation: conversation });
      },

      searchConversations: (filter: ConversationFilter): ConversationSearchResult[] => {
        const { conversations } = get();
        let filteredConversations = conversations;

        // Apply filters
        if (filter.userId) {
          filteredConversations = filteredConversations.filter(
            conv => conv.userId === filter.userId
          );
        }

        if (filter.dateRange && filter.dateRange.from && filter.dateRange.to) {
          filteredConversations = filteredConversations.filter(conv => {
            const convDate = conv.createdAt;
            return filter.dateRange && filter.dateRange.from && filter.dateRange.to && 
                   convDate >= filter.dateRange.from && convDate <= filter.dateRange.to;
          });
        }

        if (filter.archived !== undefined) {
          filteredConversations = filteredConversations.filter(
            conv => !!conv.metadata?.archived === filter.archived
          );
        }

        if (filter.pinned !== undefined) {
          filteredConversations = filteredConversations.filter(
            conv => !!conv.metadata?.pinned === filter.pinned
          );
        }

        if (filter.tags && filter.tags.length > 0) {
          filteredConversations = filteredConversations.filter(conv =>
            filter.tags!.some(tag => conv.metadata?.tags?.includes(tag))
          );
        }

        // Apply text search
        let searchResults: ConversationSearchResult[] = [];

        if (filter.query && filter.query.trim()) {
          const query = filter.query.trim();
          
          filteredConversations.forEach(conversation => {
            const searchResult = searchInConversation(conversation, query);
            
            if (searchResult.matchingMessages.length > 0 || 
                conversation.title.toLowerCase().includes(query.toLowerCase())) {
              searchResults.push({
                conversation,
                matchingMessages: searchResult.matchingMessages,
                relevanceScore: searchResult.score,
              });
            }
          });

          // Sort by relevance score
          searchResults.sort((a, b) => b.relevanceScore - a.relevanceScore);
        } else {
          // No text query, return all filtered conversations
          searchResults = filteredConversations.map(conversation => ({
            conversation,
            matchingMessages: [],
            relevanceScore: 0,
          }));

          // Sort by updated date (newest first)
          searchResults.sort((a, b) => 
            b.conversation.updatedAt.getTime() - a.conversation.updatedAt.getTime()
          );
        }

        return searchResults;
      },

      getConversationsByDateRange: (from: Date, to: Date): Conversation[] => {
        return get().conversations.filter(conv => {
          const convDate = conv.createdAt;
          return convDate >= from && convDate <= to;
        });
      },

      saveToStorage: () => {
        // This is handled automatically by zustand persist middleware
      },

      loadFromStorage: () => {
        // This is handled automatically by zustand persist middleware
      },

      clearStorage: () => {
        set({
          conversations: [],
          currentConversation: null,
        });
        localStorage.removeItem(STORAGE_KEY);
      },

      exportConversation: (id: string, format: 'json' | 'csv' | 'txt'): string => {
        const conversation = get().conversations.find(conv => conv.id === id);
        if (!conversation) {
          throw new Error('Conversation not found');
        }

        switch (format) {
          case 'json':
            return JSON.stringify(conversation, null, 2);

          case 'csv': {
            const csvHeader = 'Timestamp,Type,Content,User ID\n';
            const csvRows = conversation.messages.map(msg =>
              `"${msg.timestamp}","${msg.type}","${msg.content.replace(/"/g, '""')}","${msg.userId || ''}"`
            ).join('\n');
            return csvHeader + csvRows;
          }

          case 'txt': {
            const header = `Conversation: ${conversation.title}\nCreated: ${conversation.createdAt.toLocaleString()}\n\n`;
            const messages = conversation.messages.map(msg =>
              `[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.type.toUpperCase()}: ${msg.content}`
            ).join('\n\n');
            return header + messages;
          }

          default:
            throw new Error(`Unsupported export format: ${format as string}`);
        }
      },

      exportAllConversations: (format: 'json' | 'csv' | 'txt'): string => {
        const { conversations } = get();

        switch (format) {
          case 'json':
            return JSON.stringify(conversations, null, 2);

          case 'csv': {
            const csvHeader = 'Conversation ID,Title,Timestamp,Type,Content,User ID\n';
            const csvRows = conversations.flatMap(conv =>
              conv.messages.map(msg =>
                `"${conv.id}","${conv.title.replace(/"/g, '""')}","${msg.timestamp}","${msg.type}","${msg.content.replace(/"/g, '""')}","${msg.userId || ''}"`
              )
            ).join('\n');
            return csvHeader + csvRows;
          }

          case 'txt':
            return conversations.map(conv => {
              const header = `=== ${conv.title} ===\nCreated: ${conv.createdAt.toLocaleString()}\n`;
              const messages = conv.messages.map(msg =>
                `[${new Date(msg.timestamp).toLocaleTimeString()}] ${msg.type.toUpperCase()}: ${msg.content}`
              ).join('\n');
              return header + messages;
            }).join('\n\n' + '='.repeat(50) + '\n\n');

          default:
            throw new Error(`Unsupported export format: ${format as string}`);
        }
      },
    }),
    {
      name: STORAGE_KEY,
      // Custom serialization for dates
      storage: {
        getItem: (name: string) => {
          const item = localStorage.getItem(name);
          if (!item) return null;
          
          try {
            const parsed = JSON.parse(item, (_key, value: unknown) => {
              if (value && typeof value === 'object' && (value as {__type?: string; value?: string}).__type === 'Date') {
                return new Date((value as {value: string}).value);
              }
              return value;
            });
            return parsed;
          } catch {
            return null;
          }
        },
        setItem: (name: string, value: unknown) => {
          const serialized = JSON.stringify(value, (_key, val: unknown) => {
            if (val instanceof Date) {
              return { __type: 'Date', value: val.toISOString() };
            }
            return val;
          });
          localStorage.setItem(name, serialized);
        },
        removeItem: (name: string) => localStorage.removeItem(name),
      },
    }
  )
);