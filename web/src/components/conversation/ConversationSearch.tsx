import React, { useCallback, useMemo, useState } from 'react';
import { cn } from '@/utils/cn';
import { useConversationStore } from '@/stores/conversationStore';
import type { ConversationFilter } from '@/types/conversation';
import { Button } from '@/components/ui/button';

interface ConversationSearchProps {
  onSelectConversation?: (conversationId: string) => void;
  className?: string;
}

const ConversationSearch: React.FC<ConversationSearchProps> = ({
  onSelectConversation,
  className,
}) => {
  const [query, setQuery] = useState('');
  const [isExpanded, setIsExpanded] = useState(false);
  const [filters, setFilters] = useState<ConversationFilter>({});

  const { searchConversations } = useConversationStore();

  // Debounced search
  const searchResults = useMemo(() => {
    const filter: ConversationFilter = {
      ...filters,
      query: query.trim() || undefined,
    };
    return searchConversations(filter);
  }, [query, filters, searchConversations]);

  const handleFilterChange = useCallback(
    (key: keyof ConversationFilter, value: ConversationFilter[keyof ConversationFilter]) => {
      setFilters(prev => ({ ...prev, [key]: value }));
    },
    []
  );

  const clearFilters = useCallback(() => {
    setQuery('');
    setFilters({});
    setIsExpanded(false);
  }, []);

  const handleConversationSelect = useCallback(
    (conversationId: string) => {
      onSelectConversation?.(conversationId);
    },
    [onSelectConversation]
  );

  return (
    <div className={cn('bg-white border border-gray-200 rounded-lg', className)}>
      {/* Search Header */}
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <input
              type="text"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder="Search conversations..."
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
            />
            <svg
              className="absolute left-3 top-2.5 w-4 h-4 text-gray-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
          </div>
          
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsExpanded(!isExpanded)}
            className={cn(
              'flex items-center gap-1',
              isExpanded && 'bg-primary-50 border-primary-200'
            )}
          >
            <svg
              className="w-4 h-4"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.707A1 1 0 013 7V4z"
              />
            </svg>
            Filters
          </Button>

          {(query || Object.keys(filters).length > 0) && (
            <Button variant="ghost" size="sm" onClick={clearFilters}>
              Clear
            </Button>
          )}
        </div>

        {/* Advanced Filters */}
        {isExpanded && (
          <div className="mt-4 p-4 bg-gray-50 rounded-md space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* Date Range */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Date Range
                </label>
                <div className="flex gap-2">
                  <input
                    type="date"
                    onChange={e => {
                      const from = e.target.value ? new Date(e.target.value) : undefined;
                      handleFilterChange('dateRange', from ? {
                        ...filters.dateRange,
                        from
                      } : undefined);
                    }}
                    className="flex-1 px-3 py-1.5 border border-gray-300 rounded text-sm"
                  />
                  <input
                    type="date"
                    onChange={e => {
                      const to = e.target.value ? new Date(e.target.value) : undefined;
                      handleFilterChange('dateRange', to ? {
                        ...filters.dateRange,
                        to
                      } : undefined);
                    }}
                    className="flex-1 px-3 py-1.5 border border-gray-300 rounded text-sm"
                  />
                </div>
              </div>

              {/* Status Filters */}
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Status
                </label>
                <div className="flex gap-2">
                  <label className="flex items-center gap-1 text-sm">
                    <input
                      type="checkbox"
                      checked={filters.archived === true}
                      onChange={e => 
                        handleFilterChange('archived', e.target.checked ? true : undefined)
                      }
                      className="rounded"
                    />
                    Archived
                  </label>
                  <label className="flex items-center gap-1 text-sm">
                    <input
                      type="checkbox"
                      checked={filters.pinned === true}
                      onChange={e => 
                        handleFilterChange('pinned', e.target.checked ? true : undefined)
                      }
                      className="rounded"
                    />
                    Pinned
                  </label>
                </div>
              </div>
            </div>

            <div className="text-xs text-gray-500">
              Found {searchResults.length} conversation{searchResults.length !== 1 ? 's' : ''}
            </div>
          </div>
        )}
      </div>

      {/* Search Results */}
      <div className="max-h-96 overflow-y-auto">
        {searchResults.length === 0 ? (
          <div className="p-6 text-center text-gray-500">
            <svg
              className="w-12 h-12 mx-auto mb-3 text-gray-300"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1.5}
                d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
              />
            </svg>
            <p className="text-sm">
              {query ? 'No conversations match your search' : 'No conversations found'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {searchResults.map(({ conversation, matchingMessages, relevanceScore }) => (
              <div
                key={conversation.id}
                onClick={() => handleConversationSelect(conversation.id)}
                className="p-4 hover:bg-gray-50 cursor-pointer transition-colors"
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-medium text-sm text-gray-900 truncate">
                        {conversation.title}
                      </h3>
                      {conversation.metadata?.pinned && (
                        <svg className="w-3 h-3 text-caution-500 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                          <path d="M4 3a2 2 0 100 4h12a2 2 0 100-4H4z"/>
                          <path fillRule="evenodd" d="M3 8a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clipRule="evenodd"/>
                        </svg>
                      )}
                      {conversation.metadata?.archived && (
                        <span className="px-1.5 py-0.5 bg-gray-100 text-gray-600 text-xs rounded">
                          Archived
                        </span>
                      )}
                    </div>
                    
                    <div className="text-xs text-gray-500 mb-2">
                      {conversation.updatedAt.toLocaleString()} • {conversation.messages.length} messages
                    </div>

                    {matchingMessages.length > 0 && (
                      <div className="space-y-1">
                        {matchingMessages.slice(0, 2).map(msg => (
                          <div key={msg.id} className="text-xs text-gray-600 truncate">
                            <span className="font-medium">{msg.type}:</span> {msg.content}
                          </div>
                        ))}
                        {matchingMessages.length > 2 && (
                          <div className="text-xs text-gray-500">
                            +{matchingMessages.length - 2} more matches
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {relevanceScore > 0 && (
                    <div className="flex items-center gap-1 text-xs text-primary-600">
                      <svg className="w-3 h-3" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"/>
                      </svg>
                      {relevanceScore}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default ConversationSearch;