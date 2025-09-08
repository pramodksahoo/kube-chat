import { WebSocketProvider } from '@/contexts/WebSocketContext';
import MainLayout from '@/components/layout/MainLayout';
import { useAuth } from '@/hooks/useAuth';
import { useConversationStore } from '@/stores/conversationStore';
import API_CONFIG from '@/config/api';

function App() {
  const { token } = useAuth();
  const { currentConversation } = useConversationStore();
  
  // Generate session ID from current conversation or create a default one
  const sessionId = currentConversation?.id || `session_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  
  // Use centralized API configuration for WebSocket URL
  const wsUrl = API_CONFIG.getWebSocketUrl(sessionId);

  return (
    <WebSocketProvider
      config={{
        url: wsUrl,
        token: token || undefined,
        reconnectAttempts: 5,
        reconnectInterval: 3000,
        heartbeatInterval: 30000,
      }}
    >
      <MainLayout />
    </WebSocketProvider>
  );
}

export default App;
