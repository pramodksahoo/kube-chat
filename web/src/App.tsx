import { WebSocketProvider } from '@/contexts/WebSocketContext';
import ChatLayout from '@/components/chat/ChatLayout';
import { useAuth } from '@/hooks/useAuth';

function App() {
  const { token } = useAuth();

  return (
    <div className="min-h-screen bg-gray-100">
      <WebSocketProvider
        config={{
          url: 'ws://localhost:8080/api/v1/chat',
          token: token || undefined,
          reconnectAttempts: 5,
          reconnectInterval: 3000,
          heartbeatInterval: 30000,
        }}
      >
        <main role="main" className="container mx-auto p-4">
          <ChatLayout />
        </main>
      </WebSocketProvider>
    </div>
  );
}

export default App;
