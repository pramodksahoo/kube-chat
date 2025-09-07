import { WebSocketProvider } from '@/contexts/WebSocketContext';
import MainLayout from '@/components/layout/MainLayout';
import { useAuth } from '@/hooks/useAuth';

function App() {
  const { token } = useAuth();

  return (
    <WebSocketProvider
      config={{
        url: 'ws://localhost:8080/api/v1/chat',
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
