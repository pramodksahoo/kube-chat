import { WebSocketProvider } from '@/contexts/WebSocketContext';
import MainLayout from '@/components/layout/MainLayout';
import { useAuth } from '@/hooks/useAuth';

function App() {
  const { token } = useAuth();

  return (
    <WebSocketProvider
      config={{
        url: `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/api/v1/chat`,
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
