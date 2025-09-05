import { render, screen } from '@testing-library/react';
import ChatLayout from '@/components/chat/ChatLayout';
import { WebSocketProvider } from '@/contexts/WebSocketContext';

// Mock components that depend on WebSocket
vi.mock('@/components/websocket/ConnectionStatus', () => ({
  default: () => <div data-testid="connection-status">Connection Status</div>,
}));

vi.mock('@/components/chat/MessageList', () => ({
  default: ({ isTyping }: { isTyping: boolean }) => (
    <div data-testid="message-list">
      Message List {isTyping ? '(typing)' : ''}
    </div>
  ),
}));

vi.mock('@/components/chat/MessageInput', () => ({
  default: ({ onTypingStart, onTypingStop }: any) => (
    <div data-testid="message-input">
      <button onClick={onTypingStart}>Start Typing</button>
      <button onClick={onTypingStop}>Stop Typing</button>
    </div>
  ),
}));

vi.mock('@/components/chat/ChatHeader', () => ({
  default: () => <div data-testid="chat-header">Chat Header</div>,
}));

const TestWrapper = ({ children }: { children: React.ReactNode }) => (
  <WebSocketProvider config={{ url: 'ws://test' }}>
    {children}
  </WebSocketProvider>
);

describe('ChatLayout Component', () => {
  test('renders all main components', () => {
    render(
      <TestWrapper>
        <ChatLayout />
      </TestWrapper>
    );

    expect(screen.getByTestId('chat-header')).toBeInTheDocument();
    expect(screen.getByTestId('connection-status')).toBeInTheDocument();
    expect(screen.getByTestId('message-list')).toBeInTheDocument();
    expect(screen.getByTestId('message-input')).toBeInTheDocument();
  });

  test('has correct layout structure', () => {
    render(
      <TestWrapper>
        <ChatLayout />
      </TestWrapper>
    );

    const container = screen.getByTestId('chat-header').closest('div');
    expect(container).toHaveClass('flex', 'flex-col', 'h-screen', 'bg-gray-50');
  });

  test('applies responsive design classes', () => {
    render(
      <TestWrapper>
        <ChatLayout />
      </TestWrapper>
    );

    const container = screen.getByTestId('chat-header').closest('div');
    expect(container).toHaveClass('max-w-6xl', 'mx-auto');
    expect(container).toHaveClass('md:h-[calc(100vh-2rem)]', 'md:my-4');
  });

  test('applies custom className', () => {
    render(
      <TestWrapper>
        <ChatLayout className="custom-class" />
      </TestWrapper>
    );

    const container = screen.getByTestId('chat-header').closest('div');
    expect(container).toHaveClass('custom-class');
  });

  test('manages typing state correctly', () => {
    render(
      <TestWrapper>
        <ChatLayout />
      </TestWrapper>
    );

    const messageList = screen.getByTestId('message-list');
    const startTypingBtn = screen.getByText('Start Typing');
    const stopTypingBtn = screen.getByText('Stop Typing');

    // Initially not typing
    expect(messageList).toHaveTextContent('Message List');
    expect(messageList).not.toHaveTextContent('(typing)');

    // Start typing
    startTypingBtn.click();
    expect(messageList).toHaveTextContent('(typing)');

    // Stop typing
    stopTypingBtn.click();
    expect(messageList).not.toHaveTextContent('(typing)');
  });

  test('has proper accessibility structure', () => {
    render(
      <TestWrapper>
        <ChatLayout />
      </TestWrapper>
    );

    // Check for proper semantic structure
    const container = screen.getByTestId('chat-header').closest('div');
    expect(container).toBeInTheDocument();
    
    // Messages container should be scrollable
    const messageContainer = screen.getByTestId('message-list').parentElement;
    expect(messageContainer).toHaveClass('flex-1', 'flex', 'flex-col', 'min-h-0');
  });
});