export interface WebSocketMessage {
  id: string;
  type: 'user' | 'assistant' | 'system' | 'error' | 'status';
  content: string;
  timestamp: string;
  userId?: string;
  sessionId?: string;
  metadata?: Record<string, unknown>;
  safetyLevel?: 'safe' | 'caution' | 'destructive' | 'info' | 'disabled';
  command?: string;
  affectedResources?: string[];
  risks?: string[];
  recommendations?: string[];
  processingState?: 'idle' | 'processing' | 'executing' | 'completed' | 'failed';
  progress?: number;
}

export interface WebSocketConfig {
  url: string;
  reconnectAttempts: number;
  reconnectInterval: number;
  heartbeatInterval: number;
  token?: string;
}

export interface ConnectionStatus {
  status: 'connecting' | 'connected' | 'disconnected' | 'reconnecting' | 'error';
  lastConnected?: Date;
  reconnectAttempts: number;
  error?: string;
}

export interface MessageQueue {
  messages: WebSocketMessage[];
  maxSize: number;
}

export interface StatusUpdate {
  messageId: string;
  state: 'processing' | 'executing' | 'completed' | 'failed';
  progress?: number;
  message?: string;
  timestamp: string;
}

export interface WebSocketContextType {
  connectionStatus: ConnectionStatus;
  sendMessage: (message: Omit<WebSocketMessage, 'id' | 'timestamp'>) => void;
  sendStatusUpdate: (statusUpdate: Omit<StatusUpdate, 'timestamp'>) => void;
  messages: WebSocketMessage[];
  clearMessages: () => void;
  reconnect: () => void;
  getMessageStatus: (messageId: string) => StatusUpdate | null;
}