# WebSocket API Reference

## Overview

The KubeChat WebSocket API provides real-time, bidirectional communication between the web interface and the KubeChat operator. This API enables natural language processing, Kubernetes operations, and real-time status updates.

## Connection

### WebSocket Endpoint
```
ws://localhost:8080/ws
```

### Connection Parameters
- `sessionId` (optional): Resume an existing chat session
- `userId` (required): User identifier for authentication

### Connection Example
```javascript
const ws = new WebSocket('ws://localhost:8080/ws?userId=user123&sessionId=session456');
```

## Message Format

All WebSocket messages follow a standardized JSON format:

```typescript
interface WebSocketMessage {
  type: string;           // Message type identifier
  sessionId: string;      // Chat session identifier  
  data: any;             // Message-specific payload
  timestamp: string;     // ISO 8601 timestamp
}
```

## Client to Server Messages

### 1. Chat Message

Send a natural language command to KubeChat.

**Type**: `chat_message`

**Data Structure**:
```typescript
interface ChatMessageData {
  message: {
    role: 'user';
    content: string;      // Natural language command
    timestamp: string;    // ISO 8601 timestamp
  };
}
```

**Example**:
```json
{
  "type": "chat_message",
  "sessionId": "session-123",
  "data": {
    "message": {
      "role": "user",
      "content": "Create nginx deployment with 3 replicas",
      "timestamp": "2025-09-01T10:00:00Z"
    }
  },
  "timestamp": "2025-09-01T10:00:00Z"
}
```

### 2. Confirmation Response

Respond to a confirmation request for dangerous operations.

**Type**: `confirmation_response`

**Data Structure**:
```typescript
interface ConfirmationResponseData {
  operationId: string;    // Unique operation identifier
  confirmed: boolean;     // User's decision
}
```

**Example**:
```json
{
  "type": "confirmation_response",
  "sessionId": "session-123",
  "data": {
    "operationId": "op_session-123_1693567200000",
    "confirmed": true
  },
  "timestamp": "2025-09-01T10:00:30Z"
}
```

### 3. Ping Message

Send a heartbeat to maintain connection.

**Type**: `ping`

**Data**: `null`

**Example**:
```json
{
  "type": "ping",
  "sessionId": "session-123",
  "data": null,
  "timestamp": "2025-09-01T10:00:00Z"
}
```

## Server to Client Messages

### 1. NLP Result

Results of natural language processing.

**Type**: `nlp_result`

**Data Structure**:
```typescript
interface NLPResultData {
  intent: {
    name: string;                    // Recognized intent
    action: string;                  // Kubernetes action
    resource: {
      kind: string;                  // Resource type
      name: string;                  // Resource name
      namespace?: string;            // Resource namespace
    };
    parameters: Record<string, string>; // Extracted parameters
    confidence: number;              // Confidence score (0-1)
    timestamp: string;               // Processing timestamp
  };
  confidence: number;                // Overall confidence
  extractedParameters: Record<string, string>;
  generatedCommands: KubernetesCommand[];
  safetyAssessment: SafetyAssessment;
  processingMethod: string;          // "patterns" | "openai" | "hybrid"
  processingLatency: string;         // Processing time
}
```

**Example**:
```json
{
  "type": "nlp_result",
  "sessionId": "session-123",
  "data": {
    "intent": {
      "name": "create",
      "action": "create",
      "resource": {
        "kind": "Deployment",
        "name": "nginx",
        "namespace": "default"
      },
      "parameters": {
        "replicas": "3",
        "image": "nginx:latest"
      },
      "confidence": 0.95,
      "timestamp": "2025-09-01T10:00:01Z"
    },
    "confidence": 0.95,
    "extractedParameters": {
      "replicas": "3",
      "image": "nginx:latest"
    },
    "generatedCommands": [
      {
        "action": "create",
        "resource": {
          "kind": "Deployment",
          "name": "nginx",
          "namespace": "default"
        },
        "kubectlCmd": "kubectl create deployment nginx --image=nginx:latest --replicas=3",
        "parameters": {
          "replicas": "3",
          "image": "nginx:latest"
        },
        "isDestructive": false,
        "requiresConfirmation": false,
        "description": "Create nginx deployment with 3 replicas"
      }
    ],
    "safetyAssessment": {
      "level": "safe",
      "requiresConfirmation": false,
      "warnings": [],
      "blockingReasons": [],
      "explanation": "This operation is considered safe to execute.",
      "estimatedImpact": "minimal"
    },
    "processingMethod": "hybrid",
    "processingLatency": "1.2s"
  },
  "timestamp": "2025-09-01T10:00:02Z"
}
```

### 2. Resource Event

Notification of Kubernetes resource changes.

**Type**: `resource_event`

**Data Structure**:
```typescript
interface ResourceEventData {
  resources: GeneratedResource[];
  operation: string;               // "created" | "updated" | "deleted"
}

interface GeneratedResource {
  kind: string;                    // Resource type
  name: string;                    // Resource name
  namespace?: string;              // Resource namespace
  action: string;                  // Action performed
  timestamp: string;               // When action occurred
}
```

**Example**:
```json
{
  "type": "resource_event",
  "sessionId": "session-123",
  "data": {
    "resources": [
      {
        "kind": "Deployment",
        "name": "nginx",
        "namespace": "default",
        "action": "created",
        "timestamp": "2025-09-01T10:00:05Z"
      }
    ],
    "operation": "created"
  },
  "timestamp": "2025-09-01T10:00:05Z"
}
```

### 3. Status Update

Real-time operation status updates.

**Type**: `status_update`

**Data Structure**:
```typescript
interface StatusUpdateData {
  phase: string;                   // Current processing phase
  message: string;                 // Human-readable status message
}
```

**Phases**:
- `processing`: Analyzing natural language input
- `completed`: Operation completed successfully
- `failed`: Operation failed
- `awaiting_confirmation`: Waiting for user confirmation
- `cancelled`: Operation was cancelled by user

**Example**:
```json
{
  "type": "status_update",
  "sessionId": "session-123",
  "data": {
    "phase": "processing",
    "message": "Processing your request..."
  },
  "timestamp": "2025-09-01T10:00:01Z"
}
```

### 4. Confirmation Request

Request user confirmation for dangerous operations.

**Type**: `confirmation_request`

**Data Structure**:
```typescript
interface ConfirmationRequestData {
  operationId: string;             // Unique operation identifier
  command: KubernetesCommand;      // Command to be executed
  safetyAssessment: SafetyAssessment; // Safety evaluation
  userMessage: string;             // Original user message
}
```

**Example**:
```json
{
  "type": "confirmation_request",
  "sessionId": "session-123",
  "data": {
    "operationId": "op_session-123_1693567200000",
    "command": {
      "action": "delete",
      "resource": {
        "kind": "Deployment",
        "name": "nginx",
        "namespace": "default"
      },
      "kubectlCmd": "kubectl delete deployment nginx -n default",
      "isDestructive": true,
      "requiresConfirmation": true,
      "description": "Delete nginx deployment"
    },
    "safetyAssessment": {
      "level": "destructive",
      "requiresConfirmation": true,
      "warnings": [
        "Delete operation will permanently remove the resource",
        "Ensure you have backups before proceeding"
      ],
      "blockingReasons": [],
      "explanation": "This operation is destructive and may cause data loss or service interruption.",
      "estimatedImpact": "high"
    },
    "userMessage": "Delete deployment nginx"
  },
  "timestamp": "2025-09-01T10:00:02Z"
}
```

### 5. Error Message

Error notifications and failure details.

**Type**: `error`

**Data Structure**:
```typescript
interface ErrorData {
  error: string;                   // Error message
  details?: string;                // Additional error details
}
```

**Example**:
```json
{
  "type": "error",
  "sessionId": "session-123",
  "data": {
    "error": "Failed to process message",
    "details": "Invalid message format: missing required field 'content'"
  },
  "timestamp": "2025-09-01T10:00:01Z"
}
```

### 6. Pong Message

Response to ping message (heartbeat).

**Type**: `pong`

**Data**: `null`

**Example**:
```json
{
  "type": "pong",
  "sessionId": "session-123",
  "data": null,
  "timestamp": "2025-09-01T10:00:01Z"
}
```

## Data Types

### KubernetesCommand

```typescript
interface KubernetesCommand {
  action: string;                  // Action to perform
  resource: {
    kind: string;                  // Kubernetes resource kind
    name: string;                  // Resource name
    namespace?: string;            // Resource namespace
  };
  manifest?: any;                  // Kubernetes manifest (for create operations)
  kubectlCmd: string;              // Equivalent kubectl command
  parameters: Record<string, string>; // Command parameters
  isDestructive: boolean;          // Whether operation is destructive
  requiresConfirmation: boolean;   // Whether confirmation is needed
  description: string;             // Human-readable description
  warnings?: string[];             // Operation warnings
}
```

### SafetyAssessment

```typescript
interface SafetyAssessment {
  level: 'safe' | 'caution' | 'dangerous' | 'destructive';
  requiresConfirmation: boolean;   // Whether confirmation is required
  warnings: string[];              // Safety warnings
  blockingReasons: string[];       // Reasons preventing execution
  explanation: string;             // Detailed safety explanation
  recommendedActions?: string[];   // Suggested precautions
  estimatedImpact: 'none' | 'minimal' | 'moderate' | 'high' | 'critical';
  timestamp: string;               // Assessment timestamp
}
```

## Connection Lifecycle

### 1. Connection Establishment

```javascript
const ws = new WebSocket('ws://localhost:8080/ws?userId=user123');

ws.onopen = (event) => {
  console.log('Connected to KubeChat');
};
```

### 2. Message Handling

```javascript
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  
  switch (message.type) {
    case 'nlp_result':
      handleNLPResult(message.data);
      break;
    case 'confirmation_request':
      showConfirmationDialog(message.data);
      break;
    case 'status_update':
      updateStatus(message.data);
      break;
    // ... handle other message types
  }
};
```

### 3. Sending Messages

```javascript
function sendChatMessage(content) {
  const message = {
    type: 'chat_message',
    sessionId: getCurrentSessionId(),
    data: {
      message: {
        role: 'user',
        content: content,
        timestamp: new Date().toISOString()
      }
    },
    timestamp: new Date().toISOString()
  };
  
  ws.send(JSON.stringify(message));
}
```

### 4. Connection Management

```javascript
ws.onclose = (event) => {
  if (event.code !== 1000) { // Not a normal closure
    // Attempt to reconnect
    setTimeout(() => {
      connectWebSocket();
    }, 1000);
  }
};

ws.onerror = (error) => {
  console.error('WebSocket error:', error);
};
```

## Error Codes

### WebSocket Close Codes

| Code | Description |
|------|-------------|
| 1000 | Normal closure |
| 1001 | Going away |
| 1002 | Protocol error |
| 1003 | Unsupported data type |
| 1006 | Abnormal closure |
| 1011 | Server error |

### Application Error Codes

| Code | Description |
|------|-------------|
| 400 | Invalid message format |
| 401 | Authentication required |
| 403 | Operation not permitted |
| 404 | Session not found |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

## Rate Limiting

### Connection Limits
- Maximum 100 concurrent connections per server
- Connection rate limit: 10 connections per minute per IP

### Message Limits
- Maximum message size: 512KB
- Message rate limit: 60 messages per minute per session
- Burst allowance: 10 messages per second (short bursts)

## Authentication

### Session-based Authentication
- Each WebSocket connection requires a valid `userId` parameter
- Sessions are created automatically on first connection
- Session timeout: 24 hours of inactivity

### Token-based Authentication (Future)
```javascript
const ws = new WebSocket('ws://localhost:8080/ws', [], {
  headers: {
    'Authorization': 'Bearer <jwt-token>'
  }
});
```

## Best Practices

### Connection Management
1. **Implement Reconnection**: Handle connection drops gracefully
2. **Heartbeat**: Send ping messages every 30 seconds
3. **Error Handling**: Always handle `onerror` and `onclose` events
4. **Message Queuing**: Queue messages during disconnection

### Message Handling
1. **Parse Safely**: Always try/catch JSON parsing
2. **Validate Types**: Check message types before processing
3. **Handle Unknown Types**: Gracefully handle unknown message types
4. **Debounce Sends**: Avoid sending messages too frequently

### Performance
1. **Message Size**: Keep messages under 100KB when possible
2. **Batch Operations**: Combine related operations when possible
3. **Connection Pooling**: Reuse connections across browser tabs
4. **Memory Management**: Clean up event listeners properly

## Example Implementation

### TypeScript WebSocket Client

```typescript
class KubeChatWebSocket {
  private ws: WebSocket | null = null;
  private listeners: Map<string, Function[]> = new Map();
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  async connect(url: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(url);
      
      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.emit('connect');
        resolve();
      };
      
      this.ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data);
          this.emit('message', message);
          this.emit(message.type, message);
        } catch (error) {
          this.emit('error', new Error('Invalid JSON received'));
        }
      };
      
      this.ws.onclose = (event) => {
        this.emit('disconnect', event);
        if (event.code !== 1000) {
          this.attemptReconnect(url);
        }
      };
      
      this.ws.onerror = () => {
        reject(new Error('Connection failed'));
      };
    });
  }
  
  send(message: WebSocketMessage): void {
    if (this.isConnected()) {
      this.ws!.send(JSON.stringify(message));
    } else {
      throw new Error('Not connected');
    }
  }
  
  on(event: string, callback: Function): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, []);
    }
    this.listeners.get(event)!.push(callback);
    
    // Return unsubscribe function
    return () => {
      const callbacks = this.listeners.get(event);
      if (callbacks) {
        const index = callbacks.indexOf(callback);
        if (index > -1) {
          callbacks.splice(index, 1);
        }
      }
    };
  }
  
  private emit(event: string, ...args: any[]): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach(callback => callback(...args));
    }
  }
  
  private isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
  
  private attemptReconnect(url: string): void {
    if (this.reconnectAttempts < this.maxReconnectAttempts) {
      this.reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
      setTimeout(() => {
        this.connect(url).catch(() => {
          // Reconnection failed, will try again
        });
      }, delay);
    }
  }
}
```

### Usage Example

```typescript
const kubechat = new KubeChatWebSocket();

// Connect to server
await kubechat.connect('ws://localhost:8080/ws?userId=user123');

// Listen for NLP results
kubechat.on('nlp_result', (message) => {
  console.log('NLP Result:', message.data);
});

// Listen for confirmation requests
kubechat.on('confirmation_request', (message) => {
  const confirmed = confirm(`Confirm: ${message.data.command.description}?`);
  kubechat.send({
    type: 'confirmation_response',
    sessionId: message.sessionId,
    data: {
      operationId: message.data.operationId,
      confirmed: confirmed
    },
    timestamp: new Date().toISOString()
  });
});

// Send a chat message
kubechat.send({
  type: 'chat_message',
  sessionId: 'session-123',
  data: {
    message: {
      role: 'user',
      content: 'Deploy nginx with 3 replicas',
      timestamp: new Date().toISOString()
    }
  },
  timestamp: new Date().toISOString()
});
```

## Debugging

### Browser Developer Tools

1. **Network Tab**: Monitor WebSocket connection and messages
2. **Console**: Log WebSocket events and errors
3. **Application Tab**: Inspect WebSocket connection state

### Common Issues

1. **CORS Errors**: Ensure server allows WebSocket connections
2. **JSON Parsing Errors**: Validate message format
3. **Connection Drops**: Implement proper reconnection logic
4. **Memory Leaks**: Remove event listeners properly

### Debug Logging

```javascript
const DEBUG = true;

function debugLog(message, data) {
  if (DEBUG) {
    console.log(`[KubeChat WebSocket] ${message}`, data);
  }
}

ws.onmessage = (event) => {
  debugLog('Received message:', event.data);
  // ... handle message
};
```

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-09-01 | Initial WebSocket API release |
| 1.0.1 | TBD | Added authentication and rate limiting |