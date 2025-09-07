# KubeChat Development Coding Standards

## Introduction

This document establishes comprehensive coding standards for the KubeChat project to ensure consistency, maintainability, and security across the entire codebase. All developers and AI agents implementing KubeChat components must follow these standards.

### Enforcement
- **Mandatory for all code contributions**
- **Enforced via automated linting and code review**
- **Blocking for pull request approval**

### Change Log
| Date | Version | Description | Author |
|------|---------|-------------|---------|
| 2025-09-05 | 1.0 | Initial coding standards creation | Winston (Architect) |

---

## Go Backend Standards

### Code Style and Structure

#### Error Handling (MANDATORY)
```go
// ✅ CORRECT - Always wrap errors with context
func ProcessCommand(ctx context.Context, cmd string) (*Command, error) {
    result, err := nlpService.Translate(ctx, cmd)
    if err != nil {
        return nil, fmt.Errorf("failed to translate command '%s': %w", cmd, err)
    }
    return result, nil
}

// ❌ INCORRECT - Never ignore errors
func ProcessCommand(ctx context.Context, cmd string) *Command {
    result, _ := nlpService.Translate(ctx, cmd) // NEVER DO THIS
    return result
}
```

#### Context Usage (MANDATORY)
```go
// ✅ CORRECT - Always pass context as first parameter
func (s *AuditService) LogEvent(ctx context.Context, event *AuditEvent) error {
    // Check for cancellation
    select {
    case <-ctx.Done():
        return ctx.Err()
    default:
    }
    
    return s.repository.Save(ctx, event)
}

// ❌ INCORRECT - Missing context parameter
func (s *AuditService) LogEvent(event *AuditEvent) error {
    return s.repository.Save(event) // Cannot handle cancellation
}
```

#### Structured Logging (MANDATORY)
```go
// ✅ CORRECT - Structured logging with context
import "github.com/go-logr/logr"

func (s *NLPService) ProcessQuery(ctx context.Context, userID, query string) error {
    log := logr.FromContextOrDiscard(ctx)
    
    log.Info("processing natural language query",
        "user_id", userID,
        "query_length", len(query),
        "service", "nlp")
    
    // Process query...
    
    log.Info("query processed successfully",
        "user_id", userID,
        "processing_time_ms", time.Since(start).Milliseconds())
    
    return nil
}

// ❌ INCORRECT - Unstructured logging
func (s *NLPService) ProcessQuery(ctx context.Context, userID, query string) error {
    fmt.Printf("Processing query from %s: %s", userID, query) // NEVER DO THIS
    return nil
}
```

#### Interface Design (MANDATORY)
```go
// ✅ CORRECT - Small, focused interfaces
type CommandExecutor interface {
    Execute(ctx context.Context, cmd *KubernetesCommand) (*ExecutionResult, error)
}

type AuditLogger interface {
    LogEvent(ctx context.Context, event *AuditEvent) error
}

// ✅ CORRECT - Dependency injection pattern
type APIGateway struct {
    executor CommandExecutor
    auditor  AuditLogger
    logger   logr.Logger
}

func NewAPIGateway(executor CommandExecutor, auditor AuditLogger, logger logr.Logger) *APIGateway {
    return &APIGateway{
        executor: executor,
        auditor:  auditor,
        logger:   logger,
    }
}
```

#### Testing Patterns (MANDATORY)
```go
// ✅ CORRECT - Table-driven tests with descriptive names
func TestNLPService_ProcessQuery(t *testing.T) {
    tests := []struct {
        name          string
        input         string
        expectedCmd   string
        expectedError string
    }{
        {
            name:        "simple_get_pods_request",
            input:       "show me all pods",
            expectedCmd: "kubectl get pods",
        },
        {
            name:          "malformed_request",
            input:         "xyz invalid query",
            expectedError: "unable to parse natural language",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            service := setupTestNLPService(t)
            
            cmd, err := service.ProcessQuery(context.Background(), tt.input)
            
            if tt.expectedError != "" {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.expectedError)
                return
            }
            
            require.NoError(t, err)
            assert.Equal(t, tt.expectedCmd, cmd.GeneratedCommand)
        })
    }
}

// ✅ CORRECT - Test helper functions
func setupTestNLPService(t *testing.T) *NLPService {
    t.Helper()
    
    mockTranslator := &mockTranslator{}
    logger := logr.Discard()
    
    return NewNLPService(mockTranslator, logger)
}
```

### Security Requirements (MANDATORY)

#### Input Validation
```go
// ✅ CORRECT - Always validate input
func (s *APIGateway) ProcessCommand(ctx context.Context, req *CommandRequest) error {
    if req == nil {
        return fmt.Errorf("command request cannot be nil")
    }
    
    if strings.TrimSpace(req.Query) == "" {
        return fmt.Errorf("command query cannot be empty")
    }
    
    if len(req.Query) > MaxQueryLength {
        return fmt.Errorf("query exceeds maximum length of %d characters", MaxQueryLength)
    }
    
    // Sanitize input
    req.Query = sanitizeUserInput(req.Query)
    
    return s.processValidatedCommand(ctx, req)
}

// ✅ CORRECT - SQL injection prevention
func (r *AuditRepository) SearchEvents(ctx context.Context, filter *EventFilter) ([]*AuditEvent, error) {
    query := `
        SELECT id, user_id, action, timestamp, metadata 
        FROM audit_events 
        WHERE user_id = $1 AND timestamp BETWEEN $2 AND $3
        ORDER BY timestamp DESC
        LIMIT $4`
    
    rows, err := r.db.QueryContext(ctx, query, 
        filter.UserID, filter.StartTime, filter.EndTime, filter.Limit)
    if err != nil {
        return nil, fmt.Errorf("failed to query audit events: %w", err)
    }
    defer rows.Close()
    
    // Process results...
}
```

#### Secret Management
```go
// ✅ CORRECT - Never hardcode secrets
func (s *NLPService) connectToOpenAI(ctx context.Context) error {
    apiKey := os.Getenv("OPENAI_API_KEY")
    if apiKey == "" {
        return fmt.Errorf("OPENAI_API_KEY environment variable not set")
    }
    
    // Use External Secrets Operator in production
    s.client = openai.NewClient(apiKey)
    return nil
}

// ❌ INCORRECT - Hardcoded secrets
func (s *NLPService) connectToOpenAI() error {
    apiKey := "sk-1234567890abcdef" // NEVER DO THIS
    s.client = openai.NewClient(apiKey)
    return nil
}
```

---

## TypeScript Frontend Standards

### React Component Patterns (MANDATORY)

#### Functional Components Only
```typescript
// ✅ CORRECT - Functional component with TypeScript interface
interface ChatMessageProps {
  message: ChatMessage;
  onEdit?: (messageId: string) => void;
  onDelete?: (messageId: string) => void;
}

export function ChatMessageComponent({ message, onEdit, onDelete }: ChatMessageProps) {
  const [isEditing, setIsEditing] = useState(false);
  
  const handleEdit = useCallback(() => {
    onEdit?.(message.id);
    setIsEditing(true);
  }, [message.id, onEdit]);
  
  return (
    <div className="chat-message" data-testid={`message-${message.id}`}>
      <div className="message-content">{message.content}</div>
      {onEdit && (
        <button onClick={handleEdit} aria-label="Edit message">
          Edit
        </button>
      )}
    </div>
  );
}

// ❌ INCORRECT - Class component
class ChatMessageComponent extends React.Component<ChatMessageProps> {
  // Don't use class components
}
```

#### Custom Hooks Patterns
```typescript
// ✅ CORRECT - Custom hook with proper naming and error handling
export function useWebSocket(sessionId: string): {
  isConnected: boolean;
  sendMessage: (message: string) => void;
  error: string | null;
} {
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  
  const sendMessage = useCallback((message: string) => {
    if (!socketRef.current || socketRef.current.readyState !== WebSocket.OPEN) {
      setError('WebSocket not connected');
      return;
    }
    
    try {
      socketRef.current.send(JSON.stringify({ type: 'message', content: message }));
    } catch (err) {
      setError(`Failed to send message: ${err instanceof Error ? err.message : 'Unknown error'}`);
    }
  }, []);
  
  useEffect(() => {
    const ws = new WebSocket(`wss://api.kubechat.io/chat/${sessionId}`);
    socketRef.current = ws;
    
    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
    };
    
    ws.onclose = () => {
      setIsConnected(false);
    };
    
    ws.onerror = () => {
      setError('WebSocket connection error');
    };
    
    return () => {
      ws.close();
    };
  }, [sessionId]);
  
  return { isConnected, sendMessage, error };
}
```

#### State Management with Zustand
```typescript
// ✅ CORRECT - Zustand store with TypeScript
interface ChatStore {
  messages: ChatMessage[];
  isProcessing: boolean;
  error: string | null;
  addMessage: (message: ChatMessage) => void;
  setProcessing: (processing: boolean) => void;
  setError: (error: string | null) => void;
  clearMessages: () => void;
}

export const useChatStore = create<ChatStore>((set) => ({
  messages: [],
  isProcessing: false,
  error: null,
  
  addMessage: (message) =>
    set((state) => ({
      messages: [...state.messages, message],
      error: null, // Clear error on successful action
    })),
    
  setProcessing: (isProcessing) =>
    set({ isProcessing }),
    
  setError: (error) =>
    set({ error, isProcessing: false }),
    
  clearMessages: () =>
    set({ messages: [], error: null }),
}));

// ✅ CORRECT - Using store in component
export function ChatInterface() {
  const { messages, isProcessing, addMessage, setError } = useChatStore();
  const { sendMessage, error: wsError } = useWebSocket('session-123');
  
  useEffect(() => {
    if (wsError) {
      setError(wsError);
    }
  }, [wsError, setError]);
  
  // Component logic...
}
```

#### Error Boundary Implementation
```typescript
// ✅ CORRECT - Error boundary for chat interface
interface ErrorBoundaryState {
  hasError: boolean;
  error?: Error;
}

export class ChatErrorBoundary extends Component<
  { children: ReactNode },
  ErrorBoundaryState
> {
  constructor(props: { children: ReactNode }) {
    super(props);
    this.state = { hasError: false };
  }
  
  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }
  
  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    // Log error to monitoring service
    console.error('Chat interface error:', error, errorInfo);
    
    // Send to error tracking service
    this.logErrorToService(error, errorInfo);
  }
  
  private logErrorToService(error: Error, errorInfo: ErrorInfo) {
    // Implementation for error logging
    fetch('/api/errors', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        error: error.message,
        stack: error.stack,
        componentStack: errorInfo.componentStack,
      }),
    }).catch(console.error);
  }
  
  render() {
    if (this.state.hasError) {
      return (
        <div className="error-fallback">
          <h2>Something went wrong with the chat interface.</h2>
          <details style={{ whiteSpace: 'pre-wrap' }}>
            {this.state.error?.toString()}
          </details>
          <button onClick={() => window.location.reload()}>
            Reload Application
          </button>
        </div>
      );
    }
    
    return this.props.children;
  }
}
```

### Performance Optimization (MANDATORY)

#### Memoization Patterns
```typescript
// ✅ CORRECT - Proper use of useMemo and useCallback
interface CommandListProps {
  commands: KubernetesCommand[];
  onExecute: (commandId: string) => void;
  filter: CommandFilter;
}

export function CommandList({ commands, onExecute, filter }: CommandListProps) {
  // Memoize expensive filtering operation
  const filteredCommands = useMemo(() => {
    return commands.filter(cmd => {
      if (filter.status && cmd.status !== filter.status) return false;
      if (filter.riskLevel && cmd.riskLevel !== filter.riskLevel) return false;
      if (filter.searchQuery) {
        return cmd.naturalLanguageInput
          .toLowerCase()
          .includes(filter.searchQuery.toLowerCase());
      }
      return true;
    });
  }, [commands, filter]);
  
  // Memoize callback to prevent unnecessary re-renders
  const handleExecute = useCallback((commandId: string) => {
    onExecute(commandId);
  }, [onExecute]);
  
  return (
    <div className="command-list">
      {filteredCommands.map(command => (
        <CommandItem
          key={command.id}
          command={command}
          onExecute={handleExecute}
        />
      ))}
    </div>
  );
}

// ✅ CORRECT - Memoized component to prevent unnecessary re-renders
export const CommandItem = memo<{
  command: KubernetesCommand;
  onExecute: (commandId: string) => void;
}>(({ command, onExecute }) => {
  const handleClick = useCallback(() => {
    onExecute(command.id);
  }, [command.id, onExecute]);
  
  return (
    <div className="command-item">
      <span className="command-text">{command.generatedCommand}</span>
      <button onClick={handleClick}>Execute</button>
    </div>
  );
});
```

---

## API Design Standards (MANDATORY)

### RESTful Resource Naming
```yaml
# ✅ CORRECT - RESTful resource naming
endpoints:
  - path: "/api/v1/sessions"
    methods: ["GET", "POST"]
    description: "List and create chat sessions"
    
  - path: "/api/v1/sessions/{sessionId}"
    methods: ["GET", "PUT", "DELETE"]
    description: "Manage specific chat session"
    
  - path: "/api/v1/sessions/{sessionId}/messages"
    methods: ["GET", "POST"]
    description: "Chat messages within session"
    
  - path: "/api/v1/commands/{commandId}/execute"
    methods: ["POST"]
    description: "Execute specific command"
    
  - path: "/api/v1/audit/events"
    methods: ["GET"]
    description: "Search audit events"
    
  - path: "/api/v1/audit/export"
    methods: ["POST"]
    description: "Generate audit reports"

# ❌ INCORRECT - Non-RESTful naming
bad_endpoints:
  - "/api/getAllSessions"  # Should be GET /api/sessions
  - "/api/createCommand"   # Should be POST /api/commands
  - "/api/executeCmd"      # Should be POST /api/commands/{id}/execute
```

### HTTP Status Code Usage
```typescript
// ✅ CORRECT - Proper HTTP status codes
export const HttpStatusCodes = {
  // Success
  OK: 200,                    // GET requests successful
  CREATED: 201,              // POST requests creating resources
  ACCEPTED: 202,             // Async operations accepted
  NO_CONTENT: 204,           // DELETE requests successful
  
  // Client Errors
  BAD_REQUEST: 400,          // Invalid request format
  UNAUTHORIZED: 401,         // Authentication required
  FORBIDDEN: 403,            // Insufficient permissions
  NOT_FOUND: 404,            // Resource doesn't exist
  CONFLICT: 409,             // Resource state conflict
  UNPROCESSABLE_ENTITY: 422, // Validation errors
  
  // Server Errors
  INTERNAL_SERVER_ERROR: 500, // Unexpected server errors
  BAD_GATEWAY: 502,          // Upstream service errors
  SERVICE_UNAVAILABLE: 503,  // Service temporarily down
  GATEWAY_TIMEOUT: 504,      // Upstream timeout
} as const;

// ✅ CORRECT - Consistent error response format
interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    timestamp: string;
    traceId: string;
  };
}

// Example error response
const validationErrorResponse: ErrorResponse = {
  error: {
    code: "VALIDATION_FAILED",
    message: "Request validation failed",
    details: {
      field: "naturalLanguageInput",
      constraint: "must not be empty",
    },
    timestamp: "2025-09-05T10:30:00Z",
    traceId: "trace-123456789",
  },
};
```

### Pagination Patterns
```typescript
// ✅ CORRECT - Consistent pagination pattern
interface PaginationRequest {
  limit?: number;    // Default 20, max 100
  offset?: number;   // Default 0
  cursor?: string;   // For cursor-based pagination
}

interface PaginationResponse<T> {
  data: T[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    hasNext: boolean;
    hasPrev: boolean;
    nextCursor?: string;
    prevCursor?: string;
  };
}

// Example usage
const auditEventsResponse: PaginationResponse<AuditEvent> = {
  data: [...events],
  pagination: {
    total: 1500,
    limit: 20,
    offset: 40,
    hasNext: true,
    hasPrev: true,
    nextCursor: "cursor-xyz789",
    prevCursor: "cursor-abc123",
  },
};
```

---

## Testing Standards (MANDATORY)

### Test Naming Conventions
```go
// ✅ CORRECT - Descriptive test names
func TestNLPService_ProcessQuery_WithValidKubectlCommand_ReturnsCorrectTranslation(t *testing.T)
func TestNLPService_ProcessQuery_WithInvalidInput_ReturnsValidationError(t *testing.T)
func TestNLPService_ProcessQuery_WithNetworkTimeout_ReturnsTimeoutError(t *testing.T)

// ❌ INCORRECT - Vague test names
func TestProcessQuery(t *testing.T)
func TestNLPService(t *testing.T)
func TestError(t *testing.T)
```

### Test Data Management
```typescript
// ✅ CORRECT - Test data factories
export class ChatMessageFactory {
  static create(overrides: Partial<ChatMessage> = {}): ChatMessage {
    return {
      id: `msg-${Math.random().toString(36).substr(2, 9)}`,
      role: 'user',
      content: 'test message',
      timestamp: new Date(),
      ...overrides,
    };
  }
  
  static createUserMessage(content: string): ChatMessage {
    return this.create({ role: 'user', content });
  }
  
  static createSystemMessage(content: string): ChatMessage {
    return this.create({ role: 'system', content });
  }
}

// Usage in tests
describe('ChatInterface', () => {
  it('should display user messages correctly', () => {
    const message = ChatMessageFactory.createUserMessage('show me pods');
    render(<ChatMessage message={message} />);
    expect(screen.getByText('show me pods')).toBeInTheDocument();
  });
});
```

### Performance Test Patterns
```go
// ✅ CORRECT - Benchmark tests
func BenchmarkNLPService_ProcessQuery(b *testing.B) {
    service := setupBenchmarkNLPService(b)
    query := "scale nginx deployment to 5 replicas"
    ctx := context.Background()
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := service.ProcessQuery(ctx, query)
        if err != nil {
            b.Fatal(err)
        }
    }
}

// ✅ CORRECT - Load test simulation
func TestAPIGateway_HandleConcurrentRequests(t *testing.T) {
    gateway := setupTestAPIGateway(t)
    
    const numRequests = 100
    const concurrency = 10
    
    var wg sync.WaitGroup
    sem := make(chan struct{}, concurrency)
    
    for i := 0; i < numRequests; i++ {
        wg.Add(1)
        go func(requestID int) {
            defer wg.Done()
            sem <- struct{}{} // Acquire semaphore
            defer func() { <-sem }() // Release semaphore
            
            req := createTestRequest(requestID)
            resp, err := gateway.HandleRequest(context.Background(), req)
            
            assert.NoError(t, err)
            assert.Equal(t, http.StatusOK, resp.StatusCode)
        }(i)
    }
    
    wg.Wait()
}
```

---

## Git Workflow Standards (MANDATORY)

### Branch Naming Convention
```bash
# ✅ CORRECT - Branch naming patterns
feature/epic-1-nlp-command-translation
feature/epic-3-audit-logging-integration
fix/websocket-connection-stability
hotfix/security-rbac-bypass
chore/update-dependencies-q3-2025

# ❌ INCORRECT - Poor branch names
my-feature
fix
test-branch
john-dev
```

### Commit Message Format
```bash
# ✅ CORRECT - Conventional commit format
feat(nlp): add command safety assessment for destructive operations

- Implement risk level calculation for kubectl commands
- Add confirmation workflow for delete operations  
- Include RBAC validation in safety assessment
- Add comprehensive tests for edge cases

Closes #123

# ✅ CORRECT - Other examples
fix(audit): resolve PostgreSQL connection pool exhaustion
docs(api): update OpenAPI specification for v1.1 endpoints
test(e2e): add accessibility compliance test suite
chore(deps): update Go dependencies to latest security patches

# ❌ INCORRECT - Poor commit messages
fix bug
update code
WIP
asdf
```

### Pull Request Template
```markdown
# Pull Request Template (Mandatory)

## Summary
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change fixing an issue)
- [ ] New feature (non-breaking change adding functionality)
- [ ] Breaking change (fix or feature causing existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security patch

## Security Checklist
- [ ] No hardcoded secrets or credentials
- [ ] Input validation implemented where applicable
- [ ] Authentication/authorization changes reviewed
- [ ] Dependencies updated to secure versions
- [ ] SQL injection prevention verified

## Testing Checklist
- [ ] Unit tests added/updated with 80%+ coverage
- [ ] Integration tests pass
- [ ] E2E tests pass for affected workflows
- [ ] Manual testing completed
- [ ] Performance impact assessed

## Accessibility Checklist (Frontend changes)
- [ ] WCAG AA compliance verified
- [ ] Keyboard navigation tested
- [ ] Screen reader compatibility checked
- [ ] Color contrast verified
- [ ] Automated a11y tests pass

## Documentation
- [ ] Code changes documented in comments
- [ ] API changes reflected in OpenAPI spec
- [ ] README updated if needed
- [ ] Architecture diagrams updated if applicable

## Deployment Notes
- [ ] Database migrations included if needed
- [ ] Configuration changes documented
- [ ] Backwards compatibility considerations
- [ ] Rollback plan documented
```

---

## Code Review Standards (MANDATORY)

### Review Checklist
```yaml
security_review:
  - "No hardcoded credentials or secrets"
  - "Input validation implemented"
  - "SQL injection prevention"
  - "Authentication/authorization correct"
  - "Dependencies updated and secure"

functionality_review:
  - "Code works as intended"
  - "Edge cases handled"
  - "Error handling comprehensive"
  - "Performance implications considered"
  - "Backwards compatibility maintained"

code_quality_review:
  - "Follows coding standards"
  - "Code is readable and maintainable"
  - "No code duplication"
  - "Appropriate abstractions"
  - "Naming conventions followed"

testing_review:
  - "Adequate test coverage (80%+)"
  - "Tests are meaningful and thorough"
  - "Integration tests where appropriate"
  - "Performance tests for critical paths"

accessibility_review: # Frontend only
  - "WCAG AA compliance"
  - "Keyboard navigation support"
  - "Screen reader compatibility"
  - "Color contrast sufficient"
  - "Focus management proper"
```

### Approval Requirements
```yaml
approval_matrix:
  standard_changes:
    required_approvers: 1
    requirements: ["Tests pass", "No security issues"]
    
  security_changes:
    required_approvers: 2
    requirements: ["Security team approval", "Tests pass"]
    
  architecture_changes:
    required_approvers: 2
    requirements: ["Architecture team approval", "Documentation updated"]
    
  breaking_changes:
    required_approvers: 2
    requirements: ["Product team approval", "Migration plan", "Tests pass"]
```

---

## Conclusion

These coding standards are **mandatory** for all KubeChat development. They ensure:

- **Security:** Comprehensive input validation and secret management
- **Reliability:** Proper error handling and testing coverage
- **Maintainability:** Consistent patterns and documentation
- **Accessibility:** WCAG AA compliance for inclusive design
- **Performance:** Optimized patterns for enterprise scale

**Next Steps:**
1. Set up automated linting to enforce these standards
2. Configure CI/CD pipelines with quality gates
3. Train development team on standards
4. Create automated checks for pull requests

**Enforcement:**
- **Automated linting blocks non-compliant code**
- **CI/CD pipelines enforce testing requirements**
- **Pull request templates ensure review compliance**
- **Regular code audits verify adherence**