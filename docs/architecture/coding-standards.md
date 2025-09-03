# Coding Standards

## General Principles

### Code Quality Standards
- **Readability First**: Code should be self-documenting and easy to understand
- **Consistency**: Follow established patterns and conventions throughout the codebase
- **Security by Design**: Always consider security implications of code changes
- **Performance Awareness**: Write efficient code while maintaining readability
- **Test Coverage**: Maintain >80% test coverage for critical business logic

### Documentation Requirements
- **Public APIs**: All public functions and interfaces must have godoc/JSDoc comments
- **Complex Logic**: Add inline comments explaining non-obvious business logic
- **README Files**: Each service should have a comprehensive README
- **API Documentation**: Maintain up-to-date OpenAPI specifications

## Go Coding Standards

### Language Conventions
- **Go Version**: Use Go 1.22+ features and best practices
- **gofmt**: All code must be formatted with `gofmt`
- **golangci-lint**: Code must pass all configured linters
- **Error Handling**: Always handle errors explicitly, never ignore them

### Project Structure
```go
// Package structure example
package nlp

import (
    "context"
    "fmt"
    
    "github.com/kubechat/pkg/models"
)

// Service interface should be defined at package level
type TranslatorService interface {
    TranslateCommand(ctx context.Context, input string) (*models.KubernetesCommand, error)
}
```

### Naming Conventions
- **Packages**: lowercase, single word when possible (`nlp`, `models`, `utils`)
- **Types**: PascalCase (`UserService`, `ChatMessage`)
- **Functions**: PascalCase for public, camelCase for private (`TranslateCommand`, `parseInput`)
- **Constants**: PascalCase or SCREAMING_SNAKE_CASE based on usage
- **Variables**: camelCase (`userID`, `sessionToken`)

### Error Handling
```go
// Good: Explicit error handling with context
func (s *nlpService) ProcessRequest(ctx context.Context, input string) (*Response, error) {
    if input == "" {
        return nil, fmt.Errorf("input cannot be empty")
    }
    
    result, err := s.translator.Translate(ctx, input)
    if err != nil {
        return nil, fmt.Errorf("translation failed: %w", err)
    }
    
    return result, nil
}

// Bad: Ignoring errors
func badExample(input string) *Response {
    result, _ := someOperation(input) // Never do this
    return result
}
```

### Testing Standards
- **Test Files**: `*_test.go` suffix, same package as code under test
- **Test Functions**: `TestFunctionName` pattern
- **Table-Driven Tests**: Use for multiple test cases
- **Testify**: Use testify/assert and testify/mock for assertions and mocking

```go
func TestTranslateCommand(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected *models.KubernetesCommand
        wantErr  bool
    }{
        {
            name:  "get pods command",
            input: "show me all pods",
            expected: &models.KubernetesCommand{
                GeneratedCommand: "kubectl get pods",
                RiskLevel:       models.RiskLevelSafe,
            },
            wantErr: false,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            service := NewTranslatorService()
            result, err := service.TranslateCommand(context.Background(), tt.input)
            
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            
            assert.NoError(t, err)
            assert.Equal(t, tt.expected.GeneratedCommand, result.GeneratedCommand)
            assert.Equal(t, tt.expected.RiskLevel, result.RiskLevel)
        })
    }
}
```

### Logging Standards
- **Structured Logging**: Use structured logging with consistent field names
- **Log Levels**: Use appropriate log levels (Debug, Info, Warn, Error)
- **Context**: Include request context and trace IDs where applicable
- **No Secrets**: Never log sensitive information (tokens, passwords, etc.)

```go
// Good: Structured logging
log.Info("command translated successfully",
    "user_id", userID,
    "session_id", sessionID,
    "input_length", len(input),
    "command_type", commandType,
)

// Bad: Unstructured logging
log.Printf("User %s executed command: %s", userID, sensitiveCommand)
```

## TypeScript/React Coding Standards

### Language Conventions
- **TypeScript**: Strict mode enabled, all types explicitly defined
- **ESLint**: Code must pass all configured ESLint rules
- **Prettier**: All code formatted with Prettier
- **Import Organization**: Group imports (external, internal, relative)

### Component Structure
```typescript
// Good: Well-structured component
import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { useChatSession } from '@/hooks/useChatSession';
import { ChatMessage } from '@/types/chat';

interface ChatInterfaceProps {
  sessionId: string;
  onMessageSent: (message: ChatMessage) => void;
}

export const ChatInterface: React.FC<ChatInterfaceProps> = ({
  sessionId,
  onMessageSent,
}) => {
  const [message, setMessage] = useState('');
  const { sendMessage, isLoading } = useChatSession(sessionId);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!message.trim() || isLoading) return;

    try {
      const chatMessage = await sendMessage(message);
      onMessageSent(chatMessage);
      setMessage('');
    } catch (error) {
      console.error('Failed to send message:', error);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Ask me about your cluster..."
        disabled={isLoading}
      />
      <Button type="submit" disabled={!message.trim() || isLoading}>
        Send
      </Button>
    </form>
  );
};
```

### Type Definitions
```typescript
// Good: Well-defined interfaces
export interface KubernetesCommand {
  id: string;
  sessionId: string;
  naturalLanguageInput: string;
  generatedCommand: string;
  riskLevel: RiskLevel;
  status: CommandStatus;
  executedAt?: Date;
}

export enum RiskLevel {
  SAFE = 'safe',
  CAUTION = 'caution',
  DESTRUCTIVE = 'destructive',
}

// Use union types for string literals where appropriate
export type CommandStatus = 
  | 'pending' 
  | 'approved' 
  | 'executing' 
  | 'completed' 
  | 'failed' 
  | 'cancelled';
```

### Testing Standards (Frontend)
- **Vitest**: Primary testing framework
- **Testing Library**: For component testing
- **User-Centric Tests**: Test behavior, not implementation details

```typescript
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { ChatInterface } from './ChatInterface';
import { useChatSession } from '@/hooks/useChatSession';

// Mock the custom hook
jest.mock('@/hooks/useChatSession');

describe('ChatInterface', () => {
  const mockUseChatSession = useChatSession as jest.MockedFunction<typeof useChatSession>;
  const mockSendMessage = jest.fn();
  const mockOnMessageSent = jest.fn();

  beforeEach(() => {
    mockUseChatSession.mockReturnValue({
      sendMessage: mockSendMessage,
      isLoading: false,
    });
  });

  it('sends message when form is submitted', async () => {
    const mockMessage = { id: '1', content: 'test message' };
    mockSendMessage.mockResolvedValue(mockMessage);

    render(
      <ChatInterface 
        sessionId="session-1" 
        onMessageSent={mockOnMessageSent} 
      />
    );

    const input = screen.getByPlaceholderText('Ask me about your cluster...');
    const button = screen.getByRole('button', { name: 'Send' });

    fireEvent.change(input, { target: { value: 'get pods' } });
    fireEvent.click(button);

    await waitFor(() => {
      expect(mockSendMessage).toHaveBeenCalledWith('get pods');
      expect(mockOnMessageSent).toHaveBeenCalledWith(mockMessage);
    });
  });
});
```

## Security Standards

### Input Validation
- **Sanitize All Inputs**: Never trust external input
- **Validate Types**: Use strong typing to catch errors early
- **Escape Output**: Properly escape data in user interfaces
- **Rate Limiting**: Implement rate limiting for all public APIs

### Authentication & Authorization
- **JWT Tokens**: Use secure JWT handling practices
- **RBAC Integration**: Always check Kubernetes RBAC permissions
- **Session Management**: Implement secure session handling
- **Audit Logging**: Log all security-relevant events

### Secrets Management
- **No Hardcoded Secrets**: Never commit secrets to version control
- **Environment Variables**: Use environment variables for configuration
- **External Secrets**: Use External Secrets Operator for production
- **Minimal Exposure**: Only expose secrets to components that need them

## Performance Standards

### Go Performance
- **Context Usage**: Always use context for cancellation and timeouts
- **Connection Pooling**: Use connection pools for database and HTTP clients
- **Memory Management**: Be mindful of memory allocations in hot paths
- **Profiling**: Use Go's built-in profiling tools for optimization

### Frontend Performance
- **Code Splitting**: Use lazy loading for routes and components
- **Bundle Size**: Monitor and optimize bundle size
- **Memoization**: Use React.memo and useMemo appropriately
- **Asset Optimization**: Optimize images and static assets

### Database Performance
- **Query Optimization**: Use appropriate indexes and query patterns
- **Connection Limits**: Respect database connection limits
- **Caching**: Implement caching for frequently accessed data
- **Migration Safety**: Write safe, backward-compatible migrations

## Deployment Standards

### Container Best Practices
- **Multi-Stage Builds**: Use multi-stage Docker builds
- **Security Scanning**: Scan images for vulnerabilities
- **Minimal Base Images**: Use minimal base images (distroless, alpine)
- **Health Checks**: Implement proper health check endpoints

### Kubernetes Manifests
- **Resource Limits**: Always set resource requests and limits
- **Health Checks**: Configure readiness and liveness probes
- **Security Context**: Use appropriate security contexts
- **Labels and Annotations**: Use consistent labeling schemes

## Code Review Standards

### Review Checklist
- **Functionality**: Does the code work as intended?
- **Standards Compliance**: Does it follow these coding standards?
- **Security**: Are there any security vulnerabilities?
- **Performance**: Are there performance implications?
- **Tests**: Are there adequate tests?
- **Documentation**: Is the code properly documented?

### Review Process
- **Small PRs**: Keep pull requests small and focused
- **Clear Descriptions**: Provide clear PR descriptions and context
- **Self-Review**: Review your own code before requesting review
- **Responsive**: Respond to review comments promptly
- **Learn and Teach**: Use reviews as learning opportunities