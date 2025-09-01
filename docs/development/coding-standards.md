# KubeChat Coding Standards

## Go Development Standards

### Error Handling
```go
// Always wrap errors with context
if err != nil {
    return fmt.Errorf("failed to create deployment: %w", err)
}

// Use structured logging for errors
logger.Error(err, "failed to reconcile ChatSession", 
    "chatSession", chatSession.Name, 
    "namespace", chatSession.Namespace)
```

### Logging Standards
```go
// Use structured logging with logr
import "github.com/go-logr/logr"

func (r *ChatSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) {
    logger := log.FromContext(ctx)
    logger.Info("starting reconciliation", "request", req.NamespacedName)
}
```

### Function Structure
```go
// Every function must follow this pattern:
func FunctionName(ctx context.Context, param1 Type1, param2 Type2) (ReturnType, error) {
    // 1. Input validation
    if param1 == nil {
        return nil, fmt.Errorf("param1 cannot be nil")
    }
    
    // 2. Main logic
    result, err := doWork(ctx, param1, param2)
    if err != nil {
        return nil, fmt.Errorf("failed to do work: %w", err)
    }
    
    // 3. Return with proper error handling
    return result, nil
}
```

### Testing Standards
```go
// Table-driven tests for all functions
func TestFunctionName(t *testing.T) {
    tests := []struct {
        name     string
        input    InputType
        expected ExpectedType
        wantErr  bool
    }{
        {
            name:     "valid input",
            input:    validInput,
            expected: expectedOutput,
            wantErr:  false,
        },
        {
            name:    "invalid input",
            input:   invalidInput,
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result, err := FunctionName(tt.input)
            if tt.wantErr {
                assert.Error(t, err)
                return
            }
            assert.NoError(t, err)
            assert.Equal(t, tt.expected, result)
        })
    }
}
```

## Kubernetes Operator Standards

### Controller Pattern
```go
// Controllers must implement this pattern
type ChatSessionReconciler struct {
    client.Client
    Scheme *runtime.Scheme
    Logger logr.Logger
}

func (r *ChatSessionReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    // 1. Fetch the resource
    // 2. Validate the resource
    // 3. Implement desired state
    // 4. Update status
    // 5. Return appropriate result
}
```

### Resource Naming
- Use kebab-case for resource names
- Include "kubechat" prefix for all custom resources
- Follow Kubernetes naming conventions

### RBAC Principles
- Grant minimal required permissions
- Use specific resource names when possible
- Document all permission requirements
