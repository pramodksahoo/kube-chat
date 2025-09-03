# ChatSession API Reference

## Overview

The ChatSession Custom Resource Definition (CRD) is the core API for KubeChat, enabling natural language interactions with Kubernetes clusters. This document provides comprehensive API reference documentation, including the NLP processing capabilities.

## Natural Language Processing Integration

ChatSession resources automatically process user messages through KubeChat's NLP pipeline, which includes:

- **Intent Recognition**: Identifies user intent from natural language commands
- **Parameter Extraction**: Extracts resource names, namespaces, and configuration values
- **Command Translation**: Converts intents into Kubernetes API operations
- **Safety Validation**: Evaluates operations for security and safety risks
- **Execution Planning**: Creates detailed execution plans with confirmations

For detailed NLP usage instructions, see [NLP User Guide](../user-guides/nlp-usage.md).

## ChatSession Resource

### Group and Version
- **Group**: `kubechat.io`
- **Version**: `v1`
- **Kind**: `ChatSession`
- **Plural**: `chatsessions`
- **Short Name**: `cs`

### Resource Scope
ChatSession resources are **namespace-scoped**.

## Spec Fields

### ChatSessionSpec

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `userId` | string | Yes | Unique identifier for the user initiating the chat session |
| `sessionId` | string | Yes | Unique identifier for the chat session |
| `context` | [ChatContext](#chatcontext) | No | Execution context for chat operations |
| `preferences` | [ChatPreferences](#chatpreferences) | No | User preferences for chat behavior |
| `messages` | [][ChatMessage](#chatmessage) | No | Array of chat messages in conversation history |

### ChatContext

| Field | Type | Required | Description | Validation |
|-------|------|----------|-------------|------------|
| `namespace` | string | No | Default Kubernetes namespace for operations | Must match pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `cluster` | string | No | Cluster identifier for multi-cluster scenarios | - |
| `kubeconfig` | string | No | Kubeconfig for cluster access (not recommended for production) | - |

### ChatPreferences

| Field | Type | Required | Default | Description | Validation |
|-------|------|----------|---------|-------------|------------|
| `confirmDestructive` | boolean | No | `true` | Requires confirmation for destructive operations | - |
| `verboseLogging` | boolean | No | `false` | Enables detailed logging of operations | - |
| `defaultNamespace` | string | No | - | Default namespace for operations | Must match pattern: `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$` |
| `maxHistorySize` | integer | No | `100` | Maximum number of messages to keep in history | Min: 10, Max: 1000 |

### ChatMessage

| Field | Type | Required | Description | Validation |
|-------|------|----------|-------------|------------|
| `role` | string | Yes | Who sent the message | Must be one of: `user`, `assistant`, `system` |
| `content` | string | Yes | The actual message text | Length: 1-10000 characters |
| `timestamp` | metav1.Time | Yes | When the message was created | RFC3339 timestamp |
| `messageId` | string | No | Unique identifier for this message | - |
| `nlpProcessingResult` | [NLPProcessingResult](#nlpprocessingresult) | No | NLP processing results for user messages | Only present for processed messages |

### NLPProcessingResult

| Field | Type | Description |
|-------|------|-------------|
| `intent` | [Intent](#intent) | Recognized intent from natural language processing |
| `confidence` | float64 | Confidence score for intent recognition (0.0-1.0) |
| `extractedParameters` | map[string]string | Parameters extracted from the message |
| `generatedCommands` | [][KubernetesCommand](#kubernetescommand) | Kubernetes operations generated from intent |
| `safetyAssessment` | [SafetyAssessment](#safetyassessment) | Safety evaluation of the requested operations |
| `processingMethod` | string | Method used for processing (`pattern`, `openai`) |
| `processingLatency` | duration | Time taken to process the message |

### Intent

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Primary action requested (`create`, `delete`, `scale`, `describe`, etc.) |
| `resource` | [ResourceRef](#resourceref) | Target Kubernetes resource |
| `context` | map[string]string | Additional context information |

### ResourceRef

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Kubernetes resource kind (e.g., `deployment`, `service`) |
| `name` | string | Resource name |
| `namespace` | string | Resource namespace |
| `apiVersion` | string | Kubernetes API version |

### KubernetesCommand

| Field | Type | Description |
|-------|------|-------------|
| `action` | string | Kubernetes action to perform |
| `resource` | [ResourceRef](#resourceref) | Target resource |
| `parameters` | map[string]string | Command parameters |
| `isDestructive` | boolean | Whether this is a destructive operation |
| `kubectlCommand` | string | Equivalent kubectl command |

### SafetyAssessment

| Field | Type | Description |
|-------|------|-------------|
| `level` | string | Safety level (`safe`, `caution`, `dangerous`, `destructive`) |
| `requiresConfirmation` | boolean | Whether user confirmation is required |
| `warnings` | []string | Safety warnings |
| `blockingReasons` | []string | Reasons preventing execution |
| `explanation` | string | Human-readable safety explanation |
| `recommendedActions` | []string | Recommended safety actions |
| `estimatedImpact` | string | Estimated impact level (`none`, `minimal`, `moderate`, `high`, `critical`) |

## Status Fields

### ChatSessionStatus

| Field | Type | Description |
|-------|------|-------------|
| `phase` | string | Current processing phase (`idle`, `processing`, `completed`, `failed`) |
| `lastProcessed` | metav1.Time | Timestamp of last processed message |
| `conditions` | []metav1.Condition | Standard Kubernetes conditions |
| `generatedResources` | [][GeneratedResource](#generatedresource) | Resources created/modified by this session |
| `messageCount` | integer | Total number of messages in the session |
| `lastError` | string | Last error message if processing failed |
| `nlpStats` | [NLPStatistics](#nlpstatistics) | Statistics about NLP processing for this session |
| `pendingConfirmations` | [][PendingConfirmation](#pendingconfirmation) | Operations awaiting user confirmation |

### NLPStatistics

| Field | Type | Description |
|-------|------|-------------|
| `totalMessagesProcessed` | integer | Total number of messages processed through NLP |
| `patternMatchedCount` | integer | Number of messages processed via pattern matching |
| `openAIProcessedCount` | integer | Number of messages processed via OpenAI |
| `averageConfidence` | float64 | Average confidence score across all processed messages |
| `averageProcessingLatency` | duration | Average time taken to process messages |
| `totalTokensUsed` | integer | Total OpenAI tokens consumed |
| `operationsExecuted` | integer | Number of Kubernetes operations successfully executed |
| `operationsBlocked` | integer | Number of operations blocked by safety validation |

### PendingConfirmation

| Field | Type | Description |
|-------|------|-------------|
| `operationId` | string | Unique identifier for the pending operation |
| `command` | [KubernetesCommand](#kubernetescommand) | The command requiring confirmation |
| `safetyAssessment` | [SafetyAssessment](#safetyassessment) | Safety evaluation results |
| `requestedAt` | metav1.Time | When confirmation was requested |
| `expiresAt` | metav1.Time | When the confirmation request expires |
| `userMessage` | string | Original user message that triggered this operation |

### GeneratedResource

| Field | Type | Description |
|-------|------|-------------|
| `kind` | string | Kind of the Kubernetes resource |
| `name` | string | Name of the resource |
| `namespace` | string | Namespace of the resource (if namespace-scoped) |
| `action` | string | Action performed (`created`, `updated`, `deleted`) |
| `timestamp` | metav1.Time | When the action was performed |

## Conditions

The ChatSession status includes standard Kubernetes conditions:

### Condition Types

| Type | Description |
|------|-------------|
| `Ready` | Indicates if the ChatSession is ready for processing |
| `Processing` | Indicates if a message is currently being processed |
| `Validated` | Indicates if the ChatSession spec is valid |

### Condition Reasons

| Reason | Description |
|--------|-------------|
| `SessionActive` | ChatSession is active and ready |
| `ProcessingMessage` | Currently processing a user message |
| `ValidationFailed` | ChatSession validation failed |
| `ProcessingFailed` | Message processing failed |

## Examples

### Basic ChatSession with NLP Processing

```yaml
apiVersion: kubechat.io/v1
kind: ChatSession
metadata:
  name: user-session-123
  namespace: kubechat-system
spec:
  userId: "admin@company.com"
  sessionId: "sess_abc123"
  context:
    namespace: "default"
    cluster: "production"
  preferences:
    confirmDestructive: true
    verboseLogging: false
    defaultNamespace: "default"
    maxHistorySize: 100
  messages:
    - role: "user"
      content: "deploy nginx with 3 replicas"
      timestamp: "2025-09-01T10:00:00Z"
      messageId: "msg_001"
      nlpProcessingResult:
        intent:
          action: "create"
          resource:
            kind: "deployment"
            name: "nginx"
            namespace: "default"
            apiVersion: "apps/v1"
          context:
            replicas: "3"
        confidence: 0.95
        extractedParameters:
          name: "nginx"
          replicas: "3"
          namespace: "default"
        generatedCommands:
          - action: "create"
            resource:
              kind: "deployment"
              name: "nginx"
              namespace: "default"
            parameters:
              replicas: "3"
              image: "nginx:latest"
            isDestructive: false
            kubectlCommand: "kubectl create deployment nginx --image=nginx:latest --replicas=3 -n default"
        safetyAssessment:
          level: "safe"
          requiresConfirmation: false
          warnings: []
          blockingReasons: []
          explanation: "Safe deployment creation operation"
          estimatedImpact: "minimal"
        processingMethod: "pattern"
        processingLatency: "50ms"
    - role: "assistant"
      content: "I'll create an nginx deployment with 3 replicas in the default namespace."
      timestamp: "2025-09-01T10:00:05Z"
      messageId: "msg_002"
```

### ChatSession Status with NLP Statistics

```yaml
status:
  phase: "processing"
  lastProcessed: "2025-09-01T10:00:05Z"
  conditions:
    - type: "Ready"
      status: "True"
      reason: "SessionActive"
      message: "ChatSession is ready for processing"
      lastTransitionTime: "2025-09-01T10:00:00Z"
    - type: "Processing"
      status: "True"
      reason: "ProcessingMessage"
      message: "Processing user message: deploy nginx"
      lastTransitionTime: "2025-09-01T10:00:05Z"
  generatedResources:
    - kind: "Deployment"
      name: "nginx"
      namespace: "default"
      action: "created"
      timestamp: "2025-09-01T10:00:10Z"
  messageCount: 2
  lastError: ""
  nlpStats:
    totalMessagesProcessed: 1
    patternMatchedCount: 1
    openAIProcessedCount: 0
    averageConfidence: 0.95
    averageProcessingLatency: "50ms"
    totalTokensUsed: 0
    operationsExecuted: 1
    operationsBlocked: 0
  pendingConfirmations: []
```

### Destructive Operation with Confirmation

```yaml
apiVersion: kubechat.io/v1
kind: ChatSession
metadata:
  name: dangerous-operation
  namespace: kubechat-system
spec:
  userId: "admin@company.com"
  sessionId: "sess_danger_123"
  messages:
    - role: "user"
      content: "delete deployment nginx"
      timestamp: "2025-09-01T11:00:00Z"
      messageId: "msg_danger_001"
      nlpProcessingResult:
        intent:
          action: "delete"
          resource:
            kind: "deployment"
            name: "nginx"
            namespace: "default"
        confidence: 0.98
        extractedParameters:
          name: "nginx"
          namespace: "default"
        generatedCommands:
          - action: "delete"
            resource:
              kind: "deployment"
              name: "nginx"
              namespace: "default"
            parameters: {}
            isDestructive: true
            kubectlCommand: "kubectl delete deployment nginx -n default"
        safetyAssessment:
          level: "destructive"
          requiresConfirmation: true
          warnings:
            - "Delete operation will permanently remove the resource"
            - "Ensure you have backups before proceeding"
          blockingReasons: []
          explanation: "🔴 This operation is destructive and may cause data loss or service interruption."
          recommendedActions:
            - "Review the operation carefully"
            - "Ensure you have backups"
          estimatedImpact: "critical"
        processingMethod: "pattern"
        processingLatency: "45ms"
status:
  phase: "awaiting_confirmation"
  pendingConfirmations:
    - operationId: "op_delete_nginx_001"
      command:
        action: "delete"
        resource:
          kind: "deployment"
          name: "nginx"
          namespace: "default"
        isDestructive: true
        kubectlCommand: "kubectl delete deployment nginx -n default"
      safetyAssessment:
        level: "destructive"
        requiresConfirmation: true
        warnings:
          - "Delete operation will permanently remove the resource"
        estimatedImpact: "critical"
      requestedAt: "2025-09-01T11:00:01Z"
      expiresAt: "2025-09-01T11:05:01Z"
      userMessage: "delete deployment nginx"
```

## RBAC Requirements

The ChatSession controller requires the following RBAC permissions:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: chatsession-controller
rules:
- apiGroups: ["kubechat.io"]
  resources: ["chatsessions"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["kubechat.io"]
  resources: ["chatsessions/status"]
  verbs: ["get", "update", "patch"]
- apiGroups: ["kubechat.io"]
  resources: ["chatsessions/finalizers"]  
  verbs: ["update"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

## Validation Rules

### Field Validation

- **userId**: Required, must be a valid email or identifier
- **sessionId**: Required, must be unique per user
- **context.namespace**: Must match Kubernetes namespace naming rules
- **preferences.maxHistorySize**: Must be between 10 and 1000
- **messages[].role**: Must be `user`, `assistant`, or `system`
- **messages[].content**: Must be 1-10000 characters
- **messages[].timestamp**: Must be valid RFC3339 timestamp

### Business Logic Validation

- Sessions with more than `maxHistorySize` messages will be automatically pruned
- Destructive operations require `confirmDestructive: true` in preferences
- Message timestamps must be chronologically ordered
- Resource names must follow Kubernetes naming conventions

## Best Practices

1. **Resource Naming**: Use descriptive names that include user/session identifiers
2. **Namespace Organization**: Place ChatSessions in dedicated namespaces
3. **Message History**: Set reasonable `maxHistorySize` to prevent resource bloat
4. **Error Handling**: Monitor conditions and status for processing failures
5. **Security**: Never store sensitive information in message content
6. **Cleanup**: Implement retention policies for old ChatSession resources

## Troubleshooting

### Common Issues

1. **Validation Errors**: Check field values against validation rules
2. **Processing Stuck**: Check controller logs and conditions
3. **Permission Errors**: Verify RBAC configuration
4. **Resource Conflicts**: Ensure unique sessionId per user

### Monitoring

Monitor the following metrics:
- ChatSession creation/deletion rates
- Message processing latency
- Error rates by condition type
- Resource generation success rates