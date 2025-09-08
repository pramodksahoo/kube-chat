# KubeChat Natural Language Processing (NLP) Guide

## Overview

KubeChat provides advanced Natural Language Processing capabilities that allow you to manage your Kubernetes cluster using plain English commands. The NLP system translates your natural language requests into precise Kubernetes operations.

## Getting Started

### Prerequisites

1. KubeChat operator installed and running
2. OpenAI API key configured (see [Configuration](#configuration))
3. Proper RBAC permissions set up

### Basic Usage

Create a ChatSession resource and start sending natural language messages:

```yaml
apiVersion: kubechat.dev/v1
kind: ChatSession
metadata:
  name: my-chat
  namespace: default
spec:
  userId: "user@example.com"
  sessionId: "session-123"
  messages:
  - role: "user"
    content: "Deploy nginx with 3 replicas"
    timestamp: "2025-09-01T12:00:00Z"
```

## Supported Commands

### Deployment Operations

#### Creating Deployments
```
# Basic deployment creation
"Deploy nginx"
"Create a deployment with nginx image"
"Start nginx with 3 replicas"
"Deploy redis in the database namespace"

# With specific parameters
"Deploy nginx with 5 replicas and expose port 80"
"Create a myapp deployment using image myapp:v1.2.3"
"Deploy nginx with memory limit 256Mi"
```

#### Scaling Deployments
```
# Scale operations
"Scale nginx to 5 replicas"
"Scale deployment myapp to 10"
"Set nginx replica count to 3"
"Scale down myapp to 2 replicas"

# Scale to zero (destructive - requires confirmation)
"Scale nginx to 0 replicas"
"Stop all myapp pods"
```

#### Deleting Deployments
```
# Delete operations (destructive - requires confirmation)
"Delete deployment nginx"
"Remove the myapp deployment"
"Destroy deployment nginx"
```

### Service Operations

#### Creating Services
```
# Service creation
"Expose deployment nginx on port 80"
"Create a service for nginx"
"Expose myapp on port 8080"
"Create a service for deployment redis on port 6379"
```

#### Service Management
```
# Service operations
"Delete service nginx"
"Remove service myapp-service"
```

### Pod Operations

#### Creating Pods
```
# Direct pod creation
"Create a pod with nginx image"
"Run nginx pod"
"Start a redis pod"
```

#### Pod Information
```
# Pod queries
"Describe pods"
"Show me all pods"
"List pods in default namespace"
"Get pod information for nginx"
```

### Configuration Management

#### ConfigMaps
```
# ConfigMap creation
"Create a configmap named app-config"
"Create configmap with data config.yaml=value"
"Make a configmap for application settings"
```

#### Secrets
```
# Secret creation (requires confirmation)
"Create a secret named db-password"
"Create secret with data password=secretvalue"
"Make a secret for database credentials"
```

### Namespace Operations

#### Namespace Management
```
# Namespace creation
"Create namespace myapp"
"Make a new namespace called production"
"Create the development namespace"

# Namespace deletion (destructive - requires confirmation)
"Delete namespace myapp"
"Remove the test namespace"
```

## Safety and Validation

KubeChat includes a comprehensive safety framework with four safety levels:

### Safety Levels

1. **Safe** ✅ - Operations that don't affect running services
   - Creating new resources
   - Describing/listing resources
   - Normal scaling operations

2. **Caution** ⚠️ - Operations requiring attention
   - High replica counts (>10)
   - Large resource requests
   - Operations affecting multiple resources

3. **Dangerous** 🔶 - Operations with significant risk
   - System namespace operations
   - Operations in restricted namespaces
   - Complex multi-resource changes

4. **Destructive** 🔴 - Operations that can cause data loss or downtime
   - Delete operations
   - Scaling to zero replicas
   - Namespace deletion

### Confirmation Requirements

Destructive and dangerous operations require explicit confirmation before execution. The system will:

1. Explain what the operation will do
2. List potential warnings and risks
3. Require user confirmation
4. Provide recommended safety actions

Example confirmation workflow:
```
User: "Delete deployment nginx"

Assistant Response:
I understood your request: Delete deployment nginx

**Action**: Delete deployment 'nginx' in namespace 'default'
**Equivalent kubectl command**: `kubectl delete deployment nginx -n default`

**⚠️ Important Warnings:**
- Delete operation will permanently remove the resource
- Ensure you have backups before proceeding

🔒 **This operation requires confirmation before execution.**

⚠️ This is a destructive operation that may cause data loss or service interruption.

Please confirm this operation before proceeding.
```

## Configuration

### OpenAI API Setup

KubeChat requires an OpenAI API key for natural language processing. Configure it using a Kubernetes secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kubechat-config
  namespace: kubechat-system
type: Opaque
data:
  openai-api-key: <base64-encoded-api-key>
```

### NLP Configuration Options

Configure NLP behavior using a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubechat-nlp-config
  namespace: kubechat-system
data:
  # OpenAI Model Configuration
  openai-model: "gpt-4"
  openai-max-tokens: "1000"
  openai-temperature: "0.1"
  
  # Safety Configuration
  enable-safety-checks: "true"
  confirmation-required: "true"
  
  # Rate Limiting
  rate-limit-requests-per-minute: "60"
  rate-limit-tokens-per-minute: "10000"
  
  # Intent Recognition
  confidence-threshold: "0.8"
  pattern-matching-enabled: "true"
```

## Advanced Features

### Context Awareness

KubeChat maintains context across conversations:

```
User: "Deploy nginx with 3 replicas"
Assistant: [Creates nginx deployment]

User: "Scale it to 5"
Assistant: [Scales the nginx deployment to 5 replicas]

User: "What's the status?"
Assistant: [Shows nginx deployment status]
```

### Parameter Inference

The system intelligently infers missing parameters:

```
User: "Deploy nginx"
# System infers:
# - Resource type: deployment
# - Image: nginx:latest
# - Replicas: 1 (default)
# - Namespace: default

User: "Create a service for it"
# System infers:
# - Service name: nginx
# - Target: nginx deployment
# - Port: 80 (nginx default)
```

### Multi-Step Operations

Complex operations are broken down into steps:

```
User: "Set up a complete nginx deployment with service and configmap"

Assistant Response:
I'll set up a complete nginx deployment with service and configmap:

Step 1: Creating configmap 'nginx-config'
Step 2: Creating deployment 'nginx' with 3 replicas  
Step 3: Creating service 'nginx' exposing port 80

All resources will be created in the 'default' namespace.
```

## Troubleshooting

### Common Issues

#### "Intent not recognized"
**Problem**: The system cannot understand your command
**Solution**: 
- Use clearer, more specific language
- Include resource types explicitly (e.g., "deployment", "service")
- Break complex requests into simpler steps

```
❌ "Make that thing bigger"
✅ "Scale deployment nginx to 5 replicas"
```

#### "Insufficient permissions"
**Problem**: The operation requires additional RBAC permissions
**Solution**: 
- Check your service account permissions
- Ensure proper ClusterRole/Role bindings
- Contact your cluster administrator

#### "OpenAI API rate limit exceeded"
**Problem**: Too many requests to OpenAI API
**Solution**:
- Wait for rate limit reset
- Reduce request frequency
- Use pattern-based commands when possible (they don't use OpenAI)

#### "Safety validation failed"
**Problem**: Operation blocked by safety checks
**Solution**:
- Review the warnings and confirm the operation is intended
- Use more specific resource names and namespaces
- Consider the safety implications

### Pattern vs OpenAI Processing

KubeChat uses two processing methods:

1. **Pattern Recognition** (Fast, no API calls)
   - Simple, common commands
   - Predefined patterns
   - Immediate processing

2. **OpenAI Processing** (Slower, uses API)
   - Complex or ambiguous requests
   - Natural language variations
   - Context-aware responses

Common patterns that don't require OpenAI:
```
"create deployment nginx"
"delete service myapp"
"scale deployment nginx to 5"
"describe pods"
```

### Debug Information

To see detailed processing information, check the ChatSession status:

```bash
kubectl describe chatsession my-chat -n default
```

Look for events and conditions that show:
- Intent recognition results
- Command translation details
- Safety validation outcomes
- Processing errors

## Best Practices

### Writing Effective Commands

1. **Be Specific**
   ```
   ❌ "Start something"
   ✅ "Deploy nginx deployment"
   ```

2. **Include Context**
   ```
   ❌ "Scale to 5"
   ✅ "Scale deployment nginx to 5 replicas"
   ```

3. **Use Standard Terms**
   ```
   ❌ "Make a web thing"
   ✅ "Create a service for nginx"
   ```

4. **Specify Namespaces When Needed**
   ```
   ❌ "Delete nginx"
   ✅ "Delete deployment nginx in production namespace"
   ```

### Safety Best Practices

1. **Always Review Destructive Operations**
   - Read all warnings carefully
   - Confirm you have backups
   - Understand the impact

2. **Start with Non-Production Environments**
   - Test commands in development first
   - Validate behavior before production use

3. **Use Confirmation Workflows**
   - Don't disable safety checks
   - Explicitly confirm dangerous operations

4. **Monitor Operations**
   - Watch for events and status changes
   - Check logs after operations
   - Verify expected outcomes

## Examples by Use Case

### Development Workflow

```
# Set up development environment
"Create namespace development"
"Deploy nginx in development namespace"
"Expose deployment nginx on port 80 in development"
"Create configmap app-config in development"

# Development iterations
"Scale nginx to 3 replicas in development"
"Update deployment nginx with image nginx:1.21"
"Describe deployment nginx in development"

# Cleanup
"Delete all resources in development namespace"
```

### Production Deployment

```
# Production setup (with safety confirmations)
"Create namespace production"
"Deploy myapp with 5 replicas in production namespace"
"Create service for myapp exposing port 8080 in production"
"Create secret db-credentials in production"

# Scaling for load
"Scale myapp to 10 replicas in production"
"Describe deployment myapp in production"

# Emergency response
"Scale myapp to 0 replicas in production"  # Requires confirmation
"Delete pod myapp-xxx in production"       # Requires confirmation
```

### Debugging Workflow

```
# Investigation
"Show all pods in production namespace"
"Describe deployment myapp in production"
"List services in production namespace"

# Status checks
"Get events in production namespace"
"Show pod logs for myapp"
"Describe nodes"

# Quick fixes
"Scale deployment myapp to 3 replicas"
"Restart deployment myapp"
"Delete pod myapp-broken-xxx"
```

## Integration with CI/CD

KubeChat can be integrated with CI/CD pipelines for automated deployments:

```yaml
# Example GitOps workflow
apiVersion: kubechat.dev/v1
kind: ChatSession
metadata:
  name: cicd-deployment
  namespace: cicd
spec:
  userId: "ci-bot@company.com"
  sessionId: "build-${BUILD_NUMBER}"
  messages:
  - role: "user"
    content: "Deploy ${APP_NAME} version ${VERSION} with ${REPLICAS} replicas in ${ENVIRONMENT} namespace"
    timestamp: "${TIMESTAMP}"
```

## API Integration

For programmatic access, use the ChatSession CRD directly:

```go
// Example Go client usage
chatSession := &kubechatv1.ChatSession{
    ObjectMeta: metav1.ObjectMeta{
        Name:      "api-request",
        Namespace: "default",
    },
    Spec: kubechatv1.ChatSessionSpec{
        UserID:    "api-user",
        SessionID: "req-123",
        Messages: []kubechatv1.ChatMessage{
            {
                Role:      "user",
                Content:   "Deploy nginx with 3 replicas",
                Timestamp: metav1.Now(),
            },
        },
    },
}

// Create the ChatSession
err := client.Create(ctx, chatSession)
```

## Limitations

### Current Limitations

1. **Supported Resources**: Limited to basic Kubernetes resources (deployments, services, pods, configmaps, secrets, namespaces)
2. **Complex Operations**: Advanced Kubernetes features (custom resources, operators) not yet supported
3. **Multi-Cluster**: Single cluster operations only
4. **Resource Dependencies**: Limited understanding of resource relationships

### Future Enhancements

- Custom Resource Definition (CRD) support
- Multi-cluster operations
- Advanced RBAC integration
- Workflow automation
- Integration with monitoring systems

## Support and Feedback

For issues and feature requests:
- Check the troubleshooting section above
- Review ChatSession events and logs
- File issues in the KubeChat repository
- Consult the API documentation for advanced usage

---

*This guide covers KubeChat NLP capabilities as of version 1.0. Features and syntax may evolve in future releases.*