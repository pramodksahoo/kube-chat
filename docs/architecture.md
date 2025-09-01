# KubeChat Architecture Documentation

## System Overview
KubeChat operates as a Kubernetes operator that processes natural language requests and translates them into Kubernetes operations while building institutional knowledge.

## Component Architecture

### Phase 1 Architecture (Foundation)
```
┌─────────────────┐    ┌─────────────────┐
│   kubectl user  │    │  K8s API user   │
└─────────┬───────┘    └─────────┬───────┘
          │                      │
          └──────────┬───────────┘
                     │
    ┌────────────────▼────────────────┐
    │         KubeChat Operator       │
    │  ┌─────────────────────────┐    │
    │  │   ChatSession Controller │    │
    │  └─────────────────────────┘    │
    │  ┌─────────────────────────┐    │
    │  │    Basic NLP Processor  │    │
    │  └─────────────────────────┘    │
    │  ┌─────────────────────────┐    │
    │  │   Kubernetes API Client │    │
    │  └─────────────────────────┘    │
    └─────────────┬───────────────────┘
                  │
    ┌─────────────▼───────────────┐
    │      Kubernetes Cluster     │
    │   (Deployments, Services,   │
    │    ConfigMaps, Secrets)     │
    └─────────────────────────────┘
```

## Data Models

### ChatSession CRD
```yaml
apiVersion: kubechat.io/v1
kind: ChatSession
metadata:
  name: user-session-123
  namespace: kubechat-system
spec:
  userId: "user@company.com"
  sessionId: "sess_abc123"
  context:
    namespace: "default"
    cluster: "production"
  messages:
    - role: "user"
      content: "deploy nginx with 3 replicas"
      timestamp: "2025-09-01T10:00:00Z"
status:
  phase: "processing" # processing, completed, failed
  lastProcessed: "2025-09-01T10:00:05Z"
  generatedResources:
    - kind: "Deployment"
      name: "nginx"
      namespace: "default"
```

## Security Model

### RBAC Integration
- Operator requires cluster-wide read access
- Write access limited to managed namespaces
- User permissions inherited from Kubernetes RBAC
- All operations logged for audit trail

### Validation Pipeline
1. **Syntax Validation**: YAML structure and K8s schema
2. **Permission Check**: User RBAC validation
3. **Safety Assessment**: Risk evaluation for destructive ops
4. **Policy Compliance**: OPA/Gatekeeper integration (future)

## Performance Considerations

### Resource Limits
- Operator: 100m CPU, 128Mi memory (request)
- Operator: 500m CPU, 512Mi memory (limit)
- Processing: <3 seconds for simple operations
- Concurrent: Support 10+ simultaneous chat sessions

### Scalability Design
- Stateless operator design
- Horizontal scaling with leader election
- Efficient resource watching
- Optimized reconciliation loops
