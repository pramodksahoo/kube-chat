# Deployment Architecture - Phase 1 Model 1 (On-Premises)

## Overview

This document defines the deployment architecture for **KubeChat Phase 1: Model 1 (On-Premises FREE Platform)** - our primary development target. This architecture ensures complete data sovereignty, air-gap capability, zero vendor lock-in, and Helm-native deployment directly into customer Kubernetes clusters.

## Phase 1 Model 1 Core Principles

### 1. Data Sovereignty and Air-Gap Support

```yaml
data_sovereignty:
  deployment_location: "Customer-controlled Kubernetes clusters"
  data_residency: "100% on-premises, no external dependencies"
  vendor_lock_in: "Zero - complete customer control"
  
air_gap_capability:
  offline_installation: "Complete offline deployment capability"
  container_registry: "Customer-managed private registry"
  dependencies: "All dependencies bundled in Helm chart"
  updates: "Manual deployment with offline package"
```

### 2. Helm-Native Architecture

```yaml
helm_deployment:
  chart_structure: "Single comprehensive Helm chart"
  dependencies: "No external chart dependencies"
  customization: "Extensive values.yaml configuration"
  installation: "One-command deployment: helm install kubechat ./chart"
  
kubernetes_operator:
  pattern: "Custom Resource Definitions (CRDs)"
  controller: "Native Kubernetes controller pattern"
  lifecycle: "Declarative resource management"
  rbac: "Minimal required permissions"
```

### 3. Rancher Desktop Development Environment

```yaml
local_development:
  platform: "Rancher Desktop with Kubernetes"
  testing: "Full on-premises simulation"
  helm_testing: "helm install --dry-run validation"
  air_gap_testing: "Disconnected mode testing capability"
```

## Deployment Environments

### 1. Environment Hierarchy

```yaml
environments:
  development:
    purpose: "Feature development and unit testing on Rancher Desktop"
    platform: "Rancher Desktop Kubernetes"
    isolation: "Namespace-based"
    data_persistence: "Ephemeral"
    testing: "Air-gap simulation capability"
    
  staging:
    purpose: "Integration testing and QA validation"
    platform: "Customer-like on-premises cluster"
    isolation: "Cluster-based"
    data_persistence: "Persistent with snapshots"
    deployment: "Helm chart validation"
    
  production:
    purpose: "Customer on-premises deployment"
    platform: "Customer Kubernetes clusters"
    isolation: "Complete customer control"
    data_persistence: "Customer-managed backup/restore"
    deployment: "Helm-native single-command installation"
```

### 2. Environment Configuration Management

#### GitOps Workflow
```yaml
configuration_management:
  tool: "ArgoCD"
  repository: "git@github.com:company/kubechat-config.git"
  structure:
    - "environments/dev/"
    - "environments/staging/"
    - "environments/prod/"
    
  sync_policy:
    automated: true
    self_heal: true
    prune: true
```

## Container Architecture

### 1. Multi-Stage Docker Builds

#### Dockerfile Standards
```dockerfile
# Build stage
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kubechat ./cmd/api-gateway

# Runtime stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /root/
COPY --from=builder /app/kubechat .
USER 1000:1000
EXPOSE 8080
CMD ["./kubechat"]
```

#### Security Standards
```yaml
container_security:
  base_image: "Distroless or Alpine"
  user: "Non-root (UID 1000)"
  read_only_filesystem: true
  no_new_privileges: true
  
vulnerability_scanning:
  tool: "Trivy"
  frequency: "Every build"
  severity_threshold: "HIGH"
```

### 2. Image Management

#### Registry Configuration
```yaml
container_registry:
  primary: "ghcr.io/company/kubechat"
  backup: "harbor.company.com/kubechat"
  
image_lifecycle:
  tagging_strategy: "Semantic versioning + Git SHA"
  retention_policy: "Keep 10 latest versions"
  security_scanning: "Automatic on push"
  
examples:
  - "ghcr.io/company/kubechat:v1.2.3"
  - "ghcr.io/company/kubechat:v1.2.3-abc123"
  - "ghcr.io/company/kubechat:latest"
```

## Kubernetes Deployment Patterns

### 1. Core Application Deployment

#### Deployment Manifest Structure
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubechat-api-gateway
  namespace: kubechat-system
  labels:
    app.kubernetes.io/name: kubechat
    app.kubernetes.io/component: api-gateway
    app.kubernetes.io/version: "1.2.3"
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 25%
      maxSurge: 25%
  selector:
    matchLabels:
      app.kubernetes.io/name: kubechat
      app.kubernetes.io/component: api-gateway
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: api-gateway
        image: ghcr.io/company/kubechat:v1.2.3
        ports:
        - containerPort: 8080
          protocol: TCP
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
        readinessProbe:
          httpGet:
            path: /health/ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
        livenessProbe:
          httpGet:
            path: /health/live
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
```

### 2. Service Mesh Integration

#### Istio Configuration
```yaml
service_mesh:
  provider: "Istio"
  version: "1.20+"
  
features:
  mtls: "STRICT mode"
  traffic_management: "Canary deployments"
  security_policies: "AuthorizationPolicy per service"
  observability: "Distributed tracing enabled"

example_virtual_service:
  apiVersion: networking.istio.io/v1beta1
  kind: VirtualService
  metadata:
    name: kubechat-api-gateway
  spec:
    hosts:
    - kubechat-api-gateway
    http:
    - match:
      - headers:
          canary:
            exact: "true"
      route:
      - destination:
          host: kubechat-api-gateway
          subset: canary
        weight: 100
    - route:
      - destination:
          host: kubechat-api-gateway
          subset: stable
        weight: 100
```

## High Availability Architecture

### 1. Multi-Zone Deployment

#### Regional Distribution
```yaml
availability_zones:
  primary_region: "us-east-1"
  zones:
    - "us-east-1a"
    - "us-east-1b" 
    - "us-east-1c"
    
node_distribution:
  control_plane: "3 nodes across 3 AZs"
  worker_nodes: "6+ nodes across 3 AZs"
  
anti_affinity:
  required: true
  topology_key: "topology.kubernetes.io/zone"
```

#### Pod Disruption Budgets
```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: kubechat-api-gateway-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: kubechat
      app.kubernetes.io/component: api-gateway
```

### 2. Database High Availability

#### PostgreSQL Cluster Configuration
```yaml
database_ha:
  solution: "PostgreSQL with Patroni"
  topology: "Primary + 2 Synchronous Replicas"
  failover: "Automatic with health checks"
  
backup_strategy:
  tool: "pg_basebackup + WAL-E"
  frequency: "Continuous WAL streaming"
  retention: "30 days point-in-time recovery"
  
connection_pooling:
  tool: "PgBouncer"
  max_connections: 100
  pool_mode: "transaction"
```

## Auto-Scaling Configuration

### 1. Horizontal Pod Autoscaler (HPA)

#### HPA Configuration
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: kubechat-api-gateway-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: kubechat-api-gateway
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  - type: Pods
    pods:
      metric:
        name: http_requests_per_second
      target:
        type: AverageValue
        averageValue: "1000"
```

### 2. Vertical Pod Autoscaler (VPA)

#### VPA Configuration
```yaml
apiVersion: autoscaling.k8s.io/v1
kind: VerticalPodAutoscaler
metadata:
  name: kubechat-api-gateway-vpa
spec:
  targetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: kubechat-api-gateway
  updatePolicy:
    updateMode: "Auto"
  resourcePolicy:
    containerPolicies:
    - containerName: api-gateway
      maxAllowed:
        cpu: "2"
        memory: "4Gi"
      minAllowed:
        cpu: "100m"
        memory: "128Mi"
```

### 3. Cluster Autoscaler

#### Node Group Configuration
```yaml
cluster_autoscaler:
  min_nodes: 3
  max_nodes: 50
  scale_down_delay: "10m"
  scale_down_unneeded_time: "10m"
  
node_groups:
  - name: "general-purpose"
    instance_types: ["m5.large", "m5.xlarge"]
    min_size: 3
    max_size: 20
    
  - name: "compute-optimized"
    instance_types: ["c5.large", "c5.xlarge"]
    min_size: 0
    max_size: 10
    taints:
      - key: "workload-type"
        value: "compute-intensive"
        effect: "NoSchedule"
```

## Security Architecture

### 1. Network Security

#### Network Policies
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubechat-api-gateway-netpol
  namespace: kubechat-system
spec:
  podSelector:
    matchLabels:
      app.kubernetes.io/name: kubechat
      app.kubernetes.io/component: api-gateway
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: istio-system
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kubechat-system
    ports:
    - protocol: TCP
      port: 5432  # PostgreSQL
  - to: []  # DNS
    ports:
    - protocol: UDP
      port: 53
```

### 2. RBAC Configuration

#### Service Account and Roles
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubechat-api-gateway
  namespace: kubechat-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubechat-api-gateway
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["kubechat.ai"]
  resources: ["chatsessions"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubechat-api-gateway
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubechat-api-gateway
subjects:
- kind: ServiceAccount
  name: kubechat-api-gateway
  namespace: kubechat-system
```

## Monitoring and Observability

### 1. Metrics Collection

#### Prometheus Configuration
```yaml
prometheus_stack:
  operator: "kube-prometheus-stack"
  version: "45.0+"
  
service_monitors:
  - name: "kubechat-api-gateway"
    endpoints: ["/metrics"]
    interval: "30s"
    
alerting_rules:
  - name: "KubeChatHighErrorRate"
    expr: "rate(http_requests_total{job='kubechat-api-gateway',code=~'5..'}[5m]) > 0.05"
    for: "2m"
    severity: "warning"
```

### 2. Logging Architecture

#### Centralized Logging
```yaml
logging_stack:
  collector: "Fluent Bit"
  aggregator: "Fluentd"
  storage: "Elasticsearch"
  visualization: "Kibana"
  
log_retention:
  application_logs: "30 days"
  audit_logs: "7 years"
  system_logs: "90 days"
```

### 3. Distributed Tracing

#### Jaeger Configuration
```yaml
tracing:
  collector: "Jaeger"
  sampling_rate: "10%"
  storage: "Elasticsearch"
  
trace_retention: "7 days"
```

## Backup and Disaster Recovery

### 1. Backup Strategy

#### Application Data Backup
```yaml
backup_tools:
  kubernetes: "Velero"
  database: "pg_dump + WAL archiving"
  
backup_schedule:
  full_backup: "Daily at 2 AM UTC"
  incremental: "Every 6 hours"
  
retention_policy:
  daily: "30 days"
  weekly: "12 weeks"
  monthly: "12 months"
  yearly: "7 years"
```

### 2. Disaster Recovery Procedures

#### RTO and RPO Targets
```yaml
sla_targets:
  rto: "4 hours"  # Recovery Time Objective
  rpo: "15 minutes"  # Recovery Point Objective
  
dr_procedures:
  database_failover: "Automated with Patroni"
  cross_region_restore: "Manual process documented"
  cluster_recreation: "Infrastructure as Code"
```

## Infrastructure as Code

### 1. Terraform Configuration

#### Infrastructure Provisioning
```yaml
terraform_structure:
  modules:
    - "kubernetes_cluster"
    - "networking"
    - "security_groups" 
    - "load_balancers"
    - "rds_instances"
    
environments:
  - "terraform/environments/dev"
  - "terraform/environments/staging"
  - "terraform/environments/prod"
```

### 2. Helm Charts

#### Chart Structure
```yaml
helm_chart_structure:
  chart_name: "kubechat"
  version: "Semantic versioning"
  
templates:
  - "deployment.yaml"
  - "service.yaml"
  - "ingress.yaml"
  - "configmap.yaml"
  - "secret.yaml"
  - "hpa.yaml"
  - "pdb.yaml"
  - "networkpolicy.yaml"
  
values_files:
  - "values.yaml"  # defaults
  - "values-dev.yaml"
  - "values-staging.yaml"
  - "values-prod.yaml"
```

## Deployment Pipeline

### 1. CI/CD Workflow

#### GitHub Actions Pipeline
```yaml
pipeline_stages:
  - name: "Build and Test"
    steps:
      - "Checkout code"
      - "Run unit tests"
      - "Run integration tests"
      - "Build container image"
      - "Scan for vulnerabilities"
      
  - name: "Deploy to Staging"
    steps:
      - "Deploy to staging cluster"
      - "Run smoke tests"
      - "Run security tests"
      
  - name: "Production Deployment"
    trigger: "Manual approval"
    steps:
      - "Blue/Green deployment"
      - "Health checks"
      - "Rollback capability"
```

### 2. Deployment Strategies

#### Blue/Green Deployment
```yaml
blue_green_deployment:
  traffic_split: "Instant cutover"
  rollback_time: "< 60 seconds"
  validation: "Automated health checks"
  
canary_deployment:
  traffic_percentage: "5% -> 25% -> 50% -> 100%"
  progression_time: "30 minutes between stages"
  success_criteria: "Error rate < 0.1%"
```

This deployment architecture ensures KubeChat can be deployed reliably and securely across all environments with proper observability, scalability, and disaster recovery capabilities.