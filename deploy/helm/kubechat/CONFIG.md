# KubeChat Helm Chart Configuration Guide

## Overview

This document provides comprehensive configuration documentation for the KubeChat Helm chart deployment across different environments. The chart supports multiple deployment scenarios with specialized configuration templates.

## Configuration Files Structure

```
deploy/helm/kubechat/
├── Chart.yaml                  # Helm chart metadata
├── values.yaml                 # Default configuration values
├── values-dev-rancher.yaml     # Rancher Desktop development
├── values-airgap-test.yaml     # Air-gap deployment testing
├── values-minimal.yaml         # Minimal resource configuration
├── values-production.yaml      # Production deployment template
└── templates/                  # Kubernetes resource templates
```

## Environment-Specific Configurations

### 1. Development Environment (`values-dev-rancher.yaml`)

**Purpose**: Local development on Rancher Desktop with minimal resources and developer-friendly settings.

**Key Characteristics**:
- **Namespace**: `kubechat-dev`
- **Registry**: `localhost:5001` (local registry)
- **Resources**: Minimal CPU/memory allocation
- **Features**: Debug mode, hot reload, CORS enabled
- **Database**: Single PostgreSQL instance with small storage
- **Ingress**: Traefik with `kubechat.local`

**Usage**:
```bash
helm install kubechat ./deploy/helm/kubechat -f values-dev-rancher.yaml -n kubechat-dev --create-namespace
```

### 2. Air-Gap Testing Environment (`values-airgap-test.yaml`)

**Purpose**: Complete offline deployment testing with no external connectivity.

**Key Characteristics**:
- **Namespace**: `kubechat-airgap`
- **Registry**: `localhost:5000` with `imagePullPolicy: Never`
- **Network**: Complete isolation, external access blocked
- **Security**: Enhanced security policies, tamper-proof audit
- **Validation**: Air-gap compliance checks enabled
- **Testing**: Comprehensive air-gap test suite

**Usage**:
```bash
helm install kubechat ./deploy/helm/kubechat -f values-airgap-test.yaml -n kubechat-airgap --create-namespace
```

### 3. Minimal Resource Environment (`values-minimal.yaml`)

**Purpose**: Ultra-minimal resource allocation for constrained development environments.

**Key Characteristics**:
- **Namespace**: `kubechat-dev`
- **Resources**: Ultra-low CPU/memory limits (25-50m CPU, 32-64Mi memory)
- **Features**: Most features disabled, basic functionality only
- **Database**: SQLite in-memory (no PostgreSQL/Redis)
- **Monitoring**: Disabled to save resources
- **Service**: NodePort instead of Ingress

**Usage**:
```bash
helm install kubechat ./deploy/helm/kubechat -f values-minimal.yaml -n kubechat-dev --create-namespace
```

### 4. Production Environment (`values-production.yaml`)

**Purpose**: Enterprise-ready production deployment with high availability and security.

**Key Characteristics**:
- **Namespace**: `kubechat` (standard production namespace)
- **Registry**: Customer registry with image pull secrets
- **High Availability**: 3 replicas, multi-zone deployment
- **Resources**: Production-scale CPU/memory allocation
- **Security**: TLS everywhere, strict security policies
- **Monitoring**: Full observability stack (Prometheus, Grafana, Jaeger)
- **Backup**: Automated backup and disaster recovery

**Usage**:
```bash
helm install kubechat ./deploy/helm/kubechat -f values-production.yaml -n kubechat --create-namespace
```

## Configuration Parameters

### Global Configuration

| Parameter | Description | Default | Required |
|-----------|-------------|---------|----------|
| `global.imageRegistry` | Container registry URL | `localhost:5001` | Yes |
| `global.imageTag` | Image tag for all services | `dev` | Yes |
| `global.namespace` | Target Kubernetes namespace | `kubechat-dev` | Yes |
| `global.environment` | Deployment environment | `development` | Yes |
| `global.debug` | Enable debug mode | `true` | No |
| `global.logLevel` | Global log level | `info` | No |

### Service Configuration

#### API Gateway

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `apiGateway.enabled` | Enable API Gateway | `true` | `true`, `false` |
| `apiGateway.replicaCount` | Number of replicas | `1` | `1-10` |
| `apiGateway.image.repository` | Image repository | `localhost:5000/kubechat/api-gateway` | Any valid repository |
| `apiGateway.service.type` | Service type | `ClusterIP` | `ClusterIP`, `NodePort`, `LoadBalancer` |
| `apiGateway.config.corsEnabled` | Enable CORS | `true` | `true`, `false` |

#### Kubernetes Operator

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `operator.enabled` | Enable Kubernetes Operator | `true` | `true`, `false` |
| `operator.rbac.create` | Create RBAC resources | `true` | `true`, `false` |
| `operator.rbac.clusterWide` | Cluster-wide permissions | `false` | `true`, `false` |
| `operator.webhook.enabled` | Enable admission webhooks | `false` | `true`, `false` |
| `operator.metrics.enabled` | Enable metrics endpoint | `true` | `true`, `false` |

#### Audit Service

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `auditService.enabled` | Enable Audit Service | `true` | `true`, `false` |
| `auditService.database.type` | Database type | `postgresql` | `postgresql`, `sqlite` |
| `auditService.config.retentionDays` | Audit log retention | `30` | `1-2555` |
| `auditService.config.tamperProof` | Enable tamper-proof audit | `true` | `true`, `false` |

#### Web Frontend

| Parameter | Description | Default | Options |
|-----------|-------------|---------|---------|
| `web.enabled` | Enable Web Frontend | `true` | `true`, `false` |
| `web.ingress.enabled` | Enable Ingress | `true` | `true`, `false` |
| `web.ingress.className` | Ingress class | `traefik` | `traefik`, `nginx` |

### Resource Configuration

#### Resource Limits and Requests

```yaml
resources:
  apiGateway:
    limits:
      cpu: "1000m"
      memory: "1Gi"
    requests:
      cpu: "500m"
      memory: "512Mi"
```

#### Horizontal Pod Autoscaler

```yaml
hpa:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

### Security Configuration

#### TLS Configuration

```yaml
security:
  tls:
    enabled: true
    certificateProvider: "cert-manager"
    issuer: "letsencrypt-prod"
```

#### Network Policies

```yaml
security:
  networkPolicy:
    enabled: true
    allowedNamespaces: ["kubechat", "monitoring"]
```

## Environment Variables

Each service supports extensive environment variable configuration through `.env.example` files:

- **Root**: `/kube-chat/.env.example` - Global deployment settings
- **API Gateway**: `/kube-chat/cmd/api-gateway/.env.example` - API Gateway specific
- **Audit Service**: `/kube-chat/cmd/audit-service/.env.example` - Audit Service specific  
- **Web Frontend**: `/kube-chat/web/.env.example` - Frontend specific

### Key Environment Categories

1. **Database Configuration**
2. **Redis Configuration**
3. **Security Settings**
4. **Monitoring and Metrics**
5. **Feature Flags**
6. **Performance Tuning**
7. **Compliance Settings**

## Deployment Examples

### Development Deployment

```bash
# Create namespace
kubectl create namespace kubechat-dev

# Deploy with development values
helm install kubechat ./deploy/helm/kubechat \
  -f values-dev-rancher.yaml \
  -n kubechat-dev \
  --set global.imageTag=latest

# Access application
echo "Add to /etc/hosts: 127.0.0.1 kubechat.local"
open http://kubechat.local
```

### Air-Gap Deployment

```bash
# Ensure all images are loaded locally
docker pull localhost:5000/kubechat/api-gateway:airgap
docker pull localhost:5000/kubechat/operator:airgap
docker pull localhost:5000/kubechat/audit-service:airgap
docker pull localhost:5000/kubechat/web:airgap

# Deploy with air-gap validation
helm install kubechat ./deploy/helm/kubechat \
  -f values-airgap-test.yaml \
  -n kubechat-airgap --create-namespace \
  --set deployment.validateAirgap=true
```

### Production Deployment

```bash
# Create production namespace
kubectl create namespace kubechat

# Create image pull secret
kubectl create secret docker-registry kubechat-registry-secret \
  --docker-server=customer-registry.company.com \
  --docker-username=kubechat \
  --docker-password=<password> \
  --docker-email=admin@company.com \
  -n kubechat

# Deploy with production values
helm install kubechat ./deploy/helm/kubechat \
  -f values-production.yaml \
  -n kubechat \
  --set global.imageTag=v1.0.0
```

## Configuration Validation

### Pre-deployment Validation

```bash
# Validate Helm chart
helm lint ./deploy/helm/kubechat

# Validate with specific values
helm lint ./deploy/helm/kubechat -f values-production.yaml

# Dry run deployment
helm install kubechat ./deploy/helm/kubechat \
  -f values-production.yaml \
  -n kubechat \
  --dry-run --debug
```

### Air-Gap Validation

The air-gap configuration includes built-in validation:

```yaml
validation:
  enabled: true
  checks:
    - name: "image-availability"
      description: "Verify all images are available locally"
    - name: "network-isolation"
      description: "Verify no external network access"
    - name: "dependency-satisfaction"
      description: "Verify all dependencies are met locally"
```

## Customization Guidelines

### Creating Custom Values Files

1. **Start with base template**: Copy appropriate base values file
2. **Modify specific sections**: Update only required parameters
3. **Validate configuration**: Use `helm lint` and `--dry-run`
4. **Test deployment**: Deploy to test environment first

### Common Customizations

#### Custom Registry

```yaml
global:
  imageRegistry: "your-registry.company.com"
  imagePullSecrets:
    - name: "your-registry-secret"
```

#### Resource Scaling

```yaml
resources:
  production: true
  apiGateway:
    limits:
      cpu: "2000m"
      memory: "4Gi"
```

#### External Database

```yaml
postgresql:
  enabled: false

auditService:
  database:
    host: "external-postgres.company.com"
    port: 5432
    existingSecret: "postgres-credentials"
```

## Troubleshooting

### Common Issues

1. **Image Pull Errors**: Verify registry access and secrets
2. **Resource Constraints**: Check node resources and limits
3. **Network Issues**: Validate ingress and service configurations
4. **Storage Issues**: Ensure storage classes are available

### Debug Commands

```bash
# Check pod status
kubectl get pods -n kubechat-dev

# View pod logs
kubectl logs -f deployment/kubechat-api-gateway -n kubechat-dev

# Describe failing resources
kubectl describe pod <pod-name> -n kubechat-dev

# Check Helm release status
helm status kubechat -n kubechat-dev
```

## Security Considerations

### Production Security Checklist

- [ ] TLS enabled for all services
- [ ] Network policies configured
- [ ] RBAC permissions minimal
- [ ] Secrets externally managed
- [ ] Image scanning enabled
- [ ] Admission controllers configured
- [ ] Audit logging enabled
- [ ] Backup encryption enabled

### Air-Gap Security Features

- Complete network isolation
- Local-only image sources
- Tamper-proof audit trails
- Offline certificate management
- Self-contained monitoring

## Monitoring and Observability

### Metrics Collection

All configurations support Prometheus metrics collection:

```yaml
monitoring:
  prometheus:
    enabled: true
    scrapeInterval: "15s"
    retention: "30d"
```

### Logging Configuration

Structured logging is enabled across all environments:

```yaml
logging:
  level: "info"
  format: "json"
  output: "stdout"
```

## Backup and Disaster Recovery

### Production Backup Configuration

```yaml
backup:
  enabled: true
  type: "s3"
  schedule: "0 2 * * *"
  retention: "90d"
  
  disasterRecovery:
    enabled: true
    rpo: "1h"
    rto: "4h"
```

## Compliance and Regulatory

### Supported Compliance Standards

- **SOC2**: Enhanced audit logging and access controls
- **GDPR**: Data privacy and retention policies
- **HIPAA**: Healthcare data protection (when enabled)
- **FedRAMP**: Federal security requirements

### Compliance Configuration

```yaml
compliance:
  regulations:
    - "SOC2"
    - "GDPR"
  auditLogging:
    enabled: true
    level: "comprehensive"
    retention: "7y"
```

This configuration guide provides the foundation for deploying KubeChat across all supported environments with appropriate customization for each use case.