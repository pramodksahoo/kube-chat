# KubeChat Production Deployment Guide

This guide provides comprehensive instructions for deploying KubeChat with enterprise OIDC/SAML authentication to production environments.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Variables](#environment-variables)
3. [Redis Configuration](#redis-configuration)
4. [OIDC Provider Configuration](#oidc-provider-configuration)
5. [SAML Provider Configuration](#saml-provider-configuration)
6. [Deployment Steps](#deployment-steps)
7. [Security Considerations](#security-considerations)
8. [Monitoring and Health Checks](#monitoring-and-health-checks)
9. [Troubleshooting](#troubleshooting)

## Prerequisites

### System Requirements

- **Kubernetes**: 1.28+ cluster
- **Go**: 1.22+ for building from source
- **Redis**: 7.2+ (standalone or cluster)
- **PostgreSQL**: 16+ for audit logs and user management
- **TLS Certificates**: Valid SSL certificates for production domains

### External Dependencies

- **OIDC Provider**: One or more enterprise identity providers
- **SAML IdP**: Optional SAML identity providers (ADFS, Okta, etc.)
- **Container Registry**: For storing KubeChat images
- **Load Balancer**: For high availability and TLS termination

## Environment Variables

### Core Application Configuration

```bash
# Application Settings
KUBECHAT_LISTEN_PORT=8080                    # HTTP server port
KUBECHAT_PUBLIC_URL=https://kubechat.yourdomain.com  # Public facing URL
KUBECHAT_LOG_LEVEL=info                      # Log level: debug, info, warn, error
KUBECHAT_LOG_FORMAT=json                     # Log format: json, text

# Security Settings
KUBECHAT_JWT_ISSUER=kubechat-prod           # JWT token issuer
KUBECHAT_JWT_TOKEN_DURATION=8h              # Access token duration
KUBECHAT_JWT_REFRESH_DURATION=168h          # Refresh token duration (7 days)
KUBECHAT_SESSION_SECRET=your-secure-session-secret  # Session encryption key (32+ chars)

# Rate Limiting
KUBECHAT_RATE_LIMIT_REQUESTS=100            # Requests per minute per IP
KUBECHAT_RATE_LIMIT_WINDOW=1m               # Rate limit time window
KUBECHAT_BRUTE_FORCE_THRESHOLD=5            # Failed login attempts before lockout
KUBECHAT_BRUTE_FORCE_LOCKOUT=15m            # Account lockout duration

# Circuit Breaker Configuration
KUBECHAT_CIRCUIT_BREAKER_TIMEOUT=30s        # Circuit breaker timeout
KUBECHAT_CIRCUIT_BREAKER_MAX_FAILURES=5     # Max failures before opening circuit
KUBECHAT_CIRCUIT_BREAKER_RECOVERY_TIMEOUT=60s  # Recovery timeout
```

### Redis Configuration

```bash
# Redis Single Instance
KUBECHAT_REDIS_ADDR=redis.production.svc.cluster.local:6379
KUBECHAT_REDIS_PASSWORD=your-redis-password
KUBECHAT_REDIS_DB=0

# Redis Cluster (alternative to single instance)
KUBECHAT_REDIS_CLUSTER=redis-1.prod:6379,redis-2.prod:6379,redis-3.prod:6379

# Redis Connection Pooling
KUBECHAT_REDIS_POOL_SIZE=20                 # Connection pool size
KUBECHAT_REDIS_MIN_IDLE_CONNS=5             # Minimum idle connections
KUBECHAT_REDIS_MAX_RETRIES=3                # Maximum retry attempts
KUBECHAT_REDIS_DIAL_TIMEOUT=10s             # Connection timeout
KUBECHAT_REDIS_READ_TIMEOUT=5s              # Read timeout
KUBECHAT_REDIS_WRITE_TIMEOUT=5s             # Write timeout

# Redis TLS (if using TLS)
KUBECHAT_REDIS_TLS_ENABLED=true
KUBECHAT_REDIS_TLS_CERT_FILE=/etc/certs/redis-client.crt
KUBECHAT_REDIS_TLS_KEY_FILE=/etc/certs/redis-client.key
KUBECHAT_REDIS_TLS_CA_FILE=/etc/certs/redis-ca.crt
```

### Database Configuration (PostgreSQL)

```bash
# PostgreSQL Connection
KUBECHAT_DB_HOST=postgres.production.svc.cluster.local
KUBECHAT_DB_PORT=5432
KUBECHAT_DB_NAME=kubechat_prod
KUBECHAT_DB_USER=kubechat_user
KUBECHAT_DB_PASSWORD=your-secure-db-password
KUBECHAT_DB_SSLMODE=require

# Connection Pool
KUBECHAT_DB_MAX_OPEN_CONNS=25
KUBECHAT_DB_MAX_IDLE_CONNS=5
KUBECHAT_DB_CONN_MAX_LIFETIME=1h
```

## Redis Configuration

### Standalone Redis Setup

For production environments, use Redis with persistence and authentication:

```yaml
# redis-config.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: redis-config
data:
  redis.conf: |
    # Security
    requirepass your-redis-password
    
    # Persistence
    save 900 1
    save 300 10
    save 60 10000
    
    # Memory management
    maxmemory 2gb
    maxmemory-policy allkeys-lru
    
    # Network
    timeout 0
    tcp-keepalive 300
    
    # Logging
    loglevel notice
    logfile ""
```

### Redis Cluster Setup (Recommended for HA)

For high availability, deploy Redis in cluster mode:

```yaml
# redis-cluster.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: redis-cluster
spec:
  serviceName: redis-cluster
  replicas: 6
  template:
    spec:
      containers:
      - name: redis
        image: redis:7.2-alpine
        ports:
        - containerPort: 6379
        - containerPort: 16379
        env:
        - name: REDIS_CLUSTER_ANNOUNCE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.podIP
        command:
          - redis-server
          - --cluster-enabled
          - --cluster-config-file
          - --cluster-node-timeout
          - --appendonly
```

## OIDC Provider Configuration

### Generic OIDC Provider

```bash
# Provider Configuration
KUBECHAT_OIDC_PROVIDER_NAME=corporate-sso
KUBECHAT_OIDC_PROVIDER_DISPLAY_NAME="Corporate SSO"
KUBECHAT_OIDC_ISSUER_URL=https://auth.company.com
KUBECHAT_OIDC_CLIENT_ID=kubechat-production
KUBECHAT_OIDC_CLIENT_SECRET=your-oidc-client-secret
KUBECHAT_OIDC_REDIRECT_URL=https://kubechat.yourdomain.com/auth/callback/corporate-sso
KUBECHAT_OIDC_SCOPES=openid,email,profile,groups

# Optional: Additional Claims Mapping
KUBECHAT_OIDC_EMAIL_CLAIM=email
KUBECHAT_OIDC_NAME_CLAIM=name
KUBECHAT_OIDC_GROUPS_CLAIM=groups
KUBECHAT_OIDC_PREFERRED_USERNAME_CLAIM=preferred_username
```

### Azure AD Configuration

```bash
# Azure AD Specific
KUBECHAT_AZURE_TENANT_ID=your-tenant-id
KUBECHAT_AZURE_CLIENT_ID=your-application-id
KUBECHAT_AZURE_CLIENT_SECRET=your-client-secret
KUBECHAT_AZURE_REDIRECT_URL=https://kubechat.yourdomain.com/auth/callback/azure
```

### Google Workspace Configuration

```bash
# Google Workspace
KUBECHAT_GOOGLE_CLIENT_ID=your-google-client-id
KUBECHAT_GOOGLE_CLIENT_SECRET=your-google-client-secret
KUBECHAT_GOOGLE_REDIRECT_URL=https://kubechat.yourdomain.com/auth/callback/google
KUBECHAT_GOOGLE_HOSTED_DOMAIN=yourdomain.com  # Optional: restrict to domain
```

## SAML Provider Configuration

### ADFS Configuration

```bash
# ADFS SAML Configuration
KUBECHAT_SAML_PROVIDER_NAME=adfs
KUBECHAT_SAML_PROVIDER_DISPLAY_NAME="Active Directory"
KUBECHAT_SAML_METADATA_URL=https://adfs.company.com/FederationMetadata/2007-06/FederationMetadata.xml
KUBECHAT_SAML_ENTITY_ID=https://kubechat.yourdomain.com/saml/metadata
KUBECHAT_SAML_ASSERTION_CONSUMER_URL=https://kubechat.yourdomain.com/saml/acs

# Certificate Configuration (for signing)
KUBECHAT_SAML_CERT_FILE=/etc/certs/saml.crt
KUBECHAT_SAML_KEY_FILE=/etc/certs/saml.key

# Attribute Mapping
KUBECHAT_SAML_EMAIL_ATTRIBUTE=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
KUBECHAT_SAML_NAME_ATTRIBUTE=http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name
KUBECHAT_SAML_GROUPS_ATTRIBUTE=http://schemas.microsoft.com/ws/2008/06/identity/claims/groups
```

### Okta SAML Configuration

```bash
# Okta SAML
KUBECHAT_OKTA_SAML_METADATA_URL=https://yourorg.okta.com/app/your-app-id/sso/saml/metadata
KUBECHAT_OKTA_SAML_ENTITY_ID=https://kubechat.yourdomain.com/saml/metadata
KUBECHAT_OKTA_SAML_ACS_URL=https://kubechat.yourdomain.com/saml/acs/okta
```

## Deployment Steps

### 1. Prepare Secrets

Create Kubernetes secrets for sensitive configuration:

```bash
# Create namespace
kubectl create namespace kubechat-prod

# Create Redis password secret
kubectl create secret generic redis-credentials \
  --from-literal=password=your-redis-password \
  -n kubechat-prod

# Create database credentials
kubectl create secret generic db-credentials \
  --from-literal=username=kubechat_user \
  --from-literal=password=your-secure-db-password \
  -n kubechat-prod

# Create OIDC client secrets
kubectl create secret generic oidc-secrets \
  --from-literal=corporate-sso-secret=your-oidc-client-secret \
  --from-literal=azure-client-secret=your-azure-client-secret \
  -n kubechat-prod

# Create SAML certificates
kubectl create secret tls saml-certs \
  --cert=saml.crt \
  --key=saml.key \
  -n kubechat-prod
```

### 2. Deploy Configuration

```yaml
# kubechat-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubechat-config
  namespace: kubechat-prod
data:
  KUBECHAT_PUBLIC_URL: "https://kubechat.yourdomain.com"
  KUBECHAT_LOG_LEVEL: "info"
  KUBECHAT_JWT_ISSUER: "kubechat-prod"
  KUBECHAT_JWT_TOKEN_DURATION: "8h"
  KUBECHAT_JWT_REFRESH_DURATION: "168h"
  KUBECHAT_REDIS_ADDR: "redis.kubechat-prod.svc.cluster.local:6379"
  KUBECHAT_OIDC_PROVIDER_NAME: "corporate-sso"
  KUBECHAT_OIDC_ISSUER_URL: "https://auth.company.com"
  KUBECHAT_OIDC_CLIENT_ID: "kubechat-production"
  KUBECHAT_OIDC_REDIRECT_URL: "https://kubechat.yourdomain.com/auth/callback/corporate-sso"
```

### 3. Deploy Application

```yaml
# kubechat-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubechat
  namespace: kubechat-prod
spec:
  replicas: 3
  selector:
    matchLabels:
      app: kubechat
  template:
    metadata:
      labels:
        app: kubechat
    spec:
      containers:
      - name: kubechat
        image: your-registry.com/kubechat:v2.1.1
        ports:
        - containerPort: 8080
        env:
        # Load configuration from ConfigMap
        - name: KUBECHAT_PUBLIC_URL
          valueFrom:
            configMapKeyRef:
              name: kubechat-config
              key: KUBECHAT_PUBLIC_URL
        # Load secrets
        - name: KUBECHAT_REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: redis-credentials
              key: password
        - name: KUBECHAT_OIDC_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: oidc-secrets
              key: corporate-sso-secret
        # Resource limits
        resources:
          limits:
            cpu: 1000m
            memory: 1Gi
          requests:
            cpu: 500m
            memory: 512Mi
        # Health checks
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        # Mount certificates
        volumeMounts:
        - name: saml-certs
          mountPath: /etc/certs
          readOnly: true
      volumes:
      - name: saml-certs
        secret:
          secretName: saml-certs
```

### 4. Configure Service and Ingress

```yaml
# kubechat-service.yaml
apiVersion: v1
kind: Service
metadata:
  name: kubechat
  namespace: kubechat-prod
spec:
  selector:
    app: kubechat
  ports:
  - port: 80
    targetPort: 8080
  type: ClusterIP
---
# kubechat-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: kubechat
  namespace: kubechat-prod
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - kubechat.yourdomain.com
    secretName: kubechat-tls
  rules:
  - host: kubechat.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: kubechat
            port:
              number: 80
```

## Security Considerations

### TLS Configuration

1. **Always use HTTPS** in production
2. **Configure proper TLS certificates** using cert-manager or external CA
3. **Use strong cipher suites** and disable weak protocols
4. **Implement HSTS headers** for browser security

### Secrets Management

1. **Never commit secrets** to version control
2. **Use Kubernetes secrets** or external secret management (Vault, AWS Secrets Manager)
3. **Rotate secrets regularly** (quarterly recommended)
4. **Use least privilege access** for service accounts

### Network Security

```yaml
# Network policy example
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: kubechat-network-policy
  namespace: kubechat-prod
spec:
  podSelector:
    matchLabels:
      app: kubechat
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - protocol: TCP
      port: 8080
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: redis
    ports:
    - protocol: TCP
      port: 6379
```

## Monitoring and Health Checks

### Health Check Endpoints

- **`/health`**: Overall application health
- **`/ready`**: Readiness for traffic
- **`/metrics`**: Prometheus metrics (if enabled)

### Prometheus Metrics

```yaml
# ServiceMonitor for Prometheus
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: kubechat-metrics
  namespace: kubechat-prod
spec:
  selector:
    matchLabels:
      app: kubechat
  endpoints:
  - port: metrics
    interval: 30s
    path: /metrics
```

### Key Metrics to Monitor

- **Authentication success/failure rates**
- **JWT token generation/validation performance**
- **Redis connection health**
- **OIDC provider response times**
- **Active user sessions**
- **API request latency**

## Troubleshooting

### Common Issues

#### Redis Connection Issues

```bash
# Check Redis connectivity
kubectl exec -it kubechat-pod -- redis-cli -h redis-host -p 6379 ping

# Check Redis authentication
kubectl exec -it kubechat-pod -- redis-cli -h redis-host -p 6379 -a password ping
```

#### OIDC Provider Issues

```bash
# Test OIDC discovery endpoint
curl -v https://your-oidc-provider/.well-known/openid-configuration

# Check OIDC client configuration
kubectl logs kubechat-pod | grep -i oidc
```

#### Certificate Issues

```bash
# Verify certificate validity
openssl x509 -in /etc/certs/saml.crt -text -noout

# Check certificate expiration
openssl x509 -in /etc/certs/saml.crt -noout -dates
```

### Log Analysis

Enable debug logging for troubleshooting:

```bash
# Set debug log level
kubectl set env deployment/kubechat KUBECHAT_LOG_LEVEL=debug -n kubechat-prod

# View detailed logs
kubectl logs -f deployment/kubechat -n kubechat-prod | jq '.'
```

### Performance Tuning

#### Redis Optimization

- **Use Redis cluster** for high availability
- **Configure appropriate maxmemory** policies
- **Monitor Redis memory usage** and performance

#### Application Scaling

- **Horizontal Pod Autoscaler**:
  ```yaml
  apiVersion: autoscaling/v2
  kind: HorizontalPodAutoscaler
  metadata:
    name: kubechat-hpa
  spec:
    scaleTargetRef:
      apiVersion: apps/v1
      kind: Deployment
      name: kubechat
    minReplicas: 3
    maxReplicas: 10
    metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
  ```

## Backup and Recovery

### Database Backups

```bash
# PostgreSQL backup
kubectl exec postgres-pod -- pg_dump -U kubechat_user kubechat_prod > kubechat_backup.sql
```

### Redis Backups

```bash
# Redis backup
kubectl exec redis-pod -- redis-cli BGSAVE
kubectl cp redis-pod:/data/dump.rdb ./redis_backup.rdb
```

This concludes the comprehensive production deployment guide. Always test deployments in staging environments before production deployment.