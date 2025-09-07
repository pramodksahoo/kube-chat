# KubeChat On-Premises Deployment - Phase 1 Model 1

## Overview

This guide provides comprehensive instructions for deploying **KubeChat Phase 1: Model 1 (On-Premises FREE Platform)** using Helm charts directly into customer Kubernetes clusters, ensuring complete data sovereignty, air-gap capability, and zero vendor lock-in.

## Table of Contents

1. [Pre-Deployment Requirements](#pre-deployment-requirements)
2. [Helm Chart Deployment](#helm-chart-deployment)
3. [Air-Gap Installation](#air-gap-installation)
4. [Configuration Options](#configuration-options)
5. [Authentication Setup](#authentication-setup)
6. [Post-Deployment Validation](#post-deployment-validation)
7. [Troubleshooting](#troubleshooting)

## Pre-Deployment Requirements

### 1. Infrastructure Prerequisites

```yaml
kubernetes_cluster:
  version: "1.28+"
  nodes: "3+ nodes (development), 6+ nodes (production)"
  storage: "Persistent volumes supported"
  networking: "CNI plugin installed (Calico, Flannel, etc.)"
  
customer_control:
  cluster_admin: "Required for CRD installation"
  namespace: "kubechat-system (default) or customer choice"
  data_location: "100% within customer infrastructure"
  
optional_components:
  ingress_controller: "Customer's existing ingress (NGINX, Traefik, etc.)"
  monitoring: "Customer's existing Prometheus/Grafana"
  identity_provider: "Customer's OIDC/SAML provider"
```

### 2. Pre-Installation Checklist

```bash
#!/bin/bash
# pre-install-check.sh

echo "KubeChat Phase 1 Model 1 - Pre-Installation Check"
echo "================================================="

# Check Kubernetes version
KUBE_VERSION=$(kubectl version --client --short | grep -o 'v[0-9]\+\.[0-9]\+')
echo "Kubernetes client version: $KUBE_VERSION"

# Check cluster access
kubectl cluster-info || {
  echo "❌ Cannot access Kubernetes cluster"
  exit 1
}

# Check Helm installation
helm version --short || {
  echo "❌ Helm not installed or not in PATH"
  exit 1
}

# Check storage classes
echo "Available storage classes:"
kubectl get storageclass

# Check cluster admin permissions
kubectl auth can-i create customresourcedefinitions --all-namespaces || {
  echo "❌ Insufficient permissions - cluster admin required for CRD installation"
  exit 1
}

echo "✅ Pre-installation check completed successfully"
```

## Helm Chart Deployment

### 1. Standard Installation

```bash
# Download KubeChat Helm chart (from release or build locally)
# For production, download from GitHub releases
curl -L https://github.com/company/kubechat/releases/download/v1.0.0/kubechat-helm-chart-v1.0.0.tar.gz | tar -xz

# Or use locally built chart for development
# helm package ./deploy/helm/kubechat

cd kubechat-chart/

# Install with default values (minimal configuration)
helm install kubechat . \
  --create-namespace \
  --namespace kubechat-system \
  --wait \
  --timeout 10m

# Verify installation
kubectl get pods -n kubechat-system
kubectl get svc -n kubechat-system
```

### 2. Production Installation with Custom Values

```yaml
# values-production.yaml
global:
  # Customer's private registry (if using one)
  imageRegistry: "registry.company.com"
  
# Production sizing
apiGateway:
  replicaCount: 3
  resources:
    requests:
      memory: "512Mi"
      cpu: "500m"
    limits:
      memory: "1Gi"
      cpu: "1000m"
  
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10

# Persistent storage configuration
postgresql:
  enabled: true
  persistence:
    enabled: true
    size: "100Gi"
    storageClass: "fast-ssd"  # Customer's storage class
    
redis:
  enabled: true
  persistence:
    enabled: true
    size: "20Gi"
    storageClass: "fast-ssd"

# Customer authentication integration
auth:
  oidc:
    enabled: true
    providerName: "company-sso"
    issuerUrl: "https://auth.company.com"
    clientId: "kubechat-prod"
    clientSecret: "customer-secret"
    redirectUrl: "https://kubechat.company.com/auth/callback"

# Network configuration
ingress:
  enabled: true
  className: "nginx"  # Customer's ingress controller
  annotations:
    nginx.ingress.kubernetes.io/ssl-protocols: "TLSv1.2 TLSv1.3"
  hosts:
    - host: kubechat.company.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - hosts:
        - kubechat.company.com
      secretName: kubechat-tls  # Customer-managed certificate

# Security policies
security:
  networkPolicies:
    enabled: true
  podSecurityPolicy:
    enabled: true
```

```bash
# Production installation command
helm install kubechat ./kubechat-chart \
  --create-namespace \
  --namespace kubechat-system \
  --values values-production.yaml \
  --wait \
  --timeout 15m
```

## Air-Gap Installation

### 1. Preparing Air-Gap Bundle

```bash
#!/bin/bash
# prepare-airgap-bundle.sh (run on internet-connected machine)

VERSION="1.0.0"
BUNDLE_NAME="kubechat-airgap-${VERSION}"

echo "Preparing KubeChat air-gap bundle..."

# Create bundle directory
mkdir -p "${BUNDLE_NAME}"/{chart,images,scripts}

# Copy Helm chart
cp -r kubechat-chart/ "${BUNDLE_NAME}/chart/"

# List required images
IMAGES=(
  "kubechat/api-gateway:${VERSION}"
  "kubechat/operator:${VERSION}"
  "kubechat/audit-service:${VERSION}"
  "postgres:16-alpine"
  "redis:7.2-alpine"
)

# Export container images
echo "Exporting container images..."
mkdir -p "${BUNDLE_NAME}/images"
for image in "${IMAGES[@]}"; do
  echo "Exporting: $image"
  docker save "$image" | gzip > "${BUNDLE_NAME}/images/$(echo $image | tr '/:' '-').tar.gz"
done

# Create installation scripts
cat > "${BUNDLE_NAME}/scripts/load-images.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

REGISTRY="${1:-}"
IMAGES_DIR="../images"

if [[ "$REGISTRY" == "" ]]; then
  echo "Loading images to local Docker daemon..."
  for image_file in "$IMAGES_DIR"/*.tar.gz; do
    echo "Loading $(basename "$image_file")..."
    docker load < "$image_file"
  done
else
  echo "Loading and pushing images to registry: $REGISTRY"
  for image_file in "$IMAGES_DIR"/*.tar.gz; do
    echo "Processing $(basename "$image_file")..."
    
    # Load image
    docker load < "$image_file"
    
    # Get original image name
    original_image=$(docker load < "$image_file" | grep "Loaded image:" | cut -d' ' -f3)
    
    # Tag for customer registry
    new_image="$REGISTRY/$(echo $original_image | cut -d'/' -f2-)"
    docker tag "$original_image" "$new_image"
    
    # Push to customer registry
    docker push "$new_image"
  done
fi

echo "Image loading completed successfully!"
EOF

cat > "${BUNDLE_NAME}/scripts/install-airgap.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

REGISTRY="${1:-}"
NAMESPACE="${2:-kubechat-system}"

echo "Installing KubeChat in air-gap mode..."

if [[ "$REGISTRY" != "" ]]; then
  # Install with custom registry
  helm install kubechat ../chart/ \
    --create-namespace \
    --namespace "$NAMESPACE" \
    --set global.imageRegistry="$REGISTRY" \
    --set airgap.enabled=true \
    --wait \
    --timeout 15m
else
  # Install with local images
  helm install kubechat ../chart/ \
    --create-namespace \
    --namespace "$NAMESPACE" \
    --set airgap.enabled=true \
    --wait \
    --timeout 15m
fi

echo "KubeChat air-gap installation completed!"
EOF

chmod +x "${BUNDLE_NAME}/scripts"/*.sh

# Create air-gap values template
cat > "${BUNDLE_NAME}/chart/values-airgap.yaml" << 'EOF'
# KubeChat Air-Gap Deployment Configuration
airgap:
  enabled: true

# Disable external dependencies
auth:
  oidc:
    enabled: false

monitoring:
  prometheus:
    enabled: false

ingress:
  enabled: false  # Customer configures their own
EOF

# Create installation guide
cat > "${BUNDLE_NAME}/INSTALL.md" << 'EOF'
# KubeChat Air-Gap Installation Guide

## Installation Steps

### 1. Load Container Images

For local installation (no private registry):
```bash
cd scripts/
./load-images.sh
```

For private registry installation:
```bash
cd scripts/
./load-images.sh your-registry.company.com
```

### 2. Install KubeChat

Local installation:
```bash
./install-airgap.sh
```

Private registry installation:
```bash
./install-airgap.sh your-registry.company.com
```

### 3. Verify Installation

```bash
kubectl get pods -n kubechat-system
kubectl get svc -n kubechat-system
```

### 4. Configure Access

See chart/values-airgap.yaml for configuration options.
EOF

# Create compressed bundle
tar -czf "${BUNDLE_NAME}.tar.gz" "$BUNDLE_NAME"
rm -rf "$BUNDLE_NAME"

echo "Air-gap bundle created: ${BUNDLE_NAME}.tar.gz"
echo "Transfer this file to your air-gapped environment for installation."
```

### 2. Air-Gap Installation Process

```bash
# On air-gapped machine:

# 1. Extract bundle
tar -xzf kubechat-airgap-1.0.0.tar.gz
cd kubechat-airgap-1.0.0/

# 2. Load images (choose one method)
# Method A: Load to local Docker daemon
cd scripts/
./load-images.sh

# Method B: Load to private registry
./load-images.sh registry.company.com

# 3. Install KubeChat
./install-airgap.sh  # for local images
# OR
./install-airgap.sh registry.company.com  # for private registry

# 4. Verify installation
kubectl get pods -n kubechat-system
```

## Configuration Options

### 1. Minimal Configuration (Development/Testing)

```yaml
# values-minimal.yaml
apiGateway:
  replicaCount: 1
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"

postgresql:
  persistence:
    size: "10Gi"

redis:
  persistence:
    size: "2Gi"

auth:
  oidc:
    enabled: false  # Use built-in auth for testing
```

### 2. High Availability Configuration

```yaml
# values-ha.yaml
apiGateway:
  replicaCount: 5
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20

postgresql:
  replication:
    enabled: true
    readReplicas: 2
  persistence:
    size: "500Gi"

redis:
  cluster:
    enabled: true
    nodes: 6
  persistence:
    size: "100Gi"

# Anti-affinity for pod distribution
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
    - labelSelector:
        matchLabels:
          app.kubernetes.io/name: kubechat
      topologyKey: kubernetes.io/hostname
```

## Authentication Setup

### 1. OIDC Provider Integration

```yaml
# OIDC configuration in values.yaml
auth:
  oidc:
    enabled: true
    providerName: "corporate-sso"
    displayName: "Corporate SSO"
    issuerUrl: "https://auth.company.com"
    clientId: "kubechat-production"
    clientSecret: "secure-client-secret"
    redirectUrl: "https://kubechat.company.com/auth/callback/corporate-sso"
    scopes: "openid,email,profile,groups"
    
    # Custom claim mappings
    emailClaim: "email"
    nameClaim: "name"
    groupsClaim: "groups"
    usernameClaim: "preferred_username"
```

### 2. SAML Provider Integration

```yaml
# SAML configuration in values.yaml
auth:
  saml:
    enabled: true
    providerName: "company-saml"
    displayName: "Company SAML"
    metadataUrl: "https://saml.company.com/metadata"
    entityId: "kubechat-production"
    acsUrl: "https://kubechat.company.com/auth/saml/company-saml/acs"
    
    # Certificate configuration (customer-provided)
    certificateSecret: "saml-certificates"
    
    # Attribute mappings
    emailAttribute: "email"
    nameAttribute: "displayName"
    groupsAttribute: "memberOf"
```

## Post-Deployment Validation

### 1. Health Check Script

```bash
#!/bin/bash
# validate-deployment.sh

NAMESPACE="${1:-kubechat-system}"

echo "Validating KubeChat deployment in namespace: $NAMESPACE"
echo "======================================================="

# Check all pods are running
echo "Pod Status:"
kubectl get pods -n "$NAMESPACE"

# Check services
echo -e "\nService Status:"
kubectl get svc -n "$NAMESPACE"

# Health check endpoints
echo -e "\nHealth Checks:"
kubectl port-forward -n "$NAMESPACE" svc/kubechat-api-gateway 8080:80 &
PID=$!
sleep 3

# Test API Gateway health
curl -f http://localhost:8080/health/ready && echo "✅ API Gateway ready" || echo "❌ API Gateway not ready"
curl -f http://localhost:8080/health/live && echo "✅ API Gateway live" || echo "❌ API Gateway not live"

kill $PID

# Check custom resources
echo -e "\nCustom Resources:"
kubectl get crd | grep kubechat || echo "No KubeChat CRDs found"

# Check operator logs
echo -e "\nOperator Status:"
kubectl logs -n "$NAMESPACE" -l app.kubernetes.io/component=operator --tail=10

echo -e "\n✅ Deployment validation completed!"
```

### 2. Functional Testing

```bash
#!/bin/bash
# functional-test.sh

NAMESPACE="${1:-kubechat-system}"

echo "Running KubeChat functional tests..."

# Test custom resource creation
kubectl apply -f - <<EOF
apiVersion: kubechat.ai/v1
kind: ChatSession
metadata:
  name: test-session
  namespace: $NAMESPACE
spec:
  userId: "test-user"
  sessionId: "functional-test"
  commands: []
EOF

# Verify resource creation
if kubectl get chatsession test-session -n "$NAMESPACE" &>/dev/null; then
  echo "✅ Custom resource creation successful"
  kubectl delete chatsession test-session -n "$NAMESPACE"
else
  echo "❌ Custom resource creation failed"
fi

echo "Functional testing completed!"
```

## Troubleshooting

### Common Issues

#### 1. Pod Stuck in ImagePullBackOff (Air-Gap)
```bash
# Check if images were loaded correctly
docker images | grep kubechat

# Verify image names in deployment
kubectl describe pod [POD_NAME] -n kubechat-system

# Solution: Ensure images match exactly between bundle and chart
```

#### 2. CRD Installation Failures
```bash
# Check cluster admin permissions
kubectl auth can-i create customresourcedefinitions --all-namespaces

# Manually install CRDs if needed
kubectl apply -f kubechat-chart/crds/
```

#### 3. PVC Pending (Storage Issues)
```bash
# Check available storage classes
kubectl get storageclass

# Check if default storage class exists
kubectl get storageclass | grep "(default)"

# Solution: Specify storageClass in values.yaml or create default storage class
```

#### 4. Authentication Integration Issues
```bash
# Check OIDC/SAML configuration
kubectl get configmap kubechat-config -n kubechat-system -o yaml

# Check service connectivity to identity provider
kubectl run test-curl --rm -i --tty --image=curlimages/curl -- \
  curl -v https://your-identity-provider.com/.well-known/openid-configuration
```

### Debug Information Collection

```bash
#!/bin/bash
# collect-debug-info.sh

NAMESPACE="${1:-kubechat-system}"
DEBUG_DIR="kubechat-debug-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$DEBUG_DIR"

# Collect Kubernetes resources
kubectl get all -n "$NAMESPACE" -o yaml > "$DEBUG_DIR/resources.yaml"
kubectl describe all -n "$NAMESPACE" > "$DEBUG_DIR/descriptions.txt"

# Collect logs
for pod in $(kubectl get pods -n "$NAMESPACE" -o name); do
  pod_name=$(echo "$pod" | cut -d'/' -f2)
  kubectl logs -n "$NAMESPACE" "$pod" > "$DEBUG_DIR/${pod_name}.log"
done

# Collect Helm release info
helm get values kubechat -n "$NAMESPACE" > "$DEBUG_DIR/helm-values.yaml"
helm get manifest kubechat -n "$NAMESPACE" > "$DEBUG_DIR/helm-manifest.yaml"

# Collect cluster info
kubectl cluster-info > "$DEBUG_DIR/cluster-info.txt"
kubectl get nodes -o yaml > "$DEBUG_DIR/nodes.yaml"

tar -czf "${DEBUG_DIR}.tar.gz" "$DEBUG_DIR"
rm -rf "$DEBUG_DIR"

echo "Debug information collected: ${DEBUG_DIR}.tar.gz"
```

This comprehensive on-premises deployment guide ensures KubeChat Phase 1 Model 1 can be successfully deployed in customer environments with complete data sovereignty and zero vendor dependencies.