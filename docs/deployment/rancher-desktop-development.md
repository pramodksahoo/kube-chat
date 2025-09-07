# Rancher Desktop Development Environment

## Overview

This guide provides comprehensive setup and usage instructions for developing KubeChat **Phase 1: Model 1 (On-Premises)** using Rancher Desktop, enabling full on-premises simulation and air-gap testing capabilities.

## Table of Contents

1. [Rancher Desktop Setup](#rancher-desktop-setup)
2. [Development Workflow](#development-workflow)
3. [Local Helm Chart Testing](#local-helm-chart-testing)
4. [Air-Gap Deployment Simulation](#air-gap-deployment-simulation)
5. [Integration Testing](#integration-testing)
6. [Troubleshooting](#troubleshooting)

## Rancher Desktop Setup

### 1. Installation and Configuration

#### System Requirements
```yaml
minimum_requirements:
  ram: "8GB"
  cpu: "4 cores"
  disk: "50GB available"
  os: "macOS 10.15+, Windows 10+, Linux"
  
recommended_requirements:
  ram: "16GB"
  cpu: "8 cores"
  disk: "100GB SSD"
  os: "Latest stable version"
```

#### Rancher Desktop Configuration
```yaml
kubernetes_settings:
  version: "1.28.x (latest stable)"
  container_runtime: "containerd"
  cpu_allocation: "4 CPUs"
  memory_allocation: "8GB"
  
features_enabled:
  - kubernetes: true
  - container_registry: true  # For local image storage
  - port_forwarding: true
  - volume_mounts: true
  
networking:
  ingress: "Traefik (default)"
  load_balancer: "Built-in"
```

### 2. Initial Setup Script

```bash
#!/bin/bash
# setup-rancher-desktop-dev.sh

set -euo pipefail

echo "Setting up Rancher Desktop for KubeChat Phase 1 Model 1 development..."

# Verify Rancher Desktop is running
if ! kubectl cluster-info &>/dev/null; then
    echo "Error: Rancher Desktop Kubernetes cluster not accessible"
    echo "Please:"
    echo "1. Start Rancher Desktop"
    echo "2. Enable Kubernetes in Settings > Kubernetes"
    echo "3. Wait for cluster to be ready"
    exit 1
fi

# Verify Helm is available
if ! command -v helm &>/dev/null; then
    echo "Installing Helm..."
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
fi

# Create development namespace
echo "Creating development namespace..."
kubectl create namespace kubechat-dev --dry-run=client -o yaml | kubectl apply -f -

# Setup local registry if needed
echo "Checking for local registry..."
if ! docker ps | grep -q "registry:2"; then
    echo "Starting local Docker registry..."
    docker run -d -p 5000:5000 --restart=always --name registry registry:2
fi

# Install development tools
echo "Installing development dependencies..."
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

echo "Rancher Desktop development environment setup complete!"
echo "Cluster info:"
kubectl cluster-info
```

## Development Workflow

### 1. Local Development Process

#### Step 1: Build Local Images
```bash
#!/bin/bash
# build-local-images.sh

set -euo pipefail

VERSION="${1:-dev}"
REGISTRY="localhost:5000"

echo "Building KubeChat Phase 1 Model 1 images..."

# Build API Gateway
echo "Building API Gateway..."
docker build -f cmd/api-gateway/Dockerfile -t "${REGISTRY}/kubechat/api-gateway:${VERSION}" .

# Build Operator
echo "Building Operator..."
docker build -f cmd/operator/Dockerfile -t "${REGISTRY}/kubechat/operator:${VERSION}" .

# Build Audit Service
echo "Building Audit Service..."
docker build -f cmd/audit-service/Dockerfile -t "${REGISTRY}/kubechat/audit-service:${VERSION}" .

# Push to local registry
echo "Pushing images to local registry..."
docker push "${REGISTRY}/kubechat/api-gateway:${VERSION}"
docker push "${REGISTRY}/kubechat/operator:${VERSION}"
docker push "${REGISTRY}/kubechat/audit-service:${VERSION}"

echo "Images built and pushed successfully!"
```

#### Step 2: Local Development Values
```yaml
# values-dev.yaml for Rancher Desktop
global:
  imageRegistry: "localhost:5000"
  imagePullSecrets: []

# Development-specific settings
deployment:
  mode: "on-premises"
  airgap: false

# Use development images
images:
  apiGateway:
    repository: "kubechat/api-gateway"
    tag: "dev"
    pullPolicy: Always
  operator:
    repository: "kubechat/operator"
    tag: "dev"
    pullPolicy: Always
  auditService:
    repository: "kubechat/audit-service"
    tag: "dev"
    pullPolicy: Always

# Minimal resource requirements for development
apiGateway:
  replicaCount: 1
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

operator:
  resources:
    requests:
      memory: "64Mi"
      cpu: "50m"
    limits:
      memory: "128Mi"
      cpu: "100m"

# Use smaller databases for development
postgresql:
  enabled: true
  internal: true
  persistence:
    enabled: true
    size: "5Gi"
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

redis:
  enabled: true
  internal: true
  persistence:
    enabled: true
    size: "1Gi"
  resources:
    requests:
      memory: "64Mi"
      cpu: "50m"
    limits:
      memory: "128Mi"
      cpu: "100m"

# Development authentication (optional)
auth:
  oidc:
    enabled: false
  saml:
    enabled: false

# Enable monitoring for development
monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true

# Simple ingress for development
ingress:
  enabled: true
  className: "traefik"
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: web
  hosts:
    - host: kubechat.local
      paths:
        - path: /
          pathType: Prefix
  tls: []
```

### 2. Development Deployment Script

```bash
#!/bin/bash
# deploy-dev.sh

set -euo pipefail

NAMESPACE="${1:-kubechat-dev}"
VALUES_FILE="${2:-values-dev.yaml}"

echo "Deploying KubeChat to Rancher Desktop..."

# Build and push images
./build-local-images.sh

# Deploy with Helm
echo "Installing/upgrading KubeChat..."
helm upgrade --install kubechat-dev ./deploy/helm/kubechat \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --values "$VALUES_FILE" \
  --wait \
  --timeout 10m

# Wait for all pods to be ready
echo "Waiting for all pods to be ready..."
kubectl wait --for=condition=Ready pod --all -n "$NAMESPACE" --timeout=300s

# Get service information
echo "KubeChat deployment complete!"
echo ""
echo "Services:"
kubectl get svc -n "$NAMESPACE"
echo ""
echo "Pods:"
kubectl get pods -n "$NAMESPACE"
echo ""
echo "Access KubeChat at: http://kubechat.local (add to /etc/hosts if needed)"
```

## Local Helm Chart Testing

### 1. Helm Chart Validation

```bash
#!/bin/bash
# test-helm-chart.sh

set -euo pipefail

CHART_PATH="./deploy/helm/kubechat"

echo "Testing KubeChat Helm chart..."

# Lint the chart
echo "1. Linting Helm chart..."
helm lint "$CHART_PATH"

# Dry run installation
echo "2. Testing dry-run installation..."
helm install kubechat-test "$CHART_PATH" \
  --dry-run \
  --debug \
  --values values-dev.yaml

# Template testing
echo "3. Testing template rendering..."
helm template kubechat-test "$CHART_PATH" \
  --values values-dev.yaml \
  --output-dir ./test-output

# Validate generated Kubernetes manifests
echo "4. Validating Kubernetes manifests..."
for manifest in ./test-output/kubechat/templates/*.yaml; do
  if [[ -f "$manifest" ]]; then
    kubectl apply --dry-run=client -f "$manifest"
  fi
done

# Cleanup test output
rm -rf ./test-output

echo "Helm chart validation completed successfully!"
```

### 2. Chart Testing with Different Configurations

```bash
#!/bin/bash
# test-chart-configurations.sh

set -euo pipefail

CHART_PATH="./deploy/helm/kubechat"
TEST_CONFIGS=(
  "values-dev.yaml"
  "values-minimal.yaml"
  "values-airgap.yaml"
  "values-production.yaml"
)

echo "Testing Helm chart with different configurations..."

for config in "${TEST_CONFIGS[@]}"; do
  if [[ -f "$config" ]]; then
    echo "Testing configuration: $config"
    
    helm template "kubechat-test-$(basename "$config" .yaml)" "$CHART_PATH" \
      --values "$config" \
      --output-dir "./test-output-$(basename "$config" .yaml)"
      
    echo "✅ Configuration $config validated"
  else
    echo "⚠️  Configuration file $config not found, skipping"
  fi
done

echo "Chart configuration testing completed!"
```

## Air-Gap Deployment Simulation

### 1. Simulating Air-Gap Environment

```bash
#!/bin/bash
# simulate-airgap.sh

set -euo pipefail

echo "Simulating air-gap deployment environment..."

# Create air-gap namespace
kubectl create namespace kubechat-airgap --dry-run=client -o yaml | kubectl apply -f -

# Create local image registry secret
kubectl create secret docker-registry local-registry \
  --docker-server=localhost:5000 \
  --docker-username=admin \
  --docker-password=admin \
  --docker-email=admin@local.dev \
  --namespace=kubechat-airgap \
  --dry-run=client -o yaml | kubectl apply -f -

# Deploy in air-gap mode
helm upgrade --install kubechat-airgap ./deploy/helm/kubechat \
  --namespace kubechat-airgap \
  --values values-airgap.yaml \
  --set global.imageRegistry="localhost:5000" \
  --set airgap.enabled=true \
  --set global.imagePullSecrets[0].name="local-registry" \
  --wait

echo "Air-gap simulation deployment completed!"
```

### 2. Air-Gap Testing Values

```yaml
# values-airgap.yaml
global:
  imageRegistry: "localhost:5000"
  imagePullSecrets:
    - name: local-registry

deployment:
  mode: "on-premises"
  airgap: true

# Disable external dependencies
auth:
  oidc:
    enabled: false
  saml:
    enabled: false

monitoring:
  prometheus:
    enabled: false  # Assume customer has existing monitoring

ingress:
  enabled: false  # Customer will configure their own ingress

# Internal services only
postgresql:
  enabled: true
  internal: true
  external:
    enabled: false

redis:
  enabled: true
  internal: true
  external:
    enabled: false

# Air-gap specific settings
airgap:
  enabled: true
  imageRegistry: "localhost:5000"
  pullSecrets:
    - name: local-registry
  offlineMode: true
  externalServices: false
```

## Integration Testing

### 1. End-to-End Testing Script

```bash
#!/bin/bash
# e2e-test.sh

set -euo pipefail

NAMESPACE="kubechat-test"

echo "Running KubeChat Phase 1 Model 1 end-to-end tests..."

# Deploy test environment
helm upgrade --install kubechat-e2e ./deploy/helm/kubechat \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --values values-dev.yaml \
  --wait

# Wait for all services to be ready
kubectl wait --for=condition=Ready pod --all -n "$NAMESPACE" --timeout=300s

# Test API Gateway health
echo "Testing API Gateway health..."
kubectl port-forward -n "$NAMESPACE" svc/kubechat-api-gateway 8080:80 &
PORT_FORWARD_PID=$!
sleep 5

curl -f http://localhost:8080/health || {
  echo "❌ API Gateway health check failed"
  kill $PORT_FORWARD_PID
  exit 1
}

echo "✅ API Gateway health check passed"

# Test operator functionality
echo "Testing Kubernetes operator..."
kubectl apply -f - <<EOF
apiVersion: kubechat.ai/v1
kind: ChatSession
metadata:
  name: test-session
  namespace: $NAMESPACE
spec:
  userId: "test-user"
  sessionId: "test-session-001"
  commands: []
EOF

# Verify custom resource creation
kubectl get chatsession test-session -n "$NAMESPACE" || {
  echo "❌ Custom resource creation failed"
  kill $PORT_FORWARD_PID
  exit 1
}

echo "✅ Kubernetes operator functionality verified"

# Cleanup
kill $PORT_FORWARD_PID
kubectl delete chatsession test-session -n "$NAMESPACE"

echo "End-to-end testing completed successfully!"
```

### 2. Performance Testing

```bash
#!/bin/bash
# performance-test.sh

set -euo pipefail

NAMESPACE="kubechat-perf"

echo "Running performance tests..."

# Deploy performance test environment
helm upgrade --install kubechat-perf ./deploy/helm/kubechat \
  --namespace "$NAMESPACE" \
  --create-namespace \
  --values values-dev.yaml \
  --set apiGateway.replicaCount=3 \
  --wait

# Install k6 for load testing
if ! command -v k6 &>/dev/null; then
  echo "Installing k6..."
  brew install k6  # macOS
fi

# Run load test
kubectl port-forward -n "$NAMESPACE" svc/kubechat-api-gateway 8080:80 &
PORT_FORWARD_PID=$!
sleep 5

cat > load-test.js << 'EOF'
import http from 'k6/http';
import { check } from 'k6';

export let options = {
  stages: [
    { duration: '2m', target: 10 },
    { duration: '5m', target: 50 },
    { duration: '2m', target: 0 },
  ],
};

export default function() {
  let response = http.get('http://localhost:8080/health');
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });
}
EOF

k6 run load-test.js

# Cleanup
kill $PORT_FORWARD_PID
rm load-test.js

echo "Performance testing completed!"
```

## Troubleshooting

### 1. Common Issues and Solutions

#### Issue: Rancher Desktop Not Starting
```yaml
symptoms:
  - "kubectl cluster-info fails"
  - "No Kubernetes cluster available"
  
solutions:
  - action: "Restart Rancher Desktop"
    command: "Close and reopen Rancher Desktop application"
  - action: "Reset Kubernetes"
    path: "Settings > Kubernetes > Reset Kubernetes"
  - action: "Check system resources"
    requirement: "Ensure sufficient RAM and CPU allocated"
```

#### Issue: Image Pull Failures
```yaml
symptoms:
  - "ErrImagePull or ImagePullBackOff"
  - "Images not found in local registry"
  
solutions:
  - action: "Build and push images"
    command: "./build-local-images.sh"
  - action: "Verify registry is running"
    command: "docker ps | grep registry"
  - action: "Check image tags"
    command: "docker images | grep kubechat"
```

#### Issue: Helm Installation Failures
```yaml
symptoms:
  - "Helm install/upgrade timeouts"
  - "Pods stuck in pending state"
  
solutions:
  - action: "Check resource limits"
    command: "kubectl describe nodes"
  - action: "Verify storage classes"
    command: "kubectl get storageclass"
  - action: "Check pod events"
    command: "kubectl describe pod [POD_NAME] -n [NAMESPACE]"
```

### 2. Debugging Commands

```bash
#!/bin/bash
# debug-kubechat.sh

NAMESPACE="${1:-kubechat-dev}"

echo "KubeChat Debug Information for namespace: $NAMESPACE"
echo "=================================================="

# Cluster information
echo "Cluster Info:"
kubectl cluster-info
echo ""

# Node information
echo "Node Status:"
kubectl get nodes -o wide
echo ""

# Namespace resources
echo "Namespace Resources:"
kubectl get all -n "$NAMESPACE"
echo ""

# Pod details and logs
echo "Pod Details:"
for pod in $(kubectl get pods -n "$NAMESPACE" -o jsonpath='{.items[*].metadata.name}'); do
  echo "Pod: $pod"
  kubectl describe pod "$pod" -n "$NAMESPACE"
  echo "Logs:"
  kubectl logs "$pod" -n "$NAMESPACE" --tail=50
  echo "---"
done

# Helm release status
echo "Helm Release Status:"
helm status kubechat-dev -n "$NAMESPACE" || echo "Helm release not found"

# Storage and PVC status
echo "Storage Status:"
kubectl get pvc -n "$NAMESPACE"

# Custom Resources
echo "Custom Resources:"
kubectl get chatsessions -n "$NAMESPACE" 2>/dev/null || echo "No ChatSession resources found"

echo "Debug information collection completed!"
```

This comprehensive Rancher Desktop development guide ensures KubeChat Phase 1 Model 1 can be effectively developed, tested, and validated in a local environment that simulates the target on-premises deployment scenario.