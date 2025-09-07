# KubeChat Local Development Setup - Phase 1 Model 1

## Introduction

This guide provides comprehensive instructions for setting up a **KubeChat Phase 1: Model 1 (On-Premises)** development environment using **Rancher Desktop**. This setup enables full on-premises simulation, air-gap testing, and Helm-native deployment validation.

### Prerequisites Overview
- **Rancher Desktop** with Kubernetes enabled (replaces Docker Desktop)
- **Go 1.22+** for Kubernetes operator and API development
- **Node.js 18+** and **pnpm** for React web interface (Epic 4)
- **kubectl** and **Helm** for Kubernetes operations
- **Phase 1 Model 1 Focus**: On-premises deployment, data sovereignty, air-gap capability

### Change Log
| Date | Version | Description | Author |
|------|---------|-------------|---------|
| 2025-09-05 | 1.0 | Initial local development setup guide | Winston (Architect) |

---

## Prerequisites Installation

### 1. Rancher Desktop (Required for Phase 1 Model 1)
```bash
# macOS installation
brew install --cask rancher

# Or download from: https://rancherdesktop.io/

# Configure Rancher Desktop:
# 1. Launch Rancher Desktop
# 2. Enable Kubernetes in Settings → Kubernetes
# 3. Set Container Runtime: containerd (recommended)
# 4. Allocate resources: 8GB RAM, 4 CPUs minimum

# Verify installation
kubectl version --client
kubectl cluster-info
docker --version  # Via Rancher Desktop
```

### 2. Go Development Environment
```bash
# macOS installation
brew install go

# Verify installation
go version  # Should show 1.22+

# Set Go environment variables (add to ~/.zshrc or ~/.bashrc)
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

### 3. Node.js and Frontend Tools (Epic 4 - Web Interface)
```bash
# Install Node.js (via Homebrew)
brew install node@23

# Install pnpm globally
npm install -g pnpm

# Verify installations
node --version  # Should show 18+
pnpm --version

# Set up pnpm environment (add to ~/.zshrc or ~/.bashrc)
export PNPM_HOME="$HOME/Library/pnpm"
export PATH="$PNPM_HOME:$PATH"
```

### 4. Kubernetes Tools
```bash
# Install kubectl (if not included with Rancher Desktop)
brew install kubectl

# Install Helm
brew install helm

# Verify installations
kubectl version --client
helm version
```

### 5. Development Tools
```bash
# Git (if not already installed)
brew install git

# Visual Studio Code (recommended)
brew install --cask visual-studio-code

# Additional useful tools
brew install jq          # JSON processing
brew install httpie      # HTTP client for API testing
brew install kubectx     # Kubernetes context switching
brew install k9s         # Terminal UI for Kubernetes
```

---

## Repository Setup

### 1. Clone and Initial Setup
```bash
# Clone the repository
git clone https://github.com/pramodksahoo/kube-chat.git
cd kub-echat

# Install all dependencies
pnpm install

# Verify project structure
ls -la
# Should see: cmd/, pkg/, web/, charts/, docs/, etc.
```

### 2. Go Module Setup
```bash
# Initialize Go modules (if not already done)
go mod tidy

# Install development tools
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/onsi/ginkgo/v2/ginkgo@latest
go install sigs.k8s.io/controller-tools/cmd/controller-gen@latest

# Verify Go setup
go version
golangci-lint version
```

### 3. Frontend Development Setup (Epic 4)
```bash
# Navigate to web directory
cd web/

# Install frontend dependencies
pnpm install

# Verify web app builds
pnpm run build

# Run development server (for testing)
pnpm run dev  # Runs on http://localhost:5173

# Return to project root
cd ..
```

---

## Phase 1 Model 1 Development Environment Setup

### 1. Rancher Desktop Kubernetes Cluster Setup

```bash
# Verify Rancher Desktop Kubernetes is running
kubectl cluster-info

# Create Phase 1 Model 1 development namespace
kubectl create namespace kubechat-system

# Create separate namespace for testing air-gap deployments
kubectl create namespace kubechat-airgap

# Set default namespace for development
kubectl config set-context --current --namespace=kubechat-system

# Verify cluster is ready
kubectl get nodes
kubectl get namespaces

### 2. Local Registry Setup (For Air-Gap Testing)

```bash
# Set up local container registry for air-gap testing
docker run -d -p 5000:5000 --restart=always --name local-registry registry:2

# Verify registry is running
curl http://localhost:5000/v2/_catalog
```

### 3. Phase 1 Model 1 Development Dependencies

```bash
# Create Phase 1 Model 1 development dependencies script
mkdir -p scripts
cat > scripts/setup-phase1-dev.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🚀 Setting up KubeChat Phase 1 Model 1 development environment..."

# Add Helm repositories for development dependencies
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Install minimal PostgreSQL for development
echo "📦 Installing PostgreSQL for Phase 1 Model 1..."
helm upgrade --install postgres bitnami/postgresql \
  --namespace kubechat-system \
  --create-namespace \
  --set auth.postgresPassword=dev-password \
  --set auth.database=kubechat_dev \
  --set primary.persistence.size=5Gi \
  --set primary.resources.requests.memory=256Mi \
  --set primary.resources.requests.cpu=250m \
  --set primary.service.type=ClusterIP

# Install minimal Redis for development
echo "📦 Installing Redis for Phase 1 Model 1..."
helm upgrade --install redis bitnami/redis \
  --namespace kubechat-system \
  --set auth.password=dev-password \
  --set master.persistence.size=2Gi \
  --set master.resources.requests.memory=128Mi \
  --set master.resources.requests.cpu=100m \
  --set master.service.type=ClusterIP

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql -n kubechat-system --timeout=300s
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n kubechat-system --timeout=300s

echo "✅ Phase 1 Model 1 development dependencies installed!"

# Display connection information
echo ""
echo "📋 Service Information:"
echo "PostgreSQL Service: postgres-postgresql.kubechat-system.svc.cluster.local:5432"
echo "Redis Service: redis-master.kubechat-system.svc.cluster.local:6379"
echo ""
echo "For local development access:"
echo "kubectl port-forward -n kubechat-system svc/postgres-postgresql 5432:5432"
echo "kubectl port-forward -n kubechat-system svc/redis-master 6379:6379"
EOF

chmod +x scripts/setup-phase1-dev.sh
./scripts/setup-phase1-dev.sh
```

### 4. Phase 1 Model 1 Development Configuration

**Create Development Environment Configuration:**
```bash
# Create development values for Helm chart
cat > values-dev-rancher.yaml << 'EOF'
# KubeChat Phase 1 Model 1 Development Configuration for Rancher Desktop
global:
  imageRegistry: "localhost:5000"  # Local registry for air-gap testing
  
deployment:
  mode: "on-premises"
  airgap: false  # Set to true for air-gap testing

# Development image tags
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

# Minimal resources for development
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

# Use existing PostgreSQL and Redis
postgresql:
  enabled: false
  external:
    host: "postgres-postgresql.kubechat-system.svc.cluster.local"
    port: 5432
    database: "kubechat_dev"
    username: "postgres"
    password: "dev-password"

redis:
  enabled: false
  external:
    host: "redis-master.kubechat-system.svc.cluster.local"
    port: 6379
    password: "dev-password"

# Development authentication (disabled)
auth:
  oidc:
    enabled: false
  saml:
    enabled: false

# Simple ingress for local access
ingress:
  enabled: true
  className: "traefik"  # Rancher Desktop default
  hosts:
    - host: kubechat.local
      paths:
        - path: /
          pathType: Prefix
EOF
```

---

## Phase 1 Model 1 Development Workflow

### 1. Build and Deploy Development Images

**Create Build Script for Phase 1 Model 1:**
```bash
cat > scripts/build-dev-images.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🏗️ Building KubeChat Phase 1 Model 1 development images..."

# Build React frontend first (Epic 4)
echo "Building React frontend..."
cd web/
pnpm install
pnpm run build
cd ..

# Build API Gateway
echo "Building API Gateway..."
docker build -f cmd/api-gateway/Dockerfile -t localhost:5000/kubechat/api-gateway:dev .

# Build Kubernetes Operator
echo "Building Kubernetes Operator..."
docker build -f cmd/operator/Dockerfile -t localhost:5000/kubechat/operator:dev .

# Build Audit Service  
echo "Building Audit Service..."
docker build -f cmd/audit-service/Dockerfile -t localhost:5000/kubechat/audit-service:dev .

# Push to local registry
echo "Pushing to local registry..."
docker push localhost:5000/kubechat/api-gateway:dev
docker push localhost:5000/kubechat/operator:dev
docker push localhost:5000/kubechat/audit-service:dev

echo "✅ Development images built and pushed!"
EOF

chmod +x scripts/build-dev-images.sh
```

### 2. Deploy KubeChat to Rancher Desktop

**Create Deployment Script:**
```bash
cat > scripts/deploy-dev.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🚀 Deploying KubeChat Phase 1 Model 1 to Rancher Desktop..."

# Build and push images
./scripts/build-dev-images.sh

# Deploy using Helm
helm upgrade --install kubechat-dev ./deploy/helm/kubechat \
  --namespace kubechat-system \
  --values values-dev-rancher.yaml \
  --wait \
  --timeout 10m

echo "⏳ Waiting for all pods to be ready..."
kubectl wait --for=condition=Ready pod --all -n kubechat-system --timeout=300s

echo "✅ KubeChat development deployment complete!"
echo ""
echo "📋 Deployment Status:"
kubectl get pods -n kubechat-system
echo ""
echo "🔗 Services:"
kubectl get svc -n kubechat-system
echo ""
echo "🌐 Access KubeChat:"
echo "  - API: kubectl port-forward -n kubechat-system svc/kubechat-api-gateway 8080:80"
echo "  - Or add 'kubechat.local' to /etc/hosts pointing to 127.0.0.1"
EOF

chmod +x scripts/deploy-dev.sh
```

### 3. Air-Gap Testing

**Create Air-Gap Test Script:**
```bash
cat > scripts/test-airgap.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🔒 Testing KubeChat Phase 1 Model 1 air-gap deployment..."

# Create air-gap values
cat > values-airgap-test.yaml << 'AIRGAP_EOF'
global:
  imageRegistry: "localhost:5000"

deployment:
  airgap: true

# Disable external dependencies
auth:
  oidc:
    enabled: false
  saml:
    enabled: false

monitoring:
  prometheus:
    enabled: false

ingress:
  enabled: false
AIRGAP_EOF

# Deploy in air-gap mode
helm upgrade --install kubechat-airgap ./deploy/helm/kubechat \
  --namespace kubechat-airgap \
  --create-namespace \
  --values values-airgap-test.yaml \
  --wait

echo "⏳ Verifying air-gap deployment..."
kubectl wait --for=condition=Ready pod --all -n kubechat-airgap --timeout=300s

echo "✅ Air-gap deployment test successful!"
kubectl get pods -n kubechat-airgap
EOF

chmod +x scripts/test-airgap.sh
```

### 4. Development Testing and Validation

**Create Test Script:**
```bash
cat > scripts/test-phase1.sh << 'EOF'
#!/bin/bash
set -euo pipefail

echo "🧪 Testing KubeChat Phase 1 Model 1..."

# Run unit tests
echo "Running Go unit tests..."
go test ./pkg/... -v
go test ./cmd/... -v

# Test Kubernetes operator functionality
echo "Testing Kubernetes operator..."
kubectl apply -f - <<YAML
apiVersion: kubechat.ai/v1
kind: ChatSession
metadata:
  name: test-session
  namespace: kubechat-system
spec:
  userId: "test-user"
  sessionId: "test-001"
  commands: []
YAML

# Verify custom resource creation
if kubectl get chatsession test-session -n kubechat-system &>/dev/null; then
  echo "✅ Custom resource creation successful"
  kubectl delete chatsession test-session -n kubechat-system
else
  echo "❌ Custom resource creation failed"
fi

# Test API Gateway health
echo "Testing API Gateway health..."
kubectl port-forward -n kubechat-system svc/kubechat-api-gateway 8080:80 &
PID=$!
sleep 5

if curl -f http://localhost:8080/health/ready; then
  echo "✅ API Gateway health check passed"
else
  echo "❌ API Gateway health check failed"
fi

kill $PID

echo "✅ Phase 1 Model 1 testing completed!"
EOF

chmod +x scripts/test-phase1.sh
```

---

## Development Tools and IDE Configuration

### 1. Visual Studio Code Setup for Phase 1 Model 1

**Recommended Extensions (.vscode/extensions.json):**
```json
{
  "recommendations": [
    "golang.go",
    "ms-kubernetes-tools.vscode-kubernetes-tools",
    "redhat.vscode-yaml",
    "ms-vscode.vscode-json",
    "usernamehw.errorlens",
    "streetsidesoftware.code-spell-checker",
    "ms-vscode-remote.remote-containers",
    "bradlc.vscode-tailwindcss",
    "esbenp.prettier-vscode",
    "ms-vscode.vscode-typescript-next",
    "formulahendry.auto-rename-tag",
    "christian-kohler.npm-intellisense"
  ]
}
```

**VS Code Settings (.vscode/settings.json):**
```json
{
  "go.testFlags": ["-v"],
  "go.coverOnSave": true,
  "go.lintOnSave": "package",
  "go.formatTool": "goimports",
  "editor.formatOnSave": true,
  "files.associations": {
    "*.yaml": "yaml",
    "*.yml": "yaml"
  },
  "yaml.schemas": {
    "kubernetes://schema/v1.28.0": "*.yaml"
  },
  "kubernetes.defaultNamespace": "kubechat-system"
}
```

### 2. Phase 1 Model 1 Development Aliases

**Add to ~/.zshrc or ~/.bashrc:**
```bash
# KubeChat Phase 1 Model 1 development aliases
alias kc-build='./scripts/build-dev-images.sh'
alias kc-deploy='./scripts/deploy-dev.sh'
alias kc-test='./scripts/test-phase1.sh'
alias kc-airgap='./scripts/test-airgap.sh'
alias kc-logs='kubectl logs -f -n kubechat-system'
alias kc-pods='kubectl get pods -n kubechat-system'

# Frontend development aliases (Epic 4)
alias kc-web='cd web && pnpm run dev'
alias kc-web-build='cd web && pnpm run build'
alias kc-web-test='cd web && pnpm run test'

# Rancher Desktop context
alias rancher='kubectl config use-context rancher-desktop'

# Quick Helm operations
alias kc-status='helm status kubechat-dev -n kubechat-system'
alias kc-values='helm get values kubechat-dev -n kubechat-system'

# Port forwarding shortcuts
kc-api() {
    kubectl port-forward -n kubechat-system svc/kubechat-api-gateway 8080:80
}

kc-db() {
    kubectl port-forward -n kubechat-system svc/postgres-postgresql 5432:5432
}
```

---

## Troubleshooting Phase 1 Model 1

### Common Issues and Solutions

**1. Rancher Desktop Not Running**
```bash
# Check if Rancher Desktop Kubernetes is accessible
kubectl cluster-info

# If not working, restart Rancher Desktop and enable Kubernetes
```

**2. Image Pull Issues**
```bash
# Check local registry
curl http://localhost:5000/v2/_catalog

# Rebuild and push images
./scripts/build-dev-images.sh
```

**3. Helm Deployment Issues**
```bash
# Check Helm release status
helm status kubechat-dev -n kubechat-system

# Debug failed pods
kubectl describe pod [POD_NAME] -n kubechat-system
```

**4. Custom Resource Issues**
```bash
# Check if CRDs are installed
kubectl get crd | grep kubechat

# Manually apply CRDs if needed
kubectl apply -f deploy/helm/kubechat/crds/
```

---

## Next Steps

After completing the Phase 1 Model 1 setup:

1. **Run development setup:** `./scripts/setup-phase1-dev.sh`
2. **Build development images:** `./scripts/build-dev-images.sh`  
3. **Deploy to Rancher Desktop:** `./scripts/deploy-dev.sh`
4. **Test deployment:** `./scripts/test-phase1.sh`
5. **Test air-gap mode:** `./scripts/test-airgap.sh`

### Development Cycle

```bash
# Standard development workflow
./scripts/build-dev-images.sh    # Build new images
./scripts/deploy-dev.sh          # Deploy to Rancher Desktop  
./scripts/test-phase1.sh         # Validate deployment
```

This setup provides everything needed for **KubeChat Phase 1: Model 1 (On-Premises)** development using Rancher Desktop with complete air-gap testing capabilities.