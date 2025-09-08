#!/bin/bash
# setup-phase1-dev.sh
# KubeChat Phase 1 Model 1 Development Environment Setup
# Complete development environment initialization for Rancher Desktop

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Error handler
error_handler() {
    log_error "Script failed at line $1"
    log_error "Phase 1 Model 1 development environment setup failed"
    exit 1
}

trap 'error_handler $LINENO' ERR

# Main setup function
main() {
    log_info "🚀 Setting up KubeChat Phase 1 Model 1 development environment..."
    
    # Verify we're in the correct directory
    if [[ ! -f "go.mod" ]] || [[ ! -d "cmd" ]] || [[ ! -d "pkg" ]]; then
        log_error "Must run from KubeChat project root directory"
        log_error "Expected to find: go.mod, cmd/, pkg/ directories"
        exit 1
    fi
    
    # Check if Rancher Desktop is running
    log_info "Verifying Rancher Desktop Kubernetes cluster accessibility..."
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Rancher Desktop Kubernetes cluster not accessible"
        log_error "Please:"
        log_error "  1. Start Rancher Desktop application"
        log_error "  2. Enable Kubernetes in Settings > Kubernetes"
        log_error "  3. Wait for cluster to be ready (green indicator)"
        log_error "  4. Verify with: kubectl cluster-info"
        exit 1
    fi
    
    log_success "Rancher Desktop Kubernetes cluster is accessible"
    kubectl cluster-info
    
    # Verify required tools
    log_info "Verifying required development tools..."
    
    # Check Helm
    if ! command -v helm &>/dev/null; then
        log_warning "Helm not found, installing..."
        if command -v brew &>/dev/null; then
            brew install helm
        else
            log_error "Helm not found and Homebrew not available for installation"
            log_error "Please install Helm manually: https://helm.sh/docs/intro/install/"
            exit 1
        fi
    fi
    
    # Check Docker (via Rancher Desktop)
    if ! docker --version &>/dev/null; then
        log_error "Docker not accessible. Ensure Rancher Desktop is running with container runtime enabled"
        exit 1
    fi
    
    # Check Go
    if ! go version &>/dev/null; then
        log_error "Go not found. Please install Go 1.22+ from: https://golang.org/doc/install"
        exit 1
    fi
    
    # Check Node.js and pnpm (for web frontend)
    if ! node --version &>/dev/null; then
        log_warning "Node.js not found, required for web frontend development"
        log_warning "Install with: brew install node"
    fi
    
    if ! pnpm --version &>/dev/null; then
        log_warning "pnpm not found, required for web frontend development"
        log_warning "Install with: npm install -g pnpm"
    fi
    
    log_success "Required tools verification completed"
    
    # Create development namespaces
    log_info "Creating KubeChat development namespaces..."
    
    kubectl create namespace kubechat-system --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace kubechat-airgap --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace kubechat-dev --dry-run=client -o yaml | kubectl apply -f -
    
    # Set default namespace for development
    kubectl config set-context --current --namespace=kubechat-system
    
    log_success "Development namespaces created: kubechat-system (default), kubechat-airgap, kubechat-dev"
    
    # Setup local Docker registry for air-gap testing
    log_info "Setting up local Docker registry for air-gap testing..."
    
    # Check if registry container exists and is running
    if docker ps --filter "name=local-registry" --filter "status=running" | grep -q "local-registry"; then
        log_success "Local Docker registry already running at localhost:5001"
        curl -s http://localhost:5001/v2/_catalog | head -1
    elif docker ps -a --filter "name=local-registry" | grep -q "local-registry"; then
        # Container exists but is stopped, restart it
        log_info "Restarting existing local Docker registry..."
        docker start local-registry
        sleep 3
        if curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
            log_success "Local Docker registry restarted successfully at localhost:5001"
        else
            log_error "Failed to restart local Docker registry"
            exit 1
        fi
    else
        # No container exists, create new one
        log_info "Starting new local Docker registry on port 5001..."
        docker run -d -p 5001:5000 --restart=always --name local-registry registry:2
        
        # Wait for registry to be ready
        sleep 3
        
        # Test registry connectivity
        if curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
            log_success "Local Docker registry started successfully at localhost:5001"
        else
            log_error "Failed to start local Docker registry"
            exit 1
        fi
    fi
    
    # Add Helm repositories for development dependencies
    log_info "Adding Helm repositories for development dependencies..."
    
    helm repo add bitnami https://charts.bitnami.com/bitnami
    helm repo update
    
    log_success "Helm repositories added and updated"
    
    # Install development dependencies (PostgreSQL and Redis)
    log_info "Installing development dependencies (PostgreSQL and Redis)..."
    
    # Install PostgreSQL for development
    log_info "📦 Installing PostgreSQL for Phase 1 Model 1 development..."
    helm upgrade --install postgres bitnami/postgresql \
        --namespace kubechat-system \
        --create-namespace \
        --set auth.postgresPassword=dev-password \
        --set auth.database=kubechat_dev \
        --set primary.persistence.size=5Gi \
        --set primary.resources.requests.memory=256Mi \
        --set primary.resources.requests.cpu=250m \
        --set primary.service.type=ClusterIP \
        --wait --timeout=300s
    
    # Install Redis for development  
    log_info "📦 Installing Redis for Phase 1 Model 1 development..."
    helm upgrade --install redis bitnami/redis \
        --namespace kubechat-system \
        --set auth.password=dev-password \
        --set master.persistence.size=2Gi \
        --set master.resources.requests.memory=128Mi \
        --set master.resources.requests.cpu=100m \
        --set master.service.type=ClusterIP \
        --wait --timeout=300s
    
    # Wait for services to be ready
    log_info "⏳ Waiting for services to be ready..."
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=postgresql -n kubechat-system --timeout=300s
    kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=redis -n kubechat-system --timeout=300s
    
    log_success "Development dependencies installed successfully!"
    
    # Display service information
    log_success "✅ Phase 1 Model 1 development environment setup complete!"
    echo ""
    log_info "📋 Service Information:"
    echo "  PostgreSQL Service: postgres-postgresql.kubechat-system.svc.cluster.local:5432"
    echo "  Redis Service: redis-master.kubechat-system.svc.cluster.local:6379"
    echo "  Local Registry: localhost:5001"
    echo ""
    log_info "🔗 For local development access:"
    echo "  kubectl port-forward -n kubechat-system svc/postgres-postgresql 5432:5432"
    echo "  kubectl port-forward -n kubechat-system svc/redis-master 6379:6379"
    echo ""
    log_info "🚀 Next Steps:"
    echo "  1. Run './scripts/build-kubechat-images.sh dev' to build all service images"
    echo "  2. Run './scripts/deploy-dev.sh' to deploy KubeChat to Rancher Desktop"
    echo "  3. Run './scripts/test-phase1.sh' to validate the deployment"
    echo "  4. Run './scripts/test-airgap.sh' to test air-gap deployment"
    
    # Create .env files for development
    log_info "Creating .env.example files for development..."
    
    # API Gateway .env example
    mkdir -p cmd/api-gateway
    cat > cmd/api-gateway/.env.example << 'EOF'
# KubeChat API Gateway Development Configuration
# Copy this file to .env and adjust values for your local development

# Server Configuration
PORT=8080
HOST=0.0.0.0
LOG_LEVEL=debug

# Database Configuration
DATABASE_URL=postgres://postgres:dev-password@localhost:5432/kubechat_dev?sslmode=disable
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=kubechat_dev
DATABASE_USER=postgres
DATABASE_PASSWORD=dev-password

# Redis Configuration
REDIS_URL=redis://localhost:6379
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=dev-password

# Authentication Configuration (Development)
JWT_SECRET=dev-jwt-secret-change-in-production
JWT_EXPIRATION=24h
AUTH_ENABLED=false

# Kubernetes Configuration
KUBECONFIG_PATH=/Users/${USER}/.kube/config
KUBECTL_NAMESPACE=kubechat-system

# NLP Service Configuration
NLP_SERVICE_URL=http://localhost:8081
OLLAMA_API_URL=http://localhost:11434
OPENAI_API_KEY=optional-openai-api-key

# Audit Service Configuration
AUDIT_SERVICE_URL=http://localhost:8082

# Development Flags
DEV_MODE=true
ENABLE_CORS=true
ENABLE_DEBUG_ENDPOINTS=true
EOF
    
    # Audit Service .env example
    mkdir -p cmd/audit-service
    cat > cmd/audit-service/.env.example << 'EOF'
# KubeChat Audit Service Development Configuration
# Copy this file to .env and adjust values for your local development

# Server Configuration
PORT=8082
HOST=0.0.0.0
LOG_LEVEL=debug

# Database Configuration (dedicated audit database)
DATABASE_URL=postgres://postgres:dev-password@localhost:5432/kubechat_audit_dev?sslmode=disable
DATABASE_HOST=localhost
DATABASE_PORT=5432
DATABASE_NAME=kubechat_audit_dev
DATABASE_USER=postgres
DATABASE_PASSWORD=dev-password

# Audit Configuration
AUDIT_RETENTION_DAYS=90
ENABLE_TAMPER_PROOF=true
ENCRYPTION_KEY=dev-encryption-key-change-in-production

# SIEM Integration (Development - disabled)
SIEM_ENABLED=false
SIEM_WEBHOOK_URL=https://your-siem-system.example.com/webhook

# Development Flags
DEV_MODE=true
ENABLE_DEBUG_ENDPOINTS=true
EOF
    
    log_success ".env.example files created for all services"
}

# Execute main function
main "$@"