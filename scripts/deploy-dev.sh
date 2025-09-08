#!/bin/bash
# deploy-dev.sh
# KubeChat Phase 1 Model 1 Rancher Desktop Helm Deployment Automation
# Deploys complete KubeChat system to Rancher Desktop using Helm charts

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="${1:-kubechat-system}"
VALUES_FILE="${2:-deploy/helm/kubechat/values-dev-rancher.yaml}"
VERSION="${3:-dev}"
RELEASE_NAME="kubechat-dev"
HELM_CHART_PATH="./deploy/helm/kubechat"
TIMEOUT="10m"

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
    log_error "Deployment failed at line $1"
    log_error "KubeChat deployment to Rancher Desktop failed"
    
    # Show helpful debugging information
    log_info "Debugging Information:"
    kubectl get pods -n "$NAMESPACE" 2>/dev/null || true
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -10 2>/dev/null || true
    
    exit 1
}

trap 'error_handler $LINENO' ERR

# Verify prerequisites
verify_prerequisites() {
    log_info "Verifying deployment prerequisites..."
    
    # Verify we're in the correct directory
    if [[ ! -f "go.mod" ]] || [[ ! -d "cmd" ]] || [[ ! -d "pkg" ]]; then
        log_error "Must run from KubeChat project root directory"
        exit 1
    fi
    
    # Verify Kubernetes cluster accessibility
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Kubernetes cluster not accessible"
        log_error "Ensure Rancher Desktop is running and Kubernetes is enabled"
        exit 1
    fi
    
    # Verify Helm is available
    if ! command -v helm &>/dev/null; then
        log_error "Helm not found. Install Helm first"
        log_error "Run './scripts/setup-phase1-dev.sh' to set up development environment"
        exit 1
    fi
    
    # Verify Helm chart exists
    if [[ ! -d "$HELM_CHART_PATH" ]]; then
        log_error "Helm chart not found: $HELM_CHART_PATH"
        log_error "Ensure Task 2 (Helm Chart System) is completed"
        exit 1
    fi
    
    # Verify values file exists
    if [[ ! -f "$VALUES_FILE" ]]; then
        log_error "Values file not found: $VALUES_FILE"
        log_error "Ensure Task 4 (Configuration Templates) is completed"
        exit 1
    fi
    
    # Verify images exist in local registry
    log_info "Verifying container images in local registry..."
    if ! curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
        log_error "Local Docker registry not accessible at localhost:5001"
        log_error "Run './scripts/setup-phase1-dev.sh' first"
        exit 1
    fi
    
    # Check if images are built
    local services=("api-gateway" "audit-service" "operator" "web")
    for service in "${services[@]}"; do
        if ! docker image inspect "localhost:5001/kubechat/${service}:${VERSION}" &>/dev/null; then
            log_warning "Image not found: localhost:5001/kubechat/${service}:${VERSION}"
            log_warning "Run './scripts/build-kubechat-images.sh dev' first to build images"
        fi
    done
    
    log_success "Prerequisites verified"
}

# Build and push images if needed
build_images_if_needed() {
    local build_needed=false
    local services=("api-gateway" "audit-service" "operator" "web")
    
    for service in "${services[@]}"; do
        if ! docker image inspect "localhost:5001/kubechat/${service}:${VERSION}" &>/dev/null; then
            build_needed=true
            break
        fi
    done
    
    if [[ "$build_needed" == true ]]; then
        log_info "🏗️ Some images missing, building images first..."
        if [[ -f "./scripts/build-kubechat-images.sh dev" ]]; then
            ./scripts/build-kubechat-images.sh dev "$VERSION"
        else
            log_error "Build script not found. Ensure Task 1 is completed"
            exit 1
        fi
    else
        log_info "✅ All required images available"
    fi
}

# Validate Helm chart
validate_helm_chart() {
    log_info "🔍 Validating Helm chart..."
    
    # Lint the chart
    helm lint "$HELM_CHART_PATH" --values "$VALUES_FILE"
    
    # Dry run to validate templates
    helm install "$RELEASE_NAME" "$HELM_CHART_PATH" \
        --namespace "$NAMESPACE" \
        --values "$VALUES_FILE" \
        --set global.imageTag="$VERSION" \
        --dry-run --debug > /dev/null
    
    log_success "Helm chart validation passed"
}

# Deploy KubeChat using Helm
deploy_kubechat() {
    log_info "🚀 Deploying KubeChat to Rancher Desktop..."
    log_info "  Release: $RELEASE_NAME"
    log_info "  Namespace: $NAMESPACE"
    log_info "  Values file: $VALUES_FILE"
    log_info "  Version: $VERSION"
    log_info "  Timeout: $TIMEOUT"
    
    # Create namespace if it doesn't exist
    kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy or upgrade using Helm
    helm upgrade --install "$RELEASE_NAME" "$HELM_CHART_PATH" \
        --namespace "$NAMESPACE" \
        --values "$VALUES_FILE" \
        --set global.imageTag="$VERSION" \
        --wait \
        --timeout "$TIMEOUT" \
        --create-namespace
    
    log_success "Helm deployment completed"
}

# Wait for all pods to be ready
wait_for_pods() {
    log_info "⏳ Waiting for all pods to be ready..."
    
    # Wait for all pods in the namespace to be ready
    if kubectl wait --for=condition=Ready pod --all -n "$NAMESPACE" --timeout=300s; then
        log_success "All pods are ready"
    else
        log_error "Some pods failed to become ready within timeout"
        
        # Show pod status for debugging
        log_info "Current pod status:"
        kubectl get pods -n "$NAMESPACE" -o wide
        
        log_info "Recent events:"
        kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -20
        
        return 1
    fi
}

# Verify deployment health
verify_deployment() {
    log_info "🔍 Verifying deployment health..."
    
    # Check Helm release status
    log_info "Helm release status:"
    helm status "$RELEASE_NAME" -n "$NAMESPACE"
    
    # Show deployment status
    log_info "Deployment resources:"
    kubectl get all -n "$NAMESPACE"
    
    # Check service endpoints
    log_info "Service endpoints:"
    kubectl get endpoints -n "$NAMESPACE"
    
    # Test basic service connectivity
    log_info "Testing service connectivity..."
    
    # Test API Gateway service (if available)
    if kubectl get svc kubechat-api-gateway -n "$NAMESPACE" &>/dev/null; then
        log_info "API Gateway service detected"
        
        # Port forward temporarily to test connectivity
        kubectl port-forward -n "$NAMESPACE" svc/kubechat-api-gateway 8080:80 &
        local port_forward_pid=$!
        
        sleep 3
        
        # Test health endpoint
        if curl -f http://localhost:8080/health &>/dev/null; then
            log_success "✅ API Gateway health check passed"
        else
            log_warning "⚠️ API Gateway health check failed (service may still be starting)"
        fi
        
        # Clean up port forward
        kill $port_forward_pid &>/dev/null || true
    fi
    
    log_success "Deployment verification completed"
}

# Setup ingress access (optional)
setup_ingress_access() {
    log_info "🌐 Setting up ingress access..."
    
    # Check if ingress is configured
    if kubectl get ingress -n "$NAMESPACE" &>/dev/null; then
        log_info "Ingress configuration found:"
        kubectl get ingress -n "$NAMESPACE"
        
        # Show instructions for accessing the application
        local ingress_host
        ingress_host=$(kubectl get ingress -n "$NAMESPACE" -o jsonpath='{.items[0].spec.rules[0].host}' 2>/dev/null || echo "kubechat.local")
        
        log_info "📝 To access KubeChat web interface:"
        echo "  1. Add to /etc/hosts: 127.0.0.1 $ingress_host"
        echo "  2. Access application: http://$ingress_host"
    else
        log_info "No ingress configured, access via port forwarding"
    fi
}

# Display access information
display_access_info() {
    log_success "✅ KubeChat deployment completed successfully!"
    echo ""
    log_info "📋 Deployment Summary:"
    echo "  Release: $RELEASE_NAME"
    echo "  Namespace: $NAMESPACE"
    echo "  Version: $VERSION"
    echo ""
    
    log_info "📊 Pod Status:"
    kubectl get pods -n "$NAMESPACE"
    echo ""
    
    log_info "🔗 Services:"
    kubectl get svc -n "$NAMESPACE"
    echo ""
    
    log_info "🚀 Access Instructions:"
    echo "  API Gateway: kubectl port-forward -n $NAMESPACE svc/kubechat-api-gateway 8080:80"
    echo "  Web Interface: kubectl port-forward -n $NAMESPACE svc/kubechat-web 3000:80"
    echo "  PostgreSQL: kubectl port-forward -n $NAMESPACE svc/postgres-postgresql 5432:5432"
    echo "  Redis: kubectl port-forward -n $NAMESPACE svc/redis-master 6379:6379"
    echo ""
    
    log_info "🔧 Useful Commands:"
    echo "  Check logs: kubectl logs -f deployment/kubechat-api-gateway -n $NAMESPACE"
    echo "  Debug pod: kubectl describe pod <pod-name> -n $NAMESPACE"
    echo "  Helm status: helm status $RELEASE_NAME -n $NAMESPACE"
    echo "  Uninstall: helm uninstall $RELEASE_NAME -n $NAMESPACE"
    echo ""
    
    log_info "📝 Next Steps:"
    echo "  1. Run './scripts/test-phase1.sh' to validate the deployment"
    echo "  2. Run './scripts/test-airgap.sh' to test air-gap capabilities"
    echo "  3. Access the web interface using port forwarding instructions above"
}

# Rollback deployment (if needed)
rollback_deployment() {
    log_warning "⚠️ Rolling back deployment due to failure..."
    
    helm rollback "$RELEASE_NAME" -n "$NAMESPACE" || {
        log_error "Rollback failed, manual cleanup may be required"
        log_info "Manual cleanup commands:"
        echo "  helm uninstall $RELEASE_NAME -n $NAMESPACE"
        echo "  kubectl delete namespace $NAMESPACE"
    }
}

# Display usage information
usage() {
    echo "Usage: $0 [NAMESPACE] [VALUES_FILE] [VERSION]"
    echo ""
    echo "Deploy KubeChat Phase 1 Model 1 to Rancher Desktop using Helm"
    echo ""
    echo "Arguments:"
    echo "  NAMESPACE    Kubernetes namespace (default: kubechat-system)"
    echo "  VALUES_FILE  Helm values file (default: values-dev-rancher.yaml)"
    echo "  VERSION      Image version tag (default: dev)"
    echo ""
    echo "Options:"
    echo "  --help       Show this help message"
    echo "  --build      Force rebuild images before deployment"
    echo "  --dry-run    Perform dry run only"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Use defaults"
    echo "  $0 kubechat-test                      # Custom namespace"
    echo "  $0 kubechat-dev values-minimal.yaml   # Custom values file"
}

# Main execution
main() {
    local force_build=false
    local dry_run=false
    
    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                usage
                exit 0
                ;;
            --build)
                force_build=true
                shift
                ;;
            --dry-run)
                dry_run=true
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                # Handle positional arguments
                if [[ "${1:-}" != "" ]]; then
                    NAMESPACE="$1"
                fi
                if [[ "${2:-}" != "" ]]; then
                    VALUES_FILE="$2"
                fi
                if [[ "${3:-}" != "" ]]; then
                    VERSION="$3"
                fi
                break
                ;;
        esac
    done
    
    log_info "🚀 Starting KubeChat Phase 1 Model 1 deployment to Rancher Desktop..."
    
    verify_prerequisites
    
    if [[ "$force_build" == true ]]; then
        log_info "🔄 Force rebuilding images..."
        ./scripts/build-kubechat-images.sh dev "$VERSION"
    else
        build_images_if_needed
    fi
    
    validate_helm_chart
    
    if [[ "$dry_run" == true ]]; then
        log_info "🔍 Performing dry run only..."
        helm install "$RELEASE_NAME" "$HELM_CHART_PATH" \
            --namespace "$NAMESPACE" \
            --values "$VALUES_FILE" \
            --set global.imageTag="$VERSION" \
            --dry-run --debug
        log_success "Dry run completed successfully"
        return 0
    fi
    
    deploy_kubechat
    wait_for_pods
    verify_deployment
    setup_ingress_access
    display_access_info
    
    log_success "🎉 KubeChat deployment to Rancher Desktop completed successfully!"
}

# Execute main function
main "$@"