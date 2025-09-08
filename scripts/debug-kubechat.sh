#!/bin/bash
# debug-kubechat.sh
# KubeChat Phase 1 Model 1 Development Debugging and Troubleshooting Utilities
# Comprehensive debugging tools for development environment

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="${1:-kubechat-system}"
DEFAULT_LINES=50

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

log_section() {
    echo ""
    echo -e "${CYAN}=================================================="
    echo -e "📊 $1"
    echo -e "==================================================${NC}"
}

# Display cluster information
debug_cluster_info() {
    log_section "Kubernetes Cluster Information"
    
    log_info "Cluster Overview:"
    kubectl cluster-info 2>/dev/null || log_error "Cannot access cluster info"
    
    echo ""
    log_info "Node Information:"
    kubectl get nodes -o wide 2>/dev/null || log_error "Cannot get node information"
    
    echo ""
    log_info "Cluster Version:"
    kubectl version --short 2>/dev/null || log_warning "Cannot get cluster version"
    
    echo ""
    log_info "Storage Classes:"
    kubectl get storageclass 2>/dev/null || log_warning "Cannot get storage classes"
}

# Display namespace resources
debug_namespace_resources() {
    log_section "Namespace: $NAMESPACE Resources"
    
    # Check if namespace exists
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_error "Namespace $NAMESPACE does not exist"
        return 1
    fi
    
    log_info "All Resources in $NAMESPACE:"
    kubectl get all -n "$NAMESPACE" -o wide 2>/dev/null || log_error "Cannot get resources in namespace"
    
    echo ""
    log_info "Persistent Volume Claims:"
    kubectl get pvc -n "$NAMESPACE" -o wide 2>/dev/null || log_info "No PVCs found"
    
    echo ""
    log_info "ConfigMaps and Secrets:"
    kubectl get configmaps,secrets -n "$NAMESPACE" 2>/dev/null || log_info "No ConfigMaps/Secrets found"
    
    echo ""
    log_info "Ingress Resources:"
    kubectl get ingress -n "$NAMESPACE" -o wide 2>/dev/null || log_info "No Ingress resources found"
    
    echo ""
    log_info "Network Policies:"
    kubectl get networkpolicy -n "$NAMESPACE" 2>/dev/null || log_info "No Network Policies found"
}

# Debug pod status and logs
debug_pods() {
    log_section "Pod Debugging"
    
    local pods
    pods=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | awk '{print $1}' || echo "")
    
    if [[ -z "$pods" ]]; then
        log_warning "No pods found in namespace $NAMESPACE"
        return 0
    fi
    
    for pod in $pods; do
        echo ""
        log_info "🔍 Debugging Pod: $pod"
        echo "----------------------------------------"
        
        # Pod status
        log_info "Pod Status:"
        kubectl get pod "$pod" -n "$NAMESPACE" -o wide
        
        # Pod description (last 20 lines for events)
        echo ""
        log_info "Recent Events:"
        kubectl describe pod "$pod" -n "$NAMESPACE" | tail -20
        
        # Check if pod is running for logs
        local pod_status
        pod_status=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")
        
        if [[ "$pod_status" != "Pending" ]]; then
            echo ""
            log_info "Recent Logs (last $DEFAULT_LINES lines):"
            kubectl logs "$pod" -n "$NAMESPACE" --tail=$DEFAULT_LINES 2>/dev/null || log_warning "Cannot get logs for $pod"
            
            # Check for previous container logs if pod restarted
            local restart_count
            restart_count=$(kubectl get pod "$pod" -n "$NAMESPACE" -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
            
            if [[ "$restart_count" != "0" ]]; then
                echo ""
                log_warning "Pod has restarted $restart_count times. Previous logs:"
                kubectl logs "$pod" -n "$NAMESPACE" --previous --tail=20 2>/dev/null || log_warning "No previous logs available"
            fi
        else
            log_info "Pod is in Pending state, no logs available yet"
        fi
        
        # Resource usage (if metrics server available)
        echo ""
        log_info "Resource Usage:"
        kubectl top pod "$pod" -n "$NAMESPACE" 2>/dev/null || log_info "Metrics not available (metrics-server not installed)"
    done
}

# Debug services and endpoints
debug_services() {
    log_section "Service and Endpoint Debugging"
    
    log_info "Services in $NAMESPACE:"
    kubectl get services -n "$NAMESPACE" -o wide
    
    echo ""
    log_info "Endpoints:"
    kubectl get endpoints -n "$NAMESPACE" -o wide
    
    echo ""
    local services
    services=$(kubectl get services -n "$NAMESPACE" --no-headers -o custom-columns=":metadata.name" 2>/dev/null || echo "")
    
    for service in $services; do
        if [[ "$service" != "kubernetes" ]]; then
            echo ""
            log_info "🔍 Service Details: $service"
            kubectl describe service "$service" -n "$NAMESPACE"
        fi
    done
}

# Debug Helm releases
debug_helm() {
    log_section "Helm Release Debugging"
    
    if ! command -v helm &>/dev/null; then
        log_error "Helm not found"
        return 1
    fi
    
    log_info "Helm Releases in $NAMESPACE:"
    helm list -n "$NAMESPACE" 2>/dev/null || log_info "No Helm releases found"
    
    # Check for KubeChat release specifically
    local release_name="kubechat-dev"
    if helm status "$release_name" -n "$NAMESPACE" &>/dev/null; then
        echo ""
        log_info "🔍 KubeChat Helm Release Status:"
        helm status "$release_name" -n "$NAMESPACE"
        
        echo ""
        log_info "Helm Release Values:"
        helm get values "$release_name" -n "$NAMESPACE" || log_warning "Cannot get release values"
        
        echo ""
        log_info "Helm Release History:"
        helm history "$release_name" -n "$NAMESPACE" || log_warning "Cannot get release history"
    else
        log_info "KubeChat Helm release not found"
    fi
}

# Debug local registry
debug_local_registry() {
    log_section "Local Docker Registry Debugging"
    
    # Check if registry is running
    if docker ps | grep -q "registry:2"; then
        log_success "Local registry container is running"
        docker ps | grep "registry:2"
    else
        log_error "Local registry container not running"
        log_info "Start with: docker run -d -p 5000:5000 --restart=always --name local-registry registry:2"
        return 1
    fi
    
    echo ""
    # Check registry connectivity
    if curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
        log_success "Registry is accessible at localhost:5001"
        
        log_info "Repositories in registry:"
        curl -s http://localhost:5001/v2/_catalog | jq -r '.repositories[]' 2>/dev/null || {
            log_warning "jq not available, raw output:"
            curl -s http://localhost:5001/v2/_catalog
        }
        
        # Show KubeChat images
        echo ""
        log_info "KubeChat images in registry:"
        for repo in $(curl -s http://localhost:5001/v2/_catalog | jq -r '.repositories[]' 2>/dev/null | grep kubechat || true); do
            echo "  📦 $repo"
            local tags
            tags=$(curl -s "http://localhost:5001/v2/$repo/tags/list" | jq -r '.tags[]' 2>/dev/null || echo "unknown")
            for tag in $tags; do
                echo "    🏷️ $tag"
            done
        done
    else
        log_error "Registry not accessible at localhost:5001"
    fi
}

# Debug container images
debug_images() {
    log_section "Container Image Debugging"
    
    log_info "Docker Images (KubeChat related):"
    docker images | grep -E "(kubechat|localhost:5001)" || log_info "No KubeChat images found locally"
    
    echo ""
    log_info "Image Disk Usage:"
    docker system df
}

# Debug network connectivity
debug_networking() {
    log_section "Network Connectivity Debugging"
    
    # Test cluster networking
    log_info "Cluster DNS Resolution Test:"
    if kubectl run test-dns --image=busybox --rm -it --restart=Never -- nslookup kubernetes.default &>/dev/null; then
        log_success "Cluster DNS working"
    else
        log_error "Cluster DNS issues detected"
    fi
    
    echo ""
    log_info "Service Connectivity Tests:"
    
    # Test service connectivity from within cluster
    local services=("postgres-postgresql" "redis-master" "kubechat-api-gateway")
    for service in "${services[@]}"; do
        if kubectl get service "$service" -n "$NAMESPACE" &>/dev/null; then
            log_info "Testing connectivity to $service..."
            
            # Create a temporary pod for testing
            kubectl run network-test --image=busybox --rm -it --restart=Never -- /bin/sh -c "
                timeout 5 nc -z $service.$NAMESPACE.svc.cluster.local 80 2>/dev/null || 
                timeout 5 nc -z $service.$NAMESPACE.svc.cluster.local 5432 2>/dev/null ||
                timeout 5 nc -z $service.$NAMESPACE.svc.cluster.local 6379 2>/dev/null
            " && log_success "$service is reachable" || log_warning "$service connectivity test failed"
        fi
    done
}

# Debug persistent storage
debug_storage() {
    log_section "Persistent Storage Debugging"
    
    log_info "Persistent Volumes:"
    kubectl get pv 2>/dev/null || log_info "No persistent volumes"
    
    echo ""
    log_info "Persistent Volume Claims in $NAMESPACE:"
    kubectl get pvc -n "$NAMESPACE" -o wide 2>/dev/null || log_info "No PVCs in namespace"
    
    echo ""
    log_info "Storage Classes:"
    kubectl get storageclass 2>/dev/null || log_info "No storage classes available"
    
    # Check PVC details if any exist
    local pvcs
    pvcs=$(kubectl get pvc -n "$NAMESPACE" --no-headers -o custom-columns=":metadata.name" 2>/dev/null || echo "")
    
    for pvc in $pvcs; do
        if [[ -n "$pvc" ]]; then
            echo ""
            log_info "🔍 PVC Details: $pvc"
            kubectl describe pvc "$pvc" -n "$NAMESPACE"
        fi
    done
}

# Debug resource usage
debug_resource_usage() {
    log_section "Resource Usage Debugging"
    
    # Check if metrics server is available
    if kubectl top nodes &>/dev/null; then
        log_info "Node Resource Usage:"
        kubectl top nodes
        
        echo ""
        log_info "Pod Resource Usage in $NAMESPACE:"
        kubectl top pods -n "$NAMESPACE" || log_info "No pods in namespace"
    else
        log_warning "Metrics server not available - install metrics-server for resource monitoring"
        
        # Show resource requests/limits instead
        echo ""
        log_info "Pod Resource Requests/Limits:"
        kubectl get pods -n "$NAMESPACE" -o custom-columns="POD:.metadata.name,CPU-REQ:.spec.containers[*].resources.requests.cpu,CPU-LIM:.spec.containers[*].resources.limits.cpu,MEM-REQ:.spec.containers[*].resources.requests.memory,MEM-LIM:.spec.containers[*].resources.limits.memory" 2>/dev/null || log_info "No pods to analyze"
    fi
}

# Debug events
debug_events() {
    log_section "Recent Events"
    
    log_info "Recent Events in $NAMESPACE (last 20):"
    kubectl get events -n "$NAMESPACE" --sort-by='.lastTimestamp' | tail -20 || log_info "No events found"
    
    echo ""
    log_info "Warning Events in $NAMESPACE:"
    kubectl get events -n "$NAMESPACE" --field-selector type=Warning || log_info "No warning events"
}

# Quick health check
quick_health_check() {
    log_section "Quick Health Check"
    
    local issues=0
    
    # Check cluster
    if ! kubectl cluster-info &>/dev/null; then
        log_error "❌ Kubernetes cluster not accessible"
        issues=$((issues + 1))
    else
        log_success "✅ Kubernetes cluster accessible"
    fi
    
    # Check namespace
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_error "❌ Namespace $NAMESPACE not found"
        issues=$((issues + 1))
    else
        log_success "✅ Namespace $NAMESPACE exists"
    fi
    
    # Check pods
    local pod_count ready_count
    pod_count=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
    ready_count=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | grep -c " Running \| Succeeded " || echo "0")
    
    if [[ $pod_count -gt 0 ]]; then
        if [[ $ready_count -eq $pod_count ]]; then
            log_success "✅ All $pod_count pods are running"
        else
            log_error "❌ Only $ready_count/$pod_count pods are running"
            issues=$((issues + 1))
        fi
    else
        log_warning "⚠️ No pods found in namespace"
    fi
    
    # Check local registry
    if curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
        log_success "✅ Local Docker registry accessible"
    else
        log_error "❌ Local Docker registry not accessible"
        issues=$((issues + 1))
    fi
    
    # Check Helm
    if command -v helm &>/dev/null && helm list -n "$NAMESPACE" &>/dev/null; then
        log_success "✅ Helm accessible"
    else
        log_error "❌ Helm issues detected"
        issues=$((issues + 1))
    fi
    
    echo ""
    if [[ $issues -eq 0 ]]; then
        log_success "🎉 No critical issues detected!"
    else
        log_error "⚠️ $issues issue(s) detected. See detailed debugging output above."
    fi
}

# Display usage information
usage() {
    echo "Usage: $0 [NAMESPACE] [OPTIONS]"
    echo ""
    echo "KubeChat Phase 1 Model 1 debugging and troubleshooting utilities"
    echo ""
    echo "Arguments:"
    echo "  NAMESPACE    Kubernetes namespace (default: kubechat-system)"
    echo ""
    echo "Options:"
    echo "  --quick      Quick health check only"
    echo "  --pods       Debug pods only"
    echo "  --services   Debug services only"
    echo "  --helm       Debug Helm releases only"
    echo "  --registry   Debug local registry only"
    echo "  --network    Debug networking only"
    echo "  --storage    Debug storage only"
    echo "  --events     Show recent events only"
    echo "  --all        Full debugging (default)"
    echo "  --help       Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                      # Full debugging of default namespace"
    echo "  $0 --quick             # Quick health check"
    echo "  $0 kubechat-test       # Debug specific namespace"
    echo "  $0 --pods --services   # Debug pods and services only"
}

# Main execution
main() {
    local mode="all"
    local selected_debugs=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                usage
                exit 0
                ;;
            --quick)
                mode="quick"
                shift
                ;;
            --pods)
                selected_debugs+=("pods")
                mode="selective"
                shift
                ;;
            --services)
                selected_debugs+=("services")
                mode="selective"
                shift
                ;;
            --helm)
                selected_debugs+=("helm")
                mode="selective"
                shift
                ;;
            --registry)
                selected_debugs+=("registry")
                mode="selective"
                shift
                ;;
            --network)
                selected_debugs+=("network")
                mode="selective"
                shift
                ;;
            --storage)
                selected_debugs+=("storage")
                mode="selective"
                shift
                ;;
            --events)
                selected_debugs+=("events")
                mode="selective"
                shift
                ;;
            --all)
                mode="all"
                shift
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                NAMESPACE="$1"
                shift
                ;;
        esac
    done
    
    log_info "🔧 KubeChat Phase 1 Model 1 Debug Utility"
    log_info "Namespace: $NAMESPACE"
    log_info "Mode: $mode"
    
    case $mode in
        quick)
            quick_health_check
            ;;
        selective)
            for debug_type in "${selected_debugs[@]}"; do
                case $debug_type in
                    pods) debug_pods ;;
                    services) debug_services ;;
                    helm) debug_helm ;;
                    registry) debug_local_registry ;;
                    network) debug_networking ;;
                    storage) debug_storage ;;
                    events) debug_events ;;
                esac
            done
            ;;
        all|*)
            quick_health_check
            debug_cluster_info
            debug_namespace_resources
            debug_pods
            debug_services
            debug_helm
            debug_local_registry
            debug_images
            debug_networking
            debug_storage
            debug_resource_usage
            debug_events
            ;;
    esac
    
    echo ""
    log_success "🔧 Debug analysis completed for $NAMESPACE"
}

# Execute main function
main "$@"