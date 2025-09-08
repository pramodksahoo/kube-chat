#!/bin/bash

# KubeChat Air-Gap Deployment Troubleshooting and Verification Tools
# Comprehensive debugging and problem resolution for air-gap deployments
# Usage: ./scripts/troubleshoot-airgap.sh [options]
# Author: Development Infrastructure Team
# Version: 1.0.0

set -euo pipefail

# =============================================================================
# SCRIPT CONFIGURATION
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_DIR="${PROJECT_ROOT}/logs"
LOG_FILE="${LOG_DIR}/airgap-troubleshoot_${TIMESTAMP}.log"

# Troubleshooting configuration
AIRGAP_NAMESPACE="kubechat-airgap"
LOCAL_REGISTRY="localhost:5001"
TROUBLESHOOT_MODE="interactive"  # interactive, automated, report

# Diagnostic configuration
CHECK_NETWORK=true
CHECK_IMAGES=true
CHECK_PODS=true
CHECK_SERVICES=true
CHECK_CONFIG=true
CHECK_LOGS=true
CHECK_RESOURCES=true
CHECK_EVENTS=true

# Output configuration
VERBOSE=false
COLLECT_LOGS=true
GENERATE_REPORT=true
SUGGEST_FIXES=true

# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] ${message}" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_warn() { log "WARN" "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }
log_debug() { [[ "$VERBOSE" == "true" ]] && log "DEBUG" "${BLUE}$*${NC}" || true; }

print_header() {
    echo -e "\n${PURPLE}===========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}===========================================${NC}\n"
}

print_section() {
    echo -e "\n${CYAN}--- $1 ---${NC}\n"
}

print_issue() {
    echo -e "\n${RED}🔥 ISSUE DETECTED${NC}"
    echo -e "${RED}$1${NC}"
}

print_suggestion() {
    echo -e "\n${YELLOW}💡 SUGGESTION${NC}"
    echo -e "${YELLOW}$1${NC}"
}

print_fix() {
    echo -e "\n${GREEN}🔧 RECOMMENDED FIX${NC}"
    echo -e "${GREEN}$1${NC}"
}

check_dependencies() {
    local deps=("kubectl" "docker" "helm" "curl" "jq")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        exit 1
    fi
    
    log_success "All dependencies available"
}

pause_for_user() {
    if [[ "$TROUBLESHOOT_MODE" == "interactive" ]]; then
        echo -e "\n${BLUE}Press Enter to continue or Ctrl+C to exit...${NC}"
        read -r
    fi
}

# =============================================================================
# DIAGNOSTIC FUNCTIONS
# =============================================================================

diagnose_cluster_connectivity() {
    print_section "Diagnosing Cluster Connectivity"
    
    local issues_found=0
    
    # Test kubectl connectivity
    log_info "Testing kubectl connectivity..."
    if ! kubectl cluster-info >/dev/null 2>&1; then
        print_issue "Cannot connect to Kubernetes cluster"
        print_suggestion "Check your kubeconfig file and cluster connectivity"
        print_fix "kubectl config view\nkubectl config current-context\nkubectl cluster-info"
        ((issues_found++))
    else
        log_success "Kubectl connectivity: OK"
    fi
    
    # Test namespace access
    log_info "Testing namespace access..."
    if ! kubectl get namespace "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
        print_issue "Cannot access namespace: $AIRGAP_NAMESPACE"
        print_suggestion "Namespace may not exist or you lack permissions"
        print_fix "kubectl get namespaces\nkubectl create namespace $AIRGAP_NAMESPACE"
        ((issues_found++))
    else
        log_success "Namespace access: OK"
    fi
    
    # Test RBAC permissions
    log_info "Testing RBAC permissions..."
    local permission_errors=0
    local required_permissions=(
        "get pods"
        "list pods"
        "get services"
        "get deployments"
        "describe pods"
        "logs pods"
    )
    
    for perm in "${required_permissions[@]}"; do
        if ! kubectl auth can-i $perm -n "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
            log_warn "Missing permission: $perm"
            ((permission_errors++))
        fi
    done
    
    if [[ $permission_errors -gt 0 ]]; then
        print_issue "Insufficient RBAC permissions ($permission_errors missing)"
        print_suggestion "Contact your cluster administrator for proper permissions"
        print_fix "kubectl auth can-i --list -n $AIRGAP_NAMESPACE"
        ((issues_found++))
    else
        log_success "RBAC permissions: OK"
    fi
    
    # Test node resources
    log_info "Testing cluster resources..."
    local node_count=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    local ready_nodes=$(kubectl get nodes --no-headers | grep -c " Ready " || echo "0")
    
    if [[ $ready_nodes -eq 0 ]]; then
        print_issue "No ready nodes available"
        print_suggestion "Check node status and ensure cluster is healthy"
        print_fix "kubectl get nodes\nkubectl describe nodes"
        ((issues_found++))
    else
        log_success "Cluster nodes: $ready_nodes/$node_count ready"
    fi
    
    return $issues_found
}

diagnose_network_isolation() {
    print_section "Diagnosing Network Isolation"
    
    if [[ "$CHECK_NETWORK" != "true" ]]; then
        log_info "Network diagnostics skipped (disabled)"
        return 0
    fi
    
    local issues_found=0
    
    # Check if local registry is accessible
    log_info "Testing local registry connectivity..."
    if ! curl -s "http://$LOCAL_REGISTRY/v2/" >/dev/null 2>&1; then
        print_issue "Local registry not accessible at $LOCAL_REGISTRY"
        print_suggestion "Start local registry or check port forwarding"
        print_fix "docker run -d -p 5000:5000 --name registry registry:2\ncurl http://localhost:5001/v2/"
        ((issues_found++))
    else
        log_success "Local registry: OK"
    fi
    
    # Test if air-gap simulation is active
    log_info "Checking air-gap simulation status..."
    if ! sudo iptables -L AIRGAP_BLOCK >/dev/null 2>&1; then
        print_issue "Air-gap network isolation not active"
        print_suggestion "Start air-gap simulation before testing"
        print_fix "./scripts/simulate-airgap.sh --start"
    else
        log_success "Air-gap network isolation: Active"
    fi
    
    # Create test pod for network testing
    log_info "Testing network isolation with test pod..."
    
    # Check if test pod already exists
    if kubectl get pod network-test -n "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
        kubectl delete pod network-test -n "$AIRGAP_NAMESPACE" --timeout=30s
    fi
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: network-test
  namespace: $AIRGAP_NAMESPACE
  labels:
    test: troubleshoot-network
spec:
  containers:
  - name: nettest
    image: nicolaka/netshoot:latest
    command: ['sleep', '300']
  restartPolicy: Never
EOF
    
    # Wait for pod to be ready
    local retry_count=0
    while [[ $retry_count -lt 30 ]]; do
        if kubectl get pod network-test -n "$AIRGAP_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null | grep -q "Running"; then
            break
        fi
        sleep 2
        ((retry_count++))
    done
    
    if [[ $retry_count -ge 30 ]]; then
        print_issue "Test pod failed to start"
        kubectl describe pod network-test -n "$AIRGAP_NAMESPACE" 2>/dev/null || true
        ((issues_found++))
    else
        # Test external connectivity (should fail in air-gap)
        log_info "Testing external connectivity blocking..."
        if kubectl exec -n "$AIRGAP_NAMESPACE" network-test -- timeout 10 ping -c 1 8.8.8.8 >/dev/null 2>&1; then
            print_issue "External connectivity not properly blocked"
            print_suggestion "Air-gap network isolation may not be working"
            print_fix "./scripts/simulate-airgap.sh --validate"
            ((issues_found++))
        else
            log_success "External connectivity: Properly blocked"
        fi
        
        # Test internal connectivity (should work)
        log_info "Testing internal cluster connectivity..."
        if ! kubectl exec -n "$AIRGAP_NAMESPACE" network-test -- timeout 10 ping -c 1 kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
            print_issue "Internal cluster connectivity failed"
            print_suggestion "Check cluster networking and DNS"
            print_fix "kubectl get svc -A\nkubectl get endpoints kubernetes"
            ((issues_found++))
        else
            log_success "Internal connectivity: OK"
        fi
    fi
    
    # Cleanup test pod
    kubectl delete pod network-test -n "$AIRGAP_NAMESPACE" --timeout=30s 2>/dev/null || true
    
    return $issues_found
}

diagnose_image_issues() {
    print_section "Diagnosing Image Issues"
    
    if [[ "$CHECK_IMAGES" != "true" ]]; then
        log_info "Image diagnostics skipped (disabled)"
        return 0
    fi
    
    local issues_found=0
    
    # Get all unique images used in the namespace
    local deployed_images=$(kubectl get pods -n "$AIRGAP_NAMESPACE" -o jsonpath='{.items[*].spec.containers[*].image}' 2>/dev/null | tr ' ' '\n' | sort -u)
    
    if [[ -z "$deployed_images" ]]; then
        print_issue "No pods found in namespace $AIRGAP_NAMESPACE"
        print_suggestion "Deploy KubeChat first or check namespace name"
        print_fix "helm list -n $AIRGAP_NAMESPACE\nkubectl get pods -A | grep kubechat"
        ((issues_found++))
        return $issues_found
    fi
    
    log_info "Found images in deployment:"
    for image in $deployed_images; do
        log_info "  - $image"
    done
    
    # Check each image
    for image in $deployed_images; do
        log_info "Diagnosing image: $image"
        
        # Check if image exists locally in Docker
        if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${image}$"; then
            print_issue "Image not found in local Docker: $image"
            print_suggestion "Pull or build the missing image"
            print_fix "docker pull $image\n# OR\n./scripts/build-dev-images.sh"
            ((issues_found++))
        else
            log_success "Image available locally: $image"
        fi
        
        # Test image pull policy
        local pods_with_image=$(kubectl get pods -n "$AIRGAP_NAMESPACE" -o json | jq -r ".items[] | select(.spec.containers[].image == \"$image\") | .metadata.name")
        
        for pod in $pods_with_image; do
            local pull_policy=$(kubectl get pod "$pod" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.spec.containers[0].imagePullPolicy}' 2>/dev/null)
            
            if [[ "$pull_policy" != "Never" ]]; then
                print_issue "Pod $pod has imagePullPolicy: $pull_policy (should be 'Never' for air-gap)"
                print_suggestion "Update deployment to use imagePullPolicy: Never"
                print_fix "kubectl patch deployment <deployment-name> -n $AIRGAP_NAMESPACE -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"<container-name>\",\"imagePullPolicy\":\"Never\"}]}}}}'"
                ((issues_found++))
            fi
        done
    done
    
    # Check for image pull errors
    local image_pull_errors=$(kubectl get events -n "$AIRGAP_NAMESPACE" --field-selector type=Warning 2>/dev/null | grep -i "pull" | head -5)
    
    if [[ -n "$image_pull_errors" ]]; then
        print_issue "Recent image pull errors detected:"
        echo "$image_pull_errors"
        print_suggestion "Check image availability and pull policies"
        print_fix "kubectl describe pod <failing-pod> -n $AIRGAP_NAMESPACE"
        ((issues_found++))
    fi
    
    return $issues_found
}

diagnose_pod_issues() {
    print_section "Diagnosing Pod Issues"
    
    if [[ "$CHECK_PODS" != "true" ]]; then
        log_info "Pod diagnostics skipped (disabled)"
        return 0
    fi
    
    local issues_found=0
    
    # Get all pods in namespace
    local pods=$(kubectl get pods -n "$AIRGAP_NAMESPACE" --no-headers 2>/dev/null || echo "")
    
    if [[ -z "$pods" ]]; then
        print_issue "No pods found in namespace $AIRGAP_NAMESPACE"
        print_suggestion "Deploy KubeChat or check namespace"
        print_fix "helm install kubechat ./deploy/helm/kubechat -n $AIRGAP_NAMESPACE"
        ((issues_found++))
        return $issues_found
    fi
    
    # Analyze each pod
    while IFS= read -r pod_line; do
        local pod_name=$(echo "$pod_line" | awk '{print $1}')
        local pod_ready=$(echo "$pod_line" | awk '{print $2}')
        local pod_status=$(echo "$pod_line" | awk '{print $3}')
        local pod_restarts=$(echo "$pod_line" | awk '{print $4}')
        local pod_age=$(echo "$pod_line" | awk '{print $5}')
        
        log_info "Analyzing pod: $pod_name (Status: $pod_status)"
        
        # Check pod status
        case $pod_status in
            "Running")
                if [[ "$pod_ready" == "1/1" ]] || [[ "$pod_ready" =~ ^[0-9]+\/[0-9]+$ && $(echo "$pod_ready" | cut -d'/' -f1) -eq $(echo "$pod_ready" | cut -d'/' -f2) ]]; then
                    log_success "Pod healthy: $pod_name"
                else
                    print_issue "Pod not ready: $pod_name ($pod_ready)"
                    print_suggestion "Check pod logs and events"
                    print_fix "kubectl describe pod $pod_name -n $AIRGAP_NAMESPACE\nkubectl logs $pod_name -n $AIRGAP_NAMESPACE"
                    ((issues_found++))
                fi
                ;;
            "Pending")
                print_issue "Pod stuck in Pending: $pod_name"
                print_suggestion "Check resource constraints, node affinity, and image availability"
                print_fix "kubectl describe pod $pod_name -n $AIRGAP_NAMESPACE\nkubectl get events -n $AIRGAP_NAMESPACE"
                ((issues_found++))
                ;;
            "CrashLoopBackOff"|"Error")
                print_issue "Pod failing: $pod_name (Status: $pod_status)"
                print_suggestion "Check application logs and configuration"
                print_fix "kubectl logs $pod_name -n $AIRGAP_NAMESPACE --previous\nkubectl describe pod $pod_name -n $AIRGAP_NAMESPACE"
                ((issues_found++))
                ;;
            "ImagePullBackOff"|"ErrImagePull")
                print_issue "Image pull failed: $pod_name"
                print_suggestion "Image not available locally or wrong pull policy"
                print_fix "docker images | grep <image-name>\nkubectl patch pod $pod_name -n $AIRGAP_NAMESPACE -p '{\"spec\":{\"containers\":[{\"name\":\"<container>\",\"imagePullPolicy\":\"Never\"}]}}'"
                ((issues_found++))
                ;;
            *)
                log_warn "Unknown pod status: $pod_name ($pod_status)"
                ;;
        esac
        
        # Check restart count
        if [[ "$pod_restarts" -gt 0 ]]; then
            print_issue "Pod has restarted: $pod_name ($pod_restarts times)"
            print_suggestion "Check application stability and resource limits"
            print_fix "kubectl logs $pod_name -n $AIRGAP_NAMESPACE --previous\nkubectl describe pod $pod_name -n $AIRGAP_NAMESPACE"
            ((issues_found++))
        fi
        
    done <<< "$pods"
    
    return $issues_found
}

diagnose_service_issues() {
    print_section "Diagnosing Service Issues"
    
    if [[ "$CHECK_SERVICES" != "true" ]]; then
        log_info "Service diagnostics skipped (disabled)"
        return 0
    fi
    
    local issues_found=0
    
    # Get all services
    local services=$(kubectl get services -n "$AIRGAP_NAMESPACE" --no-headers 2>/dev/null || echo "")
    
    if [[ -z "$services" ]]; then
        print_issue "No services found in namespace $AIRGAP_NAMESPACE"
        ((issues_found++))
        return $issues_found
    fi
    
    # Check each service
    while IFS= read -r svc_line; do
        local svc_name=$(echo "$svc_line" | awk '{print $1}')
        local svc_type=$(echo "$svc_line" | awk '{print $2}')
        local svc_cluster_ip=$(echo "$svc_line" | awk '{print $3}')
        
        log_info "Analyzing service: $svc_name"
        
        # Check if service has endpoints
        local endpoints=$(kubectl get endpoints "$svc_name" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo "")
        
        if [[ -z "$endpoints" ]]; then
            print_issue "Service has no endpoints: $svc_name"
            print_suggestion "No pods match the service selector"
            print_fix "kubectl describe service $svc_name -n $AIRGAP_NAMESPACE\nkubectl get pods -n $AIRGAP_NAMESPACE --show-labels"
            ((issues_found++))
        else
            log_success "Service has endpoints: $svc_name"
        fi
        
        # Test service connectivity (basic)
        if [[ "$svc_name" == "kubechat-api-gateway" ]]; then
            log_info "Testing API Gateway service..."
            
            # Port forward test
            kubectl port-forward -n "$AIRGAP_NAMESPACE" service/"$svc_name" 18080:8080 &
            local pf_pid=$!
            
            sleep 3
            
            if timeout 10 curl -s http://localhost:18080/health >/dev/null 2>&1; then
                log_success "API Gateway health check: OK"
            else
                print_issue "API Gateway health check failed"
                print_suggestion "Service may not be responding correctly"
                print_fix "kubectl logs -l app=kubechat-api-gateway -n $AIRGAP_NAMESPACE\nkubectl describe service $svc_name -n $AIRGAP_NAMESPACE"
                ((issues_found++))
            fi
            
            kill $pf_pid 2>/dev/null || true
        fi
        
    done <<< "$services"
    
    return $issues_found
}

diagnose_configuration() {
    print_section "Diagnosing Configuration Issues"
    
    if [[ "$CHECK_CONFIG" != "true" ]]; then
        log_info "Configuration diagnostics skipped (disabled)"
        return 0
    fi
    
    local issues_found=0
    
    # Check ConfigMaps
    log_info "Checking ConfigMaps..."
    local configmaps=$(kubectl get configmaps -n "$AIRGAP_NAMESPACE" --no-headers 2>/dev/null | wc -l)
    log_info "Found $configmaps ConfigMaps"
    
    # Check Secrets
    log_info "Checking Secrets..."
    local secrets=$(kubectl get secrets -n "$AIRGAP_NAMESPACE" --no-headers 2>/dev/null | wc -l)
    log_info "Found $secrets Secrets"
    
    # Check PersistentVolumeClaims
    log_info "Checking PersistentVolumeClaims..."
    local pvcs=$(kubectl get pvc -n "$AIRGAP_NAMESPACE" --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$pvcs" ]]; then
        while IFS= read -r pvc_line; do
            local pvc_name=$(echo "$pvc_line" | awk '{print $1}')
            local pvc_status=$(echo "$pvc_line" | awk '{print $2}')
            
            if [[ "$pvc_status" != "Bound" ]]; then
                print_issue "PVC not bound: $pvc_name (Status: $pvc_status)"
                print_suggestion "Check storage class and persistent volume availability"
                print_fix "kubectl describe pvc $pvc_name -n $AIRGAP_NAMESPACE\nkubectl get pv"
                ((issues_found++))
            else
                log_success "PVC bound: $pvc_name"
            fi
        done <<< "$pvcs"
    fi
    
    # Check Helm release
    log_info "Checking Helm release..."
    local helm_releases=$(helm list -n "$AIRGAP_NAMESPACE" 2>/dev/null || echo "")
    
    if [[ -z "$helm_releases" ]]; then
        print_issue "No Helm releases found in namespace"
        print_suggestion "KubeChat may not be deployed via Helm"
        print_fix "helm list -A | grep kubechat\nkubectl get deployments -n $AIRGAP_NAMESPACE"
        ((issues_found++))
    else
        log_info "Helm releases found:"
        echo "$helm_releases"
    fi
    
    return $issues_found
}

collect_logs() {
    print_section "Collecting Logs and Diagnostics"
    
    if [[ "$COLLECT_LOGS" != "true" ]]; then
        log_info "Log collection skipped (disabled)"
        return 0
    fi
    
    local diagnostics_dir="${LOG_DIR}/diagnostics_${TIMESTAMP}"
    mkdir -p "$diagnostics_dir"
    
    log_info "Collecting diagnostics to: $diagnostics_dir"
    
    # Collect pod logs
    local pods=$(kubectl get pods -n "$AIRGAP_NAMESPACE" -o name 2>/dev/null || echo "")
    
    if [[ -n "$pods" ]]; then
        while IFS= read -r pod; do
            local pod_name=$(echo "$pod" | sed 's|pod/||')
            log_info "Collecting logs for: $pod_name"
            
            # Current logs
            kubectl logs "$pod" -n "$AIRGAP_NAMESPACE" > "$diagnostics_dir/${pod_name}.log" 2>&1 || true
            
            # Previous logs (if available)
            kubectl logs "$pod" -n "$AIRGAP_NAMESPACE" --previous > "$diagnostics_dir/${pod_name}.previous.log" 2>&1 || true
            
            # Pod description
            kubectl describe pod "$pod_name" -n "$AIRGAP_NAMESPACE" > "$diagnostics_dir/${pod_name}.describe.txt" 2>&1 || true
            
        done <<< "$pods"
    fi
    
    # Collect service information
    kubectl get services -n "$AIRGAP_NAMESPACE" -o yaml > "$diagnostics_dir/services.yaml" 2>&1 || true
    
    # Collect events
    kubectl get events -n "$AIRGAP_NAMESPACE" --sort-by='.lastTimestamp' > "$diagnostics_dir/events.txt" 2>&1 || true
    
    # Collect deployment information
    kubectl get deployments -n "$AIRGAP_NAMESPACE" -o yaml > "$diagnostics_dir/deployments.yaml" 2>&1 || true
    
    # Collect configmaps and secrets (names only for security)
    kubectl get configmaps -n "$AIRGAP_NAMESPACE" > "$diagnostics_dir/configmaps.txt" 2>&1 || true
    kubectl get secrets -n "$AIRGAP_NAMESPACE" > "$diagnostics_dir/secrets.txt" 2>&1 || true
    
    # Collect PVC information
    kubectl get pvc -n "$AIRGAP_NAMESPACE" -o yaml > "$diagnostics_dir/pvc.yaml" 2>&1 || true
    
    # Collect Helm information
    helm list -n "$AIRGAP_NAMESPACE" > "$diagnostics_dir/helm.txt" 2>&1 || true
    
    # Collect cluster information
    kubectl cluster-info > "$diagnostics_dir/cluster-info.txt" 2>&1 || true
    kubectl get nodes > "$diagnostics_dir/nodes.txt" 2>&1 || true
    
    # Collect Docker information
    docker images > "$diagnostics_dir/docker-images.txt" 2>&1 || true
    docker ps > "$diagnostics_dir/docker-containers.txt" 2>&1 || true
    
    # Create diagnostic summary
    cat > "$diagnostics_dir/summary.txt" <<EOF
KubeChat Air-Gap Deployment Diagnostics
=======================================

Generated: $(date)
Namespace: $AIRGAP_NAMESPACE
Troubleshooting Mode: $TROUBLESHOOT_MODE

Files in this diagnostic package:
- *.log: Pod logs (current and previous)
- *.describe.txt: Pod descriptions
- services.yaml: Service configurations
- events.txt: Kubernetes events
- deployments.yaml: Deployment configurations
- cluster-info.txt: Cluster information
- nodes.txt: Node status
- docker-*.txt: Docker information

To analyze:
1. Check events.txt for recent errors
2. Review pod logs for application issues
3. Check service configurations for networking problems
4. Verify deployments for configuration issues
EOF
    
    log_success "Diagnostics collected to: $diagnostics_dir"
    
    # Create tar archive
    local archive_file="${LOG_DIR}/kubechat-diagnostics_${TIMESTAMP}.tar.gz"
    tar -czf "$archive_file" -C "$LOG_DIR" "diagnostics_${TIMESTAMP}"
    
    log_success "Diagnostic archive created: $archive_file"
}

# =============================================================================
# AUTOMATED FIX SUGGESTIONS
# =============================================================================

suggest_common_fixes() {
    print_section "Common Air-Gap Deployment Issues and Fixes"
    
    if [[ "$SUGGEST_FIXES" != "true" ]]; then
        log_info "Fix suggestions skipped (disabled)"
        return 0
    fi
    
    cat <<EOF

${YELLOW}Common Issues and Solutions:${NC}

1. ${RED}Images not available locally${NC}
   ${YELLOW}Solution:${NC}
   • Build images: ./scripts/build-dev-images.sh --airgap
   • Load from bundle: ./scripts/load-images.sh
   • Check image tags match deployment

2. ${RED}External connectivity not blocked${NC}
   ${YELLOW}Solution:${NC}
   • Start air-gap simulation: ./scripts/simulate-airgap.sh --start
   • Validate isolation: ./scripts/simulate-airgap.sh --validate
   • Check iptables rules

3. ${RED}Pods stuck in ImagePullBackOff${NC}
   ${YELLOW}Solution:${NC}
   • Ensure imagePullPolicy: Never
   • Verify images exist locally: docker images
   • Check image names match exactly

4. ${RED}Services not accessible${NC}
   ${YELLOW}Solution:${NC}
   • Check pod readiness: kubectl get pods
   • Verify service selectors: kubectl describe service
   • Test port forwarding: kubectl port-forward

5. ${RED}Database connection failures${NC}
   ${YELLOW}Solution:${NC}
   • Check PVC status: kubectl get pvc
   • Verify database pod logs
   • Check connection strings and secrets

6. ${RED}Network policies blocking traffic${NC}
   ${YELLOW}Solution:${NC}
   • Review network policies: kubectl get networkpolicy
   • Allow internal cluster communication
   • Test with policy disabled temporarily

${YELLOW}Quick Diagnostic Commands:${NC}

# Check overall status
kubectl get pods,svc,pvc -n $AIRGAP_NAMESPACE

# View recent events
kubectl get events -n $AIRGAP_NAMESPACE --sort-by='.lastTimestamp'

# Check image pull policies
kubectl get pods -n $AIRGAP_NAMESPACE -o jsonpath='{.items[*].spec.containers[*].imagePullPolicy}' | tr ' ' '\n' | sort -u

# Test service connectivity
kubectl port-forward -n $AIRGAP_NAMESPACE svc/kubechat-api-gateway 8080:8080

# Check Helm status
helm status kubechat -n $AIRGAP_NAMESPACE

EOF
    
    pause_for_user
}

generate_troubleshooting_report() {
    print_section "Generating Troubleshooting Report"
    
    if [[ "$GENERATE_REPORT" != "true" ]]; then
        log_info "Report generation skipped (disabled)"
        return 0
    fi
    
    local report_file="${LOG_DIR}/troubleshooting-report_${TIMESTAMP}.md"
    
    cat > "$report_file" <<EOF
# KubeChat Air-Gap Deployment Troubleshooting Report

**Generated:** $(date)  
**Namespace:** $AIRGAP_NAMESPACE  
**Mode:** $TROUBLESHOOT_MODE

## Summary

This report contains diagnostic information for troubleshooting KubeChat air-gap deployment issues.

## Cluster Information

\`\`\`
$(kubectl cluster-info 2>/dev/null || echo "Cluster info not available")
\`\`\`

## Namespace Status

### Pods
\`\`\`
$(kubectl get pods -n "$AIRGAP_NAMESPACE" 2>/dev/null || echo "No pods found")
\`\`\`

### Services
\`\`\`
$(kubectl get services -n "$AIRGAP_NAMESPACE" 2>/dev/null || echo "No services found")
\`\`\`

### Recent Events
\`\`\`
$(kubectl get events -n "$AIRGAP_NAMESPACE" --sort-by='.lastTimestamp' | tail -10 2>/dev/null || echo "No events found")
\`\`\`

## Diagnostic Results

$(cat "$LOG_FILE")

## Recommendations

1. Review the diagnostic log for specific issues
2. Check the collected diagnostics bundle
3. Follow the suggested fixes for identified problems
4. Re-run validation after applying fixes

## Support Information

- Log file: $LOG_FILE
- Diagnostic bundle: $(ls ${LOG_DIR}/kubechat-diagnostics_${TIMESTAMP}.tar.gz 2>/dev/null || echo "Not generated")
- Troubleshooting guide: docs/troubleshooting.md

EOF
    
    log_success "Troubleshooting report generated: $report_file"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Air-Gap Deployment Troubleshooting Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --namespace NAME         Target namespace (default: $AIRGAP_NAMESPACE)
    --mode MODE             Troubleshooting mode: interactive, automated, report (default: $TROUBLESHOOT_MODE)
    --no-network            Skip network diagnostics
    --no-images             Skip image diagnostics
    --no-pods               Skip pod diagnostics
    --no-services           Skip service diagnostics
    --no-config             Skip configuration diagnostics
    --no-logs               Skip log collection
    --no-report             Skip report generation
    --no-suggestions        Skip fix suggestions
    --verbose               Enable verbose logging
    --help                  Show this help message

EXAMPLES:
    # Interactive troubleshooting (default)
    $0

    # Automated diagnostics with report
    $0 --mode automated

    # Quick pod and service check
    $0 --mode automated --no-network --no-images --no-config

    # Full diagnostic with verbose output
    $0 --verbose --mode report
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --namespace)
                AIRGAP_NAMESPACE="$2"
                shift 2
                ;;
            --mode)
                TROUBLESHOOT_MODE="$2"
                shift 2
                ;;
            --no-network)
                CHECK_NETWORK=false
                shift
                ;;
            --no-images)
                CHECK_IMAGES=false
                shift
                ;;
            --no-pods)
                CHECK_PODS=false
                shift
                ;;
            --no-services)
                CHECK_SERVICES=false
                shift
                ;;
            --no-config)
                CHECK_CONFIG=false
                shift
                ;;
            --no-logs)
                COLLECT_LOGS=false
                shift
                ;;
            --no-report)
                GENERATE_REPORT=false
                shift
                ;;
            --no-suggestions)
                SUGGEST_FIXES=false
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

run_troubleshooting_suite() {
    local total_issues=0
    
    # Run diagnostic functions
    diagnose_cluster_connectivity || ((total_issues+=$?))
    diagnose_network_isolation || ((total_issues+=$?))
    diagnose_image_issues || ((total_issues+=$?))
    diagnose_pod_issues || ((total_issues+=$?))
    diagnose_service_issues || ((total_issues+=$?))
    diagnose_configuration || ((total_issues+=$?))
    
    # Collect additional diagnostics
    collect_logs
    
    # Provide suggestions
    suggest_common_fixes
    
    return $total_issues
}

main() {
    parse_arguments "$@"
    
    print_header "KubeChat Air-Gap Deployment Troubleshooting"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Troubleshooting session starting"
    log_info "Mode: $TROUBLESHOOT_MODE"
    log_info "Target namespace: $AIRGAP_NAMESPACE"
    log_info "Log file: $LOG_FILE"
    
    # Check dependencies
    check_dependencies
    
    # Run troubleshooting suite
    log_info "Running troubleshooting diagnostics..."
    
    if run_troubleshooting_suite; then
        log_success "No critical issues detected! ✅"
        log_info "Air-gap deployment appears to be healthy"
    else
        log_warn "Issues detected during troubleshooting ⚠️"
        log_info "Review the diagnostic output and apply suggested fixes"
    fi
    
    # Generate final report
    generate_troubleshooting_report
    
    print_header "Troubleshooting Complete"
    
    log_success "Troubleshooting session completed"
    log_info "Review the generated report and diagnostic files"
    log_info "Log file: $LOG_FILE"
    
    if [[ "$TROUBLESHOOT_MODE" == "interactive" ]]; then
        echo -e "\n${YELLOW}Next steps:${NC}"
        echo -e "1. Review identified issues and suggested fixes"
        echo -e "2. Apply fixes and re-run troubleshooting"
        echo -e "3. Use './scripts/validate-airgap.sh' for validation"
        echo -e "4. Check the diagnostic bundle for detailed logs"
    fi
}

# Execute main function with all arguments
main "$@"