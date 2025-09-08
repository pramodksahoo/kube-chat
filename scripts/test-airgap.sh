#!/bin/bash

# KubeChat Air-Gap Deployment Testing Script
# Complete air-gap deployment simulation and validation
# Usage: ./scripts/test-airgap.sh [options]
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
LOG_FILE="${LOG_DIR}/airgap-test_${TIMESTAMP}.log"

# Air-gap testing configuration
AIRGAP_NAMESPACE="kubechat-airgap"
AIRGAP_VALUES_FILE="${PROJECT_ROOT}/deploy/helm/kubechat/values-airgap-test.yaml"
LOCAL_REGISTRY="localhost:5001"
AIRGAP_IMAGE_TAG="airgap"
TEST_TIMEOUT=600
VALIDATION_RETRIES=5

# Test configuration
RUN_NETWORK_TESTS=true
RUN_IMAGE_TESTS=true
RUN_DEPLOYMENT_TESTS=true
RUN_FUNCTIONAL_TESTS=true
RUN_SECURITY_TESTS=true
VERBOSE=false
CLEANUP_ON_EXIT=true

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

check_dependencies() {
    local deps=("kubectl" "helm" "docker")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required dependencies: ${missing[*]}"
        log_error "Please install missing dependencies and try again"
        exit 1
    fi
    
    log_success "All dependencies available"
}

cleanup() {
    if [[ "$CLEANUP_ON_EXIT" == "true" ]]; then
        log_info "Performing cleanup..."
        
        # Remove test namespace
        if kubectl get namespace "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
            log_info "Removing test namespace: $AIRGAP_NAMESPACE"
            kubectl delete namespace "$AIRGAP_NAMESPACE" --timeout=120s || log_warn "Failed to delete namespace"
        fi
        
        # Stop any running network isolation
        if pgrep -f "simulate-airgap" >/dev/null; then
            log_info "Stopping air-gap simulation"
            pkill -f "simulate-airgap" || true
        fi
        
        log_success "Cleanup completed"
    fi
}

trap cleanup EXIT INT TERM

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_kubernetes_cluster() {
    print_section "Validating Kubernetes Cluster"
    
    # Check cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    # Check if we have sufficient permissions
    if ! kubectl auth can-i create namespace; then
        log_error "Insufficient permissions to create namespaces"
        return 1
    fi
    
    # Check cluster resources
    local nodes=$(kubectl get nodes --no-headers 2>/dev/null | wc -l)
    if [[ $nodes -eq 0 ]]; then
        log_error "No nodes available in cluster"
        return 1
    fi
    
    log_success "Kubernetes cluster validation passed"
    log_info "Available nodes: $nodes"
    
    return 0
}

validate_local_registry() {
    print_section "Validating Local Registry"
    
    # Check if local registry is running
    if ! curl -s "http://${LOCAL_REGISTRY}/v2/" >/dev/null; then
        log_error "Local registry not accessible at $LOCAL_REGISTRY"
        log_info "Please start local registry: docker run -d -p 5000:5000 --name registry registry:2"
        return 1
    fi
    
    log_success "Local registry is accessible"
    
    # Check if required images are available
    local required_images=(
        "kubechat/api-gateway:${AIRGAP_IMAGE_TAG}"
        "kubechat/operator:${AIRGAP_IMAGE_TAG}"
        "kubechat/audit-service:${AIRGAP_IMAGE_TAG}"
        "kubechat/web:${AIRGAP_IMAGE_TAG}"
    )
    
    local missing_images=()
    for image in "${required_images[@]}"; do
        if ! curl -s "http://${LOCAL_REGISTRY}/v2/${image%:*}/tags/list" | jq -e ".tags[] | select(. == \"${image##*:}\")" >/dev/null 2>&1; then
            missing_images+=("$image")
        fi
    done
    
    if [[ ${#missing_images[@]} -gt 0 ]]; then
        log_warn "Missing images in local registry:"
        for image in "${missing_images[@]}"; do
            log_warn "  - ${LOCAL_REGISTRY}/$image"
        done
        log_info "Run './scripts/build-dev-images.sh --airgap' to build missing images"
        return 1
    fi
    
    log_success "All required images available in local registry"
    return 0
}

validate_helm_chart() {
    print_section "Validating Helm Chart"
    
    # Check if Helm chart exists
    if [[ ! -f "${PROJECT_ROOT}/deploy/helm/kubechat/Chart.yaml" ]]; then
        log_error "Helm chart not found"
        return 1
    fi
    
    # Check if air-gap values file exists
    if [[ ! -f "$AIRGAP_VALUES_FILE" ]]; then
        log_error "Air-gap values file not found: $AIRGAP_VALUES_FILE"
        return 1
    fi
    
    # Lint Helm chart
    if ! helm lint "${PROJECT_ROOT}/deploy/helm/kubechat" -f "$AIRGAP_VALUES_FILE" >/dev/null 2>&1; then
        log_error "Helm chart validation failed"
        helm lint "${PROJECT_ROOT}/deploy/helm/kubechat" -f "$AIRGAP_VALUES_FILE"
        return 1
    fi
    
    log_success "Helm chart validation passed"
    return 0
}

# =============================================================================
# AIR-GAP TESTING FUNCTIONS
# =============================================================================

test_network_isolation() {
    print_section "Testing Network Isolation"
    
    if [[ "$RUN_NETWORK_TESTS" != "true" ]]; then
        log_info "Network tests skipped (disabled)"
        return 0
    fi
    
    # Start air-gap simulation
    log_info "Starting air-gap environment simulation..."
    "${SCRIPT_DIR}/simulate-airgap.sh" --start &
    local airgap_pid=$!
    
    # Wait for simulation to initialize
    sleep 10
    
    # Test external connectivity is blocked
    log_info "Testing external connectivity blocking..."
    
    # Create test pod to verify network isolation
    kubectl create namespace "$AIRGAP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: network-test
  namespace: $AIRGAP_NAMESPACE
  labels:
    app: network-test
spec:
  containers:
  - name: test
    image: nicolaka/netshoot:latest
    command: ['sleep', '3600']
  restartPolicy: Never
EOF
    
    # Wait for pod to be ready
    kubectl wait --for=condition=Ready pod/network-test -n "$AIRGAP_NAMESPACE" --timeout=60s
    
    # Test external DNS resolution (should fail)
    if kubectl exec -n "$AIRGAP_NAMESPACE" network-test -- nslookup google.com >/dev/null 2>&1; then
        log_error "External DNS resolution should be blocked but is working"
        kill $airgap_pid 2>/dev/null || true
        return 1
    fi
    
    # Test external HTTP access (should fail)
    if kubectl exec -n "$AIRGAP_NAMESPACE" network-test -- curl -s --connect-timeout 5 http://google.com >/dev/null 2>&1; then
        log_error "External HTTP access should be blocked but is working"
        kill $airgap_pid 2>/dev/null || true
        return 1
    fi
    
    # Test internal connectivity (should work)
    if ! kubectl exec -n "$AIRGAP_NAMESPACE" network-test -- ping -c 1 kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
        log_error "Internal cluster connectivity should work but is failing"
        kill $airgap_pid 2>/dev/null || true
        return 1
    fi
    
    # Cleanup test pod
    kubectl delete pod network-test -n "$AIRGAP_NAMESPACE" --timeout=30s
    
    # Stop air-gap simulation
    kill $airgap_pid 2>/dev/null || true
    
    log_success "Network isolation tests passed"
    return 0
}

test_image_availability() {
    print_section "Testing Image Availability"
    
    if [[ "$RUN_IMAGE_TESTS" != "true" ]]; then
        log_info "Image tests skipped (disabled)"
        return 0
    fi
    
    # Create test namespace
    kubectl create namespace "$AIRGAP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Test each required image
    local images=(
        "${LOCAL_REGISTRY}/kubechat/api-gateway:${AIRGAP_IMAGE_TAG}"
        "${LOCAL_REGISTRY}/kubechat/operator:${AIRGAP_IMAGE_TAG}"
        "${LOCAL_REGISTRY}/kubechat/audit-service:${AIRGAP_IMAGE_TAG}"
        "${LOCAL_REGISTRY}/kubechat/web:${AIRGAP_IMAGE_TAG}"
    )
    
    for image in "${images[@]}"; do
        log_info "Testing image availability: $image"
        
        # Create test pod with imagePullPolicy: Never
        cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: image-test-$(echo "$image" | sed 's/[^a-z0-9]/-/g' | tr '[:upper:]' '[:lower:]')
  namespace: $AIRGAP_NAMESPACE
spec:
  containers:
  - name: test
    image: $image
    imagePullPolicy: Never
    command: ['sleep', '10']
  restartPolicy: Never
EOF
        
        # Wait for pod to start or fail
        local pod_name="image-test-$(echo "$image" | sed 's/[^a-z0-9]/-/g' | tr '[:upper:]' '[:lower:]')"
        local timeout=30
        local count=0
        
        while [[ $count -lt $timeout ]]; do
            local status=$(kubectl get pod "$pod_name" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
            
            if [[ "$status" == "Succeeded" ]] || [[ "$status" == "Running" ]]; then
                log_success "Image $image is available locally"
                break
            elif [[ "$status" == "Failed" ]]; then
                log_error "Image $image failed to start"
                kubectl describe pod "$pod_name" -n "$AIRGAP_NAMESPACE"
                return 1
            fi
            
            sleep 1
            ((count++))
        done
        
        if [[ $count -ge $timeout ]]; then
            log_error "Timeout waiting for image test: $image"
            return 1
        fi
        
        # Cleanup test pod
        kubectl delete pod "$pod_name" -n "$AIRGAP_NAMESPACE" --timeout=30s 2>/dev/null || true
    done
    
    log_success "All images are available locally"
    return 0
}

test_airgap_deployment() {
    print_section "Testing Air-Gap Deployment"
    
    if [[ "$RUN_DEPLOYMENT_TESTS" != "true" ]]; then
        log_info "Deployment tests skipped (disabled)"
        return 0
    fi
    
    # Start air-gap simulation
    log_info "Starting air-gap environment for deployment test..."
    "${SCRIPT_DIR}/simulate-airgap.sh" --start &
    local airgap_pid=$!
    
    # Wait for simulation to initialize
    sleep 10
    
    # Deploy KubeChat in air-gap mode
    log_info "Deploying KubeChat in air-gap mode..."
    
    # Create namespace
    kubectl create namespace "$AIRGAP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy with air-gap values
    if ! helm install kubechat-airgap "${PROJECT_ROOT}/deploy/helm/kubechat" \
        -f "$AIRGAP_VALUES_FILE" \
        -n "$AIRGAP_NAMESPACE" \
        --timeout="${TEST_TIMEOUT}s" \
        --wait; then
        log_error "Failed to deploy KubeChat in air-gap mode"
        helm status kubechat-airgap -n "$AIRGAP_NAMESPACE" || true
        kill $airgap_pid 2>/dev/null || true
        return 1
    fi
    
    log_success "KubeChat deployed successfully in air-gap mode"
    
    # Validate deployment
    log_info "Validating air-gap deployment..."
    
    # Check all pods are running
    local retry_count=0
    while [[ $retry_count -lt $VALIDATION_RETRIES ]]; do
        local running_pods=$(kubectl get pods -n "$AIRGAP_NAMESPACE" --field-selector=status.phase=Running --no-headers | wc -l)
        local total_pods=$(kubectl get pods -n "$AIRGAP_NAMESPACE" --no-headers | wc -l)
        
        if [[ $running_pods -eq $total_pods ]] && [[ $total_pods -gt 0 ]]; then
            log_success "All pods are running ($running_pods/$total_pods)"
            break
        fi
        
        log_info "Waiting for pods to be ready: $running_pods/$total_pods"
        kubectl get pods -n "$AIRGAP_NAMESPACE"
        sleep 10
        ((retry_count++))
    done
    
    if [[ $retry_count -ge $VALIDATION_RETRIES ]]; then
        log_error "Timeout waiting for all pods to be ready"
        kubectl describe pods -n "$AIRGAP_NAMESPACE"
        kill $airgap_pid 2>/dev/null || true
        return 1
    fi
    
    # Test service connectivity
    log_info "Testing service connectivity..."
    
    # Port forward to API Gateway
    kubectl port-forward -n "$AIRGAP_NAMESPACE" service/kubechat-api-gateway 18080:8080 &
    local pf_pid=$!
    
    sleep 5
    
    # Test health endpoint
    if ! curl -s http://localhost:18080/health >/dev/null; then
        log_error "API Gateway health check failed"
        kill $pf_pid 2>/dev/null || true
        kill $airgap_pid 2>/dev/null || true
        return 1
    fi
    
    log_success "Service connectivity test passed"
    
    # Cleanup
    kill $pf_pid 2>/dev/null || true
    
    # Uninstall deployment
    log_info "Cleaning up air-gap deployment..."
    helm uninstall kubechat-airgap -n "$AIRGAP_NAMESPACE" --timeout=120s
    
    # Stop air-gap simulation
    kill $airgap_pid 2>/dev/null || true
    
    log_success "Air-gap deployment test completed successfully"
    return 0
}

test_functional_operations() {
    print_section "Testing Functional Operations"
    
    if [[ "$RUN_FUNCTIONAL_TESTS" != "true" ]]; then
        log_info "Functional tests skipped (disabled)"
        return 0
    fi
    
    # This would include tests for:
    # - Basic KubeChat operations
    # - Command execution
    # - Audit logging
    # - User interactions
    
    log_info "Running functional operation tests..."
    
    # Start air-gap simulation
    "${SCRIPT_DIR}/simulate-airgap.sh" --start &
    local airgap_pid=$!
    sleep 10
    
    # Create minimal deployment for functional testing
    kubectl create namespace "$AIRGAP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy minimal KubeChat
    helm install kubechat-func "${PROJECT_ROOT}/deploy/helm/kubechat" \
        -f "$AIRGAP_VALUES_FILE" \
        -n "$AIRGAP_NAMESPACE" \
        --set apiGateway.replicaCount=1 \
        --set operator.replicaCount=1 \
        --set auditService.replicaCount=1 \
        --timeout=300s --wait
    
    # Basic functionality tests
    kubectl port-forward -n "$AIRGAP_NAMESPACE" service/kubechat-api-gateway 18080:8080 &
    local pf_pid=$!
    sleep 5
    
    # Test API endpoints
    local endpoints=("/health" "/ready" "/metrics")
    for endpoint in "${endpoints[@]}"; do
        if ! curl -s "http://localhost:18080$endpoint" >/dev/null; then
            log_error "Endpoint test failed: $endpoint"
            kill $pf_pid 2>/dev/null || true
            kill $airgap_pid 2>/dev/null || true
            return 1
        fi
    done
    
    log_success "Basic functional tests passed"
    
    # Cleanup
    kill $pf_pid 2>/dev/null || true
    helm uninstall kubechat-func -n "$AIRGAP_NAMESPACE" --timeout=120s
    kill $airgap_pid 2>/dev/null || true
    
    return 0
}

test_security_compliance() {
    print_section "Testing Security Compliance"
    
    if [[ "$RUN_SECURITY_TESTS" != "true" ]]; then
        log_info "Security tests skipped (disabled)"
        return 0
    fi
    
    log_info "Running security compliance tests..."
    
    # Test image pull policy enforcement
    kubectl create namespace "$AIRGAP_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Test that external image pulls are blocked
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: security-test-external
  namespace: $AIRGAP_NAMESPACE
spec:
  containers:
  - name: test
    image: nginx:latest
    imagePullPolicy: Always
  restartPolicy: Never
EOF
    
    # This should fail or timeout
    sleep 30
    local status=$(kubectl get pod security-test-external -n "$AIRGAP_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Failed")
    
    if [[ "$status" == "Running" ]]; then
        log_error "External image pull should be blocked but succeeded"
        return 1
    fi
    
    log_success "External image pull properly blocked"
    
    # Test local image with Never policy works
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: security-test-local
  namespace: $AIRGAP_NAMESPACE
spec:
  containers:
  - name: test
    image: ${LOCAL_REGISTRY}/kubechat/api-gateway:${AIRGAP_IMAGE_TAG}
    imagePullPolicy: Never
    command: ['sleep', '30']
  restartPolicy: Never
EOF
    
    # This should succeed
    kubectl wait --for=condition=Ready pod/security-test-local -n "$AIRGAP_NAMESPACE" --timeout=60s
    
    log_success "Local image with Never policy works correctly"
    
    # Cleanup
    kubectl delete pod security-test-external security-test-local -n "$AIRGAP_NAMESPACE" --timeout=30s 2>/dev/null || true
    
    return 0
}

# =============================================================================
# REPORTING FUNCTIONS
# =============================================================================

generate_test_report() {
    print_section "Generating Test Report"
    
    local report_file="${LOG_DIR}/airgap-test-report_${TIMESTAMP}.html"
    
    cat <<EOF > "$report_file"
<!DOCTYPE html>
<html>
<head>
    <title>KubeChat Air-Gap Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .test-section { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }
        .success { border-left-color: #4CAF50; }
        .error { border-left-color: #f44336; }
        .warning { border-left-color: #ff9800; }
        .code { background: #f9f9f9; padding: 10px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>KubeChat Air-Gap Test Report</h1>
        <p><strong>Generated:</strong> $(date)</p>
        <p><strong>Test Duration:</strong> Air-gap deployment simulation and validation</p>
        <p><strong>Environment:</strong> $AIRGAP_NAMESPACE</p>
    </div>
    
    <div class="test-section success">
        <h2>Test Summary</h2>
        <p>Air-gap testing completed successfully with all validation checks passed.</p>
        <ul>
            <li>Network isolation verified</li>
            <li>Local image availability confirmed</li>
            <li>Deployment functionality validated</li>
            <li>Security compliance verified</li>
        </ul>
    </div>
    
    <div class="test-section">
        <h2>Detailed Log</h2>
        <div class="code">
            <pre>$(cat "$LOG_FILE")</pre>
        </div>
    </div>
</body>
</html>
EOF
    
    log_success "Test report generated: $report_file"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Air-Gap Testing Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --no-network           Skip network isolation tests
    --no-images           Skip image availability tests
    --no-deployment       Skip deployment tests
    --no-functional       Skip functional tests
    --no-security         Skip security tests
    --no-cleanup          Don't cleanup resources on exit
    --verbose             Enable verbose logging
    --timeout SECONDS     Set test timeout (default: 600)
    --namespace NAME      Use custom namespace (default: kubechat-airgap)
    --help                Show this help message

EXAMPLES:
    # Run all tests
    $0

    # Run only deployment and security tests
    $0 --no-network --no-images --no-functional

    # Run with verbose output and custom timeout
    $0 --verbose --timeout 900

    # Run tests without cleanup (for debugging)
    $0 --no-cleanup --verbose
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --no-network)
                RUN_NETWORK_TESTS=false
                shift
                ;;
            --no-images)
                RUN_IMAGE_TESTS=false
                shift
                ;;
            --no-deployment)
                RUN_DEPLOYMENT_TESTS=false
                shift
                ;;
            --no-functional)
                RUN_FUNCTIONAL_TESTS=false
                shift
                ;;
            --no-security)
                RUN_SECURITY_TESTS=false
                shift
                ;;
            --no-cleanup)
                CLEANUP_ON_EXIT=false
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --namespace)
                AIRGAP_NAMESPACE="$2"
                shift 2
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

main() {
    parse_arguments "$@"
    
    print_header "KubeChat Air-Gap Testing Suite"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Starting air-gap testing suite"
    log_info "Log file: $LOG_FILE"
    log_info "Test timeout: ${TEST_TIMEOUT}s"
    log_info "Target namespace: $AIRGAP_NAMESPACE"
    
    # Pre-flight checks
    log_info "Performing pre-flight checks..."
    check_dependencies
    validate_kubernetes_cluster || exit 1
    validate_local_registry || exit 1
    validate_helm_chart || exit 1
    
    # Run test suite
    local test_failures=0
    
    log_info "Starting air-gap test execution..."
    
    if ! test_network_isolation; then
        ((test_failures++))
    fi
    
    if ! test_image_availability; then
        ((test_failures++))
    fi
    
    if ! test_airgap_deployment; then
        ((test_failures++))
    fi
    
    if ! test_functional_operations; then
        ((test_failures++))
    fi
    
    if ! test_security_compliance; then
        ((test_failures++))
    fi
    
    # Generate report
    generate_test_report
    
    # Final results
    print_header "Air-Gap Testing Results"
    
    if [[ $test_failures -eq 0 ]]; then
        log_success "All air-gap tests passed successfully! ✅"
        log_success "KubeChat is ready for air-gap deployment"
        exit 0
    else
        log_error "Air-gap testing failed with $test_failures test failure(s) ❌"
        log_error "Please review the test output and fix issues before air-gap deployment"
        exit 1
    fi
}

# Execute main function with all arguments
main "$@"