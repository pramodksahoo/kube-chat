#!/bin/bash

# KubeChat Air-Gap Deployment Validation Script
# Comprehensive offline deployment validation with no external connectivity
# Usage: ./scripts/validate-airgap.sh [options]
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
LOG_FILE="${LOG_DIR}/airgap-validation_${TIMESTAMP}.log"

# Validation configuration
AIRGAP_NAMESPACE="kubechat-airgap"
LOCAL_REGISTRY="localhost:5001"
VALIDATION_TIMEOUT=300
MAX_RETRY_ATTEMPTS=5

# Test configuration
VALIDATE_NETWORK_ISOLATION=true
VALIDATE_IMAGE_AVAILABILITY=true
VALIDATE_SERVICE_STARTUP=true
VALIDATE_FUNCTIONALITY=true
VALIDATE_SECURITY_POLICIES=true
VALIDATE_DATA_PERSISTENCE=true

# Monitoring configuration
VERBOSE=false
CONTINUOUS_MONITORING=false
MONITORING_INTERVAL=30
REPORT_FORMAT="text"  # text, json, html

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
    local deps=("kubectl" "docker" "curl" "jq")
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

wait_for_condition() {
    local description="$1"
    local condition_cmd="$2"
    local timeout="${3:-$VALIDATION_TIMEOUT}"
    local interval="${4:-10}"
    
    log_info "Waiting for: $description (timeout: ${timeout}s)"
    
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if eval "$condition_cmd"; then
            log_success "$description - condition met"
            return 0
        fi
        
        log_debug "Waiting... (${elapsed}/${timeout}s)"
        sleep "$interval"
        elapsed=$((elapsed + interval))
    done
    
    log_error "Timeout waiting for: $description"
    return 1
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_kubernetes_connectivity() {
    print_section "Validating Kubernetes Connectivity"
    
    # Test cluster connectivity
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "Cannot connect to Kubernetes cluster"
        return 1
    fi
    
    # Test namespace access
    if ! kubectl get namespace "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
        log_error "Cannot access namespace: $AIRGAP_NAMESPACE"
        return 1
    fi
    
    # Test RBAC permissions
    local required_verbs=("get" "list" "create" "delete")
    local required_resources=("pods" "services" "deployments")
    
    for verb in "${required_verbs[@]}"; do
        for resource in "${required_resources[@]}"; do
            if ! kubectl auth can-i "$verb" "$resource" -n "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
                log_error "Insufficient permissions: $verb $resource"
                return 1
            fi
        done
    done
    
    log_success "Kubernetes connectivity validated"
    return 0
}

validate_network_isolation() {
    print_section "Validating Network Isolation"
    
    if [[ "$VALIDATE_NETWORK_ISOLATION" != "true" ]]; then
        log_info "Network isolation validation skipped (disabled)"
        return 0
    fi
    
    # Create test pod for network testing
    local test_pod="network-isolation-test"
    
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $test_pod
  namespace: $AIRGAP_NAMESPACE
  labels:
    test: network-isolation
spec:
  containers:
  - name: nettest
    image: nicolaka/netshoot:latest
    command: ['sleep', '3600']
  restartPolicy: Never
EOF
    
    # Wait for pod to be ready
    wait_for_condition "Test pod ready" \
        "kubectl get pod $test_pod -n $AIRGAP_NAMESPACE -o jsonpath='{.status.phase}' | grep -q Running"
    
    local validation_errors=0
    
    # Test external DNS blocking
    log_info "Testing external DNS blocking..."
    if kubectl exec -n "$AIRGAP_NAMESPACE" "$test_pod" -- timeout 10 nslookup google.com 8.8.8.8 >/dev/null 2>&1; then
        log_error "External DNS not blocked - air-gap violation detected"
        ((validation_errors++))
    else
        log_success "External DNS properly blocked"
    fi
    
    # Test external HTTP blocking
    log_info "Testing external HTTP blocking..."
    if kubectl exec -n "$AIRGAP_NAMESPACE" "$test_pod" -- timeout 10 curl -s http://google.com >/dev/null 2>&1; then
        log_error "External HTTP not blocked - air-gap violation detected"
        ((validation_errors++))
    else
        log_success "External HTTP properly blocked"
    fi
    
    # Test external HTTPS blocking
    log_info "Testing external HTTPS blocking..."
    if kubectl exec -n "$AIRGAP_NAMESPACE" "$test_pod" -- timeout 10 curl -s https://google.com >/dev/null 2>&1; then
        log_error "External HTTPS not blocked - air-gap violation detected"
        ((validation_errors++))
    else
        log_success "External HTTPS properly blocked"
    fi
    
    # Test internal cluster connectivity
    log_info "Testing internal cluster connectivity..."
    if ! kubectl exec -n "$AIRGAP_NAMESPACE" "$test_pod" -- timeout 10 ping -c 1 kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
        log_error "Internal cluster connectivity failed"
        ((validation_errors++))
    else
        log_success "Internal cluster connectivity working"
    fi
    
    # Test local registry access
    log_info "Testing local registry access..."
    if ! kubectl exec -n "$AIRGAP_NAMESPACE" "$test_pod" -- timeout 10 curl -s http://host.docker.internal:5000/v2/ >/dev/null 2>&1; then
        log_warn "Local registry not accessible from pods (expected in some environments)"
    else
        log_success "Local registry accessible from pods"
    fi
    
    # Cleanup test pod
    kubectl delete pod "$test_pod" -n "$AIRGAP_NAMESPACE" --timeout=60s
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Network isolation validation passed"
        return 0
    else
        log_error "Network isolation validation failed with $validation_errors error(s)"
        return 1
    fi
}

validate_image_availability() {
    print_section "Validating Image Availability"
    
    if [[ "$VALIDATE_IMAGE_AVAILABILITY" != "true" ]]; then
        log_info "Image availability validation skipped (disabled)"
        return 0
    fi
    
    # Get list of all images used in the deployment
    local deployment_images=$(kubectl get pods -n "$AIRGAP_NAMESPACE" -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u)
    
    if [[ -z "$deployment_images" ]]; then
        log_error "No running pods found in namespace: $AIRGAP_NAMESPACE"
        return 1
    fi
    
    local validation_errors=0
    
    # Test each image
    for image in $deployment_images; do
        log_info "Validating image: $image"
        
        # Create test pod with imagePullPolicy: Never
        local test_pod="image-test-$(echo "$image" | sed 's/[^a-z0-9]/-/g' | tr '[:upper:]' '[:lower:]' | cut -c1-50)"
        
        cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $test_pod
  namespace: $AIRGAP_NAMESPACE
  labels:
    test: image-availability
spec:
  containers:
  - name: test
    image: $image
    imagePullPolicy: Never
    command: ['sleep', '60']
  restartPolicy: Never
EOF
        
        # Wait for pod to start or fail
        sleep 10
        local pod_status=$(kubectl get pod "$test_pod" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "NotFound")
        
        if [[ "$pod_status" == "Running" ]] || [[ "$pod_status" == "Succeeded" ]]; then
            log_success "Image available locally: $image"
        else
            log_error "Image not available locally: $image"
            kubectl describe pod "$test_pod" -n "$AIRGAP_NAMESPACE" | grep -E "(Events|Error|Failed)" || true
            ((validation_errors++))
        fi
        
        # Cleanup test pod
        kubectl delete pod "$test_pod" -n "$AIRGAP_NAMESPACE" --timeout=30s 2>/dev/null || true
    done
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Image availability validation passed"
        return 0
    else
        log_error "Image availability validation failed with $validation_errors error(s)"
        return 1
    fi
}

validate_service_startup() {
    print_section "Validating Service Startup"
    
    if [[ "$VALIDATE_SERVICE_STARTUP" != "true" ]]; then
        log_info "Service startup validation skipped (disabled)"
        return 0
    fi
    
    # Get all deployments in the namespace
    local deployments=$(kubectl get deployments -n "$AIRGAP_NAMESPACE" -o name 2>/dev/null || echo "")
    
    if [[ -z "$deployments" ]]; then
        log_error "No deployments found in namespace: $AIRGAP_NAMESPACE"
        return 1
    fi
    
    local validation_errors=0
    
    # Check each deployment
    for deployment in $deployments; do
        local deploy_name=$(echo "$deployment" | sed 's|deployment.apps/||')
        log_info "Validating deployment: $deploy_name"
        
        # Check if deployment is available
        local ready_replicas=$(kubectl get "$deployment" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || echo "0")
        local desired_replicas=$(kubectl get "$deployment" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.spec.replicas}' 2>/dev/null || echo "1")
        
        if [[ "$ready_replicas" -eq "$desired_replicas" ]] && [[ "$ready_replicas" -gt 0 ]]; then
            log_success "Deployment ready: $deploy_name ($ready_replicas/$desired_replicas)"
        else
            log_error "Deployment not ready: $deploy_name ($ready_replicas/$desired_replicas)"
            kubectl describe "$deployment" -n "$AIRGAP_NAMESPACE" | grep -A 10 "Conditions:" || true
            ((validation_errors++))
        fi
    done
    
    # Check services
    local services=$(kubectl get services -n "$AIRGAP_NAMESPACE" -o name 2>/dev/null || echo "")
    
    for service in $services; do
        local svc_name=$(echo "$service" | sed 's|service/||')
        log_info "Validating service: $svc_name"
        
        # Check if service has endpoints
        local endpoints=$(kubectl get endpoints "$svc_name" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null || echo "")
        
        if [[ -n "$endpoints" ]]; then
            log_success "Service has endpoints: $svc_name"
        else
            log_warn "Service has no endpoints: $svc_name"
        fi
    done
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Service startup validation passed"
        return 0
    else
        log_error "Service startup validation failed with $validation_errors error(s)"
        return 1
    fi
}

validate_functionality() {
    print_section "Validating Application Functionality"
    
    if [[ "$VALIDATE_FUNCTIONALITY" != "true" ]]; then
        log_info "Functionality validation skipped (disabled)"
        return 0
    fi
    
    local validation_errors=0
    
    # Test API Gateway health endpoint
    log_info "Testing API Gateway health endpoint..."
    
    kubectl port-forward -n "$AIRGAP_NAMESPACE" service/kubechat-api-gateway 18080:8080 &
    local pf_pid=$!
    
    # Wait for port forward to be ready
    sleep 5
    
    if timeout 30 bash -c 'until curl -s http://localhost:18080/health >/dev/null 2>&1; do sleep 1; done'; then
        log_success "API Gateway health endpoint accessible"
    else
        log_error "API Gateway health endpoint not accessible"
        ((validation_errors++))
    fi
    
    # Test API Gateway metrics endpoint
    log_info "Testing API Gateway metrics endpoint..."
    if curl -s http://localhost:18080/metrics >/dev/null 2>&1; then
        log_success "API Gateway metrics endpoint accessible"
    else
        log_error "API Gateway metrics endpoint not accessible"
        ((validation_errors++))
    fi
    
    # Kill port forward
    kill $pf_pid 2>/dev/null || true
    
    # Test Audit Service functionality
    log_info "Testing Audit Service functionality..."
    
    kubectl port-forward -n "$AIRGAP_NAMESPACE" service/kubechat-audit-service 18082:8082 &
    pf_pid=$!
    sleep 5
    
    if timeout 30 bash -c 'until curl -s http://localhost:18082/health >/dev/null 2>&1; do sleep 1; done'; then
        log_success "Audit Service health endpoint accessible"
    else
        log_error "Audit Service health endpoint not accessible"
        ((validation_errors++))
    fi
    
    kill $pf_pid 2>/dev/null || true
    
    # Test Web Frontend
    log_info "Testing Web Frontend..."
    
    kubectl port-forward -n "$AIRGAP_NAMESPACE" service/kubechat-web 18080:80 &
    pf_pid=$!
    sleep 5
    
    if timeout 30 bash -c 'until curl -s http://localhost:18080/ >/dev/null 2>&1; do sleep 1; done'; then
        log_success "Web Frontend accessible"
    else
        log_error "Web Frontend not accessible"
        ((validation_errors++))
    fi
    
    kill $pf_pid 2>/dev/null || true
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Functionality validation passed"
        return 0
    else
        log_error "Functionality validation failed with $validation_errors error(s)"
        return 1
    fi
}

validate_security_policies() {
    print_section "Validating Security Policies"
    
    if [[ "$VALIDATE_SECURITY_POLICIES" != "true" ]]; then
        log_info "Security policy validation skipped (disabled)"
        return 0
    fi
    
    local validation_errors=0
    
    # Check pod security contexts
    log_info "Validating pod security contexts..."
    
    local pods=$(kubectl get pods -n "$AIRGAP_NAMESPACE" -o name)
    
    for pod in $pods; do
        local pod_name=$(echo "$pod" | sed 's|pod/||')
        
        # Check if pod runs as non-root
        local run_as_user=$(kubectl get "$pod" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.spec.securityContext.runAsUser}' 2>/dev/null || echo "")
        
        if [[ -n "$run_as_user" ]] && [[ "$run_as_user" != "0" ]]; then
            log_success "Pod runs as non-root: $pod_name (UID: $run_as_user)"
        else
            log_warn "Pod security context not configured: $pod_name"
        fi
        
        # Check if pod has read-only root filesystem
        local read_only_fs=$(kubectl get "$pod" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.spec.containers[0].securityContext.readOnlyRootFilesystem}' 2>/dev/null || echo "false")
        
        if [[ "$read_only_fs" == "true" ]]; then
            log_success "Pod has read-only root filesystem: $pod_name"
        else
            log_info "Pod allows writable root filesystem: $pod_name"
        fi
    done
    
    # Check network policies
    log_info "Validating network policies..."
    
    local netpols=$(kubectl get networkpolicies -n "$AIRGAP_NAMESPACE" -o name 2>/dev/null || echo "")
    
    if [[ -n "$netpols" ]]; then
        log_success "Network policies are configured"
        for netpol in $netpols; do
            log_info "  - $netpol"
        done
    else
        log_warn "No network policies found - consider enabling for enhanced security"
    fi
    
    # Check image pull policies
    log_info "Validating image pull policies..."
    
    local non_never_policies=$(kubectl get pods -n "$AIRGAP_NAMESPACE" -o jsonpath='{range .items[*]}{.spec.containers[*].imagePullPolicy}{"\n"}{end}' | grep -v "Never" | wc -l)
    
    if [[ "$non_never_policies" -eq 0 ]]; then
        log_success "All pods use 'Never' image pull policy"
    else
        log_warn "Some pods don't use 'Never' image pull policy - may attempt external pulls"
        ((validation_errors++))
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Security policy validation passed"
        return 0
    else
        log_error "Security policy validation failed with $validation_errors error(s)"
        return 1
    fi
}

validate_data_persistence() {
    print_section "Validating Data Persistence"
    
    if [[ "$VALIDATE_DATA_PERSISTENCE" != "true" ]]; then
        log_info "Data persistence validation skipped (disabled)"
        return 0
    fi
    
    local validation_errors=0
    
    # Check persistent volumes
    log_info "Validating persistent volumes..."
    
    local pvcs=$(kubectl get pvc -n "$AIRGAP_NAMESPACE" -o name 2>/dev/null || echo "")
    
    if [[ -n "$pvcs" ]]; then
        for pvc in $pvcs; do
            local pvc_name=$(echo "$pvc" | sed 's|persistentvolumeclaim/||')
            local pvc_status=$(kubectl get "$pvc" -n "$AIRGAP_NAMESPACE" -o jsonpath='{.status.phase}')
            
            if [[ "$pvc_status" == "Bound" ]]; then
                log_success "PVC is bound: $pvc_name"
            else
                log_error "PVC not bound: $pvc_name (status: $pvc_status)"
                ((validation_errors++))
            fi
        done
    else
        log_info "No persistent volumes found - using ephemeral storage"
    fi
    
    # Test database connectivity (if PostgreSQL is deployed)
    if kubectl get service kubechat-postgresql -n "$AIRGAP_NAMESPACE" >/dev/null 2>&1; then
        log_info "Testing PostgreSQL connectivity..."
        
        kubectl port-forward -n "$AIRGAP_NAMESPACE" service/kubechat-postgresql 15432:5432 &
        local pf_pid=$!
        sleep 5
        
        # Use a simple connection test
        if timeout 10 bash -c 'echo "SELECT 1;" | nc -w 1 localhost 15432' >/dev/null 2>&1; then
            log_success "PostgreSQL is accessible"
        else
            log_error "PostgreSQL is not accessible"
            ((validation_errors++))
        fi
        
        kill $pf_pid 2>/dev/null || true
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Data persistence validation passed"
        return 0
    else
        log_error "Data persistence validation failed with $validation_errors error(s)"
        return 1
    fi
}

# =============================================================================
# REPORTING FUNCTIONS
# =============================================================================

generate_validation_report() {
    print_section "Generating Validation Report"
    
    local report_file="${LOG_DIR}/airgap-validation-report_${TIMESTAMP}"
    
    case $REPORT_FORMAT in
        json)
            generate_json_report "${report_file}.json"
            ;;
        html)
            generate_html_report "${report_file}.html"
            ;;
        text|*)
            generate_text_report "${report_file}.txt"
            ;;
    esac
}

generate_text_report() {
    local report_file="$1"
    
    cat > "$report_file" <<EOF
KubeChat Air-Gap Deployment Validation Report
=============================================

Generated: $(date)
Namespace: $AIRGAP_NAMESPACE
Duration: Air-gap deployment validation

Summary:
- Kubernetes connectivity: $(kubectl cluster-info >/dev/null 2>&1 && echo "✓ OK" || echo "✗ FAILED")
- Network isolation: $(if [[ "$VALIDATE_NETWORK_ISOLATION" == "true" ]]; then echo "Validated"; else echo "Skipped"; fi)
- Image availability: $(if [[ "$VALIDATE_IMAGE_AVAILABILITY" == "true" ]]; then echo "Validated"; else echo "Skipped"; fi)
- Service startup: $(if [[ "$VALIDATE_SERVICE_STARTUP" == "true" ]]; then echo "Validated"; else echo "Skipped"; fi)
- Functionality: $(if [[ "$VALIDATE_FUNCTIONALITY" == "true" ]]; then echo "Validated"; else echo "Skipped"; fi)
- Security policies: $(if [[ "$VALIDATE_SECURITY_POLICIES" == "true" ]]; then echo "Validated"; else echo "Skipped"; fi)
- Data persistence: $(if [[ "$VALIDATE_DATA_PERSISTENCE" == "true" ]]; then echo "Validated"; else echo "Skipped"; fi)

Deployment Status:
$(kubectl get pods -n "$AIRGAP_NAMESPACE" 2>/dev/null || echo "No pods found")

Detailed Log:
$(cat "$LOG_FILE")
EOF
    
    log_success "Text report generated: $report_file"
}

generate_json_report() {
    local report_file="$1"
    
    cat > "$report_file" <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "namespace": "$AIRGAP_NAMESPACE",
  "validation": {
    "network_isolation": $VALIDATE_NETWORK_ISOLATION,
    "image_availability": $VALIDATE_IMAGE_AVAILABILITY,
    "service_startup": $VALIDATE_SERVICE_STARTUP,
    "functionality": $VALIDATE_FUNCTIONALITY,
    "security_policies": $VALIDATE_SECURITY_POLICIES,
    "data_persistence": $VALIDATE_DATA_PERSISTENCE
  },
  "status": "completed",
  "log_file": "$LOG_FILE"
}
EOF
    
    log_success "JSON report generated: $report_file"
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Air-Gap Deployment Validation Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --namespace NAME         Target namespace (default: $AIRGAP_NAMESPACE)
    --timeout SECONDS       Validation timeout (default: $VALIDATION_TIMEOUT)
    --no-network            Skip network isolation validation
    --no-images             Skip image availability validation
    --no-services           Skip service startup validation
    --no-functionality      Skip functionality validation
    --no-security           Skip security policy validation
    --no-persistence        Skip data persistence validation
    --continuous            Enable continuous monitoring
    --interval SECONDS      Monitoring interval (default: $MONITORING_INTERVAL)
    --report-format FORMAT  Report format: text, json, html (default: $REPORT_FORMAT)
    --verbose               Enable verbose logging
    --help                  Show this help message

EXAMPLES:
    # Run all validations
    $0

    # Run with custom namespace
    $0 --namespace my-airgap-test

    # Skip network tests, verbose output
    $0 --no-network --verbose

    # Continuous monitoring with JSON reports
    $0 --continuous --interval 60 --report-format json
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --namespace)
                AIRGAP_NAMESPACE="$2"
                shift 2
                ;;
            --timeout)
                VALIDATION_TIMEOUT="$2"
                shift 2
                ;;
            --no-network)
                VALIDATE_NETWORK_ISOLATION=false
                shift
                ;;
            --no-images)
                VALIDATE_IMAGE_AVAILABILITY=false
                shift
                ;;
            --no-services)
                VALIDATE_SERVICE_STARTUP=false
                shift
                ;;
            --no-functionality)
                VALIDATE_FUNCTIONALITY=false
                shift
                ;;
            --no-security)
                VALIDATE_SECURITY_POLICIES=false
                shift
                ;;
            --no-persistence)
                VALIDATE_DATA_PERSISTENCE=false
                shift
                ;;
            --continuous)
                CONTINUOUS_MONITORING=true
                shift
                ;;
            --interval)
                MONITORING_INTERVAL="$2"
                shift 2
                ;;
            --report-format)
                REPORT_FORMAT="$2"
                shift 2
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

run_validation_suite() {
    local total_errors=0
    
    # Run all enabled validations
    validate_kubernetes_connectivity || ((total_errors++))
    validate_network_isolation || ((total_errors++))
    validate_image_availability || ((total_errors++))
    validate_service_startup || ((total_errors++))
    validate_functionality || ((total_errors++))
    validate_security_policies || ((total_errors++))
    validate_data_persistence || ((total_errors++))
    
    return $total_errors
}

main() {
    parse_arguments "$@"
    
    print_header "KubeChat Air-Gap Deployment Validation"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Air-gap validation starting"
    log_info "Target namespace: $AIRGAP_NAMESPACE"
    log_info "Log file: $LOG_FILE"
    
    # Check dependencies
    check_dependencies
    
    if [[ "$CONTINUOUS_MONITORING" == "true" ]]; then
        log_info "Starting continuous monitoring (interval: ${MONITORING_INTERVAL}s)"
        
        while true; do
            log_info "Running validation cycle..."
            
            if run_validation_suite; then
                log_success "Validation cycle completed successfully"
            else
                log_error "Validation cycle completed with errors"
            fi
            
            generate_validation_report
            
            log_info "Next validation in ${MONITORING_INTERVAL}s..."
            sleep "$MONITORING_INTERVAL"
        done
    else
        # Single validation run
        log_info "Running single validation cycle..."
        
        if run_validation_suite; then
            log_success "All validations passed! ✅"
            log_success "Air-gap deployment is functioning correctly"
            generate_validation_report
            exit 0
        else
            log_error "Validation failed ❌"
            log_error "Please review the errors and fix issues"
            generate_validation_report
            exit 1
        fi
    fi
}

# Execute main function with all arguments
main "$@"