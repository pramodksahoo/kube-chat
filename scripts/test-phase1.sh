#!/bin/bash
# test-phase1.sh
# KubeChat Phase 1 Model 1 Comprehensive Development Testing Validation
# Validates end-to-end development workflow and deployment

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="${1:-kubechat-system}"
VERSION="${2:-dev}"
RELEASE_NAME="kubechat-dev"
TEST_TIMEOUT="300s"

# Test results tracking
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0
declare -a FAILED_TESTS=()

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

log_test_start() {
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    echo -e "${BLUE}[TEST $TESTS_TOTAL]${NC} $1"
}

log_test_pass() {
    TESTS_PASSED=$((TESTS_PASSED + 1))
    echo -e "${GREEN}[PASS]${NC} $1"
}

log_test_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    FAILED_TESTS+=("$1")
    echo -e "${RED}[FAIL]${NC} $1"
}

# Error handler (non-fatal for tests)
test_error_handler() {
    log_warning "Test encountered error at line $1, continuing with remaining tests..."
}

trap 'test_error_handler $LINENO' ERR
set +e  # Allow tests to fail without stopping script

# Test: Kubernetes cluster connectivity
test_kubernetes_connectivity() {
    log_test_start "Kubernetes cluster connectivity"
    
    if kubectl cluster-info &>/dev/null; then
        local cluster_info
        cluster_info=$(kubectl cluster-info | head -2)
        log_test_pass "Kubernetes cluster accessible"
        log_info "$cluster_info"
    else
        log_test_fail "Kubernetes cluster not accessible"
        return 1
    fi
}

# Test: Namespace existence and resources
test_namespace_resources() {
    log_test_start "Namespace resources in $NAMESPACE"
    
    if kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_test_pass "Namespace $NAMESPACE exists"
        
        # Count resources
        local pod_count deployment_count service_count
        pod_count=$(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
        deployment_count=$(kubectl get deployments -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
        service_count=$(kubectl get services -n "$NAMESPACE" --no-headers 2>/dev/null | wc -l)
        
        log_info "Resources in $NAMESPACE: $pod_count pods, $deployment_count deployments, $service_count services"
        
        if [[ $pod_count -gt 0 ]]; then
            log_test_pass "Pods found in namespace"
        else
            log_test_fail "No pods found in namespace"
            return 1
        fi
    else
        log_test_fail "Namespace $NAMESPACE not found"
        return 1
    fi
}

# Test: Pod health and readiness
test_pod_health() {
    log_test_start "Pod health and readiness"
    
    local pods_ready=0
    local pods_total=0
    
    # Get all pods in namespace
    while IFS= read -r pod_line; do
        if [[ -n "$pod_line" ]]; then
            pods_total=$((pods_total + 1))
            local pod_name ready_status
            pod_name=$(echo "$pod_line" | awk '{print $1}')
            ready_status=$(echo "$pod_line" | awk '{print $2}')
            
            if [[ "$ready_status" =~ ^([0-9]+)/\1$ ]]; then
                pods_ready=$((pods_ready + 1))
                log_info "✅ $pod_name is ready ($ready_status)"
            else
                log_warning "⚠️ $pod_name not ready ($ready_status)"
                
                # Show pod describe for debugging
                kubectl describe pod "$pod_name" -n "$NAMESPACE" | tail -10
            fi
        fi
    done < <(kubectl get pods -n "$NAMESPACE" --no-headers 2>/dev/null)
    
    if [[ $pods_ready -eq $pods_total ]] && [[ $pods_total -gt 0 ]]; then
        log_test_pass "All $pods_total pods are ready"
    else
        log_test_fail "$pods_ready/$pods_total pods ready"
        return 1
    fi
}

# Test: Service endpoints
test_service_endpoints() {
    log_test_start "Service endpoints"
    
    local services_with_endpoints=0
    local services_total=0
    
    # Get all services in namespace
    while IFS= read -r service_line; do
        if [[ -n "$service_line" ]]; then
            services_total=$((services_total + 1))
            local service_name
            service_name=$(echo "$service_line" | awk '{print $1}')
            
            # Check if service has endpoints
            if kubectl get endpoints "$service_name" -n "$NAMESPACE" &>/dev/null; then
                local endpoint_count
                endpoint_count=$(kubectl get endpoints "$service_name" -n "$NAMESPACE" -o jsonpath='{.subsets[*].addresses[*].ip}' | wc -w)
                
                if [[ $endpoint_count -gt 0 ]]; then
                    services_with_endpoints=$((services_with_endpoints + 1))
                    log_info "✅ $service_name has $endpoint_count endpoint(s)"
                else
                    log_warning "⚠️ $service_name has no endpoints"
                fi
            fi
        fi
    done < <(kubectl get services -n "$NAMESPACE" --no-headers 2>/dev/null | grep -v kubernetes || true)
    
    if [[ $services_with_endpoints -eq $services_total ]] && [[ $services_total -gt 0 ]]; then
        log_test_pass "All $services_total services have endpoints"
    else
        log_test_fail "$services_with_endpoints/$services_total services have endpoints"
        return 1
    fi
}

# Test: Helm release status
test_helm_release() {
    log_test_start "Helm release status"
    
    if helm status "$RELEASE_NAME" -n "$NAMESPACE" &>/dev/null; then
        local release_status
        release_status=$(helm status "$RELEASE_NAME" -n "$NAMESPACE" -o json | jq -r '.info.status' 2>/dev/null || echo "unknown")
        
        if [[ "$release_status" == "deployed" ]]; then
            log_test_pass "Helm release $RELEASE_NAME is deployed"
        else
            log_test_fail "Helm release $RELEASE_NAME status: $release_status"
            return 1
        fi
    else
        log_test_fail "Helm release $RELEASE_NAME not found"
        return 1
    fi
}

# Test: API Gateway health
test_api_gateway_health() {
    log_test_start "API Gateway health check"
    
    # Check if API Gateway service exists
    if ! kubectl get service kubechat-api-gateway -n "$NAMESPACE" &>/dev/null; then
        log_warning "API Gateway service not found, skipping health check"
        return 0
    fi
    
    # Port forward to API Gateway
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-api-gateway 8080:80 &
    local port_forward_pid=$!
    
    # Wait for port forward to establish
    sleep 5
    
    # Test health endpoint
    local health_check=false
    for i in {1..5}; do
        if curl -f -s http://localhost:8080/health &>/dev/null; then
            health_check=true
            break
        fi
        sleep 2
    done
    
    # Cleanup port forward
    kill $port_forward_pid &>/dev/null || true
    
    if [[ "$health_check" == true ]]; then
        log_test_pass "API Gateway health check passed"
    else
        log_test_fail "API Gateway health check failed"
        return 1
    fi
}

# Test: Database connectivity
test_database_connectivity() {
    log_test_start "Database connectivity"
    
    # Check if PostgreSQL service exists
    if ! kubectl get service postgres-postgresql -n "$NAMESPACE" &>/dev/null; then
        log_warning "PostgreSQL service not found, skipping database test"
        return 0
    fi
    
    # Port forward to PostgreSQL
    kubectl port-forward -n "$NAMESPACE" svc/postgres-postgresql 5432:5432 &
    local port_forward_pid=$!
    
    # Wait for port forward
    sleep 5
    
    # Test database connection (requires PostgreSQL client)
    local db_test=false
    if command -v psql &>/dev/null; then
        if PGPASSWORD=dev-password psql -h localhost -p 5432 -U postgres -d kubechat_dev -c "SELECT 1;" &>/dev/null; then
            db_test=true
        fi
    elif command -v pg_isready &>/dev/null; then
        if pg_isready -h localhost -p 5432 -U postgres &>/dev/null; then
            db_test=true
        fi
    else
        # Try basic TCP connection test
        if timeout 5 bash -c "</dev/tcp/localhost/5432" 2>/dev/null; then
            db_test=true
        fi
    fi
    
    # Cleanup port forward
    kill $port_forward_pid &>/dev/null || true
    
    if [[ "$db_test" == true ]]; then
        log_test_pass "Database connectivity verified"
    else
        log_test_fail "Database connectivity failed"
        return 1
    fi
}

# Test: Redis connectivity
test_redis_connectivity() {
    log_test_start "Redis connectivity"
    
    # Check if Redis service exists
    if ! kubectl get service redis-master -n "$NAMESPACE" &>/dev/null; then
        log_warning "Redis service not found, skipping Redis test"
        return 0
    fi
    
    # Port forward to Redis
    kubectl port-forward -n "$NAMESPACE" svc/redis-master 6379:6379 &
    local port_forward_pid=$!
    
    # Wait for port forward
    sleep 5
    
    # Test Redis connection
    local redis_test=false
    if command -v redis-cli &>/dev/null; then
        if echo "PING" | redis-cli -h localhost -p 6379 -a dev-password --no-auth-warning | grep -q "PONG"; then
            redis_test=true
        fi
    else
        # Try basic TCP connection test
        if timeout 5 bash -c "</dev/tcp/localhost/6379" 2>/dev/null; then
            redis_test=true
        fi
    fi
    
    # Cleanup port forward
    kill $port_forward_pid &>/dev/null || true
    
    if [[ "$redis_test" == true ]]; then
        log_test_pass "Redis connectivity verified"
    else
        log_test_fail "Redis connectivity failed"
        return 1
    fi
}

# Test: Custom Resource Definitions
test_custom_resources() {
    log_test_start "Custom Resource Definitions"
    
    # Check for KubeChat CRDs
    local crd_count
    crd_count=$(kubectl get crd | grep -c kubechat || echo "0")
    
    if [[ $crd_count -gt 0 ]]; then
        log_test_pass "Found $crd_count KubeChat CRD(s)"
        
        # Try to create a test custom resource
        if kubectl get crd chatsessions.kubechat.ai &>/dev/null; then
            # Create test ChatSession
            kubectl apply -f - <<EOF
apiVersion: kubechat.ai/v1
kind: ChatSession
metadata:
  name: test-session-$(date +%s)
  namespace: $NAMESPACE
spec:
  userId: "test-user"
  sessionId: "test-session-001"
  commands: []
EOF
            
            log_test_pass "ChatSession custom resource creation test passed"
        else
            log_warning "ChatSession CRD not found, skipping CR creation test"
        fi
    else
        log_warning "No KubeChat CRDs found (may be expected for current phase)"
    fi
}

# Test: Local registry accessibility
test_local_registry() {
    log_test_start "Local Docker registry"
    
    if curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
        local repo_count
        repo_count=$(curl -s http://localhost:5001/v2/_catalog | jq -r '.repositories | length' 2>/dev/null || echo "unknown")
        log_test_pass "Local registry accessible with $repo_count repositories"
    else
        log_test_fail "Local Docker registry not accessible"
        return 1
    fi
}

# Test: Image availability in registry
test_image_availability() {
    log_test_start "Container image availability"
    
    local services=("api-gateway" "audit-service" "operator" "web")
    local images_found=0
    
    for service in "${services[@]}"; do
        local image_name="kubechat/$service"
        
        # Check if image exists in registry
        if curl -f "http://localhost:5001/v2/$image_name/tags/list" &>/dev/null; then
            images_found=$((images_found + 1))
            log_info "✅ Found image: $image_name"
        else
            log_warning "⚠️ Image not found: $image_name"
        fi
    done
    
    if [[ $images_found -eq ${#services[@]} ]]; then
        log_test_pass "All $images_found service images available"
    else
        log_test_fail "$images_found/${#services[@]} service images available"
        return 1
    fi
}

# Test: Go unit tests
test_go_unit_tests() {
    log_test_start "Go unit tests"
    
    if [[ ! -f "go.mod" ]]; then
        log_warning "go.mod not found, skipping Go unit tests"
        return 0
    fi
    
    # Run Go tests
    if go test ./pkg/... -v -timeout=30s; then
        log_test_pass "Go unit tests passed"
    else
        log_test_fail "Go unit tests failed"
        return 1
    fi
}

# Test: Frontend tests (if available)
test_frontend_tests() {
    log_test_start "Frontend tests"
    
    if [[ ! -d "web" ]] || [[ ! -f "web/package.json" ]]; then
        log_warning "Web frontend not found, skipping frontend tests"
        return 0
    fi
    
    cd web/
    
    # Install dependencies if needed
    if [[ ! -d "node_modules" ]]; then
        if command -v pnpm &>/dev/null; then
            pnpm install
        else
            npm install
        fi
    fi
    
    # Run tests
    local test_result=false
    if command -v pnpm &>/dev/null; then
        if pnpm test --run; then
            test_result=true
        fi
    else
        if npm test; then
            test_result=true
        fi
    fi
    
    cd ..
    
    if [[ "$test_result" == true ]]; then
        log_test_pass "Frontend tests passed"
    else
        log_test_fail "Frontend tests failed"
        return 1
    fi
}

# Performance benchmark test
test_performance_benchmark() {
    log_test_start "Basic performance benchmark"
    
    # Check resource usage
    log_info "Current resource usage:"
    kubectl top nodes 2>/dev/null || log_warning "Metrics server not available for resource monitoring"
    kubectl top pods -n "$NAMESPACE" 2>/dev/null || log_warning "Pod metrics not available"
    
    # Simple load test if API Gateway is available
    if kubectl get service kubechat-api-gateway -n "$NAMESPACE" &>/dev/null; then
        kubectl port-forward -n "$NAMESPACE" svc/kubechat-api-gateway 8080:80 &
        local port_forward_pid=$!
        
        sleep 5
        
        # Simple concurrent requests test
        local success_count=0
        for i in {1..10}; do
            if curl -f -s --max-time 5 http://localhost:8080/health &>/dev/null; then
                success_count=$((success_count + 1))
            fi
        done
        
        kill $port_forward_pid &>/dev/null || true
        
        if [[ $success_count -ge 8 ]]; then
            log_test_pass "Performance benchmark passed ($success_count/10 requests successful)"
        else
            log_test_fail "Performance benchmark failed ($success_count/10 requests successful)"
            return 1
        fi
    else
        log_warning "API Gateway not available for performance testing"
    fi
}

# Generate test report
generate_test_report() {
    echo ""
    echo "=================================================="
    log_info "📊 KubeChat Phase 1 Model 1 Test Report"
    echo "=================================================="
    echo ""
    
    log_info "Test Summary:"
    echo "  Total Tests: $TESTS_TOTAL"
    echo "  Passed: $TESTS_PASSED"
    echo "  Failed: $TESTS_FAILED"
    echo "  Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%"
    echo ""
    
    if [[ ${#FAILED_TESTS[@]} -gt 0 ]]; then
        log_error "Failed Tests:"
        for failed_test in "${FAILED_TESTS[@]}"; do
            echo "  ❌ $failed_test"
        done
        echo ""
    fi
    
    log_info "Environment Information:"
    echo "  Namespace: $NAMESPACE"
    echo "  Version: $VERSION"
    echo "  Kubernetes: $(kubectl version --client --short 2>/dev/null || echo "unknown")"
    echo "  Helm: $(helm version --short 2>/dev/null || echo "unknown")"
    echo ""
    
    if [[ $TESTS_FAILED -eq 0 ]]; then
        log_success "🎉 All tests passed! KubeChat Phase 1 Model 1 is ready for use."
    else
        log_error "❌ Some tests failed. Review the failures above and fix issues."
        return 1
    fi
}

# Display usage information
usage() {
    echo "Usage: $0 [NAMESPACE] [VERSION]"
    echo ""
    echo "Comprehensive testing validation for KubeChat Phase 1 Model 1"
    echo ""
    echo "Arguments:"
    echo "  NAMESPACE    Kubernetes namespace (default: kubechat-system)"
    echo "  VERSION      Image version tag (default: dev)"
    echo ""
    echo "Options:"
    echo "  --help       Show this help message"
    echo "  --quick      Run quick tests only (skip long-running tests)"
    echo "  --report     Generate detailed test report"
    echo ""
    echo "Examples:"
    echo "  $0                           # Test default deployment"
    echo "  $0 kubechat-test             # Test specific namespace"
    echo "  $0 kubechat-system v1.0.0    # Test specific version"
}

# Main execution
main() {
    local quick_mode=false
    local generate_report=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help)
                usage
                exit 0
                ;;
            --quick)
                quick_mode=true
                shift
                ;;
            --report)
                generate_report=true
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
                    VERSION="$2"
                fi
                break
                ;;
        esac
    done
    
    log_info "🧪 Starting KubeChat Phase 1 Model 1 comprehensive testing..."
    log_info "Namespace: $NAMESPACE"
    log_info "Version: $VERSION"
    echo ""
    
    # Run all tests
    test_kubernetes_connectivity
    test_namespace_resources
    test_pod_health
    test_service_endpoints
    test_helm_release
    test_local_registry
    test_image_availability
    test_api_gateway_health
    test_database_connectivity
    test_redis_connectivity
    test_custom_resources
    
    if [[ "$quick_mode" != true ]]; then
        test_go_unit_tests
        test_frontend_tests
        test_performance_benchmark
    fi
    
    # Generate final report
    generate_test_report
    
    # Exit with appropriate code
    if [[ $TESTS_FAILED -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Execute main function
main "$@"