#!/bin/bash
# setup-port-forwards.sh
# Helper script to set up all port forwards for KubeChat development

set -euo pipefail

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE="kubechat-system"

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

# Display usage
usage() {
    echo "Usage: $0 [start|stop|status|test]"
    echo ""
    echo "Commands:"
    echo "  start   - Start all port forwards"
    echo "  stop    - Stop all port forwards"
    echo "  status  - Check port forward status"
    echo "  test    - Test all service endpoints"
    echo ""
    echo "Port mappings:"
    echo "  API Gateway:   localhost:8080 -> kubechat-dev-api-gateway:8080"
    echo "  Audit Service: localhost:8081 -> kubechat-dev-audit-service:8081"
    echo "  Web Interface: localhost:8083 -> kubechat-dev-web:8083"
    echo "  Operator:      localhost:8082 -> kubechat-dev-operator:8082"
    echo "  NLP Service:   localhost:8084 -> kubechat-dev-nlp-service:8084"
    echo "  PostgreSQL:    localhost:5432 -> postgres-postgresql:5432"
    echo "  Redis:         localhost:6379 -> kubechat-dev-redis:6379"
    echo "  Ollama:        localhost:11434 -> kubechat-dev-ollama:11434"
}

# Check if kubectl can access the cluster
check_cluster_access() {
    if ! kubectl cluster-info &>/dev/null; then
        log_error "Cannot access Kubernetes cluster"
        log_error "Ensure Rancher Desktop is running and kubectl is configured"
        exit 1
    fi
}

# Check if namespace exists and has running pods
check_deployment() {
    if ! kubectl get namespace "$NAMESPACE" &>/dev/null; then
        log_error "Namespace '$NAMESPACE' not found"
        log_error "Deploy KubeChat first using: ./scripts/deploy-dev.sh"
        exit 1
    fi
    
    local running_pods
    running_pods=$(kubectl get pods -n "$NAMESPACE" --field-selector=status.phase=Running -o name | wc -l)
    
    if [ "$running_pods" -eq 0 ]; then
        log_error "No running pods found in namespace '$NAMESPACE'"
        log_error "Deploy KubeChat first using: ./scripts/deploy-dev.sh"
        exit 1
    fi
    
    log_info "Found $running_pods running pods in namespace '$NAMESPACE'"
}

# Start port forwards
start_port_forwards() {
    log_info "🚀 Starting port forwards for KubeChat development environment..."
    
    check_cluster_access
    check_deployment
    
    # Kill any existing port forwards
    pkill -f "kubectl port-forward.*$NAMESPACE" 2>/dev/null || true
    sleep 2
    
    # Start port forwards in background
    log_info "Starting API Gateway port forward (8080)..."
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-dev-api-gateway 8080:8080 > /dev/null 2>&1 &
    
    log_info "Starting Audit Service port forward (8081)..."
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-dev-audit-service 8081:8081 > /dev/null 2>&1 &
    
    log_info "Starting Web Interface port forward (8083)..."
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-dev-web 8083:8083 > /dev/null 2>&1 &
    
    # Operator requires pod port forward since there's no service
    log_info "Starting Operator port forward (8082)..."
    local operator_pod
    operator_pod=$(kubectl get pod -n "$NAMESPACE" -l app.kubernetes.io/component=operator -o jsonpath='{.items[0].metadata.name}')
    kubectl port-forward -n "$NAMESPACE" "$operator_pod" 8082:8082 > /dev/null 2>&1 &
    
    log_info "Starting NLP Service port forward (8084)..."
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-dev-nlp-service 8084:8084 > /dev/null 2>&1 &
    
    log_info "Starting PostgreSQL port forward (5432)..."
    kubectl port-forward -n "$NAMESPACE" svc/postgres-postgresql 5432:5432 > /dev/null 2>&1 &
    
    log_info "Starting Redis port forward (6379)..."
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-dev-redis 6379:6379 > /dev/null 2>&1 &
    
    log_info "Starting Ollama port forward (11434)..."
    kubectl port-forward -n "$NAMESPACE" svc/kubechat-dev-ollama 11434:11434 > /dev/null 2>&1 &
    
    # Wait for port forwards to establish
    log_info "Waiting for port forwards to establish..."
    sleep 5
    
    # Check if port forwards are working
    local failed=0
    for port in 8080 8081 8082 8083 8084 5432 6379 11434; do
        if ! lsof -i :$port &>/dev/null; then
            log_warning "Port forward for port $port may not be working"
            ((failed++))
        fi
    done
    
    if [ $failed -eq 0 ]; then
        log_success "✅ All port forwards started successfully!"
    else
        log_warning "⚠️ Some port forwards may have issues. Check status with: $0 status"
    fi
    
    echo ""
    log_info "📋 Access URLs:"
    echo "  🌐 Web Interface:  http://localhost:8083"
    echo "  🔌 API Gateway:    http://localhost:8080"
    echo "  📊 Audit Service:  http://localhost:8081" 
    echo "  ⚙️ Operator:       http://localhost:8082"
    echo "  🗃️ PostgreSQL:     localhost:5432"
    echo "  ⚡ Redis:          localhost:6379"
    echo ""
    log_info "Use '$0 test' to verify all endpoints are responding"
}

# Stop port forwards
stop_port_forwards() {
    log_info "🛑 Stopping all KubeChat port forwards..."
    
    # Kill all kubectl port-forward processes for kubechat-system namespace
    pkill -f "kubectl port-forward.*$NAMESPACE" 2>/dev/null || log_info "No port forwards found"
    
    # Also kill any port forwards that might be using our ports
    for port in 8080 8081 8082 8083 8084 5432 6379 11434; do
        local pid
        pid=$(lsof -t -i:$port 2>/dev/null || echo "")
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    
    sleep 2
    log_success "✅ All port forwards stopped"
}

# Check port forward status
check_status() {
    log_info "📊 Port forward status:"
    echo ""
    
    local ports=(8080 8081 8082 8083 8084 5432 6379 11434)
    local services=("API Gateway" "Audit Service" "Operator" "Web Interface" "NLP Service" "PostgreSQL" "Redis" "Ollama")
    local active=0
    
    for i in "${!ports[@]}"; do
        local port="${ports[$i]}"
        local service="${services[$i]}"
        
        if lsof -i :$port &>/dev/null; then
            log_success "✅ $service (port $port) - ACTIVE"
            ((active++))
        else
            log_error "❌ $service (port $port) - INACTIVE"
        fi
    done
    
    echo ""
    log_info "Active port forwards: $active/${#ports[@]}"
    
    if [ $active -gt 0 ]; then
        echo ""
        log_info "Running kubectl port-forward processes:"
        ps aux | grep "kubectl port-forward" | grep -v grep || echo "  None found"
    fi
}

# Test all endpoints
test_endpoints() {
    log_info "🧪 Testing all service endpoints..."
    echo ""
    
    # Check if port forwards are active first
    local active_ports=0
    for port in 8080 8081 8083 8084 11434; do
        if lsof -i :$port &>/dev/null; then
            ((active_ports++))
        fi
    done
    
    if [ $active_ports -eq 0 ]; then
        log_error "No port forwards detected. Start them first with: $0 start"
        exit 1
    fi
    
    # Test each service
    local passed=0
    local total=6
    
    # API Gateway
    log_info "Testing API Gateway (http://localhost:8080/health)..."
    if curl -f -s http://localhost:8080/health > /dev/null 2>&1; then
        log_success "✅ API Gateway - Healthy"
        ((passed++))
    else
        log_error "❌ API Gateway - Failed"
    fi
    
    # Audit Service
    log_info "Testing Audit Service (http://localhost:8081/health)..."
    if curl -f -s http://localhost:8081/health > /dev/null 2>&1; then
        log_success "✅ Audit Service - Healthy"
        ((passed++))
    else
        log_error "❌ Audit Service - Failed"
    fi
    
    # Web Interface
    log_info "Testing Web Interface (http://localhost:8083/health)..."
    if curl -f -s http://localhost:8083/health > /dev/null 2>&1; then
        log_success "✅ Web Interface - Healthy"
        ((passed++))
    else
        log_error "❌ Web Interface - Failed"
    fi
    
    # Operator (may not have port forward active)
    log_info "Testing Operator (http://localhost:8082/healthz)..."
    if lsof -i :8082 &>/dev/null && curl -f -s http://localhost:8082/healthz > /dev/null 2>&1; then
        log_success "✅ Operator - Healthy"
        ((passed++))
    else
        log_warning "⚠️ Operator - Not accessible (normal if service not exposed)"
    fi
    
    # NLP Service
    log_info "Testing NLP Service (http://localhost:8084/health)..."
    if curl -f -s http://localhost:8084/health > /dev/null 2>&1; then
        log_success "✅ NLP Service - Healthy"
        ((passed++))
    else
        log_error "❌ NLP Service - Failed"
    fi
    
    # Ollama
    log_info "Testing Ollama (http://localhost:11434/api/version)..."
    if curl -f -s http://localhost:11434/api/version > /dev/null 2>&1; then
        log_success "✅ Ollama - Healthy"
        ((passed++))
    else
        log_error "❌ Ollama - Failed"
    fi
    
    echo ""
    log_info "Health check results: $passed/$total services responding"
    
    if [ $passed -ge 4 ]; then
        log_success "🎉 Environment is ready for development!"
    else
        log_error "❌ Environment has issues. Check deployment status."
        exit 1
    fi
}

# Main execution
main() {
    case "${1:-}" in
        "start")
            start_port_forwards
            ;;
        "stop")
            stop_port_forwards
            ;;
        "status")
            check_status
            ;;
        "test")
            test_endpoints
            ;;
        "restart")
            stop_port_forwards
            sleep 2
            start_port_forwards
            ;;
        "help"|"--help"|"-h"|"")
            usage
            ;;
        *)
            log_error "Unknown command: $1"
            echo ""
            usage
            exit 1
            ;;
    esac
}

# Execute main function with all arguments
main "$@"