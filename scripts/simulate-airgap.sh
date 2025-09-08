#!/bin/bash

# KubeChat Air-Gap Environment Simulation Script
# Setup and validation of air-gap deployment environment
# Usage: ./scripts/simulate-airgap.sh [options]
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
LOG_FILE="${LOG_DIR}/airgap-simulation_${TIMESTAMP}.log"

# Air-gap simulation configuration
SIMULATION_MODE="start"
AIRGAP_NAMESPACE="kubechat-airgap"
LOCAL_REGISTRY="localhost:5001"
REGISTRY_CONTAINER="airgap-registry"
SIMULATION_PID_FILE="/tmp/airgap-simulation.pid"
IPTABLES_BACKUP_FILE="/tmp/airgap-iptables-backup"

# Network isolation configuration
BLOCK_EXTERNAL_DNS=true
BLOCK_EXTERNAL_HTTP=true
BLOCK_EXTERNAL_HTTPS=true
ALLOW_LOCAL_REGISTRY=true
ALLOW_CLUSTER_COMMUNICATION=true

# Validation configuration
VALIDATE_ISOLATION=true
VALIDATION_TIMEOUT=30
VERBOSE=false

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

check_root_privileges() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root user"
        return 0
    fi
    
    # Check if we can use sudo
    if ! sudo -n true 2>/dev/null; then
        log_error "This script requires root privileges for network configuration"
        log_error "Please run with sudo or configure passwordless sudo"
        exit 1
    fi
    
    log_info "Sudo access confirmed"
    return 0
}

check_dependencies() {
    local deps=("docker" "kubectl" "iptables")
    local optional_deps=("jq" "curl" "ping")
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
    
    # Check optional dependencies
    for dep in "${optional_deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            log_warn "Optional dependency missing: $dep"
        fi
    done
    
    log_success "Required dependencies available"
}

# =============================================================================
# REGISTRY MANAGEMENT
# =============================================================================

start_local_registry() {
    print_section "Starting Local Registry"
    
    # Check if registry is already running
    if docker ps --filter "name=$REGISTRY_CONTAINER" --filter "status=running" | grep -q "$REGISTRY_CONTAINER"; then
        log_info "Local registry already running"
        return 0
    fi
    
    # Remove existing stopped container
    if docker ps -a --filter "name=$REGISTRY_CONTAINER" | grep -q "$REGISTRY_CONTAINER"; then
        log_info "Removing existing registry container"
        docker rm "$REGISTRY_CONTAINER" >/dev/null 2>&1 || true
    fi
    
    # Start registry container
    log_info "Starting local Docker registry on port 5000..."
    docker run -d \
        --name "$REGISTRY_CONTAINER" \
        --restart=unless-stopped \
        -p 5000:5000 \
        -e REGISTRY_STORAGE_DELETE_ENABLED=true \
        -v registry-data:/var/lib/registry \
        registry:2 >/dev/null
    
    # Wait for registry to be ready
    local retry_count=0
    while [[ $retry_count -lt 30 ]]; do
        if curl -s "http://$LOCAL_REGISTRY/v2/" >/dev/null 2>&1; then
            log_success "Local registry is ready"
            return 0
        fi
        sleep 1
        ((retry_count++))
    done
    
    log_error "Failed to start local registry"
    return 1
}

stop_local_registry() {
    print_section "Stopping Local Registry"
    
    if docker ps --filter "name=$REGISTRY_CONTAINER" --filter "status=running" | grep -q "$REGISTRY_CONTAINER"; then
        log_info "Stopping local registry container"
        docker stop "$REGISTRY_CONTAINER" >/dev/null
        docker rm "$REGISTRY_CONTAINER" >/dev/null
        log_success "Local registry stopped"
    else
        log_info "Local registry not running"
    fi
}

# =============================================================================
# NETWORK ISOLATION
# =============================================================================

backup_iptables_rules() {
    log_info "Backing up current iptables rules..."
    sudo iptables-save > "$IPTABLES_BACKUP_FILE"
    log_success "Iptables rules backed up to $IPTABLES_BACKUP_FILE"
}

restore_iptables_rules() {
    if [[ -f "$IPTABLES_BACKUP_FILE" ]]; then
        log_info "Restoring original iptables rules..."
        sudo iptables-restore < "$IPTABLES_BACKUP_FILE"
        rm -f "$IPTABLES_BACKUP_FILE"
        log_success "Iptables rules restored"
    else
        log_warn "No iptables backup found, skipping restore"
    fi
}

setup_network_isolation() {
    print_section "Setting Up Network Isolation"
    
    # Backup current rules
    backup_iptables_rules
    
    # Create custom chain for air-gap rules
    sudo iptables -N AIRGAP_BLOCK 2>/dev/null || true
    sudo iptables -F AIRGAP_BLOCK
    
    # Allow loopback traffic
    sudo iptables -A AIRGAP_BLOCK -i lo -j ACCEPT
    sudo iptables -A AIRGAP_BLOCK -o lo -j ACCEPT
    
    # Allow local registry traffic
    if [[ "$ALLOW_LOCAL_REGISTRY" == "true" ]]; then
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 5000 -j ACCEPT
        sudo iptables -A AIRGAP_BLOCK -p tcp --sport 5000 -j ACCEPT
        log_info "Allowed local registry traffic on port 5000"
    fi
    
    # Allow cluster communication (Kubernetes API, kubelet, etc.)
    if [[ "$ALLOW_CLUSTER_COMMUNICATION" == "true" ]]; then
        # Allow traffic to/from cluster IP ranges
        sudo iptables -A AIRGAP_BLOCK -d 10.0.0.0/8 -j ACCEPT
        sudo iptables -A AIRGAP_BLOCK -s 10.0.0.0/8 -j ACCEPT
        sudo iptables -A AIRGAP_BLOCK -d 172.16.0.0/12 -j ACCEPT
        sudo iptables -A AIRGAP_BLOCK -s 172.16.0.0/12 -j ACCEPT
        sudo iptables -A AIRGAP_BLOCK -d 192.168.0.0/16 -j ACCEPT
        sudo iptables -A AIRGAP_BLOCK -s 192.168.0.0/16 -j ACCEPT
        
        # Allow common Kubernetes ports
        local k8s_ports=(6443 2379 2380 10250 10251 10252 10255)
        for port in "${k8s_ports[@]}"; do
            sudo iptables -A AIRGAP_BLOCK -p tcp --dport "$port" -j ACCEPT
            sudo iptables -A AIRGAP_BLOCK -p tcp --sport "$port" -j ACCEPT
        done
        
        log_info "Allowed cluster communication"
    fi
    
    # Block external DNS (port 53)
    if [[ "$BLOCK_EXTERNAL_DNS" == "true" ]]; then
        sudo iptables -A AIRGAP_BLOCK -p udp --dport 53 -d 8.8.8.8 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p udp --dport 53 -d 8.8.4.4 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p udp --dport 53 -d 1.1.1.1 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p udp --dport 53 -d 1.0.0.1 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 53 -d 8.8.8.8 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 53 -d 8.8.4.4 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 53 -d 1.1.1.1 -j DROP
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 53 -d 1.0.0.1 -j DROP
        log_info "Blocked external DNS queries"
    fi
    
    # Block external HTTP (port 80)
    if [[ "$BLOCK_EXTERNAL_HTTP" == "true" ]]; then
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 80 ! -d 10.0.0.0/8 ! -d 172.16.0.0/12 ! -d 192.168.0.0/16 ! -d 127.0.0.0/8 -j DROP
        log_info "Blocked external HTTP traffic"
    fi
    
    # Block external HTTPS (port 443)
    if [[ "$BLOCK_EXTERNAL_HTTPS" == "true" ]]; then
        sudo iptables -A AIRGAP_BLOCK -p tcp --dport 443 ! -d 10.0.0.0/8 ! -d 172.16.0.0/12 ! -d 192.168.0.0/16 ! -d 127.0.0.0/8 -j DROP
        log_info "Blocked external HTTPS traffic"
    fi
    
    # Insert the chain into OUTPUT
    sudo iptables -I OUTPUT -j AIRGAP_BLOCK
    
    log_success "Network isolation configured"
}

remove_network_isolation() {
    print_section "Removing Network Isolation"
    
    # Remove the custom chain from OUTPUT
    sudo iptables -D OUTPUT -j AIRGAP_BLOCK 2>/dev/null || true
    
    # Flush and delete custom chain
    sudo iptables -F AIRGAP_BLOCK 2>/dev/null || true
    sudo iptables -X AIRGAP_BLOCK 2>/dev/null || true
    
    # Restore original rules
    restore_iptables_rules
    
    log_success "Network isolation removed"
}

# =============================================================================
# VALIDATION FUNCTIONS
# =============================================================================

validate_network_isolation() {
    print_section "Validating Network Isolation"
    
    if [[ "$VALIDATE_ISOLATION" != "true" ]]; then
        log_info "Network validation skipped (disabled)"
        return 0
    fi
    
    local validation_errors=0
    
    # Test external DNS blocking
    log_info "Testing external DNS blocking..."
    if timeout "$VALIDATION_TIMEOUT" nslookup google.com 8.8.8.8 >/dev/null 2>&1; then
        log_error "External DNS is not properly blocked"
        ((validation_errors++))
    else
        log_success "External DNS is properly blocked"
    fi
    
    # Test external HTTP blocking
    log_info "Testing external HTTP blocking..."
    if timeout "$VALIDATION_TIMEOUT" curl -s http://google.com >/dev/null 2>&1; then
        log_error "External HTTP is not properly blocked"
        ((validation_errors++))
    else
        log_success "External HTTP is properly blocked"
    fi
    
    # Test external HTTPS blocking
    log_info "Testing external HTTPS blocking..."
    if timeout "$VALIDATION_TIMEOUT" curl -s https://google.com >/dev/null 2>&1; then
        log_error "External HTTPS is not properly blocked"
        ((validation_errors++))
    else
        log_success "External HTTPS is properly blocked"
    fi
    
    # Test local registry access
    log_info "Testing local registry access..."
    if ! timeout "$VALIDATION_TIMEOUT" curl -s "http://$LOCAL_REGISTRY/v2/" >/dev/null 2>&1; then
        log_error "Local registry is not accessible"
        ((validation_errors++))
    else
        log_success "Local registry is accessible"
    fi
    
    # Test localhost access
    log_info "Testing localhost access..."
    if ! timeout "$VALIDATION_TIMEOUT" curl -s http://localhost:5001/v2/ >/dev/null 2>&1; then
        log_error "Localhost access is blocked"
        ((validation_errors++))
    else
        log_success "Localhost access is working"
    fi
    
    if [[ $validation_errors -eq 0 ]]; then
        log_success "Network isolation validation passed"
        return 0
    else
        log_error "Network isolation validation failed with $validation_errors error(s)"
        return 1
    fi
}

validate_registry_connectivity() {
    print_section "Validating Registry Connectivity"
    
    # Test registry API endpoints
    local endpoints=("/v2/" "/v2/_catalog")
    
    for endpoint in "${endpoints[@]}"; do
        log_info "Testing registry endpoint: $endpoint"
        
        if ! curl -s "http://$LOCAL_REGISTRY$endpoint" >/dev/null; then
            log_error "Registry endpoint not accessible: $endpoint"
            return 1
        fi
    done
    
    # Test image push/pull simulation
    log_info "Testing registry functionality..."
    
    # Pull a small image if not present
    if ! docker images | grep -q "hello-world.*latest"; then
        log_info "Pulling hello-world image for testing..."
        docker pull hello-world:latest >/dev/null
    fi
    
    # Tag and push to local registry
    local test_image="$LOCAL_REGISTRY/test/hello-world:latest"
    docker tag hello-world:latest "$test_image" >/dev/null
    
    if ! docker push "$test_image" >/dev/null 2>&1; then
        log_error "Failed to push test image to registry"
        return 1
    fi
    
    # Remove local image and pull from registry
    docker rmi "$test_image" >/dev/null 2>&1 || true
    
    if ! docker pull "$test_image" >/dev/null 2>&1; then
        log_error "Failed to pull test image from registry"
        return 1
    fi
    
    # Cleanup test image
    docker rmi "$test_image" >/dev/null 2>&1 || true
    
    log_success "Registry connectivity validation passed"
    return 0
}

# =============================================================================
# SIMULATION MANAGEMENT
# =============================================================================

start_simulation() {
    print_section "Starting Air-Gap Simulation"
    
    # Check if simulation is already running
    if [[ -f "$SIMULATION_PID_FILE" ]]; then
        local existing_pid=$(cat "$SIMULATION_PID_FILE")
        if kill -0 "$existing_pid" 2>/dev/null; then
            log_warn "Air-gap simulation already running (PID: $existing_pid)"
            return 0
        else
            log_info "Removing stale PID file"
            rm -f "$SIMULATION_PID_FILE"
        fi
    fi
    
    # Start local registry
    start_local_registry
    
    # Setup network isolation
    setup_network_isolation
    
    # Validate isolation
    validate_network_isolation
    validate_registry_connectivity
    
    # Save simulation PID
    echo $$ > "$SIMULATION_PID_FILE"
    
    log_success "Air-gap simulation started successfully"
    log_info "Simulation PID: $$"
    log_info "To stop simulation: $0 --stop"
    
    return 0
}

stop_simulation() {
    print_section "Stopping Air-Gap Simulation"
    
    # Remove network isolation
    remove_network_isolation
    
    # Stop local registry (optional)
    # stop_local_registry
    
    # Remove PID file
    rm -f "$SIMULATION_PID_FILE"
    
    log_success "Air-gap simulation stopped"
    return 0
}

status_simulation() {
    print_section "Air-Gap Simulation Status"
    
    # Check if simulation is running
    if [[ -f "$SIMULATION_PID_FILE" ]]; then
        local simulation_pid=$(cat "$SIMULATION_PID_FILE")
        if kill -0 "$simulation_pid" 2>/dev/null; then
            log_info "Air-gap simulation is running (PID: $simulation_pid)"
        else
            log_warn "Stale PID file found (process not running)"
            rm -f "$SIMULATION_PID_FILE"
        fi
    else
        log_info "Air-gap simulation is not running"
    fi
    
    # Check registry status
    if docker ps --filter "name=$REGISTRY_CONTAINER" --filter "status=running" | grep -q "$REGISTRY_CONTAINER"; then
        log_info "Local registry is running"
    else
        log_info "Local registry is not running"
    fi
    
    # Check network isolation
    if sudo iptables -L AIRGAP_BLOCK >/dev/null 2>&1; then
        log_info "Network isolation is active"
    else
        log_info "Network isolation is not active"
    fi
    
    return 0
}

# =============================================================================
# CLEANUP FUNCTIONS
# =============================================================================

cleanup() {
    log_info "Performing cleanup..."
    
    # Remove network isolation if active
    if sudo iptables -L AIRGAP_BLOCK >/dev/null 2>&1; then
        remove_network_isolation
    fi
    
    # Remove PID file
    rm -f "$SIMULATION_PID_FILE"
}

# Set cleanup trap
trap cleanup EXIT INT TERM

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Air-Gap Environment Simulation Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --start               Start air-gap simulation (default)
    --stop                Stop air-gap simulation
    --status              Show simulation status
    --validate            Validate current air-gap configuration
    --no-dns-block        Don't block external DNS
    --no-http-block       Don't block external HTTP
    --no-https-block      Don't block external HTTPS
    --no-registry         Don't start local registry
    --no-validation       Skip validation checks
    --verbose             Enable verbose logging
    --timeout SECONDS     Set validation timeout (default: 30)
    --help                Show this help message

EXAMPLES:
    # Start air-gap simulation
    $0 --start

    # Stop air-gap simulation
    $0 --stop

    # Check simulation status
    $0 --status

    # Start with custom configuration
    $0 --start --no-dns-block --verbose

    # Validate current air-gap setup
    $0 --validate
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --start)
                SIMULATION_MODE="start"
                shift
                ;;
            --stop)
                SIMULATION_MODE="stop"
                shift
                ;;
            --status)
                SIMULATION_MODE="status"
                shift
                ;;
            --validate)
                SIMULATION_MODE="validate"
                shift
                ;;
            --no-dns-block)
                BLOCK_EXTERNAL_DNS=false
                shift
                ;;
            --no-http-block)
                BLOCK_EXTERNAL_HTTP=false
                shift
                ;;
            --no-https-block)
                BLOCK_EXTERNAL_HTTPS=false
                shift
                ;;
            --no-registry)
                ALLOW_LOCAL_REGISTRY=false
                shift
                ;;
            --no-validation)
                VALIDATE_ISOLATION=false
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --timeout)
                VALIDATION_TIMEOUT="$2"
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
    
    print_header "KubeChat Air-Gap Environment Simulation"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Air-gap simulation script starting"
    log_info "Mode: $SIMULATION_MODE"
    log_info "Log file: $LOG_FILE"
    
    # Check dependencies
    check_dependencies
    
    # Check root privileges for network configuration
    if [[ "$SIMULATION_MODE" == "start" ]] || [[ "$SIMULATION_MODE" == "stop" ]]; then
        check_root_privileges
    fi
    
    # Execute based on mode
    case $SIMULATION_MODE in
        start)
            start_simulation
            ;;
        stop)
            stop_simulation
            ;;
        status)
            status_simulation
            ;;
        validate)
            validate_network_isolation
            validate_registry_connectivity
            ;;
        *)
            log_error "Invalid simulation mode: $SIMULATION_MODE"
            exit 1
            ;;
    esac
    
    log_success "Air-gap simulation operation completed"
}

# Execute main function with all arguments
main "$@"