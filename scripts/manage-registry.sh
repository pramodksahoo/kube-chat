#!/bin/bash

# KubeChat Local Docker Registry Management Script
# Setup, management, and maintenance of local container registry
# Usage: ./scripts/manage-registry.sh [options]
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
LOG_FILE="${LOG_DIR}/registry-management_${TIMESTAMP}.log"

# Registry configuration
REGISTRY_NAME="kubechat-registry"
REGISTRY_PORT="5000"
REGISTRY_HOST="localhost"
REGISTRY_URL="${REGISTRY_HOST}:${REGISTRY_PORT}"
REGISTRY_DATA_DIR="${PROJECT_ROOT}/.registry-data"

# Registry settings
REGISTRY_IMAGE="registry:2"
ENABLE_DELETE_API=true
ENABLE_CORS=true
ENABLE_PROMETHEUS_METRICS=true
REGISTRY_LOG_LEVEL="info"

# Management operations
OPERATION="status"  # start, stop, restart, status, clean, backup, restore
BACKUP_DIR="${PROJECT_ROOT}/registry-backups"
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

check_dependencies() {
    local deps=("docker" "curl" "jq")
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

# =============================================================================
# REGISTRY MANAGEMENT FUNCTIONS
# =============================================================================

check_registry_status() {
    if docker ps --filter "name=$REGISTRY_NAME" --filter "status=running" | grep -q "$REGISTRY_NAME"; then
        return 0  # Running
    elif docker ps -a --filter "name=$REGISTRY_NAME" | grep -q "$REGISTRY_NAME"; then
        return 1  # Stopped
    else
        return 2  # Not found
    fi
}

get_registry_info() {
    local status_code
    check_registry_status
    status_code=$?
    
    case $status_code in
        0)
            echo "Running"
            ;;
        1)
            echo "Stopped"
            ;;
        2)
            echo "Not Found"
            ;;
    esac
}

start_registry() {
    print_section "Starting Local Docker Registry"
    
    local status
    status=$(get_registry_info)
    
    case $status in
        "Running")
            log_info "Registry already running"
            return 0
            ;;
        "Stopped")
            log_info "Starting existing registry container"
            docker start "$REGISTRY_NAME" >/dev/null
            ;;
        "Not Found")
            log_info "Creating new registry container"
            create_registry_container
            ;;
    esac
    
    # Wait for registry to be ready
    local retry_count=0
    while [[ $retry_count -lt 30 ]]; do
        if curl -s "http://$REGISTRY_URL/v2/" >/dev/null 2>&1; then
            log_success "Registry is ready at http://$REGISTRY_URL"
            break
        fi
        
        sleep 1
        ((retry_count++))
    done
    
    if [[ $retry_count -ge 30 ]]; then
        log_error "Registry failed to start within timeout"
        return 1
    fi
    
    # Display registry information
    show_registry_info
    
    return 0
}

create_registry_container() {
    # Ensure data directory exists
    mkdir -p "$REGISTRY_DATA_DIR"
    
    # Registry configuration
    local registry_config="{
        \"version\": \"0.1\",
        \"log\": {
            \"level\": \"$REGISTRY_LOG_LEVEL\"
        },
        \"storage\": {
            \"filesystem\": {
                \"rootdirectory\": \"/var/lib/registry\"
            }
        },
        \"http\": {
            \"addr\": \":5000\",
            \"headers\": {
                \"X-Content-Type-Options\": [\"nosniff\"]
            }
        },
        \"delete\": {
            \"enabled\": $ENABLE_DELETE_API
        }
    }"
    
    if [[ "$ENABLE_CORS" == "true" ]]; then
        registry_config=$(echo "$registry_config" | jq '.http.headers["Access-Control-Allow-Origin"] = ["*"]' | jq '.http.headers["Access-Control-Allow-Methods"] = ["HEAD","GET","OPTIONS","DELETE"]' | jq '.http.headers["Access-Control-Allow-Headers"] = ["Authorization","Accept","Cache-Control"]')
    fi
    
    # Save configuration
    local config_file="${REGISTRY_DATA_DIR}/config.yml"
    echo "$registry_config" | jq -r '.' > "$config_file"
    
    log_info "Creating registry container with configuration..."
    
    docker run -d \
        --name "$REGISTRY_NAME" \
        --restart=unless-stopped \
        -p "$REGISTRY_PORT:5000" \
        -v "$REGISTRY_DATA_DIR:/var/lib/registry" \
        -v "$config_file:/etc/docker/registry/config.yml" \
        -e REGISTRY_STORAGE_DELETE_ENABLED="$ENABLE_DELETE_API" \
        "$REGISTRY_IMAGE" >/dev/null
    
    log_success "Registry container created"
}

stop_registry() {
    print_section "Stopping Local Docker Registry"
    
    local status
    status=$(get_registry_info)
    
    case $status in
        "Running")
            log_info "Stopping registry container"
            docker stop "$REGISTRY_NAME" >/dev/null
            log_success "Registry stopped"
            ;;
        "Stopped")
            log_info "Registry already stopped"
            ;;
        "Not Found")
            log_info "Registry container not found"
            ;;
    esac
}

restart_registry() {
    print_section "Restarting Local Docker Registry"
    
    stop_registry
    sleep 2
    start_registry
}

remove_registry() {
    print_section "Removing Local Docker Registry"
    
    local status
    status=$(get_registry_info)
    
    if [[ "$status" == "Running" ]]; then
        log_info "Stopping running registry"
        docker stop "$REGISTRY_NAME" >/dev/null
    fi
    
    if [[ "$status" != "Not Found" ]]; then
        log_info "Removing registry container"
        docker rm "$REGISTRY_NAME" >/dev/null
        log_success "Registry container removed"
    else
        log_info "Registry container not found"
    fi
}

show_registry_status() {
    print_section "Registry Status"
    
    local status
    status=$(get_registry_info)
    
    log_info "Registry Status: $status"
    
    case $status in
        "Running")
            log_info "Registry URL: http://$REGISTRY_URL"
            log_info "Data Directory: $REGISTRY_DATA_DIR"
            
            # Test connectivity
            if curl -s "http://$REGISTRY_URL/v2/" >/dev/null; then
                log_success "Registry is accessible"
            else
                log_error "Registry is not responding"
            fi
            
            # Show container details
            if [[ "$VERBOSE" == "true" ]]; then
                docker ps --filter "name=$REGISTRY_NAME" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Size}}"
            fi
            ;;
        "Stopped")
            log_warn "Registry container exists but is stopped"
            ;;
        "Not Found")
            log_warn "Registry container does not exist"
            ;;
    esac
}

show_registry_info() {
    print_section "Registry Information"
    
    # Basic info
    log_info "Registry URL: http://$REGISTRY_URL"
    log_info "Registry Name: $REGISTRY_NAME"
    log_info "Data Directory: $REGISTRY_DATA_DIR"
    
    # API endpoints
    echo -e "\n${CYAN}Available API Endpoints:${NC}"
    echo "  - Health: http://$REGISTRY_URL/v2/"
    echo "  - Catalog: http://$REGISTRY_URL/v2/_catalog"
    echo "  - Repository tags: http://$REGISTRY_URL/v2/<name>/tags/list"
    echo "  - Manifest: http://$REGISTRY_URL/v2/<name>/manifests/<tag>"
    
    # Configuration
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "\n${CYAN}Configuration:${NC}"
        echo "  - Delete API: $ENABLE_DELETE_API"
        echo "  - CORS: $ENABLE_CORS"
        echo "  - Log Level: $REGISTRY_LOG_LEVEL"
        echo "  - Image: $REGISTRY_IMAGE"
    fi
}

# =============================================================================
# REGISTRY OPERATIONS
# =============================================================================

list_repositories() {
    print_section "Repository Catalog"
    
    if ! curl -s "http://$REGISTRY_URL/v2/" >/dev/null; then
        log_error "Registry not accessible"
        return 1
    fi
    
    local catalog
    catalog=$(curl -s "http://$REGISTRY_URL/v2/_catalog" 2>/dev/null)
    
    if [[ -z "$catalog" ]]; then
        log_warn "No repositories found or catalog unavailable"
        return 0
    fi
    
    local repositories
    repositories=$(echo "$catalog" | jq -r '.repositories[]?' 2>/dev/null || echo "")
    
    if [[ -z "$repositories" ]]; then
        log_info "No repositories found"
        return 0
    fi
    
    log_info "Found repositories:"
    while IFS= read -r repo; do
        if [[ -n "$repo" ]]; then
            echo "  - $repo"
            
            # Show tags if verbose
            if [[ "$VERBOSE" == "true" ]]; then
                local tags
                tags=$(curl -s "http://$REGISTRY_URL/v2/$repo/tags/list" | jq -r '.tags[]?' 2>/dev/null || echo "")
                
                if [[ -n "$tags" ]]; then
                    while IFS= read -r tag; do
                        if [[ -n "$tag" ]]; then
                            echo "    - $tag"
                        fi
                    done <<< "$tags"
                fi
            fi
        fi
    done <<< "$repositories"
}

show_registry_usage() {
    print_section "Registry Usage Statistics"
    
    if ! curl -s "http://$REGISTRY_URL/v2/" >/dev/null; then
        log_error "Registry not accessible"
        return 1
    fi
    
    # Data directory size
    if [[ -d "$REGISTRY_DATA_DIR" ]]; then
        local data_size
        data_size=$(du -sh "$REGISTRY_DATA_DIR" 2>/dev/null | cut -f1 || echo "Unknown")
        log_info "Data Directory Size: $data_size"
    fi
    
    # Container stats
    if docker ps --filter "name=$REGISTRY_NAME" --filter "status=running" | grep -q "$REGISTRY_NAME"; then
        local container_stats
        container_stats=$(docker stats "$REGISTRY_NAME" --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null || echo "Stats not available")
        
        if [[ "$container_stats" != "Stats not available" ]]; then
            echo -e "\n${CYAN}Container Statistics:${NC}"
            echo "$container_stats"
        fi
    fi
    
    # Repository count
    local repo_count
    repo_count=$(curl -s "http://$REGISTRY_URL/v2/_catalog" | jq -r '.repositories | length' 2>/dev/null || echo "0")
    log_info "Total Repositories: $repo_count"
    
    # Recent activity (from logs if verbose)
    if [[ "$VERBOSE" == "true" ]] && docker ps --filter "name=$REGISTRY_NAME" --filter "status=running" | grep -q "$REGISTRY_NAME"; then
        echo -e "\n${CYAN}Recent Activity (last 10 lines):${NC}"
        docker logs "$REGISTRY_NAME" --tail 10 2>/dev/null || log_warn "Logs not available"
    fi
}

# =============================================================================
# BACKUP AND RESTORE
# =============================================================================

backup_registry() {
    print_section "Backing Up Registry Data"
    
    if [[ ! -d "$REGISTRY_DATA_DIR" ]]; then
        log_error "Registry data directory not found: $REGISTRY_DATA_DIR"
        return 1
    fi
    
    mkdir -p "$BACKUP_DIR"
    
    local backup_name="registry-backup_${TIMESTAMP}.tar.gz"
    local backup_path="$BACKUP_DIR/$backup_name"
    
    log_info "Creating backup: $backup_name"
    
    # Stop registry for consistent backup
    local was_running=false
    if [[ $(get_registry_info) == "Running" ]]; then
        was_running=true
        log_info "Stopping registry for consistent backup"
        docker stop "$REGISTRY_NAME" >/dev/null
    fi
    
    # Create backup
    tar -czf "$backup_path" -C "$(dirname "$REGISTRY_DATA_DIR")" "$(basename "$REGISTRY_DATA_DIR")"
    
    # Restart registry if it was running
    if [[ "$was_running" == "true" ]]; then
        log_info "Restarting registry"
        docker start "$REGISTRY_NAME" >/dev/null
        
        # Wait for registry to be ready
        local retry_count=0
        while [[ $retry_count -lt 30 ]]; do
            if curl -s "http://$REGISTRY_URL/v2/" >/dev/null 2>&1; then
                break
            fi
            sleep 1
            ((retry_count++))
        done
    fi
    
    local backup_size
    backup_size=$(du -sh "$backup_path" | cut -f1)
    
    log_success "Backup created: $backup_path ($backup_size)"
    
    # Create backup manifest
    cat > "$BACKUP_DIR/backup-manifest_${TIMESTAMP}.json" <<EOF
{
  "backup_name": "$backup_name",
  "backup_path": "$backup_path",
  "backup_size": "$backup_size",
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "registry_url": "$REGISTRY_URL",
  "data_directory": "$REGISTRY_DATA_DIR",
  "was_running": $was_running
}
EOF
    
    log_info "Backup manifest created"
}

restore_registry() {
    print_section "Restoring Registry Data"
    
    local backup_file="$1"
    
    if [[ -z "$backup_file" ]]; then
        log_error "Backup file not specified"
        
        # List available backups
        if [[ -d "$BACKUP_DIR" ]]; then
            log_info "Available backups:"
            ls -la "$BACKUP_DIR"/*.tar.gz 2>/dev/null || log_info "No backup files found"
        fi
        
        return 1
    fi
    
    if [[ ! -f "$backup_file" ]]; then
        log_error "Backup file not found: $backup_file"
        return 1
    fi
    
    # Stop registry
    if [[ $(get_registry_info) == "Running" ]]; then
        log_info "Stopping registry for restore"
        docker stop "$REGISTRY_NAME" >/dev/null
    fi
    
    # Backup current data (if exists)
    if [[ -d "$REGISTRY_DATA_DIR" ]]; then
        local current_backup="${REGISTRY_DATA_DIR}.backup_${TIMESTAMP}"
        log_info "Backing up current data to: $current_backup"
        mv "$REGISTRY_DATA_DIR" "$current_backup"
    fi
    
    # Restore from backup
    log_info "Restoring from: $backup_file"
    tar -xzf "$backup_file" -C "$(dirname "$REGISTRY_DATA_DIR")"
    
    # Restart registry
    log_info "Starting registry after restore"
    start_registry
    
    log_success "Registry restored from backup"
}

list_backups() {
    print_section "Available Registry Backups"
    
    if [[ ! -d "$BACKUP_DIR" ]]; then
        log_info "No backup directory found: $BACKUP_DIR"
        return 0
    fi
    
    local backups
    backups=$(ls "$BACKUP_DIR"/registry-backup_*.tar.gz 2>/dev/null || echo "")
    
    if [[ -z "$backups" ]]; then
        log_info "No backup files found"
        return 0
    fi
    
    log_info "Available backups:"
    
    while IFS= read -r backup_file; do
        if [[ -f "$backup_file" ]]; then
            local filename=$(basename "$backup_file")
            local size=$(du -sh "$backup_file" | cut -f1)
            local date=$(stat -c %y "$backup_file" 2>/dev/null | cut -d' ' -f1 || echo "Unknown")
            
            echo "  - $filename ($size, $date)"
            
            # Show manifest info if available
            local manifest_file="${backup_file%.tar.gz}.json"
            if [[ -f "$manifest_file" ]] && [[ "$VERBOSE" == "true" ]]; then
                local created_at=$(jq -r '.created_at' "$manifest_file" 2>/dev/null || echo "Unknown")
                echo "    Created: $created_at"
            fi
        fi
    done <<< "$backups"
}

# =============================================================================
# CLEANUP OPERATIONS
# =============================================================================

clean_registry() {
    print_section "Cleaning Registry"
    
    local clean_type="${1:-all}"  # all, images, containers, data
    
    case $clean_type in
        "images")
            clean_unused_images
            ;;
        "containers")
            clean_registry_containers
            ;;
        "data")
            clean_registry_data
            ;;
        "all")
            clean_unused_images
            clean_registry_containers
            clean_registry_data
            ;;
        *)
            log_error "Unknown clean type: $clean_type"
            return 1
            ;;
    esac
}

clean_unused_images() {
    log_info "Cleaning unused Docker images..."
    
    # Remove unused images related to registry
    local unused_images
    unused_images=$(docker images --filter "dangling=true" -q)
    
    if [[ -n "$unused_images" ]]; then
        log_info "Removing dangling images..."
        echo "$unused_images" | xargs docker rmi 2>/dev/null || true
        log_success "Dangling images removed"
    else
        log_info "No dangling images found"
    fi
}

clean_registry_containers() {
    log_info "Cleaning stopped registry containers..."
    
    # Remove stopped registry containers (except current one)
    local stopped_containers
    stopped_containers=$(docker ps -a --filter "name=$REGISTRY_NAME" --filter "status=exited" -q)
    
    if [[ -n "$stopped_containers" ]]; then
        log_info "Removing stopped registry containers..."
        echo "$stopped_containers" | xargs docker rm 2>/dev/null || true
        log_success "Stopped containers removed"
    else
        log_info "No stopped registry containers found"
    fi
}

clean_registry_data() {
    log_info "Cleaning old registry data..."
    
    # This is a dangerous operation, so we require explicit confirmation
    if [[ $(get_registry_info) == "Running" ]]; then
        log_error "Cannot clean data while registry is running"
        log_info "Stop the registry first: $0 --stop"
        return 1
    fi
    
    if [[ -d "$REGISTRY_DATA_DIR" ]]; then
        read -p "This will delete all registry data. Are you sure? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_warn "Removing registry data directory..."
            rm -rf "$REGISTRY_DATA_DIR"
            log_success "Registry data removed"
        else
            log_info "Data cleanup cancelled"
        fi
    else
        log_info "No registry data directory found"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Local Docker Registry Management Script

USAGE:
    $0 [OPERATION] [OPTIONS]

OPERATIONS:
    start               Start the local registry
    stop                Stop the local registry
    restart             Restart the local registry
    status              Show registry status (default)
    info                Show detailed registry information
    list                List repositories in registry
    usage               Show registry usage statistics
    backup              Create backup of registry data
    restore FILE        Restore registry from backup file
    list-backups        List available backup files
    clean [TYPE]        Clean registry (types: all, images, containers, data)
    remove              Remove registry container completely

OPTIONS:
    --registry-name NAME    Registry container name (default: $REGISTRY_NAME)
    --registry-port PORT    Registry port (default: $REGISTRY_PORT)
    --data-dir DIR          Registry data directory (default: $REGISTRY_DATA_DIR)
    --backup-dir DIR        Backup directory (default: $BACKUP_DIR)
    --verbose               Enable verbose output
    --help                  Show this help message

EXAMPLES:
    # Start registry with default settings
    $0 start

    # Show detailed registry information
    $0 info --verbose

    # List all repositories and their tags
    $0 list --verbose

    # Create backup of registry data
    $0 backup

    # Restore from specific backup
    $0 restore /path/to/backup.tar.gz

    # Clean unused images and containers
    $0 clean

    # Stop and remove registry completely
    $0 remove
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            start|stop|restart|status|info|list|usage|backup|restore|list-backups|clean|remove)
                OPERATION="$1"
                shift
                ;;
            --registry-name)
                REGISTRY_NAME="$2"
                shift 2
                ;;
            --registry-port)
                REGISTRY_PORT="$2"
                REGISTRY_URL="${REGISTRY_HOST}:${REGISTRY_PORT}"
                shift 2
                ;;
            --data-dir)
                REGISTRY_DATA_DIR="$2"
                shift 2
                ;;
            --backup-dir)
                BACKUP_DIR="$2"
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
                # Handle restore file argument
                if [[ "$OPERATION" == "restore" ]] && [[ ! "$1" =~ ^-- ]]; then
                    RESTORE_FILE="$1"
                    shift
                elif [[ "$OPERATION" == "clean" ]] && [[ ! "$1" =~ ^-- ]]; then
                    CLEAN_TYPE="$1"
                    shift
                else
                    log_error "Unknown option: $1"
                    show_usage
                    exit 1
                fi
                ;;
        esac
    done
}

main() {
    parse_arguments "$@"
    
    print_header "KubeChat Registry Management"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Registry management starting"
    log_info "Operation: $OPERATION"
    log_info "Registry: $REGISTRY_NAME at $REGISTRY_URL"
    log_info "Log file: $LOG_FILE"
    
    # Check dependencies (except for help)
    if [[ "$OPERATION" != "help" ]]; then
        check_dependencies
    fi
    
    # Execute operation
    case $OPERATION in
        start)
            start_registry
            ;;
        stop)
            stop_registry
            ;;
        restart)
            restart_registry
            ;;
        status)
            show_registry_status
            ;;
        info)
            show_registry_info
            ;;
        list)
            list_repositories
            ;;
        usage)
            show_registry_usage
            ;;
        backup)
            backup_registry
            ;;
        restore)
            if [[ -n "${RESTORE_FILE:-}" ]]; then
                restore_registry "$RESTORE_FILE"
            else
                restore_registry ""
            fi
            ;;
        list-backups)
            list_backups
            ;;
        clean)
            clean_registry "${CLEAN_TYPE:-all}"
            ;;
        remove)
            remove_registry
            ;;
        *)
            log_error "Unknown operation: $OPERATION"
            show_usage
            exit 1
            ;;
    esac
    
    log_success "Registry management operation completed"
}

# Execute main function with all arguments
main "$@"