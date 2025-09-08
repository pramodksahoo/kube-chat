#!/bin/bash

# KubeChat Image Cleanup and Maintenance Utilities
# Comprehensive image cleanup, optimization, and maintenance
# Usage: ./scripts/cleanup-images.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_ROOT}/logs"
LOG_FILE="${LOG_DIR}/image-cleanup_$(date +%Y%m%d_%H%M%S).log"

# Cleanup configuration
CLEANUP_TYPE="safe"  # safe, aggressive, all
DRY_RUN=false
FORCE=false
KEEP_RECENT=3
VERBOSE=false

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log() {
    local level=$1; shift
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" | tee -a "$LOG_FILE"
}

log_info() { log "INFO" "$@"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }
log_warn() { log "WARN" "${YELLOW}$*${NC}"; }
log_error() { log "ERROR" "${RED}$*${NC}"; }

print_section() { echo -e "\n${BLUE}--- $1 ---${NC}\n"; }

cleanup_dangling_images() {
    print_section "Cleaning Dangling Images"
    
    local dangling_images
    dangling_images=$(docker images -f "dangling=true" -q)
    
    if [[ -z "$dangling_images" ]]; then
        log_info "No dangling images found"
        return 0
    fi
    
    log_info "Found dangling images:"
    docker images -f "dangling=true"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would remove $(echo "$dangling_images" | wc -l) dangling images"
    else
        echo "$dangling_images" | xargs docker rmi 2>/dev/null || true
        log_success "Dangling images cleaned"
    fi
}

cleanup_unused_images() {
    print_section "Cleaning Unused Images"
    
    if [[ "$CLEANUP_TYPE" == "safe" ]]; then
        log_info "Safe cleanup - only removing explicitly unused images"
        docker image prune -f
    else
        log_warn "Aggressive cleanup - removing all unused images"
        if [[ "$FORCE" == "true" ]] || [[ "$DRY_RUN" == "true" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "[DRY RUN] Would remove all unused images"
            else
                docker image prune -a -f
            fi
        else
            log_error "Aggressive cleanup requires --force flag"
        fi
    fi
}

cleanup_old_kubechat_images() {
    print_section "Cleaning Old KubeChat Images"
    
    # Support both local registry and direct kubechat images
    local services=("localhost:5001/kubechat/api-gateway" "localhost:5001/kubechat/operator" "localhost:5001/kubechat/audit-service" "localhost:5001/kubechat/web" "kubechat/api-gateway" "kubechat/operator" "kubechat/audit-service" "kubechat/web")
    
    for service in "${services[@]}"; do
        log_info "Cleaning old versions of: $service"
        
        # Get all tags for this service, sorted by creation time (newest first)
        local all_images
        all_images=$(docker images --format "{{.Repository}}:{{.Tag}} {{.CreatedAt}}" | \
                    grep "^$service:" | \
                    grep -v ":latest$" | \
                    sort -k2 -r)
        
        local count=0
        while IFS= read -r image_line; do
            if [[ -n "$image_line" ]]; then
                ((count++))
                
                if [[ $count -gt $KEEP_RECENT ]]; then
                    local image_name
                    image_name=$(echo "$image_line" | awk '{print $1}')
                    
                    if [[ "$DRY_RUN" == "true" ]]; then
                        log_info "[DRY RUN] Would remove: $image_name"
                    else
                        docker rmi "$image_name" 2>/dev/null && log_success "Removed: $image_name" || log_warn "Failed to remove: $image_name"
                    fi
                fi
            fi
        done <<< "$all_images"
    done
}

show_disk_usage() {
    print_section "Docker Disk Usage"
    docker system df
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --type) CLEANUP_TYPE="$2"; shift 2 ;;
            --keep) KEEP_RECENT="$2"; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --force) FORCE=true; shift ;;
            --verbose) VERBOSE=true; shift ;;
            --help) 
                echo "Usage: $0 [--type safe|aggressive|all] [--keep N] [--dry-run] [--force] [--verbose]"
                exit 0 ;;
            *) echo "Unknown option: $1"; exit 1 ;;
        esac
    done
    
    mkdir -p "$LOG_DIR"
    log_info "Starting image cleanup (type: $CLEANUP_TYPE, keep: $KEEP_RECENT)"
    
    show_disk_usage
    cleanup_dangling_images
    cleanup_old_kubechat_images
    cleanup_unused_images
    show_disk_usage
    
    log_success "Image cleanup completed"
}

main "$@"