#!/bin/bash

# KubeChat Image Tagging and Versioning System
# Automated image tagging and versioning for development builds
# Usage: ./scripts/tag-images.sh [options]
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
LOG_FILE="${LOG_DIR}/image-tagging_${TIMESTAMP}.log"

# Versioning configuration
VERSION_FILE="${PROJECT_ROOT}/VERSION"
DEFAULT_VERSION="v1.0.0"
VERSION_FORMAT="semantic"  # semantic, timestamp, build
BUILD_NUMBER="${BUILD_NUMBER:-auto}"

# Registry configuration
SOURCE_REGISTRY="localhost:5001"
TARGET_REGISTRY="${TARGET_REGISTRY:-localhost:5001}"
PUSH_TO_TARGET=false

# Image configuration
KUBECHAT_SERVICES=(
    "kubechat/api-gateway"
    "kubechat/operator"
    "kubechat/audit-service"
    "kubechat/web"
)

# Tagging strategy
TAG_STRATEGY="multi"  # single, multi, immutable
TAG_PATTERNS=(
    "latest"
    "\${VERSION}"
    "\${VERSION}-\${BUILD}"
    "\${ENVIRONMENT}"
)

# Operation mode
OPERATION="tag"  # tag, push, retag, cleanup
ENVIRONMENT="dev"
FORCE_TAG=false
DRY_RUN=false
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
    local deps=("docker" "git" "jq")
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
# VERSION MANAGEMENT
# =============================================================================

get_current_version() {
    local version
    
    # Try VERSION file first
    if [[ -f "$VERSION_FILE" ]]; then
        version=$(cat "$VERSION_FILE" | tr -d '[:space:]')
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    fi
    
    # Try git tag
    if git rev-parse --git-dir >/dev/null 2>&1; then
        version=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    fi
    
    # Default version
    echo "$DEFAULT_VERSION"
}

generate_version() {
    local format="${1:-$VERSION_FORMAT}"
    local base_version
    base_version=$(get_current_version)
    
    case $format in
        "semantic")
            echo "$base_version"
            ;;
        "timestamp")
            echo "${base_version}-${TIMESTAMP}"
            ;;
        "build")
            local build_num
            if [[ "$BUILD_NUMBER" == "auto" ]]; then
                build_num=$(date +%Y%m%d%H%M%S)
            else
                build_num="$BUILD_NUMBER"
            fi
            echo "${base_version}-build.${build_num}"
            ;;
        "git")
            if git rev-parse --git-dir >/dev/null 2>&1; then
                local git_hash
                git_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
                echo "${base_version}-git.${git_hash}"
            else
                echo "$base_version"
            fi
            ;;
        *)
            log_error "Unknown version format: $format"
            echo "$base_version"
            ;;
    esac
}

get_build_info() {
    local build_info="{}"
    
    # Git information
    if git rev-parse --git-dir >/dev/null 2>&1; then
        local git_hash git_branch git_dirty
        git_hash=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
        git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
        git_dirty=$(git diff --quiet 2>/dev/null && echo "false" || echo "true")
        
        build_info=$(echo "$build_info" | jq \
            --arg hash "$git_hash" \
            --arg branch "$git_branch" \
            --arg dirty "$git_dirty" \
            '.git = {hash: $hash, branch: $branch, dirty: ($dirty == "true")}'
        )
    fi
    
    # Build information
    build_info=$(echo "$build_info" | jq \
        --arg timestamp "$TIMESTAMP" \
        --arg build_number "$BUILD_NUMBER" \
        --arg environment "$ENVIRONMENT" \
        '.build = {timestamp: $timestamp, number: $build_number, environment: $environment}'
    )
    
    echo "$build_info"
}

# =============================================================================
# IMAGE OPERATIONS
# =============================================================================

list_local_images() {
    print_section "Local Images"
    
    local found_images=false
    
    for service in "${KUBECHAT_SERVICES[@]}"; do
        local images
        images=$(docker images --format "table {{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}" | grep "$service" || echo "")
        
        if [[ -n "$images" ]]; then
            if [[ "$found_images" == "false" ]]; then
                echo "REPOSITORY:TAG                              IMAGE ID       CREATED        SIZE"
                found_images=true
            fi
            echo "$images"
        fi
    done
    
    if [[ "$found_images" == "false" ]]; then
        log_info "No KubeChat images found locally"
    fi
}

check_image_exists() {
    local image="$1"
    docker images --format "{{.Repository}}:{{.Tag}}" | grep -q "^${image}$"
}

generate_tags() {
    local service="$1"
    local version="$2"
    local build_number="$3"
    local tags=()
    
    for pattern in "${TAG_PATTERNS[@]}"; do
        local tag="$pattern"
        
        # Replace variables in pattern
        tag="${tag//\$\{VERSION\}/$version}"
        tag="${tag//\$\{BUILD\}/$build_number}"
        tag="${tag//\$\{ENVIRONMENT\}/$ENVIRONMENT}"
        tag="${tag//\$\{TIMESTAMP\}/$TIMESTAMP}"
        tag="${tag//\$\{SERVICE\}/$service}"
        
        # Skip empty tags
        if [[ -n "$tag" && "$tag" != *"\${}"* ]]; then
            tags+=("$tag")
        fi
    done
    
    printf '%s\n' "${tags[@]}"
}

tag_image() {
    local source_image="$1"
    local target_image="$2"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would tag: $source_image -> $target_image"
        return 0
    fi
    
    if ! check_image_exists "$source_image"; then
        log_error "Source image not found: $source_image"
        return 1
    fi
    
    # Check if target tag already exists
    if check_image_exists "$target_image" && [[ "$FORCE_TAG" != "true" ]]; then
        log_warn "Target image already exists (use --force to overwrite): $target_image"
        return 1
    fi
    
    log_info "Tagging: $source_image -> $target_image"
    
    if docker tag "$source_image" "$target_image"; then
        log_success "Tagged: $target_image"
        return 0
    else
        log_error "Failed to tag: $source_image -> $target_image"
        return 1
    fi
}

push_image() {
    local image="$1"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would push: $image"
        return 0
    fi
    
    log_info "Pushing: $image"
    
    if docker push "$image"; then
        log_success "Pushed: $image"
        return 0
    else
        log_error "Failed to push: $image"
        return 1
    fi
}

tag_all_services() {
    print_section "Tagging All Services"
    
    local version
    version=$(generate_version "$VERSION_FORMAT")
    local build_info
    build_info=$(get_build_info)
    local build_number
    build_number=$(echo "$build_info" | jq -r '.build.number')
    
    log_info "Version: $version"
    log_info "Build: $build_number"
    log_info "Environment: $ENVIRONMENT"
    
    if [[ "$VERBOSE" == "true" ]]; then
        log_debug "Build info: $build_info"
    fi
    
    local total_tags=0
    local successful_tags=0
    
    for service in "${KUBECHAT_SERVICES[@]}"; do
        local service_name
        service_name=$(basename "$service")
        
        log_info "Processing service: $service"
        
        # Find source image (look for latest or dev tag)
        local source_image=""
        local candidates=("${SOURCE_REGISTRY}/${service}:latest" "${SOURCE_REGISTRY}/${service}:dev" "${service}:latest" "${service}:dev")
        
        for candidate in "${candidates[@]}"; do
            if check_image_exists "$candidate"; then
                source_image="$candidate"
                break
            fi
        done
        
        if [[ -z "$source_image" ]]; then
            log_error "No source image found for service: $service"
            continue
        fi
        
        log_info "Source image: $source_image"
        
        # Generate tags for this service
        local tags
        tags=$(generate_tags "$service_name" "$version" "$build_number")
        
        # Apply tags
        while IFS= read -r tag; do
            if [[ -n "$tag" ]]; then
                local target_image="${TARGET_REGISTRY}/${service}:${tag}"
                
                ((total_tags++))
                if tag_image "$source_image" "$target_image"; then
                    ((successful_tags++))
                    
                    # Push if requested
                    if [[ "$PUSH_TO_TARGET" == "true" ]] && [[ "$TARGET_REGISTRY" != "localhost:5001" || "$OPERATION" == "push" ]]; then
                        push_image "$target_image"
                    fi
                fi
            fi
        done <<< "$tags"
    done
    
    log_info "Tagging summary: $successful_tags/$total_tags successful"
    
    if [[ $successful_tags -eq $total_tags ]]; then
        log_success "All images tagged successfully"
        return 0
    else
        log_error "Some images failed to tag"
        return 1
    fi
}

retag_images() {
    print_section "Re-tagging Images"
    
    local old_tag="$1"
    local new_tag="$2"
    
    if [[ -z "$old_tag" || -z "$new_tag" ]]; then
        log_error "Both old and new tags must be specified for retagging"
        return 1
    fi
    
    log_info "Re-tagging from '$old_tag' to '$new_tag'"
    
    local retag_count=0
    
    for service in "${KUBECHAT_SERVICES[@]}"; do
        local old_image="${SOURCE_REGISTRY}/${service}:${old_tag}"
        local new_image="${TARGET_REGISTRY}/${service}:${new_tag}"
        
        if check_image_exists "$old_image"; then
            if tag_image "$old_image" "$new_image"; then
                ((retag_count++))
                
                if [[ "$PUSH_TO_TARGET" == "true" ]]; then
                    push_image "$new_image"
                fi
            fi
        else
            log_warn "Image not found: $old_image"
        fi
    done
    
    log_info "Re-tagged $retag_count images"
}

cleanup_old_tags() {
    print_section "Cleaning Up Old Tags"
    
    local keep_tags="${1:-5}"
    local cleanup_count=0
    
    log_info "Keeping $keep_tags most recent tags per service"
    
    for service in "${KUBECHAT_SERVICES[@]}"; do
        log_info "Cleaning up tags for: $service"
        
        # Get all tags for this service, sorted by creation time
        local all_tags
        all_tags=$(docker images --format "{{.Repository}}:{{.Tag}}\t{{.CreatedAt}}" | \
                  grep "^${service}:" | \
                  grep -v ":latest$" | \
                  sort -k2 -r | \
                  awk '{print $1}')
        
        if [[ -z "$all_tags" ]]; then
            log_info "No tags found for: $service"
            continue
        fi
        
        local tag_count=0
        while IFS= read -r tag_line; do
            if [[ -n "$tag_line" ]]; then
                ((tag_count++))
                
                if [[ $tag_count -gt $keep_tags ]]; then
                    log_info "Removing old tag: $tag_line"
                    
                    if [[ "$DRY_RUN" == "true" ]]; then
                        log_info "[DRY RUN] Would remove: $tag_line"
                    else
                        if docker rmi "$tag_line" 2>/dev/null; then
                            ((cleanup_count++))
                            log_success "Removed: $tag_line"
                        else
                            log_warn "Failed to remove: $tag_line"
                        fi
                    fi
                fi
            fi
        done <<< "$all_tags"
    done
    
    log_info "Cleaned up $cleanup_count old tags"
}

# =============================================================================
# REGISTRY OPERATIONS
# =============================================================================

push_all_tags() {
    print_section "Pushing All Tagged Images"
    
    local push_count=0
    local total_count=0
    
    for service in "${KUBECHAT_SERVICES[@]}"; do
        # Get all local tags for this service
        local service_images
        service_images=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep "^${service}:")
        
        while IFS= read -r image_line; do
            if [[ -n "$image_line" ]]; then
                ((total_count++))
                
                if push_image "$image_line"; then
                    ((push_count++))
                fi
            fi
        done <<< "$service_images"
    done
    
    log_info "Push summary: $push_count/$total_count successful"
    
    if [[ $push_count -eq $total_count ]]; then
        log_success "All images pushed successfully"
        return 0
    else
        log_error "Some images failed to push"
        return 1
    fi
}

create_image_manifest() {
    print_section "Creating Image Manifest"
    
    local manifest_file="${PROJECT_ROOT}/image-manifest.json"
    local version
    version=$(generate_version "$VERSION_FORMAT")
    local build_info
    build_info=$(get_build_info)
    
    local manifest="{
        \"version\": \"$version\",
        \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
        \"environment\": \"$ENVIRONMENT\",
        \"registry\": \"$TARGET_REGISTRY\",
        \"build_info\": $build_info,
        \"images\": []
    }"
    
    # Add image information
    for service in "${KUBECHAT_SERVICES[@]}"; do
        local service_images
        service_images=$(docker images --format "{{.Repository}}:{{.Tag}}\t{{.ID}}\t{{.Size}}" | grep "^${service}:")
        
        while IFS=$'\t' read -r repo_tag image_id size; do
            if [[ -n "$repo_tag" ]]; then
                local image_info="{
                    \"name\": \"$repo_tag\",
                    \"id\": \"$image_id\",
                    \"size\": \"$size\",
                    \"service\": \"$(basename "$service")\"
                }"
                
                manifest=$(echo "$manifest" | jq ".images += [$image_info]")
            fi
        done <<< "$service_images"
    done
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create manifest: $manifest_file"
        if [[ "$VERBOSE" == "true" ]]; then
            echo "$manifest" | jq '.'
        fi
    else
        echo "$manifest" | jq '.' > "$manifest_file"
        log_success "Image manifest created: $manifest_file"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Image Tagging and Versioning System

USAGE:
    $0 [OPERATION] [OPTIONS]

OPERATIONS:
    tag                 Tag all services with generated versions (default)
    push                Tag and push all images
    retag OLD NEW       Re-tag images from OLD to NEW
    list                List local KubeChat images
    cleanup [KEEP]      Clean up old tags (keep KEEP most recent, default: 5)
    manifest            Create image manifest file

OPTIONS:
    --version VERSION           Set version (default: auto-detected)
    --version-format FORMAT     Version format: semantic, timestamp, build, git (default: $VERSION_FORMAT)
    --build-number NUMBER       Build number (default: auto)
    --environment ENV           Target environment (default: $ENVIRONMENT)
    --source-registry REG       Source registry (default: $SOURCE_REGISTRY)
    --target-registry REG       Target registry (default: $TARGET_REGISTRY)
    --tag-strategy STRATEGY     Tagging strategy: single, multi, immutable (default: $TAG_STRATEGY)
    --force                     Force overwrite existing tags
    --push                      Push images after tagging
    --dry-run                   Show what would be done without doing it
    --verbose                   Enable verbose output
    --help                      Show this help message

TAG PATTERNS:
    Available variables: \${VERSION}, \${BUILD}, \${ENVIRONMENT}, \${TIMESTAMP}, \${SERVICE}
    
    Current patterns:
$(printf '    - %s\n' "${TAG_PATTERNS[@]}")

EXAMPLES:
    # Tag all images with current version
    $0 tag

    # Tag with custom version and push
    $0 tag --version v2.0.0 --push

    # Re-tag from dev to staging
    $0 retag dev staging --target-registry staging-registry:5000

    # Tag with timestamp format for CI/CD
    $0 tag --version-format timestamp --environment ci

    # Clean up old tags, keeping 3 most recent
    $0 cleanup 3

    # Dry run with verbose output
    $0 tag --dry-run --verbose
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            tag|push|retag|list|cleanup|manifest)
                OPERATION="$1"
                shift
                ;;
            --version)
                # Override version detection
                echo "$2" > "$VERSION_FILE"
                shift 2
                ;;
            --version-format)
                VERSION_FORMAT="$2"
                shift 2
                ;;
            --build-number)
                BUILD_NUMBER="$2"
                shift 2
                ;;
            --environment)
                ENVIRONMENT="$2"
                shift 2
                ;;
            --source-registry)
                SOURCE_REGISTRY="$2"
                shift 2
                ;;
            --target-registry)
                TARGET_REGISTRY="$2"
                shift 2
                ;;
            --tag-strategy)
                TAG_STRATEGY="$2"
                shift 2
                ;;
            --force)
                FORCE_TAG=true
                shift
                ;;
            --push)
                PUSH_TO_TARGET=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
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
                # Handle retag and cleanup arguments
                if [[ "$OPERATION" == "retag" ]]; then
                    if [[ -z "${OLD_TAG:-}" ]]; then
                        OLD_TAG="$1"
                        shift
                    elif [[ -z "${NEW_TAG:-}" ]]; then
                        NEW_TAG="$1"
                        shift
                    else
                        log_error "Too many arguments for retag operation"
                        exit 1
                    fi
                elif [[ "$OPERATION" == "cleanup" && ! "$1" =~ ^-- ]]; then
                    KEEP_TAGS="$1"
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
    
    print_header "KubeChat Image Tagging System"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Image tagging operation starting"
    log_info "Operation: $OPERATION"
    log_info "Environment: $ENVIRONMENT"
    log_info "Version format: $VERSION_FORMAT"
    log_info "Log file: $LOG_FILE"
    
    # Check dependencies
    check_dependencies
    
    # Execute operation
    case $OPERATION in
        tag)
            tag_all_services
            if [[ "$PUSH_TO_TARGET" == "true" ]]; then
                push_all_tags
            fi
            create_image_manifest
            ;;
        push)
            PUSH_TO_TARGET=true
            tag_all_services
            push_all_tags
            create_image_manifest
            ;;
        retag)
            if [[ -n "${OLD_TAG:-}" && -n "${NEW_TAG:-}" ]]; then
                retag_images "$OLD_TAG" "$NEW_TAG"
            else
                log_error "Both old and new tags required for retag operation"
                exit 1
            fi
            ;;
        list)
            list_local_images
            ;;
        cleanup)
            cleanup_old_tags "${KEEP_TAGS:-5}"
            ;;
        manifest)
            create_image_manifest
            ;;
        *)
            log_error "Unknown operation: $OPERATION"
            show_usage
            exit 1
            ;;
    esac
    
    log_success "Image tagging operation completed"
}

# Execute main function with all arguments
main "$@"