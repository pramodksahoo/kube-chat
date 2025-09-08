#!/bin/bash

# KubeChat Air-Gap Image Bundling and Distribution System
# Creates air-gap deployment packages with all required images and configurations
# Usage: ./scripts/airgap-bundle.sh [options]
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
LOG_FILE="${LOG_DIR}/airgap-bundle_${TIMESTAMP}.log"

# Bundle configuration
BUNDLE_VERSION="${KUBECHAT_VERSION:-v1.0.0}"
BUNDLE_DIR="${PROJECT_ROOT}/airgap-bundles"
BUNDLE_NAME="kubechat-airgap-${BUNDLE_VERSION}-${TIMESTAMP}"
BUNDLE_PATH="${BUNDLE_DIR}/${BUNDLE_NAME}"

# Image configuration
LOCAL_REGISTRY="localhost:5001"
IMAGE_TAG="${BUNDLE_VERSION}"
AIRGAP_IMAGE_TAG="airgap"

# Bundle components
INCLUDE_IMAGES=true
INCLUDE_HELM_CHARTS=true
INCLUDE_SCRIPTS=true
INCLUDE_DOCS=true
INCLUDE_CONFIG=true
COMPRESS_BUNDLE=true
CREATE_CHECKSUM=true

# Image lists
KUBECHAT_IMAGES=(
    "kubechat/api-gateway"
    "kubechat/operator" 
    "kubechat/audit-service"
    "kubechat/web"
)

DEPENDENCY_IMAGES=(
    "postgres:15-alpine"
    "redis:7-alpine"
    "registry:2"
    "nginx:1.25-alpine"
)

UTILITY_IMAGES=(
    "nicolaka/netshoot:latest"
    "busybox:latest"
    "alpine:latest"
)

# Bundle metadata
VERBOSE=false
DRY_RUN=false

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
    local deps=("docker" "helm" "tar" "gzip")
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

create_bundle_structure() {
    print_section "Creating Bundle Structure"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create bundle directory: $BUNDLE_PATH"
        return 0
    fi
    
    # Create bundle directory
    mkdir -p "$BUNDLE_PATH"
    
    # Create subdirectories
    mkdir -p "$BUNDLE_PATH/images"
    mkdir -p "$BUNDLE_PATH/helm"
    mkdir -p "$BUNDLE_PATH/scripts"
    mkdir -p "$BUNDLE_PATH/docs"
    mkdir -p "$BUNDLE_PATH/config"
    mkdir -p "$BUNDLE_PATH/tools"
    
    log_success "Bundle directory structure created: $BUNDLE_PATH"
}

# =============================================================================
# IMAGE BUNDLING FUNCTIONS
# =============================================================================

save_docker_images() {
    print_section "Saving Docker Images"
    
    if [[ "$INCLUDE_IMAGES" != "true" ]]; then
        log_info "Image bundling skipped (disabled)"
        return 0
    fi
    
    local all_images=()
    
    # Add KubeChat images
    for image in "${KUBECHAT_IMAGES[@]}"; do
        all_images+=("${LOCAL_REGISTRY}/${image}:${AIRGAP_IMAGE_TAG}")
    done
    
    # Add dependency images
    for image in "${DEPENDENCY_IMAGES[@]}"; do
        all_images+=("$image")
    done
    
    # Add utility images
    for image in "${UTILITY_IMAGES[@]}"; do
        all_images+=("$image")
    done
    
    # Save each image
    local saved_images=()
    local failed_images=()
    
    for image in "${all_images[@]}"; do
        log_info "Processing image: $image"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] Would save image: $image"
            continue
        fi
        
        # Check if image exists locally
        if ! docker images --format "table {{.Repository}}:{{.Tag}}" | grep -q "^${image}$"; then
            log_warn "Image not found locally, attempting to pull: $image"
            if ! docker pull "$image"; then
                log_error "Failed to pull image: $image"
                failed_images+=("$image")
                continue
            fi
        fi
        
        # Save image to tar file
        local safe_name=$(echo "$image" | sed 's/[^a-zA-Z0-9._-]/-/g')
        local image_file="${BUNDLE_PATH}/images/${safe_name}.tar"
        
        if docker save -o "$image_file" "$image"; then
            log_success "Saved image: $image -> ${safe_name}.tar"
            saved_images+=("$image")
        else
            log_error "Failed to save image: $image"
            failed_images+=("$image")
        fi
    done
    
    # Create image manifest
    create_image_manifest "${saved_images[@]}"
    
    # Report results
    log_info "Images saved: ${#saved_images[@]}"
    log_info "Images failed: ${#failed_images[@]}"
    
    if [[ ${#failed_images[@]} -gt 0 ]]; then
        log_warn "Failed images:"
        for image in "${failed_images[@]}"; do
            log_warn "  - $image"
        done
    fi
    
    return 0
}

create_image_manifest() {
    local images=("$@")
    local manifest_file="${BUNDLE_PATH}/images/manifest.json"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create image manifest"
        return 0
    fi
    
    log_info "Creating image manifest..."
    
    cat > "$manifest_file" <<EOF
{
  "version": "1.0",
  "bundle": "$BUNDLE_NAME",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "images": [
EOF
    
    local first=true
    for image in "${images[@]}"; do
        if [[ "$first" == "true" ]]; then
            first=false
        else
            echo "," >> "$manifest_file"
        fi
        
        local safe_name=$(echo "$image" | sed 's/[^a-zA-Z0-9._-]/-/g')
        local file_name="${safe_name}.tar"
        
        cat >> "$manifest_file" <<EOF
    {
      "name": "$image",
      "file": "$file_name",
      "size": "$(stat -f%z "${BUNDLE_PATH}/images/${file_name}" 2>/dev/null || echo "unknown")"
    }
EOF
    done
    
    cat >> "$manifest_file" <<EOF
  ]
}
EOF
    
    log_success "Image manifest created"
}

create_image_load_script() {
    local script_file="${BUNDLE_PATH}/scripts/load-images.sh"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create image load script"
        return 0
    fi
    
    log_info "Creating image load script..."
    
    cat > "$script_file" <<'EOF'
#!/bin/bash

# KubeChat Air-Gap Image Loading Script
# Loads all bundled Docker images into local Docker daemon
# Usage: ./load-images.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(dirname "$SCRIPT_DIR")"
IMAGE_DIR="$BUNDLE_DIR/images"
MANIFEST_FILE="$IMAGE_DIR/manifest.json"

VERBOSE=false
DRY_RUN=false

log_info() { echo "[INFO] $*"; }
log_error() { echo "[ERROR] $*" >&2; }
log_success() { echo "[SUCCESS] $*"; }

show_usage() {
    cat <<USAGE
KubeChat Air-Gap Image Loading Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --dry-run             Show what would be loaded without loading
    --verbose             Enable verbose output
    --help                Show this help message

EXAMPLES:
    # Load all images
    $0

    # Dry run to see what would be loaded
    $0 --dry-run --verbose
USAGE
}

load_images() {
    if [[ ! -f "$MANIFEST_FILE" ]]; then
        log_error "Image manifest not found: $MANIFEST_FILE"
        return 1
    fi
    
    log_info "Loading images from manifest..."
    
    # Parse manifest and load images
    if command -v jq >/dev/null 2>&1; then
        # Use jq if available
        local image_count=$(jq -r '.images | length' "$MANIFEST_FILE")
        log_info "Found $image_count images to load"
        
        for i in $(seq 0 $((image_count - 1))); do
            local image_name=$(jq -r ".images[$i].name" "$MANIFEST_FILE")
            local image_file=$(jq -r ".images[$i].file" "$MANIFEST_FILE")
            local image_path="$IMAGE_DIR/$image_file"
            
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "[DRY RUN] Would load: $image_name from $image_file"
                continue
            fi
            
            if [[ -f "$image_path" ]]; then
                log_info "Loading image: $image_name"
                if docker load -i "$image_path"; then
                    log_success "Loaded: $image_name"
                else
                    log_error "Failed to load: $image_name"
                fi
            else
                log_error "Image file not found: $image_path"
            fi
        done
    else
        # Fallback: load all .tar files
        log_info "jq not available, loading all .tar files..."
        
        for tar_file in "$IMAGE_DIR"/*.tar; do
            if [[ -f "$tar_file" ]]; then
                local filename=$(basename "$tar_file")
                
                if [[ "$DRY_RUN" == "true" ]]; then
                    log_info "[DRY RUN] Would load: $filename"
                    continue
                fi
                
                log_info "Loading image from: $filename"
                if docker load -i "$tar_file"; then
                    log_success "Loaded: $filename"
                else
                    log_error "Failed to load: $filename"
                fi
            fi
        done
    fi
    
    log_success "Image loading completed"
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
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
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "KubeChat Air-Gap Image Loader"
    log_info "Bundle directory: $BUNDLE_DIR"
    
    load_images
}

main "$@"
EOF
    
    chmod +x "$script_file"
    log_success "Image load script created"
}

# =============================================================================
# CONFIGURATION BUNDLING
# =============================================================================

bundle_helm_charts() {
    print_section "Bundling Helm Charts"
    
    if [[ "$INCLUDE_HELM_CHARTS" != "true" ]]; then
        log_info "Helm chart bundling skipped (disabled)"
        return 0
    fi
    
    local helm_source="${PROJECT_ROOT}/deploy/helm"
    local helm_dest="${BUNDLE_PATH}/helm"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would copy Helm charts from: $helm_source"
        return 0
    fi
    
    if [[ ! -d "$helm_source" ]]; then
        log_error "Helm charts directory not found: $helm_source"
        return 1
    fi
    
    # Copy Helm charts
    log_info "Copying Helm charts..."
    cp -r "$helm_source"/* "$helm_dest/"
    
    # Package Helm chart
    log_info "Packaging Helm chart..."
    helm package "$helm_dest/kubechat" -d "$helm_dest/"
    
    log_success "Helm charts bundled"
}

bundle_scripts() {
    print_section "Bundling Scripts"
    
    if [[ "$INCLUDE_SCRIPTS" != "true" ]]; then
        log_info "Script bundling skipped (disabled)"
        return 0
    fi
    
    local scripts_source="${PROJECT_ROOT}/scripts"
    local scripts_dest="${BUNDLE_PATH}/scripts"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would copy scripts from: $scripts_source"
        return 0
    fi
    
    # Copy relevant scripts
    local bundle_scripts=(
        "setup-phase1-dev.sh"
        "build-dev-images.sh"
        "deploy-dev.sh"
        "test-phase1.sh"
        "test-airgap.sh"
        "simulate-airgap.sh"
        "debug-kubechat.sh"
    )
    
    for script in "${bundle_scripts[@]}"; do
        if [[ -f "$scripts_source/$script" ]]; then
            log_info "Including script: $script"
            cp "$scripts_source/$script" "$scripts_dest/"
            chmod +x "$scripts_dest/$script"
        else
            log_warn "Script not found: $script"
        fi
    done
    
    # Create image load script
    create_image_load_script
    
    log_success "Scripts bundled"
}

bundle_configuration() {
    print_section "Bundling Configuration"
    
    if [[ "$INCLUDE_CONFIG" != "true" ]]; then
        log_info "Configuration bundling skipped (disabled)"
        return 0
    fi
    
    local config_dest="${BUNDLE_PATH}/config"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create configuration files"
        return 0
    fi
    
    # Copy environment examples
    local env_files=(
        ".env.example"
        "cmd/api-gateway/.env.example"
        "cmd/audit-service/.env.example"
        "web/.env.example"
    )
    
    for env_file in "${env_files[@]}"; do
        if [[ -f "$PROJECT_ROOT/$env_file" ]]; then
            local dest_dir="$config_dest/$(dirname "$env_file")"
            mkdir -p "$dest_dir"
            cp "$PROJECT_ROOT/$env_file" "$dest_dir/"
            log_info "Included config: $env_file"
        fi
    done
    
    # Create air-gap deployment configuration
    cat > "$config_dest/airgap-deployment.yaml" <<EOF
# KubeChat Air-Gap Deployment Configuration
# Use this file for customer air-gap deployments

# Global settings
global:
  imageRegistry: "customer-registry.local:5000"
  imageTag: "$BUNDLE_VERSION"
  namespace: "kubechat"
  
# Air-gap specific settings
deployment:
  airgap: true
  offlineMode: true
  
# Security settings for air-gap
security:
  networkPolicy:
    enabled: true
    blockExternal: true
  
# Disable external services
externalServices:
  enabled: false

# Use local images only
imagePullPolicy: "Never"
EOF
    
    log_success "Configuration bundled"
}

bundle_documentation() {
    print_section "Bundling Documentation"
    
    if [[ "$INCLUDE_DOCS" != "true" ]]; then
        log_info "Documentation bundling skipped (disabled)"
        return 0
    fi
    
    local docs_dest="${BUNDLE_PATH}/docs"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create documentation"
        return 0
    fi
    
    # Copy relevant documentation
    local doc_files=(
        "README.md"
        "deploy/helm/kubechat/CONFIG.md"
        "docs/deployment/rancher-desktop-development.md"
        "docs/development/local-setup.md"
    )
    
    for doc_file in "${doc_files[@]}"; do
        if [[ -f "$PROJECT_ROOT/$doc_file" ]]; then
            local dest_dir="$docs_dest/$(dirname "$doc_file")"
            mkdir -p "$dest_dir"
            cp "$PROJECT_ROOT/$doc_file" "$dest_dir/"
            log_info "Included doc: $doc_file"
        fi
    done
    
    # Create air-gap deployment guide
    create_airgap_deployment_guide
    
    log_success "Documentation bundled"
}

create_airgap_deployment_guide() {
    local guide_file="${BUNDLE_PATH}/docs/AIRGAP-DEPLOYMENT-GUIDE.md"
    
    cat > "$guide_file" <<'EOF'
# KubeChat Air-Gap Deployment Guide

This guide provides step-by-step instructions for deploying KubeChat in an air-gapped environment.

## Prerequisites

- Kubernetes cluster (v1.24+)
- Helm 3.x
- Docker (for image loading)
- Local container registry

## Deployment Steps

### 1. Load Container Images

```bash
# Load all bundled images into Docker
./scripts/load-images.sh

# Tag images for your registry
./scripts/tag-images.sh --registry your-registry.local:5000

# Push images to your registry
./scripts/push-images.sh --registry your-registry.local:5000
```

### 2. Install KubeChat

```bash
# Create namespace
kubectl create namespace kubechat

# Install using air-gap values
helm install kubechat ./helm/kubechat-*.tgz \
  -f config/airgap-deployment.yaml \
  -n kubechat \
  --set global.imageRegistry=your-registry.local:5000
```

### 3. Verify Deployment

```bash
# Check pod status
kubectl get pods -n kubechat

# Test connectivity
kubectl port-forward -n kubechat svc/kubechat-web 8080:80
```

## Configuration

Customize the deployment by editing `config/airgap-deployment.yaml` before installation.

## Troubleshooting

If you encounter issues:

1. Check image availability in your registry
2. Verify network policies allow cluster communication
3. Review pod logs for specific errors
4. Use the included debug scripts

For detailed troubleshooting, see the included documentation.
EOF
    
    log_info "Air-gap deployment guide created"
}

# =============================================================================
# BUNDLE FINALIZATION
# =============================================================================

create_bundle_metadata() {
    print_section "Creating Bundle Metadata"
    
    local metadata_file="${BUNDLE_PATH}/bundle-info.json"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create bundle metadata"
        return 0
    fi
    
    cat > "$metadata_file" <<EOF
{
  "name": "$BUNDLE_NAME",
  "version": "$BUNDLE_VERSION",
  "created": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "description": "KubeChat air-gap deployment bundle",
  "components": {
    "images": $INCLUDE_IMAGES,
    "helm": $INCLUDE_HELM_CHARTS,
    "scripts": $INCLUDE_SCRIPTS,
    "docs": $INCLUDE_DOCS,
    "config": $INCLUDE_CONFIG
  },
  "requirements": {
    "kubernetes": ">=1.24",
    "helm": ">=3.0",
    "docker": ">=20.0"
  },
  "size": "$(du -sh "$BUNDLE_PATH" | cut -f1)"
}
EOF
    
    log_success "Bundle metadata created"
}

compress_bundle() {
    print_section "Compressing Bundle"
    
    if [[ "$COMPRESS_BUNDLE" != "true" ]]; then
        log_info "Bundle compression skipped (disabled)"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would compress bundle"
        return 0
    fi
    
    local archive_file="${BUNDLE_DIR}/${BUNDLE_NAME}.tar.gz"
    
    log_info "Creating compressed archive..."
    tar -czf "$archive_file" -C "$BUNDLE_DIR" "$BUNDLE_NAME"
    
    # Create checksum if enabled
    if [[ "$CREATE_CHECKSUM" == "true" ]]; then
        log_info "Creating checksum..."
        sha256sum "$archive_file" > "${archive_file}.sha256"
    fi
    
    log_success "Bundle compressed: $archive_file"
    log_info "Bundle size: $(du -sh "$archive_file" | cut -f1)"
    
    # Optionally remove uncompressed directory
    read -p "Remove uncompressed bundle directory? [y/N]: " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$BUNDLE_PATH"
        log_info "Uncompressed directory removed"
    fi
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

show_usage() {
    cat <<EOF
KubeChat Air-Gap Bundle Creation Script

USAGE:
    $0 [OPTIONS]

OPTIONS:
    --version VERSION     Set bundle version (default: $BUNDLE_VERSION)
    --no-images          Skip Docker image bundling
    --no-helm            Skip Helm chart bundling
    --no-scripts         Skip script bundling
    --no-docs            Skip documentation bundling
    --no-config          Skip configuration bundling
    --no-compress        Skip bundle compression
    --no-checksum        Skip checksum creation
    --dry-run            Show what would be done without doing it
    --verbose            Enable verbose logging
    --help               Show this help message

EXAMPLES:
    # Create complete air-gap bundle
    $0

    # Create bundle without images (charts only)
    $0 --no-images --version v1.0.1

    # Dry run to see what would be bundled
    $0 --dry-run --verbose

    # Create minimal bundle
    $0 --no-docs --no-config --version dev
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --version)
                BUNDLE_VERSION="$2"
                BUNDLE_NAME="kubechat-airgap-${BUNDLE_VERSION}-${TIMESTAMP}"
                BUNDLE_PATH="${BUNDLE_DIR}/${BUNDLE_NAME}"
                shift 2
                ;;
            --no-images)
                INCLUDE_IMAGES=false
                shift
                ;;
            --no-helm)
                INCLUDE_HELM_CHARTS=false
                shift
                ;;
            --no-scripts)
                INCLUDE_SCRIPTS=false
                shift
                ;;
            --no-docs)
                INCLUDE_DOCS=false
                shift
                ;;
            --no-config)
                INCLUDE_CONFIG=false
                shift
                ;;
            --no-compress)
                COMPRESS_BUNDLE=false
                shift
                ;;
            --no-checksum)
                CREATE_CHECKSUM=false
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
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

main() {
    parse_arguments "$@"
    
    print_header "KubeChat Air-Gap Bundle Creator"
    
    # Setup logging
    mkdir -p "$LOG_DIR"
    log_info "Air-gap bundle creation starting"
    log_info "Bundle name: $BUNDLE_NAME"
    log_info "Bundle version: $BUNDLE_VERSION"
    log_info "Log file: $LOG_FILE"
    
    # Check dependencies
    check_dependencies
    
    # Create bundle structure
    create_bundle_structure
    
    # Bundle components
    save_docker_images
    bundle_helm_charts
    bundle_scripts
    bundle_configuration
    bundle_documentation
    
    # Finalize bundle
    create_bundle_metadata
    compress_bundle
    
    print_header "Bundle Creation Complete"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Dry run completed - no files were created"
    else
        log_success "Air-gap bundle created successfully! ✅"
        log_info "Bundle location: $BUNDLE_PATH"
        if [[ "$COMPRESS_BUNDLE" == "true" ]]; then
            log_info "Compressed archive: ${BUNDLE_DIR}/${BUNDLE_NAME}.tar.gz"
        fi
    fi
}

# Execute main function with all arguments
main "$@"