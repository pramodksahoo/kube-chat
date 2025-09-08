#!/usr/bin/env bash
# build-kubechat-images.sh
# KubeChat Multi-Service Docker Image Build System
# Builds and pushes all service images for dev/production environments
# Supports both macOS (development) and Linux (production) environments
# Usage: ./build-kubechat-images.sh [dev|production] [options]

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default configuration
ENVIRONMENT="dev"
VERSION="dev"
PROJECT_NAME="kubechat"

# Parse first argument for environment or help
if [[ $# -gt 0 && "$1" != "--"* ]]; then
    case $1 in
        dev|development)
            ENVIRONMENT="dev"
            ;;
        prod|production)
            ENVIRONMENT="production"
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            # If first argument is not env or help, treat it as version and use default dev env
            VERSION="$1"
            ;;
    esac
fi

# Set registry and configuration based on environment
case $ENVIRONMENT in
    dev|development)
        REGISTRY="localhost:5001"
        ENVIRONMENT="dev"
        ;;
    prod|production)
        REGISTRY="${DOCKER_REGISTRY:-docker.io}"
        REPOSITORY="${DOCKER_REPOSITORY:-kubechat/kubechat}"
        ENVIRONMENT="production"
        ;;
esac

# Services to build (using arrays that work on both macOS bash 3.x and Linux bash 4.x+)
SERVICES_NAMES=("api-gateway" "audit-service" "operator" "web")
SERVICES_DOCKERFILES=("cmd/api-gateway/Dockerfile" "cmd/audit-service/Dockerfile" "Dockerfile" "web/Dockerfile")
SERVICES_CONTEXTS=("." "." "." ".")

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

# Error handler
error_handler() {
    log_error "Build failed at line $1"
    log_error "Multi-service Docker build failed"
    exit 1
}

trap 'error_handler $LINENO' ERR

# Verify prerequisites
verify_prerequisites() {
    log_info "Verifying build prerequisites..."
    
    # Verify we're in the correct directory
    if [[ ! -f "go.mod" ]] || [[ ! -d "cmd" ]] || [[ ! -d "pkg" ]]; then
        log_error "Must run from KubeChat project root directory"
        exit 1
    fi
    
    # Verify Docker is running
    if ! docker --version &>/dev/null; then
        log_error "Docker not accessible. Ensure Rancher Desktop is running"
        exit 1
    fi
    
    # Verify local registry is accessible
    if ! curl -f http://localhost:5001/v2/_catalog &>/dev/null; then
        log_error "Local Docker registry not accessible at localhost:5001"
        log_error "Run './scripts/setup-phase1-dev.sh' first to set up the local registry"
        exit 1
    fi
    
    # Verify required Dockerfiles exist
    for i in "${!SERVICES_NAMES[@]}"; do
        service="${SERVICES_NAMES[$i]}"
        dockerfile="${SERVICES_DOCKERFILES[$i]}"
        context="${SERVICES_CONTEXTS[$i]}"
        if [[ ! -f "$dockerfile" ]]; then
            log_error "Dockerfile not found: $dockerfile for service $service (context: $context)"
            log_error "Run all previous tasks to create required Dockerfiles"
            exit 1
        fi
    done
    
    log_success "Prerequisites verified"
}

# Build React frontend first (required for web Docker image)
build_frontend() {
    log_info "🔨 Building React frontend for production..."
    
    if [[ ! -d "web" ]]; then
        log_warning "Web directory not found, skipping frontend build"
        return 0
    fi
    
    cd web/
    
    # Install dependencies if needed
    if [[ ! -d "node_modules" ]] || [[ "package.json" -nt "node_modules" ]]; then
        log_info "Installing frontend dependencies..."
        if command -v pnpm &>/dev/null; then
            pnpm install
        elif command -v npm &>/dev/null; then
            npm install
        else
            log_error "Neither pnpm nor npm found. Install Node.js and pnpm first"
            exit 1
        fi
    fi
    
    # Build production bundle
    log_info "Creating production build..."
    if command -v pnpm &>/dev/null; then
        pnpm run build
    else
        npm run build
    fi
    
    cd ..
    log_success "Frontend build completed"
}

# Build individual service image
build_service_image() {
    local service=$1
    local dockerfile=$2
    local context=$3
    local image_tag
    
    # Set image tag based on environment
    if [[ "$ENVIRONMENT" == "production" ]]; then
        image_tag="${REPOSITORY}:${service}-${VERSION}"
    else
        image_tag="${REGISTRY}/${PROJECT_NAME}/${service}:${VERSION}"
    fi
    
    log_info "🐳 Building $service image..."
    log_info "  Environment: $ENVIRONMENT"
    log_info "  Dockerfile: $dockerfile"
    log_info "  Build context: $context"
    log_info "  Image tag: $image_tag"
    
    # Build the image with correct context
    docker build \
        -f "$dockerfile" \
        -t "$image_tag" \
        --build-arg VERSION="$VERSION" \
        --build-arg SERVICE="$service" \
        --build-arg ENVIRONMENT="$ENVIRONMENT" \
        "$context"
    
    log_success "$service image built successfully: $image_tag"
    
    # Push to registry
    local registry_name
    if [[ "$ENVIRONMENT" == "production" ]]; then
        registry_name="production registry"
    else
        registry_name="local registry"
    fi
    
    log_info "📤 Pushing $service image to $registry_name..."
    docker push "$image_tag"
    
    log_success "$service image pushed to $registry_name"
}

# Build all service images
build_all_services() {
    log_info "🏗️ Building KubeChat Phase 1 Model 1 service images..."
    log_info "Registry: $REGISTRY"
    log_info "Version: $VERSION"
    log_info "Services: ${SERVICES_NAMES[*]}"
    
    # Build frontend first (web service depends on it)
    build_frontend
    
    # Build all service images
    for i in "${!SERVICES_NAMES[@]}"; do
        service="${SERVICES_NAMES[$i]}"
        dockerfile="${SERVICES_DOCKERFILES[$i]}"
        context="${SERVICES_CONTEXTS[$i]}"
        build_service_image "$service" "$dockerfile" "$context"
        echo "" # Add spacing between services
    done
}

# Verify built images
verify_images() {
    log_info "🔍 Verifying built images in local registry..."
    
    # List images in local registry
    log_info "Images in local registry:"
    curl -s http://localhost:5001/v2/_catalog | jq -r '.repositories[]' 2>/dev/null || {
        log_warning "jq not available, using raw curl output"
        curl -s http://localhost:5001/v2/_catalog
    }
    
    # Verify each service image
    for service in "${!SERVICES[@]}"; do
        image_tag="${REGISTRY}/${PROJECT_NAME}/${service}:${VERSION}"
        
        if docker image inspect "$image_tag" &>/dev/null; then
            log_success "✅ $service image verified: $image_tag"
            
            # Show image size
            size=$(docker image inspect "$image_tag" --format='{{.Size}}' | numfmt --to=iec)
            log_info "   Image size: $size"
        else
            log_error "❌ $service image not found: $image_tag"
            exit 1
        fi
    done
}

# Generate image manifest for air-gap distribution
generate_image_manifest() {
    local manifest_file="kubechat-images-${VERSION}.txt"
    
    log_info "📝 Generating image manifest for air-gap distribution..."
    
    cat > "$manifest_file" << EOF
# KubeChat Phase 1 Model 1 Image Manifest
# Version: $VERSION
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# Registry: $REGISTRY

EOF
    
    for service in "${!SERVICES[@]}"; do
        image_tag="${REGISTRY}/${PROJECT_NAME}/${service}:${VERSION}"
        echo "$image_tag" >> "$manifest_file"
    done
    
    log_success "Image manifest generated: $manifest_file"
    
    # Create image export script
    cat > "export-images-${VERSION}.sh" << EOF
#!/bin/bash
# Export KubeChat images for air-gap distribution
# Generated: $(date -u +"%Y-%m-%d %H:%M:%S UTC")

set -euo pipefail

echo "Exporting KubeChat images for air-gap distribution..."

# Create export directory
mkdir -p kubechat-images-${VERSION}/

EOF
    
    for service in "${!SERVICES[@]}"; do
        image_tag="${REGISTRY}/${PROJECT_NAME}/${service}:${VERSION}"
        cat >> "export-images-${VERSION}.sh" << EOF
echo "Exporting $service..."
docker save $image_tag > kubechat-images-${VERSION}/${PROJECT_NAME}-${service}-${VERSION}.tar

EOF
    done
    
    cat >> "export-images-${VERSION}.sh" << EOF
echo "Creating image bundle..."
tar -czf kubechat-images-${VERSION}.tar.gz kubechat-images-${VERSION}/

echo "✅ Air-gap image bundle created: kubechat-images-${VERSION}.tar.gz"
echo "📦 Transfer this bundle to air-gap environment for deployment"
EOF
    
    chmod +x "export-images-${VERSION}.sh"
    log_success "Image export script created: export-images-${VERSION}.sh"
}

# Cleanup old images (optional)
cleanup_old_images() {
    local keep_versions="${2:-3}"
    
    log_info "🧹 Cleaning up old development images (keeping last $keep_versions versions)..."
    
    # This is a simple cleanup - in production, you'd want more sophisticated cleanup
    docker image prune -f --filter "label=project=kubechat" 2>/dev/null || true
    
    log_info "Cleanup completed"
}

# Display usage information
usage() {
    cat <<EOF
Usage: $0 [ENVIRONMENT] [VERSION] [OPTIONS]

Build all KubeChat service images for development or production environments

Arguments:
  ENVIRONMENT   Target environment: 'dev' or 'production' (default: dev)
  VERSION       Image version tag (default: dev)

Options:
  --version VER  Specify version explicitly
  --cleanup      Clean up old images after build
  --help         Show this help message

Environment Variables (for production):
  DOCKER_REGISTRY    Production registry (default: docker.io)
  DOCKER_REPOSITORY  Production repository (default: kubechat/kubechat)

Examples:
  $0                              # Build dev images with 'dev' tag
  $0 dev                          # Same as above
  $0 dev v1.0.0                   # Build dev images with 'v1.0.0' tag
  $0 production v1.0.0            # Build production images with 'v1.0.0' tag
  $0 dev --cleanup                # Build and cleanup old images
  
  # Production with Docker Hub
  DOCKER_REPOSITORY=kubechat/kubechat $0 production v1.0.0

EOF
}

# Main execution
main() {
    local cleanup=false
    
    # Parse all arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            dev|development|prod|production)
                # Environment already processed, skip
                shift
                ;;
            --cleanup)
                cleanup=true
                shift
                ;;
            --help)
                usage
                exit 0
                ;;
            --version)
                VERSION="$2"
                shift 2
                ;;
            -*)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                # Assume it's the version if not specified with --version
                VERSION="$1"
                shift
                ;;
        esac
    done
    
    log_info "🚀 Starting KubeChat Phase 1 Model 1 multi-service image build..."
    log_info "Version: $VERSION"
    
    verify_prerequisites
    build_all_services
    verify_images
    generate_image_manifest
    
    if [[ "$cleanup" == true ]]; then
        cleanup_old_images
    fi
    
    log_success "✅ KubeChat multi-service image build completed successfully!"
    echo ""
    log_info "📋 Built Images ($ENVIRONMENT environment):"
    for service in "${SERVICES_NAMES[@]}"; do
        if [[ "$ENVIRONMENT" == "production" ]]; then
            echo "  ${REPOSITORY}:${service}-${VERSION}"
        else
            echo "  ${REGISTRY}/${PROJECT_NAME}/${service}:${VERSION}"
        fi
    done
    echo ""
    log_info "🚀 Next Steps:"
    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo "  1. Images are pushed to production registry: $REPOSITORY"
        echo "  2. Deploy using production Helm values"
        echo "  3. Run production validation tests"
    else
        echo "  1. Run './scripts/deploy-dev.sh' to deploy to Rancher Desktop"
        echo "  2. Run './scripts/test-phase1.sh' to validate deployment"
        echo "  3. Use './scripts/airgap-bundle.sh' for air-gap distribution"
    fi
}

# Execute main function
main "$@"