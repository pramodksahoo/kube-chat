#!/bin/bash

# KubeChat Docker Hub Registry Setup Script
# Setup Docker Hub authentication and image management
# Usage: ./scripts/setup-dockerhub.sh [options]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_DIR="${PROJECT_ROOT}/logs"
LOG_FILE="${LOG_DIR}/dockerhub-setup_$(date +%Y%m%d_%H%M%S).log"

# Docker Hub configuration
DOCKERHUB_USERNAME="${DOCKERHUB_USERNAME:-}"
DOCKERHUB_PASSWORD="${DOCKERHUB_PASSWORD:-}"
DOCKERHUB_REPOSITORY="kubechat/kubechat"
DOCKERHUB_REGISTRY="docker.io"

# Kubernetes configuration
KUBE_NAMESPACE="kubechat"
SECRET_NAME="dockerhub-registry-secret"

# Operation modes
OPERATION="setup"  # setup, login, create-secret, push-images, test
VERBOSE=false
DRY_RUN=false

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

check_credentials() {
    if [[ -z "$DOCKERHUB_USERNAME" ]]; then
        log_error "Docker Hub username not provided"
        log_info "Set DOCKERHUB_USERNAME environment variable or use --username option"
        return 1
    fi
    
    if [[ -z "$DOCKERHUB_PASSWORD" ]]; then
        log_error "Docker Hub password not provided"
        log_info "Set DOCKERHUB_PASSWORD environment variable or use --password option"
        return 1
    fi
    
    log_success "Docker Hub credentials provided"
}

docker_login() {
    print_section "Docker Hub Login"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would login to Docker Hub as: $DOCKERHUB_USERNAME"
        return 0
    fi
    
    log_info "Logging into Docker Hub as: $DOCKERHUB_USERNAME"
    
    if echo "$DOCKERHUB_PASSWORD" | docker login -u "$DOCKERHUB_USERNAME" --password-stdin; then
        log_success "Successfully logged into Docker Hub"
    else
        log_error "Failed to login to Docker Hub"
        return 1
    fi
}

create_k8s_secret() {
    print_section "Creating Kubernetes Registry Secret"
    
    # Check if namespace exists
    if ! kubectl get namespace "$KUBE_NAMESPACE" >/dev/null 2>&1; then
        log_info "Creating namespace: $KUBE_NAMESPACE"
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] Would create namespace: $KUBE_NAMESPACE"
        else
            kubectl create namespace "$KUBE_NAMESPACE"
        fi
    fi
    
    # Delete existing secret if it exists
    if kubectl get secret "$SECRET_NAME" -n "$KUBE_NAMESPACE" >/dev/null 2>&1; then
        log_info "Removing existing secret: $SECRET_NAME"
        if [[ "$DRY_RUN" != "true" ]]; then
            kubectl delete secret "$SECRET_NAME" -n "$KUBE_NAMESPACE"
        fi
    fi
    
    # Create Docker registry secret
    log_info "Creating Docker Hub registry secret: $SECRET_NAME"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would create secret: $SECRET_NAME in namespace: $KUBE_NAMESPACE"
    else
        kubectl create secret docker-registry "$SECRET_NAME" \
            --docker-server="$DOCKERHUB_REGISTRY" \
            --docker-username="$DOCKERHUB_USERNAME" \
            --docker-password="$DOCKERHUB_PASSWORD" \
            --docker-email="${DOCKERHUB_EMAIL:-$DOCKERHUB_USERNAME@example.com}" \
            -n "$KUBE_NAMESPACE"
        
        log_success "Registry secret created successfully"
    fi
}

tag_and_push_images() {
    print_section "Tagging and Pushing Images to Docker Hub"
    
    local services=("api-gateway" "operator" "audit-service" "web")
    local version="${IMAGE_VERSION:-v1.0.0}"
    
    for service in "${services[@]}"; do
        local local_image="localhost:5001/kubechat/${service}:latest"
        local dockerhub_image="${DOCKERHUB_REPOSITORY}:${service}-${version}"
        
        log_info "Processing service: $service"
        
        # Check if local image exists
        if ! docker images "$local_image" --format "{{.Repository}}:{{.Tag}}" | grep -q "$local_image"; then
            log_error "Local image not found: $local_image"
            continue
        fi
        
        # Tag for Docker Hub
        log_info "Tagging: $local_image -> $dockerhub_image"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "[DRY RUN] Would tag and push: $dockerhub_image"
        else
            if docker tag "$local_image" "$dockerhub_image"; then
                log_success "Tagged: $dockerhub_image"
                
                # Push to Docker Hub
                log_info "Pushing: $dockerhub_image"
                if docker push "$dockerhub_image"; then
                    log_success "Pushed: $dockerhub_image"
                else
                    log_error "Failed to push: $dockerhub_image"
                fi
            else
                log_error "Failed to tag: $local_image"
            fi
        fi
    done
}

test_dockerhub_access() {
    print_section "Testing Docker Hub Access"
    
    # Test login
    if docker info | grep -q "Username: $DOCKERHUB_USERNAME"; then
        log_success "Docker is logged into Docker Hub as: $DOCKERHUB_USERNAME"
    else
        log_warn "Docker not logged in or different user"
    fi
    
    # Test repository access
    log_info "Testing repository access: $DOCKERHUB_REPOSITORY"
    
    if curl -s "https://hub.docker.com/v2/repositories/$DOCKERHUB_REPOSITORY/" >/dev/null; then
        log_success "Repository accessible: $DOCKERHUB_REPOSITORY"
    else
        log_error "Repository not accessible: $DOCKERHUB_REPOSITORY"
    fi
    
    # Test Kubernetes secret
    if kubectl get secret "$SECRET_NAME" -n "$KUBE_NAMESPACE" >/dev/null 2>&1; then
        log_success "Kubernetes registry secret exists: $SECRET_NAME"
        
        if [[ "$VERBOSE" == "true" ]]; then
            kubectl describe secret "$SECRET_NAME" -n "$KUBE_NAMESPACE"
        fi
    else
        log_error "Kubernetes registry secret not found: $SECRET_NAME"
    fi
}

setup_dockerhub() {
    print_section "Setting up Docker Hub Integration"
    
    check_credentials
    docker_login
    create_k8s_secret
    
    log_success "Docker Hub setup completed"
    
    echo -e "\n${GREEN}Next steps:${NC}"
    echo "1. Build and tag your images:"
    echo "   ./scripts/build-dev-images.sh"
    echo "   ./scripts/setup-dockerhub.sh push-images"
    echo ""
    echo "2. Deploy using Docker Hub values:"
    echo "   helm install kubechat ./deploy/helm/kubechat \\"
    echo "     -f deploy/helm/kubechat/values-dockerhub-production.yaml \\"
    echo "     -n kubechat"
}

show_usage() {
    cat <<EOF
KubeChat Docker Hub Registry Setup Script

USAGE:
    $0 [OPERATION] [OPTIONS]

OPERATIONS:
    setup              Complete Docker Hub setup (default)
    login              Login to Docker Hub only
    create-secret      Create Kubernetes registry secret only
    push-images        Tag and push images to Docker Hub
    test               Test Docker Hub access and configuration

OPTIONS:
    --username USER    Docker Hub username (or set DOCKERHUB_USERNAME)
    --password PASS    Docker Hub password (or set DOCKERHUB_PASSWORD)
    --email EMAIL      Docker Hub email (optional)
    --repository REPO  Docker Hub repository (default: $DOCKERHUB_REPOSITORY)
    --namespace NS     Kubernetes namespace (default: $KUBE_NAMESPACE)
    --secret-name NAME Secret name (default: $SECRET_NAME)
    --image-version V  Image version for tagging (default: v1.0.0)
    --dry-run          Show what would be done
    --verbose          Enable verbose output
    --help             Show this help

ENVIRONMENT VARIABLES:
    DOCKERHUB_USERNAME    Docker Hub username
    DOCKERHUB_PASSWORD    Docker Hub password/token
    DOCKERHUB_EMAIL       Docker Hub email (optional)

EXAMPLES:
    # Complete setup with credentials
    export DOCKERHUB_USERNAME=your-username
    export DOCKERHUB_PASSWORD=your-password
    $0 setup

    # Setup with command line options
    $0 setup --username your-username --password your-password

    # Just create Kubernetes secret
    $0 create-secret --username your-username --password your-password

    # Tag and push images
    $0 push-images --image-version v1.0.1

    # Test configuration
    $0 test --verbose

SECURITY NOTE:
For production, use Docker Hub access tokens instead of passwords:
1. Go to Docker Hub -> Account Settings -> Security
2. Create a new access token
3. Use the token as the password

EOF
}

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            setup|login|create-secret|push-images|test)
                OPERATION="$1"
                shift
                ;;
            --username)
                DOCKERHUB_USERNAME="$2"
                shift 2
                ;;
            --password)
                DOCKERHUB_PASSWORD="$2"
                shift 2
                ;;
            --email)
                DOCKERHUB_EMAIL="$2"
                shift 2
                ;;
            --repository)
                DOCKERHUB_REPOSITORY="$2"
                shift 2
                ;;
            --namespace)
                KUBE_NAMESPACE="$2"
                shift 2
                ;;
            --secret-name)
                SECRET_NAME="$2"
                shift 2
                ;;
            --image-version)
                IMAGE_VERSION="$2"
                shift 2
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
    
    mkdir -p "$LOG_DIR"
    log_info "Docker Hub setup starting (operation: $OPERATION)"
    
    case $OPERATION in
        setup)
            setup_dockerhub
            ;;
        login)
            check_credentials
            docker_login
            ;;
        create-secret)
            check_credentials
            create_k8s_secret
            ;;
        push-images)
            tag_and_push_images
            ;;
        test)
            test_dockerhub_access
            ;;
        *)
            log_error "Unknown operation: $OPERATION"
            exit 1
            ;;
    esac
}

main "$@"