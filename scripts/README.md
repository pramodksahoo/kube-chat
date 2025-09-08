# KubeChat Scripts Directory

This directory contains automated scripts for developing, building, testing, and deploying KubeChat. All scripts are designed for KubeChat Phase 1 Model 1 (On-Premises) and support air-gap deployment capabilities.

## 📋 Quick Start Guide

### 1. Development Environment Setup
```bash
# First time setup - installs all prerequisites
./scripts/setup-phase1-dev.sh

# Verify setup
./scripts/debug-kubechat.sh --check-prereqs
```

### 2. Build Images
```bash
# Build all images with 'dev' tag
./scripts/build-kubechat-images.sh dev

# Build and push to local registry
./scripts/build-kubechat-images.sh dev --push
```

### 3. Deploy to Development
```bash
# Deploy with default configuration
./scripts/deploy-dev.sh

# Deploy with custom namespace and values
./scripts/deploy-dev.sh kubechat-test values-custom.yaml v1.0.0
```

### 4. Test Deployment
```bash
# Test all functionality from Story 1-4
./scripts/test-phase1.sh

# Test air-gap capabilities
./scripts/test-airgap.sh
```

## 🔧 Script Categories

### Development & Setup Scripts

#### `setup-phase1-dev.sh`
**Purpose**: One-time development environment setup for KubeChat Phase 1 Model 1
**Usage**: `./scripts/setup-phase1-dev.sh [OPTIONS]`
**What it does**:
- Installs and configures Rancher Desktop
- Sets up local Docker registry (localhost:5001)
- Installs required development tools (kubectl, helm, docker)
- Configures Kubernetes context for development
- Creates necessary directories and permissions

**Options**:
- `--skip-rancher`: Skip Rancher Desktop installation
- `--skip-registry`: Skip local registry setup
- `--help`: Show usage information

**Prerequisites**: macOS with Homebrew installed
**Runtime**: 5-15 minutes

---

#### `debug-kubechat.sh`
**Purpose**: Comprehensive debugging and troubleshooting tool
**Usage**: `./scripts/debug-kubechat.sh [COMMAND] [OPTIONS]`
**Commands**:
- `--check-prereqs`: Verify all prerequisites are installed
- `--check-cluster`: Verify Kubernetes cluster health
- `--check-images`: Verify container images are available
- `--check-services`: Test all service endpoints
- `--logs [SERVICE]`: Show logs for specific service
- `--describe [RESOURCE]`: Describe Kubernetes resources
- `--cleanup`: Clean up failed deployments

**Examples**:
```bash
# Complete system check
./scripts/debug-kubechat.sh --check-prereqs

# Check specific service logs
./scripts/debug-kubechat.sh --logs api-gateway

# Describe all pods
./scripts/debug-kubechat.sh --describe pods
```

### Build & Image Management Scripts

#### `build-kubechat-images.sh`
**Purpose**: Build all KubeChat container images for development and production
**Usage**: `./scripts/build-kubechat-images.sh [ENVIRONMENT] [VERSION] [OPTIONS]`
**Environments**:
- `dev`: Development build with debug symbols
- `prod`: Production build optimized for size and security

**What it builds**:
- `kubechat/api-gateway`: API Gateway service (Go + Fiber)
- `kubechat/audit-service`: Audit logging service (Go)
- `kubechat/operator`: Kubernetes operator (Go)
- `kubechat/web`: React web frontend (Nginx)

**Options**:
- `--push`: Push images to registry after building
- `--no-cache`: Build without using Docker cache
- `--parallel`: Build images in parallel (faster)
- `--registry URL`: Specify custom registry URL

**Examples**:
```bash
# Build development images
./scripts/build-kubechat-images.sh dev

# Build and push production images
./scripts/build-kubechat-images.sh prod v1.0.0 --push

# Build with no cache for clean build
./scripts/build-kubechat-images.sh dev --no-cache
```

**Build Time**: 5-10 minutes for all images

---

#### `tag-images.sh`
**Purpose**: Tag and retag container images for different environments
**Usage**: `./scripts/tag-images.sh [SOURCE_TAG] [TARGET_TAG] [OPTIONS]`
**Use Cases**:
- Promote dev images to staging: `dev` → `staging`
- Promote staging to production: `staging` → `v1.0.0`
- Create release candidates: `dev` → `v1.0.0-rc1`

**Options**:
- `--registry SOURCE`: Source registry URL
- `--target-registry TARGET`: Target registry URL
- `--push`: Push tagged images to registry
- `--services LIST`: Tag only specific services

**Examples**:
```bash
# Tag dev images as v1.0.0
./scripts/tag-images.sh dev v1.0.0 --push

# Tag between registries
./scripts/tag-images.sh dev v1.0.0 --registry localhost:5001 --target-registry harbor.company.com --push
```

---

#### `cleanup-images.sh`
**Purpose**: Clean up old and unused container images
**Usage**: `./scripts/cleanup-images.sh [OPTIONS]`
**What it cleans**:
- Dangling images (untagged)
- Old image versions (keep latest N)
- Build cache
- Unused volumes

**Options**:
- `--keep-versions N`: Keep latest N versions (default: 5)
- `--dry-run`: Show what would be deleted without deleting
- `--force`: Skip confirmation prompts
- `--registry-cleanup`: Also clean registry storage

**Examples**:
```bash
# Clean up keeping latest 3 versions
./scripts/cleanup-images.sh --keep-versions 3

# Dry run to see what would be deleted
./scripts/cleanup-images.sh --dry-run
```

### Deployment Scripts

#### `deploy-dev.sh` ⭐
**Purpose**: Deploy KubeChat to Rancher Desktop development environment
**Usage**: `./scripts/deploy-dev.sh [NAMESPACE] [VALUES_FILE] [VERSION] [OPTIONS]`
**What it deploys**:
- Complete KubeChat system with all services
- PostgreSQL database for audit storage
- Redis for session management
- Ingress configuration for web access

**Default Configuration**:
- Namespace: `kubechat-system`
- Values: `deploy/helm/kubechat/values-dev-rancher.yaml`
- Version: `dev`
- Timeout: 10 minutes

**Options**:
- `--build`: Force rebuild images before deployment
- `--dry-run`: Validate deployment without applying
- `--help`: Show detailed usage information

**Port Configuration**:
- API Gateway: 8080
- Audit Service: 8081  
- Operator: 8082
- Web Interface: 8083

**Examples**:
```bash
# Deploy with defaults
./scripts/deploy-dev.sh

# Deploy to custom namespace with specific version
./scripts/deploy-dev.sh kubechat-test values-minimal.yaml v1.0.0

# Force rebuild and deploy
./scripts/deploy-dev.sh --build

# Validate deployment configuration
./scripts/deploy-dev.sh --dry-run
```

**Prerequisites**:
- Rancher Desktop running
- Local registry with images
- Helm 3.x installed

**Deployment Time**: 3-5 minutes

### Testing Scripts

#### `test-phase1.sh`
**Purpose**: Comprehensive testing of all KubeChat Phase 1 functionality
**Usage**: `./scripts/test-phase1.sh [OPTIONS]`
**Test Coverage**:
- **Story 1**: Natural language query translation
- **Story 2**: Kubernetes command execution
- **Story 3**: Comprehensive audit logging
- **Story 4**: Real-time web interface

**Test Types**:
- Unit tests (if available)
- Integration tests
- End-to-end API tests
- Web interface functionality tests
- Database connectivity tests
- Audit trail verification

**Options**:
- `--story N`: Test only specific story (1-4)
- `--verbose`: Detailed test output
- `--report`: Generate test report
- `--parallel`: Run tests in parallel

**Examples**:
```bash
# Test all functionality
./scripts/test-phase1.sh

# Test only Story 4 (Web Interface)
./scripts/test-phase1.sh --story 4

# Generate detailed test report
./scripts/test-phase1.sh --report --verbose
```

**Test Time**: 5-10 minutes for full suite

---

#### `test-airgap.sh`
**Purpose**: Validate air-gap deployment capabilities
**Usage**: `./scripts/test-airgap.sh [OPTIONS]`
**What it tests**:
- Offline image bundle creation
- Air-gap installation process
- Network isolation compliance
- Local registry functionality
- Offline certificate management

**Test Scenarios**:
- Complete disconnected deployment
- Image bundle integrity verification
- Local registry push/pull operations
- Service discovery without external DNS
- Certificate generation and validation

**Options**:
- `--quick`: Run essential tests only
- `--full`: Complete air-gap simulation
- `--network-policy`: Test with network policies enabled

### Air-Gap & Registry Scripts

#### `airgap-bundle.sh`
**Purpose**: Create complete air-gap deployment bundles
**Usage**: `./scripts/airgap-bundle.sh [VERSION] [OPTIONS]`
**Bundle Contents**:
- All KubeChat container images
- Helm charts and configurations
- Dependency images (PostgreSQL, Redis, etc.)
- Installation documentation
- Offline certificate bundles

**Bundle Structure**:
```
kubechat-airgap-v1.0.0/
├── images/
│   ├── kubechat-images.tar
│   ├── dependency-images.tar
│   └── manifest.json
├── charts/
│   └── kubechat-helm-chart.tgz
├── scripts/
│   └── install-airgap.sh
└── docs/
    └── airgap-installation-guide.md
```

**Options**:
- `--output DIR`: Specify output directory
- `--compress`: Create compressed bundle
- `--sign`: Sign bundle with GPG
- `--manifest`: Generate detailed manifest

---

#### `manage-registry.sh`
**Purpose**: Manage local Docker registry for development
**Usage**: `./scripts/manage-registry.sh [COMMAND] [OPTIONS]`
**Commands**:
- `start`: Start local registry on localhost:5001
- `stop`: Stop local registry
- `restart`: Restart registry
- `status`: Show registry status
- `list`: List all images in registry
- `push [IMAGE]`: Push image to registry
- `pull [IMAGE]`: Pull image from registry
- `cleanup`: Remove unused images from registry

**Registry Features**:
- Persistent storage in Docker volume
- Web UI available at http://localhost:5001
- Supports air-gap scenarios
- Automatic image cleanup policies

### Validation & Troubleshooting Scripts

#### `validate-airgap.sh`
**Purpose**: Validate air-gap deployment configuration and requirements
**Usage**: `./scripts/validate-airgap.sh [OPTIONS]`
**Validation Checks**:
- Image bundle completeness
- Configuration file validity
- Certificate chain verification
- Network policy compliance
- Security scanner results

---

#### `troubleshoot-airgap.sh`
**Purpose**: Advanced troubleshooting for air-gap deployments
**Usage**: `./scripts/troubleshoot-airgap.sh [ISSUE_TYPE] [OPTIONS]`
**Issue Types**:
- `network`: Network connectivity issues
- `registry`: Registry access problems
- `images`: Image pull/push failures
- `certificates`: Certificate validation errors
- `deployment`: Kubernetes deployment issues

---

#### `scan-images.sh`
**Purpose**: Security scanning of container images
**Usage**: `./scripts/scan-images.sh [OPTIONS]`
**Security Scans**:
- Vulnerability assessment
- License compliance
- Configuration security
- Base image analysis

### Utility Scripts

#### `setup-port-forwards.sh` ⭐
**Purpose**: Automated port forwarding setup for development and testing
**Usage**: `./scripts/setup-port-forwards.sh [start|stop|status|test]`
**What it does**:
- Automatically sets up all necessary port forwards for development
- Provides easy start/stop commands
- Tests all service health endpoints
- Shows port forward status and active connections

**Commands**:
- `start`: Start all port forwards for KubeChat services
- `stop`: Stop all active port forwards
- `status`: Show current port forward status
- `test`: Test all service endpoints for health
- `restart`: Stop and start all port forwards

**Port Mappings**:
- API Gateway: `localhost:8080`
- Audit Service: `localhost:8081`
- Web Interface: `localhost:8083`
- Operator: `localhost:8082`
- PostgreSQL: `localhost:5432`
- Redis: `localhost:6379`

**Examples**:
```bash
# Start all port forwards
./scripts/setup-port-forwards.sh start

# Test all endpoints
./scripts/setup-port-forwards.sh test

# Check status
./scripts/setup-port-forwards.sh status
```

---

#### `setup-dockerhub.sh`
**Purpose**: Configure DockerHub integration for image distribution
**Usage**: `./scripts/setup-dockerhub.sh [OPTIONS]`

---

#### `simulate-airgap.sh`
**Purpose**: Simulate air-gap environment for testing
**Usage**: `./scripts/simulate-airgap.sh [COMMAND]`

## 🚀 Common Workflows

### 1. First-Time Development Setup
```bash
# Complete setup process (run once)
./scripts/setup-phase1-dev.sh
./scripts/build-kubechat-images.sh dev
./scripts/deploy-dev.sh
./scripts/test-phase1.sh
```

### 2. Daily Development Workflow
```bash
# Build latest changes
./scripts/build-kubechat-images.sh dev

# Deploy updates
./scripts/deploy-dev.sh

# Test specific functionality
./scripts/test-phase1.sh --story 4
```

### 3. Release Preparation
```bash
# Build production images
./scripts/build-kubechat-images.sh prod v1.0.0 --push

# Create air-gap bundle
./scripts/airgap-bundle.sh v1.0.0 --compress --sign

# Validate air-gap deployment
./scripts/validate-airgap.sh
./scripts/test-airgap.sh --full
```

### 4. Troubleshooting Failed Deployment
```bash
# Check prerequisites
./scripts/debug-kubechat.sh --check-prereqs

# Check cluster health
./scripts/debug-kubechat.sh --check-cluster

# View service logs
./scripts/debug-kubechat.sh --logs api-gateway

# Clean up and retry
./scripts/debug-kubechat.sh --cleanup
./scripts/deploy-dev.sh --build
```

## 📊 Port Configuration

All scripts use consistent port configuration:

| Service | Internal Port | Description |
|---------|---------------|-------------|
| API Gateway | 8080 | Main HTTP API and routing |
| Audit Service | 8081 | Audit logging and compliance |
| Operator | 8082 | Kubernetes operator management |
| Web Interface | 8083 | React frontend (Nginx) |

## 🔐 Security Considerations

- All scripts run with minimal required permissions
- Container images use non-root users
- Air-gap bundles include security signatures
- Network policies restrict inter-service communication
- Audit logging tracks all script executions

## 📝 Logging and Debugging

All scripts provide:
- Colored output for easy reading
- Detailed logging with timestamps
- Debug mode for troubleshooting
- Error handling with cleanup
- Progress indicators for long operations

## 🤝 Contributing

When adding new scripts:
1. Follow existing naming conventions
2. Include comprehensive help text
3. Add proper error handling
4. Update this README
5. Test with air-gap scenarios

## 📞 Support

For issues with scripts:
1. Run `./scripts/debug-kubechat.sh --check-prereqs`
2. Check script logs in `/tmp/kubechat-scripts.log`
3. Review deployment status with `kubectl get pods -n kubechat-system`
4. Consult troubleshooting guide in docs/

---

**Note**: All scripts are designed for KubeChat Phase 1 Model 1 (On-Premises) and support air-gap deployment scenarios. They assume Rancher Desktop for development and production Kubernetes clusters for deployment.