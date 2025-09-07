# KubeChat Development Documentation - Phase 1 Model 1

## Overview

This directory contains development documentation for **KubeChat Phase 1: Model 1 (On-Premises FREE Platform)** using **Rancher Desktop** as the local development environment.

## Development Documentation

### Core Development Guides
- [Local Setup](./local-setup.md) - **Primary Guide** - Complete Phase 1 Model 1 development setup using Rancher Desktop with air-gap testing capability
- [Coding Standards](./coding-standards.md) - Comprehensive Go development standards and best practices for Kubernetes operators

## Phase 1 Model 1 Development Focus

### Architecture Components
- **Kubernetes Operator**: Native Kubernetes controller for resource management
- **API Gateway**: RESTful API service for natural language processing  
- **Audit Service**: Comprehensive audit trail and compliance logging
- **No Web Frontend**: Phase 1 Model 1 is backend-only (web interface deferred to Phase 2)

### Development Environment
- **Rancher Desktop**: Local Kubernetes cluster with container runtime
- **Local Registry**: Container registry for air-gap testing simulation
- **Helm Charts**: Native Kubernetes deployment using Helm
- **Air-Gap Testing**: Complete offline deployment capability validation

### Key Development Principles
- **Data Sovereignty**: 100% customer-controlled deployment
- **Air-Gap Capable**: Complete offline installation with no external dependencies
- **Helm-Native**: Single-command deployment using standard Helm charts
- **Zero Vendor Lock-In**: No proprietary APIs or vendor-specific services

## Quick Start Guide

### For New Developers
1. Follow [Local Setup](./local-setup.md) for complete Rancher Desktop environment
2. Review [Coding Standards](./coding-standards.md) for development guidelines
3. Run development setup scripts to prepare environment
4. Build and deploy to local Rancher Desktop cluster

### Development Workflow
```bash
# Standard Phase 1 Model 1 development cycle
./scripts/setup-phase1-dev.sh      # One-time setup
./scripts/build-dev-images.sh      # Build development images  
./scripts/deploy-dev.sh            # Deploy to Rancher Desktop
./scripts/test-phase1.sh           # Validate deployment
./scripts/test-airgap.sh           # Test air-gap capability
```

## Development Tools and Environment

### Required Tools
- **Rancher Desktop**: Kubernetes development environment
- **Go 1.22+**: Backend service development
- **Docker**: Container building (via Rancher Desktop)
- **kubectl**: Kubernetes cluster operations
- **Helm 3.x**: Chart-based deployment

### Optional Tools
- **Visual Studio Code**: With recommended extensions for Go and Kubernetes
- **k9s**: Terminal UI for Kubernetes cluster management
- **kubectx**: Kubernetes context switching

### Development Namespaces
- **kubechat-system**: Primary development deployment
- **kubechat-airgap**: Air-gap deployment testing

## Testing and Validation

### Testing Capabilities
- **Unit Tests**: Go unit tests for all packages
- **Integration Tests**: Kubernetes operator integration testing
- **Air-Gap Testing**: Complete offline deployment simulation
- **Custom Resource Testing**: CRD creation and management validation

### Validation Procedures
- **Health Checks**: API Gateway and service health validation
- **Operator Testing**: Custom resource lifecycle testing  
- **Helm Chart Testing**: Chart deployment and upgrade testing
- **Air-Gap Validation**: Offline bundle creation and deployment

## Architecture Alignment

### Phase 1 Model 1 Specific Features
- **On-Premises Only**: No cloud components or SaaS features
- **Customer Infrastructure**: Deploys directly to customer Kubernetes clusters
- **Air-Gap Ready**: Complete offline installation capability
- **Helm Standard**: Uses industry-standard Helm chart deployment

### Future Considerations
- **Phase 2 Preparation**: Architecture designed for future SaaS model addition
- **Code Reuse**: 85% code reuse target for Phase 2 expansion
- **Multi-Tenancy Ready**: Foundation supports future tenant isolation

## Support and Resources

### Getting Help
- **Setup Issues**: Check [Local Setup](./local-setup.md) troubleshooting section
- **Coding Questions**: Review [Coding Standards](./coding-standards.md) guidelines
- **Rancher Desktop**: Official Rancher Desktop documentation at https://rancherdesktop.io/
- **Helm Charts**: Helm documentation for chart development

### Best Practices
- **Development Focus**: Phase 1 Model 1 on-premises deployment only
- **Testing**: Always test air-gap deployment scenarios
- **Standards**: Follow enterprise coding standards and Kubernetes best practices
- **Documentation**: Update documentation alongside code changes

This development documentation ensures KubeChat Phase 1 Model 1 can be effectively developed and tested using Rancher Desktop with full on-premises and air-gap capability validation.