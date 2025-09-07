# KubeChat Deployment Documentation - Phase 1 Model 1

## Overview

This directory contains comprehensive deployment documentation for **KubeChat Phase 1: Model 1 (On-Premises FREE Platform)** - our primary development target. All deployment procedures prioritize complete data sovereignty, air-gap capability, zero vendor lock-in, and Helm-native deployment directly into customer Kubernetes clusters.

## Deployment Documentation

### Core Deployment Guides
- [On-Premises Deployment](./on-premises-deployment.md) - **Primary Guide** - Complete Phase 1 Model 1 deployment using Helm charts with air-gap capability and data sovereignty
- [Configuration Reference](./configuration-reference.md) - Complete reference for all configuration parameters and environment variables

### Development Environment Documentation
- [Rancher Desktop Development](./rancher-desktop-development.md) - Complete development environment setup, testing, and air-gap simulation using Rancher Desktop

### Operational Documentation  
- [Operational Procedures](./operational-procedures.md) - Comprehensive operational procedures for deployment management, monitoring, incident response, and maintenance

## Phase 1 Model 1 Architecture Overview

KubeChat **Phase 1: Model 1 (On-Premises)** architecture ensures complete customer control:

### Core Principles
- **Data Sovereignty**: 100% customer-controlled deployment in their Kubernetes clusters
- **Air-Gap Capable**: Complete offline installation with no external dependencies
- **Helm-Native**: Single-command deployment using standard Helm charts
- **Zero Vendor Lock-In**: No proprietary APIs or vendor-specific services

### Key Components
- **Kubernetes Operator**: Native Kubernetes controller for resource management
- **API Gateway**: RESTful API service for natural language processing
- **Audit Service**: Comprehensive audit trail and compliance logging
- **PostgreSQL**: Customer-managed database for persistent storage
- **Redis**: Customer-managed caching and session storage

### Deployment Environments
- **Development**: Rancher Desktop local testing with air-gap simulation
- **Customer Production**: Direct deployment into customer Kubernetes infrastructure

## Quick Start Guide

### For Development (Rancher Desktop)
1. Follow [Rancher Desktop Development](./rancher-desktop-development.md) setup
2. Test air-gap deployment simulation
3. Validate Helm chart deployment locally

### For Customer Production Deployment
1. Review [Configuration Reference](./configuration-reference.md) for parameter details
2. Follow [On-Premises Deployment](./on-premises-deployment.md) for Helm-based installation
3. Use [Operational Procedures](./operational-procedures.md) for ongoing management

## Prerequisites

### Infrastructure Requirements
- **Kubernetes**: 1.28+ cluster (3+ nodes minimum)
- **Storage**: Persistent volumes for database and cache
- **Access**: Cluster admin permissions for CRD installation
- **Helm**: Helm 3.x installed and configured

### Optional Customer Integration
- **Identity Provider**: OIDC or SAML provider for authentication
- **Ingress Controller**: Customer's existing ingress solution
- **Monitoring**: Integration with customer's existing monitoring stack
- **Container Registry**: Customer's private registry for air-gap deployments

## Deployment Features

### Standard Helm Deployment
- Single-command installation: `helm install kubechat ./kubechat-chart`
- Configurable through values.yaml files
- Standard Kubernetes rolling updates

### Air-Gap Support  
- Offline installation bundles with all container images
- No internet connectivity required post-installation
- Manual update deployment process

### Customer Integration
- **Authentication**: OIDC/SAML integration with customer identity providers
- **Storage**: Uses customer's existing Kubernetes storage classes
- **Networking**: Integrates with customer's ingress controllers and network policies
- **Monitoring**: Optional integration with customer's monitoring stack

## Support and Troubleshooting

### Getting Help
- **Deployment Issues**: Check [On-Premises Deployment](./on-premises-deployment.md) troubleshooting section
- **Configuration Questions**: Review [Configuration Reference](./configuration-reference.md)
- **Development Setup**: Follow [Rancher Desktop Development](./rancher-desktop-development.md) guide
- **Operations**: Use [Operational Procedures](./operational-procedures.md) for ongoing management

This deployment documentation provides **Phase 1 Model 1 focused** guidance ensuring KubeChat can be successfully deployed in customer environments with complete data sovereignty and zero vendor dependencies.