# KubeChat Architecture Documentation

This directory contains the detailed technical architecture documentation for KubeChat **Phase 1: Model 1 (On-Premises FREE Platform)** - our primary development target.

## Phase 1 Model 1 Focus

KubeChat **Phase 1: Model 1 (On-Premises)** is our **immediate and primary development focus**. This free, open-source platform targets security-conscious enterprises requiring:
- **Complete data sovereignty** with customer-controlled deployment
- **Air-gap capability** for offline/isolated environments  
- **Zero vendor lock-in** through Helm-native deployment
- **Enterprise-grade security** with OIDC/SAML integration
- **Kubernetes operator pattern** for native cluster integration

## Architecture Sections

- [Tech Stack](./tech-stack.md) - Technology choices, versions, and development environment requirements
- [Source Tree](./source-tree.md) - Project structure, file organization, and naming conventions  
- [Coding Standards](./coding-standards.md) - Code quality standards, best practices, and development guidelines
- [Security Architecture](./security-architecture.md) - Comprehensive security controls, authentication, authorization, and compliance frameworks
- [Data Architecture](./data-architecture.md) - Data sovereignty, audit trails, encryption, and compliance data management
- [Integration Architecture](./integration-architecture.md) - Customer infrastructure integration, identity providers, and monitoring systems
- [Performance Architecture](./performance-architecture.md) - Scalability, optimization, caching strategies, and performance targets
- [API Design](./api-design.md) - REST API standards, versioning, authentication, and integration patterns
- [Deployment Architecture](./deployment-architecture.md) - Container deployment, Kubernetes patterns, high availability, and operational procedures
- [Helm Deployment Architecture](./helm-deployment-architecture.md) - **Phase 1 Model 1 specific** - Helm-native deployment, air-gap capability, and Rancher Desktop development

## Complete Architecture

For the complete, comprehensive architecture document, see [docs/architecture.md](../architecture.md).

## Developer Quick Start

The three files in this directory are loaded automatically by the development agent and contain all the essential information needed to implement stories according to KubeChat's architectural standards:

1. **Start with [tech-stack.md](./tech-stack.md)** to understand the technology choices
2. **Review [source-tree.md](./source-tree.md)** to understand where code should be placed
3. **Follow [coding-standards.md](./coding-standards.md)** for implementation best practices