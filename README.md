# KubeChat
### Natural Language Kubernetes Management for Enterprise DevOps

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://golang.org/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.24+-326CE5.svg)](https://kubernetes.io/)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green.svg)](#security-features)

> **Transform your Kubernetes operations with natural language commands while maintaining enterprise-grade security, complete data sovereignty, and comprehensive audit trails.**

KubeChat is an open-source Kubernetes operator that enables DevOps engineers to manage clusters through conversational interactions. Built specifically for security-conscious enterprises, KubeChat provides the operational efficiency of natural language processing while ensuring zero vendor lock-in, complete data sovereignty, and comprehensive compliance capabilities.

## 🎯 Why KubeChat?

### The Problem
DevOps engineers spend **30-40% of their time** troubleshooting kubectl syntax instead of solving real problems. Traditional Kubernetes management tools force a choice between operational efficiency and enterprise security requirements like:
- Complete data sovereignty and air-gap deployment capability
- Comprehensive audit trails for regulatory compliance (SOC 2, HIPAA, FedRAMP)
- Zero vendor lock-in with full customer control
- Enterprise-grade authentication and RBAC integration

### The Solution
KubeChat eliminates this false choice by providing:
- **🗣️ Natural Language Interface**: "show me all failing pods in production" → `kubectl get pods --field-selector=status.phase!=Running -n production`
- **🔒 Enterprise Security**: Complete OIDC/SAML integration with existing identity providers
- **📊 Comprehensive Auditing**: Tamper-proof audit trails with cryptographic integrity verification
- **🏢 Data Sovereignty**: Deploy entirely in your infrastructure with zero external dependencies
- **🚀 Open Source Freedom**: Apache 2.0 license with no vendor lock-in

## ✨ Key Features

### 🗣️ **Natural Language Processing**
- **Conversational Commands**: Interact with your clusters using plain English
- **Intelligent Context**: Maintains conversation context for follow-up questions
- **Safety-First**: All destructive operations require explicit confirmation
- **Command Preview**: See the generated kubectl commands before execution

### 🔐 **Enterprise Security & Compliance**
- **Zero Trust Architecture**: Complete RBAC integration respecting existing permissions
- **Identity Provider Integration**: Seamless OIDC/SAML with major providers (Azure AD, Okta, Auth0, Google Workspace)
- **Multi-Factor Authentication**: Full MFA support when required by your identity provider
- **Session Management**: Comprehensive session lifecycle with audit logging

### 📊 **Comprehensive Audit & Compliance**
- **100% Activity Logging**: Every user interaction, command, and system response captured
- **Tamper-Proof Storage**: Cryptographic integrity verification for all audit data
- **Regulatory Compliance**: Built-in support for SOC 2, HIPAA, FedRAMP evidence generation
- **SIEM Integration**: Real-time integration with enterprise security platforms

### 🏢 **Enterprise Deployment**
- **Complete Data Sovereignty**: All processing happens in your infrastructure
- **Air-Gap Capability**: Full offline installation with zero external dependencies
- **Helm-Native Deployment**: One-command installation in any Kubernetes cluster
- **High Availability**: Multi-zone deployment with automatic failover

### 🛡️ **Advanced Safety Controls**
- **Four-Tier Risk Assessment**: Clear safety indicators for all operations
  - ✅ **Safe**: Read operations with no cluster impact
  - ⚠️ **Caution**: Operations requiring attention
  - 🔶 **Dangerous**: High-risk operations with explicit warnings
  - 🔴 **Destructive**: Operations requiring multi-step confirmation
- **Configurable Policies**: Customizable command allowlists and approval workflows
- **Emergency Controls**: Administrative override capabilities for critical situations

## 🚀 Quick Start

### Prerequisites
<<<<<<< HEAD
- Kubernetes cluster (1.24+)
- Helm 3.x
- kubectl access to your cluster
=======

- Go 1.22+
- Node.js 18+ and pnpm (for web frontend)
- Basic understanding of kubectl commands
>>>>>>> refs/remotes/origin/develop

### Installation

1. **Add the KubeChat Helm repository**:
```bash
helm repo add kubechat https://charts.kubechat.dev
helm repo update
```

<<<<<<< HEAD
2. **Install KubeChat**:
```bash
# Basic installation
helm install kubechat kubechat/kubechat

# Or with custom values
helm install kubechat kubechat/kubechat -f values.yaml
```

3. **Access the web interface**:
=======
2. **Set up the web frontend**:
```bash
cd web
pnpm install
# Start development server (ALWAYS runs on port 3001)
pnpm dev
```

3. **Run tests to verify**:
```bash
go test ./... -v
cd web && pnpm test
```

4. **Start the NLP service**:
>>>>>>> refs/remotes/origin/develop
```bash
kubectl port-forward svc/kubechat-web 8080:80
# Navigate to http://localhost:8080
```

<<<<<<< HEAD
### First Commands
Try these natural language commands:
- `"show me all pods"`
- `"list failing deployments"`  
- `"describe the nginx service"`
- `"show resource usage for production namespace"`

## 🏗️ Architecture

KubeChat operates as a cloud-native microservices architecture:
=======
### 🚨 Web Application Port Configuration

**The web application ALWAYS runs on port 3001**

- **Frontend URL**: `http://localhost:3001`
- **Do NOT use port 3000** - Configured with `strictPort: true`
- **Team members**: Bookmark `http://localhost:3001`

## API Endpoints
>>>>>>> refs/remotes/origin/develop

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Web Interface │    │  Kubernetes     │    │   NLP Service   │
│    (React)      │◄──►│    Operator     │◄──►│   (Go + AI)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│ Authentication  │    │  Audit Service  │    │ Policy Engine   │
│   (OIDC/SAML)   │    │   (PostgreSQL)  │    │ (Safety Rules)  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Core Components
- **Kubernetes Operator**: Watches ChatSession CRDs and orchestrates operations
- **NLP Service**: Processes natural language using pattern matching and AI integration
- **Web Interface**: Professional chat-based UI with real-time WebSocket communication  
- **Audit Service**: Comprehensive logging with tamper-proof storage
- **Authentication Service**: Enterprise identity provider integration
- **Policy Engine**: Configurable safety controls and approval workflows

## 🔧 Configuration

### Environment Variables

#### Core Settings
```bash
# Application Configuration
KUBECHAT_PUBLIC_URL=https://kubechat.yourdomain.com
KUBECHAT_SESSION_SECRET=your-secure-32-character-key

# Database Configuration  
KUBECHAT_DB_HOST=postgresql.prod.svc.cluster.local
KUBECHAT_DB_PORT=5432
KUBECHAT_DB_NAME=kubechat
KUBECHAT_DB_USER=kubechat
KUBECHAT_DB_PASSWORD=your-secure-password

# Redis Configuration
KUBECHAT_REDIS_ADDR=redis.prod.svc.cluster.local:6379
KUBECHAT_REDIS_PASSWORD=your-redis-password
```

#### Authentication Configuration
```bash
# OIDC Configuration
KUBECHAT_OIDC_ISSUER_URL=https://auth.company.com
KUBECHAT_OIDC_CLIENT_ID=kubechat-production
KUBECHAT_OIDC_CLIENT_SECRET=your-oidc-secret

# SAML Configuration (if using SAML instead of OIDC)
KUBECHAT_SAML_METADATA_URL=https://auth.company.com/metadata
KUBECHAT_SAML_CERT_FILE=/etc/certs/saml.crt
KUBECHAT_SAML_KEY_FILE=/etc/certs/saml.key
```

#### Security & Compliance
```bash
# Audit Configuration
KUBECHAT_AUDIT_RETENTION_DAYS=2555  # 7 years for compliance
KUBECHAT_AUDIT_ENCRYPTION_KEY=your-32-byte-encryption-key

# Security Settings
KUBECHAT_ENABLE_MFA=true
KUBECHAT_SESSION_TIMEOUT=3600  # 1 hour
KUBECHAT_MAX_FAILED_LOGINS=5
```

## 🔒 Security Features

### Enterprise Authentication
- **OIDC Support**: Azure AD, Google Workspace, Okta, Auth0, generic OIDC providers
- **SAML 2.0 Support**: ADFS, Okta SAML, Shibboleth, generic SAML providers
- **Multi-Factor Authentication**: Full MFA integration when required by your identity provider
- **JWT Security**: Token rotation, rate limiting, brute force protection

### Data Protection
- **Encryption in Transit**: TLS 1.3 for all communications
- **Encryption at Rest**: AES-256 encryption for all audit data
- **Mutual TLS**: Secure service-to-service communication
- **Zero Trust Architecture**: Every request authenticated and authorized

### Compliance & Auditing
- **Complete Audit Trails**: 100% of user interactions logged with cryptographic integrity
- **Regulatory Support**: Built-in compliance for SOC 2, HIPAA, FedRAMP
- **Tamper Prevention**: Blockchain-style verification for audit data integrity
- **Evidence Export**: Automated compliance report generation for auditors

## 🌟 Supported Deployment Environments

### Kubernetes Platforms
- ✅ **Amazon EKS** - Full support with AWS integrations
- ✅ **Google GKE** - Native GCP service integration  
- ✅ **Azure AKS** - Azure AD and Key Vault integration
- ✅ **Red Hat OpenShift** - Enterprise Kubernetes platform
- ✅ **VMware Tanzu** - Enterprise container platform
- ✅ **On-Premises Kubernetes** - Vanilla Kubernetes on bare metal/VMs

### Security Environments
- ✅ **Air-Gap Deployments** - Complete offline installation capability
- ✅ **Government Cloud** - FedRAMP compliant deployment options
- ✅ **Healthcare Environments** - HIPAA technical safeguards  
- ✅ **Financial Services** - SOC 2 Type I/II compliance support

## 📖 Documentation

### User Guides
- **[Quick Start Guide](docs/user-guides/quick-start.md)** - Get up and running in 5 minutes
- **[Natural Language Commands](docs/user-guides/command-reference.md)** - Complete command reference
- **[Web Interface Guide](docs/user-guides/web-interface.md)** - Using the chat interface effectively

### Administrator Guides  
- **[Installation Guide](docs/deployment/installation.md)** - Production deployment instructions
- **[Configuration Reference](docs/deployment/configuration-reference.md)** - All settings and environment variables
- **[Security Configuration](docs/deployment/security-configuration.md)** - Enterprise security setup
- **[Monitoring & Observability](docs/deployment/monitoring.md)** - Production monitoring setup

### Developer Resources
- **[Architecture Overview](docs/architecture/overview.md)** - System architecture and design
- **[API Reference](docs/api/reference.md)** - REST API documentation  
- **[Contributing Guide](docs/development/contributing.md)** - How to contribute to the project
- **[Development Setup](docs/development/setup.md)** - Local development environment

## 🤝 Community & Support

### Open Source Community
- **GitHub Issues**: [Report bugs and request features](https://github.com/pramodksahoo/kube-chat/issues)
- **GitHub Discussions**: [Community discussions and questions](https://github.com/pramodksahoo/kube-chat/discussions)
- **Security Issues**: [Private security vulnerability reporting](mailto:security@kubechat.dev)

### Contributing
We welcome contributions from the community! KubeChat is built by DevOps engineers, for DevOps engineers. 

- 🐛 **Bug Reports**: Help us improve by reporting issues
- 💡 **Feature Requests**: Share ideas for new capabilities
- 📝 **Documentation**: Improve guides and tutorials
- 💻 **Code Contributions**: Submit pull requests for fixes and features
- 🧪 **Testing**: Help test new releases and report compatibility

See our [Contributing Guide](docs/development/contributing.md) for detailed information.

### Code of Conduct
This project adheres to the Contributor Covenant [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## 📊 Project Status

### Current Release: v1.0.0-beta
- ✅ **Core NLP Translation**: Natural language to kubectl command conversion
- ✅ **Enterprise Authentication**: Complete OIDC/SAML integration
- ✅ **Comprehensive Auditing**: Tamper-proof audit trails with compliance reporting
- ✅ **Web Interface**: Professional chat-based UI with real-time communication
- 🚧 **Advanced Safety Controls**: Enhanced policy engine and approval workflows
- 🚧 **Compliance Dashboard**: Automated regulatory compliance reporting
- 🚧 **Enterprise Integration**: Advanced secrets management and monitoring integration

### Roadmap
- **v1.1**: Enhanced safety controls and policy management
- **v1.2**: Advanced compliance dashboard and reporting
- **v1.3**: Enterprise integration (Vault, monitoring platforms)
- **v1.4**: Performance optimization and scalability improvements

## 📄 License

KubeChat is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

This means you can:
- ✅ Use KubeChat for commercial purposes
- ✅ Modify and distribute KubeChat
- ✅ Use KubeChat in private projects
- ✅ Include KubeChat in larger works

## 🙏 Acknowledgments

KubeChat is built on the shoulders of giants. We thank the maintainers and contributors of:
- **Kubernetes** and the **controller-runtime** project
- **OpenAI** for natural language processing capabilities
- **Helm** for the Kubernetes package management
- **PostgreSQL** and **Redis** for data persistence
- All the open-source libraries that make this project possible

---

**Ready to transform your Kubernetes operations?** [Get started with KubeChat today](docs/user-guides/quick-start.md) and join thousands of DevOps engineers using natural language to manage their clusters securely and efficiently.