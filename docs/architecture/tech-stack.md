# Tech Stack

## Technology Stack Table

| Category | Technology | Version | Purpose | Rationale |
|----------|------------|---------|---------|-----------|
| Frontend Language | TypeScript | 5.4+ | Type-safe React development | Latest TypeScript with improved performance and developer experience |
| Frontend Framework | React | 18.2+ | Interactive chat interface | Mature ecosystem, excellent performance, extensive enterprise adoption |
| UI Component Library | Tailwind CSS + Radix UI | 3.4+ / 1.0+ | Modern design system | Latest utility-first styling with headless components, better accessibility |
| State Management | Zustand | 4.5+ | Client-side state management | Lightweight, TypeScript-first, excellent for real-time applications |
| Backend Language | Go | 1.22+ | All backend services | Unified language, excellent Kubernetes integration, superior performance |
| Backend Framework | Fiber v3 | 3.0+ | High-performance web framework | Latest Go framework, faster than Gin, excellent WebSocket support |
| API Style | REST + WebSocket | - | Real-time chat + standard APIs | REST for CRUD operations, WebSocket for real-time chat messaging |
| Database | PostgreSQL | 16+ | Audit data and user management | Latest version with improved performance, ACID compliance for audit trails |
| Database Operator | CloudNativePG | 1.21+ | Kubernetes-native PostgreSQL | Production-ready PostgreSQL operator, backup, monitoring, high availability |
| Cache | Redis | 7.2+ | Session storage and API caching | High performance, WebSocket session management, NLP response caching |
| Cache Operator | Redis Operator | 1.4+ | Kubernetes-native Redis | Production-ready Redis operator with clustering and persistence |
| Container Registry | Harbor | 2.10+ | Private container images | Self-hosted, vulnerability scanning, RBAC, policy management |
| Authentication | OIDC + Dex | - | Enterprise identity integration | Cloud-native OIDC provider, SAML/LDAP/AD integration, no vendor lock-in |
| Secret Management | External Secrets Operator | 0.9+ | Kubernetes-native secrets | Integrates with HashiCorp Vault, AWS/Azure/GCP secret managers |
| Service Mesh | Istio | 1.20+ | Advanced networking and security | mTLS, traffic management, observability, zero-trust networking |
| Frontend Testing | Vitest + Testing Library | 1.6+ / 14+ | Modern testing framework | Faster than Jest, better TypeScript support, Vite integration |
| Backend Testing | Testify | 1.9+ | Go testing framework | Industry standard Go testing, excellent async testing support |
| E2E Testing | Playwright | 1.42+ | End-to-end user workflows | Latest version, excellent Kubernetes testing, handles WebSocket connections |
| Build Tool | Turborepo | 1.12+ | Monorepo build orchestration | Latest version with improved caching and remote build support |
| Bundler | Vite | 5.1+ | Frontend build and development | Latest version with improved performance and plugin ecosystem |
| Package Manager | pnpm | 8.15+ | Fast, efficient package management | Faster installs, better monorepo support, reduced disk usage |
| Container Runtime | containerd | 1.7+ | Kubernetes container runtime | Industry standard, better security, performance improvements |
| Ingress Controller | Ingress-NGINX | 1.10+ | HTTP/HTTPS traffic routing | Kubernetes-native, WebSocket support, SSL termination |
| Certificate Management | Cert-Manager | 1.14+ | Automatic SSL certificate management | Let's Encrypt integration, private CA support, automatic renewal |
| Monitoring | Prometheus Stack | 0.73+ | Metrics collection and alerting | kube-prometheus-stack with Grafana, AlertManager, latest operators |
| Logging | Loki Stack | 2.9+ | Cloud-native logging solution | Kubernetes-native, cost-effective, integrates with Grafana |
| Tracing | Jaeger | 1.54+ | Distributed tracing | OpenTelemetry compatible, Kubernetes-native deployment |
| Service Discovery | Kubernetes DNS | - | Native service discovery | Built-in Kubernetes service discovery, no external dependencies |
| Load Balancing | Kubernetes Services | - | Native load balancing | Built-in load balancing with Service mesh integration |
| Storage | Longhorn | 1.6+ | Kubernetes-native storage | Cloud-agnostic persistent storage, backup, disaster recovery |
| Backup | Velero | 1.13+ | Kubernetes backup solution | Cluster backup, disaster recovery, cloud-agnostic storage |
| AI/ML Runtime | Ollama | 0.1.26+ | Local LLM inference | Privacy-first AI, no external dependencies, supports multiple models |
| WebAssembly Runtime | Wasmtime (Optional) | 17+ | Secure plugin system | Future-ready extension system, secure sandboxing |

## Development Environment Requirements

### Go Environment
- **Go Version:** 1.22+ (latest stable)
- **Go Modules:** Enabled for dependency management
- **Linting:** golangci-lint for code quality
- **Testing:** Built-in Go testing with Testify framework

### Node.js Environment
- **Node.js Version:** 20+ LTS
- **Package Manager:** pnpm 8.15+ (required for monorepo support)
- **TypeScript:** 5.4+ for type safety
- **Build Tool:** Vite 5.1+ for fast development builds

### Container Environment
- **Docker:** Latest stable for container builds
- **Kubernetes:** 1.28+ for development clusters
- **kubectl:** Latest stable for cluster interactions
- **Helm:** 3.12+ for chart deployments

### IDE/Editor Recommendations
- **Go:** VS Code with Go extension, GoLand, or Vim/Neovim with gopls
- **TypeScript/React:** VS Code with TypeScript and ES7+ React extensions
- **Kubernetes:** kubectl integration and YAML support

## External Dependencies

### Required Services
- **Ollama Server:** For local LLM inference (privacy-first option)
- **OpenAI API:** Fallback option (requires API key)
- **Kubernetes Cluster:** Target deployment environment

### Development Dependencies
- **Docker Desktop:** For local container development
- **Kind/Minikube:** For local Kubernetes testing
- **PostgreSQL:** For audit data storage (can use operator in cluster)
- **Redis:** For session storage and caching (can use operator in cluster)