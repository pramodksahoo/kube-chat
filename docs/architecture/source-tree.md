# Unified Project Structure

## Complete Directory Structure

```
kubechat/
├── .github/                    # CI/CD workflows
│   └── workflows/
│       ├── ci.yaml             # Build and test pipeline
│       ├── helm-package.yaml   # Helm chart packaging and publishing
│       └── container-build.yaml # Container image builds
├── cmd/                        # Go application entry points
│   ├── operator/               # KubeChat operator main
│   ├── api-gateway/            # API gateway service main
│   ├── nlp-service/            # NLP processing service main
│   └── audit-service/          # Audit logging service main
├── pkg/                        # Shared Go packages
│   ├── apis/                   # Kubernetes API definitions (CRDs)
│   ├── controllers/            # Kubernetes controllers
│   ├── clients/                # Kubernetes and external API clients
│   ├── models/                 # Shared data models
│   ├── middleware/             # HTTP middleware (auth, logging, CORS)
│   ├── nlp/                    # Natural language processing logic
│   ├── audit/                  # Audit logging utilities
│   └── utils/                  # Common utilities and helpers
├── web/                        # React frontend application
│   ├── src/
│   │   ├── components/         # UI components with safety indicators
│   │   ├── pages/              # Page components (Chat, Audit, Settings)
│   │   ├── hooks/              # Custom React hooks for WebSocket, auth
│   │   ├── services/           # API client services
│   │   ├── stores/             # Zustand state management
│   │   ├── styles/             # Tailwind CSS configuration
│   │   └── utils/              # Frontend utilities and helpers
│   ├── public/                 # Static assets and favicon
│   ├── tests/                  # Frontend tests (Vitest + Testing Library)
│   ├── Dockerfile              # Frontend container build
│   └── package.json
├── charts/                     # Helm charts
│   └── kubechat/              # Main KubeChat Helm chart
│       ├── Chart.yaml          # Chart metadata and dependencies
│       ├── values.yaml         # Default configuration values
│       ├── values-production.yaml  # Production configuration
│       ├── values-enterprise.yaml  # Enterprise configuration
│       ├── templates/          # Kubernetes manifests
│       │   ├── operator/       # Operator deployment and RBAC
│       │   ├── services/       # Microservice deployments
│       │   ├── web/            # Frontend deployment and service
│       │   ├── storage/        # PostgreSQL and Redis configurations
│       │   ├── monitoring/     # Prometheus and Grafana (optional)
│       │   ├── security/       # Dex, cert-manager, secrets
│       │   └── ingress/        # Ingress controllers and routes
│       ├── crds/               # Custom Resource Definitions
│       └── charts/             # Dependency charts (operators)
├── config/                     # Configuration files
│   ├── samples/                # Sample CRD configurations
│   ├── rbac/                   # RBAC definitions
│   ├── manager/                # Operator manager configuration
│   └── default/                # Default Kustomize configuration
├── hack/                       # Development and build scripts
│   ├── install-deps.sh         # Install development dependencies
│   ├── generate-manifests.sh   # Generate Kubernetes manifests
│   ├── build-images.sh         # Build all container images
│   └── deploy-local.sh         # Local development deployment
├── docs/                       # Documentation
│   ├── prd.md
│   ├── front-end-spec.md
│   ├── architecture.md
│   ├── installation/           # Installation and deployment guides
│   ├── development/            # Development setup and guidelines
│   └── api/                    # API documentation
├── scripts/                    # Operational scripts
│   ├── backup/                 # Database backup scripts
│   ├── monitoring/             # Monitoring setup scripts
│   └── security/               # Security scanning and hardening
├── tests/                      # Integration and E2E tests
│   ├── e2e/                    # End-to-end tests (Playwright)
│   ├── integration/            # Integration tests
│   └── fixtures/               # Test data and configurations
├── .env.example                # Environment template
├── Makefile                    # Build and development tasks
├── Dockerfile.operator         # Operator container build
├── Dockerfile.api-gateway      # API Gateway container build
├── Dockerfile.nlp-service      # NLP Service container build
├── Dockerfile.audit-service    # Audit Service container build
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── package.json                # Root package.json for monorepo
├── pnpm-workspace.yaml         # pnpm monorepo workspace configuration
├── turbo.json                  # Turborepo configuration
└── README.md                   # Project overview and setup instructions
```

## File Organization Principles

### Go Services (Backend)

#### Entry Points (`cmd/`)
- Each microservice has its own main package under `cmd/`
- Main packages should be minimal, primarily handling configuration and service startup
- Example: `cmd/nlp-service/main.go`

#### Shared Packages (`pkg/`)
- **`pkg/apis/`**: Kubernetes Custom Resource Definitions (CRDs)
- **`pkg/controllers/`**: Kubernetes controller implementations
- **`pkg/models/`**: Shared data structures and business entities
- **`pkg/clients/`**: External service clients (Kubernetes API, OpenAI, etc.)
- **`pkg/middleware/`**: HTTP middleware components
- **`pkg/nlp/`**: Natural language processing business logic
- **`pkg/audit/`**: Audit logging utilities and interfaces
- **`pkg/utils/`**: Common utilities and helper functions

### React Frontend (`web/`)

#### Source Organization (`web/src/`)
- **`components/`**: Reusable UI components
  - Organized by feature or by atomic design principles
  - Include safety indicators and enterprise UI elements
- **`pages/`**: Top-level page components (Chat, Audit Dashboard, Settings)
- **`hooks/`**: Custom React hooks for WebSocket, authentication, API calls
- **`services/`**: API client services and external integrations
- **`stores/`**: Zustand state management stores
- **`styles/`**: Tailwind CSS configuration and custom styles
- **`utils/`**: Frontend utilities and helper functions

### Configuration (`config/`)
- **`samples/`**: Example configurations for CRDs and deployments
- **`rbac/`**: Kubernetes RBAC definitions
- **`manager/`**: Operator manager configuration
- **`default/`**: Default Kustomize overlays

### Testing Organization
- **`tests/integration/`**: Cross-service integration tests
- **`tests/e2e/`**: End-to-end user workflow tests with Playwright  
- **`web/tests/`**: Frontend-specific tests with Vitest
- **Co-located unit tests**: `*_test.go` files alongside Go source

### Documentation Structure
- **`docs/architecture/`**: Detailed technical architecture (this folder)
- **`docs/api/`**: OpenAPI specifications and API documentation
- **`docs/installation/`**: Deployment and setup guides
- **`docs/development/`**: Developer onboarding and contribution guides

## Naming Conventions

### Go Files and Packages
- **Package names**: lowercase, single word when possible
- **File names**: lowercase with underscores (`user_service.go`)
- **Test files**: `*_test.go` suffix
- **Interface names**: noun or noun phrase (`UserService`, `CommandTranslator`)

### TypeScript/React Files
- **Component files**: PascalCase (`ChatInterface.tsx`)
- **Hook files**: camelCase with `use` prefix (`useWebSocket.ts`)
- **Utility files**: camelCase (`apiClient.ts`)
- **Constants**: SCREAMING_SNAKE_CASE in separate files

### Kubernetes Resources
- **CRD names**: lowercase with hyphens (`chat-session.yaml`)
- **ConfigMaps/Secrets**: descriptive, project-prefixed (`kubechat-config`)
- **Service names**: lowercase with hyphens (`nlp-service`)

### Container Images
- **Naming pattern**: `kubechat-<service>:<version>`
- **Examples**: `kubechat-operator:v1.0.0`, `kubechat-web:v1.0.0`

## Directory Creation Guidelines

### When Creating New Directories
1. **Follow existing patterns**: Look at similar components for structure
2. **Logical grouping**: Group related functionality together
3. **Flat when possible**: Avoid deep nesting unless necessary for organization
4. **Consistent naming**: Use the established naming conventions

### Service-Specific Additions
- Each new microservice should follow the `cmd/<service>/` pattern
- Add corresponding Dockerfile: `Dockerfile.<service>`
- Create service-specific directories under `pkg/` if needed
- Update `charts/kubechat/templates/` with deployment manifests

This structure supports the monorepo approach with clear separation of concerns while enabling shared code reuse across microservices.