# KubeChat Source Tree - Phase 1 Model 1 (On-Premises)

## Current Project Structure (BMAD Method)

```
kube-chat/
├── .bmad/                      # BMAD framework - project management
│   ├── agents/                 # AI agents for development tasks
│   ├── cache/                  # BMAD caching and state
│   ├── planning/               # Epic and story planning
│   ├── stories/                # Active story tracking
│   └── templates/              # Story and task templates
├── .bmad-core/                 # Core BMAD framework (don't modify)
│   ├── agents/                 # Core agent definitions
│   ├── checklists/             # Quality and validation checklists
│   ├── tasks/                  # Task management system
│   └── workflows/              # BMAD development workflows
├── .github/                    # CI/CD workflows
│   └── workflows/
│       └── ci.yml              # Build and test pipeline
├── cmd/                        # Go application entry points (Phase 1)
│   ├── api-gateway/            # API gateway service main
│   ├── nlp-service/            # NLP processing service main
│   └── audit-service/          # Audit logging service main
├── pkg/                        # Shared Go packages
│   ├── audit/                  # Audit logging utilities and interfaces
│   ├── clients/                # Kubernetes and external API clients
│   ├── config/                 # Configuration management
│   ├── middleware/             # HTTP middleware (auth, logging, CORS)
│   ├── models/                 # Shared data models and CRDs
│   └── nlp/                    # Natural language processing logic
├── config/                     # Kubernetes configuration
│   ├── crd/                    # Custom Resource Definitions
│   │   └── bases/              # Base CRD definitions
│   └── rbac/                   # RBAC definitions
├── deploy/                     # Deployment configurations
│   ├── helm/                   # Helm charts (Phase 1 Model 1 primary)
│   └── manifests/              # Raw Kubernetes manifests
├── docs/                       # Documentation (comprehensive)
│   ├── architecture/           # Technical architecture docs
│   ├── deployment/             # Deployment guides (on-premises focus)
│   ├── development/            # Development setup (Rancher Desktop)
│   ├── api/                    # API documentation
│   ├── examples/               # Usage examples
│   ├── operations/             # Operational procedures
│   ├── qa/                     # QA gates and testing
│   ├── stories/                # User stories (BMAD)
│   ├── user-guides/            # End-user documentation
│   └── prd.md                  # Product Requirements Document
├── tests/                      # Testing (Phase 1 focus)
│   └── integration/            # Integration tests for services
├── examples/                   # Sample configurations and demos
├── hack/                       # Development and build scripts
├── api/                        # OpenAPI specs and protobuf definitions  
├── bin/                        # Compiled binaries
├── web/                        # 🌐 WEB INTERFACE - React frontend for Phase 1 Model 1
│   ├── src/                    # React application source code
│   │   ├── components/         # Reusable React components
│   │   ├── pages/              # Page components and routing
│   │   ├── hooks/              # Custom React hooks
│   │   ├── utils/              # Frontend utilities
│   │   └── styles/             # CSS and styling
│   ├── public/                 # Static assets
│   ├── package.json            # Frontend dependencies
│   └── vite.config.ts          # Build configuration
├── go.mod                      # Go module definition
├── go.sum                      # Go module checksums
├── package.json                # Root package.json for tooling
├── pnpm-workspace.yaml         # Workspace configuration
├── turbo.json                  # Turborepo build configuration
└── README.md                   # Project overview
```

## Phase 1 Model 1 Organization Principles

### BMAD Framework Integration
- **`.bmad/`**: BMAD project management framework
  - **`stories/`**: Current story tracking and progress
  - **`planning/`**: Epic and milestone planning
  - **`agents/`**: AI development agents and automation
- **Follow BMAD method**: Always check `.bmad/stories/current-story.md` first

### Go Services (Backend Only - Phase 1)

#### Entry Points (`cmd/`)
- **Phase 1 Model 1 services only**:
  - `api-gateway/`: HTTP API and routing service
  - `nlp-service/`: Natural language processing service  
  - `audit-service/`: Audit logging and compliance service
- **NO Kubernetes operator yet**: Will be added in later stories
- Main packages handle configuration, service startup, and graceful shutdown

#### Shared Packages (`pkg/`)
- **`pkg/audit/`**: Comprehensive audit logging with tamper-proof storage
- **`pkg/clients/`**: Kubernetes API client and external service integrations
- **`pkg/config/`**: Configuration management and validation
- **`pkg/middleware/`**: HTTP middleware (authentication, CORS, rate limiting)
- **`pkg/models/`**: Shared data structures, CRDs, and business entities
- **`pkg/nlp/`**: Natural language processing business logic

### Phase 1 Model 1 Configuration (`config/`)
- **`crd/bases/`**: Custom Resource Definitions for Kubernetes integration
- **`rbac/`**: Kubernetes RBAC definitions for on-premises deployment
- **Focus**: Customer-controlled infrastructure and data sovereignty

### Deployment Structure (`deploy/`)
- **`helm/`**: **PRIMARY** - Helm charts for on-premises deployment
  - Single-command customer installation: `helm install kubechat ./helm/kubechat`
  - Air-gap deployment support with offline bundles
- **`manifests/`**: Raw Kubernetes YAML (for customers who prefer kubectl)

### Testing Organization (Phase 1 Focus)
- **`tests/integration/`**: Service integration tests
- **Co-located unit tests**: `*_test.go` files alongside Go source
- **E2E tests**: End-to-end tests including web interface (Epic 4)
- **Focus**: API testing, Kubernetes integration, audit trail validation, web UI testing

### Documentation Structure (Enterprise Grade)
- **`docs/architecture/`**: Technical architecture aligned with Phase 1 Model 1
- **`docs/deployment/`**: On-premises deployment guides with air-gap support
- **`docs/development/`**: Rancher Desktop development environment
- **`docs/api/`**: OpenAPI specifications for REST APIs
- **`docs/operations/`**: Production operations and maintenance
- **`docs/qa/`**: Quality gates and testing procedures (BMAD compliance)

## Phase 1 Model 1 Naming Conventions

### Go Files and Packages (Primary Language)
- **Package names**: lowercase, single word when possible (`audit`, `nlp`, `models`)
- **File names**: lowercase with underscores (`audit_service.go`, `command_translator.go`)
- **Test files**: `*_test.go` suffix (co-located with source)
- **Interface names**: noun or noun phrase (`AuditService`, `CommandTranslator`)
- **Struct names**: PascalCase (`ChatSession`, `AuditEvent`)

### Kubernetes Resources (On-Premises Focus)
- **CRD names**: lowercase with hyphens (`chat-session.yaml`, `audit-event.yaml`)
- **ConfigMaps/Secrets**: descriptive, project-prefixed (`kubechat-config`, `kubechat-secrets`)
- **Service names**: lowercase with hyphens matching cmd structure:
  - `kubechat-api-gateway`
  - `kubechat-nlp-service`
  - `kubechat-audit-service`

### Container Images (Customer Registry)
- **Naming pattern**: `<customer-registry>/kubechat/<service>:<version>`
- **Phase 1 Model 1 examples**:
  - `registry.company.com/kubechat/api-gateway:v1.0.0`
  - `localhost:5000/kubechat/nlp-service:dev` (development)
- **Air-gap ready**: All images bundled for offline installation

### BMAD Framework Conventions
- **Story files**: `<epic>.<story>.story.md` (e.g., `3.1.comprehensive-user-activity-logging.story.md`)
- **Agent files**: `<role>-<specialty>-agent.md`
- **Always check**: `.bmad/stories/current-story.md` before development

## Phase 1 Model 1 Development Guidelines

### Creating New Components
1. **Follow BMAD method**: Update `.bmad/stories/current-story.md` progress
2. **Full-stack Phase 1**: Backend services AND React web interface (Epic 4)
3. **On-premises first**: Design for customer-controlled infrastructure
4. **Air-gap ready**: No external dependencies at runtime

### Service-Specific Additions
- Each new service follows `cmd/<service>/` pattern
- Add Helm chart templates in `deploy/helm/kubechat/templates/`
- Create shared utilities in appropriate `pkg/` subdirectories
- Add integration tests in `tests/integration/`

### Kubernetes Operator Pattern (Future)
- **Deferred to later stories**: Not in initial Phase 1 Model 1
- When added: will use `pkg/controllers/` for custom controllers
- CRD definitions in `config/crd/bases/`

## Phase 1 Model 1 Architecture Principles

### Data Sovereignty
- **Customer infrastructure**: All code runs in customer Kubernetes clusters
- **No vendor services**: Zero dependencies on external vendor APIs
- **Configuration management**: Environment variables and ConfigMaps only

### Air-Gap Capability
- **Offline bundles**: Complete installation packages with all dependencies
- **Local registries**: Container images stored in customer registries
- **No internet required**: Post-installation operation without external connectivity

### Helm-Native Deployment
- **Primary deployment method**: Helm charts for customer installation
- **Single command**: `helm install kubechat ./deploy/helm/kubechat`
- **Customer customization**: Comprehensive `values.yaml` configuration

This structure supports **Phase 1: Model 1 (On-Premises FREE Platform)** with complete focus on customer data sovereignty and air-gap deployment capability.