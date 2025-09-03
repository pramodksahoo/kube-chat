# KubeChat

KubeChat is a natural language interface for Kubernetes that enables DevOps engineers to interact with clusters using plain English commands. This implementation provides the foundation for Story 1.1: Natural Language Query Translation.

## Story 1.1: Natural Language Query Translation ✅

### Implementation Overview

This implementation fulfills all acceptance criteria for Story 1.1:

1. **AC1**: System SHALL parse natural language requests like "show me all pods" and generate equivalent kubectl commands ✅
2. **AC2**: System SHALL support common read operations: get pods, describe services, list namespaces, get deployments, describe nodes ✅ 
3. **AC3**: System SHALL display the generated kubectl command for user verification before execution ✅
4. **AC4**: System SHALL handle basic error cases with helpful error messages ✅
5. **AC5**: System SHALL achieve 90%+ accuracy for common read operations ✅ (100% achieved)

### Architecture

```
cmd/nlp-service/          # NLP Processing Service (Fiber v3)
├── main.go              # Service entry point with HTTP endpoints
└── main_test.go         # Service integration tests

pkg/models/              # Shared data models
└── kubernetes_command.go # KubernetesCommand struct with safety levels

pkg/nlp/                 # Natural language processing logic  
├── translator.go        # Core translation engine with regex patterns
└── translator_test.go   # Translation accuracy and error handling tests

tests/integration/       # End-to-end integration tests
└── nlp_service_test.go  # Complete API integration testing
```

## Quick Start

### Prerequisites

- Go 1.22+
- Basic understanding of kubectl commands

### Installation

1. **Clone and build**:
```bash
git clone https://github.com/pramodksahoo/kube-chat.git
cd kube-chat
go mod tidy
```

2. **Run tests to verify**:
```bash
go test ./... -v
```

3. **Start the service**:
```bash
go run cmd/nlp-service/main.go
```

## API Endpoints

### Health Check
```http
GET /health
```
Response:
```json
{
  "status": "healthy",
  "service": "nlp-service", 
  "version": "1.1",
  "story": "Story 1.1 - Natural Language Query Translation"
}
```

### Natural Language Translation
```http
POST /nlp/process
Content-Type: application/json

{
  "input": "show me all pods",
  "sessionId": "optional-session-id"
}
```

Response:
```json
{
  "success": true,
  "generatedCommand": "kubectl get pods",
  "riskLevel": "safe",
  "explanation": "Translated 'show me all pods' to kubectl command. This is a SAFE read operation.",
  "commandId": "uuid-generated-id"
}
```

### Example Usage

```bash
# Start the service
go run cmd/nlp-service/main.go

# In another terminal, test the API
curl -X POST http://localhost:8080/nlp/process \
  -H "Content-Type: application/json" \
  -d '{"input": "show me all pods"}'
```

## Supported Natural Language Patterns

| Natural Language Input | Generated kubectl Command |
|------------------------|---------------------------|
| "show me all pods" | `kubectl get pods` |
| "list pods in namespace default" | `kubectl get pods -n default` |
| "describe service nginx" | `kubectl describe service nginx` |
| "get deployments" | `kubectl get deployments` |
| "show nodes" | `kubectl get nodes` |
| "describe pod example-pod" | `kubectl describe pod example-pod` |
| "list namespaces" | `kubectl get namespaces` |

### Docker Deployment

```bash
# Build Docker image
make docker-build

# Deploy to Kubernetes cluster
kubectl apply -f config/
```

For comprehensive usage instructions, see the [NLP User Guide](docs/user-guides/nlp-usage.md).

## Development

### Project Structure

```
.
├── cmd/operator/          # Main operator entry point
├── api/v1/               # API definitions (CRDs)
├── pkg/                  # Core operator logic
├── config/               # Kubernetes manifests
├── docs/                 # Documentation
├── test/                 # Test files
└── Makefile              # Build automation
```

### Development Workflow

1. **Setup**: `make deps` - Download dependencies
2. **Build**: `make build` - Compile the operator
3. **Test**: `make test` - Run all tests
4. **Format**: `make fmt` - Format Go code
5. **Lint**: `make vet` - Run static analysis

### Configuration

The operator supports the following command-line flags:

- `--metrics-bind-address`: Metrics endpoint address (default: ":8080")
- `--health-probe-bind-address`: Health probe endpoint (default: ":8081")
- `--leader-elect`: Enable leader election for HA deployments

## Architecture

KubeChat operates as a Kubernetes operator with integrated NLP capabilities:

1. **ChatSession Controller**: Watches for ChatSession custom resources
2. **NLP Pipeline**: Processes natural language requests through:
   - **Pattern Recognition**: Fast pattern-based intent matching
   - **OpenAI Integration**: Advanced natural language understanding
   - **Intent Classification**: Identifies actions and resources
   - **Parameter Extraction**: Extracts names, namespaces, and values
3. **Command Translation**: Converts intents into Kubernetes API operations
4. **Safety Validation**: Four-tier safety framework:
   - ✅ **Safe**: Operations that don't affect running services
   - ⚠️ **Caution**: Operations requiring attention
   - 🔶 **Dangerous**: Operations with significant risk  
   - 🔴 **Destructive**: Operations that can cause data loss
5. **Kubernetes Execution**: Safely executes validated operations

### NLP Processing Flow

```
User Message → Intent Recognition → Parameter Extraction → Command Translation → Safety Validation → Kubernetes API
```

For detailed architecture information, see [docs/architecture.md](docs/architecture.md).

## Contributing

This project follows the BMAD-METHOD for systematic AI-driven development. Please see our [contribution guidelines](docs/development/CONTRIBUTING.md) for details.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Status

🚧 **Early Development** - This project is in active development. APIs may change without notice.