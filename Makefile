# KubeChat Operator Makefile

# Image URL to use all building/pushing image targets
IMG ?= kubechat-operator:latest

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: fmt vet ## Run tests.
	go test ./... -coverprofile cover.out

.PHONY: lint
lint: ## Run golangci-lint linter
	golangci-lint run

##@ Build

.PHONY: build
build: fmt vet ## Build operator binary.
	go build -o bin/operator cmd/operator/main.go

.PHONY: build-webapi
build-webapi: fmt vet ## Build WebAPI server binary.
	go build -o bin/webapi cmd/webapi/main.go

.PHONY: build-web
build-web: ## Build React web application.
	cd web && npm run build

.PHONY: build-all
build-all: build build-webapi build-web ## Build all components.

.PHONY: run
run: fmt vet ## Run the operator from your host.
	go run cmd/operator/main.go

.PHONY: run-webapi
run-webapi: fmt vet ## Run the WebAPI server from your host.
	go run cmd/webapi/main.go

.PHONY: run-web
run-web: ## Run the React development server.
	cd web && npm run dev

.PHONY: docker-build
docker-build: ## Build docker image with the operator.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the operator.
	docker push ${IMG}

##@ Deployment

.PHONY: install
install: ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	kubectl apply -f config/crd/bases

.PHONY: uninstall
uninstall: ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config.
	kubectl delete -f config/crd/bases

.PHONY: generate
generate: ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(shell go env GOPATH)/bin/controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./api/..."

.PHONY: manifests
manifests: ## Generate CRD and RBAC manifests.
	$(shell go env GOPATH)/bin/controller-gen crd:headerFile="hack/boilerplate.go.txt" paths="./api/..." output:crd:artifacts:config=config/crd/bases
	$(shell go env GOPATH)/bin/controller-gen rbac:roleName=manager-role paths="./pkg/controllers/..." output:rbac:artifacts:config=config/rbac

.PHONY: deploy
deploy: ## Deploy operator to the K8s cluster specified in ~/.kube/config.
	kubectl apply -f config/rbac
	kubectl apply -f config/manager

.PHONY: undeploy
undeploy: ## Undeploy operator from the K8s cluster specified in ~/.kube/config.
	kubectl delete -f config/manager
	kubectl delete -f config/rbac

##@ Dependencies

.PHONY: deps
deps: ## Download dependencies
	go mod download
	go mod tidy

.PHONY: deps-web
deps-web: ## Install web dependencies
	cd web && npm install

.PHONY: deps-all
deps-all: deps deps-web ## Install all dependencies

##@ Development

.PHONY: dev
dev: ## Run full development environment (operator + webapi + web)
	@echo "Starting KubeChat development environment..."
	@echo "This will start:"
	@echo "  - Kubernetes Operator"
	@echo "  - WebAPI Server (port 8080)"
	@echo "  - React Dev Server (port 3000)"
	@echo ""
	@echo "Press Ctrl+C to stop all services"
	@trap 'kill %1 %2 %3; wait' SIGINT; \
	make run & \
	make run-webapi & \
	make run-web & \
	wait