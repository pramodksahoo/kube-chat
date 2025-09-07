# Helm Deployment Architecture - Phase 1 Model 1

## Overview

This document defines the Helm-native deployment architecture for **KubeChat Phase 1: Model 1 (On-Premises FREE Platform)**, ensuring zero vendor lock-in, complete data sovereignty, and air-gap deployment capability.

## Core Design Principles

### 1. Helm-Native Single Chart Architecture

```yaml
chart_philosophy:
  approach: "Single comprehensive Helm chart"
  dependencies: "Zero external chart dependencies"
  self_contained: "All resources defined within chart"
  customization: "Extensive values.yaml configuration"
  
deployment_command:
  standard: "helm install kubechat ./kubechat-chart"
  custom_values: "helm install kubechat ./kubechat-chart -f custom-values.yaml"
  upgrade: "helm upgrade kubechat ./kubechat-chart"
  rollback: "helm rollback kubechat 1"
```

### 2. Air-Gap Deployment Support

```yaml
air_gap_requirements:
  container_images: "All images bundled in customer registry"
  dependencies: "No internet connectivity required"
  configuration: "Complete offline configuration"
  updates: "Manual package deployment"
  
offline_bundle:
  structure:
    - "kubechat-chart/ (Helm chart)"
    - "images/ (Container image archives)"
    - "install.sh (Offline installation script)"
    - "README.md (Installation instructions)"
    - "values-examples/ (Configuration templates)"
```

## Helm Chart Structure

### 1. Chart Directory Layout

```yaml
kubechat-chart/
├── Chart.yaml                 # Chart metadata and version
├── values.yaml               # Default configuration values
├── values-production.yaml    # Production configuration template
├── values-airgap.yaml       # Air-gap deployment template
├── README.md                 # Installation and configuration guide
├── NOTES.txt                # Post-installation instructions
├── templates/
│   ├── _helpers.tpl         # Template helpers
│   ├── namespace.yaml       # Namespace creation
│   ├── rbac/
│   │   ├── serviceaccount.yaml
│   │   ├── clusterrole.yaml
│   │   └── clusterrolebinding.yaml
│   ├── crd/
│   │   ├── chatsession-crd.yaml
│   │   └── auditevent-crd.yaml
│   ├── operator/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── configmap.yaml
│   ├── api-gateway/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   ├── ingress.yaml
│   │   └── hpa.yaml
│   ├── audit-service/
│   │   ├── deployment.yaml
│   │   ├── service.yaml
│   │   └── pvc.yaml
│   ├── database/
│   │   ├── postgres-deployment.yaml
│   │   ├── postgres-service.yaml
│   │   ├── postgres-pvc.yaml
│   │   └── postgres-secret.yaml
│   ├── redis/
│   │   ├── redis-deployment.yaml
│   │   ├── redis-service.yaml
│   │   └── redis-configmap.yaml
│   └── monitoring/
│       ├── servicemonitor.yaml
│       └── prometheusrule.yaml
└── crds/                     # Custom Resource Definitions
    ├── chatsession.yaml
    └── auditevent.yaml
```

### 2. Chart.yaml Configuration

```yaml
apiVersion: v2
name: kubechat
description: KubeChat - Natural Language Kubernetes Management (On-Premises)
type: application
version: 1.0.0
appVersion: "1.0.0"
home: https://github.com/company/kubechat
sources:
  - https://github.com/company/kubechat
maintainers:
  - name: KubeChat Team
    email: team@kubechat.com
keywords:
  - kubernetes
  - nlp
  - kubectl
  - automation
  - enterprise
annotations:
  category: DevOps
  licenses: Apache-2.0
```

### 3. Default values.yaml Structure

```yaml
# KubeChat Phase 1 Model 1 (On-Premises) Configuration
global:
  imageRegistry: ""  # Customer private registry
  imagePullSecrets: []
  storageClass: ""   # Customer storage class
  
# Deployment Configuration
deployment:
  mode: "on-premises"  # Fixed for Phase 1 Model 1
  airgap: false        # Set to true for air-gap deployments
  
# Image Configuration (Customer Registry)
images:
  apiGateway:
    repository: "kubechat/api-gateway"
    tag: "1.0.0"
    pullPolicy: IfNotPresent
  operator:
    repository: "kubechat/operator" 
    tag: "1.0.0"
    pullPolicy: IfNotPresent
  auditService:
    repository: "kubechat/audit-service"
    tag: "1.0.0"
    pullPolicy: IfNotPresent

# API Gateway Configuration
apiGateway:
  enabled: true
  replicaCount: 3
  service:
    type: ClusterIP
    port: 80
    targetPort: 8080
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "512Mi"
      cpu: "500m"
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70

# Kubernetes Operator Configuration
operator:
  enabled: true
  replicaCount: 1
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

# Database Configuration (PostgreSQL)
postgresql:
  enabled: true
  internal: true  # Use internal PostgreSQL
  external:
    host: ""
    port: 5432
    database: "kubechat"
    username: "kubechat"
    password: ""
  persistence:
    enabled: true
    size: "20Gi"
    storageClass: ""
  resources:
    requests:
      memory: "256Mi"
      cpu: "250m"
    limits:
      memory: "512Mi"
      cpu: "500m"

# Redis Configuration
redis:
  enabled: true
  internal: true  # Use internal Redis
  external:
    host: ""
    port: 6379
    password: ""
  persistence:
    enabled: true
    size: "8Gi"
    storageClass: ""
  resources:
    requests:
      memory: "128Mi"
      cpu: "100m"
    limits:
      memory: "256Mi"
      cpu: "200m"

# Authentication Configuration (OIDC/SAML)
auth:
  oidc:
    enabled: false
    providerName: ""
    issuerUrl: ""
    clientId: ""
    clientSecret: ""
    redirectUrl: ""
    scopes: "openid,email,profile"
  saml:
    enabled: false
    providerName: ""
    metadataUrl: ""
    entityId: ""
    acsUrl: ""

# Security Configuration
security:
  networkPolicies:
    enabled: true
  podSecurityPolicy:
    enabled: true
  rbac:
    create: true
  serviceAccount:
    create: true
    name: ""

# Monitoring Configuration
monitoring:
  prometheus:
    enabled: true
    serviceMonitor:
      enabled: true
  grafana:
    enabled: false  # Customer can integrate with existing Grafana

# Ingress Configuration  
ingress:
  enabled: false
  className: ""
  annotations: {}
  hosts: []
  tls: []

# Air-Gap Specific Configuration
airgap:
  imageRegistry: "localhost:5000"  # Default local registry
  pullSecrets:
    - name: "registry-credentials"
  offlineMode: true
  externalServices: false
```

## Air-Gap Deployment Process

### 1. Offline Bundle Creation

```bash
#!/bin/bash
# create-airgap-bundle.sh

set -euo pipefail

VERSION="${1:-1.0.0}"
BUNDLE_DIR="kubechat-airgap-${VERSION}"

echo "Creating KubeChat air-gap bundle v${VERSION}..."

# Create bundle directory
mkdir -p "$BUNDLE_DIR"/{chart,images,scripts}

# Copy Helm chart
cp -r kubechat-chart/ "$BUNDLE_DIR/chart/"

# Export container images
images=(
  "kubechat/api-gateway:${VERSION}"
  "kubechat/operator:${VERSION}" 
  "kubechat/audit-service:${VERSION}"
  "postgres:16"
  "redis:7.2-alpine"
)

for image in "${images[@]}"; do
  echo "Exporting image: $image"
  docker save "$image" | gzip > "$BUNDLE_DIR/images/$(echo $image | tr '/:' '-').tar.gz"
done

# Create installation scripts
cat > "$BUNDLE_DIR/scripts/load-images.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

REGISTRY="${1:-localhost:5000}"
IMAGES_DIR="$(dirname "$0")/../images"

echo "Loading images to registry: $REGISTRY"

for image_file in "$IMAGES_DIR"/*.tar.gz; do
  echo "Loading $(basename "$image_file")..."
  docker load < "$image_file"
  
  # Tag and push to local registry if specified
  if [[ "$REGISTRY" != "" ]]; then
    # Extract original image name and tag from filename
    original_image=$(basename "$image_file" .tar.gz | tr '-' '/' | sed 's/\([^/]*\)$/:\1/')
    new_image="$REGISTRY/${original_image#*/}"
    
    docker tag "$original_image" "$new_image"
    docker push "$new_image"
  fi
done
EOF

cat > "$BUNDLE_DIR/scripts/install-kubechat.sh" << 'EOF'
#!/bin/bash
set -euo pipefail

REGISTRY="${1:-localhost:5000}"
VALUES_FILE="${2:-values-airgap.yaml}"

echo "Installing KubeChat from air-gap bundle..."

# Load images first
./load-images.sh "$REGISTRY"

# Install with Helm
helm install kubechat ../chart/ -f "../chart/$VALUES_FILE" \
  --set global.imageRegistry="$REGISTRY" \
  --set airgap.enabled=true

echo "KubeChat installation completed!"
EOF

chmod +x "$BUNDLE_DIR/scripts"/*.sh

# Create air-gap values template
cat > "$BUNDLE_DIR/chart/values-airgap.yaml" << EOF
# KubeChat Air-Gap Configuration
global:
  imageRegistry: "localhost:5000"
  imagePullSecrets:
    - name: registry-credentials

deployment:
  airgap: true

# Disable external dependencies
monitoring:
  prometheus:
    enabled: false
  
ingress:
  enabled: false

auth:
  oidc:
    enabled: false
  saml:
    enabled: false
EOF

# Create README
cat > "$BUNDLE_DIR/README.md" << EOF
# KubeChat Air-Gap Deployment Bundle v${VERSION}

This bundle contains everything needed to deploy KubeChat in air-gapped environments.

## Contents
- \`chart/\` - Complete Helm chart
- \`images/\` - Container image archives
- \`scripts/\` - Installation and image loading scripts

## Installation Steps

1. Load container images:
   \`\`\`bash
   cd scripts/
   ./load-images.sh localhost:5000
   \`\`\`

2. Install KubeChat:
   \`\`\`bash
   ./install-kubechat.sh localhost:5000
   \`\`\`

3. Verify installation:
   \`\`\`bash
   kubectl get pods -n kubechat-system
   \`\`\`

See chart/README.md for detailed configuration options.
EOF

# Create compressed bundle
tar -czf "${BUNDLE_DIR}.tar.gz" "$BUNDLE_DIR"
rm -rf "$BUNDLE_DIR"

echo "Air-gap bundle created: ${BUNDLE_DIR}.tar.gz"
```

### 2. Customer Installation Process

```yaml
customer_installation_steps:
  step_1:
    action: "Extract air-gap bundle"
    command: "tar -xzf kubechat-airgap-1.0.0.tar.gz"
    
  step_2:
    action: "Load container images"
    command: "cd kubechat-airgap-1.0.0/scripts && ./load-images.sh"
    
  step_3:
    action: "Review configuration"
    command: "vi kubechat-airgap-1.0.0/chart/values-airgap.yaml"
    
  step_4:
    action: "Install KubeChat"
    command: "./install-kubechat.sh localhost:5000 values-airgap.yaml"
    
  step_5:
    action: "Verify deployment"
    command: "kubectl get pods -n kubechat-system"
```

## Rancher Desktop Development Environment

### 1. Local Development Setup

```yaml
rancher_desktop_config:
  kubernetes_version: "1.28+"
  container_runtime: "containerd"
  registry: "Built-in registry enabled"
  helm: "Helm 3.x pre-installed"
  
development_workflow:
  - name: "Start Rancher Desktop"
    action: "Launch Rancher Desktop with Kubernetes enabled"
    
  - name: "Build local images"
    command: "docker build -t kubechat/api-gateway:dev ."
    
  - name: "Deploy to local cluster"
    command: "helm install kubechat-dev ./kubechat-chart --set images.apiGateway.tag=dev"
    
  - name: "Test air-gap simulation"
    command: "helm install kubechat-airgap ./kubechat-chart -f values-airgap.yaml"
```

### 2. Local Testing Scripts

```bash
#!/bin/bash
# test-local-deployment.sh

set -euo pipefail

echo "Testing KubeChat local deployment on Rancher Desktop..."

# Verify Rancher Desktop is running
if ! kubectl cluster-info &>/dev/null; then
  echo "Error: Rancher Desktop Kubernetes cluster not accessible"
  echo "Please start Rancher Desktop and enable Kubernetes"
  exit 1
fi

# Build local images
echo "Building local container images..."
docker build -t kubechat/api-gateway:dev ./cmd/api-gateway/
docker build -t kubechat/operator:dev ./cmd/operator/
docker build -t kubechat/audit-service:dev ./cmd/audit-service/

# Deploy with local values
echo "Deploying KubeChat to local cluster..."
helm install kubechat-local ./kubechat-chart \
  --set images.apiGateway.tag=dev \
  --set images.operator.tag=dev \
  --set images.auditService.tag=dev \
  --set global.imageRegistry="" \
  --create-namespace \
  --namespace kubechat-system

# Wait for deployment
echo "Waiting for deployment to be ready..."
kubectl wait --for=condition=Available deployment --all -n kubechat-system --timeout=300s

# Test air-gap simulation
echo "Testing air-gap deployment simulation..."
helm install kubechat-airgap ./kubechat-chart -f kubechat-chart/values-airgap.yaml \
  --create-namespace \
  --namespace kubechat-airgap

echo "Local deployment testing completed successfully!"
```

## Integration with Kubernetes Operator Pattern

### 1. Custom Resource Definitions

```yaml
# chatsession-crd.yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: chatsessions.kubechat.ai
spec:
  group: kubechat.ai
  versions:
  - name: v1
    served: true
    storage: true
    schema:
      openAPIV3Schema:
        type: object
        properties:
          spec:
            type: object
            properties:
              userId:
                type: string
              sessionId:
                type: string
              commands:
                type: array
                items:
                  type: object
                  properties:
                    naturalLanguage:
                      type: string
                    translatedCommand:
                      type: string
                    executed:
                      type: boolean
                    timestamp:
                      type: string
          status:
            type: object
            properties:
              phase:
                type: string
              lastActivity:
                type: string
  scope: Namespaced
  names:
    plural: chatsessions
    singular: chatsession
    kind: ChatSession
```

### 2. Operator Deployment Template

```yaml
# templates/operator/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "kubechat.operator.fullname" . }}
  namespace: {{ .Values.namespace | default "kubechat-system" }}
  labels:
    {{- include "kubechat.operator.labels" . | nindent 4 }}
spec:
  replicas: {{ .Values.operator.replicaCount }}
  selector:
    matchLabels:
      {{- include "kubechat.operator.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "kubechat.operator.selectorLabels" . | nindent 8 }}
    spec:
      serviceAccountName: {{ include "kubechat.serviceAccountName" . }}
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: operator
        image: "{{ .Values.global.imageRegistry | default "" }}{{ .Values.images.operator.repository }}:{{ .Values.images.operator.tag }}"
        imagePullPolicy: {{ .Values.images.operator.pullPolicy }}
        ports:
        - name: metrics
          containerPort: 8080
          protocol: TCP
        - name: webhook
          containerPort: 9443
          protocol: TCP
        env:
        - name: WATCH_NAMESPACE
          value: ""
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: OPERATOR_NAME
          value: "kubechat-operator"
        {{- if .Values.deployment.airgap }}
        - name: AIRGAP_MODE
          value: "true"
        {{- end }}
        resources:
          {{- toYaml .Values.operator.resources | nindent 12 }}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop: ["ALL"]
      {{- with .Values.global.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
```

This Helm deployment architecture ensures KubeChat Phase 1 Model 1 meets all on-premises, air-gap, and zero vendor lock-in requirements while providing seamless integration with Rancher Desktop for local development and testing.