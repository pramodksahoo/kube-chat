# Multi-stage build for KubeChat Kubernetes Operator
# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

# Build arguments
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG SERVICE=operator

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /workspace

# Copy Go modules manifests for dependency caching
COPY go.mod go.sum ./

# Download dependencies (cached layer) with toolchain support
ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY api/ api/
COPY config/ config/

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -a -ldflags "-s -w -X main.version=${VERSION} -X main.service=${SERVICE}" \
    -o operator cmd/operator/main.go

# Stage 2: Create minimal runtime image
FROM gcr.io/distroless/static:nonroot

# Image metadata
LABEL org.opencontainers.image.title="KubeChat Kubernetes Operator"
LABEL org.opencontainers.image.description="KubeChat Phase 1 Model 1 Kubernetes Operator"
LABEL org.opencontainers.image.version="${VERSION:-dev}"
LABEL org.opencontainers.image.vendor="KubeChat"
LABEL org.opencontainers.image.source="https://github.com/pramodksahoo/kube-chat"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Security: Use non-root user
WORKDIR /
COPY --from=builder /workspace/operator .
USER 65532:65532

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/operator", "--health-check"]

# Expose metrics and webhook ports
EXPOSE 8080 9443

# Run the binary
ENTRYPOINT ["/operator"]