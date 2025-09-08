# Multi-stage build for KubeChat Audit Service
# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

# Build arguments
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG SERVICE=audit-service

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /workspace

# Copy Go modules manifests for dependency caching
COPY go.mod go.sum ./

# Download dependencies (cached layer)
# Download dependencies with toolchain support
ENV GOTOOLCHAIN=auto
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY api/ api/

# Build the binary with optimizations
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -a -ldflags "-s -w -X main.version=${VERSION} -X main.service=${SERVICE}" \
    -o audit-service cmd/audit-service/main.go

# Stage 2: Create minimal runtime image  
FROM gcr.io/distroless/static:nonroot

# Image metadata
LABEL org.opencontainers.image.title="KubeChat Audit Service"
LABEL org.opencontainers.image.description="KubeChat Phase 1 Model 1 Audit and Compliance Service"
LABEL org.opencontainers.image.version="${VERSION:-dev}"
LABEL org.opencontainers.image.vendor="KubeChat"
LABEL org.opencontainers.image.source="https://github.com/pramodksahoo/kube-chat"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Security: Use non-root user
WORKDIR /
COPY --from=builder /workspace/audit-service .
USER 65532:65532

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/audit-service", "--health-check"]

# Expose service port
EXPOSE 8082

# Run the binary
ENTRYPOINT ["/audit-service"]