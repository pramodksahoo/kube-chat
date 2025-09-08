# Multi-stage build for KubeChat NLP Service
# Stage 1: Build the Go binary
FROM golang:1.25-alpine AS builder

# Build arguments
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG VERSION=dev
ARG SERVICE=nlp-service

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
    -o nlp-service cmd/nlp-service/main.go

# Stage 2: Create runtime image with kubectl
FROM alpine:3.20 AS kubectl-installer

# Install kubectl
RUN apk add --no-cache curl ca-certificates && \
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" && \
    install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl

# Stage 3: Final runtime image
FROM gcr.io/distroless/base:nonroot

# Image metadata
LABEL org.opencontainers.image.title="KubeChat NLP Service"
LABEL org.opencontainers.image.description="KubeChat Phase 1 Model 1 Natural Language Processing Service with kubectl"
LABEL org.opencontainers.image.version="${VERSION:-dev}"
LABEL org.opencontainers.image.vendor="KubeChat"
LABEL org.opencontainers.image.source="https://github.com/pramodksahoo/kube-chat"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy kubectl from installer stage
COPY --from=kubectl-installer /usr/local/bin/kubectl /usr/local/bin/kubectl

# Set PATH to include kubectl location
ENV PATH="/usr/local/bin:$PATH"

# Security: Use non-root user
WORKDIR /
COPY --from=builder /workspace/nlp-service .
USER 65532:65532

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/nlp-service", "--health-check"]

# Expose service port
EXPOSE 8084

# Run the binary
ENTRYPOINT ["/nlp-service"]