# KubeChat Configuration Reference

This document provides a complete reference for all KubeChat configuration parameters, environment variables, and deployment options.

## Table of Contents

1. [Environment Variables Reference](#environment-variables-reference)
2. [Redis Configuration](#redis-configuration)
3. [Authentication Providers](#authentication-providers)
4. [Security Settings](#security-settings)
5. [Performance Tuning](#performance-tuning)
6. [Monitoring Configuration](#monitoring-configuration)
7. [Default Values](#default-values)

## Environment Variables Reference

### Core Application Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_LISTEN_PORT` | int | `8080` | HTTP server listening port |
| `KUBECHAT_PUBLIC_URL` | string | `http://localhost:8080` | Public-facing URL for redirects |
| `KUBECHAT_LOG_LEVEL` | string | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `KUBECHAT_LOG_FORMAT` | string | `json` | Log format: `json`, `text` |
| `KUBECHAT_GRACEFUL_TIMEOUT` | duration | `30s` | Graceful shutdown timeout |

### JWT Token Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_JWT_ISSUER` | string | `kubechat` | JWT token issuer claim |
| `KUBECHAT_JWT_TOKEN_DURATION` | duration | `8h` | Access token validity duration |
| `KUBECHAT_JWT_REFRESH_DURATION` | duration | `168h` | Refresh token validity (7 days) |
| `KUBECHAT_JWT_PRIVATE_KEY_PEM` | string | auto-generated | RSA private key for JWT signing |
| `KUBECHAT_JWT_ROTATION_ENABLED` | bool | `true` | Enable automatic token rotation |
| `KUBECHAT_JWT_ROTATION_INTERVAL` | duration | `24h` | Token rotation check interval |

### Session Management

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_SESSION_SECRET` | string | **required** | Session encryption key (32+ chars) |
| `KUBECHAT_SESSION_DURATION` | duration | `24h` | Session validity duration |
| `KUBECHAT_SESSION_CLEANUP_INTERVAL` | duration | `1h` | Expired session cleanup interval |

## Redis Configuration

### Connection Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_REDIS_ADDR` | string | `localhost:6379` | Redis server address |
| `KUBECHAT_REDIS_PASSWORD` | string | empty | Redis authentication password |
| `KUBECHAT_REDIS_DB` | int | `0` | Redis database number |
| `KUBECHAT_REDIS_CLUSTER` | string | empty | Comma-separated Redis cluster addresses |

### Connection Pool Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_REDIS_POOL_SIZE` | int | `10` | Maximum number of connections |
| `KUBECHAT_REDIS_MIN_IDLE_CONNS` | int | `2` | Minimum idle connections |
| `KUBECHAT_REDIS_MAX_RETRIES` | int | `3` | Maximum retry attempts |
| `KUBECHAT_REDIS_DIAL_TIMEOUT` | duration | `10s` | Connection establishment timeout |
| `KUBECHAT_REDIS_READ_TIMEOUT` | duration | `5s` | Read operation timeout |
| `KUBECHAT_REDIS_WRITE_TIMEOUT` | duration | `5s` | Write operation timeout |

### TLS Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_REDIS_TLS_ENABLED` | bool | `false` | Enable TLS for Redis connections |
| `KUBECHAT_REDIS_TLS_CERT_FILE` | string | empty | Client certificate file path |
| `KUBECHAT_REDIS_TLS_KEY_FILE` | string | empty | Client private key file path |
| `KUBECHAT_REDIS_TLS_CA_FILE` | string | empty | CA certificate file path |
| `KUBECHAT_REDIS_TLS_SKIP_VERIFY` | bool | `false` | Skip TLS certificate verification |

## Authentication Providers

### Generic OIDC Provider

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `KUBECHAT_OIDC_PROVIDER_NAME` | string | ✓ | Unique provider identifier |
| `KUBECHAT_OIDC_PROVIDER_DISPLAY_NAME` | string | ✓ | Human-readable provider name |
| `KUBECHAT_OIDC_ISSUER_URL` | string | ✓ | OIDC issuer URL |
| `KUBECHAT_OIDC_CLIENT_ID` | string | ✓ | OIDC client identifier |
| `KUBECHAT_OIDC_CLIENT_SECRET` | string | ✓ | OIDC client secret |
| `KUBECHAT_OIDC_REDIRECT_URL` | string | ✓ | OAuth callback URL |
| `KUBECHAT_OIDC_SCOPES` | string | `openid,email,profile` | Requested OAuth scopes |

### Claim Mapping

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_OIDC_EMAIL_CLAIM` | string | `email` | JWT claim for user email |
| `KUBECHAT_OIDC_NAME_CLAIM` | string | `name` | JWT claim for user name |
| `KUBECHAT_OIDC_GROUPS_CLAIM` | string | `groups` | JWT claim for user groups |
| `KUBECHAT_OIDC_PREFERRED_USERNAME_CLAIM` | string | `preferred_username` | JWT claim for username |

### Azure AD Configuration

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `KUBECHAT_AZURE_TENANT_ID` | string | ✓ | Azure AD tenant identifier |
| `KUBECHAT_AZURE_CLIENT_ID` | string | ✓ | Application registration ID |
| `KUBECHAT_AZURE_CLIENT_SECRET` | string | ✓ | Application client secret |
| `KUBECHAT_AZURE_REDIRECT_URL` | string | ✓ | Azure AD callback URL |

### Google Workspace Configuration

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `KUBECHAT_GOOGLE_CLIENT_ID` | string | ✓ | Google OAuth client ID |
| `KUBECHAT_GOOGLE_CLIENT_SECRET` | string | ✓ | Google OAuth client secret |
| `KUBECHAT_GOOGLE_REDIRECT_URL` | string | ✓ | Google OAuth callback URL |
| `KUBECHAT_GOOGLE_HOSTED_DOMAIN` | string | empty | Restrict to specific domain |

### SAML Configuration

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `KUBECHAT_SAML_PROVIDER_NAME` | string | ✓ | Unique SAML provider identifier |
| `KUBECHAT_SAML_PROVIDER_DISPLAY_NAME` | string | ✓ | Human-readable provider name |
| `KUBECHAT_SAML_METADATA_URL` | string | ✓* | IdP metadata endpoint URL |
| `KUBECHAT_SAML_METADATA_FILE` | string | ✓* | Path to IdP metadata XML file |
| `KUBECHAT_SAML_ENTITY_ID` | string | ✓ | SP entity identifier |
| `KUBECHAT_SAML_ASSERTION_CONSUMER_URL` | string | ✓ | SAML ACS endpoint URL |

*Either `METADATA_URL` or `METADATA_FILE` is required.

### SAML Certificate Configuration

| Variable | Type | Required | Description |
|----------|------|----------|-------------|
| `KUBECHAT_SAML_CERT_FILE` | string | ✓ | SAML signing certificate path |
| `KUBECHAT_SAML_KEY_FILE` | string | ✓ | SAML signing private key path |
| `KUBECHAT_SAML_CERT_PEM` | string | ✓* | SAML certificate in PEM format |
| `KUBECHAT_SAML_KEY_PEM` | string | ✓* | SAML private key in PEM format |

*Either file paths or PEM strings are required.

### SAML Attribute Mapping

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_SAML_EMAIL_ATTRIBUTE` | string | `email` | SAML attribute for email |
| `KUBECHAT_SAML_NAME_ATTRIBUTE` | string | `name` | SAML attribute for display name |
| `KUBECHAT_SAML_GROUPS_ATTRIBUTE` | string | `groups` | SAML attribute for group membership |
| `KUBECHAT_SAML_USERNAME_ATTRIBUTE` | string | `username` | SAML attribute for username |

## Security Settings

### Rate Limiting

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_RATE_LIMIT_ENABLED` | bool | `true` | Enable rate limiting |
| `KUBECHAT_RATE_LIMIT_REQUESTS` | int | `100` | Requests per window per IP |
| `KUBECHAT_RATE_LIMIT_WINDOW` | duration | `1m` | Rate limit time window |
| `KUBECHAT_RATE_LIMIT_SKIP_SUCCESSFUL` | bool | `false` | Skip rate limiting for successful requests |

### Brute Force Protection

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_BRUTE_FORCE_ENABLED` | bool | `true` | Enable brute force protection |
| `KUBECHAT_BRUTE_FORCE_THRESHOLD` | int | `5` | Failed attempts before lockout |
| `KUBECHAT_BRUTE_FORCE_WINDOW` | duration | `15m` | Time window for counting failures |
| `KUBECHAT_BRUTE_FORCE_LOCKOUT` | duration | `15m` | Account lockout duration |
| `KUBECHAT_BRUTE_FORCE_CLEANUP_INTERVAL` | duration | `1h` | Cleanup expired entries interval |

### Circuit Breaker

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_CIRCUIT_BREAKER_ENABLED` | bool | `true` | Enable circuit breaker |
| `KUBECHAT_CIRCUIT_BREAKER_TIMEOUT` | duration | `30s` | Request timeout before failure |
| `KUBECHAT_CIRCUIT_BREAKER_MAX_FAILURES` | int | `5` | Failures before opening circuit |
| `KUBECHAT_CIRCUIT_BREAKER_RECOVERY_TIMEOUT` | duration | `60s` | Time before attempting recovery |

### CORS Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_CORS_ALLOWED_ORIGINS` | string | `*` | Comma-separated allowed origins |
| `KUBECHAT_CORS_ALLOWED_METHODS` | string | `GET,POST,PUT,DELETE,OPTIONS` | Allowed HTTP methods |
| `KUBECHAT_CORS_ALLOWED_HEADERS` | string | `*` | Allowed request headers |
| `KUBECHAT_CORS_EXPOSED_HEADERS` | string | empty | Headers to expose to browser |
| `KUBECHAT_CORS_MAX_AGE` | duration | `12h` | Preflight cache duration |
| `KUBECHAT_CORS_CREDENTIALS` | bool | `true` | Allow credentials in CORS requests |

## Performance Tuning

### HTTP Server Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_HTTP_READ_TIMEOUT` | duration | `30s` | HTTP request read timeout |
| `KUBECHAT_HTTP_WRITE_TIMEOUT` | duration | `30s` | HTTP response write timeout |
| `KUBECHAT_HTTP_IDLE_TIMEOUT` | duration | `120s` | HTTP keep-alive idle timeout |
| `KUBECHAT_HTTP_MAX_HEADER_SIZE` | int | `1048576` | Maximum HTTP header size (1MB) |

### Concurrency Settings

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_MAX_CONCURRENT_REQUESTS` | int | `1000` | Maximum concurrent HTTP requests |
| `KUBECHAT_WORKER_POOL_SIZE` | int | `100` | Background worker pool size |
| `KUBECHAT_QUEUE_BUFFER_SIZE` | int | `1000` | Internal queue buffer size |

## Monitoring Configuration

### Health Checks

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_HEALTH_CHECK_INTERVAL` | duration | `30s` | Internal health check interval |
| `KUBECHAT_HEALTH_CHECK_TIMEOUT` | duration | `5s` | Health check operation timeout |
| `KUBECHAT_READINESS_CHECK_DEPENDENCIES` | bool | `true` | Include dependencies in readiness |

### Metrics and Observability

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `KUBECHAT_METRICS_ENABLED` | bool | `true` | Enable Prometheus metrics |
| `KUBECHAT_METRICS_PATH` | string | `/metrics` | Metrics endpoint path |
| `KUBECHAT_METRICS_PORT` | int | `9090` | Metrics server port |
| `KUBECHAT_TRACING_ENABLED` | bool | `false` | Enable distributed tracing |
| `KUBECHAT_TRACING_ENDPOINT` | string | empty | Jaeger/OTLP endpoint URL |
| `KUBECHAT_TRACING_SAMPLE_RATE` | float | `0.1` | Trace sampling rate (0.0-1.0) |

## Default Values

### Timeouts and Intervals

```yaml
# Default timeout values
HTTP_READ_TIMEOUT: 30s
HTTP_WRITE_TIMEOUT: 30s
GRACEFUL_SHUTDOWN_TIMEOUT: 30s
JWT_TOKEN_DURATION: 8h
JWT_REFRESH_DURATION: 168h
REDIS_DIAL_TIMEOUT: 10s
REDIS_READ_TIMEOUT: 5s
REDIS_WRITE_TIMEOUT: 5s
CIRCUIT_BREAKER_TIMEOUT: 30s
CIRCUIT_BREAKER_RECOVERY: 60s

# Default intervals
JWT_ROTATION_INTERVAL: 24h
SESSION_CLEANUP_INTERVAL: 1h
HEALTH_CHECK_INTERVAL: 30s
RATE_LIMIT_WINDOW: 1m
BRUTE_FORCE_WINDOW: 15m
BRUTE_FORCE_LOCKOUT: 15m
```

### Connection Pools

```yaml
# Default pool sizes
REDIS_POOL_SIZE: 10
REDIS_MIN_IDLE_CONNS: 2
MAX_CONCURRENT_REQUESTS: 1000
WORKER_POOL_SIZE: 100
QUEUE_BUFFER_SIZE: 1000
```

### Security Defaults

```yaml
# Default security settings
RATE_LIMIT_REQUESTS: 100
BRUTE_FORCE_THRESHOLD: 5
CIRCUIT_BREAKER_MAX_FAILURES: 5
CORS_MAX_AGE: 12h
```

## Configuration Validation

KubeChat validates all configuration at startup. The following validations are performed:

### Required Settings
- `KUBECHAT_SESSION_SECRET` must be at least 32 characters
- At least one authentication provider must be configured
- Redis connection must be valid
- SAML certificates must be valid if SAML is enabled

### Format Validation
- Duration strings must be valid Go duration format (`1h30m`, `30s`, etc.)
- URLs must be valid HTTP/HTTPS URLs
- Port numbers must be in valid range (1-65535)
- Log levels must be one of: `debug`, `info`, `warn`, `error`

### Security Validation
- HTTPS must be used in production (non-localhost `PUBLIC_URL`)
- Strong session secrets are enforced
- Certificate expiration is checked for SAML providers
- Redirect URLs must match configured public URL

## Example Configurations

### Minimal Development Configuration

```bash
KUBECHAT_PUBLIC_URL=http://localhost:8080
KUBECHAT_SESSION_SECRET=this-is-a-development-secret-key-change-in-production
KUBECHAT_OIDC_PROVIDER_NAME=dev-provider
KUBECHAT_OIDC_ISSUER_URL=https://dev-auth.example.com
KUBECHAT_OIDC_CLIENT_ID=kubechat-dev
KUBECHAT_OIDC_CLIENT_SECRET=dev-secret
```

### Production High-Availability Configuration

```bash
# Core settings
KUBECHAT_PUBLIC_URL=https://kubechat.company.com
KUBECHAT_LOG_LEVEL=info
KUBECHAT_GRACEFUL_TIMEOUT=45s

# Security
KUBECHAT_SESSION_SECRET=generate-a-secure-32-character-key
KUBECHAT_RATE_LIMIT_REQUESTS=200
KUBECHAT_BRUTE_FORCE_THRESHOLD=3

# Redis cluster
KUBECHAT_REDIS_CLUSTER=redis-1.prod:6379,redis-2.prod:6379,redis-3.prod:6379
KUBECHAT_REDIS_PASSWORD=secure-redis-password
KUBECHAT_REDIS_POOL_SIZE=50

# OIDC
KUBECHAT_OIDC_PROVIDER_NAME=corporate-sso
KUBECHAT_OIDC_ISSUER_URL=https://sso.company.com
KUBECHAT_OIDC_CLIENT_ID=kubechat-prod
KUBECHAT_OIDC_CLIENT_SECRET=production-secret

# Performance
KUBECHAT_MAX_CONCURRENT_REQUESTS=2000
KUBECHAT_WORKER_POOL_SIZE=200

# Monitoring
KUBECHAT_METRICS_ENABLED=true
KUBECHAT_TRACING_ENABLED=true
KUBECHAT_TRACING_ENDPOINT=https://jaeger.monitoring.svc:14268/api/traces
```

This configuration reference provides comprehensive documentation for all KubeChat settings. Always test configuration changes in development environments before applying to production.