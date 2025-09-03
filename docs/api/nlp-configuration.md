# NLP Configuration API Reference

## Overview

This document describes the configuration options for KubeChat's Natural Language Processing (NLP) system, including OpenAI integration, safety settings, and processing parameters.

## Configuration Resources

### OpenAI API Configuration

The NLP system requires OpenAI API access for advanced natural language processing. Configuration is managed through Kubernetes Secrets and ConfigMaps.

#### Secret: kubechat-config

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: kubechat-config
  namespace: kubechat-system
type: Opaque
data:
  openai-api-key: <base64-encoded-api-key>
  # Optional: Organization ID for OpenAI API
  openai-org-id: <base64-encoded-org-id>
```

**Fields:**
- `openai-api-key` (required): Base64-encoded OpenAI API key
- `openai-org-id` (optional): Base64-encoded OpenAI organization ID

#### ConfigMap: kubechat-nlp-config

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubechat-nlp-config
  namespace: kubechat-system
data:
  # OpenAI Model Configuration
  openai-model: "gpt-4"
  openai-max-tokens: "1000"
  openai-temperature: "0.1"
  openai-timeout: "30s"
  
  # Safety Configuration
  enable-safety-checks: "true"
  confirmation-required: "true"
  safety-level-threshold: "caution"
  
  # Rate Limiting
  rate-limit-requests-per-minute: "60"
  rate-limit-tokens-per-minute: "10000"
  rate-limit-burst-size: "10"
  
  # Intent Recognition
  confidence-threshold: "0.8"
  pattern-matching-enabled: "true"
  fallback-to-openai: "true"
  
  # Processing Options
  max-retry-attempts: "3"
  processing-timeout: "60s"
  enable-context-awareness: "true"
  max-context-history: "10"
```

## Configuration Parameters

### OpenAI Model Settings

| Parameter | Type | Default | Description | Valid Values |
|-----------|------|---------|-------------|--------------|
| `openai-model` | string | `"gpt-4"` | OpenAI model to use for NLP processing | `gpt-4`, `gpt-3.5-turbo`, `gpt-4-turbo` |
| `openai-max-tokens` | integer | `1000` | Maximum tokens per OpenAI request | 1-4096 |
| `openai-temperature` | float | `0.1` | Temperature for OpenAI completions | 0.0-2.0 |
| `openai-timeout` | duration | `"30s"` | Timeout for OpenAI API requests | Valid duration string |

### Safety Configuration

| Parameter | Type | Default | Description | Valid Values |
|-----------|------|---------|-------------|--------------|
| `enable-safety-checks` | boolean | `true` | Enable/disable safety validation | `true`, `false` |
| `confirmation-required` | boolean | `true` | Require confirmation for dangerous operations | `true`, `false` |
| `safety-level-threshold` | string | `"caution"` | Minimum safety level to trigger warnings | `safe`, `caution`, `dangerous`, `destructive` |

### Rate Limiting

| Parameter | Type | Default | Description | Valid Values |
|-----------|------|---------|-------------|--------------|
| `rate-limit-requests-per-minute` | integer | `60` | Maximum OpenAI requests per minute | 1-10000 |
| `rate-limit-tokens-per-minute` | integer | `10000` | Maximum tokens consumed per minute | 1-1000000 |
| `rate-limit-burst-size` | integer | `10` | Burst size for rate limiting | 1-100 |

### Intent Recognition

| Parameter | Type | Default | Description | Valid Values |
|-----------|------|---------|-------------|--------------|
| `confidence-threshold` | float | `0.8` | Minimum confidence for intent acceptance | 0.0-1.0 |
| `pattern-matching-enabled` | boolean | `true` | Enable pattern-based intent recognition | `true`, `false` |
| `fallback-to-openai` | boolean | `true` | Use OpenAI when pattern matching fails | `true`, `false` |

### Processing Options

| Parameter | Type | Default | Description | Valid Values |
|-----------|------|---------|-------------|--------------|
| `max-retry-attempts` | integer | `3` | Maximum retries for failed processing | 1-10 |
| `processing-timeout` | duration | `"60s"` | Total timeout for message processing | Valid duration string |
| `enable-context-awareness` | boolean | `true` | Enable conversation context tracking | `true`, `false` |
| `max-context-history` | integer | `10` | Maximum messages to keep in context | 1-100 |

## Environment-Specific Configuration

### Development Environment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubechat-nlp-config
  namespace: kubechat-system
data:
  openai-model: "gpt-3.5-turbo"
  openai-max-tokens: "500"
  rate-limit-requests-per-minute: "30"
  enable-safety-checks: "false"
  confirmation-required: "false"
```

### Production Environment

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kubechat-nlp-config
  namespace: kubechat-system
data:
  openai-model: "gpt-4"
  openai-max-tokens: "1000"
  openai-temperature: "0.05"
  rate-limit-requests-per-minute: "120"
  enable-safety-checks: "true"
  confirmation-required: "true"
  safety-level-threshold: "caution"
  max-retry-attempts: "5"
```

## Configuration Validation

### Required Configurations

The following configurations are required for NLP functionality:

1. **OpenAI API Key**: Must be provided via the `kubechat-config` Secret
2. **Valid Model**: Must specify a supported OpenAI model
3. **Rate Limits**: Must be within OpenAI API limits

### Configuration Validation Rules

- `openai-max-tokens` must be ≤ model's maximum context length
- `confidence-threshold` must be between 0.0 and 1.0
- `rate-limit-requests-per-minute` must not exceed OpenAI tier limits
- `processing-timeout` must be ≥ `openai-timeout`
- `max-context-history` must be ≤ `maxHistorySize` in ChatSession preferences

### Error Conditions

| Error | Cause | Resolution |
|-------|-------|------------|
| `InvalidAPIKey` | Missing or invalid OpenAI API key | Check Secret configuration |
| `ModelNotSupported` | Unsupported OpenAI model specified | Use supported model version |
| `RateLimitExceeded` | Too many requests per minute | Increase rate limits or upgrade OpenAI tier |
| `TokenLimitExceeded` | Message too large for model | Reduce content size or increase max-tokens |
| `ConfigurationMissing` | Required ConfigMap not found | Create kubechat-nlp-config ConfigMap |

## Monitoring Configuration

### Metrics to Monitor

Monitor these configuration-related metrics:

- `openai_requests_per_minute`: Current OpenAI request rate
- `openai_tokens_consumed_per_minute`: Current token consumption rate  
- `nlp_processing_latency_seconds`: Processing time distribution
- `nlp_confidence_score`: Intent recognition confidence distribution
- `safety_assessments_by_level`: Distribution of safety levels

### Alerts

Set up alerts for:

- Rate limit approaching (>80% of configured limits)
- High processing latency (>processing-timeout * 0.8)
- Low confidence scores (<confidence-threshold * 1.1)
- Configuration validation failures

## Best Practices

### Security

1. **API Key Management**
   - Store API keys in Kubernetes Secrets
   - Use least-privilege service accounts
   - Rotate API keys regularly
   - Monitor API key usage

2. **Configuration Management**
   - Use GitOps for configuration management
   - Validate configurations before deployment
   - Maintain environment-specific configs
   - Document configuration changes

### Performance

1. **Rate Limiting**
   - Set conservative limits initially
   - Monitor actual usage patterns
   - Adjust limits based on OpenAI tier
   - Implement backoff strategies

2. **Model Selection**
   - Use GPT-3.5-turbo for development
   - Use GPT-4 for production accuracy
   - Consider cost implications
   - Test different temperature settings

3. **Caching**
   - Enable pattern matching for common commands
   - Cache frequent intent patterns
   - Implement response caching where appropriate

### Reliability

1. **Error Handling**
   - Configure appropriate retry limits
   - Set reasonable timeouts
   - Implement graceful degradation
   - Monitor error rates

2. **Failover**
   - Enable pattern matching as fallback
   - Configure multiple retry attempts
   - Implement circuit breaker patterns
   - Monitor system health

## Migration and Upgrades

### Configuration Migration

When upgrading KubeChat versions:

1. Review new configuration parameters
2. Update ConfigMaps with new defaults
3. Test configuration in non-production first
4. Monitor for deprecated parameters
5. Update documentation and runbooks

### OpenAI Model Updates

When switching OpenAI models:

1. Test new model with representative workloads
2. Adjust token limits for new model constraints
3. Update temperature settings if needed
4. Monitor confidence scores and accuracy
5. Have rollback plan ready

## Troubleshooting

### Common Configuration Issues

1. **NLP Processing Not Working**
   - Verify OpenAI API key is valid
   - Check ConfigMap exists and is readable
   - Validate configuration parameter formats
   - Review controller logs for errors

2. **High Latency**
   - Reduce openai-max-tokens
   - Increase openai-timeout
   - Check rate limiting settings
   - Monitor OpenAI API status

3. **Low Accuracy**
   - Increase confidence-threshold temporarily
   - Switch to more capable model (GPT-4)
   - Adjust temperature settings
   - Review intent patterns

4. **Rate Limit Errors**
   - Check current usage against limits
   - Upgrade OpenAI tier if needed
   - Implement request queuing
   - Adjust burst size settings

For additional troubleshooting information, see the [NLP User Guide](../user-guides/nlp-usage.md#troubleshooting).