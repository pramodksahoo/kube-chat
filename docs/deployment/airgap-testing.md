# KubeChat Air-Gap Testing Guide

This comprehensive guide covers air-gap deployment testing, validation, and troubleshooting for KubeChat in completely offline environments.

## Overview

Air-gap deployment testing ensures that KubeChat operates correctly in environments with no external network connectivity. This is critical for high-security, regulated, or isolated environments where internet access is prohibited or restricted.

## Prerequisites

### System Requirements

- Kubernetes cluster (v1.24+) with air-gap capability
- Docker runtime with local image support
- Local container registry (localhost:5000)
- Helm 3.x for deployment management
- Sufficient cluster resources for all components

### Required Tools

```bash
# Verify tool availability
kubectl version --client
docker --version
helm version
curl --version
jq --version
```

### Network Requirements

- **Internal**: Full cluster networking must be functional
- **External**: All external connectivity must be blocked or unavailable
- **Registry**: Local container registry must be accessible
- **DNS**: Internal cluster DNS must work, external DNS blocked

## Air-Gap Testing Scripts

KubeChat provides comprehensive air-gap testing automation through specialized scripts:

### 1. Air-Gap Environment Simulation

**Script**: `scripts/simulate-airgap.sh`

Creates a controlled air-gap environment by blocking external network access while preserving internal cluster communication.

```bash
# Start air-gap simulation
sudo ./scripts/simulate-airgap.sh --start

# Check simulation status
./scripts/simulate-airgap.sh --status

# Validate network isolation
./scripts/simulate-airgap.sh --validate

# Stop simulation
sudo ./scripts/simulate-airgap.sh --stop
```

**Features**:
- Blocks external DNS, HTTP, and HTTPS traffic
- Preserves local registry access (localhost:5000)
- Maintains Kubernetes cluster communication
- Validates isolation effectiveness

### 2. Complete Air-Gap Testing Suite

**Script**: `scripts/test-airgap.sh`

Comprehensive testing suite that validates all aspects of air-gap deployment.

```bash
# Run complete test suite
./scripts/test-airgap.sh

# Run specific test categories
./scripts/test-airgap.sh --no-network --no-images

# Verbose testing with custom timeout
./scripts/test-airgap.sh --verbose --timeout 900

# Testing without cleanup (for debugging)
./scripts/test-airgap.sh --no-cleanup --verbose
```

**Test Categories**:
- **Network Isolation**: Validates external connectivity blocking
- **Image Availability**: Confirms all images exist locally
- **Deployment Testing**: Tests complete KubeChat deployment
- **Functional Testing**: Validates application functionality
- **Security Testing**: Verifies security policies and isolation

### 3. Deployment Validation

**Script**: `scripts/validate-airgap.sh`

Continuous validation of air-gap deployment health and compliance.

```bash
# Single validation run
./scripts/validate-airgap.sh

# Continuous monitoring
./scripts/validate-airgap.sh --continuous --interval 60

# Custom validation scope
./scripts/validate-airgap.sh --no-network --no-security

# Generate JSON report
./scripts/validate-airgap.sh --report-format json
```

**Validation Areas**:
- Kubernetes connectivity and permissions
- Network isolation effectiveness
- Image availability and pull policies
- Service startup and health
- Application functionality
- Security policy compliance
- Data persistence and integrity

### 4. Troubleshooting and Diagnostics

**Script**: `scripts/troubleshoot-airgap.sh`

Interactive and automated troubleshooting for air-gap deployment issues.

```bash
# Interactive troubleshooting
./scripts/troubleshoot-airgap.sh

# Automated diagnostic with report
./scripts/troubleshoot-airgap.sh --mode automated

# Collect logs and generate diagnostic bundle
./scripts/troubleshoot-airgap.sh --verbose

# Quick health check
./scripts/troubleshoot-airgap.sh --mode automated --no-logs --no-report
```

**Diagnostic Capabilities**:
- Cluster connectivity analysis
- Network isolation verification
- Image availability checking
- Pod and service health assessment
- Configuration validation
- Log collection and analysis
- Automated fix suggestions

## Testing Workflow

### Phase 1: Environment Preparation

1. **Setup Local Registry**
   ```bash
   # Start local Docker registry
   docker run -d -p 5000:5000 --name registry registry:2
   
   # Verify registry accessibility
   curl http://localhost:5000/v2/
   ```

2. **Build and Tag Images**
   ```bash
   # Build all KubeChat images for air-gap
   ./scripts/build-dev-images.sh --airgap
   
   # Verify images are available
   docker images | grep kubechat
   ```

3. **Create Image Bundle** (Optional)
   ```bash
   # Create complete air-gap bundle
   ./scripts/airgap-bundle.sh --version v1.0.0
   
   # Create minimal bundle for testing
   ./scripts/airgap-bundle.sh --no-docs --version test
   ```

### Phase 2: Network Isolation Setup

1. **Start Air-Gap Simulation**
   ```bash
   # Initialize air-gap environment
   sudo ./scripts/simulate-airgap.sh --start
   
   # Validate network isolation
   ./scripts/simulate-airgap.sh --validate
   ```

2. **Verify Isolation**
   ```bash
   # Test external connectivity (should fail)
   ping google.com    # Should timeout
   curl http://google.com    # Should fail
   nslookup google.com 8.8.8.8    # Should fail
   
   # Test internal connectivity (should work)
   kubectl cluster-info
   curl http://localhost:5000/v2/
   ```

### Phase 3: Deployment Testing

1. **Deploy KubeChat in Air-Gap Mode**
   ```bash
   # Create test namespace
   kubectl create namespace kubechat-airgap
   
   # Deploy using air-gap values
   helm install kubechat-airgap ./deploy/helm/kubechat \
     -f deploy/helm/kubechat/values-airgap-test.yaml \
     -n kubechat-airgap
   ```

2. **Run Comprehensive Tests**
   ```bash
   # Execute full test suite
   ./scripts/test-airgap.sh --verbose
   
   # Monitor test progress
   tail -f logs/airgap-test_*.log
   ```

### Phase 4: Validation and Verification

1. **Validate Deployment Health**
   ```bash
   # Run deployment validation
   ./scripts/validate-airgap.sh --verbose
   
   # Check specific components
   kubectl get pods,svc,pvc -n kubechat-airgap
   ```

2. **Functional Testing**
   ```bash
   # Test API Gateway
   kubectl port-forward -n kubechat-airgap svc/kubechat-api-gateway 8080:8080 &
   curl http://localhost:8080/health
   
   # Test Web Frontend  
   kubectl port-forward -n kubechat-airgap svc/kubechat-web 3000:80 &
   curl http://localhost:3000/
   ```

### Phase 5: Troubleshooting (If Needed)

1. **Run Diagnostics**
   ```bash
   # Interactive troubleshooting
   ./scripts/troubleshoot-airgap.sh
   
   # Automated diagnostic collection
   ./scripts/troubleshoot-airgap.sh --mode automated --verbose
   ```

2. **Analyze Issues**
   ```bash
   # Check recent events
   kubectl get events -n kubechat-airgap --sort-by='.lastTimestamp'
   
   # Review pod logs
   kubectl logs -l app=kubechat-api-gateway -n kubechat-airgap
   
   # Examine diagnostic bundle
   tar -tzf logs/kubechat-diagnostics_*.tar.gz
   ```

## Common Issues and Solutions

### Image Pull Issues

**Problem**: Pods stuck in `ImagePullBackOff`

**Symptoms**:
```
NAME                           READY   STATUS             RESTARTS   AGE
kubechat-api-gateway-xxx       0/1     ImagePullBackOff   0          5m
```

**Diagnosis**:
```bash
kubectl describe pod kubechat-api-gateway-xxx -n kubechat-airgap
```

**Solutions**:
1. **Verify Image Availability**
   ```bash
   # Check local images
   docker images | grep kubechat
   
   # Ensure images are tagged correctly
   docker tag kubechat/api-gateway:dev localhost:5000/kubechat/api-gateway:airgap
   ```

2. **Fix Image Pull Policy**
   ```bash
   # Update deployment to use Never pull policy
   kubectl patch deployment kubechat-api-gateway -n kubechat-airgap \
     -p '{"spec":{"template":{"spec":{"containers":[{"name":"api-gateway","imagePullPolicy":"Never"}]}}}}'
   ```

3. **Load Images from Bundle**
   ```bash
   # If using image bundle
   ./scripts/load-images.sh
   ```

### Network Connectivity Issues

**Problem**: Services cannot communicate

**Symptoms**:
- API Gateway cannot reach database
- Web frontend cannot reach API Gateway
- External connectivity working (air-gap violation)

**Diagnosis**:
```bash
# Test network isolation
./scripts/simulate-airgap.sh --validate

# Check service endpoints
kubectl get endpoints -n kubechat-airgap

# Test internal connectivity
kubectl run nettest --image=nicolaka/netshoot -n kubechat-airgap --rm -it -- /bin/bash
```

**Solutions**:
1. **Fix Network Isolation**
   ```bash
   # Restart air-gap simulation
   sudo ./scripts/simulate-airgap.sh --stop
   sudo ./scripts/simulate-airgap.sh --start
   ```

2. **Check Network Policies**
   ```bash
   # Review network policies
   kubectl get networkpolicy -n kubechat-airgap
   
   # Temporarily disable for testing
   kubectl delete networkpolicy --all -n kubechat-airgap
   ```

3. **Verify Service Configuration**
   ```bash
   # Check service selectors
   kubectl describe service kubechat-api-gateway -n kubechat-airgap
   
   # Verify pod labels
   kubectl get pods -n kubechat-airgap --show-labels
   ```

### Resource Constraints

**Problem**: Pods pending due to insufficient resources

**Symptoms**:
```
NAME                     READY   STATUS    RESTARTS   AGE
kubechat-postgres-xxx    0/1     Pending   0          10m
```

**Diagnosis**:
```bash
kubectl describe pod kubechat-postgres-xxx -n kubechat-airgap
kubectl top nodes
kubectl describe nodes
```

**Solutions**:
1. **Use Minimal Configuration**
   ```bash
   # Deploy with minimal resources
   helm upgrade kubechat-airgap ./deploy/helm/kubechat \
     -f deploy/helm/kubechat/values-minimal.yaml \
     -n kubechat-airgap
   ```

2. **Adjust Resource Limits**
   ```bash
   # Edit deployment to reduce resource requests
   kubectl edit deployment kubechat-api-gateway -n kubechat-airgap
   ```

### Storage Issues

**Problem**: PVCs not bound

**Symptoms**:
```
NAME                STATUS    VOLUME   CAPACITY   ACCESS MODES   AGE
data-postgres-0     Pending                                      5m
```

**Diagnosis**:
```bash
kubectl describe pvc data-postgres-0 -n kubechat-airgap
kubectl get pv
kubectl get storageclass
```

**Solutions**:
1. **Use Local Storage**
   ```bash
   # Create local persistent volume
   kubectl apply -f - <<EOF
   apiVersion: v1
   kind: PersistentVolume
   metadata:
     name: local-pv
   spec:
     capacity:
       storage: 10Gi
     accessModes:
     - ReadWriteOnce
     persistentVolumeReclaimPolicy: Retain
     hostPath:
       path: /tmp/kubechat-data
   EOF
   ```

2. **Disable Persistence for Testing**
   ```bash
   # Use ephemeral storage
   helm upgrade kubechat-airgap ./deploy/helm/kubechat \
     -f deploy/helm/kubechat/values-airgap-test.yaml \
     --set postgresql.primary.persistence.enabled=false \
     --set redis.master.persistence.enabled=false \
     -n kubechat-airgap
   ```

## Test Automation

### CI/CD Integration

For automated testing in CI/CD pipelines:

```yaml
# .github/workflows/airgap-test.yml
name: Air-Gap Testing
on:
  pull_request:
    paths:
      - 'deploy/**'
      - 'scripts/**'

jobs:
  airgap-test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Kubernetes
      uses: helm/kind-action@v1.4.0
      
    - name: Setup Local Registry
      run: |
        docker run -d -p 5000:5000 --name registry registry:2
        
    - name: Build Images
      run: ./scripts/build-dev-images.sh --airgap
      
    - name: Run Air-Gap Tests
      run: |
        sudo ./scripts/simulate-airgap.sh --start
        ./scripts/test-airgap.sh --no-cleanup
        
    - name: Collect Logs
      if: failure()
      run: ./scripts/troubleshoot-airgap.sh --mode automated
      
    - name: Upload Diagnostics
      if: failure()
      uses: actions/upload-artifact@v3
      with:
        name: airgap-diagnostics
        path: logs/kubechat-diagnostics_*.tar.gz
```

### Continuous Monitoring

For ongoing air-gap environment monitoring:

```bash
#!/bin/bash
# monitor-airgap.sh - Continuous air-gap monitoring

while true; do
    echo "$(date): Running air-gap validation..."
    
    if ./scripts/validate-airgap.sh --no-output; then
        echo "$(date): ✅ Air-gap deployment healthy"
    else
        echo "$(date): ❌ Air-gap validation failed"
        
        # Send alert (customize as needed)
        echo "Air-gap validation failed at $(date)" | \
          mail -s "KubeChat Air-Gap Alert" admin@company.com
        
        # Collect diagnostics
        ./scripts/troubleshoot-airgap.sh --mode automated --no-logs
    fi
    
    sleep 300  # Check every 5 minutes
done
```

## Security Considerations

### Air-Gap Security Validation

1. **Network Isolation Verification**
   ```bash
   # Ensure no external network access
   kubectl run security-test --image=nicolaka/netshoot \
     -n kubechat-airgap --rm -it -- /bin/bash
   
   # Inside pod, test external access (should all fail)
   ping google.com
   nslookup google.com 8.8.8.8
   curl -I https://google.com
   wget -O /dev/null http://example.com
   ```

2. **Image Security Scanning**
   ```bash
   # Scan images for vulnerabilities (before air-gap deployment)
   docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
     aquasec/trivy image localhost:5000/kubechat/api-gateway:airgap
   ```

3. **Certificate Management**
   ```bash
   # Use internal CA for air-gap environments
   kubectl create secret tls kubechat-tls \
     --cert=internal-ca.crt \
     --key=internal-ca.key \
     -n kubechat-airgap
   ```

### Compliance Validation

For regulated environments:

1. **Audit Trail Verification**
   ```bash
   # Ensure all actions are logged
   kubectl logs -l app=kubechat-audit-service -n kubechat-airgap
   
   # Verify tamper-proof audit storage
   ./scripts/validate-airgap.sh --no-network --no-images --only-security
   ```

2. **Data Residency Confirmation**
   ```bash
   # Ensure no data leaves the air-gap environment
   kubectl get pods -n kubechat-airgap -o wide
   kubectl describe persistentvolumes
   ```

## Performance Testing

### Load Testing in Air-Gap

```bash
# Create load test pod
kubectl run load-test --image=busybox \
  -n kubechat-airgap --rm -it -- /bin/sh

# Inside pod, generate load
while true; do
  wget -O /dev/null http://kubechat-api-gateway:8080/health
  sleep 0.1
done
```

### Resource Monitoring

```bash
# Monitor resource usage during testing
kubectl top pods -n kubechat-airgap
kubectl top nodes

# Get detailed metrics
kubectl describe pod kubechat-api-gateway-xxx -n kubechat-airgap
```

## Documentation and Reporting

### Test Results Documentation

Each test run should produce comprehensive documentation:

1. **Test Summary Report**
   - Test execution date and duration
   - Environment configuration
   - Test results summary
   - Issues identified and resolutions

2. **Technical Details**
   - Network isolation validation results
   - Image availability confirmation
   - Service health checks
   - Performance metrics

3. **Compliance Evidence**
   - Air-gap effectiveness proof
   - Security policy compliance
   - Audit trail integrity
   - Data residency confirmation

### Report Generation

```bash
# Generate comprehensive test report
./scripts/test-airgap.sh --generate-report

# Create validation report
./scripts/validate-airgap.sh --report-format html

# Collect full diagnostic bundle
./scripts/troubleshoot-airgap.sh --mode report --verbose
```

## Best Practices

### Before Testing
- [ ] Verify all dependencies are available
- [ ] Build and tag all required images
- [ ] Start local registry and verify accessibility
- [ ] Backup any important data
- [ ] Document baseline configuration

### During Testing
- [ ] Monitor test progress continuously
- [ ] Capture logs and metrics
- [ ] Validate each test phase before proceeding
- [ ] Document any issues encountered
- [ ] Take snapshots of working configurations

### After Testing
- [ ] Generate comprehensive test reports
- [ ] Archive test artifacts and logs
- [ ] Document lessons learned
- [ ] Update procedures based on findings
- [ ] Clean up test environments

### Ongoing Maintenance
- [ ] Regular validation runs
- [ ] Update test scenarios for new features
- [ ] Monitor for configuration drift
- [ ] Refresh image bundles periodically
- [ ] Review and update security policies

## Conclusion

Air-gap testing is critical for validating KubeChat deployments in secure, isolated environments. The provided scripts and procedures ensure comprehensive testing coverage while maintaining security and compliance requirements.

For additional support or questions about air-gap testing:

1. Review the troubleshooting guide: `./scripts/troubleshoot-airgap.sh --help`
2. Check diagnostic logs: `logs/airgap-*`
3. Examine deployment documentation: `deploy/helm/kubechat/CONFIG.md`
4. Run validation tests: `./scripts/validate-airgap.sh --verbose`

Regular air-gap testing ensures deployment reliability and security compliance in the most demanding environments.