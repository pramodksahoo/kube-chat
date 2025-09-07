# Operational Procedures

## Overview

This document outlines comprehensive operational procedures for managing KubeChat in production environments, including deployment processes, monitoring, incident response, and maintenance procedures.

## Table of Contents

1. [Deployment Procedures](#deployment-procedures)
2. [Monitoring and Alerting](#monitoring-and-alerting)
3. [Incident Response](#incident-response)
4. [Backup and Recovery](#backup-and-recovery)
5. [Security Operations](#security-operations)
6. [Performance Management](#performance-management)
7. [Change Management](#change-management)
8. [Capacity Planning](#capacity-planning)
9. [Maintenance Procedures](#maintenance-procedures)
10. [Disaster Recovery](#disaster-recovery)

## Deployment Procedures

### Pre-Deployment Checklist

#### Development Environment Validation
```yaml
pre_deployment_checks:
  - name: "Unit Tests"
    command: "make test-unit"
    success_criteria: "100% pass rate"
    
  - name: "Integration Tests"  
    command: "make test-integration"
    success_criteria: "100% pass rate"
    
  - name: "Security Scan"
    command: "trivy image kubechat:latest"
    success_criteria: "No HIGH or CRITICAL vulnerabilities"
    
  - name: "Code Quality"
    command: "golangci-lint run"
    success_criteria: "No linting errors"
    
  - name: "Load Testing"
    command: "k6 run load-test.js"
    success_criteria: "< 500ms p95 latency, < 1% error rate"
```

#### Staging Environment Validation
```yaml
staging_validation:
  - name: "Deployment Health"
    check: "All pods running and ready"
    timeout: "10 minutes"
    
  - name: "Database Connectivity"
    check: "Connection pool healthy"
    timeout: "2 minutes"
    
  - name: "Authentication Flow"
    check: "OIDC/SAML login successful"
    timeout: "5 minutes"
    
  - name: "API Endpoints"
    check: "All health checks passing"
    timeout: "2 minutes"
    
  - name: "Performance Baseline"
    check: "Response times within SLA"
    timeout: "10 minutes"
```

### Blue/Green Deployment Process

#### Step 1: Green Environment Preparation
```bash
#!/bin/bash
# prepare-green-deployment.sh

set -euo pipefail

# Configuration
NAMESPACE="kubechat-system"
GREEN_DEPLOYMENT="kubechat-api-gateway-green"
BLUE_DEPLOYMENT="kubechat-api-gateway-blue"
IMAGE_TAG="${1:-latest}"

echo "Starting green deployment preparation..."

# Create green deployment
kubectl apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${GREEN_DEPLOYMENT}
  namespace: ${NAMESPACE}
  labels:
    app.kubernetes.io/name: kubechat
    app.kubernetes.io/component: api-gateway
    app.kubernetes.io/version: "${IMAGE_TAG}"
    deployment-slot: green
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: kubechat
      app.kubernetes.io/component: api-gateway
      deployment-slot: green
  template:
    metadata:
      labels:
        app.kubernetes.io/name: kubechat
        app.kubernetes.io/component: api-gateway
        deployment-slot: green
    spec:
      containers:
      - name: api-gateway
        image: harbor.company.com/kubechat/api-gateway:${IMAGE_TAG}
        # ... rest of container spec
EOF

# Wait for green deployment to be ready
kubectl rollout status deployment/${GREEN_DEPLOYMENT} -n ${NAMESPACE} --timeout=600s

echo "Green deployment ready. Performing health checks..."

# Health check green deployment
kubectl run temp-curl --rm -i --tty --image=curlimages/curl -- \
  curl -f http://${GREEN_DEPLOYMENT}.${NAMESPACE}.svc.cluster.local/health/ready

echo "Green deployment health check passed."
```

#### Step 2: Traffic Switching
```bash
#!/bin/bash
# switch-traffic.sh

set -euo pipefail

NAMESPACE="kubechat-system"
SERVICE_NAME="kubechat-api-gateway"
GREEN_DEPLOYMENT="kubechat-api-gateway-green"

echo "Switching traffic to green deployment..."

# Update service to point to green deployment
kubectl patch service ${SERVICE_NAME} -n ${NAMESPACE} -p '{
  "spec": {
    "selector": {
      "app.kubernetes.io/name": "kubechat",
      "app.kubernetes.io/component": "api-gateway",
      "deployment-slot": "green"
    }
  }
}'

# Monitor for 5 minutes
echo "Monitoring green deployment for 5 minutes..."
sleep 300

# Check error rate
ERROR_RATE=$(kubectl exec -n monitoring-system prometheus-0 -- \
  promtool query instant \
  'rate(http_requests_total{job="kubechat-api-gateway",code=~"5.."}[5m])' \
  | grep -o '[0-9.]*' | head -1)

if (( $(echo "$ERROR_RATE > 0.01" | bc -l) )); then
  echo "High error rate detected: $ERROR_RATE"
  echo "Rolling back to blue deployment..."
  ./rollback-to-blue.sh
  exit 1
fi

echo "Traffic switch successful. Cleaning up blue deployment..."
```

#### Step 3: Blue Deployment Cleanup
```bash
#!/bin/bash
# cleanup-blue-deployment.sh

set -euo pipefail

NAMESPACE="kubechat-system"
BLUE_DEPLOYMENT="kubechat-api-gateway-blue"

echo "Cleaning up blue deployment..."

# Scale down blue deployment
kubectl scale deployment ${BLUE_DEPLOYMENT} -n ${NAMESPACE} --replicas=0

# Wait 10 minutes before complete removal
sleep 600

# Remove blue deployment
kubectl delete deployment ${BLUE_DEPLOYMENT} -n ${NAMESPACE} --ignore-not-found=true

echo "Blue deployment cleanup complete."
```

### Canary Deployment Process

#### Canary Configuration
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: kubechat-api-gateway
  namespace: kubechat-system
spec:
  replicas: 10
  strategy:
    canary:
      maxSurge: "25%"
      maxUnavailable: 0
      steps:
      - setWeight: 5
      - pause: {duration: 2m}
      - setWeight: 10
      - pause: {duration: 5m}
      - setWeight: 25
      - pause: {duration: 10m}
      - setWeight: 50
      - pause: {duration: 10m}
      - setWeight: 75
      - pause: {duration: 5m}
      analysis:
        templates:
        - templateName: success-rate
        args:
        - name: service-name
          value: kubechat-api-gateway
      trafficRouting:
        nginx:
          stableService: kubechat-api-gateway-stable
          canaryService: kubechat-api-gateway-canary
  selector:
    matchLabels:
      app.kubernetes.io/name: kubechat
      app.kubernetes.io/component: api-gateway
  template:
    # ... pod template spec
---
apiVersion: argoproj.io/v1alpha1
kind: AnalysisTemplate
metadata:
  name: success-rate
  namespace: kubechat-system
spec:
  args:
  - name: service-name
  metrics:
  - name: success-rate
    interval: 30s
    successCondition: result[0] >= 0.95
    failureLimit: 3
    provider:
      prometheus:
        address: http://prometheus.monitoring-system.svc.cluster.local:9090
        query: |
          sum(rate(http_requests_total{service="{{args.service-name}}",code!~"5.*"}[2m])) / 
          sum(rate(http_requests_total{service="{{args.service-name}}"}[2m]))
```

## Monitoring and Alerting

### Key Performance Indicators (KPIs)

#### Application Metrics
```yaml
application_metrics:
  availability:
    metric: "up"
    target: "> 99.9%"
    alert_threshold: "< 99.5%"
    
  response_time:
    metric: "http_request_duration_seconds"
    target: "p95 < 500ms"
    alert_threshold: "p95 > 1s"
    
  error_rate:
    metric: "http_requests_total"
    target: "< 0.1%"
    alert_threshold: "> 1%"
    
  throughput:
    metric: "http_requests_total"
    target: "> 1000 RPS"
    alert_threshold: "< 500 RPS"
```

#### Infrastructure Metrics
```yaml
infrastructure_metrics:
  cpu_utilization:
    metric: "container_cpu_usage_seconds_total"
    target: "< 70%"
    alert_threshold: "> 85%"
    
  memory_utilization:
    metric: "container_memory_usage_bytes"
    target: "< 80%"
    alert_threshold: "> 90%"
    
  disk_utilization:
    metric: "node_filesystem_avail_bytes"
    target: "> 20%"
    alert_threshold: "< 10%"
    
  network_latency:
    metric: "probe_duration_seconds"
    target: "< 100ms"
    alert_threshold: "> 500ms"
```

### Alert Runbooks

#### High Error Rate Alert
```yaml
alert_name: "KubeChatHighErrorRate"
severity: "warning"
runbook_url: "https://wiki.company.com/kubechat/runbooks/high-error-rate"

investigation_steps:
  - step: 1
    action: "Check recent deployments"
    command: "kubectl get deployment kubechat-api-gateway -o yaml | grep image"
    
  - step: 2
    action: "Review application logs"
    command: "kubectl logs -l app.kubernetes.io/name=kubechat --tail=100"
    
  - step: 3
    action: "Check downstream dependencies"
    command: "kubectl get pods -l app=postgresql -o wide"
    
  - step: 4
    action: "Verify configuration"
    command: "kubectl get configmap kubechat-config -o yaml"

mitigation_steps:
  - step: 1
    action: "Scale up replicas if needed"
    command: "kubectl scale deployment kubechat-api-gateway --replicas=10"
    
  - step: 2
    action: "Restart unhealthy pods"
    command: "kubectl rollout restart deployment kubechat-api-gateway"
    
  - step: 3
    action: "Rollback if recent deployment"
    command: "kubectl rollout undo deployment kubechat-api-gateway"
```

#### Pod Crash Looping Alert
```yaml
alert_name: "KubeChatPodCrashLooping"
severity: "critical"

investigation_steps:
  - step: 1
    action: "Check pod events"
    command: "kubectl describe pod [POD_NAME] -n kubechat-system"
    
  - step: 2
    action: "Review container logs"
    command: "kubectl logs [POD_NAME] -n kubechat-system --previous"
    
  - step: 3
    action: "Check resource constraints"
    command: "kubectl top pod [POD_NAME] -n kubechat-system"
    
  - step: 4
    action: "Verify secrets and configmaps"
    command: "kubectl get secret,configmap -n kubechat-system"

mitigation_steps:
  - step: 1
    action: "Increase resource limits if OOMKilled"
    command: "kubectl patch deployment kubechat-api-gateway -p '{\"spec\":{\"template\":{\"spec\":{\"containers\":[{\"name\":\"api-gateway\",\"resources\":{\"limits\":{\"memory\":\"1Gi\"}}}]}}}}'"
    
  - step: 2
    action: "Update failing pod with debug image"
    command: "kubectl debug [POD_NAME] -it --image=busybox"
```

## Incident Response

### Incident Classification

#### Severity Levels
```yaml
severity_1:
  definition: "Complete service outage"
  examples:
    - "All API endpoints returning 5xx errors"
    - "Database completely unavailable"
    - "Security breach confirmed"
  response_time: "15 minutes"
  escalation_time: "30 minutes"
  
severity_2:
  definition: "Significant degradation"
  examples:
    - "50% of requests failing"
    - "Response time > 5 seconds"
    - "Single AZ failure"
  response_time: "30 minutes"
  escalation_time: "1 hour"
  
severity_3:
  definition: "Minor degradation"
  examples:
    - "Increased error rate < 5%"
    - "Single pod failures"
    - "Non-critical feature unavailable"
  response_time: "2 hours"
  escalation_time: "4 hours"
```

### Incident Response Process

#### Initial Response (0-15 minutes)
```yaml
initial_response:
  - step: 1
    action: "Acknowledge alert"
    responsible: "On-call engineer"
    
  - step: 2
    action: "Assess severity"
    responsible: "On-call engineer"
    
  - step: 3
    action: "Start war room if Sev 1/2"
    responsible: "On-call engineer"
    
  - step: 4
    action: "Notify stakeholders"
    responsible: "Incident commander"
    
  - step: 5
    action: "Begin investigation"
    responsible: "Technical lead"
```

#### Investigation and Mitigation (15-60 minutes)
```yaml
investigation_process:
  - step: 1
    action: "Collect system state"
    tools: ["kubectl", "prometheus", "grafana"]
    
  - step: 2
    action: "Identify root cause"
    approach: "Timeline analysis, log correlation"
    
  - step: 3
    action: "Implement immediate mitigation"
    options: ["rollback", "scale up", "restart services"]
    
  - step: 4
    action: "Monitor impact"
    metrics: ["error rate", "response time", "availability"]
```

### Communication Templates

#### Incident Declaration
```markdown
**INCIDENT DECLARED - SEV {{ SEVERITY }}**

**Summary:** {{ Brief description of the issue }}

**Impact:** 
- Services affected: {{ List of affected services }}
- User impact: {{ Description of user-facing impact }}
- Started: {{ Incident start time }}

**Status:** INVESTIGATING

**War Room:** {{ Link to communication channel }}

**Next Update:** {{ Time of next scheduled update }}
```

#### Status Update
```markdown
**INCIDENT UPDATE - SEV {{ SEVERITY }}**

**Current Status:** {{ INVESTIGATING | MITIGATING | MONITORING | RESOLVED }}

**Progress:**
- {{ Action taken 1 }}
- {{ Action taken 2 }}

**Next Steps:**
- {{ Planned action 1 }}
- {{ Planned action 2 }}

**Impact Change:** {{ Any change in user impact }}

**Next Update:** {{ Time of next scheduled update }}
```

## Backup and Recovery

### Automated Backup Procedures

#### Database Backup Configuration
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: kubechat-system
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: postgres-backup
            image: postgres:16
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-credentials
                  key: password
            command:
            - /bin/bash
            - -c
            - |
              DATE=$(date +%Y%m%d_%H%M%S)
              pg_dump -h postgres-primary -U kubechat_user kubechat_prod | \
              gzip > /backup/kubechat_backup_${DATE}.sql.gz
              
              # Upload to S3
              aws s3 cp /backup/kubechat_backup_${DATE}.sql.gz \
                s3://kubechat-backups/postgres/daily/
              
              # Cleanup local files older than 7 days
              find /backup -name "kubechat_backup_*.sql.gz" -mtime +7 -delete
            volumeMounts:
            - name: backup-storage
              mountPath: /backup
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: backup-pvc
          restartPolicy: OnFailure
```

#### Application Configuration Backup
```bash
#!/bin/bash
# backup-kubernetes-configs.sh

set -euo pipefail

BACKUP_DIR="/backup/kubernetes/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup all KubeChat resources
kubectl get all,configmap,secret,pvc,ingress -n kubechat-system -o yaml > \
  "$BACKUP_DIR/kubechat-resources.yaml"

# Backup custom resource definitions
kubectl get crd -o yaml > "$BACKUP_DIR/custom-resources.yaml"

# Backup RBAC configurations
kubectl get clusterrole,clusterrolebinding,role,rolebinding -o yaml > \
  "$BACKUP_DIR/rbac-config.yaml"

# Compress and upload to S3
tar -czf "$BACKUP_DIR.tar.gz" -C "/backup/kubernetes" "$(basename $BACKUP_DIR)"
aws s3 cp "$BACKUP_DIR.tar.gz" s3://kubechat-backups/kubernetes/

# Cleanup old backups (keep 30 days)
find /backup/kubernetes -name "*.tar.gz" -mtime +30 -delete

echo "Kubernetes configuration backup completed: $BACKUP_DIR.tar.gz"
```

### Recovery Procedures

#### Database Point-in-Time Recovery
```bash
#!/bin/bash
# postgres-point-in-time-recovery.sh

set -euo pipefail

RECOVERY_TIME="${1}"  # Format: 2024-01-01 12:00:00
TARGET_DATABASE="kubechat_prod_recovery"

echo "Starting point-in-time recovery to: $RECOVERY_TIME"

# Create recovery target
kubectl apply -f - <<EOF
apiVersion: postgresql.cnpg.io/v1
kind: Cluster
metadata:
  name: kubechat-postgres-recovery
  namespace: kubechat-system
spec:
  instances: 1
  
  bootstrap:
    recovery:
      backup:
        name: kubechat-postgres-backup-$(date +%Y%m%d)
      recoveryTarget:
        targetTime: "$RECOVERY_TIME"
        
  storage:
    size: 500Gi
    storageClass: fast-ssd
EOF

# Wait for recovery to complete
kubectl wait --for=condition=Ready cluster/kubechat-postgres-recovery \
  -n kubechat-system --timeout=1800s

echo "Point-in-time recovery completed successfully"
```

#### Application Recovery Process
```bash
#!/bin/bash
# application-recovery.sh

set -euo pipefail

BACKUP_FILE="${1}"
NAMESPACE="kubechat-system"

echo "Starting application recovery from: $BACKUP_FILE"

# Download backup from S3
aws s3 cp "s3://kubechat-backups/kubernetes/$BACKUP_FILE" ./backup.tar.gz
tar -xzf backup.tar.gz

# Create namespace if it doesn't exist
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Apply configurations in order
kubectl apply -f backup/custom-resources.yaml
kubectl apply -f backup/rbac-config.yaml
kubectl apply -f backup/kubechat-resources.yaml

# Wait for all deployments to be ready
kubectl wait --for=condition=Available deployment --all -n "$NAMESPACE" --timeout=600s

echo "Application recovery completed successfully"
```

## Security Operations

### Security Monitoring

#### Security Event Detection
```yaml
security_alerts:
  - name: "Failed Authentication Attempts"
    query: 'increase(kubechat_auth_failures_total[5m]) > 100'
    severity: "warning"
    action: "Review authentication logs"
    
  - name: "Privilege Escalation Attempt"
    query: 'increase(kubechat_rbac_denials_total{reason="forbidden"}[5m]) > 50'
    severity: "critical"
    action: "Immediate investigation required"
    
  - name: "Unusual API Usage"
    query: 'rate(kubechat_api_requests_total[5m]) > 10000'
    severity: "warning"
    action: "Check for potential DDoS"
```

#### Security Audit Procedures
```bash
#!/bin/bash
# security-audit.sh

set -euo pipefail

AUDIT_DATE=$(date +%Y%m%d)
REPORT_FILE="security_audit_$AUDIT_DATE.txt"

echo "KubeChat Security Audit Report - $AUDIT_DATE" > "$REPORT_FILE"
echo "===========================================" >> "$REPORT_FILE"

# Check for pods running as root
echo "Pods running as root:" >> "$REPORT_FILE"
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{.spec.securityContext.runAsUser}{"\n"}{end}' | \
  grep " 0$" >> "$REPORT_FILE"

# Check for privileged containers
echo -e "\nPrivileged containers:" >> "$REPORT_FILE"
kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.securityContext.privileged}{" "}{$.metadata.namespace}{" "}{$.metadata.name}{" "}{.name}{"\n"}{end}{end}' | \
  grep "^true" >> "$REPORT_FILE"

# Check service accounts with cluster-admin
echo -e "\nService accounts with cluster-admin:" >> "$REPORT_FILE"
kubectl get clusterrolebinding -o jsonpath='{range .items[?(@.roleRef.name=="cluster-admin")]}{.subjects[*].name}{" "}{.subjects[*].namespace}{"\n"}{end}' >> "$REPORT_FILE"

# Upload report to secure storage
aws s3 cp "$REPORT_FILE" s3://kubechat-security-reports/audits/ --sse AES256

echo "Security audit completed: $REPORT_FILE"
```

This operational procedures document provides comprehensive guidance for managing KubeChat in production with enterprise-grade operational standards.