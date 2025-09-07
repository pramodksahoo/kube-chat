# KubeChat Operational Debugging Guide

## Introduction

This comprehensive debugging guide provides systematic troubleshooting procedures for KubeChat production issues. It includes service-specific runbooks, common failure scenarios, debugging tools, and escalation procedures to ensure rapid issue resolution.

### Target Audience
- **DevOps Engineers** managing KubeChat deployments
- **Site Reliability Engineers** responsible for system availability  
- **Support Engineers** handling customer issues
- **Development Teams** investigating complex bugs

### Change Log
| Date | Version | Description | Author |
|------|---------|-------------|---------|
| 2025-09-05 | 1.0 | Initial operational debugging guide | Winston (Architect) |

---

## Quick Reference - Emergency Response

### Severity Classification
```yaml
severity_levels:
  P0_critical:
    description: "Complete system outage, data loss, security breach"
    response_time: "< 15 minutes"
    escalation: "Immediate to on-call engineer and management"
    
  P1_high:
    description: "Major functionality broken, high user impact"
    response_time: "< 1 hour" 
    escalation: "On-call engineer within 30 minutes"
    
  P2_medium:
    description: "Partial functionality affected, moderate user impact"
    response_time: "< 4 hours"
    escalation: "Next business day if unresolved"
    
  P3_low:
    description: "Minor issues, low user impact"
    response_time: "< 24 hours"
    escalation: "Weekly review if unresolved"
```

### Emergency Commands
```bash
# Quick system health check
kubectl get pods -n kubechat-system --no-headers | grep -v Running

# Check service logs for errors
kubectl logs -n kubechat-system deployment/api-gateway --tail=100 | grep -i error

# Scale service replicas for immediate relief
kubectl scale deployment/api-gateway -n kubechat-system --replicas=5

# Emergency maintenance mode
kubectl patch deployment/web-app -n kubechat-system -p '{"spec":{"replicas":0}}'
```

---

## Service-Specific Debugging

### API Gateway Service

#### Common Issues and Solutions

**Issue: High Response Times (>500ms)**
```yaml
symptoms:
  - Response times above 500ms in monitoring
  - User complaints about slow interface
  - Increased CPU usage on API Gateway pods

investigation_steps:
  1. Check current resource usage:
     command: "kubectl top pods -n kubechat-system -l app=api-gateway"
     
  2. Review recent traffic patterns:
     command: "kubectl logs -n kubechat-system deployment/api-gateway --tail=1000 | grep -E 'duration|latency'"
     
  3. Examine connection pool status:
     endpoint: "GET /metrics"
     metric: "http_request_duration_histogram"
     
  4. Check downstream service health:
     command: "kubectl get pods -n kubechat-system -l tier=backend"

resolution_steps:
  immediate:
    - Scale API Gateway replicas: "kubectl scale deployment/api-gateway --replicas=5"
    - Restart unhealthy pods: "kubectl delete pod -l app=api-gateway"
    
  short_term:
    - Review and optimize database queries
    - Increase connection pool limits
    - Enable response caching for static endpoints
    
  long_term:
    - Implement request rate limiting
    - Add circuit breaker for downstream services
    - Optimize hot code paths
```

**Issue: WebSocket Connection Failures**
```yaml
symptoms:
  - Chat interface shows "disconnected" status
  - Users unable to send messages
  - High WebSocket error rate in metrics

investigation_steps:
  1. Check WebSocket endpoint health:
     command: "kubectl exec -it deployment/api-gateway -- netstat -an | grep :8080"
     
  2. Review WebSocket-specific logs:
     command: "kubectl logs -n kubechat-system deployment/api-gateway | grep -i websocket"
     
  3. Verify Redis connectivity (session store):
     command: "kubectl exec -it deployment/redis -- redis-cli ping"
     
  4. Check ingress controller logs:
     command: "kubectl logs -n ingress-nginx deployment/ingress-nginx-controller | grep websocket"

resolution_steps:
  immediate:
    - Restart API Gateway pods with WebSocket issues
    - Verify Redis service is accessible
    - Check ingress WebSocket configuration
    
  verification:
    - Test WebSocket connection manually:
      "wscat -c wss://your-domain.com/chat/test-session"
    - Monitor connection success rate in metrics
```

### Natural Language Processing Service

#### Common Issues and Solutions

**Issue: Command Translation Failures**
```yaml
symptoms:
  - NLP service returning empty or invalid commands
  - High error rate on /nlp/process endpoint
  - Users reporting "unable to understand request"

investigation_steps:
  1. Check NLP service health:
     command: "kubectl get pods -n kubechat-system -l app=nlp-service"
     
  2. Review recent translation requests:
     command: "kubectl logs -n kubechat-system deployment/nlp-service --tail=200 | grep -A5 -B5 'translation error'"
     
  3. Test NLP endpoint directly:
     command: |
       kubectl exec -it deployment/api-gateway -- curl -X POST \
         http://nlp-service:8080/process \
         -H "Content-Type: application/json" \
         -d '{"query": "show me all pods", "user_id": "test"}'
         
  4. Check external AI service connectivity:
     endpoint: "OpenAI API or local Ollama service"

resolution_steps:
  immediate:
    - Restart NLP service pods
    - Verify external AI service credentials
    - Check network connectivity to external services
    
  debugging_commands:
    - Check Ollama status: "kubectl exec deployment/nlp-service -- ollama list"
    - Test OpenAI connectivity: "kubectl exec deployment/nlp-service -- curl https://api.openai.com/v1/models"
    
  fallback_procedures:
    - Switch to backup AI service if configured
    - Enable manual command mode for critical users
    - Scale down NLP service and restart with debug logging
```

**Issue: High Processing Latency (>2s)**
```yaml
symptoms:
  - NLP requests taking longer than 2 seconds
  - Timeout errors from frontend
  - Queue buildup in NLP service

investigation_steps:
  1. Check NLP service resource usage:
     command: "kubectl top pods -n kubechat-system -l app=nlp-service"
     
  2. Monitor request queue depth:
     metric: "nlp_request_queue_depth"
     
  3. Analyze processing time distribution:
     command: "kubectl logs -n kubechat-system deployment/nlp-service | grep 'processing_time' | tail -50"
     
  4. Check AI service response times:
     endpoint: "External AI API latency metrics"

resolution_steps:
  immediate:
    - Scale up NLP service replicas
    - Enable request caching for common queries
    - Implement request timeouts to prevent blocking
    
  optimization:
    - Tune AI model parameters for speed
    - Implement response streaming for long requests
    - Add load balancing between multiple AI providers
```

### Audit Service

#### Common Issues and Solutions

**Issue: Audit Log Ingestion Failures**
```yaml
symptoms:
  - Missing audit events in database
  - Audit service pod crashes or restarts
  - Database connection errors

investigation_steps:
  1. Check audit service pod status:
     command: "kubectl describe pods -n kubechat-system -l app=audit-service"
     
  2. Review audit service logs:
     command: "kubectl logs -n kubechat-system deployment/audit-service --tail=500"
     
  3. Test database connectivity:
     command: |
       kubectl exec -it deployment/audit-service -- pg_isready \
         -h postgres-service -p 5432 -U kubechat
         
  4. Check database disk space:
     command: "kubectl exec -it statefulset/postgres -- df -h /var/lib/postgresql/data"

resolution_steps:
  immediate:
    - Restart audit service if crashed
    - Verify database connection parameters
    - Check database credentials in secrets
    
  database_recovery:
    - Restore from backup if data corruption detected
    - Scale up database resources if performance issues
    - Clean up old audit logs if disk space full
    
  verification:
    - Generate test audit event and verify ingestion
    - Check audit log completeness for recent time period
```

**Issue: SIEM Export Failures**
```yaml
symptoms:
  - SIEM integration not receiving audit events
  - Export job failures in logs
  - Missing compliance evidence

investigation_steps:
  1. Check SIEM export job status:
     command: "kubectl get jobs -n kubechat-system -l component=siem-export"
     
  2. Review export service logs:
     command: "kubectl logs -n kubechat-system job/siem-export-$(date +%Y%m%d)"
     
  3. Test SIEM endpoint connectivity:
     command: |
       kubectl exec -it deployment/audit-service -- curl -v \
         -X POST https://siem.company.com/api/events \
         -H "Authorization: Bearer $SIEM_TOKEN"
         
  4. Verify audit data format:
     sql: "SELECT * FROM audit_events WHERE created_at > NOW() - INTERVAL '1 hour' LIMIT 5"

resolution_steps:
  immediate:
    - Restart failed export jobs
    - Verify SIEM endpoint availability
    - Check authentication credentials
    
  data_recovery:
    - Re-export missed time periods
    - Verify data integrity in SIEM system
    - Update export job schedule if needed
```

### Kubernetes Operator

#### Common Issues and Solutions

**Issue: Custom Resource Reconciliation Failures**
```yaml
symptoms:
  - KubeChat custom resources not updating
  - Operator pod in CrashLoopBackOff
  - Commands not executing in cluster

investigation_steps:
  1. Check operator pod status:
     command: "kubectl get pods -n kubechat-system -l app=kubechat-operator"
     
  2. Review operator logs:
     command: "kubectl logs -n kubechat-system deployment/kubechat-operator --tail=200"
     
  3. Check custom resource status:
     command: "kubectl get kubechatcommands -A -o wide"
     
  4. Verify RBAC permissions:
     command: "kubectl auth can-i '*' '*' --as=system:serviceaccount:kubechat-system:kubechat-operator"

resolution_steps:
  immediate:
    - Restart operator deployment
    - Verify service account permissions
    - Check custom resource definitions are installed
    
  rbac_fixes:
    - Update ClusterRole if permissions insufficient
    - Verify RoleBindings are correct
    - Check for conflicting policies
    
  verification:
    - Create test custom resource
    - Monitor reconciliation loop
    - Verify command execution works
```

### Web Application (Frontend)

#### Common Issues and Solutions

**Issue: Application Won't Load**
```yaml
symptoms:
  - White screen or loading spinner indefinitely
  - JavaScript errors in browser console
  - Network errors to API endpoints

investigation_steps:
  1. Check web application pod status:
     command: "kubectl get pods -n kubechat-system -l app=web-app"
     
  2. Test application endpoint:
     command: "curl -I https://kubechat.company.com"
     
  3. Review ingress configuration:
     command: "kubectl describe ingress -n kubechat-system kubechat-ingress"
     
  4. Check browser console for errors:
     browser: "Open DevTools → Console tab"

resolution_steps:
  immediate:
    - Restart web application pods
    - Verify ingress controller status
    - Check TLS certificate validity
    
  frontend_debugging:
    - Enable debug mode in React app
    - Check API endpoint connectivity from browser
    - Verify authentication service integration
    
  browser_issues:
    - Clear browser cache and cookies
    - Test in incognito/private mode
    - Try different browser or device
```

---

## System-Wide Debugging Procedures

### Performance Investigation

**High CPU Usage Across Services**
```bash
#!/bin/bash
# System performance investigation script

echo "=== KubeChat Performance Investigation ==="
echo "Timestamp: $(date)"
echo

echo "1. Pod Resource Usage:"
kubectl top pods -n kubechat-system --sort-by=cpu

echo -e "\n2. Node Resource Availability:"
kubectl top nodes

echo -e "\n3. High CPU Pods (>80%):"
kubectl top pods -n kubecchat-system --no-headers | awk '$2 > 80 {print $1 " " $2}'

echo -e "\n4. Memory Usage by Pod:"
kubectl top pods -n kubechat-system --sort-by=memory

echo -e "\n5. Recent Pod Restarts:"
kubectl get pods -n kubechat-system -o json | jq -r '.items[] | select(.status.containerStatuses[]?.restartCount > 0) | .metadata.name + " " + (.status.containerStatuses[0].restartCount | tostring)'

echo -e "\n6. Service Endpoints Health:"
for svc in api-gateway nlp-service audit-service web-app; do
  echo "Testing $svc..."
  kubectl exec -it deployment/api-gateway -- curl -f -m 10 "http://$svc:8080/health" >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "✅ $svc: Healthy"
  else
    echo "❌ $svc: Unhealthy"
  fi
done
```

### Database Performance Issues
```sql
-- PostgreSQL performance investigation queries

-- Check slow running queries
SELECT 
  query,
  calls,
  total_time,
  mean_time,
  rows
FROM pg_stat_statements 
WHERE mean_time > 1000 
ORDER BY mean_time DESC 
LIMIT 10;

-- Check database connections
SELECT 
  state,
  count(*) as connections
FROM pg_stat_activity 
WHERE datname = 'kubechat'
GROUP BY state;

-- Check table sizes and bloat
SELECT 
  tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables 
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Check index usage
SELECT 
  schemaname,
  tablename,
  indexname,
  idx_scan,
  idx_tup_read,
  idx_tup_fetch
FROM pg_stat_user_indexes 
WHERE idx_scan < 100
ORDER BY idx_scan;
```

### Network Connectivity Issues
```bash
#!/bin/bash
# Network connectivity debugging script

echo "=== Network Connectivity Check ==="

# Test internal service communication
echo "1. Internal Service Connectivity:"
for svc in api-gateway nlp-service audit-service postgres-service redis-service; do
  echo -n "Testing $svc... "
  if kubectl exec -it deployment/api-gateway -- timeout 5 nc -z $svc 8080 2>/dev/null; then
    echo "✅ Reachable"
  else
    echo "❌ Unreachable"
  fi
done

# Test external dependencies
echo -e "\n2. External Dependencies:"
echo -n "OpenAI API... "
kubectl exec -it deployment/nlp-service -- timeout 10 curl -s -I https://api.openai.com >/dev/null
if [ $? -eq 0 ]; then
  echo "✅ Reachable"
else
  echo "❌ Unreachable"
fi

# Test DNS resolution
echo -e "\n3. DNS Resolution:"
for domain in api.openai.com github.com; do
  echo -n "Resolving $domain... "
  kubectl exec -it deployment/api-gateway -- nslookup $domain >/dev/null 2>&1
  if [ $? -eq 0 ]; then
    echo "✅ Success"
  else
    echo "❌ Failed"
  fi
done

# Check network policies
echo -e "\n4. Network Policies:"
kubectl get networkpolicies -n kubechat-system -o wide
```

---

## Monitoring and Alerting Integration

### Key Metrics to Monitor

**Application Metrics:**
```yaml
critical_metrics:
  - name: "http_request_duration_p95"
    threshold: "> 500ms"
    service: "api-gateway"
    
  - name: "websocket_connection_success_rate"
    threshold: "< 95%"
    service: "api-gateway"
    
  - name: "nlp_processing_duration_p95"
    threshold: "> 2000ms"
    service: "nlp-service"
    
  - name: "audit_ingestion_rate"
    threshold: "< 100 events/min"
    service: "audit-service"
    
  - name: "postgres_connection_utilization"
    threshold: "> 80%"
    service: "postgres"

infrastructure_metrics:
  - name: "pod_restart_rate"
    threshold: "> 5 restarts/hour"
    scope: "all services"
    
  - name: "memory_usage_percent"
    threshold: "> 85%"
    scope: "all pods"
    
  - name: "disk_usage_percent"
    threshold: "> 90%"
    scope: "persistent volumes"
```

**Alert Response Runbooks:**
```yaml
alert_responses:
  high_response_time:
    investigation: "Check pod resources, database performance, external dependencies"
    immediate_action: "Scale up affected service, restart unhealthy pods"
    
  websocket_failures:
    investigation: "Check Redis connectivity, ingress configuration, pod health"
    immediate_action: "Restart API Gateway, verify Redis service"
    
  database_issues:
    investigation: "Check connections, slow queries, disk space"
    immediate_action: "Scale database, clean up old data if needed"
    
  pod_crash_loop:
    investigation: "Review pod logs, check resource limits, configuration"
    immediate_action: "Increase resource limits, fix configuration issues"
```

### Log Analysis Commands

**Centralized Logging Queries:**
```bash
# Search for errors across all services (using Loki/LogQL)
logcli query --since=1h '{namespace="kubechat-system"} |= "ERROR"'

# Find authentication failures
logcli query --since=1h '{service="api-gateway"} |= "authentication failed"'

# Monitor database connection issues
logcli query --since=30m '{service="audit-service"} |= "connection refused"'

# Track command execution patterns
logcli query --since=1h '{service="nlp-service"} |= "command translated"'

# Find performance bottlenecks
logcli query --since=1h '{namespace="kubechat-system"} |= "duration" | regexp "duration=(?P<duration>[0-9]+)ms" | unwrap duration | quantile_over_time(0.95, 5m)'
```

---

## Disaster Recovery Procedures

### Complete System Failure

**Recovery Steps:**
```bash
#!/bin/bash
# Disaster recovery script

echo "=== KubeChat Disaster Recovery ==="
echo "Starting recovery at: $(date)"

# Step 1: Verify cluster health
echo "1. Checking cluster health..."
kubectl get nodes
kubectl get pods --all-namespaces | grep -v Running

# Step 2: Restore from backup
echo "2. Restoring database from backup..."
velero restore create kubechat-restore-$(date +%Y%m%d) \
  --from-backup kubechat-daily-$(date -d yesterday +%Y%m%d)

# Step 3: Redeploy services in order
echo "3. Redeploying services..."
kubectl apply -f /path/to/kubechat-operator/
sleep 30

kubectl apply -f /path/to/postgres/
kubectl wait --for=condition=ready pod -l app=postgres --timeout=300s

kubectl apply -f /path/to/redis/
kubectl wait --for=condition=ready pod -l app=redis --timeout=180s

kubectl apply -f /path/to/backend-services/
kubectl wait --for=condition=ready pod -l tier=backend --timeout=300s

kubectl apply -f /path/to/web-app/
kubectl wait --for=condition=ready pod -l app=web-app --timeout=180s

# Step 4: Verify system health
echo "4. Verifying system health..."
./health-check.sh

# Step 5: Run post-recovery tests
echo "5. Running recovery validation..."
./integration-tests.sh

echo "Recovery completed at: $(date)"
```

### Data Corruption Recovery

**Database Recovery Steps:**
```sql
-- Create recovery database
CREATE DATABASE kubechat_recovery;

-- Restore from backup
pg_restore --host=postgres-service --port=5432 --username=kubechat \
  --dbname=kubechat_recovery --verbose /backups/kubechat_backup.sql

-- Verify data integrity
SELECT count(*) as total_audit_events FROM audit_events;
SELECT count(*) as total_users FROM users;
SELECT max(created_at) as latest_event FROM audit_events;

-- Switch to recovery database (update connection strings)
UPDATE deployment_configs SET database_name = 'kubechat_recovery';
```

---

## Escalation Procedures

### When to Escalate

**Immediate Escalation (P0):**
- Complete system outage >15 minutes
- Data loss or corruption detected
- Security breach or unauthorized access
- Critical compliance violation

**Escalation Chain:**
```yaml
escalation_levels:
  level_1: 
    role: "On-call Engineer"
    contact: "Pager/SMS alert"
    response_time: "15 minutes"
    
  level_2:
    role: "Engineering Manager" 
    contact: "Phone call"
    response_time: "30 minutes"
    
  level_3:
    role: "VP Engineering"
    contact: "Phone + Email"
    response_time: "1 hour"
    
  level_4:
    role: "CTO"
    contact: "All channels"
    response_time: "2 hours"
```

### Incident Communication

**Status Page Updates:**
```markdown
# Incident Communication Template

## Initial Alert (T+0)
🔴 **INVESTIGATING** - We're currently investigating connectivity issues with KubeChat. Users may experience difficulties accessing the chat interface.

## Progress Update (T+15m) 
🔴 **IDENTIFIED** - We've identified a database connectivity issue affecting all services. Our team is working on a resolution.

## Resolution (T+45m)
🟢 **RESOLVED** - The database connectivity issue has been resolved. All services are operating normally. We will conduct a post-incident review.

## Post-Incident (T+24h)
📋 **POST-MORTEM** - We've published a detailed post-incident review with root cause analysis and preventive measures.
```

---

## Conclusion

This debugging guide provides systematic approaches to troubleshooting KubeChat issues. Regular use of these procedures, combined with proactive monitoring and alerting, ensures rapid issue resolution and minimal user impact.

**Key Success Metrics:**
- **Mean Time to Detection (MTTD):** <5 minutes for critical issues
- **Mean Time to Resolution (MTTR):** <30 minutes for P0 issues, <4 hours for P1
- **System Availability:** >99.9% uptime
- **False Positive Rate:** <5% for alerts

**Next Steps:**
1. Train operations team on debugging procedures
2. Implement automated health checks and self-healing
3. Create custom dashboards for key metrics
4. Establish regular disaster recovery drills
5. Build automated incident response playbooks