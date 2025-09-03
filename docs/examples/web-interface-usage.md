# KubeChat Web Interface Usage Examples

This document provides comprehensive examples of using the KubeChat web interface for managing your Kubernetes clusters through natural language commands.

## Table of Contents

- [Getting Started](#getting-started)
- [Basic Operations](#basic-operations)
- [Resource Management](#resource-management)
- [Advanced Scenarios](#advanced-scenarios)
- [Dashboard Features](#dashboard-features)
- [Safety and Confirmations](#safety-and-confirmations)
- [Troubleshooting Common Issues](#troubleshooting-common-issues)

## Getting Started

### Initial Setup

1. **Access the Web Interface**
   ```
   URL: http://localhost:3000
   ```

2. **Connection Status Check**
   - Look for the connection indicator in the top-right corner
   - 🟢 **Connected**: Ready to process commands
   - 🟡 **Connecting**: Attempting to establish connection
   - 🔴 **Disconnected**: No connection to server

3. **First Command**
   Try your first natural language command:
   ```
   Hello KubeChat
   ```
   Expected response: Welcome message and basic instructions

## Basic Operations

### 1. Listing Resources

#### Example 1: List All Pods
**Command:**
```
List all pods
```

**Expected Output:**
```
📦 Found 5 pods across all namespaces:

default/nginx-deployment-7fb96c846b-abc123 (Running)
default/nginx-deployment-7fb96c846b-def456 (Running)
kube-system/coredns-558bd4d5db-xyz789 (Running)
kube-system/etcd-minikube (Running)
kube-system/kube-apiserver-minikube (Running)
```

**Dashboard Update:**
- New entries appear in Resource Dashboard
- Statistics updated to show pod counts
- Filter tabs updated with pod counts

#### Example 2: List Deployments in Specific Namespace
**Command:**
```
Show me deployments in default namespace
```

**Expected Output:**
```
🚀 Found 2 deployments in default namespace:

nginx-deployment (3/3 replicas ready)
redis-deployment (1/1 replicas ready)
```

#### Example 3: Get Services
**Command:**
```
Get services
```

**Expected Output:**
```
🌐 Found 3 services:

default/kubernetes (ClusterIP: 10.96.0.1:443)
default/nginx-service (LoadBalancer: 10.96.0.100:80)
kube-system/kube-dns (ClusterIP: 10.96.0.10:53)
```

### 2. Describing Resources

#### Example 4: Describe a Specific Pod
**Command:**
```
Describe pod nginx-deployment-7fb96c846b-abc123
```

**Expected Output:**
```
📦 Pod Details: nginx-deployment-7fb96c846b-abc123

Status: Running
Node: minikube (192.168.49.2)
Start Time: 2025-09-01T10:30:00Z
Labels:
  app=nginx
  pod-template-hash=7fb96c846b

Containers:
- nginx (nginx:1.14.2)
  State: Running
  Resources: 100m CPU, 128Mi Memory

Events:
  Successfully assigned pod to minikube
  Container image pulled successfully
  Container started
```

## Resource Management

### 3. Creating Resources

#### Example 5: Create a Simple Deployment
**Command:**
```
Create nginx deployment with 3 replicas
```

**NLP Analysis Shown:**
```
🔍 Intent Analysis:
Action: CREATE_DEPLOYMENT
Resource: nginx
Replicas: 3
Confidence: 95%

Generated Command:
kubectl create deployment nginx --image=nginx --replicas=3
```

**Safety Assessment:**
```
🟢 Safety Level: SAFE
- Creating new deployment (non-destructive)
- Standard nginx image
- Reasonable replica count
```

**Expected Output:**
```
✅ Deployment created successfully!

🚀 nginx deployment created with 3 replicas
📊 Resource Dashboard updated with new entry
```

**Dashboard Update:**
- New deployment card appears
- Statistics show +1 created resource
- Filter tabs updated

#### Example 6: Create Service for Deployment
**Command:**
```
Create a service for nginx deployment on port 80
```

**Expected Output:**
```
🔍 Intent Analysis:
Action: CREATE_SERVICE
Target: nginx deployment
Port: 80
Type: ClusterIP (default)
Confidence: 92%

Generated Command:
kubectl expose deployment nginx --port=80 --target-port=80
```

**Safety Assessment:**
```
🟢 Safety Level: SAFE
- Exposing existing deployment
- Standard HTTP port
- Internal service only
```

**Result:**
```
✅ Service created successfully!

🌐 nginx service created (ClusterIP)
- Port: 80 → 80
- Selector: app=nginx
📊 Resource Dashboard updated
```

### 4. Scaling Operations

#### Example 7: Scale Deployment
**Command:**
```
Scale nginx to 5 replicas
```

**NLP Analysis:**
```
🔍 Intent Analysis:
Action: SCALE_DEPLOYMENT
Resource: nginx
Target Replicas: 5
Current Replicas: 3
Confidence: 98%

Generated Command:
kubectl scale deployment nginx --replicas=5
```

**Safety Assessment:**
```
🟡 Safety Level: CAUTION
- Scaling operation may impact performance
- Resource usage will increase
- Consider cluster capacity
```

**Confirmation Dialog:**
```
⚠️  Confirm Scaling Operation

Operation: Scale nginx deployment from 3 to 5 replicas
Impact: +2 additional pods will be created
Resource Usage: ~200m CPU, ~256Mi Memory

Recommendations:
✓ Ensure cluster has sufficient capacity
✓ Monitor resource utilization after scaling

[✅ Confirm] [❌ Cancel]
```

**After Confirmation:**
```
✅ Scaling operation successful!

🚀 nginx deployment scaled to 5 replicas
📈 2 new pods are being created
📊 Resource Dashboard updated - deployment shows "updated" status
```

### 5. Updating Resources

#### Example 8: Update Container Image
**Command:**
```
Update nginx deployment to use nginx:1.20
```

**NLP Analysis:**
```
🔍 Intent Analysis:
Action: UPDATE_IMAGE
Resource: nginx deployment
New Image: nginx:1.20
Current Image: nginx:latest
Confidence: 96%

Generated Command:
kubectl set image deployment/nginx nginx=nginx:1.20
```

**Safety Assessment:**
```
🟠 Safety Level: DANGEROUS
- Image updates can cause service disruption
- Rolling update will restart pods
- New image compatibility unknown
```

**Confirmation Dialog:**
```
⚠️  Confirm Image Update

Operation: Update nginx deployment image
From: nginx:latest → nginx:1.20

Potential Impact:
⚠️  All pods will be recreated (rolling update)
⚠️  Brief service interruption possible
⚠️  Image compatibility should be verified

Safety Recommendations:
✓ Test image in development first
✓ Have rollback plan ready
✓ Monitor application health after update

[✅ Proceed] [❌ Cancel]
```

## Advanced Scenarios

### 6. Complex Multi-Step Operations

#### Example 9: Deploy Complete Application Stack
**Command:**
```
Deploy a complete redis stack with service and configmap
```

**NLP Analysis:**
```
🔍 Intent Analysis:
Action: CREATE_STACK
Components: Deployment, Service, ConfigMap
Application: Redis
Confidence: 89%

Generated Commands:
1. kubectl create configmap redis-config --from-literal=maxmemory=256mb
2. kubectl create deployment redis --image=redis:6-alpine
3. kubectl expose deployment redis --port=6379 --name=redis-service
```

**Safety Assessment:**
```
🟡 Safety Level: CAUTION
- Multiple resources will be created
- Redis will store data in memory
- Default configuration applied
```

**Execution Progress:**
```
📋 Executing multi-step operation...

Step 1/3: Creating ConfigMap... ✅
Step 2/3: Creating Deployment... ✅
Step 3/3: Creating Service... ✅

✅ Redis stack deployed successfully!

📊 Resources Created:
- 🔧 redis-config ConfigMap
- 🚀 redis Deployment (1 replica)
- 🌐 redis-service Service (ClusterIP:6379)
```

#### Example 10: Batch Resource Management
**Command:**
```
List all resources in production namespace and scale down any deployments with more than 2 replicas
```

**NLP Analysis:**
```
🔍 Intent Analysis:
Action: BATCH_OPERATION
Steps:
1. LIST_RESOURCES (namespace: production)
2. SCALE_DOWN (condition: replicas > 2, target: 2)
Confidence: 87%
```

**Safety Assessment:**
```
🟠 Safety Level: DANGEROUS
- Batch operations affect multiple resources
- Scaling down may impact availability
- Production namespace modification
```

**Confirmation Required:**
```
⚠️  Confirm Batch Operation

Target: production namespace
Operations:
1. List all resources
2. Scale down deployments with >2 replicas to 2 replicas

Potential Impact:
⚠️  Production workloads may be affected
⚠️  Service capacity will be reduced
⚠️  Multiple deployments may be modified

[✅ Proceed with Caution] [❌ Cancel]
```

## Dashboard Features

### 7. Resource Dashboard Usage

#### Viewing Resource Statistics
The dashboard shows real-time statistics:

```
📊 Resource Dashboard
12 resources managed

Statistics:
Total: 12    Created: 8    Updated: 3    Deleted: 1    Types: 5
```

#### Filtering Resources
Click filter tabs to view specific resource types:

- **All (12)** - Show all resources
- **🚀 Deployment (4)** - Show only deployments
- **🌐 Service (3)** - Show only services
- **📦 Pod (5)** - Show only pods

#### Resource Cards
Each resource displays:
```
🚀 nginx-deployment                           [updated]
Deployment | default namespace
Kind: Deployment  Name: nginx-deployment  Action: updated
2 minutes ago
```

### 8. Real-time Updates

#### WebSocket Status Monitoring
Connection status indicator shows:
- **🟢 Connected** - Real-time updates active
- **🟡 Reconnecting** - Attempting to reconnect
- **🔴 Disconnected** - No real-time updates

#### Live Resource Updates
When resources change:
```
📡 Real-time Update Received

🚀 nginx-deployment scaled from 3 to 5 replicas
📊 Dashboard updated automatically
🔄 Resource card refreshed with new status
```

## Safety and Confirmations

### 9. Safety System Examples

#### Safe Operations (No Confirmation)
```
✅ Safe Operations - Execute Immediately:
- List pods
- Describe services  
- Get deployments
- Show namespace resources
```

#### Caution Level Operations
```
⚠️  Caution Operations - Confirmation Recommended:
- Scale deployments
- Create large resource counts
- Update configurations
```

#### Dangerous Operations  
```
🟠 Dangerous Operations - Confirmation Required:
- Update container images
- Restart deployments
- Modify running services
- Batch operations
```

#### Destructive Operations
```
🔴 Destructive Operations - Strong Confirmation Required:
- Delete deployments
- Remove services
- Drop namespaces
- Purge resources
```

### 10. Confirmation Dialog Examples

#### Standard Confirmation
```
⚠️  Confirm Operation

Action: Delete nginx-deployment
Impact: All 3 pods will be terminated
Recovery: Deployment cannot be easily restored

Safety Checklist:
□ Verify this is the correct deployment
□ Ensure no critical services depend on this
□ Have backup/restoration plan if needed

[✅ I understand, proceed] [❌ Cancel]
```

#### High-Risk Confirmation
```
🚨 HIGH RISK OPERATION

Action: Delete production namespace
Impact: ALL resources in namespace will be PERMANENTLY deleted
This includes: 12 deployments, 8 services, 45 pods, 6 configmaps

⚠️  THIS ACTION CANNOT BE UNDONE ⚠️

Type 'DELETE production' to confirm:
[Text Input Field]

[🚨 PERMANENTLY DELETE] [❌ Cancel]
```

## Troubleshooting Common Issues

### 11. Connection Problems

#### WebSocket Connection Failed
**Symptoms:**
```
🔴 Connection Status: Disconnected
Unable to send messages
```

**Troubleshooting Steps:**
1. **Check Connection:**
   ```
   Try: "Check connection status"
   Expected: Connection diagnostics
   ```

2. **Manual Reconnect:**
   ```
   Refresh browser page
   Look for: 🟡 Connecting... then 🟢 Connected
   ```

3. **Verify Server:**
   ```
   Check: http://localhost:8080/health
   Expected: {"status": "ok", "websocket": "available"}
   ```

### 12. Command Processing Issues

#### Intent Not Recognized
**Problem:**
```
❌ Sorry, I don't understand what you want to do.

Your command: "make the pods go fast"
Confidence: 12% (too low to execute)
```

**Solutions:**
```
✅ Use clearer commands:
- "Scale pods to 5 replicas"
- "Increase nginx deployment replicas"
- "Make nginx deployment larger"
```

#### Ambiguous Resource References
**Problem:**
```
❌ Multiple resources match 'app':
- app-deployment (deployment)
- app-service (service)  
- app-configmap (configmap)

Please be more specific.
```

**Solutions:**
```
✅ Be specific:
- "Scale app-deployment to 3 replicas"
- "Describe app-service"
- "Update app-deployment image"
```

### 13. Resource Not Found

#### Missing Resource Error
**Problem:**
```
❌ Resource not found: nginx-deployment
Searched in: default namespace
Available deployments: redis, postgres
```

**Troubleshooting:**
```
1. Check namespace:
   "List deployments in all namespaces"

2. Verify resource name:
   "List all deployments"

3. Check resource type:
   "Show me all nginx resources"
```

### 14. Permission Issues

#### RBAC Access Denied
**Problem:**
```
❌ Access denied: insufficient permissions
Action: DELETE deployment/nginx
Required: deployments.delete in default namespace
Your permissions: deployments.get, deployments.list
```

**Solutions:**
```
1. Contact cluster administrator
2. Request additional permissions:
   - deployments.delete
   - deployments.update (for scaling)
   
3. Use read-only operations:
   - "List deployments"
   - "Describe nginx deployment"
```

## Best Practices

### 15. Effective Command Patterns

#### Good Command Examples
```
✅ Clear and Specific:
- "Scale nginx deployment to 3 replicas"
- "Create redis service on port 6379"
- "List pods in kube-system namespace"
- "Describe nginx-deployment"
- "Delete old-app deployment"
```

#### Commands to Avoid
```
❌ Vague or Unclear:
- "Fix my app" (too vague)
- "Make it faster" (unclear action)
- "Delete everything" (too broad)
- "Scale up" (missing target and amount)
```

### 16. Safety Best Practices

#### Pre-Operation Checks
```
1. Verify target resources:
   "List deployments in default namespace"

2. Check current state:
   "Describe nginx deployment"

3. Understand impact:
   "Show nginx service dependencies"
```

#### Post-Operation Validation
```
1. Verify changes:
   "List pods for nginx deployment"

2. Check health:
   "Describe nginx deployment status"

3. Monitor resources:
   Use Resource Dashboard to track changes
```

## Summary

The KubeChat web interface provides a powerful, intuitive way to manage Kubernetes resources through natural language. Key features include:

- **Natural Language Processing** - Understands intent from plain English
- **Safety Assessment** - Evaluates operation risk levels
- **Real-time Updates** - WebSocket-based live resource monitoring  
- **Resource Dashboard** - Visual overview of managed resources
- **Confirmation Workflows** - Prevents accidental destructive operations
- **Comprehensive Logging** - Full audit trail of all operations

For additional help, refer to:
- [Web Interface User Guide](../user-guides/web-interface.md)
- [WebSocket API Documentation](../api/websocket-api.md)
- [Troubleshooting Guide](../troubleshooting/common-issues.md)