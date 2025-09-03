# KubeChat Web Interface - Quick Start Guide

Get up and running with KubeChat's web interface in 5 minutes! This guide provides essential commands and workflows for immediate productivity.

## 🚀 Quick Setup

1. **Access KubeChat Web Interface**
   ```
   http://localhost:3000
   ```

2. **Verify Connection**  
   Look for 🟢 **Connected** status in top-right corner

3. **Test First Command**
   ```
   Hello KubeChat
   ```

## ⚡ Essential Commands (Copy & Paste Ready)

### Resource Discovery
```bash
# See what's running
List all pods

# Check deployments  
Show me deployments

# View services
Get all services

# Explore a namespace
List everything in kube-system namespace
```

### Quick Deployments
```bash
# Deploy nginx
Create nginx deployment with 3 replicas

# Deploy redis
Create redis deployment

# Deploy postgres
Create postgres deployment with persistent storage
```

### Instant Scaling
```bash
# Scale up
Scale nginx to 5 replicas  

# Scale down
Scale nginx to 1 replica

# Auto-scale based on CPU
Enable autoscaling for nginx deployment
```

### Service Management
```bash
# Expose deployment
Create service for nginx on port 80

# Load balancer service
Create LoadBalancer service for nginx on port 80

# Internal service
Create ClusterIP service for redis on port 6379
```

## 📊 Dashboard Features

### Resource Overview
- **Total resources managed**: Real-time count
- **Statistics**: Created/Updated/Deleted breakdown  
- **Resource types**: Filter by Deployment, Service, Pod, etc.

### Quick Actions
Click the 📊 button for:
- Visual resource cards
- Resource filtering
- Real-time updates
- Resource details

### Filters
- **All (X)** - Show everything
- **🚀 Deployment (X)** - Only deployments  
- **🌐 Service (X)** - Only services
- **📦 Pod (X)** - Only pods

## 🛡️ Safety Features

### Automatic Risk Assessment
- 🟢 **Safe**: Read operations (no confirmation)
- 🟡 **Caution**: Performance impact (confirmation recommended)  
- 🟠 **Dangerous**: Service disruption (confirmation required)
- 🔴 **Destructive**: Data loss risk (strong confirmation required)

### Smart Confirmations
KubeChat automatically shows confirmation dialogs for risky operations:

**Example: Deletion Confirmation**
```
⚠️ Confirm Deletion
Resource: nginx-deployment  
Impact: 3 pods will be terminated
Recovery: Manual recreation required

[✅ Confirm] [❌ Cancel]
```

## 🔄 Common Workflows

### 1. Deploy & Scale Application
```bash
# Step 1: Deploy
Create nginx deployment with 2 replicas

# Step 2: Expose  
Create service for nginx on port 80

# Step 3: Scale based on demand
Scale nginx to 5 replicas

# Step 4: Monitor in dashboard
# Click 📊 to see resource cards update in real-time
```

### 2. Investigate Issues
```bash
# Step 1: Overview
List all pods

# Step 2: Check problematic pods
Describe pod [pod-name]

# Step 3: Check logs
Show logs for pod [pod-name]  

# Step 4: Check deployments
List deployments with issues
```

### 3. Clean Up Resources
```bash
# Step 1: List what you have
List all deployments

# Step 2: Remove unused apps
Delete old-app deployment

# Step 3: Clean up services
Delete old-app service

# Step 4: Verify cleanup
List all resources
```

## 💡 Pro Tips

### Better Commands
```bash
# ✅ Specific and clear
Scale nginx-deployment to 3 replicas in production namespace

# ❌ Vague and unclear  
Make my app bigger
```

### Use Namespaces
```bash
# Target specific namespace
List pods in production namespace
Create nginx deployment in staging namespace
```

### Batch Operations
```bash
# Multiple actions in one command
Create nginx deployment with 3 replicas and expose on port 80
```

### Resource Monitoring
```bash
# Check resource usage
Show resource usage for nginx deployment

# Monitor health
Check health of all deployments
```

## 🚨 Emergency Commands

### Quick Fixes
```bash
# Restart deployment
Restart nginx deployment

# Scale to zero (stop)
Scale nginx to 0 replicas

# Scale back up  
Scale nginx to 3 replicas

# Delete problematic pod
Delete pod [problematic-pod-name]
```

### Troubleshooting
```bash
# Check cluster status
Show cluster status

# List failing pods
List pods with issues

# Check recent events
Show recent events

# Describe problematic resources
Describe deployment [name]
```

## 🔗 Next Steps

Once comfortable with basics:

1. **Read Full Documentation**
   - [Complete User Guide](../user-guides/web-interface.md)
   - [WebSocket API Reference](../api/websocket-api.md)

2. **Explore Advanced Features**
   - [Detailed Usage Examples](./web-interface-usage.md)
   - Safety and confirmation workflows
   - Resource dashboard deep-dive

3. **Learn Best Practices**
   - Resource naming conventions
   - Namespace organization
   - Security considerations

## 🆘 Need Help?

### Connection Issues
```bash
# Check connection
Check connection status

# Manual reconnect  
Refresh browser page and wait for 🟢 Connected
```

### Command Not Working
```bash
# Get suggestions
Help me deploy an application

# List available commands
What can I do with deployments?
```

### Resource Not Found
```bash
# Search across namespaces
Find deployment named nginx

# List everything
List all resources in all namespaces
```

---

**Happy Kubernetting! 🎉**

Your cluster management just got a lot more conversational!