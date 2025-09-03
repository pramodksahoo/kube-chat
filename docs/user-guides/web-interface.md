# KubeChat Web Interface User Guide

## Overview

The KubeChat Web Interface provides a modern, intuitive chat-based interface for managing your Kubernetes clusters using natural language. This guide covers all features and functionality of the web application.

## Table of Contents

- [Getting Started](#getting-started)
- [Chat Interface](#chat-interface)
- [Resource Dashboard](#resource-dashboard)
- [Safety Features](#safety-features)
- [Real-time Updates](#real-time-updates)
- [WebSocket Connection](#websocket-connection)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)
- [Advanced Features](#advanced-features)

## Getting Started

### Prerequisites

1. **KubeChat Operator**: Ensure the KubeChat operator is running in your Kubernetes cluster
2. **WebSocket API Server**: The WebSocket API server must be accessible
3. **Modern Browser**: Chrome 88+, Firefox 78+, Safari 14+, or Edge 88+
4. **Network Access**: Your browser must be able to connect to the WebSocket server

### Accessing the Interface

1. Navigate to the KubeChat web interface URL (typically `http://localhost:3000` in development)
2. The interface will automatically attempt to connect to the WebSocket server
3. You'll see a connection status indicator in the top-right corner
4. Once connected, you can start chatting with KubeChat

## Chat Interface

### Main Components

#### Chat Header
- **Application Title**: "🤖 KubeChat"
- **Connection Status**: Shows current WebSocket connection state
  - 🟢 **Connected**: Ready to process commands
  - 🟡 **Connecting**: Attempting to establish connection
  - 🔴 **Disconnected**: No connection to server

#### Message History
- **User Messages**: Your natural language commands (right-aligned, blue)
- **Assistant Messages**: KubeChat responses (left-aligned, gray)
- **System Messages**: Status updates and notifications
- **Automatic Scrolling**: New messages automatically scroll into view

#### Message Input
- **Text Area**: Type your natural language commands
- **Send Button**: Click to send message (or press Enter)
- **Character Counter**: Shows remaining characters (max 2000)
- **Quick Suggestions**: Helpful command examples when input is empty

### Sending Messages

#### Basic Commands
```
List all pods
Show me deployments in default namespace
Describe service nginx
Get pods in kube-system
```

#### Creating Resources
```
Create nginx deployment with 3 replicas
Deploy redis in cache namespace
Create a service for nginx on port 80
Scale deployment myapp to 5 replicas
```

#### Destructive Operations
```
Delete deployment nginx
Remove service redis
Scale down to 0 replicas
Delete namespace test
```

### Message Types

#### Chat Messages
Regular conversation messages between you and KubeChat.

#### NLP Results
Shows how KubeChat interpreted your message:
- **Intent Recognition**: What action KubeChat understood
- **Confidence Score**: How certain KubeChat is about the intent
- **Extracted Parameters**: Resource names, namespaces, etc.
- **Generated Commands**: Equivalent kubectl commands

#### Status Updates
Real-time updates about operation progress:
- 🔄 **Processing**: Analyzing your request
- ✅ **Completed**: Operation finished successfully
- ❌ **Failed**: Operation encountered an error
- ⏸️ **Awaiting Confirmation**: Waiting for your approval

## Resource Dashboard

### Overview
The Resource Dashboard (accessible via the 📊 button) provides a comprehensive view of all Kubernetes resources managed through KubeChat.

### Dashboard Sections

#### Connection Status
- **Operator Connection**: Shows if KubeChat operator is reachable
- **Cluster Information**: Displays cluster version, nodes, and namespaces
- **Operator Version**: Current version of KubeChat operator

#### Current Session
- **Session ID**: Unique identifier for your chat session
- **User ID**: Your user identifier
- **Message Count**: Number of messages in current session
- **Session Phase**: Current processing state

#### Generated Resources
- **Resource Cards**: Visual cards for each managed resource
- **Resource Statistics**: Total count, created, updated, deleted
- **Filter by Type**: Filter resources by kind (Deployment, Service, etc.)
- **Sorting**: Resources sorted by creation time (newest first)

#### Quick Actions
Pre-defined commands for common operations:
- 📋 List all pods
- 🚀 List deployments  
- 🌐 List services

### Resource Cards

Each resource card displays:
- **Resource Icon**: Emoji representing the resource type
- **Resource Name**: Name of the Kubernetes resource
- **Resource Kind**: Type of resource (badge)
- **Action Badge**: What was done (created, updated, deleted)
- **Details**: Namespace, kind, and other metadata
- **Timestamp**: When the action was performed

### Resource Types and Icons

| Resource Type | Icon | Description |
|---------------|------|-------------|
| Deployment | 🚀 | Application deployments |
| Service | 🌐 | Network services |
| Pod | 📦 | Running containers |
| ConfigMap | ⚙️ | Configuration data |
| Secret | 🔐 | Sensitive data |
| Namespace | 📁 | Resource isolation |
| Ingress | 🚪 | HTTP routing |
| PersistentVolume | 💾 | Storage volumes |
| Job | ⚡ | Batch jobs |
| CronJob | ⏰ | Scheduled jobs |

## Safety Features

KubeChat includes comprehensive safety features to prevent accidental damage to your cluster.

### Safety Levels

#### 🟢 Safe
- Read-only operations (list, describe, get)
- No confirmation required
- Examples: "list pods", "describe deployment"

#### 🟡 Caution
- Operations that may impact performance
- Usually requires confirmation
- Examples: "scale to 10 replicas", "create large deployment"

#### 🟠 Dangerous
- Operations that could cause service disruption
- Always requires confirmation
- Examples: "restart deployment", "update image"

#### 🔴 Destructive
- Operations that could cause data loss
- Requires explicit confirmation
- Examples: "delete deployment", "remove namespace"

### Confirmation Dialogs

When KubeChat detects a potentially dangerous operation, a confirmation dialog appears:

#### Dialog Components
- **Operation Description**: Clear explanation of what will happen
- **Safety Assessment**: Risk level and warnings
- **Generated Command**: Equivalent kubectl command
- **Impact Assessment**: Estimated impact on your cluster
- **Action Buttons**: 
  - ✅ **Confirm**: Proceed with operation
  - ❌ **Cancel**: Abort operation

#### Safety Warnings
- List of potential risks
- Recommendations for safe execution
- Suggested precautions (e.g., "ensure you have backups")

## Real-time Updates

### WebSocket Communication
The interface uses WebSocket technology for real-time communication with the KubeChat operator.

### Update Types

#### Processing Updates
- Real-time progress of NLP analysis
- Intent recognition progress
- Command translation status

#### Resource Events
- Kubernetes resource creation/modification
- Resource status changes
- Operation completion notifications

#### Error Handling
- Connection failures
- Processing errors
- Recovery attempts

### Status Indicators

#### Connection States
- **Connected**: Solid green indicator, ready for commands
- **Connecting**: Pulsing yellow indicator, establishing connection
- **Disconnected**: Red indicator, no connection
- **Reconnecting**: Animated indicator, attempting to reconnect

## WebSocket Connection

### Connection Management

#### Automatic Connection
- Connects automatically on page load
- Uses configuration from environment variables
- Displays connection status in header

#### Reconnection Logic
- Automatically attempts to reconnect on connection loss
- Exponential backoff for reconnection attempts
- Queues messages during disconnection
- Processes queued messages after reconnection

#### Connection Settings
```javascript
// Default WebSocket configuration
{
  url: 'ws://localhost:8080/ws',
  reconnectAttempts: 5,
  reconnectInterval: 1000, // 1 second
  maxReconnectInterval: 30000, // 30 seconds
  heartbeatInterval: 30000 // 30 seconds
}
```

## Common Use Cases

### 1. Deploying Applications

**Scenario**: Deploy a new application to your cluster

**Steps**:
1. Type: "Create nginx deployment with 3 replicas"
2. Review the NLP analysis and generated command
3. Confirm if prompted for safety reasons
4. Monitor the deployment in the Resource Dashboard

**Expected Outcome**: 
- New deployment created
- Resource card appears in dashboard
- Status updates show progress

### 2. Scaling Applications

**Scenario**: Scale an existing deployment

**Steps**:
1. Type: "Scale nginx to 5 replicas"
2. Review the scaling operation details
3. Confirm the operation
4. Watch the resource card update with new information

**Expected Outcome**:
- Deployment scaled to 5 replicas
- Resource card shows "updated" status
- Real-time status updates in chat

### 3. Investigating Issues

**Scenario**: Check the status of pods

**Steps**:
1. Type: "List all pods in default namespace"
2. Review the returned pod information
3. For more details: "Describe pod [pod-name]"
4. Check Resource Dashboard for visual overview

**Expected Outcome**:
- Detailed pod information displayed
- Current status and health visible
- No resources created (read-only operation)

### 4. Cleaning Up Resources

**Scenario**: Remove unused deployments

**Steps**:
1. Type: "Delete deployment old-app"
2. **IMPORTANT**: Review the destructive operation warning
3. Confirm deletion only if you're certain
4. Verify removal in Resource Dashboard

**Expected Outcome**:
- Deployment deleted from cluster
- Resource card shows "deleted" status
- Confirmation prevents accidental deletions

## Troubleshooting

### Connection Issues

#### WebSocket Connection Failed
**Symptoms**: Red connection indicator, cannot send messages

**Causes**:
- WebSocket server not running
- Network connectivity issues
- CORS configuration problems
- Firewall blocking WebSocket traffic

**Solutions**:
1. Check if WebSocket server is running on configured port
2. Verify network connectivity to server
3. Check browser console for error messages
4. Ensure CORS is properly configured
5. Try refreshing the page

#### Frequent Disconnections
**Symptoms**: Connection indicator frequently changes state

**Causes**:
- Unstable network connection
- Server resource constraints
- Proxy or load balancer issues

**Solutions**:
1. Check network stability
2. Monitor server resources
3. Review proxy/load balancer configuration
4. Adjust reconnection settings if needed

### Message Processing Issues

#### Messages Not Processed
**Symptoms**: Messages sent but no response received

**Causes**:
- Server processing errors
- Invalid message format
- Authentication issues

**Solutions**:
1. Check message format and content
2. Review server logs for errors
3. Verify authentication/session state
4. Try resending the message

#### Incorrect Intent Recognition
**Symptoms**: KubeChat misunderstands your commands

**Causes**:
- Ambiguous natural language
- Limited training data
- Complex multi-step operations

**Solutions**:
1. Use more specific language
2. Break complex requests into steps
3. Use resource names explicitly
4. Refer to the supported commands list

### Resource Dashboard Issues

#### Resources Not Appearing
**Symptoms**: Dashboard shows empty or incomplete data

**Causes**:
- WebSocket connection issues
- Resource synchronization problems
- Filtering settings

**Solutions**:
1. Check WebSocket connection
2. Refresh the dashboard (↻ button)
3. Clear active filters
4. Verify resources exist in cluster

#### Outdated Information
**Symptoms**: Dashboard shows stale data

**Causes**:
- Event streaming issues
- Client-side caching problems
- Server synchronization delays

**Solutions**:
1. Refresh the dashboard
2. Check WebSocket connection
3. Clear browser cache if needed
4. Restart the web application

### Performance Issues

#### Slow Response Times
**Symptoms**: Long delays between message and response

**Causes**:
- High server load
- Complex NLP processing
- Network latency
- Large cluster with many resources

**Solutions**:
1. Monitor server performance
2. Use simpler, more direct commands
3. Check network latency
4. Consider scaling the server

#### Browser Performance
**Symptoms**: Web interface becomes slow or unresponsive

**Causes**:
- Large message history
- Many resources in dashboard
- Memory leaks
- Browser resource constraints

**Solutions**:
1. Refresh the page to clear history
2. Filter resources to reduce load
3. Close unnecessary browser tabs
4. Use a modern browser version

## Advanced Features

### Session Management

#### Session Persistence
- Chat sessions are persisted as Kubernetes resources
- Sessions can be resumed after browser refresh
- Message history is maintained server-side

#### Multiple Sessions
- Each browser tab creates a separate session
- Sessions are identified by unique session IDs
- Resources are tracked per session

### Customization

#### Theme Support
- Default light theme
- Responsive design for mobile devices
- Accessibility features (ARIA labels, keyboard navigation)

#### Configuration
- WebSocket endpoint configuration
- Reconnection behavior settings
- Message history limits

### Integration Features

#### Kubernetes Integration
- Direct integration with ChatSession CRDs
- Real-time sync with cluster state
- RBAC-aware operations

#### Monitoring and Logging
- Connection status monitoring
- Message processing metrics
- Error tracking and reporting

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Enter` | Send message |
| `Shift+Enter` | New line in message |
| `Ctrl+/` | Show keyboard shortcuts |
| `Escape` | Close modals/dialogs |

### URL Parameters

#### Session ID
```
https://kubechat.example.com/session/session-123
```
Opens a specific chat session

#### Auto-connect
```
https://kubechat.example.com/?autoconnect=false
```
Disable automatic WebSocket connection

## Best Practices

### Writing Effective Commands

1. **Be Specific**: Use exact resource names when possible
2. **Include Namespace**: Specify namespace for clarity
3. **Use Clear Intent**: State clearly what you want to do
4. **Check Safety Level**: Pay attention to safety assessments

### Managing Resources

1. **Review Before Confirming**: Always review destructive operations
2. **Use Dashboard**: Monitor resources through the dashboard
3. **Regular Cleanup**: Remove unused resources periodically
4. **Follow Naming Conventions**: Use consistent resource names

### Security Considerations

1. **RBAC Compliance**: Ensure proper permissions are configured
2. **Network Security**: Use HTTPS and secure WebSocket connections
3. **Session Management**: Log out when done in shared environments
4. **Audit Trails**: Monitor resource changes through logs

## Support and Feedback

For additional help or to report issues:

1. **Documentation**: Check the complete KubeChat documentation
2. **GitHub Issues**: Report bugs and feature requests
3. **Community**: Join the KubeChat community discussions
4. **Logs**: Include browser console logs when reporting issues

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-09-01 | Initial web interface release |
| 1.0.1 | TBD | Performance improvements and bug fixes |