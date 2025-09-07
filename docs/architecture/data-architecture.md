# Data Architecture - Phase 1 Model 1 (On-Premises)

## Overview

This document defines the comprehensive data architecture for **KubeChat Phase 1: Model 1 (On-Premises FREE Platform)**, ensuring complete data sovereignty, audit trail integrity, and compliance with enterprise requirements.

## Table of Contents

1. [Data Sovereignty Principles](#data-sovereignty-principles)
2. [Data Storage Architecture](#data-storage-architecture)
3. [Audit Data Management](#audit-data-management)
4. [Data Encryption and Security](#data-encryption-and-security)
5. [Compliance and Retention](#compliance-and-retention)
6. [Backup and Recovery](#backup-and-recovery)
7. [Data Flow Diagrams](#data-flow-diagrams)

## Data Sovereignty Principles

### Phase 1 Model 1 Core Requirements

```yaml
data_sovereignty:
  customer_control: "100% customer-controlled data storage"
  data_residency: "All data remains within customer infrastructure"
  vendor_access: "Zero vendor access to customer data"
  external_dependencies: "No external data services or APIs"

air_gap_compliance:
  offline_operation: "Complete operation without internet connectivity"
  local_storage: "All data stored in customer-managed databases"
  no_external_apis: "No dependencies on external data services"
  customer_encryption: "Customer-controlled encryption keys"
```

### Data Classification

```yaml
data_types:
  operational_data:
    classification: "Internal"
    retention: "As per customer policy"
    encryption: "AES-256 at rest, TLS 1.3 in transit"
    
  audit_data:
    classification: "Restricted"
    retention: "7 years minimum (compliance)"
    encryption: "AES-256-GCM with cryptographic integrity"
    immutability: "Tamper-proof audit trail"
    
  configuration_data:
    classification: "Internal"
    retention: "As per customer policy"
    encryption: "AES-256 at rest"
    backup: "Customer-controlled backup systems"
    
  session_data:
    classification: "Restricted"
    retention: "24 hours to 30 days (configurable)"
    encryption: "AES-256 with secure session management"
```

## Data Storage Architecture

### Primary Data Stores

#### PostgreSQL - Primary Database
```yaml
postgresql_config:
  purpose: "Primary operational and audit data storage"
  version: "16+"
  deployment: "Customer-managed with HA clustering"
  
schemas:
  kubechat_operational:
    tables:
      - chat_sessions
      - user_profiles
      - kubernetes_contexts
      - command_history
      
  kubechat_audit:
    tables:
      - audit_events
      - security_logs
      - compliance_events
      - system_activities
      
  kubechat_config:
    tables:
      - system_configuration
      - user_preferences
      - rbac_policies

storage_requirements:
  initial_size: "20GB"
  growth_estimate: "5GB per 1000 users per month"
  backup_space: "3x primary storage for retention"
  
performance_targets:
  query_response: "< 100ms for operational queries"
  audit_write: "< 50ms for audit event insertion"
  concurrent_users: "1000+ simultaneous connections"
```

#### Redis - Caching and Sessions
```yaml
redis_config:
  purpose: "Session management, caching, and temporary data"
  version: "7.2+"
  deployment: "Customer-managed cluster mode"
  
data_types:
  user_sessions:
    ttl: "24 hours (configurable)"
    structure: "JSON session data"
    encryption: "AES-256 encrypted values"
    
  api_cache:
    ttl: "5 minutes to 1 hour"
    structure: "Serialized response data"
    eviction: "LRU policy"
    
  rate_limiting:
    ttl: "1 hour sliding window"
    structure: "Counter data"
    
storage_requirements:
  memory_allocation: "2GB minimum, 8GB recommended"
  persistence: "AOF and RDB snapshots"
  clustering: "3-6 nodes for high availability"
```

### Data Models

#### Chat Session Data Model
```yaml
chat_session:
  table: "chat_sessions"
  primary_key: "session_id (UUID)"
  
fields:
  session_id: "UUID - unique session identifier"
  user_id: "String - authenticated user identifier"
  kubernetes_context: "String - target cluster context"
  created_at: "Timestamp - session start time"
  updated_at: "Timestamp - last activity"
  status: "Enum - active, completed, expired"
  metadata: "JSONB - session configuration and state"
  
relationships:
  chat_messages: "One-to-many chat messages"
  audit_events: "One-to-many audit events"
  
indexes:
  - "session_id (primary)"
  - "user_id, created_at (performance)"
  - "status, updated_at (cleanup)"

retention_policy:
  active_sessions: "30 days"
  completed_sessions: "90 days (configurable)"
  cleanup_job: "Daily automated cleanup"
```

#### Audit Event Data Model
```yaml
audit_event:
  table: "audit_events"
  primary_key: "event_id (UUID)"
  
fields:
  event_id: "UUID - unique event identifier"
  session_id: "UUID - related chat session"
  user_id: "String - user who performed action"
  event_type: "Enum - command_execution, auth_event, system_event"
  action: "String - specific action performed"
  kubernetes_command: "Text - kubectl command executed"
  success: "Boolean - whether action succeeded"
  timestamp: "Timestamp with timezone - when event occurred"
  ip_address: "INET - source IP address"
  user_agent: "String - client information"
  metadata: "JSONB - additional event context"
  checksum: "String - cryptographic integrity check"
  
immutability:
  insert_only: "No updates or deletes allowed"
  cryptographic_integrity: "SHA-256 checksum per event"
  tamper_detection: "Automatic integrity verification"
  
indexes:
  - "event_id (primary)"
  - "user_id, timestamp (audit queries)"
  - "event_type, timestamp (compliance reporting)"
  - "session_id (session audit trail)"

retention_policy:
  minimum_retention: "7 years (compliance)"
  archive_strategy: "Compressed JSON export"
  verification: "Daily integrity checks"
```

## Audit Data Management

### Tamper-Proof Audit Trail

#### Cryptographic Integrity
```yaml
audit_integrity:
  hashing_algorithm: "SHA-256"
  checksum_calculation: "event_data + previous_checksum + timestamp"
  chain_verification: "Sequential integrity verification"
  
implementation:
  per_event_checksum: |
    checksum = SHA256(
      event_data + 
      previous_event_checksum + 
      timestamp + 
      secret_salt
    )
    
  daily_verification: "Automated integrity check job"
  tamper_detection: "Alert on checksum mismatch"
  
compliance_features:
  non_repudiation: "Cryptographic proof of event authenticity"
  time_stamping: "Trusted timestamp with each event"
  immutable_storage: "Write-once audit event storage"
```

### Audit Data Processing Pipeline

```yaml
audit_pipeline:
  ingestion:
    source: "All KubeChat services"
    format: "Structured JSON events"
    validation: "Schema validation on ingestion"
    
  processing:
    enrichment: "Add context and metadata"
    classification: "Assign compliance categories"
    integrity: "Generate cryptographic checksums"
    
  storage:
    primary: "PostgreSQL audit schema"
    replication: "Real-time replication to secondary"
    archival: "Long-term compressed storage"
    
  monitoring:
    real_time: "Audit event rate monitoring"
    integrity: "Continuous tamper detection"
    compliance: "Automated compliance reporting"
```

## Data Encryption and Security

### Encryption At Rest

#### Database Encryption
```yaml
database_encryption:
  postgresql:
    method: "Transparent Data Encryption (TDE)"
    algorithm: "AES-256-CBC"
    key_management: "Customer-controlled keys"
    
  redis:
    method: "Encrypted data values"
    algorithm: "AES-256-GCM"
    key_rotation: "Monthly automatic rotation"
    
  file_system:
    method: "LUKS full-disk encryption"
    algorithm: "AES-256-XTS"
    mount_encryption: "Encrypted mount points"
```

#### Key Management
```yaml
key_management:
  storage: "Customer-controlled key management system"
  rotation: "Quarterly key rotation schedule"
  escrow: "Customer-managed key escrow"
  
  key_hierarchy:
    master_key: "Customer-controlled master encryption key"
    database_keys: "Per-database encryption keys"
    session_keys: "Per-session temporary keys"
    
  compliance:
    fips_140_2: "FIPS 140-2 Level 2 compliance"
    key_ceremony: "Multi-person key generation"
    audit_trail: "Complete key lifecycle audit"
```

### Encryption In Transit

#### Service-to-Service Communication
```yaml
internal_tls:
  protocol: "mTLS (Mutual TLS)"
  version: "TLS 1.3 minimum"
  certificates: "Customer-managed PKI"
  
  service_mesh:
    implementation: "Istio service mesh"
    certificate_rotation: "Automatic certificate rotation"
    policy_enforcement: "Zero-trust network policies"
    
external_tls:
  client_connections: "TLS 1.3 with strong cipher suites"
  certificate_management: "Customer-provided certificates"
  hsts: "HTTP Strict Transport Security enabled"
```

## Compliance and Retention

### Regulatory Compliance

#### SOC 2 Type II
```yaml
soc2_controls:
  security:
    - "Logical access controls implemented"
    - "Data encryption at rest and in transit"
    - "Network security controls active"
    
  availability:
    - "System monitoring and alerting"
    - "Backup and recovery procedures"
    - "Capacity management processes"
    
  processing_integrity:
    - "Data validation and verification"
    - "Error handling and logging"
    - "Change management controls"
    
  confidentiality:
    - "Data classification implemented"
    - "Access controls enforced"
    - "Secure disposal procedures"
```

#### HIPAA Technical Safeguards
```yaml
hipaa_safeguards:
  access_control:
    unique_user_identification: "Individual user accounts"
    emergency_access: "Break-glass access procedures"
    automatic_logoff: "Session timeout controls"
    encryption_decryption: "AES-256 encryption"
    
  audit_controls:
    audit_logs: "Comprehensive access logging"
    audit_review: "Regular audit log review"
    audit_reporting: "Compliance reporting tools"
    
  integrity:
    data_integrity: "Cryptographic integrity verification"
    transmission_security: "TLS 1.3 for all transmissions"
```

### Data Retention Policies

```yaml
retention_schedules:
  operational_data:
    chat_sessions: "90 days default, configurable"
    user_preferences: "Until user deletion"
    system_logs: "30 days"
    
  audit_data:
    security_events: "7 years minimum"
    compliance_events: "10 years for regulated industries"
    access_logs: "1 year minimum"
    
  configuration_data:
    system_config: "Version-controlled, indefinite"
    user_settings: "Until user deletion"
    
automated_cleanup:
  schedule: "Daily cleanup job"
  verification: "Cleanup audit trail"
  exceptions: "Compliance hold procedures"
```

## Backup and Recovery

### Backup Strategy

#### Database Backups
```yaml
postgresql_backup:
  full_backup:
    frequency: "Daily at 2 AM local time"
    retention: "30 daily, 12 weekly, 12 monthly"
    compression: "gzip compression enabled"
    
  continuous_archiving:
    wal_shipping: "Continuous WAL archiving"
    point_in_time_recovery: "15-minute granularity"
    storage: "Customer-controlled backup storage"
    
  verification:
    restore_testing: "Monthly restore verification"
    integrity_checks: "Daily backup verification"
    
redis_backup:
  snapshot_frequency: "Every 6 hours"
  aof_persistence: "Always enabled"
  backup_retention: "7 days snapshots"
```

#### Disaster Recovery
```yaml
disaster_recovery:
  rto_target: "4 hours (Recovery Time Objective)"
  rpo_target: "15 minutes (Recovery Point Objective)"
  
  procedures:
    automated_failover: "Database cluster automatic failover"
    manual_recovery: "Documented manual recovery procedures"
    cross_region: "Geographic backup distribution"
    
  testing:
    dr_testing: "Quarterly disaster recovery testing"
    documentation: "Detailed recovery playbooks"
    automation: "Automated recovery scripts"
```

## Data Flow Diagrams

### Operational Data Flow
```
User → API Gateway → Authentication → Session Store (Redis)
                  → Business Logic → PostgreSQL (Operational)
                  → Audit Service → PostgreSQL (Audit)
                  → Kubernetes API → External Cluster
```

### Audit Data Flow
```
All Services → Audit Service → Validation → Checksum Generation
                             → PostgreSQL (Audit Schema)
                             → Real-time Replication
                             → Compliance Reporting
                             → Long-term Archive
```

### Backup Data Flow
```
PostgreSQL → WAL Archive → Customer Backup Storage
          → Full Backup → Compressed Archive
          → Verification → Restore Testing

Redis → AOF/RDB → Local Storage → Backup Replication
```

This data architecture ensures **KubeChat Phase 1: Model 1 (On-Premises)** meets all enterprise data sovereignty, compliance, and security requirements while maintaining complete customer control over all data assets.