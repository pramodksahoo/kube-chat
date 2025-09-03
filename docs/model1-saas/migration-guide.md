# Model 2 to Model 1 Migration Guide

## Overview

This guide details the step-by-step process to transform KubeChat Model 2 (on-premises Helm charts) into Model 1 (hosted SaaS platform). The migration is designed to reuse 80%+ of existing code while adding SaaS-specific layers.

## Migration Strategy

### Phase 1: SaaS Foundation (2 months)
Add multi-tenancy and cloud infrastructure without changing core business logic.

### Phase 2: Multi-Region Scale (2 months)  
Deploy global infrastructure and enterprise integrations.

### Phase 3: Advanced SaaS (2 months)
Add competitive differentiation and customer success features.

## Detailed Migration Steps

### Step 1: Add Tenant Context to Existing Services

**Goal:** Inject tenant awareness into Model 2 services without breaking existing logic.

**API Gateway Service Transformation:**
```go
// Model 2: pkg/middleware/auth.go
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := extractToken(r)
        user, err := validateToken(token)
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        ctx := context.WithValue(r.Context(), "user", user)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// Model 1: Add tenant context extraction
func TenantAwareAuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := extractToken(r)
        claims, err := validateTokenWithTenant(token) // Enhanced validation
        if err != nil {
            http.Error(w, "Unauthorized", 401)
            return
        }
        
        // Extract tenant from JWT or subdomain
        tenantID := extractTenantID(claims, r.Host)
        
        // Validate tenant is active
        if err := validateTenantAccess(tenantID, claims.UserID); err != nil {
            http.Error(w, "Forbidden", 403)
            return  
        }
        
        // Add both user and tenant to context
        ctx := r.Context()
        ctx = context.WithValue(ctx, "user", claims.User)
        ctx = context.WithValue(ctx, "tenant_id", tenantID)
        
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

**Database Service Transformation:**
```go
// Model 2: pkg/database/user.go
func (s *UserService) GetUser(ctx context.Context, userID string) (*User, error) {
    query := "SELECT * FROM users WHERE id = ?"
    return s.db.QueryRow(query, userID).Scan(&user)
}

// Model 1: Add tenant-aware queries  
func (s *UserService) GetUser(ctx context.Context, userID string) (*User, error) {
    tenantID := tenant.FromContext(ctx) // Extract tenant from context
    
    query := `
        SELECT * FROM users 
        WHERE id = ? AND tenant_id = ?
    `
    return s.db.QueryRow(query, userID, tenantID).Scan(&user)
}

// Alternative: Use Row-Level Security (preferred for SaaS)
func (s *UserService) GetUser(ctx context.Context, userID string) (*User, error) {
    tenantID := tenant.FromContext(ctx)
    
    // Set tenant context for RLS
    _, err := s.db.Exec("SET app.current_tenant = ?", tenantID)
    if err != nil {
        return nil, err
    }
    
    // Original Model 2 query works unchanged due to RLS
    query := "SELECT * FROM users WHERE id = ?"
    return s.db.QueryRow(query, userID).Scan(&user)
}
```

### Step 2: Database Schema Migration

**Add Tenant Fields to Existing Tables:**
```sql
-- Migration: 001_add_tenant_support.sql
ALTER TABLE users ADD COLUMN tenant_id VARCHAR(50);
ALTER TABLE chat_sessions ADD COLUMN tenant_id VARCHAR(50);  
ALTER TABLE kubernetes_commands ADD COLUMN tenant_id VARCHAR(50);
ALTER TABLE audit_events ADD COLUMN tenant_id VARCHAR(50);

-- Create tenant organizations table
CREATE TABLE tenant_organizations (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255),
    subscription_plan VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add foreign keys
ALTER TABLE users ADD CONSTRAINT fk_users_tenant 
    FOREIGN KEY (tenant_id) REFERENCES tenant_organizations(id);

-- Create indexes for performance
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_sessions_tenant_id ON chat_sessions(tenant_id);
CREATE INDEX idx_commands_tenant_id ON kubernetes_commands(tenant_id);
CREATE INDEX idx_audit_tenant_id ON audit_events(tenant_id);

-- Row-Level Security policies
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    FOR ALL TO kubechat_app
    USING (tenant_id = current_setting('app.current_tenant'));
```

### Step 3: Frontend Multi-Tenant Extensions

**Add Tenant Context to React App:**
```typescript
// Model 2: src/stores/auth.ts
interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  login: (token: string) => void;
  logout: () => void;
}

// Model 1: Add tenant awareness
interface AuthState {
  user: User | null;
  tenant: TenantOrganization | null;
  isAuthenticated: boolean;
  login: (token: string) => void;
  logout: () => void;
  switchTenant: (tenantId: string) => Promise<void>;
}

const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  tenant: null,
  isAuthenticated: false,
  
  login: (token: string) => {
    const decoded = jwt.decode(token) as JWTClaims;
    set({
      user: decoded.user,
      tenant: decoded.tenant, // New: tenant from JWT
      isAuthenticated: true
    });
  },
  
  switchTenant: async (tenantId: string) => {
    // New: tenant switching capability
    const response = await api.post('/auth/switch-tenant', { tenantId });
    const newToken = response.data.token;
    
    // Update local storage and state
    localStorage.setItem('auth_token', newToken);
    get().login(newToken);
  }
}));
```

**Add Tenant Switcher Component:**
```typescript
// New: src/components/TenantSwitcher.tsx
export function TenantSwitcher() {
  const { tenant, user, switchTenant } = useAuthStore();
  const [availableTenants, setAvailableTenants] = useState<TenantOrganization[]>([]);
  
  useEffect(() => {
    // Fetch user's accessible tenants
    api.get('/user/tenants').then(response => {
      setAvailableTenants(response.data);
    });
  }, []);
  
  return (
    <Select
      value={tenant?.id}
      onValueChange={switchTenant}
      className="w-48"
    >
      <SelectTrigger>
        <SelectValue>
          <div className="flex items-center gap-2">
            <Building className="w-4 h-4" />
            {tenant?.name}
          </div>
        </SelectValue>
      </SelectTrigger>
      <SelectContent>
        {availableTenants.map(t => (
          <SelectItem key={t.id} value={t.id}>
            <div className="flex items-center gap-2">
              <Building className="w-4 h-4" />
              <div>
                <div className="font-medium">{t.name}</div>
                <div className="text-xs text-gray-500">{t.domain}</div>
              </div>
            </div>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
```

### Step 4: Infrastructure Migration

**Kubernetes to AWS EKS:**
```yaml
# Model 2: charts/kubechat/values.yaml
global:
  domain: kubechat.company.com
  storageClass: longhorn

operator:
  replicaCount: 2

postgresql:
  operator:
    enabled: true

# Model 1: infrastructure/environments/production/terraform.tf
resource "aws_eks_cluster" "kubechat" {
  name     = "kubechat-prod"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.28"
  
  vpc_config {
    subnet_ids = module.vpc.private_subnets
    endpoint_config {
      private_access = true
      public_access  = true
    }
  }
}

resource "aws_rds_global_cluster" "kubechat" {
  cluster_identifier = "kubechat-global"
  engine             = "aurora-postgresql"
  engine_version     = "15.4"
  database_name      = "kubechat"
  
  # Multi-region setup
  source_db_cluster_identifier = aws_rds_cluster.primary.cluster_identifier
}
```

### Step 5: New SaaS Services

**Tenant Management Service:**
```go
// New: cmd/tenant-service/main.go
package main

import (
    "github.com/kubechat/pkg/tenancy"
    "github.com/kubechat/pkg/billing" 
)

func main() {
    router := fiber.New()
    
    tenantService := tenancy.NewService(db, k8sClient)
    billingService := billing.NewService(stripeClient, db)
    
    // Tenant lifecycle endpoints
    router.Post("/tenants", tenantService.CreateTenant)
    router.Get("/tenants/:id", tenantService.GetTenant)
    router.Put("/tenants/:id", tenantService.UpdateTenant)
    router.Delete("/tenants/:id", tenantService.DeleteTenant)
    
    // Billing integration endpoints
    router.Get("/tenants/:id/usage", billingService.GetUsage)
    router.Post("/tenants/:id/invoice", billingService.GenerateInvoice)
    
    router.Listen(":8080")
}
```

**Billing Service Implementation:**
```go
// New: pkg/billing/service.go
type Service struct {
    db     *sql.DB
    stripe *stripe.Client
}

func (s *Service) TrackUsage(ctx context.Context, event UsageEvent) error {
    tenantID := tenant.FromContext(ctx)
    
    // Record usage event
    _, err := s.db.ExecContext(ctx, `
        INSERT INTO usage_events (tenant_id, user_id, event_type, quantity, timestamp)
        VALUES (?, ?, ?, ?, ?)
    `, tenantID, event.UserID, event.Type, event.Quantity, time.Now())
    
    if err != nil {
        return err
    }
    
    // Check if billing threshold reached
    usage, err := s.getMonthlyUsage(ctx, tenantID)
    if err != nil {
        return err
    }
    
    if usage.ShouldTriggerBilling() {
        return s.triggerBilling(ctx, tenantID, usage)
    }
    
    return nil
}
```

## Migration Timeline and Effort

### Phase 1: Core SaaS Transformation (8 weeks)

**Week 1-2: Database and Backend**
- Add tenant fields to all tables
- Implement tenant context middleware
- Add Row-Level Security policies
- **Effort:** 2 backend engineers

**Week 3-4: Frontend Multi-Tenancy**  
- Add tenant context to React stores
- Build tenant switcher component
- Update all API calls with tenant context
- **Effort:** 1 frontend engineer

**Week 5-6: Infrastructure Setup**
- Deploy AWS EKS clusters in us-east-1
- Set up RDS Aurora with Multi-AZ
- Configure ElastiCache and CloudFront
- **Effort:** 1 DevOps engineer

**Week 7-8: New SaaS Services**
- Build tenant management service
- Implement basic billing integration
- Create tenant onboarding flow
- **Effort:** 1 backend engineer, 1 frontend engineer

### Phase 2: Enterprise Features (6 weeks)

**Week 9-10: Multi-Region Deployment**
- Deploy eu-west-1 region
- Configure Aurora Global Database
- Set up global DNS routing
- **Effort:** 1 DevOps engineer

**Week 11-12: Enterprise SSO**
- Integrate AWS Cognito with SAML
- Build SSO configuration UI
- Add SCIM provisioning support
- **Effort:** 1 backend engineer

**Week 13-14: Advanced Analytics**
- Build usage analytics dashboard
- Implement customer success metrics
- Create automated billing workflows
- **Effort:** 1 full-stack engineer

### Code Reuse Breakdown

**Reused from Model 2 (85%):**
- All Go business logic (NLP, command processing, validation)
- All React UI components (chat, confirmation dialogs, audit views)
- All data models and API interfaces
- All Kubernetes controllers and CRDs
- All test suites and documentation

**New SaaS Code (15%):**
- Tenant management service (~2,000 lines)
- Billing integration service (~1,500 lines) 
- Multi-tenant middleware (~500 lines)
- Frontend tenant features (~1,000 lines)
- Infrastructure as code (~3,000 lines)

**Total Additional Code:** ~8,000 lines vs ~50,000 lines in Model 2

## Success Metrics

**Technical Metrics:**
- Code reuse: >80% from Model 2
- Migration time: <6 months total
- Performance: <200ms API response times globally
- Availability: 99.9% uptime SLA

**Business Metrics:**
- Customer migration: >90% of Model 2 customers upgrade
- Time-to-revenue: <3 months from Model 2 success
- Development velocity: Maintain Model 2 feature parity + SaaS features
- Operational overhead: <2 additional engineers for SaaS operations

This migration strategy ensures KubeChat can rapidly transition from successful on-premises deployment to global SaaS platform while leveraging proven technology investments and maintaining engineering velocity.