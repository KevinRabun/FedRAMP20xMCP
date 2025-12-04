# Code Analyzer Expansion Roadmap

## Current Status: Phase 6A Complete ✅

**Coverage:** 45 KSIs out of 72 (62.5%)
**Families Covered:** IAM (7/7 complete), MLA (5/8), SVC (8/10), CNA (6/8), PIY (3/8), CMT (3/3 complete), AFR (4/6), CED (1/2), INR (2/2 complete), RPL (4/4 complete)

### Phase 1: Foundation (COMPLETE) ✅

**IaC Checks (Bicep/Terraform):**
- ✅ KSI-MLA-05: Diagnostic logging configuration
- ✅ KSI-SVC-06: Key Vault secrets management
- ✅ KSI-CNA-01: Network Security Groups
- ✅ KSI-IAM-03: RBAC role assignments
- ✅ KSI-SVC-03: Encryption configuration

**App Code Checks (Python):**
- ✅ KSI-IAM-01: API authentication
- ✅ KSI-SVC-06: Secrets management (hardcoded keys)
- ✅ KSI-SVC-08: Dependency security (vulnerable libraries)
- ✅ KSI-PIY-02: PII handling and encryption
- ✅ KSI-MLA-05: Diagnostic logging

**Test Coverage:** 22 tests passing (14 analyzer + 8 tool tests)

---

### Phase 2: Critical Infrastructure Security (COMPLETE) ✅

**Target:** Add 9 KSIs → 17 total (24% coverage)
**Focus:** High-priority infrastructure security checks
**Completed:** December 2024
**Priority:** HIGH

### IaC Additions (7 KSIs)

#### KSI-IAM-02: Multi-Factor Authentication Enforcement ✅
**Implementation:**
- Bicep: Checks for Conditional Access policies with MFA requirements
- Terraform: Validates `azurerm_conditional_access_policy` has MFA built-in controls
- Detects missing phishing-resistant MFA enforcement

**Detection Patterns:**
- Missing `grantControls.builtInControls: ["mfa"]` in Conditional Access
- Missing authentication strength requirements
- Reports good practice when MFA detected

#### KSI-IAM-06: Privileged Access Management ✅
**Implementation:**
- Detects permanent admin role assignments (Owner/Contributor to Users)
- Checks for Azure PIM eligible assignments
- Validates just-in-time access configuration

**Detection Patterns:**
- `principalType: 'User'` with `Owner`/`Contributor` roles (HIGH severity)
- Missing PIM configuration for privileged roles
- Reports good practice when PIM detected

#### KSI-CNA-02: Container Security and Isolation ✅
**Implementation:**
- AKS cluster security: Defender, network policies, pod security
- ACR security: Quarantine and trust policies
- Container image scanning validation

**Detection Patterns:**
- AKS missing Defender for Containers
- Missing network policy (azure/calico)
- Missing pod security standards
- ACR missing quarantine/trust policies

#### KSI-CNA-04: Immutable Infrastructure ✅
**Implementation:**
- Resource locks on critical infrastructure (Storage, SQL, Key Vault, VNet)
- Detects mutable infrastructure patterns
- Validates IaC-only deployment enforcement

**Detection Patterns:**
- Critical resources without `Microsoft.Authorization/locks` (Bicep)
- Missing `azurerm_management_lock` (Terraform)
- Reports good practice when locks detected

#### KSI-CNA-06: API Gateway Configuration ✅
**Implementation:**
- API Management security policy validation
- Rate limiting, JWT validation, CORS configuration
- Service-level security checks

**Detection Patterns:**
- Missing API policies (rate-limit, validate-jwt)
- CORS set to wildcard (*) - security risk
- Missing authentication on APIs

#### KSI-SVC-04: Backup and Recovery Configuration ✅
**What to Check:**
**Implementation:**
- Azure Backup vault configuration for Storage, SQL, VMs
- Backup policy validation (daily, geo-redundant)
- Recovery Services vault checks

**Detection Patterns:**
- Storage accounts/SQL/VMs without backup configuration
- Missing `Microsoft.RecoveryServices/vaults` (Bicep)
- Missing `azurerm_recovery_services_vault` (Terraform)

#### KSI-SVC-05: Patch Management Automation ✅
**Implementation:**
- VM automatic OS patching (AutomaticByPlatform)
- AKS automatic upgrade configuration
- Update Management validation

**Detection Patterns:**
- VMs without `patchSettings` or `automatic_updates_enabled`
- AKS without `automatic_channel_upgrade = "patch"`
- Reports good practice when automatic patching detected

#### KSI-MLA-01: Centralized Logging to SIEM ✅
**Implementation:**
- Log Analytics workspace configuration
- Microsoft Sentinel onboarding
- Diagnostic settings centralization validation

**Detection Patterns:**
- Diagnostic settings without Log Analytics workspace reference
- Missing Sentinel configuration
- Reports good practice when workspace + Sentinel detected

#### KSI-MLA-02: Audit Log Retention ✅
**Implementation:**
- Log retention validation (≥90 days for FedRAMP)
- Immutable storage for audit logs
- Automatic severity flagging for non-compliance

**Detection Patterns:**
- `retention_in_days < 90` (HIGH severity)
- Missing explicit retention configuration (MEDIUM)
- Missing immutability policy on log storage (MEDIUM)
- Reports good practice for retention ≥90 days

### App Code Additions (2 KSIs)

#### KSI-IAM-05: Service Account Management ✅
**Implementation (Python):**
- Detects hardcoded credentials (passwords, API keys, connection strings)
- Validates Azure Managed Identity usage
**Detection Patterns:**
- Hardcoded credentials: `password='...'`, `api_key='...'`, `secret='...'`
- Missing Managed Identity imports
- Reports good practice when `DefaultAzureCredential` or Key Vault detected
- Suggests migration from environment variables to Managed Identity

#### KSI-CNA-03: Microservices Security ✅
**Implementation (Python):**
- Service-to-service authentication validation (OAuth/JWT)
- SSL/TLS certificate verification checks
- mTLS configuration detection
- API rate limiting validation

**Detection Patterns:**
- HTTP client without `DefaultAzureCredential` or Bearer tokens
- `verify=False` in requests (SSL verification disabled - HIGH severity)
- Missing mTLS certificates for service calls
- Missing rate limiting decorators on API endpoints
- Reports good practice when proper auth + TLS detected

---

## Phase 3: Application Security (COMPLETE) ✅

**Target:** Add 8 KSIs → 25 total (35% coverage)
**Focus:** Secure coding practices, input validation, data privacy
**Completed:** December 2024
**Priority:** HIGH

### App Code Additions (8 KSIs)

#### KSI-SVC-01: Error Handling and Logging ✅
**Implementation (Python):**
- Detects bare `except:` clauses (should use specific exceptions)
- Validates error logging (should log to monitoring system)
- Checks for sensitive data in error messages

**Detection Patterns:**
- `except:` without exception type (MEDIUM severity)
- Missing logging in exception handlers
- Password/token/key in error messages (HIGH severity)
- Reports good practice when proper error handling detected

#### KSI-SVC-02: Input Validation ✅
**Implementation (Python):**
- SQL injection detection (string concatenation in SQL)
- Command injection detection (shell=True with user input)
- Path traversal prevention (os.path.join with user input)
- API input validation (Pydantic/Marshmallow schemas)

**Detection Patterns:**
- `.format()` or f-strings in SQL queries (HIGH severity)
- `subprocess` with `shell=True` and user input (HIGH severity)
- Unvalidated path operations (MEDIUM severity)
- Missing input validation schemas on API endpoints (MEDIUM severity)
- Reports good practice when parameterized queries/validation detected

#### KSI-SVC-07: Secure Coding Practices ✅
**Implementation (Python):**
- Detects use of `eval()` or `exec()` (code injection risk)
- Validates secure random number generation (secrets vs random module)
- Checks for unsafe deserialization (pickle)
- Detects hardcoded passwords in code

**Detection Patterns:**
- `eval(` or `exec(` usage (HIGH severity)
- `import random` for security purposes (should use secrets module - MEDIUM)
- `pickle.loads()` with untrusted data (HIGH severity)
- `password = "..."` hardcoded (HIGH severity)
- Reports good practice when `secrets` module used

#### KSI-PIY-01: Data Inventory and Classification ✅
**Implementation (Python):**
- Detects PII handling without classification tags
- Validates data classification metadata
- Checks for proper data handling based on classification

**Detection Patterns:**
- PII variables (ssn, email, name) without `@dataclass` or classification decorators (MEDIUM)
- Missing data classification tags on models
- Reports good practice when classification metadata present

#### KSI-PIY-03: Privacy Controls Implementation ✅
**Implementation (Python):**
- Data retention policy validation
- User consent mechanisms
- Data export/deletion capabilities (GDPR compliance)

**Detection Patterns:**
- Database models without `retention_days` or TTL configuration (LOW severity)
- Missing deletion methods for user data (MEDIUM severity)
- Missing data export functionality (MEDIUM severity)
- Reports good practice when privacy controls implemented

#### KSI-CNA-07: Service Mesh Configuration ✅
**Implementation (Python):**
- Istio/Linkerd configuration security validation
- mTLS enforcement in service mesh
- Authorization policies validation

**Detection Patterns:**
- Istio/Linkerd config without `STRICT` mTLS mode (HIGH severity)
- Missing authorization policies (MEDIUM severity)
- Permissive network policies (LOW severity)
- Reports good practice when proper service mesh security detected

#### KSI-IAM-04: Least Privilege Access ✅
**Implementation (Python):**
- Detects wildcard permissions in Azure SDK calls
- Validates scope limitation in RBAC assignments
- Checks for overly broad role definitions

**Detection Patterns:**
- `scope='*'` in role assignments (HIGH severity)
- Wildcard resource access (e.g., `storage_account='*'`) (HIGH severity)
- Missing scope limitation on privileged operations (MEDIUM severity)
- Reports good practice when least privilege enforced

#### KSI-IAM-07: Session Management ✅
**Implementation (Python):**
- Session timeout validation (Flask/Django)
- Secure cookie configuration (httponly, secure, samesite)
- Token rotation enforcement (JWT refresh)

**Detection Patterns:**
- Missing session timeout configuration (MEDIUM severity)
- Cookies without `httponly=True, secure=True, samesite='Strict'` (HIGH severity)
- Missing JWT refresh token logic (MEDIUM severity)
- Reports good practice when secure session management detected

**Test Coverage:** All Phase 1 + Phase 2 tests (14) continue passing with Phase 3 additions.

---

## Phase 4: DevSecOps Automation 🤖
- No wildcard permissions
- Scope limited to necessary resources

#### KSI-IAM-07: Session Management (Python)
- Secure session tokens
- Session timeout configured
- Token rotation implemented

---

## Phase 4: DevSecOps Automation 🔧

**Target:** Add 6 KSIs → 31 total (43% coverage)
**Focus:** CI/CD security, change management
**Effort:** 2-3 weeks
**Priority:** MEDIUM

### CI/CD Pipeline Checks (6 KSIs)

#### KSI-CMT-01: Change Management Automation
- All changes via pull requests
- Required reviewers configured
- Branch protection enabled

#### KSI-CMT-02: Deployment Procedures
- Deployment gates configured
- Approval workflows required
- Rollback procedures defined

#### KSI-CMT-03: Automated Testing in CI/CD
- Unit tests in pipeline
- Security scanning in pipeline
- Integration tests before deployment

#### KSI-AFR-01: Automated Vulnerability Scanning
- Container image scanning
- IaC scanning (Checkov, Terrascan)
- SAST/DAST tools integrated

#### KSI-AFR-02: Security Finding Remediation
- Auto-create tickets for vulnerabilities
- SLA tracking for fixes
- Critical vulnerabilities block deployment

#### KSI-CED-01: Continuous Evidence Collection
- Automated evidence generation
- Evidence stored in compliance repository
- API for evidence retrieval

---

## Phase 5: Runtime Security & Monitoring (COMPLETE) ✅

**Target:** Add 6 KSIs → 37 total (51% coverage)
**Focus:** Runtime detection, incident response
**Completed:** December 2024
**Priority:** MEDIUM

### Runtime Monitoring (6 KSIs) ✅

#### KSI-MLA-03: Security Monitoring Alerts ✅
**Implementation:**
- Detects missing Application Insights or Log Analytics workspace
- Checks for Azure Monitor alert rules and scheduled query rules
- Validates SIEM integration and alert thresholds
- Reports good practice when monitoring + alerts configured

**Detection Patterns:**
- Missing `Microsoft.Insights/components` or `Microsoft.OperationalInsights/workspaces`
- Missing `Microsoft.Insights/scheduledQueryRules` or `metricAlerts`
- Recommends security alert rules for failed logins, anomalies

#### KSI-MLA-04: Performance Monitoring ✅
**Implementation:**
- Checks for Application Insights on scalable resources
- Validates autoscale settings on App Service Plans, AKS, VMSS
- Recommends performance baselines and anomaly detection
- Reports good practice when App Insights configured

**Detection Patterns:**
- Scalable resources (`Microsoft.Web/serverfarms`, AKS, VMSS) without App Insights
- Missing `Microsoft.Insights/autoscalesettings` for performance optimization

#### KSI-MLA-06: Log Analysis Automation ✅
**Implementation:**
- Detects missing Log Analytics workspace or Sentinel
- Checks for Sentinel analytics rules (scheduled, fusion)
- Validates KQL queries for threat detection
- Reports good practice when analytics rules exist

**Detection Patterns:**
- Missing `Microsoft.OperationalInsights/workspaces` or Sentinel solution
- Missing `Microsoft.SecurityInsights/alertRules`
- Recommends KQL queries for failed logins, anomalous activity

#### KSI-INR-01: Incident Detection ✅
**Implementation:**
- Detects missing Sentinel for incident detection
- Checks for automation rules for incident triage
- Validates incident auto-creation and severity classification
- Reports good practice when automation rules configured

**Detection Patterns:**
- Missing `Microsoft.SecurityInsights` (Sentinel)
- Missing `Microsoft.SecurityInsights/automationRules`
- Recommends incident creation rules, severity classification

#### KSI-INR-02: Incident Response Logging ✅
**Implementation:**
- Checks for diagnostic logging on Logic Apps (incident response)
- Validates response action logging for audit purposes
- Ensures 365-day retention for FedRAMP compliance
- Reports good practice when diagnostic settings exist

**Detection Patterns:**
- Logic Apps without diagnostic settings
- Missing `Microsoft.Insights/diagnosticSettings` with `scope: logicApp`
- Recommends WorkflowRuntime logging with 1-year retention

#### KSI-AFR-03: Threat Intelligence Integration ✅
**Implementation:**
- Detects missing Defender for Cloud or Sentinel
- Checks for threat intelligence data connectors
- Validates IOC matching and threat feeds
- Reports good practice when threat intel configured

**Detection Patterns:**
- Missing `Microsoft.Security/pricings` (Defender for Cloud)
- Missing `Microsoft.SecurityInsights/dataConnectors` with threat intel
- Recommends TAXII feeds, IOC matching, threat scores

**Test Coverage:** 12 new tests (71 total) - All passing ✅

---

## Phase 6A: Infrastructure Resilience & Security (COMPLETE) ✅

**Target:** Add 8 KSIs → 45 total (62.5% coverage)
**Focus:** Disaster recovery, backup, network security, cryptography
**Completed:** December 2024
**Priority:** HIGH

### Infrastructure Resilience (8 KSIs) ✅

#### KSI-RPL-01: Recovery Objectives ✅
**Implementation:**
- Detects missing Recovery Services Vault or backup configuration
- Checks for RTO/RPO documentation in resource tags
- Validates recovery infrastructure for critical resources
- Reports good practice when RTO/RPO properly documented

**Detection Patterns:**
- Missing `Microsoft.RecoveryServices/vaults` (Bicep) or `azurerm_recovery_services_vault` (Terraform)
- Missing RTO/RPO tags on recovery resources
- Recommends 365-day retention for FedRAMP compliance

#### KSI-RPL-02: Recovery Plans ✅
**Implementation:**
- Detects missing Azure Site Recovery replication
- Checks for recovery plan resources and orchestration
- Validates replication policies and failover configuration
- Reports good practice when recovery plans exist

**Detection Patterns:**
- Missing `Microsoft.RecoveryServices/vaults/replicationRecoveryPlans` (Bicep)
- Missing `azurerm_site_recovery_replication_policy` (Terraform)
- Recommends DR drills and recovery plan testing

#### KSI-RPL-03: System Backups ✅
**Implementation:**
- Checks for backup vault and policies on critical resources
- Validates backup configuration for VMs, SQL, Storage
- Ensures 365-day retention for FedRAMP compliance
- Reports good practice when backup policies configured

**Detection Patterns:**
- Critical resources (VMs, SQL, Storage) without backup protection
- Missing `Microsoft.RecoveryServices/vaults/backupPolicies` (Bicep)
- Missing `azurerm_backup_policy_vm` (Terraform)

#### KSI-RPL-04: Recovery Testing ✅
**Implementation:**
- Detects missing automation for recovery testing
- Checks for scheduled runbooks for DR drills
- Validates test failover automation
- Reports good practice when recovery testing automated

**Detection Patterns:**
- Missing `Microsoft.Automation/automationAccounts` (Bicep)
- Missing `azurerm_automation_runbook` with recovery testing (Terraform)
- Recommends monthly DR drills to validate RTO/RPO

#### KSI-CNA-03: Traffic Flow Enforcement ✅
**Implementation:**
- Detects missing Azure Firewall or route tables
- Checks for NSG flow logs and traffic analytics
- Validates network segmentation and traffic control
- Reports good practice when firewall and flow logs configured

**Detection Patterns:**
- Missing `Microsoft.Network/azureFirewalls` or route tables (Bicep)
- Missing `azurerm_firewall` or `azurerm_route_table` (Terraform)
- Missing NSG flow logs for traffic monitoring

#### KSI-CNA-05: DDoS Protection ✅
**Implementation:**
- Detects VNets without DDoS Protection Plan
- Checks for DDoS Standard tier (required for FedRAMP)
- Validates DDoS enablement on virtual networks
- Reports good practice when DDoS Protection configured

**Detection Patterns:**
- VNets without `Microsoft.Network/ddosProtectionPlans` (Bicep)
- Missing `azurerm_network_ddos_protection_plan` (Terraform)
- Notes DDoS Protection Standard cost (~$2,944/month)

#### KSI-IAM-05: Least Privilege Access ✅
**Implementation:**
- Detects missing or overly permissive RBAC roles
- Checks for Owner/Contributor role assignments (high risk)
- Validates JIT access and managed identity usage
- Reports good practice when least privilege implemented

**Detection Patterns:**
- Missing RBAC role assignments
- Owner/Contributor roles assigned to users (HIGH severity)
- Missing JIT access for privileged operations
- Recommends specific roles (e.g., Virtual Machine Contributor)

#### KSI-AFR-11: FIPS Cryptographic Modules ✅
**Implementation:**
- Detects missing Key Vault Premium (HSM-backed)
- Checks for TLS 1.2+ enforcement on all resources
- Validates FIPS 140-2 Level 2/3 cryptography
- Reports good practice when HSM and TLS 1.2+ configured

**Detection Patterns:**
- Missing Key Vault Premium SKU (FIPS 140-2 Level 2 HSMs)
- Missing TLS 1.2 enforcement on Storage, SQL, App Service
- Missing customer-managed keys for encryption
- Notes Managed HSM for FIPS 140-2 Level 3

**Test Coverage:** 16 new tests (71 total) - All passing ✅
**Implementations:** BicepAnalyzer + TerraformAnalyzer complete

---

## Phase 6B: Service Management & Advanced Monitoring 🎯

**Target:** Add 8 KSIs → 53 total (~74% coverage)
**Focus:** Service integrity, advanced logging, configuration management
**Effort:** 1-2 weeks
**Priority:** MEDIUM

### Remaining High-Priority KSIs (8 total)

#### Service Management (2 KSIs)
- KSI-SVC-09: Service integrity verification
- KSI-SVC-10: Secure data destruction

#### Advanced Monitoring (2 KSIs)
- KSI-MLA-07: Log correlation and analysis
- KSI-MLA-08: Anomaly detection

#### Authorization & Findings (2 KSIs)
- KSI-AFR-07: Remediation tracking
- KSI-AFR-08: False positive management

#### Cloud Native Architecture (1 KSI)
- KSI-CNA-08: Microservices security

#### Incident Response (1 KSI)
- KSI-INR-03: Incident response automation

#### Configuration Management (1 KSI)
- KSI-CMT-04: Configuration drift detection

---

## Phase 7: Full Coverage 🎯

**Target:** Add 19 KSIs → 72 total (100% coverage)
**Focus:** Remaining families (TPR, remaining AFR, CED, PIY, MLA)
**Effort:** 3-4 weeks
**Priority:** LOW

### Remaining Families

#### TPR: Third-Party Risk (4 KSIs)
- KSI-TPR-01: Vendor security assessment
- KSI-TPR-02: Third-party monitoring
- KSI-TPR-03: Supply chain security
- KSI-TPR-04: Vendor SLA compliance

#### Additional AFR (3 KSIs)
- KSI-AFR-04, AFR-05, AFR-06: Additional findings management

#### Additional CED (1 KSI)
- KSI-CED-02: Evidence automation enhancement

#### Additional PIY (5 KSIs)
- KSI-PIY-04 through KSI-PIY-08: Privacy and inventory management

#### Additional MLA (3 KSIs)
- KSI-MLA-09, MLA-10, MLA-11: Advanced monitoring

#### Additional CMT (2 KSIs)
- KSI-CMT-05, CMT-06: Change management automation

---

## Implementation Strategy

### Adding New KSI Checks

1. **Research the KSI**
   - Review KSI definition from FedRAMP 20x data
   - Understand technical requirements
   - Identify Azure/cloud-native implementations

2. **Define Detection Patterns**
   - What code patterns indicate compliance?
   - What patterns indicate violations?
   - What edge cases exist?

3. **Implement Check Method**
   - Add `_check_*` method to appropriate analyzer
   - Use regex for pattern matching
   - Create Finding objects with proper severity

4. **Write Tests**
   - Positive test (should detect issue)
   - Negative test (should recognize good practice)
   - Edge case tests

5. **Update Documentation**
   - Add to analyzer documentation
   - Update README with new KSI coverage
   - Update TESTING.md with test guidance

### Code Organization

```
analyzers/
  ├── base.py              # Base classes (no changes)
  ├── iac_analyzer.py      # Bicep/Terraform (expand here)
  ├── app_analyzer.py      # Python (expand here)
  └── cicd_analyzer.py     # NEW: CI/CD pipeline checks (Phase 4)
```

### Testing Strategy

- Each new KSI should have 2-3 tests minimum
- Test both detection and good practice recognition
- Run full test suite after additions
- Maintain >95% test coverage

---

## Timeline

| Phase | KSIs Added | Total Coverage | Duration | Status |
|-------|-----------|----------------|----------|--------|
| 1 | 8 | 11% | - | ✅ Complete |
| 2 | 9 | 24% | 2-3 weeks | 🎯 Next |
| 3 | 8 | 35% | 2-3 weeks | Planned |
| 4 | 6 | 43% | 2-3 weeks | Planned |
| 5 | 6 | 51% | 2-3 weeks | Planned |
| 6 | 35 | 100% | 4-6 weeks | Planned |

**Total Timeline to 100% Coverage:** ~4-5 months

---

## Success Metrics

- **KSI Coverage:** Target 100% (72 KSIs)
- **Test Coverage:** Maintain >95%
- **False Positives:** <5% across all checks
- **Performance:** Analysis completes in <5 seconds per file
- **Usability:** PR comments actionable and helpful

---

## Contributing

To add a new KSI check:

1. Review this roadmap for priority
2. Follow implementation strategy above
3. Ensure tests pass
4. Update documentation
5. Submit PR with clear description

See `CONTRIBUTING.md` for detailed guidelines.
