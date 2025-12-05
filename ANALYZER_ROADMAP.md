# Code Analyzer Expansion Roadmap

## Current Status: Phase 7 Complete ✅

**Coverage:** 55 KSIs out of 72 (76.4%) - **Active** KSIs: 55 out of 65 (84.6%)
**Note:** 7 KSIs retired/superseded by FedRAMP, reducing total active count from 72 to 65
**Families Covered:** IAM (7/7 complete), MLA (7/8), SVC (10/10 complete), CNA (8/8 complete), PIY (3/8), CMT (4/4 complete), AFR (5/7), CED (1/2), INR (3/3 complete), RPL (4/4 complete), TPR (2/4)

### Phase 1: Foundation (COMPLETE) ✅

**IaC Checks (Bicep/Terraform):**
- ✅ KSI-MLA-05: Diagnostic logging configuration
- ✅ KSI-SVC-06: Key Vault secrets management
- ✅ KSI-CNA-01: Network Security Groups
- ✅ KSI-IAM-03: RBAC role assignments
- ✅ KSI-SVC-03: Encryption configuration

**App Code Checks (Python/C#/Java/TypeScript):**
- ✅ KSI-IAM-01: API authentication
- ✅ KSI-SVC-06: Secrets management (hardcoded keys)
- ✅ KSI-SVC-08: Dependency security (vulnerable libraries)
- ✅ KSI-PIY-02: PII handling and encryption
- ✅ KSI-MLA-05: Diagnostic logging

**Phase 1 Coverage:** 8 KSIs (11.1%) - Python/C#/Java/TypeScript
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

**Phase 2 Coverage:** 10 KSIs (13.9%) - Python/C#/Java/TypeScript

#### KSI-IAM-05: Service Account Management ✅
**Implementation (Python/C#/Java/TypeScript):**
- Detects hardcoded credentials (passwords, API keys, connection strings)
- Validates Azure Managed Identity usage
**Detection Patterns:**
- Hardcoded credentials: `password='...'`, `api_key='...'`, `secret='...'`
- Missing Managed Identity imports
- Reports good practice when `DefaultAzureCredential` or Key Vault detected
- Suggests migration from environment variables to Managed Identity

#### KSI-CNA-03: Microservices Security ✅
**Implementation (Python/C#/Java/TypeScript):**
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

## Phase 6B: Advanced Infrastructure Security (COMPLETE) ✅

**Target:** Add 8 KSIs → 53 total (73.6% coverage)
**Focus:** Communication integrity, data lifecycle, advanced monitoring, microservices
**Completed:** January 2025
**Priority:** MEDIUM

### IaC Additions (8 KSIs)

#### KSI-SVC-09: Communication Integrity ✅
**Implementation:**
- Detects mutual TLS (mTLS) and certificate-based authentication
- Validates Application Gateway SSL policies (TLS 1.2+, modern cipher suites)
- Checks App Service client certificate validation
- Validates API Management certificate requirements

**Detection Patterns (Bicep):**
- `Microsoft.Network/applicationGateways` with `sslPolicy` (predefined/custom)
- `Microsoft.Web/sites` with `clientCertEnabled: true`, `clientCertMode: 'Required'`
- `Microsoft.ApiManagement` with certificate configuration
- Missing mTLS = MEDIUM severity

**Detection Patterns (Terraform):**
- `azurerm_application_gateway` with `ssl_policy` block
- `azurerm_linux_web_app` with `client_certificate_enabled`, `client_certificate_mode = "Required"`
- `azurerm_api_management` with certificate blocks
- Reports good practice when mTLS detected

#### KSI-SVC-10: Data Destruction ✅
**Implementation:**
- Detects soft delete and lifecycle policies for secure data removal
- Validates blob lifecycle management policies
- Checks SQL/Cosmos DB backup retention
- Key Vault purge protection validation

**Detection Patterns (Bicep):**
- `Microsoft.Storage/storageAccounts/managementPolicies` with lifecycle rules
- Key Vault `softDeleteRetentionInDays` (90 days recommended)
- Storage `deleteRetentionPolicy` (30+ days)
- SQL `shortTermRetentionPolicy` with retention days

**Detection Patterns (Terraform):**
- `azurerm_storage_management_policy` with delete actions
- `azurerm_key_vault` with `soft_delete_retention_days`, `purge_protection_enabled`
- Storage `delete_retention_policy` in blob_properties
- SQL `short_term_retention_policy` configuration

#### KSI-MLA-07: Event Types Monitoring ✅
**Implementation:**
- Validates comprehensive event type documentation
- Checks Data Collection Rules for event categorization
- Detects monitoring workbooks for event visibility
- Log Analytics workspace validation

**Detection Patterns (Bicep):**
- `Microsoft.OperationalInsights/workspaces` with diagnostic settings
- `Microsoft.Insights/dataCollectionRules` with specific event streams
- `Microsoft.Insights/workbooks` for event monitoring
- Missing DCR = MEDIUM severity

**Detection Patterns (Terraform):**
- `azurerm_log_analytics_workspace` configuration
- `azurerm_monitor_data_collection_rule` with data_flow blocks
- `azurerm_application_insights_workbook` for dashboards
- Reports good practice when comprehensive logging configured

#### KSI-MLA-08: Log Data Access ✅
**Implementation:**
- Validates least-privilege RBAC on Log Analytics workspaces
- Checks for resource-scoped log permissions
- Detects Private Link endpoints for secure log access
- PIM integration for just-in-time log access

**Detection Patterns (Bicep):**
- Log Analytics with `Microsoft.Authorization/roleAssignments` (scope = workspace)
- `publicNetworkAccessForQuery: 'Disabled'` for private-only access
- `enableLogAccessUsingOnlyResourcePermissions: true` for resource context
- Missing RBAC = HIGH severity

**Detection Patterns (Terraform):**
- `azurerm_log_analytics_workspace` with role assignments
- `public_network_access_enabled = false` for secure access
- `azurerm_private_endpoint` for Log Analytics
- RBAC alone = good practice; Private Link absence = suggestion

#### KSI-AFR-07: Secure Configuration ✅
**Implementation:**
- Validates secure-by-default settings across all resources
- Checks HTTPS enforcement (httpsOnly, minTlsVersion)
- Detects disabled public access (publicNetworkAccess)
- Validates Azure AD authentication enforcement

**Detection Patterns (Bicep):**
- App Service: `httpsOnly: true`, `minTlsVersion: '1.2'`
- Storage: `allowBlobPublicAccess: false`, `minimumTlsVersion: 'TLS1_2'`
- SQL: `minimalTlsVersion: '1.2'`, `publicNetworkAccess: 'Disabled'`
- Key Vault: `enableRbacAuthorization: true`, `publicNetworkAccess: 'disabled'`

**Detection Patterns (Terraform):**
- `azurerm_linux_web_app`: `https_only = true`, `minimum_tls_version = "1.2"`
- `azurerm_storage_account`: `allow_nested_items_to_be_public = false`, `min_tls_version = "TLS1_2"`
- `azurerm_mssql_server`: `minimum_tls_version = "1.2"`, `public_network_access_enabled = false`
- Insecure defaults = HIGH severity

#### KSI-CNA-08: Microservices Security ✅
**Implementation:**
- Detects service mesh configuration (Istio on AKS)
- Validates Dapr for distributed applications
- Checks API Management for microservices gateway
- Network policy enforcement for pod-to-pod

**Detection Patterns (Bicep):**
- AKS `serviceMeshProfile` with `mode: 'Istio'`
- Container Apps with `dapr` configuration (`appId`, `appProtocol`)
- `Microsoft.ApiManagement` for gateway pattern
- Missing service mesh = MEDIUM severity

**Detection Patterns (Terraform):**
- `azurerm_kubernetes_cluster` with `service_mesh_profile { mode = "Istio" }`
- `azurerm_container_app` with `dapr { enabled = true }`
- `azurerm_api_management` for microservices
- Any control (service mesh OR dapr OR apim) = good practice

#### KSI-INR-03: Incident After-Action Reports ✅
**Implementation:**
- Detects automated incident after-action reporting
- Validates Logic Apps for post-incident workflows
- Checks Automation runbooks for lessons learned
- Sentinel playbook integration

**Detection Patterns (Bicep):**
- `Microsoft.Logic/workflows` for automated reporting
- `Microsoft.Automation/automationAccounts/runbooks` for quarterly reviews
- Logic Apps with SecurityInsights integration (Sentinel playbooks)
- Missing automation = MEDIUM severity

**Detection Patterns (Terraform):**
- `azurerm_logic_app_workflow` for after-action automation
- `azurerm_automation_runbook` for lessons learned integration
- `azurerm_sentinel_automation_rule` for playbooks
- Reports good practice when workflows configured

#### KSI-CMT-04: Change Management Procedures ✅
**Implementation:**
- Validates change tracking via resource tags
- Detects staged deployment patterns (slots, blue-green)
- Checks Traffic Manager for controlled rollouts
- Resource locks for production protection

**Detection Patterns (Bicep):**
- Resource tags: `changeTicket`, `deploymentId`, `version`, `approvedBy`
- App Service slots for staged deployments
- Traffic Manager with weighted routing (blue-green)
- Management locks (CanNotDelete) on critical resources

**Detection Patterns (Terraform):**
- Tags map with `change_ticket`, `deployment_id`, `version`
- `azurerm_linux_web_app_slot` for staging
- `azurerm_traffic_manager_profile` with weighted endpoints
- `azurerm_management_lock` for production resources

**Test Coverage:** 16 new tests (87 total) - All passing ✅
**Implementations:** BicepAnalyzer + TerraformAnalyzer complete

---

## Phase 7: Supply Chain Security (COMPLETE) ✅

**Target:** Add 2 detectable KSIs → 55 total (76.4% of 72, 84.6% of 65 active)
**Focus:** Supply chain risk mitigation (remaining KSIs are organizational/policy-only)
**Completed:** December 2024
**Priority:** MEDIUM

### Supply Chain Security (2 KSIs) ✅

#### KSI-TPR-03: Supply Chain Risk Mitigation ✅
**Implementation:**
- Detects ACR (Azure Container Registry) security controls
- Validates image signing/trust policies (Notary, content trust)
- Checks for quarantine policies (unscanned image protection)
- Enforces private network access (no public exposure)
- AKS cluster supply chain controls (Azure Policy addon)
- Image cleaner and workload identity validation

**Detection Patterns (Bicep):**
- ACR without `trustPolicy.status: enabled` or `quarantinePolicy.status: enabled`
- ACR with `publicNetworkAccess: 'Enabled'` (should be Disabled)
- Missing retention policy for automatic image cleanup
- AKS without `azurePolicyEnabled: true` (can't enforce trusted registries)
- Missing severity: HIGH for ACR, MEDIUM for AKS

**Detection Patterns (Terraform):**
- `azurerm_container_registry` without `trust_policy { enabled = true }`
- Missing `quarantine_policy_enabled = true`
- `public_network_access_enabled = true` (should be false)
- `azurerm_kubernetes_cluster` without `azure_policy_enabled = true`
- Reports good practice when all controls present

**Authoritative Sources:**
- ACR security best practices: https://learn.microsoft.com/azure/container-registry/container-registry-best-practices
- AKS security: https://learn.microsoft.com/azure/aks/use-azure-policy
- Azure WAF - Security pillar (container security)

#### KSI-TPR-04: Third-Party Software Monitoring ✅
**Implementation:**
- Detects automated vulnerability monitoring infrastructure
- Validates Defender for Cloud configuration (dependency scanning)
- Checks for Log Analytics + Sentinel (SIEM)
- Automation accounts for third-party advisory monitoring
- Security alert configuration

**Detection Patterns (Bicep):**
- No `Microsoft.OperationalInsights/workspaces` (Log Analytics)
- Missing `Microsoft.Security/pricings` (Defender for Cloud)
- No `Microsoft.Automation/automationAccounts` for vulnerability monitoring
- Missing severity: MEDIUM
- Reports good practice when Defender OR Automation OR (LogAnalytics + diagnostics)

**Detection Patterns (Terraform):**
- No `azurerm_log_analytics_workspace`
- Missing `azurerm_security_center_subscription_pricing`
- No `azurerm_automation_account` for monitoring
- Missing `azurerm_sentinel_log_analytics_workspace_onboarding`
- Reports good practice when monitoring infrastructure present

**Authoritative Sources:**
- Defender for DevOps: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-devops-introduction
- Azure Sentinel (SIEM): https://learn.microsoft.com/azure/sentinel/
- Note: Complement with GitHub Advanced Security, Dependabot, Snyk in CI/CD

**Test Coverage:** 9 new tests (96 total) - All passing ✅
**Implementations:** BicepAnalyzer + TerraformAnalyzer complete

---

## Remaining KSIs: Organizational/Policy Requirements (14 KSIs)

**Reality Check:** The remaining 14 active KSIs (**19% of total**) are organizational and policy requirements that **CANNOT be detected through code analysis**. They require manual audits, documentation reviews, and process validation:

### AFR Family (6 KSIs - Documentation/Process)
- **AFR-04:** Vulnerability detection and response method documentation
- **AFR-05:** Significant change tracking process
- **AFR-06:** Ongoing Authorization Report maintenance plan
- **AFR-08:** Secure inbox for FedRAMP communications
- **AFR-09:** Effectiveness validation and reporting
- **AFR-10:** Incident Communications Procedures integration

**Why not detectable:** These require organizational documentation, manual processes, communication procedures, and external reporting - not code constructs.

### CED Family (3 KSIs - Training Programs)
- **CED-02:** Role-specific training for high-risk personnel
- **CED-03:** Training for privileged users
- **CED-04:** Stakeholder training effectiveness monitoring

**Why not detectable:** Training programs, effectiveness monitoring, and role assignments are HR/organizational functions - not infrastructure code.

### PIY Family (5 KSIs - Program Effectiveness)
- **PIY-04:** Security/privacy consideration effectiveness monitoring
- **PIY-05:** Information resource implementation evaluation methods
- **PIY-06:** Organizational investment effectiveness monitoring
- **PIY-07:** Software supply chain risk management decisions documentation
- **PIY-08:** Executive support measurement

**Why not detectable:** Program maturity metrics, executive communications, and organizational effectiveness - requires manual assessment.

### Analysis Complete

**Code-Detectable KSIs:** 55 out of 65 active (84.6% coverage)
**Policy/Organizational KSIs:** 14 out of 65 active (21.5% - manual audit required)
**Retired KSIs:** 7 (superseded by other requirements)

**Conclusion:** Phase 7 achieves **maximum practical code analysis coverage**. Remaining KSIs require organizational maturity assessments, not code scanning.

---

## Phase 7 (Legacy): Full Coverage 🎯

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
  ├── python_analyzer.py   # Python code analysis
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
