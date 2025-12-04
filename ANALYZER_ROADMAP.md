# Code Analyzer Expansion Roadmap

## Current Status: Phase 2 Complete ✅

**Coverage:** 17 KSIs out of 72 (24%)
**Families Covered:** IAM (4/7), MLA (3/8), SVC (5/10), CNA (4/8), PIY (1/8)

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

## Phase 3: Application Security 📱 🎯 NEXT

**Target:** Add 8 KSIs → 25 total (35% coverage)
**Focus:** Secure coding practices, input validation
**Effort:** 2-3 weeks
**Priority:** HIGH

### App Code Additions (8 KSIs)

#### KSI-SVC-01: Error Handling and Logging
- Proper exception handling
- No sensitive data in error messages
- Errors logged to monitoring system

#### KSI-SVC-02: Input Validation
- Validate all user inputs
- Parameterized queries (SQL injection prevention)
- XSS prevention in output

#### KSI-SVC-07: Secure Coding Practices
- No use of unsafe functions (eval, exec)
- Secure random number generation
- Memory safety checks

#### KSI-PIY-01: Data Inventory and Classification
- Data classification tags in code
- Sensitive data marked appropriately
- Data handling follows classification

#### KSI-PIY-03: Privacy Controls Implementation
- Data retention policies in code
- User consent mechanisms
- Data export/deletion capabilities

#### KSI-CNA-07: Service Mesh Configuration
- Istio/Linkerd configuration security
- mTLS enabled
- Authorization policies defined

#### KSI-IAM-04: Least Privilege Access (Python)
- Minimal permissions in IAM calls
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

## Phase 5: Runtime Security & Monitoring 🔍

**Target:** Add 6 KSIs → 37 total (51% coverage)
**Focus:** Runtime detection, incident response
**Effort:** 2-3 weeks
**Priority:** MEDIUM

### Runtime Monitoring (6 KSIs)

#### KSI-MLA-03: Security Monitoring Alerts
- Alert rules configured
- Security alerts sent to SIEM
- Alert thresholds defined

#### KSI-MLA-04: Performance Monitoring
- Application Insights configured
- Performance baselines set
- Anomaly detection enabled

#### KSI-MLA-06: Log Analysis Automation
- KQL queries for threat detection
- Automated log parsing
- Correlation rules defined

#### KSI-INR-01: Incident Detection
- Sentinel analytics rules
- Incident auto-creation
- Severity classification

#### KSI-INR-02: Incident Response Logging
- All incidents logged
- Response actions tracked
- Post-mortem documentation

#### KSI-AFR-03: Threat Intelligence Integration
- Threat intel feeds configured
- IOC matching enabled
- Threat scores calculated

---

## Phase 6: Full Coverage 🎯

**Target:** Add 35 KSIs → 72 total (100% coverage)
**Focus:** Remaining families (RPL, TPR, remaining AFR, CED, PIY)
**Effort:** 4-6 weeks
**Priority:** LOW

### Remaining Families

#### RPL: Recovery & Planning (4 KSIs)
- KSI-RPL-01: Backup testing
- KSI-RPL-02: Disaster recovery plans
- KSI-RPL-03: Business continuity
- KSI-RPL-04: Recovery time objectives

#### TPR: Third-Party Risk (4 KSIs)
- KSI-TPR-01: Vendor security assessment
- KSI-TPR-02: Third-party monitoring
- KSI-TPR-03: Supply chain security
- KSI-TPR-04: Vendor SLA compliance

#### Additional AFR (9 KSIs)
- KSI-AFR-04 through KSI-AFR-11: Advanced findings and remediation

#### Additional CED (3 KSIs)
- KSI-CED-02 through KSI-CED-04: Evidence delivery automation

#### Additional PIY (5 KSIs)
- KSI-PIY-04 through KSI-PIY-08: Privacy and inventory management

#### Additional CNA (5 KSIs)
- KSI-CNA-05, KSI-CNA-08: Cloud-native architecture

#### Additional SVC (4 KSIs)
- KSI-SVC-09, KSI-SVC-10: Service management

#### Additional MLA (5 KSIs)
- KSI-MLA-07, KSI-MLA-08: Advanced logging/monitoring

#### Additional CMT (2 KSIs)
- KSI-CMT-04, KSI-CMT-05: Change management automation

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
