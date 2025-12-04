# Code Analyzer Expansion Roadmap

## Current Status: Phase 1 Complete ✅

**Coverage:** 8 KSIs out of 72 (11%)
**Families Covered:** IAM (2/7), MLA (1/8), SVC (3/10), CNA (1/8), PIY (1/8)

### Phase 1: Foundation (COMPLETE)

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

## Phase 2: Critical Infrastructure Security 🎯 NEXT

**Target:** Add 9 KSIs → 17 total (24% coverage)
**Focus:** High-priority infrastructure security checks
**Effort:** 2-3 weeks
**Priority:** HIGH

### IaC Additions (7 KSIs)

#### KSI-IAM-02: Multi-Factor Authentication Enforcement
**What to Check:**
- Bicep: Conditional Access policies require MFA
- Terraform: `azurerm_conditional_access_policy` with MFA requirement
- Detect missing MFA enforcement on admin accounts

**Detection Patterns:**
- Missing `grantControls.builtInControls: ["mfa"]`
- Conditional Access policies without MFA
- Admin roles without MFA requirement

#### KSI-IAM-06: Privileged Access Management
**What to Check:**
- Azure Privileged Identity Management (PIM) configuration
- Just-in-time (JIT) access policies
- Elevated permissions time-limited
- Approval workflows for privileged roles

**Detection Patterns:**
- Permanent admin role assignments (not JIT)
- Missing `azurerm_role_assignment` with `eligible` type
- No approval requirement for privileged roles

#### KSI-CNA-02: Container Security and Isolation
**What to Check:**
- Container images from trusted registries only
- Image scanning enabled
- Pod security policies/standards
- Container privilege escalation disabled

**Detection Patterns:**
- `image: public/untrusted-registry`
- Missing `imagePullSecrets`
- `privileged: true` in container specs
- No network policies for pod isolation

#### KSI-CNA-04: Immutable Infrastructure
**What to Check:**
- Infrastructure as Code (IaC) only deployment
- No manual changes to resources
- Resource locks on critical infrastructure
- Drift detection enabled

**Detection Patterns:**
- Missing resource locks on production resources
- No Azure Policy for enforcing IaC-only changes
- Mutable infrastructure configurations

#### KSI-CNA-06: API Gateway Configuration
**What to Check:**
- API Management (APIM) security policies
- Rate limiting configured
- OAuth/JWT validation
- CORS policies properly set

**Detection Patterns:**
- Missing rate limiting policies
- No authentication on APIs
- CORS set to `*` (allow all origins)
- Missing request validation

#### KSI-SVC-04: Backup and Recovery Configuration
**What to Check:**
- Azure Backup configured
- Backup retention policies set
- Geo-redundant storage for backups
- Recovery testing scheduled

**Detection Patterns:**
- Storage accounts without backup
- Databases without backup policies
- No geo-redundancy for backups
- Missing `azurerm_backup_policy_*`

#### KSI-SVC-05: Patch Management Automation
**What to Check:**
- Azure Update Management configured
- Automatic patching enabled for VMs
- Container base images up-to-date
- Maintenance windows defined

**Detection Patterns:**
- VMs without Update Management
- `automatic_os_upgrade_policy.enable = false`
- Missing `azurerm_maintenance_configuration`

#### KSI-MLA-01: Centralized Logging to SIEM
**What to Check:**
- All logs sent to Log Analytics workspace
- Microsoft Sentinel configured
- Log retention meets requirements
- Critical resources monitored

**Detection Patterns:**
- Diagnostic settings not pointing to workspace
- Missing Sentinel configuration
- Logs not centralized across resources

#### KSI-MLA-02: Audit Log Retention
**What to Check:**
- Log retention ≥ 90 days (or per requirements)
- Immutable storage for audit logs
- Automated archival to long-term storage

**Detection Patterns:**
- `retention_in_days < 90`
- Missing immutable storage policy
- No archival automation

### App Code Additions (2 KSIs)

#### KSI-IAM-05: Service Account Management
**What to Check (Python):**
- Managed Identity used (not service principals)
- No hardcoded client secrets
- Service accounts follow least privilege
- Service account credentials rotated

**Detection Patterns:**
- `ServicePrincipalCredentials` instead of `DefaultAzureCredential`
- Hardcoded `AZURE_CLIENT_SECRET`
- Overly broad permissions in code

#### KSI-CNA-03: Microservices Security
**What to Check (Python):**
- Service-to-service authentication
- mTLS between services
- Circuit breaker patterns
- API versioning

**Detection Patterns:**
- HTTP instead of HTTPS for internal calls
- Missing authentication headers
- No retry/circuit breaker logic

---

## Phase 3: Application Security 📱

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
