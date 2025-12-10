# KSI Evidence Automation Implementation Tracker

## Progress Overview

**Total Active KSIs:** 65  
**Implemented:** 39 (60.0%)  
**Remaining:** 26 (40.0%)

**Target:** Implement evidence automation for all 65 active KSIs

**Phase 1 Complete:** All 10 high-priority KSIs implemented ✅  
**MLA Family Complete:** All 5 MLA KSIs implemented ✅  
**INR Family Complete:** All 1 INR KSI implemented ✅  
**IAM Family Complete:** All 7 IAM KSIs implemented ✅  
**CNA Family Complete:** All 8 CNA KSIs implemented ✅  
**AFR Family Complete:** All 11 AFR KSIs implemented ✅

---

## Implementation Status by Family

### ✅ IAM - Identity and Access Management (7/7 = 100% COMPLETE)

- [x] **KSI-IAM-01** - Phishing-Resistant MFA ✅ COMPLETE
  - Evidence Type: log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 4 (Azure AD, Log Analytics, Blob Storage, Graph API)
  - Queries: 4 (2 KQL, 2 REST API)
  - Artifacts: 5

- [x] **KSI-IAM-02** - Privileged Access Management ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Entra ID, PIM, Conditional Access, Monitor, Graph API)
  - Queries: 6 (2 KQL, 4 Graph API)
  - Artifacts: 6

- [x] **KSI-IAM-03** - Non-User Accounts ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Managed Identity, Service Principals, Key Vault, Monitor, Policy)
  - Queries: 5 (2 Resource Graph, 2 KQL, 1 Graph API)
  - Artifacts: 5

- [x] **KSI-IAM-04** - Just-in-Time Authorization ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: high
  - Azure Services: 5 (PIM, RBAC, Conditional Access, Monitor, Graph)
  - Queries: 5 (1 KQL, 1 Resource Graph, 3 Graph API)
  - Artifacts: 5

- [x] **KSI-IAM-05** - Least Privilege ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (RBAC, Entitlement Management, Access Reviews, Defender, Monitor)
  - Queries: 5 (2 Resource Graph, 2 KQL, 1 Graph API)
  - Artifacts: 5

- [x] **KSI-IAM-06** - Suspicious Activity Response ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Identity Protection, Sentinel, Smart Lockout, Monitor, Defender for Cloud Apps)
  - Queries: 5 (3 Graph API, 2 KQL)
  - Artifacts: 5

- [x] **KSI-IAM-07** - Automated Account Management ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Lifecycle Workflows, Governance, Automation, SCIM, Monitor)
  - Queries: 5 (3 Graph API, 2 KQL)
  - Artifacts: 5

### ✅ CNA - Cloud Native Architecture (8/8 = 100% COMPLETE)

- [x] **KSI-CNA-01** - Restrict Network Traffic ✅ COMPLETE
  - Evidence Type: config-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 4 (Resource Graph, Network Watcher, Policy, Storage)
  - Queries: 5 (4 Resource Graph, 1 REST API)
  - Artifacts: 5

- [x] **KSI-CNA-02** - Minimize Attack Surface ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Firewall, NSG, Private Link, Bastion, Defender for Cloud)
  - Queries: 5 (3 Resource Graph, 1 REST API, 1 custom)
  - Artifacts: 5

- [x] **KSI-CNA-03** - Infrastructure as Code ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Network Watcher, Firewall, Policy, Monitor, Resource Graph)
  - Queries: 6 (4 Resource Graph, 2 KQL)
  - Artifacts: 6

- [x] **KSI-CNA-04** - Immutable Infrastructure ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (VMSS, AKS, ACR, DevOps/GitHub, Policy)
  - Queries: 5 (2 Resource Graph, 1 REST API, 1 DevOps API, 1 KQL)
  - Artifacts: 5

- [x] **KSI-CNA-05** - Unwanted Activity (DDoS Protection) ✅ COMPLETE
  - Evidence Type: log-based, metric-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (DDoS Protection, App Gateway/Front Door WAF, Firewall Premium, Monitor, Sentinel)
  - Queries: 5 (4 KQL, 1 Resource Graph)
  - Artifacts: 5

- [x] **KSI-CNA-06** - High Availability ✅ COMPLETE
  - Evidence Type: config-based, metric-based, process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Availability Zones, Site Recovery, Load Balancer/Traffic Manager, Monitor, Advisor)
  - Queries: 5 (2 Resource Graph, 2 REST API, 1 KQL)
  - Artifacts: 5

- [x] **KSI-CNA-07** - Best Practices ✅ COMPLETE
  - Evidence Type: config-based, process-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 5 (Advisor, Policy, Defender for Cloud, WAF Review, Monitor Workbooks)
  - Queries: 5 (3 REST API, 2 Resource Graph)
  - Artifacts: 5

- [x] **KSI-CNA-08** - Persistent Assessment and Automated Enforcement ✅ COMPLETE
  - Evidence Type: config-based, log-based, metric-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Defender for Cloud, Policy, Automation DSC, Arc, Monitor)
  - Queries: 5 (2 REST API, 2 Resource Graph, 1 KQL)
  - Artifacts: 5
- [ ] **KSI-CNA-06** - Microservices Security
- [ ] **KSI-CNA-07** - Service Mesh Security
- [ ] **KSI-CNA-08** - Zero Trust Architecture

### ✅ AFR - Authorization Framework (11/11 = 100% COMPLETE)

- [x] **KSI-AFR-01** - Minimum Assessment Scope (MAS) ✅ COMPLETE
  - Evidence Type: process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Policy, Monitor, DevOps, Resource Graph, Defender)
  - Queries: 5 (2 Resource Graph, 1 Policy, 1 Monitor KQL, 1 DevOps API)
  - Artifacts: 5
- [x] **KSI-AFR-02** - Key Security Indicators (Meta-KSI) ✅ COMPLETE
  - Evidence Type: process-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 5 (Monitor, Automation, DevOps, Logic Apps, Storage)
  - Queries: 5 (3 Azure KQL, 1 Storage API, 1 DevOps API)
  - Artifacts: 5
  - Special Note: Meta-KSI addressed by implementing all other 64 KSIs
- [x] **KSI-AFR-03** - Authorization Data Sharing ✅ COMPLETE
  - Evidence Type: process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Monitor, DevOps, Storage, Purview, Logic Apps)
  - Queries: 5 (1 DevOps API, 1 Purview API, 1 Monitor KQL, 2 Resource Graph)
  - Artifacts: 5
- [x] **KSI-AFR-04** - Vulnerability Detection and Response (VDR) ✅ COMPLETE
  - Evidence Type: log-based, metric-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Defender for Cloud, Defender for DevOps, ACR, Monitor, DevOps)
  - Queries: 5 (3 KQL, 1 REST API, 1 DevOps API)
  - Artifacts: 6
- [x] **KSI-AFR-05** - Significant Change Notifications (SCN) ✅ COMPLETE
  - Evidence Type: process-based
  - Automation Feasibility: high
  - Implementation Effort: high
  - Azure Services: 5 (Monitor, Logic Apps, DevOps, Policy, Sentinel)
  - Queries: 5 (2 Azure KQL, 1 Logic Apps API, 1 DevOps API, 1 Policy API)
  - Artifacts: 5
- [x] **KSI-AFR-06** - Collaborative Continuous Monitoring (CCM) ✅ COMPLETE
  - Evidence Type: log-based, metric-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Monitor, Sentinel, Defender for Cloud, Policy, DevOps)
  - Queries: 5 (2 KQL, 1 Resource Graph, 1 REST API, 1 DevOps API)
  - Artifacts: 6
- [x] **KSI-AFR-07** - Recommended Secure Configuration (RSC) ✅ COMPLETE
  - Evidence Type: config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Policy, Defender, Automation DSC, DevOps, Advisor)
  - Queries: 5 (1 Policy API, 1 Defender API, 1 Automation API, 1 Advisor API, 1 DevOps API)
  - Artifacts: 5
- [x] **KSI-AFR-08** - FedRAMP Security Inbox (FSI) ✅ COMPLETE
  - Evidence Type: process-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 5 (Microsoft 365, Defender for Office 365, Monitor, Sentinel, Logic Apps)
  - Queries: 5 (2 Graph API, 1 Audit Log, 1 Defender API, 2 KQL)
  - Artifacts: 5
- [x] **KSI-AFR-09** - Persistent Validation and Assessment (PVA) ✅ COMPLETE
  - Evidence Type: metric-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Defender for Cloud, Policy, Sentinel, Monitor, Automation)
  - Queries: 5 (1 Defender API, 1 Policy API, 2 KQL, 1 Resource Graph)
  - Artifacts: 5
- [x] **KSI-AFR-10** - Incident Communications Procedures (ICP) ✅ COMPLETE
  - Evidence Type: process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Sentinel, Logic Apps, Microsoft 365, DevOps, Monitor)
  - Queries: 5 (2 KQL, 1 Graph API, 2 DevOps API)
  - Artifacts: 5
- [x] **KSI-AFR-11** - Using Cryptographic Modules (UCM) ✅ COMPLETE
  - Evidence Type: config-based
  - Automation Feasibility: high
  - Implementation Effort: high
  - Azure Services: 5 (Key Vault, Defender for Cloud, Policy, Monitor, Defender for DevOps)
  - Queries: 5 (1 KQL, 1 Policy API, 1 Defender API, 1 DevOps API, 1 Resource Graph)
  - Artifacts: 5
- [ ] **KSI-AFR-09** - Continuous Authorization
- [ ] **KSI-AFR-10** - Risk Management
- [ ] **KSI-AFR-11** - Using Cryptographic Modules (UCM)

### ✅ MLA - Monitoring, Logging & Analysis (5/5 = 100%) ✅ FAMILY COMPLETE

- [x] **KSI-MLA-01** - Centralized Logging ✅
  - Services: 5 (Sentinel, Log Analytics, Monitor, Blob Storage, Policy)
  - Methods: 4
  - Queries: 6
  - Artifacts: 6
- [x] **KSI-MLA-02** - Log Retention ✅
  - Services: 5 (Monitor, Log Analytics, Storage, Sentinel, Policy)
  - Methods: 4
  - Queries: 5
  - Artifacts: 6
- [x] **KSI-MLA-05** - Infrastructure as Code Testing ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (DevOps, Policy, ARM, Defender for DevOps, Monitor)
  - Queries: 5 (1 DevOps API, 2 REST API, 1 KQL, 1 GitHub API)
  - Artifacts: 5
- [x] **KSI-MLA-07** - Event Types ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 4 (Monitor, Sentinel, Policy, Resource Graph)
  - Queries: 4 (2 Resource Graph, 2 KQL)
  - Artifacts: 5
- [x] **KSI-MLA-08** - Log Data Access ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 4 (RBAC, PIM, Private Link, Activity Log)
  - Queries: 5 (1 REST API, 1 Graph API, 2 KQL, 1 Resource Graph)
  - Artifacts: 5

### SVC - Service Management (6/9 = 66.7%)

- [x] **KSI-SVC-01** - Continuous Improvement ✅ COMPLETE
  - Evidence Type: log-based, config-based, process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Defender for Cloud, Advisor, Monitor Workbooks, DevOps/GitHub, Log Analytics)
  - Queries: 5 (2 REST API, 1 DevOps API, 1 KQL, 1 custom)
  - Artifacts: 5
- [x] **KSI-SVC-02** - Network Encryption ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 5 (App Gateway/Front Door, VPN Gateway, ExpressRoute, Policy, Defender for Cloud)
  - Queries: 5 (3 Resource Graph, 1 REST API, 1 KQL)
  - Artifacts: 5
- [ ] **KSI-SVC-03** - RETIRED (superseded by KSI-AFR-11)
- [x] **KSI-SVC-04** - Configuration Automation ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Automation, Policy, Arc, Monitor, DevOps)
  - Queries: 5 (2 KQL, 1 REST API, 1 Resource Graph, 1 DevOps API)
  - Artifacts: 6
- [x] **KSI-SVC-05** - Resource Integrity ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Policy, Defender for Cloud FIM, ACR, Key Vault, Change Tracking)
  - Queries: 5 (3 KQL, 1 REST API, 1 DevOps API)
  - Artifacts: 5
- [x] **KSI-SVC-06** - Secret Management ✅ COMPLETE
  - Evidence Type: config-based, log-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Key Vault, Monitor, Policy, Defender for Cloud, Managed Identity)
  - Queries: 5 (2 Resource Graph, 2 KQL, 1 REST API)
  - Artifacts: 6
- [x] **KSI-SVC-07** - Patching ✅ COMPLETE
  - Evidence Type: log-based, config-based, process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Update Manager, Defender for Cloud, Policy, Automation, Monitor)
  - Queries: 5 (3 KQL, 1 REST API, 1 Resource Graph)
  - Artifacts: 5
- [ ] **KSI-SVC-08** - Resource Management
- [ ] **KSI-SVC-09** - Communication Validation
- [ ] **KSI-SVC-10** - Data Deletion

### PIY - Privacy (0/8 = 0%)

- [ ] **KSI-PIY-01** - Privacy Controls
- [ ] **KSI-PIY-02** - Data Minimization
- [ ] **KSI-PIY-03** - Consent Management
- [ ] **KSI-PIY-04** - Data Subject Rights
- [ ] **KSI-PIY-05** - Privacy Impact Assessment
- [ ] **KSI-PIY-06** - Third-Party Risk
- [ ] **KSI-PIY-07** - Data Breach Response
- [ ] **KSI-PIY-08** - Privacy Training

### CMT - Configuration Management (1/4 = 25%)

- [x] **KSI-CMT-01** - Version Control and Change Logging ✅ COMPLETE
  - Evidence Type: log-based, config-based
  - Automation Feasibility: high
  - Implementation Effort: low
  - Azure Services: 5 (DevOps/GitHub, Activity Log, Policy, Automation Change Tracking, Monitor)
  - Queries: 5 (1 DevOps API, 3 KQL, 1 custom)
  - Artifacts: 5
- [ ] **KSI-CMT-02** - Baseline Configuration
- [ ] **KSI-CMT-03** - Configuration Change Control
- [ ] **KSI-CMT-04** - Security Impact Analysis

### RPL - Recovery & Planning (0/4 = 0%)

- [ ] **KSI-RPL-01** - Backup and Recovery
- [ ] **KSI-RPL-02** - Disaster Recovery
- [ ] **KSI-RPL-03** - Contingency Planning
- [ ] **KSI-RPL-04** - Business Continuity

### CED - Credential Management (0/4 = 0%)

- [ ] **KSI-CED-01** - Credential Storage
- [ ] **KSI-CED-02** - Credential Rotation
- [ ] **KSI-CED-03** - Secret Management
- [ ] **KSI-CED-04** - Key Management

### INR - Incident Response (1/3 = 33%)

- [x] **KSI-INR-01** - Incident Response Procedure ✅ COMPLETE
  - Evidence Type: log-based, process-based
  - Automation Feasibility: high
  - Implementation Effort: medium
  - Azure Services: 5 (Sentinel, Logic Apps, Monitor, Defender for Cloud, DevOps)
  - Queries: 5 (3 KQL, 1 REST API, 1 DevOps API)
  - Artifacts: 6
- [ ] **KSI-INR-02** - Incident Response Testing
- [ ] **KSI-INR-03** - Incident Reporting

### TPR - Third-Party Risk (0/2 = 0%)

- [ ] **KSI-TPR-03** - Vendor Assessment
- [ ] **KSI-TPR-04** - Supply Chain Security

---

## Implementation Priority

### ✅ Phase 1: High-Value, High-Automation (COMPLETE - 10/10 KSIs) 

These KSIs have high automation potential and are commonly required:

1. ✅ **KSI-MLA-01** - Centralized Logging (log-based, Azure Monitor)
2. ✅ **KSI-MLA-02** - Log Retention (config-based, Storage Account policies)
3. ✅ **KSI-IAM-02** - Privileged Access Management (log-based, PIM logs)
4. ✅ **KSI-CNA-03** - Infrastructure as Code (config-based, Azure DevOps/GitHub)
5. ✅ **KSI-SVC-04** - Configuration Automation (config-based, Azure Automation)
6. ✅ **KSI-SVC-06** - Secret Management (config-based, Key Vault)
7. ✅ **KSI-AFR-04** - Vulnerability Detection (log-based, Defender for Cloud)
8. ✅ **KSI-AFR-06** - Continuous Monitoring (metric-based, Sentinel)
9. ✅ **KSI-INR-01** - Incident Detection (log-based, Sentinel)
10. ✅ **KSI-IAM-01** - Phishing-Resistant MFA (log-based, Azure AD)
11. ✅ **KSI-CNA-01** - Restrict Network Traffic (config-based, Network Watcher)

**Phase 1 Achievement:** All high-priority KSIs with maximum automation potential are complete!

### Phase 2: Medium Automation (In Progress - 13/X KSIs)

These require more manual processes but have automation components:

1. ✅ **KSI-IAM-03** - Identity Lifecycle Management
2. ✅ **KSI-IAM-04** - Session Management
3. ✅ **KSI-IAM-05** - Least Privilege
4. ✅ **KSI-IAM-06** - Suspicious Activity Response
5. ✅ **KSI-CNA-02** - Minimize Attack Surface
6. ✅ **KSI-CNA-04** - Immutable Infrastructure
7. **KSI-CNA-05** - API Security
8. ✅ **KSI-SVC-01** - Continuous Improvement
9. ✅ **KSI-SVC-02** - Network Encryption
10. **KSI-SVC-05** - Configuration Baseline
11. **KSI-SVC-07** - Dependency Management
12. **KSI-CED-02** - Credential Rotation
13. **KSI-CED-03** - Secret Management
14. **KSI-AFR-02** - Continuous Monitoring
15. **KSI-AFR-03** - Significant Change Notification

### Phase 3: Process-Heavy (Remaining KSIs)

These are more process-based but still need evidence collection guidance:

26-65. Remaining KSIs (privacy, compliance, planning, risk management)

---

## Implementation Template

For each KSI, implement these three methods:

### 1. get_evidence_automation_recommendations()

```python
def get_evidence_automation_recommendations(self) -> dict:
    return {
        "ksi_id": self.KSI_ID,
        "ksi_name": self.KSI_NAME,
        "evidence_type": "log-based|config-based|metric-based|process-based",
        "automation_feasibility": "high|medium|low|manual-only",
        "azure_services": [
            {
                "service": "Azure Service Name",
                "purpose": "What it does for evidence collection",
                "configuration": "How to set it up",
                "cost": "Estimated cost"
            }
        ],
        "collection_methods": [
            {
                "method": "Collection Method Name",
                "description": "What evidence is collected",
                "frequency": "daily|weekly|monthly|on-change",
                "data_points": ["list", "of", "data", "points"]
            }
        ],
        "storage_requirements": {
            "retention_period": "3 years minimum (FedRAMP Moderate)",
            "format": "json|csv|pdf",
            "immutability": "Required|Optional",
            "encryption": "AES-256 at rest, TLS 1.2+ in transit",
            "estimated_size": "Size estimate"
        },
        "api_integration": {
            "frr_ads_endpoints": ["/evidence/ksi-id/endpoint"],
            "authentication": "OAuth 2.0 method",
            "response_format": "JSON with FIPS 140-2 signatures",
            "rate_limits": "API rate limits"
        },
        "code_examples": {
            "python": "Description of Python example",
            "csharp": "Description of C# example",
            "powershell": "Description of PowerShell example"
        },
        "infrastructure_templates": {
            "bicep": "Description of Bicep template",
            "terraform": "Description of Terraform template"
        },
        "retention_policy": "3 years minimum per FedRAMP Moderate",
        "implementation_effort": "low|medium|high",
        "implementation_time": "Time estimate",
        "prerequisites": ["List of prerequisites"],
        "notes": "Implementation notes with Azure WAF references"
    }
```

### 2. get_evidence_collection_queries()

```python
def get_evidence_collection_queries(self) -> List[dict]:
    return [
        {
            "name": "Query Name",
            "query_type": "kusto|resource_graph|rest_api",
            "query": "Actual query text (KQL, Resource Graph, or API call)",
            "data_source": "Azure service name",
            "schedule": "frequency",
            "output_format": "json|csv",
            "description": "What this query does"
        }
    ]
```

### 3. get_evidence_artifacts()

```python
def get_evidence_artifacts(self) -> List[dict]:
    return [
        {
            "artifact_name": "filename.ext",
            "artifact_type": "log|config|report|screenshot|policy",
            "description": "What this artifact demonstrates",
            "collection_method": "How to collect it",
            "format": "json|csv|pdf",
            "frequency": "continuous|daily|weekly|monthly|on-demand",
            "retention": "3 years"
        }
    ]
```

---

## Next Steps

1. **Start with Phase 1 KSIs** (high automation potential)
2. **Implement systematically** - one KSI at a time
3. **Test each implementation** - verify queries and artifacts
4. **Update tracker** - mark completed KSIs
5. **Run tests** - ensure no regressions

---

## Quick Reference Commands

### Check implementation status
```bash
python -c "from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory; factory = get_factory(); implemented = [k for k, a in sorted(factory._analyzers.items()) if not a.RETIRED and a.get_evidence_automation_recommendations()['automation_feasibility'] != 'manual-only']; print(f'Implemented: {len(implemented)}/65'); [print(f'  ✅ {k}') for k in implemented]"
```

### Test specific KSI
```bash
python -c "from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory; factory = get_factory(); analyzer = factory.get_analyzer('KSI-XXX-YY'); rec = analyzer.get_evidence_automation_recommendations(); print(f'Feasibility: {rec[\"automation_feasibility\"]}'); print(f'Services: {len(rec[\"azure_services\"])}'); print(f'Methods: {len(rec[\"collection_methods\"])}')"
```

### Run evidence automation tests
```bash
python tests/test_ksi_evidence_automation.py
```

---

**Last Updated:** December 9, 2025  
**Current Branch:** feature/ksi-evidence-automation  
**Next Target:** KSI-MLA-01 (Centralized Logging)
