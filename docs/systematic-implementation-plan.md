# Systematic Evidence Automation Implementation Plan

## Overview

This document outlines the systematic approach to implementing evidence automation for all 65 active FedRAMP 20x KSIs. The implementation follows a phased approach prioritizing high-automation, high-value KSIs first.

## Current Status

- **Completed:** 2/65 KSIs (3.1%)
  - ✅ KSI-IAM-01 - Phishing-Resistant MFA
  - ✅ KSI-CNA-01 - Restrict Network Traffic
  
- **Remaining:** 63/65 KSIs (96.9%)

- **Target:** 100% coverage of all active KSIs

## Tools Created

### 1. Implementation Tracker (`docs/evidence-automation-implementation-tracker.md`)
- Complete checklist of all 65 KSIs organized by family
- Progress tracking by family
- Priority order for implementation
- Implementation template and quick reference commands

### 2. Implementation Helper Script (`scripts/implement_evidence_automation.py`)
- Shows next KSI to implement based on priority
- Displays KSI details and NIST controls
- Generates implementation templates
- Provides step-by-step instructions

**Usage:**
```bash
# Show status
python scripts/implement_evidence_automation.py --status

# Show next KSI to implement
python scripts/implement_evidence_automation.py --next

# Show template for specific KSI
python scripts/implement_evidence_automation.py --ksi KSI-MLA-01
```

## Implementation Workflow

### Step-by-Step Process

For each KSI, follow this systematic workflow:

#### 1. **Identify Next KSI**
```bash
python scripts/implement_evidence_automation.py --next
```

#### 2. **Understand the KSI**
- Review KSI statement and NIST controls
- Determine evidence type (log-based, config-based, metric-based, process-based)
- Assess automation feasibility (high, medium, low, manual-only)

#### 3. **Research Azure Services**
- Identify Azure services that collect relevant evidence
- Document configuration requirements
- Estimate costs
- Reference Azure Well-Architected Framework

#### 4. **Define Collection Methods**
- Determine collection frequency (continuous, daily, weekly, monthly)
- Specify data points to collect
- Plan collection schedules

#### 5. **Create Queries**
- Write KQL queries for Log Analytics
- Write Resource Graph queries for Azure resources
- Write REST API calls for Microsoft Graph or ARM APIs
- Test queries in Azure portal

#### 6. **Specify Artifacts**
- List all evidence artifacts needed
- Define artifact formats (JSON, CSV, PDF)
- Specify retention requirements
- Document collection methods

#### 7. **Implement in Code**
Open the KSI analyzer file and add three methods:
```python
# File: src/fedramp_20x_mcp/analyzers/ksi/ksi_xxx_yy.py

def get_evidence_automation_recommendations(self) -> dict:
    # Implementation details...
    
def get_evidence_collection_queries(self) -> List[dict]:
    # Query definitions...
    
def get_evidence_artifacts(self) -> List[dict]:
    # Artifact specifications...
```

#### 8. **Test Implementation**
```bash
# Quick test
python -c "from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory; factory = get_factory(); analyzer = factory.get_analyzer('KSI-XXX-YY'); print(analyzer.get_evidence_automation_recommendations()['automation_feasibility'])"

# Full test suite
python tests/test_ksi_evidence_automation.py
```

#### 9. **Update Documentation**
- Mark KSI as complete in tracker
- Update progress percentages
- Document any special considerations

#### 10. **Commit Changes**
```bash
git add src/fedramp_20x_mcp/analyzers/ksi/ksi_xxx_yy.py
git add docs/evidence-automation-implementation-tracker.md
git commit -m "Add evidence automation for KSI-XXX-YY"
```

## Priority Implementation Order

### Phase 1: High-Automation KSIs (Target: 10 KSIs)

These have the highest automation potential and immediate value:

1. **KSI-MLA-01** - Centralized Logging (SIEM)
   - Azure Services: Sentinel, Log Analytics, Storage
   - Evidence: Log ingestion configs, retention policies, SIEM rules

2. **KSI-MLA-02** - Log Retention
   - Azure Services: Storage Account (immutable storage), Log Analytics
   - Evidence: Retention policies, immutability settings, storage configs

3. **KSI-IAM-02** - Privileged Access Management
   - Azure Services: PIM, Azure AD, Log Analytics
   - Evidence: PIM assignments, elevation logs, access reviews

4. **KSI-CNA-03** - Infrastructure as Code
   - Azure Services: Azure DevOps, GitHub Actions, Azure Repos
   - Evidence: IaC templates, pipeline configs, deployment logs

5. **KSI-SVC-04** - Configuration Automation
   - Azure Services: Azure Automation, Azure Policy, Resource Manager
   - Evidence: Automation runbooks, DSC configs, policy assignments

6. **KSI-SVC-06** - Patch Management
   - Azure Services: Update Management, Defender for Cloud
   - Evidence: Patch compliance reports, update schedules, deployment logs

7. **KSI-CED-01** - Credential Storage
   - Azure Services: Key Vault, Managed Identity
   - Evidence: Key Vault configs, access policies, secret metadata

8. **KSI-AFR-04** - Vulnerability Detection
   - Azure Services: Defender for Cloud, Security Center
   - Evidence: Vulnerability assessments, recommendations, remediation logs

9. **KSI-AFR-06** - Authorization Data Sharing
   - Azure Services: API Management, Storage, Event Grid
   - Evidence: API configs, data sharing logs, authorization records

10. **KSI-INR-01** - Incident Detection
    - Azure Services: Sentinel, Defender for Cloud, Log Analytics
    - Evidence: Incident records, detection rules, response logs

### Phase 2: Medium-Automation KSIs (Target: 15 KSIs)

KSIs 11-25 with moderate automation potential.

### Phase 3: Process-Heavy KSIs (Target: 38 KSIs)

Remaining KSIs that are more process-based but still need evidence guidance.

## Quality Standards

Each implementation must include:

### 1. **Azure Services** (minimum 3)
- Service name
- Purpose for evidence collection
- Configuration requirements
- Cost estimates

### 2. **Collection Methods** (minimum 2)
- Method name
- Description
- Frequency
- Data points collected

### 3. **Queries** (minimum 2)
- KQL, Resource Graph, or REST API
- Query name and description
- Data source
- Schedule
- Output format

### 4. **Artifacts** (minimum 3)
- Artifact name
- Type (log, config, report, policy)
- Description
- Collection method
- Format and frequency
- Retention period

### 5. **Azure Well-Architected Framework References**
- Link to relevant WAF guidance
- Security pillar references
- Operational excellence considerations

## Testing Strategy

### Per-KSI Testing
```bash
# Test specific KSI implementation
python -c "
from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
factory = get_factory()
analyzer = factory.get_analyzer('KSI-XXX-YY')
rec = analyzer.get_evidence_automation_recommendations()
assert rec['automation_feasibility'] != 'manual-only', 'Must implement automation'
assert len(rec['azure_services']) >= 3, 'Need at least 3 Azure services'
assert len(rec['collection_methods']) >= 2, 'Need at least 2 collection methods'
queries = analyzer.get_evidence_collection_queries()
assert len(queries) >= 2, 'Need at least 2 queries'
artifacts = analyzer.get_evidence_artifacts()
assert len(artifacts) >= 3, 'Need at least 3 artifacts'
print('✅ All validations passed')
"
```

### Full Test Suite
```bash
# Run all evidence automation tests
python tests/test_ksi_evidence_automation.py

# Run all tests (ensure no regressions)
python tests/run_all_tests.py
```

## Milestone Tracking

### Milestone 1: Phase 1 Complete (10 KSIs)
- **Target Date:** 2 weeks
- **Success Criteria:** All Phase 1 KSIs have high automation feasibility
- **Deliverable:** 10 fully implemented KSIs with queries and artifacts

### Milestone 2: Phase 2 Complete (25 KSIs total)
- **Target Date:** 4 weeks
- **Success Criteria:** 15 additional KSIs with medium+ automation
- **Deliverable:** 25 total KSIs implemented

### Milestone 3: All KSIs Complete (65 KSIs)
- **Target Date:** 8 weeks
- **Success Criteria:** All active KSIs have evidence automation guidance
- **Deliverable:** Complete evidence automation coverage

## Progress Monitoring

### Daily Checks
```bash
# Check progress
python scripts/implement_evidence_automation.py --status

# Verify no regressions
python tests/test_ksi_evidence_automation.py
```

### Weekly Reviews
- Update tracker with completed KSIs
- Review quality of implementations
- Adjust priorities if needed
- Document lessons learned

## Documentation Requirements

For each implemented KSI, document:

1. **Azure services** used and why
2. **Evidence collection approach** and rationale
3. **Query development process** and validation
4. **Artifact specifications** and retention
5. **Implementation challenges** and solutions
6. **Cost considerations** and optimization
7. **WAF alignment** and security best practices

## Success Metrics

- **Coverage:** 100% of active KSIs (65/65)
- **Quality:** Average 4+ Azure services per KSI
- **Automation:** 80%+ with high/medium automation feasibility
- **Testing:** 100% test pass rate
- **Documentation:** Complete tracker and implementation notes

## Next Action

**Start with KSI-MLA-01 (Centralized Logging)**

```bash
python scripts/implement_evidence_automation.py --ksi KSI-MLA-01
```

This KSI is ideal because:
- High automation potential (log-based evidence)
- Clear Azure services (Sentinel, Log Analytics)
- Well-defined queries (KQL for log ingestion)
- Common requirement across all FedRAMP systems
- Foundation for other logging/monitoring KSIs

---

**Created:** December 9, 2025  
**Branch:** feature/ksi-evidence-automation  
**Owner:** Implementation team  
**Next Review:** After completing 10 KSIs (Phase 1)
