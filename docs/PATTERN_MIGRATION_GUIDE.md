# Pattern Schema V2 Migration Guide

## Overview

This guide provides step-by-step instructions for migrating existing V1 patterns to the extended V2 schema that includes evidence collection, automation, implementation guidance, and SSP mapping capabilities.

**Goal:** Update all 74 existing KSI patterns from V1 to V2 schema to enable complete replacement of traditional analyzers.

## Migration Timeline

- **Phase 2A:** Extend existing 74 KSI patterns with V2 fields (estimated: 40 hours)
- **Phase 2B:** Create 199 FRR patterns using V2 schema (estimated: 160 hours)
- **Phase 2C:** Validate all patterns with automated tests (estimated: 20 hours)

**Total Phase 2 Effort:** ~220 hours (5-6 weeks with 1 person)

## V1 to V2 Schema Comparison

### V1 Schema (Current)
```yaml
pattern_id: "iam.mfa.fido2"
name: "FIDO2 MFA Detection"
description: "..."
family: "IAM"
severity: "HIGH"

languages:
  python: {...}
  
finding:
  title_template: "..."
  remediation_template: "..."
  
tags: [...]
nist_controls: [...]
```

### V2 Schema (Extended)
```yaml
# Everything from V1, plus:

evidence_collection:
  azure_monitor_kql: [...]
  azure_cli: [...]

evidence_artifacts: [...]

automation:
  implementation: |
    Bicep/Terraform code
  azure_services: [...]

implementation:
  steps: [...]
  total_effort_hours: X

ssp_mapping:
  ssp_sections: [...]

azure_guidance:
  recommended_services: [...]

compliance_frameworks:
  fedramp_20x: {...}

testing:
  positive_test_cases: [...]
  negative_test_cases: [...]
```

## Migration Process

### Step 1: Identify Source Data

For each pattern, gather data from:

1. **Traditional Analyzer File** (`src/fedramp_20x_mcp/analyzers/ksi/ksi_*.py`)
   - Extract `get_evidence_collection_queries()` → `evidence_collection`
   - Extract `get_evidence_artifacts()` → `evidence_artifacts`
   - Extract `get_evidence_automation_recommendations()` → `automation`

2. **Metadata File** (`data/requirements/ksi_metadata.json`)
   - Extract `guidance.evidence_collection` → `evidence_collection`
   - Extract `guidance.implementation_checklist` → `implementation.steps`
   - Extract `guidance.automation_opportunities` → `automation`
   - Extract `guidance.azure_services` → `azure_guidance.recommended_services`

3. **FedRAMP Documentation** (if available)
   - SSP section templates → `ssp_mapping.ssp_sections`
   - Compliance framework mappings → `compliance_frameworks`

### Step 2: Create V2 Pattern Template

Use this template for each pattern migration:

```yaml
---
pattern_id: "{existing_pattern_id}"
name: "{existing_name}"
description: "{existing_description}"
family: "{FAMILY}"
severity: "{SEVERITY}"
pattern_type: "{type}"

# ============================================================================
# DETECTION LOGIC (Copy from V1)
# ============================================================================
languages:
  python:
    # Copy existing detection logic
  csharp:
    # Copy existing detection logic

# ============================================================================
# FINDING GENERATION (Copy from V1, enhance)
# ============================================================================
finding:
  title_template: "{Copy from V1}"
  description_template: |
    {Enhance with FedRAMP requirement context}
  remediation_template: |
    {Copy from V1, add Azure-specific examples}

# ============================================================================
# EVIDENCE COLLECTION (NEW - From traditional analyzer)
# ============================================================================
evidence_collection:
  azure_monitor_kql:
    - query: |
        {From get_evidence_collection_queries()['azure_monitor_kql']}
      description: "{Purpose of query}"
      retention_days: 90
      
  azure_cli:
    - command: "{From get_evidence_collection_queries()['azure_cli']}"
      description: "{Purpose of command}"
      output_format: "json"

# ============================================================================
# EVIDENCE ARTIFACTS (NEW - From traditional analyzer)
# ============================================================================
evidence_artifacts:
  - artifact_type: "report|configuration|logs|screenshot"
    name: "{From get_evidence_artifacts()}"
    source: "{Where to collect}"
    frequency: "monthly|weekly|real-time"
    retention_months: 12
    format: "JSON|CSV|PDF|PNG"

# ============================================================================
# AUTOMATION (NEW - From traditional analyzer + metadata)
# ============================================================================
automation:
  {key_from_automation_recommendations}:
    description: "{From get_evidence_automation_recommendations()}"
    implementation: |
      # Bicep or code example
    azure_services: ["{From metadata}"]
    effort_hours: {estimate}

# ============================================================================
# IMPLEMENTATION (NEW - From metadata implementation_checklist)
# ============================================================================
implementation:
  prerequisites:
    - "{From common Azure prerequisites}"
  
  steps:
    - step: 1
      action: "{From implementation_checklist}"
      azure_service: "{From metadata.azure_services}"
      estimated_hours: {estimate}
      validation: "{How to verify}"

# ============================================================================
# SSP MAPPING (NEW - Create from NIST controls)
# ============================================================================
ssp_mapping:
  control_family: "{From NIST control}"
  control_numbers: ["{From nist_controls}"]
  
  ssp_sections:
    - section: "{Control ID}: {Control Name}"
      description_template: |
        {How this pattern addresses the control}
      implementation_details: |
        {Azure-specific implementation}
      evidence_references:
        - "{From evidence_artifacts}"

# ============================================================================
# AZURE GUIDANCE (NEW - From metadata + Azure docs)
# ============================================================================
azure_guidance:
  recommended_services:
    - service: "{From metadata.azure_services}"
      tier: "{Service tier}"
      purpose: "{Why needed}"
      monthly_cost_estimate: "{Estimate}"

# ============================================================================
# COMPLIANCE FRAMEWORKS (NEW)
# ============================================================================
compliance_frameworks:
  fedramp_20x:
    requirement_id: "{KSI ID}"
    requirement_name: "{KSI name}"
    impact_levels: ["{From metadata}"]

# ============================================================================
# TESTING (NEW - Create test cases)
# ============================================================================
testing:
  positive_test_cases:
    - description: "{What should pass}"
      code_sample: |
        # Code that complies
      expected_severity: "INFO"
      expected_finding: true
  
  negative_test_cases:
    - description: "{What should fail}"
      code_sample: |
        # Code that violates
      expected_severity: "HIGH"
      expected_finding: true

# ============================================================================
# METADATA (Copy from V1)
# ============================================================================
tags: ["{Copy from V1}"]
nist_controls: ["{Copy from V1}"]
related_ksis: ["{Copy from V1}"]
related_frrs: ["{Copy from V1}"]
```

### Step 3: Extract Evidence Collection

#### From Traditional Analyzer

```python
# File: src/fedramp_20x_mcp/analyzers/ksi/ksi_iam_01.py

def get_evidence_collection_queries(self) -> Dict[str, List[str]]:
    return {
        "azure_monitor_kql": [
            "SigninLogs | where TimeGenerated > ago(30d) | ..."
        ],
        "azure_cli": [
            "az ad user list --query ..."
        ]
    }
```

#### Convert to V2 Pattern

```yaml
evidence_collection:
  azure_monitor_kql:
    - query: |
        SigninLogs | where TimeGenerated > ago(30d) | ...
      description: "Sign-in logs with MFA method usage"
      retention_days: 90
      schedule: "daily"
  
  azure_cli:
    - command: "az ad user list --query ..."
      description: "List users with MFA methods"
      output_format: "json"
      frequency: "weekly"
```

### Step 4: Extract Evidence Artifacts

#### From Traditional Analyzer

```python
def get_evidence_artifacts(self) -> List[str]:
    return [
        "Monthly vulnerability scan reports from Defender for Cloud",
        "CI/CD pipeline scan results (Trivy, Snyk, CodeQL artifacts)",
    ]
```

#### Convert to V2 Pattern

```yaml
evidence_artifacts:
  - artifact_type: "report"
    name: "Monthly vulnerability scan reports"
    source: "Microsoft Defender for Cloud"
    frequency: "monthly"
    retention_months: 12
    format: "PDF"
    location: "evidence/defender_scans/"
  
  - artifact_type: "logs"
    name: "CI/CD pipeline scan results"
    source: "GitHub Actions"
    frequency: "per-build"
    retention_months: 6
    format: "JSON"
    location: "artifacts/security-scans/"
```

### Step 5: Extract Automation Recommendations

#### From Traditional Analyzer

```python
def get_evidence_automation_recommendations(self) -> Dict[str, str]:
    return {
        "defender_enablement": "Enable Defender for Cloud for all resource types",
        "cicd_integration": "Integrate vulnerability scanning in all CI/CD pipelines",
    }
```

#### From Metadata

```json
"automation_opportunities": [
  "Azure Policy for compliance enforcement",
  "PowerShell script to audit MFA methods",
]
```

#### Convert to V2 Pattern

```yaml
automation:
  defender_enablement:
    description: "Enable Defender for Cloud for all resource types with automated assessment"
    implementation: |
      resource defenderForServers 'Microsoft.Security/pricings@2023-01-01' = {
        name: 'VirtualMachines'
        properties: { pricingTier: 'Standard' }
      }
    azure_services: 
      - "Microsoft Defender for Cloud"
      - "Azure Policy"
    effort_hours: 2
  
  cicd_integration:
    description: "Integrate vulnerability scanning (Trivy, Snyk) in CI/CD pipelines"
    implementation: |
      - name: Run Trivy scan
        uses: aquasecurity/trivy-action@master
    azure_services:
      - "GitHub Actions"
      - "Azure DevOps"
    effort_hours: 4
```

### Step 6: Extract Implementation Steps

#### From Metadata

```json
"implementation_checklist": [
  "Enable Microsoft Entra ID Premium P2",
  "Configure Conditional Access policies",
  "Set up phishing-resistant MFA (FIDO2, certificate-based)",
  "Test MFA enforcement for all user types"
]
```

#### Convert to V2 Pattern

```yaml
implementation:
  prerequisites:
    - "Azure subscription with Global Administrator role"
    - "Microsoft Entra ID Premium P2 licenses"
  
  steps:
    - step: 1
      action: "Enable Microsoft Entra ID Premium P2"
      azure_service: "Microsoft Entra ID"
      estimated_hours: 0.5
      validation: "Verify license assignment in Azure Portal"
    
    - step: 2
      action: "Configure Conditional Access policies"
      azure_service: "Conditional Access"
      estimated_hours: 2
      validation: "Test policy enforcement with test user"
      bicep_template: "templates/bicep/iam/conditional-access.bicep"
    
    - step: 3
      action: "Set up phishing-resistant MFA (FIDO2, certificate-based)"
      azure_service: "Microsoft Entra ID"
      estimated_hours: 4
      validation: "PowerShell script to check FIDO2 registration"
    
    - step: 4
      action: "Test MFA enforcement for all user types"
      azure_service: null
      estimated_hours: 1
      validation: "Attempt sign-in with non-phishing-resistant method (should fail)"
  
  total_effort_hours: 7.5
```

### Step 7: Create SSP Mapping

#### From NIST Controls

```yaml
nist_controls: ["ia-2", "ia-2.1", "ia-2.2", "ia-2.8"]
```

#### Convert to V2 Pattern

```yaml
ssp_mapping:
  control_family: "IA - Identification and Authentication"
  control_numbers: ["IA-2", "IA-2(1)", "IA-2(2)", "IA-2(8)"]
  
  ssp_sections:
    - section: "IA-2: Identification and Authentication (Organizational Users)"
      description_template: |
        The {system_name} enforces multi-factor authentication using 
        phishing-resistant methods for all organizational users.
      
      implementation_details: |
        Microsoft Entra ID Conditional Access policies require FIDO2 
        security keys or Windows Hello for Business.
      
      evidence_references:
        - "Conditional Access policy configuration (JSON export)"
        - "Sign-in logs showing MFA method usage"
```

### Step 8: Add Testing Section

Create positive and negative test cases:

```yaml
testing:
  positive_test_cases:
    - description: "FIDO2 library import detected"
      code_sample: |
        from fido2.server import Fido2Server
      expected_severity: "INFO"
      expected_finding: true
      expected_message: "Phishing-resistant MFA library detected"
  
  negative_test_cases:
    - description: "TOTP-only MFA (insufficient)"
      code_sample: |
        import pyotp
        totp = pyotp.TOTP('secret')
      expected_severity: "HIGH"
      expected_finding: true
      expected_message: "TOTP-only MFA detected (not phishing-resistant)"
  
  validation_scripts:
    - "tests/test_ksi_iam_01_patterns.py"
```

### Step 9: Validate Pattern

```bash
python scripts/validate_pattern_schema.py data/patterns/{family}_patterns.yaml --schema v2
```

### Step 10: Test Pattern

```bash
python tests/test_pattern_{family}.py
```

## Migration Checklist (Per Pattern)

- [ ] Create backup of original V1 pattern file
- [ ] Extract evidence collection from traditional analyzer
- [ ] Extract evidence artifacts from traditional analyzer
- [ ] Extract automation recommendations from analyzer + metadata
- [ ] Extract implementation steps from metadata
- [ ] Create SSP mapping from NIST controls
- [ ] Add Azure guidance from metadata + docs
- [ ] Create compliance framework mappings
- [ ] Write positive test cases (2-3 minimum)
- [ ] Write negative test cases (2-3 minimum)
- [ ] Run schema validator (must pass)
- [ ] Run pattern tests (must pass)
- [ ] Update pattern library documentation
- [ ] Commit changes to git

## Automation Scripts

### Bulk Migration Helper

```python
# scripts/migrate_patterns_v1_to_v2.py
"""
Automates migration of V1 patterns to V2 schema by:
1. Reading V1 pattern YAML
2. Reading traditional analyzer Python file
3. Reading metadata JSON
4. Combining data into V2 template
5. Writing V2 pattern YAML
"""

# Run: python scripts/migrate_patterns_v1_to_v2.py --family IAM
```

### Validation Batch Script

```bash
# Validate all patterns
for file in data/patterns/*_patterns.yaml; do
    python scripts/validate_pattern_schema.py "$file" --schema v2
done
```

## Common Migration Issues

### Issue 1: Missing Evidence Methods in Traditional Analyzer

**Problem:** Some traditional analyzers don't have `get_evidence_collection_queries()`.

**Solution:** 
1. Check if metadata has `guidance.evidence_collection`
2. Create evidence queries based on Azure service in metadata
3. Use generic template for the service type

### Issue 2: Implementation Steps Too Generic

**Problem:** Metadata has generic checklist like "Configure security settings".

**Solution:**
1. Review Azure documentation for the specific service
2. Break down into specific, measurable steps
3. Add validation criteria for each step

### Issue 3: Missing NIST Control Mappings

**Problem:** Pattern doesn't have SSP section templates.

**Solution:**
1. Look up NIST control text from NIST SP 800-53
2. Create template describing how pattern addresses control
3. Reference Azure service implementing the control

## Migration Priority

### High Priority (Code-Detectable KSIs)
1. IAM family (7 KSIs) - Identity critical for FedRAMP
2. VDR family (8 KSIs) - Vulnerability detection required
3. SVC family (8 KSIs) - Secure coding practices

### Medium Priority (Infrastructure)
4. MLA family (5 KSIs) - Logging and monitoring
5. AFR family (4 KSIs) - Assessment and authorization
6. CNA family (6 KSIs) - Configuration management

### Lower Priority (Process-Heavy)
7. PIY family (2 code-detectable) - Privacy controls
8. Other families - Remaining KSIs

## FRR Pattern Creation

For creating FRR patterns (199 patterns):

1. **Use FRR Metadata:** `data/requirements/frr_metadata.json`
2. **Follow Same V2 Template:** All fields from V2 schema
3. **Focus on CI/CD and IaC:** FRRs often about infrastructure
4. **Include Process Guidance:** Many FRRs are process-based

### FRR Pattern Template

```yaml
---
pattern_id: "vdr.scanning.persistent"  # Note: lowercase family
name: "Persistent Vulnerability Scanning"
description: "Detects persistent vulnerability scanning implementation in CI/CD and IaC"
family: "VDR"
severity: "HIGH"
pattern_type: "infrastructure_control"

# Detection for Bicep, Terraform, GitHub Actions, Azure Pipelines
languages:
  bicep: {...}
  terraform: {...}
  github_actions: {...}

# Standard V2 fields...
evidence_collection: {...}
evidence_artifacts: {...}
automation: {...}
implementation: {...}
ssp_mapping: {...}

compliance_frameworks:
  fedramp_20x:
    requirement_id: "FRR-VDR-01"
    requirement_name: "Vulnerability Detection"
    impact_levels: ["Low", "Moderate", "High"]
```

## Success Criteria

Pattern migration is complete when:

1. ✅ All 74 KSI patterns have V2 schema fields
2. ✅ All 199 FRR patterns created with V2 schema
3. ✅ All patterns pass `validate_pattern_schema.py`
4. ✅ All patterns have 2+ positive and 2+ negative test cases
5. ✅ All tests pass in `tests/test_pattern_*.py`
6. ✅ Documentation updated (`PATTERN_SCHEMA_V2.md`)
7. ✅ Pattern library size documented (should be ~500KB total)

## Next Steps After Migration

After all patterns migrated to V2:

1. **Phase 3:** Build generic language analyzers that consume V2 patterns
2. **Phase 4:** Integration testing with both old and new analyzers
3. **Phase 5:** Deprecate and remove traditional analyzers (6MB reduction)

## References

- **Pattern Schema V2:** `docs/PATTERN_SCHEMA_V2.md`
- **V2 Example Pattern:** `data/patterns/iam_patterns_v2_example.yaml`
- **Schema Validator:** `scripts/validate_pattern_schema.py`
- **Refactoring Plan:** `docs/REFACTORING_PLAN.md`
- **Traditional Analyzers:** `src/fedramp_20x_mcp/analyzers/ksi/*.py`
- **Metadata:** `data/requirements/ksi_metadata.json`
