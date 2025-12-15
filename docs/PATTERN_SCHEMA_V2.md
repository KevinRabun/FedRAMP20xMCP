# Pattern Schema V2 - Extended for Evidence Collection

## Overview

This document defines the extended YAML pattern schema that enables patterns to provide the same comprehensive guidance as traditional analyzers, supporting complete elimination of the 271 traditional analyzer files.

**Goal:** Replace 6MB of traditional analyzer code with pattern-driven architecture achieving 90%+ code reduction while maintaining **100% accuracy and completeness** of guidance.

## Schema Changes from V1

### V1 Schema (Current - KSI Patterns Only)
```yaml
pattern_id: "family.category.specific"
name: "Pattern Name"
description: "What this pattern detects"
family: "FAMILY_CODE"
severity: "CRITICAL|HIGH|MEDIUM|LOW|INFO"
pattern_type: "import|function|configuration|..."

languages:
  python: {...}
  csharp: {...}
  
finding:
  title_template: "..."
  description_template: "..."
  remediation_template: "..."
  
tags: ["tag1", "tag2"]
nist_controls: ["control-1", "control-2"]
related_ksis: ["KSI-XXX-01"]
```

### V2 Schema (Extended - Full Replacement)
```yaml
pattern_id: "family.category.specific"
name: "Pattern Name"
description: "What this pattern detects"
family: "FAMILY_CODE"
severity: "CRITICAL|HIGH|MEDIUM|LOW|INFO"
pattern_type: "import|function|configuration|..."

# EXISTING: Detection logic
languages:
  python: {...}
  csharp: {...}
  java: {...}
  typescript: {...}
  bicep: {...}
  terraform: {...}
  github_actions: {...}
  azure_pipelines: {...}
  gitlab_ci: {...}

# EXISTING: Finding generation
finding:
  title_template: "..."
  description_template: "..."
  remediation_template: "..."

# NEW: Evidence collection (replaces get_evidence_collection_queries)
evidence_collection:
  azure_monitor_kql:
    - query: "SecurityRecommendation | where ..."
      description: "Monthly vulnerability trends"
      retention_days: 365
  azure_cli:
    - command: "az security pricing list ..."
      description: "Defender for Cloud configuration"
      output_format: "json"
  powershell:
    - script: "Get-AzSecurityPricing | ..."
      description: "Security pricing tier validation"
  rest_api:
    - endpoint: "/subscriptions/{id}/providers/Microsoft.Security/..."
      method: "GET"
      description: "Security assessments"

# NEW: Artifacts to collect (replaces get_evidence_artifacts)
evidence_artifacts:
  - artifact_type: "report"
    name: "Monthly vulnerability scan reports"
    source: "Microsoft Defender for Cloud"
    frequency: "monthly"
    retention_months: 12
    format: "PDF|JSON"
  - artifact_type: "configuration"
    name: "Defender for Cloud configuration export"
    source: "Azure Portal"
    format: "JSON"
    retention_months: 12

# NEW: Automation recommendations (replaces get_evidence_automation_recommendations)
automation:
  defender_enablement:
    description: "Enable Defender for Cloud for all resource types"
    implementation: |
      # Bicep
      resource defenderForServers 'Microsoft.Security/pricings@2023-01-01' = {
        name: 'VirtualMachines'
        properties: { pricingTier: 'Standard' }
      }
    azure_services: ["Microsoft Defender for Cloud"]
    
  cicd_integration:
    description: "Integrate vulnerability scanning in CI/CD"
    implementation: |
      # GitHub Actions
      - name: Run Trivy scan
        uses: aquasecurity/trivy-action@master
    azure_services: ["GitHub Advanced Security", "Azure DevOps"]

# NEW: Implementation guidance (replaces implementation checklist in metadata)
implementation:
  prerequisites:
    - "Azure subscription with required permissions"
    - "Microsoft Entra ID tenant configured"
  
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
      
  validation_queries:
    - "az ad sp list --filter \"displayName eq 'MFA-Required'\""

# NEW: SSP (System Security Plan) mapping
ssp_mapping:
  control_family: "IA - Identification and Authentication"
  control_numbers: ["IA-2", "IA-2(1)", "IA-2(2)", "IA-2(8)"]
  
  ssp_sections:
    - section: "IA-2: Identification and Authentication"
      description_template: |
        The system enforces phishing-resistant multi-factor authentication
        using FIDO2/WebAuthn for all user authentication.
      
      implementation_details: |
        Microsoft Entra ID Conditional Access policies require FIDO2
        security keys or Windows Hello for Business for all users.
      
      evidence_references:
        - "Conditional Access policy configuration (JSON export)"
        - "Sign-in logs showing MFA method usage"
        - "MFA registration status report"
    
    - section: "IA-2(8): Replay Resistant"
      description_template: |
        FIDO2/WebAuthn provides cryptographic proof of possession
        preventing replay attacks.

# EXISTING: Metadata
tags: ["mfa", "authentication", "phishing-resistant"]
nist_controls: ["ia-2", "ia-2.1", "ia-2.2", "ia-2.8"]
related_ksis: ["KSI-IAM-01", "KSI-IAM-02"]
related_frrs: ["FRR-ADS-AC-01"]

# NEW: Azure-specific guidance
azure_guidance:
  recommended_services:
    - service: "Microsoft Entra ID"
      tier: "Premium P2"
      purpose: "Conditional Access and MFA enforcement"
      alternatives: []
      
    - service: "Conditional Access"
      tier: "Premium P2"
      purpose: "Policy enforcement"
      alternatives: ["Third-party IAM with Azure AD integration"]
  
  well_architected_framework:
    pillar: "Security"
    design_area: "Identity and Access Management"
    recommendation_id: "SEC-04"
    reference_url: "https://learn.microsoft.com/azure/well-architected/security/identity"
  
  cloud_adoption_framework:
    stage: "Secure"
    guidance: "Implement phishing-resistant MFA across all accounts"
    reference_url: "https://learn.microsoft.com/azure/cloud-adoption-framework/secure/best-practices/end-user-authentication"

# NEW: Compliance framework mapping
compliance_frameworks:
  fedramp_20x:
    requirement_id: "KSI-IAM-01"
    requirement_name: "Phishing-Resistant MFA"
    impact_levels: ["Low", "Moderate"]
    
  nist_800_53_rev5:
    controls: ["IA-2", "IA-2(1)", "IA-2(2)", "IA-2(8)"]
    
  pci_dss_4:
    requirements: ["8.4.2", "8.4.3"]
    
  hipaa:
    standards: ["164.312(d) - Person or Entity Authentication"]

# NEW: Testing and validation
testing:
  positive_test_cases:
    - description: "FIDO2 library import detected"
      code_sample: |
        from fido2.server import Fido2Server
      expected_severity: "INFO"
      expected_finding: true
      
  negative_test_cases:
    - description: "TOTP-only MFA (insufficient)"
      code_sample: |
        import pyotp
        totp = pyotp.TOTP('base32secret')
      expected_severity: "HIGH"
      expected_finding: true
      
  validation_scripts:
    - "tests/test_ksi_iam_01_patterns.py"
```

## Field Definitions

### Required Fields (All Patterns)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `pattern_id` | string | Unique identifier (family.category.specific) | `"iam.mfa.fido2"` |
| `name` | string | Human-readable pattern name | `"FIDO2 MFA Implementation"` |
| `description` | string | What this pattern detects | `"Detects FIDO2-based MFA"` |
| `family` | string | FedRAMP 20x family code | `"IAM"` |
| `severity` | enum | Finding severity | `"HIGH"` |

### Detection Fields (Required for Code-Detectable)

| Field | Type | Description |
|-------|------|-------------|
| `languages` | object | Detection logic per language |
| `languages.<lang>.ast_queries` | array | AST-based detection queries |
| `languages.<lang>.regex_fallback` | string | Regex fallback when AST fails |
| `languages.<lang>.positive_indicators` | array | Indicators of compliance |
| `languages.<lang>.negative_indicators` | array | Indicators of non-compliance |

### Evidence Collection Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `evidence_collection` | object | Queries to collect compliance evidence |
| `evidence_collection.azure_monitor_kql` | array | KQL queries for Azure Monitor |
| `evidence_collection.azure_cli` | array | Azure CLI commands |
| `evidence_collection.powershell` | array | PowerShell scripts |
| `evidence_collection.rest_api` | array | REST API calls |

### Evidence Artifacts Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `evidence_artifacts` | array | Artifacts to collect as evidence |
| `evidence_artifacts[].artifact_type` | string | Type: report, configuration, logs, etc. |
| `evidence_artifacts[].name` | string | Artifact name |
| `evidence_artifacts[].source` | string | Where to collect from |
| `evidence_artifacts[].frequency` | string | Collection frequency |
| `evidence_artifacts[].retention_months` | int | How long to retain |
| `evidence_artifacts[].format` | string | File format(s) |

### Automation Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `automation` | object | Automation recommendations |
| `automation.<key>.description` | string | What to automate |
| `automation.<key>.implementation` | string | Code/config to implement |
| `automation.<key>.azure_services` | array | Azure services used |

### Implementation Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `implementation` | object | Step-by-step implementation guide |
| `implementation.prerequisites` | array | Prerequisites before starting |
| `implementation.steps` | array | Ordered implementation steps |
| `implementation.steps[].step` | int | Step number |
| `implementation.steps[].action` | string | What to do |
| `implementation.steps[].azure_service` | string | Azure service involved |
| `implementation.steps[].estimated_hours` | float | Time estimate |
| `implementation.steps[].validation` | string | How to verify |
| `implementation.steps[].bicep_template` | string | Optional template path |
| `implementation.validation_queries` | array | Queries to validate implementation |

### SSP Mapping Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `ssp_mapping` | object | System Security Plan mapping |
| `ssp_mapping.control_family` | string | NIST control family |
| `ssp_mapping.control_numbers` | array | Specific control numbers |
| `ssp_mapping.ssp_sections` | array | SSP section templates |
| `ssp_mapping.ssp_sections[].section` | string | Section name |
| `ssp_mapping.ssp_sections[].description_template` | string | Template text for SSP |
| `ssp_mapping.ssp_sections[].implementation_details` | string | How it's implemented |
| `ssp_mapping.ssp_sections[].evidence_references` | array | Evidence artifacts referenced |

### Azure Guidance Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `azure_guidance` | object | Azure-specific guidance |
| `azure_guidance.recommended_services` | array | Azure services to use |
| `azure_guidance.recommended_services[].service` | string | Service name |
| `azure_guidance.recommended_services[].tier` | string | Service tier |
| `azure_guidance.recommended_services[].purpose` | string | Why use this service |
| `azure_guidance.recommended_services[].alternatives` | array | Alternative services |
| `azure_guidance.well_architected_framework` | object | WAF reference |
| `azure_guidance.cloud_adoption_framework` | object | CAF reference |

### Compliance Framework Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `compliance_frameworks` | object | Mapping to compliance frameworks |
| `compliance_frameworks.fedramp_20x` | object | FedRAMP 20x mapping |
| `compliance_frameworks.nist_800_53_rev5` | object | NIST 800-53 Rev 5 mapping |
| `compliance_frameworks.pci_dss_4` | object | PCI DSS 4.0 mapping |
| `compliance_frameworks.hipaa` | object | HIPAA mapping |

### Testing Fields (NEW)

| Field | Type | Description |
|-------|------|-------------|
| `testing` | object | Test cases and validation |
| `testing.positive_test_cases` | array | Should detect as compliant |
| `testing.negative_test_cases` | array | Should detect as non-compliant |
| `testing.validation_scripts` | array | Automated test script paths |

## Pattern Types

### Code-Detectable Patterns
- Must include: `languages`, `finding`, `testing`
- Should include: `evidence_collection`, `automation`, `implementation`
- Example: KSI-IAM-01 (Phishing-Resistant MFA detection in code)

### Process-Based Patterns
- Must include: `implementation`, `evidence_artifacts`, `ssp_mapping`
- Should NOT include: `languages` (no code detection)
- Example: KSI-CED-01 (Training program - documentation only)

### Infrastructure Patterns (Bicep/Terraform)
- Must include: `languages.bicep`, `languages.terraform`, `finding`
- Should include: `evidence_collection`, `azure_guidance`
- Example: FRR-VDR-01 (Defender for Cloud configuration)

### CI/CD Patterns
- Must include: `languages.github_actions` or `languages.azure_pipelines`
- Should include: `automation`, `implementation.steps`
- Example: FRR-VDR-01 (Vulnerability scanning in pipeline)

## Migration Path

### Phase 1: Extend Schema ✅ (This Document)
- [x] Define V2 schema with all new fields
- [x] Document field definitions and requirements
- [x] Create migration examples

### Phase 2: Update Existing KSI Patterns (74 patterns)
- [ ] Add evidence_collection to existing patterns
- [ ] Add evidence_artifacts to existing patterns
- [ ] Add automation recommendations
- [ ] Add implementation steps
- [ ] Add SSP mapping
- [ ] Add testing section

### Phase 3: Create FRR Patterns (199 patterns)
- [ ] Generate pattern files for all FRRs
- [ ] Populate from frr_metadata.json
- [ ] Extract evidence methods from traditional analyzers
- [ ] Add FRR-specific guidance

### Phase 4: Build Generic Analyzers
- [ ] Create GenericPatternAnalyzer base class
- [ ] Implement language-specific analyzers consuming V2 patterns
- [ ] Add evidence collection methods using pattern data

### Phase 5: Deprecate Traditional Analyzers
- [ ] Remove 72 KSI analyzer files
- [ ] Remove 199 FRR analyzer files
- [ ] Remove 271+ test files
- [ ] Achieve 90%+ code reduction

## Benefits of V2 Schema

### Completeness
- ✅ 100% parity with traditional analyzers
- ✅ All evidence collection capabilities preserved
- ✅ All implementation guidance preserved
- ✅ All SSP mapping preserved

### Accuracy
- ✅ Single source of truth (no code duplication)
- ✅ Version controlled in git (track all changes)
- ✅ Testable (positive/negative test cases embedded)

### Maintainability
- ✅ Update pattern once (affects all languages)
- ✅ Non-developers can contribute YAML
- ✅ Self-documenting (schema enforces completeness)
- ✅ Easy to review (diff YAML vs. 500-line Python files)

### Extensibility
- ✅ Add new language: update language mappings only
- ✅ Add new framework: update compliance_frameworks
- ✅ Add new Azure service: update azure_guidance

## Example: Complete V2 Pattern

See `data/patterns/iam_patterns_v2_example.yaml` for a fully-populated example demonstrating all V2 schema fields.

## Validation

Pattern validation is performed automatically by the pattern engine during loading:

Validates:
- Required fields present (pattern_id, name, family, languages)
- Field types correct (YAML schema compliance)
- Pattern syntax valid (AST queries, regex patterns)
- NIST control IDs valid (when specified)
- Azure service names correct
- Test cases executable
- Evidence queries syntactically valid

## References

- **REFACTORING_PLAN.md** - Overall refactoring strategy
- **Traditional KSI Analyzers** - `src/fedramp_20x_mcp/analyzers/ksi/*.py`
- **Traditional FRR Analyzers** - `src/fedramp_20x_mcp/analyzers/frr/*.py`
- **Metadata Files** - `data/requirements/{ksi,frr}_metadata.json`
- **Current Patterns** - `data/patterns/*.yaml` (V1 schema)
