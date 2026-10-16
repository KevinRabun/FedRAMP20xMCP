# Pattern Authoring Guide

Complete guide for creating and maintaining YAML-based detection patterns for the FedRAMP 20x MCP Server.

> **Note**: This guide covers basic pattern authoring. For complete V2 schema documentation including evidence collection, automation, and SSP mapping, see [PATTERN_SCHEMA_V2.md](PATTERN_SCHEMA_V2.md).

## Table of Contents

- [Overview](#overview)
- [Pattern Format](#pattern-format)
- [V2 Schema Extensions](#v2-schema-extensions)
- [Writing Your First Pattern](#writing-your-first-pattern)
- [AST Query Patterns](#ast-query-patterns)
- [Regex Fallback Patterns](#regex-fallback-patterns)
- [Multi-Language Support](#multi-language-support)
- [Pattern Composition](#pattern-composition)
- [Testing Patterns](#testing-patterns)
- [Best Practices](#best-practices)
- [Common Pitfalls](#common-pitfalls)

## Overview

Patterns are YAML-defined detection rules that identify FedRAMP compliance issues in code. The pattern engine supports:

- **AST-first detection**: Using tree-sitter for accurate, context-aware analysis
- **Regex fallback**: For languages/platforms without tree-sitter support
- **14 languages**: Python, C#, Java, TypeScript, JavaScript, Bicep, Terraform, GitHub Actions, Azure Pipelines, GitLab CI, YAML, JSON, Dockerfile, GitHub
- **Pattern composition**: Combine patterns with boolean logic (requires_all, requires_any, requires_absence)
- **V2 Schema**: Extended fields for evidence collection, automation, SSP mapping, and more

**Design Philosophy**: AST over regex whenever possible. Regex should only be used for languages without tree-sitter support (e.g., GitLab CI YAML, Azure Pipelines YAML).

## Pattern Format

Patterns use a **dict format** where each language has its own configuration:

```yaml
pattern_id: family.category.specific_name
name: Human-Readable Pattern Name
family: FAMILY  # CR26 family code: IAM, MLA, SVC, VDR, VER, CDS, SCG, CMU, IEC, IVV, AFC, ... or COMMON
severity: critical|high|medium|low
description: |
  Multi-line description of what this pattern detects.
  Should reference the relevant FRR requirement.
pattern_type: import|function_call|configuration|decorator|resource|pipeline|function_definition
languages:
  python:
    ast_queries:
      - query_type: import_statement
        target: module_name
    regex_fallback: "(pattern1)|(pattern2)"
  csharp:
    ast_queries:
      - query_type: function_call
        target: function_name
    regex_fallback: "(pattern1)|(pattern2)"
  # ... more languages
finding:
  title: Finding Title
  description: Description of the finding
  recommendation: Remediation guidance with specific FRR reference
  references:
    - VDR-CSO-DET   # CR26 rule ID, must exist in fedramp-consolidated-rules.json
    - KSI-SCR-MON   # CR26 KSI ID
tags: [optional, tags, for, categorization]
nist_controls: [AC-1, SC-7]  # Optional
related_ksis: [KSI-IAM-APM]  # Optional: KSI-* IDs from the CR26 rules JSON
related_frrs: [VDR-CSO-DET]  # Optional: CR26 rule IDs (every pattern needs at least one of the two)
requires_all: [other.pattern.id]  # Optional: Must match all listed patterns
requires_any: [pattern1.id, pattern2.id]  # Optional: Must match at least one
requires_absence: [pattern.to.avoid]  # Optional: Must NOT match these patterns
conflicts_with: [conflicting.pattern]  # Optional: Cannot coexist with these
```

### Field Descriptions

#### Core Fields (V1 Schema)

| Field | Required | Description |
|-------|----------|-------------|
| `pattern_id` | Yes | Unique identifier: `family.category.name` |
| `name` | Yes | Human-readable name |
| `family` | Yes | FedRAMP family code |
| `severity` | Yes | Finding severity level |
| `description` | Yes | What the pattern detects |
| `pattern_type` | Yes | Type of code construct to detect |
| `languages` | Yes | Dict of language configs |
| `finding` | Yes | Template for findings |
| `tags` | No | Categorization tags |
| `nist_controls` | No | Related NIST controls |
| `related_ksis` | No | Related KSI indicators |
| `requires_all` | No | Boolean AND composition |
| `requires_any` | No | Boolean OR composition |
| `requires_absence` | No | Negative detection |
| `conflicts_with` | No | Mutual exclusion |

#### V2 Schema Extensions

| Field | Required | Description |
|-------|----------|-------------|
| `evidence_artifacts` | No | Artifacts to collect for compliance evidence |
| `automation` | No | Automation recommendations and implementation |
| `implementation` | No | Step-by-step implementation guidance |
| `ssp_mapping` | No | System Security Plan control mapping |
| `azure_guidance` | No | Azure-specific service recommendations |
| `compliance_frameworks` | No | Cross-framework compliance mapping |
| `testing` | No | Positive/negative test cases |

> **Note**: See [PATTERN_SCHEMA_V2.md](PATTERN_SCHEMA_V2.md) for complete field definitions and examples.

## V2 Schema Extensions

V2 schema adds fields for comprehensive compliance guidance beyond code detection:

### Evidence Artifacts

Define what evidence to collect for auditors:

```yaml
evidence_artifacts:
  - artifact_type: logs
    name: Authentication logs with MFA details
    source: Azure Monitor - SigninLogs
    frequency: daily
    retention_months: 36
    format: JSON
  - artifact_type: configuration
    name: Conditional Access policies export
    source: Microsoft Graph API
    frequency: weekly
    retention_months: 36
    format: JSON
```

### Automation Recommendations

Provide implementation code and effort estimates:

```yaml
automation:
  policy_enforcement:
    description: Azure Policy for compliance enforcement
    implementation: |
      # Bicep
      resource policy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
        name: 'enforce-mfa'
        properties: {
          policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/...'
        }
      }
    azure_services:
      - Azure Policy
      - Microsoft Entra ID
```

### SSP Mapping

Map to System Security Plan sections:

```yaml
ssp_mapping:
  control_family: IA - Identification and Authentication
  control_numbers:
    - IA-2
    - IA-2(1)
  ssp_sections:
    - section: IA-2 Identification and Authentication
      description_template: |
        The system enforces phishing-resistant MFA using FIDO2/WebAuthn.
      implementation_details: |
        Microsoft Entra ID Conditional Access policies require FIDO2 security keys.
      evidence_references:
        - Conditional Access policy configuration (JSON export)
        - Sign-in logs showing MFA method usage
```

### Implementation Steps

Provide step-by-step guidance:

```yaml
implementation:
  prerequisites:
    - Azure subscription with required permissions
    - Microsoft Entra ID tenant configured
  steps:
    - step: 1
      action: Enable Microsoft Entra ID Premium P2
      azure_service: Microsoft Entra ID
      estimated_hours: 0.5
      validation: Verify license assignment in Azure Portal
    - step: 2
      action: Configure Conditional Access policies
      azure_service: Conditional Access
      estimated_hours: 2
      validation: Test policy enforcement with test user
```

See [PATTERN_SCHEMA_V2.md](PATTERN_SCHEMA_V2.md) for complete V2 schema documentation.

## Writing Your First Pattern

Let's create a pattern to detect hardcoded secrets in Python:

```yaml
pattern_id: svc.secrets.hardcoded_secret
name: Hardcoded Secret Detection
family: SVC
severity: critical
description: |
  Detects hardcoded secrets in source code.
  KSI-SVC-ASM requires secrets to be stored in secure vaults (Azure Key Vault).
pattern_type: configuration
languages:
  python:
    regex_fallback: "(API_KEY|PASSWORD|SECRET|TOKEN)\\s*=\\s*['\"]\\w{10,}"
  csharp:
    regex_fallback: "(ApiKey|Password|Secret|Token)\\s*=\\s*\"\\w{10,}\""
finding:
  title: Hardcoded secret detected
  description: Code contains hardcoded credentials
  recommendation: Store secrets in Azure Key Vault per KSI-SVC-ASM (Secret Management)
  references:
    - KSI-SVC-ASM
```

## AST Query Patterns

AST queries provide accurate, context-aware detection. Supported query types:

### Import Detection

```yaml
languages:
  python:
    ast_queries:
      - query_type: import_statement
        target: requests  # Detects: import requests, from requests import get
```

### Function Call Detection

```yaml
languages:
  python:
    ast_queries:
      - query_type: function_call
        target: eval  # Detects: eval(...), obj.eval(...)
```

### Decorator Detection

```yaml
languages:
  python:
    ast_queries:
      - query_type: decorator
        target: "@app.route"  # Detects: @app.route('/path')
```

### Class Definition Detection

```yaml
languages:
  python:
    ast_queries:
      - query_type: class_definition
        target: BaseClass  # Detects: class MyClass(BaseClass):
```

### Resource Detection (IaC)

```yaml
languages:
  bicep:
    ast_queries:
      - query_type: resource_type
        target: Microsoft.Storage/storageAccounts
  terraform:
    ast_queries:
      - query_type: resource_type
        target: azurerm_storage_account
```

### Conditional Queries

Add conditions to filter matches:

```yaml
languages:
  python:
    ast_queries:
      - query_type: function_call
        target: logging.basicConfig
        conditions:
          - "not contains('siem')"  # Must NOT contain 'siem'
          - "not contains('syslog')"
```

## Regex Fallback Patterns

Use regex for languages without tree-sitter support or as a complement to AST queries.

### Best Practices

1. **Use alternation for multiple patterns**: `(pattern1)|(pattern2)|(pattern3)`
2. **Make patterns specific**: Avoid overly broad matches
3. **Use word boundaries**: `\b` to avoid partial matches
4. **Case insensitive**: Patterns are case-insensitive by default
5. **Document why**: Add comment if using regex when AST is available

### Examples

**Good** - Specific, targeted:
```yaml
regex_fallback: "(console\.log|System\.out\.println|Debug\.WriteLine)\("
```

**Bad** - Too broad:
```yaml
regex_fallback: "log"  # Matches "logic", "logarithm", etc.
```

**Multi-pattern**:
```yaml
regex_fallback: "(import requests)|(import urllib)|(import http\.client)"
```

## Multi-Language Support

Patterns can support multiple languages with different detection logic per language:

```yaml
pattern_id: common.logging.centralized
name: Centralized Logging Detection
family: COMMON
severity: high
description: Detects centralized logging configuration
pattern_type: configuration
languages:
  python:
    ast_queries:
      - query_type: import_statement
        target: azure.monitor
      - query_type: function_call
        target: LogAnalyticsDataCollector
    regex_fallback: "(azure\.monitor|LogAnalytics|ApplicationInsights)"
  csharp:
    ast_queries:
      - query_type: function_call
        target: AddApplicationInsights
    regex_fallback: "(AddApplicationInsights|TelemetryClient|LogAnalytics)"
  java:
    ast_queries:
      - query_type: import_statement
        target: com.azure.monitor
    regex_fallback: "(azure\.monitor|ApplicationInsights)"
  typescript:
    regex_fallback: "(applicationInsights|@azure/monitor)"
  bicep:
    ast_queries:
      - query_type: resource_type
        target: Microsoft.Insights/components
    regex_fallback: "Microsoft\\.Insights/components"
  terraform:
    ast_queries:
      - query_type: resource_type
        target: azurerm_application_insights
    regex_fallback: "azurerm_application_insights"
  github_actions:
    regex_fallback: "(Az\\.ApplicationInsights|azure/login)"
  azure_pipelines:
    regex_fallback: "(AzureLogAnalytics|ApplicationInsights)"
finding:
  title: Centralized logging configured
  description: Application uses centralized logging service
  recommendation: Ensure all logs are exported to Azure Log Analytics per KSI-MLA-OSM
  references:
    - CCM-OCR-AVL
    - KSI-MLA-OSM
```

## Pattern Composition

Combine patterns with boolean logic for complex detection scenarios.

### Requires All (AND)

All listed patterns must match:

```yaml
pattern_id: iam.mfa.complete_implementation
name: Complete MFA Implementation
requires_all:
  - iam.mfa.library_import
  - iam.mfa.configuration
  - iam.mfa.enforcement
finding:
  title: Complete MFA implementation detected
```

### Requires Any (OR)

At least one listed pattern must match:

```yaml
pattern_id: svc.secrets.any_vault
name: Any Secret Vault Usage
requires_any:
  - svc.secrets.azure_key_vault
  - svc.secrets.hashicorp_vault
finding:
  title: Secret vault usage detected
```

### Requires Absence (NOT)

Listed patterns must NOT match:

```yaml
pattern_id: svc.secrets.no_hardcoded
name: No Hardcoded Secrets
severity: critical
requires_absence:
  - svc.secrets.hardcoded_secret
finding:
  title: No hardcoded secrets detected
  severity: info  # Positive finding
```

### Conflicts With

Pattern cannot coexist with listed patterns:

```yaml
pattern_id: iam.auth.oauth2
name: OAuth2 Authentication
conflicts_with:
  - iam.auth.basic_auth  # Can't have both OAuth2 and Basic Auth
finding:
  title: OAuth2 authentication detected
```

## Testing Patterns

### 1. Create Test File

Create `tests/test_pattern_[family]_[name].py`:

```python
"""Test [family].[name] pattern detection."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine


def test_positive_detection():
    """Test pattern detects positive case."""
    engine = PatternEngine()
    engine.load_patterns("data/patterns/[family]_patterns.yaml")
    
    code = """
    # Code that SHOULD trigger the pattern
    API_KEY = "hardcoded-secret-123"
    """
    
    result = engine.analyze(code, "python")
    
    # Verify pattern detected the issue
    assert len(result.findings) > 0, "Pattern should detect hardcoded secret"
    assert any("[family].[name]" in f.requirement_id for f in result.findings)


def test_negative_case():
    """Test pattern does NOT match correct code."""
    engine = PatternEngine()
    engine.load_patterns("data/patterns/[family]_patterns.yaml")
    
    code = """
    # Code that SHOULD NOT trigger the pattern
    from azure.keyvault import SecretClient
    secret = secret_client.get_secret("api-key")
    """
    
    result = engine.analyze(code, "python")
    
    # Verify pattern does NOT detect
    findings = [f for f in result.findings if "[family].[name]" in f.requirement_id]
    assert len(findings) == 0, "Pattern should not trigger on correct code"


if __name__ == "__main__":
    test_positive_detection()
    test_negative_case()
    print("[PASS] All pattern tests passed")
```

### 2. Run Test

```bash
python tests/test_pattern_[family]_[name].py
```

### 3. Integration Test

Verify pattern works in hybrid analysis:

```python
from fedramp_20x_mcp.tools.analyzer import analyze_application_code_impl

result = await analyze_application_code_impl(
    code=test_code,
    language="python",
    file_path="test.py"
)

assert result['analysis_mode'] == 'hybrid'
assert result['pattern_findings_count'] > 0
```

## Best Practices

### 1. AST-First Approach

**DO**: Use AST queries for supported languages
```yaml
languages:
  python:
    ast_queries:
      - query_type: function_call
        target: eval
```

**DON'T**: Use regex when AST is available
```yaml
# Bad - AST is available for Python
languages:
  python:
    regex_fallback: "eval\\("  # Use AST instead!
```

### 2. Specific Patterns

**DO**: Be specific and targeted
```yaml
regex_fallback: "(supportsHttpsTrafficOnly.*false|allowBlobPublicAccess.*true)"
```

**DON'T**: Use overly broad patterns
```yaml
regex_fallback: "http"  # Too broad - matches "https", "method", etc.
```

### 3. Document Patterns

**DO**: Provide clear descriptions and recommendations
```yaml
description: |
  Detects storage accounts without HTTPS enforcement.
  KSI-SVC-SIN requires encrypted network connections.
finding:
  recommendation: Set supportsHttpsTrafficOnly to true per KSI-SVC-SIN
```

**DON'T**: Leave descriptions vague
```yaml
description: "Storage issue"  # What issue? How to fix?
```

### 4. Test Coverage

**DO**: Test both positive and negative cases
```python
def test_positive(): # Should detect
def test_negative(): # Should NOT detect
def test_edge_cases(): # Boundary conditions
```

**DON'T**: Only test happy path
```python
def test_detection():  # Only tests one scenario
```

### 5. Language Coverage

**DO**: Support all relevant languages for a requirement
```yaml
languages:
  python: { ... }
  csharp: { ... }
  java: { ... }
  typescript: { ... }
```

**DON'T**: Only support one language when others are relevant
```yaml
languages:
  python: { ... }  # What about C#, Java developers?
```

## Common Pitfalls

### 1. Regex Instead of AST

**Problem**: Using regex when tree-sitter is available

**Solution**: Check `analyzers/ast_utils.py` for supported languages. Use AST for: Python, C#, Java, TypeScript, JavaScript, Bicep, Terraform.

### 2. Overly Broad Patterns

**Problem**: Pattern matches too many false positives

**Solution**: Add specificity with word boundaries, context, or conditions

```yaml
# Bad
regex_fallback: "password"

# Good
regex_fallback: "(PASSWORD|PWD|PASSWD)\\s*=\\s*['\"]\\w{8,}"
```

### 3. Missing Negative Tests

**Problem**: Only testing that pattern detects issues, not that it ignores correct code

**Solution**: Always include negative test cases

```python
def test_no_false_positives():
    """Verify pattern doesn't trigger on compliant code."""
    # Test correct implementations
```

### 4. Inconsistent Severity

**Problem**: Similar patterns have different severities

**Solution**: Follow severity guidelines:
- `critical`: Direct security vulnerability (hardcoded secrets, missing encryption)
- `high`: Compliance violation (missing logging, improper auth)
- `medium`: Best practice violation (missing tags, suboptimal config)
- `low`: Informational (optimization opportunities)

### 5. Missing References

**Problem**: Finding doesn't reference specific requirements

**Solution**: Always include CR26 rule and KSI references. Never invent IDs and never state numeric requirements CR26 does not contain (for example log retention periods or 7/15/30/90 day severity buckets; VDR-TFR-PVR uses the Potential Agency Impact N-rating, internet reachability and likely exploitability).

```yaml
finding:
  references:
    - KSI-SVC-ASM  # Primary KSI (Automating Secret Management)
    - SCG-CSO-RSC  # Related rule (Secure Configuration Guide)
```

### 6. Duplicate Language Configs

**Problem**: Copy-pasting same config for all languages

**Solution**: Only include languages with different detection logic. Share patterns when possible using YAML anchors:

```yaml
languages:
  python:
    ast_queries: &common_queries
      - query_type: import_statement
        target: module
    regex_fallback: &common_regex "(pattern)"
  csharp:
    ast_queries: *common_queries
    regex_fallback: *common_regex
```

## Pattern File Organization

Patterns are organized by CR26 family in `data/patterns/`. Detection patterns live in the file of the KSI category or rule family they map to; the `family:` field is authoritative. Pattern ids keep their historical prefix (for example `ads.*`, `ucm.*`) as stable keys.

```
data/patterns/
├── afc_patterns.yaml            # Addressing FedRAMP Communication (16)
├── ccm_patterns.yaml            # Collaborative Continuous Monitoring (25)
├── cds_patterns.yaml            # Certification Data Sharing (28)
├── ced_patterns.yaml            # KSI-CED training (12)
├── cmt_patterns.yaml            # KSI-CMT change management (25)
├── cmu_patterns.yaml            # Cryptographic Module Use (4)
├── cna_patterns.yaml            # KSI-CNA cloud native architecture (33)
├── common_patterns.yaml         # Cross-cutting Azure governance (8)
├── cross_family_patterns.yaml   # Cross-rule patterns, family set per pattern (25)
├── iam_patterns.yaml            # KSI-IAM (34)
├── iec_patterns.yaml            # Incident Evaluation and Communication (9)
├── inr_patterns.yaml            # KSI-INR incident response (9)
├── ivv_patterns.yaml            # Independent Verification and Validation (22)
├── mas_patterns.yaml            # Minimum Assessment Scope (9)
├── mla_patterns.yaml            # KSI-MLA logging and monitoring (17)
├── piy_patterns.yaml            # KSI-PIY policy and inventory (21)
├── rpl_patterns.yaml            # KSI-RPL recovery (9)
├── scg_patterns.yaml            # Secure Configuration Guide (10)
├── scn_patterns.yaml            # Significant Change Notification (19)
├── scr_patterns.yaml            # KSI-SCR supply chain risk (8)
├── svc_patterns.yaml            # KSI-SVC service configuration (30)
└── vdr_patterns.yaml            # Vulnerability detection and response, scanning (79)
```

**Total**: 452 patterns across 25 `family:` values (CR26 FRR families AFC, AGU, CCM, CDS, CMU, FRC, IEC, IVV, MAS, SCG, SCN, SDR, VDR, VER; KSI categories CED, CMT, CNA, IAM, INR, MLA, PIY, RPL, SCR, SVC; plus COMMON).

Retired pre-CR26 families map as follows: ADS to CDS, FSI to AFC, UCM to CMU, PVA to IVV, ICP to IEC, RSC to SCG, TPR to SCR (as KSI-SCR). The KSI-AFR family was removed; its items became FRR families. VDR evaluation and reporting rules moved to VER.

## Pattern Coverage

Current pattern library status (computed from the YAML; recompute after changes):

| Family | Patterns |
|--------|----------|
| AFC | 18 |
| AGU | 7 |
| CCM | 22 |
| CDS | 30 |
| CED | 12 |
| CMT | 25 |
| CMU | 6 |
| CNA | 35 |
| COMMON | 8 |
| FRC | 3 |
| IAM | 34 |
| IEC | 10 |
| INR | 9 |
| IVV | 14 |
| MAS | 10 |
| MLA | 17 |
| PIY | 21 |
| RPL | 9 |
| SCG | 11 |
| SCN | 22 |
| SCR | 8 |
| SDR | 1 |
| SVC | 30 |
| VDR | 60 |
| VER | 30 |
| **Total** | **452** |

All 46 CR26 KSIs and 142 CR26 rule IDs are referenced by at least one pattern.

**V2 Migration Status**: V2 fields (`evidence_artifacts`, `automation`, `implementation`, `ssp_mapping`) are being added to existing patterns. See [PATTERN_SCHEMA_V2.md](PATTERN_SCHEMA_V2.md) for migration roadmap.

## Contributing Patterns

When contributing new patterns:

1. **Choose the right family**: Place pattern in appropriate family file
2. **Follow naming convention**: `family.category.specific_name`
3. **Use AST first**: Only use regex for unsupported languages
4. **Test thoroughly**: Include positive, negative, and edge cases
5. **Document clearly**: Explain what, why, and how to fix
6. **Reference requirements**: Link to FRR and KSI documents
7. **Check for duplicates**: Ensure similar pattern doesn't exist
8. **Update coverage**: Run `check_language_coverage.py` to verify

## Next Steps

- **Read existing patterns**: Study `data/patterns/` for examples
- **Run tests**: Execute `python tests/test_pattern_integration.py`
- **Check coverage**: Run `python tests/check_language_coverage.py`
- **Experiment**: Create test patterns in a scratch file
- **Contribute**: Submit PR with new patterns and tests

## Resources

- **V2 Schema Documentation**: `docs/PATTERN_SCHEMA_V2.md` - Complete field reference
- **Pattern Engine**: `src/fedramp_20x_mcp/analyzers/pattern_engine.py`
- **AST Utils**: `src/fedramp_20x_mcp/analyzers/ast_utils.py`
- **Tool Adapter**: `src/fedramp_20x_mcp/analyzers/pattern_tool_adapter.py`
- **Integration Tests**: `tests/test_pattern_integration.py`
- **Example Patterns**: `data/patterns/*.yaml` (153 patterns across 18 families)

## Support

For questions or issues:
1. Check existing patterns for examples
2. Review test files for usage patterns
3. Open GitHub issue with pattern YAML and test code
4. Include: What you want to detect, language, expected behavior
