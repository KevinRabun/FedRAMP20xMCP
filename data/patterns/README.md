# FedRAMP 20x Pattern Libraries

This directory contains YAML-based pattern definitions for detecting compliance issues and security configurations across multiple programming languages and platforms.

## Overview

Pattern libraries enable data-driven code analysis by separating detection logic from analyzer implementation. Each pattern defines:
- **What to detect**: AST queries, regex patterns, configuration checks
- **Which languages**: Python, C#, Java, TypeScript, Bicep, Terraform, etc.
- **How to report**: Finding templates with severity and remediation
- **FedRAMP context**: Related KSIs, NIST controls, Azure services

## Pattern Libraries

Patterns are aligned to the FedRAMP Consolidated Rules for 2026 (CR26), version 2026.10.13.01.
Every pattern maps to at least one real CR26 rule or KSI ID (`related_ksis` for `KSI-*` IDs,
`related_frrs` for rule IDs such as `VDR-CSO-DET`). The source of truth is
`src/fedramp_20x_mcp/rules_data/fedramp-consolidated-rules.json`; legacy IDs are resolved with
`src/fedramp_20x_mcp/rules_data/legacy-crosswalk.json`.

Two kinds of pattern exist:

- **Detection patterns** (262): code, IaC and pipeline checks (AST first, regex fallback), mapped to KSIs and rules.
- **Compliance patterns** (190, `pattern_type: compliance`, ids `*.frr.*`): one placeholder per CR26 rule used for evidence and checklist guidance.

### CR26 families used by `family:`

| Family | Meaning | Source |
|--------|---------|--------|
| AFC | Addressing FedRAMP Communication | was FSI |
| AGU | Agency Use of FedRAMP Certified Cloud Services | |
| CCM | Collaborative Continuous Monitoring | |
| CDS | Certification Data Sharing | was ADS |
| CMU | Cryptographic Module Use | was UCM |
| FRC | FedRAMP Certification | |
| IEC | Incident Evaluation and Communication | was ICP |
| IVV | Independent Verification and Validation | was PVA |
| MAS | Minimum Assessment Scope | |
| SCG | Secure Configuration Guide | was RSC |
| SCN | Significant Change Notification | |
| SDR | Security Decision Record | |
| VDR | Vulnerability Detection and Response | |
| VER | Vulnerability Evaluation and Reporting | split out of VDR |
| CED CMT CNA IAM INR MLA PIY RPL SCR SVC | KSI categories (SCR was TPR) | |
| COMMON | Cross-cutting Azure governance checks | not a FedRAMP family |

There is no `KSI-AFR` family (its items became FRR families) and no `KSI-VDR` family.

### Files (452 patterns, 25 family values)

| File | Patterns | Contents |
|------|----------|----------|
| afc_patterns.yaml | 16 | Addressing FedRAMP Communication (compliance) |
| ccm_patterns.yaml | 25 | Collaborative Continuous Monitoring (compliance) |
| cds_patterns.yaml | 28 | Certification Data Sharing: JSON/XML export, trust center access, Azure Monitor export |
| ced_patterns.yaml | 12 | Training (KSI-CED-RAT) |
| cmt_patterns.yaml | 25 | Change management: Git, PR approval, deployment gates, rollback (KSI-CMT-*) |
| cmu_patterns.yaml | 4 | Cryptographic Module Use (compliance) |
| cna_patterns.yaml | 33 | Cloud native architecture, network, containers, resource limits and quotas (KSI-CNA-*) |
| common_patterns.yaml | 8 | Cross-cutting Azure governance |
| cross_family_patterns.yaml | 25 | Cross-rule detections and compliance (was afr and ksi files); `family:` is set per pattern |
| iam_patterns.yaml | 34 | MFA, RBAC, least privilege, managed identity (KSI-IAM-*) |
| iec_patterns.yaml | 9 | Incident Evaluation and Communication (compliance) |
| inr_patterns.yaml | 9 | Incident response (KSI-INR-*) |
| ivv_patterns.yaml | 22 | Independent Verification and Validation (compliance, includes VDR-TFR-MVX/NMV) |
| mas_patterns.yaml | 9 | Minimum Assessment Scope (compliance) |
| mla_patterns.yaml | 17 | Logging, SIEM, alerting (KSI-MLA-*) |
| piy_patterns.yaml | 21 | Policy and inventory, SDLC, vulnerability disclosure (KSI-PIY-*) |
| rpl_patterns.yaml | 9 | Backup and recovery (KSI-RPL-*) |
| scg_patterns.yaml | 10 | Secure Configuration Guide (compliance) |
| scn_patterns.yaml | 19 | Significant Change Notifications (compliance) |
| scr_patterns.yaml | 8 | Supply chain risk: dependency scanning, SBOM (KSI-SCR-MIT, KSI-SCR-MON) |
| svc_patterns.yaml | 30 | Encryption, secrets, configuration automation (KSI-SVC-*) |
| vdr_patterns.yaml | 79 | Vulnerability detection (SAST, SCA, container, IaC, DAST scanning, patching) plus VDR/VER compliance patterns |

Notes:

- Pattern ids keep their historical prefix (for example `ads.machine_readable.json_export`, `ucm.rbac.role_definition`, `rsc.allocation.resource_limits`). The id is a stable key; the `family:` field and the related rule IDs are authoritative.
- Pattern ids prefixed `scn.` (scanning), `ucm.` (RBAC), `rsc.` (resource limits) and `ccm.` (change management) that are detections now live under the KSI family that matches their intent (VDR, IAM, CNA, CMT).
- The upstream-invented IDs (the old numbered KSI-VDR and MAS-AY series) never existed in a FedRAMP release and were remapped by intent or removed.

### Coverage

- **452 patterns**, 25 `family:` values.
- **46 of 46** CR26 KSIs and **142** CR26 rule IDs are referenced by at least one pattern.
- Languages (pattern count per language key): Bicep 285, Terraform 292, Python/C#/Java/TypeScript 103 each, GitHub Actions 35, Azure Pipelines 29, GitLab CI 23.

## Pattern Structure

Each pattern follows this YAML schema:

```yaml
---
pattern_id: "family.category.specific_check"
name: "Human-Readable Pattern Name"
description: "What this pattern detects"
family: "CR26 family code, for example IAM, VDR, VER, CDS, SCG, COMMON"
severity: "INFO|MEDIUM|HIGH|CRITICAL"
pattern_type: "import|function_call|configuration|decorator|resource|pipeline"

languages:
  python:
    ast_queries:
      - query_type: "import_statement"
        target: "module_name"
    regex_fallback: "import\\s+module_name"
    positive_indicators: ["keyword1", "keyword2"]  # Positive finding
    negative_indicators: ["keyword1", "keyword2"]  # Security gap
    
  # Additional languages...

finding:
  title_template: "Finding title with {placeholder}"
  description_template: "Detailed description"
  remediation_template: "How to fix the issue"
  evidence_collection:
    - "Artifact 1 to collect"
    - "Artifact 2 to collect"
  azure_services:
    - "Azure Service Name"

tags: ["tag1", "tag2", "tag3"]
nist_controls: ["ia-2", "au-3", "sc-8"]
related_ksis: ["KSI-IAM-APM", "KSI-MLA-OSM"]   # KSI-* IDs from the CR26 rules JSON
related_frrs: ["VDR-CSO-DET"]                    # CR26 rule IDs (<FAMILY>-<GROUP>-<RULE>)

# Pattern relationships (optional)
requires_all: ["pattern_id_1", "pattern_id_2"]  # All must match
requires_any: ["pattern_id_3", "pattern_id_4"]  # At least one must match
requires_absence: ["pattern_id_5"]              # Must NOT match
conflicts_with: ["pattern_id_6"]                # Cannot coexist
```

## Language Support

### Application Code
- **Python**: AST-based analysis (tree-sitter) + regex fallback
- **C#/.NET**: AST-based analysis + regex fallback
- **Java**: AST-based analysis + regex fallback
- **TypeScript/JavaScript**: AST-based analysis + regex fallback

### Infrastructure as Code
- **Bicep**: AST-based resource analysis + regex fallback
- **Terraform**: AST-based resource analysis + regex fallback

### CI/CD Pipelines
- **GitHub Actions**: Workflow analysis
- **Azure Pipelines**: Pipeline YAML analysis
- **GitLab CI**: Pipeline YAML analysis

### Container Images
- **Dockerfile**: Instruction analysis

## Pattern Types

1. **import** - Library/module imports (positive or negative indicators)
2. **function_call** - Function/method invocations
3. **configuration** - Configuration settings, constants, environment variables
4. **decorator** - Decorators/attributes applied to functions/classes
5. **resource** - IaC resource definitions
6. **pipeline** - CI/CD pipeline steps and tasks

## Severity Levels

- **INFO**: Positive finding (compliance met) or informational
- **MEDIUM**: Minor security gap or configuration issue
- **HIGH**: Significant security gap requiring attention
- **CRITICAL**: Severe security gap or missing critical control

## Finding Templates

Templates support placeholders for dynamic content:
- `{resource_type}` - Type of resource
- `{version}` - Version number
- `{value}` - Configuration value
- `{package_name}` - Package name
- `{cve_count}` - Number of CVEs
- `{fixed_version}` - Fixed version number

## Pattern Composition

Patterns can reference other patterns using boolean logic:

```yaml
# All patterns must match
requires_all: ["iam.mfa.fido2_import", "iam.mfa.azure_ad_import"]

# At least one pattern must match
requires_any: ["mla.logging.azure_monitor", "mla.logging.siem_integration"]

# Pattern must NOT match (used for negative findings)
requires_absence: ["iam.mfa.totp_import", "iam.mfa.sms_mfa"]

# Cannot coexist with this pattern
conflicts_with: ["svc.security.missing_hsts"]
```

## Statistics

See "Coverage" above. Recompute counts from the YAML after any change; do not hand-maintain them.

## Usage

Patterns are consumed by the pattern engine (`src/fedramp_20x_mcp/analyzers/pattern_engine.py`):

```python
from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine

engine = PatternEngine()

# Load patterns from YAML
engine.load_patterns("data/patterns/iam_patterns.yaml")

# Analyze code
results = engine.analyze(
    code=code_snippet,
    language="python",
    file_path="app.py"
)

# Filter by family, severity, or KSI
iam_findings = engine.analyze(code, language="python", family="IAM")
critical_findings = [r for r in results if r.severity == "CRITICAL"]
```

## Pattern Development Guidelines

### AST-First Approach (CRITICAL)

**ALWAYS prioritize tree-sitter AST over regex:**

1. **Primary**: Use AST queries for accurate, context-aware detection
2. **Fallback**: Use regex ONLY when AST unavailable (e.g., GitLab CI YAML)
3. **Document**: Explain why regex is used when AST not available

Example:
```yaml
languages:
  python:
    ast_queries:
      - query_type: "function_call"
        target: "dangerous_function"
    regex_fallback: "dangerous_function\\("  # Fallback only
```

### Pattern Quality Checklist

- [ ] Pattern ID follows naming convention: `family.category.specific_check`
- [ ] Language coverage includes all relevant platforms
- [ ] AST queries used when language has tree-sitter support
- [ ] Regex fallback provided for robustness
- [ ] Finding templates are clear and actionable
- [ ] Remediation guidance includes code examples
- [ ] Related KSIs and NIST controls documented
- [ ] Azure services listed when applicable
- [ ] Tags help categorize and filter patterns

### Creating New Patterns

1. **Identify requirement**: Start with a CR26 rule or KSI ID that exists in `fedramp-consolidated-rules.json` (never invent IDs; CR26 sets no numeric log retention rule and no severity-bucket remediation deadlines)
2. **Research detection**: Analyze existing code for detection logic
3. **Define AST queries**: Use tree-sitter for primary detection
4. **Add regex fallback**: Ensure compatibility if AST fails
5. **Test across languages**: Verify detection in all supported languages
6. **Document findings**: Create clear templates with remediation
7. **Add metadata**: Include KSIs, NIST controls, Azure services

### Pattern Validation

Before committing patterns:

```bash
# Validate YAML syntax
python -c "import yaml; yaml.safe_load(open('data/patterns/iam_patterns.yaml'))"

# Test pattern matching
python tests/test_pattern_engine.py

# Run full test suite
python tests/run_all_tests.py
```

## Next Steps

Phase 2 continuation:
1. **Implement pattern engine** (`src/fedramp_20x_mcp/analyzers/pattern_engine.py`)
2. **Implement pattern compiler** (`src/fedramp_20x_mcp/analyzers/pattern_compiler.py`)
3. **Create test suite** for pattern matching
4. **Expand patterns** for CR26 families with no detection coverage
5. **Integrate with existing analyzers** for backward compatibility

## References

- Pattern schema: `docs/PATTERN_SCHEMA_V2.md`
- Pattern authoring guide: `docs/PATTERN_AUTHORING_GUIDE.md`
- AST utilities: `src/fedramp_20x_mcp/analyzers/ast_utils.py`
- Pattern engine: `src/fedramp_20x_mcp/analyzers/pattern_engine.py`
- KSI factory: `src/fedramp_20x_mcp/analyzers/ksi/factory.py`
- FRR factory: `src/fedramp_20x_mcp/analyzers/frr/factory.py`
