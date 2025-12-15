# FedRAMP 20x Pattern Libraries

This directory contains YAML-based pattern definitions for detecting compliance issues and security configurations across multiple programming languages and platforms.

## Overview

Pattern libraries enable data-driven code analysis by separating detection logic from analyzer implementation. Each pattern defines:
- **What to detect**: AST queries, regex patterns, configuration checks
- **Which languages**: Python, C#, Java, TypeScript, Bicep, Terraform, etc.
- **How to report**: Finding templates with severity and remediation
- **FedRAMP context**: Related KSIs, NIST controls, Azure services

## Pattern Libraries

### Phase 1: Core Families (52 patterns)

1. **iam_patterns.yaml** - Identity and Access Management (10 patterns)
   - Phishing-resistant MFA detection (KSI-IAM-01)
   - FIDO2, WebAuthn, Azure AD integrations
   - RBAC and least privilege (KSI-IAM-02)
   - Session management (KSI-IAM-05)

2. **mla_patterns.yaml** - Monitoring, Logging, and Alerting (11 patterns)
   - Centralized logging to SIEM (KSI-MLA-01)
   - Azure Monitor, Sentinel integration
   - Log retention policies (KSI-MLA-02)
   - Security event monitoring (KSI-MLA-05)
   - Real-time alerting (KSI-MLA-07)

3. **svc_patterns.yaml** - Security Vulnerability and Configuration (13 patterns)
   - Security headers (HSTS, CSP) (KSI-SVC-01)
   - Key Vault secret management (KSI-SVC-02)
   - Encryption at rest (KSI-SVC-04)
   - Network security (NSG, private endpoints) (KSI-SVC-06)
   - TLS configuration (KSI-SVC-07)

4. **vdr_patterns.yaml** - Vulnerability Detection and Remediation (10 patterns)
   - Microsoft Defender for Cloud (KSI-VDR-01)
   - CI/CD security scanning (SAST, container scanning) (KSI-VDR-01, KSI-VDR-02)
   - Patch management (KSI-VDR-03)
   - Dependency vulnerability tracking (KSI-VDR-04)

5. **common_patterns.yaml** - Cross-Cutting Concerns (8 patterns)
   - Environment configuration
   - Error handling
   - Input validation
   - Documentation

### Phase 2: Extended Families (68 patterns)

6. **ads_patterns.yaml** - Audit Data System (10 patterns)
   - Machine-readable formats (JSON/XML export)
   - REST API for audit data access
   - Structured logging with required fields
   - Azure Monitor data export
   - Log Analytics workspace configuration

7. **ucm_patterns.yaml** - User Capability Management (11 patterns)
   - RBAC role definitions and enforcement
   - Authorization decorators/attributes
   - Explicit capability checks
   - Session timeout configuration
   - Azure Managed Identity and RBAC assignments
   - Key Vault access policies

8. **cna_patterns.yaml** - Cloud Native Architecture (11 patterns)
   - Network Security Groups (NSGs)
   - Azure Firewall configuration
   - Container images and AKS clusters
   - Azure Container Registry
   - Service mesh and API Gateway
   - Container build and IaC validation

9. **ccm_patterns.yaml** - Configuration Change Management (12 patterns)
   - Git version control usage
   - Change audit logging
   - Pull request approval workflows
   - Automated testing before deployment
   - Rollback capabilities
   - ARM/Bicep/Terraform validation
   - Deployment gates and configuration backup

10. **rsc_patterns.yaml** - Resource Management (11 patterns)
    - Resource limits configuration (CPU, memory)
    - Resource metrics monitoring
    - Autoscaling configuration
    - Namespace resource quotas
    - Cost budget alerts
    - App Service Plans and VM sizing
    - Reserved instance usage

11. **scn_patterns.yaml** - Security Scanning (13 patterns)
    - SAST tool integration (CodeQL, SonarQube, Snyk)
    - Software Composition Analysis (SCA)
    - Container image scanning (Trivy, Aqua, Clair)
    - IaC security scanning (Checkov, TFSec, Terrascan)
    - Secrets scanning (GitLeaks, TruffleHog)
    - DAST integration
    - Microsoft Defender for Cloud
    - Azure Policy assignments
    - Security scan gates

### Total Coverage
- **120 patterns** across **11 families**
- **100% FedRAMP 20x family coverage**
- Multi-language support: Python, C#, Java, TypeScript/JavaScript
- IaC support: Bicep, Terraform
- CI/CD support: GitHub Actions, Azure Pipelines, GitLab CI

5. **common_patterns.yaml** - Cross-Cutting Patterns
   - Azure resource tagging
   - Diagnostic settings for all resources
   - Managed identity usage
   - Public network access restrictions
   - Azure Policy assignments
   - Resource locks
   - Backup configuration
   - Geo-redundancy
   - 8 patterns applicable across all families

## Pattern Structure

Each pattern follows this YAML schema:

```yaml
---
pattern_id: "family.category.specific_check"
name: "Human-Readable Pattern Name"
description: "What this pattern detects"
family: "IAM|MLA|SVC|VDR|COMMON"
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
related_ksis: ["KSI-IAM-01", "KSI-MLA-01"]

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

### Total Patterns: 65

| Library | Patterns | KSIs Covered | Focus Areas |
|---------|----------|--------------|-------------|
| IAM     | 12       | 3            | MFA, RBAC, session management |
| MLA     | 15       | 7            | Logging, monitoring, alerting |
| SVC     | 18       | 8            | Security, secrets, encryption |
| VDR     | 12       | 5            | Vulnerability scanning, patching |
| Common  | 8        | -            | Cross-cutting governance patterns |

### Language Coverage

- **Python**: 55 patterns (85%)
- **C#**: 48 patterns (74%)
- **Java**: 12 patterns (18%)
- **TypeScript**: 18 patterns (28%)
- **Bicep**: 38 patterns (58%)
- **Terraform**: 38 patterns (58%)
- **GitHub Actions**: 8 patterns (12%)
- **Azure Pipelines**: 8 patterns (12%)
- **GitLab CI**: 4 patterns (6%)

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

1. **Identify requirement**: Start with FedRAMP requirement (KSI/FRR)
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
4. **Expand patterns** to remaining families (AFR, CNA, PIY, RPL, etc.)
5. **Integrate with existing analyzers** for backward compatibility

## References

- Pattern schema: `docs/PATTERN_SCHEMA_V2.md`
- Pattern authoring guide: `docs/PATTERN_AUTHORING_GUIDE.md`
- AST utilities: `src/fedramp_20x_mcp/analyzers/ast_utils.py`
- Pattern engine: `src/fedramp_20x_mcp/analyzers/pattern_engine.py`
- KSI factory: `src/fedramp_20x_mcp/analyzers/ksi/factory.py`
- FRR factory: `src/fedramp_20x_mcp/analyzers/frr/factory.py`
