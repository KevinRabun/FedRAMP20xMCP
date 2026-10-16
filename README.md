# FedRAMP 20x MCP Server

[![Tests](https://github.com/KevinRabun/FedRAMP20xMCP/actions/workflows/test.yml/badge.svg)](https://github.com/KevinRabun/FedRAMP20xMCP/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/fedramp-20x-mcp.svg)](https://pypi.org/project/fedramp-20x-mcp/)
[![Python Versions](https://img.shields.io/pypi/pyversions/fedramp-20x-mcp.svg)](https://pypi.org/project/fedramp-20x-mcp/)

<!-- mcp-name: io.github.KevinRabun/FedRAMP20xMCP -->

An MCP (Model Context Protocol) server that provides access to the **FedRAMP Consolidated Rules for 2026 (CR26)** with **Azure-first guidance**, plus a pipeline scanner (`fedramp-20x-scan`) that evaluates code against the same rules and records evidence of each run.

> **Release 1.4.0 moved the server to CR26, version 2026.10.13.01.** The pre-2026 data source no longer exists upstream, family names changed, and the KSI set changed. See [docs/CR26-MIGRATION.md](docs/CR26-MIGRATION.md) for what moved and how legacy IDs resolve.

**Attribution:** this project originated as [KevinRabun/FedRAMP20xMCP](https://github.com/KevinRabun/FedRAMP20xMCP) (MIT License). This repository is now a fork maintained locally; the badges and the package metadata above still point at the upstream project. Credit for the original server, pattern engine and tool design belongs to its author.

## Overview

The server loads the CR26 rules from the official [FedRAMP/rules](https://github.com/FedRAMP/rules) repository and provides tools for querying requirements by control, family, or keyword, reviewing code against them, and generating evidence-collection guidance.

**Data Sources:**

| Data | Source | Notes |
|---|---|---|
| Rules | `fedramp-consolidated-rules.json` in [FedRAMP/rules](https://github.com/FedRAMP/rules) | Fetched live by default, cached for 1 hour |
| Documentation | `content/` in [FedRAMP/2026](https://github.com/FedRAMP/2026) (markdown site content) | Keyed by relative path, for example `providers/20x/index.md` |
| Bundled snapshot | `src/fedramp_20x_mcp/rules_data/fedramp-consolidated-rules.json` | Pinned fallback when the network or upstream is unavailable |
| Legacy-ID crosswalk | `src/fedramp_20x_mcp/rules_data/legacy-crosswalk.json` | Resolves pre-CR26 IDs; each entry records its `basis` and `confidence` |

Every load records the rules `source`, `version`, `last_updated` and `sha256`. The scanner writes these to `run.json`, so stored evidence names the exact rules release it was evaluated against. The bundled snapshot is version `2026.10.13.01`, sha256 `fb48d677a85d77fb72735a325de2c1945a1e0ceab1d2e655292fe9ebe3e4e0b4`.

Rules source order: in-memory and on-disk cache, then `FEDRAMP_RULES_FILE` or a live fetch of `FEDRAMP_RULES_URL`, then a stale cache, then the bundled snapshot.

| Variable | Effect |
|---|---|
| `FEDRAMP_RULES_OFFLINE=1` | Use the bundled snapshot, no network. Reproducible runs. |
| `FEDRAMP_RULES_FILE=path` | Use a local rules JSON (air-gapped mirror). |
| `FEDRAMP_RULES_URL=url` | Fetch rules from another URL (internal mirror). |
| `GITHUB_TOKEN` | Raises GitHub API limits for rules and documentation fetches. |

**Azure Focus:** All implementation examples, architecture patterns, and vendor recommendations prioritize Microsoft Azure services (Azure Government, Microsoft Entra ID, Azure Key Vault, AKS, Azure Functions, Bicep, etc.) while remaining cloud-agnostic where appropriate. Azure hardening defaults in the templates (customer-managed keys, Key Vault Premium, private endpoints, diagnostic settings) are recommended practices that support the KSIs. They are not values mandated by CR26.

### Data Coverage

The bundled CR26 snapshot contains:

- **245 FedRAMP Requirement rules (FRR)** across **17 families**
- **46 Key Security Indicators (KSI)** across **10 families**
- **80 FedRAMP definitions (FRD)**
- **79 control parameter entries (CTL)** across 14 NIST SP 800-53 control families, holding FedRAMP parameter values and guidance

**FRR families (245 rules):**

| Family | Name | Rules |
|---|---|---|
| AFC | Addressing FedRAMP Communication | 16 |
| AGU | Agency Use of FedRAMP Certified Cloud Services | 20 |
| CCM | Collaborative Continuous Monitoring | 19 |
| CDS | Certification Data Sharing | 21 |
| CMU | Cryptographic Module Use | 3 |
| CPO | Certification Package Overview | 5 |
| FRC | FedRAMP Certification | 28 |
| IEC | Incident Evaluation and Communication | 8 |
| IVV | Independent Verification and Validation | 20 |
| MAS | Minimum Assessment Scope | 5 |
| MKT | Marketplace Listing | 12 |
| REC | FedRAMP Recognition of Independent Assessment Services | 16 |
| SCG | Secure Configuration Guide | 9 |
| SCN | Significant Change Notification | 17 |
| SDR | Security Decision Record | 5 |
| VDR | Vulnerability Detection and Response | 18 |
| VER | Vulnerability Evaluation and Reporting | 23 |

**KSI families (46 indicators):**

| Family | Name | KSIs | Indicators |
|---|---|---|---|
| CED | Cybersecurity Education | 1 | RAT |
| CMT | Change Management | 4 | LMC, RMV, RVP, VTD |
| CNA | Cloud Native Architecture | 8 | DFP, EIS, IBP, MAT, OFA, RNT, RVP, ULN |
| IAM | Identity and Access Management | 6 | AAM, APM, ELP, JIT, SNU, SUS |
| INR | Incident Response | 3 | AAR, RIR, RPI |
| MLA | Monitoring, Logging, and Auditing | 5 | ALA, EVC, LET, OSM, RVL |
| PIY | Policy and Inventory | 5 | GIV, RES, RIS, RSD, RVD |
| RPL | Recovery Planning | 4 | ABO, ARP, RRO, TRC |
| SCR | Supply Chain Risk | 2 | MIT, MON |
| SVC | Service Configuration | 8 | ACM, ASM, EIS, PRR, RUD, SIN, VCM, VRI |

IDs are written `KSI-<family>-<code>`, for example `KSI-IAM-APM` (Adopting Passwordless Methods) or `KSI-SVC-ASM` (Automating Secret Management). Rule IDs are `<family>-<subset>-<code>`, for example `VDR-CSO-DET` (Vulnerability Detection) or `CDS-TRC-HMR` (Human and Machine-Readable Certification Data).

**Renamed families:** several pre-2026 families were renamed, split or removed in CR26, and the AFR and TPR KSI families no longer exist. The old-to-new mapping and the confidence of each crosswalk entry are in [docs/CR26-MIGRATION.md](docs/CR26-MIGRATION.md). Legacy IDs still resolve in the lookup tools through the crosswalk.

## Features

- **Rule lookup**: query CR26 requirements by ID, family or keyword, with legacy IDs resolved through the crosswalk
- **Control parameters**: FedRAMP parameter values and guidance for NIST SP 800-53 controls (`get_control_parameters`)
- **Definitions**: look up official FedRAMP term definitions
- **Key Security Indicators**: query KSIs, implementation status and coverage
- **Documentation search**: search and retrieve the FedRAMP/2026 site content
- **Evidence automation guidance**: Azure-native services, queries and artifact specifications for KSIs and FRRs, plus IaC and code templates
- **Code analysis**: pattern-driven analysis of application code, IaC, and CI/CD pipelines, using tree-sitter AST parsing with regex fallback
- **Context-aware filtering**: reduce false positives with the `application_profile` parameter (`cli-tool`, `mcp-server`, `web-app`, `api-service`, `iac-only`, `library`, `batch-job`, `full`)
- **Pipeline scanner and evidence storage**: `fedramp-20x-scan` plus Azure DevOps templates (see [CI/CD and evidence storage](#cicd-and-evidence-storage))
- **Implementation planning**: strategic interview questions, checklists and effort estimates

### Pattern-Based Analysis Architecture

All code analysis runs through one declarative engine (`GenericPatternAnalyzer`) over YAML pattern files in `data/patterns/`.

- **452 patterns** across 22 files and 25 `family:` values
- **Two kinds**: 262 detection patterns (code, IaC and pipeline checks) and 190 compliance patterns (`pattern_type: compliance`, one placeholder per rule for evidence and checklist guidance)
- **Coverage**: all 46 CR26 KSIs and 142 CR26 rule IDs are referenced by at least one pattern
- **Languages**: Python, C#, Java, TypeScript (103 patterns each), Bicep (285), Terraform (292), GitHub Actions (35), Azure Pipelines (29), GitLab CI (23)
- **Detection**: AST-first with tree-sitter, regex fallback where needed

Pattern files are named by CR26 family: `afc`, `ccm`, `cds`, `cmu`, `ivv`, `iec`, `mas`, `scg`, `scn`, `vdr`, the KSI categories `ced`, `cmt`, `cna`, `iam`, `inr`, `mla`, `piy`, `rpl`, `scr`, `svc`, plus `common` and `cross_family`. Per-file counts, the schema and authoring rules are in [data/patterns/README.md](data/patterns/README.md) and [docs/PATTERN_AUTHORING_GUIDE.md](docs/PATTERN_AUTHORING_GUIDE.md).

How it works: patterns load from `data/patterns/`, code is analyzed with AST parsing plus pattern matching, findings carry severity, description, remediation and the CR26 rule or KSI IDs they inform, and results are grouped by family.

**Findings are review signals, not a compliance determination.** A clean scan does not demonstrate that a rule is met, and a finding does not demonstrate that it is not.

**Machine-readable formats:** the CDS rules ask for human and machine-readable certification data (see `CDS-TRC-HMR`). Read the rule text with `get_control` for the exact requirement; do not assume a specific format such as OSCAL.

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (included with Python)
- Python must be in your system PATH

### Setup

```bash
# From your local checkout of this repository
cd FedRAMP20xMCP

# Create virtual environment and install
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .

# If using uv (alternative package manager):
uv pip install -e .
```

**Use an editable install (`pip install -e .`).** The pattern library lives in `data/patterns/` at the repository root and is not packaged inside the wheel, so both the analysis tools and the `fedramp-20x-scan` command need the checkout. The bundled rules snapshot and legacy-ID crosswalk do ship inside the package.

**`mcp` is pinned below 2** (`mcp>=1.2.0,<2`). The 2.x series renamed `FastMCP`, and `server.py` imports `mcp.server.fastmcp`. Do not upgrade `mcp` past 1.x until the server is ported.

**Dependencies** (see `pyproject.toml` for the authoritative list):
- `mcp>=1.2.0,<2` - Model Context Protocol SDK
- `httpx>=0.27.0` - HTTP client for fetching rules and documentation
- `openpyxl>=3.1.0` - Excel generation for export features
- `python-docx>=1.1.0` - Word document generation for KSI specifications
- `pyyaml>=6.0` - pattern library loading
- `tree-sitter>=0.21.0` plus the Python, C#, Java and JavaScript language bindings - AST parsing

**Troubleshooting:**

If you encounter issues, see [Advanced Setup Guide](docs/ADVANCED-SETUP.md#troubleshooting) for detailed troubleshooting steps.

## Security

**Vulnerability Disclosure:** If you discover a security vulnerability, please see our [Security Policy](SECURITY.md) for responsible disclosure procedures (KSI-PIY-RVD).

**Audit Logging:** All MCP server operations are logged to stderr for audit purposes (KSI-MLA-LET).

**Security Features:**
- No authentication required (local development tool)
- No Federal Customer Data handling
- HTTPS-only connections to GitHub
- 1-hour cache TTL reduces external requests
- All dependencies use minimum secure versions

For complete security documentation, see [SECURITY.md](SECURITY.md).

## Usage

### With VS Code and GitHub Copilot

1. **Install the VS Code MCP extension** (if not already installed)

2. **Configure the MCP server** - Choose one of the following scopes:

   **Option A: Workspace-level (Recommended for sharing)**

   Add to `.vscode/mcp.json` in your project:
   ```jsonc
   {
     "servers": {
       "fedramp-20x-mcp": {
         "type": "stdio",
         "command": "python",
         "args": ["-m", "fedramp_20x_mcp"]
       }
     }
   }
   ```

   **If Python is not in PATH**, update the command to use your virtual environment's Python:
   ```jsonc
   {
     "servers": {
       "fedramp-20x-mcp": {
         "type": "stdio",
         "command": "${workspaceFolder}/.venv/Scripts/python.exe",  // Windows
         // "command": "${workspaceFolder}/.venv/bin/python",       // macOS/Linux
         "args": ["-m", "fedramp_20x_mcp"]
       }
     }
   }
   ```

   **Option B: User-level (Global across all projects)**

   Add to VS Code User Settings (`settings.json`):
   ```jsonc
   {
     "github.copilot.chat.mcp.servers": {
       "fedramp-20x-mcp": {
         "type": "stdio",
         "command": "python",
         "args": ["-m", "fedramp_20x_mcp"]
       }
     }
   }
   ```

   **Security Note:** Do NOT use `"alwaysAllow"` in configuration. VS Code will prompt you to grant permissions on first use, which is a security best practice.

3. **Optional: Configure VS Code settings** by copying `.vscode/settings.json.example` to `.vscode/settings.json`

4. **Reload VS Code** to activate the MCP server

5. **Grant permissions** when prompted by VS Code (first use only)

6. **Use with GitHub Copilot Chat**: open Copilot Chat and ask about CR26 requirements; the server exposes 49 tools and 18 prompts.

### With Claude Desktop

Add this server to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "fedramp-20x": {
      "command": "uv",
      "args": [
        "--directory",
        "/absolute/path/to/FedRAMP20xMCP",
        "run",
        "fedramp-20x-mcp"
      ]
    }
  }
}
```

**Note:** Replace `/absolute/path/to/FedRAMP20xMCP` with your actual installation path. Add an `env` block with `FEDRAMP_RULES_OFFLINE` set to `1` for network-free, reproducible runs against the bundled snapshot.

### With MCP Inspector

Test the server using the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector python -m fedramp_20x_mcp
```

### Copilot Execution Policy

This repository uses strict instructions for all AI-assisted coding.

See: [Copilot Instructions](./.github/copilot-instructions.md)

## CI/CD and evidence storage

The same rules data and pattern engine are available to pipelines through the `fedramp-20x-scan` command, with no MCP client needed. Full detail, including every option and the Azure DevOps prerequisites, is in [docs/CI-CD-INTEGRATION.md](docs/CI-CD-INTEGRATION.md).

### fedramp-20x-scan

```bash
pip install -e .
fedramp-20x-scan . --output-dir fedramp-scan --fail-on high --exclude 'tests/*'
```

| Option | Default | Purpose |
|---|---|---|
| `--output-dir` | `fedramp-scan` | Where `findings.json`, `report.md` and `run.json` are written |
| `--fail-on` | `high` | Exit 1 if any issue is at or above `critical`/`high`/`medium`/`low`; `none` never fails |
| `--families` | all | Comma-separated pattern families, for example `IAM,SVC,MLA` |
| `--profile` | none | Application profile that removes inapplicable findings |
| `--exclude` | build and vendor dirs | Extra relative-path globs; repeatable |
| `--patterns-dir` | `data/patterns` | Alternate pattern library (also `FEDRAMP_PATTERNS_DIR`) |

Exit codes: `0` pass, `1` gate tripped, `2` tool error.

| Output | Contents |
|---|---|
| `findings.json` | Findings, summary by severity and requirement, gate result, provenance |
| `report.md` | Human-readable report |
| `run.json` | Provenance: tool version, **rules version and sha256**, pattern count, inputs, CI context, timestamps, sha256 of the two outputs |

`summary.invalid_requirement_ids` in `findings.json` lists any cited ID that is not in the loaded rules release, which is how rules drift shows up in CI.

### Azure DevOps templates

Both live in `.azuredevops/templates/`:

| Template | Does |
|---|---|
| `fedramp-scan-steps.yml` | Installs the scanner, runs it, publishes the output, then enforces the gate as a separate last step, so a failing scan still produces its report |
| `evidence-upload-steps.yml` | Stages a directory, writes `run.json`, `pipeline-run.json` and `sha256-manifest.txt`, uploads without overwrite, verifies by listing back |

Example pipelines: `.azuredevops/fedramp-compliance-pipeline.yml` (scans this repo), `examples/azure-devops/scan-and-store-evidence.yml` (an application repo consuming the templates) and `examples/azure-devops/ksi-evidence-collection.yml` (daily read-only Azure Resource Graph collection for selected KSIs using `collect_ksi_evidence.py`). Outside a pipeline, `examples/azure_evidence_store.py` applies the same storage rules with `DefaultAzureCredential`. A GitHub Actions workflow, `.github/workflows/fedramp-compliance-check.yml`, runs the scanner and publishes an artifact and job summary.

### Evidence storage convention

Evidence is stored in an immutable (WORM) blob container with these rules:

- **Entra ID only.** Uploads use `--auth-mode login`; there is no key, SAS or connection-string path.
- **No overwrite.** `--overwrite` is never passed. A re-run gets a new run folder, and a real name collision fails the step.
- **Verified writes.** The step lists the prefix back and fails if the blob count differs from what was staged.
- **Blocking by default.** A failed upload fails the job, because evidence that silently failed to store is a gap.
- **No evidence from PR builds.** Pull request scans are review feedback only.

Blob layout:

```
<container>/<report>/<yyyy-MM-dd>/<runId>/
  findings.json  report.md       # producer output
  run.json                       # provenance (rules version + sha256)
  pipeline-run.json              # build, commit, branch, requester
  sha256-manifest.txt            # sha256 of every other file
```

Account, container and service-connection names in the template are organization-specific defaults; see the docs before running with `uploadEvidence: true` and override them for your environment.

## Advanced Configuration

- **[CR26 Migration](docs/CR26-MIGRATION.md)** - what changed from the pre-2026 data, crosswalk bases and confidence levels, rules-source order, guardrail tests
- **[CI/CD Integration Guide](docs/CI-CD-INTEGRATION.md)** - scanner options, Azure DevOps templates, evidence storage, keeping the rules current
- **[Advanced Setup Guide](docs/ADVANCED-SETUP.md)** - Multi-server configuration, Azure integration, troubleshooting

## Available Tools

The server provides **49 tools**:

| Category | Count | Tools |
|---|---|---|
| Requirements | 4 | `get_control`, `list_family_controls`, `search_requirements`, `get_control_parameters` |
| Definitions | 3 | `get_definition`, `list_definitions`, `search_definitions` |
| KSI | 6 | `get_ksi`, `list_ksi`, `get_ksi_implementation_summary`, `get_ksi_evidence_automation`, `get_ksi_evidence_queries`, `get_ksi_evidence_artifacts` |
| KSI status and coverage | 4 | `get_ksi_implementation_status`, `get_ksi_family_status`, `get_ksi_coverage_summary`, `get_ksi_coverage_status` |
| FRR | 7 | `analyze_frr_code`, `analyze_all_frrs`, `analyze_frr_family`, `list_frrs_by_family`, `get_frr_metadata`, `get_frr_evidence_automation`, `get_frr_implementation_status` |
| Documentation | 3 | `search_documentation`, `get_documentation_file`, `list_documentation_files` |
| Export | 3 | `export_to_excel`, `export_to_csv`, `generate_ksi_specification` |
| Enhancements and planning | 9 | `compare_with_rev4`, `get_implementation_examples`, `check_requirement_dependencies`, `estimate_implementation_effort`, `get_cloud_native_guidance`, `validate_architecture`, `generate_implementation_questions`, `get_ksi_implementation_matrix`, `generate_implementation_checklist` |
| Evidence collection | 3 | `get_infrastructure_code_for_ksi`, `get_evidence_collection_code`, `get_evidence_automation_architecture` |
| Code analysis | 4 | `analyze_infrastructure_code`, `analyze_application_code`, `analyze_cicd_pipeline`, `validate_fedramp_config` |
| Security | 2 | `check_package_vulnerabilities`, `scan_dependency_file` |
| Code enrichment | 1 | `add_requirement_comments` |

**Legacy IDs.** `get_control` and `get_ksi` accept pre-CR26 IDs. Legacy numbered KSI IDs resolve through the legacy crosswalk to their CR26 successor (for example the old numbered MFA indicator resolves to `KSI-IAM-APM`), and the response notes the resolution. Each crosswalk entry records its derivation `basis` and `confidence`; entries with `related` basis and low confidence have no single CR26 successor and must not be treated as renames. FedRAMP publishes no official crosswalk, so review the low and medium confidence entries in [docs/CR26-MIGRATION.md](docs/CR26-MIGRATION.md) before relying on them.

### Requirements

#### get_control
Get detailed information about a specific CR26 requirement.

**Parameters:**
- `control_id` (string): The requirement identifier (for example `"VDR-CSO-DET"`, `"CDS-TRC-HMR"`, `"KSI-IAM-APM"`, or a legacy ID)

#### list_family_controls
List all requirements within a specific family.

**Parameters:**
- `family` (string): The family code (for example `"VDR"`, `"CDS"`, `"IAM"`)

#### search_requirements
Search for requirements containing specific keywords.

**Parameters:**
- `keywords` (string): Keywords to search for in requirement text

#### get_control_parameters
Get the FedRAMP parameter values and guidance for a NIST SP 800-53 control. Reads the CTL section of the CR26 rules, which lists the organization-defined parameter values FedRAMP sets for a control.

**Parameters:**
- `control_id` (string): NIST control identifier, for example `"AC-6(1)"`, `"ac-6.1"` or `"SC-28"`

**Returns:** Parameter IDs and FedRAMP-defined values for the control, plus any guidance text the data carries. Reports when no parameter data exists for the control.

### Definitions

- `get_definition(term)`: the FedRAMP definition for a term (for example `"vulnerability"`)
- `list_definitions()`: all FedRAMP definitions with their terms
- `search_definitions(keywords)`: search definitions by keyword

### Key Security Indicators

- `get_ksi(ksi_id)`: details for one KSI (for example `"KSI-IAM-APM"`); legacy KSI IDs resolve through the crosswalk
- `list_ksi()`: all KSIs by family with implementation status, code detectability and summary statistics
- `get_ksi_implementation_summary()`: implementation coverage by family, code-detectable versus process-based
- `get_ksi_implementation_status()`: overall KSI implementation status
- `get_ksi_family_status(family)`: status for one KSI family, for example `"IAM"`, `"SVC"`, `"SCR"`
- `get_ksi_coverage_summary()`: how well the pattern library covers the KSIs
- `get_ksi_coverage_status(ksi_id)`: pattern coverage for one KSI, for example `"KSI-MLA-EVC"`

#### get_ksi_evidence_automation
Get evidence automation recommendations for a KSI.

**Parameters:**
- `ksi_id` (string): for example `"KSI-IAM-APM"`, `"KSI-CNA-RNT"`

**Returns:** Guidance for automating evidence collection: Azure services, collection methods and schedules, storage considerations, certification data sharing (CDS family) integration, code and infrastructure templates, and implementation effort. Microsoft Defender for Cloud is recommended, not required, for some KSIs; alternative tools can be used. Retention periods are a decision for your own policy and agency agreements: CR26 defines no numeric log retention period.

#### get_ksi_evidence_queries
Get ready-to-use evidence collection queries for a KSI.

**Parameters:**
- `ksi_id` (string): for example `"KSI-IAM-APM"`

**Returns:** Queries for collecting evidence from Azure: KQL for Log Analytics, Azure Resource Graph, REST and Microsoft Graph calls, with usage guidance.

#### get_ksi_evidence_artifacts
Get specifications for the evidence artifacts to collect for a KSI.

**Parameters:**
- `ksi_id` (string): for example `"KSI-IAM-APM"`

**Returns:** Artifact names and types, collection methods and frequency, file formats and retention considerations.

### FedRAMP Requirement (FRR) analysis

Valid family codes: `AFC AGU CCM CDS CMU CPO FRC IEC IVV MAS MKT REC SCG SCN SDR VDR VER` (see the [family table](#data-coverage)).

#### analyze_frr_code
Analyze code against a specific rule.

**Parameters:**
- `frr_id` (string): for example `"VDR-CSO-DET"`, `"SCG-CSO-RSC"`, `"CDS-CSO-PUB"`
- `code` (string): code to analyze
- `language` (string): `python`, `csharp`, `java`, `typescript`, `bicep`, `terraform`, `github-actions`, `azure-pipelines`, `gitlab-ci`
- `file_path` (string, optional): file path for context

**Returns:** Findings with severity and remediation recommendations.

```python
result = analyze_frr_code(
    frr_id="VDR-CSO-DET",
    code="import subprocess\nsubprocess.run(['trivy', 'image', 'myapp:latest'])",
    language="python",
)
```

#### analyze_all_frrs
Analyze code against every rule that has code patterns.

**Parameters:** `code` (string), `language` (string), `file_path` (string, optional)

**Returns:** Results grouped by family with summary statistics.

#### analyze_frr_family
Analyze code against all rules in one family.

**Parameters:**
- `family` (string): a CR26 FRR family code such as `"VDR"`, `"SCG"`, `"CMU"`, `"SCN"`, `"CDS"`, `"CCM"`, `"MAS"`, `"IEC"`, `"AFC"`, `"IVV"`
- `code` (string), `language` (string), `file_path` (string, optional)

```python
result = analyze_frr_family(family="VDR", code=github_actions_yaml, language="github-actions")
```

#### list_frrs_by_family
List all rules in a family with implementation status and code detectability.

**Parameters:**
- `family` (string): a CR26 FRR family code, for example `"VDR"` or `"CDS"`

#### get_frr_metadata
Get metadata for a rule: the statement, related controls and KSIs, and detection strategy.

**Parameters:**
- `frr_id` (string): for example `"VDR-CSO-DET"`

#### get_frr_evidence_automation
Get evidence automation recommendations for a rule.

**Parameters:**
- `frr_id` (string): for example `"VDR-CSO-DET"`, `"CDS-CSO-PUB"`

**Returns:** Azure services, collection methods and queries (KQL, REST API), storage considerations and evidence artifacts.

#### get_frr_implementation_status
Get an implementation status summary across all rule analyzers, with a family-by-family breakdown. Takes no parameters.

**Vulnerability remediation timeframes.** The FRR tools and the `vulnerability_remediation_timeline` prompt do not use fixed severity buckets. Mitigation and remediation expectations are set by `VDR-TFR-PVR`, which depends on the Certification Class, the Potential Agency Impact N-rating, and whether a vulnerability is internet-reachable and likely exploitable. Read the rule with `get_control("VDR-TFR-PVR")`.

### Documentation

- `search_documentation(keywords)`: search the FedRAMP/2026 site content for keywords
- `get_documentation_file(file_path)`: full content of one file, by relative path such as `"providers/20x/index.md"` (a bare, unique filename also works)
- `list_documentation_files()`: all available documentation files

### Export

#### export_to_excel / export_to_csv
Export CR26 data for offline analysis.

**Parameters:**
- `export_type` (string): `"ksi"` (all KSIs in the loaded rules), `"all_requirements"` (all FRR rules and KSIs across families) or `"definitions"` (all FedRAMP definitions)
- `output_path` (string, optional): custom output path; defaults to the Downloads folder

**Returns:** Path to the generated file.

```python
export_to_excel("ksi")
export_to_csv("all_requirements")
```

#### generate_ksi_specification
Generate a product specification Word document for a KSI to guide engineering planning.

**Parameters:**
- `ksi_id` (string): for example `"KSI-IAM-APM"`
- `evidence_collection_strategy` (string): your high-level evidence collection strategy
- `output_path` (string, optional): custom output path

**Returns:** Path to the generated `.docx`, covering the requirement statement, related NIST controls, Azure-first implementation guidance, evidence collection, a phased plan, team roles, success criteria and risks.

### Enhancements and planning

| Tool | Parameter | Purpose |
|---|---|---|
| `compare_with_rev4` | `requirement_area` (for example "continuous monitoring", "vulnerability management") | Compare 20x with Rev 4/Rev 5 for an area |
| `get_implementation_examples` | `requirement_id` (for example `"KSI-IAM-APM"`, `"VDR-CSO-DET"`) | Practical implementation examples |
| `check_requirement_dependencies` | `requirement_id` | Related or dependent requirements |
| `estimate_implementation_effort` | `requirement_id` | Rough effort estimate |
| `get_cloud_native_guidance` | `technology` (for example "kubernetes", "containers", "serverless", "terraform") | Cloud-native guidance, Azure first |
| `validate_architecture` | `architecture_description` | Validate an architecture description against the rules |
| `generate_implementation_questions` | `requirement_id` (for example `"CCM-QTR-MTG"`, `"KSI-IAM-APM"`) | Strategic questions for product managers and engineers, plus Azure-specific considerations |
| `get_ksi_implementation_matrix` | `ksi_family` (for example `"IAM"`) | All KSIs in a family with Azure services, effort and priority |
| `generate_implementation_checklist` | `ksi_id` | Step-by-step implementation checklist for one KSI |

### Evidence collection

#### get_infrastructure_code_for_ksi
Generate IaC templates for evidence-collection infrastructure.

**Parameters:**
- `ksi_id` (string): for example `"KSI-IAM-APM"`, `"KSI-MLA-OSM"`
- `infrastructure_type` (string, default `"bicep"`): `"bicep"` or `"terraform"`

The evidence storage templates are built on a WORM baseline: Entra-only access, private networking, customer-managed keys and an immutability policy. Retention length and network design are your own decisions.

#### get_evidence_collection_code
Generate code for collecting and storing KSI evidence programmatically.

**Parameters:**
- `ksi_id` (string): for example `"KSI-IAM-APM"`
- `language` (string, default `"python"`): `python`, `csharp`, `powershell`, `java`, `typescript` (also `javascript`)

#### get_evidence_automation_architecture
Get architecture guidance for automated evidence collection.

**Parameters:**
- `ksi_category` (string, default `"all"`): `"all"` or a KSI category code such as `"IAM"` or `"MLA"`

### Code analysis

#### analyze_infrastructure_code
Analyze Bicep or Terraform for compliance issues.

**Parameters:**
- `code` (string): the IaC content
- `file_type` (string): `"bicep"` or `"terraform"`
- `file_path` (string, optional): path, for reporting
- `context` (string, optional): extra context such as a PR description
- `application_profile` (string, optional): `cli-tool`, `mcp-server`, `web-app`, `api-service`, `iac-only`, `library`, `batch-job` or `full`; default is no filtering

**Returns:** Findings with rule or KSI IDs, severity and recommendations, a summary, a PR-comment markdown block, and, when a profile is set, the profile metadata and the count of findings it suppressed.

#### analyze_application_code
Analyze application code for security issues mapped to KSIs and rules.

**Parameters:**
- `code` (string)
- `language` (string): `python`, `csharp`, `java`, `typescript` or `javascript`
- `file_path` (string, optional)
- `dependencies` (array of strings, optional): for example `["flask==2.3.0", "requests==2.31.0"]`
- `application_profile` (string, optional): same profiles as above

**Returns:** Findings, summary and a PR-comment block.

#### analyze_cicd_pipeline
Analyze a CI/CD pipeline definition.

**Parameters:**
- `code` (string): pipeline YAML or JSON
- `pipeline_type` (string): `github-actions`, `azure-pipelines`, `gitlab-ci` or `generic`
- `file_path` (string, optional)
- `application_profile` (string, optional): same profiles as above

**Returns:** Findings for change management (the CMT KSIs), vulnerability scanning and evidence handling, with a summary and PR-comment block.

#### validate_fedramp_config
Check IaC against Azure hardening practices before deploying.

**Parameters:**
- `code` (string), `file_type` (string: `"bicep"` or `"terraform"`), `strict_mode` (bool, default `True`)

**Returns:** A result object with `passed` and per-check findings. Public network access and missing diagnostic settings are high severity. Log Analytics retention, customer-managed keys and Key Vault SKU checks are advisory recommended practices; CR26 sets no numeric log retention. `passed=true` means none of the checks flagged the code; it is not an assessment.

### Security

- `check_package_vulnerabilities(package_name, ecosystem, version=None, github_token=None)`: CVE lookup for one package; `ecosystem` is `nuget`, `npm`, `pypi` or `maven`
- `scan_dependency_file(file_content, file_type, github_token=None)`: scan a manifest; `file_type` is `csproj`, `packages.config`, `package.json`, `requirements.txt` or `pom.xml`

### Code enrichment

#### add_requirement_comments
Add requirement-reference comments to code.

**Parameters:**
- `code` (string)
- `ksi_ids` (string, optional): comma-separated, for example `"KSI-IAM-APM,KSI-MLA-OSM"`
- `frr_ids` (string, optional): comma-separated, for example `"VDR-CSO-DET,CDS-CSO-PUB"`
- `language` (string, default `"bicep"`): `bicep`, `terraform`, `python`, `csharp`, `java`, `typescript` or `powershell`

## Available Prompts

The server provides **18 prompts**, all written against CR26. Prompts guide a workflow; they are not a substitute for reading the rule text with `get_control`.

**Planning and assessment:** `initial_assessment_roadmap`, `gap_analysis`, `vendor_evaluation`, `migration_from_rev5`, `significant_change_assessment` (SCN family)

**Implementation and automation:** `ksi_implementation_priorities`, `azure_ksi_automation`, `api_design_guide` (CDS family certification data sharing), `authorization_boundary_review` (MAS family)

**Monitoring and compliance:** `continuous_monitoring_setup`, `quarterly_review_checklist` (CCM-QTR-MTG and related rules), `vulnerability_remediation_timeline` (VDR-TFR-PVR)

**Audit and documentation:** `audit_preparation`, `ato_package_checklist`, `documentation_generator`

**FRR compliance and code review:** `frr_code_review`, `frr_family_assessment`, `frr_implementation_roadmap`

## Example Workflows

Calls below use the tool names above; output depends on the loaded rules release and is not reproduced here.

**Look up and review a rule**

```python
get_control("VDR-CSO-DET")                  # statement and metadata
get_frr_metadata("VDR-CSO-DET")             # related controls and KSIs
get_control("VDR-TFR-PVR")                  # mitigation and remediation expectations
analyze_frr_family("VDR", code=pipeline_yaml, language="azure-pipelines")
```

**Plan evidence for a KSI**

```python
get_ksi("KSI-IAM-APM")
get_ksi_evidence_automation("KSI-IAM-APM")
get_ksi_evidence_queries("KSI-IAM-APM")
get_ksi_evidence_artifacts("KSI-IAM-APM")
get_control_parameters("AC-6(1)")           # FedRAMP parameter values for a related control
```

**Pre-deployment review**

```python
analyze_infrastructure_code(code=bicep_template, file_type="bicep", file_path="main.bicep")
analyze_cicd_pipeline(code=pipeline_yaml, pipeline_type="azure-pipelines")
get_ksi_coverage_summary()                  # what the pattern library does and does not cover
```

For repeatable runs in a pipeline, use `fedramp-20x-scan` and store the output (see [CI/CD and evidence storage](#cicd-and-evidence-storage)).

## Data Source

Rules: https://github.com/FedRAMP/rules (`fedramp-consolidated-rules.json`). Documentation: https://github.com/FedRAMP/2026 (`content/`). The pre-2026 `FedRAMP/docs` repository was renamed `FedRAMP/docs-legacy` and no longer carries the rules JSON.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup and testing
- Security scanning requirements
- Dependency management guidelines
- Pull request process
- Project structure and architecture
- Complete test documentation

When citing rule or KSI IDs in patterns, prompts, templates or docs, they must exist in the bundled CR26 snapshot. `tests/test_rules_alignment.py` enforces this, and `scripts/migrate_rule_ids.py` finds stale IDs. To move the snapshot to a new FedRAMP release, follow "Keeping the rules current" in [docs/CI-CD-INTEGRATION.md](docs/CI-CD-INTEGRATION.md).

## License

MIT License - See [LICENSE](LICENSE) file for details.

The FedRAMP data is provided by the U.S. General Services Administration as public domain content.

## References

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [FedRAMP Official Website](https://www.fedramp.gov/)
- [FedRAMP Rules Repository (CR26)](https://github.com/FedRAMP/rules)
- [FedRAMP 2026 Site Content](https://github.com/FedRAMP/2026)
