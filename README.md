# FedRAMP 20x MCP Server

[![Tests](https://github.com/KevinRabun/FedRAMP20xMCP/actions/workflows/test.yml/badge.svg)](https://github.com/KevinRabun/FedRAMP20xMCP/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/fedramp-20x-mcp.svg)](https://pypi.org/project/fedramp-20x-mcp/)
[![Python Versions](https://img.shields.io/pypi/pyversions/fedramp-20x-mcp.svg)](https://pypi.org/project/fedramp-20x-mcp/)

<!-- mcp-name: io.github.KevinRabun/FedRAMP20xMCP -->

An MCP (Model Context Protocol) server that provides access to FedRAMP 20x security requirements and controls with **Azure-first guidance**.

## Overview

This server loads FedRAMP 20x data from the official [FedRAMP documentation repository](https://github.com/FedRAMP/docs) and provides tools for querying requirements by control, family, or keyword.

**Data Sources:**
- **Requirements Data:** JSON files from [github.com/FedRAMP/docs/tree/main/data](https://github.com/FedRAMP/docs/tree/main/data)
- **Documentation:** Markdown files from [github.com/FedRAMP/docs/tree/main/docs](https://github.com/FedRAMP/docs/tree/main/docs)

**Azure Focus:** All implementation examples, architecture patterns, and vendor recommendations prioritize Microsoft Azure services (Azure Government, Microsoft Entra ID, Azure Key Vault, AKS, Azure Functions, Bicep, etc.) while remaining cloud-agnostic where appropriate.

### Complete Data Coverage

The server provides access to **271 requirements** (199 FRRs + 72 KSIs) plus **50 definitions** (FRDs) across FedRAMP 20x documents:

**FedRAMP Requirements (FRR) - 199 requirements across 10 families:**
- **ADS** - Authorization Data Sharing (20 requirements)
- **CCM** - Collaborative Continuous Monitoring (25 requirements)
- **FSI** - FedRAMP Security Inbox (16 requirements)
- **ICP** - Incident Communications Procedures (9 requirements)
- **MAS** - Minimum Assessment Scope (12 requirements)
- **PVA** - Persistent Validation and Assessment (22 requirements)
- **RSC** - Recommended Secure Configuration (10 requirements)
- **SCN** - Significant Change Notifications (22 requirements)
- **UCM** - Using Cryptographic Modules (4 requirements)
- **VDR** - Vulnerability Detection and Response (57 requirements)
- **KSI** - Key Security Indicators (2 requirements)

**Key Security Indicators (KSI) - 72 indicators across 11 families:**
- **AFR** - Architecture, Features, and Resources (11 indicators)
- **CED** - Continuous Evidence Delivery (4 indicators)
- **CMT** - Continuous Monitoring and Testing (5 indicators)
- **CNA** - Cloud Native Architecture (8 indicators)
- **IAM** - Identity and Access Management (7 indicators)
- **INR** - Incident and Near-Miss Reporting (3 indicators)
- **MLA** - Monitoring, Logging, and Alerting (8 indicators)
- **PIY** - Privacy and Transparency (8 indicators)
- **RPL** - Resilience and Recovery Planning (4 indicators)
- **SVC** - Secure Coding and Vulnerability Management (10 indicators)
- **TPR** - Third-Party Risk Management (4 indicators)

**FedRAMP Definitions (FRD) - 50 official term definitions**

## Features

- **🎯 Automated Evidence Collection (NEW)**: Complete automation guidance for all 65 active KSIs with Azure-native services, ready-to-use queries, and artifact specifications
- **Query by Control**: Get detailed information about specific FedRAMP requirements
- **Query by Family**: List all requirements within a family
- **Keyword Search**: Search across all requirements using keywords
- **FedRAMP Definitions**: Look up official FedRAMP term definitions
- **Key Security Indicators**: Access and query FedRAMP Key Security Indicators (KSI) with implementation status
- **Documentation Search**: Search and retrieve official FedRAMP documentation markdown files
- **Dynamic Content**: Automatically discovers and loads all markdown documentation files
- **Implementation Planning**: Generate strategic interview questions to help product managers and engineers think through FedRAMP 20x implementation considerations
- **AST-Powered Code Analysis**: Advanced Abstract Syntax Tree parsing using tree-sitter for accurate, context-aware security analysis across Python, C#, Java, TypeScript/JavaScript, Bicep, and Terraform
- **Semantic Analysis**: Deep code understanding with symbol resolution, control flow analysis, and interprocedural analysis capabilities
- **🚀 Hybrid Analysis (NEW)**: Combines fast pattern-based detection (120 YAML patterns) with deep traditional analyzers (72 KSIs + 199 FRRs) for comprehensive, performant compliance checking
- **Pattern Engine**: Declarative YAML-driven detection across 14 languages with intelligent deduplication and coverage metadata

### Hybrid Analysis Architecture

The server uses a **hybrid analysis approach** combining two complementary analysis methods:

1. **Pattern Engine** (Fast, Broad Coverage)
   - **120 YAML-defined patterns** across 11 requirement families
   - **14 languages**: Python, C#, Java, TypeScript, JavaScript, Bicep, Terraform, GitHub Actions, Azure Pipelines, GitLab CI, YAML, JSON, Dockerfile, GitHub
   - AST-first detection with regex fallback for accuracy
   - Declarative, easy-to-maintain pattern definitions
   - Coverage: ADS, CCM, CNA, COMMON, IAM, MLA, RSC, SCN, SVC, UCM, VDR

2. **Traditional Analyzers** (Deep, Specialized)
   - **72 KSI analyzers** for Key Security Indicators
   - **199 FRR analyzers** for specific FedRAMP requirements
   - Context-aware, interprocedural analysis
   - Complex security logic and data flow tracking

3. **Intelligent Deduplication**
   - Merges findings from both engines
   - Removes duplicates (same requirement + similar description)
   - Prefers pattern findings when duplicate (faster, clearer source)
   - Preserves unique insights from both approaches

**Performance**: Pattern engine provides comparable speed to traditional analyzers with broader language coverage. First-run initialization overhead is amortized across multiple analyses.

**Important Clarification: OSCAL Format**
FedRAMP 20x requires **machine-readable** formats (JSON, XML, or structured data) for Authorization Data Sharing. **OSCAL is NOT mentioned in FedRAMP 20x requirements** - it's a NIST standard that can be used as one potential implementation approach. The actual requirement is simply "machine-readable" - you can use custom JSON/XML or OSCAL based on your implementation needs.

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (included with Python)
- Python must be in your system PATH

### Setup

```bash
# Clone the repository
git clone https://github.com/KevinRabun/FedRAMP20xMCP.git
cd FedRAMP20xMCP

# Create virtual environment and install
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .

# If using uv (alternative package manager):
uv pip install -e .
```

**Dependencies:**
- `mcp>=1.2.0` - Model Context Protocol SDK
- `httpx>=0.27.0` - HTTP client for fetching FedRAMP data
- `openpyxl>=3.1.0` - Excel file generation for export features
- `python-docx>=1.1.0` - Word document generation for KSI specifications
- `tree-sitter>=0.21.0` - AST parsing library for code analysis
- `tree-sitter-python>=0.21.0` - Python language bindings for tree-sitter
- `tree-sitter-c-sharp>=0.21.0` - C# language bindings for tree-sitter
- `tree-sitter-java>=0.21.0` - Java language bindings for tree-sitter
- `tree-sitter-javascript>=0.21.0` - JavaScript/TypeScript language bindings

**Troubleshooting:** 

If you encounter issues, see [Advanced Setup Guide](docs/ADVANCED-SETUP.md#troubleshooting) for detailed troubleshooting steps.

## Security

**Vulnerability Disclosure:** If you discover a security vulnerability, please see our [Security Policy](SECURITY.md) for responsible disclosure procedures (KSI-PIY-03).

**Audit Logging:** All MCP server operations are logged to stderr for audit purposes (KSI-MLA-05).

**Security Features:**
- ✅ No authentication required (local development tool)
- ✅ No Federal Customer Data handling
- ✅ HTTPS-only connections to GitHub
- ✅ 1-hour cache TTL reduces external requests
- ✅ All dependencies use minimum secure versions

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

6. **Use with GitHub Copilot Chat**:
   - Open Copilot Chat
   - Ask questions about FedRAMP 20x requirements
   - Use `@workspace` to query specific controls or families
   - Access all 48 tools and 15 comprehensive prompts

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

**Note:** Replace `/absolute/path/to/FedRAMP20xMCP` with your actual installation path.

### With MCP Inspector

Test the server using the MCP Inspector:

```bash
npx @modelcontextprotocol/inspector python -m fedramp_20x_mcp
```

## Advanced Configuration

For CI/CD integration, multi-server setup with Azure and GitHub, or detailed troubleshooting, see:

- **[CI/CD Integration Guide](docs/CI-CD-INTEGRATION.md)** - Use analyzers in GitHub Actions, Azure DevOps, and other pipelines
- **[Advanced Setup Guide](docs/ADVANCED-SETUP.md)** - Multi-server configuration, Azure integration, troubleshooting

## Available Tools

The server provides **48 tools** organized into the following categories:

**Core Tools (11):** Query requirements, definitions, KSIs, and KSI evidence automation
**FRR Analysis Tools (7):** Analyze code against FedRAMP Requirements (FRR) with comprehensive compliance checking across all 199 requirements
**Documentation Tools (3):** Search and retrieve FedRAMP documentation
**Enhancement Tools (7):** Implementation examples, dependencies, effort estimation, architecture validation
**Export Tools (3):** Excel/CSV export and KSI specification generation
**Planning Tools (1):** Generate strategic implementation questions
**Evidence Collection Automation Tools (3):** Infrastructure code, collection code, architecture guidance
**Implementation Mapping Tools (2):** KSI family matrices and step-by-step implementation checklists
**Code Analysis Tools (3):** AST-powered FedRAMP compliance scanning using tree-sitter for accurate, semantic analysis of IaC, application code, and CI/CD pipelines across 6 languages (Python, C#, Java, TypeScript/JavaScript, Bicep, Terraform)
**Security Tools (2):** CVE vulnerability checking for packages and dependency files
**Audit Tools (2):** KSI coverage summary and status checking
**KSI Status Tools (1):** Implementation status tracking across all KSI families

### get_control
Get detailed information about a specific FedRAMP requirement or control.

**Parameters:**
- `control_id` (string): The requirement identifier (e.g., "FRD-ALL-01", "KSI-AFR-01")

### list_family_controls
List all requirements within a specific family.

**Parameters:**
- `family` (string): The family identifier (e.g., "FRD", "KSI", "MAS")

### search_requirements
Search for requirements containing specific keywords.

**Parameters:**
- `keywords` (string): Keywords to search for in requirement text

### get_definition
Get the FedRAMP definition for a specific term.

**Parameters:**
- `term` (string): The term to look up (e.g., "vulnerability", "cloud service offering")

### list_definitions
List all FedRAMP definitions with their terms.

**Returns:** Complete list of all FedRAMP definition terms

### search_definitions
Search FedRAMP definitions by keywords.

**Parameters:**
- `keywords` (string): Keywords to search for in definitions

### get_ksi
Get detailed information about a specific Key Security Indicator.

**Parameters:**
- `ksi_id` (string): The KSI identifier (e.g., "KSI-AFR-01")

### list_ksi
List all Key Security Indicators.

**Returns:** Complete list of all Key Security Indicators with their names

### get_ksi_evidence_automation
Get comprehensive evidence automation recommendations for a specific KSI. **All 65 active KSIs** include complete automated evidence collection guidance.

**Parameters:**
- `ksi_id` (string): The KSI identifier (e.g., "KSI-IAM-01", "KSI-CNA-01")

**Returns:** Comprehensive guidance for automating evidence collection including:
- **Azure Services**: 5 Azure services per KSI (Log Analytics, Resource Graph, Azure Policy, Azure Monitor, etc.) with specific configuration guidance
  - *Note: Microsoft Defender for Cloud is recommended (not mandatory) for ~8-10 KSIs to streamline vulnerability scanning, security posture management, and compliance monitoring. Alternative tools (Qualys, Tenable, Trivy) can be used.*
- **Collection Methods**: 4-5 automated collection approaches (continuous monitoring, scheduled assessments, event-driven triggers, log aggregation)
- **Storage Requirements**: Retention policies (30-90 days operational, 1-7 years compliance), encryption standards, access controls
- **FRR-ADS Integration**: Machine-readable API endpoints for Authorization Data Sharing compliance
- **Implementation Details**: Effort estimates, prerequisites, cost considerations, responsible parties (Security, DevOps, Compliance, Engineering)
- **Code Examples**: Infrastructure-as-code templates (Bicep, Terraform) and automation scripts

**Coverage:** 100% of active KSIs across all 11 families:
- IAM (7): MFA, Privilege Management, Session Controls, Credential Lifecycle, User Termination, JIT Access, Shared Accounts
- CNA (8): Network Segmentation, TLS Configuration, Connection Logging, Azure Monitor, Key Vault, Secrets Detection, Container Registry, GitHub Security
- MLA (5): Log Aggregation, Retention, Tamper Detection, Search Capabilities, Alerting
- INR (3): Incident Response Plans, Incident Logging, After Action Reports
- AFR (11): Asset Discovery, SBOM, Penetration Testing, Dev/Prod Separation, GitHub Actions Security, Container Scanning, and more
- SVC (9): FIPS 140-3 Cryptography, API Authentication, Rate Limiting, Input Validation, Error Handling, Secrets Management, DoS Protection, Secrets Rotation, Dependency Management
- CMT (4): Continuous Monitoring, Health Checks, Configuration Baselines, Drift Detection
- CED (4): Authorization Documents, System Boundary, SSP Updates, Continuous Delivery
- TPR (2): Supply Chain Risk Assessment, Supply Chain Risk Monitoring
- RPL (4): Recovery Objectives, Recovery Plans, System Backups, Recovery Testing
- PIY (8): Automated Inventory, Data Minimization, Vulnerability Disclosure, Secure By Design, Security Evaluations, Investment Effectiveness, Supply Chain Risk, Executive Support

**Example:** `get_ksi_evidence_automation("KSI-IAM-01")` returns automated evidence collection for phishing-resistant MFA including Entra ID Conditional Access policies, sign-in logs via Log Analytics, MFA method registration queries, and compliance reporting dashboards.

### get_ksi_evidence_queries
Get ready-to-use evidence collection queries for a specific KSI.

**Parameters:**
- `ksi_id` (string): The KSI identifier (e.g., "KSI-IAM-01", "KSI-CNA-01")

**Returns:** Production-ready queries for collecting evidence from Azure (5 queries per KSI):
- **KQL Queries**: Log Analytics/Azure Monitor Kusto queries for log analysis and metrics
- **Azure Resource Graph**: Infrastructure and configuration state queries
- **REST API**: Azure Resource Manager API calls for programmatic data retrieval
- **Azure CLI**: Command-line scripts for evidence extraction
- **PowerShell**: Azure PowerShell cmdlets for automated collection

**Example:** `get_ksi_evidence_queries("KSI-CNA-01")` returns Resource Graph queries for NSG rules, Azure Firewall policies, virtual network configurations, subnet segmentation analysis, and network topology validation.

### get_ksi_evidence_artifacts
Get specifications for evidence artifacts to collect for a specific KSI.

**Parameters:**
- `ksi_id` (string): The KSI identifier (e.g., "KSI-IAM-01", "KSI-CNA-01")

**Returns:** Detailed artifact specifications (5 artifacts per KSI):
- **Artifact Names**: Specific evidence files/reports required (e.g., "MFA_Sign_In_Logs.csv", "NSG_Rule_Export.json")
- **Collection Methods**: How to gather each artifact (automated export, API retrieval, dashboard screenshot, compliance report)
- **File Formats**: CSV, JSON, PDF, PNG (dashboard screenshots), XLSX (compliance matrices)
- **Update Frequencies**: Daily, weekly, monthly, or quarterly collection schedules based on requirement criticality
- **Retention Requirements**: 30-90 days for operational data, 1-7 years for compliance evidence
- **Storage Recommendations**: Azure Blob Storage with encryption, access logging, immutability policies

**Example:** `get_ksi_evidence_artifacts("KSI-IAM-01")` returns sign-in logs (CSV, daily, 90 days), Conditional Access policy exports (JSON, weekly, 1 year), MFA method registration reports (XLSX, monthly, 3 years), authentication dashboard screenshots (PNG, quarterly, 1 year), and MFA compliance matrices (PDF, monthly, 7 years).

### analyze_frr_code
Analyze code against a specific FedRAMP Requirement (FRR) for compliance issues.

**Parameters:**
- `frr_id` (string): FRR identifier (e.g., "FRR-VDR-01", "FRR-RSC-01", "FRR-ADS-01")
- `code` (string): Code to analyze
- `language` (string): Language/platform - `"python"`, `"csharp"`, `"java"`, `"typescript"`, `"bicep"`, `"terraform"`, `"github-actions"`, `"azure-pipelines"`, `"gitlab-ci"`
- `file_path` (string, optional): File path for context

**Returns:** Analysis results with findings, severity levels, and remediation recommendations

**Supported FRR Families:**
- **VDR** - Vulnerability Detection and Response (59 requirements): Vulnerability scanning, patch management, remediation timeframes, deviation tracking, KEV vulnerability handling
- **RSC** - Recommended Secure Configuration (10 requirements): Security baselines, configuration management, hardening standards
- **UCM** - Using Cryptographic Modules (4 requirements): FIPS 140-3 compliance, key management, encryption standards
- **SCN** - Significant Change Notifications (26 requirements): Change management, notification procedures, impact assessment
- **ADS** - Authorization Data Sharing (22 requirements): Machine-readable evidence APIs, data formats, authentication
- **CCM** - Collaborative Continuous Monitoring (25 requirements): Monitoring procedures, quarterly reviews, assessment coordination
- **MAS** - Minimum Assessment Scope (12 requirements): Authorization boundaries, system inventory, assessment requirements
- **ICP** - Incident Communications Procedures (9 requirements): Incident notification, communication protocols, escalation procedures
- **FSI** - FedRAMP Security Inbox (16 requirements): Security inbox management, vulnerability disclosure, response procedures
- **PVA** - Persistent Validation and Assessment (22 requirements): Continuous validation, assessment procedures, testing requirements

**What It Checks:**
Analyzes code for FRR-specific compliance issues using AST-powered semantic analysis:
- **Application Code**: Security controls, API implementations, cryptographic usage, logging, error handling
- **Infrastructure as Code**: Resource configurations, security settings, compliance controls, network policies
- **CI/CD Pipelines**: Security gates, testing requirements, deployment procedures, evidence collection

**Example Usage:**
```python
# Check Python code for FRR-VDR-01 compliance (vulnerability scanning)
result = analyze_frr_code(
    frr_id="FRR-VDR-01",
    code="""import subprocess
    subprocess.run(['trivy', 'image', 'myapp:latest'])
    """,
    language="python"
)
# ✅ Detects Trivy vulnerability scanning implementation

# Check Bicep for FRR-ADS-01 compliance (machine-readable evidence)
result = analyze_frr_code(
    frr_id="FRR-ADS-01",
    code="""resource apiManagement 'Microsoft.ApiManagement/service@2023-05-01-preview' = {
      name: 'evidence-api'
      properties: {
        publisherEmail: 'admin@contoso.com'
        publisherName: 'Contoso'
      }
    }""",
    language="bicep"
)
# ✅ Validates API Management for authorization data sharing
```

### analyze_all_frrs
Analyze code against all 199 FedRAMP requirements for comprehensive compliance checking.

**Parameters:**
- `code` (string): Code to analyze
- `language` (string): Language/platform (python, csharp, java, typescript, bicep, terraform, github-actions, azure-pipelines, gitlab-ci)
- `file_path` (string, optional): File path for context

**Returns:** Complete analysis results grouped by FRR family with summary statistics

**Use Cases:**
- **Pre-deployment validation**: Check all code before production deployment
- **Comprehensive audits**: Full compliance scan for certification preparation
- **Security reviews**: Identify all FedRAMP compliance gaps
- **CI/CD integration**: Automated compliance checking in pipelines

**Output Structure:**
- Findings organized by family (VDR, RSC, UCM, SCN, ADS, CCM, etc.)
- Summary statistics: total findings, critical/high/medium/low counts
- Compliant requirements listed
- Actionable remediation guidance

**Example Usage:**
```python
# Comprehensive FRR analysis of Bicep infrastructure code
result = analyze_all_frrs(
    code=bicep_template,
    language="bicep",
    file_path="main.bicep"
)
# Returns findings across all 10 FRR families
```

**Performance:** Analyzes all 199 FRRs in 2-5 seconds using parallel processing and AST caching.

### analyze_frr_family
Analyze code against all requirements in a specific FRR family.

**Parameters:**
- `family` (string): Family code - `"VDR"`, `"RSC"`, `"UCM"`, `"SCN"`, `"ADS"`, `"CCM"`, `"MAS"`, `"ICP"`, `"FSI"`, `"PVA"`
- `code` (string): Code to analyze
- `language` (string): Language/platform
- `file_path` (string, optional): File path for context

**Returns:** Analysis results for all requirements in the specified family

**Common Use Cases:**

**VDR Family (59 requirements):**
```python
# Check CI/CD pipeline for vulnerability management compliance
result = analyze_frr_family(
    family="VDR",
    code=github_actions_yaml,
    language="github-actions"
)
# Checks: Vulnerability scanning, patch procedures, remediation timeframes,
# deviation management, KEV tracking, monthly reporting
```

**ADS Family (22 requirements):**
```python
# Validate authorization data sharing API implementation
result = analyze_frr_family(
    family="ADS",
    code=python_api_code,
    language="python"
)
# Checks: Machine-readable formats, API authentication, data accuracy,
# real-time updates, audit logging, access controls
```

**RSC Family (10 requirements):**
```python
# Check infrastructure for secure configuration compliance
result = analyze_frr_family(
    family="RSC",
    code=terraform_code,
    language="terraform"
)
# Checks: Security baselines, configuration standards, hardening,
# drift detection, compliance validation
```

### list_frrs_by_family
List all FRR requirements in a specific family with implementation status.

**Parameters:**
- `family` (string): Family code (VDR, RSC, UCM, SCN, ADS, CCM, MAS, ICP, FSI, PVA)

**Returns:** List of all FRRs in the family with:
- FRR ID and name
- Implementation status (Implemented/Not Implemented)
- Code detectability (Code-Detectable/Process-Based)
- NIST 800-53 control mappings
- Impact levels (Low/Moderate/High)

**Example Usage:**
```python
# List all vulnerability detection requirements
result = list_frrs_by_family("VDR")
# Returns 59 VDR requirements with status indicators

# List all authorization data sharing requirements
result = list_frrs_by_family("ADS")
# Returns 22 ADS requirements
```

**Use Cases:**
- Discover available FRR requirements in a family
- Check implementation coverage
- Plan FRR implementation priorities
- Understand code vs. process requirements

### get_frr_metadata
Get detailed metadata for a specific FRR including NIST controls, related KSIs, and detection strategy.

**Parameters:**
- `frr_id` (string): FRR identifier (e.g., "FRR-VDR-01")

**Returns:** Comprehensive FRR metadata including:
- **FRR Details**: ID, name, family, requirement statement
- **NIST 800-53 Controls**: Related security controls with full titles
- **Related KSIs**: Key Security Indicators that align with this FRR
- **Impact Levels**: Applicable authorization levels (Low/Moderate/High)
- **Detection Strategy**: How the requirement can be validated (code analysis, configuration checks, process review)
- **Implementation Guidance**: Azure-specific recommendations and best practices

**Example Usage:**
```python
# Get metadata for FRR-VDR-01 (vulnerability scanning)
result = get_frr_metadata("FRR-VDR-01")
# Returns: NIST controls (RA-5, SI-2), related KSIs (KSI-AFR-04),
# detection strategy (CI/CD pipeline analysis, tool configuration checks)

# Get metadata for FRR-ADS-01 (machine-readable evidence)
result = get_frr_metadata("FRR-ADS-01")
# Returns: NIST controls (CA-2, CA-5, CA-7), related KSIs (KSI-CED-01),
# detection strategy (API endpoint analysis, data format validation)
```

**Use Cases:**
- Understand FRR requirements before implementation
- Map FRRs to NIST controls for compliance documentation
- Identify related KSIs for integrated compliance approach
- Get Azure-specific implementation guidance

### get_frr_evidence_automation
Get evidence automation recommendations for a specific FRR.

**Parameters:**
- `frr_id` (string): FRR identifier (e.g., "FRR-VDR-01", "FRR-ADS-01")

**Returns:** Comprehensive evidence automation guidance including:
- **Evidence Type**: Configuration-based, log-based, or API-based evidence
- **Automation Feasibility**: High/Medium/Low automation potential
- **Azure Services**: 3-5 recommended services for evidence collection
- **Collection Methods**: Automated approaches (Azure Monitor, Resource Graph, Policy, APIs)
- **Storage Requirements**: Retention policies, encryption, access controls
- **Evidence Artifacts**: Specific files/reports to collect
- **Implementation Steps**: Step-by-step automation setup
- **Code Examples**: Infrastructure templates and scripts
- **Update Frequency**: Daily/weekly/monthly/quarterly collection schedules
- **Responsible Party**: Team ownership (Security, DevOps, Compliance)

**Example Usage:**
```python
# Get evidence automation for FRR-VDR-01 (vulnerability scanning)
result = get_frr_evidence_automation("FRR-VDR-01")
# Returns: Azure Defender for Cloud configuration, KQL queries for
# vulnerability data, scan result export automation, compliance dashboards

# Get evidence automation for FRR-ADS-01 (data sharing API)
result = get_frr_evidence_automation("FRR-ADS-01")
# Returns: API Management setup, authentication configuration,
# audit logging, API call metrics, response format validation
```

**Supported FRR Families:**
- **VDR**: Vulnerability scan results, patch status, remediation tracking, deviation approvals
- **ADS**: API call logs, data format compliance, authentication records, access audits
- **CCM**: Monitoring metrics, quarterly review artifacts, assessment coordination logs
- **RSC**: Configuration baselines, drift detection reports, compliance scan results
- **All others**: Family-specific evidence recommendations

### get_frr_implementation_status
Get implementation status summary across all FRR analyzers.

**Parameters:** None

**Returns:** Implementation status summary including:
- **Total FRRs**: 199 requirements across 10 families
- **Implementation by Family**: VDR (59), RSC (10), UCM (4), SCN (26), ADS (22), CCM (25), MAS (12), ICP (9), FSI (16), PVA (22)
- **Status Breakdown**: Implemented vs. Not Implemented counts
- **Code-Detectable**: Requirements that can be validated through code analysis
- **Process-Based**: Requirements requiring manual review or documentation
- **Coverage Statistics**: Implementation completion percentage by family

**Example Usage:**
```python
# Get overall FRR implementation status
result = get_frr_implementation_status()
# Returns: Family-by-family breakdown with implementation rates
```

**Use Cases:**
- Track FRR analyzer development progress
- Identify gaps in FRR coverage
- Plan FRR implementation priorities
- Report on compliance automation capabilities

**Output Example:**
```
FRR Implementation Status:
- VDR Family: 59/59 implemented (100%)
- RSC Family: 10/10 implemented (100%)
- ADS Family: 22/22 implemented (100%)
- Total: 199/199 implemented (100%)

Code-Detectable: 145 FRRs (73%)
Process-Based: 54 FRRs (27%)
```

### compare_with_rev4
Compare FedRAMP 20x with Rev 4/Rev 5 requirements for specific areas.

**Parameters:**
- `requirement_area` (string): Area to compare (e.g., "continuous monitoring", "vulnerability management", "authorization boundary", "evidence collection", "change management", "incident response")

### get_implementation_examples
Get practical implementation examples for specific requirements.

**Parameters:**
- `requirement_id` (string): The requirement identifier (e.g., "KSI-IAM-01", "FRR-VDR-01")

### check_requirement_dependencies
Check dependencies between FedRAMP 20x requirements.

**Parameters:**
- `requirement_id` (string): The requirement identifier to check dependencies for

### estimate_implementation_effort
Estimate implementation effort for specific requirements.

**Parameters:**
- `requirement_id` (string): The requirement identifier to estimate effort for

### get_cloud_native_guidance
Get cloud-native implementation guidance for specific Azure and multi-cloud technologies.

**Parameters:**
- `technology` (string): Technology to get guidance for (e.g., "kubernetes", "containers", "serverless", "terraform")

**Note:** All cloud examples and best practices prioritize Azure services (AKS, Azure Functions, Key Vault, Bicep, etc.)

### validate_architecture
Validate a system architecture against FedRAMP 20x requirements.

**Parameters:**
- `architecture_description` (string): Description of the architecture to validate

### search_documentation
Search FedRAMP official documentation markdown files for specific keywords.

**Parameters:**
- `keywords` (string): Keywords to search for in documentation

**Returns:** Matching documentation sections with context from all available markdown files

**Note:** Automatically loads all markdown files from the docs directory, so new documentation is always searchable.

### get_documentation_file
Get the full content of a specific FedRAMP documentation file.

**Parameters:**
- `filename` (string): The markdown filename (e.g., "overview.md", "key-security-indicators.md")

**Returns:** Full markdown content of the documentation file

### list_documentation_files
List all available FedRAMP documentation files.

**Returns:** Complete list of all markdown documentation files dynamically discovered from the repository

### export_to_excel
Export FedRAMP 20x data to Excel files for offline analysis and reporting.

**Parameters:**
- `export_type` (string): Type of data to export:
  - `"ksi"` - All 72 Key Security Indicators
  - `"all_requirements"` - All 329 requirements across all families
  - `"definitions"` - All FedRAMP term definitions
- `output_path` (string, optional): Custom output path. If not provided, saves to Downloads folder

**Returns:** Path to the generated Excel file with professional formatting (styled headers, borders, frozen panes)

**KSI Export Columns:**
1. **KSI ID** - Unique identifier (e.g., KSI-AFR-01)
2. **Name** - KSI name
3. **Category** - Control family category
4. **Status** - Active or Retired
5. **Statement** - Full requirement statement
6. **Note** - Additional information (e.g., supersession notes for retired KSIs)
7. **NIST 800-53 Controls** - Related security controls with titles
8. **Reference** - Reference document name (if applicable)
9. **Reference URL** - Link to FedRAMP documentation (if applicable)
10. **Impact Levels** - Applicable levels (Low, Moderate, High)

**All Requirements Export Columns:**
1. **Requirement ID** - Unique identifier
2. **Family** - Control family
3. **Term/Name** - Requirement name
4. **Description** - Full description
5. **Document** - Source document

**Definitions Export Columns:**
1. **Term** - FedRAMP term
2. **Definition** - Term definition
3. **Notes** - Additional context
4. **References** - Related documentation

**Example usage:**
- Export all KSIs: `export_to_excel("ksi")`
- Export all requirements: `export_to_excel("all_requirements")`
- Export definitions: `export_to_excel("definitions")`

### export_to_csv
Export FedRAMP 20x data to CSV files for data analysis and spreadsheet imports.

**Parameters:**
- `export_type` (string): Type of data to export:
  - `"ksi"` - All 72 Key Security Indicators
  - `"all_requirements"` - All 329 requirements across all families
  - `"definitions"` - All FedRAMP term definitions
- `output_path` (string, optional): Custom output path. If not provided, saves to Downloads folder

**Returns:** Path to the generated CSV file

**Columns:** Same structure as Excel export (see above for detailed column descriptions)

**Example usage:**
- Export all KSIs: `export_to_csv("ksi")`
- Export all requirements: `export_to_csv("all_requirements")`
- Export definitions: `export_to_csv("definitions")`

### generate_ksi_specification
Generate a comprehensive product specification Word document for a KSI to guide engineering implementation and planning.

**Parameters:**
- `ksi_id` (string): The KSI identifier (e.g., "KSI-AFR-01")
- `evidence_collection_strategy` (string): High-level evidence collection strategy description provided by the user
- `output_path` (string, optional): Custom output path. If not provided, saves to Downloads folder

**Returns:** Path to the generated Word (.docx) document

**Document Contents:**
- **Metadata**: KSI ID, category, impact levels, status, date
- **Overview**: Purpose and scope aligned with FedRAMP 20x
- **Requirement Statement**: Full KSI requirement text
- **NIST 800-53 Controls**: Related security controls with titles
- **Azure-First Implementation**: Recommended Azure services, IaC guidance, automation strategies
- **Evidence Collection**: User-defined strategy + recommended evidence types and flexible collection schedule
- **5-Phase Implementation Plan**: Requirements analysis → Design → Implementation → Testing → Documentation (engineering teams determine timelines)
- **Team Roles**: Cloud architect, DevOps, security engineer, compliance specialist, etc.
- **Success Criteria**: Measurable outcomes for implementation validation
- **Risks and Mitigation**: Common risks with Azure-specific mitigation strategies
- **Resources**: Links to FedRAMP, NIST, Azure documentation

**Azure Services Recommended** (context-aware based on KSI category):
- Microsoft Entra ID, Azure Policy, Azure Monitor (all KSIs)
- Microsoft Defender for Cloud, Azure Key Vault, Azure Firewall (category-specific)
- Microsoft Sentinel, Azure Automation, Log Analytics (control-specific)

**Example usage:**
```
Generate specification for KSI-AFR-01:
> generate_ksi_specification with ksi_id="KSI-AFR-01" 
  and evidence_collection_strategy="Collect Azure Policy compliance reports quarterly using Azure Automation runbooks. Store evidence in Azure Blob Storage with immutable storage policy."
```

### generate_implementation_questions
Generate strategic interview questions for product managers and engineers to facilitate thoughtful planning discussions.

**Parameters:**
- `requirement_id` (string): The requirement or KSI identifier (e.g., "FRR-CCM-01", "KSI-IAM-01")

**Returns:** Comprehensive set of strategic questions organized by stakeholder role

**Question Categories:**
1. **Strategic Questions for Product Managers** (10 questions):
   - Business Impact & ROI
   - Customer Value & Competitive Position
   - Resource Allocation & Prioritization
   - Dependencies & Phasing

2. **Technical Questions for Engineers** (15 questions):
   - Architecture & Design Decisions
   - Azure Service Selection
   - Automation Opportunities
   - Monitoring & Evidence Collection
   - Operations & Maintenance

3. **Cross-Functional Questions** (10 questions):
   - Security & Compliance Integration
   - User Experience Impact
   - Training & Support Needs
   - Incident Response Alignment

4. **Azure-Specific Considerations** (dynamic, up to 20 questions):
   - Microsoft Entra ID configuration
   - Azure RBAC and Conditional Access
   - Log Analytics and Sentinel integration
   - Azure Policy and governance
   - Defender for Cloud setup
   - Key Vault and encryption strategy

**Additional Guidance:**
- Decision Framework (5 must-answer questions before implementation)
- Success Criteria (5 measurable outcomes)
- Red Flags (5 warning signs to watch for)
- Next Steps (9-phase implementation approach)
- Recommended Resources (Microsoft docs, FedRAMP resources, community)

### analyze_infrastructure_code
Analyze Infrastructure as Code (IaC) files for FedRAMP 20x compliance issues and provide actionable recommendations.

**Parameters:**
- `code` (string): The IaC code content to analyze
- `file_type` (string): Type of IaC file - `"bicep"` or `"terraform"`
- `file_path` (string): Path to the file being analyzed (for reporting)
- `context` (string, optional): Additional context about the code (e.g., PR description)

**Returns:**
- **findings**: Array of compliance findings with requirement IDs, severity, descriptions, and recommendations
- **summary**: Counts of high/medium/low priority issues and good practices
- **pr_comment**: Formatted markdown suitable for GitHub/ADO PR comments

**Supported Languages:**
- **Bicep**: Azure Resource Manager templates
- **Terraform**: Azure RM provider resources

**What It Checks:**
Analyzes your infrastructure code against 40+ FedRAMP KSIs including:
- Identity & Access Management (MFA, RBAC, privileged access)
- Service Configuration (encryption, secrets management, backups)
- Network Architecture (security groups, DDoS protection, segmentation)
- Monitoring & Logging (diagnostic settings, audit logs, alerting)
- DevSecOps (change management, vulnerability scanning, testing)
- Privacy & Data Protection (data classification, retention policies)
- Incident Response (detection, logging, automation)
- Supply Chain Security (container scanning, trusted registries)

**Example Usage:**
```bicep
// This Bicep code will be flagged for missing diagnostic settings
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  properties: {
    // Missing: diagnostic settings for KSI-MLA-05
  }
}
```

### analyze_application_code
Analyze application code for FedRAMP 20x security compliance issues.

**Parameters:**
- `code` (string): The application code content to analyze
- `language` (string): Programming language - `"python"`, `"csharp"`, `"java"`, `"typescript"`, or `"javascript"`
- `file_path` (string): Path to the file being analyzed (for reporting)
- `dependencies` (array, optional): List of project dependencies (e.g., `["flask==2.3.0", "requests==2.31.0"]`)

**Returns:**
- **findings**: Array of security findings (same structure as infrastructure analysis)
- **summary**: Counts of high/medium/low priority issues and good practices
- **pr_comment**: Formatted markdown for PR reviews
- **dependencies_checked**: Number of dependencies analyzed

**Supported Languages & Frameworks:**
- **Python**: Flask, Django, FastAPI applications
- **C#**: ASP.NET Core, Entity Framework, Azure SDK for .NET
- **Java**: Spring Boot, Spring Security, Jakarta EE, Azure SDK for Java
- **TypeScript/JavaScript**: Express, NestJS, Next.js, React, Angular, Vue, Azure SDK for JS

**FedRAMP Requirements Checked (Phase 1 + Phase 2):**

**Phase 1 - Foundation:**
- **KSI-IAM-01**: API authentication and authorization
- **KSI-SVC-06**: Secrets management (hardcoded passwords, API keys)
- **KSI-SVC-08**: Dependency security (vulnerable libraries, unsafe functions)
- **KSI-PIY-02**: PII handling and encryption (SSN, email, phone, DOB, address)
- **KSI-MLA-05**: Diagnostic logging configuration

**Phase 2 - Application Security:**
- **KSI-IAM-05**: Service account management (Managed Identity vs hardcoded credentials)
- **KSI-CNA-03**: Microservices security (service-to-service auth, mTLS, rate limiting)

**Phase 3 - Secure Coding Practices:**
- **KSI-SVC-01**: Error handling and logging
- **KSI-SVC-02**: Input validation (SQL/command injection prevention)
- **KSI-SVC-07**: Secure coding (no eval/exec, secure random)
- **KSI-PIY-01**: Data classification and tagging
- **KSI-PIY-03**: Privacy controls (retention, deletion, export)
- **KSI-CNA-07**: Service mesh security (Istio/Linkerd)
- **KSI-IAM-04**: Least privilege access
- **KSI-IAM-07**: Session management and token security

### analyze_cicd_pipeline
Analyze CI/CD pipeline configurations for FedRAMP 20x DevSecOps compliance.

**Parameters:**
- `code` (string): The pipeline configuration content (YAML/JSON)
- `pipeline_type` (string): Type of pipeline - `"github-actions"`, `"azure-pipelines"`, `"gitlab-ci"`, or `"generic"`
- `file_path` (string): Path to the pipeline file (for reporting)

**Returns:**
- **findings**: Array of DevSecOps findings (same structure as code analysis)
- **summary**: Counts of high/medium/low priority issues and good practices
- **pr_comment**: Formatted markdown for PR reviews
- **pipeline_type**: The detected pipeline platform

**Supported Platforms:**
- **GitHub Actions** (`.github/workflows/*.yml`)
- **Azure DevOps Pipelines** (`azure-pipelines.yml`)
- **GitLab CI/CD** (`.gitlab-ci.yml`)

**FedRAMP Requirements Checked (Phase 4):**
- **KSI-CMT-01**: Change management automation (PR triggers, required reviews, branch protection)
- **KSI-CMT-02**: Deployment procedures (approval gates, environment protection, rollback capabilities)
- **KSI-CMT-03**: Automated testing in CI/CD (unit tests, security scans in pipeline)
- **KSI-AFR-01**: Automated vulnerability scanning (container, IaC, SAST/DAST tools)
- **KSI-AFR-02**: Security finding remediation (blocking on vulnerabilities, automated issue creation)
- **KSI-CED-01**: Continuous evidence collection (artifact uploads, test results, retention policies)

**Example usage:**
```yaml
# GitHub Actions workflow that will be flagged for missing security scans
name: Build
on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: docker build -t myapp .
      - run: docker push myapp:latest
      # ❌ No vulnerability scanning
      # ❌ No test execution
      # ❌ No evidence collection
```

> **💡 Result:** Analyzer recommends adding Trivy container scanning, unit test execution, security gates, and artifact uploads for compliance evidence.

**Example usage:**
```python
# This Python code will be flagged for multiple issues
from flask import Flask

app = Flask(__name__)
API_KEY = "sk-1234567890abcdef"  # KSI-SVC-06: Hardcoded secret

@app.route('/api/users')  # KSI-IAM-01: Missing authentication
def get_users():
    users = [
        {'name': 'Alice', 'ssn': '123-45-6789'},  # KSI-PIY-02: Unencrypted PII
    ]
    return {'users': users}
```

**Automated PR Review Workflow:**
1. Code submitted via PR (GitHub/Azure DevOps)
2. Analyzer tools examine IaC and application code
3. Findings generated with FedRAMP requirement citations
4. PR comment posted with compliance review
5. Developers address issues before merge

**Purpose:** Help teams think deeply about implementation considerations, trade-offs, and success criteria before committing resources. Questions are designed to facilitate planning sessions, design reviews, and stakeholder alignment.

### get_infrastructure_code_for_ksi
Generate Infrastructure as Code templates (Bicep or Terraform) for automated evidence collection infrastructure.

**Parameters:**
- `ksi_id` (string): The Key Security Indicator identifier (e.g., "KSI-IAM-01", "KSI-MLA-01")
- `infrastructure_type` (string): Either "bicep" or "terraform"

**Returns:** Complete IaC templates for deploying evidence collection infrastructure

**Supported KSI Families:**
- **IAM (Identity and Access Management)**: Microsoft Entra ID, Log Analytics workspaces, diagnostic settings, automation accounts
- **MLA (Monitoring, Logging, and Auditing)**: Log Analytics workspaces, Azure Sentinel, diagnostic settings, alert rules
- **AFR (Audit and Financial Reporting)**: Storage accounts with immutability, event subscriptions, audit logs
- **CNA (Change Notification and Approval)**: Event Grid topics, Logic Apps, DevOps pipelines, change tracking
- **RPL (Release Pipeline)**: Azure DevOps pipelines, deployment slots, rollback capabilities, approval gates
- **SVC (Service and Vulnerability Management)**: Defender for Cloud, security assessments, compliance dashboards

**Example Usage:**
```
> get_infrastructure_code_for_ksi with ksi_id="KSI-IAM-01" and infrastructure_type="bicep"
```

**Output Includes:**
- Azure resource definitions (Log Analytics, Storage, Event Grid, etc.)
- Diagnostic settings for evidence collection
- Retention policies and immutability
- Integration with Azure Monitor and Sentinel
- Automation for evidence gathering
- RBAC roles and permissions

### get_evidence_collection_code
Generate business logic code (Python, C#, PowerShell, Java, or TypeScript) for collecting and storing KSI evidence programmatically.

**Parameters:**
- `ksi_id` (string): The Key Security Indicator identifier (e.g., "KSI-IAM-01")
- `language` (string): Either "python", "csharp", "powershell", "java", or "typescript" (also accepts "javascript")

**Returns:** Complete code examples with authentication, evidence collection, and storage

**Code Features:**
- **Authentication**: Azure DefaultAzureCredential pattern for managed identity or local development
- **Evidence Collection**: SDKs for Microsoft Graph API, Azure Resource Manager, Azure Monitor
- **Evidence Storage**: Save to Azure Blob Storage with immutability and metadata tagging
- **Error Handling**: Comprehensive try-catch patterns and logging
- **Documentation**: Inline comments explaining each step

**Supported Languages:**
- **Python**: Uses azure-identity, azure-storage-blob, azure-monitor-query, msgraph-sdk
- **C#**: Uses Azure.Identity, Azure.Storage.Blobs, Azure.Monitor.Query, Microsoft.Graph
- **PowerShell**: Uses Az.Accounts, Az.Storage, Az.Monitor, Microsoft.Graph modules
- **Java**: Uses Azure Identity, Azure Storage Blobs, Azure Resource Manager, Microsoft Graph SDK
- **TypeScript/JavaScript**: Uses @azure/identity, @azure/storage-blob, @azure/arm-resources, @microsoft/microsoft-graph-client

**Example Usage:**
```
> get_evidence_collection_code with ksi_id="KSI-MLA-01" and language="python"
```

**Output Includes:**
- SDK imports and authentication setup
- Evidence collection logic specific to the KSI
- JSON formatting and metadata tagging
- Blob storage upload with immutability
- Error handling and retry logic

### get_evidence_automation_architecture
Get comprehensive architecture guidance for automated evidence collection systems.

**Parameters:**
- `scope` (string): Architecture scope - "minimal", "single-ksi", "category", or "all"

**Returns:** Complete architecture patterns with components, data flows, and implementation guidance

**Architecture Scopes:**
1. **minimal**: Quick-start architecture for pilot projects
   - Single Log Analytics workspace
   - Azure Function for scheduled evidence collection
   - Blob storage with basic retention
   - Event Grid for notifications

2. **single-ksi**: Production architecture for one KSI
   - Dedicated evidence collection infrastructure
   - Azure Functions with monitoring
   - Managed identities for security
   - Sentinel integration

3. **category**: Enterprise architecture for one KSI category (IAM, MLA, etc.)
   - Category-specific evidence collectors
   - Centralized evidence storage
   - Automated reporting dashboards
   - Integration with Azure Policy

4. **all**: Complete enterprise architecture for all 72 KSIs
   - Multi-region evidence collection
   - High-availability design
   - Automated compliance reporting
   - Integration with GRC tools

**Example Usage:****
```
> get_evidence_automation_architecture with scope="all"
```

**Output Includes:**
- Component diagram and descriptions
- Data flow architecture
- Security and identity patterns
- Monitoring and alerting strategy
- Evidence storage and retention
- Disaster recovery considerations
- Integration patterns with Azure services
- Scaling recommendations
- Implementation steps

## Available Prompts

The server provides **18 prompts** for FedRAMP compliance workflows:

### Comprehensive Planning & Assessment Prompts

**initial_assessment_roadmap** - Complete 6-phase roadmap for FedRAMP 20x authorization with checklists, deliverables, and critical success factors (engineering teams determine timelines)

**gap_analysis** - Detailed gap analysis framework comparing current state against FedRAMP 20x requirements with prioritization and remediation planning

**vendor_evaluation** - Comprehensive vendor assessment framework with category-specific questions, scorecard template, and evaluation criteria

**migration_from_rev5** - Detailed migration plan from FedRAMP Rev 5 to 20x with 7-phase approach, gap analysis, and requirement mapping (teams determine timelines and budgets)

**significant_change_assessment** - Framework for evaluating significant changes per FRR-CCM-SC including impact analysis, testing requirements, and authorization update triggers

### Implementation & Automation Prompts

**ksi_implementation_priorities** - Prioritized guide for implementing all 72 Key Security Indicators across 8 priority phases with dependency mapping (engineering teams determine rollout timelines)

**azure_ksi_automation** - **Complete guide for implementing all 72 KSIs using Microsoft, Azure, and M365 capabilities** including PowerShell scripts, Azure CLI commands, Microsoft Graph API integration, KQL queries, Azure Functions/Logic Apps, evidence collection framework, and integration with Defender suite, Entra ID, Key Vault, and Sentinel

**api_design_guide** - Complete guide for Authorization Data Sharing API (FRR-ADS) with endpoints, authentication, OSCAL formats, and examples

**authorization_boundary_review** - Guidance for defining and documenting authorization boundaries, system interconnections, and data flows per FedRAMP 20x requirements

### Monitoring & Compliance Prompts

**continuous_monitoring_setup** - Guide for establishing continuous monitoring programs aligned with FedRAMP 20x requirements including automation, metrics, and reporting

**quarterly_review_checklist** - Comprehensive checklist for FedRAMP 20x quarterly reviews (FRR-CCM-QR) covering all 72 KSIs, vulnerability review, and change review

**vulnerability_remediation_timeline** - Timeline and prioritization framework for vulnerability remediation aligned with FedRAMP 20x VDR requirements

### Audit & Documentation Prompts

**audit_preparation** - Comprehensive guide for FedRAMP 20x assessment preparation with evidence gathering, common findings, and interview prep (teams determine preparation timeline)

**ato_package_checklist** - Complete checklist for Authority to Operate (ATO) package preparation including all required artifacts, templates, and submission requirements

**documentation_generator** - OSCAL SSP templates, procedure templates (VDR, ICP, SCN), and KSI implementation documentation templates

### FRR Compliance & Code Review Prompts

**frr_code_review** - Guide for reviewing code against FedRAMP Requirements (FRR) using AST-powered semantic analysis across all 10 FRR families (VDR, ADS, RSC, UCM, CCM, SCN, MAS, ICP, FSI, PVA) with PR workflow integration

**frr_family_assessment** - Comprehensive family-specific assessment guide for all 199 FRR requirements with detailed checklists, assessment questions, and evidence planning for each of the 10 FRR families

**frr_implementation_roadmap** - Strategic 16-week, 4-phase roadmap for implementing all 199 FRR requirements with prioritization framework, Azure service recommendations, and KSI integration strategies

## Combined KSI + FRR Analysis Examples

The MCP server provides integrated analysis capabilities combining Key Security Indicators (KSI) with FedRAMP Revised Requirements (FRR) for comprehensive compliance validation. These examples demonstrate how to use both KSI code analyzers and FRR analysis tools together for holistic security assessments.

### Example 1: Network Segmentation (KSI-CNA-01 + FRR-RSC Family)

**Scenario:** Validate network security controls for both KSI tracking and FRR compliance

```python
# Step 1: Analyze infrastructure code with KSI analyzer
from analyzers.ksi.factory import get_factory

bicep_code = """
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'prod-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-https'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
    ]
  }
}
"""

# Analyze against KSI-CNA-01 (Network Segmentation)
factory = get_factory()
ksi_result = factory.analyze("KSI-CNA-01", bicep_code, "bicep", "nsg.bicep")

print(f"KSI-CNA-01 Analysis:")
print(f"  Compliant: {ksi_result.is_compliant}")
print(f"  Findings: {len(ksi_result.findings)}")
for finding in ksi_result.findings:
    print(f"  - {finding.severity.value}: {finding.message}")

# Step 2: Analyze against FRR-RSC (Secure Configuration) requirements
frr_analysis = analyze_frr_family(
    family="RSC",
    code=bicep_code,
    language="bicep",
    file_path="nsg.bicep"
)

print(f"\nFRR-RSC Family Analysis:")
print(f"  Total FRRs: {frr_analysis['total_frrs']}")
print(f"  Compliant: {frr_analysis['compliant_count']}")
print(f"  Non-compliant: {frr_analysis['non_compliant_count']}")

# Step 3: Get integrated remediation guidance
for frr_id, result in frr_analysis['results'].items():
    if not result['compliant']:
        print(f"\n{frr_id}: {result['frr_name']}")
        print(f"  Related KSI: {get_frr_metadata(frr_id)['related_ksis']}")
        print(f"  Remediation: {result['recommendation']}")

# Output:
# KSI-CNA-01 Analysis:
#   Compliant: False
#   Findings: 2
#   - HIGH: NSG allows traffic from any source (sourceAddressPrefix: *)
#   - MEDIUM: NSG rule priority too permissive (100 vs recommended >1000)
#
# FRR-RSC Family Analysis:
#   Total FRRs: 10
#   Compliant: 7
#   Non-compliant: 3
#
# FRR-RSC-01: Network Security Groups Configuration
#   Related KSI: ['KSI-CNA-01', 'KSI-CNA-03']
#   Remediation: Use specific source IP ranges, implement deny-by-default rules
```

**Integration Benefits:**
- KSI analysis provides tactical code-level findings
- FRR analysis provides strategic compliance coverage
- Combined view shows both security defects and policy compliance
- Remediation guidance links code fixes to compliance requirements

### Example 2: Vulnerability Management (KSI-AFR-04 + FRR-VDR Family)

**Scenario:** Validate vulnerability scanning configuration and remediation processes

```python
# Step 1: Analyze vulnerability scanning implementation with KSI
cicd_pipeline = """
name: Security Scanning
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 0 * * *'  # Daily scans

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Trivy vulnerability scanner
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'json'
          output: 'trivy-results.json'
          severity: 'CRITICAL,HIGH,MEDIUM'
      
      - name: Upload scan results
        uses: actions/upload-artifact@v3
        with:
          name: trivy-results
          path: trivy-results.json
          retention-days: 90
"""

# Analyze against KSI-AFR-04 (Vulnerability Detection)
ksi_result = factory.analyze("KSI-AFR-04", cicd_pipeline, "yaml", ".github/workflows/security.yml")

print(f"KSI-AFR-04 Analysis:")
print(f"  Compliant: {ksi_result.is_compliant}")
print(f"  Evidence: {ksi_result.evidence}")

# Step 2: Analyze against all FRR-VDR requirements (59 total)
vdr_analysis = analyze_frr_family(
    family="VDR",
    code=cicd_pipeline,
    language="yaml",
    file_path=".github/workflows/security.yml"
)

print(f"\nFRR-VDR Family Analysis (59 requirements):")
print(f"  Scan configuration: {vdr_analysis['results']['FRR-VDR-01']['compliant']}")
print(f"  Remediation timeframes: {vdr_analysis['results']['FRR-VDR-TF-01']['compliant']}")
print(f"  KEV tracking: {vdr_analysis['results']['FRR-VDR-TF-02']['compliant']}")
print(f"  Authenticated scanning: {vdr_analysis['results']['FRR-VDR-AC-01']['compliant']}")

# Step 3: Get evidence automation recommendations
evidence_guidance = get_frr_evidence_automation("FRR-VDR-01")
ksi_evidence = get_ksi_evidence_automation("KSI-AFR-04")

print(f"\nIntegrated Evidence Collection:")
print(f"  FRR-VDR-01 Artifacts: {evidence_guidance['evidence_artifacts']}")
print(f"  KSI-AFR-04 Queries: {ksi_evidence['collection_methods']}")
print(f"  Storage: Azure Blob (retention: 730 days per FRR-VDR, KSI-MLA-02)")

# Output:
# KSI-AFR-04 Analysis:
#   Compliant: True
#   Evidence: Daily vulnerability scans, artifact retention 90 days
#
# FRR-VDR Family Analysis (59 requirements):
#   Scan configuration: True
#   Remediation timeframes: False (missing deadline tracking)
#   KEV tracking: False (no CISA KEV integration)
#   Authenticated scanning: False (filesystem scan only)
#
# Integrated Evidence Collection:
#   FRR-VDR-01 Artifacts: ['scan-results.json', 'remediation-status.csv', 'kev-report.pdf']
#   KSI-AFR-04 Queries: ['Log Analytics vulnerability metrics', 'Defender scan results']
#   Storage: Azure Blob (retention: 730 days per FRR-VDR, KSI-MLA-02)
```

**Integration Benefits:**
- KSI-AFR-04 validates scanning tool configuration
- FRR-VDR family checks compliance with all 59 vulnerability requirements
- Combined analysis identifies gaps (KEV tracking, authenticated scans)
- Evidence automation recommendations cover both KSI and FRR needs

### Example 3: Authorization Data Sharing (KSI-CED-01 + FRR-ADS Family)

**Scenario:** Validate API implementation for machine-readable compliance data

```python
# Step 1: Analyze API implementation with KSI
api_code = """
@app.route('/api/authorization/technical-controls', methods=['GET'])
@require_auth
def get_technical_controls():
    \"\"\"FRR-ADS-TC-02: Technical controls data endpoint\"\"\"
    
    # Query compliance data from storage
    controls_data = storage_client.get_blob(
        container='security-controls',
        blob='latest-technical-controls.json'
    )
    
    response = {
        'metadata': {
            'timestamp': datetime.utcnow().isoformat(),
            'version': '1.0',
            'frr_requirement': 'FRR-ADS-TC-02',
            'classification': 'CUI'
        },
        'data': json.loads(controls_data)
    }
    
    return jsonify(response), 200
"""

# Analyze against KSI-CED-01 (Continuous Evidence Delivery)
ksi_result = factory.analyze("KSI-CED-01", api_code, "python", "api/authorization.py")

print(f"KSI-CED-01 Analysis:")
print(f"  API endpoint defined: {ksi_result.is_compliant}")
print(f"  Authentication required: {'@require_auth' in api_code}")

# Step 2: Analyze against FRR-ADS family (22 requirements)
ads_analysis = analyze_frr_family(
    family="ADS",
    code=api_code,
    language="python",
    file_path="api/authorization.py"
)

print(f"\nFRR-ADS Family Analysis (22 requirements):")
for frr_id in ['FRR-ADS-01', 'FRR-ADS-02', 'FRR-ADS-AC-01', 'FRR-ADS-TC-02']:
    result = ads_analysis['results'][frr_id]
    print(f"  {frr_id}: {result['compliant']} - {result['frr_name']}")

# Step 3: List all required FRR-ADS-TC endpoints
tc_endpoints = list_frrs_by_family("ADS")
tc_frrs = [frr for frr in tc_endpoints if 'TC-' in frr['frr_id']]

print(f"\nRequired FRR-ADS-TC Endpoints ({len(tc_frrs)} total):")
for frr in tc_frrs:
    print(f"  {frr['frr_id']}: {frr['name']}")
    metadata = get_frr_metadata(frr['frr_id'])
    print(f"    Related KSI: {metadata['related_ksis']}")

# Output:
# KSI-CED-01 Analysis:
#   API endpoint defined: True
#   Authentication required: True
#
# FRR-ADS Family Analysis (22 requirements):
#   FRR-ADS-01: True - Machine-readable authorization data
#   FRR-ADS-02: True - Real-time compliance data API
#   FRR-ADS-AC-01: True - API authentication and access control
#   FRR-ADS-TC-02: True - Technical controls data endpoint
#
# Required FRR-ADS-TC Endpoints (7 total):
#   FRR-ADS-TC-01: Continuous monitoring data
#     Related KSI: ['KSI-CED-01', 'KSI-MLA-01']
#   FRR-ADS-TC-02: Technical controls data
#     Related KSI: ['KSI-CED-01']
#   FRR-ADS-TC-03: Vulnerability data
#     Related KSI: ['KSI-CED-01', 'KSI-AFR-04']
#   [... 4 more endpoints ...]
```

**Integration Benefits:**
- KSI-CED-01 validates evidence delivery mechanism
- FRR-ADS family ensures all 22 authorization data sharing requirements met
- Combined analysis identifies which KSIs map to which FRR endpoints
- Comprehensive coverage of machine-readable compliance data requirements

### Example 4: Comprehensive Pre-Deployment Scan

**Scenario:** Full compliance check before production deployment combining all KSIs and FRRs

```python
# Complete infrastructure/application scan
terraform_infra = open('main.tf', 'r').read()
app_code = open('app.py', 'r').read()
cicd_pipeline = open('.github/workflows/deploy.yml', 'r').read()

# Step 1: Analyze against all 72 KSIs
print("KSI Analysis (72 indicators):")
all_ksi_results = factory.analyze_all_ksis(terraform_infra, "terraform", "main.tf")
ksi_summary = {
    'compliant': sum(1 for r in all_ksi_results if r.is_compliant),
    'non_compliant': sum(1 for r in all_ksi_results if not r.is_compliant),
    'high_severity': sum(1 for r in all_ksi_results for f in r.findings if f.severity.value == 'HIGH')
}
print(f"  Total KSIs analyzed: {len(all_ksi_results)}")
print(f"  Compliant: {ksi_summary['compliant']}")
print(f"  Non-compliant: {ksi_summary['non_compliant']}")
print(f"  High-severity findings: {ksi_summary['high_severity']}")

# Step 2: Analyze against all 199 FRRs
print("\nFRR Analysis (199 requirements):")
all_frr_results = analyze_all_frrs(
    code=terraform_infra,
    language="terraform",
    file_path="main.tf"
)

frr_summary = {
    'compliant': all_frr_results['compliant_count'],
    'non_compliant': all_frr_results['non_compliant_count'],
    'not_applicable': all_frr_results['not_applicable_count']
}
print(f"  Total FRRs analyzed: {all_frr_results['total_frrs']}")
print(f"  Compliant: {frr_summary['compliant']}")
print(f"  Non-compliant: {frr_summary['non_compliant']}")
print(f"  Not applicable: {frr_summary['not_applicable']}")

# Step 3: Family-specific deep dive on critical families
critical_families = ['VDR', 'ADS', 'CCM', 'RSC', 'UCM']
print("\nCritical Family Analysis:")
for family in critical_families:
    family_result = analyze_frr_family(family, terraform_infra, "terraform", "main.tf")
    print(f"  FRR-{family}: {family_result['compliant_count']}/{family_result['total_frrs']} compliant")

# Step 4: Generate deployment checklist
print("\nPre-Deployment Checklist:")
print("  [" + ("✓" if ksi_summary['high_severity'] == 0 else "✗") + "] No high-severity KSI findings")
print("  [" + ("✓" if frr_summary['non_compliant'] == 0 else "✗") + "] All applicable FRRs compliant")
print("  [" + ("✓" if frr_summary['non_compliant'] < 10 else "✗") + "] Less than 10 FRR findings")
print("  [" + ("✓" if ksi_summary['compliant'] >= 65 else "✗") + "] At least 65/72 KSIs compliant")

# Step 5: Get implementation status for tracking
ksi_status = get_ksi_implementation_status()
frr_status = get_frr_implementation_status()

print("\nCompliance Tracking:")
print(f"  KSI Implementation: {ksi_status['implementation_percentage']}%")
print(f"  FRR Implementation: {frr_status['overall_compliance_percentage']}%")
print(f"  Combined Score: {(ksi_status['implementation_percentage'] + frr_status['overall_compliance_percentage']) / 2}%")

# Output:
# KSI Analysis (72 indicators):
#   Total KSIs analyzed: 72
#   Compliant: 58
#   Non-compliant: 14
#   High-severity findings: 5
#
# FRR Analysis (199 requirements):
#   Total FRRs analyzed: 199
#   Compliant: 167
#   Non-compliant: 18
#   Not applicable: 14
#
# Critical Family Analysis:
#   FRR-VDR: 45/59 compliant
#   FRR-ADS: 22/22 compliant
#   FRR-CCM: 18/25 compliant
#   FRR-RSC: 8/10 compliant
#   FRR-UCM: 4/4 compliant
#
# Pre-Deployment Checklist:
#   [✗] No high-severity KSI findings
#   [✗] All applicable FRRs compliant
#   [✓] Less than 10 FRR findings
#   [✓] At least 65/72 KSIs compliant
#
# Compliance Tracking:
#   KSI Implementation: 80.6%
#   FRR Implementation: 90.3%
#   Combined Score: 85.4%
```

**Integration Benefits:**
- Comprehensive scan across all 72 KSIs and 199 FRRs
- Single command provides full compliance posture
- Family-specific analysis highlights priority areas
- Automated checklist for deployment approval
- Tracking metrics for continuous improvement

### Recommended Workflow

1. **Development Phase**: Use KSI analyzers for tactical code reviews
   - `factory.analyze(ksi_id, code, language, file_path)` for specific security checks
   - `analyze_frr_code(frr_id, code, language, file_path)` for requirement validation

2. **Pre-Commit Phase**: Analyze against critical FRR families
   - `analyze_frr_family("VDR", code, language, file_path)` for vulnerability management
   - `analyze_frr_family("RSC", code, language, file_path)` for secure configuration

3. **CI/CD Pipeline**: Full compliance scan before deployment
   - `factory.analyze_all_ksis(code, language, file_path)` for all KSIs
   - `analyze_all_frrs(code, language, file_path)` for all FRRs

4. **Quarterly Review**: Compliance tracking and reporting
   - `get_ksi_implementation_status()` for KSI progress
   - `get_frr_implementation_status()` for FRR compliance
   - Generate combined compliance report for stakeholders

## Data Source

Data is fetched from the official FedRAMP repository:
https://github.com/FedRAMP/docs/tree/main/data

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup and testing
- Security scanning requirements
- Dependency management guidelines
- Pull request process
- Project structure and architecture
- Complete test documentation

## Security

For security vulnerability reporting and security best practices, see [SECURITY.md](SECURITY.md).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup and testing
- Security scanning requirements
- Dependency management guidelines
- Pull request process

## License

MIT License - See [LICENSE](LICENSE) file for details.

This project is open source and contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The FedRAMP data is provided by the U.S. General Services Administration as public domain content.

## References

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [FedRAMP Official Website](https://www.fedramp.gov/)
- [FedRAMP Data Repository](https://github.com/FedRAMP/docs)
