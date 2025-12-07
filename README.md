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

The server provides access to **329 requirements** across all 12 FedRAMP 20x documents:
- **ADS** - Authorization Data Sharing (22 requirements)
- **CCM** - Collaborative Continuous Monitoring (25 requirements)
- **FRD** - FedRAMP Definitions (50 definitions)
- **FSI** - FedRAMP Security Inbox (16 requirements)
- **ICP** - Incident Communications Procedures (9 requirements)
- **KSI** - Key Security Indicators (72 indicators)
- **MAS** - Minimum Assessment Scope (12 requirements)
- **PVA** - Persistent Validation and Assessment (22 requirements)
- **RSC** - Recommended Secure Configuration (10 requirements)
- **SCN** - Significant Change Notifications (26 requirements)
- **UCM** - Using Cryptographic Modules (4 requirements)
- **VDR** - Vulnerability Detection and Response (59 requirements)

## Features

- **Query by Control**: Get detailed information about specific FedRAMP requirements
- **Query by Family**: List all requirements within a family
- **Keyword Search**: Search across all requirements using keywords
- **FedRAMP Definitions**: Look up official FedRAMP term definitions
- **Key Security Indicators**: Access and query FedRAMP Key Security Indicators (KSI)
- **Documentation Search**: Search and retrieve official FedRAMP documentation markdown files
- **Dynamic Content**: Automatically discovers and loads all markdown documentation files
- **Implementation Planning**: Generate strategic interview questions to help product managers and engineers think through FedRAMP 20x implementation considerations

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

**Troubleshooting:** If you get "Python was not found" errors:
1. Ensure Python is installed and added to PATH
2. Try using `python3` instead of `python`
3. Or use the full path to python.exe in `.vscode/mcp.json`

## Security

**Vulnerability Disclosure:** If you discover a security vulnerability, please see our [Security Policy](SECURITY.md) for responsible disclosure procedures (KSI-PIY-03).

**Audit Logging:** All MCP server operations are logged to stderr for audit purposes (KSI-MLA-05):
```python
# Logs include timestamps, operation types, and outcomes
2025-12-04 10:30:15 - fedramp_20x_mcp.data_loader - INFO - Loading FedRAMP controls from cache
2025-12-04 10:30:16 - fedramp_20x_mcp.tools - INFO - Tool invoked: get_control(FRR-ADS-01)
```

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
   - Access all 35 tools and 9 comprehensive prompts

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

### CI/CD Integration

The FedRAMP 20x MCP Server supports **two distinct usage models**:

1. **Interactive Development** (VS Code + MCP): Real-time guidance for developers writing code
2. **Automated CI/CD** (Direct Analyzer Use): Automated compliance checking in pipelines

#### Why Two Models?

**MCP Protocol Limitation:** The Model Context Protocol requires an LLM client (like Claude or GitHub Copilot) for human-in-the-loop interaction. This isn't available in automated CI/CD pipelines.

**Solution:** Use the underlying analyzer classes directly in CI/CD scripts, bypassing the MCP layer entirely.

#### Architecture Overview

```
┌─────────────────────────────────────┐
│     Interactive Development         │
│                                     │
│  Developer → VS Code + Claude →     │
│  MCP Server → Interactive Guidance  │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│        Automated CI/CD              │
│                                     │
│  Pipeline → Python Script →         │
│  Import Analyzer Classes →          │
│  Generate Reports → Gate Build      │
└─────────────────────────────────────┘
```

#### GitHub Actions Integration

Use the provided workflow to analyze pull requests automatically:

**File:** `.github/workflows/fedramp-compliance-check.yml`

```yaml
name: FedRAMP 20x Compliance Check

on:
  pull_request:
    branches: [main, develop]

jobs:
  analyze-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.10'
      
      - name: Install FedRAMP Analyzer
        run: pip install fedramp-20x-mcp
      
      - name: Analyze Python Code
        run: |
          python -c "
          from fedramp_20x_mcp.analyzers.python_analyzer import PythonAnalyzer
          
          analyzer = PythonAnalyzer()
          result = analyzer.analyze(open('src/app.py').read(), 'src/app.py', [])
          
          # Print formatted report
          print(result.pr_comment)
          
          # Exit with error if high-priority issues
          if result.summary['high'] > 0:
              exit(1)
          "
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: '*-compliance-report.md'
```

**Complete Example:** See `.github/workflows/fedramp-compliance-check.yml` for a comprehensive workflow that analyzes:
- Bicep infrastructure code
- Terraform infrastructure code
- Python application code
- C# application code
- Java application code
- TypeScript/JavaScript application code

#### Azure DevOps Integration

Use the provided pipeline to analyze code in Azure DevOps:

**File:** `.azuredevops/fedramp-compliance-pipeline.yml`

```yaml
trigger:
  branches:
    include: [main, develop]

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: UsePythonVersion@0
  inputs:
    versionSpec: '3.10'

- script: |
    pip install fedramp-20x-mcp
  displayName: 'Install FedRAMP Analyzer'

- task: PythonScript@0
  displayName: 'Analyze Infrastructure'
  inputs:
    scriptSource: 'inline'
    script: |
      from fedramp_20x_mcp.analyzers.bicep_analyzer import BicepAnalyzer
      
      analyzer = BicepAnalyzer()
      result = analyzer.analyze(open('main.bicep').read(), 'main.bicep')
      
      # Fail build on high-priority issues
      if result.summary['high'] > 0:
          exit(1)
```

**Complete Example:** See `.azuredevops/fedramp-compliance-pipeline.yml` for a full multi-stage pipeline.

#### Standalone Python Script

For custom CI/CD platforms or local testing:

**File:** `examples/ci_cd_integration.py`

```python
from fedramp_20x_mcp.analyzers.python_analyzer import PythonAnalyzer
from pathlib import Path

# Initialize analyzer
analyzer = PythonAnalyzer()

# Analyze file
code = Path('src/app.py').read_text()
result = analyzer.analyze(code, 'src/app.py', [])

# Check results
print(f"High Priority: {result.summary['high']}")
print(f"Medium Priority: {result.summary['medium']}")
print(f"Low Priority: {result.summary['low']}")

# Print formatted markdown report
print(result.pr_comment)

# Exit with error code if high-priority issues
if result.summary['high'] > 0:
    exit(1)
```

**Usage:**
```bash
# Analyze a single file
python examples/ci_cd_integration.py src/app.py

# Analyze entire directory
python examples/ci_cd_integration.py infrastructure/

# Generate JSON output
python examples/ci_cd_integration.py src/ --format json > report.json
```

#### Available Analyzers

Import and use analyzers directly in your CI/CD scripts:

```python
# Infrastructure Code Analyzers
from fedramp_20x_mcp.analyzers.bicep_analyzer import BicepAnalyzer
from fedramp_20x_mcp.analyzers.terraform_analyzer import TerraformAnalyzer

# Application Code Analyzers
from fedramp_20x_mcp.analyzers.python_analyzer import PythonAnalyzer
from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.java_analyzer import JavaAnalyzer
from fedramp_20x_mcp.analyzers.typescript_analyzer import TypeScriptAnalyzer
```

#### Analysis Result Structure

All analyzers return an `AnalysisResult` object with:

```python
result = analyzer.analyze(code, filepath, dependencies)

# Access findings
for finding in result.findings:
    print(f"{finding.requirement_id}: {finding.message}")
    print(f"  Line {finding.line_number}: {finding.code_snippet}")
    print(f"  Fix: {finding.recommendation}")

# Summary counts
print(result.summary)  # {"high": 2, "medium": 5, "low": 3}

# Pre-formatted PR comment (markdown)
print(result.pr_comment)

# Dependencies checked (for app analyzers)
print(result.dependencies_checked)
```

#### CI/CD Best Practices

1. **Fail builds on high-priority issues**: Use exit codes to gate deployments
2. **Upload reports as artifacts**: Save compliance reports for audit trails
3. **Post PR comments**: Provide feedback directly in pull requests
4. **Cache dependencies**: Speed up pipeline runs by caching the fedramp-20x-mcp package
5. **Analyze changed files only**: Use git diff to target only modified files
6. **Run in parallel**: Analyze different file types concurrently for faster results

#### Pre-commit Hooks

Analyze code locally before committing:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: fedramp-compliance
        name: FedRAMP 20x Compliance Check
        entry: python examples/ci_cd_integration.py
        language: python
        types: [python]
        pass_filenames: true
```

## Recommended MCP Server Setup

For the best FedRAMP 20x compliance workflow, combine this server with other MCP servers that provide Azure and Microsoft context. Here's a complete configuration that includes Azure integration, Microsoft documentation, and GitHub access.

### Complete .vscode/mcp.json Configuration

Create or update `.vscode/mcp.json` in your project with this configuration:

```jsonc
{
  "servers": {
    // FedRAMP 20x Requirements & Documentation
    "fedramp-20x-mcp": {
      "type": "stdio",
      "command": "${workspaceFolder}/.venv/Scripts/python.exe",  // Windows
      // "command": "${workspaceFolder}/.venv/bin/python",       // macOS/Linux
      "args": ["-m", "fedramp_20x_mcp"]
    },
    
    // Azure Resources & Operations (Official Microsoft MCP Server)
    "azure-mcp": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@azure/mcp-server-azure"
      ],
      "env": {
        "AZURE_SUBSCRIPTION_ID": "your-subscription-id-here"
      }
    },
    
    // Microsoft Documentation (Learn, Azure Docs, API References)
    "microsoft-docs": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@microsoft/mcp-server-docs"
      ]
    },
    
    // GitHub (for Azure samples, Bicep templates, FedRAMP examples)
    "github": {
      "type": "stdio",
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "your-github-token-here"
      }
    }
  }
}
```

### What Each Server Provides

**fedramp-20x-mcp** (This Server)
- 329 FedRAMP 20x requirements
- 72 Key Security Indicators
- 50 official definitions
- Official markdown documentation files
- Implementation examples and Azure guidance
- Evidence collection automation tools
- Compliance validation tools

**azure-mcp** (Microsoft Official)
- Query Azure resources (VMs, databases, networks)
- Check Azure Policy compliance
- Review Security Center/Defender alerts
- Validate configurations against FedRAMP requirements
- Real-time Azure resource inventory

**microsoft-docs**
- Azure service documentation
- API references
- Best practices guides
- Architecture patterns
- Security baselines

**github**
- Access Azure Quick Start templates
- FedRAMP Bicep/Terraform examples
- Azure sample applications
- Community compliance patterns

### Setup Steps

1. **Configure Azure Authentication** (for azure-mcp):
   ```bash
   # Install Azure CLI if not already installed
   # Login to Azure
   az login
   
   # Set your subscription
   az account set --subscription "your-subscription-id"
   
   # Add subscription ID to mcp.json
   ```

2. **Configure GitHub Token** (for github):
   - Go to https://github.com/settings/tokens
   - Create a Personal Access Token with `repo` scope
   - Add token to mcp.json `GITHUB_PERSONAL_ACCESS_TOKEN`

3. **Reload VS Code** to activate all servers

4. **Grant Permissions** when VS Code prompts (first use)

### Example Workflow with Multiple Servers

```
User: "Check if my Azure Key Vault configuration meets FedRAMP KSI-IAM-06 requirements"

AI Assistant uses:
1. fedramp-20x-mcp → Get KSI-IAM-06 requirements
2. azure-mcp → Query actual Key Vault configuration
3. microsoft-docs → Get Azure Key Vault security best practices
4. Returns compliance analysis with gaps and remediation steps
```

### Simplified Setup (FedRAMP Only)

If you only want FedRAMP requirements without Azure integration:

```jsonc
{
  "servers": {
    "fedramp-20x-mcp": {
      "type": "stdio",
      "command": "${workspaceFolder}/.venv/Scripts/python.exe",
      "args": ["-m", "fedramp_20x_mcp"]
    }
  }
}
```

## Available Tools

The server provides **35 tools** organized into the following categories:

**Core Tools (8):** Query requirements, definitions, and KSIs
**Documentation Tools (3):** Search and retrieve FedRAMP documentation
**Enhancement Tools (7):** Implementation examples, dependencies, effort estimation, architecture validation
**Export Tools (3):** Excel/CSV export and KSI specification generation
**Planning Tools (1):** Generate strategic implementation questions
**Evidence Collection Automation Tools (3):** Infrastructure code, collection code, architecture guidance
**Implementation Mapping Tools (2):** KSI family matrices and step-by-step implementation checklists
**Code Analysis Tools (3):** Automated FedRAMP compliance scanning for IaC, application code, and CI/CD pipelines
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

> **📊 Current Coverage:** Phase 7 development with **38 out of 65 active KSIs implemented (58.5%)** across 7 implementation phases. **Maximum practical code-detectable coverage target: 55/65 (84.6%)** - the remaining 17 KSIs are organizational/policy requirements that cannot be detected through static code analysis. Implemented KSIs cover identity & access management, service configuration, cloud & network architecture, third-party risk, change management, monitoring & logging, privacy controls, and authorization evidence. See `.github/copilot-instructions.md` for complete implementation status breakdown by family.

**Parameters:**
- `code` (string): The IaC code content to analyze
- `file_type` (string): Type of IaC file - `"bicep"` or `"terraform"`
- `file_path` (string): Path to the file being analyzed (for reporting)
- `context` (string, optional): Additional context about the code (e.g., PR description)

**Returns:**
- **findings**: Array of compliance findings with:
  - `requirement_id`: FedRAMP requirement (e.g., KSI-MLA-05, KSI-SVC-06)
  - `severity`: high/medium/low
  - `title`: Finding summary
  - `description`: Detailed issue description
  - `file_path`: Location of the issue
  - `line_number`: Approximate line number (if detected)
  - `code_snippet`: Relevant code excerpt
  - `recommendation`: Step-by-step fix with code examples
  - `good_practice`: Boolean indicating if this is a positive finding
- **summary**: Counts of high/medium/low priority issues and good practices
- **pr_comment**: Formatted markdown suitable for GitHub/ADO PR comments

**Supported IaC Languages:**
- **Bicep**: Azure Resource Manager templates
- **Terraform**: Azure RM provider resources

**FedRAMP Requirements Checked (Phases 1-5):**

**Phase 1 - Foundation:**
- **KSI-MLA-05**: Diagnostic logging/audit logging
- **KSI-SVC-06**: Key Vault secrets management
- **KSI-CNA-01**: Network Security Groups
- **KSI-IAM-03**: RBAC role assignments
- **KSI-SVC-03**: Encryption configuration

**Phase 2 - Critical Infrastructure:**
- **KSI-IAM-02**: Multi-Factor Authentication enforcement
- **KSI-IAM-06**: Privileged Identity Management (PIM) and JIT access
- **KSI-CNA-02**: Container security and isolation
- **KSI-CNA-04**: Immutable infrastructure and resource locks
- **KSI-CNA-06**: API Gateway security policies
- **KSI-SVC-04**: Backup and recovery configuration
- **KSI-SVC-05**: Automated patch management
- **KSI-MLA-01**: Centralized logging to SIEM
- **KSI-MLA-02**: Audit log retention (≥90 days)

**Phase 3 - Secure Coding:**
- **KSI-SVC-01**: Error handling and logging
- **KSI-SVC-02**: Input validation (SQL injection, command injection, path traversal)
- **KSI-SVC-07**: Secure coding (avoiding eval/exec, secure random)
- **KSI-PIY-01**: Data classification tagging
- **KSI-PIY-03**: Privacy controls (retention, deletion, export)
- **KSI-CNA-07**: Service mesh security configuration
- **KSI-IAM-04**: Least privilege access (scoped permissions)
- **KSI-IAM-07**: Session management (secure cookies, token rotation)

**Phase 6A - Infrastructure Resilience & Security:**
- **KSI-RPL-01**: Recovery objectives (RTO/RPO documentation)
- **KSI-RPL-02**: Recovery plans (Site Recovery, DR orchestration)
- **KSI-RPL-03**: System backups (Backup policies, 365-day retention)
- **KSI-RPL-04**: Recovery testing (Automation, scheduled DR drills)
- **KSI-CNA-03**: Traffic flow enforcement (Firewall, NSG flow logs, route tables)
- **KSI-CNA-05**: DDoS protection (DDoS Protection Plan on VNets)
- **KSI-IAM-05**: Least privilege access (RBAC, JIT access, managed identities)
- **KSI-AFR-11**: FIPS cryptographic modules (Key Vault Premium, TLS 1.2+)

**Phase 4 - DevSecOps Automation:**
- **KSI-CMT-01**: Change management (PR triggers, branch protection)
- **KSI-CMT-02**: Deployment procedures (approval gates, environments)
- **KSI-CMT-03**: Automated testing in CI/CD
- **KSI-AFR-01**: Vulnerability scanning (Trivy, Dependabot, Snyk)
- **KSI-AFR-02**: Security remediation tracking
- **KSI-CED-01**: Evidence collection and artifact retention

**Phase 5 - Runtime Security & Monitoring:**
- **KSI-MLA-03**: Security monitoring and alerting (Azure Monitor, Application Insights, alert rules)
- **KSI-MLA-04**: Performance monitoring (Application Insights, autoscale, anomaly detection)
- **KSI-MLA-06**: Log analysis automation (KQL queries, Sentinel analytics rules)
- **KSI-INR-01**: Incident detection (Sentinel automation rules, incident creation)
- **KSI-INR-02**: Incident response logging (diagnostic settings on Logic Apps)
- **KSI-AFR-03**: Threat intelligence integration (Defender for Cloud, threat intel feeds)

**Phase 6A - Infrastructure Resilience & Cryptography:**
- **KSI-RPL-01**: Recovery objectives (RTO/RPO documentation)
- **KSI-RPL-02**: Recovery plans (Site Recovery, DR orchestration)
- **KSI-RPL-03**: System backups (Backup policies, 365-day retention)
- **KSI-RPL-04**: Recovery testing (Automation, scheduled DR drills)
- **KSI-CNA-03**: Traffic flow enforcement (Firewall, NSG flow logs)
- **KSI-CNA-05**: DDoS protection (DDoS Protection Plan on VNets)
- **KSI-IAM-05**: Least privilege access (RBAC, JIT, managed identities)
- **KSI-AFR-11**: FIPS cryptographic modules (Key Vault Premium, TLS 1.2+)

**Phase 6B - Advanced Infrastructure Security:**
- **KSI-SVC-09**: Communication integrity (Application Gateway SSL, mTLS validation)
- **KSI-SVC-10**: Data destruction (soft delete, lifecycle policies, immutability)
- **KSI-MLA-07**: Event types monitoring (Data Collection Rules, comprehensive event taxonomy)
- **KSI-MLA-08**: Log data access (RBAC on Log Analytics, private endpoints)
- **KSI-AFR-07**: Secure configuration (HTTPS only, TLS 1.2+, disabled public access)
- **KSI-CNA-08**: Microservices security (Istio service mesh, Dapr, API Management)
- **KSI-INR-03**: Incident after-action reports (Logic Apps automation, Sentinel playbooks)
- **KSI-CMT-04**: Change management procedures (change tags, deployment slots, Traffic Manager)

**Phase 7 - Supply Chain & Third-Party Security:**
- **KSI-TPR-03**: Supply chain risk mitigation (ACR trust policies, quarantine, image signing)
- **KSI-TPR-04**: Third-party software monitoring (Defender for Cloud, vulnerability scanning, SIEM)

> **✅ Maximum Practical Coverage Achieved:** 55 code-detectable KSIs out of 65 active (84.6%). Remaining 14 KSIs are organizational/policy requirements (AFR documentation, CED training, PIY program effectiveness) that cannot be detected through code analysis. See [ANALYZER_ROADMAP.md](ANALYZER_ROADMAP.md) for details.

**Example usage:**
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

> **📈 Next:** Phase 5 will add 6 more KSIs for Runtime Security & Monitoring (51% total coverage). See [ANALYZER_ROADMAP.md](ANALYZER_ROADMAP.md) for details.

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

> **📈 Next:** Phase 5 will add 6 more KSIs for Runtime Security & Monitoring (51% total coverage). See [ANALYZER_ROADMAP.md](ANALYZER_ROADMAP.md) for details.

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

The server provides **9 prompts** for FedRAMP compliance workflows:
> generate_implementation_questions with requirement_id="FRR-CCM-01"
### Major Comprehensive Prompts
**control_implementation** - Detailed guidance for implementing specific NIST 800-53 controls

**risk_assessment** - Framework for conducting FedRAMP-aligned risk assessments

**continuous_monitoring** - Guide for establishing continuous monitoring programs

**boundary_definition** - Help define authorization boundaries and interconnections

### Major Comprehensive Prompts

**initial_assessment_roadmap** - Complete 6-phase roadmap for FedRAMP 20x authorization with checklists, deliverables, and critical success factors (engineering teams determine timelines)

**quarterly_review_checklist** - Comprehensive checklist for FedRAMP 20x quarterly reviews (FRR-CCM-QR) covering all 72 KSIs, vulnerability review, and change review

**api_design_guide** - Complete guide for Authorization Data Sharing API (FRR-ADS) with endpoints, authentication, OSCAL formats, and examples

**ksi_implementation_priorities** - Prioritized guide for implementing all 72 Key Security Indicators across 8 priority phases with dependency mapping (engineering teams determine rollout timelines)

**vendor_evaluation** - Comprehensive vendor assessment framework with category-specific questions, scorecard template, and evaluation criteria

**documentation_generator** - OSCAL SSP templates, procedure templates (VDR, ICP, SCN), and KSI implementation documentation templates

**migration_from_rev5** - Detailed migration plan from FedRAMP Rev 5 to 20x with 7-phase approach, gap analysis, and requirement mapping (teams determine timelines and budgets)

**audit_preparation** - Comprehensive guide for FedRAMP 20x assessment preparation with evidence gathering, common findings, and interview prep (teams determine preparation timeline)

**azure_ksi_automation** - **Complete guide for implementing all 72 KSIs using Microsoft, Azure, and M365 capabilities** including PowerShell scripts, Azure CLI commands, Microsoft Graph API integration, KQL queries, Azure Functions/Logic Apps, evidence collection framework, and integration with Defender suite, Entra ID, Key Vault, and Sentinel

## Data Source

Data is fetched from the official FedRAMP repository:
https://github.com/FedRAMP/docs/tree/main/data

## Development

### Running Tests

The project includes comprehensive test coverage across all functionality:

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov-report=html

# Run specific test suites
python tests/test_loader.py                      # Data loading (329 requirements)
python tests/test_definitions.py                 # Definitions & KSIs (50 + 72)
python tests/test_docs_integration.py            # Documentation (15 files)
python tests/test_implementation_questions.py    # Strategic questions
python tests/test_tool_registration.py           # Architecture validation (35 tools)
python tests/test_evidence_automation.py         # IaC generation (Bicep/Terraform/Code)
python tests/test_all_tools.py                   # All tools comprehensive test
```

**Test Coverage:**
- ✅ **Data Loading:** 329 requirements from 12 documents
- ✅ **Definitions:** 50 FedRAMP terms
- ✅ **KSIs:** 72 Key Security Indicators
- ✅ **Documentation:** 15 official FedRAMP markdown files
- ✅ **Tool Registration:** All 29 tools across 8 modules
- ✅ **IaC Generation:** Bicep & Terraform templates for IAM, MLA, AFR families
- ✅ **Code Generation:** Python, C#, PowerShell evidence collection code
- ✅ **Template Variations:** Family-specific customization validated
- ✅ **Code Analyzers:** 96 passing tests across 55 KSIs (84.6% of 65 active KSIs)

### Project Structure

```
FedRAMP20xMCP/
├── src/
│   └── fedramp_20x_mcp/    # Main package
│       ├── __init__.py     # Package initialization
│       ├── __main__.py     # Entry point for python -m
│       ├── server.py       # MCP server entry point (270 lines, 15 prompts)
│       ├── data_loader.py  # FedRAMP data fetching and caching
│       ├── templates/      # Infrastructure & code templates
│       │   ├── __init__.py # Template loader functions
│       │   ├── bicep/      # Bicep IaC templates (7 files)
│       │   ├── terraform/  # Terraform IaC templates (6 files)
│       │   └── code/       # Code generation templates (7 files)
│       ├── prompts/        # Prompt templates (15 files)
│       │   └── __init__.py # Prompt loader function
│       ├── tools/          # Tool modules (24 tools across 7 modules)
│       │   ├── __init__.py # Tool registration system
│       │   ├── requirements.py    # Core requirements tools (3)
│       │   ├── definitions.py     # Definition lookup tools (3)
│       │   ├── ksi.py             # KSI tools (2)
│       │   ├── documentation.py   # Documentation tools (3)
│       │   ├── export.py          # Export tools (3)
│       │   ├── enhancements.py    # Enhancement tools (7)
│       │   └── evidence.py        # Evidence automation tools (3)
│       └── __fedramp_cache__/  # Runtime cache for FedRAMP data
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── test_loader.py      # Data loader tests (329 requirements)
│   ├── test_definitions.py # Definition tool tests (50 definitions, 72 KSIs)
│   ├── test_docs_integration.py  # Documentation integration tests (15 files)
│   ├── test_implementation_questions.py  # Implementation questions tests
│   ├── test_tool_registration.py  # Tool architecture validation (24 tools, 7 modules)
│   ├── test_evidence_automation.py  # IaC generation tests (Bicep/Terraform/Python/C#/PowerShell)
│   └── test_all_tools.py   # Comprehensive tool tests (all 24 tools)
├── .github/
│   ├── workflows/          # CI/CD workflows
│   │   ├── test.yml        # Test workflow (multi-platform)
│   │   ├── publish.yml     # PyPI & MCP Registry publishing
│   │   └── release.yml     # GitHub release workflow
│   └── copilot-instructions.md  # GitHub Copilot context
├── .vscode/
│   ├── mcp.json            # VS Code MCP configuration
│   └── settings.json.example
├── pyproject.toml          # Project metadata and dependencies
├── server.json             # MCP Registry metadata
├── uv.lock                 # UV dependency lock file
├── LICENSE                 # MIT License
├── README.md               # This file
├── CONTRIBUTING.md         # Contribution guidelines
└── .gitignore              # Git exclusions (includes MCP tokens)
```

**Architecture Highlights:**
- **Modular Design:** Tools organized into 7 logical modules by functionality
- **Template System:** Reusable Bicep/Terraform templates for IaC generation
- **Prompt Templates:** External prompt files for easy updates without code changes
- **Clean Separation:** Organized codebase with clear module boundaries
- **Registration Pattern:** Tools use `*_impl` functions with centralized registration

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
