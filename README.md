# FedRAMP 20x MCP Server

An MCP (Model Context Protocol) server that provides access to FedRAMP 20x security requirements and controls with **Azure-first guidance**.

## Overview

This server loads FedRAMP 20x requirements data from the official [FedRAMP documentation repository](https://github.com/FedRAMP/docs/tree/main/data) and provides tools for querying requirements by control, family, or keyword.

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
   - Access all 17 tools and 9 comprehensive prompts

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

## Available Tools

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
- **Evidence Collection**: User-defined strategy + recommended evidence types and schedule
- **5-Phase Implementation Plan**: Requirements analysis → Design → Implementation → Testing → Documentation
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

## Available Prompts

### initial_assessment_roadmap
Provides a complete 9-11 month roadmap for achieving FedRAMP 20x authorization, including phases, timelines, team requirements, and budget estimates.

### quarterly_review_checklist
Comprehensive checklist for conducting FedRAMP 20x quarterly reviews (FRR-CCM-QR), covering all 72 KSIs, vulnerability review, change review, and more.

### api_design_guide
Complete guide for designing and implementing the Authorization Data Sharing API (FRR-ADS), including required endpoints, authentication, OSCAL formats, and examples.

### ksi_implementation_priorities
Prioritized guide for implementing all 72 Key Security Indicators across 8 priority phases with a 12-month rollout timeline.

### vendor_evaluation
Comprehensive vendor assessment framework with category-specific questions, scorecard template, and evaluation criteria for FedRAMP 20x compliance.

### documentation_generator
Provides OSCAL SSP templates, procedure templates (VDR, ICP, SCN), and KSI implementation documentation templates.

### migration_from_rev5
Detailed migration plan from FedRAMP Rev 5 to FedRAMP 20x, including 7-phase approach, gap analysis, requirement mapping, and budget estimates ($180K-630K).

### audit_preparation
Comprehensive guide for preparing for FedRAMP 20x assessment and audit, including 12-week preparation timeline, evidence gathering, common findings, and interview preparation.

### azure_ksi_automation
**Complete guide for implementing all 72 KSIs using Microsoft, Azure, and M365 capabilities.** Provides detailed automation approaches for each KSI family including:
- PowerShell scripts for evidence collection
- Azure CLI commands for infrastructure automation
- Microsoft Graph API integration for identity/M365
- KQL queries for Sentinel/Log Analytics
- Azure Functions, Logic Apps, and Automation runbooks
- Complete evidence collection framework with Azure Blob Storage
- Integration with Microsoft Defender suite, Entra ID, Key Vault, and Sentinel

## Data Source

Data is fetched from the official FedRAMP repository:
https://github.com/FedRAMP/docs/tree/main/data

## Development

### Running Tests

```bash
pytest
# or with coverage
pytest --cov=src --cov-report=html
```

### Project Structure

```
FedRAMP20xMCP/
├── src/
│   └── fedramp_20x_mcp/    # Main package
│       ├── __init__.py     # Package initialization
│       ├── __main__.py     # Entry point for python -m
│       ├── server.py       # MCP server implementation
│       └── data_loader.py  # FedRAMP data fetching and caching
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── test_loader.py
│   ├── test_definitions.py
│   └── test_all_tools.py
├── .github/
│   ├── workflows/          # CI/CD workflows
│   └── copilot-instructions.md
├── .vscode/
│   ├── mcp.json            # VS Code MCP configuration
│   └── settings.json.example
├── pyproject.toml          # Project metadata and dependencies
├── LICENSE                 # MIT License
├── README.md               # This file
└── CONTRIBUTING.md         # Contribution guidelines
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

This project is open source and contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

The FedRAMP data is provided by the U.S. General Services Administration as public domain content.

## References

- [Model Context Protocol Documentation](https://modelcontextprotocol.io/)
- [FedRAMP Official Website](https://www.fedramp.gov/)
- [FedRAMP Data Repository](https://github.com/FedRAMP/docs)
