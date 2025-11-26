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
```

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
   - Access all 14 tools and 9 comprehensive prompts

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
