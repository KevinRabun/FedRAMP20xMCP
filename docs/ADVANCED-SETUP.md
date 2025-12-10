# Advanced MCP Server Setup

For the best FedRAMP 20x compliance workflow, you can combine this server with other MCP servers that provide Azure and Microsoft context. This guide shows how to configure multiple MCP servers together.

## Complete Multi-Server Configuration

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

## What Each Server Provides

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

## Setup Steps

### 1. Configure Azure Authentication (for azure-mcp)

```bash
# Install Azure CLI if not already installed
# Login to Azure
az login

# Set your subscription
az account set --subscription "your-subscription-id"

# Add subscription ID to mcp.json
```

### 2. Configure GitHub Token (for github)

- Go to https://github.com/settings/tokens
- Create a Personal Access Token with `repo` scope
- Add token to mcp.json `GITHUB_PERSONAL_ACCESS_TOKEN`

### 3. Reload VS Code

Reload VS Code to activate all servers.

### 4. Grant Permissions

VS Code will prompt you to grant permissions on first use.

## Example Workflow with Multiple Servers

```
User: "Check if my Azure Key Vault configuration meets FedRAMP KSI-IAM-06 requirements"

AI Assistant uses:
1. fedramp-20x-mcp → Get KSI-IAM-06 requirements
2. azure-mcp → Query actual Key Vault configuration
3. microsoft-docs → Get Azure Key Vault security best practices
4. Returns compliance analysis with gaps and remediation steps
```

## Simplified Setup (FedRAMP Only)

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

## Troubleshooting

### Python Not Found

If you get "Python was not found" errors:
1. Ensure Python is installed and added to PATH
2. Try using `python3` instead of `python`
3. Or use the full path to python.exe in `.vscode/mcp.json`

### Missing Tree-Sitter Packages

If the MCP server reports fewer than 72 KSIs:
1. Check that all tree-sitter packages are installed: `pip list | grep tree-sitter`
2. Reinstall dependencies: `pip install -e . --force-reinstall`
3. Check server logs for import errors (logged to stderr)

### MCP Server Not Responding

1. Check VS Code Output panel → Model Context Protocol
2. Verify Python virtual environment is activated
3. Restart VS Code
4. Check that all required dependencies are installed

## See Also

- [README.md](../README.md) - Main documentation and basic setup
- [MCP Documentation](https://modelcontextprotocol.io/) - Official MCP protocol docs
