# Contributing to FedRAMP 20x MCP Server

Thank you for your interest in contributing to the FedRAMP 20x MCP Server! This document provides guidelines for contributing to the project.

## Code of Conduct

This project follows a professional and respectful code of conduct. Please be considerate and constructive in all interactions.

## How to Contribute

### Reporting Issues

- Check existing issues before creating a new one
- Provide clear steps to reproduce bugs
- Include relevant environment information (Python version, OS, etc.)
- Use descriptive titles and detailed descriptions

### Suggesting Features

- Check if the feature has already been requested
- Explain the use case and benefits
- Consider how it aligns with FedRAMP 20x requirements
- Be open to discussion and alternative solutions

### Pull Requests

1. **Fork the repository** and create a feature branch
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Keep commits focused and atomic

3. **Test your changes**
   ```bash
   uv run pytest
   ```

4. **Update documentation**
   - Update README.md if adding features or changing behavior
   - Update docstrings for new functions/tools
   - Add examples if applicable

5. **Submit the pull request**
   - Use the PR template (automatically populated)
   - Complete all relevant sections of the template
   - Reference any related issues (use `Fixes #123` or `Relates to #456`)
   - Ensure CI/CD checks pass
   - Complete the security checklist
   - Request review from maintainers

## Development Setup

### Prerequisites

- Python 3.10 or higher

### Installation

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/FedRAMP20xMCP.git
cd FedRAMP20xMCP

# Create virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_loader.py

# Run with coverage
pytest --cov=src --cov-report=html
```

### Security Scanning

Before submitting pull requests, run security checks:

```bash
# Scan dependencies for known vulnerabilities (KSI-SVC-PRR)
pip install safety
safety check --json

# Scan code for security issues (KSI-SVC-PRR)
pip install bandit
bandit -r src/

# Update dependencies (check for security updates)
pip list --outdated
```

**Required Security Practices:**
- ✅ Keep dependencies at minimum secure versions (see `pyproject.toml`)
- ✅ Run `safety check` before commits to detect vulnerable dependencies
- ✅ Run `bandit` to identify security issues in code
- ✅ Review dependency licenses for compliance
- ✅ Never commit secrets, API keys, or sensitive data

### Dependency Management

**Adding New Dependencies (KSI-SVC-07):**
1. Verify the package is actively maintained (recent commits/releases)
2. Check for known security vulnerabilities using `safety check`
3. Review the package license (must be compatible with MIT)
4. Add with minimum secure version: `package>=X.Y.Z`
5. Document why the dependency is needed
6. Update `pyproject.toml` dependencies list
7. Test thoroughly before submitting PR

**Updating Dependencies:**
1. Check release notes for breaking changes
2. Update version constraint in `pyproject.toml`
3. Run full test suite: `pytest`
4. Run security scans: `safety check` and `bandit -r src/`
5. Update documentation if behavior changes

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector python -m fedramp_20x_mcp
```

### Testing with VS Code

1. The `.vscode/mcp.json` is already configured and committed
2. Ensure you've installed the package: `pip install -e ".[dev]"`
3. Reload VS Code
4. Grant permissions when prompted (first use)
5. Test the server using GitHub Copilot Chat

**Note:** The mcp.json uses `python -m fedramp_20x_mcp` which requires the package to be installed in your active Python environment. If you're using a virtual environment, ensure it's activated or configure VS Code to use it.

**Security Best Practice:** Never use `"alwaysAllow"` in MCP configurations that will be shared. Users should explicitly grant permissions.

## Running Tests

The project includes comprehensive test coverage across all functionality. See [TESTING.md](TESTING.md) for complete test documentation.

### Quick Test Commands

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
python tests/test_tool_registration.py           # Architecture validation (38 tools)
python tests/test_ksi_evidence_automation.py     # Evidence automation (65 KSIs)
python tests/test_all_tools.py                   # All tools comprehensive test
```

### Test Coverage Metrics

- **Total Tests:** 122 (100% pass rate)
- **Test Categories:** Core functionality, tool functional, security, resource validation, KSI analyzers, evidence automation
- **Coverage Achievement:** 100% KSI analyzer coverage (72/72)

See [TESTING.md](TESTING.md) for detailed test documentation including:
- Test file descriptions
- Coverage details
- AST parsing and semantic analysis tests
- KSI-specific analyzer tests
- Running individual test suites

## Project Structure

```
FedRAMP20xMCP/
├── src/
│   └── fedramp_20x_mcp/    # Main package
│       ├── __init__.py     # Package initialization
│       ├── __main__.py     # Entry point for python -m
│       ├── server.py       # MCP server entry point (270 lines, 15 prompts)
│       ├── data_loader.py  # FedRAMP data fetching and caching
│       ├── cve_fetcher.py  # CVE vulnerability data (GitHub Advisory + NVD)
│       ├── templates/      # Infrastructure & code templates
│       │   ├── __init__.py # Template loader functions
│       │   ├── bicep/      # Bicep IaC templates (7 files)
│       │   ├── terraform/  # Terraform IaC templates (7 files)
│       │   └── code/       # Code generation templates (9 files)
│       ├── prompts/        # Prompt templates (15 files)
│       ├── tools/          # Tool modules (36 tools across 12 modules)
│       │   ├── __init__.py # Tool registration system
│       │   ├── requirements.py    # Core requirements tools (3)
│       │   ├── definitions.py     # Definition lookup tools (3)
│       │   ├── ksi.py             # KSI tools (2)
│       │   ├── documentation.py   # Documentation tools (3)
│       │   ├── export.py          # Export tools (3)
│       │   ├── enhancements.py    # Enhancement tools (9)
│       │   ├── evidence.py        # Evidence automation tools (3)
│       │   ├── analyzer.py        # Code analysis tools (2)
│       │   ├── validation.py      # Pre-generation validation tools (3)
│       │   ├── security.py        # CVE vulnerability checking tools (2)
│       │   ├── audit.py           # Coverage audit tools (2)
│       │   └── ksi_status.py      # KSI implementation status tools (1)
│       └── analyzers/      # KSI-centric code analyzers
│           ├── __init__.py
│           ├── base.py     # Base classes (Finding, AnalysisResult, Severity)
│           └── ksi/        # 72 KSI analyzer files + factory
│               ├── __init__.py
│               ├── base.py    # BaseKSIAnalyzer
│               ├── factory.py # KSIAnalyzerFactory (singleton pattern)
│               └── ksi_*.py   # Individual KSI analyzers (72 files)
├── tests/                   # Test suite (122 test files)
├── docs/                    # Additional documentation
│   ├── CI-CD-INTEGRATION.md # CI/CD integration guide
│   └── ADVANCED-SETUP.md    # Advanced MCP configuration
├── .github/
│   ├── workflows/          # CI/CD workflows
│   └── copilot-instructions.md  # GitHub Copilot context
├── .vscode/
│   ├── mcp.json            # VS Code MCP configuration
│   └── settings.json.example
├── pyproject.toml          # Project metadata and dependencies
├── server.json             # MCP Registry metadata
├── README.md               # User documentation
├── CONTRIBUTING.md         # This file
├── TESTING.md              # Test documentation
└── SECURITY.md             # Security policy

```

**Architecture Highlights:**
- **Modular Design:** Tools organized into 12 logical modules by functionality
- **Template System:** Reusable Bicep/Terraform templates for IaC generation
- **Prompt Templates:** 15 external prompt files for easy updates without code changes
- **KSI-Centric Analysis:** 72 dedicated KSI analyzer files with factory pattern
- **AST-Powered:** Tree-sitter integration for accurate, semantic code analysis
- **Clean Separation:** Organized codebase with clear module boundaries
- **Registration Pattern:** Tools use `*_impl` functions with centralized registration

## Code Style

- Follow PEP 8 conventions
- Use type hints for function signatures
- Write descriptive docstrings for all public functions
- Keep functions focused and single-purpose
- Use meaningful variable names

## Project Structure

```
FedRAMP20xMCP/
├── src/
│   └── fedramp_20x_mcp/    # Main package
│       ├── __init__.py     # Package initialization
│       ├── __main__.py     # Entry point for python -m
│       ├── server.py       # MCP server (21 tools, 15 prompts)
│       ├── data_loader.py  # Data fetching and caching logic
│       └── __fedramp_cache__/  # Runtime cache for FedRAMP data
├── tests/                   # Test suite
│   ├── __init__.py
│   ├── test_loader.py      # Data loader tests
│   ├── test_definitions.py # Definition tool tests
│   ├── test_docs_integration.py  # Documentation integration tests
│   ├── test_implementation_questions.py  # Implementation questions tests
│   └── test_all_tools.py   # Comprehensive tool tests
├── .github/                # GitHub configuration
│   ├── workflows/          # CI/CD workflows
│   │   ├── test.yml        # Multi-platform test workflow
│   │   ├── publish.yml     # Automated PyPI & MCP Registry publishing
│   │   └── release.yml     # GitHub release creation
│   └── copilot-instructions.md  # GitHub Copilot context
├── .vscode/                # VS Code configuration
│   ├── mcp.json            # MCP server configuration
│   └── settings.json.example  # Example VS Code settings
├── pyproject.toml          # Project metadata and dependencies
├── server.json             # MCP Registry server metadata
├── uv.lock                 # UV package manager lock file
├── LICENSE                 # MIT License
├── README.md               # User-facing documentation
├── CONTRIBUTING.md         # This file
└── .gitignore              # Git exclusions (includes MCP token files)
```

## Adding New Tools

When adding a new MCP tool:

1. Add the tool function in `src/fedramp_20x_mcp/server.py`
2. Decorate with `@mcp.tool()`
3. Provide clear parameter descriptions
4. Return structured data
5. Add tests in `test_all_tools.py`
6. Document in README.md

Example:
```python
@server.call_tool()
async def your_tool_name(
    parameter_name: str
) -> list[types.TextContent]:
    """
    Brief description of what the tool does.
    
    Args:
        parameter_name: Description of the parameter
        
    Returns:
        List of TextContent with the results
    """
    # Implementation
    return [types.TextContent(type="text", text=result)]
```

## Adding New Prompts

When adding a new comprehensive prompt:

1. Add the prompt function in `fedramp_server.py`
2. Decorate with `@server.list_prompts()` or `@server.get_prompt()`
3. Provide detailed, actionable content
4. Include examples and templates
5. Document in README.md under "Available Prompts"

## Data Updates

The server fetches FedRAMP 20x data from:
https://github.com/FedRAMP/docs

If FedRAMP updates their data format:
1. Update `data_loader.py` to handle new structure
2. Add tests for new data formats
3. Update documentation
4. Bump version number

## Azure-First Guidance

This project prioritizes Azure services in all examples and recommendations:
- Use Azure services in code examples (Azure Functions, Key Vault, AKS, etc.)
- Reference Azure Government for FedRAMP compliance
- Include Azure CLI and PowerShell examples
- Mention Bicep/ARM templates for IaC
- Highlight Microsoft Entra ID, Defender, Sentinel integration

## Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking API changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

## Questions?

- Open an issue for general questions
- Tag issues with `question` label
- Check existing documentation first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing! 🎉
