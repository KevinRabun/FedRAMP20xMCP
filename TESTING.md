# Testing Guide for FedRAMP 20x MCP

Comprehensive testing documentation for the FedRAMP 20x MCP server.

## Table of Contents

- [Quick Start](#quick-start)
- [Test Organization](#test-organization)
- [Prerequisites](#prerequisites)
- [Running Tests](#running-tests)
- [Test Coverage](#test-coverage)
- [Writing New Tests](#writing-new-tests)
- [Troubleshooting](#troubleshooting)
- [CI/CD Integration](#cicd-integration)

## Quick Start

### 1. Install Test Dependencies

```powershell
pip install pytest pytest-asyncio
```

### 2. Set GitHub Token (Required for CVE Tests)

```powershell
$env:GITHUB_TOKEN = (gh auth token)
```

### 3. Run All Tests

```powershell
python tests/run_all_tests.py
```

## Test Organization

The test suite is organized into 7 primary test files plus pattern-specific test files:

### Critical Tests

**`test_pattern_language_parity.py`** - **NEW: Pattern Language Parity Validation**
- Validates 100% parity across Python, C#, Java, TypeScript
- Prevents incomplete language implementations
- Ensures consistent compliance checking across all technology stacks
- **MUST PASS before merging pattern changes**

### Core Module Tests

**`test_data_loader.py`** - FedRAMP Data Loader
- Data fetching from GitHub
- Caching mechanism
- Requirement and KSI retrieval
- Search functionality
- Definition lookups

**`test_cve_fetcher.py`** - CVE/Vulnerability Checking
- Package vulnerability scanning
- Dependency file parsing (requirements.txt, package.json)
- GitHub Advisory Database integration
- Error handling

### Pattern and Analysis Tests

**`test_pattern_engine.py`** - Pattern Engine
- Pattern file loading and validation
- YAML schema validation
- Pattern detection across languages
- Generic analyzer functionality
- Multi-language code analysis

**`test_ksi_analyzers.py`** - KSI Analyzers (72 Total)
- KSI factory pattern functionality
- Pattern-based analysis
- All KSI families: IAM, CNA, VDR, SCN, RSC, ADS, PIY, etc.
- Multi-language support (Python, C#, Java, TypeScript, Bicep, Terraform)
- CI/CD pipeline analysis

**`test_frr_analyzers.py`** - FRR Analyzers (199 Total)
- FRR factory pattern functionality
- Family-based organization (VDR, IAM, SCN, RSC, ADS, CNA, PIY)
- Infrastructure-as-Code analysis
- Application code analysis
- Comprehensive coverage across all families

### Tool Tests

**`test_mcp_tools.py`** - MCP Tools (48 Tools Across 13 Modules)
- Requirements tools (get_control, list_family_controls, search_requirements)
- Definitions tools (get_definition, list_definitions, search_definitions)
- KSI tools (get_ksi, list_ksi, evidence automation, queries, artifacts)
- FRR tools (list_frrs_by_family, implementation effort)
- Documentation tools (get_documentation, search_documentation)
- Export tools (export_to_excel)
- Enhancement tools (compare_with_rev4, implementation questions)
- Evidence tools (automation architecture, infrastructure code)
- Analyzer tools (analyze_code, analyze_all_frrs, infrastructure, CI/CD)
- Audit tools (validate_architecture)
- Security tools (check_package_vulnerabilities, scan_dependency_file)
- KSI status tools (implementation status, coverage summary)
- Validation tools (validate_fedramp_config)

**`test_code_enrichment.py`** - Code Enrichment
- Python code enrichment with FedRAMP requirements
- C# code enrichment with compliance headers
- Requirement header generation

### Pattern Tests (18 Files)

**Family-Specific Pattern Tests** - Each pattern file has corresponding tests:
- test_ads_patterns.py, test_afr_patterns.py, test_ccm_patterns.py
- test_ced_patterns.py, test_cmt_patterns.py, test_cna_patterns.py
- test_iam_patterns.py, test_inr_patterns.py, test_mla_patterns.py
- test_piy_patterns.py, test_rpl_patterns.py, test_rsc_patterns.py
- test_scn_patterns.py, test_svc_patterns.py, test_tpr_patterns.py
- test_ucm_patterns.py, test_vdr_patterns.py, test_common_patterns.py

## Prerequisites

### Required

- **Python 3.10+**
- **pytest**: `pip install pytest`
- **pytest-asyncio**: `pip install pytest-asyncio`

### Optional but Recommended

- **GitHub Token**: For CVE vulnerability checking
  ```powershell
  $env:GITHUB_TOKEN = (gh auth token)
  ```
  
- **Pattern Files**: Must exist in `data/patterns/` directory
  - 18 pattern family files (IAM, VDR, SCN, RSC, ADS, etc.)
  - Common patterns file
  - All files must be valid YAML

## Running Tests

### Run All Tests

```powershell
# Comprehensive test run with reporting
python tests/run_all_tests.py
```

### Run Individual Test Files

```powershell
# Data loader tests
python tests/test_data_loader.py

# CVE fetcher tests
python tests/test_cve_fetcher.py

# Pattern engine tests
python tests/test_pattern_engine.py

# KSI analyzer tests
python tests/test_ksi_analyzers.py

# FRR analyzer tests
python tests/test_frr_analyzers.py

# MCP tools tests
python tests/test_mcp_tools.py

# Code enrichment tests
python tests/test_code_enrichment.py

# Pattern tests (any family)
python tests/test_iam_patterns.py
python tests/test_vdr_patterns.py
```

### Run Specific Test Classes

```powershell
pytest tests/test_ksi_analyzers.py::TestKSIFactory -v
pytest tests/test_frr_analyzers.py::TestFRRAnalysisVDR -v
pytest tests/test_mcp_tools.py::TestRequirementsTools -v
```

### Run Specific Test Methods

```powershell
pytest tests/test_ksi_analyzers.py::TestKSIAnalysis::test_ksi_iam_01_mfa_python -v
```

### Pytest Options

```powershell
# Verbose output
pytest tests/test_data_loader.py -v

# Show print statements
pytest tests/test_data_loader.py -s

# Stop on first failure
pytest tests/test_data_loader.py -x

# Run with coverage
pytest tests/test_data_loader.py --cov=fedramp_20x_mcp

# Show full traceback
pytest tests/test_data_loader.py --tb=long
```

## Test Coverage

### Coverage by Component

| Component | Test File | Test Classes | Coverage |
|-----------|-----------|--------------|----------|
| Data Loader | test_data_loader.py | 1 | Core functionality |
| CVE Fetcher | test_cve_fetcher.py | 1 | Package scanning |
| Pattern Engine | test_pattern_engine.py | 3 | Pattern loading, validation, detection |
| KSI Analyzers | test_ksi_analyzers.py | 3 | All 72 KSI analyzers via factory |
| FRR Analyzers | test_frr_analyzers.py | 8 | All FRR families |
| MCP Tools | test_mcp_tools.py | 14 | All 48 tools across 13 modules |

### KSI Family Coverage

Tested KSI families:
- **IAM** (Identity and Access Management) - MFA, privileged access
- **CNA** (Cloud Network Architecture) - Network segmentation, NSGs
- **VDR** (Vulnerability Detection) - Scanning, patching
- **SCN** (Secure Configuration) - Baseline configuration
- **RSC** (Resilience) - Backup and recovery
- **ADS** (Audit Services) - Logging and monitoring
- **PIY** (Privacy) - Encryption at rest and in transit
- **AFR** (Additional families as needed)

### FRR Family Coverage

Tested FRR families:
- **VDR** - Vulnerability scanning, patching
- **IAM** - MFA enforcement, session management
- **SCN** - System hardening, configuration
- **RSC** - Backup and recovery policies
- **ADS** - Audit log collection, retention
- **CNA** - Network segmentation, security groups
- **PIY** - Data encryption

### Language Coverage

Code analysis tested across:
- **Python** - Application code, automation scripts
- **C#/.NET** - Application code, Azure SDK usage
- **Java** - Application code (limited)
- **TypeScript/JavaScript** - Application code, Node.js
- **Bicep** - Infrastructure-as-Code
- **Terraform** - Infrastructure-as-Code
- **Azure Pipelines** - CI/CD pipeline YAML
- **GitHub Actions** - CI/CD workflows (limited)

## Writing New Tests

### Test File Template

```python
"""
Tests for [Component Name]

Description of what this test file covers.
"""
import pytest
import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.module import Component


class TestComponentName:
    """Test [Component] functionality"""
    
    @pytest.fixture
    def component(self):
        """Create component instance"""
        return Component()
    
    def test_basic_functionality(self, component):
        """Test basic functionality"""
        result = component.method()
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_async_functionality(self, component):
        """Test async functionality"""
        result = await component.async_method()
        assert result is not None


def run_tests():
    """Run tests with pytest"""
    print("Running [Component] tests...")
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
```

### Testing Guidelines

1. **Test Independence**: Each test should be independent and not rely on other tests
2. **Fixtures**: Use pytest fixtures for setup/teardown
3. **Async Tests**: Use `@pytest.mark.asyncio` for async functions
4. **Assertions**: Use clear, specific assertions
5. **Error Handling**: Test both success and error cases
6. **Documentation**: Document what each test validates

### Pattern-Based Analyzer Tests

When testing KSI/FRR analyzers:

```python
def test_ksi_xyz_01_feature(self, factory):
    """Test KSI-XYZ-01: Feature description"""
    code = """
# Sample code that should trigger the pattern
import relevant_library
feature.use()
"""
    
    result = factory.analyze("KSI-XYZ-01", code, "python")
    assert result is not None
    assert result.ksi_id == "KSI-XYZ-01"
    # Additional assertions based on expected findings
```

### Tool Tests

When testing MCP tools:

```python
@pytest.mark.asyncio
async def test_tool_name_impl(self, data_loader):
    """Test tool_name implementation"""
    result = await module.tool_name_impl(params, data_loader)
    
    assert result is not None
    assert isinstance(result, str)
    # Additional assertions for expected content
```

## Troubleshooting

### Common Issues

#### 1. Import Errors

**Problem**: `ModuleNotFoundError: No module named 'fedramp_20x_mcp'`

**Solution**: Ensure src path is added:
```python
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
```

#### 2. CVE Tests Failing

**Problem**: CVE tests fail or skip

**Solution**: Set GitHub token:
```powershell
$env:GITHUB_TOKEN = (gh auth token)
```

#### 3. Pattern Files Not Found

**Problem**: `FileNotFoundError: Pattern file not found`

**Solution**: Ensure pattern files exist in `data/patterns/` directory

#### 4. Async Test Errors

**Problem**: `RuntimeError: Event loop is closed`

**Solution**: Ensure `pytest-asyncio` is installed and use `@pytest.mark.asyncio` decorator

#### 5. Timeout Errors

**Problem**: Tests timeout during data loading

**Solution**: Network issues or GitHub API limits - retry or check connectivity

### Debug Mode

Run tests with verbose output and debugging:

```powershell
# Maximum verbosity
pytest tests/test_ksi_analyzers.py -vv

# Show print statements
pytest tests/test_ksi_analyzers.py -s

# Full traceback
pytest tests/test_ksi_analyzers.py --tb=long

# Drop into debugger on failure
pytest tests/test_ksi_analyzers.py --pdb
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Test Suite

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install pytest pytest-asyncio
    
    - name: Run tests
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      run: |
        python tests/run_all_tests.py
```

### Pre-Commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
set -e

echo "Running FedRAMP 20x MCP tests..."
python tests/run_all_tests.py

if [ $? -ne 0 ]; then
    echo "Tests failed! Commit aborted."
    exit 1
fi

echo "All tests passed!"
```

Make executable:
```powershell
chmod +x .git/hooks/pre-commit
```

## Best Practices

### Before Committing

**ALWAYS** run the full test suite before committing:

```powershell
# 1. Set GitHub token
$env:GITHUB_TOKEN = (gh auth token)

# 2. Run all tests
python tests/run_all_tests.py

# 3. Verify ALL tests pass

# 4. Only then commit
git add .
git commit -m "Your changes"
```

### Test-Driven Development

1. **Write test first** - Define expected behavior
2. **Run test** - Verify it fails
3. **Implement feature** - Make test pass
4. **Refactor** - Improve code while keeping tests green
5. **Repeat**

### Continuous Testing

- Run tests frequently during development
- Run specific test files for components you're working on
- Run full suite before pushing to repository
- Monitor test execution time - optimize slow tests

## Test Metrics

### Expected Test Counts

- **Data Loader**: ~8 tests
- **CVE Fetcher**: ~7 tests
- **Pattern Engine**: ~12 tests
- **KSI Analyzers**: ~15 tests (covering all families)
- **FRR Analyzers**: ~15 tests (covering all families)
- **MCP Tools**: ~48 tests (covering all 48 tools)

**Total**: ~87 tests

### Expected Runtime

- **Individual test file**: 10-60 seconds
- **Full test suite**: 2-5 minutes (depending on network)
- **With CVE scanning**: +30 seconds

## Support

### Getting Help

If tests fail:

1. Check this documentation for troubleshooting
2. Review test output for specific errors
3. Verify prerequisites are installed
4. Check pattern files are valid YAML
5. Ensure GitHub token is set for CVE tests

### Reporting Issues

When reporting test failures, include:

- Test file and test name
- Full error output
- Python version: `python --version`
- Pytest version: `pytest --version`
- Operating system
- Whether GitHub token is set

## Appendix

### Pattern File Locations

```
data/patterns/
├── iam_patterns.yaml
├── vdr_patterns.yaml
├── scn_patterns.yaml
├── rsc_patterns.yaml
├── ads_patterns.yaml
├── ccm_patterns.yaml
├── cna_patterns.yaml
├── afr_patterns.yaml
├── mla_patterns.yaml
├── piy_patterns.yaml
├── svc_patterns.yaml
├── tpr_patterns.yaml
├── ucm_patterns.yaml
├── cmt_patterns.yaml
├── inr_patterns.yaml
├── rpl_patterns.yaml
├── ced_patterns.yaml
└── common_patterns.yaml
```

### Test File Locations

```
tests/
├── run_all_tests.py           # Main test runner
├── conftest.py                # Pytest configuration
├── test_data_loader.py        # Data loader tests
├── test_cve_fetcher.py        # CVE fetcher tests
├── test_pattern_engine.py     # Pattern engine tests
├── test_ksi_analyzers.py      # KSI analyzer tests
├── test_frr_analyzers.py      # FRR analyzer tests
├── test_mcp_tools.py          # MCP tools tests
├── test_code_enrichment.py    # Code enrichment tests
└── test_*_patterns.py         # 18 pattern-specific test files
```

---

**Last Updated**: December 15, 2025  
**Version**: 1.0.0  
**Test Coverage**: Core modules, patterns, KSI/FRR analyzers, all 48 MCP tools
