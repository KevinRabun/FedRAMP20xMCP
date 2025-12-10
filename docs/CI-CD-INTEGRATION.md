# CI/CD Integration Guide

The FedRAMP 20x MCP Server supports **two distinct usage models**:

1. **Interactive Development** (VS Code + MCP): Real-time guidance for developers writing code
2. **Automated CI/CD** (Direct Analyzer Use): Automated compliance checking in pipelines

## Why Two Models?

**MCP Protocol Limitation:** The Model Context Protocol requires an LLM client (like Claude or GitHub Copilot) for human-in-the-loop interaction. This isn't available in automated CI/CD pipelines.

**Solution:** Use the underlying analyzer classes directly in CI/CD scripts, bypassing the MCP layer entirely.

## Architecture Overview

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

## GitHub Actions Integration

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

## Azure DevOps Integration

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

## Standalone Python Script

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

## Available Analyzers

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

## Analysis Result Structure

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

## CI/CD Best Practices

1. **Fail builds on high-priority issues**: Use exit codes to gate deployments
2. **Upload reports as artifacts**: Save compliance reports for audit trails
3. **Post PR comments**: Provide feedback directly in pull requests
4. **Cache dependencies**: Speed up pipeline runs by caching the fedramp-20x-mcp package
5. **Analyze changed files only**: Use git diff to target only modified files
6. **Run in parallel**: Analyze different file types concurrently for faster results

## Pre-commit Hooks

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

## See Also

- [CONTRIBUTING.md](../CONTRIBUTING.md) - Development setup and testing
- [examples/ci_cd_integration.py](../examples/ci_cd_integration.py) - Complete script example
- [.github/workflows/](../.github/workflows/) - GitHub Actions examples
- [.azuredevops/](../.azuredevops/) - Azure DevOps pipeline examples
