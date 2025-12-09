"""
Tests for KSI-TPR-04 Enhanced: Supply Chain Risk Monitoring

Tests automated vulnerability scanning detection in:
- CI/CD pipelines (GitHub Actions, Azure Pipelines, GitLab CI)
- IaC (Bicep, Terraform - Container Registry without Defender)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_tpr_04 import KSI_TPR_04_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage


def test_github_actions_missing_scan():
    """Test detection of GitHub Actions without dependency scanning."""
    code = """
name: CI
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: npm install && npm build
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "github_actions", ".github/workflows/ci.yml")
    
    print(f"\n[GitHub Actions Missing Scan] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Dependency" in f.title and "Vulnerability" in f.title for f in result.findings)
    print("[PASS] GitHub Actions missing dependency scanning detected")


def test_github_actions_with_dependency_review():
    """Test recognition of GitHub Actions with dependency-review-action."""
    code = """
name: CI
on: [pull_request]
jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dependency Review
        uses: actions/dependency-review-action@v4
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "github_actions", ".github/workflows/ci.yml")
    
    print(f"\n[GitHub Actions With Dependency Review] Findings: {result.total_issues}")
    
    # Should pass - has dependency scanning
    assert result.total_issues == 0
    print("[PASS] GitHub Actions with dependency-review-action recognized")


def test_github_actions_with_snyk():
    """Test recognition of GitHub Actions with Snyk scanning."""
    code = """
name: Security
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "github_actions", ".github/workflows/security.yml")
    
    print(f"\n[GitHub Actions With Snyk] Findings: {result.total_issues}")
    
    # Should pass - has Snyk scanning
    assert result.total_issues == 0
    print("[PASS] GitHub Actions with Snyk recognized")


def test_azure_pipelines_missing_scan():
    """Test detection of Azure Pipelines without dependency scanning."""
    code = """
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: NuGetCommand@2
  inputs:
    command: 'restore'
- task: VSBuild@1
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "azure_pipelines", "azure-pipelines.yml")
    
    print(f"\n[Azure Pipelines Missing Scan] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Dependency" in f.title and "Vulnerability" in f.title for f in result.findings)
    print("[PASS] Azure Pipelines missing dependency scanning detected")


def test_azure_pipelines_with_msdo():
    """Test recognition of Azure Pipelines with Microsoft Security DevOps."""
    code = """
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: MicrosoftSecurityDevOps@1
  displayName: 'Run Microsoft Security DevOps'
  inputs:
    categories: 'dependencies'
- task: NuGetCommand@2
  inputs:
    command: 'restore'
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "azure_pipelines", "azure-pipelines.yml")
    
    print(f"\n[Azure Pipelines With MSDO] Findings: {result.total_issues}")
    
    # Should pass - has MSDO scanning
    assert result.total_issues == 0
    print("[PASS] Azure Pipelines with Microsoft Security DevOps recognized")


def test_azure_pipelines_with_whitesource():
    """Test recognition of Azure Pipelines with WhiteSource/Mend."""
    code = """
trigger:
- main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: WhiteSource@21
  inputs:
    cwd: '$(System.DefaultWorkingDirectory)'
    projectName: 'MyProject'
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "azure_pipelines", "azure-pipelines.yml")
    
    print(f"\n[Azure Pipelines With WhiteSource] Findings: {result.total_issues}")
    
    # Should pass - has WhiteSource scanning
    assert result.total_issues == 0
    print("[PASS] Azure Pipelines with WhiteSource recognized")


def test_gitlab_ci_missing_scan():
    """Test detection of GitLab CI without dependency scanning."""
    code = """
stages:
  - build
  - test

build:
  stage: build
  script:
    - npm install
    - npm build
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "gitlab_ci", ".gitlab-ci.yml")
    
    print(f"\n[GitLab CI Missing Scan] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Dependency" in f.title and "Vulnerability" in f.title for f in result.findings)
    print("[PASS] GitLab CI missing dependency scanning detected")


def test_gitlab_ci_with_dependency_scanning():
    """Test recognition of GitLab CI with dependency scanning template."""
    code = """
include:
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

stages:
  - build
  - test

build:
  stage: build
  script:
    - npm install
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "gitlab_ci", ".gitlab-ci.yml")
    
    print(f"\n[GitLab CI With Dependency Scanning] Findings: {result.total_issues}")
    
    # Should pass - has dependency scanning template
    assert result.total_issues == 0
    print("[PASS] GitLab CI with dependency scanning recognized")


def test_bicep_acr_without_defender():
    """Test detection of Azure Container Registry without Defender."""
    code = """
resource acr 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: 'myregistry'
  location: 'eastus'
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
  }
}
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "bicep", "main.bicep")
    
    print(f"\n[Bicep ACR Without Defender] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Container Registry" in f.title and "Vulnerability" in f.title for f in result.findings)
    print("[PASS] Bicep ACR without Defender detected")


def test_bicep_acr_with_defender():
    """Test recognition of Azure Container Registry with Defender."""
    code = """
resource acr 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {
  name: 'myregistry'
  location: 'eastus'
  sku: {
    name: 'Premium'
  }
}

resource defender 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'ContainerRegistry'
  properties: {
    pricingTier: 'Standard'  // Enables vulnerability scanning
  }
}
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "bicep", "main.bicep")
    
    print(f"\n[Bicep ACR With Defender] Findings: {result.total_issues}")
    
    # Should pass - has Defender enabled
    assert result.total_issues == 0
    print("[PASS] Bicep ACR with Defender recognized")


def test_terraform_acr_without_defender():
    """Test detection of Azure Container Registry without Defender."""
    code = """
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
  admin_enabled       = false
}
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "terraform", "main.tf")
    
    print(f"\n[Terraform ACR Without Defender] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Container Registry" in f.title and "Vulnerability" in f.title for f in result.findings)
    print("[PASS] Terraform ACR without Defender detected")


def test_terraform_acr_with_defender():
    """Test recognition of Azure Container Registry with Defender."""
    code = """
resource "azurerm_container_registry" "acr" {
  name                = "myregistry"
  resource_group_name = azurerm_resource_group.rg.name
  location            = azurerm_resource_group.rg.location
  sku                 = "Premium"
}

resource "azurerm_security_center_subscription_pricing" "containers" {
  tier          = "Standard"
  resource_type = "ContainerRegistry"
}
"""
    analyzer = KSI_TPR_04_Analyzer()
    result = analyzer.analyze(code, "terraform", "main.tf")
    
    print(f"\n[Terraform ACR With Defender] Findings: {result.total_issues}")
    
    # Should pass - has Defender enabled
    assert result.total_issues == 0
    print("[PASS] Terraform ACR with Defender recognized")


def test_factory_function():
    """Test that KSI-TPR-04 analyzer can be retrieved via factory."""
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    
    # Test factory knows about KSI-TPR-04
    ksi_ids = factory.list_ksis()
    assert "KSI-TPR-04" in ksi_ids
    
    print("[PASS] Factory function works correctly")


if __name__ == "__main__":
    print("=== KSI-TPR-04 Enhanced Analyzer Tests ===\n")
    
    tests = [
        test_github_actions_missing_scan,
        test_github_actions_with_dependency_review,
        test_github_actions_with_snyk,
        test_azure_pipelines_missing_scan,
        test_azure_pipelines_with_msdo,
        test_azure_pipelines_with_whitesource,
        test_gitlab_ci_missing_scan,
        test_gitlab_ci_with_dependency_scanning,
        test_bicep_acr_without_defender,
        test_bicep_acr_with_defender,
        test_terraform_acr_without_defender,
        test_terraform_acr_with_defender,
        test_factory_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed}/{len(tests)} passed")
    if failed > 0:
        print(f"{failed} test(s) failed")
    else:
        print("ALL TESTS PASSED!")
    print(f"{'='*60}\n")
    
    sys.exit(0 if failed == 0 else 1)

