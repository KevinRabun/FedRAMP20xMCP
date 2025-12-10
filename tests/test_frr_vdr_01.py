"""
Test FRR-VDR-01: Vulnerability Detection analyzer

Tests detection of missing vulnerability scanning in:
- GitHub Actions workflows
- Azure Pipelines YAML
- GitLab CI configurations  
- Bicep infrastructure templates
- Terraform configurations
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_01 import FRR_VDR_01_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_github_actions_missing_container_scan():
    """Test detection of container build without vulnerability scanning."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: docker build -t myapp:latest .
      - run: docker push myapp:latest
"""
    
    result = analyzer.analyze(code, "github_actions", "build.yml")
    
    assert result.total_issues > 0, "Should detect missing container scan"
    assert any("container" in f.title.lower() and "scan" in f.title.lower() for f in result.findings), \
        "Should have finding about missing container scanning"
    assert any(f.severity == Severity.HIGH for f in result.findings), \
        "Container without scan should be HIGH severity"
    
    print("✓ GitHub Actions missing container scan detected")


def test_github_actions_missing_sast():
    """Test detection of missing SAST in workflow."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install
      - run: npm test
"""
    
    result = analyzer.analyze(code, "github_actions", "ci.yml")
    
    assert result.total_issues > 0, "Should detect missing SAST"
    assert any("sast" in f.title.lower() or "static application security" in f.description.lower() 
               for f in result.findings), \
        "Should have finding about missing SAST"
    
    print("✓ GitHub Actions missing SAST detected")


def test_github_actions_missing_dependency_scan():
    """Test detection of missing dependency scanning."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install
      - run: npm run build
"""
    
    result = analyzer.analyze(code, "github_actions", "build.yml")
    
    assert result.total_issues > 0, "Should detect missing dependency scan"
    assert any("dependency" in f.title.lower() for f in result.findings), \
        "Should have finding about missing dependency scanning"
    
    print("✓ GitHub Actions missing dependency scan detected")


def test_github_actions_with_all_scanners():
    """Test that workflow with all scanners has no findings."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
name: Secure Build
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build container
        run: docker build -t myapp:latest .
      
      - name: Scan container
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:latest
      
      - name: CodeQL Analysis
        uses: github/codeql-action/analyze@v2
      
      - name: Dependency Review
        uses: actions/dependency-review-action@v3
"""
    
    result = analyzer.analyze(code, "github_actions", "secure.yml")
    
    if result.total_issues > 0:
        print(f"  DEBUG: Found {result.total_issues} issues in complete workflow:")
        for f in result.findings:
            print(f"    - {f.title}")
    
    assert result.total_issues == 0, f"Complete workflow should have no findings, but found {result.total_issues}: {[f.title for f in result.findings]}"
    
    print("✓ GitHub Actions with all scanners: no findings")


def test_azure_pipelines_missing_security_devops():
    """Test detection of missing Microsoft Security DevOps task."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
trigger:
  - main

pool:
  vmImage: ubuntu-latest

steps:
  - task: Docker@2
    inputs:
      command: build
      tags: |
        latest
"""
    
    result = analyzer.analyze(code, "azure_pipelines", "azure-pipelines.yml")
    
    assert result.total_issues > 0, "Should detect missing security task"
    assert any("microsoft security devops" in f.title.lower() for f in result.findings), \
        "Should have finding about missing MicrosoftSecurityDevOps task"
    
    print("✓ Azure Pipelines missing security task detected")


def test_gitlab_ci_missing_scanning_templates():
    """Test detection of missing GitLab security templates."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
stages:
  - build

build-job:
  stage: build
  script:
    - docker build -t myapp .
"""
    
    result = analyzer.analyze(code, "gitlab_ci", ".gitlab-ci.yml")
    
    assert result.total_issues > 0, "Should detect missing security templates"
    assert any("dependency" in f.title.lower() or "sast" in f.title.lower() or "container" in f.title.lower() 
               for f in result.findings), \
        "Should have findings about missing security templates"
    
    print("✓ GitLab CI missing security templates detected")


def test_bicep_missing_defender():
    """Test detection of VMs without Defender for Cloud."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: resourceGroup().location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
  }
}
"""
    
    result = analyzer.analyze(code, "bicep", "vm.bicep")
    
    assert result.total_issues > 0, "Should detect missing Defender for Cloud"
    assert any("defender" in f.title.lower() for f in result.findings), \
        "Should have finding about missing Defender configuration"
    
    print("✓ Bicep missing Defender for Cloud detected")


def test_terraform_missing_defender():
    """Test detection of compute without Defender for Cloud in Terraform."""
    analyzer = FRR_VDR_01_Analyzer()
    
    code = """
resource "azurerm_linux_virtual_machine" "main" {
  name                = "myvm"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_D2s_v3"
  
  admin_username = "adminuser"
}
"""
    
    result = analyzer.analyze(code, "terraform", "main.tf")
    
    assert result.total_issues > 0, "Should detect missing Defender for Cloud"
    assert any("defender" in f.title.lower() for f in result.findings), \
        "Should have finding about missing Defender configuration"
    
    print("✓ Terraform missing Defender for Cloud detected")


def test_frr_vdr_01_metadata():
    """Test FRR-VDR-01 analyzer metadata."""
    analyzer = FRR_VDR_01_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-01"
    assert analyzer.FAMILY == "VDR"
    assert analyzer.CODE_DETECTABLE == True
    assert analyzer.IMPLEMENTATION_STATUS == "IMPLEMENTED"
    assert "KSI-AFR-04" in analyzer.RELATED_KSIS
    assert len(analyzer.NIST_CONTROLS) >= 5
    
    print("✓ FRR-VDR-01 metadata validated")


def test_evidence_automation():
    """Test evidence automation recommendations."""
    analyzer = FRR_VDR_01_Analyzer()
    
    evidence = analyzer.get_evidence_automation_recommendations()
    
    assert evidence["frr_id"] == "FRR-VDR-01"
    assert "azure_services" in evidence
    assert len(evidence["azure_services"]) > 0
    assert "Microsoft Defender for Cloud" in evidence["azure_services"]
    
    queries = analyzer.get_evidence_collection_queries()
    assert len(queries) >= 3
    assert any(q["query_type"] == "Azure Monitor KQL" for q in queries)
    
    artifacts = analyzer.get_evidence_artifacts()
    assert len(artifacts) >= 4
    
    print("✓ Evidence automation validated")


def run_all_tests():
    """Run all FRR-VDR-01 tests."""
    print("\n" + "="*70)
    print("Testing FRR-VDR-01: Vulnerability Detection Analyzer")
    print("="*70 + "\n")
    
    tests = [
        test_github_actions_missing_container_scan,
        test_github_actions_missing_sast,
        test_github_actions_missing_dependency_scan,
        test_github_actions_with_all_scanners,
        test_azure_pipelines_missing_security_devops,
        test_gitlab_ci_missing_scanning_templates,
        test_bicep_missing_defender,
        test_terraform_missing_defender,
        test_frr_vdr_01_metadata,
        test_evidence_automation
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"✗ {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"✗ {test.__name__}: Unexpected error: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
