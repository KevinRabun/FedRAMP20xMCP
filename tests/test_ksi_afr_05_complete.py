"""
Comprehensive tests for KSI-AFR-05: Significant Change Notifications

Tests automated vulnerability scanning and notification detection across:
- GitHub Actions workflows
- Azure Pipelines
- Bicep IaC
"""

import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.ksi.ksi_afr_05 import KSI_AFR_05_Analyzer


def test_github_actions_with_codeql():
    """Test detection of CodeQL security scanning"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
name: Security Scanning
on: [push, pull_request]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: github/codeql-action/init@v2
        with:
          languages: python
      - uses: github/codeql-action/analyze@v2
      - name: Notify team
        uses: 8398a7/action-slack@v3
        with:
          status: ${{ job.status }}
"""
    
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/security.yml')
    
    # Should have no findings - has scanning and notifications
    print(f"CodeQL + Notifications test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with CodeQL and notifications, got: {result.findings}"
    print("  PASS - CodeQL + Notifications detected")


def test_github_actions_missing_scanner():
    """Test detection of missing security scanner"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: npm install
      - run: npm test
"""
    
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/build.yml')
    
    # Should detect missing security scanning
    print(f"Missing scanner test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('security scanning' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing scanner detected")


def test_github_actions_scanner_no_notifications():
    """Test detection of scanner without notifications"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
name: Security
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
"""
    
    result = analyzer.analyze(code, 'github-actions', '.github/workflows/scan.yml')
    
    # Should detect missing notifications
    print(f"Scanner without notifications test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('notification' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing notifications detected")


def test_azure_pipelines_with_security_tasks():
    """Test detection of Azure Pipelines security tasks"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
trigger:
  - main

pool:
  vmImage: 'windows-latest'

steps:
- task: CredScan@3
  inputs:
    outputFormat: 'sarif'

- task: Semmle@1
  inputs:
    sourceCodeDirectory: '$(Build.SourcesDirectory)'
    
- task: PublishSecurityAnalysisLogs@3
"""
    
    result = analyzer.analyze(code, 'azure-pipelines', 'azure-pipelines.yml')
    
    # Should pass - has security scanning
    print(f"Azure Pipelines security tasks test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with security tasks, got: {result.findings}"
    print("  PASS - Azure security tasks detected")


def test_azure_pipelines_missing_security():
    """Test detection of missing security tasks"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: DotNetCoreCLI@2
  inputs:
    command: 'build'
    
- task: DotNetCoreCLI@2
  inputs:
    command: 'test'
"""
    
    result = analyzer.analyze(code, 'azure-pipelines', 'azure-pipelines.yml')
    
    # Should detect missing security tasks
    print(f"Missing security tasks test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('security scanning' in f.title.lower() for f in result.findings)
    print("  PASS - Missing security tasks detected")


def test_bicep_with_monitoring():
    """Test detection of Azure Monitor resources"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'security-alerts'
  location: 'global'
  properties: {
    enabled: true
    emailReceivers: [
      {
        name: 'SecurityTeam'
        emailAddress: 'security@example.com'
      }
    ]
  }
}

resource metricAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'vulnerabilities-detected'
  location: 'global'
  properties: {
    enabled: true
    severity: 2
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
    criteria: {
      allOf: [
        {
          name: 'VulnerabilityCount'
          metricName: 'Vulnerabilities'
          operator: 'GreaterThan'
          threshold: 0
        }
      ]
    }
  }
}
"""
    
    result = analyzer.analyze(code, 'bicep', 'monitoring.bicep')
    
    # Should pass - has alerts and action groups
    print(f"Bicep monitoring test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with monitoring, got: {result.findings}"
    print("  PASS - Azure Monitor resources detected")


def test_bicep_missing_alerts():
    """Test detection of missing alert rules"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
}
"""
    
    result = analyzer.analyze(code, 'bicep', 'storage.bicep')
    
    # Should detect missing monitoring
    print(f"Missing alerts test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('monitor' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing alerts detected")


def test_bicep_alerts_no_action_groups():
    """Test detection of alerts without action groups"""
    analyzer = KSI_AFR_05_Analyzer()
    
    code = """
resource metricAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'cpu-alert'
  location: 'global'
  properties: {
    enabled: true
    criteria: {
      allOf: [
        {
          name: 'CPUPercentage'
          metricName: 'Percentage CPU'
          operator: 'GreaterThan'
          threshold: 80
        }
      ]
    }
  }
}
"""
    
    result = analyzer.analyze(code, 'bicep', 'alerts.bicep')
    
    # Should detect missing action groups
    print(f"Alerts without action groups test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('action group' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing action groups detected")


def run_all_tests():
    """Run all KSI-AFR-05 tests"""
    print("=" * 70)
    print("KSI-AFR-05: Significant Change Notifications - Complete Test Suite")
    print("=" * 70)
    
    tests = [
        ("GitHub Actions - CodeQL + Notifications", test_github_actions_with_codeql),
        ("GitHub Actions - Missing Scanner", test_github_actions_missing_scanner),
        ("GitHub Actions - Scanner No Notifications", test_github_actions_scanner_no_notifications),
        ("Azure Pipelines - Security Tasks", test_azure_pipelines_with_security_tasks),
        ("Azure Pipelines - Missing Security", test_azure_pipelines_missing_security),
        ("Bicep - Complete Monitoring", test_bicep_with_monitoring),
        ("Bicep - Missing Alerts", test_bicep_missing_alerts),
        ("Bicep - Alerts No Action Groups", test_bicep_alerts_no_action_groups),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\nTest: {test_name}")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL - {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR - {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 70)
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)


