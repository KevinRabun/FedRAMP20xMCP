"""
Auto-generated tests for pattern detection.
Tests both positive cases (pattern should detect) and negative cases (should not detect).
"""
import pytest
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.generic_analyzer import GenericPatternAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity

class TestVdrPatterns:
    """Test VDR pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_vdr_scanning_defender_for_cloud_positive(self, analyzer):
        """Test vdr.scanning.defender_for_cloud: Microsoft Defender for Cloud - Should detect"""
        code = """resource defenderPricing 'Microsoft.Security/pricings@2024-01-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.defender_for_cloud" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.defender_for_cloud should detect this code"
    
    def test_vdr_scanning_defender_for_cloud_negative(self, analyzer):
        """Test vdr.scanning.defender_for_cloud: Microsoft Defender for Cloud - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.defender_for_cloud" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.defender_for_cloud should NOT detect compliant code"


    def test_vdr_scanning_ci_cd_scanning_positive(self, analyzer):
        """Test vdr.scanning.ci_cd_scanning: CI/CD Security Scanning - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run CodeQL Analysis
        uses: github/codeql-action/analyze@v2"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.ci_cd_scanning" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.ci_cd_scanning should detect this code"
    
    def test_vdr_scanning_ci_cd_scanning_negative(self, analyzer):
        """Test vdr.scanning.ci_cd_scanning: CI/CD Security Scanning - Should NOT detect"""
        code = """name: Simple Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: npm test"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.ci_cd_scanning" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.ci_cd_scanning should NOT detect compliant code"


    def test_vdr_scanning_missing_sast_positive(self, analyzer):
        """Test vdr.scanning.missing_sast: Missing SAST Scanning - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build application
        run: npm install && npm run build"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_sast" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.missing_sast should detect this code"
    
    def test_vdr_scanning_missing_sast_negative(self, analyzer):
        """Test vdr.scanning.missing_sast: Missing SAST Scanning - Should NOT detect"""
        code = """name: CI Pipeline with SAST
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_sast" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.missing_sast should NOT detect compliant code"


    def test_vdr_scanning_missing_container_scan_positive(self, analyzer):
        """Test vdr.scanning.missing_container_scan: Missing Container Image Scanning - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build application
        run: npm install && npm run build"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_container_scan" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.missing_container_scan should detect this code"
    
    def test_vdr_scanning_missing_container_scan_negative(self, analyzer):
        """Test vdr.scanning.missing_container_scan: Missing Container Image Scanning - Should NOT detect"""
        code = """name: Container Pipeline with Scanning
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build image
        run: docker build -t myapp:latest .
      - name: Scan container
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:latest"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_container_scan" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.missing_container_scan should NOT detect compliant code"


    def test_vdr_patching_update_management_positive(self, analyzer):
        """Test vdr.patching.update_management: Azure Update Management - Should detect"""
        code = """resource automationAccount 'Microsoft.Automation/automationAccounts@2023-11-01' = {
  name: 'myAutomationAccount'
  location: location
}

resource softwareUpdateConfigurations 'Microsoft.Automation/automationAccounts/softwareUpdateConfigurations@2023-11-01' = {
  parent: automationAccount
  name: 'weeklyPatching'
  properties: {
    scheduleInfo: { frequency: 'Week' }
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.update_management" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.patching.update_management should detect this code"
    
    def test_vdr_patching_update_management_negative(self, analyzer):
        """Test vdr.patching.update_management: Azure Update Management - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.update_management" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.patching.update_management should NOT detect compliant code"


    def test_vdr_patching_outdated_base_image_positive(self, analyzer):
        """Test vdr.patching.outdated_base_image: Outdated Container Base Image - Should detect"""
        code = """FROM python:3.9-slim
RUN pip install flask
COPY app.py /app/
CMD ["python", "/app/app.py"]"""
        
        result = analyzer.analyze(code, "dockerfile")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.outdated_base_image" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.patching.outdated_base_image should detect this code"
    
    def test_vdr_patching_outdated_base_image_negative(self, analyzer):
        """Test vdr.patching.outdated_base_image: Outdated Container Base Image - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "dockerfile")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.outdated_base_image" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.patching.outdated_base_image should NOT detect compliant code"


    def test_vdr_dependencies_dependabot_positive(self, analyzer):
        """Test vdr.dependencies.dependabot: Dependabot Configuration - Should detect"""
        code = """# Code that triggers vdr.dependencies.dependabot"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.dependabot" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.dependencies.dependabot should detect this code"
    
    def test_vdr_dependencies_dependabot_negative(self, analyzer):
        """Test vdr.dependencies.dependabot: Dependabot Configuration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.dependabot" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.dependencies.dependabot should NOT detect compliant code"


    def test_vdr_dependencies_outdated_packages_positive(self, analyzer):
        """Test vdr.dependencies.outdated_packages: Outdated Dependencies - Should detect"""
        code = """flask==2.0.1
requests==2.25.0
django==3.2.0
numpy==1.20.0"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.outdated_packages" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.dependencies.outdated_packages should detect this code"
    
    def test_vdr_dependencies_outdated_packages_negative(self, analyzer):
        """Test vdr.dependencies.outdated_packages: Outdated Dependencies - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.outdated_packages" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.dependencies.outdated_packages should NOT detect compliant code"


    def test_vdr_secure_dev_pre_commit_hooks_positive(self, analyzer):
        """Test vdr.secure_dev.pre_commit_hooks: Pre-Commit Hooks - Should detect"""
        code = """repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.4
    hooks:
      - id: bandit
        args: ['-r', 'src']"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.secure_dev.pre_commit_hooks" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.secure_dev.pre_commit_hooks should detect this code"
    
    def test_vdr_secure_dev_pre_commit_hooks_negative(self, analyzer):
        """Test vdr.secure_dev.pre_commit_hooks: Pre-Commit Hooks - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.secure_dev.pre_commit_hooks" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.secure_dev.pre_commit_hooks should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
