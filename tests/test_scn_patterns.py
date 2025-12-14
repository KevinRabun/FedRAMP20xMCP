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

class TestScnPatterns:
    """Test SCN pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_scn_sast_tool_integration_positive(self, analyzer):
        """Test scn.sast.tool_integration: SAST Tool Integration - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run SAST scan
        run: semgrep --config=auto ."""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.sast.tool_integration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.sast.tool_integration should detect this code"
    
    def test_scn_sast_tool_integration_negative(self, analyzer):
        """Test scn.sast.tool_integration: SAST Tool Integration - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.sast.tool_integration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.sast.tool_integration should NOT detect compliant code"


    def test_scn_sca_dependency_scanning_positive(self, analyzer):
        """Test scn.sca.dependency_scanning: Software Composition Analysis (SCA) - Should detect"""
        code = """name: Security Scan
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Dependency Scan
        run: npm audit
      - name: Snyk Test
        run: snyk test"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.sca.dependency_scanning" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.sca.dependency_scanning should detect this code"
    
    def test_scn_sca_dependency_scanning_negative(self, analyzer):
        """Test scn.sca.dependency_scanning: Software Composition Analysis (SCA) - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.sca.dependency_scanning" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.sca.dependency_scanning should NOT detect compliant code"


    def test_scn_container_image_scanning_positive(self, analyzer):
        """Test scn.container.image_scanning: Container Image Scanning - Should detect"""
        code = """name: Container Scan
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Scan Container Image
        run: trivy image myapp:latest
      - name: Docker Scan
        run: docker scan myapp:latest"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.container.image_scanning" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.container.image_scanning should detect this code"
    
    def test_scn_container_image_scanning_negative(self, analyzer):
        """Test scn.container.image_scanning: Container Image Scanning - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.container.image_scanning" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.container.image_scanning should NOT detect compliant code"


    def test_scn_iac_security_scanning_positive(self, analyzer):
        """Test scn.iac.security_scanning: IaC Security Scanning - Should detect"""
        code = """name: IaC Security
on: [push]
jobs:
  iac_scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Checkov Scan
        run: checkov -d .
      - name: TFSec Scan
        run: tfsec ."""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.iac.security_scanning" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.iac.security_scanning should detect this code"
    
    def test_scn_iac_security_scanning_negative(self, analyzer):
        """Test scn.iac.security_scanning: IaC Security Scanning - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.iac.security_scanning" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.iac.security_scanning should NOT detect compliant code"


    def test_scn_secrets_scanning_positive(self, analyzer):
        """Test scn.secrets.scanning: Secrets Scanning - Should detect"""
        code = """name: Secrets Scan
on: [push]
jobs:
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: GitLeaks Scan
        run: gitleaks detect --source .
      - name: TruffleHog
        run: trufflehog filesystem ."""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.secrets.scanning" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.secrets.scanning should detect this code"
    
    def test_scn_secrets_scanning_negative(self, analyzer):
        """Test scn.secrets.scanning: Secrets Scanning - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.secrets.scanning" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.secrets.scanning should NOT detect compliant code"


    def test_scn_dast_dynamic_testing_positive(self, analyzer):
        """Test scn.dast.dynamic_testing: DAST Tool Integration - Should detect"""
        code = """name: DAST Scan
on: [push]
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - name: Run OWASP ZAP
        run: zap-baseline.py -t https://example.com"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.dast.dynamic_testing" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.dast.dynamic_testing should detect this code"
    
    def test_scn_dast_dynamic_testing_negative(self, analyzer):
        """Test scn.dast.dynamic_testing: DAST Tool Integration - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.dast.dynamic_testing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.dast.dynamic_testing should NOT detect compliant code"


    def test_scn_code_security_library_positive(self, analyzer):
        """Test scn.code.security_library: Security Library Integration - Should detect"""
        code = """import bandit

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.code.security_library" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.code.security_library should detect this code"
    
    def test_scn_code_security_library_negative(self, analyzer):
        """Test scn.code.security_library: Security Library Integration - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.code.security_library" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.code.security_library should NOT detect compliant code"


    def test_scn_policy_enforcement_positive(self, analyzer):
        """Test scn.policy.enforcement: Security Policy Enforcement - Should detect"""
        code = """apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    allowPrivilegeEscalation: false
  containers:
  - name: app
    image: nginx"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.policy.enforcement" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.policy.enforcement should detect this code"
    
    def test_scn_policy_enforcement_negative(self, analyzer):
        """Test scn.policy.enforcement: Security Policy Enforcement - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.policy.enforcement" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.policy.enforcement should NOT detect compliant code"


    def test_scn_iac_defender_for_cloud_positive(self, analyzer):
        """Test scn.iac.defender_for_cloud: Microsoft Defender for Cloud - Should detect"""
        code = """resource defenderPricing 'Microsoft.Security/pricings@2022-03-01' = {
  name: 'VirtualMachines'
  properties: {
    pricingTier: 'Standard'
  }
}

resource defenderContainers 'Microsoft.Security/pricings@2022-03-01' = {
  name: 'Containers'
  properties: {
    pricingTier: 'Standard'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.iac.defender_for_cloud" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.iac.defender_for_cloud should detect this code"
    
    def test_scn_iac_defender_for_cloud_negative(self, analyzer):
        """Test scn.iac.defender_for_cloud: Microsoft Defender for Cloud - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.iac.defender_for_cloud" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.iac.defender_for_cloud should NOT detect compliant code"


    def test_scn_iac_policy_assignment_positive(self, analyzer):
        """Test scn.iac.policy_assignment: Azure Policy Assignment - Should detect"""
        code = """resource policyAssignment 'Microsoft.Authorization/policyAssignments@2021-06-01' = {
  name: 'fedramp-baseline'
  properties: {
    policyDefinitionId: '/providers/Microsoft.Authorization/policySetDefinitions/xxxxxx'
    displayName: 'FedRAMP High Baseline'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.iac.policy_assignment" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.iac.policy_assignment should detect this code"
    
    def test_scn_iac_policy_assignment_negative(self, analyzer):
        """Test scn.iac.policy_assignment: Azure Policy Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.iac.policy_assignment" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.iac.policy_assignment should NOT detect compliant code"


    def test_scn_cicd_scan_gate_positive(self, analyzer):
        """Test scn.cicd.scan_gate: Security Scan Gate - Should detect"""
        code = """name: Security Gate
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: SAST Scan
        run: semgrep --config=auto . --severity=ERROR --fail-on-high
      - name: Check Vulnerabilities
        run: |
          if trivy image myapp | grep -q HIGH; then
            exit 1
          fi"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.cicd.scan_gate" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.cicd.scan_gate should detect this code"
    
    def test_scn_cicd_scan_gate_negative(self, analyzer):
        """Test scn.cicd.scan_gate: Security Scan Gate - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.cicd.scan_gate" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.cicd.scan_gate should NOT detect compliant code"


    def test_scn_missing_sast_positive(self, analyzer):
        """Test scn.missing_sast: Missing SAST Scanning - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.missing_sast" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.missing_sast should detect this code"
    
    def test_scn_missing_sast_negative(self, analyzer):
        """Test scn.missing_sast: Missing SAST Scanning - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.missing_sast" == f.pattern_id]
        assert len(findings) == 0, f"Pattern scn.missing_sast should NOT detect compliant code"


    def test_scn_missing_dependency_scan_positive(self, analyzer):
        """Test scn.missing_dependency_scan: Missing Dependency Scanning - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "scn.missing_dependency_scan" == f.pattern_id]
        assert len(findings) > 0, f"Pattern scn.missing_dependency_scan should detect this code"
    
    def test_scn_missing_dependency_scan_negative(self, analyzer):
        """Test scn.missing_dependency_scan: Missing Dependency Scanning - Should NOT detect"""
        code = """name: Pipeline with Dependency Scanning
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: NPM Audit
        run: npm audit
      - name: Snyk Test
        run: snyk test --severity-threshold=high"""
    pytest.main([__file__, "-v"])
