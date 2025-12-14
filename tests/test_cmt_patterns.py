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

class TestCmtPatterns:
    """Test CMT pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_cmt_vcs_repository_integration_positive(self, analyzer):
        """Test cmt.vcs.repository_integration: Version Control Integration - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: echo "Building..." """
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.vcs.repository_integration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cmt.vcs.repository_integration should detect this code"
    
    def test_cmt_vcs_repository_integration_negative(self, analyzer):
        """Test cmt.vcs.repository_integration: Version Control Integration - Should NOT detect"""
        code = """name: Simple Pipeline
on: [manual]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: echo 'Building...'"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.vcs.repository_integration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cmt.vcs.repository_integration should NOT detect compliant code"


    def test_cmt_vcs_missing_integration_positive(self, analyzer):
        """Test cmt.vcs.missing_integration: Missing Version Control - Should detect"""
        code = """name: Deploy Pipeline
on: [workflow_dispatch]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Azure
        uses: azure/webapps-deploy@v2
        with:
          app-name: myapp
          package: ."""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.vcs.missing_integration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cmt.vcs.missing_integration should detect this code"
    
    def test_cmt_vcs_missing_integration_negative(self, analyzer):
        """Test cmt.vcs.missing_integration: Missing Version Control - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.vcs.missing_integration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cmt.vcs.missing_integration should NOT detect compliant code"


    def test_cmt_testing_pre_deploy_gates_positive(self, analyzer):
        """Test cmt.testing.pre_deploy_gates: Pre-Deployment Testing Gates - Should detect"""
        code = """name: CI/CD Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: npm test
  
  deploy:
    needs: [test]
    runs-on: ubuntu-latest
    steps:
      - uses: azure/webapps-deploy@v2"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.testing.pre_deploy_gates" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cmt.testing.pre_deploy_gates should detect this code"
    
    def test_cmt_testing_pre_deploy_gates_negative(self, analyzer):
        """Test cmt.testing.pre_deploy_gates: Pre-Deployment Testing Gates - Should NOT detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.testing.pre_deploy_gates" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cmt.testing.pre_deploy_gates should NOT detect compliant code"


    def test_cmt_rollback_deployment_strategy_positive(self, analyzer):
        """Test cmt.rollback.deployment_strategy: Rollback Capability - Should detect"""
        code = """resource webApp 'Microsoft.Web/sites@2022-09-01' = {
  name: appName
  location: location
}

resource stagingSlot 'Microsoft.Web/sites/slots@2022-09-01' = {
  name: '${webApp.name}/staging'
  location: location
  properties: {
    serverFarmId: webApp.properties.serverFarmId
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.rollback.deployment_strategy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cmt.rollback.deployment_strategy should detect this code"
    
    def test_cmt_rollback_deployment_strategy_negative(self, analyzer):
        """Test cmt.rollback.deployment_strategy: Rollback Capability - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cmt.rollback.deployment_strategy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cmt.rollback.deployment_strategy should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
