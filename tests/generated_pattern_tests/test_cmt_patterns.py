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
        code = """# Code that triggers cmt.vcs.repository_integration"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "cmt.vcs.repository_integration" in f.requirement_id]
        assert len(findings) > 0, f"Pattern cmt.vcs.repository_integration should detect this code"
    
    def test_cmt_vcs_repository_integration_negative(self, analyzer):
        """Test cmt.vcs.repository_integration: Version Control Integration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "cmt.vcs.repository_integration" in f.requirement_id]
        assert len(findings) == 0, f"Pattern cmt.vcs.repository_integration should NOT detect compliant code"


    def test_cmt_vcs_missing_integration_positive(self, analyzer):
        """Test cmt.vcs.missing_integration: Missing Version Control - Should detect"""
        code = """# Code that triggers cmt.vcs.missing_integration"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "cmt.vcs.missing_integration" in f.requirement_id]
        assert len(findings) > 0, f"Pattern cmt.vcs.missing_integration should detect this code"
    
    def test_cmt_vcs_missing_integration_negative(self, analyzer):
        """Test cmt.vcs.missing_integration: Missing Version Control - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "cmt.vcs.missing_integration" in f.requirement_id]
        assert len(findings) == 0, f"Pattern cmt.vcs.missing_integration should NOT detect compliant code"


    def test_cmt_testing_pre_deploy_gates_positive(self, analyzer):
        """Test cmt.testing.pre_deploy_gates: Pre-Deployment Testing Gates - Should detect"""
        code = """# Code that triggers cmt.testing.pre_deploy_gates"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "cmt.testing.pre_deploy_gates" in f.requirement_id]
        assert len(findings) > 0, f"Pattern cmt.testing.pre_deploy_gates should detect this code"
    
    def test_cmt_testing_pre_deploy_gates_negative(self, analyzer):
        """Test cmt.testing.pre_deploy_gates: Pre-Deployment Testing Gates - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "cmt.testing.pre_deploy_gates" in f.requirement_id]
        assert len(findings) == 0, f"Pattern cmt.testing.pre_deploy_gates should NOT detect compliant code"


    def test_cmt_rollback_deployment_strategy_positive(self, analyzer):
        """Test cmt.rollback.deployment_strategy: Rollback Capability - Should detect"""
        code = """// Bicep code for cmt.rollback.deployment_strategy
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "cmt.rollback.deployment_strategy" in f.requirement_id]
        assert len(findings) > 0, f"Pattern cmt.rollback.deployment_strategy should detect this code"
    
    def test_cmt_rollback_deployment_strategy_negative(self, analyzer):
        """Test cmt.rollback.deployment_strategy: Rollback Capability - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "cmt.rollback.deployment_strategy" in f.requirement_id]
        assert len(findings) == 0, f"Pattern cmt.rollback.deployment_strategy should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
