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

class TestTprPatterns:
    """Test TPR pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_tpr_dependencies_unverified_positive(self, analyzer):
        """Test tpr.dependencies.unverified: Unverified Third-Party Dependencies - Should detect"""
        code = """# Code that triggers tpr.dependencies.unverified
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "tpr.dependencies.unverified" in f.requirement_id]
        assert len(findings) > 0, f"Pattern tpr.dependencies.unverified should detect this code"
    
    def test_tpr_dependencies_unverified_negative(self, analyzer):
        """Test tpr.dependencies.unverified: Unverified Third-Party Dependencies - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "tpr.dependencies.unverified" in f.requirement_id]
        assert len(findings) == 0, f"Pattern tpr.dependencies.unverified should NOT detect compliant code"


    def test_tpr_monitoring_supply_chain_missing_positive(self, analyzer):
        """Test tpr.monitoring.supply_chain_missing: Missing Supply Chain Security Monitoring - Should detect"""
        code = """# Code that triggers tpr.monitoring.supply_chain_missing
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "tpr.monitoring.supply_chain_missing" in f.requirement_id]
        assert len(findings) > 0, f"Pattern tpr.monitoring.supply_chain_missing should detect this code"
    
    def test_tpr_monitoring_supply_chain_missing_negative(self, analyzer):
        """Test tpr.monitoring.supply_chain_missing: Missing Supply Chain Security Monitoring - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "tpr.monitoring.supply_chain_missing" in f.requirement_id]
        assert len(findings) == 0, f"Pattern tpr.monitoring.supply_chain_missing should NOT detect compliant code"


    def test_tpr_sources_insecure_positive(self, analyzer):
        """Test tpr.sources.insecure: Insecure Third-Party Package Sources - Should detect"""
        code = """# Code that triggers tpr.sources.insecure
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "tpr.sources.insecure" in f.requirement_id]
        assert len(findings) > 0, f"Pattern tpr.sources.insecure should detect this code"
    
    def test_tpr_sources_insecure_negative(self, analyzer):
        """Test tpr.sources.insecure: Insecure Third-Party Package Sources - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "tpr.sources.insecure" in f.requirement_id]
        assert len(findings) == 0, f"Pattern tpr.sources.insecure should NOT detect compliant code"


    def test_tpr_sbom_missing_positive(self, analyzer):
        """Test tpr.sbom.missing: Missing Software Bill of Materials (SBOM) - Should detect"""
        code = """# Code that triggers tpr.sbom.missing"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "tpr.sbom.missing" in f.requirement_id]
        assert len(findings) > 0, f"Pattern tpr.sbom.missing should detect this code"
    
    def test_tpr_sbom_missing_negative(self, analyzer):
        """Test tpr.sbom.missing: Missing Software Bill of Materials (SBOM) - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "tpr.sbom.missing" in f.requirement_id]
        assert len(findings) == 0, f"Pattern tpr.sbom.missing should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
