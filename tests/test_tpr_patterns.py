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
        code = """# Install packages without hash verification
pip install flask
pip install requests
pip install django
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.dependencies.unverified" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.dependencies.unverified" == f.pattern_id]
        assert len(findings) == 0, f"Pattern tpr.dependencies.unverified should NOT detect compliant code"


    def test_tpr_monitoring_supply_chain_missing_positive(self, analyzer):
        """Test tpr.monitoring.supply_chain_missing: Missing Supply Chain Security Monitoring - Should detect"""
        # GitHub Actions with dependency-review but not enabled/configured
        code = """name: CI Pipeline
on: [push]
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Dependency Review
        run: echo "dependency-review would run here"
      - name: Security Scan
        run: echo "security-scan placeholder"
"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.monitoring.supply_chain_missing" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.monitoring.supply_chain_missing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern tpr.monitoring.supply_chain_missing should NOT detect compliant code"


    def test_tpr_sources_insecure_positive(self, analyzer):
        """Test tpr.sources.insecure: Insecure Third-Party Package Sources - Should detect"""
        code = """# Install from insecure HTTP source
pip install --index-url http://pypi.example.com/simple requests
pip install --extra-index-url http://internal-repo.com/pypi django
pip install --trusted-host insecure-host.com flask
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.sources.insecure" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.sources.insecure" == f.pattern_id]
        assert len(findings) == 0, f"Pattern tpr.sources.insecure should NOT detect compliant code"


    def test_tpr_sbom_missing_positive(self, analyzer):
        """Test tpr.sbom.missing: Missing Software Bill of Materials (SBOM) - Should detect"""
        # GitHub Actions mentioning SBOM but not actually generating it
        code = """name: Build Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: echo "Building..."
      - name: SBOM Placeholder
        run: echo "bill-of-materials would be generated here" """
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.sbom.missing" == f.pattern_id]
        assert len(findings) > 0, f"Pattern tpr.sbom.missing should detect this code"
    
    def test_tpr_sbom_missing_negative(self, analyzer):
        """Test tpr.sbom.missing: Missing Software Bill of Materials (SBOM) - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "tpr.sbom.missing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern tpr.sbom.missing should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
