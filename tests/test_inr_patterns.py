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

class TestInrPatterns:
    """Test INR pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_inr_alerts_missing_configuration_positive(self, analyzer):
        """Test inr.alerts.missing_configuration: Missing Alert Rules - Should detect"""
        code = """resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'myWorkspace'
  location: 'eastus'
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "inr.alerts.missing_configuration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern inr.alerts.missing_configuration should detect this code"
    
    def test_inr_alerts_missing_configuration_negative(self, analyzer):
        """Test inr.alerts.missing_configuration: Missing Alert Rules - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "inr.alerts.missing_configuration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern inr.alerts.missing_configuration should NOT detect compliant code"


    def test_inr_logging_incident_tracking_positive(self, analyzer):
        """Test inr.logging.incident_tracking: Missing Incident Logging - Should detect"""
        code = """def process_data(data):
    try:
        result = risky_operation(data)
        return result
    except Exception as e:
        # No logging!
        return None"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "inr.logging.incident_tracking" == f.pattern_id]
        assert len(findings) > 0, f"Pattern inr.logging.incident_tracking should detect this code"
    
    def test_inr_logging_incident_tracking_negative(self, analyzer):
        """Test inr.logging.incident_tracking: Missing Incident Logging - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "inr.logging.incident_tracking" == f.pattern_id]
        assert len(findings) == 0, f"Pattern inr.logging.incident_tracking should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
