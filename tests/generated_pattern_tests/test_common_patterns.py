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

class TestCommonPatterns:
    """Test COMMON pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_common_tagging_required_tags_positive(self, analyzer):
        """Test common.tagging.required_tags: Required Azure Resource Tags - Should detect"""
        code = """// Bicep code for common.tagging.required_tags
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.tagging.required_tags" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.tagging.required_tags should detect this code"
    
    def test_common_tagging_required_tags_negative(self, analyzer):
        """Test common.tagging.required_tags: Required Azure Resource Tags - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.tagging.required_tags" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.tagging.required_tags should NOT detect compliant code"


    def test_common_diagnostics_missing_diagnostic_settings_positive(self, analyzer):
        """Test common.diagnostics.missing_diagnostic_settings: Missing Diagnostic Settings - Should detect"""
        code = """resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diagnostics'
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: []
    metrics: []
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.diagnostics.missing_diagnostic_settings" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.diagnostics.missing_diagnostic_settings should detect this code"
    
    def test_common_diagnostics_missing_diagnostic_settings_negative(self, analyzer):
        """Test common.diagnostics.missing_diagnostic_settings: Missing Diagnostic Settings - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.diagnostics.missing_diagnostic_settings" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.diagnostics.missing_diagnostic_settings should NOT detect compliant code"


    def test_common_identity_managed_identity_positive(self, analyzer):
        """Test common.identity.managed_identity: Managed Identity Usage - Should detect"""
        code = """from azure.identity.DefaultAzureCredential import *

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.identity.managed_identity" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.identity.managed_identity should detect this code"
    
    def test_common_identity_managed_identity_negative(self, analyzer):
        """Test common.identity.managed_identity: Managed Identity Usage - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.identity.managed_identity" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.identity.managed_identity should NOT detect compliant code"


    def test_common_network_public_access_enabled_positive(self, analyzer):
        """Test common.network.public_access_enabled: Public Network Access Enabled - Should detect"""
        code = """// Bicep code for common.network.public_access_enabled
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.network.public_access_enabled" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.network.public_access_enabled should detect this code"
    
    def test_common_network_public_access_enabled_negative(self, analyzer):
        """Test common.network.public_access_enabled: Public Network Access Enabled - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.network.public_access_enabled" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.network.public_access_enabled should NOT detect compliant code"


    def test_common_governance_azure_policy_positive(self, analyzer):
        """Test common.governance.azure_policy: Azure Policy Assignment - Should detect"""
        code = """// Bicep code for common.governance.azure_policy
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.governance.azure_policy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.governance.azure_policy should detect this code"
    
    def test_common_governance_azure_policy_negative(self, analyzer):
        """Test common.governance.azure_policy: Azure Policy Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.governance.azure_policy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.governance.azure_policy should NOT detect compliant code"


    def test_common_governance_resource_lock_positive(self, analyzer):
        """Test common.governance.resource_lock: Resource Lock - Should detect"""
        code = """// Bicep code for common.governance.resource_lock
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.governance.resource_lock" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.governance.resource_lock should detect this code"
    
    def test_common_governance_resource_lock_negative(self, analyzer):
        """Test common.governance.resource_lock: Resource Lock - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.governance.resource_lock" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.governance.resource_lock should NOT detect compliant code"


    def test_common_resilience_backup_missing_positive(self, analyzer):
        """Test common.resilience.backup_missing: Missing Backup Configuration - Should detect"""
        code = """// Bicep code for common.resilience.backup_missing
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.resilience.backup_missing" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.resilience.backup_missing should detect this code"
    
    def test_common_resilience_backup_missing_negative(self, analyzer):
        """Test common.resilience.backup_missing: Missing Backup Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.resilience.backup_missing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.resilience.backup_missing should NOT detect compliant code"


    def test_common_resilience_geo_redundancy_positive(self, analyzer):
        """Test common.resilience.geo_redundancy: Geo-Redundant Storage - Should detect"""
        code = """// Bicep code for common.resilience.geo_redundancy
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.resilience.geo_redundancy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern common.resilience.geo_redundancy should detect this code"
    
    def test_common_resilience_geo_redundancy_negative(self, analyzer):
        """Test common.resilience.geo_redundancy: Geo-Redundant Storage - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "common.resilience.geo_redundancy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern common.resilience.geo_redundancy should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
