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

class TestRplPatterns:
    """Test RPL pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_rpl_storage_geo_redundancy_positive(self, analyzer):
        """Test rpl.storage.geo_redundancy: Geo-Redundant Storage Configuration - Should detect"""
        code = """resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true  // Potential issue
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rpl.storage.geo_redundancy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rpl.storage.geo_redundancy should detect this code"
    
    def test_rpl_storage_geo_redundancy_negative(self, analyzer):
        """Test rpl.storage.geo_redundancy: Geo-Redundant Storage Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rpl.storage.geo_redundancy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rpl.storage.geo_redundancy should NOT detect compliant code"


    def test_rpl_backup_missing_policy_positive(self, analyzer):
        """Test rpl.backup.missing_policy: Missing Backup Policy - Should detect"""
        code = """resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: 'eastus'
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_DS1_v2'
    }
  }
  // Missing backup vault configuration!
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rpl.backup.missing_policy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern rpl.backup.missing_policy should detect this code"
    
    def test_rpl_backup_missing_policy_negative(self, analyzer):
        """Test rpl.backup.missing_policy: Missing Backup Policy - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "rpl.backup.missing_policy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern rpl.backup.missing_policy should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
