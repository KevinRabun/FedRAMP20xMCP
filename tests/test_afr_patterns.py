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

class TestAfrPatterns:
    """Test AFR pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_afr_crypto_weak_algorithms_positive(self, analyzer):
        """Test afr.crypto.weak_algorithms: Weak or Deprecated Cryptographic Algorithms - Should detect"""
        code = """import hashlib

result = hashlib.md5(data.encode())
print(result.hexdigest())"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.crypto.weak_algorithms" == f.pattern_id]
        assert len(findings) > 0, f"Pattern afr.crypto.weak_algorithms should detect this code"
    
    def test_afr_crypto_weak_algorithms_negative(self, analyzer):
        """Test afr.crypto.weak_algorithms: Weak or Deprecated Cryptographic Algorithms - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.crypto.weak_algorithms" == f.pattern_id]
        assert len(findings) == 0, f"Pattern afr.crypto.weak_algorithms should NOT detect compliant code"


    def test_afr_config_debug_mode_positive(self, analyzer):
        """Test afr.config.debug_mode: Debug Mode Enabled in Production - Should detect"""
        code = """DEBUG = True
app.debug = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.config.debug_mode" == f.pattern_id]
        assert len(findings) > 0, f"Pattern afr.config.debug_mode should detect this code"
    
    def test_afr_config_debug_mode_negative(self, analyzer):
        """Test afr.config.debug_mode: Debug Mode Enabled in Production - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.config.debug_mode" == f.pattern_id]
        assert len(findings) == 0, f"Pattern afr.config.debug_mode should NOT detect compliant code"


    def test_afr_scanning_missing_vulnerability_scan_positive(self, analyzer):
        """Test afr.scanning.missing_vulnerability_scan: Missing Vulnerability Scanning Configuration - Should detect"""
        code = """name: Security Scanning
on: [push]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
      - uses: github/codeql-action/analyze@v3"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.scanning.missing_vulnerability_scan" == f.pattern_id]
        assert len(findings) > 0, f"Pattern afr.scanning.missing_vulnerability_scan should detect this code"
    
    def test_afr_scanning_missing_vulnerability_scan_negative(self, analyzer):
        """Test afr.scanning.missing_vulnerability_scan: Missing Vulnerability Scanning Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.scanning.missing_vulnerability_scan" == f.pattern_id]
        assert len(findings) == 0, f"Pattern afr.scanning.missing_vulnerability_scan should NOT detect compliant code"


    def test_afr_config_insecure_defaults_positive(self, analyzer):
        """Test afr.config.insecure_defaults: Insecure Default Configurations Detected - Should detect"""
        code = """resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  properties: {
    supportsHttpsTrafficOnly: false
    publicNetworkAccess: 'Enabled'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.config.insecure_defaults" == f.pattern_id]
        assert len(findings) > 0, f"Pattern afr.config.insecure_defaults should detect this code"
    
    def test_afr_config_insecure_defaults_negative(self, analyzer):
        """Test afr.config.insecure_defaults: Insecure Default Configurations Detected - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "afr.config.insecure_defaults" == f.pattern_id]
        assert len(findings) == 0, f"Pattern afr.config.insecure_defaults should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
