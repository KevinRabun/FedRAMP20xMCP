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
        code = """# Code that triggers scn.sast.tool_integration"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.sast.tool_integration" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.sast.tool_integration should detect this code"
    
    def test_scn_sast_tool_integration_negative(self, analyzer):
        """Test scn.sast.tool_integration: SAST Tool Integration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.sast.tool_integration" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.sast.tool_integration should NOT detect compliant code"


    def test_scn_sca_dependency_scanning_positive(self, analyzer):
        """Test scn.sca.dependency_scanning: Software Composition Analysis (SCA) - Should detect"""
        code = """# Code that triggers scn.sca.dependency_scanning"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.sca.dependency_scanning" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.sca.dependency_scanning should detect this code"
    
    def test_scn_sca_dependency_scanning_negative(self, analyzer):
        """Test scn.sca.dependency_scanning: Software Composition Analysis (SCA) - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.sca.dependency_scanning" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.sca.dependency_scanning should NOT detect compliant code"


    def test_scn_container_image_scanning_positive(self, analyzer):
        """Test scn.container.image_scanning: Container Image Scanning - Should detect"""
        code = """# Code that triggers scn.container.image_scanning"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.container.image_scanning" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.container.image_scanning should detect this code"
    
    def test_scn_container_image_scanning_negative(self, analyzer):
        """Test scn.container.image_scanning: Container Image Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.container.image_scanning" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.container.image_scanning should NOT detect compliant code"


    def test_scn_iac_security_scanning_positive(self, analyzer):
        """Test scn.iac.security_scanning: IaC Security Scanning - Should detect"""
        code = """# Code that triggers scn.iac.security_scanning"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.iac.security_scanning" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.iac.security_scanning should detect this code"
    
    def test_scn_iac_security_scanning_negative(self, analyzer):
        """Test scn.iac.security_scanning: IaC Security Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.iac.security_scanning" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.iac.security_scanning should NOT detect compliant code"


    def test_scn_secrets_scanning_positive(self, analyzer):
        """Test scn.secrets.scanning: Secrets Scanning - Should detect"""
        code = """# Code that triggers scn.secrets.scanning"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.secrets.scanning" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.secrets.scanning should detect this code"
    
    def test_scn_secrets_scanning_negative(self, analyzer):
        """Test scn.secrets.scanning: Secrets Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.secrets.scanning" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.secrets.scanning should NOT detect compliant code"


    def test_scn_dast_dynamic_testing_positive(self, analyzer):
        """Test scn.dast.dynamic_testing: DAST Tool Integration - Should detect"""
        code = """# Code that triggers scn.dast.dynamic_testing"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.dast.dynamic_testing" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.dast.dynamic_testing should detect this code"
    
    def test_scn_dast_dynamic_testing_negative(self, analyzer):
        """Test scn.dast.dynamic_testing: DAST Tool Integration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.dast.dynamic_testing" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.dast.dynamic_testing should NOT detect compliant code"


    def test_scn_code_security_library_positive(self, analyzer):
        """Test scn.code.security_library: Security Library Integration - Should detect"""
        code = """import bandit

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.code.security_library" in f.requirement_id]
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
        findings = [f for f in result.findings if "scn.code.security_library" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.code.security_library should NOT detect compliant code"


    def test_scn_policy_enforcement_positive(self, analyzer):
        """Test scn.policy.enforcement: Security Policy Enforcement - Should detect"""
        code = """# Code that triggers scn.policy.enforcement"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.policy.enforcement" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.policy.enforcement should detect this code"
    
    def test_scn_policy_enforcement_negative(self, analyzer):
        """Test scn.policy.enforcement: Security Policy Enforcement - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.policy.enforcement" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.policy.enforcement should NOT detect compliant code"


    def test_scn_iac_defender_for_cloud_positive(self, analyzer):
        """Test scn.iac.defender_for_cloud: Microsoft Defender for Cloud - Should detect"""
        code = """// Bicep code for scn.iac.defender_for_cloud
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.iac.defender_for_cloud" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.iac.defender_for_cloud should detect this code"
    
    def test_scn_iac_defender_for_cloud_negative(self, analyzer):
        """Test scn.iac.defender_for_cloud: Microsoft Defender for Cloud - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.iac.defender_for_cloud" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.iac.defender_for_cloud should NOT detect compliant code"


    def test_scn_iac_policy_assignment_positive(self, analyzer):
        """Test scn.iac.policy_assignment: Azure Policy Assignment - Should detect"""
        code = """// Bicep code for scn.iac.policy_assignment
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.iac.policy_assignment" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.iac.policy_assignment should detect this code"
    
    def test_scn_iac_policy_assignment_negative(self, analyzer):
        """Test scn.iac.policy_assignment: Azure Policy Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.iac.policy_assignment" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.iac.policy_assignment should NOT detect compliant code"


    def test_scn_cicd_scan_gate_positive(self, analyzer):
        """Test scn.cicd.scan_gate: Security Scan Gate - Should detect"""
        code = """# Code that triggers scn.cicd.scan_gate"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.cicd.scan_gate" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.cicd.scan_gate should detect this code"
    
    def test_scn_cicd_scan_gate_negative(self, analyzer):
        """Test scn.cicd.scan_gate: Security Scan Gate - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.cicd.scan_gate" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.cicd.scan_gate should NOT detect compliant code"


    def test_scn_missing_sast_positive(self, analyzer):
        """Test scn.missing_sast: Missing SAST Scanning - Should detect"""
        code = """# Code that triggers scn.missing_sast"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.missing_sast" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.missing_sast should detect this code"
    
    def test_scn_missing_sast_negative(self, analyzer):
        """Test scn.missing_sast: Missing SAST Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.missing_sast" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.missing_sast should NOT detect compliant code"


    def test_scn_missing_dependency_scan_positive(self, analyzer):
        """Test scn.missing_dependency_scan: Missing Dependency Scanning - Should detect"""
        code = """# Code that triggers scn.missing_dependency_scan"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "scn.missing_dependency_scan" in f.requirement_id]
        assert len(findings) > 0, f"Pattern scn.missing_dependency_scan should detect this code"
    
    def test_scn_missing_dependency_scan_negative(self, analyzer):
        """Test scn.missing_dependency_scan: Missing Dependency Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "scn.missing_dependency_scan" in f.requirement_id]
        assert len(findings) == 0, f"Pattern scn.missing_dependency_scan should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
