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

class TestVdrPatterns:
    """Test VDR pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_vdr_scanning_defender_for_cloud_positive(self, analyzer):
        """Test vdr.scanning.defender_for_cloud: Microsoft Defender for Cloud - Should detect"""
        code = """// Bicep code for vdr.scanning.defender_for_cloud
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.defender_for_cloud" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.defender_for_cloud should detect this code"
    
    def test_vdr_scanning_defender_for_cloud_negative(self, analyzer):
        """Test vdr.scanning.defender_for_cloud: Microsoft Defender for Cloud - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.defender_for_cloud" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.defender_for_cloud should NOT detect compliant code"


    def test_vdr_scanning_ci_cd_scanning_positive(self, analyzer):
        """Test vdr.scanning.ci_cd_scanning: CI/CD Security Scanning - Should detect"""
        code = """# Code that triggers vdr.scanning.ci_cd_scanning"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.ci_cd_scanning" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.ci_cd_scanning should detect this code"
    
    def test_vdr_scanning_ci_cd_scanning_negative(self, analyzer):
        """Test vdr.scanning.ci_cd_scanning: CI/CD Security Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.ci_cd_scanning" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.ci_cd_scanning should NOT detect compliant code"


    def test_vdr_scanning_missing_sast_positive(self, analyzer):
        """Test vdr.scanning.missing_sast: Missing SAST Scanning - Should detect"""
        code = """# Code that triggers vdr.scanning.missing_sast"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_sast" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.missing_sast should detect this code"
    
    def test_vdr_scanning_missing_sast_negative(self, analyzer):
        """Test vdr.scanning.missing_sast: Missing SAST Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_sast" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.missing_sast should NOT detect compliant code"


    def test_vdr_scanning_missing_container_scan_positive(self, analyzer):
        """Test vdr.scanning.missing_container_scan: Missing Container Image Scanning - Should detect"""
        code = """# Code that triggers vdr.scanning.missing_container_scan"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_container_scan" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.scanning.missing_container_scan should detect this code"
    
    def test_vdr_scanning_missing_container_scan_negative(self, analyzer):
        """Test vdr.scanning.missing_container_scan: Missing Container Image Scanning - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.scanning.missing_container_scan" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.scanning.missing_container_scan should NOT detect compliant code"


    def test_vdr_patching_update_management_positive(self, analyzer):
        """Test vdr.patching.update_management: Azure Update Management - Should detect"""
        code = """// Bicep code for vdr.patching.update_management
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.update_management" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.patching.update_management should detect this code"
    
    def test_vdr_patching_update_management_negative(self, analyzer):
        """Test vdr.patching.update_management: Azure Update Management - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.update_management" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.patching.update_management should NOT detect compliant code"


    def test_vdr_patching_outdated_base_image_positive(self, analyzer):
        """Test vdr.patching.outdated_base_image: Outdated Container Base Image - Should detect"""
        code = """# Code that triggers vdr.patching.outdated_base_image"""
        
        result = analyzer.analyze(code, "dockerfile")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.outdated_base_image" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.patching.outdated_base_image should detect this code"
    
    def test_vdr_patching_outdated_base_image_negative(self, analyzer):
        """Test vdr.patching.outdated_base_image: Outdated Container Base Image - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "dockerfile")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.patching.outdated_base_image" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.patching.outdated_base_image should NOT detect compliant code"


    def test_vdr_dependencies_dependabot_positive(self, analyzer):
        """Test vdr.dependencies.dependabot: Dependabot Configuration - Should detect"""
        code = """# Code that triggers vdr.dependencies.dependabot"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.dependabot" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.dependencies.dependabot should detect this code"
    
    def test_vdr_dependencies_dependabot_negative(self, analyzer):
        """Test vdr.dependencies.dependabot: Dependabot Configuration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.dependabot" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.dependencies.dependabot should NOT detect compliant code"


    def test_vdr_dependencies_outdated_packages_positive(self, analyzer):
        """Test vdr.dependencies.outdated_packages: Outdated Dependencies - Should detect"""
        code = """# Code that triggers vdr.dependencies.outdated_packages
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.outdated_packages" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.dependencies.outdated_packages should detect this code"
    
    def test_vdr_dependencies_outdated_packages_negative(self, analyzer):
        """Test vdr.dependencies.outdated_packages: Outdated Dependencies - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.dependencies.outdated_packages" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.dependencies.outdated_packages should NOT detect compliant code"


    def test_vdr_secure_dev_pre_commit_hooks_positive(self, analyzer):
        """Test vdr.secure_dev.pre_commit_hooks: Pre-Commit Hooks - Should detect"""
        code = """# Code that triggers vdr.secure_dev.pre_commit_hooks"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.secure_dev.pre_commit_hooks" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.secure_dev.pre_commit_hooks should detect this code"
    
    def test_vdr_secure_dev_pre_commit_hooks_negative(self, analyzer):
        """Test vdr.secure_dev.pre_commit_hooks: Pre-Commit Hooks - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.secure_dev.pre_commit_hooks" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.secure_dev.pre_commit_hooks should NOT detect compliant code"


    def test_vdr_secure_dev_code_review_required_positive(self, analyzer):
        """Test vdr.secure_dev.code_review_required: Code Review Required - Should detect"""
        code = """# Code that triggers vdr.secure_dev.code_review_required"""
        
        result = analyzer.analyze(code, "github")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.secure_dev.code_review_required" == f.pattern_id]
        assert len(findings) > 0, f"Pattern vdr.secure_dev.code_review_required should detect this code"
    
    def test_vdr_secure_dev_code_review_required_negative(self, analyzer):
        """Test vdr.secure_dev.code_review_required: Code Review Required - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "vdr.secure_dev.code_review_required" == f.pattern_id]
        assert len(findings) == 0, f"Pattern vdr.secure_dev.code_review_required should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
