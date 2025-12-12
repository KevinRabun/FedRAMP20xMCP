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

class TestUcmPatterns:
    """Test UCM pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_ucm_rbac_role_definition_positive(self, analyzer):
        """Test ucm.rbac.role_definition: Role-Based Access Control Definition - Should detect"""
        code = """# Code that triggers ucm.rbac.role_definition
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.rbac.role_definition" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.rbac.role_definition should detect this code"
    
    def test_ucm_rbac_role_definition_negative(self, analyzer):
        """Test ucm.rbac.role_definition: Role-Based Access Control Definition - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.rbac.role_definition" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.rbac.role_definition should NOT detect compliant code"


    def test_ucm_authorization_decorator_positive(self, analyzer):
        """Test ucm.authorization.decorator: Authorization Decorator/Attribute - Should detect"""
        code = """# Code that triggers ucm.authorization.decorator
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.authorization.decorator" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.authorization.decorator should detect this code"
    
    def test_ucm_authorization_decorator_negative(self, analyzer):
        """Test ucm.authorization.decorator: Authorization Decorator/Attribute - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.authorization.decorator" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.authorization.decorator should NOT detect compliant code"


    def test_ucm_capability_check_explicit_positive(self, analyzer):
        """Test ucm.capability_check.explicit: Explicit Capability Check - Should detect"""
        code = """result = has_permission(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.capability_check.explicit" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.capability_check.explicit should detect this code"
    
    def test_ucm_capability_check_explicit_negative(self, analyzer):
        """Test ucm.capability_check.explicit: Explicit Capability Check - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.capability_check.explicit" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.capability_check.explicit should NOT detect compliant code"


    def test_ucm_least_privilege_default_deny_positive(self, analyzer):
        """Test ucm.least_privilege.default_deny: Default Deny Access Control - Should detect"""
        code = """# Code that triggers ucm.least_privilege.default_deny
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.least_privilege.default_deny" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.least_privilege.default_deny should detect this code"
    
    def test_ucm_least_privilege_default_deny_negative(self, analyzer):
        """Test ucm.least_privilege.default_deny: Default Deny Access Control - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.least_privilege.default_deny" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.least_privilege.default_deny should NOT detect compliant code"


    def test_ucm_session_timeout_positive(self, analyzer):
        """Test ucm.session.timeout: Session Timeout Configuration - Should detect"""
        code = """# Code that triggers ucm.session.timeout
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.session.timeout" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.session.timeout should detect this code"
    
    def test_ucm_session_timeout_negative(self, analyzer):
        """Test ucm.session.timeout: Session Timeout Configuration - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.session.timeout" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.session.timeout should NOT detect compliant code"


    def test_ucm_audit_access_log_positive(self, analyzer):
        """Test ucm.audit.access_log: Access Logging for Capabilities - Should detect"""
        code = """# Code that triggers ucm.audit.access_log
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.audit.access_log" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.audit.access_log should detect this code"
    
    def test_ucm_audit_access_log_negative(self, analyzer):
        """Test ucm.audit.access_log: Access Logging for Capabilities - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.audit.access_log" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.audit.access_log should NOT detect compliant code"


    def test_ucm_missing_authorization_positive(self, analyzer):
        """Test ucm.missing_authorization: Missing Authorization Check - Should detect"""
        code = """# Code that triggers ucm.missing_authorization
trigger_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.missing_authorization" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.missing_authorization should detect this code"
    
    def test_ucm_missing_authorization_negative(self, analyzer):
        """Test ucm.missing_authorization: Missing Authorization Check - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.missing_authorization" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.missing_authorization should NOT detect compliant code"


    def test_ucm_iac_managed_identity_positive(self, analyzer):
        """Test ucm.iac.managed_identity: Azure Managed Identity for Capability Management - Should detect"""
        code = """// Bicep code for ucm.iac.managed_identity
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.iac.managed_identity" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.iac.managed_identity should detect this code"
    
    def test_ucm_iac_managed_identity_negative(self, analyzer):
        """Test ucm.iac.managed_identity: Azure Managed Identity for Capability Management - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.iac.managed_identity" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.iac.managed_identity should NOT detect compliant code"


    def test_ucm_iac_rbac_assignment_positive(self, analyzer):
        """Test ucm.iac.rbac_assignment: Azure RBAC Role Assignment - Should detect"""
        code = """// Bicep code for ucm.iac.rbac_assignment
resource example 'Microsoft.Resources/tags@2022-09-01' = {}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.iac.rbac_assignment" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.iac.rbac_assignment should detect this code"
    
    def test_ucm_iac_rbac_assignment_negative(self, analyzer):
        """Test ucm.iac.rbac_assignment: Azure RBAC Role Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.iac.rbac_assignment" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.iac.rbac_assignment should NOT detect compliant code"


    def test_ucm_iac_key_vault_access_policy_positive(self, analyzer):
        """Test ucm.iac.key_vault_access_policy: Key Vault Access Policy - Should detect"""
        code = """resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: { name: 'standard' }
    tenantId: tenant().tenantId
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.iac.key_vault_access_policy" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.iac.key_vault_access_policy should detect this code"
    
    def test_ucm_iac_key_vault_access_policy_negative(self, analyzer):
        """Test ucm.iac.key_vault_access_policy: Key Vault Access Policy - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.iac.key_vault_access_policy" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.iac.key_vault_access_policy should NOT detect compliant code"


    def test_ucm_cicd_rbac_validation_positive(self, analyzer):
        """Test ucm.cicd.rbac_validation: CI/CD RBAC Validation Step - Should detect"""
        code = """# Code that triggers ucm.cicd.rbac_validation"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if "ucm.cicd.rbac_validation" in f.requirement_id]
        assert len(findings) > 0, f"Pattern ucm.cicd.rbac_validation should detect this code"
    
    def test_ucm_cicd_rbac_validation_negative(self, analyzer):
        """Test ucm.cicd.rbac_validation: CI/CD RBAC Validation Step - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if "ucm.cicd.rbac_validation" in f.requirement_id]
        assert len(findings) == 0, f"Pattern ucm.cicd.rbac_validation should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
