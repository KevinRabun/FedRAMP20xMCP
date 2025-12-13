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

class TestIamPatterns:
    """Test IAM pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_iam_mfa_fido2_import_positive(self, analyzer):
        """Test iam.mfa.fido2_import: FIDO2 Library Import - Should detect"""
        code = """import fido2

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.fido2_import" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.fido2_import should detect this code"
    
    def test_iam_mfa_fido2_import_negative(self, analyzer):
        """Test iam.mfa.fido2_import: FIDO2 Library Import - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.fido2_import" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.fido2_import should NOT detect compliant code"


    def test_iam_mfa_webauthn_import_positive(self, analyzer):
        """Test iam.mfa.webauthn_import: WebAuthn Library Import - Should detect"""
        code = """import webauthn

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.webauthn_import" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.webauthn_import should detect this code"
    
    def test_iam_mfa_webauthn_import_negative(self, analyzer):
        """Test iam.mfa.webauthn_import: WebAuthn Library Import - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.webauthn_import" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.webauthn_import should NOT detect compliant code"


    def test_iam_mfa_azure_ad_import_positive(self, analyzer):
        """Test iam.mfa.azure_ad_import: Azure AD/MSAL Import - Should detect"""
        code = """import msal

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.azure_ad_import" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.azure_ad_import should detect this code"
    
    def test_iam_mfa_azure_ad_import_negative(self, analyzer):
        """Test iam.mfa.azure_ad_import: Azure AD/MSAL Import - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.azure_ad_import" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.azure_ad_import should NOT detect compliant code"


    def test_iam_mfa_totp_import_positive(self, analyzer):
        """Test iam.mfa.totp_import: TOTP Library Import (Not Phishing-Resistant) - Should detect"""
        code = """import pyotp

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.totp_import" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.totp_import should detect this code"
    
    def test_iam_mfa_totp_import_negative(self, analyzer):
        """Test iam.mfa.totp_import: TOTP Library Import (Not Phishing-Resistant) - Should NOT detect"""
        code = """from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

def setup_mfa():
    rp = PublicKeyCredentialRpEntity("example.com", "Example App")
    server = Fido2Server(rp)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.totp_import" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.totp_import should NOT detect compliant code"


    def test_iam_mfa_sms_mfa_positive(self, analyzer):
        """Test iam.mfa.sms_mfa: SMS-Based MFA (Not Phishing-Resistant) - Should detect"""
        code = """import twilio

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.sms_mfa" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.sms_mfa should detect this code"
    
    def test_iam_mfa_sms_mfa_negative(self, analyzer):
        """Test iam.mfa.sms_mfa: SMS-Based MFA (Not Phishing-Resistant) - Should NOT detect"""
        code = """from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

def setup_authentication():
    rp = PublicKeyCredentialRpEntity("example.com", "Example App")
    server = Fido2Server(rp)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.sms_mfa" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.sms_mfa should NOT detect compliant code"


    def test_iam_mfa_login_without_mfa_positive(self, analyzer):
        """Test iam.mfa.login_without_mfa: Login Function Without MFA - Should detect"""
        code = """def login(username, password):
    user = authenticate(username, password)
    if user:
        session['user_id'] = user.id
        return redirect('/dashboard')"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.login_without_mfa" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.login_without_mfa should detect this code"
    
    def test_iam_mfa_login_without_mfa_negative(self, analyzer):
        """Test iam.mfa.login_without_mfa: Login Function Without MFA - Should NOT detect"""
        code = """def login(username, password):
    user = authenticate(username, password)
    if user:
        mfa_verified = verify_fido2_challenge(user)
        if mfa_verified:
            session['user_id'] = user.id
            return redirect('/dashboard')"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.login_without_mfa" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.login_without_mfa should NOT detect compliant code"


    def test_iam_mfa_decorator_login_required_positive(self, analyzer):
        """Test iam.mfa.decorator_login_required: Login Required Decorator Without MFA - Should detect"""
        code = """@login_required
def protected_view():
    return 'Protected content'"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.decorator_login_required" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.mfa.decorator_login_required should detect this code"
    
    def test_iam_mfa_decorator_login_required_negative(self, analyzer):
        """Test iam.mfa.decorator_login_required: Login Required Decorator Without MFA - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.mfa.decorator_login_required" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.mfa.decorator_login_required should NOT detect compliant code"


    def test_iam_rbac_azure_rbac_assignment_positive(self, analyzer):
        """Test iam.rbac.azure_rbac_assignment: Azure RBAC Assignment - Should detect"""
        code = """resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, 'Contributor')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b24988ac-6180-42a0-ab88-20f7382dd24c')
    principalId: 'user-principal-id'
    principalType: 'User'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.rbac.azure_rbac_assignment" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.rbac.azure_rbac_assignment should detect this code"
    
    def test_iam_rbac_azure_rbac_assignment_negative(self, analyzer):
        """Test iam.rbac.azure_rbac_assignment: Azure RBAC Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.rbac.azure_rbac_assignment" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.rbac.azure_rbac_assignment should NOT detect compliant code"


    def test_iam_rbac_wildcard_permissions_positive(self, analyzer):
        """Test iam.rbac.wildcard_permissions: Wildcard Permission Assignment - Should detect"""
        code = """resource roleDefinition 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(subscription().id, 'CustomRole')
  properties: {
    roleName: 'Custom Admin Role'
    description: 'Role with wildcard permissions'
    permissions: [
      {
        actions: ['*']  // Wildcard - non-compliant
        notActions: []
      }
    ]
    assignableScopes: [
      subscription().id
    ]
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.rbac.wildcard_permissions" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.rbac.wildcard_permissions should detect this code"
    
    def test_iam_rbac_wildcard_permissions_negative(self, analyzer):
        """Test iam.rbac.wildcard_permissions: Wildcard Permission Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.rbac.wildcard_permissions" == f.pattern_id]
        assert len(findings) == 0, f"Pattern iam.rbac.wildcard_permissions should NOT detect compliant code"


    def test_iam_identity_missing_managed_identity_positive(self, analyzer):
        """Test iam.identity.missing_managed_identity: Missing Managed Identity - Should detect"""
        code = """resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: 'eastus'
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_DS1_v2'
    }
  }
  // Missing identity configuration
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "iam.identity.missing_managed_identity" == f.pattern_id]
        assert len(findings) > 0, f"Pattern iam.identity.missing_managed_identity should detect this code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
