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
        code = """from enum import Enum

class UserRole(Enum):
    ADMIN = 'admin'
    USER = 'user'
    VIEWER = 'viewer'
    
ROLES = {
    'admin': ['create', 'read', 'update', 'delete'],
    'user': ['create', 'read', 'update'],
    'viewer': ['read']
}"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.rbac.role_definition" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.rbac.role_definition" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.rbac.role_definition should NOT detect compliant code"


    def test_ucm_authorization_decorator_positive(self, analyzer):
        """Test ucm.authorization.decorator: Authorization Decorator/Attribute - Should detect"""
        code = """@@require_permission
def protected_view():
    return 'Protected content'"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.authorization.decorator" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.authorization.decorator" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.authorization.decorator should NOT detect compliant code"


    def test_ucm_capability_check_explicit_positive(self, analyzer):
        """Test ucm.capability_check.explicit: Explicit Capability Check - Should detect"""
        code = """result = has_permission(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.capability_check.explicit" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.capability_check.explicit" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.capability_check.explicit should NOT detect compliant code"


    def test_ucm_least_privilege_default_deny_positive(self, analyzer):
        """Test ucm.least_privilege.default_deny: Default Deny Access Control - Should detect"""
        code = """def check_access(user, resource):
    # Default deny - access denied unless explicitly permitted
    if not user.has_permission(resource):
        return 403  # Forbidden
    return access_granted()

def api_endpoint(request):
    if not is_authorized(request.user):
        return forbidden_response()"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.least_privilege.default_deny" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.least_privilege.default_deny" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.least_privilege.default_deny should NOT detect compliant code"


    def test_ucm_session_timeout_positive(self, analyzer):
        """Test ucm.session.timeout: Session Timeout Configuration - Should detect"""
        code = """# Session configuration
SESSION_TIMEOUT = 900  # 15 minutes
IDLE_TIMEOUT = 600  # 10 minutes inactivity

app.config.update(
    SESSION_COOKIE_SECURE=True,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_REFRESH_EACH_REQUEST=True
)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.session.timeout" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.session.timeout" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.session.timeout should NOT detect compliant code"


    def test_ucm_audit_access_log_positive(self, analyzer):
        """Test ucm.audit.access_log: Access Logging for Capabilities - Should detect"""
        code = """import logging

def check_permission(user, resource, action):
    # Audit access attempts
    logger.info(f"Access check: user={user.id} resource={resource} action={action}")
    
    if user.has_permission(resource, action):
        logger.info(f"Permission granted: {user.id} -> {resource}")
        return True
    else:
        logger.warn(f"Permission denied: {user.id} -> {resource}")
        return False"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.audit.access_log" == f.pattern_id]
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.audit.access_log" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.audit.access_log should NOT detect compliant code"


    def test_ucm_missing_authorization_positive(self, analyzer):
        """Test ucm.missing_authorization: Missing Authorization Check - Should detect"""
        code = """@app.route('/api/data', methods=['GET'])
def get_data():
    # Missing authorization decorator!
    return {'status': 'ok', 'data': fetch_data()}"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.missing_authorization" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ucm.missing_authorization should detect this code"


    def test_ucm_iac_managed_identity_positive(self, analyzer):
        """Test ucm.iac.managed_identity: Azure Managed Identity for Capability Management - Should detect"""
        code = """resource appService 'Microsoft.Web/sites@2023-01-01' = {
  name: 'myAppService'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.iac.managed_identity" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ucm.iac.managed_identity should detect this code"
    
    def test_ucm_iac_managed_identity_negative(self, analyzer):
        """Test ucm.iac.managed_identity: Azure Managed Identity for Capability Management - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.iac.managed_identity" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.iac.managed_identity should NOT detect compliant code"


    def test_ucm_iac_rbac_assignment_positive(self, analyzer):
        """Test ucm.iac.rbac_assignment: Azure RBAC Role Assignment - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.iac.rbac_assignment" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ucm.iac.rbac_assignment should detect this code"
    
    def test_ucm_iac_rbac_assignment_negative(self, analyzer):
        """Test ucm.iac.rbac_assignment: Azure RBAC Role Assignment - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.iac.rbac_assignment" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.iac.rbac_assignment should NOT detect compliant code"


    def test_ucm_iac_key_vault_access_policy_positive(self, analyzer):
        """Test ucm.iac.key_vault_access_policy: Key Vault Access Policy - Should detect"""
        code = """resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: { name: 'standard' }
    tenantId: tenant().tenantId
    accessPolicies: [
      {
        tenantId: tenant().tenantId
        objectId: 'user-object-id'
        permissions: {
          secrets: ['get', 'list']
          keys: ['get']
        }
      }
    ]
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.iac.key_vault_access_policy" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ucm.iac.key_vault_access_policy should detect this code"
    
    def test_ucm_iac_key_vault_access_policy_negative(self, analyzer):
        """Test ucm.iac.key_vault_access_policy: Key Vault Access Policy - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.iac.key_vault_access_policy" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.iac.key_vault_access_policy should NOT detect compliant code"


    def test_ucm_cicd_rbac_validation_positive(self, analyzer):
        """Test ucm.cicd.rbac_validation: CI/CD RBAC Validation Step - Should detect"""
        code = """name: CI Pipeline
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate RBAC
        run: python scripts/validate_rbac.py
      - name: Build
        run: echo "Building..." """
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.cicd.rbac_validation" == f.pattern_id]
        assert len(findings) > 0, f"Pattern ucm.cicd.rbac_validation should detect this code"
    
    def test_ucm_cicd_rbac_validation_negative(self, analyzer):
        """Test ucm.cicd.rbac_validation: CI/CD RBAC Validation Step - Should NOT detect"""
        code = """name: Simple Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: npm test"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "ucm.cicd.rbac_validation" == f.pattern_id]
        assert len(findings) == 0, f"Pattern ucm.cicd.rbac_validation should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
