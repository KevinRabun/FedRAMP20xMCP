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

class TestSvcPatterns:
    """Test SVC pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_svc_security_flask_security_headers_positive(self, analyzer):
        """Test svc.security.flask_security_headers: Flask Security Headers - Should detect"""
        code = """import flask_talisman

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.flask_security_headers" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.security.flask_security_headers should detect this code"
    
    def test_svc_security_flask_security_headers_negative(self, analyzer):
        """Test svc.security.flask_security_headers: Flask Security Headers - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.flask_security_headers" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.security.flask_security_headers should NOT detect compliant code"


    def test_svc_security_aspnet_hsts_positive(self, analyzer):
        """Test svc.security.aspnet_hsts: ASP.NET Core HSTS - Should detect"""
        code = """result = Talisman(data)
print(result)"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.aspnet_hsts" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.security.aspnet_hsts should detect this code"
    
    def test_svc_security_aspnet_hsts_negative(self, analyzer):
        """Test svc.security.aspnet_hsts: ASP.NET Core HSTS - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.aspnet_hsts" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.security.aspnet_hsts should NOT detect compliant code"


    def test_svc_security_missing_hsts_positive(self, analyzer):
        """Test svc.security.missing_hsts: Missing HSTS Configuration - Should detect"""
        code = """# Pattern detected
code_with_pattern = True"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.missing_hsts" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.security.missing_hsts should detect this code"
    
    def test_svc_security_missing_hsts_negative(self, analyzer):
        """Test svc.security.missing_hsts: Missing HSTS Configuration - Should NOT detect"""
        code = """from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=True)
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.missing_hsts" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.security.missing_hsts should NOT detect compliant code"


    def test_svc_security_csp_header_positive(self, analyzer):
        """Test svc.security.csp_header: Content Security Policy - Should detect"""
        code = """from flask import Flask

app = Flask(__name__)

@app.after_request
def set_csp(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.csp_header" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.security.csp_header should detect this code"
    
    def test_svc_security_csp_header_negative(self, analyzer):
        """Test svc.security.csp_header: Content Security Policy - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.security.csp_header" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.security.csp_header should NOT detect compliant code"


    def test_svc_secrets_keyvault_reference_positive(self, analyzer):
        """Test svc.secrets.keyvault_reference: Azure Key Vault Reference - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.keyvault_reference" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.secrets.keyvault_reference should detect this code"
    
    def test_svc_secrets_keyvault_reference_negative(self, analyzer):
        """Test svc.secrets.keyvault_reference: Azure Key Vault Reference - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.keyvault_reference" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.secrets.keyvault_reference should NOT detect compliant code"


    def test_svc_secrets_keyvault_soft_delete_positive(self, analyzer):
        """Test svc.secrets.keyvault_soft_delete: Key Vault Soft Delete - Should detect"""
        code = """resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: { name: 'standard' }
    tenantId: tenant().tenantId
    enableSoftDelete: false  // Non-compliant
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.keyvault_soft_delete" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.secrets.keyvault_soft_delete should detect this code"
    
    def test_svc_secrets_keyvault_soft_delete_negative(self, analyzer):
        """Test svc.secrets.keyvault_soft_delete: Key Vault Soft Delete - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.keyvault_soft_delete" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.secrets.keyvault_soft_delete should NOT detect compliant code"


    def test_svc_secrets_hardcoded_secret_positive(self, analyzer):
        """Test svc.secrets.hardcoded_secret: Hardcoded Secret - Should detect"""
        code = """password = 'hardcoded123'
api_key = 'sk-1234567890abcdef'
secret = 'my-secret-key'"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.hardcoded_secret" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.secrets.hardcoded_secret should detect this code"
    
    def test_svc_secrets_hardcoded_secret_negative(self, analyzer):
        """Test svc.secrets.hardcoded_secret: Hardcoded Secret - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.hardcoded_secret" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.secrets.hardcoded_secret should NOT detect compliant code"


    def test_svc_encryption_storage_encryption_positive(self, analyzer):
        """Test svc.encryption.storage_encryption: Storage Account Encryption - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.storage_encryption" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.encryption.storage_encryption should detect this code"
    
    def test_svc_encryption_storage_encryption_negative(self, analyzer):
        """Test svc.encryption.storage_encryption: Storage Account Encryption - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.storage_encryption" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.encryption.storage_encryption should NOT detect compliant code"


    def test_svc_encryption_sql_tde_positive(self, analyzer):
        """Test svc.encryption.sql_tde: SQL Transparent Data Encryption - Should detect"""
        code = """resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'myserver'
  location: 'eastus'
}

resource database 'Microsoft.Sql/servers/databases@2021-11-01' = {
  parent: sqlServer
  name: 'mydb'
  location: 'eastus'
}

resource tde 'Microsoft.Sql/servers/databases/transparentDataEncryption@2021-11-01' = {
  parent: database
  name: 'current'
  properties: {
    state: 'Disabled'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.sql_tde" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.encryption.sql_tde should detect this code"
    
    def test_svc_encryption_sql_tde_negative(self, analyzer):
        """Test svc.encryption.sql_tde: SQL Transparent Data Encryption - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.sql_tde" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.encryption.sql_tde should NOT detect compliant code"


    def test_svc_network_nsg_allow_all_positive(self, analyzer):
        """Test svc.network.nsg_allow_all: Network Security Group Allow All - Should detect"""
        code = """resource nsgRule 'Microsoft.Network/networkSecurityGroups/securityRules@2021-02-01' = {
  properties: {
    sourceAddressPrefix: '*'
    access: 'Allow'
    direction: 'Inbound'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.network.nsg_allow_all" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.network.nsg_allow_all should detect this code"
    
    def test_svc_network_nsg_allow_all_negative(self, analyzer):
        """Test svc.network.nsg_allow_all: Network Security Group Allow All - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.network.nsg_allow_all" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.network.nsg_allow_all should NOT detect compliant code"


    def test_svc_network_private_endpoint_positive(self, analyzer):
        """Test svc.network.private_endpoint: Private Endpoint - Should detect"""
        code = """resource privateEndpoint 'Microsoft.Network/privateEndpoints@2021-05-01' = {
  name: 'myPrivateEndpoint'
  location: 'eastus'
  properties: {
    subnet: {
      id: '/subscriptions/.../subnets/default'
    }
    privateLinkServiceConnections: []
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.network.private_endpoint" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.network.private_endpoint should detect this code"
    
    def test_svc_network_private_endpoint_negative(self, analyzer):
        """Test svc.network.private_endpoint: Private Endpoint - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.network.private_endpoint" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.network.private_endpoint should NOT detect compliant code"


    def test_svc_tls_minimum_version_positive(self, analyzer):
        """Test svc.tls.minimum_version: TLS Minimum Version - Should detect"""
        code = """resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'mystorageacct'
  location: 'eastus'
  properties: {
    minimumTlsVersion: 'TLS1_0'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.tls.minimum_version" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.tls.minimum_version should detect this code"
    
    def test_svc_tls_minimum_version_negative(self, analyzer):
        """Test svc.tls.minimum_version: TLS Minimum Version - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.tls.minimum_version" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.tls.minimum_version should NOT detect compliant code"


    def test_svc_waf_application_gateway_positive(self, analyzer):
        """Test svc.waf.application_gateway: Application Gateway with WAF - Should detect"""
        code = """resource appGateway 'Microsoft.Network/applicationGateways@2021-05-01' = {
  name: 'myAppGateway'
  location: 'eastus'
  properties: {
    webApplicationFirewallConfiguration: {
      enabled: true
      firewallMode: 'Prevention'
      ruleSetType: 'OWASP'
      ruleSetVersion: '3.2'
    }
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.waf.application_gateway" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.waf.application_gateway should detect this code"
    
    def test_svc_waf_application_gateway_negative(self, analyzer):
        """Test svc.waf.application_gateway: Application Gateway with WAF - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.waf.application_gateway" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.waf.application_gateway should NOT detect compliant code"


    def test_svc_secrets_key_vault_missing_positive(self, analyzer):
        """Test svc.secrets.key_vault_missing: Missing Key Vault for Secret Management - Should detect"""
        code = """password = 'hardcoded123'
api_key = 'sk-1234567890abcdef'
secret = 'my-secret-key'"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.key_vault_missing" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.secrets.key_vault_missing should detect this code"
    
    def test_svc_secrets_key_vault_missing_negative(self, analyzer):
        """Test svc.secrets.key_vault_missing: Missing Key Vault for Secret Management - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.secrets.key_vault_missing" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.secrets.key_vault_missing should NOT detect compliant code"


    def test_svc_encryption_storage_https_only_positive(self, analyzer):
        """Test svc.encryption.storage_https_only: Storage Account HTTPS Enforcement - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.storage_https_only" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.encryption.storage_https_only should detect this code"
    
    def test_svc_encryption_storage_https_only_negative(self, analyzer):
        """Test svc.encryption.storage_https_only: Storage Account HTTPS Enforcement - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.storage_https_only" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.encryption.storage_https_only should NOT detect compliant code"


    def test_svc_encryption_sql_tls_version_positive(self, analyzer):
        """Test svc.encryption.sql_tls_version: SQL Database Minimum TLS Version - Should detect"""
        code = """resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'myserver'
  location: 'eastus'
  properties: {
    administratorLogin: 'sqladmin'
    minimalTlsVersion: '1.0'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.sql_tls_version" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.encryption.sql_tls_version should detect this code"
    
    def test_svc_encryption_sql_tls_version_negative(self, analyzer):
        """Test svc.encryption.sql_tls_version: SQL Database Minimum TLS Version - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.encryption.sql_tls_version" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.encryption.sql_tls_version should NOT detect compliant code"


    def test_svc_network_storage_public_access_positive(self, analyzer):
        """Test svc.network.storage_public_access: Storage Account Public Network Access - Should detect"""
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
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.network.storage_public_access" == f.pattern_id]
        assert len(findings) > 0, f"Pattern svc.network.storage_public_access should detect this code"
    
    def test_svc_network_storage_public_access_negative(self, analyzer):
        """Test svc.network.storage_public_access: Storage Account Public Network Access - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "svc.network.storage_public_access" == f.pattern_id]
        assert len(findings) == 0, f"Pattern svc.network.storage_public_access should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
