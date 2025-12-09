"""
Tests for KSI-SVC-06 Enhanced Analyzer: Secret Management

Tests AST-based detection of hardcoded secrets and Azure Key Vault usage.
"""

import sys
sys.path.insert(0, 'c:\\source\\FedRAMP20xMCP\\src')

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_06 import KSI_SVC_06_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_hardcoded_password():
    """Test detection of hardcoded password in Python."""
    code = """
import flask

app = flask.Flask(__name__)

# Database connection
db_password = "SuperSecret123!"
connection_string = f"Server=localhost;Password={db_password}"

def connect_db():
    return connect(connection_string)
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect hardcoded password"
    assert any("password" in f.title.lower() for f in critical_findings)
    
    print("[PASS] Python hardcoded password detection working")


def test_python_keyvault_without_managed_identity():
    """Test detection of Key Vault usage without managed identity."""
    code = """
from azure.keyvault.secrets import SecretClient
from azure.identity import ClientSecretCredential

vault_url = "https://myvault.vault.azure.net"
credential = ClientSecretCredential(tenant_id="...", client_id="...", client_secret="...")
client = SecretClient(vault_url=vault_url, credential=credential)

secret = client.get_secret("database-password")
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect Key Vault without managed identity"
    assert any("managed identity" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Python Key Vault without managed identity detection working")


def test_python_env_vars_for_secrets():
    """Test detection of environment variables for secrets."""
    code = """
import os

api_key = os.getenv('API_KEY')
password = os.environ['DB_PASSWORD']

def authenticate():
    return verify(api_key, password)
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect environment variables for secrets"
    assert any("environment variable" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Python environment variable secrets detection working")


def test_python_secure_keyvault():
    """Test that proper Key Vault usage is recognized as secure."""
    code = """
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

vault_url = "https://myvault.vault.azure.net"
credential = DefaultAzureCredential()
client = SecretClient(vault_url=vault_url, credential=credential)

secret = client.get_secret("database-password")
print(f"Retrieved secret version: {secret.properties.version}")
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    # Should not have critical findings for proper Key Vault usage
    assert len(critical_findings) == 0, "Proper Key Vault usage should not trigger critical findings"
    
    print("[PASS] Python secure Key Vault usage passes")


def test_csharp_hardcoded_connection_string():
    """Test detection of hardcoded connection string in C#."""
    code = """
using System.Data.SqlClient;

public class DatabaseService
{
    private string connectionString = "Server=localhost;Database=mydb;User=admin;Password=P@ssw0rd123";
    
    public void Connect()
    {
        using var connection = new SqlConnection(connectionString);
        connection.Open();
    }
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "csharp", "DatabaseService.cs")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect hardcoded connection string"
    assert any("connectionstring" in f.title.lower() or "secret" in f.title.lower() for f in critical_findings)
    
    print("[PASS] C# hardcoded connection string detection working")


def test_csharp_configuration_without_keyvault():
    """Test detection of IConfiguration without Key Vault."""
    code = """
using Microsoft.Extensions.Configuration;

public class AppSettings
{
    private readonly IConfiguration _configuration;
    
    public AppSettings(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public string GetApiKey()
    {
        return _configuration["ApiKey"];
    }
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "csharp", "AppSettings.cs")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect IConfiguration without Key Vault"
    assert any("key vault" in f.title.lower() or "configuration" in f.title.lower() for f in medium_findings)
    
    print("[PASS] C# configuration without Key Vault detection working")


def test_csharp_secure_keyvault():
    """Test that proper Key Vault usage in C# is recognized."""
    code = """
using Azure.Security.KeyVault.Secrets;
using Azure.Identity;

public class SecureService
{
    private readonly SecretClient _secretClient;
    
    public SecureService()
    {
        var credential = new DefaultAzureCredential();
        _secretClient = new SecretClient(new Uri("https://myvault.vault.azure.net"), credential);
    }
    
    public async Task<string> GetSecretAsync()
    {
        var secret = await _secretClient.GetSecretAsync("database-password");
        return secret.Value.Value;
    }
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "csharp", "SecureService.cs")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) == 0, "Proper Key Vault usage should not trigger critical findings"
    
    print("[PASS] C# secure Key Vault usage passes")


def test_java_hardcoded_jdbc_password():
    """Test detection of hardcoded password in JDBC URL."""
    code = """
import java.sql.Connection;
import java.sql.DriverManager;

public class DatabaseConnection {
    private static final String JDBC_URL = "jdbc:mysql://localhost:3306/mydb?user=admin&password=Secret123";
    
    public Connection getConnection() throws Exception {
        return DriverManager.getConnection(JDBC_URL);
    }
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "java", "DatabaseConnection.java")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect hardcoded JDBC password"
    assert any("jdbc" in f.title.lower() or "password" in f.title.lower() for f in critical_findings)
    
    print("[PASS] Java hardcoded JDBC password detection working")


def test_java_spring_without_keyvault():
    """Test detection of Spring configuration without Key Vault."""
    code = """
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ApiService {
    
    @Value("${api.key}")
    private String apiKey;
    
    public String callApi() {
        return httpClient.get("https://api.example.com", apiKey);
    }
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "java", "ApiService.java")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect Spring configuration without Key Vault"
    assert any("key vault" in f.title.lower() or "spring" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Java Spring without Key Vault detection working")


def test_javascript_hardcoded_api_key():
    """Test detection of hardcoded API key in JavaScript."""
    code = """
const express = require('express');
const app = express();

const api_key = "sk-1234567890abcdef";
const token = "ghp_abcdefghijklmnopqrstuvwxyz";

app.get('/api/data', async (req, res) => {
    const response = await fetch('https://api.example.com', {
        headers: { 'Authorization': `Bearer ${api_key}` }
    });
    res.json(await response.json());
});
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "javascript", "server.js")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect hardcoded API key"
    assert any("api" in f.title.lower() or "token" in f.title.lower() for f in critical_findings)
    
    print("[PASS] JavaScript hardcoded API key detection working")


def test_javascript_process_env_secrets():
    """Test detection of process.env for secrets."""
    code = """
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DATABASE_PASSWORD;

async function connect() {
    return db.connect({ password: dbPassword });
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "javascript", "config.js")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect process.env for secrets"
    assert any("environment" in f.title.lower() for f in medium_findings)
    
    print("[PASS] JavaScript process.env secrets detection working")


def test_bicep_keyvault_without_soft_delete():
    """Test detection of Key Vault without soft delete in Bicep."""
    code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: 'myKeyVault'
  location: 'eastus'
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
  }
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "bicep", "main.bicep")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect Key Vault without soft delete"
    assert any("soft delete" in f.title.lower() for f in high_findings)
    
    print("[PASS] Bicep Key Vault without soft delete detection working")


def test_terraform_keyvault_without_purge_protection():
    """Test detection of Key Vault without purge protection in Terraform."""
    code = """
resource "azurerm_key_vault" "example" {
  name                = "examplekeyvault"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  
  sku_name = "standard"
  
  soft_delete_retention_days = 90
}
"""
    
    analyzer = KSI_SVC_06_Analyzer()
    result = analyzer.analyze(code, "terraform", "main.tf")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect Key Vault without purge protection"
    assert any("purge protection" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Terraform Key Vault without purge protection detection working")


def test_factory_function():
    """Test direct instantiation of analyzers."""
    analyzer_py = KSI_SVC_06_Analyzer(CodeLanguage.PYTHON)
    assert analyzer_py.direct_language == CodeLanguage.PYTHON
    
    analyzer_cs = KSI_SVC_06_Analyzer(CodeLanguage.CSHARP)
    assert analyzer_cs.direct_language == CodeLanguage.CSHARP
    
    analyzer_java = KSI_SVC_06_Analyzer(CodeLanguage.JAVA)
    assert analyzer_java.direct_language == CodeLanguage.JAVA
    
    analyzer_js = KSI_SVC_06_Analyzer(CodeLanguage.JAVASCRIPT)
    assert analyzer_js.direct_language == CodeLanguage.JAVASCRIPT
    
    analyzer_bicep = KSI_SVC_06_Analyzer(CodeLanguage.BICEP)
    assert analyzer_bicep.direct_language == CodeLanguage.BICEP
    
    analyzer_tf = KSI_SVC_06_Analyzer(CodeLanguage.TERRAFORM)
    assert analyzer_tf.direct_language == CodeLanguage.TERRAFORM
    
    print("[PASS] Direct instantiation working")


if __name__ == "__main__":
    print("Running KSI-SVC-06 Enhanced Analyzer tests...\n")
    
    tests = [
        test_python_hardcoded_password,
        test_python_keyvault_without_managed_identity,
        test_python_env_vars_for_secrets,
        test_python_secure_keyvault,
        test_csharp_hardcoded_connection_string,
        test_csharp_configuration_without_keyvault,
        test_csharp_secure_keyvault,
        test_java_hardcoded_jdbc_password,
        test_java_spring_without_keyvault,
        test_javascript_hardcoded_api_key,
        test_javascript_process_env_secrets,
        test_bicep_keyvault_without_soft_delete,
        test_terraform_keyvault_without_purge_protection,
        test_factory_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} error: {e}")
            failed += 1
    
    print(f"\n{'=' * 60}")
    print(f"KSI-SVC-06 Enhanced Tests: {passed}/{len(tests)} passed")
    if failed > 0:
        print(f"FAILURES: {failed}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED [PASS]")
        sys.exit(0)

