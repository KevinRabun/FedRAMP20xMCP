#!/usr/bin/env python3
"""
Quick validation: Run first 10 C# analyzer tests with v2
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity

def test_1_hardcoded_secrets():
    """Test detection of hardcoded secrets."""
    code = '''
    public class DatabaseConfig
    {
        private string connectionString = "Server=myserver;Database=mydb;User Id=admin;Password=SuperSecret123!;";
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    secret_findings = [f for f in result.findings if not f.good_practice and "secret" in f.description.lower() or "password" in f.description.lower()]
    assert len(secret_findings) >= 1, f"Expected secret finding, got {len(secret_findings)}"
    print("[PASS] Test 1: Hardcoded secrets")

def test_2_authorize_attribute():
    """Test [Authorize] attribute detection."""
    code = '''
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        public IActionResult GetSecureData() => Ok("data");
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    auth_findings = [f for f in result.findings if "authentication" in f.description.lower() or "authentication" in f.title.lower()]
    high_severity_auth = [f for f in auth_findings if f.severity == Severity.HIGH and not f.good_practice]
    assert len(high_severity_auth) == 0, f"Expected no HIGH auth issues, found {len(high_severity_auth)}"
    print("[PASS] Test 2: [Authorize] attribute")

def test_3_key_vault_usage():
    """Test Key Vault usage detection."""
    code = '''
    using Azure.Identity;
    using Azure.Security.KeyVault.Secrets;
    
    public class SecretManager
    {
        private readonly SecretClient client;
        public SecretManager()
        {
            client = new SecretClient(new Uri("https://myvault.vault.azure.net"), new DefaultAzureCredential());
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    good_practices = [f for f in result.findings if f.good_practice and "key vault" in f.description.lower()]
    assert len(good_practices) >= 1, f"Expected Key Vault good practice, got {len(good_practices)}"
    print("[PASS] Test 3: Key Vault usage")

def test_4_missing_authentication():
    """Test detection of missing authentication."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UnsecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetData() => Ok("data");
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    auth_issues = [f for f in result.findings if not f.good_practice and ("authentication" in f.description.lower() or "authorize" in f.description.lower())]
    assert len(auth_issues) >= 1, f"Expected auth issue, got {len(auth_issues)}"
    print("[PASS] Test 4: Missing authentication")

def test_5_configuration_secrets():
    """Test configuration-based secrets (not hardcoded)."""
    code = '''
    using Microsoft.Extensions.Configuration;
    
    public class ConfigService
    {
        private readonly IConfiguration _config;
        public ConfigService(IConfiguration config)
        {
            _config = config;
            string apiKey = _config["ApiKey"];
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    secret_issues = [f for f in result.findings if not f.good_practice and ("secret" in f.description.lower() or "password" in f.description.lower() or "api key" in f.description.lower())]
    # Should NOT flag configuration retrieval as hardcoded
    assert len(secret_issues) == 0, f"Expected no secret issues (using config), got {len(secret_issues)}"
    print("[PASS] Test 5: Configuration-based secrets")

if __name__ == "__main__":
    print("Running AST Analyzer Validation Tests")
    print("="*70)
    
    try:
        test_1_hardcoded_secrets()
        test_2_authorize_attribute()
        test_3_key_vault_usage()
        test_4_missing_authentication()
        test_5_configuration_secrets()
        
        print("="*70)
        print("[OK] All 5 validation tests passed!")
        print("\nAST analyzer is working correctly. Ready to:")
        print("  1. Test against full test suite")
        print("  2. Enhance remaining checks with AST")
        print("  3. Apply to Java and TypeScript analyzers")
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        sys.exit(1)

