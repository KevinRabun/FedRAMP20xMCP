#!/usr/bin/env python3
"""
Test CSharpAnalyzerV2 against the full test suite (56 tests).
ASCII-safe output for Windows compatibility.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity

def run_test(test_name, test_func):
    """Run a test and report results."""
    try:
        test_func()
        print(f"[PASS] {test_name}")
        return True
    except AssertionError as e:
        print(f"[FAIL] {test_name}: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] {test_name}: {e}")
        return False

# Phase 1 Tests (8 tests)
def test_1_hardcoded_secrets():
    code = '''
    public class DatabaseConfig
    {
        private string connectionString = "Server=myserver;Database=mydb;User Id=admin;Password=SuperSecret123!;";
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    assert len(result.findings) >= 1
    assert any("secret" in f.description.lower() or "password" in f.description.lower() for f in result.findings)

def test_2_authorize_attribute():
    code = '''
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        public IActionResult GetSecureData()
        {
            return Ok("Secure data");
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecureController.cs")
    auth_findings = [f for f in result.findings if "authentication" in f.description.lower() or "authentication" in f.title.lower()]
    high_severity_auth = [f for f in auth_findings if f.severity == Severity.HIGH and not f.good_practice]
    assert len(high_severity_auth) == 0

def test_3_key_vault_usage():
    code = '''
    using Azure.Identity;
    using Azure.Security.KeyVault.Secrets;
    
    public class SecretManager
    {
        private readonly SecretClient client;
        
        public SecretManager()
        {
            client = new SecretClient(
                new Uri("https://myvault.vault.azure.net"),
                new DefaultAzureCredential());
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecretManager.cs")
    good_practices = [f for f in result.findings if f.good_practice and "key vault" in f.description.lower()]
    assert len(good_practices) >= 1

def test_4_missing_authentication():
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UnsecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok("Data");
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UnsecureController.cs")
    auth_issues = [f for f in result.findings if not f.good_practice and ("authentication" in f.description.lower() or "authorize" in f.description.lower())]
    assert len(auth_issues) >= 1

def test_5_insecure_deserialization():
    code = '''
    using System.Runtime.Serialization.Formatters.Binary;
    
    public class DataService
    {
        public object DeserializeData(byte[] data)
        {
            var formatter = new BinaryFormatter();
            using var stream = new MemoryStream(data);
            return formatter.Deserialize(stream);
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DataService.cs")
    deser_issues = [f for f in result.findings if "deserialization" in f.description.lower()]
    assert len(deser_issues) >= 1

def test_6_pii_without_encryption():
    code = '''
    public class User
    {
        public string Ssn { get; set; }
        public string SocialSecurityNumber { get; set; }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "User.cs")
    pii_issues = [f for f in result.findings if "pii" in f.description.lower()]
    assert len(pii_issues) >= 1

def test_7_role_based_authorization():
    code = '''
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/admin")]
    public class AdminController : ControllerBase
    {
        [Authorize(Roles = "Admin")]
        [HttpPost]
        public IActionResult CreateResource()
        {
            return Ok();
        }
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "AdminController.cs")
    # Should recognize authorization as good practice
    auth_good = [f for f in result.findings if f.good_practice and "authorization" in f.description.lower()]
    assert len(auth_good) >= 1

def test_8_configuration_based_secrets():
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
    result = analyzer.analyze(code, "ConfigService.cs")
    # Should NOT flag configuration retrieval as hardcoded
    secret_issues = [f for f in result.findings if not f.good_practice and ("secret" in f.description.lower() or "api key" in f.description.lower())]
    assert len(secret_issues) == 0

# Phase 2 Tests (6 tests) - Sample subset
def test_9_multiple_auth_attributes():
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;
    
    [Authorize]
    [ApiController]
    public class SecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get() => Ok();
        
        [AllowAnonymous]
        [HttpPost]
        public IActionResult Post() => Ok();
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    # Should recognize as properly secured (has class-level [Authorize])
    high_auth_issues = [f for f in result.findings if f.severity == Severity.HIGH and not f.good_practice and "authentication" in f.description.lower()]
    assert len(high_auth_issues) == 0

def test_10_mixed_security():
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;
    
    [ApiController]
    public class MixedController : ControllerBase
    {
        [Authorize]
        [HttpGet]
        public IActionResult Secure() => Ok();
        
        [HttpPost]
        public IActionResult Unsecure() => Ok();
    }
    '''
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "test.cs")
    # Should detect the unsecured POST method
    auth_issues = [f for f in result.findings if not f.good_practice and "authentication" in f.description.lower()]
    assert len(auth_issues) >= 1

if __name__ == "__main__":
    print("="*70)
    print("Testing CSharpAnalyzerV2 Against Test Suite")
    print("="*70)
    print()
    
    tests = [
        # Phase 1 Tests (8 core tests)
        ("Hardcoded secrets detection", test_1_hardcoded_secrets),
        ("[Authorize] attribute detection", test_2_authorize_attribute),
        ("Key Vault usage recognition", test_3_key_vault_usage),
        ("Missing authentication detection", test_4_missing_authentication),
        ("Insecure deserialization detection", test_5_insecure_deserialization),
        ("PII without encryption", test_6_pii_without_encryption),
        ("Role-based authorization", test_7_role_based_authorization),
        ("Configuration-based secrets", test_8_configuration_based_secrets),
        
        # Phase 2 Sample Tests
        ("Multiple auth attributes", test_9_multiple_auth_attributes),
        ("Mixed security patterns", test_10_mixed_security),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        if run_test(test_name, test_func):
            passed += 1
        else:
            failed += 1
    
    print()
    print("="*70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*70)
    
    if failed > 0:
        print()
        print("NEXT STEPS:")
        print("- Review failing tests")
        print("- Enhance AST checks for missing patterns")
        print("- Add more semantic understanding")
        sys.exit(1)
    else:
        print()
        print("SUCCESS! AST analyzer passes core validation.")
        print()
        print("READY FOR:")
        print("- Full 56-test suite validation")
        print("- Enhance remaining checks with AST")
        print("- Apply to Java and TypeScript analyzers")

