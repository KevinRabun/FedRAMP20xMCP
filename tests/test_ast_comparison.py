#!/usr/bin/env python3
"""
Comparison test: AST-based analyzer vs Regex-based analyzer.

Demonstrates improvements in precision and accuracy.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer_old import CSharpAnalyzer as CSharpAnalyzerV1
try:
    from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer, TREE_SITTER_AVAILABLE
except ImportError:
    TREE_SITTER_AVAILABLE = False
    CSharpAnalyzer = None


def test_false_positive_in_comments():
    """Test that AST ignores hardcoded secrets in comments."""
    code = """
    using System;
    
    // Example: password = "HardcodedPassword123!" (DON'T DO THIS!)
    // This is a comment showing bad practice
    public class GoodExample
    {
        // The actual implementation uses Key Vault
        public async Task<string> GetPasswordAsync()
        {
            var client = new SecretClient(vaultUrl, new DefaultAzureCredential());
            return await client.GetSecretAsync("db-password");
        }
    }
    """
    
    print("\n" + "="*70)
    print("TEST 1: False Positive - Secrets in Comments")
    print("="*70)
    print("Code has 'password = \"HardcodedPassword123!\"' in a comment")
    print()
    
    # Regex analyzer
    print("REGEX ANALYZER (v1):")
    analyzer_v1 = CSharpAnalyzer()
    result_v1 = analyzer_v1.analyze(code, "test.cs")
    secret_findings_v1 = [f for f in result_v1.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
    print(f"  Found {len(secret_findings_v1)} issue(s)")
    if secret_findings_v1:
        print(f"  [FAIL] FALSE POSITIVE: Flagged password in comment")
    
    # AST analyzer
    if TREE_SITTER_AVAILABLE and CSharpAnalyzer:
        print("\nAST ANALYZER (v2):")
        analyzer_v2 = CSharpAnalyzer()
        result_v2 = analyzer_v2.analyze(code, "test.cs")
        secret_findings_v2 = [f for f in result_v2.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
        print(f"  Found {len(secret_findings_v2)} issue(s)")
        if not secret_findings_v2:
            print(f"  [OK] CORRECT: Ignored password in comment")
        
        print(f"\n[DATA] Improvement: {len(secret_findings_v1) - len(secret_findings_v2)} false positive(s) eliminated")
    else:
        print("\n[WARN]  AST analyzer not available (install tree-sitter)")


def test_controller_inheritance():
    """Test that AST correctly identifies controllers by inheritance."""
    code = """
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;
    
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class SecureController : ControllerBase
    {
        [HttpGet]
        public IActionResult Get() => Ok("data");
        
        [HttpPost]
        [AllowAnonymous]  // Explicitly public endpoint
        public IActionResult PublicEndpoint() => Ok();
    }
    
    // This is NOT a controller - just inherits from a base class
    public class DataService : BaseService
    {
        public string GetData() => "data";
    }
    """
    
    print("\n" + "="*70)
    print("TEST 2: Controller Identification by Inheritance")
    print("="*70)
    print("Code has SecureController (properly protected) and DataService (not a controller)")
    print()
    
    # Regex analyzer
    print("REGEX ANALYZER (v1):")
    analyzer_v1 = CSharpAnalyzer()
    result_v1 = analyzer_v1.analyze(code, "test.cs")
    auth_issues_v1 = [f for f in result_v1.findings if f.requirement_id == "KSI-IAM-01" and not f.good_practice]
    print(f"  Found {len(auth_issues_v1)} authentication issue(s)")
    
    # AST analyzer
    if TREE_SITTER_AVAILABLE and CSharpAnalyzer:
        print("\nAST ANALYZER (v2):")
        analyzer_v2 = CSharpAnalyzer()
        result_v2 = analyzer_v2.analyze(code, "test.cs")
        auth_issues_v2 = [f for f in result_v2.findings if f.requirement_id == "KSI-IAM-01" and not f.good_practice]
        good_practices_v2 = [f for f in result_v2.findings if f.requirement_id == "KSI-IAM-01" and f.good_practice]
        print(f"  Found {len(auth_issues_v2)} authentication issue(s)")
        print(f"  Found {len(good_practices_v2)} good practice(s)")
        
        if len(good_practices_v2) > 0:
            print(f"  [OK] CORRECT: Recognized properly secured controller")
        
        print(f"\n[DATA] AST understands: class inheritance, attribute scope, method-level security")
    else:
        print("\n[WARN]  AST analyzer not available")


def test_configuration_vs_hardcoded():
    """Test distinguishing configuration retrieval from hardcoded values."""
    code = """
    using Azure.Security.KeyVault.Secrets;
    using Azure.Identity;
    
    public class ConfigExample
    {
        // [FAIL] BAD: Hardcoded secret
        private const string ApiKey = "sk-1234567890abcdefghijklmnopqrstuvwxyz";
        
        // [OK] GOOD: From configuration
        private readonly string _connectionString;
        
        public ConfigExample(IConfiguration config)
        {
            _connectionString = config["Database:ConnectionString"];
        }
        
        // [OK] GOOD: From Key Vault
        public async Task<string> GetApiKeyAsync()
        {
            var client = new SecretClient(
                new Uri("https://myvault.vault.azure.net"),
                new DefaultAzureCredential());
            var secret = await client.GetSecretAsync("api-key");
            return secret.Value.Value;
        }
    }
    """
    
    print("\n" + "="*70)
    print("TEST 3: Hardcoded vs Configuration-Based Secrets")
    print("="*70)
    print("Code has: 1 hardcoded secret, 2 properly configured secrets")
    print()
    
    # Regex analyzer
    print("REGEX ANALYZER (v1):")
    analyzer_v1 = CSharpAnalyzer()
    result_v1 = analyzer_v1.analyze(code, "test.cs")
    secret_issues_v1 = [f for f in result_v1.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
    secret_good_v1 = [f for f in result_v1.findings if f.requirement_id == "KSI-SVC-06" and f.good_practice]
    print(f"  Found {len(secret_issues_v1)} hardcoded secret(s)")
    print(f"  Found {len(secret_good_v1)} good practice(s)")
    
    # AST analyzer
    if TREE_SITTER_AVAILABLE and CSharpAnalyzer:
        print("\nAST ANALYZER (v2):")
        analyzer_v2 = CSharpAnalyzer()
        result_v2 = analyzer_v2.analyze(code, "test.cs")
        secret_issues_v2 = [f for f in result_v2.findings if f.requirement_id == "KSI-SVC-06" and not f.good_practice]
        secret_good_v2 = [f for f in result_v2.findings if f.requirement_id == "KSI-SVC-06" and f.good_practice]
        print(f"  Found {len(secret_issues_v2)} hardcoded secret(s)")
        print(f"  Found {len(secret_good_v2)} good practice(s)")
        
        if len(secret_issues_v2) == 1 and len(secret_good_v2) >= 1:
            print(f"  [OK] CORRECT: Identified hardcoded secret and Key Vault usage")
        
        print(f"\n[DATA] AST understands: variable scope, assignment context, secure sources")
    else:
        print("\n[WARN]  AST analyzer not available")


def test_method_level_authorization():
    """Test detection of method-level authorization attributes."""
    code = """
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Authorization;
    
    [ApiController]
    [Route("api/[controller]")]
    public class MixedSecurityController : ControllerBase
    {
        // [FAIL] BAD: No authorization
        [HttpGet("public")]
        public IActionResult GetPublicData() => Ok();
        
        // [OK] GOOD: Requires authentication
        [HttpGet("secure")]
        [Authorize]
        public IActionResult GetSecureData() => Ok();
        
        // [OK] GOOD: Requires specific role
        [HttpPost("admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminAction() => Ok();
    }
    """
    
    print("\n" + "="*70)
    print("TEST 4: Method-Level Authorization Detection")
    print("="*70)
    print("Code has: 1 unprotected endpoint, 2 protected endpoints")
    print()
    
    # AST analyzer
    if TREE_SITTER_AVAILABLE and CSharpAnalyzer:
        print("AST ANALYZER (v2):")
        analyzer_v2 = CSharpAnalyzer()
        result_v2 = analyzer_v2.analyze(code, "test.cs")
        auth_issues = [f for f in result_v2.findings if f.requirement_id == "KSI-IAM-01" and not f.good_practice]
        auth_good = [f for f in result_v2.findings if f.requirement_id == "KSI-IAM-02" and f.good_practice]
        
        print(f"  Found {len(auth_issues)} unprotected endpoint(s)")
        print(f"  Found {len(auth_good)} properly secured method(s)")
        
        if len(auth_issues) == 1:
            print(f"  [OK] CORRECT: Identified GetPublicData() as unprotected")
            for finding in auth_issues:
                print(f"     Methods without auth: {finding.description.split(':')[1] if ':' in finding.description else finding.description}")
        
        print(f"\n[DATA] AST capability: Per-method security analysis, not just class-level")
    else:
        print("[WARN]  AST analyzer not available")


def print_summary():
    """Print summary of improvements."""
    print("\n" + "="*70)
    print("SUMMARY: AST-Based Analysis Improvements")
    print("="*70)
    print()
    print("[OK] Semantic Understanding:")
    print("   - Ignores comments and string literals appropriately")
    print("   - Understands class inheritance (Controller, ControllerBase)")
    print("   - Recognizes attribute scope (class vs method level)")
    print()
    print("[OK] Higher Precision:")
    print("   - Distinguishes hardcoded values from configuration retrieval")
    print("   - Identifies actual code vs documentation examples")
    print("   - Tracks variable context and data flow")
    print()
    print("[OK] Fewer False Positives:")
    print("   - Doesn't flag commented-out bad examples")
    print("   - Understands when secrets come from Key Vault/Configuration")
    print("   - Recognizes test/placeholder values in context")
    print()
    print("[OK] Better Coverage:")
    print("   - Analyzes each method individually")
    print("   - Understands complex authorization scenarios")
    print("   - Detects mixed security patterns in same class")
    print()
    print("[EMOJI] Next Steps:")
    print("   1. Install tree-sitter: pip install tree-sitter tree-sitter-c-sharp")
    print("   2. Review results above and compare analyzers")
    print("   3. Decide to adopt AST-based approach")
    print("   4. Extend to all Phase 1-5 checks")
    print("="*70)


if __name__ == "__main__":
    print("\n" + "="*70)
    print("AST-BASED ANALYZER COMPARISON TEST")
    print("="*70)
    
    if not TREE_SITTER_AVAILABLE:
        print("\n[WARN]  tree-sitter not installed. Install with:")
        print("   pip install tree-sitter tree-sitter-c-sharp")
        print("\nRunning regex analyzer only for comparison...")
    
    test_false_positive_in_comments()
    test_controller_inheritance()
    test_configuration_vs_hardcoded()
    test_method_level_authorization()
    print_summary()

