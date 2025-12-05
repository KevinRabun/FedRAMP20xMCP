"""
Test data flow tracking capabilities for C# analyzer.

Tests cross-method data flow analysis including:
- Sensitive data propagation detection
- Indirect PII exposure through return values
- Sensitive data in logging statements
- Variable assignment tracking
- Method call graph analysis
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from src.fedramp_20x_mcp.analyzers.base import Severity


def test_sensitive_data_in_logging():
    """Test detection of sensitive data being logged without redaction."""
    print("\n=== Test: Sensitive Data in Logging ===")
    
    code = """
using Microsoft.Extensions.Logging;

public class UserController : ControllerBase
{
    private readonly ILogger<UserController> _logger;
    
    [HttpGet]
    public IActionResult GetUser(int id)
    {
        var userSSN = GetUserSSN(id);
        _logger.LogInformation("Retrieved user SSN: {SSN}", userSSN);
        return Ok();
    }
    
    private string GetUserSSN(int userId)
    {
        return "123-45-6789";
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect sensitive data (SSN) being logged
    logging_findings = [f for f in result.findings if "logged" in f.title.lower() or "logged" in f.description.lower()]
    
    assert len(logging_findings) >= 1, f"Expected at least 1 logging finding, got {len(logging_findings)}"
    assert any(f.severity == Severity.HIGH for f in logging_findings), "Expected HIGH severity for unredacted PII in logs"
    assert any("ssn" in f.description.lower() for f in logging_findings), "Expected SSN to be identified"
    
    print(f"✅ PASS - Detected {len(logging_findings)} sensitive data logging violations")
    for finding in logging_findings:
        print(f"  - {finding.title}: {finding.description[:100]}...")


def test_sensitive_data_returned_from_api():
    """Test detection of sensitive data returned from public API without encryption."""
    print("\n=== Test: Sensitive Data Returned from API ===")
    
    code = """
using Microsoft.AspNetCore.Mvc;

public class CustomerController : ControllerBase
{
    [HttpGet]
    public IActionResult GetCustomerCreditCard(int id)
    {
        var creditCardNumber = GetCreditCardFromDatabase(id);
        return Ok(new { CardNumber = creditCardNumber });
    }
    
    private string GetCreditCardFromDatabase(int customerId)
    {
        return "4111-1111-1111-1111";
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "CustomerController.cs")
    
    # Should detect credit card being returned without encryption
    api_findings = [f for f in result.findings if "returned" in f.description.lower() or "api" in f.description.lower()]
    
    assert len(api_findings) >= 1, f"Expected at least 1 API exposure finding, got {len(api_findings)}"
    assert any(f.severity == Severity.HIGH for f in api_findings), "Expected HIGH severity for unencrypted PII"
    
    print(f"✅ PASS - Detected {len(api_findings)} sensitive data API exposure violations")
    for finding in api_findings:
        print(f"  - {finding.title}: {finding.description[:100]}...")


def test_password_propagation():
    """Test detection of password propagation through variables."""
    print("\n=== Test: Password Propagation ===")
    
    code = """
using Microsoft.Extensions.Logging;

public class AuthService
{
    private readonly ILogger<AuthService> _logger;
    
    public void AuthenticateUser(string username, string password)
    {
        var userCredential = password;
        var authToken = GenerateToken(userCredential);
        _logger.LogInformation("Generated token: {Token}", authToken);
    }
    
    private string GenerateToken(string credential)
    {
        return "token-" + credential;
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "AuthService.cs")
    
    # Should detect password being propagated and logged
    password_findings = [f for f in result.findings if "password" in f.description.lower() or "credential" in f.description.lower()]
    
    assert len(password_findings) >= 1, f"Expected password findings, got {len(password_findings)}"
    
    print(f"✅ PASS - Detected {len(password_findings)} password propagation violations")
    for finding in password_findings:
        print(f"  - {finding.title}: {finding.description[:100]}...")


def test_token_exposure():
    """Test detection of token exposure in logs."""
    print("\n=== Test: Token Exposure ===")
    
    code = """
using Microsoft.Extensions.Logging;

public class TokenService
{
    private readonly ILogger<TokenService> _logger;
    
    public void ProcessToken(string accessToken)
    {
        var token = accessToken;
        _logger.LogInformation("Processing access token: {Token}", token);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "TokenService.cs")
    
    # Should detect token being logged
    token_findings = [f for f in result.findings if "token" in f.description.lower()]
    
    assert len(token_findings) >= 1, f"Expected token findings, got {len(token_findings)}"
    assert any(f.severity == Severity.HIGH for f in token_findings), "Expected HIGH severity for token exposure"
    
    print(f"✅ PASS - Detected {len(token_findings)} token exposure violations")
    for finding in token_findings:
        print(f"  - {finding.title}: {finding.description[:100]}...")


def test_email_address_tracking():
    """Test detection of email address (PII) exposure."""
    print("\n=== Test: Email Address Tracking ===")
    
    code = """
using Microsoft.Extensions.Logging;

public class NotificationService
{
    private readonly ILogger<NotificationService> _logger;
    
    [HttpPost]
    public IActionResult SendNotification(string emailAddress)
    {
        var userEmail = emailAddress;
        _logger.LogInformation("Sending notification to: {Email}", userEmail);
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "NotificationService.cs")
    
    # Should detect email being logged (PII)
    email_findings = [f for f in result.findings if "email" in f.description.lower()]
    
    assert len(email_findings) >= 1, f"Expected email findings, got {len(email_findings)}"
    
    print(f"✅ PASS - Detected {len(email_findings)} email address tracking violations")
    for finding in email_findings:
        print(f"  - {finding.title}: {finding.description[:100]}...")


def test_redacted_logging_no_false_positive():
    """Test that redacted logging doesn't trigger false positives."""
    print("\n=== Test: Redacted Logging (No False Positive) ===")
    
    code = """
using Microsoft.Extensions.Logging;

public class SecureController : ControllerBase
{
    private readonly ILogger<SecureController> _logger;
    
    public void ProcessUserData(string ssn)
    {
        var redactedSSN = RedactSSN(ssn);
        _logger.LogInformation("Processing user data: {RedactedSSN}", redactedSSN);
    }
    
    private string RedactSSN(string value)
    {
        return "***-**-" + value.Substring(7);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecureController.cs")
    
    # Should NOT detect issue when redaction is present
    logging_findings = [f for f in result.findings if "logged" in f.title.lower() and f.severity == Severity.HIGH]
    
    # Might have some findings, but shouldn't be HIGH severity for the redacted case
    high_severity_unredacted = [f for f in logging_findings if "redacted" not in f.description.lower()]
    
    assert len(high_severity_unredacted) == 0, f"Expected no HIGH severity for redacted logging, got {len(high_severity_unredacted)}"
    
    print("✅ PASS - No false positives for redacted logging")


def test_encrypted_api_return_no_false_positive():
    """Test that encrypted data returns don't trigger false positives."""
    print("\n=== Test: Encrypted API Return (No False Positive) ===")
    
    code = """
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

public class SecureApiController : ControllerBase
{
    private readonly IDataProtectionProvider _dataProtection;
    
    [HttpGet]
    public IActionResult GetSensitiveData(int id)
    {
        var ssn = GetUserSSN(id);
        var protector = _dataProtection.CreateProtector("SSNProtection");
        var encryptedSSN = protector.Protect(ssn);
        return Ok(new { Data = encryptedSSN });
    }
    
    private string GetUserSSN(int userId)
    {
        return "123-45-6789";
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecureApiController.cs")
    
    # Should NOT detect issue when encryption is present
    api_findings = [f for f in result.findings if "returned" in f.description.lower() and f.severity == Severity.HIGH]
    
    # Filter out findings that mention encryption
    unencrypted_findings = [f for f in api_findings if "encrypt" not in f.description.lower()]
    
    assert len(unencrypted_findings) == 0, f"Expected no findings for encrypted returns, got {len(unencrypted_findings)}"
    
    print("✅ PASS - No false positives for encrypted API returns")


def test_sensitive_identifier_detection():
    """Test identification of various sensitive identifier patterns."""
    print("\n=== Test: Sensitive Identifier Detection ===")
    
    analyzer = CSharpAnalyzer()
    
    # Test various sensitive identifiers
    test_cases = [
        ("userSSN", True, "pii"),
        ("creditCardNumber", True, "pii"),
        ("password", True, "password"),
        ("accessToken", True, "token"),
        ("apiSecret", True, "secret"),
        ("emailAddress", True, "pii"),
        ("dateOfBirth", True, "pii"),
        ("userName", False, None),  # Not sensitive
        ("userId", False, None),     # Not sensitive
        ("customerName", False, None),  # Not sensitive
    ]
    
    passed = 0
    failed = 0
    
    for identifier, should_be_sensitive, expected_type in test_cases:
        is_sensitive, sensitivity_type = analyzer._is_sensitive_identifier(identifier)
        
        if is_sensitive == should_be_sensitive:
            if not should_be_sensitive or sensitivity_type == expected_type:
                passed += 1
                print(f"  ✓ '{identifier}': sensitive={is_sensitive}, type={sensitivity_type}")
            else:
                failed += 1
                print(f"  ✗ '{identifier}': expected type={expected_type}, got {sensitivity_type}")
        else:
            failed += 1
            print(f"  ✗ '{identifier}': expected sensitive={should_be_sensitive}, got {is_sensitive}")
    
    assert failed == 0, f"Failed {failed} identifier detection tests"
    print(f"✅ PASS - All {passed} identifier patterns correctly detected")


def run_all_tests():
    """Run all data flow tracking tests."""
    print("\n" + "="*80)
    print("Running Data Flow Tracking Tests for C# Analyzer")
    print("="*80)
    
    tests = [
        test_sensitive_data_in_logging,
        test_sensitive_data_returned_from_api,
        test_password_propagation,
        test_token_exposure,
        test_email_address_tracking,
        test_redacted_logging_no_false_positive,
        test_encrypted_api_return_no_false_positive,
        test_sensitive_identifier_detection,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ FAIL - {test.__name__}: {str(e)}")
            failed += 1
        except Exception as e:
            print(f"\n❌ ERROR - {test.__name__}: {str(e)}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "="*80)
    print(f"Test Results: {passed}/{len(tests)} passed, {failed}/{len(tests)} failed")
    print("="*80)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
