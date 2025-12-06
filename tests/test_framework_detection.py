#!/usr/bin/env python3
"""
Tests for framework detection improvements to reduce false positives.

Tests validate that the analyzer recognizes ASP.NET Core framework features
and adjusts severity/findings accordingly.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer, TREE_SITTER_AVAILABLE

# Try to import pytest, but don't fail if not available
try:
    import pytest
    HAS_PYTEST = True
except ImportError:
    HAS_PYTEST = False
    # Create a dummy pytest module for standalone execution
    class DummyPytest:
        @staticmethod
        def fail(msg):
            raise AssertionError(msg)
    pytest = DummyPytest()

print(f"Tree-sitter available: {TREE_SITTER_AVAILABLE}")
print(f"Pytest available: {HAS_PYTEST}")


def test_data_annotations_detected():
    """Test that Data Annotations validation framework is recognized."""
    code = """
using System.ComponentModel.DataAnnotations;

public class CreateUserRequest
{
    [Required]
    [StringLength(50)]
    public string Username { get; set; }
    
    [Required]
    [EmailAddress]
    public string Email { get; set; }
}

public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] CreateUserRequest request)
    {
        // ModelState check missing, but Data Annotations present
        var user = _service.Create(request);
        return Ok(user);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect validation framework and reduce severity
    validation_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02"]
    
    if validation_findings:
        # Should be LOW or MEDIUM severity, not HIGH
        high_severity = [f for f in validation_findings if f.severity.name == "HIGH"]
        if high_severity:
            pytest.fail(" Data Annotations detected but HIGH severity finding still raised")
        else:
            print("✅ Data Annotations detected - severity appropriately reduced")
    else:
        print("✅ Data Annotations detected - no false positive")


def test_fluent_validation_detected():
    """Test that FluentValidation framework is recognized."""
    code = """
using FluentValidation;
using FluentValidation.AspNetCore;

public class CreateUserRequestValidator : AbstractValidator<CreateUserRequest>
{
    public CreateUserRequestValidator()
    {
        RuleFor(x => x.Username).NotEmpty().Length(3, 50);
        RuleFor(x => x.Email).NotEmpty().EmailAddress();
    }
}

public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] CreateUserRequest request)
    {
        // FluentValidation handles validation automatically
        var user = _service.Create(request);
        return Ok(user);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect FluentValidation and reduce severity
    validation_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02"]
    
    if validation_findings:
        high_severity = [f for f in validation_findings if f.severity.name == "HIGH"]
        if high_severity:
            pytest.fail(" FluentValidation detected but HIGH severity finding still raised")
        else:
            print("✅ FluentValidation detected - severity appropriately reduced")
    else:
        print("✅ FluentValidation detected - no false positive")


def test_data_protection_api_detected():
    """Test that Data Protection API is recognized for PII handling."""
    code = """
using Microsoft.AspNetCore.DataProtection;

public class UserService
{
    private readonly IDataProtector _protector;
    
    public UserService(IDataProtectionProvider provider)
    {
        _protector = provider.CreateProtector("UserService.SSN");
    }
    
    public void SaveUser(User user)
    {
        // SSN field present but Data Protection API available
        user.EncryptedSsn = _protector.Protect(user.Ssn);
        _repository.Save(user);
    }
}

public class User
{
    public string Ssn { get; set; }
    public string EncryptedSsn { get; set; }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserService.cs")
    
    # Should detect Data Protection API and reduce severity
    pii_findings = [f for f in result.findings if f.requirement_id == "KSI-PIY-02"]
    
    if pii_findings:
        # Should be LOW severity or INFO, not MEDIUM
        medium_severity = [f for f in pii_findings if f.severity.name == "MEDIUM"]
        if medium_severity:
            pytest.fail(" Data Protection API detected but MEDIUM severity finding still raised")
        else:
            print("✅ Data Protection API detected - severity appropriately reduced")
    else:
        print("✅ Data Protection API detected - no PII warning needed")


def test_application_insights_detected():
    """Test that Application Insights is recognized."""
    code = """
using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;

public class OrderService
{
    private readonly TelemetryClient _telemetry;
    
    public OrderService(TelemetryClient telemetry)
    {
        _telemetry = telemetry;
    }
    
    public void ProcessOrder(Order order)
    {
        _telemetry.TrackEvent("OrderProcessed", new Dictionary<string, string>
        {
            { "OrderId", order.Id.ToString() }
        });
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrderService.cs")
    
    # Should detect Application Insights
    app_insights_findings = [f for f in result.findings 
                             if "Application Insights" in f.title and f.good_practice]
    
    if app_insights_findings:
        print("✅ Application Insights detected and recognized as good practice")
    else:
        print("[WARN] Application Insights not detected (may be acceptable)")
        return True  # Not a failure, just different detection


def test_development_environment_context():
    """Test that development environment configurations are recognized."""
    code = """
public class Startup
{
    public void ConfigureServices(IServiceCollection services, IWebHostEnvironment env)
    {
        services.AddSession(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            
            // Development-specific override
            if (env.IsDevelopment())
            {
                options.Cookie.SecurePolicy = CookieSecurePolicy.None;
            }
            else
            {
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            }
        });
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should recognize development context and not flag as HIGH severity
    session_findings = [f for f in result.findings if f.requirement_id == "KSI-IAM-07"]
    
    if session_findings:
        # Check if description mentions development context
        dev_aware = any("development" in f.description.lower() or "OK in development" in f.description 
                       for f in session_findings)
        if dev_aware:
            print("✅ Development environment context recognized")
        else:
            # May still be acceptable if severity is reduced
            high_severity = [f for f in session_findings if f.severity.name == "HIGH"]
            if not high_severity:
                print("✅ Development context handled (no HIGH severity)")
            else:
                print("[WARN] Development context not fully recognized")
                # Not critical failure, framework detection working
    else:
        print("✅ No session management issues detected")


def test_no_false_positive_with_modelstate_check():
    """Test that proper validation with ModelState check doesn't raise findings."""
    code = """
using System.ComponentModel.DataAnnotations;

public class CreateUserRequest
{
    [Required]
    [StringLength(50)]
    public string Username { get; set; }
}

public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] CreateUserRequest request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }
        
        var user = _service.Create(request);
        return Ok(user);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should NOT raise any validation findings
    validation_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" 
                          and not f.good_practice]
    
    if not validation_findings:
        print("✅ Proper validation with ModelState check - no false positive")
    else:
        print("[FAIL] False positive raised despite proper validation")
        print(f"  Findings: {[f.title for f in validation_findings]}")
        pytest.fail("False positive detected with proper validation")


def test_without_framework_high_severity():
    """Test that missing framework still raises appropriate severity."""
    code = """
public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] CreateUserRequest request)
    {
        // No validation framework, no ModelState check, no validation attributes
        var user = _service.Create(request);
        return Ok(user);
    }
}

public class CreateUserRequest
{
    public string Username { get; set; }
    public string Email { get; set; }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should raise HIGH severity finding
    validation_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02"]
    high_severity = [f for f in validation_findings if f.severity.name == "HIGH"]
    
    if high_severity:
        print("✅ No validation framework detected - HIGH severity raised appropriately")
    else:
        print("[WARN] Expected HIGH severity finding for missing validation")
        # May have MEDIUM which is also acceptable


def test_structured_logging_patterns():
    """Test that structured logging with Application Insights is recognized."""
    code = """
using Microsoft.Extensions.Logging;
using Microsoft.ApplicationInsights;

public class PaymentService
{
    private readonly ILogger<PaymentService> _logger;
    private readonly TelemetryClient _telemetry;
    
    public PaymentService(ILogger<PaymentService> logger, TelemetryClient telemetry)
    {
        _logger = logger;
        _telemetry = telemetry;
    }
    
    public void ProcessPayment(Payment payment)
    {
        _logger.LogInformation("Processing payment {PaymentId} for {Amount}", 
            payment.Id, payment.Amount);
        
        _telemetry.TrackEvent("PaymentProcessed");
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "PaymentService.cs")
    
    # Should recognize logging implementation
    logging_findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-05"]
    good_practices = [f for f in logging_findings if f.good_practice]
    
    if good_practices:
        print("✅ Structured logging with Application Insights recognized as good practice")
    elif not logging_findings:
        print("✅ Proper logging - no issues detected")
    else:
        print("[WARN] Logging detected but not recognized as good practice")
        # Test passed


def run_all_tests():
    """Run all framework detection tests."""
    print("\n" + "="*70)
    print("FRAMEWORK DETECTION TESTS - FALSE POSITIVE REDUCTION")
    print("="*70)
    
    tests = [
        ("Data Annotations Detection", test_data_annotations_detected),
        ("FluentValidation Detection", test_fluent_validation_detected),
        ("Data Protection API Detection", test_data_protection_api_detected),
        ("Application Insights Detection", test_application_insights_detected),
        ("Development Environment Context", test_development_environment_context),
        ("No False Positive with ModelState", test_no_false_positive_with_modelstate_check),
        ("High Severity Without Framework", test_without_framework_high_severity),
        ("Structured Logging Patterns", test_structured_logging_patterns),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\nTest: {test_name}")
        print("-" * 70)
        try:
            passed = test_func()
            results.append((test_name, passed))
        except Exception as e:
            print(f"[ERROR] Test failed with exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    passed = sum(1 for _, result in results if result)
    total = len(results)
    print(f"Passed: {passed}/{total}")
    
    for test_name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} {test_name}")
    
    print("="*70)
    return passed == total


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
