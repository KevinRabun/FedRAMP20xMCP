#!/usr/bin/env python3
"""
Test AST-enhanced logging implementation detection for C# analyzer (Tier 2.3).

Tests KSI-MLA-05 requirements for secure logging with sensitive data redaction.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer


def test_password_in_logs_without_redaction():
    """Test detection of password being logged without redaction."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        
        public IActionResult Login(string username, string password)
        {
            _logger.LogInformation("Login attempt: {Username}, {Password}", username, password);
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "AuthController.cs")
    
    # Should detect HIGH severity issue - password in logs
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-MLA-05" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect password in logs"
    assert "password" in issues[0].description.lower(), "Issue should mention password"
    assert "redaction" in issues[0].description.lower(), "Issue should mention redaction"
    print("[PASS] Password in logs without redaction detection test passed")


def test_token_in_logs_without_redaction():
    """Test detection of token being logged without redaction."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class ApiController : ControllerBase
    {
        private readonly ILogger<ApiController> _logger;
        
        public IActionResult ProcessRequest(string bearerToken)
        {
            _logger.LogInformation("Processing request with token: {Token}", bearerToken);
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ApiController.cs")
    
    # Should detect HIGH severity issue - token in logs
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-MLA-05" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect token in logs"
    assert "token" in issues[0].description.lower(), "Issue should mention token"
    print("[PASS] Token in logs without redaction detection test passed")


def test_ssn_in_logs_without_redaction():
    """Test detection of SSN being logged without redaction."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class UserController : ControllerBase
    {
        private readonly ILogger<UserController> _logger;
        
        public IActionResult CreateUser(string name, string ssn)
        {
            _logger.LogInformation("Creating user: {Name}, SSN: {SSN}", name, ssn);
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect HIGH severity issue - SSN in logs
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-MLA-05" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect SSN in logs"
    assert "ssn" in issues[0].description.lower(), "Issue should mention SSN"
    print("[PASS] SSN in logs without redaction detection test passed")


def test_sensitive_data_with_redaction():
    """Test recognition of sensitive data being properly redacted."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class SecureController : ControllerBase
    {
        private readonly ILogger<SecureController> _logger;
        
        public IActionResult ProcessPayment(string email, string creditCard)
        {
            _logger.LogInformation("Payment from: {Email}, Card: {Card}", 
                Redact(email), Mask(creditCard));
            return Ok();
        }
        
        private string Redact(string value) => value.Substring(0, 2) + "***";
        private string Mask(string value) => "****" + value.Substring(value.Length - 4);
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SecureController.cs")
    
    # Should recognize as good practice - sensitive data with redaction
    good_practices = [f for f in result.findings 
                     if f.requirement_id == "KSI-MLA-05" 
                     and f.good_practice]
    
    assert len(good_practices) > 0, "Failed to recognize sensitive data redaction"
    assert "redact" in good_practices[0].description.lower(), "Should mention redaction"
    print("[PASS] Sensitive data with redaction recognition test passed")


def test_api_key_with_sanitization():
    """Test recognition of API key being sanitized before logging."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class IntegrationController : ControllerBase
    {
        private readonly ILogger<IntegrationController> _logger;
        
        public IActionResult CallExternalApi(string apiKey)
        {
            _logger.LogInformation("External API call with key: {Key}", Sanitize(apiKey));
            return Ok();
        }
        
        private string Sanitize(string key) => "***";
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "IntegrationController.cs")
    
    # Should recognize as good practice - API key with sanitization
    good_practices = [f for f in result.findings 
                     if f.requirement_id == "KSI-MLA-05" 
                     and f.good_practice]
    
    assert len(good_practices) > 0, "Failed to recognize API key sanitization"
    print("[PASS] API key with sanitization recognition test passed")


def test_no_logging_implementation():
    """Test detection of missing logging implementation."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    public class NoLoggingController : ControllerBase
    {
        private readonly DataService _service;
        
        public IActionResult GetData()
        {
            var data = _service.FetchData();
            return Ok(data);
        }
        
        [HttpPost]
        public IActionResult CreateResource(Resource resource)
        {
            _service.Save(resource);
            return Created("", resource);
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "NoLoggingController.cs")
    
    # Should detect MEDIUM severity - no logging
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-MLA-05" 
              and not f.good_practice
              and f.severity.value == "medium"]
    
    assert len(issues) > 0, "Failed to detect missing logging"
    assert "no logging" in issues[0].title.lower() or "no ilogger" in issues[0].description.lower(), "Should mention missing logging"
    print("[PASS] No logging implementation detection test passed")


def test_application_insights_configured():
    """Test recognition of Application Insights configuration."""
    code = '''
    using Microsoft.ApplicationInsights;
    using Microsoft.Extensions.Logging;
    
    public class MonitoredController : ControllerBase
    {
        private readonly ILogger<MonitoredController> _logger;
        private readonly TelemetryClient _telemetry;
        
        public MonitoredController(ILogger<MonitoredController> logger, TelemetryClient telemetry)
        {
            _logger = logger;
            _telemetry = telemetry;
        }
        
        public IActionResult ProcessRequest()
        {
            _logger.LogInformation("Processing request");
            _telemetry.TrackEvent("RequestProcessed");
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "MonitoredController.cs")
    
    # Should recognize Application Insights as good practice
    good_practices = [f for f in result.findings 
                     if f.requirement_id == "KSI-MLA-05" 
                     and f.good_practice]
    
    assert len(good_practices) > 0, "Failed to recognize Application Insights"
    assert "application insights" in good_practices[0].title.lower() or "telemetry" in good_practices[0].description.lower(), "Should mention Application Insights"
    print("[PASS] Application Insights configuration recognition test passed")


def test_multiple_sensitive_fields():
    """Test detection of multiple sensitive fields in single log statement."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class RegistrationController : ControllerBase
    {
        private readonly ILogger<RegistrationController> _logger;
        
        public IActionResult Register(string username, string password, string email, string ssn)
        {
            _logger.LogInformation("New registration: {User}, {Pass}, {Email}, {SSN}", 
                username, password, email, ssn);
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "RegistrationController.cs")
    
    # Should detect HIGH severity issue - multiple sensitive fields
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-MLA-05" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    # May find multiple findings (one per sensitive field detected)
    assert len(issues) > 0, "Failed to detect sensitive data in logs"
    print("[PASS] Multiple sensitive fields detection test passed")


def test_safe_logging_without_sensitive_data():
    """Test that safe logging doesn't trigger false positives."""
    code = '''
    using Microsoft.Extensions.Logging;
    
    public class SafeController : ControllerBase
    {
        private readonly ILogger<SafeController> _logger;
        
        public IActionResult GetUser(int userId)
        {
            _logger.LogInformation("Fetching user data: {UserId}", userId);
            return Ok();
        }
        
        [HttpPost]
        public IActionResult UpdateStatus(string status)
        {
            _logger.LogInformation("Status update: {Status}", status);
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "SafeController.cs")
    
    # Should NOT have HIGH severity findings (only safe data logged)
    high_issues = [f for f in result.findings 
                   if f.requirement_id == "KSI-MLA-05" 
                   and f.severity.value == "high"]
    
    assert len(high_issues) == 0, "False positive: flagged safe logging as sensitive"
    print("[PASS] Safe logging without sensitive data test passed")


if __name__ == "__main__":
    print("\n=== Testing AST-Enhanced Logging Implementation (Tier 2.3) ===\n")
    
    test_password_in_logs_without_redaction()
    test_token_in_logs_without_redaction()
    test_ssn_in_logs_without_redaction()
    test_sensitive_data_with_redaction()
    test_api_key_with_sanitization()
    test_no_logging_implementation()
    test_application_insights_configured()
    test_multiple_sensitive_fields()
    test_safe_logging_without_sensitive_data()
    
    print("\n=== All AST Logging Implementation Tests Passed ===")
