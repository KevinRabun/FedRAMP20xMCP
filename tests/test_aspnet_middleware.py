#!/usr/bin/env python3
"""
Test suite for ASP.NET Core Middleware Security (Phase B Enhancements).

Tests validate security headers, rate limiting, and request size limits detection.
"""

import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer, TREE_SITTER_AVAILABLE
from fedramp_20x_mcp.analyzers.base import Severity

print(f"Tree-sitter available: {TREE_SITTER_AVAILABLE}")


def test_missing_security_headers():
    """Test detection of missing critical security headers."""
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.UseHttpsRedirection();
        app.UseAuthorization();
        app.UseEndpoints(endpoints =>
        {
            endpoints.MapControllers();
        });
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should detect missing security headers
    header_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "security headers" in f.title.lower()]
    
    assert len(header_findings) >= 1, f"Expected >= 1 missing headers finding, got {len(header_findings)}"
    
    finding = header_findings[0]
    assert finding.severity == Severity.MEDIUM, f"Expected MEDIUM severity, got {finding.severity}"
    assert "X-Content-Type-Options" in finding.title or "X-Content-Type-Options" in finding.description, "Should mention X-Content-Type-Options"
    assert "X-Frame-Options" in finding.title or "X-Frame-Options" in finding.description, "Should mention X-Frame-Options"
    assert "NWebsec" in finding.recommendation, "Should recommend NWebsec package"
    
    print("✅ Missing security headers detected")
    print(f"   Finding: {finding.title}")


def test_nwebsec_security_headers_good():
    """Test that NWebsec middleware is recognized as good practice."""
    code = """
using Microsoft.AspNetCore.Builder;
using NWebsec.AspNetCore.Middleware;

public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.UseXContentTypeOptions();
        app.UseXfo(options => options.Deny());
        app.UseCsp(opts => opts.DefaultSources(s => s.Self()));
        
        app.UseHttpsRedirection();
        app.UseAuthorization();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should NOT raise missing headers warning
    header_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "missing" in f.title.lower() and "security headers" in f.title.lower()]
    
    assert len(header_findings) == 0, f"Should not raise warning with NWebsec, got {len(header_findings)} findings"
    
    print("✅ NWebsec middleware recognized - no false positive")


def test_manual_security_headers_good():
    """Test that manual header configuration is recognized."""
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.Use(async (context, next) => {
            context.Response.Headers.Add("X-Content-Type-Options", "nosniff");
            context.Response.Headers.Add("X-Frame-Options", "DENY");
            context.Response.Headers.Add("Content-Security-Policy", "default-src 'self'");
            await next();
        });
        
        app.UseHttpsRedirection();
        app.UseAuthorization();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should NOT raise missing headers warning
    header_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "missing" in f.title.lower() and "security headers" in f.title.lower()]
    
    assert len(header_findings) == 0, f"Should not raise warning with manual headers, got {len(header_findings)} findings"
    
    print("✅ Manual header configuration recognized - no false positive")


def test_missing_rate_limiting():
    """Test detection of POST endpoint without rate limiting."""
    code = """
using Microsoft.AspNetCore.Mvc;

public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        var user = _service.Create(request);
        return Ok(user);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should detect missing rate limiting
    rate_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "rate limiting" in f.title.lower()]
    
    assert len(rate_limit_findings) >= 1, f"Expected >= 1 rate limiting finding, got {len(rate_limit_findings)}"
    
    finding = rate_limit_findings[0]
    assert finding.severity == Severity.MEDIUM, f"Expected MEDIUM severity, got {finding.severity}"
    assert "POST" in finding.title, "Should mention POST verb"
    assert "AddRateLimiter" in finding.recommendation, "Should mention AddRateLimiter"
    
    print("✅ Missing rate limiting detected on POST endpoint")
    print(f"   Finding: {finding.title}")


def test_rate_limiting_with_attribute():
    """Test that [EnableRateLimiting] attribute is recognized."""
    code = """
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

public class UserController : ControllerBase
{
    [EnableRateLimiting("fixed")]
    [HttpPost]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        var user = _service.Create(request);
        return Ok(user);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserController.cs")
    
    # Should NOT raise rate limiting warning
    rate_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "rate limiting" in f.title.lower() and "Missing" in f.title]
    
    assert len(rate_limit_findings) == 0, f"Should not raise warning with [EnableRateLimiting], got {len(rate_limit_findings)} findings"
    
    print("✅ [EnableRateLimiting] attribute recognized - no false positive")


def test_rate_limiting_with_service():
    """Test that AddRateLimiter service registration is recognized."""
    code = """
using Microsoft.AspNetCore.Builder;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddRateLimiter(options => {
    options.AddFixedWindowLimiter("fixed", options => {
        options.PermitLimit = 100;
        options.Window = TimeSpan.FromMinutes(1);
    });
});

public class UserController : ControllerBase
{
    [HttpPost]
    public IActionResult CreateUser([FromBody] CreateUserRequest request)
    {
        var user = _service.Create(request);
        return Ok(user);
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should NOT raise rate limiting warning (global rate limiter configured)
    rate_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "rate limiting" in f.title.lower() and "Missing" in f.title]
    
    assert len(rate_limit_findings) == 0, f"Should not raise warning with AddRateLimiter, got {len(rate_limit_findings)} findings"
    
    print("✅ AddRateLimiter service registration recognized - no false positive")


def test_missing_request_size_limit():
    """Test detection of file upload without request size limit."""
    code = """
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

public class UploadController : ControllerBase
{
    [HttpPost]
    public IActionResult Upload(IFormFile file)
    {
        // Process file
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UploadController.cs")
    
    # Should detect missing request size limit
    size_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "request size limit" in f.title.lower()]
    
    assert len(size_limit_findings) >= 1, f"Expected >= 1 size limit finding, got {len(size_limit_findings)}"
    
    finding = size_limit_findings[0]
    assert finding.severity == Severity.HIGH, f"Expected HIGH severity, got {finding.severity}"
    assert "file upload" in finding.title.lower() or "file upload" in finding.description.lower(), "Should mention file upload"
    assert "RequestSizeLimit" in finding.recommendation, "Should mention [RequestSizeLimit] attribute"
    assert "denial-of-service" in finding.description.lower() or "DoS" in finding.description, "Should mention DoS risk"
    
    print("✅ Missing request size limit detected on file upload")
    print(f"   Finding: {finding.title}")


def test_request_size_limit_with_attribute():
    """Test that [RequestSizeLimit] attribute is recognized."""
    code = """
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;

public class UploadController : ControllerBase
{
    [RequestSizeLimit(10_000_000)]
    [HttpPost]
    public IActionResult Upload(IFormFile file)
    {
        // Process file
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UploadController.cs")
    
    # Should NOT raise size limit warning
    size_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "Missing" in f.title and "request size limit" in f.title.lower()]
    
    assert len(size_limit_findings) == 0, f"Should not raise warning with [RequestSizeLimit], got {len(size_limit_findings)} findings"
    
    print("✅ [RequestSizeLimit] attribute recognized - no false positive")


def test_request_size_limit_with_global_config():
    """Test that global FormOptions configuration is recognized."""
    code = """
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Features;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<FormOptions>(options => {
    options.MultipartBodyLengthLimit = 10_000_000;
});

public class UploadController : ControllerBase
{
    [HttpPost]
    public IActionResult Upload(IFormFile file)
    {
        // Process file
        return Ok();
    }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should NOT raise size limit warning (global limit configured)
    size_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "Missing" in f.title and "request size limit" in f.title.lower()]
    
    assert len(size_limit_findings) == 0, f"Should not raise warning with global FormOptions, got {len(size_limit_findings)} findings"
    
    print("✅ Global FormOptions configuration recognized - no false positive")


def test_multiple_endpoints_rate_limiting():
    """Test detection across multiple endpoints."""
    code = """
using Microsoft.AspNetCore.Mvc;

public class ApiController : ControllerBase
{
    [HttpPost]
    public IActionResult Create([FromBody] Item item) { return Ok(); }
    
    [HttpPut]
    public IActionResult Update(int id, [FromBody] Item item) { return Ok(); }
    
    [HttpDelete]
    public IActionResult Delete(int id) { return Ok(); }
    
    [HttpGet]
    public IActionResult Get(int id) { return Ok(); }
}
"""
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ApiController.cs")
    
    # Should detect missing rate limiting on POST, PUT, DELETE (but not GET)
    rate_limit_findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-07" and "rate limiting" in f.title.lower()]
    
    assert len(rate_limit_findings) >= 3, f"Expected >= 3 rate limiting findings (POST, PUT, DELETE), got {len(rate_limit_findings)}"
    
    # Verify correct verbs detected
    titles = " ".join([f.title for f in rate_limit_findings])
    assert "POST" in titles, "Should detect POST endpoint"
    assert "PUT" in titles, "Should detect PUT endpoint"
    assert "DELETE" in titles, "Should detect DELETE endpoint"
    
    print(f"✅ Detected rate limiting issues on {len(rate_limit_findings)} endpoints (POST, PUT, DELETE)")


def run_all_tests():
    """Run all Phase B middleware security tests."""
    print("\n" + "="*70)
    print("PHASE B: ASP.NET CORE MIDDLEWARE SECURITY TEST SUITE")
    print("="*70)
    
    try:
        # Security Headers Tests
        test_missing_security_headers()
        test_nwebsec_security_headers_good()
        test_manual_security_headers_good()
        
        # Rate Limiting Tests
        test_missing_rate_limiting()
        test_rate_limiting_with_attribute()
        test_rate_limiting_with_service()
        test_multiple_endpoints_rate_limiting()
        
        # Request Size Limit Tests
        test_missing_request_size_limit()
        test_request_size_limit_with_attribute()
        test_request_size_limit_with_global_config()
        
        print("\n" + "="*70)
        print("ALL PHASE B TESTS PASSED ✓")
        print("="*70)
        print("\nPhase B Coverage:")
        print("  ✓ Security Headers Validation (3 tests)")
        print("  ✓ Rate Limiting Detection (4 tests)")
        print("  ✓ Request Size Limits (3 tests)")
        print("\nTotal: 10 tests, all passing")
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
