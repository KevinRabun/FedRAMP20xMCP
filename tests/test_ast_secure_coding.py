"""
Test AST-enhanced secure coding practices check (Tier 1.3).

Tests cover:
1. Correct middleware ordering (good practice)
2. Missing HTTPS redirection (HIGH)
3. Missing HSTS (HIGH)
4. UseAuthorization before UseAuthentication (HIGH)
5. Permissive CORS with AllowAnyOrigin (MEDIUM)
6. Permissive CORS with wildcard in WithOrigins (MEDIUM)
7. Proper CORS with specific origins (good practice)
8. Non-startup file ignored (no middleware)
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from src.fedramp_20x_mcp.analyzers.base import Severity


def test_correct_middleware_ordering():
    """Test recognition of properly ordered security middleware."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    var app = builder.Build();
    
    if (!app.Environment.IsDevelopment())
    {
        app.UseHsts();
    }
    
    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseRouting();
    app.UseCors("AllowedOrigins");
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-07"]
    
    assert len(good_practices) > 0, "Failed to recognize proper middleware ordering"
    print("[PASS] Correct middleware ordering test passed")


def test_missing_https_redirection():
    """Test detection of missing UseHttpsRedirection."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    var app = builder.Build();
    
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should detect missing HTTPS redirection
    high_findings = [f for f in result.findings 
                    if f.requirement_id == "KSI-SVC-07"
                    and f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Failed to detect missing UseHttpsRedirection"
    assert any("UseHttpsRedirection is missing" in f.description for f in high_findings)
    print("[PASS] Missing HTTPS redirection detection test passed")


def test_missing_hsts():
    """Test detection of missing UseHsts."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    var app = builder.Build();
    
    app.UseHttpsRedirection();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should detect missing HSTS
    high_findings = [f for f in result.findings 
                    if f.requirement_id == "KSI-SVC-07"
                    and f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Failed to detect missing UseHsts"
    assert any("UseHsts is missing" in f.description for f in high_findings)
    print("[PASS] Missing HSTS detection test passed")


def test_authorization_before_authentication():
    """Test detection of incorrect middleware order (Authorization before Authentication)."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    var app = builder.Build();
    
    app.UseHttpsRedirection();
    app.UseAuthorization();  // Wrong order!
    app.UseAuthentication();  // Should be before Authorization
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should detect incorrect ordering
    ordering_findings = [f for f in result.findings 
                        if "ordering" in f.title.lower() 
                        and f.requirement_id == "KSI-SVC-07"
                        and f.severity == Severity.HIGH]
    
    assert len(ordering_findings) > 0, "Failed to detect incorrect middleware ordering"
    assert any("UseAuthentication must be called before UseAuthorization" in f.description 
              for f in ordering_findings)
    print("[PASS] Authorization before Authentication detection test passed")


def test_permissive_cors_allowanyorigin():
    """Test detection of AllowAnyOrigin CORS policy."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowAll", policy =>
        {
            policy.AllowAnyOrigin()
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
    });
    
    var app = builder.Build();
    
    app.UseHttpsRedirection();
    app.UseHsts();
    app.UseCors("AllowAll");
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should detect permissive CORS
    cors_findings = [f for f in result.findings 
                    if "cors" in f.title.lower() 
                    and f.requirement_id == "KSI-SVC-07"
                    and f.severity == Severity.MEDIUM]
    
    assert len(cors_findings) > 0, "Failed to detect permissive CORS with AllowAnyOrigin"
    print("[PASS] Permissive CORS AllowAnyOrigin detection test passed")


def test_permissive_cors_wildcard():
    """Test detection of wildcard in WithOrigins CORS configuration."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("WildcardPolicy", policy =>
        {
            policy.WithOrigins("*")
                  .AllowAnyHeader()
                  .AllowAnyMethod();
        });
    });
    
    var app = builder.Build();
    
    app.UseHttpsRedirection();
    app.UseHsts();
    app.UseCors("WildcardPolicy");
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should detect wildcard CORS
    cors_findings = [f for f in result.findings 
                    if "cors" in f.title.lower() 
                    and f.requirement_id == "KSI-SVC-07"
                    and f.severity == Severity.MEDIUM]
    
    assert len(cors_findings) > 0, "Failed to detect permissive CORS with wildcard"
    print("[PASS] Permissive CORS wildcard detection test passed")


def test_proper_cors_configuration():
    """Test recognition of proper CORS configuration with specific origins."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    var builder = WebApplication.CreateBuilder(args);
    
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowedOrigins", policy =>
        {
            policy.WithOrigins(
                    "https://yourdomain.com",
                    "https://app.yourdomain.com"
                )
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });
    
    var app = builder.Build();
    
    if (!app.Environment.IsDevelopment())
    {
        app.UseHsts();
    }
    
    app.UseHttpsRedirection();
    app.UseStaticFiles();
    app.UseRouting();
    app.UseCors("AllowedOrigins");
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapControllers();
    
    app.Run();
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Program.cs")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-SVC-07"]
    
    # Should NOT have CORS warnings
    cors_warnings = [f for f in result.findings 
                    if "cors" in f.title.lower() 
                    and not f.good_practice
                    and f.requirement_id == "KSI-SVC-07"]
    
    assert len(good_practices) > 0, "Failed to recognize proper CORS and middleware configuration"
    assert len(cors_warnings) == 0, "False positive: Flagged proper CORS configuration"
    print("[PASS] Proper CORS configuration test passed")


def test_non_startup_file_ignored():
    """Test that non-startup files (controllers, models) are ignored."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetUsers()
        {
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UsersController.cs")
    
    # Should NOT report KSI-SVC-07 findings for controller files
    svc07_findings = [f for f in result.findings 
                     if f.requirement_id == "KSI-SVC-07"]
    
    assert len(svc07_findings) == 0, "Incorrectly flagged non-startup file"
    print("[PASS] Non-startup file ignored test passed")


if __name__ == "__main__":
    print("=== Running AST Secure Coding Tests (Tier 1.3) ===\n")
    
    test_correct_middleware_ordering()
    test_missing_https_redirection()
    test_missing_hsts()
    test_authorization_before_authentication()
    test_permissive_cors_allowanyorigin()
    test_permissive_cors_wildcard()
    test_proper_cors_configuration()
    test_non_startup_file_ignored()
    
    print("\n=== All AST Secure Coding Tests Passed ===")
