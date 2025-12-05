#!/usr/bin/env python3
"""
Test AST-enhanced session management detection for C# analyzer (Tier 2.2).

Tests KSI-IAM-07 requirements for secure session cookie configuration.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer


def test_missing_httponly_flag():
    """Test detection of HttpOnly flag set to false."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = false;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.IdleTimeout = TimeSpan.FromMinutes(20);
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should detect HttpOnly = false as HIGH severity issue
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-IAM-07" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect HttpOnly = false"
    assert "HttpOnly" in issues[0].description, "Issue should mention HttpOnly"
    print("[PASS] Missing HttpOnly flag detection test passed")


def test_missing_secure_policy():
    """Test detection of SecurePolicy set to None."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.None;
                options.Cookie.SameSite = SameSiteMode.Strict;
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should detect SecurePolicy = None as HIGH severity issue
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-IAM-07" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect SecurePolicy = None"
    assert "SecurePolicy" in issues[0].description or "Secure" in issues[0].description, "Issue should mention SecurePolicy"
    print("[PASS] Missing SecurePolicy detection test passed")


def test_insecure_samesite():
    """Test detection of SameSite set to None."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.None;
                options.IdleTimeout = TimeSpan.FromMinutes(20);
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should detect SameSite = None as HIGH severity issue
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-IAM-07" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect SameSite = None"
    assert "SameSite" in issues[0].description, "Issue should mention SameSite"
    print("[PASS] Insecure SameSite detection test passed")


def test_missing_timeout():
    """Test detection of missing session timeout configuration."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should detect missing timeout as HIGH severity issue
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-IAM-07" 
              and not f.good_practice
              and f.severity.value == "high"]
    
    assert len(issues) > 0, "Failed to detect missing timeout"
    assert "timeout" in issues[0].description.lower(), "Issue should mention timeout"
    print("[PASS] Missing timeout detection test passed")


def test_secure_session_configuration():
    """Test recognition of fully secure session configuration."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.IdleTimeout = TimeSpan.FromMinutes(20);
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should recognize as good practice
    good_practices = [f for f in result.findings 
                     if f.requirement_id == "KSI-IAM-07" 
                     and f.good_practice]
    
    assert len(good_practices) > 0, "Failed to recognize secure session configuration"
    assert "secure" in good_practices[0].title.lower(), "Should mention secure in title"
    print("[PASS] Secure session configuration recognition test passed")


def test_secure_authentication_cookie():
    """Test recognition of secure authentication cookie configuration."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should recognize as good practice
    good_practices = [f for f in result.findings 
                     if f.requirement_id == "KSI-IAM-07" 
                     and f.good_practice]
    
    assert len(good_practices) > 0, "Failed to recognize secure authentication cookie"
    print("[PASS] Secure authentication cookie recognition test passed")


def test_multiple_security_issues():
    """Test detection of multiple security issues in single configuration."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = false;
                options.Cookie.SecurePolicy = CookieSecurePolicy.None;
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should detect multiple issues (HttpOnly, SecurePolicy, SameSite, timeout)
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-IAM-07" 
              and not f.good_practice]
    
    assert len(issues) > 0, "Failed to detect security issues"
    # Should mention multiple problems in description
    issue_text = issues[0].description.lower()
    assert "httponly" in issue_text, "Should mention HttpOnly issue"
    assert "securepolicy" in issue_text or "secure" in issue_text, "Should mention SecurePolicy issue"
    print("[PASS] Multiple security issues detection test passed")


def test_samesite_lax_acceptable():
    """Test that SameSite=Lax is acceptable (not just Strict)."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSession(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.IdleTimeout = TimeSpan.FromMinutes(30);
            });
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should NOT report SameSite issue for Lax (it's acceptable)
    issues = [f for f in result.findings 
              if f.requirement_id == "KSI-IAM-07" 
              and not f.good_practice]
    
    # If there are issues, they should not complain about SameSite=Lax
    for issue in issues:
        if "samesite" in issue.description.lower():
            assert "lax" not in issue.description.lower(), "Should not flag SameSite=Lax as issue"
    
    print("[PASS] SameSite=Lax acceptance test passed")


def test_no_session_config_no_findings():
    """Test that code without session configuration doesn't trigger false positives."""
    code = '''
    using Microsoft.AspNetCore.Builder;
    
    public class Startup
    {
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddEndpointsApiExplorer();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "Startup.cs")
    
    # Should have NO KSI-IAM-07 findings
    session_findings = [f for f in result.findings if f.requirement_id == "KSI-IAM-07"]
    
    assert len(session_findings) == 0, "Should not report session issues when no session config present"
    print("[PASS] No false positives for non-session code test passed")


if __name__ == "__main__":
    print("\n=== Testing AST-Enhanced Session Management (Tier 2.2) ===\n")
    
    test_missing_httponly_flag()
    test_missing_secure_policy()
    test_insecure_samesite()
    test_missing_timeout()
    test_secure_session_configuration()
    test_secure_authentication_cookie()
    test_multiple_security_issues()
    test_samesite_lax_acceptable()
    test_no_session_config_no_findings()
    
    print("\n=== All AST Session Management Tests Passed ===")
