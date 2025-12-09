"""
Tests for KSI-IAM-06 Enhanced Analyzer: Suspicious Activity

Test coverage:
- Python: Django AXES, Flask-Login, lockout configuration
- C#: ASP.NET Core Identity lockout settings
- Java: Spring Security failure handlers
- JavaScript: Passport.js rate limiting
- Bicep: Azure AD Conditional Access policies
- Terraform: azuread_conditional_access_policy
"""

import sys
sys.path.insert(0, 'src')

from fedramp_20x_mcp.analyzers.ksi.ksi_iam_06 import KSI_IAM_06_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_django_axes_missing_config():
    """Test detection of Django AXES without FAILURE_LIMIT."""
    code = """
import axes
from axes.middleware import AxesMiddleware

# Missing AXES_FAILURE_LIMIT configuration
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "python", "settings.py")
    
    print(f"\n[Python Django AXES Missing Config] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("AXES_FAILURE_LIMIT" in f.title for f in result.findings)
    assert result.findings[0].severity == Severity.HIGH
    print("[PASS] Django AXES missing config detected")


def test_python_django_axes_weak_threshold():
    """Test detection of weak AXES_FAILURE_LIMIT."""
    code = """
import axes

AXES_FAILURE_LIMIT = 15  # Too high!
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "python", "settings.py")
    
    print(f"\n[Python Django AXES Weak Threshold] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Weak" in f.title or "Threshold" in f.title for f in result.findings)
    assert result.findings[0].severity == Severity.MEDIUM
    print("[PASS] Django AXES weak threshold detected")


def test_python_django_axes_proper_config():
    """Test proper Django AXES configuration."""
    code = """
import axes

AXES_FAILURE_LIMIT = 5
AXES_COOLOFF_TIME = timedelta(minutes=30)
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "python", "settings.py")
    
    print(f"\n[Python Django AXES Proper Config] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # Should pass - proper config
    assert result.total_issues == 0
    print("[PASS] Django AXES proper config recognized")


def test_python_flask_login_without_lockout():
    """Test detection of Flask-Login without lockout mechanism."""
    code = """
from flask_login import LoginManager, login_user

login_manager = LoginManager()

@app.route('/login', methods=['POST'])
def login():
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        login_user(user)
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "python", "auth.py")
    
    print(f"\n[Python Flask-Login Without Lockout] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Lockout" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Flask-Login without lockout detected")


def test_python_missing_failed_login_logging():
    """Test detection of authentication without logging."""
    code = """
def login(username, password):
    user = authenticate(username, password)
    if user:
        return user
    return None
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "python", "auth.py")
    
    print(f"\n[Python Missing Failed Login Logging] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Logging" in f.title or "logging" in f.title for f in result.findings)
    print("[PASS] Missing failed login logging detected")


def test_csharp_identity_missing_max_failed():
    """Test detection of Identity without MaxFailedAccessAttempts."""
    code = """
using Microsoft.AspNetCore.Identity;

services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    options.Password.RequireDigit = true;
    // Missing MaxFailedAccessAttempts
});
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    print(f"\n[C# Identity Missing MaxFailed] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("MaxFailedAccessAttempts" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] C# Identity missing MaxFailedAccessAttempts detected")


def test_csharp_identity_weak_threshold():
    """Test detection of weak MaxFailedAccessAttempts."""
    code = """
using Microsoft.AspNetCore.Identity;

services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    options.Lockout.MaxFailedAccessAttempts = 20;  // Too high!
});
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    print(f"\n[C# Identity Weak Threshold] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Weak" in f.title or "Threshold" in f.title for f in result.findings)
    print("[PASS] C# Identity weak threshold detected")


def test_csharp_identity_proper_config():
    """Test proper ASP.NET Core Identity lockout configuration."""
    code = """
using Microsoft.AspNetCore.Identity;

services.AddIdentity<ApplicationUser, IdentityRole>(options => {
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.LockoutEnabled = true;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
});
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    print(f"\n[C# Identity Proper Config] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    # Should pass - proper config
    assert result.total_issues == 0
    print("[PASS] C# Identity proper config recognized")


def test_java_spring_security_missing_failure_handler():
    """Test detection of Spring Security without failure handler."""
    code = """
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin();
        // Missing AuthenticationFailureHandler
    }
}
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "java", "SecurityConfig.java")
    
    print(f"\n[Java Spring Security Missing Handler] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1, f"Expected findings but got {result.total_issues}"
    assert any("Failure Handler" in f.title or "FailureHandler" in f.title for f in result.findings)
    print("[PASS] Java Spring Security missing failure handler detected")


def test_javascript_passport_without_rate_limit():
    """Test detection of Passport.js without rate limiting."""
    code = """
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

passport.use(new LocalStrategy(
  function(username, password, done) {
    // Missing rate limiting
  }
));
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "javascript", "auth.js")
    
    print(f"\n[JavaScript Passport Without Rate Limit] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Rate Limiting" in f.title or "Rate" in f.title for f in result.findings)
    print("[PASS] JavaScript Passport without rate limiting detected")


def test_bicep_missing_conditional_access():
    """Test detection of missing Azure AD Conditional Access policy."""
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  kind: 'StorageV2'
}
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "bicep", "main.bicep")
    
    print(f"\n[Bicep Missing Conditional Access] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Conditional Access" in f.title for f in result.findings)
    print("[PASS] Bicep missing Conditional Access detected")


def test_terraform_missing_conditional_access():
    """Test detection of missing azuread_conditional_access_policy."""
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
"""
    analyzer = KSI_IAM_06_Analyzer()
    result = analyzer.analyze(code, "terraform", "main.tf")
    
    print(f"\n[Terraform Missing Conditional Access] Findings: {result.total_issues}")
    for finding in result.findings:
        print(f"  - {finding.title}")
    
    assert result.total_issues >= 1
    assert any("Conditional Access" in f.title for f in result.findings)
    print("[PASS] Terraform missing Conditional Access detected")


def test_factory_function():
    """Test factory function returns correct instance."""
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    assert factory is not None
    
    # Test factory can create analyzer
    analyzer = factory.get_analyzer("KSI-IAM-06")
    assert analyzer is not None
    print("[PASS] Factory function works correctly")


if __name__ == "__main__":
    print("\n=== KSI-IAM-06 Enhanced Analyzer Tests ===\n")
    
    tests = [
        ("Python Django AXES missing config", test_python_django_axes_missing_config),
        ("Python Django AXES weak threshold", test_python_django_axes_weak_threshold),
        ("Python Django AXES proper config", test_python_django_axes_proper_config),
        ("Python Flask-Login without lockout", test_python_flask_login_without_lockout),
        ("Python missing failed login logging", test_python_missing_failed_login_logging),
        ("C# Identity missing MaxFailed", test_csharp_identity_missing_max_failed),
        ("C# Identity weak threshold", test_csharp_identity_weak_threshold),
        ("C# Identity proper config", test_csharp_identity_proper_config),
        ("Java Spring Security missing handler", test_java_spring_security_missing_failure_handler),
        ("JavaScript Passport without rate limit", test_javascript_passport_without_rate_limit),
        ("Bicep missing Conditional Access", test_bicep_missing_conditional_access),
        ("Terraform missing Conditional Access", test_terraform_missing_conditional_access),
        ("Factory function", test_factory_function),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}\n")
    
    sys.exit(0 if failed == 0 else 1)

