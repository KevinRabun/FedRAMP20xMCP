"""
Tests for KSI-IAM-01 Enhanced Analyzer: Phishing-Resistant MFA

Tests AST-based detection of MFA implementation and phishing-resistant methods.
"""

import sys
sys.path.insert(0, 'c:\\source\\FedRAMP20xMCP\\src')

from fedramp_20x_mcp.analyzers.ksi.ksi_iam_01 import KSI_IAM_01_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_totp_non_phishing_resistant():
    """Test detection of TOTP as non-phishing-resistant MFA."""
    code = """
import pyotp
from flask import Flask, request, session

app = Flask(__name__)

@app.route('/verify-mfa', methods=['POST'])
def verify_mfa():
    totp = pyotp.TOTP(session['mfa_secret'])
    token = request.form['token']
    if totp.verify(token):
        return "MFA verified"
    return "Invalid token"
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect TOTP as non-phishing-resistant"
    assert any("totp" in f.title.lower() and "phishing" in f.description.lower() for f in medium_findings)
    
    print("[PASS] Python TOTP non-phishing-resistant detection working")


def test_python_login_without_mfa():
    """Test detection of login function without MFA."""
    code = """
from flask import Flask, request, session

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if verify_credentials(username, password):
        session['user'] = username
        return "Login successful"
    return "Invalid credentials"
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect login without MFA"
    assert any("mfa" in f.title.lower() or "multi-factor" in f.description.lower() for f in critical_findings)
    
    print("[PASS] Python login without MFA detection working")


def test_python_phishing_resistant_fido2():
    """Test that FIDO2/WebAuthn implementation is recognized as good."""
    code = """
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
from flask import Flask, request

app = Flask(__name__)
rp = PublicKeyCredentialRpEntity("example.com", "Example App")
server = Fido2Server(rp)

@app.route('/login', methods=['POST'])
def login():
    # Verify password first
    if verify_password(request.form['username'], request.form['password']):
        # Then require FIDO2 MFA
        credentials = get_user_credentials(request.form['username'])
        auth_data = server.authenticate_begin(credentials)
        return auth_data
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    # Should not have critical findings for FIDO2 implementation
    assert len(critical_findings) == 0, "FIDO2 implementation should not trigger critical findings"
    
    print("[PASS] Python FIDO2 phishing-resistant MFA passes")


def test_python_decorator_without_mfa():
    """Test detection of auth decorator without MFA enforcement."""
    code = """
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route('/protected')
@login_required
def protected_view():
    return "This is protected"
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect decorator without MFA enforcement"
    assert any("decorator" in f.title.lower() or "mfa" in f.description.lower() for f in high_findings)
    
    print("[PASS] Python auth decorator without MFA detection working")


def test_csharp_authorize_without_mfa():
    """Test detection of [Authorize] without MFA requirement."""
    code = """
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace MyApp.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[controller]")]
    public class DataController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetData()
        {
            return Ok(new { data = "sensitive" });
        }
    }
}
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "csharp", "DataController.cs")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect [Authorize] without MFA"
    assert any("authorize" in f.title.lower() or "mfa" in f.description.lower() for f in high_findings)
    
    print("[PASS] C# [Authorize] without MFA detection working")


def test_csharp_identity_without_mfa_enforcement():
    """Test detection of ASP.NET Core Identity without RequireTwoFactor."""
    code = """
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        
        services.Configure<IdentityOptions>(options =>
        {
            options.Password.RequireDigit = true;
            options.Password.RequiredLength = 8;
        });
    }
}
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect Identity without RequireTwoFactor"
    assert any("identity" in f.title.lower() and "mfa" in f.description.lower() for f in critical_findings)
    
    print("[PASS] C# Identity without MFA enforcement detection working")


def test_csharp_certificate_auth_secure():
    """Test that certificate-based authentication is recognized as secure."""
    code = """
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
            .AddCertificate(options =>
            {
                options.AllowedCertificateTypes = CertificateTypes.All;
                options.RevocationMode = X509RevocationMode.Online;
            });
    }
}
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    # Certificate auth is phishing-resistant, should not have critical findings
    assert len(critical_findings) == 0, "Certificate authentication should not trigger critical findings"
    
    print("[PASS] C# certificate-based authentication passes")


def test_java_spring_security_without_mfa():
    """Test detection of Spring Security without MFA."""
    code = """
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/**").authenticated()
            .and()
            .formLogin();
    }
}
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "java", "SecurityConfig.java")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect Spring Security without MFA"
    assert any("spring security" in f.title.lower() and "mfa" in f.description.lower() for f in critical_findings)
    
    print("[PASS] Java Spring Security without MFA detection working")


def test_java_totp_non_phishing_resistant():
    """Test detection of TOTP as non-phishing-resistant in Java."""
    code = """
import com.warrenstrange.googleauth.GoogleAuthenticator;
import org.springframework.stereotype.Service;

@Service
public class MfaService {
    
    private final GoogleAuthenticator googleAuth = new GoogleAuthenticator();
    
    public boolean verifyCode(String secret, int code) {
        return googleAuth.authorize(secret, code);
    }
}
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "java", "MfaService.java")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect TOTP as non-phishing-resistant"
    assert any("totp" in f.title.lower() and "phishing" in f.description.lower() for f in medium_findings)
    
    print("[PASS] Java TOTP non-phishing-resistant detection working")


def test_javascript_passport_without_mfa():
    """Test detection of Passport.js without phishing-resistant MFA."""
    code = """
const express = require('express');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const app = express();

passport.use(new LocalStrategy(
    function(username, password, done) {
        User.findOne({ username: username }, function(err, user) {
            if (err) return done(err);
            if (!user) return done(null, false);
            if (!user.verifyPassword(password)) return done(null, false);
            return done(null, user);
        });
    }
));

app.post('/login', passport.authenticate('local'), (req, res) => {
    res.json({ message: 'Logged in' });
});
"""
    
    analyzer = KSI_IAM_01_Analyzer()
    result = analyzer.analyze(code, "javascript", "auth.js")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect Passport without MFA"
    assert any("passport" in f.title.lower() and "mfa" in f.description.lower() for f in high_findings)
    
    print("[PASS] JavaScript Passport.js without MFA detection working")


def test_factory_function():
    """Test direct instantiation of analyzers."""
    analyzer_py = KSI_IAM_01_Analyzer(CodeLanguage.PYTHON)
    assert analyzer_py.direct_language == CodeLanguage.PYTHON
    
    analyzer_cs = KSI_IAM_01_Analyzer(CodeLanguage.CSHARP)
    assert analyzer_cs.direct_language == CodeLanguage.CSHARP
    
    analyzer_java = KSI_IAM_01_Analyzer(CodeLanguage.JAVA)
    assert analyzer_java.direct_language == CodeLanguage.JAVA
    
    analyzer_js = KSI_IAM_01_Analyzer(CodeLanguage.JAVASCRIPT)
    assert analyzer_js.direct_language == CodeLanguage.JAVASCRIPT
    
    print("[PASS] Direct instantiation working")


if __name__ == "__main__":
    print("Running KSI-IAM-01 Enhanced Analyzer tests...\n")
    
    tests = [
        test_python_totp_non_phishing_resistant,
        test_python_login_without_mfa,
        test_python_phishing_resistant_fido2,
        test_python_decorator_without_mfa,
        test_csharp_authorize_without_mfa,
        test_csharp_identity_without_mfa_enforcement,
        test_csharp_certificate_auth_secure,
        test_java_spring_security_without_mfa,
        test_java_totp_non_phishing_resistant,
        test_javascript_passport_without_mfa,
        test_factory_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} error: {e}")
            failed += 1
    
    print(f"\n{'=' * 60}")
    print(f"KSI-IAM-01 Enhanced Tests: {passed}/{len(tests)} passed")
    if failed > 0:
        print(f"FAILURES: {failed}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED [PASS]")
        sys.exit(0)

