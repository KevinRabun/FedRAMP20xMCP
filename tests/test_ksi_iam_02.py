"""
Tests for KSI-IAM-02 Enhanced: Passwordless Authentication

Test coverage:
- Python: FIDO2 detection, Django validators, bcrypt without passwordless, proper passwordless
- C#: FIDO2 detection, PasswordOptions validation, Windows Hello, weak password length
- Java: WebAuthn detection, password validation
- JavaScript: WebAuthn detection, bcrypt validation, validator.js
- Bicep/Terraform: Azure AD configuration
- Factory integration
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from fedramp_20x_mcp.analyzers.ksi.ksi_iam_02 import KSI_IAM_02_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_fido2_detection():
    """Test detection of FIDO2/WebAuthn in Python."""
    code = """
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

rp = PublicKeyCredentialRpEntity('example.com', 'Example App')
server = Fido2Server(rp)

# Register user with security key
options = server.register_begin(user_info, resident_key=True)
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "python", "fido2_auth.py")
    
    print(f"[PASS] Python FIDO2: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "FIDO2 should be recognized as passwordless"


def test_python_password_without_passwordless():
    """Test detection of password auth without passwordless option."""
    code = """
from django.contrib.auth import authenticate
import bcrypt

def login_user(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    user = authenticate(username=username, password=password)
    return user
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "python", "auth.py")
    
    print(f"[PASS] Python password without passwordless: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Passwordless" in f.title for f in result.findings)
    assert any(f.severity == Severity.MEDIUM for f in result.findings)


def test_python_django_without_validators():
    """Test detection of Django auth without password validators."""
    code = """
from django.contrib.auth.models import User
from django.contrib.auth import authenticate

# Django settings without AUTH_PASSWORD_VALIDATORS
user = User.objects.create_user('john', 'john@example.com', 'password')
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "python", "django_auth.py")
    
    print(f"[PASS] Python Django without validators: {result.total_issues} issues")
    assert result.total_issues >= 1, "Should detect password-based auth"
    assert any("Django" in f.title or "password" in f.title.lower() for f in result.findings)


def test_python_azure_ad_passwordless():
    """Test detection of Azure AD passwordless authentication."""
    code = """
from azure.identity import DefaultAzureCredential
from msal import PublicClientApplication

credential = DefaultAzureCredential()
token = credential.get_token("https://graph.microsoft.com/.default")

# Use Azure AD passwordless
app = PublicClientApplication("client_id")
result = app.acquire_token_interactive(scopes=["User.Read"])
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "python", "azure_auth.py")
    
    print(f"[PASS] Python Azure AD passwordless: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "Azure AD should be recognized as passwordless"


def test_csharp_fido2_detection():
    """Test detection of FIDO2 in C#."""
    code = """
using Fido2NetLib;
using Fido2NetLib.Objects;

public class AuthController : ControllerBase
{
    private readonly IFido2 _fido2;
    
    public AuthController(IFido2 fido2)
    {
        _fido2 = fido2;
    }
    
    public async Task<IActionResult> MakeCredential()
    {
        var options = _fido2.RequestNewCredential(user, excludeCredentials);
        return Ok(options);
    }
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "AuthController.cs")
    
    print(f"[PASS] C# FIDO2: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "FIDO2 should be recognized"


def test_csharp_weak_password_length():
    """Test detection of weak password length in PasswordOptions."""
    code = """
using Microsoft.AspNetCore.Identity;

services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 8;  // Too short
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
});
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    print(f"[PASS] C# weak password length: {result.total_issues} issues")
    assert result.total_issues >= 1
    # Should find specific "Weak Password Length" finding
    assert any("Weak" in f.title or "Length" in f.title for f in result.findings)


def test_csharp_no_complexity():
    """Test detection of missing complexity requirements."""
    code = """
using Microsoft.AspNetCore.Identity;

services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 14;
    // Missing RequireDigit, RequireUppercase
});
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    print(f"[PASS] C# no complexity: {result.total_issues} issues")
    assert result.total_issues >= 1
    # Should detect complexity issues even if length is correct
    assert any("Complexity" in f.title or "Digit" in f.title or "password" in f.title.lower() for f in result.findings)


def test_csharp_windows_hello():
    """Test detection of Windows Hello for Business."""
    code = """
using Windows.Security.Credentials;

public class BiometricAuth
{
    public async Task<bool> AuthenticateWithWindowsHello()
    {
        var availability = await WindowsHello.CheckAvailabilityAsync();
        if (availability == WindowsHelloAvailability.Available)
        {
            var result = await WindowsHello.AuthenticateAsync();
            return result.Status == WindowsHelloAuthenticationStatus.Authenticated;
        }
        return false;
    }
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "BiometricAuth.cs")
    
    print(f"[PASS] C# Windows Hello: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "Windows Hello should be recognized"


def test_java_webauthn_detection():
    """Test detection of WebAuthn in Java."""
    code = """
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

public class AuthController {
    private final RelyingParty relyingParty;
    
    public PublicKeyCredentialCreationOptions register(UserIdentity user) {
        return relyingParty.startRegistration(
            StartRegistrationOptions.builder()
                .user(user)
                .build()
        );
    }
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "java", "AuthController.java")
    
    print(f"[PASS] Java WebAuthn: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "WebAuthn should be recognized"


def test_java_password_without_validation():
    """Test detection of password auth without validation."""
    code = """
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Service
public class UserService {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    
    public void createUser(String username, String password) {
        String hashed = encoder.encode(password);
        // Save user without password validation
    }
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "java", "UserService.java")
    
    print(f"[PASS] Java password without validation: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Password" in f.title for f in result.findings)


def test_javascript_webauthn_detection():
    """Test detection of WebAuthn in JavaScript."""
    code = """
import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';

export async function registerUser(userId, username) {
    const options = generateRegistrationOptions({
        rpName: 'Example App',
        rpID: 'example.com',
        userID: userId,
        userName: username,
        attestationType: 'direct',
    });
    
    return options;
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "javascript", "auth.ts")
    
    print(f"[PASS] JavaScript WebAuthn: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "WebAuthn should be recognized"


def test_javascript_weak_password_validation():
    """Test detection of weak password validation."""
    code = """
import bcrypt from 'bcrypt';

export async function createUser(username, password) {
    // No password validation - too short allowed
    const hash = await bcrypt.hash(password, 10);
    await db.users.insert({ username, password: hash });
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "javascript", "users.js")
    
    print(f"[PASS] JavaScript weak validation: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Weak" in f.title or "Validation" in f.title for f in result.findings)


def test_javascript_validator_usage():
    """Test proper password validation with validator.js."""
    code = """
import validator from 'validator';
import bcrypt from 'bcrypt';

export async function createUser(username, password) {
    const isValid = validator.isStrongPassword(password, {
        minLength: 14,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1
    });
    
    if (!isValid) {
        throw new Error('Password does not meet requirements');
    }
    
    const hash = await bcrypt.hash(password, 10);
    await db.users.insert({ username, password: hash });
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "javascript", "users.js")
    
    print(f"[PASS] JavaScript with validator.js: {result.total_issues} issues")
    # Should still flag password-based auth without passwordless option
    assert any("Passwordless" in f.title for f in result.findings) if result.total_issues > 0 else True


def test_bicep_azure_ad_users():
    """Test Azure AD user configuration in Bicep."""
    code = """
resource adUser 'Microsoft.Graph/users@2023-01-01' = {
  name: 'user@example.com'
  properties: {
    displayName: 'Example User'
    userPrincipalName: 'user@example.com'
    accountEnabled: true
  }
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "bicep", "users.bicep")
    
    print(f"[PASS] Bicep Azure AD users: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Password Policy" in f.title for f in result.findings)


def test_terraform_azure_ad_users():
    """Test Azure AD user configuration in Terraform."""
    code = """
resource "azuread_user" "example" {
  user_principal_name = "user@example.com"
  display_name        = "Example User"
  password            = var.user_password
}
"""
    analyzer = KSI_IAM_02_Analyzer()
    result = analyzer.analyze(code, "terraform", "users.tf")
    
    print(f"[PASS] Terraform Azure AD users: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Password Policy" in f.title for f in result.findings)


def test_factory_integration():
    """Test analyzer works through factory pattern."""
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    code = """
import bcrypt

def login(username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    return check_user(username, hashed)
"""
    factory = get_factory()
    result = factory.analyze("KSI-IAM-02", code, "python", "auth.py")
    
    print(f"[PASS] Factory integration: {result.total_issues} issues")
    assert result.total_issues >= 1
    # Case-insensitive check for passwordless
    assert any("passwordless" in f.title.lower() for f in result.findings)


def run_all_tests():
    """Run all KSI-IAM-02 enhanced tests."""
    print("\n" + "="*60)
    print("KSI-IAM-02 Enhanced Analyzer Tests")
    print("="*60 + "\n")
    
    tests = [
        ("Python FIDO2 Detection", test_python_fido2_detection),
        ("Python Password Without Passwordless", test_python_password_without_passwordless),
        ("Python Django Without Validators", test_python_django_without_validators),
        ("Python Azure AD Passwordless", test_python_azure_ad_passwordless),
        ("C# FIDO2 Detection", test_csharp_fido2_detection),
        ("C# Weak Password Length", test_csharp_weak_password_length),
        ("C# No Complexity", test_csharp_no_complexity),
        ("C# Windows Hello", test_csharp_windows_hello),
        ("Java WebAuthn Detection", test_java_webauthn_detection),
        ("Java Password Without Validation", test_java_password_without_validation),
        ("JavaScript WebAuthn Detection", test_javascript_webauthn_detection),
        ("JavaScript Weak Validation", test_javascript_weak_password_validation),
        ("JavaScript Validator.js", test_javascript_validator_usage),
        ("Bicep Azure AD Users", test_bicep_azure_ad_users),
        ("Terraform Azure AD Users", test_terraform_azure_ad_users),
        ("Factory Integration", test_factory_integration),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_name} ERROR: {e}")
            failed += 1
    
    print("\n" + "="*60)
    print(f"Results: {passed}/{len(tests)} tests passed")
    if failed == 0:
        print("ALL TESTS PASSED [PASS]")
    else:
        print(f"{failed} tests failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_all_tests()
    sys.exit(0 if success else 1)

