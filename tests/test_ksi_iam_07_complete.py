"""
Comprehensive test suite for KSI-IAM-07: Automated Account Management
Tests AST-based detection for account lifecycle automation
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory


def test_python_manual_user_creation_without_automation():
    """Test detection of manual User.objects.create() without lifecycle automation"""
    code = """
from django.contrib.auth.models import User

def register_user(request):
    username = request.POST.get('username')
    email = request.POST.get('email')
    password = request.POST.get('password')
    
    # Manual user creation without automation
    user = User.objects.create(
        username=username,
        email=email,
        password=password
    )
    
    return JsonResponse({'status': 'created'})
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "views.py")
    
    assert result.total_issues >= 1, f"Expected detection but got {result.total_issues} findings"
    
    medium_findings = [f for f in result.findings if f.severity.value == "medium"]
    assert len(medium_findings) >= 1, "Expected medium severity finding for manual user creation"
    
    assert any("Manual User Creation" in f.title for f in medium_findings), \
        f"Expected 'Manual User Creation' in title, got: {[f.title for f in medium_findings]}"
    
    print("[PASS] Python: Detects manual user creation without lifecycle automation")


def test_python_user_creation_with_automation():
    """Test acceptance of user creation WITH automation (Django signals)"""
    code = """
from django.contrib.auth.models import User
from django.db.models.signals import post_save
from django.dispatch import receiver

def register_user(request):
    user = User.objects.create(
        username=request.POST.get('username'),
        email=request.POST.get('email')
    )
    return JsonResponse({'status': 'created'})

@receiver(post_save, sender=User)
def on_user_created(sender, instance, created, **kwargs):
    if created:
        # Automated provisioning workflow
        provision_user_accounts(instance)
        send_welcome_email(instance)
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "views.py")
    
    # Should NOT flag because @receiver decorator is present (automation)
    manual_findings = [f for f in result.findings if "Manual User Creation" in f.title]
    assert len(manual_findings) == 0, \
        f"Should not flag user creation with @receiver automation, but got: {[f.title for f in manual_findings]}"
    
    print("[PASS] Python: Accepts user creation with @receiver automation")


def test_python_user_management_without_deprovisioning():
    """Test detection of User management without deprovisioning logic"""
    code = """
from django.contrib.auth.models import User

def get_users():
    users = User.objects.all()
    return list(users)

def update_user(user_id, email):
    user = User.objects.get(id=user_id)
    user.email = email
    user.save()
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "views.py")
    
    assert result.total_issues >= 1, f"Expected detection but got {result.total_issues} findings"
    
    high_findings = [f for f in result.findings if f.severity.value == "high"]
    assert len(high_findings) >= 1, "Expected high severity finding for missing deprovisioning"
    
    assert any("Deprovisioning" in f.title for f in high_findings), \
        f"Expected 'Deprovisioning' in title, got: {[f.title for f in high_findings]}"
    
    print("[PASS] Python: Detects User management without deprovisioning logic")


def test_python_user_management_with_deprovisioning():
    """Test acceptance of User management WITH deprovisioning"""
    code = """
from django.contrib.auth.models import User

def get_users():
    users = User.objects.all()
    return list(users)

def disable_user(user_id):
    user = User.objects.get(id=user_id)
    user.is_active = False
    user.save()
    revoke_all_sessions(user_id)
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "views.py")
    
    # Should NOT flag because deprovisioning logic is present (is_active = False)
    deprovision_findings = [f for f in result.findings if "Deprovisioning" in f.title]
    assert len(deprovision_findings) == 0, \
        f"Should not flag with deprovisioning logic, but got: {[f.title for f in deprovision_findings]}"
    
    print("[PASS] Python: Accepts User management with deprovisioning logic")


def test_python_user_model_without_lifecycle_fields():
    """Test detection of User model without lifecycle tracking fields"""
    code = """
from django.db import models

class User(models.Model):
    username = models.CharField(max_length=150)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    created_at = models.DateTimeField(auto_now_add=True)
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "models.py")
    
    assert result.total_issues >= 1, f"Expected detection but got {result.total_issues} findings"
    
    medium_findings = [f for f in result.findings if f.severity.value == "medium"]
    assert len(medium_findings) >= 1, "Expected medium severity finding for missing lifecycle fields"
    
    assert any("Lifecycle Tracking" in f.title for f in medium_findings), \
        f"Expected 'Lifecycle Tracking' in title, got: {[f.title for f in medium_findings]}"
    
    print("[PASS] Python: Detects User model without lifecycle tracking fields")


def test_python_user_model_with_lifecycle_fields():
    """Test acceptance of User model WITH lifecycle tracking fields"""
    code = """
from django.db import models

class User(models.Model):
    username = models.CharField(max_length=150)
    email = models.EmailField()
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(null=True)
    last_activity = models.DateTimeField(auto_now=True)
    account_expiration_date = models.DateTimeField(null=True)
    is_active = models.BooleanField(default=True)
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "models.py")
    
    # Should NOT flag because lifecycle tracking fields are present
    lifecycle_findings = [f for f in result.findings if "Lifecycle Tracking" in f.title]
    assert len(lifecycle_findings) == 0, \
        f"Should not flag with lifecycle fields, but got: {[f.title for f in lifecycle_findings]}"
    
    print("[PASS] Python: Accepts User model with lifecycle tracking fields")


def test_csharp_manual_user_creation_without_automation():
    """Test detection of C# UserManager.CreateAsync without automation"""
    code = """
using Microsoft.AspNetCore.Identity;

public class UserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    
    public async Task<IdentityResult> RegisterUser(string username, string email, string password)
    {
        var user = new ApplicationUser
        {
            UserName = username,
            Email = email
        };
        
        // Manual user creation without automation
        var result = await _userManager.CreateAsync(user, password);
        
        return result;
    }
}
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "csharp", "UserService.cs")
    
    assert result.total_issues >= 1, f"Expected detection but got {result.total_issues} findings"
    
    medium_findings = [f for f in result.findings if f.severity.value == "medium"]
    assert len(medium_findings) >= 1, "Expected medium severity finding for manual user creation"
    
    print("[PASS] C#: Detects UserManager.CreateAsync without lifecycle automation")


def test_java_manual_user_creation_without_automation():
    """Test detection of Java user repository save without automation"""
    code = """
import org.springframework.security.core.userdetails.User;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    
    public User createUser(String username, String email, String password) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        
        // Manual user creation without automation
        return userRepository.save(user);
    }
}
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "java", "UserService.java")
    
    assert result.total_issues >= 1, f"Expected detection but got {result.total_issues} findings"
    
    print("[PASS] Java: Detects userRepository.save() without lifecycle automation")


def test_python_regex_fallback():
    """Test regex fallback works when Python code has syntax errors"""
    code = """
def register_user(request):
    # Syntax error: unclosed bracket
    user = User.objects.create(
        username=request.POST.get('username'
"""
    
    factory = get_factory()
    result = factory.analyze("KSI-IAM-07", code, "python", "views.py")
    
    # Should use regex fallback and detect manual user creation
    assert result.total_issues >= 1, "Regex fallback should detect manual user creation"
    
    fallback_findings = [f for f in result.findings if "Regex Fallback" in f.title or "Manual User Creation" in f.title]
    assert len(fallback_findings) >= 1, "Expected regex fallback finding"
    
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all KSI-IAM-07 tests"""
    print("\n" + "="*70)
    print("Running KSI-IAM-07 (Automated Account Management) Tests")
    print("="*70 + "\n")
    
    tests = [
        test_python_manual_user_creation_without_automation,
        test_python_user_creation_with_automation,
        test_python_user_management_without_deprovisioning,
        test_python_user_management_with_deprovisioning,
        test_python_user_model_without_lifecycle_fields,
        test_python_user_model_with_lifecycle_fields,
        test_csharp_manual_user_creation_without_automation,
        test_java_manual_user_creation_without_automation,
        test_python_regex_fallback,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("="*70 + "\n")
    
    if failed == 0:
        print("ALL TESTS PASSED!\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
