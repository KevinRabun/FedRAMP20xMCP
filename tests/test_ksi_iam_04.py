"""
Tests for KSI-IAM-04 Enhanced: Just-in-Time Authorization

Test coverage:
- Python: Permanent admin access, missing route authorization, Azure PIM integration
- C#: Controllers without [Authorize], permanent admin roles, missing policies
- Java: Endpoints without @Secured, permanent admin roles
- JavaScript: Routes without middleware, permanent admin access
- Bicep/Terraform: Role assignments without PIM
- Factory integration
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / "src"))

from fedramp_20x_mcp.analyzers.ksi.ksi_iam_04 import KSI_IAM_04_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_permanent_admin():
    """Test detection of permanent admin access."""
    code = """
from django.contrib.auth.models import User

def promote_user(user_id):
    user = User.objects.get(id=user_id)
    user.is_superuser = True  # Permanent admin without time limit
    user.save()
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "python", "views.py")
    
    print(f"[PASS] Python permanent admin: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Permanent Privileged Access" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_python_route_without_auth():
    """Test detection of routes without authorization decorators."""
    code = """
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/admin')
def admin_endpoint():
    return jsonify({'data': 'sensitive'})
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    print(f"[PASS] Python route without auth: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Route Without" in f.title or "Authorization" in f.title for f in result.findings)
    assert any(f.severity == Severity.MEDIUM for f in result.findings)


def test_python_proper_jit_auth():
    """Test proper JIT authorization implementation."""
    code = """
from flask import Flask
from flask_login import login_required
from datetime import datetime, timedelta

app = Flask(__name__)

@app.route('/api/resource')
@login_required
@permission_required('resource.read')
def get_resource():
    return {'data': 'value'}

def grant_temporary_admin(user):
    user.is_admin = True
    user.admin_expires_at = datetime.utcnow() + timedelta(hours=8)
    user.save()
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "python", "secure_app.py")
    
    print(f"[PASS] Python proper JIT auth: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "Proper JIT authorization should not trigger findings"


def test_python_azure_pim_suggestion():
    """Test Azure PIM integration suggestion."""
    code = """
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = AuthorizationManagementClient(credential, subscription_id)

# Permanent role assignment
role_assignment = client.role_assignments.create(
    scope=scope,
    role_assignment_name=name,
    parameters={
        'role_definition_id': role_id,
        'principal_id': user_id
    }
)
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "python", "azure_iam.py")
    
    print(f"[PASS] Python Azure PIM suggestion: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Azure PIM" in f.title for f in result.findings)
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_csharp_controller_without_authorize():
    """Test detection of controllers without [Authorize]."""
    code = """
using Microsoft.AspNetCore.Mvc;

public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult GetUsers()
    {
        return Ok(users);
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "AdminController.cs")
    
    print(f"[PASS] C# controller without [Authorize]: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Controller Without Authorization" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_csharp_permanent_admin_role():
    """Test detection of permanent admin role assignment."""
    code = """
using Microsoft.AspNetCore.Identity;

public class UserService
{
    private readonly UserManager<ApplicationUser> _userManager;
    
    public async Task PromoteToAdmin(ApplicationUser user)
    {
        await _userManager.AddToRoleAsync(user, "Admin");
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "UserService.cs")
    
    print(f"[PASS] C# permanent admin role: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Permanent Admin" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_csharp_missing_auth_policies():
    """Test detection of missing authorization policies."""
    code = """
using Microsoft.AspNetCore.Authentication.JwtBearer;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer();
        
        // Missing AddAuthorization
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    print(f"[PASS] C# missing auth policies: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Missing" in f.title and "Authorization Policies" in f.title for f in result.findings)


def test_csharp_proper_authorization():
    """Test proper authorization implementation."""
    code = """
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[Authorize(Roles = "Admin,User")]
public class SecureController : ControllerBase
{
    [HttpGet("resource")]
    [Authorize(Policy = "RequireReadPermission")]
    public IActionResult GetResource()
    {
        return Ok(resource);
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "csharp", "SecureController.cs")
    
    print(f"[PASS] C# proper authorization: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "Proper authorization should not trigger findings"


def test_java_endpoint_without_security():
    """Test detection of Spring endpoints without security."""
    code = """
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class ResourceController {
    
    @GetMapping("/admin")
    public ResponseEntity<String> getAdminData() {
        return ResponseEntity.ok("admin data");
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "java", "ResourceController.java")
    
    print(f"[PASS] Java endpoint without security: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Endpoint" in f.title and "Authorization" in f.title for f in result.findings)


def test_java_permanent_admin():
    """Test detection of permanent admin role."""
    code = """
public class UserService {
    public void promoteToAdmin(User user) {
        user.addRole("ADMIN");
        userRepository.save(user);
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "java", "UserService.java")
    
    print(f"[PASS] Java permanent admin: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Permanent" in f.title and "Admin" in f.title for f in result.findings)


def test_java_proper_security():
    """Test proper Spring Security implementation."""
    code = """
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
public class SecureController {
    
    @PreAuthorize("hasRole('USER')")
    @GetMapping("/resource")
    public ResponseEntity<String> getResource() {
        return ResponseEntity.ok("data");
    }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "java", "SecureController.java")
    
    print(f"[PASS] Java proper security: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "Proper security should not trigger findings"


def test_javascript_route_without_middleware():
    """Test detection of Express routes without auth middleware."""
    code = """
import express from 'express';

const app = express();

app.get('/api/admin', (req, res) => {
    res.json({ data: 'sensitive' });
});
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "javascript", "server.js")
    
    print(f"[PASS] JavaScript route without middleware: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Route" in f.title and "Authorization" in f.title for f in result.findings)


def test_javascript_permanent_admin():
    """Test detection of permanent admin access."""
    code = """
async function promoteUser(userId) {
    const user = await User.findById(userId);
    user.role = 'admin';
    await user.save();
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "javascript", "users.ts")
    
    print(f"[PASS] JavaScript permanent admin: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Permanent" in f.title and "Admin" in f.title for f in result.findings)


def test_javascript_proper_auth():
    """Test proper authorization implementation."""
    code = """
import express from 'express';
import { authenticate, authorize } from './middleware';

const app = express();

app.get('/api/resource', 
    authenticate, 
    authorize('admin'), 
    (req, res) => {
        res.json({ data: 'value' });
    }
);
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "javascript", "secure_server.js")
    
    print(f"[PASS] JavaScript proper auth: {result.total_issues} issues (expected: 0)")
    assert result.total_issues == 0, "Proper authorization should not trigger findings"


def test_bicep_role_assignment_without_pim():
    """Test detection of permanent role assignments in Bicep."""
    code = """
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(subscription().id)
  properties: {
    roleDefinitionId: contributorRole.id
    principalId: principalId
    principalType: 'User'
  }
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "bicep", "rbac.bicep")
    
    print(f"[PASS] Bicep role assignment without PIM: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Permanent" in f.title or "PIM" in f.title for f in result.findings)


def test_terraform_role_assignment_without_jit():
    """Test detection of permanent role assignments in Terraform."""
    code = """
resource "azurerm_role_assignment" "example" {
  scope                = azurerm_resource_group.example.id
  role_definition_name = "Contributor"
  principal_id         = data.azuread_user.example.object_id
}
"""
    analyzer = KSI_IAM_04_Analyzer()
    result = analyzer.analyze(code, "terraform", "rbac.tf")
    
    print(f"[PASS] Terraform role assignment without JIT: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("Permanent" in f.title or "JIT" in f.title for f in result.findings)


def test_factory_integration():
    """Test analyzer works through factory pattern."""
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    code = """
from flask import Flask

app = Flask(__name__)

@app.route('/admin')
def admin_route():
    return 'admin page'
"""
    factory = get_factory()
    result = factory.analyze("KSI-IAM-04", code, "python", "app.py")
    
    print(f"[PASS] Factory integration: {result.total_issues} issues")
    assert result.total_issues >= 1
    assert any("route" in f.title.lower() or "authorization" in f.title.lower() for f in result.findings)


def run_all_tests():
    """Run all KSI-IAM-04 enhanced tests."""
    print("\n" + "="*60)
    print("KSI-IAM-04 Enhanced Analyzer Tests")
    print("="*60 + "\n")
    
    tests = [
        ("Python Permanent Admin", test_python_permanent_admin),
        ("Python Route Without Auth", test_python_route_without_auth),
        ("Python Proper JIT Auth", test_python_proper_jit_auth),
        ("Python Azure PIM Suggestion", test_python_azure_pim_suggestion),
        ("C# Controller Without [Authorize]", test_csharp_controller_without_authorize),
        ("C# Permanent Admin Role", test_csharp_permanent_admin_role),
        ("C# Missing Auth Policies", test_csharp_missing_auth_policies),
        ("C# Proper Authorization", test_csharp_proper_authorization),
        ("Java Endpoint Without Security", test_java_endpoint_without_security),
        ("Java Permanent Admin", test_java_permanent_admin),
        ("Java Proper Security", test_java_proper_security),
        ("JavaScript Route Without Middleware", test_javascript_route_without_middleware),
        ("JavaScript Permanent Admin", test_javascript_permanent_admin),
        ("JavaScript Proper Auth", test_javascript_proper_auth),
        ("Bicep Role Assignment Without PIM", test_bicep_role_assignment_without_pim),
        ("Terraform Role Assignment Without JIT", test_terraform_role_assignment_without_jit),
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

