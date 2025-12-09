"""
Test KSI-IAM-04 AST conversion.
Tests the converted AST-based analyzers for Just-in-Time Authorization.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_iam_04 import KSI_IAM_04_Analyzer

def test_python_permanent_admin():
    """Test Python permanent admin detection using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
def create_user(username):
    user = User.objects.create(username=username)
    user.is_superuser = True
    user.save()
    return user
"""
    
    findings = analyzer.analyze_python(code, "test.py")
    assert len(findings) > 0, "Should detect permanent superuser"
    assert findings[0].severity.name == "HIGH", "Should be HIGH severity"
    assert "Permanent Privileged Access" in findings[0].title
    print(f"[PASS] Python permanent admin: {len(findings)} findings")


def test_python_route_without_auth():
    """Test Python route without authorization decorator using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
from flask import Flask
app = Flask(__name__)

@app.route('/admin/users')
def admin_users():
    return User.query.all()
"""
    
    findings = analyzer.analyze_python(code, "test.py")
    assert len(findings) > 0, "Should detect route without auth"
    assert any("Authorization" in f.title for f in findings), "Should flag missing authorization"
    print(f"[PASS] Python route without auth: {len(findings)} findings")


def test_csharp_controller_without_authorize():
    """Test C# controller without [Authorize] using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
using Microsoft.AspNetCore.Mvc;

public class UsersController : ControllerBase
{
    [HttpGet]
    public IActionResult GetUsers()
    {
        return Ok(users);
    }
}
"""
    
    findings = analyzer.analyze_csharp(code, "test.cs")
    assert len(findings) > 0, "Should detect controller without [Authorize]"
    assert findings[0].severity.name == "HIGH", "Should be HIGH severity"
    assert "Controller Without Authorization" in findings[0].title
    print(f"[PASS] C# controller without Authorize: {len(findings)} findings")


def test_csharp_permanent_role_assignment():
    """Test C# permanent admin role assignment using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
public async Task GrantAdminAccess(string userId)
{
    var user = await userManager.FindByIdAsync(userId);
    await userManager.AddToRoleAsync(user, "Admin");
}
"""
    
    findings = analyzer.analyze_csharp(code, "test.cs")
    assert len(findings) > 0, "Should detect permanent admin role"
    assert findings[0].severity.name == "HIGH", "Should be HIGH severity"
    assert "Permanent Admin Role" in findings[0].title
    print(f"[PASS] C# permanent role assignment: {len(findings)} findings")


def test_java_endpoint_without_security():
    """Test Java endpoint without @Secured using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {
    
    @GetMapping("/admin/users")
    public List<User> getUsers() {
        return userService.findAll();
    }
}
"""
    
    findings = analyzer.analyze_java(code, "test.java")
    assert len(findings) > 0, "Should detect endpoint without security"
    assert findings[0].severity.name == "HIGH", "Should be HIGH severity"
    assert "Without Role-Based Authorization" in findings[0].title
    print(f"[PASS] Java endpoint without security: {len(findings)} findings")


def test_typescript_route_without_auth():
    """Test TypeScript route without auth middleware using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
const express = require('express');
const app = express();

app.get('/api/admin/users', (req, res) => {
    res.json(users);
});
"""
    
    findings = analyzer.analyze_typescript(code, "test.ts")
    assert len(findings) > 0, "Should detect route without auth"
    assert findings[0].severity.name == "HIGH", "Should be HIGH severity"
    assert "Without Authorization Middleware" in findings[0].title
    print(f"[PASS] TypeScript route without auth: {len(findings)} findings")


def test_typescript_jwt_without_expiration():
    """Test TypeScript JWT without expiration using AST."""
    analyzer = KSI_IAM_04_Analyzer()
    
    code = """
const jwt = require('jsonwebtoken');

function generateToken(user) {
    return jwt.sign({ userId: user.id }, SECRET_KEY);
}
"""
    
    findings = analyzer.analyze_typescript(code, "test.ts")
    assert len(findings) > 0, "Should detect JWT without expiration"
    assert findings[0].severity.name == "HIGH", "Should be HIGH severity"
    assert "JWT Token Without Expiration" in findings[0].title
    print(f"[PASS] TypeScript JWT without expiration: {len(findings)} findings")


def run_all_tests():
    """Run all IAM-04 conversion tests."""
    print("\n" + "="*70)
    print("KSI-IAM-04 AST Conversion Tests")
    print("="*70 + "\n")
    
    tests = [
        ("Python Permanent Admin", test_python_permanent_admin),
        ("Python Route Without Auth", test_python_route_without_auth),
        ("C# Controller Without Authorize", test_csharp_controller_without_authorize),
        ("C# Permanent Role Assignment", test_csharp_permanent_role_assignment),
        ("Java Endpoint Without Security", test_java_endpoint_without_security),
        ("TypeScript Route Without Auth", test_typescript_route_without_auth),
        ("TypeScript JWT Without Expiration", test_typescript_jwt_without_expiration),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {str(e)}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_name}: ERROR - {str(e)}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Test Results: {passed} passed, {failed} failed out of {passed + failed} total")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
