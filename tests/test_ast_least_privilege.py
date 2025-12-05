"""
Test AST-enhanced least privilege authorization check (Tier 2.1).

Tests cover:
1. Sensitive operations without authorization (HIGH/CRITICAL)
2. [Authorize] without Roles or Policy on sensitive ops (MEDIUM)
3. [AllowAnonymous] on sensitive operations (CRITICAL)
4. Proper role-based authorization (good practice)
5. Proper policy-based authorization (good practice)
6. Inline authorization checks (good practice)
7. Read-only operations without authorization (no finding)
8. Non-controller class ignored
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from src.fedramp_20x_mcp.analyzers.base import Severity


def test_sensitive_operations_without_auth():
    """Test detection of sensitive operations without any authorization."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _db.Users.FindAsync(id);
            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UsersController.cs")
    
    # Should detect HIGH severity - sensitive operation without authorization
    high_findings = [f for f in result.findings 
                    if f.requirement_id == "KSI-IAM-04"
                    and f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Failed to detect sensitive operation without authorization"
    assert any("without authorization" in f.title.lower() for f in high_findings)
    print("[PASS] Sensitive operations without authorization detection test passed")


def test_authorize_without_roles_or_policy():
    """Test detection of [Authorize] without Roles or Policy on sensitive operations."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    
    [ApiController]
    [Route("api/[controller]")]
    public class DataController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        
        [HttpPost]
        [Authorize]  // Too broad - any authenticated user
        public async Task<IActionResult> UpdateData(DataModel model)
        {
            _db.Data.Update(model);
            await _db.SaveChangesAsync();
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DataController.cs")
    
    # Should detect MEDIUM severity - overly permissive authorization
    medium_findings = [f for f in result.findings 
                      if f.requirement_id == "KSI-IAM-04"
                      and f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Failed to detect overly permissive [Authorize]"
    assert any("permissive" in f.title.lower() or "without roles" in f.description.lower() 
              for f in medium_findings)
    print("[PASS] Overly permissive [Authorize] detection test passed")


def test_allowanonymous_on_sensitive_operation():
    """Test detection of [AllowAnonymous] on sensitive operations."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    [Authorize]
    public class AdminController : ControllerBase
    {
        [HttpDelete("{id}")]
        [AllowAnonymous]  // CRITICAL - allows unauthenticated delete!
        public async Task<IActionResult> DeleteResource(int id)
        {
            await _db.Resources.Remove(resource);
            await _db.SaveChangesAsync();
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "AdminController.cs")
    
    # Should detect HIGH severity - AllowAnonymous on sensitive operation
    high_findings = [f for f in result.findings 
                    if f.requirement_id == "KSI-IAM-04"
                    and f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Failed to detect [AllowAnonymous] on sensitive operation"
    assert any("allowanonymous" in f.title.lower() for f in high_findings)
    print("[PASS] [AllowAnonymous] on sensitive operation detection test passed")


def test_proper_role_based_authorization():
    """Test recognition of proper role-based authorization."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    
    [ApiController]
    [Route("api/[controller]")]
    public class AdminController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        
        [HttpDelete("{id}")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var user = await _db.Users.FindAsync(id);
            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "AdminController.cs")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-IAM-04"]
    
    assert len(good_practices) > 0, "Failed to recognize proper role-based authorization"
    print("[PASS] Proper role-based authorization recognition test passed")


def test_proper_policy_based_authorization():
    """Test recognition of proper policy-based authorization."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using System.IO;
    
    [ApiController]
    [Route("api/[controller]")]
    public class FilesController : ControllerBase
    {
        [HttpDelete("{filename}")]
        [Authorize(Policy = "RequireAdminRole")]
        public IActionResult DeleteFile(string filename)
        {
            File.Delete($"/uploads/{filename}");
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "FilesController.cs")
    
    # Should recognize good practice
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-IAM-04"]
    
    assert len(good_practices) > 0, "Failed to recognize proper policy-based authorization"
    print("[PASS] Proper policy-based authorization recognition test passed")


def test_inline_authorization_checks():
    """Test recognition of inline authorization checks."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    
    [ApiController]
    [Route("api/[controller]")]
    public class ResourcesController : ControllerBase
    {
        private readonly ApplicationDbContext _db;
        
        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> UpdateResource(int id, ResourceModel model)
        {
            if (!User.IsInRole("Admin") && !User.IsInRole("Editor"))
            {
                return Forbid();
            }
            
            _db.Resources.Update(model);
            await _db.SaveChangesAsync();
            return Ok();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ResourcesController.cs")
    
    # Should recognize good practice - inline auth check
    good_practices = [f for f in result.findings 
                     if f.good_practice 
                     and f.requirement_id == "KSI-IAM-04"]
    
    assert len(good_practices) > 0, "Failed to recognize inline authorization checks"
    print("[PASS] Inline authorization checks recognition test passed")


def test_readonly_operations_without_auth():
    """Test that read-only operations without auth don't trigger HIGH severity."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetProducts()
        {
            var products = _db.Products.ToList();
            return Ok(products);
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ProductsController.cs")
    
    # Should NOT detect HIGH severity for read-only operations
    high_findings = [f for f in result.findings 
                    if f.requirement_id == "KSI-IAM-04"
                    and f.severity == Severity.HIGH]
    
    assert len(high_findings) == 0, "False positive: Flagged read-only operation as sensitive"
    print("[PASS] Read-only operations without auth test passed")


def test_non_controller_class_ignored():
    """Test that non-controller classes are ignored."""
    code = '''
    using System;
    
    public class UserService
    {
        public void DeleteUser(int id)
        {
            // This is a service class, not a controller
            _db.Users.Remove(user);
            _db.SaveChanges();
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserService.cs")
    
    # Should NOT report KSI-IAM-04 findings for non-controller classes
    iam04_findings = [f for f in result.findings 
                     if f.requirement_id == "KSI-IAM-04"]
    
    assert len(iam04_findings) == 0, "Incorrectly flagged non-controller class"
    print("[PASS] Non-controller class ignored test passed")


def test_http_calls_require_authorization():
    """Test detection of HTTP calls to external services without authorization."""
    code = '''
    using Microsoft.AspNetCore.Mvc;
    using System.Net.Http;
    
    [ApiController]
    [Route("api/[controller]")]
    public class ProxyController : ControllerBase
    {
        private readonly HttpClient _httpClient;
        
        [HttpPost]
        public async Task<IActionResult> ForwardRequest(DataModel data)
        {
            // Sensitive: Making external HTTP calls without authorization
            var response = await _httpClient.PostAsync("https://api.external.com/data", content);
            return Ok(response);
        }
    }
    '''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ProxyController.cs")
    
    # Should detect HIGH severity - HTTP calls without authorization
    high_findings = [f for f in result.findings 
                    if f.requirement_id == "KSI-IAM-04"
                    and f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Failed to detect HTTP calls without authorization"
    assert any("http_call" in f.description.lower() or "sensitive" in f.description.lower() 
              for f in high_findings)
    print("[PASS] HTTP calls without authorization detection test passed")


if __name__ == "__main__":
    print("=== Running AST Least Privilege Authorization Tests (Tier 2.1) ===\n")
    
    test_sensitive_operations_without_auth()
    test_authorize_without_roles_or_policy()
    test_allowanonymous_on_sensitive_operation()
    test_proper_role_based_authorization()
    test_proper_policy_based_authorization()
    test_inline_authorization_checks()
    test_readonly_operations_without_auth()
    test_non_controller_class_ignored()
    test_http_calls_require_authorization()
    
    print("\n=== All AST Least Privilege Authorization Tests Passed ===")
