"""
Tests for Entity Framework security enhancements (Phase A).

Tests Phase A enhancements:
- A.1: SQL Injection via ExecuteSqlRaw/FromSqlRaw
- A.2: N+1 Query Detection
- A.3: Missing AsNoTracking() in read-only queries
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.csharp_analyzer import CSharpAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity


# ============================================================================
# Phase A.1: SQL Injection Detection Tests
# ============================================================================

def test_sql_injection_executesqlraw_interpolation():
    """Test detection of ExecuteSqlRaw with string interpolation."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class UserRepository
{
    private readonly DbContext _context;
    
    public User GetUser(int userId)
    {
        // Dangerous: string interpolation in raw SQL
        return _context.Database.ExecuteSqlRaw($"SELECT * FROM Users WHERE Id = {userId}");
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserRepository.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "SQL injection" in f.title]
    assert len(findings) >= 1, "Should detect SQL injection in ExecuteSqlRaw"
    assert findings[0].severity == Severity.HIGH
    print("✅ SQL injection ExecuteSqlRaw interpolation detected")


def test_sql_injection_fromsqlraw_concatenation():
    """Test detection of FromSqlRaw with string concatenation."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class ProductRepository
{
    private readonly DbContext _context;
    
    public List<Product> SearchProducts(string searchTerm)
    {
        // Dangerous: string concatenation
        return _context.Products
            .FromSqlRaw("SELECT * FROM Products WHERE Name LIKE '%" + searchTerm + "%'")
            .ToList();
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "ProductRepository.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "SQL injection" in f.title]
    assert len(findings) >= 1, "Should detect SQL injection in FromSqlRaw"
    assert findings[0].severity == Severity.HIGH
    print("✅ SQL injection FromSqlRaw concatenation detected")


def test_sql_injection_safe_parameterized():
    """Test that parameterized queries don't trigger false positives."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class UserRepository
{
    private readonly DbContext _context;
    
    public User GetUser(int userId)
    {
        // Safe: parameterized query
        return _context.Database.ExecuteSqlRaw("SELECT * FROM Users WHERE Id = {0}", userId);
    }
    
    public User GetUserSafe(int userId)
    {
        // Safe: ExecuteSqlInterpolated handles parameters
        return _context.Database.ExecuteSqlInterpolated($"SELECT * FROM Users WHERE Id = {userId}");
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserRepository.cs")
    
    # Should not have HIGH severity SQL injection findings for safe patterns
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-02" and "SQL injection" in f.title and f.severity == Severity.HIGH]
    assert len(findings) == 0, "Should not detect SQL injection in parameterized queries"
    print("✅ Parameterized queries correctly marked as safe")


# ============================================================================
# Phase A.2: N+1 Query Detection Tests
# ============================================================================

def test_n_plus_one_foreach_navigation():
    """Test detection of N+1 query in foreach loop."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class OrderService
{
    private readonly DbContext _context;
    
    public void PrintOrders()
    {
        var orders = _context.Orders.ToList();
        
        // N+1 problem: accessing Customer in loop without Include
        foreach (var order in orders)
        {
            Console.WriteLine(order.Customer.Name);
            Console.WriteLine(order.Customer.Email);
        }
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrderService.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-01" and "N+1" in f.title]
    assert len(findings) >= 1, "Should detect N+1 query problem"
    assert findings[0].severity == Severity.MEDIUM
    print("✅ N+1 query problem detected")


def test_n_plus_one_safe_with_include():
    """Test that queries with Include() don't trigger false positive."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class OrderService
{
    private readonly DbContext _context;
    
    public void PrintOrders()
    {
        // Safe: Include loads related data eagerly
        var orders = _context.Orders
            .Include(o => o.Customer)
            .ToList();
        
        foreach (var order in orders)
        {
            Console.WriteLine(order.Customer.Name);
        }
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrderService.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-01" and "N+1" in f.title]
    assert len(findings) == 0, "Should not detect N+1 with Include()"
    print("✅ Include() pattern correctly recognized as safe")


def test_n_plus_one_safe_with_projection():
    """Test that projection queries don't trigger false positive."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class OrderService
{
    private readonly DbContext _context;
    
    public void PrintOrders()
    {
        // Safe: Projection loads only needed data
        var orders = _context.Orders
            .Select(o => new { o.Id, CustomerName = o.Customer.Name })
            .ToList();
        
        foreach (var order in orders)
        {
            Console.WriteLine(order.CustomerName);
        }
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrderService.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-SVC-01" and "N+1" in f.title]
    assert len(findings) == 0, "Should not detect N+1 with Select projection"
    print("✅ Select projection correctly recognized as safe")


# ============================================================================
# Phase A.3: Tracking Performance Tests
# ============================================================================

def test_tracking_missing_asnotracking_get():
    """Test detection of missing AsNoTracking() in GET endpoint."""
    code = '''
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class UsersController : ControllerBase
{
    private readonly DbContext _context;
    
    [HttpGet]
    public IActionResult GetUsers()
    {
        // Missing AsNoTracking() in read-only query
        var users = _context.Users.ToList();
        return Ok(users);
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UsersController.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-06" and "AsNoTracking" in f.title]
    assert len(findings) >= 1, "Should detect missing AsNoTracking()"
    assert findings[0].severity == Severity.LOW
    print("✅ Missing AsNoTracking() detected")


def test_tracking_asnotracking_present():
    """Test that queries with AsNoTracking() are recognized as good practice."""
    code = '''
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class UsersController : ControllerBase
{
    private readonly DbContext _context;
    
    [HttpGet]
    public IActionResult GetUsers()
    {
        // Good: AsNoTracking() for read-only query
        var users = _context.Users.AsNoTracking().ToList();
        return Ok(users);
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UsersController.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-06" and "Optimized" in f.title]
    assert len(findings) >= 1, "Should recognize AsNoTracking() as good practice"
    assert findings[0].severity == Severity.INFO
    assert findings[0].good_practice
    print("✅ AsNoTracking() good practice recognized")


def test_tracking_asnotracking_with_include():
    """Test AsNoTracking() with Include() navigation."""
    code = '''
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class OrdersController : ControllerBase
{
    private readonly DbContext _context;
    
    [HttpGet]
    public IActionResult GetOrders()
    {
        // Good: AsNoTracking() with Include
        var orders = _context.Orders
            .Include(o => o.Customer)
            .AsNoTracking()
            .ToList();
        return Ok(orders);
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "OrdersController.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-06" and "Optimized" in f.title]
    assert len(findings) >= 1, "Should recognize AsNoTracking() with Include()"
    assert findings[0].good_practice
    print("✅ AsNoTracking() with Include() recognized")


def test_tracking_get_method_name_convention():
    """Test detection based on method naming convention (Get...)."""
    code = '''
using Microsoft.EntityFrameworkCore;

public class UserService
{
    private readonly DbContext _context;
    
    public List<User> GetAllUsers()
    {
        // Missing AsNoTracking() in Get method
        return _context.Users.ToList();
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UserService.cs")
    
    findings = [f for f in result.findings if f.requirement_id == "KSI-MLA-06" and "AsNoTracking" in f.title]
    assert len(findings) >= 1, "Should detect missing AsNoTracking() in Get methods"
    print("✅ Get method naming convention recognized")


# ============================================================================
# Integration Tests
# ============================================================================

def test_multiple_ef_issues_in_one_file():
    """Test detection of multiple EF security issues in a single file."""
    code = '''
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class DataController : ControllerBase
{
    private readonly DbContext _context;
    
    [HttpGet]
    public IActionResult GetUsers(string search)
    {
        // Issue 1: Missing AsNoTracking()
        // Issue 2: SQL injection (direct interpolation)
        return Ok(_context.Users.FromSqlRaw($"SELECT * FROM Users WHERE Name LIKE '%{search}%'").ToList());
    }
    
    public void ProcessOrders()
    {
        var orders = _context.Orders.ToList();
        
        // Issue 3: N+1 query
        foreach (var order in orders)
        {
            Console.WriteLine(order.Customer.Name);
        }
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "DataController.cs")
    
    sql_injection = [f for f in result.findings if "SQL injection" in f.title]
    n_plus_one = [f for f in result.findings if "N+1" in f.title]
    tracking = [f for f in result.findings if "AsNoTracking" in f.title]
    
    assert len(sql_injection) >= 1, "Should detect SQL injection"
    assert len(n_plus_one) >= 1, "Should detect N+1 query"
    assert len(tracking) >= 1, "Should detect missing AsNoTracking()"
    
    print("✅ Multiple EF issues detected in single file")


def test_ef_no_false_positives_clean_code():
    """Test that clean EF code doesn't generate false positives."""
    code = '''
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;

[ApiController]
public class UsersController : ControllerBase
{
    private readonly DbContext _context;
    
    [HttpGet]
    public IActionResult GetUsers()
    {
        // Clean code: AsNoTracking(), LINQ (no raw SQL), no loops
        return Ok(_context.Users.AsNoTracking().ToList());
    }
    
    [HttpGet("{id}")]
    public IActionResult GetUser(int id)
    {
        // Clean code: LINQ with parameter
        var user = _context.Users
            .AsNoTracking()
            .FirstOrDefault(u => u.Id == id);
        
        if (user == null)
            return NotFound();
        
        return Ok(user);
    }
    
    [HttpPost]
    public IActionResult CreateUser([FromBody] User user)
    {
        // Write operation: tracking is appropriate
        _context.Users.Add(user);
        _context.SaveChanges();
        return Created($"/users/{user.Id}", user);
    }
}
'''
    
    analyzer = CSharpAnalyzer()
    result = analyzer.analyze(code, "UsersController.cs")
    
    # Should only have INFO/good practice findings, no HIGH/MEDIUM issues
    high_medium_findings = [f for f in result.findings if f.severity in [Severity.HIGH, Severity.MEDIUM]]
    ef_issues = [f for f in high_medium_findings if any(kw in f.title.lower() for kw in ["sql injection", "n+1", "tracking"])]
    
    assert len(ef_issues) == 0, "Clean code should not trigger EF security findings"
    print("✅ Clean EF code produces no false positives")


# ============================================================================
# Run All Tests
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*70)
    print("Entity Framework Security Tests (Phase A)")
    print("="*70 + "\n")
    
    print("Phase A.1: SQL Injection Detection")
    print("-" * 70)
    test_sql_injection_executesqlraw_interpolation()
    test_sql_injection_fromsqlraw_concatenation()
    test_sql_injection_safe_parameterized()
    
    print("\nPhase A.2: N+1 Query Detection")
    print("-" * 70)
    test_n_plus_one_foreach_navigation()
    test_n_plus_one_safe_with_include()
    test_n_plus_one_safe_with_projection()
    
    print("\nPhase A.3: Tracking Performance")
    print("-" * 70)
    test_tracking_missing_asnotracking_get()
    test_tracking_asnotracking_present()
    test_tracking_asnotracking_with_include()
    test_tracking_get_method_name_convention()
    
    print("\nIntegration Tests")
    print("-" * 70)
    test_multiple_ef_issues_in_one_file()
    test_ef_no_false_positives_clean_code()
    
    print("\n" + "="*70)
    print("✅ All Entity Framework Security Tests Passed!")
    print("="*70)
