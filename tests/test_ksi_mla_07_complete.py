"""
Test suite for KSI-MLA-07 Enhanced: Event Types
Tests AST-based Python analyzer and regex-based C#/Java/TypeScript/IaC analyzers
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_07 import KSI_MLA_07_Analyzer


def test_python_auth_function_without_logging():
    """Test Python AST detection of auth function without logging"""
    code = """
from flask import Flask, request

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = authenticate(username, password)
    return {'success': True}
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'auth.py')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected findings for auth function without logging, got {len(findings)}"
    assert any("Auth Function" in f.title and "Logging" in f.title for f in findings)
    assert any(f.severity.value == "high" for f in findings)
    print("[PASS] Python: Detects auth function without logging")


def test_python_auth_function_with_logging():
    """Test Python AST accepts auth function with logging"""
    code = """
import logging
from flask import Flask, request

logger = logging.getLogger(__name__)
app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    logger.info(f'Login attempt for {username}', extra={'event_type': 'authentication'})
    user = authenticate(username, password)
    if user:
        logger.info(f'Login successful', extra={'user_id': user.id})
    return {'success': True}
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'auth.py')
    findings = result.findings
    
    # Should not flag auth function with logging
    auth_findings = [f for f in findings if "Auth Function" in f.title]
    assert len(auth_findings) == 0, "Should not flag auth function with logging"
    print("[PASS] Python: Accepts auth function with logging")


def test_python_authenticate_function():
    """Test Python AST detection of authenticate function without logging"""
    code = """
def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return user
    return None
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'auth.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect authenticate function without logging"
    print("[PASS] Python: Detects authenticate function without logging")


def test_python_data_access_without_logging():
    """Test Python AST detection of multiple data access without logging"""
    code = """
from flask import Flask
from models import User, Order, Product

app = Flask(__name__)

@app.route('/users')
def get_users():
    return User.query.all()

@app.route('/orders')
def get_orders():
    return Order.query.filter_by(status='active').all()

@app.route('/products')
def get_products():
    return Product.query.all()

@app.route('/search')
def search():
    results = User.query.filter(User.name.like('%search%')).all()
    return results
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'api.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect multiple data access without logging"
    data_findings = [f for f in findings if "Data Access" in f.title]
    assert len(data_findings) >= 1, "Should flag missing audit logging for data access"
    print("[PASS] Python: Detects data access operations without logging")


def test_python_data_access_with_logging():
    """Test Python AST accepts data access with logging"""
    code = """
import logging
from flask import Flask
from models import User

logger = logging.getLogger(__name__)
app = Flask(__name__)

@app.route('/users')
def get_users():
    logger.info('Fetching all users', extra={'event_type': 'data_access'})
    return User.query.all()

@app.route('/user/<id>')
def get_user(id):
    logger.info(f'Fetching user {id}', extra={'event_type': 'data_access', 'resource': 'user'})
    return User.query.get(id)
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'api.py')
    findings = result.findings
    
    # Should not flag when logger is present
    data_findings = [f for f in findings if "Data Access" in f.title]
    assert len(data_findings) == 0, "Should not flag data access with logging"
    print("[PASS] Python: Accepts data access with logging")


def test_python_sql_query_detection():
    """Test Python AST detection of SQL queries"""
    code = """
import sqlite3

def get_all_records():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE active = 1')
    cursor.execute('SELECT * FROM orders WHERE status = "pending"')
    cursor.execute('SELECT * FROM products')
    cursor.execute('SELECT * FROM inventory')
    return cursor.fetchall()
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'db.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect SQL queries without logging"
    print("[PASS] Python: Detects SQL queries without logging")


def test_csharp_auth_without_logging():
    """Test C# detection of authentication without logging"""
    code = """
public class AuthController : ControllerBase
{
    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginModel model)
    {
        var result = await _signInManager.SignInAsync(model.Username, model.Password);
        return Ok(result);
    }
}
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'AuthController.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect SignInAsync without logging"
    assert any(f.severity.value == "high" for f in findings)
    print("[PASS] C#: Detects authentication without logging")


def test_csharp_data_operations_without_logging():
    """Test C# detection of database operations without logging"""
    code = """
public class UserRepository
{
    private readonly AppDbContext _context;
    
    public async Task AddUser(User user)
    {
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
    }
    
    public async Task UpdateUser(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
    }
    
    public async Task DeleteUser(int id)
    {
        var user = await _context.Users.FindAsync(id);
        _context.Users.Remove(user);
        await _context.SaveChangesAsync();
    }
    
    public async Task BulkUpdate(List<User> users)
    {
        _context.Users.UpdateRange(users);
        await _context.SaveChangesAsync();
    }
}
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'UserRepository.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect database operations without logging"
    data_findings = [f for f in findings if "Data operations" in f.title]
    assert len(data_findings) >= 1, "Should flag missing ILogger"
    print("[PASS] C#: Detects data operations without logging")


def test_java_auth_annotation_without_logging():
    """Test Java detection of auth annotations without logging"""
    code = """
@RestController
@RequestMapping("/api")
public class UserController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public List<User> getAdminUsers() {
        return userService.findAll();
    }
    
    @Secured("ROLE_USER")
    @GetMapping("/profile")
    public User getProfile() {
        return getCurrentUser();
    }
}
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'java', 'UserController.java')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect auth annotations without logging"
    print("[PASS] Java: Detects auth annotations without logging")


def test_python_regex_fallback():
    """Test Python regex fallback on syntax error"""
    code = """
# Invalid syntax to trigger fallback
def login(username, password
    user = authenticate(username, password)
    return user
"""
    analyzer = KSI_MLA_07_Analyzer()
    result = analyzer.analyze(code, 'python', 'invalid.py')
    findings = result.findings
    
    # Should use regex fallback
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title]
    assert len(fallback_findings) >= 1, "Should use regex fallback on syntax error"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all MLA-07 tests"""
    tests = [
        test_python_auth_function_without_logging,
        test_python_auth_function_with_logging,
        test_python_authenticate_function,
        test_python_data_access_without_logging,
        test_python_data_access_with_logging,
        test_python_sql_query_detection,
        test_csharp_auth_without_logging,
        test_csharp_data_operations_without_logging,
        test_java_auth_annotation_without_logging,
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
    
    print(f"\n{'='*60}")
    print(f"MLA-07 Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
