"""
Test suite for KSI-CNA-03 Enhanced: Enforce Traffic Flow
Tests AST-based Python analyzer and regex-based C#/IaC analyzers
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_03 import KSI_CNA_03_Analyzer


def test_python_cors_wildcard():
    """Test Python AST detection of CORS with wildcard origin"""
    code = """
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["*"])
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected findings for CORS wildcard, got {len(findings)}"
    cors_findings = [f for f in findings if "CORS" in f.title and "All Origins" in f.title]
    assert len(cors_findings) >= 1, "Should detect CORS origins=['*']"
    assert any(f.severity.value == "high" for f in findings), "Should be HIGH severity"
    print("[PASS] Python: Detects CORS with wildcard origin")


def test_python_cors_specific_origins():
    """Test Python AST accepts CORS with specific origins"""
    code = """
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://app.example.com", "https://admin.example.com"])
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    # Should not flag specific origins
    cors_findings = [f for f in findings if "CORS" in f.title and "All Origins" in f.title]
    assert len(cors_findings) == 0, "Should not flag CORS with specific origins"
    print("[PASS] Python: Accepts CORS with specific origins")


def test_python_fastapi_cors_wildcard():
    """Test Python AST detection of FastAPI CORS middleware with wildcard"""
    code = """
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True
)
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'main.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect FastAPI CORS wildcard"
    assert any("CORS" in f.title for f in findings)
    print("[PASS] Python: Detects FastAPI CORS middleware with wildcard")


def test_python_admin_route_without_ip_filter():
    """Test Python AST detection of admin route without IP filtering"""
    code = """
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin/dashboard.html')
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'routes.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect admin route without IP filtering"
    admin_findings = [f for f in findings if "admin" in f.title.lower() and "IP" in f.title]
    assert len(admin_findings) >= 1, "Should detect missing IP filtering"
    print("[PASS] Python: Detects admin route without IP filtering")


def test_python_admin_route_with_ip_filter():
    """Test Python AST accepts admin route with IP filtering"""
    code = """
from flask import Flask, request, abort
import ipaddress

app = Flask(__name__)

ALLOWED_ADMIN_IPS = ['10.0.0.0/8']

@app.route('/admin/dashboard')
def admin_dashboard():
    client_ip = request.remote_addr
    if not any(ipaddress.ip_address(client_ip) in ipaddress.ip_network(ip) 
              for ip in ALLOWED_ADMIN_IPS):
        abort(403)
    return 'Admin Dashboard'
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'admin.py')
    findings = result.findings
    
    # Should not flag admin route with IP filtering
    admin_findings = [f for f in findings if "admin" in f.title.lower() and "IP" in f.title]
    assert len(admin_findings) == 0, "Should not flag admin route with IP filtering"
    print("[PASS] Python: Accepts admin route with IP filtering")


def test_python_fastapi_admin_endpoint():
    """Test Python AST detection of FastAPI admin endpoint without IP filtering"""
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/admin/users')
async def get_admin_users():
    return {'users': []}
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'api.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect FastAPI admin endpoint"
    assert any("admin" in f.description.lower() for f in findings)
    print("[PASS] Python: Detects FastAPI admin endpoint without IP filtering")


def test_csharp_cors_allowanyorigin():
    """Test C# detection of AllowAnyOrigin()"""
    code = """
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", builder =>
            {
                builder.AllowAnyOrigin()
                       .AllowAnyMethod()
                       .AllowAnyHeader();
            });
        });
    }
}
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'Startup.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect AllowAnyOrigin()"
    assert any("CORS" in f.title for f in findings)
    assert any(f.severity.value == "high" for f in findings)
    print("[PASS] C#: Detects AllowAnyOrigin() in CORS policy")


def test_csharp_admin_controller_without_ip_filter():
    """Test C# detection of admin controller without IP filtering"""
    code = """
[Route("admin")]
[ApiController]
public class AdminController : ControllerBase
{
    [HttpGet("users")]
    public IActionResult GetUsers()
    {
        return Ok(users);
    }
}
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'AdminController.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect admin controller without IP filtering"
    admin_findings = [f for f in findings if "admin" in f.title.lower()]
    assert len(admin_findings) >= 1, "Should detect missing IP filter on admin controller"
    print("[PASS] C#: Detects admin controller without IP filtering")


def test_python_regex_fallback():
    """Test Python regex fallback on syntax error"""
    code = """
# Invalid syntax to trigger fallback
from flask_cors import CORS
CORS(app, origins=["*"]
@app.route('/admin')
def admin(
    return 'Admin'
"""
    analyzer = KSI_CNA_03_Analyzer()
    result = analyzer.analyze(code, 'python', 'invalid.py')
    findings = result.findings
    
    # Should use regex fallback and detect CORS issue
    assert len(findings) >= 1, "Regex fallback should detect patterns"
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title]
    assert len(fallback_findings) >= 1, "Should use regex fallback on syntax error"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all CNA-03 tests"""
    tests = [
        test_python_cors_wildcard,
        test_python_cors_specific_origins,
        test_python_fastapi_cors_wildcard,
        test_python_admin_route_without_ip_filter,
        test_python_admin_route_with_ip_filter,
        test_python_fastapi_admin_endpoint,
        test_csharp_cors_allowanyorigin,
        test_csharp_admin_controller_without_ip_filter,
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
    print(f"CNA-03 Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
