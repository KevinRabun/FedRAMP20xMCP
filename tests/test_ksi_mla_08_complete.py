"""
Test suite for KSI-MLA-08 Enhanced: Log Data Access
Tests AST-based Python analyzer and regex-based C#/Java/TypeScript/IaC analyzers
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_08 import KSI_MLA_08_Analyzer


def test_python_log_file_access_without_authz():
    """Test Python AST detection of log file access without authorization"""
    code = """
from flask import Flask

app = Flask(__name__)

@app.route('/view-logs')
def view_logs():
    with open('/var/log/app.log', 'r') as f:
        logs = f.read()
    return logs
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'python', 'logs.py')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected findings for log file access without authz, got {len(findings)}"
    assert any("Log File Access" in f.title and "Authorization" in f.title for f in findings)
    assert any(f.severity.value == "high" for f in findings)
    print("[PASS] Python: Detects log file access without authorization")


def test_python_log_file_access_with_authz():
    """Test Python AST accepts log file access with authorization decorator"""
    code = """
from flask import Flask
from auth import require_admin_role

app = Flask(__name__)

@app.route('/view-logs')
@require_admin_role
def view_logs():
    with open('/var/log/app.log', 'r') as f:
        logs = f.read()
    return logs
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'python', 'logs.py')
    findings = result.findings
    
    # Should not flag with authorization decorator
    log_findings = [f for f in findings if "Log File Access" in f.title]
    assert len(log_findings) == 0, "Should not flag log access with authorization decorator"
    print("[PASS] Python: Accepts log file access with authorization decorator")


def test_python_log_file_with_role_check():
    """Test Python AST accepts log file access with role check in function"""
    code = """
from flask import Flask, current_user, abort

app = Flask(__name__)

@app.route('/view-logs')
def view_logs():
    if not current_user.has_role('admin'):
        abort(403)
    
    with open('/var/log/app.log', 'r') as f:
        logs = f.read()
    return logs
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'python', 'logs.py')
    findings = result.findings
    
    # Should not flag with role check
    log_findings = [f for f in findings if "Log File Access" in f.title]
    assert len(log_findings) == 0, "Should not flag log access with role check"
    print("[PASS] Python: Accepts log file access with role check")


def test_python_azure_monitor_without_scope():
    """Test Python AST detection of Azure Monitor without explicit scope"""
    code = """
from azure.monitor.query import LogsQueryClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = LogsQueryClient(credential)

response = client.query_workspace(workspace_id, query, timespan)
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'python', 'monitor.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect Azure Monitor without explicit scope"
    monitor_findings = [f for f in findings if "Azure Monitor" in f.title or "Scope" in f.title]
    assert len(monitor_findings) >= 1, "Should flag missing scope/role specification"
    print("[PASS] Python: Detects Azure Monitor query without explicit scope")


def test_python_open_call_detection():
    """Test Python AST detection of open() calls with .log files"""
    code = """
def read_error_log():
    with open('/var/log/error.log') as f:
        return f.read()
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'python', 'utils.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect open() with .log file"
    print("[PASS] Python: Detects open() calls with .log files")


def test_csharp_log_file_access_without_authz():
    """Test C# detection of log file access without authorization"""
    code = """
public class LogController : ControllerBase
{
    [HttpGet("logs")]
    public IActionResult GetLogs()
    {
        var logs = File.ReadAllText("/var/log/app.log");
        return Ok(logs);
    }
}
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'LogController.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect log file access without authorization"
    assert any(f.severity.value == "high" for f in findings)
    print("[PASS] C#: Detects log file access without authorization")


def test_csharp_log_file_with_authorize():
    """Test C# accepts log file access with [Authorize] attribute"""
    code = """
[Authorize(Roles = "Admin")]
public class LogController : ControllerBase
{
    [HttpGet("logs")]
    public IActionResult GetLogs()
    {
        var logs = File.ReadAllText("/var/log/app.log");
        return Ok(logs);
    }
}
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'LogController.cs')
    findings = result.findings
    
    # Should not flag with [Authorize]
    log_findings = [f for f in findings if "Log file access" in f.title]
    assert len(log_findings) == 0, "Should not flag with [Authorize] attribute"
    print("[PASS] C#: Accepts log file access with [Authorize] attribute")


def test_java_log_file_access_without_authz():
    """Test Java detection of log file access without authorization"""
    code = """
@RestController
public class LogController {
    
    @GetMapping("/logs")
    public String getLogs() throws IOException {
        return Files.readAllLines(Paths.get("/var/log/app.log"))
                   .stream()
                   .collect(Collectors.joining("\\n"));
    }
}
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'java', 'LogController.java')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect log file access without authorization"
    print("[PASS] Java: Detects log file access without authorization")


def test_python_regex_fallback():
    """Test Python regex fallback on syntax error"""
    code = """
# Invalid syntax to trigger fallback
def view_logs(
    with open('/var/log/app.log', 'r') as f
        return f.read()
"""
    analyzer = KSI_MLA_08_Analyzer()
    result = analyzer.analyze(code, 'python', 'invalid.py')
    findings = result.findings
    
    # Should use regex fallback
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title]
    assert len(fallback_findings) >= 1, "Should use regex fallback on syntax error"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all MLA-08 tests"""
    tests = [
        test_python_log_file_access_without_authz,
        test_python_log_file_access_with_authz,
        test_python_log_file_with_role_check,
        test_python_azure_monitor_without_scope,
        test_python_open_call_detection,
        test_csharp_log_file_access_without_authz,
        test_csharp_log_file_with_authorize,
        test_java_log_file_access_without_authz,
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
    print(f"MLA-08 Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
