"""
Tests for inter-procedural analysis.

Validates:
1. Call graph construction
2. Parameter-to-argument tracking
3. Return value flows
4. Cross-function taint propagation
5. Vulnerability detection across functions
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.interprocedural import (
    InterProceduralAnalyzer,
    CallGraph,
    analyze_interprocedural,
)
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage


def test_call_graph_construction():
    """Test that call graph correctly identifies function calls."""
    code = """
def get_password():
    return "secret123"

def authenticate(username, password):
    return username + password

def login(user):
    pwd = get_password()
    result = authenticate(user, pwd)
    return result
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    call_graph = results["call_graph"]
    
    # Check functions are registered
    assert "get_password" in call_graph.nodes
    assert "authenticate" in call_graph.nodes
    assert "login" in call_graph.nodes
    
    # Check call edges
    assert ("login", "get_password") in call_graph.edges
    assert ("login", "authenticate") in call_graph.edges
    
    # Check callees
    login_callees = call_graph.get_callees("login")
    assert "get_password" in login_callees
    assert "authenticate" in login_callees
    
    print("[PASS] Call graph construction working")


def test_parameter_extraction():
    """Test that function parameters are correctly extracted."""
    code = """
def process_data(username, password, api_key):
    return username + password + api_key
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    summaries = results["function_summaries"]
    
    assert "process_data" in summaries
    summary = summaries["process_data"]
    
    assert summary.parameters == ["username", "password", "api_key"]
    
    print("[PASS] Parameter extraction working")


def test_return_value_tracking():
    """Test that return values are tracked across calls."""
    code = """
def get_secret():
    return "secret123"

def process():
    my_secret = get_secret()
    return my_secret
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    call_sites = results["call_graph"].call_sites
    
    # Find call to get_secret
    get_secret_call = [cs for cs in call_sites if cs.callee == "get_secret"][0]
    
    assert get_secret_call.return_var == "my_secret"
    
    print("[PASS] Return value tracking working")


def test_taint_propagation_through_parameters():
    """Test that taint propagates through function parameters."""
    code = """
def leak_data(data):
    print(data)

def process_password(password):
    leak_data(password)
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    
    taint_flows = results["taint_flows"]
    
    # Should have flow from password parameter to leak_data call
    param_flows = [f for f in taint_flows if f.source_var == "password"]
    
    assert len(param_flows) > 0
    assert param_flows[0].is_tainted
    assert param_flows[0].edge_type == "call"
    
    print("[PASS] Taint propagation through parameters working")


def test_taint_propagation_through_returns():
    """Test that taint propagates through return values."""
    code = """
def get_api_key():
    return "sk-1234567890"

def use_key():
    key = get_api_key()
    return key
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    
    summaries = results["function_summaries"]
    taint_flows = results["taint_flows"]
    
    # get_api_key should be marked as returning sensitive data
    assert summaries["get_api_key"].returns_sensitive
    
    # Should have return flow from get_api_key to key variable
    return_flows = [f for f in taint_flows if f.edge_type == "return"]
    
    assert len(return_flows) > 0
    assert return_flows[0].is_tainted
    assert return_flows[0].target_var == "key"
    
    print("[PASS] Taint propagation through returns working")


def test_interprocedural_vulnerability_detection():
    """Test that vulnerabilities are detected across function boundaries."""
    code = """
def get_password():
    return "admin123"

def log_sensitive():
    pwd = get_password()
    print(pwd)
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    
    vulnerabilities = results["vulnerabilities"]
    
    # Debug: print what we found
    print(f"  DEBUG: Found {len(vulnerabilities)} vulnerabilities")
    for v in vulnerabilities:
        print(f"  DEBUG: {v}")
    
    # Should detect sensitive data (pwd) passed to print
    assert len(vulnerabilities) > 0, "No vulnerabilities detected"
    
    vuln = vulnerabilities[0]
    assert vuln["type"] == "sensitive_data_leak"
    assert vuln["severity"] == "CRITICAL"
    assert vuln["variable"] == "pwd"
    assert vuln["sink"] == "print"
    
    print("[PASS] Inter-procedural vulnerability detection working")


def test_transitive_calls():
    """Test analysis of transitive function calls (A calls B calls C)."""
    code = """
def get_token():
    return "secret_token"

def fetch_data(token):
    return token

def main():
    t = get_token()
    data = fetch_data(t)
    return data
"""
    
    analyzer = InterProceduralAnalyzer(CodeLanguage.PYTHON)
    results = analyzer.analyze(code)
    call_graph = results["call_graph"]
    
    # Check reachability
    assert call_graph.is_reachable("main", "get_token")
    assert call_graph.is_reachable("main", "fetch_data")
    
    # Check that token flows through both calls
    taint_flows = results["taint_flows"]
    
    # Debug: print flows
    print(f"  DEBUG: Found {len(taint_flows)} taint flows")
    for f in taint_flows:
        print(f"  DEBUG: {f.source_func}.{f.source_var} -> {f.target_func}.{f.target_var} ({f.edge_type})")
    
    # Should have flows: t -> token, and return from fetch_data -> data
    assert len(taint_flows) >= 1, f"Expected at least 1 taint flow, got {len(taint_flows)}"
    
    print("[PASS] Transitive call analysis working")


def test_convenience_function():
    """Test the convenience function for quick analysis."""
    code = """
def get_api_key():
    return "key123"

def send_to_server(data):
    post(data)
"""
    
    results = analyze_interprocedural(code, language="python")
    
    assert "call_graph" in results
    assert "function_summaries" in results
    assert "taint_flows" in results
    assert "vulnerabilities" in results
    
    print("[PASS] Convenience function working")


def run_all_tests():
    """Run all inter-procedural analysis tests."""
    print("Running inter-procedural analysis tests...\n")
    
    tests = [
        test_call_graph_construction,
        test_parameter_extraction,
        test_return_value_tracking,
        test_taint_propagation_through_parameters,
        test_taint_propagation_through_returns,
        test_interprocedural_vulnerability_detection,
        test_transitive_calls,
        test_convenience_function,
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
    
    print(f"\n{'='*60}")
    print(f"Inter-Procedural Analysis Tests: {passed}/{len(tests)} passed")
    
    if failed == 0:
        print("ALL TESTS PASSED [PASS]")
        return 0
    else:
        print(f"FAILURES: {failed}")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
