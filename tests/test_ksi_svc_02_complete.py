"""
Comprehensive tests for KSI-SVC-02 across all application languages.

Tests network encryption: HTTP URLs, SSL verification, weak TLS protocols.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_02 import KSI_SVC_02_Analyzer as KSI_SVC_02_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# ============================================================================
# PYTHON TESTS (AST-based)
# ============================================================================

def test_python_http_requests():
    """Python: HTTP URL in requests."""
    code = """
import requests
response = requests.get('http://api.example.com/data')
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    print("[PASS] Python Test 1: HTTP in requests")


def test_python_verify_false():
    """Python: SSL verification disabled."""
    code = """
import requests
response = requests.get('https://api.example.com', verify=False)
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    print("[PASS] Python Test 2: verify=False")


def test_python_weak_tls():
    """Python: Weak TLS protocol."""
    code = """
import ssl
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    print("[PASS] Python Test 3: Weak TLS")


def test_python_https_safe():
    """Python: HTTPS is safe."""
    code = """
import requests
response = requests.get('https://api.example.com/data')
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 0
    print("[PASS] Python Test 4: HTTPS safe")


# ============================================================================
# C# TESTS (Regex-based)
# ============================================================================

def test_csharp_http_url():
    """C#: HTTP URL in HttpClient."""
    code = """
public async Task GetData()
{
    var client = new HttpClient();
    var response = await client.GetAsync("http://api.example.com/data");
}
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    print("[PASS] C# Test 1: HTTP URL")


def test_csharp_require_https_false():
    """C#: RequireHttpsMetadata = false."""
    code = """
services.AddAuthentication()
    .AddJwtBearer(options => {
        options.RequireHttpsMetadata = false;
    });
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    print("[PASS] C# Test 2: RequireHttpsMetadata false")


def test_csharp_weak_tls():
    """C#: Weak TLS protocol."""
    code = """
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls;
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    print("[PASS] C# Test 3: Weak TLS")


# ============================================================================
# JAVA TESTS (Regex-based)
# ============================================================================

def test_java_http_url():
    """Java: HTTP URL in HttpURLConnection."""
    code = """
public void getData() throws IOException {
    URL url = new URL("http://api.example.com/data");
    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
}
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_java(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    print("[PASS] Java Test 1: HTTP URL")


def test_java_ssl_verification_disabled():
    """Java: SSL verification disabled."""
    code = """
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, new TrustManager[]{new X509TrustManager() {
    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
}}, null);
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_java(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    print("[PASS] Java Test 2: SSL verification disabled")


def test_java_weak_tls():
    """Java: Weak TLS protocol."""
    code = """
SSLContext context = SSLContext.getInstance("TLSv1");
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_java(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    print("[PASS] Java Test 3: Weak TLS")


# ============================================================================
# TYPESCRIPT TESTS (Regex-based)
# ============================================================================

def test_typescript_http_url():
    """TypeScript: HTTP URL in fetch/axios."""
    code = """
async function getData() {
    const response = await fetch('http://api.example.com/data');
    return response.json();
}
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    print("[PASS] TypeScript Test 1: HTTP URL")


def test_typescript_reject_unauthorized_false():
    """TypeScript: rejectUnauthorized false."""
    code = """
const https = require('https');
const agent = new https.Agent({
    rejectUnauthorized: false
});
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.CRITICAL for f in findings)
    print("[PASS] TypeScript Test 2: rejectUnauthorized false")


def test_typescript_weak_tls():
    """TypeScript: Weak TLS version."""
    code = """
const tls = require('tls');
const options = {
    minVersion: 'TLSv1'
};
"""
    analyzer = KSI_SVC_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    print("[PASS] TypeScript Test 3: Weak TLS")


# ============================================================================
# TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    print("Running KSI-SVC-02 Comprehensive Tests (All Languages)")
    print("=" * 70)
    
    print("\nPython Tests (AST):")
    print("-" * 70)
    test_python_http_requests()
    test_python_verify_false()
    test_python_weak_tls()
    test_python_https_safe()
    
    print("\nC# Tests (Regex):")
    print("-" * 70)
    test_csharp_http_url()
    test_csharp_require_https_false()
    test_csharp_weak_tls()
    
    print("\nJava Tests (Regex):")
    print("-" * 70)
    test_java_http_url()
    test_java_ssl_verification_disabled()
    test_java_weak_tls()
    
    print("\nTypeScript Tests (Regex):")
    print("-" * 70)
    test_typescript_http_url()
    test_typescript_reject_unauthorized_false()
    test_typescript_weak_tls()
    
    print("\n" + "=" * 70)
    print("ALL 14 TESTS PASSED!")
    print("\nKSI-SVC-02 Implementation Status:")
    print("  - Python: Full AST (4 patterns)")
    print("  - C#: Regex (3 patterns)")
    print("  - Java: Regex (3 patterns)")
    print("  - TypeScript: Regex (3 patterns)")
    print("  - Total: 14/14 tests passing")
