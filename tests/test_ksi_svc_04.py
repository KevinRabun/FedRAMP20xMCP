"""
Comprehensive Test Suite for KSI-SVC-04 (Configuration Automation)

Tests AST-first conversion with regex fallback for Python, C#, Java, and TypeScript.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_04 import KSI_SVC_04_Analyzer

def test_python_hardcoded_endpoint():
    """Test: Python code with hardcoded endpoint (should detect)"""
    code = '''
import requests

# Production API endpoint
api_endpoint = "https://api.production.example.com/v1"
port = 8443

def call_api():
    response = requests.get(api_endpoint)
    return response.json()
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_python(code, "app.py")
    
    assert len(findings) >= 1, f"Expected at least 1 finding for hardcoded endpoint, got {len(findings)}"
    assert any(f.severity.name == "MEDIUM" for f in findings), "Expected MEDIUM severity finding"
    assert any("endpoint" in f.title.lower() or "port" in f.title.lower() for f in findings), \
        f"Expected hardcoded configuration finding, got: {[f.title for f in findings]}"
    print("[PASS] Python hardcoded endpoint detected (MEDIUM)")

def test_python_with_env_var():
    """Test: Python code using environment variables (should pass)"""
    code = '''
import os
import requests

# Configuration from environment
api_endpoint = os.getenv('API_ENDPOINT', 'https://api.example.com')
port = int(os.getenv('API_PORT', '8080'))

def call_api():
    response = requests.get(api_endpoint)
    return response.json()
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_python(code, "app.py")
    
    assert len(findings) == 0, f"Expected no findings for env var usage, got {len(findings)}: {[f.title for f in findings]}"
    print("[PASS] Python with environment variables passes")

def test_python_no_config():
    """Test: Python code without configuration (should pass)"""
    code = '''
def process_data(items):
    result = []
    for item in items:
        result.append(item.upper())
    return result
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_python(code, "utils.py")
    
    assert len(findings) == 0, f"Expected no findings for code without config, got {len(findings)}"
    print("[PASS] Python without configuration passes")

def test_csharp_hardcoded_url():
    """Test: C# code with hardcoded URL (should detect)"""
    code = '''
using System;
using System.Net.Http;

public class ApiClient
{
    private string serviceEndpoint = "https://api.production.com/v1";
    private int servicePort = 443;
    
    public async Task<string> GetDataAsync()
    {
        using var client = new HttpClient();
        var response = await client.GetAsync(serviceEndpoint);
        return await response.Content.ReadAsStringAsync();
    }
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_csharp(code, "ApiClient.cs")
    
    assert len(findings) >= 1, f"Expected at least 1 finding for hardcoded URL, got {len(findings)}"
    assert any(f.severity.name == "MEDIUM" for f in findings), "Expected MEDIUM severity finding"
    assert any("url" in f.title.lower() or "endpoint" in f.title.lower() or "port" in f.title.lower() for f in findings), \
        f"Expected hardcoded configuration finding, got: {[f.title for f in findings]}"
    print("[PASS] C# hardcoded URL detected (MEDIUM)")

def test_csharp_with_iconfiguration():
    """Test: C# code using IConfiguration (should pass)"""
    code = '''
using Microsoft.Extensions.Configuration;

public class ApiClient
{
    private readonly IConfiguration _configuration;
    
    public ApiClient(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public string GetEndpoint()
    {
        return _configuration["ServiceEndpoint"];
    }
    
    public int GetPort()
    {
        return _configuration.GetValue<int>("ServicePort");
    }
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_csharp(code, "ApiClient.cs")
    
    assert len(findings) == 0, f"Expected no findings for IConfiguration usage, got {len(findings)}: {[f.title for f in findings]}"
    print("[PASS] C# with IConfiguration passes")

def test_csharp_no_config():
    """Test: C# code without configuration (should pass)"""
    code = '''
public class DataProcessor
{
    public string ProcessData(string input)
    {
        return input.ToUpper();
    }
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_csharp(code, "DataProcessor.cs")
    
    assert len(findings) == 0, f"Expected no findings for code without config, got {len(findings)}"
    print("[PASS] C# without configuration passes")

def test_java_hardcoded_constant():
    """Test: Java code with hardcoded constant (should detect)"""
    code = '''
package com.example.api;

import java.net.http.*;

public class ApiClient {
    private static final String API_ENDPOINT = "https://api.production.com/v1";
    private static final int API_PORT = 8443;
    
    public String getData() throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(API_ENDPOINT))
            .build();
        HttpResponse<String> response = client.send(request, 
            HttpResponse.BodyHandlers.ofString());
        return response.body();
    }
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_java(code, "ApiClient.java")
    
    assert len(findings) >= 1, f"Expected at least 1 finding for hardcoded constant, got {len(findings)}"
    assert any(f.severity.name == "MEDIUM" for f in findings), "Expected MEDIUM severity finding"
    assert any("constant" in f.title.lower() or "endpoint" in f.title.lower() or "port" in f.title.lower() for f in findings), \
        f"Expected hardcoded configuration finding, got: {[f.title for f in findings]}"
    print("[PASS] Java hardcoded constant detected (MEDIUM)")

def test_java_with_value_annotation():
    """Test: Java code using @Value annotation (should pass)"""
    code = '''
package com.example.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ApiClient {
    
    @Value("${api.endpoint}")
    private String apiEndpoint;
    
    @Value("${api.port}")
    private int apiPort;
    
    public String getData() {
        // Use apiEndpoint
        return "data";
    }
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_java(code, "ApiClient.java")
    
    assert len(findings) == 0, f"Expected no findings for @Value usage, got {len(findings)}: {[f.title for f in findings]}"
    print("[PASS] Java with @Value annotation passes")

def test_java_no_config():
    """Test: Java code without configuration (should pass)"""
    code = '''
package com.example.util;

public class DataProcessor {
    public String processData(String input) {
        return input.toUpperCase();
    }
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_java(code, "DataProcessor.java")
    
    assert len(findings) == 0, f"Expected no findings for code without config, got {len(findings)}"
    print("[PASS] Java without configuration passes")

def test_typescript_hardcoded_in_const():
    """Test: TypeScript code with hardcoded URL in const (should detect)"""
    code = '''
import axios from 'axios';

const apiEndpoint = 'https://api.production.com/v1';
const apiPort = 8443;

export async function getData() {
    const response = await axios.get(apiEndpoint);
    return response.data;
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_typescript(code, "api.ts")
    
    assert len(findings) >= 1, f"Expected at least 1 finding for hardcoded URL, got {len(findings)}"
    assert any(f.severity.name == "MEDIUM" for f in findings), "Expected MEDIUM severity finding"
    assert any("url" in f.title.lower() or "endpoint" in f.title.lower() or "port" in f.title.lower() for f in findings), \
        f"Expected hardcoded configuration finding, got: {[f.title for f in findings]}"
    print("[PASS] TypeScript hardcoded URL detected (MEDIUM)")

def test_typescript_hardcoded_in_object():
    """Test: TypeScript object literal with hardcoded baseURL (should detect)"""
    code = '''
import axios from 'axios';

const apiClient = axios.create({
    baseURL: 'https://api.production.com/v1',
    timeout: 5000
});

export async function getData() {
    const response = await apiClient.get('/data');
    return response.data;
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_typescript(code, "api.ts")
    
    assert len(findings) >= 1, f"Expected at least 1 finding for hardcoded baseURL, got {len(findings)}"
    assert any(f.severity.name == "MEDIUM" for f in findings), "Expected MEDIUM severity finding"
    assert any("object" in f.title.lower() or "baseurl" in f.title.lower() or "literal" in f.title.lower() for f in findings), \
        f"Expected hardcoded object literal finding, got: {[f.title for f in findings]}"
    print("[PASS] TypeScript hardcoded object literal detected (MEDIUM)")

def test_typescript_with_env_var():
    """Test: TypeScript code using process.env (should pass)"""
    code = '''
import axios from 'axios';

const apiEndpoint = process.env.API_ENDPOINT || 'https://api.example.com';
const apiPort = parseInt(process.env.API_PORT || '8080');

export async function getData() {
    const response = await axios.get(apiEndpoint);
    return response.data;
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_typescript(code, "api.ts")
    
    assert len(findings) == 0, f"Expected no findings for process.env usage, got {len(findings)}: {[f.title for f in findings]}"
    print("[PASS] TypeScript with process.env passes")

def test_typescript_no_config():
    """Test: TypeScript code without configuration (should pass)"""
    code = '''
export function processData(items: string[]): string[] {
    return items.map(item => item.toUpperCase());
}
'''
    analyzer = KSI_SVC_04_Analyzer()
    findings = analyzer.analyze_typescript(code, "utils.ts")
    
    assert len(findings) == 0, f"Expected no findings for code without config, got {len(findings)}"
    print("[PASS] TypeScript without configuration passes")

if __name__ == "__main__":
    print("=" * 50)
    print("KSI-SVC-04 COMPREHENSIVE TEST SUITE")
    print("Testing: Configuration Automation")
    print("=" * 50)
    
    tests = [
        ("Python hardcoded endpoint", test_python_hardcoded_endpoint),
        ("Python with env var", test_python_with_env_var),
        ("Python no config", test_python_no_config),
        ("C# hardcoded URL", test_csharp_hardcoded_url),
        ("C# with IConfiguration", test_csharp_with_iconfiguration),
        ("C# no config", test_csharp_no_config),
        ("Java hardcoded constant", test_java_hardcoded_constant),
        ("Java with @Value", test_java_with_value_annotation),
        ("Java no config", test_java_no_config),
        ("TypeScript hardcoded const", test_typescript_hardcoded_in_const),
        ("TypeScript hardcoded object", test_typescript_hardcoded_in_object),
        ("TypeScript with process.env", test_typescript_with_env_var),
        ("TypeScript no config", test_typescript_no_config),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1
    
    print()
    print(f"Total: {len(tests)} | Passed: {passed} | Failed: {failed}")
    
    if failed == 0:
        print(f"ALL KSI-SVC-04 TESTS PASSED [PASS]")
        print("=" * 50)
        exit(0)
    else:
        print(f"SOME TESTS FAILED [FAIL]")
        print("=" * 50)
        exit(1)
