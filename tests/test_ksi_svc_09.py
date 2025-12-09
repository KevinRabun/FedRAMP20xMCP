#!/usr/bin/env python3
"""
Test suite for KSI-SVC-09 Communication Integrity analyzer.

Tests certificate validation in machine-to-machine communications:
- Python: verify=False in requests/httpx/urllib
- C#: ServerCertificateValidationCallback => true
- Java: Empty checkServerTrusted() in X509TrustManager
- TypeScript: rejectUnauthorized: false
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_09 import KSI_SVC_09_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_verify_false():
    """Test Python AST detection of verify=False."""
    code = '''
import requests

def fetch_data():
    # CRITICAL: Disables certificate validation
    response = requests.get('https://api.example.com/data', verify=False)
    return response.json()
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.CRITICAL
    assert "verify=False" in findings[0].description or "Certificate Validation Disabled" in findings[0].title
    assert findings[0].line_number == 6  # Line with verify=False
    print("[PASS] Python verify=False detection (AST)")


def test_python_verify_true_safe():
    """Test Python AST: verify=True is safe."""
    code = '''
import requests

def fetch_data():
    # Safe: Certificate validation enabled
    response = requests.get('https://api.example.com/data', verify=True)
    return response.json()
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) == 0, f"Expected 0 findings (verify=True safe), got {len(findings)}"
    print("[PASS] Python verify=True is safe")


def test_python_default_verify():
    """Test Python AST: default (no verify parameter) is safe."""
    code = '''
import requests

def fetch_data():
    # Safe: Default behavior validates certificates
    response = requests.get('https://api.example.com/data')
    return response.json()
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_python(code)
    
    assert len(findings) == 0, f"Expected 0 findings (default verify safe), got {len(findings)}"
    print("[PASS] Python default verify is safe")


def test_python_regex_fallback():
    """Test Python regex fallback for syntax errors."""
    code = '''
import requests

# Syntax error on purpose (missing closing paren)
def fetch_data(
    response = requests.get('https://api.example.com/data', verify=False)
    return response.json()
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_python(code)
    
    # Should use fallback regex and still detect verify=False
    assert len(findings) == 1, f"Expected 1 finding from fallback, got {len(findings)}"
    assert findings[0].severity == Severity.CRITICAL
    print("[PASS] Python regex fallback for syntax errors")


def test_csharp_callback_true():
    """Test C# detection of ServerCertificateValidationCallback => true."""
    code = '''
using System.Net.Http;

public class ApiClient
{
    public HttpClient CreateClient()
    {
        var handler = new HttpClientHandler
        {
            // CRITICAL: Always accepts any certificate
            ServerCertificateValidationCallback = (sender, cert, chain, sslPolicyErrors) => true
        };
        return new HttpClient(handler);
    }
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.CRITICAL
    assert "Certificate Validation" in findings[0].title or "ServerCertificateValidationCallback" in findings[0].title
    assert findings[0].line_number == 11  # Line with callback
    print("[PASS] C# ServerCertificateValidationCallback => true detection")


def test_csharp_safe_callback():
    """Test C# safe callback with proper validation."""
    code = '''
using System.Net.Http;

public class ApiClient
{
    public HttpClient CreateClient()
    {
        var handler = new HttpClientHandler
        {
            // Safe: Default validation
        };
        return new HttpClient(handler);
    }
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    assert len(findings) == 0, f"Expected 0 findings (safe callback), got {len(findings)}"
    print("[PASS] C# safe callback (no override)")


def test_java_empty_checkservertrusted():
    """Test Java detection of empty checkServerTrusted()."""
    code = '''
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

public class ApiClient {
    public void createClient() throws Exception {
        // CRITICAL: Trust-all TrustManager
        TrustManager[] trustAllCerts = new TrustManager[] {
            new X509TrustManager() {
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                public X509Certificate[] getAcceptedIssuers() { return null; }
            }
        };
        
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
    }
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_java(code)
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.CRITICAL
    assert "Trust-All" in findings[0].title or "TrustManager" in findings[0].title
    assert findings[0].line_number == 10  # Line with checkServerTrusted
    print("[PASS] Java empty checkServerTrusted() detection")


def test_java_safe_trustmanager():
    """Test Java safe TrustManager with proper validation."""
    code = '''
import javax.net.ssl.*;

public class ApiClient {
    public void createClient() throws Exception {
        // Safe: Use default TrustManager
        HttpClient client = HttpClient.newBuilder()
            .sslContext(SSLContext.getDefault())
            .build();
    }
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_java(code)
    
    assert len(findings) == 0, f"Expected 0 findings (safe TrustManager), got {len(findings)}"
    print("[PASS] Java safe TrustManager (default SSL context)")


def test_typescript_reject_unauthorized_false():
    """Test TypeScript detection of rejectUnauthorized: false."""
    code = '''
import https from 'https';
import axios from 'axios';

async function fetchData() {
    // CRITICAL: Disables certificate validation
    const agent = new https.Agent({
        rejectUnauthorized: false
    });
    
    const response = await axios.get('https://api.example.com/data', {
        httpsAgent: agent
    });
    return response.data;
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.CRITICAL
    assert "rejectUnauthorized" in findings[0].title or "Certificate Validation Disabled" in findings[0].title
    assert findings[0].line_number == 8  # Line with rejectUnauthorized
    print("[PASS] TypeScript rejectUnauthorized: false detection")


def test_typescript_safe_agent():
    """Test TypeScript safe HTTPS agent with proper validation."""
    code = '''
import axios from 'axios';

async function fetchData() {
    // Safe: Default behavior validates certificates
    const response = await axios.get('https://api.example.com/data');
    return response.data;
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    assert len(findings) == 0, f"Expected 0 findings (safe agent), got {len(findings)}"
    print("[PASS] TypeScript safe HTTPS agent (default)")


def test_bicep_appgw_no_ssl_policy():
    """Test Bicep Application Gateway without SSL policy."""
    code = '''resource appGateway 'Microsoft.Network/applicationGateways@2023-05-01' = {
  name: appGatewayName
  location: location
  properties: {
    sku: {
      name: 'WAF_v2'
      tier: 'WAF_v2'
    }
  }
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_bicep(code)
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.MEDIUM
    assert "SSL Policy" in findings[0].title
    print("[PASS] Bicep Application Gateway without SSL policy")


def test_terraform_storage_https_disabled():
    """Test Terraform Storage Account with HTTPS disabled."""
    code = '''
resource "azurerm_storage_account" "example" {
  name                     = "examplestorageacct"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  
  enable_https_traffic_only = false  # CRITICAL
  min_tls_version          = "TLS1_2"
}
'''
    analyzer = KSI_SVC_09_Analyzer()
    findings = analyzer.analyze_terraform(code)
    
    assert len(findings) == 1, f"Expected 1 finding, got {len(findings)}"
    assert findings[0].severity == Severity.HIGH
    assert "HTTPS" in findings[0].title
    print("[PASS] Terraform Storage Account with HTTPS disabled")


def run_all_tests():
    """Run all KSI-SVC-09 tests."""
    tests = [
        # Python tests (4)
        ("Python verify=False (AST)", test_python_verify_false),
        ("Python verify=True safe", test_python_verify_true_safe),
        ("Python default verify safe", test_python_default_verify),
        ("Python regex fallback", test_python_regex_fallback),
        
        # C# tests (2)
        ("C# ServerCertificateValidationCallback => true", test_csharp_callback_true),
        ("C# safe callback", test_csharp_safe_callback),
        
        # Java tests (2)
        ("Java empty checkServerTrusted()", test_java_empty_checkservertrusted),
        ("Java safe TrustManager", test_java_safe_trustmanager),
        
        # TypeScript tests (2)
        ("TypeScript rejectUnauthorized: false", test_typescript_reject_unauthorized_false),
        ("TypeScript safe agent", test_typescript_safe_agent),
        
        # IaC tests (2)
        ("Bicep AppGW no SSL policy", test_bicep_appgw_no_ssl_policy),
        ("Terraform Storage HTTPS disabled", test_terraform_storage_https_disabled),
    ]
    
    passed = 0
    failed = 0
    
    print("=" * 70)
    print("KSI-SVC-09 Communication Integrity Analyzer Test Suite")
    print("=" * 70)
    print()
    
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {name}: {e}")
            failed += 1
    
    print()
    print("=" * 70)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} total")
    print("=" * 70)
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
