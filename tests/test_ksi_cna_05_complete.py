"""
Comprehensive Test Suite for KSI-CNA-05 (Unwanted Activity / DDoS Protection)

Tests Python, C#, Java, TypeScript, Bicep, and Terraform analyzers for rate limiting and DDoS protection.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_05 import KSI_CNA_05_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity

def test_python_flask_without_limiter():
    """Test 1: Python - Flask app without rate limiting"""
    code = """
from flask import Flask, jsonify

app = Flask(__name__)

@app.route('/api/data')
def get_data():
    return jsonify({'data': 'value'})

if __name__ == '__main__':
    app.run()
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    # Should detect missing rate limiter
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Rate Limiting' in f.title and 'Flask' in f.title for f in findings), "Should detect Flask without limiter"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("[PASS] Python: Detects Flask without rate limiting")

def test_python_flask_with_limiter():
    """Test 2: Python - Flask app WITH rate limiting (secure)"""
    code = """
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
limiter = Limiter(app=app, key_func=get_remote_address)

@app.route('/api/data')
@limiter.limit('10 per minute')
def get_data():
    return jsonify({'data': 'value'})
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    # Should NOT detect issue - has limiter
    flask_findings = [f for f in findings if 'Flask' in f.title and 'Rate Limiting' in f.title]
    assert len(flask_findings) == 0, f"Should not detect issue with Flask-Limiter, got {len(flask_findings)} findings"
    print("[PASS] Python: Accepts Flask with rate limiting")

def test_python_django_without_throttle():
    """Test 3: Python - Django REST Framework without throttling"""
    code = """
# settings.py
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'rest_framework',
]

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'python', 'settings.py')
    findings = result.findings
    
    # Should detect missing throttling
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Django' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect Django without throttling"
    print("[PASS] Python: Detects Django without rate limiting")

def test_python_fastapi_without_slowapi():
    """Test 4: Python - FastAPI without rate limiting"""
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/api/data')
async def get_data():
    return {'data': 'value'}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'python', 'main.py')
    findings = result.findings
    
    # Should detect missing rate limiter
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('FastAPI' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect FastAPI without SlowAPI"
    print("[PASS] Python: Detects FastAPI without rate limiting")

def test_csharp_aspnetcore_without_ratelimit():
    """Test 5: C# - ASP.NET Core without rate limiting"""
    code = """
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

var app = builder.Build();

app.MapControllers();
app.Run();
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'Program.cs')
    findings = result.findings
    
    # Should detect missing rate limiting
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('ASP.NET Core' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect ASP.NET Core without rate limiting"
    print("[PASS] C#: Detects ASP.NET Core without rate limiting")

def test_java_springboot_without_ratelimit():
    """Test 6: Java - Spring Boot without rate limiting"""
    code = """
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
    
    @GetMapping("/data")
    public String getData() {
        return "data";
    }
}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'java', 'DemoApplication.java')
    findings = result.findings
    
    # Should detect missing rate limiting
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Spring Boot' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect Spring Boot without rate limiting"
    print("[PASS] Java: Detects Spring Boot without rate limiting")

def test_typescript_express_without_ratelimit():
    """Test 7: TypeScript - Express without rate limiting"""
    code = """
import express from 'express';

const app = express();

app.get('/api/data', (req, res) => {
    res.json({ data: 'value' });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'typescript', 'server.ts')
    findings = result.findings
    
    # Should detect missing rate limiting
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Express' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect Express without rate limiting"
    print("[PASS] TypeScript: Detects Express without rate limiting")

def test_typescript_nestjs_without_throttler():
    """Test 8: TypeScript - NestJS without throttler"""
    code = """
import { Module } from '@nestjs/common';
import { Controller, Get } from '@nestjs/common';

@Controller('api')
export class ApiController {
    @Get('data')
    getData() {
        return { data: 'value' };
    }
}

@Module({
    controllers: [ApiController],
})
export class AppModule {}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'typescript', 'app.module.ts')
    findings = result.findings
    
    # Should detect missing throttler
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('NestJS' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect NestJS without throttler"
    print("[PASS] TypeScript: Detects NestJS without rate limiting")

def test_bicep_web_app_without_ddos():
    """Test 9: Bicep - Web App without DDoS protection (Front Door)"""
    code = """
resource webApp 'Microsoft.Web/sites@2022-03-01' = {
  name: 'myWebApp'
  location: resourceGroup().location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
  }
}

resource appServicePlan 'Microsoft.Web/serverfarms@2022-03-01' = {
  name: 'myAppServicePlan'
  location: resourceGroup().location
  sku: {
    name: 'P1V2'
    tier: 'PremiumV2'
  }
}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'main.bicep')
    findings = result.findings
    
    # Should detect missing DDoS protection
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('DDoS' in f.title or 'Front Door' in f.title for f in findings), "Should detect missing DDoS protection"
    print("[PASS] Bicep: Detects Web App without DDoS protection")

def test_bicep_apim_without_ratelimit():
    """Test 10: Bicep - API Management without rate limiting"""
    code = """
resource apimService 'Microsoft.ApiManagement/service@2021-08-01' = {
  name: 'myApiManagement'
  location: resourceGroup().location
  sku: {
    name: 'Developer'
    capacity: 1
  }
  properties: {
    publisherEmail: 'admin@contoso.com'
    publisherName: 'Contoso'
  }
}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'apim.bicep')
    findings = result.findings
    
    # Should detect missing rate limiting
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('API Management' in f.title and 'Rate Limiting' in f.title for f in findings), "Should detect APIM without rate limiting"
    print("[PASS] Bicep: Detects API Management without rate limiting")

def test_python_regex_fallback():
    """Test 11: Python regex fallback on syntax error"""
    code = """
from flask import Flask

app = Flask(__name__

# Syntax error: missing closing parenthesis
@app.route('/api/data'
def get_data():
    return {'data': 'value'}
"""
    
    analyzer = KSI_CNA_05_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    # Should use regex fallback and still detect issue
    assert len(findings) >= 1, f"Regex fallback should detect issue, got {len(findings)} findings"
    assert any('Regex Fallback' in f.title for f in findings), "Should indicate regex fallback"
    print("[PASS] Python: Regex fallback works on syntax error")

def run_all_tests():
    """Run all KSI-CNA-05 tests"""
    print("\n" + "="*80)
    print("KSI-CNA-05 Unwanted Activity / DDoS Protection - Comprehensive Test Suite")
    print("="*80 + "\n")
    
    tests = [
        test_python_flask_without_limiter,
        test_python_flask_with_limiter,
        test_python_django_without_throttle,
        test_python_fastapi_without_slowapi,
        test_csharp_aspnetcore_without_ratelimit,
        test_java_springboot_without_ratelimit,
        test_typescript_express_without_ratelimit,
        test_typescript_nestjs_without_throttler,
        test_bicep_web_app_without_ddos,
        test_bicep_apim_without_ratelimit,
        test_python_regex_fallback
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_func.__name__}: {e}")
            failed += 1
    
    print("\n" + "="*80)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if failed == 0:
        print("ALL TESTS PASSED!")
    print("="*80 + "\n")
    
    return failed == 0

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
