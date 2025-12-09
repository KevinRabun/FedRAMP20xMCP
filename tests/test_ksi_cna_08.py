"""
Test suite for KSI-CNA-08: Persistent Assessment and Automated Enforcement

Validates detection of missing monitoring and health check integrations:
- Python: Flask, Django, FastAPI without Application Insights
- C#: ASP.NET Core without Application Insights
- Java: Spring Boot without Actuator
- TypeScript: Express, NestJS without health checks
- Bicep: AKS without Defender, ACR without scanning
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_08 import KSI_CNA_08_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity

def test_flask_without_appinsights():
    """Test detection of Flask app without Application Insights."""
    code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello World'
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    findings = result.findings
    
    # Should detect Flask without Application Insights
    flask_findings = [f for f in findings if "Flask" in f.title and "Application Insights" in f.title]
    assert len(flask_findings) > 0, "Should detect Flask without Application Insights"
    assert flask_findings[0].severity == Severity.HIGH
    assert "KSI-CNA-08" in flask_findings[0].description
    assert "CA-2.1" in flask_findings[0].description or "CA-7.1" in flask_findings[0].description
    print("[PASS] Python: Detects Flask without Application Insights")


def test_flask_with_appinsights():
    """Test that Flask with Application Insights is accepted."""
    code = """
from flask import Flask
from azure.monitor.opentelemetry import configure_azure_monitor
from opentelemetry.instrumentation.flask import FlaskInstrumentor

configure_azure_monitor(connection_string="InstrumentationKey=...")

app = Flask(__name__)
FlaskInstrumentor().instrument_app(app)

@app.route('/')
def index():
    return 'Hello World'
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    findings = result.findings
    
    # Should NOT detect issue (monitoring is configured)
    flask_findings = [f for f in findings if "Flask" in f.title]
    assert len(flask_findings) == 0, "Should accept Flask with Application Insights"
    print("[PASS] Python: Accepts Flask with Application Insights")


def test_django_without_monitoring():
    """Test detection of Django without Application Insights."""
    code = """
# settings.py
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'myapp',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
]
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "python", "settings.py")
    findings = result.findings
    
    # Should detect Django without monitoring
    django_findings = [f for f in findings if "Django" in f.title]
    assert len(django_findings) > 0, "Should detect Django without monitoring"
    assert django_findings[0].severity == Severity.HIGH
    print("[PASS] Python: Detects Django without Application Insights")


def test_fastapi_without_monitoring():
    """Test detection of FastAPI without Application Insights."""
    code = """
from fastapi import FastAPI

app = FastAPI()

@app.get('/')
async def root():
    return {'message': 'Hello World'}
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "python", "main.py")
    findings = result.findings
    
    # Should detect FastAPI without monitoring
    fastapi_findings = [f for f in findings if "FastAPI" in f.title]
    assert len(fastapi_findings) > 0, "Should detect FastAPI without monitoring"
    assert fastapi_findings[0].severity == Severity.HIGH
    print("[PASS] Python: Detects FastAPI without Application Insights")


def test_aspnetcore_without_appinsights():
    """Test detection of ASP.NET Core without Application Insights."""
    code = """
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var app = builder.Build();
app.MapControllers();
app.Run();
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "csharp", "Program.cs")
    findings = result.findings
    
    # Should detect ASP.NET Core without Application Insights
    aspnet_findings = [f for f in findings if "ASP.NET Core" in f.title]
    assert len(aspnet_findings) > 0, "Should detect ASP.NET Core without Application Insights"
    assert aspnet_findings[0].severity == Severity.HIGH
    print("[PASS] C#: Detects ASP.NET Core without Application Insights")


def test_springboot_without_actuator():
    """Test detection of Spring Boot without Actuator."""
    code = """
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
    
    @GetMapping("/")
    public String hello() {
        return "Hello World";
    }
}
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "java", "DemoApplication.java")
    findings = result.findings
    
    # Should detect Spring Boot without Actuator
    springboot_findings = [f for f in findings if "Spring Boot" in f.title]
    assert len(springboot_findings) > 0, "Should detect Spring Boot without Actuator"
    assert springboot_findings[0].severity == Severity.HIGH
    print("[PASS] Java: Detects Spring Boot without Actuator")


def test_express_without_health_checks():
    """Test detection of Express without health checks."""
    code = """
import express from 'express';

const app = express();

app.get('/', (req, res) => {
    res.send('Hello World');
});

app.listen(3000);
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "typescript", "server.ts")
    findings = result.findings
    
    # Should detect Express without health checks
    express_findings = [f for f in findings if "Express" in f.title]
    assert len(express_findings) > 0, "Should detect Express without health checks"
    assert express_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript: Detects Express without health checks")


def test_nestjs_without_terminus():
    """Test detection of NestJS without Terminus health checks."""
    code = """
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';

@Module({
    controllers: [AppController],
})
export class AppModule {}
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "typescript", "app.module.ts")
    findings = result.findings
    
    # Should detect NestJS without health checks
    nestjs_findings = [f for f in findings if "NestJS" in f.title]
    assert len(nestjs_findings) > 0, "Should detect NestJS without health checks"
    assert nestjs_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript: Detects NestJS without Terminus")


def test_bicep_aks_without_defender():
    """Test detection of AKS without Microsoft Defender."""
    code = """
resource aksCluster 'Microsoft.ContainerService/managedClusters@2023-09-01' = {
  name: 'myAKSCluster'
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: 'myaks'
    agentPoolProfiles: [
      {
        name: 'agentpool'
        count: 3
        vmSize: 'Standard_DS2_v2'
      }
    ]
  }
}
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "bicep", "aks.bicep")
    findings = result.findings
    
    # Should detect AKS without Defender
    aks_findings = [f for f in findings if "AKS" in f.title and "Defender" in f.title]
    assert len(aks_findings) > 0, "Should detect AKS without Defender"
    assert aks_findings[0].severity == Severity.HIGH
    print("[PASS] Bicep: Detects AKS without Microsoft Defender")


def test_bicep_acr_without_scanning():
    """Test detection of Container Registry without scanning."""
    code = """
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: 'myregistry'
  location: resourceGroup().location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "bicep", "acr.bicep")
    findings = result.findings
    
    # Should detect ACR without vulnerability scanning
    acr_findings = [f for f in findings if "Container Registry" in f.title]
    assert len(acr_findings) > 0, "Should detect ACR without scanning"
    assert acr_findings[0].severity == Severity.MEDIUM
    print("[PASS] Bicep: Detects Container Registry without scanning")


def test_python_regex_fallback():
    """Test regex fallback when AST parsing fails."""
    code = """
# Intentionally malformed Python to trigger regex fallback
from flask import Flask
app = Flask(__name__
# Missing closing parenthesis
"""
    
    analyzer = KSI_CNA_08_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    findings = result.findings
    
    # Should detect via regex fallback
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title or "Flask" in f.title]
    assert len(fallback_findings) > 0, "Should detect via regex fallback"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all KSI-CNA-08 tests."""
    print("\n" + "="*70)
    print("KSI-CNA-08: Persistent Assessment and Automated Enforcement")
    print("Testing monitoring and health check detection across languages")
    print("="*70 + "\n")
    
    tests = [
        ("Flask without Application Insights", test_flask_without_appinsights),
        ("Flask with Application Insights", test_flask_with_appinsights),
        ("Django without monitoring", test_django_without_monitoring),
        ("FastAPI without monitoring", test_fastapi_without_monitoring),
        ("ASP.NET Core without Application Insights", test_aspnetcore_without_appinsights),
        ("Spring Boot without Actuator", test_springboot_without_actuator),
        ("Express without health checks", test_express_without_health_checks),
        ("NestJS without Terminus", test_nestjs_without_terminus),
        ("Bicep AKS without Defender", test_bicep_aks_without_defender),
        ("Bicep ACR without scanning", test_bicep_acr_without_scanning),
        ("Python regex fallback", test_python_regex_fallback),
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
    
    print("\n" + "="*70)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if failed == 0:
        print("ALL TESTS PASSED!")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

