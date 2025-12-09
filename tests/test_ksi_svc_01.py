"""
Test KSI-SVC-01: Continuous Improvement

Tests AST-based analysis for security improvements across multiple languages.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_01 import KSI_SVC_01_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_flask_missing_security_headers():
    """Test detection of missing security headers in Flask"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return 'Hello World'

if __name__ == '__main__':
    app.run()
"""
    
    findings = analyzer.analyze_python(code, "app.py")
    
    assert len(findings) > 0, "Should detect missing security headers"
    assert any("Security Headers" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] Python Flask missing security headers detected")


def test_python_flask_with_talisman():
    """Test Flask with Talisman (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
from flask import Flask
from flask_talisman import Talisman

app = Flask(__name__)
Talisman(app, force_https=True)

@app.route('/')
def index():
    return 'Hello World'
"""
    
    findings = analyzer.analyze_python(code, "app.py")
    
    # Should not detect issues when Talisman is present
    security_findings = [f for f in findings if "Security Headers" in f.title]
    assert len(security_findings) == 0, "Should not flag when Talisman is present"
    print("[PASS] Python Flask with Talisman passes")


def test_python_flask_with_after_request():
    """Test Flask with @after_request decorator (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

@app.route('/')
def index():
    return 'Hello World'
"""
    
    findings = analyzer.analyze_python(code, "app.py")
    
    security_findings = [f for f in findings if "Security Headers" in f.title]
    assert len(security_findings) == 0, "Should not flag when @after_request is present"
    print("[PASS] Python Flask with @after_request passes")


def test_csharp_aspnet_missing_hsts():
    """Test detection of missing HSTS in ASP.NET Core"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();

var app = builder.Build();
app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
"""
    
    findings = analyzer.analyze_csharp(code, "Program.cs")
    
    assert len(findings) > 0, "Should detect missing HSTS"
    assert any("HSTS" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] C# ASP.NET Core missing HSTS detected")


def test_csharp_aspnet_with_hsts():
    """Test ASP.NET Core with HSTS (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddHsts(options => {
    options.MaxAge = TimeSpan.FromDays(365);
    options.IncludeSubDomains = true;
});

var app = builder.Build();

if (!app.Environment.IsDevelopment()) {
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

app.Run();
"""
    
    findings = analyzer.analyze_csharp(code, "Program.cs")
    
    hsts_findings = [f for f in findings if "HSTS" in f.title]
    assert len(hsts_findings) == 0, "Should not flag when HSTS is present"
    print("[PASS] C# ASP.NET Core with HSTS passes")


def test_java_spring_missing_headers():
    """Test detection of missing security headers in Spring Security"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        );
        return http.build();
    }
}
"""
    
    findings = analyzer.analyze_java(code, "SecurityConfig.java")
    
    assert len(findings) > 0, "Should detect missing headers configuration"
    assert any("Headers" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] Java Spring Security missing headers detected")


def test_java_spring_with_headers():
    """Test Spring Security with headers configuration (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.headers(headers -> headers
            .frameOptions(FrameOptionsConfig::deny)
            .contentTypeOptions(Customizer.withDefaults())
            .httpStrictTransportSecurity(hsts -> hsts
                .maxAgeInSeconds(31536000)
                .includeSubDomains(true)
            )
        );
        
        http.authorizeHttpRequests(auth -> auth
            .anyRequest().authenticated()
        );
        
        return http.build();
    }
}
"""
    
    findings = analyzer.analyze_java(code, "SecurityConfig.java")
    
    header_findings = [f for f in findings if "Headers" in f.title]
    assert len(header_findings) == 0, "Should not flag when headers are configured"
    print("[PASS] Java Spring Security with headers passes")


def test_typescript_express_missing_helmet():
    """Test detection of missing Helmet in Express"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
import express from 'express';

const app = express();

app.get('/', (req, res) => {
    res.send('Hello World');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
"""
    
    findings = analyzer.analyze_typescript(code, "server.ts")
    
    assert len(findings) > 0, "Should detect missing Helmet"
    assert any("Helmet" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] TypeScript Express missing Helmet detected")


def test_typescript_express_with_helmet():
    """Test Express with Helmet (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
import express from 'express';
import helmet from 'helmet';

const app = express();

app.use(helmet());

app.get('/', (req, res) => {
    res.send('Hello World');
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
"""
    
    findings = analyzer.analyze_typescript(code, "server.ts")
    
    helmet_findings = [f for f in findings if "Helmet" in f.title]
    assert len(helmet_findings) == 0, "Should not flag when Helmet is present"
    print("[PASS] TypeScript Express with Helmet passes")


def test_bicep_storage_missing_diagnostics():
    """Test detection of storage without diagnostic settings in Bicep"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
"""
    
    findings = analyzer.analyze_bicep(code, "storage.bicep")
    
    assert len(findings) > 0, "Should detect missing diagnostic settings"
    assert any("Diagnostic" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] Bicep storage missing diagnostics detected")


def test_bicep_storage_with_diagnostics():
    """Test Bicep storage with diagnostic settings (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${storageAccount.name}-diagnostics'
  scope: storageAccount
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
    ]
  }
}
"""
    
    findings = analyzer.analyze_bicep(code, "storage.bicep")
    
    diag_findings = [f for f in findings if "Diagnostic" in f.title]
    assert len(diag_findings) == 0, "Should not flag when diagnostics are present"
    print("[PASS] Bicep storage with diagnostics passes")


def test_terraform_storage_missing_diagnostics():
    """Test detection of storage without diagnostic settings in Terraform"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  min_tls_version          = "TLS1_2"
  enable_https_traffic_only = true
}
"""
    
    findings = analyzer.analyze_terraform(code, "storage.tf")
    
    assert len(findings) > 0, "Should detect missing diagnostic settings"
    assert any("Diagnostic" in f.title for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] Terraform storage missing diagnostics detected")


def test_terraform_storage_with_diagnostics():
    """Test Terraform storage with diagnostic settings (should pass)"""
    analyzer = KSI_SVC_01_Analyzer()
    
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  min_tls_version          = "TLS1_2"
  enable_https_traffic_only = true
}

resource "azurerm_monitor_diagnostic_setting" "storage_diag" {
  name                       = "${azurerm_storage_account.example.name}-diagnostics"
  target_resource_id         = azurerm_storage_account.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id

  enabled_log {
    category = "StorageRead"
  }
  
  metric {
    category = "Transaction"
    enabled  = true
  }
}
"""
    
    findings = analyzer.analyze_terraform(code, "storage.tf")
    
    diag_findings = [f for f in findings if "Diagnostic" in f.title]
    assert len(diag_findings) == 0, "Should not flag when diagnostics are present"
    print("[PASS] Terraform storage with diagnostics passes")


if __name__ == "__main__":
    print("Testing KSI-SVC-01: Continuous Improvement (AST-based)\n")
    
    # Python tests
    test_python_flask_missing_security_headers()
    test_python_flask_with_talisman()
    test_python_flask_with_after_request()
    
    # C# tests
    test_csharp_aspnet_missing_hsts()
    test_csharp_aspnet_with_hsts()
    
    # Java tests
    test_java_spring_missing_headers()
    test_java_spring_with_headers()
    
    # TypeScript tests
    test_typescript_express_missing_helmet()
    test_typescript_express_with_helmet()
    
    # Bicep tests
    test_bicep_storage_missing_diagnostics()
    test_bicep_storage_with_diagnostics()
    
    # Terraform tests
    test_terraform_storage_missing_diagnostics()
    test_terraform_storage_with_diagnostics()
    
    print("\n" + "="*50)
    print("ALL KSI-SVC-01 TESTS PASSED [PASS]")
    print("="*50)
