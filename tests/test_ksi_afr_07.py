"""
Comprehensive test suite for KSI-AFR-07: Recommended Secure Configuration
Tests AST-based analysis with regex fallback for all supported languages.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_afr_07 import KSI_AFR_07_Analyzer

def test_python_debug_mode():
    """Test Python debug mode detection."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: debug=True
    code = """
from flask import Flask
app = Flask(__name__)
app.config['DEBUG'] = True
app.run()
"""
    findings = analyzer.analyze_python(code, "app.py")
    assert len(findings) >= 1
    assert any('Debug Mode Enabled' in f.title for f in findings)
    print("[PASS] Python debug mode detected")

def test_python_secure_debug():
    """Test Python with proper debug configuration."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: environment-based debug
    code = """
import os
from flask import Flask
app = Flask(__name__)
app.config['DEBUG'] = os.getenv('DEBUG', 'False') == 'True'
app.run()
"""
    findings = analyzer.analyze_python(code, "app.py")
    debug_findings = [f for f in findings if 'Debug Mode' in f.title]
    assert len(debug_findings) == 0
    print("[PASS] Python secure debug configuration passes")

def test_python_missing_session_config():
    """Test Python Flask without session configuration."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: Flask without secure session config
    code = """
from flask import Flask
app = Flask(__name__)
app.secret_key = 'some_secret'
"""
    findings = analyzer.analyze_python(code, "app.py")
    assert len(findings) >= 1
    assert any('Session Configuration' in f.title for f in findings)
    print("[PASS] Python missing session config detected")

def test_python_secure_session():
    """Test Python Flask with secure session configuration."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: Flask with secure session config
    code = """
from flask import Flask
app = Flask(__name__)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
"""
    findings = analyzer.analyze_python(code, "app.py")
    session_findings = [f for f in findings if 'Session' in f.title]
    assert len(session_findings) == 0
    print("[PASS] Python secure session configuration passes")

def test_csharp_dev_exception_page():
    """Test C# developer exception page without environment check."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: UseDeveloperExceptionPage without environment check
    code = """
using Microsoft.AspNetCore.Builder;
var app = WebApplication.Create(args);
app.UseDeveloperExceptionPage();
app.Run();
"""
    findings = analyzer.analyze_csharp(code, "Program.cs")
    assert len(findings) >= 1
    assert any('Developer Exception Page' in f.title for f in findings)
    print("[PASS] C# developer exception page detected")

def test_csharp_secure_exception_handling():
    """Test C# with proper environment-based exception handling."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: Environment-based exception handling
    code = """
using Microsoft.AspNetCore.Builder;
var app = WebApplication.Create(args);
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
app.Run();
"""
    findings = analyzer.analyze_csharp(code, "Program.cs")
    exception_findings = [f for f in findings if 'Developer Exception' in f.title]
    assert len(exception_findings) == 0
    print("[PASS] C# secure exception handling passes")

def test_csharp_missing_https():
    """Test C# ASP.NET Core without HTTPS redirection."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: No HTTPS redirection
    code = """
using Microsoft.AspNetCore.Builder;
var app = WebApplication.Create(args);
app.UseRouting();
app.Run();
"""
    findings = analyzer.analyze_csharp(code, "Program.cs")
    assert len(findings) >= 1
    assert any('HTTPS Redirection' in f.title for f in findings)
    print("[PASS] C# missing HTTPS redirection detected")

def test_csharp_with_https():
    """Test C# ASP.NET Core with HTTPS redirection."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: HTTPS redirection enabled
    code = """
using Microsoft.AspNetCore.Builder;
var app = WebApplication.Create(args);
app.UseHttpsRedirection();
app.UseHsts();
app.UseRouting();
app.Run();
"""
    findings = analyzer.analyze_csharp(code, "Program.cs")
    https_findings = [f for f in findings if 'HTTPS' in f.title]
    assert len(https_findings) == 0
    print("[PASS] C# with HTTPS redirection passes")

def test_java_debug_logging():
    """Test Java with debug logging enabled."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: Debug logging
    code = """
# application.properties
logging.level.root=DEBUG
logging.level.org.springframework=DEBUG
"""
    findings = analyzer.analyze_java(code, "application.properties")
    assert len(findings) >= 1
    assert any('Debug Logging' in f.title for f in findings)
    print("[PASS] Java debug logging detected")

def test_java_info_logging():
    """Test Java with INFO level logging."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: INFO logging
    code = """
# application.properties
logging.level.root=INFO
logging.level.com.yourapp=INFO
"""
    findings = analyzer.analyze_java(code, "application.properties")
    debug_findings = [f for f in findings if 'Debug Logging' in f.title]
    assert len(debug_findings) == 0
    print("[PASS] Java INFO logging passes")

def test_java_wildcard_cors():
    """Test Java with wildcard CORS origin."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: Wildcard CORS
    code = """
@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("*")
                    .allowedMethods("GET", "POST");
            }
        };
    }
}
"""
    findings = analyzer.analyze_java(code, "CorsConfig.java")
    assert len(findings) >= 1
    assert any('CORS' in f.title for f in findings)
    print("[PASS] Java wildcard CORS detected")

def test_java_secure_cors():
    """Test Java with specific CORS origins."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: Specific origins
    code = """
@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://yourdomain.com")
                    .allowedMethods("GET", "POST");
            }
        };
    }
}
"""
    findings = analyzer.analyze_java(code, "CorsConfig.java")
    cors_findings = [f for f in findings if 'CORS' in f.title]
    assert len(cors_findings) == 0
    print("[PASS] Java secure CORS passes")

def test_typescript_missing_helmet():
    """Test TypeScript Express without Helmet."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: No Helmet
    code = """
import express from 'express';
const app = express();
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    assert len(findings) >= 1
    assert any('Helmet' in f.title for f in findings)
    print("[PASS] TypeScript missing Helmet detected")

def test_typescript_with_helmet():
    """Test TypeScript Express with Helmet."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: With Helmet
    code = """
import express from 'express';
import helmet from 'helmet';
const app = express();
app.use(helmet());
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    helmet_findings = [f for f in findings if 'Helmet' in f.title]
    assert len(helmet_findings) == 0
    print("[PASS] TypeScript with Helmet passes")

def test_typescript_wildcard_cors():
    """Test TypeScript with wildcard CORS."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: Wildcard CORS
    code = """
import express from 'express';
import cors from 'cors';
const app = express();
const corsOptions = {
  origin: '*',
  credentials: true
};
app.use(cors(corsOptions));
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    assert len(findings) >= 1
    assert any('CORS' in f.title for f in findings)
    print("[PASS] TypeScript wildcard CORS detected")

def test_typescript_secure_cors():
    """Test TypeScript with specific CORS origins."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: Specific origins
    code = """
import express from 'express';
import cors from 'cors';
const app = express();
const corsOptions = {
  origin: ['https://yourdomain.com'],
  credentials: true
};
app.use(cors(corsOptions));
"""
    findings = analyzer.analyze_typescript(code, "server.ts")
    cors_findings = [f for f in findings if 'CORS' in f.title]
    assert len(cors_findings) == 0
    print("[PASS] TypeScript secure CORS passes")

def test_bicep_storage_without_https():
    """Test Bicep storage without secure transfer."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: No supportsHttpsTrafficOnly
    code = """
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
  }
}
"""
    findings = analyzer.analyze_bicep(code, "storage.bicep")
    assert len(findings) >= 1
    assert any('Secure Transfer' in f.title for f in findings)
    print("[PASS] Bicep storage without HTTPS detected")

def test_bicep_storage_with_https():
    """Test Bicep storage with secure transfer."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: With supportsHttpsTrafficOnly
    code = """
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
  }
}
"""
    findings = analyzer.analyze_bicep(code, "storage.bicep")
    secure_findings = [f for f in findings if 'Secure Transfer' in f.title]
    assert len(secure_findings) == 0
    print("[PASS] Bicep storage with HTTPS passes")

def test_terraform_storage_without_https():
    """Test Terraform storage without secure transfer."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Insecure: No enable_https_traffic_only
    code = """
resource "azurerm_storage_account" "main" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}
"""
    findings = analyzer.analyze_terraform(code, "main.tf")
    assert len(findings) >= 1
    assert any('Secure Transfer' in f.title for f in findings)
    print("[PASS] Terraform storage without HTTPS detected")

def test_terraform_storage_with_https():
    """Test Terraform storage with secure transfer."""
    analyzer = KSI_AFR_07_Analyzer()
    
    # Secure: With enable_https_traffic_only
    code = """
resource "azurerm_storage_account" "main" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"
}
"""
    findings = analyzer.analyze_terraform(code, "main.tf")
    secure_findings = [f for f in findings if 'Secure Transfer' in f.title]
    assert len(secure_findings) == 0
    print("[PASS] Terraform storage with HTTPS passes")

if __name__ == '__main__':
    print("Testing KSI-AFR-07: Recommended Secure Configuration (AST-based)\n")
    
    # Python tests
    test_python_debug_mode()
    test_python_secure_debug()
    test_python_missing_session_config()
    test_python_secure_session()
    
    # C# tests
    test_csharp_dev_exception_page()
    test_csharp_secure_exception_handling()
    test_csharp_missing_https()
    test_csharp_with_https()
    
    # Java tests
    test_java_debug_logging()
    test_java_info_logging()
    test_java_wildcard_cors()
    test_java_secure_cors()
    
    # TypeScript tests
    test_typescript_missing_helmet()
    test_typescript_with_helmet()
    test_typescript_wildcard_cors()
    test_typescript_secure_cors()
    
    # Bicep tests
    test_bicep_storage_without_https()
    test_bicep_storage_with_https()
    
    # Terraform tests
    test_terraform_storage_without_https()
    test_terraform_storage_with_https()
    
    print("\n" + "="*50)
    print("ALL KSI-AFR-07 TESTS PASSED [PASS]")
    print("="*50)
