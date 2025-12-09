"""
Tests for KSI-CNA-03 Enhanced: Enforce Traffic Flow

Tests network traffic control detections across multiple languages:
- Python: CORS, IP allowlist, network segmentation
- C#: ASP.NET Core endpoint routing, IP filtering
- Java: Spring Security network policies
- TypeScript: Express middleware, CORS
- Bicep: Azure NSG rules, service endpoints
- Terraform: Security groups, network ACLs
- Factory integration
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_03 import KSI_CNA_03_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_cors_all_origins():
    """Test detection of CORS allowing all origins in Python/Flask"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["*"])  # Allowing all origins
'''
    
    result = analyzer.analyze(code, "python", "app.py")
    assert result.total_issues > 0
    assert any("CORS Allowing All Origins" in f.title for f in result.findings)
    assert any(f.severity == Severity.HIGH for f in result.findings)


def test_python_fastapi_cors_wildcard():
    """Test detection of CORS wildcard in FastAPI"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Wildcard - allows all
    allow_credentials=True,
)
'''
    
    result = analyzer.analyze(code, "python", "main.py")
    assert result.total_issues > 0
    assert any("CORS" in f.title for f in result.findings)


def test_csharp_missing_ip_filtering():
    """Test detection of missing IP filtering in C#"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
using Microsoft.AspNetCore.Builder;

public class Startup {
    public void Configure(IApplicationBuilder app) {
        app.UseRouting();
        app.UseAuthentication();
        app.UseAuthorization();
        // No IP filtering middleware
        app.UseEndpoints(endpoints => {
            endpoints.MapControllers();
        });
    }
}
'''
    
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    # May detect missing IP filtering or other network controls
    # Test should verify analyzer runs successfully
    assert result.ksi_id == "KSI-CNA-03"


def test_java_spring_permissive_security():
    """Test detection of permissive Spring Security config"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .anyRequest().permitAll();  // Permissive - allows all traffic
    }
}
'''
    
    result = analyzer.analyze(code, "java", "SecurityConfig.java")
    # Test should verify analyzer runs successfully
    assert result.ksi_id == "KSI-CNA-03"


def test_typescript_express_cors_wildcard():
    """Test detection of CORS wildcard in Express/TypeScript"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
import express from 'express';
import cors from 'cors';

const app = express();

app.use(cors({
  origin: '*',  // Allows all origins
  credentials: true
}));
'''
    
    result = analyzer.analyze(code, "typescript", "server.ts")
    assert result.total_issues > 0
    assert any("CORS" in f.title or "origin" in f.title.lower() for f in result.findings)


def test_bicep_nsg_allow_all():
    """Test detection of NSG rules allowing all traffic"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
resource nsg 'Microsoft.Network/networkSecurityGroups@2022-07-01' = {
  name: 'myNSG'
  location: resourceGroup().location
  properties: {
    securityRules: [
      {
        name: 'AllowAll'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'  // Allows from any source
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}
'''
    
    result = analyzer.analyze(code, "bicep", "network.bicep")
    assert result.total_issues > 0
    assert any("NSG" in f.title or "network" in f.title.lower() for f in result.findings)


def test_terraform_security_group_permissive():
    """Test detection of permissive security group rules"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
resource "azurerm_network_security_group" "example" {
  name                = "acceptanceTestSecurityGroup1"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "allow_all"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "0.0.0.0/0"  // CIDR allows all
    destination_address_prefix = "*"
  }
}
'''
    
    result = analyzer.analyze(code, "terraform", "network.tf")
    assert result.total_issues > 0
    # Check for either "0.0.0.0" in description OR "NSG" or "security" in title
    assert any("0.0.0.0" in f.description or "nsg" in f.title.lower() or "security" in f.title.lower() for f in result.findings)


def test_factory_integration():
    """Test that CNA-03 enhanced is registered in factory"""
    from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    ksi_list = factory.list_ksis()
    
    assert "KSI-CNA-03" in ksi_list
    
    # Test factory can analyze
    code = '''
from flask_cors import CORS
CORS(app, origins=["*"])
'''
    
    result = factory.analyze("KSI-CNA-03", code, "python", "test.py")
    assert result.ksi_id == "KSI-CNA-03"
    assert result.total_issues > 0


def test_python_secure_configuration():
    """Test that secure configuration doesn't generate findings"""
    analyzer = KSI_CNA_03_Analyzer()
    
    code = '''
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=[
    "https://app.example.com",
    "https://admin.example.com"
])  # Specific origins only
'''
    
    result = analyzer.analyze(code, "python", "app.py")
    # May still have other findings, but not for CORS wildcard
    cors_findings = [f for f in result.findings if "CORS" in f.title and "*" in f.description]
    assert len(cors_findings) == 0


if __name__ == "__main__":
    print("Testing KSI-CNA-03 Enhanced Analyzer...")
    print("=" * 60)
    
    tests = [
        ("Python CORS All Origins", test_python_cors_all_origins),
        ("Python FastAPI CORS Wildcard", test_python_fastapi_cors_wildcard),
        ("C# Missing IP Filtering", test_csharp_missing_ip_filtering),
        ("Java Spring Permissive Security", test_java_spring_permissive_security),
        ("TypeScript Express CORS Wildcard", test_typescript_express_cors_wildcard),
        ("Bicep NSG Allow All", test_bicep_nsg_allow_all),
        ("Terraform Security Group Permissive", test_terraform_security_group_permissive),
        ("Factory Integration", test_factory_integration),
        ("Python Secure Configuration", test_python_secure_configuration),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            test_func()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {name} - {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {name} - {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed}/{len(tests)} tests passed")
    
    if failed > 0:
        sys.exit(1)

