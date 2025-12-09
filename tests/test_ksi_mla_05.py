"""
Test suite for KSI-MLA-05 Enhanced Analyzer (Infrastructure as Code)

Tests comprehensive IaC testing and validation detection across:
- Python: pytest-terraform, terraform-compliance, checkov
- C#: Pester, Azure SDK validation
- Java: Terratest, Runtime.exec validation
- JavaScript/TypeScript: CDK, Pulumi testing
- Bicep: Parameter validation, Azure Policy
- Terraform: Variable validation, Sentinel policy

Target: 14+ tests covering all detection patterns
"""

import sys
sys.path.insert(0, 'c:\\source\\FedRAMP20xMCP\\src')

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_05 import KSI_MLA_05_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_missing_iac_testing_framework():
    """Test detection of infrastructure code without testing framework."""
    code = """
# infra_deploy.py - Infrastructure deployment script
import os
import subprocess

def deploy_terraform():
    subprocess.run(['terraform', 'apply', '-auto-approve'])

def main():
    deploy_terraform()
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "python", "infra_deploy.py")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect missing IaC testing framework"
    assert any("testing framework" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Python missing IaC testing framework detection working")


def test_python_iac_framework_without_tests():
    """Test detection of IaC framework imported but no tests implemented."""
    code = """
import pytest
from python_terraform import Terraform

# Framework imported but no tests!
terraform = Terraform(working_dir='./infra')
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "python", "test_infra.py")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect framework without tests"
    assert any("no tests found" in f.title.lower() or "no test" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Python IaC framework without tests detection working")


def test_python_proper_iac_testing():
    """Test that proper IaC testing implementation passes."""
    code = """
import pytest
from python_terraform import Terraform

@pytest.fixture
def terraform():
    return Terraform(working_dir='./infra')

def test_terraform_validate(terraform):
    ret_code, stdout, stderr = terraform.validate()
    assert ret_code == 0, 'Terraform validation should succeed'

def test_infrastructure_compliance():
    # Validate security configuration
    assert check_encryption_enabled()
    assert check_public_access_disabled()
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "python", "test_infrastructure.py")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    # Should not have medium findings for proper testing
    assert len(medium_findings) == 0, "Proper IaC testing should not trigger findings"
    
    print("[PASS] Python proper IaC testing passes")


def test_csharp_missing_iac_testing():
    """Test detection of C# deployment code without Pester/validation."""
    code = """
using System.Diagnostics;

public class InfrastructureDeployer
{
    public void DeployBicep(string templateFile)
    {
        var process = Process.Start("az", $"deployment group create --template-file {templateFile}");
        process.WaitForExit();
    }
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "csharp", "InfrastructureDeployer.cs")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect missing IaC testing"
    assert any("testing" in f.title.lower() for f in medium_findings)
    
    print("[PASS] C# missing IaC testing detection working")


def test_csharp_with_pester_invocation():
    """Test that C# code invoking Pester passes."""
    code = """
using System.Diagnostics;

public class InfrastructureValidator
{
    public void ValidateWithPester()
    {
        var psi = new ProcessStartInfo
        {
            FileName = "pwsh",
            Arguments = "-Command Invoke-Pester -Path ./infra/tests -PassThru"
        };
        var process = Process.Start(psi);
        process.WaitForExit();
        
        if (process.ExitCode != 0)
            throw new Exception("Infrastructure tests failed");
    }
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "csharp", "InfrastructureValidator.cs")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) == 0, "Pester invocation should pass"
    
    print("[PASS] C# with Pester invocation passes")


def test_java_missing_iac_validation():
    """Test detection of Java infrastructure code without validation."""
    code = """
package com.example.infra;

import java.io.IOException;

public class TerraformDeployer {
    public void deployInfrastructure() throws IOException {
        Runtime.getRuntime().exec("terraform apply -auto-approve");
    }
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "java", "TerraformDeployer.java")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect missing validation"
    assert any("validation" in f.title.lower() or "testing" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Java missing IaC validation detection working")


def test_java_with_terraform_validate():
    """Test Java code with terraform validate command."""
    code = """
package com.example.infra;

import org.junit.Test;
import java.io.IOException;
import static org.junit.Assert.*;

public class TerraformTest {
    @Test
    public void testTerraformValidate() throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("terraform", "validate");
        Process process = pb.start();
        int exitCode = process.waitFor();
        assertEquals(0, exitCode);
    }
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "java", "TerraformTest.java")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) == 0, "Terraform validate should pass"
    
    print("[PASS] Java with terraform validate passes")


def test_javascript_missing_iac_framework():
    """Test JavaScript infrastructure code without testing framework."""
    code = """
// infra-deploy.js
const { exec } = require('child_process');

function deployInfrastructure() {
    exec('terraform apply -auto-approve', (error, stdout, stderr) => {
        if (error) throw error;
        console.log(stdout);
    });
}

module.exports = { deployInfrastructure };
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "javascript", "infra-deploy.js")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect missing framework"
    assert any("testing framework" in f.title.lower() for f in medium_findings)
    
    print("[PASS] JavaScript missing IaC framework detection working")


def test_javascript_with_cdktf():
    """Test JavaScript with CDK for Terraform testing."""
    code = """
import { Testing } from 'cdktf';
import { MyInfraStack } from './stack';

describe('Infrastructure Tests', () => {
    it('should validate terraform configuration', () => {
        const app = Testing.app();
        const stack = new MyInfraStack(app, 'test');
        const synthesized = Testing.synth(stack);
        expect(synthesized).toBeDefined();
    });
    
    it('should have required resources', () => {
        const app = Testing.app();
        const stack = new MyInfraStack(app, 'test');
        expect(Testing.toHaveResource(stack, 'azurerm_key_vault')).toBeTruthy();
    });
});
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "javascript", "infra.test.js")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) == 0, "CDKTF testing should pass"
    
    print("[PASS] JavaScript with CDKTF testing passes")


def test_bicep_parameter_without_validation():
    """Test detection of Bicep parameter without validation decorators."""
    code = """
param location string
param environment string
param resourceGroupName string

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'storage${uniqueString(resourceGroup().id)}'
  location: location
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "bicep", "main.bicep")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) >= 2, "Should detect multiple parameters without validation"
    assert any("missing validation" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Bicep parameter without validation detection working")


def test_bicep_with_proper_validation():
    """Test Bicep with proper parameter validation."""
    code = """
@description('The Azure region for resources')
@allowed([
  'eastus'
  'westus'
  'centralus'
])
param location string

@description('Environment name')
@minLength(3)
@maxLength(10)
param environment string

@description('Resource group name')
@minLength(1)
@maxLength(90)
param resourceGroupName string

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'storage${uniqueString(resourceGroup().id)}'
  location: location
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "bicep", "main.bicep")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    # Should not have medium findings for properly validated parameters
    assert len(medium_findings) == 0, "Properly validated parameters should pass"
    
    print("[PASS] Bicep with proper validation passes")


def test_terraform_variable_without_validation():
    """Test detection of Terraform variable without validation block."""
    code = """
variable "location" {
  type        = string
  description = "Azure region"
}

variable "environment" {
  type = string
}

variable "vm_size" {
  type        = string
  default     = "Standard_B2s"
  description = "VM size"
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.environment}"
  location = var.location
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "terraform", "main.tf")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) >= 2, "Should detect multiple variables without validation"
    assert any("missing validation" in f.title.lower() for f in medium_findings)
    
    print("[PASS] Terraform variable without validation detection working")


def test_terraform_with_validation():
    """Test Terraform with proper validation blocks."""
    code = """
variable "location" {
  type        = string
  description = "Azure region"
  
  validation {
    condition     = contains(["eastus", "westus", "centralus"], var.location)
    error_message = "Location must be one of: eastus, westus, centralus."
  }
}

variable "environment" {
  type = string
  
  validation {
    condition     = can(regex("^(dev|staging|prod)$", var.environment))
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "vm_size" {
  type        = string
  default     = "Standard_B2s"
  
  validation {
    condition     = length(var.vm_size) > 0
    error_message = "VM size cannot be empty."
  }
}
"""
    
    analyzer = KSI_MLA_05_Analyzer()
    result = analyzer.analyze(code, "terraform", "variables.tf")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    # Should not have medium findings with validation blocks
    assert len(medium_findings) == 0, "Variables with validation should pass"
    
    print("[PASS] Terraform with validation blocks passes")


def test_factory_function():
    """Test that factory function works for all languages."""
    from fedramp_20x_mcp.analyzers.ksi.factory import KSIAnalyzerFactory
    
    factory = KSIAnalyzerFactory()
    
    # Test that KSI-MLA-05 analyzer supports all expected languages
    for language in [CodeLanguage.PYTHON, CodeLanguage.CSHARP, CodeLanguage.JAVA, 
                     CodeLanguage.JAVASCRIPT, CodeLanguage.BICEP, CodeLanguage.TERRAFORM]:
        analyzer = KSI_MLA_05_Analyzer(language)
        result = analyzer.analyze("# test code", "test.file")
        assert result.ksi_id == "KSI-MLA-05", f"Should return correct KSI ID for {language}"
    
    print("[PASS] Factory function working")


if __name__ == "__main__":
    print("Running KSI-MLA-05 Enhanced Analyzer tests...\n")
    
    test_count = 0
    passed = 0
    failures = []
    
    tests = [
        ("test_python_missing_iac_testing_framework", test_python_missing_iac_testing_framework),
        ("test_python_iac_framework_without_tests", test_python_iac_framework_without_tests),
        ("test_python_proper_iac_testing", test_python_proper_iac_testing),
        ("test_csharp_missing_iac_testing", test_csharp_missing_iac_testing),
        ("test_csharp_with_pester_invocation", test_csharp_with_pester_invocation),
        ("test_java_missing_iac_validation", test_java_missing_iac_validation),
        ("test_java_with_terraform_validate", test_java_with_terraform_validate),
        ("test_javascript_missing_iac_framework", test_javascript_missing_iac_framework),
        ("test_javascript_with_cdktf", test_javascript_with_cdktf),
        ("test_bicep_parameter_without_validation", test_bicep_parameter_without_validation),
        ("test_bicep_with_proper_validation", test_bicep_with_proper_validation),
        ("test_terraform_variable_without_validation", test_terraform_variable_without_validation),
        ("test_terraform_with_validation", test_terraform_with_validation),
        ("test_factory_function", test_factory_function),
    ]
    
    for test_name, test_func in tests:
        test_count += 1
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name} failed: {e}")
            failures.append(test_name)
        except Exception as e:
            print(f"[FAIL] {test_name} error: {e}")
            failures.append(test_name)
    
    print("\n" + "=" * 60)
    print(f"KSI-MLA-05 Enhanced Tests: {passed}/{test_count} passed")
    
    if failures:
        print(f"FAILURES: {len(failures)}")
        for failure in failures:
            print(f"  - {failure}")
        exit(1)
    else:
        print("ALL TESTS PASSED [PASS]")
        exit(0)

