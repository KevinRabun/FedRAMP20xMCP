"""
Test suite for KSI-RPL-03 (Backup Validation) analyzer.

Tests AST-first implementation for Python, C#, Java, TypeScript.
Tests regex-only implementation for Bicep, Terraform.
"""

import sys
sys.path.insert(0, 'c:\\source\\FedRAMP20xMCP\\src')

from fedramp_20x_mcp.analyzers.ksi.ksi_rpl_03 import KSI_RPL_03_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_azure_backup_detected():
    """Test Python Azure Backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
client = RecoveryServicesClient(credential, subscription_id)
"""
    findings = analyzer.analyze_python(code, "backup_script.py")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Azure Backup SDK" in findings[0].title
    print("[PASS] Python with Azure Backup SDK detected")


def test_python_aws_backup_detected():
    """Test Python AWS boto3 backup detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import boto3

backup_client = boto3.client('backup')
backup_client.create_backup_plan(BackupPlan={...})
"""
    findings = analyzer.analyze_python(code, "backup_script.py")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "AWS Backup" in findings[0].title
    print("[PASS] Python with AWS boto3 backup detected")


def test_python_gcp_backup_detected():
    """Test Python GCP backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
from google.cloud import storage
from google.cloud import compute

storage_client = storage.Client()
compute_client = compute.SnapshotsClient()
"""
    findings = analyzer.analyze_python(code, "backup_script.py")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "GCP Backup" in findings[0].title
    print("[PASS] Python with GCP backup SDK detected")


def test_python_no_backup_clean():
    """Test Python without backup SDKs"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import requests
import json

response = requests.get('https://api.example.com/data')
data = response.json()
"""
    findings = analyzer.analyze_python(code, "api_client.py")
    assert len(findings) == 0
    print("[PASS] Python without backup SDKs passes")


def test_csharp_azure_backup_detected():
    """Test C# Azure Recovery Services SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
using Azure.ResourceManager.RecoveryServices;
using Azure.ResourceManager.RecoveryServicesBackup;
using Azure.Identity;

var credential = new DefaultAzureCredential();
var client = new RecoveryServicesBackupClient(credential);
"""
    findings = analyzer.analyze_csharp(code, "BackupManager.cs")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Azure Backup SDK" in findings[0].title
    print("[PASS] C# with Azure Backup SDK detected")


def test_csharp_aws_backup_detected():
    """Test C# AWS Backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
using Amazon.Backup;
using Amazon.Backup.Model;

var backupClient = new AmazonBackupClient();
var request = new CreateBackupPlanRequest();
"""
    findings = analyzer.analyze_csharp(code, "BackupService.cs")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "AWS Backup SDK" in findings[0].title
    print("[PASS] C# with AWS Backup SDK detected")


def test_csharp_no_backup_clean():
    """Test C# without backup SDKs"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
using System;
using System.Net.Http;

public class ApiClient
{
    private readonly HttpClient _client = new HttpClient();
}
"""
    findings = analyzer.analyze_csharp(code, "ApiClient.cs")
    assert len(findings) == 0
    print("[PASS] C# without backup SDKs passes")


def test_java_azure_backup_detected():
    """Test Java Azure Backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import com.azure.resourcemanager.recoveryservices.RecoveryServicesBackupManager;
import com.azure.identity.DefaultAzureCredential;

public class BackupService {
    private RecoveryServicesBackupManager manager;
}
"""
    findings = analyzer.analyze_java(code, "BackupService.java")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Azure Backup SDK" in findings[0].title
    print("[PASS] Java with Azure Backup SDK detected")


def test_java_aws_backup_detected():
    """Test Java AWS Backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import software.amazon.awssdk.services.backup.BackupClient;
import software.amazon.awssdk.services.backup.model.CreateBackupPlanRequest;

public class BackupManager {
    private BackupClient backupClient;
}
"""
    findings = analyzer.analyze_java(code, "BackupManager.java")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "AWS Backup SDK" in findings[0].title
    print("[PASS] Java with AWS Backup SDK detected")


def test_java_no_backup_clean():
    """Test Java without backup SDKs"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import java.net.http.HttpClient;
import java.net.http.HttpRequest;

public class ApiClient {
    private final HttpClient client = HttpClient.newHttpClient();
}
"""
    findings = analyzer.analyze_java(code, "ApiClient.java")
    assert len(findings) == 0
    print("[PASS] Java without backup SDKs passes")


def test_typescript_azure_backup_detected():
    """Test TypeScript Azure Backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import { RecoveryServicesBackupClient } from '@azure/arm-recoveryservicesbackup';
import { DefaultAzureCredential } from '@azure/identity';

const credential = new DefaultAzureCredential();
const client = new RecoveryServicesBackupClient(credential, subscriptionId);
"""
    findings = analyzer.analyze_typescript(code, "backupService.ts")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "Azure Backup SDK" in findings[0].title
    print("[PASS] TypeScript with Azure Backup SDK detected")


def test_typescript_aws_backup_detected():
    """Test TypeScript AWS Backup SDK detection"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import { BackupClient, CreateBackupPlanCommand } from '@aws-sdk/client-backup';

const client = new BackupClient({ region: 'us-east-1' });
const command = new CreateBackupPlanCommand({...});
"""
    findings = analyzer.analyze_typescript(code, "backupManager.ts")
    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "AWS Backup SDK" in findings[0].title
    print("[PASS] TypeScript with AWS Backup SDK detected")


def test_typescript_no_backup_clean():
    """Test TypeScript without backup SDKs"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
import axios from 'axios';

const client = axios.create({
    baseURL: 'https://api.example.com'
});
"""
    findings = analyzer.analyze_typescript(code, "apiClient.ts")
    assert len(findings) == 0
    print("[PASS] TypeScript without backup SDKs passes")


def test_bicep_missing_backup_vault():
    """Test Bicep missing Recovery Services Vault (HIGH)"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: 'eastus'
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
  }
}
"""
    findings = analyzer.analyze_bicep(code, "main.bicep")
    assert len(findings) >= 1
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1
    assert "Missing Azure Backup" in high_findings[0].title or "No Recovery" in high_findings[0].description
    print("[PASS] Bicep with VM but no backup vault detected (HIGH)")


def test_bicep_with_backup_vault():
    """Test Bicep with Recovery Services Vault"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
resource backupVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
  name: 'myBackupVault'
  location: 'eastus'
  sku: {
    name: 'RS0'
    tier: 'Standard'
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: 'eastus'
}
"""
    findings = analyzer.analyze_bicep(code, "main.bicep")
    high_findings = [f for f in findings if f.severity == Severity.HIGH and "Missing Azure Backup" in f.title]
    assert len(high_findings) == 0
    print("[PASS] Bicep with Recovery Services Vault passes")


def test_terraform_missing_backup():
    """Test Terraform missing backup configuration (HIGH)"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_D2s_v3"
}
"""
    findings = analyzer.analyze_terraform(code, "main.tf")
    assert len(findings) >= 1
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1
    print("[PASS] Terraform with VM but no backup detected (HIGH)")


def test_terraform_with_backup():
    """Test Terraform with backup configuration"""
    analyzer = KSI_RPL_03_Analyzer()
    code = """
resource "azurerm_recovery_services_vault" "example" {
  name                = "example-vault"
  location            = "eastus"
  resource_group_name = azurerm_resource_group.example.name
  sku                 = "Standard"
}

resource "azurerm_backup_policy_vm" "example" {
  name                = "example-policy"
  resource_group_name = azurerm_resource_group.example.name
  recovery_vault_name = azurerm_recovery_services_vault.example.name

  retention_daily {
    count = 30
  }
}

resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = "eastus"
  size                = "Standard_D2s_v3"
}
"""
    findings = analyzer.analyze_terraform(code, "main.tf")
    # Should not have "Missing Azure Backup Configuration" finding (primary check)
    # May have other HIGH findings like encryption warnings
    missing_backup_findings = [f for f in findings if f.severity == Severity.HIGH and "Missing Azure Backup Configuration" in f.title]
    assert len(missing_backup_findings) == 0, f"Should not detect missing backup when vault+policy exist: {[f.title for f in missing_backup_findings]}"
    print("[PASS] Terraform with backup configuration passes")


def run_all_tests():
    """Run all RPL-03 analyzer tests"""
    print("\n=== KSI-RPL-03 (Backup Validation) Analyzer Tests ===\n")
    
    tests = [
        # Python tests (4)
        test_python_azure_backup_detected,
        test_python_aws_backup_detected,
        test_python_gcp_backup_detected,
        test_python_no_backup_clean,
        
        # C# tests (3)
        test_csharp_azure_backup_detected,
        test_csharp_aws_backup_detected,
        test_csharp_no_backup_clean,
        
        # Java tests (3)
        test_java_azure_backup_detected,
        test_java_aws_backup_detected,
        test_java_no_backup_clean,
        
        # TypeScript tests (3)
        test_typescript_azure_backup_detected,
        test_typescript_aws_backup_detected,
        test_typescript_no_backup_clean,
        
        # IaC tests (4)
        test_bicep_missing_backup_vault,
        test_bicep_with_backup_vault,
        test_terraform_missing_backup,
        test_terraform_with_backup,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print(f"\n=== Test Summary ===")
    print(f"Total: {len(tests)} | Passed: {passed} | Failed: {failed}")
    
    if failed == 0:
        print("\nALL KSI-RPL-03 TESTS PASSED [PASS]")
        return True
    else:
        print(f"\n{failed} TESTS FAILED [FAIL]")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
