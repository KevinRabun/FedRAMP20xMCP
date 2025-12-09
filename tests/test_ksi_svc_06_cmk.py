"""
Test KSI-SVC-06 Customer-Managed Key (CMK) detection for Secret Management compliance.
Tests the enhanced Bicep and Terraform analysis for storage, SQL, and disks.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory


def test_bicep_storage_with_pmk():
    """Test detection of Bicep storage account using platform-managed keys (BAD)."""
    print("\n=== Test 1: Bicep Storage with PMK ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
      sku: {
        name: 'Standard_LRS'
      }
      kind: 'StorageV2'
      properties: {
        encryption: {
          keySource: 'Microsoft.Storage'  // Platform-managed key (BAD)
        }
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-SVC-06", code, "bicep", "test.bicep")
    
    # Should detect PMK usage as HIGH severity
    pmk_findings = [f for f in result.findings if "Platform-Managed Keys" in f.title]
    assert len(pmk_findings) == 1, f"Expected 1 PMK finding, got {len(pmk_findings)}"
    assert pmk_findings[0].severity.value == "high", f"Expected high severity, got {pmk_findings[0].severity.value}"
    print(f"[OK] Detected PMK usage: {pmk_findings[0].title}")
    return True


def test_bicep_storage_with_cmk():
    """Test detection of Bicep storage account using customer-managed keys (GOOD)."""
    print("\n=== Test 2: Bicep Storage with CMK ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
      identity: {
        type: 'SystemAssigned'
      }
      properties: {
        encryption: {
          keySource: 'Microsoft.Keyvault'  // Customer-managed key (GOOD)
          keyvaultproperties: {
            keyname: 'storage-key'
            keyvaulturi: 'https://myvault.vault.azure.net/'
          }
        }
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-SVC-06", code, "bicep", "test.bicep")
    
    # Should NOT detect PMK issues (CMK properly configured)
    pmk_findings = [f for f in result.findings if "Platform-Managed Keys" in f.title]
    assert len(pmk_findings) == 0, f"Expected 0 PMK findings for CMK config, got {len(pmk_findings)}"
    print("[OK] No PMK issues detected (CMK properly configured)")
    return True


def test_bicep_sql_without_cmk():
    """Test detection of Bicep SQL database without CMK (BAD)."""
    print("\n=== Test 3: Bicep SQL Without CMK ===")
    
    code = """
    resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
      parent: sqlServer
      name: 'mydatabase'
      location: location
      properties: {
        collation: 'SQL_Latin1_General_CP1_CI_AS'
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-SVC-06", code, "bicep", "test.bicep")
    
    # Should detect missing CMK for TDE
    sql_findings = [f for f in result.findings if "SQL Database" in f.title and "Customer-Managed Key" in f.title]
    assert len(sql_findings) == 1, f"Expected 1 SQL CMK finding, got {len(sql_findings)}"
    assert sql_findings[0].severity.value == "high", f"Expected high severity, got {sql_findings[0].severity.value}"
    print(f"[OK] Detected SQL without CMK: {sql_findings[0].title}")
    return True


def test_terraform_storage_without_cmk():
    """Test detection of Terraform storage account without CMK (BAD)."""
    print("\n=== Test 4: Terraform Storage Without CMK ===")
    
    code = """
    resource "azurerm_storage_account" "example" {
      name                     = "mystorageaccount"
      resource_group_name      = azurerm_resource_group.example.name
      location                 = azurerm_resource_group.example.location
      account_tier             = "Standard"
      account_replication_type = "LRS"
      
      identity {
        type = "SystemAssigned"
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-SVC-06", code, "terraform", "test.tf")
    
    # Should detect missing customer_managed_key block
    cmk_findings = [f for f in result.findings if "Customer-Managed Key" in f.title and "example" in f.title]
    assert len(cmk_findings) == 1, f"Expected 1 CMK finding, got {len(cmk_findings)}"
    assert cmk_findings[0].severity.value == "high", f"Expected high severity, got {cmk_findings[0].severity.value}"
    print(f"[OK] Detected missing CMK: {cmk_findings[0].title}")
    return True


def test_terraform_storage_with_cmk():
    """Test detection of Terraform storage account with CMK (GOOD)."""
    print("\n=== Test 5: Terraform Storage With CMK ===")
    
    code = """
    resource "azurerm_storage_account" "example" {
      name                     = "mystorageaccount"
      resource_group_name      = azurerm_resource_group.example.name
      location                 = azurerm_resource_group.example.location
      account_tier             = "Standard"
      account_replication_type = "LRS"
      
      identity {
        type = "SystemAssigned"
      }
      
      customer_managed_key {
        key_vault_key_id          = azurerm_key_vault_key.example.id
        user_assigned_identity_id = null
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-SVC-06", code, "terraform", "test.tf")
    
    # Should NOT detect CMK issues (properly configured)
    cmk_findings = [f for f in result.findings if "Customer-Managed Key" in f.title and "example" in f.title]
    assert len(cmk_findings) == 0, f"Expected 0 CMK findings for proper config, got {len(cmk_findings)}"
    print("[OK] No CMK issues detected (properly configured)")
    return True


def test_bicep_disk_without_des():
    """Test detection of Bicep managed disk without Disk Encryption Set (BAD)."""
    print("\n=== Test 6: Bicep Disk Without DES ===")
    
    code = """
    resource dataDisk 'Microsoft.Compute/disks@2023-04-02' = {
      name: 'myDataDisk'
      location: location
      sku: {
        name: 'Premium_LRS'
      }
      properties: {
        diskSizeGB: 1024
        creationData: {
          createOption: 'Empty'
        }
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-SVC-06", code, "bicep", "test.bicep")
    
    # Should detect missing Disk Encryption Set
    des_findings = [f for f in result.findings if "Disk Encryption Set" in f.title]
    assert len(des_findings) == 1, f"Expected 1 DES finding, got {len(des_findings)}"
    assert des_findings[0].severity.value == "medium", f"Expected medium severity, got {des_findings[0].severity.value}"
    print(f"[OK] Detected missing DES: {des_findings[0].title}")
    return True


def run_all_tests():
    """Run all KSI-SVC-06 CMK tests."""
    print("=" * 70)
    print("TESTING KSI-SVC-06 CUSTOMER-MANAGED KEY (CMK) DETECTION")
    print("KSI-SVC-06: Secret Management - Key Lifecycle Control")
    print("=" * 70)
    
    tests = [
        ("Bicep Storage with PMK", test_bicep_storage_with_pmk),
        ("Bicep Storage with CMK", test_bicep_storage_with_cmk),
        ("Bicep SQL without CMK", test_bicep_sql_without_cmk),
        ("Terraform Storage without CMK", test_terraform_storage_without_cmk),
        ("Terraform Storage with CMK", test_terraform_storage_with_cmk),
        ("Bicep Disk without DES", test_bicep_disk_without_des),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test_name}: {e}")
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\n[OK] All KSI-SVC-06 CMK tests passed!")
        return True
    else:
        print(f"\n[ERROR] {failed} test(s) failed")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
