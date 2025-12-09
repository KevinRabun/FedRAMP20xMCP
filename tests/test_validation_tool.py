"""
Test validate_fedramp_config tool - Pre-generation validation.
Verifies that the tool catches compliance violations before code is deployed.
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.fedramp_20x_mcp.tools.validation import validate_fedramp_config_impl


async def test_bicep_90_day_retention_violation():
    """Test detection of 90-day retention violation."""
    print("\n=== Test 1: Bicep 90-day retention (VIOLATION) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
      name: 'law-example'
      properties: {
        retentionInDays: 90
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    assert result["passed"] == False, "Should fail validation with 90-day retention"
    assert result["total_violations"] > 0, "Should have violations"
    
    # Check for specific violation
    retention_violations = [v for v in result["violations"] if "Retention" in v["requirement"]]
    assert len(retention_violations) == 1, f"Expected 1 retention violation, got {len(retention_violations)}"
    assert "730 days" in retention_violations[0]["expected"]
    assert "90 days" in retention_violations[0]["found"]
    
    print(f"[OK] Detected 90-day retention violation")
    print(f"     Violations: {result['total_violations']}, Compliant: {result['total_compliant']}")
    return True


async def test_bicep_730_day_retention_compliant():
    """Test 730-day retention passes validation."""
    print("\n=== Test 2: Bicep 730-day retention (COMPLIANT) ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
      name: 'law-example'
      properties: {
        retentionInDays: 730
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    # Check for compliant retention
    retention_compliant = [c for c in result["compliant_values"] if "Retention" in c["requirement"]]
    assert len(retention_compliant) == 1, f"Expected 1 compliant retention, got {len(retention_compliant)}"
    assert "730 days" in retention_compliant[0]["value"]
    
    print(f"[OK] 730-day retention is compliant")
    print(f"     Violations: {result['total_violations']}, Compliant: {result['total_compliant']}")
    return True


async def test_bicep_platform_managed_keys_violation():
    """Test detection of platform-managed keys violation."""
    print("\n=== Test 3: Bicep platform-managed keys (VIOLATION) ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'stexample'
      properties: {
        encryption: {
          keySource: 'Microsoft.Storage'
        }
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    assert result["passed"] == False, "Should fail validation with platform-managed keys"
    
    # Check for CMK violation
    cmk_violations = [v for v in result["violations"] if "Customer-Managed Keys" in v["requirement"]]
    assert len(cmk_violations) == 1, f"Expected 1 CMK violation, got {len(cmk_violations)}"
    assert "Microsoft.Keyvault" in cmk_violations[0]["expected"]
    assert "Microsoft.Storage" in cmk_violations[0]["found"]
    
    print(f"[OK] Detected platform-managed keys violation")
    return True


async def test_bicep_customer_managed_keys_compliant():
    """Test Customer-Managed Keys pass validation."""
    print("\n=== Test 4: Bicep Customer-Managed Keys (COMPLIANT) ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'stexample'
      identity: { type: 'SystemAssigned' }
      properties: {
        encryption: {
          keySource: 'Microsoft.Keyvault'
          keyvaultproperties: {
            keyname: 'storage-key'
            keyvaulturi: 'https://myvault.vault.azure.net/'
          }
        }
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    # Check for compliant CMK
    cmk_compliant = [c for c in result["compliant_values"] if "Customer-Managed Keys for Storage" in c["requirement"]]
    assert len(cmk_compliant) == 1, f"Expected 1 compliant CMK, got {len(cmk_compliant)}"
    
    print(f"[OK] Customer-Managed Keys are compliant")
    return True


async def test_bicep_cosmos_without_cmk_violation():
    """Test detection of Cosmos DB without CMK."""
    print("\n=== Test 5: Bicep Cosmos DB without CMK (VIOLATION) ===")
    
    code = """
    resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-example'
      properties: {
        databaseAccountOfferType: 'Standard'
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    assert result["passed"] == False, "Should fail validation without Cosmos DB CMK"
    
    # Check for Cosmos CMK violation
    cosmos_violations = [v for v in result["violations"] if "Cosmos DB" in v["requirement"]]
    assert len(cosmos_violations) == 1, f"Expected 1 Cosmos CMK violation, got {len(cosmos_violations)}"
    assert "keyVaultKeyUri" in cosmos_violations[0]["expected"]
    
    print(f"[OK] Detected Cosmos DB without CMK")
    return True


async def test_bicep_cosmos_with_cmk_compliant():
    """Test Cosmos DB with CMK passes validation."""
    print("\n=== Test 6: Bicep Cosmos DB with CMK (COMPLIANT) ===")
    
    code = """
    resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-example'
      identity: { type: 'SystemAssigned' }
      properties: {
        databaseAccountOfferType: 'Standard'
        keyVaultKeyUri: 'https://myvault.vault.azure.net/keys/cosmos-key/version'
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    # Check for compliant Cosmos CMK
    cosmos_compliant = [c for c in result["compliant_values"] if "Cosmos DB" in c["requirement"]]
    assert len(cosmos_compliant) == 1, f"Expected 1 compliant Cosmos CMK, got {len(cosmos_compliant)}"
    
    print(f"[OK] Cosmos DB with CMK is compliant")
    return True


async def test_bicep_standard_keyvault_violation():
    """Test detection of standard Key Vault SKU."""
    print("\n=== Test 7: Bicep Standard Key Vault (VIOLATION) ===")
    
    code = """
    resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
      name: 'kv-example'
      properties: {
        sku: {
          name: 'standard'
        }
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    assert result["passed"] == False, "Should fail validation with standard Key Vault"
    
    # Check for Premium SKU violation
    kv_violations = [v for v in result["violations"] if "Key Vault Premium SKU" in v["requirement"]]
    assert len(kv_violations) == 1, f"Expected 1 Key Vault SKU violation, got {len(kv_violations)}"
    assert "premium" in kv_violations[0]["expected"].lower()
    assert "standard" in kv_violations[0]["found"].lower()
    
    print(f"[OK] Detected standard Key Vault SKU violation")
    return True


async def test_bicep_premium_keyvault_compliant():
    """Test Premium Key Vault passes validation."""
    print("\n=== Test 8: Bicep Premium Key Vault (COMPLIANT) ===")
    
    code = """
    resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
      name: 'kv-example'
      properties: {
        sku: {
          name: 'premium'
        }
        enabledForDiskEncryption: true
      }
    }
    """
    
    result = await validate_fedramp_config_impl(code, "bicep", strict_mode=True)
    
    # Check for compliant Premium SKU
    kv_compliant = [c for c in result["compliant_values"] if "Key Vault Premium SKU" in c["requirement"]]
    assert len(kv_compliant) == 1, f"Expected 1 compliant Key Vault SKU, got {len(kv_compliant)}"
    
    print(f"[OK] Premium Key Vault is compliant")
    return True


async def test_terraform_retention_violation():
    """Test detection of insufficient retention in Terraform."""
    print("\n=== Test 9: Terraform 180-day retention (VIOLATION) ===")
    
    code = """
    resource "azurerm_log_analytics_workspace" "siem" {
      name                = "law-siem"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
      sku                 = "PerGB2018"
      retention_in_days   = 180
    }
    """
    
    result = await validate_fedramp_config_impl(code, "terraform", strict_mode=True)
    
    assert result["passed"] == False, "Should fail validation with 180-day retention"
    
    # Check for retention violation
    retention_violations = [v for v in result["violations"] if "Retention" in v["requirement"]]
    assert len(retention_violations) == 1, f"Expected 1 retention violation, got {len(retention_violations)}"
    assert "180 days" in retention_violations[0]["found"]
    
    print(f"[OK] Detected 180-day retention violation in Terraform")
    return True


async def test_terraform_cmk_violation():
    """Test detection of missing CMK in Terraform."""
    print("\n=== Test 10: Terraform Storage without CMK (VIOLATION) ===")
    
    code = """
    resource "azurerm_storage_account" "example" {
      name                     = "stexample"
      resource_group_name      = azurerm_resource_group.main.name
      location                 = azurerm_resource_group.main.location
      account_tier             = "Standard"
      account_replication_type = "LRS"
    }
    """
    
    result = await validate_fedramp_config_impl(code, "terraform", strict_mode=True)
    
    assert result["passed"] == False, "Should fail validation without CMK"
    
    # Check for CMK violation
    cmk_violations = [v for v in result["violations"] if "Customer-Managed Keys" in v["requirement"]]
    assert len(cmk_violations) == 1, f"Expected 1 CMK violation, got {len(cmk_violations)}"
    
    print(f"[OK] Detected missing CMK in Terraform")
    return True


async def run_all_tests():
    """Run all validation tool tests."""
    print("=" * 70)
    print("TESTING validate_fedramp_config TOOL")
    print("Pre-generation validation for FedRAMP 20x compliance")
    print("=" * 70)
    
    tests = [
        ("Bicep 90-day retention violation", test_bicep_90_day_retention_violation),
        ("Bicep 730-day retention compliant", test_bicep_730_day_retention_compliant),
        ("Bicep platform-managed keys violation", test_bicep_platform_managed_keys_violation),
        ("Bicep Customer-Managed Keys compliant", test_bicep_customer_managed_keys_compliant),
        ("Bicep Cosmos DB without CMK violation", test_bicep_cosmos_without_cmk_violation),
        ("Bicep Cosmos DB with CMK compliant", test_bicep_cosmos_with_cmk_compliant),
        ("Bicep Standard Key Vault violation", test_bicep_standard_keyvault_violation),
        ("Bicep Premium Key Vault compliant", test_bicep_premium_keyvault_compliant),
        ("Terraform 180-day retention violation", test_terraform_retention_violation),
        ("Terraform Storage without CMK violation", test_terraform_cmk_violation),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if await test_func():
                passed += 1
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test_name}: {e}")
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\n[OK] All validation tool tests passed!")
        return True
    else:
        print(f"\n[ERROR] {failed} test(s) failed")
        return False


if __name__ == "__main__":
    import asyncio
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
