"""
Tests for validation tool - disableLocalAuth detection (KSI-IAM-01, KSI-IAM-03).

This test verifies that the validate_fedramp_config tool correctly detects
Cosmos DB configurations with disableLocalAuth set to false, which violates
FedRAMP 20x requirements for Azure AD authentication enforcement.
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.tools.validation import validate_fedramp_config_impl


async def test_cosmos_disable_local_auth_violation():
    """Test detection of disableLocalAuth: false (VIOLATION)."""
    bicep_code = """
    resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-test'
      location: 'eastus'
      properties: {
        disableLocalAuth: false  // ❌ VIOLATION - allows shared key auth
        keyVaultKeyUri: 'https://kv-test.vault.azure.net/keys/cosmos-key/abc123'
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("\n=== Test 1: Cosmos DB disableLocalAuth: false ===")
    print(f"Passed: {result['passed']}")
    print(f"Violations: {result['total_violations']}")
    
    # Should detect violation
    assert result['passed'] == False, "Should fail validation"
    assert result['total_violations'] >= 1, "Should have at least 1 violation"
    
    # Check for specific violation
    violation_found = False
    for violation in result['violations']:
        if 'Disable Local Auth' in violation['requirement']:
            violation_found = True
            assert 'disableLocalAuth: false' in violation['found']
            assert 'disableLocalAuth: true' in violation['expected']
            print(f"✅ Detected: {violation['requirement']}")
            print(f"   Expected: {violation['expected']}")
            print(f"   Found: {violation['found']}")
            print(f"   Fix: {violation['fix']}")
    
    assert violation_found, "Should detect disableLocalAuth: false violation"
    print("[PASS] Cosmos DB disableLocalAuth: false violation detected\n")


async def test_cosmos_disable_local_auth_compliant():
    """Test detection of disableLocalAuth: true (COMPLIANT)."""
    bicep_code = """
    resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-test'
      location: 'eastus'
      properties: {
        disableLocalAuth: true  // ✅ COMPLIANT - enforces Azure AD
        keyVaultKeyUri: 'https://kv-test.vault.azure.net/keys/cosmos-key/abc123'
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("=== Test 2: Cosmos DB disableLocalAuth: true ===")
    print(f"Violations: {result['total_violations']}")
    print(f"Compliant: {result['total_compliant']}")
    
    # Should not detect violation for disableLocalAuth
    local_auth_violation = False
    for violation in result['violations']:
        if 'Disable Local Auth' in violation['requirement']:
            local_auth_violation = True
    
    assert not local_auth_violation, "Should not flag disableLocalAuth: true as violation"
    
    # Should detect compliant configuration
    compliant_found = False
    for compliant in result['compliant_values']:
        if 'Disable Local Auth' in compliant['requirement']:
            compliant_found = True
            print(f"✅ Compliant: {compliant['requirement']}")
            print(f"   Value: {compliant['value']}")
    
    assert compliant_found, "Should detect disableLocalAuth: true as compliant"
    print("[PASS] Cosmos DB disableLocalAuth: true recognized as compliant\n")


async def test_cosmos_disable_local_auth_missing():
    """Test detection of missing disableLocalAuth property (WARNING)."""
    bicep_code = """
    resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-test'
      location: 'eastus'
      properties: {
        keyVaultKeyUri: 'https://kv-test.vault.azure.net/keys/cosmos-key/abc123'
        // Missing disableLocalAuth - defaults to false
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("=== Test 3: Cosmos DB missing disableLocalAuth ===")
    print(f"Warnings: {result['total_warnings']}")
    
    # Should generate warning
    warning_found = False
    for warning in result['warnings']:
        if 'Disable Local Auth' in warning['requirement']:
            warning_found = True
            print(f"⚠️  Warning: {warning['requirement']}")
            print(f"   Expected: {warning['expected']}")
            print(f"   Found: {warning['found']}")
            print(f"   Note: {warning['note']}")
    
    assert warning_found, "Should warn about missing disableLocalAuth property"
    print("[PASS] Missing disableLocalAuth property generates warning\n")


async def test_terraform_cosmos_local_auth_violation():
    """Test Terraform Cosmos DB local_authentication_disabled = false."""
    terraform_code = """
    resource "azurerm_cosmosdb_account" "cosmos" {
      name                = "cosmos-test"
      location            = "East US"
      resource_group_name = azurerm_resource_group.rg.name
      offer_type          = "Standard"
      
      local_authentication_disabled = false  # ❌ VIOLATION
      
      consistency_policy {
        consistency_level = "Session"
      }
    }
    """
    
    result = await validate_fedramp_config_impl(terraform_code, "terraform")
    
    print("=== Test 4: Terraform Cosmos DB local_authentication_disabled = false ===")
    print(f"Violations: {result['total_violations']}")
    
    # Should detect violation
    violation_found = False
    for violation in result['violations']:
        if 'Disable Local Auth' in violation['requirement']:
            violation_found = True
            assert 'local_authentication_disabled = false' in violation['found']
            print(f"✅ Detected: {violation['requirement']}")
            print(f"   Fix: {violation['fix']}")
    
    assert violation_found, "Should detect Terraform local_authentication_disabled = false"
    print("[PASS] Terraform local_authentication_disabled = false detected\n")


async def test_terraform_cosmos_local_auth_compliant():
    """Test Terraform Cosmos DB local_authentication_disabled = true."""
    terraform_code = """
    resource "azurerm_cosmosdb_account" "cosmos" {
      name                = "cosmos-test"
      location            = "East US"
      resource_group_name = azurerm_resource_group.rg.name
      offer_type          = "Standard"
      
      local_authentication_disabled = true  # ✅ COMPLIANT
      
      consistency_policy {
        consistency_level = "Session"
      }
    }
    """
    
    result = await validate_fedramp_config_impl(terraform_code, "terraform")
    
    print("=== Test 5: Terraform Cosmos DB local_authentication_disabled = true ===")
    print(f"Compliant: {result['total_compliant']}")
    
    # Should detect compliant configuration
    compliant_found = False
    for compliant in result['compliant_values']:
        if 'Disable Local Auth' in compliant['requirement']:
            compliant_found = True
            print(f"✅ Compliant: {compliant['requirement']}")
    
    assert compliant_found, "Should detect Terraform local_authentication_disabled = true as compliant"
    print("[PASS] Terraform local_authentication_disabled = true recognized\n")


async def test_storage_shared_key_compliant():
    """Test Storage Account with allowSharedKeyAccess: false."""
    bicep_code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'sttest'
      location: 'eastus'
      sku: {
        name: 'Standard_ZRS'
      }
      properties: {
        allowSharedKeyAccess: false  // ✅ COMPLIANT - disables shared key auth
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("=== Test 6: Storage Account allowSharedKeyAccess: false ===")
    print(f"Compliant: {result['total_compliant']}")
    
    # Should detect compliant configuration
    compliant_found = False
    for compliant in result['compliant_values']:
        if 'Storage Disable Shared Key' in compliant['requirement']:
            compliant_found = True
            print(f"✅ Compliant: {compliant['requirement']}")
    
    assert compliant_found, "Should detect Storage allowSharedKeyAccess: false as compliant"
    print("[PASS] Storage allowSharedKeyAccess: false recognized\n")


async def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("VALIDATION TOOL - disableLocalAuth DETECTION TESTS")
    print("Testing: KSI-IAM-01, KSI-IAM-03 (Azure AD enforcement)")
    print("="*70 + "\n")
    
    try:
        await test_cosmos_disable_local_auth_violation()
        await test_cosmos_disable_local_auth_compliant()
        await test_cosmos_disable_local_auth_missing()
        await test_terraform_cosmos_local_auth_violation()
        await test_terraform_cosmos_local_auth_compliant()
        await test_storage_shared_key_compliant()
        
        print("="*70)
        print("ALL TESTS PASSED ✓")
        print("="*70)
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())