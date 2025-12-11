"""
Tests for validation tool - Private Endpoint detection (KSI-CNA-01, KSI-CNA-03).

This test verifies that the validate_fedramp_config tool correctly detects
when publicNetworkAccess is disabled WITHOUT Private Endpoints configured,
which renders resources completely inaccessible.
"""

import sys
import asyncio
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.tools.validation import validate_fedramp_config_impl


async def test_public_access_disabled_no_private_endpoints():
    """Test detection of publicNetworkAccess: 'Disabled' WITHOUT Private Endpoints (VIOLATION)."""
    bicep_code = """
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'sttest'
      location: 'eastus'
      sku: { name: 'Standard_GRS' }
      properties: {
        publicNetworkAccess: 'Disabled'  // [FAIL] VIOLATION - no Private Endpoints!
        minimumTlsVersion: 'TLS1_2'
      }
    }
    
    resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-test'
      location: 'eastus'
      properties: {
        publicNetworkAccess: 'Disabled'  // [FAIL] VIOLATION - no Private Endpoints!
        disableLocalAuth: true
        keyVaultKeyUri: 'https://kv-test.vault.azure.net/keys/cosmos-key/abc123'
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("\n=== Test 1: publicNetworkAccess: 'Disabled' WITHOUT Private Endpoints ===")
    print(f"Passed: {result['passed']}")
    print(f"Violations: {result['total_violations']}")
    
    # Should detect CRITICAL violation
    assert result['passed'] == False, "Should fail validation"
    assert result['total_violations'] >= 1, "Should have at least 1 violation"
    
    # Check for specific violation
    violation_found = False
    for violation in result['violations']:
        if 'Private Endpoints Required' in violation['requirement']:
            violation_found = True
            assert 'NO Private Endpoints found' in violation['found']
            assert 'CRITICAL' == violation['severity']
            print(f"[OK] Detected: {violation['requirement']}")
            print(f"   Severity: {violation['severity']}")
            print(f"   Found: {violation['found']}")
            print(f"   Fix: {violation['fix']}")
    
    assert violation_found, "Should detect missing Private Endpoints violation"
    print("[PASS] Missing Private Endpoints violation detected\n")


async def test_public_access_disabled_with_private_endpoints():
    """Test detection of publicNetworkAccess: 'Disabled' WITH Private Endpoints (COMPLIANT)."""
    bicep_code = """
    resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
      name: 'vnet-test'
      location: 'eastus'
      properties: {
        addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
        subnets: [{
          name: 'snet-private-endpoints'
          properties: {
            addressPrefix: '10.0.1.0/24'
            privateEndpointNetworkPolicies: 'Disabled'
          }
        }]
      }
    }
    
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'sttest'
      location: 'eastus'
      sku: { name: 'Standard_GRS' }
      properties: {
        publicNetworkAccess: 'Disabled'  // [OK] OK - Private Endpoints configured
        minimumTlsVersion: 'TLS1_2'
      }
    }
    
    resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
      name: 'pe-storage-blob'
      location: 'eastus'
      properties: {
        subnet: {
          id: '${vnet.id}/subnets/snet-private-endpoints'
        }
        privateLinkServiceConnections: [{
          name: 'storage-connection'
          properties: {
            privateLinkServiceId: storage.id
            groupIds: ['blob']
          }
        }]
      }
    }
    
    resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
      name: 'cosmos-test'
      location: 'eastus'
      properties: {
        publicNetworkAccess: 'Disabled'  // [OK] OK - Private Endpoints configured
        disableLocalAuth: true
        keyVaultKeyUri: 'https://kv-test.vault.azure.net/keys/cosmos-key/abc123'
      }
    }
    
    resource cosmosPrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = {
      name: 'pe-cosmos'
      location: 'eastus'
      properties: {
        subnet: {
          id: '${vnet.id}/subnets/snet-private-endpoints'
        }
        privateLinkServiceConnections: [{
          name: 'cosmos-connection'
          properties: {
            privateLinkServiceId: cosmosDb.id
            groupIds: ['Sql']
          }
        }]
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("=== Test 2: publicNetworkAccess: 'Disabled' WITH Private Endpoints ===")
    print(f"Violations: {result['total_violations']}")
    print(f"Compliant: {result['total_compliant']}")
    
    # Should not detect Private Endpoint violation
    private_endpoint_violation = False
    for violation in result['violations']:
        if 'Private Endpoints Required' in violation['requirement']:
            private_endpoint_violation = True
    
    assert not private_endpoint_violation, "Should not flag Private Endpoints as missing when configured"
    
    # Should detect compliant configuration
    compliant_found = False
    for compliant in result['compliant_values']:
        if 'Private Endpoints' in compliant['requirement']:
            compliant_found = True
            print(f"[OK] Compliant: {compliant['requirement']}")
            print(f"   Value: {compliant['value']}")
    
    assert compliant_found, "Should detect Private Endpoints as compliant"
    print("[PASS] Private Endpoints configuration recognized as compliant\n")


async def test_terraform_no_private_endpoints():
    """Test Terraform public_network_access_enabled = false WITHOUT Private Endpoints."""
    terraform_code = """
    resource "azurerm_storage_account" "evidence" {
      name                     = "stfedrampevidence"
      resource_group_name      = azurerm_resource_group.rg.name
      location                 = "East US"
      account_tier             = "Standard"
      account_replication_type = "GRS"
      
      public_network_access_enabled = false  # [FAIL] VIOLATION - no Private Endpoints!
    }
    
    resource "azurerm_cosmosdb_account" "db" {
      name                = "cosmos-fedramp"
      location            = "East US"
      resource_group_name = azurerm_resource_group.rg.name
      offer_type          = "Standard"
      
      public_network_access_enabled = false  # [FAIL] VIOLATION - no Private Endpoints!
      local_authentication_disabled = true
    }
    """
    
    result = await validate_fedramp_config_impl(terraform_code, "terraform")
    
    print("=== Test 3: Terraform public_network_access_enabled = false WITHOUT Private Endpoints ===")
    print(f"Violations: {result['total_violations']}")
    
    # Should detect violation
    violation_found = False
    for violation in result['violations']:
        if 'Private Endpoints Required' in violation['requirement']:
            violation_found = True
            assert 'NO Private Endpoints found' in violation['found']
            print(f"[OK] Detected: {violation['requirement']}")
            print(f"   Fix: {violation['fix']}")
    
    assert violation_found, "Should detect missing Terraform Private Endpoints"
    print("[PASS] Terraform missing Private Endpoints detected\n")


async def test_terraform_with_private_endpoints():
    """Test Terraform public_network_access_enabled = false WITH Private Endpoints."""
    terraform_code = """
    resource "azurerm_virtual_network" "vnet" {
      name                = "vnet-fedramp"
      location            = "East US"
      resource_group_name = azurerm_resource_group.rg.name
      address_space       = ["10.0.0.0/16"]
    }
    
    resource "azurerm_subnet" "private_endpoints" {
      name                 = "snet-private-endpoints"
      resource_group_name  = azurerm_resource_group.rg.name
      virtual_network_name = azurerm_virtual_network.vnet.name
      address_prefixes     = ["10.0.1.0/24"]
      
      private_endpoint_network_policies_enabled = false
    }
    
    resource "azurerm_storage_account" "evidence" {
      name                     = "stfedrampevidence"
      resource_group_name      = azurerm_resource_group.rg.name
      location                 = "East US"
      account_tier             = "Standard"
      account_replication_type = "GRS"
      
      public_network_access_enabled = false  # [OK] OK - Private Endpoints configured
    }
    
    resource "azurerm_private_endpoint" "storage" {
      name                = "pe-storage-blob"
      location            = "East US"
      resource_group_name = azurerm_resource_group.rg.name
      subnet_id           = azurerm_subnet.private_endpoints.id
      
      private_service_connection {
        name                           = "storage-connection"
        private_connection_resource_id = azurerm_storage_account.evidence.id
        subresource_names              = ["blob"]
        is_manual_connection           = false
      }
    }
    """
    
    result = await validate_fedramp_config_impl(terraform_code, "terraform")
    
    print("=== Test 4: Terraform public_network_access_enabled = false WITH Private Endpoints ===")
    print(f"Compliant: {result['total_compliant']}")
    
    # Should detect compliant configuration
    compliant_found = False
    for compliant in result['compliant_values']:
        if 'Private Endpoints' in compliant['requirement']:
            compliant_found = True
            print(f"[OK] Compliant: {compliant['requirement']}")
    
    assert compliant_found, "Should detect Terraform Private Endpoints as compliant"
    print("[PASS] Terraform Private Endpoints recognized as compliant\n")


async def test_public_access_enabled():
    """Test publicNetworkAccess: 'Enabled' (should flag as violation, regardless of Private Endpoints)."""
    bicep_code = """
    resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'sttest'
      location: 'eastus'
      sku: { name: 'Standard_GRS' }
      properties: {
        publicNetworkAccess: 'Enabled'  // [FAIL] VIOLATION - public access enabled
        minimumTlsVersion: 'TLS1_2'
      }
    }
    """
    
    result = await validate_fedramp_config_impl(bicep_code, "bicep")
    
    print("=== Test 5: publicNetworkAccess: 'Enabled' ===")
    print(f"Violations: {result['total_violations']}")
    
    # Should detect public access violation
    violation_found = False
    for violation in result['violations']:
        if 'Public Access Disabled' in violation['requirement']:
            violation_found = True
            print(f"[OK] Detected: {violation['requirement']}")
    
    assert violation_found, "Should detect enabled public access as violation"
    print("[PASS] Enabled public access detected as violation\n")


async def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("VALIDATION TOOL - PRIVATE ENDPOINTS DETECTION TESTS")
    print("Testing: KSI-CNA-01, KSI-CNA-03 (Private network connectivity)")
    print("="*70 + "\n")
    
    try:
        await test_public_access_disabled_no_private_endpoints()
        await test_public_access_disabled_with_private_endpoints()
        await test_terraform_no_private_endpoints()
        await test_terraform_with_private_endpoints()
        await test_public_access_enabled()
        
        print("="*70)
        print("ALL TESTS PASSED [PASS]")
        print("="*70)
        
    except AssertionError as e:
        print(f"\n[FAIL] TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[FAIL] ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
