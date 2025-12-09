"""
Tests for KSI-PIY-01 Enhanced Analyzer: Automated Inventory
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from fedramp_20x_mcp.analyzers.ksi.ksi_piy_01 import KSI_PIY_01_Analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory


def test_bicep_resource_without_tags():
    """Test detection of Bicep resource without any tags (HIGH)"""
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
  }
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'storage.bicep')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('without inventory tags' in f.title.lower() for f in findings), \
        f"Expected 'without inventory tags' finding, got: {[f.title for f in findings]}"
    print("[PASS] Bicep resource without tags detected")


def test_bicep_resource_with_complete_tags():
    """Test Bicep resource with all required tags (no findings)"""
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  tags: {
    environment: 'production'
    owner: 'platform-team'
    'cost-center': 'engineering'
    compliance: 'fedramp'
    'data-classification': 'confidential'
    'created-date': utcNow('yyyy-MM-dd')
    application: 'myapp'
    'managed-by': 'bicep'
  }
  sku: {
    name: 'Standard_LRS'
  }
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'storage.bicep')
    findings = result.findings
    
    # Should have no HIGH findings (maybe LOW for common tags pattern)
    high_findings = [f for f in findings if f.severity.value == 'HIGH']
    assert len(high_findings) == 0, f"Expected 0 HIGH findings, got {len(high_findings)}"
    print("[PASS] Bicep resource with complete tags recognized correctly")


def test_bicep_resource_missing_required_tags():
    """Test Bicep resource with some tags but missing required ones (HIGH)"""
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  tags: {
    environment: 'production'
    application: 'myapp'
  }
  sku: {
    name: 'Standard_LRS'
  }
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'storage.bicep')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('missing required' in f.title.lower() for f in findings), \
        f"Expected 'missing required' finding, got: {[f.title for f in findings]}"
    print("[PASS] Bicep missing required tags detected")


def test_bicep_multiple_resources_mixed():
    """Test Bicep file with multiple resources (some tagged, some not)"""
    code = """
resource taggedStorage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'taggedstorage'
  location: location
  tags: {
    environment: 'production'
    owner: 'team-a'
    'cost-center': 'engineering'
    compliance: 'fedramp'
    'data-classification': 'public'
    'created-date': '2024-01-01'
  }
}

resource untaggedKeyVault 'Microsoft.KeyVault/vaults@2023-02-01' = {
  name: 'untaggedvault'
  location: location
  properties: {
    sku: { name: 'standard', family: 'A' }
    tenantId: subscription().tenantId
  }
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'resources.bicep')
    findings = result.findings
    
    # Should flag untagged KeyVault
    assert len(findings) >= 1, f"Expected at least 1 finding for untagged resource"
    untagged_findings = [f for f in findings if 'untaggedKeyVault' in f.description or 'untaggedvault' in f.description.lower()]
    assert len(untagged_findings) >= 1, "Expected finding for untagged KeyVault"
    print("[PASS] Bicep multiple resources with mixed tagging detected")


def test_terraform_resource_without_tags():
    """Test Terraform resource without tags (HIGH)"""
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'storage.tf')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('without inventory tags' in f.title.lower() for f in findings), \
        f"Expected 'without inventory tags' finding, got: {[f.title for f in findings]}"
    print("[PASS] Terraform resource without tags detected")


def test_terraform_resource_with_complete_tags():
    """Test Terraform resource with all required tags (no HIGH findings)"""
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  tags = merge(var.common_tags, {
    environment         = "production"
    owner               = "platform-team"
    cost-center         = "engineering"
    compliance          = "fedramp"
    data-classification = "confidential"
    created-date        = "2024-01-01"
    application         = "myapp"
    managed-by          = "terraform"
  })
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'storage.tf')
    findings = result.findings
    
    high_findings = [f for f in findings if f.severity.value == 'HIGH']
    assert len(high_findings) == 0, f"Expected 0 HIGH findings, got {len(high_findings)}"
    print("[PASS] Terraform resource with complete tags recognized correctly")


def test_terraform_missing_required_tags():
    """Test Terraform resource with some tags but missing required ones (HIGH)"""
    code = """
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  
  tags = {
    environment = "production"
    application = "myapp"
  }
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'storage.tf')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('missing required' in f.title.lower() for f in findings), \
        f"Expected 'missing required' finding, got: {[f.title for f in findings]}"
    print("[PASS] Terraform missing required tags detected")


def test_terraform_common_tags_pattern():
    """Test Terraform file without common_tags variable (MEDIUM)"""
    code = """
resource "azurerm_storage_account" "example" {
  name = "mystorageaccount"
  
  tags = {
    environment = "production"
  }
}

resource "azurerm_key_vault" "example" {
  name = "mykeyvault"
  
  tags = {
    environment = "staging"
  }
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'resources.tf')
    findings = result.findings
    
    # Should suggest common_tags variable pattern
    common_tags_findings = [f for f in findings if 'common tags' in f.title.lower() or 'common_tags' in f.title.lower()]
    assert len(common_tags_findings) >= 1, "Expected finding for common tags pattern"
    print("[PASS] Terraform common_tags pattern suggestion detected")


def test_python_azure_resource_graph():
    """Test Python code with Azure Resource Graph queries (INFO)"""
    code = """
from azure.mgmt.resourcegraph import ResourceGraphClient
from azure.identity import DefaultAzureCredential

def get_resource_inventory():
    credential = DefaultAzureCredential()
    client = ResourceGraphClient(credential)
    
    query = '''
    Resources
    | where tags has 'environment' and tags has 'owner'
    | project name, type, location, tags
    '''
    
    result = client.resources(query=query)
    return result.data
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'python', 'inventory.py')
    findings = result.findings
    
    # Should detect Resource Graph usage (informational)
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('inventory query' in f.title.lower() for f in findings), \
        f"Expected 'inventory query' finding, got: {[f.title for f in findings]}"
    print("[PASS] Python Azure Resource Graph query detected")


def test_csharp_azure_sdk_inventory():
    """Test C# code with Azure SDK inventory queries (INFO)"""
    code = """
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Resources;

public async Task<List<GenericResource>> GetResourceInventory()
{
    var credential = new DefaultAzureCredential();
    var client = new ArmClient(credential);
    var subscription = await client.GetDefaultSubscriptionAsync();
    
    var resources = new List<GenericResource>();
    await foreach (var resource in subscription.GetGenericResourcesAsync())
    {
        if (resource.Data.Tags.ContainsKey("environment") && 
            resource.Data.Tags.ContainsKey("owner"))
        {
            resources.Add(resource);
        }
    }
    return resources;
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'Inventory.cs')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('inventory query' in f.title.lower() for f in findings), \
        f"Expected 'inventory query' finding, got: {[f.title for f in findings]}"
    print("[PASS] C# Azure SDK inventory query detected")


def test_typescript_azure_resource_graph():
    """Test TypeScript code with Azure Resource Graph queries (INFO)"""
    code = """
import { ResourceGraphClient } from '@azure/arm-resourcegraph';
import { DefaultAzureCredential } from '@azure/identity';

export async function getResourceInventory(): Promise<any[]> {
  const credential = new DefaultAzureCredential();
  const client = new ResourceGraphClient(credential);
  
  const query = `
    Resources
    | where tags has 'environment' and tags has 'owner'
    | project name, type, location, tags
  `;
  
  const result = await client.resources({ query });
  return result.data || [];
}
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'typescript', 'inventory.ts')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('inventory query' in f.title.lower() for f in findings), \
        f"Expected 'inventory query' finding, got: {[f.title for f in findings]}"
    print("[PASS] TypeScript Azure Resource Graph query detected")


def test_github_actions_scheduled_inventory():
    """Test GitHub Actions with scheduled inventory collection (INFO)"""
    code = """
name: Azure Resource Inventory

on:
  schedule:
    - cron: '0 */6 * * *'  # Every 6 hours
  workflow_dispatch:

jobs:
  inventory:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - uses: azure/login@v1
        with:
          creds: ${{ secrets.AZURE_CREDENTIALS }}
      
      - name: Collect resource inventory
        run: |
          az graph query -q "Resources | where tags has 'environment' | project name, type, tags"
          az resource list --query "[].{name:name, type:type, tags:tags}" -o json > inventory.json
      
      - name: Upload inventory
        uses: actions/upload-artifact@v3
        with:
          name: resource-inventory
          path: inventory.json
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'github-actions', 'inventory.yml')
    findings = result.findings
    
    # Should detect scheduled inventory job (informational)
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('inventory collection' in f.title.lower() for f in findings), \
        f"Expected 'inventory collection' finding, got: {[f.title for f in findings]}"
    print("[PASS] GitHub Actions scheduled inventory detected")


def test_azure_pipelines_scheduled_inventory():
    """Test Azure Pipelines with scheduled inventory collection (INFO)"""
    code = """
schedules:
- cron: "0 */6 * * *"
  displayName: Every 6 hours inventory collection
  branches:
    include:
    - main

jobs:
- job: InventoryCollection
  displayName: 'Collect Azure Resource Inventory'
  pool:
    vmImage: 'ubuntu-latest'
  steps:
  - task: AzureCLI@2
    displayName: 'Query Azure resources'
    inputs:
      azureSubscription: 'MySubscription'
      scriptType: 'bash'
      scriptLocation: 'inlineScript'
      inlineScript: |
        az graph query -q "Resources | project name, type, tags"
        az resource list -o json > inventory.json
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'azure-pipelines', 'inventory-pipeline.yml')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('inventory collection' in f.title.lower() for f in findings), \
        f"Expected 'inventory collection' finding, got: {[f.title for f in findings]}"
    print("[PASS] Azure Pipelines scheduled inventory detected")


def test_gitlab_ci_scheduled_inventory():
    """Test GitLab CI with scheduled inventory collection (INFO)"""
    code = """
inventory:collect:
  stage: monitor
  script:
    - az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID
    - az graph query -q "Resources | where tags has 'environment' | project name, type, tags"
    - az resource list --query "[].{name:name, type:type, tags:tags}" -o json > inventory.json
  artifacts:
    paths:
      - inventory.json
    expire_in: 30 days
  only:
    - schedules
"""
    analyzer = KSI_PIY_01_Analyzer()
    result = analyzer.analyze(code, 'gitlab-ci', '.gitlab-ci.yml')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('inventory collection' in f.title.lower() for f in findings), \
        f"Expected 'inventory collection' finding, got: {[f.title for f in findings]}"
    print("[PASS] GitLab CI scheduled inventory detected")


def test_factory_integration():
    """Test KSI-PIY-01 enhanced analyzer is registered in factory"""
    factory = get_factory()
    
    # Check if PIY-01 is registered
    analyzer = factory.get_analyzer('KSI-PIY-01')
    assert analyzer is not None, "PIY-01 analyzer not found in factory"
    
    # Test factory analyze method
    code = """
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'untagged'
  location: location
}
"""
    result = factory.analyze('KSI-PIY-01', code, 'bicep', 'test.bicep')
    assert len(result.findings) >= 1, "Factory analyze should return findings"
    
    print("[PASS] Factory integration works correctly")


def run_all_tests():
    """Run all PIY-01 enhanced analyzer tests"""
    print("\n=== KSI-PIY-01 Enhanced Analyzer Tests ===\n")
    
    tests = [
        ("Bicep Resource Without Tags", test_bicep_resource_without_tags),
        ("Bicep Complete Tags", test_bicep_resource_with_complete_tags),
        ("Bicep Missing Required Tags", test_bicep_resource_missing_required_tags),
        ("Bicep Multiple Resources Mixed", test_bicep_multiple_resources_mixed),
        ("Terraform Resource Without Tags", test_terraform_resource_without_tags),
        ("Terraform Complete Tags", test_terraform_resource_with_complete_tags),
        ("Terraform Missing Required Tags", test_terraform_missing_required_tags),
        ("Terraform Common Tags Pattern", test_terraform_common_tags_pattern),
        ("Python Azure Resource Graph", test_python_azure_resource_graph),
        ("C# Azure SDK Inventory", test_csharp_azure_sdk_inventory),
        ("TypeScript Resource Graph", test_typescript_azure_resource_graph),
        ("GitHub Actions Scheduled", test_github_actions_scheduled_inventory),
        ("Azure Pipelines Scheduled", test_azure_pipelines_scheduled_inventory),
        ("GitLab CI Scheduled", test_gitlab_ci_scheduled_inventory),
        ("Factory Integration", test_factory_integration),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\n[{test_name}]", end=" ")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"\n[ERROR] {test_name}: {e}")
            failed += 1
    
    print(f"\n\n{'='*60}")
    print(f"Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} tests failed")
    print(f"{'='*60}\n")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)

