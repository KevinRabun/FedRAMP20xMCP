"""
Tests for KSI-CNA-04 Enhanced: Immutable Infrastructure

Tests immutable infrastructure patterns across multiple languages:
- Python: Container deployment patterns, configuration management
- C#: Immutable collections, readonly configurations
- Java: Immutable objects, final fields
- TypeScript: readonly properties, const declarations
- Bicep: VM vs containers, managed identities, AKS image scanning
- Terraform: VM configurations, container apps, AKS security
- Factory integration
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_04 import KSI_CNA_04_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_bicep_vm_without_managed_identity():
    """Test detection of VM deployment without managed identity"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource vm 'Microsoft.Compute/virtualMachines@2022-11-01' = {
  name: 'myVM'
  location: resourceGroup().location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_DS1_v2'
    }
    // No managed identity configured - mutable infrastructure
  }
}
'''
    
    result = analyzer.analyze(code, "bicep", "vm.bicep")
    assert result.total_issues > 0
    assert any("identity" in f.title.lower() or "vm" in f.title.lower() for f in result.findings)


def test_bicep_container_app_with_mutable_volume():
    """Test detection of container app with mutable storage volume"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource containerApp 'Microsoft.App/containerApps@2022-03-01' = {
  name: 'myapp'
  properties: {
    template: {
      volumes: [
        {
          name: 'data-volume'
          storageType: 'AzureFile'  // Mutable storage
        }
      ]
    }
  }
}
'''
    
    result = analyzer.analyze(code, "bicep", "app.bicep")
    assert result.total_issues > 0
    assert any("mutable" in f.title.lower() or "volume" in f.title.lower() for f in result.findings)


def test_bicep_aks_without_image_scanning():
    """Test detection of AKS cluster without image security validation"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource aksCluster 'Microsoft.ContainerService/managedClusters@2023-01-01' = {
  name: 'myAKSCluster'
  location: resourceGroup().location
  properties: {
    dnsPrefix: 'myaks'
    agentPoolProfiles: [
      {
        name: 'agentpool'
        count: 3
        vmSize: 'Standard_DS2_v2'
      }
    ]
    // No image scanning or Defender for Containers
  }
}
'''
    
    result = analyzer.analyze(code, "bicep", "aks.bicep")
    assert result.total_issues > 0
    assert any("image" in f.title.lower() or "security" in f.title.lower() for f in result.findings)


def test_terraform_vm_without_managed_identity():
    """Test detection of VM without managed identity in Terraform"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_F2"
  # No identity block - missing managed identity
}
'''
    
    result = analyzer.analyze(code, "terraform", "vm.tf")
    assert result.total_issues > 0
    assert any("identity" in f.title.lower() or "vm" in f.title.lower() for f in result.findings)


def test_terraform_container_app_mutable_storage():
    """Test detection of container app with mutable storage"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource "azurerm_container_app" "example" {
  name                         = "example-app"
  container_app_environment_id = azurerm_container_app_environment.example.id
  revision_mode                = "Single"

  template {
    container {
      name   = "myapp"
      image  = "myregistry.azurecr.io/myapp:latest"
      cpu    = 0.25
      memory = "0.5Gi"
    }
    volume {
      name = "data"
      storage_type = "AzureFile"  # Mutable storage
    }
  }
}
'''
    
    result = analyzer.analyze(code, "terraform", "app.tf")
    assert result.total_issues > 0
    assert any("mutable" in f.title.lower() or "volume" in f.title.lower() for f in result.findings)


def test_terraform_aks_without_defender():
    """Test detection of AKS without Defender for Containers"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 1
    vm_size    = "Standard_D2_v2"
  }
  # No Defender for Containers configured
}
'''
    
    result = analyzer.analyze(code, "terraform", "aks.tf")
    assert result.total_issues > 0
    assert any("defender" in f.title.lower() or "security" in f.title.lower() for f in result.findings)


def test_python_immutable_patterns():
    """Test Python code analysis (limited applicability)"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
# Python application code - limited code detection for CNA-04
config = {"setting": "value"}
config["setting"] = "new_value"  # Mutable configuration
'''
    
    result = analyzer.analyze(code, "python", "config.py")
    # CNA-04 primarily IaC-focused, app code detection limited
    assert result.ksi_id == "KSI-CNA-04"


def test_factory_integration():
    """Test that CNA-04 enhanced is registered in factory"""
    from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    ksi_list = factory.list_ksis()
    
    assert "KSI-CNA-04" in ksi_list
    
    # Test factory can analyze
    code = '''
resource vm 'Microsoft.Compute/virtualMachines@2022-11-01' = {
  name: 'myVM'
}
'''
    
    result = factory.analyze("KSI-CNA-04", code, "bicep", "test.bicep")
    assert result.ksi_id == "KSI-CNA-04"


def test_bicep_aks_with_defender():
    """Test that AKS with Defender is recognized as more compliant"""
    analyzer = KSI_CNA_04_Analyzer()
    
    code = '''
resource aksCluster 'Microsoft.ContainerService/managedClusters@2023-01-01' = {
  name: 'myAKSCluster'
  location: resourceGroup().location
  properties: {
    dnsPrefix: 'myaks'
    securityProfile: {
      defender: {
        securityMonitoring: {
          enabled: true  // Defender for Containers enabled
        }
      }
    }
  }
}
'''
    
    result = analyzer.analyze(code, "bicep", "aks.bicep")
    # With Defender enabled, should have fewer security findings
    defender_findings = [f for f in result.findings if "defender" in f.title.lower() and "without" in f.title.lower()]
    assert len(defender_findings) == 0


if __name__ == "__main__":
    print("Testing KSI-CNA-04 Enhanced Analyzer...")
    print("=" * 60)
    
    tests = [
        ("Bicep VM Without Managed Identity", test_bicep_vm_without_managed_identity),
        ("Bicep Container App With Mutable Volume", test_bicep_container_app_with_mutable_volume),
        ("Bicep AKS Without Image Scanning", test_bicep_aks_without_image_scanning),
        ("Terraform VM Without Managed Identity", test_terraform_vm_without_managed_identity),
        ("Terraform Container App Mutable Storage", test_terraform_container_app_mutable_storage),
        ("Terraform AKS Without Defender", test_terraform_aks_without_defender),
        ("Python Immutable Patterns", test_python_immutable_patterns),
        ("Factory Integration", test_factory_integration),
        ("Bicep AKS With Defender", test_bicep_aks_with_defender),
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

