"""
Comprehensive Test Suite for KSI-CNA-04 (Immutable Infrastructure)

Tests Python, Java, TypeScript, Bicep, and Terraform analyzers for immutable infrastructure patterns.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_04 import KSI_CNA_04_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity

def test_python_docker_without_readonly():
    """Test 1: Python - Docker container without read-only root filesystem"""
    code = """
import docker

client = docker.from_env()

# BAD: Container without read_only=True
container = client.containers.run(
    'myapp:latest',
    detach=True,
    volumes={'/data': {'bind': '/app/data', 'mode': 'rw'}}
)
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'test.py')
    findings = result.findings
    
    # Should detect missing read-only root
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Read-Only Root Filesystem' in f.title for f in findings), "Should detect missing read-only root"
    assert any(f.severity == Severity.MEDIUM for f in findings), "Should be MEDIUM severity"
    print("[PASS] Python: Detects Docker container without read-only root")

def test_python_docker_with_readonly():
    """Test 2: Python - Docker container WITH read-only root filesystem (secure)"""
    code = """
import docker

client = docker.from_env()

# GOOD: Container with read_only=True
container = client.containers.run(
    'myapp:latest',
    read_only=True,  # Immutable container
    detach=True,
    volumes={'/tmp': {'bind': '/tmp', 'mode': 'rw'}}
)
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'test.py')
    findings = result.findings
    
    # Should NOT detect issue - read_only is True
    readonly_findings = [f for f in findings if 'Read-Only Root Filesystem' in f.title]
    assert len(readonly_findings) == 0, f"Should not detect issue with read_only=True, got {len(readonly_findings)} findings"
    print("[PASS] Python: Accepts Docker container with read_only=True")

def test_python_kubernetes_without_readonly():
    """Test 3: Python - Kubernetes container without readOnlyRootFilesystem"""
    code = """
from kubernetes import client

# BAD: Container without read-only root
container = client.V1Container(
    name='myapp',
    image='myapp:latest',
    ports=[client.V1ContainerPort(container_port=8080)]
)
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'test.py')
    findings = result.findings
    
    # Should detect missing readOnlyRootFilesystem
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Kubernetes Container' in f.title and 'Read-Only' in f.title for f in findings), "Should detect missing K8s read-only root"
    print("[PASS] Python: Detects Kubernetes container without readOnlyRootFilesystem")

def test_java_docker_without_readonly():
    """Test 4: Java - Docker Java SDK without read-only root"""
    code = """
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.core.DockerClientBuilder;

public class DockerExample {
    public void runContainer() {
        DockerClient dockerClient = DockerClientBuilder.getInstance().build();
        
        // BAD: Container without withReadonlyRootfs
        CreateContainerResponse container = dockerClient.createContainerCmd("myapp:latest")
            .withVolumes(new Volume("/tmp"))
            .exec();
    }
}
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'java', 'DockerExample.java')
    findings = result.findings
    
    # Should detect missing read-only root
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Read-Only Root Filesystem' in f.title for f in findings), "Should detect missing withReadonlyRootfs"
    print("[PASS] Java: Detects Docker container without withReadonlyRootfs")

def test_typescript_dockerode_without_readonly():
    """Test 5: TypeScript - Dockerode without ReadonlyRootfs"""
    code = """
import Docker from 'dockerode';

const docker = new Docker();

// BAD: Container without ReadonlyRootfs
const container = await docker.createContainer({
    Image: 'myapp:latest',
    HostConfig: {
        Binds: ['/tmp:/tmp:rw']
    }
});

await container.start();
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'typescript', 'docker.ts')
    findings = result.findings
    
    # Should detect missing ReadonlyRootfs
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Read-Only Root Filesystem' in f.title for f in findings), "Should detect missing ReadonlyRootfs"
    print("[PASS] TypeScript: Detects Dockerode without ReadonlyRootfs")

def test_bicep_vm_without_identity():
    """Test 6: Bicep - Virtual Machine without managed identity"""
    code = """
resource virtualMachine 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myVM'
  location: resourceGroup().location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_DS1_v2'
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'UbuntuServer'
        sku: '18.04-LTS'
        version: 'latest'
      }
    }
  }
}
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'main.bicep')
    findings = result.findings
    
    # Should detect missing managed identity
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Managed Identity' in f.title for f in findings), "Should detect missing managed identity"
    print("[PASS] Bicep: Detects VM without managed identity")

def test_bicep_container_app_with_volume():
    """Test 7: Bicep - Container App with mutable volume"""
    code = """
resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {
  name: 'myApp'
  location: resourceGroup().location
  properties: {
    template: {
      containers: [
        {
          name: 'main'
          image: 'myapp:latest'
        }
      ]
      volumes: [
        {
          name: 'data-volume'
          storageType: 'AzureFile'
          storageName: 'mystorageaccount'
        }
      ]
    }
  }
}
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'app.bicep')
    findings = result.findings
    
    # Should detect mutable storage volume
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Mutable Storage Volume' in f.title for f in findings), "Should detect mutable AzureFile volume"
    assert any(f.severity == Severity.HIGH for f in findings), "Should be HIGH severity"
    print("[PASS] Bicep: Detects Container App with mutable volume")

def test_terraform_vm_without_identity():
    """Test 8: Terraform - VM without managed identity"""
    code = """
resource "azurerm_linux_virtual_machine" "example" {
  name                = "example-vm"
  resource_group_name = azurerm_resource_group.example.name
  location            = azurerm_resource_group.example.location
  size                = "Standard_DS1_v2"

  admin_username                  = "azureuser"
  disable_password_authentication = true

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "UbuntuServer"
    sku       = "18.04-LTS"
    version   = "latest"
  }
}
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'main.tf')
    findings = result.findings
    
    # Should detect missing managed identity
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Managed Identity' in f.title for f in findings), "Should detect missing identity block"
    print("[PASS] Terraform: Detects VM without managed identity")

def test_terraform_container_app_with_volume():
    """Test 9: Terraform - Container App with mutable volume"""
    code = """
resource "azurerm_container_app" "example" {
  name                         = "example-app"
  resource_group_name          = azurerm_resource_group.example.name
  container_app_environment_id = azurerm_container_app_environment.example.id

  template {
    container {
      name   = "main"
      image  = "myapp:latest"
      cpu    = 0.5
      memory = "1Gi"
    }

    volume {
      name         = "data-volume"
      storage_type = "AzureFile"
      storage_name = "mystorageaccount"
    }
  }
}
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'main.tf')
    findings = result.findings
    
    # Should detect mutable volume
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Mutable Storage Volume' in f.title for f in findings), "Should detect AzureFile volume"
    print("[PASS] Terraform: Detects Container App with mutable volume")

def test_terraform_aks_without_defender():
    """Test 10: Terraform - AKS without Microsoft Defender"""
    code = """
resource "azurerm_kubernetes_cluster" "example" {
  name                = "example-aks"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name
  dns_prefix          = "exampleaks"

  default_node_pool {
    name       = "default"
    node_count = 3
    vm_size    = "Standard_DS2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'aks.tf')
    findings = result.findings
    
    # Should detect missing Defender
    assert len(findings) >= 1, f"Expected at least 1 finding, got {len(findings)}"
    assert any('Image Security Validation' in f.title or 'Defender' in f.title for f in findings), "Should detect missing Defender"
    print("[PASS] Terraform: Detects AKS without Microsoft Defender")

def test_python_regex_fallback():
    """Test 11: Python regex fallback for syntax errors"""
    code = """
import docker
client = docker.from_env()

# Intentional syntax error to trigger fallback
container = client.containers.run(
    'myapp:latest
    detach=True  # Missing closing quote above
)
"""
    
    analyzer = KSI_CNA_04_Analyzer()
    result = analyzer.analyze(code, 'python', 'test.py')
    findings = result.findings
    
    # Should use regex fallback and still detect issue
    assert len(findings) >= 1, f"Regex fallback should detect issue, got {len(findings)} findings"
    assert any('Regex Fallback' in f.title for f in findings), "Should indicate regex fallback"
    print("[PASS] Python: Regex fallback works on syntax error")

def run_all_tests():
    """Run all KSI-CNA-04 tests"""
    print("\n" + "="*80)
    print("KSI-CNA-04 Immutable Infrastructure - Comprehensive Test Suite")
    print("="*80 + "\n")
    
    tests = [
        test_python_docker_without_readonly,
        test_python_docker_with_readonly,
        test_python_kubernetes_without_readonly,
        test_java_docker_without_readonly,
        test_typescript_dockerode_without_readonly,
        test_bicep_vm_without_identity,
        test_bicep_container_app_with_volume,
        test_terraform_vm_without_identity,
        test_terraform_container_app_with_volume,
        test_terraform_aks_without_defender,
        test_python_regex_fallback
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_func.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_func.__name__}: {e}")
            failed += 1
    
    print("\n" + "="*80)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if failed == 0:
        print("ALL TESTS PASSED!")
    print("="*80 + "\n")
    
    return failed == 0

if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
