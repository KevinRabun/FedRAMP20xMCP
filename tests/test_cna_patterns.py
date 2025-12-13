"""
Auto-generated tests for pattern detection.
Tests both positive cases (pattern should detect) and negative cases (should not detect).
"""
import pytest
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.generic_analyzer import GenericPatternAnalyzer
from fedramp_20x_mcp.analyzers.base import Severity

class TestCnaPatterns:
    """Test CNA pattern detection"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer

    def test_cna_network_nsg_configuration_positive(self, analyzer):
        """Test cna.network.nsg_configuration: Network Security Group Configuration - Should detect"""
        code = """resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'myNSG'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowAll'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.network.nsg_configuration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.network.nsg_configuration should detect this code"
    
    def test_cna_network_nsg_configuration_negative(self, analyzer):
        """Test cna.network.nsg_configuration: Network Security Group Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.network.nsg_configuration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.network.nsg_configuration should NOT detect compliant code"


    def test_cna_network_azure_firewall_positive(self, analyzer):
        """Test cna.network.azure_firewall: Azure Firewall Configuration - Should detect"""
        code = """resource firewall 'Microsoft.Network/azureFirewalls@2023-05-01' = {
  name: 'myFirewall'
  location: 'eastus'
  properties: {
    networkRuleCollections: []
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.network.azure_firewall" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.network.azure_firewall should detect this code"
    
    def test_cna_network_azure_firewall_negative(self, analyzer):
        """Test cna.network.azure_firewall: Azure Firewall Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.network.azure_firewall" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.network.azure_firewall should NOT detect compliant code"


    def test_cna_attack_surface_minimal_dependencies_positive(self, analyzer):
        """Test cna.attack_surface.minimal_dependencies: Minimal Dependencies Analysis - Should detect"""
        code = """import requests
import numpy
from flask import Flask, request"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.attack_surface.minimal_dependencies" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.attack_surface.minimal_dependencies should detect this code"
    
    def test_cna_attack_surface_minimal_dependencies_negative(self, analyzer):
        """Test cna.attack_surface.minimal_dependencies: Minimal Dependencies Analysis - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.attack_surface.minimal_dependencies" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.attack_surface.minimal_dependencies should NOT detect compliant code"


    def test_cna_immutable_infra_container_image_positive(self, analyzer):
        """Test cna.immutable_infra.container_image: Immutable Container Image - Should detect"""
        code = """FROM gcr.io/distroless/python3-debian12
COPY app.py /app/
CMD ["app.py"]"""
        
        result = analyzer.analyze(code, "dockerfile")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.immutable_infra.container_image" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.immutable_infra.container_image should detect this code"
    
    def test_cna_immutable_infra_container_image_negative(self, analyzer):
        """Test cna.immutable_infra.container_image: Immutable Container Image - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "dockerfile")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.immutable_infra.container_image" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.immutable_infra.container_image should NOT detect compliant code"


    def test_cna_iac_aks_cluster_positive(self, analyzer):
        """Test cna.iac.aks_cluster: Azure Kubernetes Service Configuration - Should detect"""
        code = """resource aks 'Microsoft.ContainerService/managedClusters@2023-07-01' = {
  name: 'myAKS'
  location: 'eastus'
  properties: {
    dnsPrefix: 'myaks'
    networkProfile: {
      networkPlugin: 'azure'
    }
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.iac.aks_cluster" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.iac.aks_cluster should detect this code"
    
    def test_cna_iac_aks_cluster_negative(self, analyzer):
        """Test cna.iac.aks_cluster: Azure Kubernetes Service Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.iac.aks_cluster" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.iac.aks_cluster should NOT detect compliant code"


    def test_cna_iac_container_registry_positive(self, analyzer):
        """Test cna.iac.container_registry: Azure Container Registry Configuration - Should detect"""
        code = """resource acr 'Microsoft.ContainerRegistry/registries@2023-01-01' = {
  name: 'myacr'
  location: 'eastus'
  sku: {
    name: 'Premium'
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.iac.container_registry" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.iac.container_registry should detect this code"
    
    def test_cna_iac_container_registry_negative(self, analyzer):
        """Test cna.iac.container_registry: Azure Container Registry Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.iac.container_registry" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.iac.container_registry should NOT detect compliant code"


    def test_cna_observability_monitoring_integration_positive(self, analyzer):
        """Test cna.observability.monitoring_integration: Cloud-Native Monitoring Integration - Should detect"""
        code = """import opencensus

def main():
    pass"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.observability.monitoring_integration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.observability.monitoring_integration should detect this code"
    
    def test_cna_observability_monitoring_integration_negative(self, analyzer):
        """Test cna.observability.monitoring_integration: Cloud-Native Monitoring Integration - Should NOT detect"""
        code = """def compliant_function():
    # This is compliant code
    return True

if __name__ == "__main__":
    compliant_function()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.observability.monitoring_integration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.observability.monitoring_integration should NOT detect compliant code"


    def test_cna_api_gateway_configuration_positive(self, analyzer):
        """Test cna.api_gateway.configuration: API Gateway Configuration - Should detect"""
        code = """resource apim 'Microsoft.ApiManagement/service@2023-03-01' = {
  name: 'myAPIManagement'
  location: 'eastus'
  sku: {
    name: 'Developer'
    capacity: 1
  }
}"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.api_gateway.configuration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.api_gateway.configuration should detect this code"
    
    def test_cna_api_gateway_configuration_negative(self, analyzer):
        """Test cna.api_gateway.configuration: API Gateway Configuration - Should NOT detect"""
        code = """param location string = resourceGroup().location

output resourceLocation string = location
"""
        
        result = analyzer.analyze(code, "bicep")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.api_gateway.configuration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.api_gateway.configuration should NOT detect compliant code"


    def test_cna_service_mesh_configuration_positive(self, analyzer):
        """Test cna.service_mesh.configuration: Service Mesh Configuration - Should detect"""
        code = """apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: my-service
spec:
  hosts:
  - my-service"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.service_mesh.configuration" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.service_mesh.configuration should detect this code"
    
    def test_cna_service_mesh_configuration_negative(self, analyzer):
        """Test cna.service_mesh.configuration: Service Mesh Configuration - Should NOT detect"""
        code = """# Compliant code that should not trigger detection"""
        
        result = analyzer.analyze(code, "yaml")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.service_mesh.configuration" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.service_mesh.configuration should NOT detect compliant code"


    def test_cna_cicd_container_build_positive(self, analyzer):
        """Test cna.cicd.container_build: Container Build in CI/CD - Should detect"""
        code = """name: Container Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build container image
        run: docker build -t myapp:latest ."""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.cicd.container_build" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.cicd.container_build should detect this code"
    
    def test_cna_cicd_container_build_negative(self, analyzer):
        """Test cna.cicd.container_build: Container Build in CI/CD - Should NOT detect"""
        code = """name: Simple Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: npm test"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.cicd.container_build" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.cicd.container_build should NOT detect compliant code"


    def test_cna_cicd_infrastructure_validation_positive(self, analyzer):
        """Test cna.cicd.infrastructure_validation: Infrastructure Validation in CI/CD - Should detect"""
        code = """name: IaC Validation
on: [push]
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Validate Bicep
        run: az bicep build --file main.bicep"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.cicd.infrastructure_validation" == f.pattern_id]
        assert len(findings) > 0, f"Pattern cna.cicd.infrastructure_validation should detect this code"
    
    def test_cna_cicd_infrastructure_validation_negative(self, analyzer):
        """Test cna.cicd.infrastructure_validation: Infrastructure Validation in CI/CD - Should NOT detect"""
        code = """name: Simple Pipeline
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run tests
        run: npm test"""
        
        result = analyzer.analyze(code, "github_actions")
        
        # Should NOT detect the pattern
        findings = [f for f in result.findings if hasattr(f, 'pattern_id') and "cna.cicd.infrastructure_validation" == f.pattern_id]
        assert len(findings) == 0, f"Pattern cna.cicd.infrastructure_validation should NOT detect compliant code"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
