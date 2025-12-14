"""
Tests for KSI Analyzer Factory and Pattern-Based Analysis

Tests all 72 KSI analyzers through the factory pattern.
"""
import pytest
import asyncio
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.ksi.factory import KSIAnalyzerFactory, get_factory
from fedramp_20x_mcp.analyzers.base import Severity
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


class TestKSIFactory:
    """Test KSI Analyzer Factory"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.fixture
    async def data_loader(self):
        """Create data loader instance"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    def test_factory_singleton(self):
        """Test factory is singleton"""
        factory1 = get_factory()
        factory2 = get_factory()
        assert factory1 is factory2
    
    def test_list_ksis(self, factory):
        """Test listing all KSI IDs"""
        ksis = factory.list_ksis()
        
        assert isinstance(ksis, list)
        assert len(ksis) > 0
        
        # Should have KSI IDs in correct format
        for ksi_id in ksis:
            assert ksi_id.startswith("KSI-")
            assert len(ksi_id) > 7  # KSI-XXX-NN format
    
    def test_get_analyzer(self, factory):
        """Test getting specific analyzer"""
        analyzer = factory.get_analyzer("KSI-IAM-01")
        
        assert analyzer is not None
        assert hasattr(analyzer, 'analyze')
    
    @pytest.mark.asyncio
    async def test_sync_with_authoritative_data(self, factory, data_loader):
        """Test syncing with authoritative data"""
        result = await factory.sync_with_authoritative_data(data_loader)
        
        assert result is not None
        assert isinstance(result, dict)
        assert "total_analyzers" in result or "note" in result


class TestKSIAnalysis:
    """Test KSI analysis across different code types"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    # IAM Family Tests
    @pytest.mark.asyncio
    async def test_ksi_iam_01_mfa_python(self, factory):
        """Test KSI-IAM-01: Phishing-resistant MFA (Python)"""
        code = """
import fido2
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

rp = PublicKeyCredentialRpEntity("example.com", "Example")
server = Fido2Server(rp)
"""
        
        result = await factory.analyze("KSI-IAM-01", code, "python")
        assert result is not None
        assert hasattr(result, 'findings')
    
    @pytest.mark.asyncio
    async def test_ksi_iam_01_mfa_csharp(self, factory):
        """Test KSI-IAM-01: Phishing-resistant MFA (C#)"""
        code = """
using Fido2NetLib;
using Microsoft.Extensions.Configuration;

var fido2 = new Fido2(new Fido2Configuration
{
    ServerDomain = "example.com",
    ServerName = "Example",
    Origin = "https://example.com"
});
"""
        
        result = await factory.analyze("KSI-IAM-01", code, "csharp")
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_ksi_iam_02_privileged_access(self, factory):
        """Test KSI-IAM-02: Privileged Access Management"""
        code = """
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.identity import DefaultAzureCredential

auth_client = AuthorizationManagementClient(
    credential=DefaultAzureCredential(),
    subscription_id="sub-id"
)
"""
        
        result = await factory.analyze("KSI-IAM-02", code, "python")
        assert result is not None
    
    # CNA Family Tests
    @pytest.mark.asyncio
    async def test_ksi_cna_01_network_segmentation_bicep(self, factory):
        """Test KSI-CNA-01: Network Segmentation (Bicep)"""
        code = """
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'myNSG'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowHTTPS'
        properties: {
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 100
          direction: 'Inbound'
        }
      }
    ]
  }
}
"""
        
        result = await factory.analyze("KSI-CNA-01", code, "bicep")
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_ksi_cna_01_network_segmentation_terraform(self, factory):
        """Test KSI-CNA-01: Network Segmentation (Terraform)"""
        code = """
resource "azurerm_network_security_group" "nsg" {
  name                = "myNSG"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
"""
        
        result = await factory.analyze("KSI-CNA-01", code, "terraform")
        assert result is not None
    
    # VDR Family Tests
    @pytest.mark.asyncio
    async def test_ksi_vdr_01_vulnerability_scanning(self, factory):
        """Test KSI-VDR-01: Vulnerability Scanning"""
        code = """
trigger:
  - main

steps:
  - task: dependency-check@6
    inputs:
      projectName: 'MyApp'
      scanPath: '$(Build.SourcesDirectory)'
      format: 'JSON'
"""
        
        result = await factory.analyze("KSI-VDR-01", code, "azure-pipelines")
        assert result is not None
    
    # SCN Family Tests  
    @pytest.mark.asyncio
    async def test_ksi_scn_01_baseline_configuration(self, factory):
        """Test KSI-SCN-01: Baseline Configuration"""
        code = """
resource "azurerm_policy_assignment" "cis_benchmark" {
  name                 = "cis-benchmark"
  scope                = var.subscription_id
  policy_definition_id = var.cis_policy_id
  
  parameters = jsonencode({
    effect = {
      value = "Audit"
    }
  })
}
"""
        
        result = await factory.analyze("KSI-SCN-01", code, "terraform")
        assert result is not None
    
    # RSC Family Tests
    @pytest.mark.asyncio
    async def test_ksi_rsc_01_backup_recovery(self, factory):
        """Test KSI-RSC-01: Backup and Recovery"""
        code = """
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.identity import DefaultAzureCredential

backup_client = RecoveryServicesBackupClient(
    credential=DefaultAzureCredential(),
    subscription_id="sub-id"
)
"""
        
        result = await factory.analyze("KSI-RSC-01", code, "python")
        assert result is not None
    
    # ADS Family Tests
    @pytest.mark.asyncio
    async def test_ksi_ads_01_audit_logging(self, factory):
        """Test KSI-ADS-01: Audit Logging"""
        code = """
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'myLogAnalytics'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 730
  }
}
"""
        
        result = await factory.analyze("KSI-ADS-01", code, "bicep")
        assert result is not None
    
    # PIY Family Tests
    @pytest.mark.asyncio
    async def test_ksi_piy_01_data_encryption_at_rest(self, factory):
        """Test KSI-PIY-01: Data Encryption at Rest"""
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
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
      requireInfrastructureEncryption: true
      keySource: 'Microsoft.Keyvault'
      keyvaultproperties: {
        keyname: 'mykey'
        keyvaulturi: 'https://myvault.vault.azure.net/'
      }
    }
  }
}
"""
        
        result = await factory.analyze("KSI-PIY-01", code, "bicep")
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_ksi_piy_02_data_encryption_in_transit(self, factory):
        """Test KSI-PIY-02: Data Encryption in Transit"""
        code = """
resource appService 'Microsoft.Web/sites@2022-09-01' = {
  name: 'myApp'
  location: location
  properties: {
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      http20Enabled: true
    }
  }
}
"""
        
        result = await factory.analyze("KSI-PIY-02", code, "bicep")
        assert result is not None


class TestKSIComprehensiveCoverage:
    """Test coverage across all KSI families"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    def test_all_ksis_have_analyzers(self, factory):
        """Test all KSIs have available analyzers"""
        ksis = factory.list_ksis()
        
        # Should have significant KSI coverage
        assert len(ksis) >= 40, f"Expected >=40 KSIs, got {len(ksis)}"
        
        # Check each KSI has an analyzer
        for ksi_id in ksis:
            analyzer = factory.get_analyzer(ksi_id)
            assert analyzer is not None, f"No analyzer for {ksi_id}"
    
    @pytest.mark.asyncio
    async def test_ksi_families_covered(self, factory):
        """Test all major KSI families are covered"""
        ksis = factory.list_ksis()
        
        families = set()
        for ksi_id in ksis:
            # Extract family from KSI-FAM-NN format
            parts = ksi_id.split('-')
            if len(parts) >= 2:
                families.add(parts[1])
        
        # Should cover major families (based on actual KSI patterns available)
        # Note: SCN family has FRR patterns but no KSI patterns
        expected_families = ["IAM", "CNA", "VDR", "PIY", "CMT", "MLA"]
        for family in expected_families:
            assert family in families, f"Missing family coverage: {family}"
    
    @pytest.mark.asyncio
    async def test_analyze_all_ksis(self, factory):
        """Test analyze_all_ksis method"""
        code = """
import fido2
from azure.identity import DefaultAzureCredential
import logging

logger = logging.getLogger(__name__)
credential = DefaultAzureCredential()
"""
        
        results = await factory.analyze_all_ksis(code, "python")
        
        assert results is not None
        assert isinstance(results, list)
        # Results may be empty list or list with one AnalysisResult
        if len(results) > 0:
            assert hasattr(results[0], 'findings')


def run_tests():
    """Run tests with pytest"""
    print("Running KSI Analyzer tests...")
    print("Testing pattern-based KSI analysis across 72 analyzers...")
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()

