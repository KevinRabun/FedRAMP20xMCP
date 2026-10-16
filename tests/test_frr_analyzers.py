"""
Tests for FRR Analyzer Factory and Pattern-Based Analysis

Tests FRR analyzers across all families through the factory pattern.
"""
import pytest
import asyncio
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.frr.factory import FRRAnalyzerFactory, get_factory
from fedramp_20x_mcp.analyzers.base import Severity
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


class TestFRRFactory:
    """Test FRR Analyzer Factory"""
    
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
    
    def test_list_frrs(self, factory):
        """Test listing all FRR IDs - note that FRR patterns don't store FRR IDs"""
        frrs = factory.list_frrs()
        
        assert isinstance(frrs, list)
        # FRR patterns are organized by family, not individual FRR IDs
        # So list_frrs() returns empty list
        assert len(frrs) == 0
    
    def test_list_frrs_by_family(self, factory):
        """Test listing FRRs by family"""
        # Valid FRR families from authoritative source:
        # ADS, CCM, FSI, ICP, KSI, MAS, PVA, RSC, SCN, UCM, VDR
        for family in ["VDR", "SCN", "RSC", "ADS", "CCM", "FSI"]:
            frrs = factory.list_frrs_by_family(family)
            assert isinstance(frrs, list)
            
            # Check all returned FRRs belong to the family
            for frr_id in frrs:
                assert family in frr_id, f"{frr_id} not in family {family}"
    
    def test_get_analyzer(self, factory):
        """Test getting specific analyzer"""
        analyzer = factory.get_analyzer("FRR-VDR-01")
        
        assert analyzer is not None
        assert hasattr(analyzer, 'analyze')
    
    @pytest.mark.asyncio
    async def test_sync_with_authoritative_data(self, factory, data_loader):
        """Test syncing with authoritative data"""
        result = await factory.sync_with_authoritative_data(data_loader)
        
        assert result is not None
        assert isinstance(result, dict)


class TestFRRAnalysisVDR:
    """Test VDR (Vulnerability Detection and Remediation) Family"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_frr_vdr_01_vulnerability_scanning(self, factory):
        """Test FRR-VDR-01: Automated vulnerability scanning"""
        code = """
trigger:
  - main

steps:
  - task: dependency-check@6
    displayName: 'OWASP Dependency Check'
    inputs:
      projectName: 'MyApplication'
      scanPath: '$(Build.SourcesDirectory)'
      format: 'JSON'
      
  - task: PublishTestResults@2
    displayName: 'Publish vulnerability scan results'
    inputs:
      testResultsFormat: 'JUnit'
      testResultsFiles: '**/dependency-check-report.xml'
"""
        
        result = await factory.analyze("FRR-VDR-01", code, "azure-pipelines")
        assert result is not None
    
    @pytest.mark.asyncio
    async def test_frr_vdr_08_automated_patching(self, factory):
        """Test FRR-VDR-08: Automated patching (Python)"""
        code = """
from azure.mgmt.compute import ComputeManagementClient
from azure.identity import DefaultAzureCredential

compute_client = ComputeManagementClient(
    credential=DefaultAzureCredential(),
    subscription_id="sub-id"
)

# Enable automatic OS updates
vm_parameters = {
    'os_profile': {
        'windows_configuration': {
            'enable_automatic_updates': True,
            'patch_settings': {
                'patch_mode': 'AutomaticByPlatform',
                'assessment_mode': 'AutomaticByPlatform'
            }
        }
    }
}
"""
        
        result = await factory.analyze("FRR-VDR-08", code, "python")
        assert result is not None


class TestKSIPatternAnalysisIAM:
    """Test IAM patterns via generic pattern analyzer
    
    Note: IAM is a KSI family (KSI-IAM-*), not an FRR family.
    These tests validate that the pattern engine can analyze IAM-related patterns.
    """
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_iam_mfa_patterns(self, factory):
        """Test IAM MFA patterns (KSI-IAM-01: Phishing-Resistant MFA)"""
        code = """
resource conditionalAccessPolicy 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {
  name: 'require-mfa'
  properties: {
    displayName: 'Require MFA for all users'
    policyType: 'Custom'
    mode: 'All'
    parameters: {}
    policyRule: {
      if: {
        field: 'type'
        equals: 'Microsoft.Compute/virtualMachines'
      }
      then: {
        effect: 'audit'
      }
    }
  }
}
"""
        # IAM patterns are loaded but don't map to FRR IDs
        # The generic analyzer should still process the code
        result = await factory.analyze("KSI-IAM-01", code, "bicep")
        # Result may be None since IAM is not an FRR family
        # This test validates the analyzer handles unknown FRRs gracefully
    
    @pytest.mark.asyncio
    async def test_iam_session_patterns(self, factory):
        """Test IAM session patterns (KSI-IAM-02+: Session management)"""
        code = """
from flask import Flask, session
from datetime import timedelta

app = Flask(__name__)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
"""
        # This tests session management patterns
        result = await factory.analyze("KSI-IAM-02", code, "python")
        # Result may be None since IAM is not an FRR family


class TestFRRAnalysisSCN:
    """Test SCN (Secure Configuration) Family"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_frr_scn_01_system_hardening(self, factory):
        """Test FRR-SCN-01: System hardening"""
        code = """
resource "azurerm_linux_virtual_machine" "vm" {
  name                = "myVM"
  location            = var.location
  resource_group_name = var.resource_group_name
  size                = "Standard_B2s"
  
  admin_username      = "adminuser"
  
  disable_password_authentication = true
  
  admin_ssh_key {
    username   = "adminuser"
    public_key = file("~/.ssh/id_rsa.pub")
  }
  
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }
}
"""
        
        result = await factory.analyze("FRR-SCN-01", code, "terraform")
        assert result is not None


class TestFRRAnalysisRSC:
    """Test RSC (Resilience and Continuity) Family"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_frr_rsc_01_backup_requirements(self, factory):
        """Test FRR-RSC-01: Backup requirements"""
        code = """
resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
  name: 'myRecoveryVault'
  location: location
  sku: {
    name: 'RS0'
    tier: 'Standard'
  }
  properties: {}
}

resource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {
  parent: vault
  name: 'DailyBackupPolicy'
  properties: {
    backupManagementType: 'AzureIaasVM'
    schedulePolicy: {
      schedulePolicyType: 'SimpleSchedulePolicy'
      scheduleRunFrequency: 'Daily'
      scheduleRunTimes: [
        '2023-01-01T02:00:00Z'
      ]
    }
    retentionPolicy: {
      retentionPolicyType: 'LongTermRetentionPolicy'
      dailySchedule: {
        retentionTimes: [
          '2023-01-01T02:00:00Z'
        ]
        retentionDuration: {
          count: 30
          durationType: 'Days'
        }
      }
    }
  }
}
"""
        
        result = await factory.analyze("FRR-RSC-01", code, "bicep")
        assert result is not None


class TestFRRAnalysisADS:
    """Test ADS (Audit and Detection Services) Family"""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_frr_ads_01_audit_log_collection(self, factory):
        """Test FRR-ADS-01: Audit log collection"""
        code = """
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  name: 'audit-logs'
  properties: {
    workspaceId: logAnalyticsWorkspace.id
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 730
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 730
        }
      }
    ]
  }
}
"""
        
        result = await factory.analyze("FRR-ADS-01", code, "bicep")
        assert result is not None


class TestKSIPatternAnalysisCNA:
    """Test CNA patterns via generic pattern analyzer
    
    Note: CNA is a KSI family (KSI-CNA-*), not an FRR family.
    These tests validate that the pattern engine can analyze CNA-related patterns.
    """
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_cna_network_segmentation_patterns(self, factory):
        """Test CNA network patterns (KSI-CNA-01: Restrict Network Traffic)"""
        code = """
resource "azurerm_virtual_network" "vnet" {
  name                = "myVNet"
  address_space       = ["10.0.0.0/16"]
  location            = var.location
  resource_group_name = var.resource_group_name
}

resource "azurerm_subnet" "frontend" {
  name                 = "frontend-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "backend" {
  name                 = "backend-subnet"
  resource_group_name  = var.resource_group_name
  virtual_network_name = azurerm_virtual_network.vnet.name
  address_prefixes     = ["10.0.2.0/24"]
}

resource "azurerm_network_security_group" "frontend_nsg" {
  name                = "frontend-nsg"
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
        # CNA patterns are loaded but don't map to FRR IDs
        result = await factory.analyze("KSI-CNA-01", code, "terraform")
        # Result may be None since CNA is not an FRR family


class TestKSIPatternAnalysisPIY:
    """Test PIY-related patterns (Policy and Inventory)
    
    Note: PIY is a KSI family (KSI-PIY-*), not an FRR family.
    KSI-PIY-01 = "Automated Inventory" - maintains real-time inventories
    KSI-PIY-02 = "Security Objectives and Requirements" - document security objectives
    
    These tests validate patterns that relate to KSI-PIY requirements.
    """
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.mark.asyncio
    async def test_ksi_piy_inventory_patterns(self, factory):
        """Test inventory patterns that support KSI-PIY-01 (Automated Inventory)"""
        code = """
using Azure.Security.KeyVault.Keys;
using Azure.Identity;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

var keyVaultUri = new Uri("https://myvault.vault.azure.net");
var credential = new DefaultAzureCredential();

var keyClient = new KeyClient(keyVaultUri, credential);
var key = await keyClient.CreateKeyAsync("storage-key", KeyType.Rsa);

var blobServiceClient = new BlobServiceClient(
    new Uri("https://mystorage.blob.core.windows.net"),
    credential
);

var containerClient = blobServiceClient.GetBlobContainerClient("encrypted-data");
await containerClient.CreateIfNotExistsAsync(PublicAccessType.None);
"""
        # PIY patterns are for KSI, not FRR
        # This tests the generic analyzer with PIY-related code
        result = await factory.analyze("KSI-PIY-01", code, "csharp")
        # Result may be None since PIY is not an FRR family


class TestFRRComprehensiveCoverage:
    """Test comprehensive FRR coverage using authoritative data sources."""
    
    @pytest.fixture
    def factory(self):
        """Create factory instance"""
        return get_factory()
    
    @pytest.fixture
    def data_loader(self):
        """Create data loader to access authoritative FRR data."""
        return FedRAMPDataLoader()
    
    @pytest.mark.asyncio
    async def test_all_frr_families_covered(self, factory, data_loader):
        """Test all major FRR families have analyzer coverage.
        
        Validates against authoritative FedRAMP JSON files to ensure
        the factory can analyze code for all 11 FRR families.
        """
        # Load authoritative FRR data
        await data_loader.load_data()
        
        # Valid FRR families from authoritative source:
        # ADS, CCM, FSI, ICP, KSI, MAS, PVA, RSC, SCN, UCM, VDR
        expected_families = ["VDR", "RSC", "ADS", "SCN", "CCM", "MAS", "UCM", "ICP", "FSI", "PVA", "KSI"]
        
        # Check each family has an analyzer available
        families_with_analyzers = []
        for family in expected_families:
            # Try to get analyzer for first FRR in family
            frr_id = f"FRR-{family}-01"
            analyzer = factory.get_analyzer(frr_id)
            if analyzer is not None:
                families_with_analyzers.append(family)
        
        # Should have analyzers for most families (at least 7 of 11)
        assert len(families_with_analyzers) >= 7, (
            f"Expected analyzers for >=7 families, got {len(families_with_analyzers)}: "
            f"{families_with_analyzers}. Missing: {set(expected_families) - set(families_with_analyzers)}"
        )
    
    @pytest.mark.asyncio
    async def test_significant_frr_coverage(self, factory, data_loader):
        """Test significant number of FRRs have analyzer support.
        
        Validates that the factory can provide analyzers for a substantial
        portion of the 199 FRR requirements from the authoritative source.
        """
        # Load authoritative FRR data
        await data_loader.load_data()
        
        # Get all FRRs from authoritative source using get_family_controls
        all_frrs = []
        for family in ["VDR", "RSC", "ADS", "SCN", "CCM", "MAS", "UCM", "ICP", "FSI", "PVA", "KSI"]:
            frrs = data_loader.get_family_controls(family)
            if frrs:
                all_frrs.extend(frrs)
        
        # Count FRRs with analyzer support
        frrs_with_analyzers = 0
        for frr in all_frrs:
            # Get FRR ID from requirement data - could be 'id' or 'requirement_id'
            frr_id = frr.get("id", frr.get("requirement_id", ""))
            if frr_id:
                analyzer = factory.get_analyzer(frr_id)
                if analyzer is not None:
                    frrs_with_analyzers += 1
        
        # Report coverage
        total_frrs = len(all_frrs)
        coverage_pct = (frrs_with_analyzers / total_frrs * 100) if total_frrs > 0 else 0
        
        # Should have analyzer support for at least 50 FRRs
        # (Pattern-based analyzers cover families, so individual FRR coverage may vary)
        assert frrs_with_analyzers >= 50, (
            f"Expected analyzer support for >=50 FRRs, got {frrs_with_analyzers}/{total_frrs} "
            f"({coverage_pct:.1f}%)"
        )
    
    @pytest.mark.asyncio
    async def test_analyze_all_frrs(self, factory):
        """Test analyze_all_frrs method"""
        code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'premium'
    }
    enablePurgeProtection: true
    enableSoftDelete: true
    enableRbacAuthorization: true
  }
}
"""
        
        result = await factory.analyze_all_frrs(code, "bicep")
        
        assert result is not None
        assert isinstance(result, list)
        # Each item in list should be AnalysisResult
        if len(result) > 0:
            assert hasattr(result[0], 'findings')


class TestFRREvidenceAutomation:
    """Test FRR Evidence Automation module with Azure KQL queries (CR26 rule IDs)."""

    def test_get_frr_evidence_automation_vdr(self):
        """Test VDR family evidence automation returns correct structure."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        automation = get_frr_evidence_automation("VDR-CSO-DET")

        assert automation is not None
        assert automation.frr_id == "VDR-CSO-DET"
        assert automation.family == "VDR"
        assert automation.evidence_type == "log-based"
        assert automation.automation_feasibility == "high"
        assert len(automation.azure_services) > 0
        assert "Microsoft Defender for Cloud" in automation.azure_services
        assert len(automation.queries) >= 2  # Should have KQL queries

    def test_get_frr_evidence_automation_scg(self):
        """Test SCG (Secure Configuration Guide) family evidence automation."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        automation = get_frr_evidence_automation("SCG-CSO-RSC")

        assert automation is not None
        assert automation.family == "SCG"
        assert "Azure Policy" in automation.azure_services
        assert len(automation.queries) > 0

    def test_get_frr_evidence_automation_cds(self):
        """Test CDS (Authorization Data Sharing) family evidence automation."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        automation = get_frr_evidence_automation("CDS-CSO-PUB")

        assert automation is not None
        assert automation.family == "CDS"
        assert "Azure Monitor Log Analytics" in automation.azure_services
        # Should have audit log completeness query
        query_names = [q.query_name for q in automation.queries]
        assert any("Audit" in name for name in query_names)

    def test_get_frr_evidence_automation_scn(self):
        """Test SCN family evidence automation."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        automation = get_frr_evidence_automation("SCN-CSO-EVA")

        assert automation is not None
        assert automation.family == "SCN"
        # Should include network security queries
        assert len(automation.queries) > 0

    def test_family_parsed_from_first_id_segment(self):
        """Family is the first segment of the CR26 ID, never a generic 'FRR'."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        for frr_id, family in [("CCM-OCR-AVL", "CCM"), ("MAS-CSO-IIR", "MAS"), ("VER-EVA-EIR", "VER")]:
            automation = get_frr_evidence_automation(frr_id)
            assert automation is not None
            assert automation.family == family

    def test_malformed_id_returns_none(self):
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        assert get_frr_evidence_automation("VDR") is None

    def test_evidence_queries_have_kql(self):
        """Test that evidence queries contain valid KQL syntax."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import VDR_EVIDENCE_QUERIES

        for frr_id, queries in VDR_EVIDENCE_QUERIES.items():
            for query in queries:
                # All queries should have content
                assert query.query is not None
                assert len(query.query.strip()) > 0

                # KQL queries should have typical operators
                query_text = query.query.lower()
                assert any(op in query_text for op in [
                    'where', 'project', 'summarize', 'extend', 'order', 'join', '|'
                ]), f"Query {query.query_name} missing KQL operators"

    def test_format_evidence_automation_markdown(self):
        """Test markdown formatting of evidence automation."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import (
            get_frr_evidence_automation,
            format_evidence_automation_markdown
        )

        automation = get_frr_evidence_automation("VDR-CSO-DET")
        assert automation is not None, "Expected automation for VDR-CSO-DET"
        markdown = format_evidence_automation_markdown(automation)

        assert markdown is not None
        assert "# Evidence Automation for VDR-CSO-DET" in markdown
        assert "**Family:** VDR" in markdown
        assert "Azure Services Required" in markdown
        assert "Implementation Steps" in markdown
        assert "Evidence Collection Queries" in markdown
        assert "```kql" in markdown  # Should have KQL code blocks

    def test_get_all_frr_evidence_queries(self):
        """Test retrieving all evidence queries."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_all_frr_evidence_queries

        all_queries = get_all_frr_evidence_queries()

        assert len(all_queries) > 0
        # Should have queries for multiple FRRs
        assert "VDR-CSO-DET" in all_queries
        assert "SCG-CSO-RSC" in all_queries
        assert "CDS-CSO-PUB" in all_queries

    def test_get_all_frr_evidence_queries_filtered(self):
        """Test filtering evidence queries by family."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_all_frr_evidence_queries

        vdr_queries = get_all_frr_evidence_queries("VDR")

        assert len(vdr_queries) > 0
        for frr_id in vdr_queries.keys():
            assert frr_id.startswith("VDR-")

    def test_all_evidence_query_ids_exist_in_rules(self):
        """Every FRR id with bundled evidence queries is a real CR26 rule."""
        import asyncio
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_all_frr_evidence_queries
        from fedramp_20x_mcp.data_loader import FedRAMPDataLoader

        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        for frr_id in get_all_frr_evidence_queries():
            assert loader.get_control(frr_id) is not None, f"{frr_id} not in CR26 rules"

    def test_evidence_artifacts_have_required_fields(self):
        """Test evidence artifacts have all required fields."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        automation = get_frr_evidence_automation("VDR-CSO-DET")
        assert automation is not None, "Expected automation for VDR-CSO-DET"

        for artifact in automation.artifacts:
            assert artifact.artifact_name is not None
            assert artifact.artifact_type is not None
            assert artifact.description is not None
            assert artifact.collection_method is not None
            assert artifact.storage_location is not None
            # Retention is an organizational default (CR26 sets no numeric period)
            assert artifact.retention_months > 0

    def test_evidence_queries_have_retention(self):
        """Evidence queries carry a positive retention default (not a FedRAMP number)."""
        from fedramp_20x_mcp.analyzers.frr.evidence_automation import get_frr_evidence_automation

        automation = get_frr_evidence_automation("VDR-CSO-DET")
        assert automation is not None, "Expected automation for VDR-CSO-DET"

        for query in automation.queries:
            assert query.retention_days > 0, f"Query {query.query_name} has no retention default"


def _template_path(*parts):
    import os
    return os.path.join(os.path.dirname(__file__), '..', 'src', 'fedramp_20x_mcp', 'templates', *parts)


def _read_template(*parts):
    with open(_template_path(*parts), 'r', encoding='utf-8') as f:
        return f.read()


_CODE_TEMPLATES = (
    'frr_evidence_python.txt', 'frr_evidence_csharp.txt',
    'frr_evidence_java.txt', 'frr_evidence_typescript.txt',
)


class TestFRREvidenceTemplates:
    """Test FRR Evidence Collection Templates exist and have required content (CR26)."""

    def test_python_template_exists(self):
        """Test Python evidence collection template exists."""
        import os
        assert os.path.exists(_template_path('code', 'frr_evidence_python.txt')), "Python template not found"
        content = _read_template('code', 'frr_evidence_python.txt')

        assert "FRREvidenceCollector" in content
        assert "azure-identity" in content
        assert "VDR-CSO-DET" in content
        assert "collect_vdr_01_evidence" in content

    def test_csharp_template_exists(self):
        """Test C# evidence collection template exists."""
        import os
        assert os.path.exists(_template_path('code', 'frr_evidence_csharp.txt')), "C# template not found"
        content = _read_template('code', 'frr_evidence_csharp.txt')

        assert "FRREvidenceCollector" in content
        assert "Azure.Identity" in content
        assert "VDR-CSO-DET" in content
        assert "CollectVdr01Evidence" in content

    def test_java_template_exists(self):
        """Test Java evidence collection template exists."""
        import os
        assert os.path.exists(_template_path('code', 'frr_evidence_java.txt')), "Java template not found"
        content = _read_template('code', 'frr_evidence_java.txt')

        assert "FRREvidenceCollector" in content
        assert "azure-identity" in content
        assert "VDR-CSO-DET" in content
        assert "collectVdr01Evidence" in content

    def test_typescript_template_exists(self):
        """Test TypeScript evidence collection template exists."""
        import os
        assert os.path.exists(_template_path('code', 'frr_evidence_typescript.txt')), "TypeScript template not found"
        content = _read_template('code', 'frr_evidence_typescript.txt')

        assert "FRREvidenceCollector" in content
        assert "@azure/identity" in content
        assert "VDR-CSO-DET" in content
        assert "collectVdr01Evidence" in content

    def test_bicep_template_exists(self):
        """Test Bicep infrastructure template exists and is a hardened immutable store."""
        import os
        assert os.path.exists(_template_path('bicep', 'frr_evidence_collection.txt')), "Bicep template not found"
        content = _read_template('bicep', 'frr_evidence_collection.txt')

        assert "Microsoft.Storage/storageAccounts" in content
        assert "immutabilityPolicies" in content
        assert "immutabilityPeriodDays" in content

    def test_terraform_template_exists(self):
        """Test Terraform infrastructure template exists and is a hardened immutable store."""
        import os
        assert os.path.exists(_template_path('bicep', 'frr_evidence_terraform.txt')), "Terraform template not found"
        content = _read_template('bicep', 'frr_evidence_terraform.txt')

        assert "terraform" in content
        assert "azurerm" in content
        assert "azurerm_storage_account" in content
        assert "azurerm_storage_container_immutability_policy" in content
        assert "immutability_period_in_days" in content

    def test_all_templates_cover_frr_families(self):
        """Test all code templates cover the same CR26 rules."""
        expected_frrs = ["VDR-CSO-DET", "VER-EVA-EIR", "SCG-CSO-RSC", "CDS-CSO-PUB", "SCN-CSO-EVA", "CCM-OCR-AVL"]

        for filename in _CODE_TEMPLATES:
            content = _read_template('code', filename)
            for frr_id in expected_frrs:
                assert frr_id in content, f"{filename} missing {frr_id}"

    def test_templates_use_no_retired_ids(self):
        """No template still uses legacy FRR-<family>-NN identifiers."""
        import re
        files = [('code', f) for f in _CODE_TEMPLATES]
        files += [('bicep', 'frr_evidence_collection.txt'), ('bicep', 'frr_evidence_terraform.txt')]
        for parts in files:
            content = _read_template(*parts)
            assert not re.search(r'FRR-[A-Z]{3}-[0-9]{2}\b', content), f"{parts[-1]} has legacy FRR-XXX-NN ids"

    def test_templates_do_not_present_retention_as_fedramp_requirement(self):
        """CR26 has no numeric log retention rule: templates must not claim one."""
        import re
        iac = [('bicep', 'frr_evidence_collection.txt'), ('bicep', 'frr_evidence_terraform.txt')]
        files = iac + [('code', f) for f in _CODE_TEMPLATES]
        for parts in files:
            content = _read_template(*parts)
            assert "730" not in content, f"{parts[-1]} hardcodes the legacy 730 day retention"
            assert not re.search(
                r'fedramp[^\n]{0,40}(requires|requirement)[^\n]{0,40}(retention|[0-9]+ ?(days|years))',
                content, re.I), f"{parts[-1]} presents retention as a FedRAMP requirement"
        for parts in iac:
            content = _read_template(*parts)
            assert "organizational choice" in content, f"{parts[-1]} should label retention as organizational"

    def test_infrastructure_templates_are_immutable_and_no_shared_key(self):
        """Evidence storage templates enforce immutability and Entra-only access."""
        bicep = _read_template('bicep', 'frr_evidence_collection.txt')
        assert "allowSharedKeyAccess: false" in bicep
        assert "allowBlobPublicAccess: false" in bicep
        assert "immutabilityPeriodSinceCreationInDays" in bicep

        tf = _read_template('bicep', 'frr_evidence_terraform.txt')
        assert "shared_access_key_enabled         = false" in tf
        assert "allow_nested_items_to_be_public   = false" in tf
        assert "immutability_period_in_days" in tf
        # Locking is a deliberate out-of-band step: never locked in code by default
        assert "lock_immutability_policy" in tf


def run_tests():
    """Run tests with pytest"""
    print("Running FRR Analyzer tests...")
    print("Testing pattern-based FRR analysis across all families...")
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()

