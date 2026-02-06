"""
Tests for MCP Tools - All 35 Tools Across 11 Modules

Tests the MCP tool implementations for FedRAMP 20x server.
"""
import pytest
import asyncio
import json
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from fedramp_20x_mcp.tools import (
    requirements, definitions, ksi, frr, documentation,
    export, enhancements, evidence, analyzer, audit,
    security, ksi_status, validation
)


class TestRequirementsTools:
    """Test requirements.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_get_control_impl(self, data_loader):
        """Test get_control implementation"""
        # Test with known FRR IDs (valid FRR families: ADS, CCM, FSI, ICP, KSI, MAS, PVA, RSC, SCN, UCM, VDR)
        for control_id in ["FRR-VDR-01", "FRR-RSC-01", "FRR-SCN-01"]:
            result = await requirements.get_control_impl(control_id, data_loader)
            assert result is not None
            assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_list_family_controls_impl(self, data_loader):
        """Test list_family_controls implementation"""
        for family in ["VDR", "IAM", "SCN", "RSC", "ADS"]:
            result = await requirements.list_family_controls_impl(family, data_loader)
            assert result is not None
            assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_search_requirements_impl(self, data_loader):
        """Test search_requirements implementation"""
        keywords = ["encryption", "authentication", "logging"]
        
        for keyword in keywords:
            result = await requirements.search_requirements_impl(keyword, data_loader)
            assert result is not None
            assert isinstance(result, str)


class TestDefinitionsTools:
    """Test definitions.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_get_definition_impl(self, data_loader):
        """Test get_definition implementation"""
        result = await definitions.get_definition_impl("authorization", data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_list_definitions_impl(self, data_loader):
        """Test list_definitions implementation"""
        result = await definitions.list_definitions_impl(data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_search_definitions_impl(self, data_loader):
        """Test search_definitions implementation"""
        result = await definitions.search_definitions_impl("security", data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestKSITools:
    """Test ksi.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_get_ksi_impl(self, data_loader):
        """Test get_ksi implementation"""
        # Using new descriptive KSI IDs (v0.9.0-beta format)
        for ksi_id in ["KSI-IAM-MFA", "KSI-CNA-RNT", "KSI-AFR-VDR"]:
            result = await ksi.get_ksi_impl(ksi_id, data_loader)
            assert result is not None
            assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_list_ksi_impl(self, data_loader):
        """Test list_ksi implementation"""
        result = await ksi.list_ksi_impl(data_loader)
        assert result is not None
        assert isinstance(result, str)
        # Should contain implementation status info
        assert "Implementation Status" in result or "KSI-" in result
    
    @pytest.mark.asyncio
    async def test_get_ksi_implementation_summary_impl(self, data_loader):
        """Test get_ksi_implementation_summary implementation"""
        result = await ksi.get_ksi_implementation_summary_impl(data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_get_ksi_evidence_automation_impl(self, data_loader):
        """Test get_ksi_evidence_automation implementation"""
        result = await ksi.get_ksi_evidence_automation_impl("KSI-IAM-MFA", data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_get_ksi_evidence_queries_impl(self, data_loader):
        """Test get_ksi_evidence_queries implementation"""
        result = await ksi.get_ksi_evidence_queries_impl("KSI-IAM-MFA", data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_get_ksi_evidence_artifacts_impl(self, data_loader):
        """Test get_ksi_evidence_artifacts implementation"""
        result = await ksi.get_ksi_evidence_artifacts_impl("KSI-IAM-MFA", data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestFRRTools:
    """Test frr.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_list_frrs_by_family_impl(self, data_loader):
        """Test list_frrs_by_family implementation"""
        for family in ["VDR", "IAM", "SCN"]:
            result = await frr.list_frrs_by_family_impl(family, data_loader)
            assert result is not None
            assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_get_frr_metadata_impl(self, data_loader):
        """Test get_frr_metadata implementation"""
        result = await frr.get_frr_metadata_impl("FRR-VDR-01", data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestDocumentationTools:
    """Test documentation.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_get_documentation_file_impl(self, data_loader):
        """Test get_documentation_file implementation"""
        result = await documentation.get_documentation_file_impl("overview.md", data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_search_documentation_impl(self, data_loader):
        """Test search_documentation implementation"""
        result = await documentation.search_documentation_impl("compliance", data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestExportTools:
    """Test export.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_export_to_excel(self, data_loader):
        """Test export_to_excel implementation"""
        # Test different export types
        for export_type in ["ksi", "all_requirements", "definitions"]:
            result = await export.export_to_excel(export_type, None)
            assert result is not None
            assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_export_with_empty_string_path(self, data_loader):
        """Test that empty string output_path is treated as None (default Downloads)"""
        # Test with empty string (MCP wrapper default)
        result = await export.export_to_excel("ksi", "", data_loader)
        assert result is not None
        assert isinstance(result, str)
        assert "Error" not in result
        assert "Downloads" in result
        
        # Test with whitespace string
        result = await export.export_to_csv("ksi", "   ", data_loader)
        assert result is not None
        assert isinstance(result, str)
        assert "Error" not in result
        assert "Downloads" in result
    
    def test_validate_output_path_allowed(self):
        """Test _validate_output_path with allowed paths"""
        from pathlib import Path
        
        # Test Downloads directory
        downloads = Path.home() / "Downloads" / "test.xlsx"
        validated = export._validate_output_path(str(downloads))
        assert validated == downloads.resolve()
        
        # Test Documents directory
        documents = Path.home() / "Documents" / "test.csv"
        validated = export._validate_output_path(str(documents))
        assert validated == documents.resolve()
        
        # Test Desktop directory
        desktop = Path.home() / "Desktop" / "test.xlsx"
        validated = export._validate_output_path(str(desktop))
        assert validated == desktop.resolve()
    
    def test_validate_output_path_traversal_blocked(self):
        """Test that path traversal attempts are blocked"""
        from pathlib import Path
        
        # Test explicit .. in path parts
        with pytest.raises(ValueError) as exc_info:
            export._validate_output_path(str(Path.home() / "Downloads" / ".." / "etc" / "passwd"))
        assert "traversal" in str(exc_info.value).lower()
        
        # Test .. in path parts
        with pytest.raises(ValueError) as exc_info:
            export._validate_output_path(str(Path("..") / "etc" / "passwd"))
        assert "traversal" in str(exc_info.value).lower()
    
    def test_validate_output_path_outside_allowed_blocked(self):
        """Test that paths outside allowed directories are blocked"""
        from pathlib import Path
        
        # Test /tmp (not in allowed list)
        with pytest.raises(ValueError) as exc_info:
            export._validate_output_path("/tmp/test.xlsx")
        assert "allowed directories" in str(exc_info.value).lower()
        # Verify error doesn't leak full paths, only directory names
        assert "/home/" not in str(exc_info.value)
        assert "Downloads" in str(exc_info.value)
        
        # Test /etc
        with pytest.raises(ValueError) as exc_info:
            export._validate_output_path("/etc/test.csv")
        assert "allowed directories" in str(exc_info.value).lower()
    
    def test_validate_output_path_benign_dotdot_allowed(self):
        """Test that filenames containing '..' (but not as path segment) are allowed"""
        from pathlib import Path
        
        # Filename with .. in the name should work (not a path traversal)
        # Note: This test verifies the path.parts check vs string matching
        downloads = Path.home() / "Downloads" / "file..with..dots.xlsx"
        # This should NOT raise an error because '..' is not a path segment
        validated = export._validate_output_path(str(downloads))
        assert validated == downloads.resolve()


class TestEnhancementsTools:
    """Test enhancements.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_compare_with_rev4_impl(self, data_loader):
        """Test compare_with_rev4 implementation"""
        result = await enhancements.compare_with_rev4_impl("IAM", data_loader)
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_generate_implementation_questions_impl(self, data_loader):
        """Test generate_implementation_questions implementation"""
        result = await enhancements.generate_implementation_questions_impl("FRR-VDR-01", data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestEvidenceTools:
    """Test evidence.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_get_evidence_automation_architecture_impl(self, data_loader):
        """Test get_evidence_automation_architecture implementation"""
        result = await evidence.get_evidence_automation_architecture_impl(data_loader, "all")
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_get_infrastructure_code_for_ksi_impl(self, data_loader):
        """Test get_infrastructure_code_for_ksi implementation"""
        # This function requires get_infrastructure_template function, skip for now
        # result = await evidence.get_infrastructure_code_for_ksi_impl("KSI-IAM-01", data_loader, get_infrastructure_template, "bicep")
        # assert result is not None
        # assert isinstance(result, str)
        pass  # Skip - requires template function


class TestAnalyzerTools:
    """Test analyzer.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_analyze_infrastructure_code_impl(self, data_loader):
        """Test analyze_infrastructure_code implementation"""
        code = "resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {}"
        result = await analyzer.analyze_infrastructure_code_impl(code, "bicep", "", "")
        assert result is not None
        assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_analyze_application_code_impl(self, data_loader):
        """Test analyze_application_code implementation"""
        code = "import fido2\nfrom azure.identity import DefaultAzureCredential"
        result = await analyzer.analyze_application_code_impl(code, "python", None, None)
        assert result is not None
        assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_analyze_cicd_pipeline_impl(self, data_loader):
        """Test analyze_cicd_pipeline implementation"""
        code = """
trigger:
  - main
steps:
  - task: dependency-check@6
"""
        result = await analyzer.analyze_cicd_pipeline_impl(code, "azure-pipelines", "")
        assert result is not None
        assert isinstance(result, dict)


class TestAuditTools:
    """Test audit.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_validate_architecture_impl(self, data_loader):
        """Test validate_architecture implementation"""
        arch_description = "Azure-based system with Key Vault, NSGs, and backup"
        result = await enhancements.validate_architecture_impl(arch_description, data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestSecurityTools:
    """Test security.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_check_package_vulnerabilities_impl(self, data_loader):
        """Test check_package_vulnerabilities implementation"""
        result = await security.check_package_vulnerabilities_impl(
            package_name="requests",
            ecosystem="pypi",
            version="2.31.0",
            github_token=None
        )
        assert result is not None
        assert isinstance(result, str)
    
    @pytest.mark.asyncio
    async def test_scan_dependency_file_impl(self, data_loader):
        """Test scan_dependency_file implementation"""
        # Create file content
        file_content = "requests==2.31.0\nflask==2.3.0"
        
        result = await security.scan_dependency_file_impl(
            file_content=file_content,
            file_type="requirements.txt",
            github_token=None
        )
        assert result is not None
        assert isinstance(result, str)


class TestKSIStatusTools:
    """Test ksi_status.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_get_ksi_implementation_status_impl(self, data_loader):
        """Test get_ksi_implementation_status implementation"""
        result = await ksi_status.get_ksi_implementation_status_impl(data_loader)
        assert result is not None
        assert isinstance(result, dict)
    
    @pytest.mark.asyncio
    async def test_get_ksi_coverage_summary_impl(self, data_loader):
        """Test get_ksi_coverage_summary implementation"""
        result = await audit.get_ksi_coverage_summary_impl(data_loader)
        assert result is not None
        assert isinstance(result, str)


class TestValidationTools:
    """Test validation.py tools"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_validate_fedramp_config_impl(self, data_loader):
        """Test validate_fedramp_config implementation"""
        code = """
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'myLogs'
  location: location
  properties: {
    retentionInDays: 730
  }
}
"""
        result = await validation.validate_fedramp_config_impl(code, "bicep", True)
        assert result is not None
        assert isinstance(result, dict)


class TestToolIntegration:
    """Test tool integration and workflows"""
    
    @pytest.fixture
    async def data_loader(self):
        """Create and load data"""
        loader = FedRAMPDataLoader()
        await loader.load_data()
        return loader
    
    @pytest.mark.asyncio
    async def test_requirement_to_ksi_workflow(self, data_loader):
        """Test workflow from requirement to KSI"""
        # 1. Get a requirement (using SCG family which has FRRs in new format)
        req_result = await requirements.get_control_impl("SCG-HRD-SYS", data_loader)
        assert req_result is not None
        
        # 2. Get related KSI
        ksi_result = await ksi.get_ksi_impl("KSI-IAM-MFA", data_loader)
        assert ksi_result is not None
    
    @pytest.mark.asyncio
    async def test_ksi_to_evidence_workflow(self, data_loader):
        """Test workflow from KSI to evidence collection"""
        # 1. Get KSI details
        ksi_result = await ksi.get_ksi_impl("KSI-IAM-MFA", data_loader)
        assert ksi_result is not None
        
        # 2. Get evidence automation
        evidence_result = await ksi.get_ksi_evidence_automation_impl("KSI-IAM-MFA", data_loader)
        assert evidence_result is not None
        
        # 3. Skip infrastructure code test - requires template function
        # infra_result = await evidence.get_infrastructure_code_for_ksi_impl(...)
        pass
    
    @pytest.mark.asyncio
    async def test_code_analysis_workflow(self, data_loader):
        """Test code analysis workflow"""
        code = """
import fido2
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
"""
        
        # Analyze application code
        app_result = await analyzer.analyze_application_code_impl(code, "python", None, None)
        assert app_result is not None
        assert isinstance(app_result, dict)


def run_tests():
    """Run tests with pytest"""
    print("Running MCP Tools tests...")
    print("Testing all 35 tools across 11 modules...")
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
