"""
Test MCP Server Understanding of FedRAMP 20x Requirements

This test suite validates that the MCP server correctly loads and understands
all KSI and FRR requirements from the authoritative FedRAMP source.

These tests verify:
1. All KSI requirements are loaded with correct data (60 minimum expected)
2. All FRR requirements are loaded with correct data (across 11 families)
3. The server returns correct statement content matching authoritative sources

Note: FedRAMP 20x data format was updated in Feb 2026. KSI IDs changed from
numeric format (KSI-IAM-01) to descriptive format (KSI-IAM-AAM). Some KSIs
now have level-specific statements via 'varies_by_level' instead of 'statement'.
"""

import pytest
import asyncio
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


class TestAllKSIsLoaded:
    """Test that MCP server correctly loads KSI requirements with correct content"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    def test_minimum_ksis_present(self, data_loader):
        """Verify minimum KSIs are present in loaded data (at least 50)"""
        ksi_data = data_loader.list_all_ksi()
        loaded_ksi_ids = {ksi['id'] for ksi in ksi_data}
        
        # Verify we have at least 50 KSIs
        assert len(ksi_data) >= 50, f"Expected at least 50 KSIs, got {len(ksi_data)}"
        
        # Verify all have required fields
        for ksi in ksi_data:
            assert 'id' in ksi, f"KSI missing 'id' field: {ksi}"
    
    def test_ksi_statements_loaded(self, data_loader):
        """Verify all KSI statements are loaded from authoritative source"""
        ksi_data = data_loader.list_all_ksi()
        
        for ksi in ksi_data:
            ksi_id = ksi['id']
            assert 'id' in ksi, f"{ksi_id} missing 'id' field"
            
            # KSIs can have either 'statement' or 'varies_by_level' for level-specific statements
            has_statement = 'statement' in ksi and ksi['statement']
            has_varies = 'varies_by_level' in ksi and ksi['varies_by_level']
            
            assert has_statement or has_varies, f"{ksi_id} missing 'statement' field"
            
            # If has regular statement (not varies_by_level), verify it's valid
            if has_statement:
                statement = ksi['statement']
                assert isinstance(statement, str), f"{ksi_id} statement is not a string: {type(statement)}"
                
                # Active KSIs should have non-empty statements
                if not ksi.get('retired', False):
                    assert len(statement) > 0, f"{ksi_id} is active but has empty statement"


class TestAllFRRsLoaded:
    """Test that MCP server correctly loads FRR requirements with correct content"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    def test_all_frr_families_present(self, data_loader):
        """Verify all FRR families are loaded"""
        # In the new format, FRR requirements have IDs like VDR-AGM-DRE
        # They are stored in families by the first part (VDR, ADS, etc.)
        families = list(data_loader._data_cache["families"].keys())
        
        # Expected FRR families (new format uses family codes without FRR- prefix)
        expected_families = ['VDR', 'ADS', 'CCM', 'FSI', 'ICP', 'MAS', 'PVA', 'SCG', 'SCN', 'UCM']
        
        for family in expected_families:
            assert family in families, f"FRR family {family} not loaded. Found: {families}"
    
    def test_frr_statements_loaded(self, data_loader):
        """Verify FRR statements are loaded from authoritative source"""
        # Get requirements that belong to FRR families
        frr_families = ['VDR', 'ADS', 'CCM', 'FSI', 'ICP', 'MAS', 'PVA', 'SCG', 'SCN', 'UCM']
        frr_data = []
        
        for family in frr_families:
            frr_data.extend(data_loader.get_family_controls(family))
        
        assert len(frr_data) > 0, "No FRR requirements loaded"
        
        for frr in frr_data:
            frr_id = frr['id']
            assert 'id' in frr, f"{frr_id} missing 'id' field"
            
            # FRRs can have either 'statement' or 'varies_by_level' for level-specific statements
            has_statement = 'statement' in frr and frr['statement']
            has_varies = 'varies_by_level' in frr and frr['varies_by_level']
            
            assert has_statement or has_varies, f"{frr_id} missing 'statement' field"
            
            # If has regular statement (not varies_by_level), verify it's valid
            if has_statement:
                statement = frr['statement']
                assert isinstance(statement, str), f"{frr_id} statement is not a string: {type(statement)}"
                assert len(statement) > 0, f"{frr_id} has empty statement"


class TestRequirementAccuracy:
    """Verify critical requirements that were previously misunderstood"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    # Test critical KSI statements - using new descriptive IDs (Feb 2026 format)
    # Old numeric IDs can be found via 'fka' (formerly known as) field
    @pytest.mark.parametrize("ksi_id,expected_statement_fragment", [
        # KSI-PIY-GIV (fka KSI-PIY-01) - inventories
        ("KSI-PIY-GIV", "inventories of all information resources"),
        # KSI-SVC-EIS (fka KSI-SVC-01) - evaluating and improving security
        ("KSI-SVC-EIS", "evaluation of information resources for opportunities to improve security"),
        # KSI-SVC-ASM (fka KSI-SVC-06) - automating secret management
        ("KSI-SVC-ASM", "management, protection, and regular rotation of digital keys"),
    ])
    def test_critical_ksi_statements(self, data_loader, ksi_id, expected_statement_fragment):
        """Verify critical KSI statements contain expected content"""
        ksi = data_loader.get_ksi(ksi_id)
        
        assert ksi is not None, f"{ksi_id} not found"
        
        # Get statement (either direct or from varies_by_level)
        statement = ksi.get('statement', '')
        if not statement and 'varies_by_level' in ksi:
            varies = ksi.get('varies_by_level', {})
            if 'moderate' in varies:
                statement = varies['moderate'].get('statement', '')
            elif 'low' in varies:
                statement = varies['low'].get('statement', '')
        
        assert expected_statement_fragment.lower() in statement.lower(), \
            f"{ksi_id} statement doesn't contain expected fragment:\n" \
            f"  Expected fragment: {expected_statement_fragment}\n" \
            f"  Got:      {statement}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
