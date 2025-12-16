"""
Test MCP Server Understanding of FedRAMP 20x Requirements

This test suite validates that the MCP server correctly loads and understands
all KSI and FRR requirements from the authoritative FedRAMP source.

These tests verify:
1. All KSI requirements are loaded with correct data (72 total: 65 active + 7 retired)
2. All FRR requirements are loaded with correct data (199 total across 10 families)
3. The server returns EXACT statement content matching authoritative sources

CRITICAL: Every single KSI and FRR has an individual test verifying exact statement match.
This ensures the MCP server has the CORRECT understanding, not just that data exists.
"""

import pytest
import asyncio
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
from requirement_statements import KSI_STATEMENTS, FRR_STATEMENTS


class TestAllKSIsLoaded:
    """Test that MCP server correctly loads ALL 72 KSI requirements with exact content"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    def test_all_72_ksis_present(self, data_loader):
        """Verify all 72 KSIs are present in loaded data"""
        ksi_data = data_loader.list_all_ksi()
        loaded_ksi_ids = {ksi['id'] for ksi in ksi_data}
        expected_ksi_ids = set(KSI_STATEMENTS.keys())
        
        missing = expected_ksi_ids - loaded_ksi_ids
        extra = loaded_ksi_ids - expected_ksi_ids
        
        assert len(missing) == 0, f"Missing KSIs: {sorted(missing)}"
        assert len(extra) == 0, f"Unexpected KSIs: {sorted(extra)}"
        assert len(ksi_data) == 72, f"Expected 72 total KSIs, got {len(ksi_data)}"
    
    @pytest.mark.parametrize("ksi_id", list(KSI_STATEMENTS.keys()))
    def test_ksi_statement_exact_match(self, data_loader, ksi_id):
        """Verify KSI statement matches authoritative source EXACTLY - tests all 72 KSIs"""
        ksi = data_loader.get_ksi(ksi_id)
        expected_statement = KSI_STATEMENTS[ksi_id]
        
        assert ksi is not None, f"{ksi_id} not found in loaded data"
        assert 'id' in ksi, f"{ksi_id} missing 'id' field"
        # Note: Some KSIs (especially retired ones) may not have 'name' field in authoritative source
        # This is acceptable as long as they have id and statement
        assert 'statement' in ksi, f"{ksi_id} missing 'statement' field"
        
        # For retired KSIs, statement may be empty
        actual_statement = ksi['statement']
        if expected_statement == "":
            assert actual_statement == "", \
                f"{ksi_id} is retired but has non-empty statement: {actual_statement}"
        else:
            assert actual_statement == expected_statement, \
                f"{ksi_id} statement mismatch:\n" \
                f"  Expected: {expected_statement}\n" \
                f"  Actual:   {actual_statement}"


class TestAllFRRsLoaded:
    """Test that MCP server correctly loads ALL 199 FRR requirements with exact content"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    def test_all_frr_families_present(self, data_loader):
        """Verify all 10 FRR families are loaded with correct counts"""
        all_requirements = data_loader.search_controls("FRR-")
        frr_data = [r for r in all_requirements if r.get('id', '').startswith('FRR-')]
        
        loaded_frr_ids = {frr['id'] for frr in frr_data}
        expected_frr_ids = set(FRR_STATEMENTS.keys())
        
        missing = expected_frr_ids - loaded_frr_ids
        extra = loaded_frr_ids - expected_frr_ids
        
        assert len(missing) == 0, f"Missing FRRs: {sorted(missing)}"
        assert len(extra) == 0, f"Unexpected FRRs: {sorted(extra)}"
        
        # Count by family
        family_counts = {}
        for frr in frr_data:
            parts = frr['id'].split('-')
            if len(parts) >= 2:
                family = parts[1]
                family_counts[family] = family_counts.get(family, 0) + 1
        
        # Expected FRR families
        expected_families = ['ADS', 'CCM', 'FSI', 'ICP', 'MAS', 'PVA', 'RSC', 'SCN', 'UCM', 'VDR']
        
        for family in expected_families:
            assert family in family_counts, f"FRR family {family} not loaded"
            assert family_counts[family] > 0, f"FRR family {family} has no requirements"
    
    @pytest.mark.parametrize("frr_id", list(FRR_STATEMENTS.keys()))
    def test_frr_statement_exact_match(self, data_loader, frr_id):
        """Verify FRR statement matches authoritative source EXACTLY - tests all 199 FRRs"""
        frr = data_loader.get_control(frr_id)
        expected_statement = FRR_STATEMENTS[frr_id]
        
        assert frr is not None, f"{frr_id} not found in loaded data"
        assert 'id' in frr, f"{frr_id} missing 'id' field"
        assert frr['id'] == frr_id, f"{frr_id} ID mismatch"
        # Note: Some FRRs may not have 'name' field in authoritative source
        # This is acceptable as long as they have id and statement
        assert 'statement' in frr, f"{frr_id} missing 'statement' field"
        
        actual_statement = frr['statement']
        assert actual_statement == expected_statement, \
            f"{frr_id} statement mismatch:\n" \
            f"  Expected: {expected_statement}\n" \
            f"  Actual:   {actual_statement}"


class TestRequirementAccuracy:
    """Verify critical requirements that were previously misunderstood"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    # Test critical KSI statements that were previously misunderstood
    @pytest.mark.parametrize("ksi_id,expected_statement", [
        ("KSI-PIY-01", "Use authoritative sources to automatically maintain real-time inventories of all information resources."),
        ("KSI-PIY-02", "Document the security objectives and requirements for each information resource or set of information resources."),
        ("KSI-SVC-01", "Implement improvements based on persistent evaluation of information resources for opportunities to improve security."),
        ("KSI-SVC-06", "Automate management, protection, and regular rotation of digital keys, certificates, and other secrets."),
    ])
    def test_critical_ksi_statements(self, data_loader, ksi_id, expected_statement):
        """Verify critical KSI statements that were previously misunderstood match exactly"""
        ksi = data_loader.get_ksi(ksi_id)
        
        assert ksi is not None, f"{ksi_id} not found"
        assert ksi['statement'] == expected_statement, \
            f"{ksi_id} statement mismatch:\n" \
            f"  Expected: {expected_statement}\n" \
            f"  Got:      {ksi['statement']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
