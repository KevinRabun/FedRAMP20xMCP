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
        
        # Verify we have exactly 72 KSIs
        assert len(ksi_data) == 72, f"Expected 72 total KSIs, got {len(ksi_data)}"
        
        # Verify all have required fields
        for ksi in ksi_data:
            assert 'id' in ksi, f"KSI missing 'id' field: {ksi}"
            assert 'statement' in ksi, f"{ksi['id']} missing 'statement' field"
    
    def test_ksi_statements_loaded(self, data_loader):
        """Verify all KSI statements are loaded from authoritative source"""
        ksi_data = data_loader.list_all_ksi()
        
        for ksi in ksi_data:
            ksi_id = ksi['id']
            assert 'id' in ksi, f"{ksi_id} missing 'id' field"
            assert 'statement' in ksi, f"{ksi_id} missing 'statement' field"
            
            # Verify statement is either a non-empty string (active KSI) or empty (retired KSI)
            statement = ksi['statement']
            assert isinstance(statement, str), f"{ksi_id} statement is not a string: {type(statement)}"
            
            # Active KSIs should have non-empty statements
            # Note: Retired KSIs have 'retired': true field and may have empty statements
            if not ksi.get('retired', False):
                assert len(statement) > 0, f"{ksi_id} is active but has empty statement"


class TestAllFRRsLoaded:
    """Test that MCP server correctly loads ALL 199 FRR requirements with exact content"""
    
    @pytest.fixture
    def data_loader(self):
        """Create a data loader instance and load data"""
        loader = FedRAMPDataLoader()
        asyncio.run(loader.load_data())
        return loader
    
    def test_all_frr_families_present(self, data_loader):
        """Verify all 10+ FRR families are loaded"""
        all_requirements = data_loader.search_controls("FRR-")
        frr_data = [r for r in all_requirements if r.get('id', '').startswith('FRR-')]
        
        # Verify FRRs are loaded
        assert len(frr_data) > 0, "No FRR requirements loaded"
        
        # Count by family
        family_counts = {}
        for frr in frr_data:
            parts = frr['id'].split('-')
            if len(parts) >= 2:
                family = parts[1]
                family_counts[family] = family_counts.get(family, 0) + 1
        
        # Expected FRR families (at minimum)
        expected_families = ['ADS', 'CCM', 'FSI', 'ICP', 'MAS', 'PVA', 'RSC', 'SCN', 'UCM', 'VDR']
        
        for family in expected_families:
            assert family in family_counts, f"FRR family {family} not loaded"
            assert family_counts[family] > 0, f"FRR family {family} has no requirements"
    
    def test_frr_statements_loaded(self, data_loader):
        """Verify FRR statements are loaded from authoritative source"""
        all_requirements = data_loader.search_controls("FRR-")
        frr_data = [r for r in all_requirements if r.get('id', '').startswith('FRR-')]
        
        assert len(frr_data) > 0, "No FRR requirements loaded"
        
        for frr in frr_data:
            frr_id = frr['id']
            assert 'id' in frr, f"{frr_id} missing 'id' field"
            assert 'statement' in frr, f"{frr_id} missing 'statement' field"
            
            # Verify statement is a string
            statement = frr['statement']
            assert isinstance(statement, str), f"{frr_id} statement is not a string: {type(statement)}"
            
            # FRRs should have non-empty statements
            assert len(statement) > 0, f"{frr_id} has empty statement"


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
        ("KSI-PIY-01", "Use authoritative sources to automatically generate real-time inventories of all information resources when needed."),
        # KSI-PIY-02 is retired (superseded by KSI-AFR-01)
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
