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
        """Verify the CR26 KSI set is loaded: 46 KSIs across 10 families"""
        ksi_data = data_loader.list_all_ksi()
        loaded_ksi_ids = {ksi['id'] for ksi in ksi_data}
        
        # CR26 (2026.10.13.01) defines exactly 46 KSIs in 10 families
        assert len(ksi_data) == 46, f"Expected 46 KSIs, got {len(ksi_data)}"
        families = {i.split('-')[1] for i in loaded_ksi_ids}
        assert families == {"CED", "CMT", "CNA", "IAM", "INR", "MLA", "PIY", "RPL", "SCR", "SVC"}
        assert not any(i.startswith(("KSI-AFR", "KSI-TPR", "KSI-VDR")) for i in loaded_ksi_ids)
        
        # Verify all have required fields
        for ksi in ksi_data:
            assert 'id' in ksi, f"KSI missing 'id' field: {ksi}"
    
    def test_ksi_statements_loaded(self, data_loader):
        """Verify all KSI statements are loaded from authoritative source"""
        ksi_data = data_loader.list_all_ksi()
        
        for ksi in ksi_data:
            ksi_id = ksi['id']
            assert 'id' in ksi, f"{ksi_id} missing 'id' field"
            
            # CR26: a KSI has a top-level 'statement' or only class-specific
            # statements under 'varies_by_class' (some have neither, see below)
            has_statement = 'statement' in ksi and ksi['statement']
            has_varies = 'varies_by_class' in ksi and ksi['varies_by_class']
            
            if not (has_statement or has_varies):
                # A few CR26 KSIs carry no statement text at all (name and controls only)
                assert ksi.get('name'), f"{ksi_id} has neither statement nor name"
                continue
            
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
        # CR26 rules have IDs like VDR-CSO-DET, stored in families by the first segment
        families = list(data_loader._data_cache["families"].keys())
        
        # The 17 CR26 FRR families (ADS->CDS, FSI->AFC, UCM->CMU, PVA->IVV, ICP->IEC, RSC->SCG)
        expected_families = ['AFC', 'AGU', 'CCM', 'CDS', 'CMU', 'CPO', 'FRC', 'IEC', 'IVV',
                             'MAS', 'MKT', 'REC', 'SCG', 'SCN', 'SDR', 'VDR', 'VER']
        
        for family in expected_families:
            assert family in families, f"FRR family {family} not loaded. Found: {families}"
    
    def test_frr_statements_loaded(self, data_loader):
        """Verify FRR statements are loaded from authoritative source"""
        # Get requirements that belong to FRR families
        frr_families = ['AFC', 'AGU', 'CCM', 'CDS', 'CMU', 'CPO', 'FRC', 'IEC', 'IVV',
                        'MAS', 'MKT', 'REC', 'SCG', 'SCN', 'SDR', 'VDR', 'VER']
        frr_data = []
        
        for family in frr_families:
            frr_data.extend(data_loader.get_family_controls(family))
        
        assert len(frr_data) == 245, f"Expected 245 CR26 FRRs, got {len(frr_data)}"
        
        for frr in frr_data:
            frr_id = frr['id']
            assert 'id' in frr, f"{frr_id} missing 'id' field"
            
            # CR26 rules have a top-level 'statement' or only class-specific
            # statements under 'varies_by_class'
            has_statement = 'statement' in frr and frr['statement']
            has_varies = 'varies_by_class' in frr and frr['varies_by_class']
            
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
        # CR26 statement text: "Information resources are persistently evaluated for
        # opportunities to improve security and those improvements are persistently made."
        ("KSI-SVC-EIS", "persistently evaluated for opportunities to improve security"),
        # KSI-SVC-ASM (fka KSI-SVC-06) - automating secret management
        ("KSI-SVC-ASM", "management, protection, and regular rotation of digital keys"),
    ])
    def test_critical_ksi_statements(self, data_loader, ksi_id, expected_statement_fragment):
        """Verify critical KSI statements contain expected content"""
        ksi = data_loader.get_ksi(ksi_id)
        
        assert ksi is not None, f"{ksi_id} not found"
        
        # Get statement (either direct or from varies_by_class)
        statement = ksi.get('statement', '')
        if not statement and ksi.get('varies_by_class'):
            statement = ' '.join(v.get('statement', '') for v in ksi['varies_by_class'].values())
        
        assert expected_statement_fragment.lower() in statement.lower(), \
            f"{ksi_id} statement doesn't contain expected fragment:\n" \
            f"  Expected fragment: {expected_statement_fragment}\n" \
            f"  Got:      {statement}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
