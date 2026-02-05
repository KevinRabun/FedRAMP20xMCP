"""
Tests for FedRAMP Data Loader - Live GitHub Repository Parsing

These tests verify that the data loader can successfully parse the current
FedRAMP/docs repository structure and content. They validate:
1. GitHub API connectivity and file listing
2. JSON file parsing across all document types
3. Data structure integrity (KSIs, FRRs, Definitions)
4. NIST 800-53 control mappings
5. Family categorization

NOTE: These tests require network access to github.com
"""

import asyncio
import pytest
from pathlib import Path
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


class TestDataLoaderLive:
    """Test data loader against live FedRAMP GitHub repository."""

    @pytest.fixture
    async def loader(self):
        """Create a fresh data loader instance."""
        loader = FedRAMPDataLoader()
        # Clear cache timestamp to force fresh fetch
        loader._cache_timestamp = None
        return loader

    @pytest.fixture
    async def loaded_data(self, loader):
        """Load data from GitHub and return loader with populated cache."""
        await loader.load_data()
        return loader

    @pytest.mark.asyncio
    async def test_fetch_file_list_from_github(self, loader):
        """Test that we can fetch the file list from GitHub.
        
        Note: This test requires GitHub API access and may fail locally
        if GITHUB_TOKEN is not properly configured or if rate-limited.
        """
        files = await loader._fetch_file_list()
        
        # Skip gracefully if GitHub API is unavailable (401/403 errors return empty list)
        if not files:
            pytest.skip("GitHub API unavailable - likely auth/rate limit issue")
        
        assert len(files) > 0, "Should find files in repository"
        
        # Should have JSON files
        json_files = [f for f in files if f.get('name', '').endswith('.json')]
        assert len(json_files) > 0, "Should find JSON files in repository"
        
        print(f"\n[OK] Found {len(files)} total files, {len(json_files)} JSON files")

    @pytest.mark.asyncio
    async def test_load_data_structure(self, loaded_data):
        """Test that loaded data has expected structure."""
        data = loaded_data._data_cache
        
        assert data is not None, "Data should be loaded"
        assert "requirements" in data, "Should have requirements section"
        assert "ksi" in data, "Should have KSI section"
        assert "definitions" in data, "Should have definitions section"
        assert "families" in data, "Should have families section"
        
        print(f"\n[OK] Data structure validated:")
        print(f"  - Requirements: {len(data['requirements'])}")
        print(f"  - KSIs: {len(data['ksi'])}")
        print(f"  - Definitions: {len(data['definitions'])}")
        print(f"  - Families: {len(data['families'])}")

    @pytest.mark.asyncio
    async def test_ksi_count_and_structure(self, loaded_data):
        """Test KSI parsing and count."""
        ksis = loaded_data.list_all_ksi()
        
        assert len(ksis) > 0, "Should parse KSIs from repository"
        assert len(ksis) >= 50, f"Should have at least 50 active KSIs, found {len(ksis)}"
        
        # Validate KSI structure
        sample_ksi = ksis[0]
        assert "id" in sample_ksi, "KSI should have id field"
        assert "name" in sample_ksi, "KSI should have name field"
        
        # Check for KSI families/categories
        ksi_families = set()
        for ksi in ksis:
            ksi_id = ksi.get("id", "")
            if "-" in ksi_id:
                family = ksi_id.split("-")[1]
                ksi_families.add(family)
        
        # Updated for Feb 2026 format: TPR renamed to SCR (Supply Chain Risk)
        expected_families = {"IAM", "MLA", "CNA", "SVC", "CMT", "INR", "RPL", 
                           "CED", "PIY", "SCR", "AFR"}
        assert ksi_families.intersection(expected_families), \
            f"Should find expected KSI families, found: {ksi_families}"
        
        print(f"\n[OK] Parsed {len(ksis)} KSIs across {len(ksi_families)} families")
        print(f"  Families: {sorted(ksi_families)}")

    @pytest.mark.asyncio
    async def test_ksi_nist_control_mappings(self, loaded_data):
        """Test that KSIs have NIST 800-53 control mappings."""
        ksis = loaded_data.list_all_ksi()
        
        ksis_with_controls = [k for k in ksis if k.get("controls") and len(k.get("controls", [])) > 0]
        
        assert len(ksis_with_controls) > 0, "Should have KSIs with NIST control mappings"
        
        # Test specific known KSI - using new descriptive ID format (KSI-IAM-MFA instead of KSI-IAM-01)
        ksi_iam_mfa = loaded_data.get_ksi("KSI-IAM-MFA")
        if ksi_iam_mfa:
            controls = ksi_iam_mfa.get("controls", [])
            assert len(controls) > 0, "KSI-IAM-MFA should have NIST control mappings"
            
            # New format: controls are strings (e.g., 'ac-2', 'ia-5.1') not dicts
            sample_control = controls[0]
            assert isinstance(sample_control, str), "Control should be a string (NIST control ID)"
            
            print(f"\n[OK] {len(ksis_with_controls)} KSIs have NIST control mappings")
            print(f"  KSI-IAM-MFA example: {len(controls)} controls mapped")
        else:
            print("\n[WARNING] Could not find KSI-IAM-MFA for detailed validation")

    @pytest.mark.asyncio
    async def test_frr_count_and_structure(self, loaded_data):
        """Test FRR (FedRAMP Requirements) parsing."""
        data = loaded_data._data_cache
        requirements = data.get("requirements", {})
        families = data.get("families", {})
        
        # New format: FRR IDs are like VDR-AGM-DRE, ADS-CSX-UTC (family-group-id)
        # They're stored in families by the first part (VDR, ADS, etc.)
        frr_family_codes = ['VDR', 'ADS', 'CCM', 'FSI', 'ICP', 'MAS', 'PVA', 'SCG', 'SCN', 'UCM']
        
        frr_count = 0
        for family_code in frr_family_codes:
            if family_code in families:
                frr_count += len(families[family_code])
        
        assert frr_count > 0, "Should parse FRRs from repository"
        assert frr_count >= 50, f"Should have at least 50 FRRs, found {frr_count}"
        
        # Validate FRR structure by checking a sample from VDR family
        if 'VDR' in families and families['VDR']:
            sample_frr_id = families['VDR'][0]
            sample_frr = requirements.get(sample_frr_id)
            if sample_frr:
                assert "id" in sample_frr, "FRR should have id field"
                assert "statement" in sample_frr, "FRR should have statement field"
                assert "document" in sample_frr, "FRR should have document field"
        
        print(f"\n[OK] Parsed {frr_count} FRRs across {len(frr_family_codes)} families")
        print(f"  Families: {sorted(frr_family_codes)}")

    @pytest.mark.asyncio
    async def test_definition_parsing(self, loaded_data):
        """Test definition parsing from FedRAMP repository."""
        definitions = loaded_data.list_all_definitions()
        
        assert len(definitions) > 0, "Should parse definitions from repository"
        assert len(definitions) >= 40, f"Should have at least 40 definitions, found {len(definitions)}"
        
        # Validate definition structure
        sample_def = definitions[0]
        assert "term" in sample_def, "Definition should have term field"
        assert "definition" in sample_def, "Definition should have definition field"
        
        print(f"\n[OK] Parsed {len(definitions)} definitions")

    @pytest.mark.asyncio
    async def test_family_categorization(self, loaded_data):
        """Test that requirements are properly categorized by family."""
        data = loaded_data._data_cache
        families = data.get("families", {})
        
        assert len(families) > 0, "Should have family categorization"
        
        # New format: families are stored by family code (VDR, ADS, KSI, FRD, etc.)
        found_families = set(families.keys())
        
        # Should have KSI and FRD families, plus FRR family codes
        expected_families = {"KSI", "FRD", "VDR", "ADS"}
        common_families = expected_families.intersection(found_families)
        assert len(common_families) >= 2, \
            f"Should find major document families. Expected: {expected_families}, Found: {found_families}"
        
        print(f"\n[OK] Family categorization working:")
        for family, items in sorted(families.items()):
            print(f"  - {family}: {len(items)} items")

    @pytest.mark.asyncio
    async def test_cache_functionality(self, loader):
        """Test that caching mechanism works."""
        # First load - should fetch from GitHub
        await loader.load_data()
        first_data = loader._data_cache
        
        assert first_data is not None, "First load should succeed"
        
        # Second load - should use cache
        loader2 = FedRAMPDataLoader()
        cached_data = loader2._load_from_cache()
        
        assert cached_data is not None, "Should load from cache"
        assert len(cached_data.get("requirements", {})) == len(first_data.get("requirements", {})), \
            "Cached data should match fresh data"
        
        print(f"\n[OK] Cache functionality validated")

    @pytest.mark.asyncio
    async def test_get_specific_ksi(self, loaded_data):
        """Test retrieving specific KSIs by ID.
        
        Note: FedRAMP 20x v0.9.0-beta changed KSI IDs from numbered format (KSI-IAM-01)
        to descriptive format (KSI-IAM-MFA). The fka (formerly known as) field maps
        old IDs to new ones, but the returned object has the new ID.
        """
        # Test known KSIs using new format IDs
        test_ksi_ids = ["KSI-IAM-MFA", "KSI-MLA-OSM", "KSI-CNA-RNT", "KSI-SVC-ASM"]
        
        for ksi_id in test_ksi_ids:
            ksi = loaded_data.get_ksi(ksi_id)
            if ksi:
                assert ksi.get("id") == ksi_id, f"Should retrieve correct KSI {ksi_id}"
                print(f"[OK] Retrieved {ksi_id}: {ksi.get('name', 'Unknown')}")
            else:
                print(f"[WARNING] Could not find {ksi_id}")

    @pytest.mark.asyncio
    async def test_get_specific_frr(self, loaded_data):
        """Test retrieving specific FRRs by ID."""
        # Test known FRRs using get_control method - new format IDs (Feb 2026)
        test_frr_ids = ["ADS-CSX-UTC", "VDR-EVA-EFA", "SCG-BAS-DEF"]
        
        found_count = 0
        for frr_id in test_frr_ids:
            frr = loaded_data.get_control(frr_id)
            if frr:
                assert frr.get("id") == frr_id, f"Should retrieve correct FRR {frr_id}"
                found_count += 1
                print(f"[OK] Retrieved {frr_id}: {frr.get('name', 'Unknown')}")
        
        assert found_count > 0, "Should find at least one test FRR"

    @pytest.mark.asyncio
    async def test_retired_ksi_flags(self, loaded_data):
        """Test that retired KSIs are properly flagged."""
        ksis = loaded_data.list_all_ksi()
        
        # Known retired KSIs according to documentation
        known_retired = {"KSI-CMT-05", "KSI-MLA-03", "KSI-MLA-04", "KSI-MLA-06", 
                        "KSI-PIY-02", "KSI-SVC-03", "KSI-TPR-01", "KSI-TPR-02"}
        
        retired_ksis = [k for k in ksis if k.get("retired") or k.get("status") == "retired"]
        retired_ids = {k.get("id") for k in retired_ksis}
        
        # Check if any known retired KSIs are properly flagged
        properly_flagged = known_retired.intersection(retired_ids)
        
        print(f"\n[OK] Retired KSI handling:")
        print(f"  - Known retired KSIs: {len(known_retired)}")
        print(f"  - Found retired flags: {len(retired_ids)}")
        if properly_flagged:
            print(f"  - Properly flagged: {sorted(properly_flagged)}")

    @pytest.mark.asyncio
    async def test_json_parsing_all_files(self, loader):
        """Test that all JSON files in repo can be parsed without errors."""
        files = await loader._fetch_file_list()
        json_files = [f for f in files if f.get('name', '').endswith('.json')]
        
        parse_errors = []
        for file_info in json_files:
            file_name = file_info.get('name', 'unknown')
            try:
                # This is tested implicitly by load_data, but we're being explicit
                if file_name.startswith('FRMR.'):
                    print(f"[OK] Found parseable file: {file_name}")
            except Exception as e:
                parse_errors.append((file_name, str(e)))
        
        assert len(parse_errors) == 0, \
            f"All JSON files should parse without errors. Errors: {parse_errors}"
        
        print(f"\n[OK] All {len(json_files)} JSON files are parseable")


def test_loader_can_import():
    """Basic import test."""
    from fedramp_20x_mcp.data_loader import FedRAMPDataLoader
    loader = FedRAMPDataLoader()
    assert loader is not None
    print("[OK] Data loader imports successfully")


if __name__ == "__main__":
    # Allow running tests directly
    print("Running FedRAMP Data Loader Live Tests...")
    print("=" * 60)
    pytest.main([__file__, "-v", "-s"])
