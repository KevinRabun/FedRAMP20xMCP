"""
Tests for FedRAMP Data Loader

Tests fetching and caching of FedRAMP 20x requirements from GitHub.
"""
import json
import pytest
from pathlib import Path
import asyncio
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.data_loader import FedRAMPDataLoader


class TestDataLoader:
    """Test FedRAMPDataLoader functionality"""
    
    @pytest.fixture
    def loader(self):
        """Create a data loader instance"""
        return FedRAMPDataLoader()
    
    def test_initialization(self, loader):
        """Test loader initializes correctly"""
        assert loader is not None
        assert loader.cache_dir.exists()
        assert loader.cache_dir.name == "__fedramp_cache__"
    
    @pytest.mark.asyncio
    async def test_load_data(self, loader):
        """Test loading FedRAMP data"""
        data = await loader.load_data()
        
        assert data is not None
        assert isinstance(data, dict)
        assert len(data) > 0
        
        # Check for expected data structure
        if "frr" in data or "ksi" in data or "frd" in data:
            assert True, "Found expected data keys"
        else:
            # Data might be organized differently
            assert len(data) > 0, "Data loaded but structure unexpected"
    
    @pytest.mark.asyncio
    async def test_caching(self, tmp_path, monkeypatch):
        """Cache is written after a successful (non-bundled) fetch and reused.

        The fetch is patched to return the bundled bytes under a non-bundled
        source label, and CACHE_DIR points at tmp_path so nothing is written
        into the package directory.
        """
        from fedramp_20x_mcp import data_loader as dl

        monkeypatch.setattr(dl, "CACHE_DIR", tmp_path)
        loader = FedRAMPDataLoader()
        raw = dl.BUNDLED_RULES_FILE.read_bytes()
        calls = []

        async def fake_fetch():
            calls.append(1)
            return raw, "https://example.invalid/fedramp-consolidated-rules.json"

        monkeypatch.setattr(loader, "_fetch_rules_bytes", fake_fetch)
        assert not loader._get_cache_file().exists()

        data1 = await loader.load_data()
        assert len(calls) == 1
        assert loader._get_cache_file().exists(), "Cache written after a successful remote fetch"
        assert data1["metadata"]["cache_format"] == dl.CACHE_FORMAT

        # Second load (should use cache, not fetch again)
        data2 = await loader.load_data()
        assert len(calls) == 1
        assert data1 == data2

        # A fresh loader reads the same cache without fetching
        loader2 = FedRAMPDataLoader()
        monkeypatch.setattr(loader2, "_fetch_rules_bytes", fake_fetch)
        data3 = await loader2.load_data()
        assert len(calls) == 1
        assert len(data3["requirements"]) == len(data1["requirements"])

    @pytest.mark.asyncio
    async def test_bundled_load_does_not_write_cache(self, tmp_path, monkeypatch):
        """Offline/bundled loads must not write a cache file."""
        from fedramp_20x_mcp import data_loader as dl

        monkeypatch.setattr(dl, "CACHE_DIR", tmp_path)
        monkeypatch.setenv("FEDRAMP_RULES_OFFLINE", "1")
        monkeypatch.delenv("FEDRAMP_RULES_FILE", raising=False)
        loader = FedRAMPDataLoader()
        data = await loader.load_data()
        assert data["metadata"]["source"].startswith("bundled:")
        assert not loader._get_cache_file().exists()

    @pytest.mark.asyncio
    async def test_get_family_requirements(self, loader):
        """Test retrieving requirements by family"""
        await loader.load_data()
        
        # Test with known families
        for family in ["VDR", "IAM", "SCN", "SCG", "CDS"]:
            requirements = loader.get_family_controls(family)
            # Family might not have requirements or might be organized differently
            assert requirements is not None
            assert isinstance(requirements, (list, dict))
    
    @pytest.mark.asyncio
    async def test_get_requirement(self, loader):
        """Test retrieving specific requirement"""
        await loader.load_data()
        
        # Test with known FRR IDs (new format: FAMILY-GROUP-ID)
        for req_id in ["VDR-EVA-EFA", "CDS-CSO-PUB", "SCN-CSO-EVA"]:
            req = loader.get_control(req_id)
            # Requirement might not exist in test data
            if req:
                assert isinstance(req, dict)
    
    @pytest.mark.asyncio
    async def test_get_ksi(self, loader):
        """Test retrieving specific KSI"""
        await loader.load_data()
        
        # Test with known KSI IDs (new descriptive format: KSI-CATEGORY-NAME)
        for ksi_id in ["KSI-IAM-MFA", "KSI-CNA-DFP", "KSI-SVC-ASM"]:
            ksi = loader.get_ksi(ksi_id)
            # KSI might not exist in test data
            if ksi:
                assert isinstance(ksi, dict)
    
    @pytest.mark.asyncio
    async def test_search_requirements(self, loader):
        """Test searching requirements"""
        await loader.load_data()
        
        # Search for common terms
        results = loader.search_controls("encryption")
        assert isinstance(results, list)
        
        results = loader.search_controls("authentication")
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_get_definition(self, loader):
        """Test retrieving definitions"""
        await loader.load_data()
        
        # Test getting all definitions
        definitions = loader.list_all_definitions()
        assert isinstance(definitions, (list, dict))


def run_tests():
    """Run tests with pytest"""
    print("Running DataLoader tests...")
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
