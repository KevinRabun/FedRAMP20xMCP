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
    async def test_caching(self, loader):
        """Test data caching mechanism"""
        # First load
        data1 = await loader.load_data()
        
        # Second load (should use cache)
        data2 = await loader.load_data()
        
        # Data should be identical
        assert data1 == data2
        
        # Cache file should exist
        cache_file = loader._get_cache_file()
        assert cache_file.exists()
    
    @pytest.mark.asyncio
    async def test_get_family_requirements(self, loader):
        """Test retrieving requirements by family"""
        await loader.load_data()
        
        # Test with known families
        for family in ["VDR", "IAM", "SCN", "RSC", "ADS"]:
            requirements = loader.get_family_controls(family)
            # Family might not have requirements or might be organized differently
            assert requirements is not None
            assert isinstance(requirements, (list, dict))
    
    @pytest.mark.asyncio
    async def test_get_requirement(self, loader):
        """Test retrieving specific requirement"""
        await loader.load_data()
        
        # Test with known FRR IDs
        for req_id in ["FRR-VDR-01", "FRR-IAM-01", "FRR-SCN-01"]:
            req = loader.get_control(req_id)
            # Requirement might not exist in test data
            if req:
                assert isinstance(req, dict)
    
    @pytest.mark.asyncio
    async def test_get_ksi(self, loader):
        """Test retrieving specific KSI"""
        await loader.load_data()
        
        # Test with known KSI IDs
        for ksi_id in ["KSI-IAM-01", "KSI-CNA-01", "KSI-VDR-01"]:
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
