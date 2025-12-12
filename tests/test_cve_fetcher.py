"""
Tests for CVE Fetcher Module

Tests vulnerability checking functionality using GitHub Advisory Database.
"""
import pytest
import asyncio
import sys
import os
import json

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.cve_fetcher import CVEFetcher
from fedramp_20x_mcp.tools.security import (
    check_package_vulnerabilities_impl,
    scan_dependency_file_impl
)


class TestCVEFetcher:
    """Test CVE fetching functionality"""
    
    def test_github_token(self):
        """Test GitHub token availability"""
        token = os.environ.get("GITHUB_TOKEN")
        # Token is optional but helpful
        if token:
            assert isinstance(token, str)
            assert len(token) > 0
    
    def test_cve_fetcher_initialization(self):
        """Test CVEFetcher class initialization"""
        fetcher = CVEFetcher()
        assert fetcher is not None
        assert fetcher.cache_dir.exists()
    
    @pytest.mark.asyncio
    async def test_check_package_no_vulnerabilities(self):
        """Test checking a safe package"""
        # Use a well-maintained package unlikely to have vulnerabilities
        result = await check_package_vulnerabilities_impl(
            package_name="requests",
            ecosystem="pypi",
            version="2.31.0",
            github_token=os.environ.get("GITHUB_TOKEN")
        )
        
        assert result is not None
        assert isinstance(result, str)
        data = json.loads(result)
        assert "package" in data
        assert "ecosystem" in data
        assert "vulnerabilities_found" in data
    
    @pytest.mark.asyncio
    async def test_check_package_with_version(self):
        """Test checking specific package version"""
        # Test with a known package
        result = await check_package_vulnerabilities_impl(
            package_name="flask",
            ecosystem="pypi",
            version=None,  # Check all versions
            github_token=os.environ.get("GITHUB_TOKEN")
        )
        
        assert result is not None
        assert isinstance(result, str)
        data = json.loads(result)
        assert data["package"] == "flask"
        assert data["ecosystem"] == "pypi"
    
    @pytest.mark.asyncio
    async def test_scan_requirements_txt(self):
        """Test scanning a requirements.txt file"""
        # Create a temporary requirements file
        test_req = """requests==2.31.0
flask==2.3.0
pytest==7.4.0
"""
        result = await scan_dependency_file_impl(
            file_content=test_req,
            file_type="requirements.txt",
            github_token=os.environ.get("GITHUB_TOKEN")
        )
        
        assert result is not None
        assert isinstance(result, str)
        data = json.loads(result)
        assert "file_type" in data
        assert "packages_scanned" in data
        assert "vulnerable_packages" in data
        
        # Should have scanned 3 packages
        assert data["packages_scanned"] >= 3
    
    @pytest.mark.asyncio
    async def test_scan_package_json(self):
        """Test scanning a package.json file"""
        # Create a temporary package.json file
        test_pkg = """{
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21"
  }
}"""
        result = await scan_dependency_file_impl(
            file_content=test_pkg,
            file_type="package.json",
            github_token=os.environ.get("GITHUB_TOKEN")
        )
        
        assert result is not None
        assert isinstance(result, str)
        data = json.loads(result)
        assert "packages_scanned" in data
    
    @pytest.mark.asyncio
    async def test_invalid_ecosystem(self):
        """Test handling of invalid ecosystem"""
        result = await check_package_vulnerabilities_impl(
            package_name="test",
            ecosystem="invalid",
            version="1.0.0",
            github_token=os.environ.get("GITHUB_TOKEN")
        )
        
        # Should handle gracefully
        assert result is not None
        assert isinstance(result, str)
        data = json.loads(result)
        assert "status" in data
    
    @pytest.mark.asyncio
    async def test_malformed_package_name(self):
        """Test handling of malformed package names"""
        result = await check_package_vulnerabilities_impl(
            package_name="",
            ecosystem="pypi",
            version="1.0.0",
            github_token=os.environ.get("GITHUB_TOKEN")
        )
        
        # Should handle gracefully
        assert result is not None
        assert isinstance(result, str)


def run_tests():
    """Run tests with pytest"""
    print("Running CVE Fetcher tests...")
    print("Note: GitHub token is required for full functionality")
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("WARNING: GITHUB_TOKEN not set - some tests may be limited")
    
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
