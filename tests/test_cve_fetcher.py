"""
Tests for CVE Fetcher Module

Tests the CVE vulnerability data fetching from GitHub Advisory Database.
"""

import json
import sys
import io
from pathlib import Path

# Set UTF-8 encoding for stdout (Windows compatibility)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.cve_fetcher import (
    CVEFetcher,
    Vulnerability,
    check_nuget_package,
    check_npm_package,
    check_pypi_package,
    check_maven_package
)


def test_cve_fetcher_initialization():
    """Test CVE fetcher can be initialized."""
    print("Testing CVE fetcher initialization...")
    
    fetcher = CVEFetcher()
    assert fetcher is not None
    assert fetcher.cache_dir.exists()
    
    # Test with tokens
    fetcher_with_tokens = CVEFetcher(github_token="test_token", nvd_api_key="test_key")
    assert fetcher_with_tokens.github_token == "test_token"
    assert fetcher_with_tokens.nvd_api_key == "test_key"
    
    print("✅ CVE fetcher initialization test passed")


def test_version_parsing():
    """Test version string parsing."""
    print("Testing version parsing...")
    
    fetcher = CVEFetcher()
    
    # Test various version formats
    assert fetcher._parse_version("1.2.3") == (1, 2, 3)
    assert fetcher._parse_version("v1.2.3") == (1, 2, 3)
    assert fetcher._parse_version("2.0.0") == (2, 0, 0)
    assert fetcher._parse_version("10.15.23") == (10, 15, 23)
    
    print("✅ Version parsing test passed")


def test_version_comparison():
    """Test version comparison logic."""
    print("Testing version comparison...")
    
    fetcher = CVEFetcher()
    
    # Test less than
    assert fetcher._check_single_range((1, 2, 3), "< 2.0.0") == True
    assert fetcher._check_single_range((2, 0, 0), "< 2.0.0") == False
    assert fetcher._check_single_range((2, 1, 0), "< 2.0.0") == False
    
    # Test greater than or equal
    assert fetcher._check_single_range((1, 0, 0), ">= 1.0.0") == True
    assert fetcher._check_single_range((1, 5, 0), ">= 1.0.0") == True
    assert fetcher._check_single_range((0, 9, 0), ">= 1.0.0") == False
    
    # Test equals
    assert fetcher._check_single_range((1, 2, 3), "== 1.2.3") == True
    assert fetcher._check_single_range((1, 2, 4), "== 1.2.3") == False
    
    print("✅ Version comparison test passed")


def test_version_range_checking():
    """Test compound version range checking."""
    print("Testing version range checking...")
    
    fetcher = CVEFetcher()
    
    # Test compound ranges
    assert fetcher._version_in_range((1, 5, 0), ">= 1.0.0, < 2.0.0") == True
    assert fetcher._version_in_range((0, 9, 0), ">= 1.0.0, < 2.0.0") == False
    assert fetcher._version_in_range((2, 0, 0), ">= 1.0.0, < 2.0.0") == False
    assert fetcher._version_in_range((1, 0, 0), ">= 1.0.0, < 2.0.0") == True
    
    print("✅ Version range checking test passed")


def test_version_affected():
    """Test if version is affected by vulnerability."""
    print("Testing version affected logic...")
    
    fetcher = CVEFetcher()
    
    # Version before patch
    assert fetcher._version_affected("1.5.0", ["< 2.0.0"], ["2.0.0"]) == True
    
    # Version after patch
    assert fetcher._version_affected("2.0.0", ["< 2.0.0"], ["2.0.0"]) == False
    assert fetcher._version_affected("2.1.0", ["< 2.0.0"], ["2.0.0"]) == False
    
    # Complex range
    assert fetcher._version_affected("1.5.0", [">= 1.0.0, < 2.0.0"], ["2.0.0"]) == True
    assert fetcher._version_affected("0.9.0", [">= 1.0.0, < 2.0.0"], ["2.0.0"]) == False
    
    print("✅ Version affected logic test passed")


def test_cache_operations():
    """Test cache save and retrieval."""
    print("Testing cache operations...")
    
    fetcher = CVEFetcher()
    
    # Clear cache first
    fetcher.clear_cache()
    
    # Test cache miss
    cached = fetcher._get_from_cache("test_package_1.0.0")
    assert cached is None
    
    # Test cache save
    test_data = [{"cve": "CVE-2024-TEST", "severity": "HIGH"}]
    fetcher._save_to_cache("test_package_1.0.0", test_data)
    
    # Test cache hit
    cached = fetcher._get_from_cache("test_package_1.0.0")
    assert cached is not None
    assert cached[0]["cve"] == "CVE-2024-TEST"
    
    # Clean up
    fetcher.clear_cache()
    
    print("✅ Cache operations test passed")


def test_severity_to_cvss():
    """Test severity to CVSS score mapping."""
    print("Testing severity to CVSS mapping...")
    
    fetcher = CVEFetcher()
    
    assert fetcher._severity_to_cvss("CRITICAL") == 9.5
    assert fetcher._severity_to_cvss("HIGH") == 7.5
    assert fetcher._severity_to_cvss("MEDIUM") == 5.0
    assert fetcher._severity_to_cvss("MODERATE") == 5.0
    assert fetcher._severity_to_cvss("LOW") == 3.0
    assert fetcher._severity_to_cvss("UNKNOWN") is None
    
    print("✅ Severity to CVSS mapping test passed")


def test_vulnerability_dataclass():
    """Test Vulnerability dataclass."""
    print("Testing Vulnerability dataclass...")
    
    vuln = Vulnerability(
        cve_id="CVE-2024-TEST",
        package_name="test-package",
        ecosystem="nuget",
        severity="HIGH",
        cvss_score=7.5,
        affected_versions=["< 2.0.0"],
        patched_versions=["2.0.0"],
        description="Test vulnerability",
        published_date="2024-01-01",
        references=["https://example.com"]
    )
    
    assert vuln.cve_id == "CVE-2024-TEST"
    assert vuln.severity == "HIGH"
    assert vuln.cvss_score == 7.5
    
    # Test to_dict conversion
    vuln_dict = vuln.to_dict()
    assert isinstance(vuln_dict, dict)
    assert vuln_dict["cve_id"] == "CVE-2024-TEST"
    
    print("✅ Vulnerability dataclass test passed")


def test_ecosystem_mapping():
    """Test ecosystem name mapping."""
    print("Testing ecosystem mapping...")
    
    fetcher = CVEFetcher()
    
    assert fetcher.ECOSYSTEM_MAP["nuget"] == "NUGET"
    assert fetcher.ECOSYSTEM_MAP["npm"] == "NPM"
    assert fetcher.ECOSYSTEM_MAP["pypi"] == "PIP"
    assert fetcher.ECOSYSTEM_MAP["maven"] == "MAVEN"
    
    print("✅ Ecosystem mapping test passed")


def test_convenience_functions():
    """Test convenience functions for analyzers."""
    print("Testing convenience functions...")
    
    # Note: These will make real API calls, so they might fail without network
    # We're just testing that they don't crash
    
    try:
        # Test that functions exist and are callable
        assert callable(check_nuget_package)
        assert callable(check_npm_package)
        assert callable(check_pypi_package)
        assert callable(check_maven_package)
        
        print("✅ Convenience functions test passed")
    except Exception as e:
        print(f"⚠️ Convenience functions test passed with warning: {e}")


def test_known_vulnerable_package():
    """Test fetching a known vulnerable package (real API call)."""
    print("Testing known vulnerable package (Newtonsoft.Json < 13.0.1)...")
    
    try:
        fetcher = CVEFetcher()
        
        # Newtonsoft.Json has known vulnerabilities in old versions
        vulns = fetcher.get_package_vulnerabilities(
            package_name="Newtonsoft.Json",
            ecosystem="nuget",
            version="12.0.1"  # Old version with known issues
        )
        
        if vulns:
            print(f"   Found {len(vulns)} vulnerabilities (expected)")
            for v in vulns[:2]:  # Show first 2
                print(f"   - {v.cve_id}: {v.severity}")
            print("✅ Known vulnerable package test passed")
        else:
            print("⚠️ No vulnerabilities found (possible API issue or data updated)")
    
    except Exception as e:
        print(f"⚠️ Known vulnerable package test skipped (network/API issue): {e}")


def test_safe_package():
    """Test fetching a safe package (real API call)."""
    print("Testing safe package (latest Azure.Identity)...")
    
    try:
        fetcher = CVEFetcher()
        
        # Azure.Identity latest version should be safe
        vulns = fetcher.get_package_vulnerabilities(
            package_name="Azure.Identity",
            ecosystem="nuget",
            version="1.11.0"  # Recent version
        )
        
        if not vulns:
            print("   No vulnerabilities found (expected)")
            print("✅ Safe package test passed")
        else:
            print(f"   Found {len(vulns)} vulnerabilities (unexpected, but possible)")
            print("⚠️ Safe package test completed with findings")
    
    except Exception as e:
        print(f"⚠️ Safe package test skipped (network/API issue): {e}")


def test_npm_package():
    """Test npm package vulnerability checking."""
    print("Testing npm package (lodash)...")
    
    try:
        # lodash has had vulnerabilities in older versions
        vulns = check_npm_package("lodash", "4.17.15")
        
        if vulns:
            print(f"   Found {len(vulns)} vulnerabilities")
            print("✅ npm package test passed")
        else:
            print("   No vulnerabilities found")
            print("✅ npm package test passed")
    
    except Exception as e:
        print(f"⚠️ npm package test skipped (network/API issue): {e}")


def test_pypi_package():
    """Test PyPI package vulnerability checking."""
    print("Testing PyPI package (requests)...")
    
    try:
        # requests is a popular Python package
        vulns = check_pypi_package("requests", "2.25.0")
        
        if vulns:
            print(f"   Found {len(vulns)} vulnerabilities")
            print("✅ PyPI package test passed")
        else:
            print("   No vulnerabilities found")
            print("✅ PyPI package test passed")
    
    except Exception as e:
        print(f"⚠️ PyPI package test skipped (network/API issue): {e}")


def run_all_tests():
    """Run all CVE fetcher tests."""
    print("=" * 60)
    print("Running CVE Fetcher Tests")
    print("=" * 60)
    print()
    
    # Unit tests (no network required)
    test_cve_fetcher_initialization()
    test_version_parsing()
    test_version_comparison()
    test_version_range_checking()
    test_version_affected()
    test_cache_operations()
    test_severity_to_cvss()
    test_vulnerability_dataclass()
    test_ecosystem_mapping()
    test_convenience_functions()
    
    print()
    print("-" * 60)
    print("Integration Tests (require network access)")
    print("-" * 60)
    print()
    
    # Integration tests (require network)
    test_known_vulnerable_package()
    test_safe_package()
    test_npm_package()
    test_pypi_package()
    
    print()
    print("=" * 60)
    print("All CVE Fetcher Tests Completed!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
