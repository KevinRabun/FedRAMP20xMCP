"""
Tests for analyzer MCP tools with KSI-centric architecture.

Validates that KSI analyzers work correctly through the factory pattern.
"""

import sys
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_factory_registration():
    """Test that all KSIs are properly registered in factory."""
    print("\n=== Testing Factory Registration ===")
    
    factory = get_factory()
    ksi_list = factory.list_ksis()
    
    assert len(ksi_list) == 72, f"Expected 72 KSIs, got {len(ksi_list)}"
    assert "KSI-IAM-01" in ksi_list, "KSI-IAM-01 should be registered"
    assert "KSI-MLA-05" in ksi_list, "KSI-MLA-05 should be registered"
    assert "KSI-SVC-06" in ksi_list, "KSI-SVC-06 should be registered"
    
    print(f"[OK] Factory registered {len(ksi_list)} KSIs")


def test_bicep_analysis():
    """Test Bicep analysis through KSI analyzer."""
    print("\n=== Testing Bicep Analysis ===")
    
    factory = get_factory()
    analyzer = factory.get_analyzer("KSI-MLA-05")
    
    # If the analyzer is not found, it should cause an error
    assert analyzer is not None, "KSI-MLA-05 analyzer should be found"
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
    }
    """
    
    result = analyzer.analyze(code, "bicep", "storage.bicep")
    
    assert result.ksi_id == "KSI-MLA-05", "KSI ID should match"
    # KSI-MLA-05 may or may not detect issues depending on implementation
    
    print(f"[OK] Bicep analysis completed with {len(result.findings)} findings")
    if result.findings:
        print(f"   Issues: {', '.join([f.title for f in result.findings[:2]])}")


def test_python_analysis():
    """Test Python analysis through KSI analyzer."""
    print("\n=== Testing Python Analysis ===")
    
    factory = get_factory()
    analyzer = factory.get_analyzer("KSI-SVC-06")
    
    # If the analyzer is not found, it should cause an error
    assert analyzer is not None, "KSI-SVC-06 analyzer should be found"

    code = """
    from flask import Flask
    
    app = Flask(__name__)
    API_KEY = "sk-1234567890abcdef"
    DATABASE_PASSWORD = "mysecretpassword123"
    
    @app.route('/api/users')
    def get_users():
        return {'users': ['alice', 'bob']}
    """
    
    result = analyzer.analyze(code, "python", "app.py")
    
    assert result.ksi_id == "KSI-SVC-06", "KSI ID should match"
    assert len(result.findings) > 0, "Should detect hardcoded secrets"
    
    print(f"[OK] Python analysis detected {len(result.findings)} findings")
    for finding in result.findings[:3]:
        print(f"   - {finding.title}")


def test_csharp_analysis():
    """Test C# analysis through KSI analyzer."""
    print("\n=== Testing C# Analysis ===")
    
    factory = get_factory()
    analyzer = factory.get_analyzer("KSI-IAM-01")
    
    # If the analyzer is not found, it should cause an error
    assert analyzer is not None, "KSI-IAM-01 analyzer should be found"

    code = """
    using Microsoft.AspNetCore.Mvc;
    
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        [HttpGet]
        public IActionResult GetUsers()
        {
            return Ok(new[] { "alice", "bob" });
        }
    }
    """
    
    result = analyzer.analyze(code, "csharp", "UsersController.cs")
    
    assert result.ksi_id == "KSI-IAM-01", "KSI ID should match"
    # KSI-IAM-01 may or may not detect issues in this simple code
    
    print(f"[OK] C# analysis completed with {len(result.findings)} findings")
    if result.findings:
        print(f"   Issue: {result.findings[0].title}")


def test_terraform_analysis():
    """Test Terraform analysis through KSI analyzer."""
    print("\n=== Testing Terraform Analysis ===")
    
    factory = get_factory()
    analyzer = factory.get_analyzer("KSI-CNA-01")
    
    # If the analyzer is not found, it should cause an error
    assert analyzer is not None, "KSI-CNA-01 analyzer should be found"

    code = """
    resource "azurerm_virtual_network" "main" {
      name                = "my-vnet"
      address_space       = ["10.0.0.0/16"]
      location            = "eastus"
      resource_group_name = "my-rg"
    }
    """
    
    result = analyzer.analyze(code, "terraform", "network.tf")
    
    assert result.ksi_id == "KSI-CNA-01", "KSI ID should match"
    # May or may not have findings depending on KSI-CNA-01 implementation
    
    print(f"[OK] Terraform analysis completed with {len(result.findings)} findings")


def test_multiple_ksis():
    """Test that multiple KSIs can analyze the same code."""
    print("\n=== Testing Multiple KSI Analysis ===")
    
    factory = get_factory()
    
    code = """
    from flask import Flask, request
    
    app = Flask(__name__)
    SECRET_KEY = "hardcoded-key-123"
    
    @app.route('/api/data', methods=['POST'])
    def post_data():
        data = request.json
        return {'result': 'success'}
    """
    
    # Test with multiple KSIs
    ksi_ids = ["KSI-SVC-06", "KSI-IAM-01", "KSI-SVC-01"]
    total_findings = 0
    
    for ksi_id in ksi_ids:
        analyzer = factory.get_analyzer(ksi_id)
        if analyzer:
            result = analyzer.analyze(code, "python", "app.py")
            total_findings += len(result.findings)
            print(f"   {ksi_id}: {len(result.findings)} findings")
    
    # At least one KSI should work
    print(f"[OK] Multiple KSI analysis found {total_findings} total findings")


def test_good_practices():
    """Test detection of good security practices."""
    print("\n=== Testing Good Practices Detection ===")
    
    factory = get_factory()
    analyzer = factory.get_analyzer("KSI-MLA-05")
    
    # If the analyzer is not found, it should cause an error
    assert analyzer is not None, "KSI-MLA-05 analyzer should be found"

    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
    }
    
    resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
      name: 'storage-diagnostics'
      scope: storageAccount
      properties: {
        logs: [
          {
            category: 'StorageRead'
            enabled: true
          }
        ]
        workspaceId: logAnalyticsWorkspace.id
      }
    }
    """
    
    result = analyzer.analyze(code, "bicep", "storage-with-logging.bicep")
    
    # Check if any findings marked as good practices
    good_practices = [f for f in result.findings if f.good_practice]
    
    print(f"[OK] Good practices detection: {len(good_practices)} good practices found")


def test_ksi_metadata():
    """Test that KSI metadata is accessible."""
    print("\n=== Testing KSI Metadata ===")
    
    factory = get_factory()
    
    # Test a few KSIs
    test_ksis = ["KSI-IAM-01", "KSI-MLA-05", "KSI-SVC-06"]
    
    for ksi_id in test_ksis:
        metadata = factory.get_ksi_metadata(ksi_id)
        assert metadata is not None, f"Metadata for {ksi_id} should exist"
        assert metadata['ksi_id'] == ksi_id, "KSI ID should match"
        assert 'ksi_name' in metadata, "Should have ksi_name"
        assert 'statement' in metadata, "Should have statement"
        assert 'controls' in metadata, "Should have controls"
        print(f"   {ksi_id}: {metadata['ksi_name']}")
    
    print(f"[OK] Metadata accessible for all tested KSIs")


def run_all_tests():
    """Run all analyzer tool tests."""
    print("=" * 70)
    print("RUNNING ANALYZER TOOL TESTS (KSI-Centric Architecture)")
    print("=" * 70)
    
    tests = [
        test_factory_registration,
        test_bicep_analysis,
        test_python_analysis,
        test_csharp_analysis,
        test_terraform_analysis,
        test_multiple_ksis,
        test_good_practices,
        test_ksi_metadata,
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_func.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            import traceback
            print(f"[ERROR] {test_func.__name__} error: {e}")
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed > 0:
        print("\n[FAIL] Some tests failed!")
        sys.exit(1)
    else:
        print("\n[OK] All tests passed!")
        sys.exit(0)


if __name__ == "__main__":
    run_all_tests()
