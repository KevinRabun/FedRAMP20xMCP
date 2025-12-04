"""
Tests for analyzer MCP tools.

Validates that tools return proper findings with FedRAMP requirement citations.
"""

import sys
import asyncio
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from fedramp_20x_mcp.tools.analyzer import (
    analyze_infrastructure_code_impl,
    analyze_application_code_impl
)


async def test_bicep_analysis_tool():
    """Test Bicep analysis tool returns proper structure."""
    print("\n=== Testing Bicep Analysis Tool ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'mystorageaccount'
      location: location
      properties: {
        password: 'hardcoded123'
      }
    }
    """
    
    result = await analyze_infrastructure_code_impl(
        code=code,
        file_type="bicep",
        file_path="storage.bicep",
        context="PR #123: Add storage account"
    )
    
    # Verify structure
    assert "findings" in result, "Result should have findings key"
    assert "summary" in result, "Result should have summary key"
    assert "pr_comment" in result, "Result should have pr_comment key"
    assert result["files_analyzed"] == 1, "Should analyze 1 file"
    
    # Verify findings have requirement IDs
    findings = result["findings"]
    assert len(findings) > 0, "Should have at least one finding"
    
    for finding in findings:
        assert "requirement_id" in finding, "Finding should have requirement_id"
        assert finding["requirement_id"].startswith("KSI-"), f"Requirement ID should start with KSI-: {finding['requirement_id']}"
        assert "severity" in finding, "Finding should have severity"
        assert "recommendation" in finding, "Finding should have recommendation"
    
    # Verify PR comment format
    pr_comment = result["pr_comment"]
    assert "FedRAMP 20x Compliance Review" in pr_comment, "PR comment should have header"
    assert "KSI-" in pr_comment, "PR comment should include requirement IDs"
    
    print(f"✅ Tool returned {len(findings)} findings with proper structure")
    print(f"   Requirements: {', '.join([f['requirement_id'] for f in findings[:3]])}")


async def test_terraform_analysis_tool():
    """Test Terraform analysis tool."""
    print("\n=== Testing Terraform Analysis Tool ===")
    
    code = """
    resource "azurerm_storage_account" "example" {
      name                     = "mystorageaccount"
      resource_group_name      = azurerm_resource_group.example.name
      account_tier             = "Standard"
    }
    """
    
    result = await analyze_infrastructure_code_impl(
        code=code,
        file_type="terraform",
        file_path="storage.tf"
    )
    
    # Verify structure
    assert "findings" in result
    assert "summary" in result
    assert result["files_analyzed"] == 1
    
    # Should detect missing diagnostic settings
    findings = result["findings"]
    ksi_mla_findings = [f for f in findings if f["requirement_id"] == "KSI-MLA-05"]
    assert len(ksi_mla_findings) > 0, "Should detect KSI-MLA-05 (logging) issue"
    
    print(f"✅ Terraform analysis detected {len(findings)} findings")


async def test_python_analysis_tool():
    """Test Python application code analysis tool."""
    print("\n=== Testing Python Analysis Tool ===")
    
    code = """
    from flask import Flask
    
    app = Flask(__name__)
    API_KEY = "sk-1234567890abcdef"
    
    @app.route('/api/users')
    def get_users():
        return {'users': ['alice', 'bob']}
    """
    
    result = await analyze_application_code_impl(
        code=code,
        language="python",
        file_path="app.py",
        dependencies=["flask==2.3.0"]
    )
    
    # Verify structure
    assert "findings" in result
    assert "summary" in result
    assert result["files_analyzed"] == 1
    assert "dependencies_checked" in result
    
    findings = result["findings"]
    assert len(findings) > 0, "Should have findings"
    
    # Should detect hardcoded API key (KSI-SVC-06)
    ksi_svc_findings = [f for f in findings if f["requirement_id"] == "KSI-SVC-06"]
    assert len(ksi_svc_findings) > 0, "Should detect KSI-SVC-06 (secrets) issue"
    
    # Should detect missing authentication (KSI-IAM-01)
    ksi_iam_findings = [f for f in findings if f["requirement_id"] == "KSI-IAM-01"]
    assert len(ksi_iam_findings) > 0, "Should detect KSI-IAM-01 (auth) issue"
    
    print(f"✅ Python analysis detected {len(findings)} findings")
    print(f"   Security issues: {[f['requirement_id'] for f in findings if not f['good_practice']]}")


async def test_pr_comment_formatting():
    """Test PR comment formatting includes all required elements."""
    print("\n=== Testing PR Comment Formatting ===")
    
    code = """
    resource vnet 'Microsoft.Network/virtualNetworks@2023-04-01' = {
      name: 'myvnet'
    }
    
    resource nsg 'Microsoft.Network/networkSecurityGroups@2023-04-01' = {
      name: 'mynsg'
      properties: {
        securityRules: [
          { name: 'AllowSSH', properties: { priority: 100, access: 'Allow' } }
        ]
      }
    }
    """
    
    result = await analyze_infrastructure_code_impl(
        code=code,
        file_type="bicep",
        file_path="network.bicep"
    )
    
    pr_comment = result["pr_comment"]
    
    # Verify required elements
    required_elements = [
        "## 🔒 FedRAMP 20x Compliance Review",
        "**File:**",
        "network.bicep",
        "**Summary:**",
    ]
    
    for element in required_elements:
        assert element in pr_comment, f"PR comment should contain: {element}"
    
    # Should have requirement IDs
    assert "KSI-" in pr_comment, "Should include FedRAMP requirement IDs"
    
    # Should have severity indicators if issues found
    if result["summary"]["high_priority"] > 0:
        assert "High Priority" in pr_comment or "⚠️" in pr_comment
    
    # Should have good practices section if any detected
    if result["summary"]["good_practices"] > 0:
        assert "Good Practices" in pr_comment or "✅" in pr_comment
    
    print("✅ PR comment formatting validated")
    print(f"   Length: {len(pr_comment)} characters")


async def test_unsupported_file_type():
    """Test handling of unsupported file types."""
    print("\n=== Testing Unsupported File Type ===")
    
    result = await analyze_infrastructure_code_impl(
        code="some code",
        file_type="cloudformation",
        file_path="template.yaml"
    )
    
    assert "error" in result, "Should return error for unsupported type"
    assert "cloudformation" in result["error"].lower()
    
    print("✅ Unsupported file type handled correctly")


async def test_unsupported_language():
    """Test handling of unsupported programming languages."""
    print("\n=== Testing Unsupported Language ===")
    
    result = await analyze_application_code_impl(
        code="some code",
        language="ruby",  # Ruby is not supported
        file_path="app.rb"
    )
    
    assert "error" in result, "Should return error for unsupported language"
    assert "ruby" in result["error"].lower()
    
    print("✅ Unsupported language handled correctly")


async def test_good_practices_detection():
    """Test that good practices are properly detected and reported."""
    print("\n=== Testing Good Practices Detection ===")
    
    code = """
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.secrets import SecretClient
    
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url="https://vault.vault.azure.net", credential=credential)
    api_key = client.get_secret("api-key").value
    """
    
    result = await analyze_application_code_impl(
        code=code,
        language="python",
        file_path="config.py"
    )
    
    # Should detect good practice
    assert result["summary"]["good_practices"] > 0, "Should detect good practices"
    
    good_practices = [f for f in result["findings"] if f["good_practice"]]
    assert len(good_practices) > 0, "Should have good practice findings"
    assert good_practices[0]["requirement_id"] == "KSI-SVC-06", "Should be KSI-SVC-06 (Key Vault)"
    
    # PR comment should highlight good practices
    pr_comment = result["pr_comment"]
    assert "Good Practices" in pr_comment or "✅" in pr_comment
    
    print(f"✅ Detected {len(good_practices)} good practices")


async def test_summary_calculations():
    """Test that summary counts are accurate."""
    print("\n=== Testing Summary Calculations ===")
    
    code = """
    resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
      name: 'storage'
      properties: {
        password: 'hardcoded'
      }
    }
    """
    
    result = await analyze_infrastructure_code_impl(
        code=code,
        file_type="bicep",
        file_path="test.bicep"
    )
    
    summary = result["summary"]
    findings = result["findings"]
    
    # Verify counts match
    high_count = len([f for f in findings if f["severity"] == "high" and not f["good_practice"]])
    medium_count = len([f for f in findings if f["severity"] == "medium" and not f["good_practice"]])
    low_count = len([f for f in findings if f["severity"] == "low" and not f["good_practice"]])
    good_count = len([f for f in findings if f["good_practice"]])
    
    assert summary["high_priority"] == high_count, f"High count mismatch: {summary['high_priority']} != {high_count}"
    assert summary["medium_priority"] == medium_count
    assert summary["low_priority"] == low_count
    assert summary["good_practices"] == good_count
    
    print(f"✅ Summary calculations correct: {high_count}H/{medium_count}M/{low_count}L, {good_count} good practices")


async def run_all_tests():
    """Run all analyzer tool tests."""
    print("\n" + "="*70)
    print("RUNNING ANALYZER TOOL TESTS")
    print("="*70)
    
    tests = [
        test_bicep_analysis_tool,
        test_terraform_analysis_tool,
        test_python_analysis_tool,
        test_pr_comment_formatting,
        test_unsupported_file_type,
        test_unsupported_language,
        test_good_practices_detection,
        test_summary_calculations,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            await test()
            passed += 1
        except AssertionError as e:
            print(f"❌ FAILED: {test.__name__}")
            print(f"   Error: {e}")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR in {test.__name__}: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("="*70)
    
    if failed > 0:
        print("\n❌ Some tests failed!")
        return False
    else:
        print("\n✅ All tests passed!")
        return True


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
