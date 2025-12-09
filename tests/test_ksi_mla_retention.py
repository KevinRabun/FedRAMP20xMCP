"""
Test KSI-MLA-01 retention period detection.
Verifies that analyzer detects insufficient retention periods (< 730 days).
"""

import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory


def test_bicep_retention_90_days():
    """Test detection of 90-day retention (INSUFFICIENT)."""
    print("\n=== Test 1: Bicep Log Analytics with 90-day retention ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
      name: 'law-example'
      location: location
      properties: {
        sku: {
          name: 'PerGB2018'
        }
        retentionInDays: 90
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "bicep", "test.bicep")
    
    # Should detect insufficient retention
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 1, f"Expected 1 retention finding, got {len(retention_findings)}"
    assert "90-day retention" in retention_findings[0].description
    assert "730 days (2 years)" in retention_findings[0].description
    print(f"[OK] Detected 90-day retention: {retention_findings[0].title}")
    return True


def test_bicep_retention_365_days():
    """Test detection of 365-day retention (INSUFFICIENT)."""
    print("\n=== Test 2: Bicep Log Analytics with 365-day retention ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
      name: 'law-example'
      location: location
      properties: {
        sku: {
          name: 'PerGB2018'
        }
        retentionInDays: 365
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "bicep", "test.bicep")
    
    # Should detect insufficient retention (365 < 730)
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 1, f"Expected 1 retention finding, got {len(retention_findings)}"
    assert "365-day retention" in retention_findings[0].description
    print(f"[OK] Detected 365-day retention: {retention_findings[0].title}")
    return True


def test_bicep_retention_730_days():
    """Test NO detection for 730-day retention (COMPLIANT)."""
    print("\n=== Test 3: Bicep Log Analytics with 730-day retention ===")
    
    code = """
    resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
      name: 'law-example'
      location: location
      properties: {
        sku: {
          name: 'PerGB2018'
        }
        retentionInDays: 730
      }
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "bicep", "test.bicep")
    
    # Should NOT detect retention issues (730 is compliant)
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 0, f"Expected 0 retention findings for 730-day config, got {len(retention_findings)}"
    print("[OK] No retention issues detected (730 days is compliant)")
    return True


def test_terraform_retention_90_days():
    """Test detection of 90-day retention in Terraform (INSUFFICIENT)."""
    print("\n=== Test 4: Terraform Log Analytics with 90-day retention ===")
    
    code = """
    resource "azurerm_log_analytics_workspace" "siem" {
      name                = "law-siem"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
      sku                 = "PerGB2018"
      retention_in_days   = 90
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "terraform", "test.tf")
    
    # Should detect insufficient retention
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 1, f"Expected 1 retention finding, got {len(retention_findings)}"
    assert "90-day retention" in retention_findings[0].description
    assert "AU-11" in retention_findings[0].description
    print(f"[OK] Detected 90-day retention: {retention_findings[0].title}")
    return True


def test_terraform_retention_180_days():
    """Test detection of 180-day retention in Terraform (INSUFFICIENT)."""
    print("\n=== Test 5: Terraform Log Analytics with 180-day retention ===")
    
    code = """
    resource "azurerm_log_analytics_workspace" "siem" {
      name                = "law-siem"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
      sku                 = "PerGB2018"
      retention_in_days   = 180
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "terraform", "test.tf")
    
    # Should detect insufficient retention
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 1, f"Expected 1 retention finding, got {len(retention_findings)}"
    assert "180-day retention" in retention_findings[0].description
    print(f"[OK] Detected 180-day retention: {retention_findings[0].title}")
    return True


def test_terraform_retention_730_days():
    """Test NO detection for 730-day retention in Terraform (COMPLIANT)."""
    print("\n=== Test 6: Terraform Log Analytics with 730-day retention ===")
    
    code = """
    resource "azurerm_log_analytics_workspace" "siem" {
      name                = "law-siem"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
      sku                 = "PerGB2018"
      retention_in_days   = 730
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "terraform", "test.tf")
    
    # Should NOT detect retention issues (730 is compliant)
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 0, f"Expected 0 retention findings for 730-day config, got {len(retention_findings)}"
    print("[OK] No retention issues detected (730 days is compliant)")
    return True


def test_terraform_retention_2_years():
    """Test NO detection for 2-year retention in Terraform (COMPLIANT)."""
    print("\n=== Test 7: Terraform Log Analytics with 2+ year retention ===")
    
    code = """
    resource "azurerm_log_analytics_workspace" "siem" {
      name                = "law-siem"
      location            = azurerm_resource_group.main.location
      resource_group_name = azurerm_resource_group.main.name
      sku                 = "PerGB2018"
      retention_in_days   = 1095  # 3 years
    }
    """
    
    factory = get_factory()
    result = factory.analyze("KSI-MLA-01", code, "terraform", "test.tf")
    
    # Should NOT detect retention issues (1095 > 730)
    retention_findings = [f for f in result.findings if "Insufficient Log Retention" in f.title]
    assert len(retention_findings) == 0, f"Expected 0 retention findings for 1095-day config, got {len(retention_findings)}"
    print("[OK] No retention issues detected (1095 days exceeds requirement)")
    return True


def run_all_tests():
    """Run all KSI-MLA-01 retention period tests."""
    print("=" * 70)
    print("TESTING KSI-MLA-01 RETENTION PERIOD DETECTION")
    print("KSI-MLA-01: SIEM - Log Retention (730 days / 2 years)")
    print("=" * 70)
    
    tests = [
        ("Bicep 90-day retention", test_bicep_retention_90_days),
        ("Bicep 365-day retention", test_bicep_retention_365_days),
        ("Bicep 730-day retention (compliant)", test_bicep_retention_730_days),
        ("Terraform 90-day retention", test_terraform_retention_90_days),
        ("Terraform 180-day retention", test_terraform_retention_180_days),
        ("Terraform 730-day retention (compliant)", test_terraform_retention_730_days),
        ("Terraform 1095-day retention (3 years)", test_terraform_retention_2_years),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
        except Exception as e:
            failed += 1
            print(f"[FAIL] {test_name}: {e}")
    
    print("\n" + "=" * 70)
    print(f"TEST RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\n[OK] All KSI-MLA-01 retention tests passed!")
        return True
    else:
        print(f"\n[ERROR] {failed} test(s) failed")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
