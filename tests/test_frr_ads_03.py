"""
Tests for FRR-ADS-03: Detailed Service List
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_ads_03 import FRR_ADS_03_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_complete_service_list():
    """Test that complete service list with impact levels passes."""
    analyzer = FRR_ADS_03_Analyzer()
    content = """
# FedRAMP Authorization Scope

## Services Included in Authorization

### High Impact Level
- Azure Virtual Machines (all SKUs, all regions)
- Azure Key Vault Premium (HSM-backed)
- Azure Storage (all tiers: Blob, File, Queue, Table)
- Azure SQL Database
- Azure Kubernetes Service (AKS)

### Moderate Impact Level
- Azure App Service (Web Apps, API Apps, Mobile Apps)
- Azure Functions (all hosting plans)
- Azure Container Instances
- Azure Container Registry
- Azure Service Bus

### Low Impact Level
- Azure Monitor
- Azure Log Analytics
- Application Insights

### Services NOT Included in Authorization
- Azure DevOps (separate authorization)
- Microsoft 365 services
- Dynamics 365
"""
    findings = analyzer.analyze_documentation(content, "README.md")
    assert len(findings) == 0, f"Complete service list should have no findings, got {len(findings)}"
    print("[PASS] test_complete_service_list PASSED")


def test_missing_service_list():
    """Test detection of missing service list."""
    analyzer = FRR_ADS_03_Analyzer()
    content = """
# Cloud Service

Welcome to our cloud service platform. We provide enterprise-grade solutions.

## Features
- Scalable infrastructure
- High availability
- 24/7 support
"""
    findings = analyzer.analyze_documentation(content, "README.md")
    assert len(findings) > 0, "Should detect missing service list"
    assert any("Missing service list" in f.title for f in findings), "Should flag missing service list"
    assert findings[0].severity == Severity.HIGH, "Missing service list should be HIGH severity"
    print("[PASS] test_missing_service_list PASSED")


def test_service_list_without_impact_levels():
    """Test detection of service list missing impact level designation."""
    analyzer = FRR_ADS_03_Analyzer()
    content = """
# Services Included in FedRAMP Authorization

Our cloud service offering includes the following services:
- Virtual Machines
- Storage accounts
- Database services
- Networking components
- Identity and access management

All services are fully managed and highly available.
"""
    findings = analyzer.analyze_documentation(content, "SERVICES.md")
    assert len(findings) > 0, "Should detect missing impact levels"
    assert any("impact level" in f.title.lower() for f in findings), "Should flag missing impact levels"
    print("[PASS] test_service_list_without_impact_levels PASSED")


def test_vague_service_names():
    """Test detection of vague service descriptions."""
    analyzer = FRR_ADS_03_Analyzer()
    content = """
# Service List - High Impact Level

Our authorized services include:
- Compute services
- Storage solutions
- Database offerings
- Network services
"""
    findings = analyzer.analyze_documentation(content, "README.md")
    assert len(findings) > 0, "Should detect vague service names"
    assert any("specific service names" in f.title.lower() for f in findings), "Should flag vague names"
    print("[PASS] test_vague_service_names PASSED")


def test_non_documentation_file_ignored():
    """Test that non-documentation files are ignored."""
    analyzer = FRR_ADS_03_Analyzer()
    code = """
import azure.storage
import azure.keyvault

def deploy_resources():
    # Deploy various Azure services
    pass
"""
    findings = analyzer.analyze_documentation(code, "deploy.py")
    assert len(findings) == 0, "Non-documentation files should be ignored"
    print("[PASS] test_non_documentation_file_ignored PASSED")


def test_analyzer_metadata():
    """Test FRR-ADS-03 analyzer metadata."""
    analyzer = FRR_ADS_03_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-ADS-03", "FRR_ID should be FRR-ADS-03"
    assert analyzer.FAMILY == "ADS", "Family should be ADS"
    assert analyzer.FRR_NAME == "Detailed Service List", "Name mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword should be MUST"
    assert analyzer.IMPACT_LOW == True, "Impact Low should be True"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate should be True"
    assert analyzer.IMPACT_HIGH == True, "Impact High should be True"
    assert analyzer.CODE_DETECTABLE == "Partial", "Code detectable should be Partial"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_automation_recommendations():
    """Test evidence automation recommendations."""
    analyzer = FRR_ADS_03_Analyzer()
    
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert recommendations['frr_id'] == "FRR-ADS-03", "FRR_ID mismatch"
    assert recommendations['code_detectable'] == "Partial", "Should be Partial"
    assert len(recommendations['evidence_artifacts']) > 0, "Should have evidence artifacts"
    assert len(recommendations['manual_validation_steps']) > 0, "Should have validation steps"
    
    print("[PASS] test_evidence_automation_recommendations PASSED")


def run_all_tests():
    """Run all FRR-ADS-03 tests."""
    test_functions = [
        ("Complete service list", test_complete_service_list),
        ("Missing service list", test_missing_service_list),
        ("Service list without impact levels", test_service_list_without_impact_levels),
        ("Vague service names", test_vague_service_names),
        ("Non-documentation file ignored", test_non_documentation_file_ignored),
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence automation recommendations", test_evidence_automation_recommendations),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-ADS-03 Tests ({len(test_functions)} tests)")
    print("=" * 70 + "\n")
    
    for test_name, test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name} FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test_name} ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Test Results: {passed}/{len(test_functions)} passed, {failed} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\nALL TESTS PASSED [PASS]\n")
    else:
        print(f"\nSOME TESTS FAILED [FAIL]\n")
        print("TODO: Implement remaining tests to achieve 100% pass rate")
        exit(1)


if __name__ == "__main__":
    run_all_tests()
