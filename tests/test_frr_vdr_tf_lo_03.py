"""
Tests for FRR-VDR-TF-LO-03: Monthly Drift Detection
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_tf_lo_03 import FRR_VDR_TF_LO_03_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-VDR-TF-LO-03
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-VDR-TF-LO-03 analyzer metadata."""
    analyzer = FRR_VDR_TF_LO_03_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-TF-LO-03", "FRR_ID should be FRR-VDR-TF-LO-03"
    assert analyzer.FAMILY == "VDR", "Family should be VDR"
    assert analyzer.FRR_NAME == "Monthly Drift Detection", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "SHOULD", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == True, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == False, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == False, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods."""
    analyzer = FRR_VDR_TF_LO_03_Analyzer()
    
    # Test queries
    queries = analyzer.get_evidence_collection_queries()
    assert "Drift-prone resource identification" in queries, "Missing drift identification queries"
    assert "Monthly vulnerability scanning on drift-prone assets" in queries, "Missing scan queries"
    assert "Persistent drift detection verification" in queries, "Missing persistence verification"
    
    # Test artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert any("drift" in a.lower() for a in artifacts), "Missing drift detection"
    assert any("monthly" in a.lower() or "30" in a for a in artifacts), "Missing monthly frequency"
    assert any("persistent" in a.lower() for a in artifacts), "Missing persistent scanning"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert "Drift-prone resource tagging" in recommendations, "Missing tagging recommendation"
    assert "Automated monthly drift scanning" in recommendations, "Missing scan recommendation"
    
    print("[PASS] test_evidence_collection PASSED")


# TODO: Add language-specific tests
# Examples:
# - test_python_detection()
# - test_csharp_detection()
# - test_java_detection()
# - test_typescript_detection()
# - test_bicep_detection()
# - test_terraform_detection()
# - test_github_actions_detection()
# - test_azure_pipelines_detection()
# - test_compliant_code_passes()


def run_all_tests():
    """Run all FRR-VDR-TF-LO-03 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
        # TODO: Add more test functions
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-VDR-TF-LO-03 Tests ({len(test_functions)} tests)")
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
