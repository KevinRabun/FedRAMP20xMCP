"""
Tests for FRR-VDR-TF-HI-06: Treat N4/N5 As Incident
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_tf_hi_06 import FRR_VDR_TF_HI_06_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-VDR-TF-HI-06
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-VDR-TF-HI-06 analyzer metadata."""
    analyzer = FRR_VDR_TF_HI_06_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-TF-HI-06", "FRR_ID should be FRR-VDR-TF-HI-06"
    assert analyzer.FAMILY == "VDR", "Family should be VDR"
    assert analyzer.FRR_NAME == "Treat N4/N5 As Incident", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "SHOULD", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == False, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == False, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == True, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods."""
    analyzer = FRR_VDR_TF_HI_06_Analyzer()
    
    # Test queries
    queries = analyzer.get_evidence_collection_queries()
    assert "N4/N5 vulnerability incident creation" in queries, "Missing incident creation queries"
    assert "Internet-reachable vulnerability detection" in queries, "Missing internet exposure queries"
    assert "Incident status through partial mitigation to N3" in queries, "Missing mitigation tracking queries"
    
    # Test artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert any("n4" in a.lower() or "n5" in a.lower() for a in artifacts), "Missing N4/N5 references"
    assert any("internet" in a.lower() for a in artifacts), "Missing internet-reachable"
    assert any("incident" in a.lower() for a in artifacts), "Missing incident treatment"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert "Automated incident creation" in recommendations, "Missing incident creation recommendation"
    assert "Internet exposure detection" in recommendations, "Missing exposure detection recommendation"
    
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
    """Run all FRR-VDR-TF-HI-06 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
        # TODO: Add more test functions
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-VDR-TF-HI-06 Tests ({len(test_functions)} tests)")
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
