"""
Tests for FRR-VDR-TF-HI-05: Evaluate Within 2 Days
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_tf_hi_05 import FRR_VDR_TF_HI_05_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-VDR-TF-HI-05
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-VDR-TF-HI-05 analyzer metadata."""
    analyzer = FRR_VDR_TF_HI_05_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-TF-HI-05", "FRR_ID should be FRR-VDR-TF-HI-05"
    assert analyzer.FAMILY == "VDR", "Family should be VDR"
    assert analyzer.FRR_NAME == "Evaluate Within 2 Days", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == False, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == False, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == True, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods."""
    analyzer = FRR_VDR_TF_HI_05_Analyzer()
    
    # Test queries
    queries = analyzer.get_evidence_collection_queries()
    assert "Vulnerability evaluation time tracking" in queries, "Missing time tracking queries"
    assert "FRR-VDR-07/08/09 evaluation tracking" in queries, "Missing FRR evaluation queries"
    assert "Evaluation SLA violations" in queries, "Missing SLA violation queries"
    
    # Test artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert any("2 day" in a.lower() or "2-day" in a.lower() for a in artifacts), "Missing 2-day timeframe"
    assert any("evaluation" in a.lower() for a in artifacts), "Missing evaluation tracking"
    assert any("frr-vdr-07" in a.lower() or "frr-vdr-08" in a.lower() or "frr-vdr-09" in a.lower() for a in artifacts), "Missing FRR references"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert "Automated evaluation workflow" in recommendations, "Missing workflow recommendation"
    assert "2-day SLA tracking" in recommendations, "Missing SLA tracking recommendation"
    
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
    """Run all FRR-VDR-TF-HI-05 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
        # TODO: Add more test functions
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-VDR-TF-HI-05 Tests ({len(test_functions)} tests)")
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
