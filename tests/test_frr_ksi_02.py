"""
Tests for FRR-KSI-02: Implementation Summaries
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_ksi_02 import FRR_KSI_02_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-KSI-02
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-KSI-02 analyzer metadata."""
    analyzer = FRR_KSI_02_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-KSI-02", "FRR_ID should be FRR-KSI-02"
    assert analyzer.FAMILY == "KSI", "Family should be KSI"
    assert analyzer.FRR_NAME == "Implementation Summaries", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == True, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == False, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods."""
    analyzer = FRR_KSI_02_Analyzer()
    
    queries = analyzer.get_evidence_collection_queries()
    assert 'KSI summary documentation' in queries, "Missing KSI summary documentation"
    assert 'Summary completeness' in queries, "Missing summary completeness"
    
    artifacts = analyzer.get_evidence_artifacts()
    assert len(artifacts) > 0, "Missing evidence artifacts"
    
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert 'automated_summary_collection' in recommendations, "Missing summary collection"
    
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
    """Run all FRR-KSI-02 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-KSI-02 Tests ({len(test_functions)} tests)")
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
