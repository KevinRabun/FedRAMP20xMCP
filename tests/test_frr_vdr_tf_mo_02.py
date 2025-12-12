"""
Tests for FRR-VDR-TF-MO-02: 3-Day Sampling
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_tf_mo_02 import FRR_VDR_TF_MO_02_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-VDR-TF-MO-02
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-VDR-TF-MO-02 analyzer metadata."""
    analyzer = FRR_VDR_TF_MO_02_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-TF-MO-02", "FRR_ID should be FRR-VDR-TF-MO-02"
    assert analyzer.FAMILY == "VDR", "Family should be VDR"
    assert analyzer.FRR_NAME == "3-Day Sampling", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "SHOULD", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == False, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == False, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods for 3-day vulnerability sampling."""
    analyzer = FRR_VDR_TF_MO_02_Analyzer()
    
    # Test evidence collection queries
    queries = analyzer.get_evidence_collection_queries()
    assert 'Representative sample identification' in queries, "Missing sample identification queries"
    assert 'Three-day vulnerability scan execution' in queries, "Missing 3-day scan queries"
    assert 'Persistent 3-day sampling verification' in queries, "Missing persistence queries"
    
    # Test evidence artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert len(artifacts) > 0, "Should have evidence artifacts"
    artifacts_text = ' '.join(artifacts).lower()
    assert 'representative' in artifacts_text or 'sample' in artifacts_text, "Missing sample artifact"
    assert '3-day' in artifacts_text or 'three-day' in artifacts_text, "Missing 3-day artifact"
    assert 'persistent' in artifacts_text, "Missing persistent artifact"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert 'representative_sample_tagging' in recommendations, "Missing sample tagging"
    assert 'three_day_automated_scanning' in recommendations, "Missing 3-day scanning"
    
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
    """Run all FRR-VDR-TF-MO-02 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-VDR-TF-MO-02 Tests ({len(test_functions)} tests)")
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
