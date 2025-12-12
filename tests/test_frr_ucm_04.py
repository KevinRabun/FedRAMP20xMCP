"""
Tests for FRR-UCM-04: Update Streams (High)
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_ucm_04 import FRR_UCM_04_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-UCM-04
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-UCM-04 analyzer metadata."""
    analyzer = FRR_UCM_04_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-UCM-04", "FRR_ID should be FRR-UCM-04"
    assert analyzer.FAMILY == "UCM", "Family should be UCM"
    assert analyzer.FRR_NAME == "Update Streams (High)", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == False, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == False, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == True, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection support."""
    analyzer = FRR_UCM_04_Analyzer()
    
    # Test evidence queries
    queries = analyzer.get_evidence_collection_queries()
    assert isinstance(queries, dict), "Evidence queries must be a dict"
    assert "azure_resource_graph" in queries or "azure_cli" in queries, "Must include Azure queries"
    
    # Test evidence artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert isinstance(artifacts, list), "Evidence artifacts must be a list"
    assert len(artifacts) > 0, "Must specify evidence artifacts"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert isinstance(recommendations, dict), "Recommendations must be a dict"
    assert len(recommendations) > 0, "Must provide automation recommendations"
    
    print("[PASS] test_evidence_collection PASSED")


def test_metadata():
    """Test analyzer metadata."""
    analyzer = FRR_UCM_04_Analyzer()
    assert analyzer.FRR_NAME == "Update Streams (High)", f"Expected FRR_NAME='Update Streams (High)', got {analyzer.FRR_NAME}"
    assert analyzer.CODE_DETECTABLE == "Yes", f"Expected CODE_DETECTABLE='Yes', got {analyzer.CODE_DETECTABLE}"
    print("[PASS] test_metadata PASSED")


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
    """Run all FRR-UCM-04 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
        ("Metadata", test_metadata),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-UCM-04 Tests ({len(test_functions)} tests)")
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
