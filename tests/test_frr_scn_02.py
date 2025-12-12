"""
Tests for FRR-SCN-02: Procedures and Documentation
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_scn_02 import FRR_SCN_02_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-SCN-02
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-SCN-02 analyzer metadata."""
    analyzer = FRR_SCN_02_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-SCN-02", "FRR_ID should be FRR-SCN-02"
    assert analyzer.FAMILY == "SCN", "Family should be SCN"
    assert analyzer.FRR_NAME == "Procedures and Documentation", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "MUST", "Keyword mismatch"
    assert analyzer.CODE_DETECTABLE == "Partial", "CODE_DETECTABLE should be Partial"
    assert analyzer.IMPACT_LOW == True, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == True, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_automation_recommendations():
    """Test evidence automation recommendations."""
    analyzer = FRR_SCN_02_Analyzer()
    
    # Test all 3 evidence methods
    queries = analyzer.get_evidence_collection_queries()
    assert queries['frr_id'] == "FRR-SCN-02", "FRR_ID mismatch in queries"
    assert 'azure_resource_graph' in queries, "Missing automated_queries key"
    
    artifacts = analyzer.get_evidence_artifacts()
    assert artifacts['frr_id'] == "FRR-SCN-02", "FRR_ID mismatch in artifacts"
    assert 'code_locations' in artifacts, "Missing evidence_artifacts key"
    
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert recommendations['frr_id'] == "FRR-SCN-02", "FRR_ID mismatch in recommendations"
    assert recommendations['code_detectable'] == "Partial", "code_detectable should be Partial"
    assert 'implementation_notes' in recommendations, "Missing implementation_notes key"
    
    print("[PASS] test_evidence_automation_recommendations PASSED")


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
    """Run all FRR-SCN-02 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence automation recommendations", test_evidence_automation_recommendations),
        # TODO: Add more test functions
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-SCN-02 Tests ({len(test_functions)} tests)")
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
