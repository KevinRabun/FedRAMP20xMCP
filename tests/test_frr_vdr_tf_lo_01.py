"""
Tests for FRR-VDR-TF-LO-01: Machine-Readable History
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_tf_lo_01 import FRR_VDR_TF_LO_01_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-VDR-TF-LO-01
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-VDR-TF-LO-01 analyzer metadata."""
    analyzer = FRR_VDR_TF_LO_01_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-TF-LO-01", "FRR_ID should be FRR-VDR-TF-LO-01"
    assert analyzer.FAMILY == "VDR", "Family should be VDR"
    assert analyzer.FRR_NAME == "Machine-Readable History", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "SHOULD", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == True, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == False, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == False, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods."""
    analyzer = FRR_VDR_TF_LO_01_Analyzer()
    
    # Test queries
    queries = analyzer.get_evidence_collection_queries()
    assert "API service availability for VDR history" in queries, "Missing API availability queries"
    assert "Machine-readable format verification" in queries, "Missing format verification queries"
    assert "Monthly update frequency verification" in queries, "Missing update frequency queries"
    
    # Test artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert any("API service documentation" in a for a in artifacts), "Missing API documentation"
    assert any("machine-readable" in a.lower() for a in artifacts), "Missing format verification"
    assert any("monthly" in a.lower() or "30" in a for a in artifacts), "Missing monthly frequency"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert "REST API implementation" in recommendations, "Missing API recommendation"
    assert "Automated monthly updates" in recommendations, "Missing monthly update recommendation"
    
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
    """Run all FRR-VDR-TF-LO-01 tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence collection", test_evidence_collection),
        # TODO: Add more test functions
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "=" * 70)
    print(f"Running FRR-VDR-TF-LO-01 Tests ({len(test_functions)} tests)")
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
