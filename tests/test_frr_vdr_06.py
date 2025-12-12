"""
Tests for FRR-VDR-06: Evaluate False Positives
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.frr_vdr_06 import FRR_VDR_06_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for FRR-VDR-06
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test FRR-VDR-06 analyzer metadata."""
    analyzer = FRR_VDR_06_Analyzer()
    
    assert analyzer.FRR_ID == "FRR-VDR-06", "FRR_ID should be FRR-VDR-06"
    assert analyzer.FAMILY == "VDR", "Family should be VDR"
    assert analyzer.FRR_NAME == "Evaluate False Positives", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "SHOULD", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == True, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == True, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == True, "Impact High mismatch"
    
    print("[PASS] test_analyzer_metadata PASSED")


def test_evidence_collection():
    """Test evidence collection methods."""
    analyzer = FRR_VDR_06_Analyzer()
    
    # Test evidence queries
    queries = analyzer.get_evidence_collection_queries()
    assert isinstance(queries, dict), "Queries should be a dictionary"
    assert "azure_monitor_kql" in queries, "Should have Azure Monitor KQL queries"
    assert len(queries["azure_monitor_kql"]) > 0, "Should have at least one KQL query"
    
    # Test evidence artifacts
    artifacts = analyzer.get_evidence_artifacts()
    assert isinstance(artifacts, list), "Artifacts should be a list"
    assert len(artifacts) > 0, "Should have at least one artifact"
    
    # Test automation recommendations
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert isinstance(recommendations, dict), "Recommendations should be a dictionary"
    assert len(recommendations) > 0, "Should have at least one recommendation"
    
    print("[PASS] test_evidence_collection PASSED")


def test_metadata():
    """Test analyzer metadata comprehensively."""
    analyzer = FRR_VDR_06_Analyzer()
    
    # Verify all required metadata fields
    assert hasattr(analyzer, 'FRR_ID'), "Should have FRR_ID"
    assert hasattr(analyzer, 'FAMILY'), "Should have FAMILY"
    assert hasattr(analyzer, 'FRR_NAME'), "Should have FRR_NAME"
    assert hasattr(analyzer, 'PRIMARY_KEYWORD'), "Should have PRIMARY_KEYWORD"
    assert hasattr(analyzer, 'CODE_DETECTABLE'), "Should have CODE_DETECTABLE"
    
    # Verify metadata values
    assert analyzer.FRR_ID == "FRR-VDR-06"
    assert analyzer.FAMILY == "VDR"
    assert analyzer.FRR_NAME == "Evaluate False Positives"
    assert analyzer.PRIMARY_KEYWORD == "SHOULD"
    
    print("[PASS] test_metadata PASSED")


if __name__ == "__main__":
    import sys
    passed = 0
    failed = 0
    
    tests = [
        test_analyzer_metadata,
        test_evidence_collection,
        test_metadata
    ]
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed")
    print(f"{'='*50}")
    
    if failed > 0:
        sys.exit(1)
