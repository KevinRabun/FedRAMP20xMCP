"""
Test ksi_tpr_02: KSI_TPR_02 Analyzer

Status: STUB - This analyzer returns empty findings for all inputs.
"""

from fedramp_20x_mcp.analyzers.ksi.ksi_tpr_02 import KSI_TPR_02_Analyzer


def test_ksi_tpr_02_stub():
    """Verify ksi_tpr_02 analyzer is a stub (returns no findings)."""
    analyzer = KSI_TPR_02_Analyzer()
    
    # Test Python
    code = "import os\npassword = 'test123'"
    result = analyzer.analyze(code, 'python', 'test.py')
    assert result.total_issues == 0, f"Stub should return 0 findings, got {result.total_issues}"
    print("[PASS] Python stub returns 0 findings")
    
    # Test Bicep
    bicep_code = "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {}"
    result = analyzer.analyze(bicep_code, 'bicep', 'test.bicep')
    assert result.total_issues == 0, f"Stub should return 0 findings, got {result.total_issues}"
    print("[PASS] Bicep stub returns 0 findings")
    
    print(f"\nKSI_TPR_02_Analyzer is correctly implemented as a stub")


if __name__ == "__main__":
    print("Testing ksi_tpr_02: STUB Implementation")
    print("=" * 60)
    test_ksi_tpr_02_stub()
    print("=" * 60)
    print("STUB test passed!")
