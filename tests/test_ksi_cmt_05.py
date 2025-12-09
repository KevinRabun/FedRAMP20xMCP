"""
Test ksi_cmt_05: KSI_CMT_05 Analyzer

Status: STUB - This analyzer returns empty findings for all inputs.
"""

from fedramp_20x_mcp.analyzers.ksi.ksi_cmt_05 import KSI_CMT_05_Analyzer


def test_ksi_cmt_05_stub():
    """Verify ksi_cmt_05 analyzer is a stub (returns no findings)."""
    analyzer = KSI_CMT_05_Analyzer()
    
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
    
    print(f"\nKSI_CMT_05_Analyzer is correctly implemented as a stub")


if __name__ == "__main__":
    print("Testing ksi_cmt_05: STUB Implementation")
    print("=" * 60)
    test_ksi_cmt_05_stub()
    print("=" * 60)
    print("STUB test passed!")
