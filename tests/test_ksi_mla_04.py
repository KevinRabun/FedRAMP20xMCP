"""
Test ksi_mla_04: KSI_MLA_04 Analyzer

Status: STUB - This analyzer returns empty findings for all inputs.
"""

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_04 import KSI_MLA_04_Analyzer


def test_ksi_mla_04_stub():
    """Verify ksi_mla_04 analyzer is a stub (returns no findings)."""
    analyzer = KSI_MLA_04_Analyzer()
    
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
    
    print(f"\nKSI_MLA_04_Analyzer is correctly implemented as a stub")


if __name__ == "__main__":
    print("Testing ksi_mla_04: STUB Implementation")
    print("=" * 60)
    test_ksi_mla_04_stub()
    print("=" * 60)
    print("STUB test passed!")
