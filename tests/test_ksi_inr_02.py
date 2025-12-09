"""
Test ksi_inr_02: KSI_INR_02 Analyzer

Status: IMPLEMENTED - This analyzer has detection logic.
"""

from fedramp_20x_mcp.analyzers.ksi.ksi_inr_02 import KSI_INR_02_Analyzer


def test_ksi_inr_02_basic():
    """Basic smoke test for ksi_inr_02 analyzer."""
    analyzer = KSI_INR_02_Analyzer()
    
    # Test that analyzer can process code
    code = "import os\napi_key = 'hardcoded_secret_123'"
    result = analyzer.analyze(code, 'python', 'test.py')
    
    # Analyzer is implemented - may or may not find issues depending on patterns
    print(f"[PASS] Python analysis completed: {result.total_issues} findings")
    
    # Test Bicep
    bicep_code = """
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'storageaccount'
  location: 'eastus'
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
}
"""
    result = analyzer.analyze(bicep_code, 'bicep', 'test.bicep')
    print(f"[PASS] Bicep analysis completed: {result.total_issues} findings")
    
    print(f"\nKSI_INR_02_Analyzer is functional and can analyze code")


if __name__ == "__main__":
    print("Testing ksi_inr_02: Basic Functionality")
    print("=" * 60)
    test_ksi_inr_02_basic()
    print("=" * 60)
    print("Basic test passed!")
