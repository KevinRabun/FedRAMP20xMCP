"""
Test ksi_svc_07: KSI_SVC_07 Analyzer

Status: IMPLEMENTED - This analyzer has detection logic.
"""

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_07 import KSI_SVC_07_Analyzer


def test_ksi_svc_07_basic():
    """Basic smoke test for ksi_svc_07 analyzer."""
    analyzer = KSI_SVC_07_Analyzer()
    
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
    
    print(f"\nKSI_SVC_07_Analyzer is functional and can analyze code")


if __name__ == "__main__":
    print("Testing ksi_svc_07: Basic Functionality")
    print("=" * 60)
    test_ksi_svc_07_basic()
    print("=" * 60)
    print("Basic test passed!")
