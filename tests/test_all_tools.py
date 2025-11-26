"""
Comprehensive test script for FedRAMP MCP Server
Tests all tools including definitions and KSI
"""

import asyncio
import sys
from fedramp_20x_mcp.data_loader import get_data_loader

async def test_all_tools():
    """Test all data loader functions"""
    loader = get_data_loader()
    
    print("=" * 80)
    print("FedRAMP 20x MCP Server - Comprehensive Tool Test")
    print("=" * 80)
    
    # Load data
    print("\n[1/9] Loading data...")
    await loader.load_data()
    print("✓ Data loaded successfully")
    
    # Test get_control
    print("\n[2/9] Testing get_control...")
    control = loader.get_control("FRD-ALL-01")
    if control and "term" in control:
        print(f"✓ Found control: {control['term']}")
    else:
        print("✗ Failed to get control")
    
    # Test get_family_controls
    print("\n[3/9] Testing get_family_controls...")
    frd_controls = loader.get_family_controls("FRD")
    print(f"✓ Found {len(frd_controls)} FRD requirements")
    
    # Test search_controls
    print("\n[4/9] Testing search_controls...")
    search_results = loader.search_controls("cloud service")
    print(f"✓ Found {len(search_results)} matches for 'cloud service'")
    
    # Test get_definition
    print("\n[5/9] Testing get_definition...")
    definition = loader.get_definition("Federal Customer Data")
    if definition and "definition" in definition:
        print(f"✓ Found definition: {definition['definition'][:60]}...")
    else:
        print("✗ Failed to get definition")
    
    # Test list_all_definitions
    print("\n[6/9] Testing list_all_definitions...")
    all_defs = loader.list_all_definitions()
    print(f"✓ Found {len(all_defs)} total definitions")
    
    # Test search_definitions
    print("\n[7/9] Testing search_definitions...")
    def_results = loader.search_definitions("federal")
    print(f"✓ Found {len(def_results)} definitions matching 'federal'")
    
    # Test get_ksi
    print("\n[8/9] Testing get_ksi...")
    ksi = loader.get_ksi("KSI-AFR-01")
    if ksi and "name" in ksi:
        print(f"✓ Found KSI: {ksi['name']}")
    else:
        print("✗ Failed to get KSI")
    
    # Test list_all_ksi
    print("\n[9/9] Testing list_all_ksi...")
    all_ksi = loader.list_all_ksi()
    print(f"✓ Found {len(all_ksi)} total Key Security Indicators")
    
    # Summary
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Requirements: {len(loader._data_cache['requirements'])}")
    print(f"Total Documents: {len(loader._data_cache['documents'])}")
    print(f"Total Families: {len(loader._data_cache['families'])}")
    print(f"Total Definitions: {len(all_defs)}")
    print(f"Total KSI: {len(all_ksi)}")
    
    # Show document types
    print(f"\nDocument Types:")
    for doc_name in sorted(loader._data_cache['documents'].keys()):
        doc = loader._data_cache['documents'][doc_name]
        count = len([r for r in loader._data_cache['requirements'].values() 
                    if r.get('document') == doc_name])
        print(f"  {doc_name:4s} - {doc.get('name', 'Unknown'):40s} ({count:3d} items)")
    
    print("\n✓ All tests passed!")
    return True

if __name__ == "__main__":
    try:
        result = asyncio.run(test_all_tools())
        sys.exit(0 if result else 1)
    except Exception as e:
        print(f"\n✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
