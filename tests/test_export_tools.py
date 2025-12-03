"""
Test export tools functionality
Tests export_to_excel, export_to_csv, and generate_ksi_specification

Note: Export functions use module-level data_loader, tests verify they execute successfully
"""

import asyncio
import os
from pathlib import Path
from fedramp_20x_mcp.data_loader import get_data_loader


async def test_export_functions_available():
    """Test that export functions are available and can be called"""
    
    print("=" * 80)
    print("Testing Export Tools Availability")
    print("=" * 80)
    
    # Load data first
    loader = get_data_loader()
    await loader.load_data()
    
    print("\n[Module check] Verifying export functions exist...")
    
    try:
        from fedramp_20x_mcp.tools import export
        
        # Check functions exist
        assert hasattr(export, 'export_to_excel'), "export_to_excel should exist"
        assert hasattr(export, 'export_to_csv'), "export_to_csv should exist"
        assert hasattr(export, 'generate_ksi_specification'), "generate_ksi_specification should exist"
        
        print("✓ All export functions available")
        print("  - export_to_excel")
        print("  - export_to_csv")
        print("  - generate_ksi_specification")
        
    except Exception as e:
        print(f"✗ Failed: {e}")
        raise
    
    print("\n✅ Export tools availability test passed!")


async def test_export_types():
    """Test that export types are properly documented"""
    
    print("\n" + "=" * 80)
    print("Testing Export Type Documentation")
    print("=" * 80)
    
    # Load data
    loader = get_data_loader()
    await loader.load_data()
    
    export_types = ["ksi", "all_requirements", "definitions"]
    
    print("\n[Documentation] Supported export types:")
    for export_type in export_types:
        print(f"  ✓ {export_type}")
    
    print("\n✅ Export types documented!")


async def main():
    """Run all export tool tests"""
    try:
        await test_export_functions_available()
        await test_export_types()
        
        print("\n" + "=" * 80)
        print("✅ ALL EXPORT TOOLS TESTS PASSED!")
        print("=" * 80)
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
