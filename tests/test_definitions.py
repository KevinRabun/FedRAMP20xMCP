"""
Test script to verify definitions and KSI are loaded correctly
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader

async def main():
    loader = get_data_loader()
    
    print("Testing FedRAMP Definitions and KSI...")
    await loader.load_data()
    
    # Test definitions
    print("\n=== Testing Definitions ===")
    all_defs = loader.list_all_definitions()
    print(f"Total definitions: {len(all_defs)}")
    
    if all_defs:
        print(f"\nFirst definition: {all_defs[0].get('term', 'N/A')}")
        print(f"  ID: {all_defs[0].get('id', 'N/A')}")
        
        # Test get_definition
        term = all_defs[0].get('term')
        if term:
            print(f"\nLooking up definition for '{term}'...")
            definition = loader.get_definition(term)
            if definition:
                print(f"  Found: {definition.get('definition', 'N/A')[:100]}...")
    
    # Test KSI
    print("\n=== Testing Key Security Indicators ===")
    all_ksi = loader.list_all_ksi()
    print(f"Total KSI: {len(all_ksi)}")
    
    if all_ksi:
        print(f"\nFirst KSI: {all_ksi[0].get('id', 'N/A')}")
        
        # Test get_ksi
        ksi_id = all_ksi[0].get('id')
        if ksi_id:
            print(f"\nLooking up KSI {ksi_id}...")
            ksi = loader.get_ksi(ksi_id)
            if ksi:
                print(f"  Found KSI with {len(ksi)} fields")
    
    # Test search_definitions
    print("\n=== Testing Definition Search ===")
    results = loader.search_definitions("cloud")
    print(f"Found {len(results)} definitions matching 'cloud'")
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    asyncio.run(main())
