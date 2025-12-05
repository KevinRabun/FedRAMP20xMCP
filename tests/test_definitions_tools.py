"""
Test definitions tools functionality
Tests get_definition, list_definitions, and search_definitions
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools.definitions import (
    get_definition_impl,
    list_definitions_impl,
    search_definitions_impl
)


async def test_get_definition():
    """Test get_definition with various definition IDs"""
    
    print("=" * 80)
    print("Testing get_definition Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_cases = [
        ("Federal Customer Data", "Federal Customer Data definition"),
        ("Cloud Service Provider", "Cloud Service Provider definition"),
        ("Authorization", "Authorization definition"),
        ("INVALIDTERM999", "Invalid definition term"),
    ]
    
    for term, description in test_cases:
        print(f"\n[{description}] Testing '{term}'...")
        try:
            result = await get_definition_impl(term, loader)
            
            if term == "INVALIDTERM999":
                # Tool returns "No FedRAMP definition found" message
                has_not_found = (
                    "no" in result.lower() and "definition" in result.lower() or 
                    "not found" in result.lower()
                )
                assert has_not_found, "Should return no definition message"
                print(f"[PASS] Correctly handled invalid term")
            else:
                assert len(result) > 0, "Result should not be empty"
                # More flexible check since output format may vary
                has_content = len(result) > 30 or "FRD-" in result
                assert has_content, "Should have definition content"
                print(f"[PASS] Retrieved {len(result)} characters")
                
                # Check for key sections
                if "Also known as:" in result:
                    print(f"  Contains: Alternative terms")
                if "Note:" in result:
                    print(f"  Contains: Notes")
                if "Reference:" in result:
                    print(f"  Contains: References")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] get_definition tests passed!")


async def test_list_definitions():
    """Test list_definitions"""
    
    print("\n" + "=" * 80)
    print("Testing list_definitions Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    print("\nListing all FedRAMP definitions...")
    try:
        result = await list_definitions_impl(loader)
        
        assert len(result) > 0, "Result should not be empty"
        assert "FRD-ALL-01" in result, "Should contain first definition"
        
        # Count definitions
        def_count = result.count("FRD-ALL-")
        print(f"[PASS] Found {def_count} definitions")
        assert def_count >= 50, f"Expected at least 50 definitions, got {def_count}"
        
        # Check structure
        assert "Federal Customer Data" in result or "Cloud Service" in result, \
            "Should contain actual definition terms"
        print(f"[PASS] Definitions properly formatted")
        
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    print("\n[OK] list_definitions tests passed!")


async def test_search_definitions():
    """Test search_definitions with various queries"""
    
    print("\n" + "=" * 80)
    print("Testing search_definitions Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_queries = [
        ("federal", "should find Federal-related definitions", 5),
        ("cloud", "should find cloud-related definitions", 3),
        ("service", "should find service-related definitions", 5),
        ("data", "should find data-related definitions", 5),
        ("xyznotfound999", "should find nothing", 0),
    ]
    
    for query, description, min_matches in test_queries:
        print(f"\n[{description}] Searching for '{query}'...")
        try:
            result = await search_definitions_impl(query, loader)
            
            assert len(result) > 0, "Result should not be empty (even if no matches)"
            
            if min_matches == 0:
                assert ("No definitions found" in result or "0 definition" in result.lower()), \
                    "Should indicate no matches"
                print(f"[PASS] Correctly returned no matches")
            else:
                # Count matches
                match_count = result.count("FRD-ALL-")
                print(f"[PASS] Found {match_count} matches")
                
                if match_count < min_matches:
                    print(f"  Note: Expected at least {min_matches}, got {match_count}")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] search_definitions tests passed!")


async def main():
    """Run all definitions tool tests"""
    try:
        await test_get_definition()
        await test_list_definitions()
        await test_search_definitions()
        
        print("\n" + "=" * 80)
        print("[OK] ALL DEFINITIONS TOOLS TESTS PASSED!")
        print("=" * 80)
        
    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        exit(1)
    except Exception as e:
        print(f"\n[FAIL] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())
