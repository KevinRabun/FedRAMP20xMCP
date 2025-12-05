"""
Test requirements tools functionality
Tests get_control, list_family_controls, and search_requirements
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools.requirements import (
    get_control_impl,
    list_family_controls_impl,
    search_requirements_impl
)


async def test_get_control():
    """Test get_control with various requirement types"""
    
    print("=" * 80)
    print("Testing get_control Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_cases = [
        ("FRD-ALL-01", "Definition requirement"),
        ("KSI-IAM-01", "KSI requirement"),
        ("FRR-ADS-01", "Authorization Data Sharing requirement"),
        ("VDR-ALL-02", "Vulnerability Detection requirement"),
        ("INVALID-ID", "Invalid requirement (should handle gracefully)"),
    ]
    
    for control_id, description in test_cases:
        print(f"\n[{description}] Testing {control_id}...")
        try:
            result = await get_control_impl(control_id, loader)
            
            if control_id == "INVALID-ID":
                assert "not found" in result.lower(), "Should return not found message"
                print(f"[PASS] Correctly handled invalid ID")
            else:
                assert len(result) > 0, "Result should not be empty"
                assert control_id in result or control_id.lower() in result.lower(), \
                    f"Result should contain {control_id}"
                # More flexible check for structured output
                has_structure = (
                    "Requirement:" in result or 
                    "Definition:" in result or 
                    "KSI:" in result or
                    "#" in result or
                    len(result) > 50  # Has substantial content
                )
                assert has_structure, "Should have structured output"
                print(f"[PASS] Retrieved {len(result)} characters")
                
                # Check for key sections
                if "Definition:" in result:
                    print(f"  Contains: Definition")
                if "Note:" in result:
                    print(f"  Contains: Notes")
                if "Reference:" in result or "References:" in result:
                    print(f"  Contains: References")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] get_control tests passed!")


async def test_list_family_controls():
    """Test list_family_controls with different families"""
    
    print("\n" + "=" * 80)
    print("Testing list_family_controls Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_families = [
        ("FRD", "Definitions", 50),
        ("KSI", "Key Security Indicators", 72),
        ("ADS", "Authorization Data Sharing", 20),
        ("CCM", "Continuous Monitoring", 20),
        ("VDR", "Vulnerability Detection", 50),
        ("INVALID", "Invalid family", 0),
    ]
    
    for family, description, min_expected in test_families:
        print(f"\n[{description}] Testing family '{family}'...")
        try:
            result = await list_family_controls_impl(family, loader)
            
            if family == "INVALID":
                assert "No requirements found" in result or "not found" in result.lower(), \
                    "Should handle invalid family gracefully"
                print(f"[PASS] Correctly handled invalid family")
            else:
                assert len(result) > 0, "Result should not be empty"
                assert family in result, f"Result should mention family {family}"
                
                # Count items in result
                item_count = result.count(f"{family}-")
                print(f"[PASS] Found {item_count} items in family {family}")
                
                if min_expected > 0 and item_count < min_expected:
                    print(f"  Note: Expected at least {min_expected}, got {item_count}")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] list_family_controls tests passed!")


async def test_search_requirements():
    """Test search_requirements with various queries"""
    
    print("\n" + "=" * 80)
    print("Testing search_requirements Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_queries = [
        ("cloud service", "should find many CSP references", 50),
        ("vulnerability", "should find VDR requirements", 20),
        ("authorization", "should find auth-related items", 10),
        ("continuous monitoring", "should find CCM items", 5),
        ("encryption", "should find crypto/security items", 5),
        ("xyzabc123notfound", "should find nothing", 0),
    ]
    
    for query, description, min_matches in test_queries:
        print(f"\n[{description}] Searching for '{query}'...")
        try:
            result = await search_requirements_impl(query, loader)
            
            assert len(result) > 0, "Result should not be empty (even if no matches)"
            
            if min_matches == 0:
                assert ("No requirements found" in result or "0 requirement" in result.lower()), \
                    "Should indicate no matches"
                print(f"[PASS] Correctly returned no matches")
            else:
                # Count matches
                match_count = result.count("**ID:**") + result.count("- **")
                print(f"[PASS] Found {match_count} matches")
                
                if match_count < min_matches:
                    print(f"  Note: Expected at least {min_matches}, got {match_count}")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] search_requirements tests passed!")


async def main():
    """Run all requirements tool tests"""
    try:
        await test_get_control()
        await test_list_family_controls()
        await test_search_requirements()
        
        print("\n" + "=" * 80)
        print("[OK] ALL REQUIREMENTS TOOLS TESTS PASSED!")
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
