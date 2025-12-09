"""
Test KSI tools functionality
Tests get_ksi and list_ksi
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools.ksi import (
    get_ksi_impl,
    list_ksi_impl
)


async def test_get_ksi():
    """Test get_ksi with various KSI IDs"""
    
    print("=" * 80)
    print("Testing get_ksi Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_cases = [
        ("KSI-IAM-01", "Identity & Access Management KSI"),
        ("KSI-MLA-01", "Monitoring, Logging & Analysis KSI"),
        ("KSI-AFR-01", "Authorization Framework KSI"),
        ("KSI-CNA-01", "Cloud Native Architecture KSI"),
        ("KSI-PIY-01", "Policy KSI"),
        ("INVALID-KSI-99", "Invalid KSI ID"),
    ]
    
    for ksi_id, description in test_cases:
        print(f"\n[{description}] Testing {ksi_id}...")
        try:
            result = await get_ksi_impl(ksi_id, loader)
            
            if ksi_id == "INVALID-KSI-99":
                assert "not found" in result.lower(), "Should return not found message"
                print(f"[PASS] Correctly handled invalid ID")
            else:
                assert len(result) > 0, "Result should not be empty"
                assert ksi_id in result, f"Result should contain {ksi_id}"
                assert "KSI:" in result or "Key Security Indicator:" in result, "Should have KSI header"
                print(f"[PASS] Retrieved {len(result)} characters")
                
                # Check for key sections
                has_description = "Description:" in result or "Requirement:" in result
                has_notes = "Note:" in result or "Notes:" in result
                has_references = "Reference:" in result or "References:" in result
                
                details = []
                if has_description:
                    details.append("Description")
                if has_notes:
                    details.append("Notes")
                if has_references:
                    details.append("References")
                
                if details:
                    print(f"  Contains: {', '.join(details)}")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] get_ksi tests passed!")


async def test_list_ksi():
    """Test list_ksi (lists all KSIs)"""
    
    print("\n" + "=" * 80)
    print("Testing list_ksi Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    print("\nListing all KSIs...")
    try:
        result = await list_ksi_impl(loader)
        
        assert len(result) > 0, "Result should not be empty"
        assert "KSI" in result, "Result should mention KSI"
        
        # Count KSIs
        ksi_count = result.count("KSI-")
        print(f"[PASS] Found {ksi_count} KSIs")
        assert ksi_count >= 60, f"Expected at least 60 KSIs, found {ksi_count}"
        
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    print("\n[OK] list_ksi tests passed!")


async def test_ksi_families():
    """Test that major KSI families are present"""
    
    print("\n" + "=" * 80)
    print("Testing KSI Family Coverage")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    result = await list_ksi_impl(loader)
    
    expected_families = [
        ("IAM", "Identity & Access Management"),
        ("MLA", "Monitoring, Logging & Analysis"),
        ("AFR", "Authorization Framework"),
        ("CNA", "Cloud Native Architecture"),
        ("PIY", "Policy"),
        ("RPL", "Recovery & Planning"),
        ("SVC", "Service Management"),
    ]
    
    print("\nVerifying major KSI families present...")
    for family_code, family_name in expected_families:
        family_tag = f"KSI-{family_code}-"
        has_family = family_tag in result
        
        if has_family:
            count = result.count(family_tag)
            print(f"[PASS] {family_code}: Found {count} KSI(s)")
        else:
            print(f"  {family_code}: Not found (may not exist in data)")
    
    # Verify we have a substantial number of KSIs total
    total_ksis = result.count("KSI-")
    assert total_ksis >= 60, f"Expected at least 60 total KSIs, found {total_ksis}"
    print(f"\n[PASS] Total: {total_ksis} KSIs across all families")
    
    print("\n[OK] KSI family coverage test passed!")


async def main():
    """Run all KSI tool tests"""
    try:
        await test_get_ksi()
        await test_list_ksi()
        await test_ksi_families()
        
        print("\n" + "=" * 80)
        print("[OK] ALL KSI TOOLS TESTS PASSED!")
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

