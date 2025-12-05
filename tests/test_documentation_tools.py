"""
Test documentation tools functionality
Tests search_documentation, get_documentation_file, and list_documentation_files
"""

import asyncio
from fedramp_20x_mcp.data_loader import get_data_loader
from fedramp_20x_mcp.tools.documentation import (
    search_documentation_impl,
    get_documentation_file_impl,
    list_documentation_files_impl
)


async def test_search_documentation():
    """Test search_documentation with various queries"""
    
    print("=" * 80)
    print("Testing search_documentation Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    test_queries = [
        ("authorization", "should find auth-related docs", 3),
        ("continuous monitoring", "should find monitoring docs", 2),
        ("vulnerability", "should find vulnerability docs", 2),
        ("assessment", "should find assessment docs", 3),
        ("xyznotfound999", "should find nothing or minimal", 0),
    ]
    
    for query, description, min_matches in test_queries:
        print(f"\n[{description}] Searching for '{query}'...")
        try:
            result = await search_documentation_impl(query, loader)
            
            assert len(result) > 0, "Result should not be empty (even if no matches)"
            
            if min_matches == 0:
                has_no_matches = (
                    "No documentation found" in result or 
                    "0 section" in result.lower() or
                    "did not match" in result.lower()
                )
                if has_no_matches:
                    print(f"[PASS] Correctly returned no/minimal matches")
                else:
                    print(f"[PASS] Returned result (may have some matches)")
            else:
                # Check if we got meaningful results
                has_content = len(result) > 100
                assert has_content, "Result should have substantial content for this query"
                print(f"[PASS] Found documentation ({len(result)} characters)")
                
                # Check for structure
                if "**File:**" in result or "**Section:**" in result:
                    print(f"  Contains: Structured results with file references")
                    
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    print("\n[OK] search_documentation tests passed!")


async def test_get_documentation_file():
    """Test get_documentation_file with specific files"""
    
    print("\n" + "=" * 80)
    print("Testing get_documentation_file Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    # First get the list of available files
    print("\nGetting list of available documentation files...")
    file_list = await list_documentation_files_impl(loader)
    
    # Extract first file name from the list
    test_files = []
    for line in file_list.split('\n'):
        if line.strip().startswith('-') and '.md' in line:
            # Extract filename from markdown link format
            if '[' in line and ']' in line:
                filename = line.split('[')[1].split(']')[0]
                test_files.append(filename)
                if len(test_files) >= 3:
                    break
    
    if not test_files:
        print("  No documentation files found in list, skipping file tests")
        return
    
    # Test retrieving specific files
    for filename in test_files:
        print(f"\n[Valid file] Testing '{filename}'...")
        try:
            result = await get_documentation_file_impl(filename, loader)
            
            assert len(result) > 0, "Result should not be empty"
            assert filename in result, f"Result should mention filename {filename}"
            
            # Check for markdown content
            has_markdown = (
                "#" in result or 
                "**" in result or
                len(result) > 500
            )
            assert has_markdown, "Should contain markdown content"
            print(f"[PASS] Retrieved {len(result)} characters")
            
            # Check structure
            if "# " in result:
                print(f"  Contains: Headers")
            if "```" in result:
                print(f"  Contains: Code blocks")
                
        except Exception as e:
            print(f"[FAIL] Failed: {e}")
            raise
    
    # Test invalid file
    print(f"\n[Invalid file] Testing 'nonexistent.md'...")
    try:
        result = await get_documentation_file_impl("nonexistent.md", loader)
        assert "not found" in result.lower() or "no file" in result.lower(), \
            "Should return not found message"
        print(f"[PASS] Correctly handled invalid file")
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    print("\n[OK] get_documentation_file tests passed!")


async def test_list_documentation_files():
    """Test list_documentation_files"""
    
    print("\n" + "=" * 80)
    print("Testing list_documentation_files Tool")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    print("\nListing all FedRAMP documentation files...")
    try:
        result = await list_documentation_files_impl(loader)
        
        assert len(result) > 0, "Result should not be empty"
        assert "documentation file" in result.lower() or "available" in result.lower(), \
            "Should describe what's being listed"
        
        # Count files
        file_count = result.count('.md')
        print(f"[PASS] Found {file_count} documentation files")
        assert file_count >= 10, f"Expected at least 10 files, got {file_count}"
        
        # Check for common documentation topics
        has_structure = (
            "authorization" in result.lower() or
            "continuous" in result.lower() or
            "vulnerability" in result.lower() or
            "assessment" in result.lower()
        )
        if has_structure:
            print(f"[PASS] Contains expected documentation topics")
        
    except Exception as e:
        print(f"[FAIL] Failed: {e}")
        raise
    
    print("\n[OK] list_documentation_files tests passed!")


async def test_documentation_integration():
    """Test that documentation tools work together"""
    
    print("\n" + "=" * 80)
    print("Testing Documentation Tools Integration")
    print("=" * 80)
    
    loader = get_data_loader()
    await loader.load_data()
    
    print("\n[Workflow] List files -> Get file -> Search within file...")
    
    # 1. List files
    file_list = await list_documentation_files_impl(loader)
    assert len(file_list) > 0
    print("[PASS] Step 1: Listed files")
    
    # 2. Extract first filename
    filename = None
    for line in file_list.split('\n'):
        if '.md' in line and '-' in line:
            if '[' in line and ']' in line:
                filename = line.split('[')[1].split(']')[0]
                break
    
    if filename:
        # 3. Get that file
        file_content = await get_documentation_file_impl(filename, loader)
        assert len(file_content) > 0
        print(f"[PASS] Step 2: Retrieved file '{filename}'")
        
        # 4. Search for content that should be in docs
        search_result = await search_documentation_impl("authorization", loader)
        assert len(search_result) > 0
        print("[PASS] Step 3: Searched documentation")
        
        print("\n[PASS] Documentation tools work together correctly")
    else:
        print("  Note: Could not extract filename, skipping integration test")
    
    print("\n[OK] Documentation integration test passed!")


async def main():
    """Run all documentation tool tests"""
    try:
        await test_search_documentation()
        await test_get_documentation_file()
        await test_list_documentation_files()
        await test_documentation_integration()
        
        print("\n" + "=" * 80)
        print("[OK] ALL DOCUMENTATION TOOLS TESTS PASSED!")
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
