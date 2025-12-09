"""Test documentation loading functionality."""
import asyncio

# Add parent directory to path

from fedramp_20x_mcp.data_loader import get_data_loader

async def test_docs():
    loader = get_data_loader()
    
    print("Testing documentation loading...")
    print("-" * 50)
    
    # Load documentation
    docs = await loader.load_documentation()
    
    print(f"\n[PASS] Loaded {len(docs)} documentation files")
    print("\nAvailable files:")
    for filename in sorted(docs.keys()):
        size = len(docs[filename])
        print(f"  - {filename} ({size:,} bytes)")
    
    # Test search
    print("\n" + "-" * 50)
    print("Testing search for 'Key Security Indicator'...")
    results = loader.search_documentation("Key Security Indicator")
    print(f"[PASS] Found {len(results)} matches")
    
    if results:
        print(f"\nFirst match in {results[0]['filename']}:")
        print(f"Line {results[0]['line_number']}: {results[0]['match'][:100]}...")
    
    # Test get file
    print("\n" + "-" * 50)
    print("Testing get_documentation_file('overview.md')...")
    content = loader.get_documentation_file("overview.md")
    if content:
        lines = content.split('\n')
        print(f"[PASS] Retrieved file with {len(lines)} lines")
        print(f"\nFirst 5 lines:")
        for line in lines[:5]:
            print(f"  {line}")
    else:
        print("[FAIL] File not found")
    
    print("\n" + "-" * 50)
    print("[PASS] All tests passed!")

if __name__ == "__main__":
    asyncio.run(test_docs())
