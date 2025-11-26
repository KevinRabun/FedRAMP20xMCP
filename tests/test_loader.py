"""
Simple test script to verify the FedRAMP data loader works.
"""

import asyncio
import sys
from fedramp_20x_mcp.data_loader import get_data_loader

async def main():
    print("Testing FedRAMP Data Loader...", file=sys.stderr)
    
    loader = get_data_loader()
    
    # Test loading data
    print("Loading FedRAMP data from GitHub...", file=sys.stderr)
    data = await loader.load_data()
    
    print(f"Loaded {len(data['requirements'])} requirements", file=sys.stderr)
    print(f"From {len(data['documents'])} documents", file=sys.stderr)
    print(f"Metadata: {data['metadata']}", file=sys.stderr)
    
    # Test requirement lookup
    if data['requirements']:
        first_req_id = list(data['requirements'].keys())[0]
        print(f"\nTesting requirement lookup for {first_req_id}...", file=sys.stderr)
        req = loader.get_control(first_req_id)
        if req:
            print(f"Found requirement: {req.get('id', 'Unknown')}", file=sys.stderr)
            print(f"  Term: {req.get('term', 'N/A')}", file=sys.stderr)
            print(f"  Document: {req.get('document_name', 'N/A')}", file=sys.stderr)
        
    # Test family lookup
    print("\nTesting family lookup for FRD...", file=sys.stderr)
    frd_reqs = loader.get_family_controls("FRD")
    print(f"Found {len(frd_reqs)} FRD requirements", file=sys.stderr)
    
    # Test search
    print("\nTesting search for 'vulnerability'...", file=sys.stderr)
    search_results = loader.search_controls("vulnerability")
    print(f"Found {len(search_results)} matching requirements", file=sys.stderr)
    
    print("\nAll tests completed!", file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(main())
