"""Quick script to check VDR requirements structure."""
import asyncio
from src.fedramp_20x_mcp.data_loader import FedRAMPDataLoader

async def main():
    loader = FedRAMPDataLoader()
    data = await loader.load_data()
    
    # Check available families
    families = data.get('families', {})
    print("Available families:")
    for family, req_list in sorted(families.items()):
        print(f"  {family}: {len(req_list)} requirements")
    
    print("\n" + "="*80)
    print("ALL FRR Requirements by subfamily:")
    print("="*80 + "\n")
    
    all_reqs = data.get('requirements', {})
    frr_reqs = {r_id: r for r_id, r in all_reqs.items() if r_id.startswith('FRR-')}
    
    # Group by subfamily (VDR, RSC, UCM, etc.)
    subfamilies = {}
    for req_id, req in frr_reqs.items():
        # Extract subfamily from ID (FRR-VDR-01 -> VDR)
        parts = req_id.split('-')
        if len(parts) >= 2:
            subfamily = parts[1]
            if subfamily not in subfamilies:
                subfamilies[subfamily] = []
            subfamilies[subfamily].append(req)
    
    # Print summary
    for subfamily in sorted(subfamilies.keys()):
        reqs_list = subfamilies[subfamily]
        print(f"\n{subfamily} ({len(reqs_list)} requirements):")
        print("-" * 80)
        for req in sorted(reqs_list[:5], key=lambda x: x.get('id', '')):
            req_id = req.get('id', 'N/A')
            term = req.get('term', req.get('name', req.get('description', 'No description')))
            if len(term) > 80:
                term = term[:80] + "..."
            print(f"  {req_id}: {term}")
        if len(reqs_list) > 5:
            print(f"  ... and {len(reqs_list) - 5} more")

if __name__ == "__main__":
    asyncio.run(main())
