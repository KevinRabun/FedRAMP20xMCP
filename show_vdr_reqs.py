import sys
sys.path.insert(0, 'src')
from fedramp_20x_mcp.data_loader import FedRAMPDataLoader

loader = FedRAMPDataLoader()
frr_data = loader.get_family_controls('FRR')

# Filter VDR requirements
vdr_reqs = [r for r in frr_data if r.get('id', '').startswith('FRR-VDR-')]
vdr_base = [r for r in vdr_reqs if len(r.get('id', '').split('-')) == 3]
vdr_sorted = sorted(vdr_base, key=lambda x: int(x.get('id', 'FRR-VDR-99').split('-')[-1]))

print('FRR-VDR Base Requirements (02-11):')
print('=' * 100)
for req in vdr_sorted[1:11]:  # Skip 01, get 02-11
    req_id = req.get('id')
    title = req.get('title')
    statement = req.get('statement', 'N/A')
    related_ksis = req.get('related_ksis', [])
    
    print(f'\n{req_id}: {title}')
    print(f'Statement: {statement[:200]}...' if len(statement) > 200 else f'Statement: {statement}')
    if related_ksis:
        print(f'Related KSIs: {", ".join(related_ksis)}')
