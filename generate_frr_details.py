"""
Generate comprehensive FRR requirements data for analyzer implementation.
Extracts all FRR requirements with impact levels, keywords, and statements.
"""
import json
import csv

# Load data
data = json.load(open('src/fedramp_20x_mcp/__fedramp_cache__/fedramp_controls.json'))
frr_reqs = {k: v for k, v in data['requirements'].items() if k.startswith('FRR-')}

# Prepare CSV data
csv_data = []
for frr_id in sorted(frr_reqs.keys()):
    req = frr_reqs[frr_id]
    
    # Extract fields
    title = req.get('name', 'N/A')
    keyword = req.get('primary_key_word', 'N/A')
    statement = req.get('statement', 'N/A')
    family = frr_id.split('-')[1]
    
    # Impact levels
    impact = req.get('impact', {})
    impact_low = 'Yes' if impact.get('low') else 'No'
    impact_mod = 'Yes' if impact.get('moderate') else 'No'
    impact_high = 'Yes' if impact.get('high') else 'No'
    
    # Determine code detectability (simplified heuristic)
    code_detectable = 'Unknown'
    if frr_id == 'FRR-VDR-01':
        code_detectable = 'Yes'
    elif frr_id in ['FRR-VDR-08', 'FRR-UCM-02', 'FRR-RSC-04', 'FRR-UCM-01', 'FRR-ADS-03']:
        code_detectable = 'Partial'
    elif any(term in statement.lower() for term in ['document', 'guidance', 'report', 'coordinate', 'notify', 'train']):
        code_detectable = 'No'
    else:
        code_detectable = 'Unknown'
    
    csv_data.append({
        'FRR_ID': frr_id,
        'Family': family,
        'Title': title,
        'Primary_Keyword': keyword,
        'Impact_Low': impact_low,
        'Impact_Moderate': impact_mod,
        'Impact_High': impact_high,
        'Code_Detectable': code_detectable,
        'Statement': statement
    })

# Write to CSV
with open('FRR_REQUIREMENTS_DETAIL.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=[
        'FRR_ID', 'Family', 'Title', 'Primary_Keyword',
        'Impact_Low', 'Impact_Moderate', 'Impact_High',
        'Code_Detectable', 'Statement'
    ])
    writer.writeheader()
    writer.writerows(csv_data)

print(f'✓ Generated FRR_REQUIREMENTS_DETAIL.csv with {len(csv_data)} requirements')

# Generate summary by family
families = {}
for row in csv_data:
    family = row['Family']
    if family not in families:
        families[family] = {'total': 0, 'must': 0, 'should': 0, 'may': 0, 'code_detectable': 0}
    families[family]['total'] += 1
    if row['Primary_Keyword'] == 'MUST':
        families[family]['must'] += 1
    elif row['Primary_Keyword'] == 'SHOULD':
        families[family]['should'] += 1
    elif row['Primary_Keyword'] == 'MAY':
        families[family]['may'] += 1
    if row['Code_Detectable'] in ['Yes', 'Partial']:
        families[family]['code_detectable'] += 1

print('\nFRR Summary by Family:')
print('=' * 80)
for family in sorted(families.keys()):
    stats = families[family]
    print(f"{family:3} | Total: {stats['total']:3} | MUST: {stats['must']:3} | SHOULD: {stats['should']:3} | MAY: {stats['may']:2} | Code-Detectable: {stats['code_detectable']:2}")
