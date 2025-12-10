#!/usr/bin/env python3
"""
Update FRR_REQUIREMENTS_DETAIL.csv with CODE_DETECTABLE values from analyzers.
"""
import csv
import re
from pathlib import Path

def extract_code_detectable(file_path):
    """Extract CODE_DETECTABLE and FRR_ID from analyzer file."""
    content = file_path.read_text(encoding='utf-8')
    
    frr_id_match = re.search(r'FRR_ID = ["\']([^"\']+)["\']', content)
    code_det_match = re.search(r'CODE_DETECTABLE = ["\']([^"\']+)["\']', content)
    
    if frr_id_match and code_det_match:
        return frr_id_match.group(1), code_det_match.group(1)
    return None, None

def main():
    # Read CSV
    csv_path = Path('FRR_REQUIREMENTS_DETAIL.csv')
    rows = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    
    # Build mapping from analyzers
    analyzer_dir = Path('src/fedramp_20x_mcp/analyzers/frr')
    detectability_map = {}
    
    for analyzer_file in analyzer_dir.glob('frr_*.py'):
        frr_id, code_det = extract_code_detectable(analyzer_file)
        if frr_id and code_det:
            detectability_map[frr_id] = code_det
    
    # Update CSV rows
    updated_count = 0
    for row in rows:
        frr_id = row.get('FRR_ID', '')
        if frr_id in detectability_map:
            old_val = row.get('Code_Detectable', '')
            new_val = detectability_map[frr_id]
            if old_val != new_val:
                row['Code_Detectable'] = new_val
                updated_count += 1
                print(f"Updated {frr_id}: {old_val} -> {new_val}")
    
    # Write back to CSV
    with open(csv_path, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"\n[OK] Updated {updated_count} FRR entries in CSV")
    
    # Print summary
    detectable_counts = {}
    for row in rows:
        val = row.get('Code_Detectable', 'Unknown')
        detectable_counts[val] = detectable_counts.get(val, 0) + 1
    
    print("\nFinal CSV counts:")
    for status, count in sorted(detectable_counts.items()):
        print(f"  {status}: {count}")

if __name__ == '__main__':
    main()
