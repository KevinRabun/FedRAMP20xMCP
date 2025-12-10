#!/usr/bin/env python3
"""
Fix FRR analyzers based on official FedRAMP controls data.
"""
import json
import re
from pathlib import Path
from typing import Dict

def load_fedramp_cache() -> Dict:
    """Load official FedRAMP controls from cache."""
    cache_file = Path('src/fedramp_20x_mcp/__fedramp_cache__/fedramp_controls.json')
    with open(cache_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data['requirements']

def fix_frr_file(file_path: Path, official_data: Dict) -> bool:
    """Fix FRR analyzer file. Returns True if changes made."""
    content = file_path.read_text(encoding='utf-8')
    original_content = content
    
    # Extract FRR_ID
    frr_id_match = re.search(r'FRR_ID = ["\']([^"\']+)["\']', content)
    if not frr_id_match:
        return False
    
    frr_id = frr_id_match.group(1)
    if frr_id not in official_data:
        return False
    
    official = official_data[frr_id]
    
    # Fix FRR_NAME (handle None -> "Unknown" or keep null)
    official_name = official.get('name')
    if official_name is None:
        # Replace 'N/A' with None for Python
        content = re.sub(
            r'FRR_NAME = ["\']N/A["\']',
            'FRR_NAME = None',
            content
        )
    else:
        # Update to official name
        current_name_match = re.search(r'FRR_NAME = ["\']([^"\']+)["\']', content)
        if current_name_match:
            current_name = current_name_match.group(1)
            if current_name != official_name:
                content = re.sub(
                    r'FRR_NAME = ["\']' + re.escape(current_name) + r'["\']',
                    f'FRR_NAME = "{official_name}"',
                    content
                )
    
    # Fix IMPACT_HIGH for KSI requirements (None in official data means not applicable)
    official_impact = official.get('impact', {})
    if 'high' not in official_impact or official_impact.get('high') is None:
        # KSI requirements don't have high impact - set to False
        if frr_id.startswith('FRR-KSI'):
            content = re.sub(
                r'IMPACT_HIGH = False',
                'IMPACT_HIGH = False  # Not applicable for this requirement',
                content
            )
    
    # Fix VDR-01 statement
    if frr_id == 'FRR-VDR-01':
        official_stmt = official.get('statement', '')
        # Update the statement
        content = re.sub(
            r'FRR_STATEMENT = """[^"]*"""',
            f'FRR_STATEMENT = """{official_stmt}"""',
            content,
            flags=re.DOTALL
        )
    
    # Fix VDR-08 statement  
    if frr_id == 'FRR-VDR-08':
        official_stmt = official.get('statement', '')
        content = re.sub(
            r'FRR_STATEMENT = """[^"]*"""',
            f'FRR_STATEMENT = """{official_stmt}"""',
            content,
            flags=re.DOTALL
        )
    
    # Write back if changed
    if content != original_content:
        file_path.write_text(content, encoding='utf-8')
        return True
    
    return False

def main():
    """Fix all FRR analyzers."""
    print("Loading official FedRAMP controls data...")
    official_data = load_fedramp_cache()
    
    analyzer_dir = Path('src/fedramp_20x_mcp/analyzers/frr')
    
    fixed = []
    
    # Fix specific files
    files_to_fix = [
        'frr_ksi_01.py', 'frr_ksi_02.py',
        'frr_scn_04.py', 'frr_scn_05.py', 'frr_scn_06.py', 'frr_scn_07.py',
        'frr_scn_08.py', 'frr_scn_09.py', 'frr_scn_10.py', 'frr_scn_ad_01.py',
        'frr_scn_ex_01.py', 'frr_scn_ex_02.py', 'frr_scn_im_01.py', 'frr_scn_rr_01.py',
        'frr_scn_tr_01.py', 'frr_scn_tr_02.py', 'frr_scn_tr_03.py', 'frr_scn_tr_04.py',
        'frr_scn_tr_05.py', 'frr_scn_tr_06.py', 'frr_scn_tr_07.py',
        'frr_vdr_01.py', 'frr_vdr_08.py'
    ]
    
    for filename in files_to_fix:
        file_path = analyzer_dir / filename
        if file_path.exists():
            if fix_frr_file(file_path, official_data):
                fixed.append(filename)
                print(f"[FIXED] {filename}")
    
    print(f"\n{'='*60}")
    print(f"Fixed {len(fixed)} files")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
