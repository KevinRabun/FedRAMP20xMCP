#!/usr/bin/env python3
"""
Verify each FRR analyzer against official FedRAMP controls data.

Checks:
1. FRR_STATEMENT matches official statement
2. FAMILY matches document family
3. PRIMARY_KEYWORD matches official primary_key_word
4. IMPACT_* flags match official impact levels
5. FRR_NAME matches official name

Reports any discrepancies found.
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

def load_fedramp_cache() -> Dict:
    """Load official FedRAMP controls from cache."""
    cache_file = Path('src/fedramp_20x_mcp/__fedramp_cache__/fedramp_controls.json')
    with open(cache_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data['requirements']

def extract_frr_metadata(file_path: Path) -> Dict:
    """Extract metadata from FRR analyzer file."""
    content = file_path.read_text(encoding='utf-8')
    
    # Extract fields
    frr_id = re.search(r'FRR_ID = ["\']([^"\']+)["\']', content)
    frr_name = re.search(r'FRR_NAME = ["\']([^"\']+)["\']', content)
    statement = re.search(r'FRR_STATEMENT = """([^"]*(?:"{1,2}[^"]*)*)"""', content, re.DOTALL)
    family = re.search(r'FAMILY = ["\']([^"\']+)["\']', content)
    primary_keyword = re.search(r'PRIMARY_KEYWORD = ["\']([^"\']+)["\']', content)
    impact_low = re.search(r'IMPACT_LOW = (True|False)', content)
    impact_moderate = re.search(r'IMPACT_MODERATE = (True|False)', content)
    impact_high = re.search(r'IMPACT_HIGH = (True|False)', content)
    
    return {
        'frr_id': frr_id.group(1) if frr_id else None,
        'frr_name': frr_name.group(1) if frr_name else None,
        'statement': statement.group(1).strip() if statement else None,
        'family': family.group(1) if family else None,
        'primary_keyword': primary_keyword.group(1) if primary_keyword else None,
        'impact_low': impact_low.group(1) == 'True' if impact_low else None,
        'impact_moderate': impact_moderate.group(1) == 'True' if impact_moderate else None,
        'impact_high': impact_high.group(1) == 'True' if impact_high else None,
    }

def normalize_statement(text: str) -> str:
    """Normalize statement for comparison (handle whitespace, line breaks)."""
    # Remove extra whitespace and normalize line breaks
    text = ' '.join(text.split())
    # Remove trailing punctuation for comparison
    text = text.rstrip('.:;, ')
    return text

def verify_frr(file_path: Path, official_data: Dict) -> List[str]:
    """Verify FRR analyzer against official data. Returns list of issues."""
    analyzer = extract_frr_metadata(file_path)
    frr_id = analyzer['frr_id']
    
    if not frr_id:
        return [f"ERROR: Could not extract FRR_ID from {file_path.name}"]
    
    if frr_id not in official_data:
        return [f"WARNING: {frr_id} not found in official FedRAMP cache"]
    
    official = official_data[frr_id]
    issues = []
    
    # Check FRR_NAME
    if analyzer['frr_name'] != official.get('name'):
        issues.append(f"NAME MISMATCH: '{analyzer['frr_name']}' != '{official.get('name')}'")
    
    # Check FAMILY
    official_family = official.get('document', '').upper()
    if analyzer['family'] != official_family:
        issues.append(f"FAMILY MISMATCH: '{analyzer['family']}' != '{official_family}'")
    
    # Check PRIMARY_KEYWORD
    official_keyword = official.get('primary_key_word', '')
    if analyzer['primary_keyword'] != official_keyword:
        issues.append(f"KEYWORD MISMATCH: '{analyzer['primary_keyword']}' != '{official_keyword}'")
    
    # Check IMPACT levels
    # Note: None in official data means "not applicable" which equals False
    official_impact = official.get('impact', {})
    if analyzer['impact_low'] != official_impact.get('low', False):
        issues.append(f"IMPACT_LOW MISMATCH: {analyzer['impact_low']} != {official_impact.get('low')}")
    if analyzer['impact_moderate'] != official_impact.get('moderate', False):
        issues.append(f"IMPACT_MODERATE MISMATCH: {analyzer['impact_moderate']} != {official_impact.get('moderate')}")
    # For IMPACT_HIGH: None (not in official) or False both mean "not applicable"
    official_high = official_impact.get('high')
    analyzer_high = analyzer['impact_high']
    if official_high is not None and analyzer_high != official_high:
        issues.append(f"IMPACT_HIGH MISMATCH: {analyzer_high} != {official_high}")
    
    # Check STATEMENT (normalized comparison)
    official_stmt = official.get('statement', '')
    analyzer_stmt = analyzer['statement']
    
    if analyzer_stmt and official_stmt:
        norm_analyzer = normalize_statement(analyzer_stmt)
        norm_official = normalize_statement(official_stmt)
        
        # Check if analyzer statement is a prefix of official (some may be truncated)
        if not norm_official.startswith(norm_analyzer) and norm_analyzer != norm_official:
            # Allow for minor differences but flag if significantly different
            similarity_ratio = len(set(norm_analyzer.split()) & set(norm_official.split())) / len(set(norm_official.split()))
            if similarity_ratio < 0.8:
                issues.append(f"STATEMENT MISMATCH (similarity: {similarity_ratio:.1%})")
                issues.append(f"  Analyzer: {analyzer_stmt[:100]}...")
                issues.append(f"  Official: {official_stmt[:100]}...")
    
    return issues

def main():
    """Verify all FRR analyzers."""
    print("Loading official FedRAMP controls data...")
    official_data = load_fedramp_cache()
    print(f"Loaded {len(official_data)} official requirements\n")
    
    analyzer_dir = Path('src/fedramp_20x_mcp/analyzers/frr')
    
    total = 0
    verified = 0
    errors = 0
    
    all_issues = {}
    
    for frr_file in sorted(analyzer_dir.glob('frr_*.py')):
        total += 1
        issues = verify_frr(frr_file, official_data)
        
        if issues:
            all_issues[frr_file.name] = issues
            errors += 1
        else:
            verified += 1
    
    # Report results
    print("="*80)
    print(f"VERIFICATION SUMMARY")
    print("="*80)
    print(f"Total FRR analyzers: {total}")
    print(f"Verified correct: {verified}")
    print(f"Issues found: {errors}")
    print("="*80)
    
    if all_issues:
        print("\nDETAILED ISSUES:\n")
        for filename, issues in sorted(all_issues.items()):
            print(f"\n{filename}:")
            for issue in issues:
                print(f"  • {issue}")
    else:
        print("\n✓ All FRR analyzers verified correct!")
    
    print(f"\n{'='*80}\n")

if __name__ == '__main__':
    main()
