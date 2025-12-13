#!/usr/bin/env python3
"""Analyze pattern files for V2 schema completeness."""

import yaml
import json
from pathlib import Path
from collections import defaultdict

def analyze_patterns():
    pattern_dir = Path('data/patterns')
    stats = {}
    detailed_issues = defaultdict(list)
    
    for pattern_file in sorted(pattern_dir.glob('*.yaml')):
        if pattern_file.name == 'README.md':
            continue
            
        with open(pattern_file, 'r', encoding='utf-8') as f:
            try:
                patterns = list(yaml.safe_load_all(f))
                patterns = [p for p in patterns if p]  # Filter out None
                
                file_stats = {
                    'count': len(patterns),
                    'has_evidence_artifacts': 0,
                    'has_automation': 0,
                    'has_implementation': 0,
                    'has_ssp_mapping': 0,
                    'has_evidence_collection': 0,
                    'has_azure_guidance': 0,
                    'has_compliance_frameworks': 0,
                    'has_testing': 0,
                    'todos_found': 0
                }
                
                for idx, pattern in enumerate(patterns):
                    if not pattern:
                        continue
                    
                    pid = pattern.get('pattern_id', f'pattern_{idx}')
                    
                    # Check for V2 schema fields
                    if 'evidence_artifacts' in pattern:
                        file_stats['has_evidence_artifacts'] += 1
                    
                    if 'automation' in pattern:
                        file_stats['has_automation'] += 1
                        # Check for TODO in automation
                        if isinstance(pattern['automation'], dict):
                            for key, val in pattern['automation'].items():
                                if isinstance(val, dict) and 'implementation' in val:
                                    if 'TODO' in str(val['implementation']):
                                        file_stats['todos_found'] += 1
                                        detailed_issues[pattern_file.name].append(
                                            f"{pid}: automation.{key}.implementation has TODO"
                                        )
                    
                    if 'implementation' in pattern:
                        file_stats['has_implementation'] += 1
                    
                    if 'ssp_mapping' in pattern:
                        file_stats['has_ssp_mapping'] += 1
                        # Check for TODO in SSP mapping
                        ssp = pattern['ssp_mapping']
                        if 'ssp_sections' in ssp:
                            for section in ssp['ssp_sections']:
                                desc = section.get('description_template', '')
                                if 'TODO' in str(desc):
                                    file_stats['todos_found'] += 1
                                    detailed_issues[pattern_file.name].append(
                                        f"{pid}: ssp_mapping has TODO in description"
                                    )
                    
                    if 'evidence_collection' in pattern.get('finding', {}):
                        file_stats['has_evidence_collection'] += 1
                    
                    if 'azure_guidance' in pattern:
                        file_stats['has_azure_guidance'] += 1
                    
                    if 'compliance_frameworks' in pattern:
                        file_stats['has_compliance_frameworks'] += 1
                    
                    if 'testing' in pattern:
                        file_stats['has_testing'] += 1
                        # Check for TODO in testing
                        testing = pattern['testing']
                        for test_type in ['positive_test_cases', 'negative_test_cases']:
                            if test_type in testing:
                                for test in testing[test_type]:
                                    if 'TODO' in str(test.get('description', '')) or 'TODO' in str(test.get('code_sample', '')):
                                        file_stats['todos_found'] += 1
                                        detailed_issues[pattern_file.name].append(
                                            f"{pid}: testing.{test_type} has TODO"
                                        )
                
                stats[pattern_file.name] = file_stats
                
            except Exception as e:
                print(f"Error processing {pattern_file.name}: {e}")
                stats[pattern_file.name] = {'error': str(e)}
    
    # Print summary
    print("=" * 80)
    print("PATTERN FILE ANALYSIS - V2 SCHEMA COMPLETENESS")
    print("=" * 80)
    print()
    
    total_patterns = sum(s.get('count', 0) for s in stats.values())
    total_todos = sum(s.get('todos_found', 0) for s in stats.values())
    
    print(f"Total pattern files: {len(stats)}")
    print(f"Total patterns: {total_patterns}")
    print(f"Total TODO items found: {total_todos}")
    print()
    
    for filename in sorted(stats.keys()):
        file_stats = stats[filename]
        if 'error' in file_stats:
            print(f"\n{filename}: ERROR - {file_stats['error']}")
            continue
            
        count = file_stats['count']
        print(f"\n{filename} ({count} patterns):")
        print(f"  Evidence Artifacts:       {file_stats['has_evidence_artifacts']}/{count}")
        print(f"  Automation:               {file_stats['has_automation']}/{count}")
        print(f"  Implementation:           {file_stats['has_implementation']}/{count}")
        print(f"  SSP Mapping:              {file_stats['has_ssp_mapping']}/{count}")
        print(f"  Evidence Collection:      {file_stats['has_evidence_collection']}/{count}")
        print(f"  Azure Guidance:           {file_stats['has_azure_guidance']}/{count}")
        print(f"  Compliance Frameworks:    {file_stats['has_compliance_frameworks']}/{count}")
        print(f"  Testing:                  {file_stats['has_testing']}/{count}")
        print(f"  TODO items:               {file_stats['todos_found']}")
    
    # Print detailed issues
    if detailed_issues:
        print("\n" + "=" * 80)
        print("DETAILED ISSUES (TODOs)")
        print("=" * 80)
        for filename, issues in sorted(detailed_issues.items()):
            print(f"\n{filename}:")
            for issue in issues:
                print(f"  - {issue}")
    
    # Save to JSON for further processing
    with open('pattern_analysis_results.json', 'w') as f:
        json.dump({
            'summary': {
                'total_files': len(stats),
                'total_patterns': total_patterns,
                'total_todos': total_todos
            },
            'file_stats': stats,
            'detailed_issues': dict(detailed_issues)
        }, f, indent=2)
    
    print(f"\n\nResults saved to pattern_analysis_results.json")

if __name__ == '__main__':
    analyze_patterns()
