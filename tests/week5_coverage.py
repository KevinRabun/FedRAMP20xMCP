#!/usr/bin/env python3
"""Week 5 Coverage Analysis - Accurate KSI vs Pattern comparison"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine

# Accurate KSI counts from KSI factory (65 active KSIs total)
KSI_COUNTS = {
    'AFR': 11, 'CED': 4, 'CMT': 4, 'CNA': 8, 'IAM': 7,
    'INR': 3, 'MLA': 5, 'PIY': 8, 'RPL': 4, 'SVC': 9, 'TPR': 2
}

def analyze_coverage():
    """Analyze pattern coverage vs KSI requirements"""
    # Load patterns
    engine = PatternEngine()
    engine.load_all_patterns()
    
    # Count patterns by family
    family_patterns = {}
    for pattern_id, pattern in engine.patterns.items():
        family = pattern.family.upper()
        family_patterns[family] = family_patterns.get(family, 0) + 1
    
    # Calculate coverage
    print('ACCURATE COVERAGE ANALYSIS - WEEK 5 PRIORITIES:')
    print('=' * 80)
    print(f'{"Family":<8} {"KSIs":<6} {"Patterns":<10} {"Coverage":<12} {"Gap":<8} {"Priority"}')
    print('-' * 80)
    
    priorities = []
    for family, ksis in KSI_COUNTS.items():
        patterns = family_patterns.get(family, 0)
        coverage = (patterns / ksis) * 100
        gap = max(0, ksis - patterns)
        
        # Priority score: gap * severity multiplier
        if coverage < 50:
            priority_mult = 3  # HIGH
        elif coverage < 80:
            priority_mult = 2  # MEDIUM
        else:
            priority_mult = 1  # LOW
        
        priority_score = gap * priority_mult
        priorities.append((family, ksis, patterns, coverage, gap, priority_score))
    
    # Sort by priority score (descending)
    priorities.sort(key=lambda x: x[5], reverse=True)
    
    for family, ksis, patterns, coverage, gap, score in priorities:
        if coverage < 50:
            priority = 'HIGH'
        elif coverage < 80:
            priority = 'MEDIUM'
        else:
            priority = 'LOW'
        
        print(f'{family:<8} {ksis:<6} {patterns:<10} {coverage:>6.1f}%     {gap:<8} {priority} (score: {score:.1f})')
    
    print('=' * 80)
    total_ksis = sum(KSI_COUNTS.values())
    total_patterns = sum(family_patterns.get(f, 0) for f in KSI_COUNTS.keys())
    print(f'Total: {total_patterns} patterns for {total_ksis} active KSIs ({(total_patterns/total_ksis)*100:.1f}% coverage)')
    print()
    print('TOP 3 PRIORITIES FOR WEEK 5:')
    for i, (family, ksis, patterns, coverage, gap, score) in enumerate(priorities[:3], 1):
        print(f'{i}. {family}: {ksis} KSIs, {patterns} patterns, {coverage:.1f}% coverage, gap of {gap}')

if __name__ == '__main__':
    analyze_coverage()
