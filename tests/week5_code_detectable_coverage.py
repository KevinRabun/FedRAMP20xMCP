#!/usr/bin/env python3
"""Accurate Week 5 Coverage Analysis - Code-Detectable KSIs Only"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine
from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory

# Get actual code-detectable KSI counts
factory = get_factory()
code_detectable_ksis = {}

for ksi_id in factory.list_ksis():
    analyzer = factory.get_analyzer(ksi_id)
    if analyzer.RETIRED:
        continue
    if not analyzer.CODE_DETECTABLE:
        continue
    
    family = ksi_id.split('-')[1]
    code_detectable_ksis[family] = code_detectable_ksis.get(family, 0) + 1

# Load patterns
engine = PatternEngine()
engine.load_all_patterns()

# Count patterns by family
family_patterns = {}
for pattern_id, pattern in engine.patterns.items():
    family = pattern.family.upper()
    family_patterns[family] = family_patterns.get(family, 0) + 1

# Calculate coverage
print('ACCURATE WEEK 5 COVERAGE - CODE-DETECTABLE KSIs ONLY:')
print('=' * 85)
print(f'{"Family":<8} {"Code-Det KSIs":<15} {"Patterns":<10} {"Coverage":<12} {"Gap":<8} {"Status"}')
print('-' * 85)

priorities = []
for family in sorted(set(list(code_detectable_ksis.keys()) + list(family_patterns.keys()))):
    ksis = code_detectable_ksis.get(family, 0)
    patterns = family_patterns.get(family, 0)
    
    if ksis == 0:
        # Family with patterns but no code-detectable KSIs
        continue
    
    coverage = (patterns / ksis) * 100
    gap = max(0, ksis - patterns)
    
    # Priority score
    if coverage < 100:
        priority_mult = 3  # HIGH
    else:
        priority_mult = 0  # COMPLETE
    
    priority_score = gap * priority_mult
    priorities.append((family, ksis, patterns, coverage, gap, priority_score))

# Sort by priority score (descending)
priorities.sort(key=lambda x: x[5], reverse=True)

for family, ksis, patterns, coverage, gap, score in priorities:
    if coverage < 100:
        status = f'INCOMPLETE (need {gap})'
    else:
        status = 'COMPLETE [OK]'
    
    print(f'{family:<8} {ksis:<15} {patterns:<10} {coverage:>6.1f}%     {gap:<8} {status}')

print('=' * 85)
total_code_det_ksis = sum(code_detectable_ksis.values())
total_patterns = sum(family_patterns.get(f, 0) for f in code_detectable_ksis.keys())
print(f'Total: {total_patterns} patterns for {total_code_det_ksis} code-detectable KSIs')
print(f'Overall Coverage: {(total_patterns/total_code_det_ksis)*100:.1f}%')
print()

incomplete = [p for p in priorities if p[4] > 0]
if incomplete:
    print(f'FAMILIES NEEDING PATTERNS ({len(incomplete)}):')
    for family, ksis, patterns, coverage, gap, score in incomplete:
        print(f'  - {family}: {gap} patterns needed ({ksis} KSIs, {patterns} patterns, {coverage:.1f}%)')
else:
    print('*** ALL CODE-DETECTABLE KSIs HAVE PATTERNS! ***')
