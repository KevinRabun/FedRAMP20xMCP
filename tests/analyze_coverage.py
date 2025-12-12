"""
Analyze pattern coverage vs KSI requirements
"""
from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from pathlib import Path
from collections import defaultdict

# Load patterns
engine = PatternEngine()
patterns_dir = Path('data/patterns')
for pattern_file in patterns_dir.glob('*.yaml'):
    engine.load_patterns(str(pattern_file))

# Count patterns by family
pattern_counts = defaultdict(int)
for p in engine.patterns.values():
    if p.family:
        pattern_counts[p.family] += 1

# Count KSIs by family
factory = get_factory()
ksi_counts = defaultdict(int)
for ksi_id in factory.list_ksis():
    analyzer = factory.get_analyzer(ksi_id)
    if analyzer and not getattr(analyzer, 'RETIRED', False):
        ksi_counts[analyzer.FAMILY] += 1

# Calculate coverage
print('WEEK 4 PRIORITY ANALYSIS')
print('=' * 70)
print()
print(f'{"Family":<8} {"KSIs":<6} {"Patterns":<10} {"Coverage":<10} Priority')
print('-' * 70)

coverage_data = []
for family in sorted(set(list(pattern_counts.keys()) + list(ksi_counts.keys()))):
    ksis = ksi_counts.get(family, 0)
    patterns = pattern_counts.get(family, 0)
    coverage = (patterns / ksis * 100) if ksis > 0 else 0
    gap = ksis - patterns
    
    # Priority: Low coverage + high KSI count
    priority_score = gap * (100 - coverage) / 100 if ksis > 0 else 0
    
    coverage_data.append({
        'family': family,
        'ksis': ksis,
        'patterns': patterns,
        'coverage': coverage,
        'gap': gap,
        'priority': priority_score
    })

# Sort by priority (descending)
coverage_data.sort(key=lambda x: -x['priority'])

for item in coverage_data:
    family = item['family']
    ksis = item['ksis']
    patterns = item['patterns']
    coverage = item['coverage']
    gap = item['gap']
    priority = item['priority']
    
    priority_label = 'HIGH' if priority > 5 else 'MEDIUM' if priority > 2 else 'LOW'
    print(f'{family:<8} {ksis:<6} {patterns:<10} {coverage:>6.1f}%    {priority_label}')

print()
print(f'Total patterns: {sum(pattern_counts.values())}')
print(f'Total active KSIs: {sum(ksi_counts.values())}')
print(f'Overall coverage: {sum(pattern_counts.values()) / sum(ksi_counts.values()) * 100:.1f}%')
print()
print('TOP 3 PRIORITIES FOR WEEK 4:')
print('-' * 70)
for i, item in enumerate(coverage_data[:3], 1):
    print(f'{i}. {item["family"]}: {item["gap"]} patterns needed ({item["coverage"]:.0f}% coverage)')
