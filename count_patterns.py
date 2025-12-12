#!/usr/bin/env python3
"""Count patterns in YAML files."""
import os
import yaml

pattern_files = [f for f in os.listdir('data/patterns') if f.endswith('.yaml')]
total = 0
families = {}

for f in pattern_files:
    with open(f'data/patterns/{f}', 'r', encoding='utf-8') as file:
        data = yaml.safe_load(file)
        if data and 'patterns' in data:
            count = len(data['patterns'])
            total += count
            family = f.replace('_patterns.yaml', '').upper()
            families[family] = count
            print(f'{f}: {count} patterns')

print(f'\nTotal patterns: {total}')
print(f'\nBy family:')
for family, count in sorted(families.items()):
    print(f'  {family}: {count}')
