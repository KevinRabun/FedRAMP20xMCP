#!/usr/bin/env python3
"""Check AFR KSI Code-Detectability"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory

factory = get_factory()

print('AFR KSI CODE-DETECTABILITY ANALYSIS:')
print('=' * 80)
print(f'{"KSI ID":<15} {"Name":<45} {"Code-Detectable"}')
print('-' * 80)

afr_ksis = [k for k in factory.list_ksis() if k.startswith('KSI-AFR-')]
code_detectable = []
process_based = []

for ksi_id in sorted(afr_ksis):
    analyzer = factory.get_analyzer(ksi_id)
    if analyzer.CODE_DETECTABLE:
        code_detectable.append((ksi_id, analyzer.KSI_NAME))
        status = 'YES ✓'
    else:
        process_based.append((ksi_id, analyzer.KSI_NAME))
        status = 'NO (process-based)'
    print(f'{ksi_id:<15} {analyzer.KSI_NAME:<45} {status}')

print('=' * 80)
print(f'\nCode-Detectable AFR KSIs ({len(code_detectable)}):')
for ksi_id, name in code_detectable:
    print(f'  - {ksi_id}: {name}')

print(f'\nProcess-Based AFR KSIs ({len(process_based)}):')
for ksi_id, name in process_based:
    print(f'  - {ksi_id}: {name}')
