#!/usr/bin/env python3
"""Analyze remaining KSIs for Phase 6 planning."""

import asyncio
from src.fedramp_20x_mcp.data_loader import FedRAMPDataLoader

async def main():
    loader = FedRAMPDataLoader()
    data = await loader.load_data()
    all_ksis = [v for k, v in data['requirements'].items() if k.startswith('KSI-')]
    
    # Already implemented KSIs from Phases 1-5
    implemented = [
        'KSI-MLA-05', 'KSI-SVC-06', 'KSI-CNA-01', 'KSI-IAM-03', 'KSI-SVC-03',
        'KSI-IAM-01', 'KSI-SVC-08', 'KSI-PIY-02',  # Phase 1
        'KSI-IAM-02', 'KSI-IAM-06', 'KSI-CNA-02', 'KSI-CNA-04', 'KSI-CNA-06',
        'KSI-SVC-04', 'KSI-SVC-05', 'KSI-MLA-01', 'KSI-MLA-02',  # Phase 2
        'KSI-SVC-01', 'KSI-SVC-02', 'KSI-SVC-07', 'KSI-PIY-01', 'KSI-PIY-03',
        'KSI-CNA-07', 'KSI-IAM-04', 'KSI-IAM-07',  # Phase 3
        'KSI-CMT-01', 'KSI-CMT-02', 'KSI-CMT-03', 'KSI-AFR-01', 'KSI-AFR-02',
        'KSI-CED-01',  # Phase 4
        'KSI-MLA-03', 'KSI-MLA-04', 'KSI-MLA-06', 'KSI-INR-01', 'KSI-INR-02',
        'KSI-AFR-03',  # Phase 5
    ]
    
    print(f"Total KSIs: {len(all_ksis)}")
    print(f"Implemented: {len(implemented)}")
    print(f"Remaining: {len(all_ksis) - len(implemented)}")
    print()
    
    # Group remaining by family
    remaining_ksis = [k for k in all_ksis if k['id'] not in implemented]
    
    families = {}
    for ksi in remaining_ksis:
        family = ksi['id'].split('-')[1]
        if family not in families:
            families[family] = []
        families[family].append(ksi)
    
    # Print by family
    for family in sorted(families.keys()):
        print(f"\n{family} ({len(families[family])} KSIs):")
        for ksi in sorted(families[family], key=lambda x: x['id']):
            name = ksi.get('name', ksi.get('title', 'Unknown'))
            statement = ksi.get('statement', ksi.get('description', ''))
            if len(statement) > 100:
                statement = statement[:100] + '...'
            print(f"  {ksi['id']}: {name}")
            print(f"    {statement}")
    
    # Analyze which are IaC-analyzable
    print("\n" + "="*80)
    print("IaC ANALYSIS SUITABILITY")
    print("="*80)
    
    iac_suitable = []
    runtime_only = []
    
    # Keywords that suggest IaC analysis is possible
    iac_keywords = ['backup', 'recovery', 'encryption', 'configuration', 'policy', 
                    'firewall', 'network', 'storage', 'database', 'retention',
                    'replication', 'snapshot', 'vault', 'key', 'certificate']
    
    # Keywords that suggest runtime/manual analysis only
    runtime_keywords = ['testing', 'monitoring', 'assessment', 'evaluation', 'review',
                       'validation', 'verification', 'documentation', 'training',
                       'process', 'procedure', 'incident', 'response']
    
    for ksi in remaining_ksis:
        name = ksi.get('name', ksi.get('title', ''))
        statement = ksi.get('statement', ksi.get('description', ''))
        text = (name + ' ' + statement).lower()
        
        has_iac = any(keyword in text for keyword in iac_keywords)
        has_runtime = any(keyword in text for keyword in runtime_keywords)
        
        if has_iac and not has_runtime:
            iac_suitable.append(ksi)
        elif has_runtime and not has_iac:
            runtime_only.append(ksi)
        else:
            # Mixed - need manual review
            iac_suitable.append(ksi)
    
    print(f"\nIaC-Suitable KSIs ({len(iac_suitable)}):")
    for ksi in sorted(iac_suitable, key=lambda x: x['id']):
        name = ksi.get('name', ksi.get('title', 'Unknown'))
        print(f"  {ksi['id']}: {name}")
    
    print(f"\nRuntime-Only KSIs ({len(runtime_only)}):")
    for ksi in sorted(runtime_only, key=lambda x: x['id']):
        name = ksi.get('name', ksi.get('title', 'Unknown'))
        print(f"  {ksi['id']}: {name}")

if __name__ == '__main__':
    asyncio.run(main())
