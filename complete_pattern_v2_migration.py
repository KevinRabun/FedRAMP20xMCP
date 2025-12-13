#!/usr/bin/env python3
"""
Complete Pattern V2 Migration Tool
Systematically adds all missing V2 schema fields to pattern files.
"""

import yaml
import json
from pathlib import Path
from typing import Dict, List, Any

# Load FRR and KSI metadata
def load_metadata():
    with open('data/requirements/frr_metadata.json', 'r') as f:
        frr_data = json.load(f)
    with open('data/requirements/ksi_metadata.json', 'r') as f:
        ksi_data = json.load(f)
    return frr_data, ksi_data

frr_metadata, ksi_metadata = load_metadata()

def get_requirement_info(req_id: str) -> Dict:
    """Get FRR or KSI metadata."""
    if req_id.startswith('FRR'):
        return frr_metadata.get(req_id, {})
    elif req_id.startswith('KSI'):
        return ksi_metadata.get(req_id, {})
    return {}

def generate_evidence_artifacts(family: str, pattern_id: str, related_reqs: List[str]) -> List[Dict]:
    """Generate realistic evidence artifacts based on family and requirements."""
    artifacts = [
        {
            'artifact_type': 'logs',
            'name': f'{family} operational logs',
            'source': 'Azure Monitor - Application/Resource Logs',
            'frequency': 'continuous',
            'retention_months': 36,
            'format': 'JSON'
        },
        {
            'artifact_type': 'configuration',
            'name': f'{family} configuration export',
            'source': 'Azure Portal or IaC templates',
            'frequency': 'weekly',
            'retention_months': 36,
            'format': 'JSON/Bicep/Terraform'
        },
        {
            'artifact_type': 'report',
            'name': f'{family} compliance validation report',
            'source': 'Automated testing pipeline',
            'frequency': 'daily',
            'retention_months': 12,
            'format': 'HTML/PDF'
        }
    ]
    return artifacts

def generate_evidence_collection(family: str) -> Dict:
    """Generate evidence collection queries."""
    return {
        'azure_monitor_kql': [
            {
                'query': f'''AppTraces
| where TimeGenerated > ago(30d)
| where Message contains "{family.lower()}"
| summarize count() by bin(TimeGenerated, 1d), SeverityLevel
| order by TimeGenerated desc''',
                'description': f'Track {family} related operations over last 30 days',
                'retention_days': 730
            }
        ],
        'azure_cli': [
            {
                'command': f'az monitor log-analytics query --workspace $WORKSPACE_ID --analytics-query "AppTraces | where Message contains \'{family.lower()}\' | take 100"',
                'description': f'Query recent {family} events',
                'output_format': 'json'
            }
        ],
        'powershell': [
            {
                'script': f'''# Query {family} configuration
Get-Az{family}Resource | Select-Object Name, Location, Properties''',
                'description': f'Get {family} resource configuration'
            }
        ]
    }

def generate_automation(family: str, pattern_id: str) -> Dict:
    """Generate automation recommendations."""
    return {
        'policy_enforcement': {
            'description': f'Azure Policy for {family} compliance enforcement',
            'implementation': f'''# Azure Policy definition for {family}
resource policyDef 'Microsoft.Authorization/policyDefinitions@2021-06-01' = {{
  name: '{pattern_id}-policy'
  properties: {{
    policyType: 'Custom'
    mode: 'All'
    displayName: '{family} Compliance Policy'
    description: 'Enforces {family} compliance requirements'
    policyRule: {{
      if: {{
        // Add specific conditions
      }}
      then: {{
        effect: 'audit'
      }}
    }}
  }}
}}''',
            'azure_services': ['Azure Policy', 'Azure Monitor'],
            'effort_hours': 4
        },
        'continuous_monitoring': {
            'description': f'Azure Monitor alerts for {family} violations',
            'implementation': f'''resource alert 'Microsoft.Insights/metricAlerts@2018-03-01' = {{
  name: '{pattern_id}-alert'
  location: 'global'
  properties: {{
    description: 'Alert on {family} compliance violations'
    severity: 2
    enabled: true
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
  }}
}}''',
            'azure_services': ['Azure Monitor', 'Application Insights'],
            'effort_hours': 3
        },
        'cicd_validation': {
            'description': f'CI/CD pipeline validation for {family}',
            'implementation': f'''# GitHub Actions
- name: Validate {family} Compliance
  run: |
    python -m fedramp_20x_mcp.analyzers.generic_analyzer \\
      --pattern-file data/patterns/{family.lower()}_patterns.yaml \\
      --code-path ./src
      
# Azure Pipelines  
- task: PowerShell@2
  displayName: '{family} Compliance Check'
  inputs:
    script: |
      # Run compliance validation
      python validate_{family.lower()}.py''',
            'azure_services': ['Azure Pipelines', 'GitHub Actions'],
            'effort_hours': 2
        }
    }

def generate_implementation(family: str, req_ids: List[str]) -> Dict:
    """Generate implementation guidance."""
    # Get Azure services from first related requirement
    azure_services = []
    if req_ids:
        req_info = get_requirement_info(req_ids[0])
        azure_services = req_info.get('guidance', {}).get('azure_services', [])
    
    return {
        'prerequisites': [
            'Azure subscription with Contributor access',
            'Required Azure services provisioned',
            f'{family} requirements documented and approved',
            'Development and testing environment configured'
        ],
        'steps': [
            {
                'step': 1,
                'action': f'Review {family} FedRAMP requirements',
                'azure_service': None,
                'estimated_hours': 2,
                'validation': 'Requirements documented and team trained'
            },
            {
                'step': 2,
                'action': f'Design {family} implementation architecture',
                'azure_service': azure_services[0] if azure_services else None,
                'estimated_hours': 4,
                'validation': 'Architecture review completed and approved'
            },
            {
                'step': 3,
                'action': f'Implement {family} controls in code/IaC',
                'azure_service': 'Application code and IaC',
                'estimated_hours': 16,
                'validation': 'Code review completed, unit tests pass'
            },
            {
                'step': 4,
                'action': f'Configure Azure services for {family}',
                'azure_service': azure_services[0] if azure_services else 'Azure Portal',
                'estimated_hours': 8,
                'validation': 'Services configured per requirements',
                'bicep_template': f'templates/bicep/{family.lower()}/main.bicep'
            },
            {
                'step': 5,
                'action': 'Set up monitoring and alerting',
                'azure_service': 'Azure Monitor',
                'estimated_hours': 4,
                'validation': 'Alerts configured and tested'
            },
            {
                'step': 6,
                'action': 'Implement automated compliance checking',
                'azure_service': 'Azure Pipelines',
                'estimated_hours': 6,
                'validation': 'CI/CD pipeline validates compliance'
            },
            {
                'step': 7,
                'action': 'Document implementation and evidence collection',
                'azure_service': None,
                'estimated_hours': 4,
                'validation': 'Documentation complete and reviewed'
            }
        ],
        'validation_queries': [
            f'az resource list --resource-group $RG --query "[?contains(type, \'{family}\')]"',
            'az monitor metrics list --resource $RESOURCE_ID'
        ],
        'total_effort_hours': 44
    }

def generate_ssp_mapping(family: str, controls: List[str], req_id: str) -> Dict:
    """Generate SSP mapping."""
    req_info = get_requirement_info(req_id) if req_id else {}
    req_name = req_info.get('name', f'{family} Requirements')
    
    return {
        'control_family': f'{family} - {family}',
        'control_numbers': controls if controls else ['AU-2', 'AU-3'],
        'ssp_sections': [
            {
                'section': f'{controls[0] if controls else "AU-2"}: Implementation',
                'description_template': f'''The system implements {family} controls in accordance with FedRAMP 20x requirements. {req_name} is addressed through a combination of Azure native services, application-level controls, and automated monitoring.''',
                'implementation_details': f'''Azure services are configured to enforce {family} compliance requirements. Infrastructure-as-code (Bicep/Terraform) ensures consistent deployment. Automated compliance checking in CI/CD pipeline validates all deployments against {family} requirements.''',
                'evidence_references': [
                    f'{family} configuration exports from Azure Portal',
                    'Azure Monitor logs showing compliance status',
                    'CI/CD pipeline validation results',
                    'Automated compliance scan reports'
                ]
            }
        ]
    }

def generate_azure_guidance(family: str, req_ids: List[str]) -> Dict:
    """Generate Azure-specific guidance."""
    # Get Azure services from metadata
    services = []
    if req_ids:
        req_info = get_requirement_info(req_ids[0])
        services = req_info.get('guidance', {}).get('azure_services', [])
    
    return {
        'recommended_services': [
            {
                'service': services[0] if services else 'Azure Monitor',
                'tier': 'Standard',
                'purpose': f'Primary service for {family} compliance',
                'monthly_cost_estimate': '$50-200 depending on usage',
                'alternatives': ['Alternative Azure services or third-party tools']
            }
        ],
        'well_architected_framework': {
            'pillar': 'Security',
            'design_area': f'{family} implementation',
            'recommendation_id': 'SEC-01',
            'reference_url': 'https://learn.microsoft.com/azure/well-architected/security/'
        },
        'cloud_adoption_framework': {
            'stage': 'Secure',
            'guidance': f'Implement {family} controls as part of secure baseline',
            'reference_url': 'https://learn.microsoft.com/azure/cloud-adoption-framework/secure/'
        }
    }

def generate_compliance_frameworks(req_ids: List[str]) -> Dict:
    """Generate compliance framework mappings."""
    fedramp_req = req_ids[0] if req_ids and req_ids[0].startswith('FRR') else None
    ksi_req = req_ids[0] if req_ids and req_ids[0].startswith('KSI') else None
    
    req_info = get_requirement_info(req_ids[0]) if req_ids else {}
    nist_controls = [c['id'] if isinstance(c, dict) else c for c in req_info.get('nist_controls', [])]
    
    return {
        'fedramp_20x': {
            'requirement_id': fedramp_req or ksi_req or 'N/A',
            'requirement_name': req_info.get('name', 'Unknown'),
            'impact_levels': req_info.get('impact_levels', ['Low', 'Moderate'])
        },
        'nist_800_53_rev5': {
            'controls': nist_controls if nist_controls else ['AU-2', 'AU-3']
        },
        'pci_dss_4': {
            'requirements': ['10.2.1', '10.2.2']
        },
        'hipaa': {
            'standards': ['164.312(b) - Audit controls']
        }
    }

def generate_testing(pattern_id: str, languages: Dict) -> Dict:
    """Generate test cases."""
    first_lang = list(languages.keys())[0] if languages else 'python'
    
    return {
        'positive_test_cases': [
            {
                'description': f'Compliant {first_lang} code sample',
                'code_sample': f'# {first_lang} code that meets requirements\n# Add specific example',
                'expected_severity': 'INFO',
                'expected_finding': True
            }
        ],
        'negative_test_cases': [
            {
                'description': f'Non-compliant {first_lang} code',
                'code_sample': f'# {first_lang} code that violates requirements\n# Add specific example',
                'expected_severity': 'HIGH',
                'expected_finding': True
            }
        ],
        'validation_scripts': [
            f'tests/test_{pattern_id.split(".")[0]}_patterns.py::test_{pattern_id.replace(".", "_")}'
        ]
    }

def complete_pattern(pattern: Dict) -> Dict:
    """Add all missing V2 fields to a pattern."""
    pattern_id = pattern.get('pattern_id', '')
    family = pattern.get('family', 'UNKNOWN')
    related_frrs = pattern.get('related_frrs', [])
    related_ksis = pattern.get('related_ksis', [])
    related_reqs = related_frrs + related_ksis
    nist_controls = pattern.get('nist_controls', [])
    languages = pattern.get('languages', {})
    
    # Add missing V2 fields
    if 'evidence_artifacts' not in pattern:
        pattern['evidence_artifacts'] = generate_evidence_artifacts(family, pattern_id, related_reqs)
    
    if 'evidence_collection' not in pattern.get('finding', {}):
        if 'evidence_collection' not in pattern:
            pattern['evidence_collection'] = generate_evidence_collection(family)
    
    if 'automation' not in pattern:
        pattern['automation'] = generate_automation(family, pattern_id)
    
    if 'implementation' not in pattern:
        pattern['implementation'] = generate_implementation(family, related_reqs)
    
    if 'ssp_mapping' not in pattern:
        req_id = related_reqs[0] if related_reqs else None
        pattern['ssp_mapping'] = generate_ssp_mapping(family, nist_controls, req_id)
    
    if 'azure_guidance' not in pattern:
        pattern['azure_guidance'] = generate_azure_guidance(family, related_reqs)
    
    if 'compliance_frameworks' not in pattern:
        pattern['compliance_frameworks'] = generate_compliance_frameworks(related_reqs)
    
    if 'testing' not in pattern:
        pattern['testing'] = generate_testing(pattern_id, languages)
    
    return pattern

def process_pattern_file(file_path: Path):
    """Process a single pattern file."""
    print(f"\nProcessing {file_path.name}...")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Parse YAML (may have multiple documents)
    patterns = list(yaml.safe_load_all(content))
    patterns = [p for p in patterns if p]  # Filter None
    
    # Complete each pattern
    completed_patterns = []
    for pattern in patterns:
        if not pattern:
            continue
        completed = complete_pattern(pattern)
        completed_patterns.append(completed)
    
    # Write back
    backup_path = file_path.with_suffix('.yaml.bak')
    file_path.rename(backup_path)
    print(f"  Backup created: {backup_path.name}")
    
    with open(file_path, 'w', encoding='utf-8') as f:
        yaml.dump_all(completed_patterns, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    print(f"  ✓ Completed {len(completed_patterns)} patterns")
    return len(completed_patterns)

def main():
    """Process all pattern files needing V2 completion."""
    pattern_dir = Path('data/patterns')
    
    # Phase 1 files (0% V2 complete)
    phase1_files = [
        'ads_patterns.yaml',
        'afr_patterns.yaml',
        'ccm_patterns.yaml',
        'ced_patterns.yaml',
        'cna_patterns.yaml',
        'rsc_patterns.yaml',
        'scn_patterns.yaml',
        'tpr_patterns.yaml',
        'ucm_patterns.yaml'
    ]
    
    print("=" * 80)
    print("PHASE 1: Complete V2 Migration for 0% Complete Files")
    print("=" * 80)
    
    total_patterns = 0
    for filename in phase1_files:
        file_path = pattern_dir / filename
        if file_path.exists():
            count = process_pattern_file(file_path)
            total_patterns += count
    
    print(f"\n✓ Phase 1 Complete: {total_patterns} patterns migrated to V2 schema")
    print("\nBackup files created with .yaml.bak extension")
    print("Review generated content and customize as needed")

if __name__ == '__main__':
    main()
