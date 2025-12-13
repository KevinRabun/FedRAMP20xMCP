#!/usr/bin/env python3
"""
Add missing evidence_artifacts and automation fields to existing patterns.
"""

import yaml
import glob
from pathlib import Path
from typing import Dict, List

# Standard evidence artifacts template
STANDARD_EVIDENCE_ARTIFACTS = """evidence_artifacts:
- artifact_type: configuration
  name: Configuration compliance evidence
  source: Azure Resource Graph
  frequency: daily
  retention_months: 36
  format: JSON
- artifact_type: logs
  name: Compliance audit logs
  source: Azure Monitor
  frequency: daily
  retention_months: 36
  format: JSON
- artifact_type: report
  name: Compliance assessment report
  source: Microsoft Defender for Cloud
  frequency: weekly
  retention_months: 36
  format: JSON
"""

# Standard automation template
STANDARD_AUTOMATION = """automation:
  automation_1:
    description: Azure Policy for compliance enforcement
    implementation: |
      # Azure Policy enforcement
      # GitHub Actions
      - name: Compliance Check
        run: |
          python -m fedramp_20x_mcp.analyzers.generic_analyzer \\
            --pattern {pattern_id} \\
            --code-path ./src
      
      # Azure Pipelines
      - task: PowerShell@2
        displayName: 'Compliance Validation'
        inputs:
          script: |
            # Validate compliance
            python validate.py --pattern {pattern_id}
    azure_services:
    - Azure Policy
    - Azure Monitor
    - Microsoft Defender for Cloud
  automation_2:
    description: Continuous monitoring and alerting
    implementation: |
      # Azure Monitor continuous monitoring
      # Log Analytics Query
      AzureActivity
      | where CategoryValue == "Policy" or CategoryValue == "Security"
      | where ResourceId contains "{pattern_id}"
      | project TimeGenerated, ResourceId, OperationName, ActivityStatusValue
    azure_services:
    - Azure Monitor
    - Log Analytics
    - Azure Alerts
"""

def add_missing_fields_to_pattern(pattern_dict: Dict, pattern_id: str) -> Dict:
    """Add missing evidence_artifacts and automation to a pattern."""
    modified = False
    
    # Add evidence_artifacts if missing
    if 'evidence_artifacts' not in pattern_dict or not pattern_dict['evidence_artifacts']:
        # Parse YAML template
        evidence_data = yaml.safe_load(STANDARD_EVIDENCE_ARTIFACTS)
        pattern_dict['evidence_artifacts'] = evidence_data['evidence_artifacts']
        modified = True
        print(f"  Added evidence_artifacts to {pattern_id}")
    
    # Add automation if missing
    if 'automation' not in pattern_dict or not pattern_dict['automation']:
        # Parse YAML template and substitute pattern_id
        automation_yaml = STANDARD_AUTOMATION.replace('{pattern_id}', pattern_id)
        automation_data = yaml.safe_load(automation_yaml)
        pattern_dict['automation'] = automation_data['automation']
        modified = True
        print(f"  Added automation to {pattern_id}")
    
    return pattern_dict, modified

def process_pattern_file(file_path: Path):
    """Process a single pattern file to add missing fields."""
    print(f"\nProcessing {file_path.name}...")
    
    # Read all documents
    with open(file_path, 'r', encoding='utf-8') as f:
        documents = list(yaml.safe_load_all(f))
    
    # Process each document
    modified_count = 0
    for i, doc in enumerate(documents):
        if doc and 'pattern_id' in doc:
            pattern_id = doc['pattern_id']
            doc, modified = add_missing_fields_to_pattern(doc, pattern_id)
            if modified:
                documents[i] = doc
                modified_count += 1
    
    # Write back if any modifications
    if modified_count > 0:
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.safe_dump_all(documents, f, 
                             default_flow_style=False, 
                             allow_unicode=True,
                             sort_keys=False,
                             width=1000)
        print(f"  Updated {modified_count} patterns in {file_path.name}")
    else:
        print(f"  No changes needed for {file_path.name}")
    
    return modified_count

def main():
    patterns_dir = Path(__file__).parent.parent / "data/patterns"
    
    print("Adding missing evidence_artifacts and automation to patterns...")
    
    total_modified = 0
    for file in sorted(patterns_dir.glob("*_patterns.yaml")):
        count = process_pattern_file(file)
        total_modified += count
    
    print(f"\n✓ Successfully updated {total_modified} patterns!")

if __name__ == "__main__":
    main()
