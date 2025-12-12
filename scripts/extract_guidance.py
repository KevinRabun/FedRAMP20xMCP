#!/usr/bin/env python3
"""
Enhanced Metadata Extraction with Guidance Information

This script extends the basic metadata extraction to include guidance fields:
- evidence_collection: What artifacts to collect for audits
- implementation_checklist: Step-by-step implementation tasks
- automation_opportunities: What can be automated
- azure_services: Recommended Azure services
- process_based: True for process-based (NOT_IMPLEMENTED) requirements
- requires_documentation: True if policy/procedure docs needed

Phase 1 completion: Extract comprehensive metadata including guidance.
"""

import ast
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


def extract_azure_services_from_code(code: str, family: str) -> List[str]:
    """Extract Azure service mentions from code and comments."""
    services = set()
    
    # Common Azure services by family
    family_services = {
        'IAM': ['Microsoft Entra ID', 'Conditional Access', 'Privileged Identity Management', 'Azure RBAC'],
        'MLA': ['Azure Monitor', 'Log Analytics', 'Microsoft Sentinel', 'Application Insights'],
        'AFR': ['Microsoft Defender for Cloud', 'Azure Policy', 'Security Center'],
        'SVC': ['Azure Key Vault', 'Azure Automation', 'Managed Identity'],
        'CNA': ['Azure Virtual Network', 'Azure Bastion', 'Azure Firewall', 'Network Security Groups'],
        'VDR': ['Microsoft Defender for Cloud', 'Azure Security Center', 'Vulnerability Assessment'],
        'ADS': ['Azure API Management', 'Azure Front Door', 'Application Gateway'],
        'CED': ['Microsoft Learn', 'Azure Blob Storage', 'Log Analytics'],
        'RPL': ['Azure Site Recovery', 'Azure Backup', 'Availability Zones'],
        'PIY': ['Azure Private Link', 'Azure Confidential Computing'],
        'INR': ['Azure Monitor', 'Microsoft Sentinel', 'Log Analytics'],
    }
    
    # Always include these
    base_services = ['Azure Monitor', 'Log Analytics', 'Azure Blob Storage']
    services.update(base_services)
    
    # Add family-specific services
    if family in family_services:
        services.update(family_services[family])
    
    # Look for explicit mentions in code
    azure_pattern = r'(?:Microsoft |Azure |Entra )[A-Z][a-zA-Z ]+'
    matches = re.findall(azure_pattern, code)
    for match in matches:
        cleaned = match.strip()
        if cleaned and len(cleaned) > 5:  # Filter out short matches
            services.add(cleaned)
    
    return sorted(list(services))


def extract_evidence_collection(family: str, requirement_name: str, code_detectable: bool) -> List[str]:
    """Generate evidence collection guidance based on family and detectability."""
    evidence = []
    
    # Common evidence for all requirements
    evidence.append("Configuration export from Azure Portal (JSON format)")
    evidence.append("Azure Policy compliance reports")
    evidence.append("Azure Monitor logs showing compliance status")
    
    # Family-specific evidence
    if family == 'IAM':
        evidence.extend([
            "Microsoft Entra ID configuration exports",
            "Conditional Access policy JSON exports",
            "Sign-in logs with MFA events",
            "Azure RBAC role assignments report",
            "Privileged Identity Management (PIM) activation logs"
        ])
    elif family == 'MLA':
        evidence.extend([
            "Log Analytics workspace configuration",
            "Diagnostic settings for all resources",
            "Alert rules and action groups",
            "Log retention policy documentation",
            "Sample logs demonstrating collection"
        ])
    elif family == 'AFR' or family == 'VDR':
        evidence.extend([
            "Microsoft Defender for Cloud security posture scores",
            "Vulnerability assessment scan results",
            "Remediation tracking reports",
            "Compliance dashboard screenshots",
            "Security recommendations status"
        ])
    elif family == 'SVC':
        evidence.extend([
            "Azure Key Vault configuration",
            "Secret rotation policies",
            "Access policies or RBAC assignments",
            "Audit logs for secret access",
            "Managed Identity assignments"
        ])
    elif family == 'CNA':
        evidence.extend([
            "Network topology diagrams",
            "NSG rule exports",
            "Azure Firewall configuration",
            "Virtual network configuration",
            "DDoS protection settings"
        ])
    elif family == 'CED':
        evidence.extend([
            "Training completion reports",
            "Training content versions",
            "Quiz/assessment results",
            "Attendance records",
            "Annual acknowledgment forms"
        ])
    elif family == 'RPL':
        evidence.extend([
            "Recovery objectives documentation (RTO/RPO)",
            "Disaster recovery plan",
            "Recovery test results",
            "Backup configuration and schedules",
            "Failover test reports"
        ])
    elif family == 'INR':
        evidence.extend([
            "Incident response plan",
            "Incident logs and tickets",
            "After-action reports",
            "Communication procedures",
            "Escalation matrix"
        ])
    elif family == 'PIY':
        evidence.extend([
            "Privacy policy documentation",
            "Data classification records",
            "Privacy impact assessments",
            "Third-party risk assessments",
            "Vendor security questionnaires"
        ])
    
    # For process-based requirements
    if not code_detectable:
        evidence.extend([
            "Standard Operating Procedures (SOPs)",
            "Policy documentation with approval signatures",
            "Process flowcharts or diagrams",
            "Training materials for procedures"
        ])
    
    return evidence


def extract_implementation_checklist(family: str, requirement_name: str, code_detectable: bool) -> List[str]:
    """Generate implementation checklist based on family and detectability."""
    checklist = []
    
    # Common checklist items
    checklist.extend([
        "Review FedRAMP 20x requirement documentation",
        "Identify systems and resources in scope",
        "Create resource group for FedRAMP resources",
        "Set up Azure Key Vault for secrets management",
        "Configure Log Analytics workspace"
    ])
    
    # Family-specific checklist
    if family == 'IAM':
        checklist.extend([
            "Enable Microsoft Entra ID Premium P2",
            "Configure Conditional Access policies",
            "Set up phishing-resistant MFA (FIDO2, certificate-based)",
            "Configure Privileged Identity Management (PIM)",
            "Enable Identity Protection",
            "Set up Azure RBAC with least privilege",
            "Test MFA enforcement for all user types"
        ])
    elif family == 'MLA':
        checklist.extend([
            "Deploy Log Analytics workspace",
            "Enable diagnostic settings for all resources",
            "Configure log retention (1 year minimum for FedRAMP)",
            "Set up Azure Monitor alerts",
            "Deploy Microsoft Sentinel (if required)",
            "Create dashboards for compliance monitoring",
            "Test log collection and alerting"
        ])
    elif family == 'AFR' or family == 'VDR':
        checklist.extend([
            "Enable Microsoft Defender for Cloud",
            "Configure vulnerability scanning",
            "Set up security recommendations tracking",
            "Enable Defender plans for all resource types",
            "Configure compliance standards (FedRAMP)",
            "Set up automated remediation where possible",
            "Schedule regular vulnerability scans"
        ])
    elif family == 'SVC':
        checklist.extend([
            "Deploy Azure Key Vault with soft delete",
            "Configure access policies or RBAC",
            "Set up Managed Identities for applications",
            "Implement secret rotation automation",
            "Configure diagnostic logging for Key Vault",
            "Test secret retrieval from applications",
            "Document secret management procedures"
        ])
    elif family == 'CNA':
        checklist.extend([
            "Design network architecture with security zones",
            "Deploy Azure Virtual Network with subnets",
            "Configure Network Security Groups (NSGs)",
            "Set up Azure Firewall or third-party NVA",
            "Enable DDoS Protection Standard",
            "Configure Azure Bastion for secure access",
            "Document network topology and data flows"
        ])
    elif family == 'CED':
        checklist.extend([
            "Select or deploy Learning Management System (LMS)",
            "Develop security awareness training curriculum",
            "Create role-specific training modules",
            "Assign training to employees via Microsoft Entra ID groups",
            "Set up automated training reminders",
            "Configure completion tracking and reporting",
            "Schedule annual training refreshers"
        ])
    elif family == 'RPL':
        checklist.extend([
            "Define Recovery Time Objective (RTO) and Recovery Point Objective (RPO)",
            "Document disaster recovery procedures",
            "Configure Azure Site Recovery or Azure Backup",
            "Set up geo-redundant storage",
            "Deploy across availability zones",
            "Test disaster recovery procedures",
            "Document test results and lessons learned"
        ])
    elif family == 'INR':
        checklist.extend([
            "Develop incident response plan",
            "Set up incident tracking system",
            "Configure Azure Monitor alerts for security events",
            "Enable Microsoft Sentinel for SIEM",
            "Define escalation procedures",
            "Conduct tabletop exercises",
            "Document incident response procedures"
        ])
    
    # For code-detectable requirements, add automation tasks
    if code_detectable:
        checklist.extend([
            "Generate infrastructure-as-code templates (Bicep/Terraform)",
            "Deploy infrastructure via CI/CD pipeline",
            "Implement automated compliance checking",
            "Set up automated evidence collection",
            "Test detection logic against sample code"
        ])
    
    # For process-based requirements, add documentation tasks
    if not code_detectable:
        checklist.extend([
            "Create Standard Operating Procedures (SOPs)",
            "Get policy documentation approved by stakeholders",
            "Train staff on new procedures",
            "Set up periodic compliance reviews",
            "Document evidence collection process"
        ])
    
    return checklist


def extract_automation_opportunities(family: str, code_detectable: bool) -> List[str]:
    """Generate automation opportunities based on family and detectability."""
    automation = []
    
    # Common automation
    automation.extend([
        "Azure Policy for compliance enforcement",
        "Azure Monitor for continuous monitoring",
        "Log Analytics queries for compliance validation",
        "Azure Functions for automated evidence collection",
        "PowerShell/Azure CLI scripts for configuration auditing"
    ])
    
    # Family-specific automation
    if family == 'IAM':
        automation.extend([
            "Conditional Access policy deployment via Bicep/Terraform",
            "PowerShell script to audit MFA methods",
            "Automated user access reviews via PIM",
            "Azure AD reporting API for authentication metrics"
        ])
    elif family == 'MLA':
        automation.extend([
            "Azure Monitor workbooks for compliance dashboards",
            "Automated log export to Azure Blob Storage",
            "KQL queries for security event detection",
            "Azure Logic Apps for alert orchestration"
        ])
    elif family == 'AFR' or family == 'VDR':
        automation.extend([
            "Microsoft Defender for Cloud continuous export",
            "Automated vulnerability scanning in CI/CD",
            "Azure DevOps pipeline for security testing",
            "GitHub Advanced Security for code scanning"
        ])
    elif family == 'SVC':
        automation.extend([
            "Azure Automation runbooks for secret rotation",
            "Key Vault event grid notifications",
            "Managed Identity automatic assignment",
            "Terraform for Key Vault infrastructure"
        ])
    elif family == 'CNA':
        automation.extend([
            "Terraform modules for network infrastructure",
            "Azure Firewall rule deployment via IaC",
            "NSG flow logs analysis with Network Watcher",
            "Automated network topology discovery"
        ])
    elif family == 'CED':
        automation.extend([
            "Power Automate for training reminders",
            "Microsoft Entra ID learning path assignments",
            "Azure Function to export training completion reports",
            "LMS integration via API for automated tracking"
        ])
    
    # For code-detectable requirements
    if code_detectable:
        automation.extend([
            "CI/CD pipeline integration for compliance scanning",
            "Pre-commit hooks for security validation",
            "Automated pull request checks",
            "Policy-as-code enforcement in deployment pipelines"
        ])
    
    return automation


def enhance_metadata_with_guidance(metadata: Dict[str, Any], raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """Add guidance fields to metadata."""
    family = metadata['family']
    name = metadata['name']
    code_detectable = metadata['code_detectable']
    
    # Extract Azure services from code
    code = raw_data.get('module_docstring', '') + '\n' + raw_data.get('docstring', '')
    azure_services = extract_azure_services_from_code(code, family)
    
    # Generate guidance
    guidance = {
        'evidence_collection': extract_evidence_collection(family, name, code_detectable),
        'implementation_checklist': extract_implementation_checklist(family, name, code_detectable),
        'automation_opportunities': extract_automation_opportunities(family, code_detectable),
        'azure_services': azure_services,
        'process_based': not code_detectable,
        'requires_documentation': not code_detectable
    }
    
    metadata['guidance'] = guidance
    return metadata


def parse_analyzer_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Parse a single analyzer file and extract metadata."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        
        # Find the analyzer class
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name.endswith('Analyzer'):
                attributes = extract_class_attributes(node)
                docstring = extract_docstring(node)
                
                # Extract module docstring
                module_docstring = None
                if (tree.body and 
                    isinstance(tree.body[0], ast.Expr) and 
                    isinstance(tree.body[0].value, ast.Constant)):
                    module_docstring = tree.body[0].value.value
                
                return {
                    'class_name': node.name,
                    'file_path': str(file_path),
                    'attributes': attributes,
                    'docstring': docstring,
                    'module_docstring': module_docstring,
                    'full_code': content
                }
        
        return None
    
    except Exception as e:
        print(f"Error parsing {file_path}: {e}", file=sys.stderr)
        return None


def extract_class_attributes(node: ast.ClassDef) -> Dict[str, Any]:
    """Extract class-level attributes from an analyzer class."""
    attributes = {}
    
    for item in node.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    attr_name = target.id
                    try:
                        value = ast.literal_eval(item.value)
                        attributes[attr_name] = value
                    except (ValueError, TypeError):
                        attributes[attr_name] = ast.unparse(item.value)
    
    return attributes


def extract_docstring(node: ast.ClassDef) -> Optional[str]:
    """Extract docstring from class."""
    if (node.body and 
        isinstance(node.body[0], ast.Expr) and 
        isinstance(node.body[0].value, ast.Constant)):
        return node.body[0].value.value
    return None


def normalize_ksi_metadata(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize extracted KSI metadata to standard schema with guidance."""
    attrs = raw_data['attributes']
    
    # Extract NIST controls
    nist_controls = []
    if 'NIST_CONTROLS' in attrs:
        controls_raw = attrs['NIST_CONTROLS']
        if isinstance(controls_raw, list):
            for item in controls_raw:
                if isinstance(item, tuple) and len(item) >= 2:
                    nist_controls.append({'id': item[0], 'name': item[1]})
                elif isinstance(item, str):
                    nist_controls.append({'id': item, 'name': ''})
    
    # Extract impact levels
    impact_levels = []
    if attrs.get('IMPACT_LOW'):
        impact_levels.append('Low')
    if attrs.get('IMPACT_MODERATE'):
        impact_levels.append('Moderate')
    if attrs.get('IMPACT_HIGH'):
        impact_levels.append('High')
    
    # Extract related requirements
    related_ksis = attrs.get('RELATED_KSIS', [])
    if isinstance(related_ksis, str):
        related_ksis = [related_ksis]
    
    related_frrs = attrs.get('RELATED_FRRS', [])
    if isinstance(related_frrs, str):
        related_frrs = [related_frrs]
    
    metadata = {
        'id': attrs.get('KSI_ID', ''),
        'name': attrs.get('KSI_NAME', ''),
        'statement': attrs.get('KSI_STATEMENT', ''),
        'family': attrs.get('FAMILY', ''),
        'family_name': attrs.get('FAMILY_NAME', ''),
        'impact_levels': impact_levels,
        'nist_controls': nist_controls,
        'code_detectable': attrs.get('CODE_DETECTABLE', False),
        'implementation_status': attrs.get('IMPLEMENTATION_STATUS', 'NOT_IMPLEMENTED'),
        'retired': attrs.get('RETIRED', False),
        'related_ksis': related_ksis,
        'related_frrs': related_frrs,
        'source_file': raw_data['file_path'],
        'class_name': raw_data['class_name']
    }
    
    # Add guidance
    metadata = enhance_metadata_with_guidance(metadata, raw_data)
    
    return metadata


def normalize_frr_metadata(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize extracted FRR metadata to standard schema with guidance."""
    attrs = raw_data['attributes']
    
    # Extract NIST controls
    nist_controls = []
    if 'NIST_CONTROLS' in attrs:
        controls_raw = attrs['NIST_CONTROLS']
        if isinstance(controls_raw, list):
            for item in controls_raw:
                if isinstance(item, tuple) and len(item) >= 2:
                    nist_controls.append({'id': item[0], 'name': item[1]})
                elif isinstance(item, str):
                    nist_controls.append({'id': item, 'name': ''})
    
    # Extract impact levels
    impact_levels = []
    if attrs.get('IMPACT_LOW'):
        impact_levels.append('Low')
    if attrs.get('IMPACT_MODERATE'):
        impact_levels.append('Moderate')
    if attrs.get('IMPACT_HIGH'):
        impact_levels.append('High')
    
    # Extract related requirements
    related_ksis = attrs.get('RELATED_KSIS', [])
    if isinstance(related_ksis, str):
        related_ksis = [related_ksis]
    
    related_frrs = attrs.get('RELATED_FRRS', [])
    if isinstance(related_frrs, str):
        related_frrs = [related_frrs]
    
    metadata = {
        'id': attrs.get('FRR_ID', ''),
        'name': attrs.get('FRR_NAME', ''),
        'statement': attrs.get('FRR_STATEMENT', ''),
        'family': attrs.get('FAMILY', ''),
        'family_name': attrs.get('FAMILY_NAME', ''),
        'primary_keyword': attrs.get('PRIMARY_KEYWORD', ''),
        'impact_levels': impact_levels,
        'nist_controls': nist_controls,
        'code_detectable': attrs.get('CODE_DETECTABLE', False),
        'implementation_status': attrs.get('IMPLEMENTATION_STATUS', 'NOT_IMPLEMENTED'),
        'related_ksis': related_ksis,
        'related_frrs': related_frrs,
        'source_file': raw_data['file_path'],
        'class_name': raw_data['class_name']
    }
    
    # Add guidance
    metadata = enhance_metadata_with_guidance(metadata, raw_data)
    
    return metadata


def extract_ksi_metadata(ksi_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Extract metadata from all KSI analyzer files."""
    ksi_metadata = {}
    
    ksi_files = sorted(ksi_dir.glob('ksi_*.py'))
    print(f"Found {len(ksi_files)} KSI analyzer files")
    
    for file_path in ksi_files:
        if file_path.name in ['__init__.py', 'base.py', 'factory.py']:
            continue
        
        print(f"Processing {file_path.name}...", end=' ')
        raw_data = parse_analyzer_file(file_path)
        
        if raw_data and 'KSI_ID' in raw_data['attributes']:
            metadata = normalize_ksi_metadata(raw_data)
            ksi_id = metadata['id']
            ksi_metadata[ksi_id] = metadata
            print(f"✓ {ksi_id}")
        else:
            print("✗ (no metadata found)")
    
    return ksi_metadata


def extract_frr_metadata(frr_dir: Path) -> Dict[str, Dict[str, Any]]:
    """Extract metadata from all FRR analyzer files."""
    frr_metadata = {}
    
    frr_files = sorted(frr_dir.glob('frr_*.py'))
    print(f"Found {len(frr_files)} FRR analyzer files")
    
    for file_path in frr_files:
        if file_path.name in ['__init__.py', 'base.py', 'factory.py']:
            continue
        
        print(f"Processing {file_path.name}...", end=' ')
        raw_data = parse_analyzer_file(file_path)
        
        if raw_data and 'FRR_ID' in raw_data['attributes']:
            metadata = normalize_frr_metadata(raw_data)
            frr_id = metadata['id']
            frr_metadata[frr_id] = metadata
            print(f"✓ {frr_id}")
        else:
            print("✗ (no metadata found)")
    
    return frr_metadata


def generate_summary(ksi_metadata: Dict, frr_metadata: Dict) -> Dict[str, Any]:
    """Generate summary statistics."""
    ksi_families = {}
    frr_families = {}
    
    for ksi_id, data in ksi_metadata.items():
        family = data['family']
        ksi_families[family] = ksi_families.get(family, 0) + 1
    
    for frr_id, data in frr_metadata.items():
        family = data['family']
        frr_families[family] = frr_families.get(family, 0) + 1
    
    ksi_process_based = sum(1 for d in ksi_metadata.values() if d.get('guidance', {}).get('process_based', False))
    frr_process_based = sum(1 for d in frr_metadata.values() if d.get('guidance', {}).get('process_based', False))
    
    return {
        'extraction_date': '2024-12-12',
        'total_ksis': len(ksi_metadata),
        'total_frrs': len(frr_metadata),
        'ksi_families': ksi_families,
        'frr_families': frr_families,
        'ksi_implemented': sum(1 for d in ksi_metadata.values() if d['implementation_status'] == 'IMPLEMENTED'),
        'frr_implemented': sum(1 for d in frr_metadata.values() if d['implementation_status'] == 'IMPLEMENTED'),
        'ksi_retired': sum(1 for d in ksi_metadata.values() if d['retired']),
        'ksi_process_based': ksi_process_based,
        'frr_process_based': frr_process_based,
        'ksi_code_detectable': len(ksi_metadata) - ksi_process_based,
        'frr_code_detectable': len(frr_metadata) - frr_process_based,
    }


def main():
    """Main extraction process."""
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    ksi_dir = project_root / "src" / "fedramp_20x_mcp" / "analyzers" / "ksi"
    frr_dir = project_root / "src" / "fedramp_20x_mcp" / "analyzers" / "frr"
    output_dir = project_root / "data" / "requirements"
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print("FedRAMP 20x Enhanced Metadata Extraction with Guidance")
    print("=" * 80)
    print()
    
    # Extract KSI metadata with guidance
    print("Extracting KSI metadata with guidance...")
    print("-" * 80)
    ksi_metadata = extract_ksi_metadata(ksi_dir)
    print(f"\n✓ Extracted {len(ksi_metadata)} KSI requirements with guidance\n")
    
    # Extract FRR metadata with guidance
    print("Extracting FRR metadata with guidance...")
    print("-" * 80)
    frr_metadata = extract_frr_metadata(frr_dir)
    print(f"\n✓ Extracted {len(frr_metadata)} FRR requirements with guidance\n")
    
    # Generate summary
    summary = generate_summary(ksi_metadata, frr_metadata)
    
    # Write output files
    print("Writing output files...")
    print("-" * 80)
    
    ksi_output = output_dir / "ksi_metadata.json"
    with open(ksi_output, 'w', encoding='utf-8') as f:
        json.dump(ksi_metadata, f, indent=2, ensure_ascii=False)
    print(f"✓ {ksi_output} ({len(ksi_metadata)} KSIs)")
    
    frr_output = output_dir / "frr_metadata.json"
    with open(frr_output, 'w', encoding='utf-8') as f:
        json.dump(frr_metadata, f, indent=2, ensure_ascii=False)
    print(f"✓ {frr_output} ({len(frr_metadata)} FRRs)")
    
    summary_output = output_dir / "extraction_summary.json"
    with open(summary_output, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"✓ {summary_output}")
    
    # Print summary
    print()
    print("=" * 80)
    print("Extraction Summary with Guidance")
    print("=" * 80)
    print(f"Total KSI requirements: {summary['total_ksis']}")
    print(f"  - Code-detectable: {summary['ksi_code_detectable']}")
    print(f"  - Process-based: {summary['ksi_process_based']}")
    print(f"  - Implemented: {summary['ksi_implemented']}")
    print(f"  - Retired: {summary['ksi_retired']}")
    
    print(f"\nTotal FRR requirements: {summary['total_frrs']}")
    print(f"  - Code-detectable: {summary['frr_code_detectable']}")
    print(f"  - Process-based: {summary['frr_process_based']}")
    print(f"  - Implemented: {summary['frr_implemented']}")
    
    print("\n✓ Enhanced metadata extraction complete!")
    print(f"Output directory: {output_dir}")
    print("\nEach requirement now includes:")
    print("  - evidence_collection: Audit artifacts needed")
    print("  - implementation_checklist: Step-by-step tasks")
    print("  - automation_opportunities: What can be automated")
    print("  - azure_services: Recommended Azure services")
    print("  - process_based: True for process-based requirements")
    print("  - requires_documentation: True if docs/policies needed")


if __name__ == '__main__':
    main()
