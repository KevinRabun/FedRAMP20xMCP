#!/usr/bin/env python3
"""
Review and fix all FRR analyzers to ensure correctness.

Checks:
1. NIST controls mapping (add appropriate controls based on requirement type)
2. CODE_DETECTABLE accuracy (many are incorrectly marked as "Partial")
3. Related KSIs (add based on requirement content)
4. Detection strategy consistency

Fixes based on requirement analysis and FedRAMP 20x guidance.
"""
import re
from pathlib import Path
from typing import Dict, List, Tuple

# NIST control mappings by FRR family and requirement type
NIST_CONTROL_MAPPINGS = {
    # Authorization Data Sharing - Program Management & Planning
    'ADS': {
        'default': [
            ('PM-9', 'Risk Management Strategy'),
            ('PL-2', 'System Security Plan'),
            ('SA-4', 'Acquisition Process'),
            ('SA-9', 'External System Services'),
        ],
        'access': [  # Access management (AC, TC)
            ('AC-2', 'Account Management'),
            ('AC-3', 'Access Enforcement'),
            ('AU-2', 'Event Logging'),
        ],
        'api': [  # API/programmatic access
            ('SC-8', 'Transmission Confidentiality and Integrity'),
            ('IA-2', 'Identification and Authentication'),
        ],
    },
    # Collaborative Continuous Monitoring - Reporting & Assessment
    'CCM': {
        'default': [
            ('CA-7', 'Continuous Monitoring'),
            ('CA-2', 'Control Assessments'),
            ('SI-4', 'System Monitoring'),
            ('PM-31', 'Continuous Monitoring Strategy'),
        ],
    },
    # Federal System Integration - Integration & Security
    'FSI': {
        'default': [
            ('SA-9', 'External System Services'),
            ('CA-3', 'Information Exchange'),
            ('SC-7', 'Boundary Protection'),
        ],
    },
    # Incident Communication and Response - Incident Handling
    'ICP': {
        'default': [
            ('IR-4', 'Incident Handling'),
            ('IR-6', 'Incident Reporting'),
            ('IR-5', 'Incident Monitoring'),
            ('IR-8', 'Incident Response Plan'),
        ],
    },
    # Minimum Authorization Scope - Inventory & Assessment
    'MAS': {
        'default': [
            ('PM-5', 'System Inventory'),
            ('CM-8', 'System Component Inventory'),
            ('SA-4', 'Acquisition Process'),
        ],
    },
    # Provider Validation Activities - Assessment & Testing
    'PVA': {
        'default': [
            ('CA-2', 'Control Assessments'),
            ('CA-7', 'Continuous Monitoring'),
            ('CA-8', 'Penetration Testing'),
        ],
        'testing': [
            ('CA-8', 'Penetration Testing'),
            ('RA-5', 'Vulnerability Monitoring and Scanning'),
        ],
    },
    # Required Security Capabilities - Security Controls
    'RSC': {
        'default': [
            ('CM-7', 'Least Functionality'),
            ('CM-6', 'Configuration Settings'),
            ('SC-7', 'Boundary Protection'),
        ],
    },
    # Stakeholder Communication and Notification - Communication
    'SCN': {
        'default': [
            ('IR-6', 'Incident Reporting'),
            ('PM-15', 'Security and Privacy Groups and Associations'),
            ('CP-2', 'Contingency Plan'),
        ],
    },
    # Using Cryptographic Modules - Cryptography
    'UCM': {
        'default': [
            ('SC-13', 'Cryptographic Protection'),
            ('SC-12', 'Cryptographic Key Establishment and Management'),
            ('IA-7', 'Cryptographic Module Authentication'),
        ],
    },
    # Vulnerability Detection and Response - Vulnerability Management
    'VDR': {
        'default': [
            ('RA-5', 'Vulnerability Monitoring and Scanning'),
            ('SI-2', 'Flaw Remediation'),
            ('CA-7', 'Continuous Monitoring'),
        ],
        'remediation': [
            ('SI-2', 'Flaw Remediation'),
            ('SI-2(1)', 'Central Management'),
            ('SI-2(2)', 'Automated Flaw Remediation Status'),
        ],
    },
}

# Keywords that indicate code-detectability
CODE_DETECTABLE_KEYWORDS = {
    'encrypt', 'authentication', 'authorization', 'access control',
    'credential', 'certificate', 'key', 'password', 'mfa',
    'audit', 'log', 'monitor', 'scan', 'vulnerability',
    'patch', 'update', 'crypto', 'tls', 'ssl', 'https',
    'firewall', 'network', 'configuration', 'secure default',
}

# Keywords that indicate process-only (NOT code-detectable)
PROCESS_ONLY_KEYWORDS = {
    'must notify', 'must provide', 'must share', 'must establish',
    'must publicly', 'must make available', 'must maintain',
    'agency must', 'fedramp must', 'report', 'document',
    'guidance', 'policy', 'procedure', 'training', 'review',
    'assessment', 'third party', '3pao', 'auditor',
}


def analyze_frr_detectability(statement: str, family: str) -> str:
    """
    Analyze FRR statement to determine accurate CODE_DETECTABLE value.
    
    Returns: "Yes", "Partial", or "No"
    """
    statement_lower = statement.lower()
    
    # Families that are generally process-only
    PROCESS_FAMILIES = ['ADS', 'CCM', 'FSI', 'ICP', 'MAS', 'SCN']
    
    # Check for process-only keywords (strong indicator of "No")
    if any(keyword in statement_lower for keyword in PROCESS_ONLY_KEYWORDS):
        return 'No'
    
    # Check if family is process-oriented
    if family in PROCESS_FAMILIES:
        # Even in process families, some technical requirements might be partially detectable
        if any(keyword in statement_lower for keyword in CODE_DETECTABLE_KEYWORDS):
            return 'Partial'
        return 'No'
    
    # Technical families (UCM, VDR, RSC, PVA)
    # Check for code-detectable patterns
    if any(keyword in statement_lower for keyword in CODE_DETECTABLE_KEYWORDS):
        # Strong technical indicators suggest Partial or Yes
        if family in ['UCM', 'VDR'] and any(word in statement_lower for word in ['systematically', 'automated', 'tooling']):
            return 'Yes'  # High confidence code detection
        return 'Partial'
    
    return 'No'


def get_nist_controls(family: str, statement: str) -> List[Tuple[str, str]]:
    """Get appropriate NIST controls for FRR based on family and statement."""
    statement_lower = statement.lower()
    
    if family not in NIST_CONTROL_MAPPINGS:
        return []
    
    controls = NIST_CONTROL_MAPPINGS[family]['default'].copy()
    
    # Add specific controls based on keywords
    if family == 'ADS':
        if 'access' in statement_lower or 'log' in statement_lower:
            controls.extend(NIST_CONTROL_MAPPINGS['ADS']['access'])
        if 'api' in statement_lower or 'programmatic' in statement_lower:
            controls.extend(NIST_CONTROL_MAPPINGS['ADS']['api'])
    elif family == 'PVA':
        if 'test' in statement_lower or 'penetration' in statement_lower:
            controls.extend(NIST_CONTROL_MAPPINGS['PVA']['testing'])
    elif family == 'VDR':
        if 'remediat' in statement_lower or 'fix' in statement_lower:
            controls.extend(NIST_CONTROL_MAPPINGS['VDR']['remediation'])
    
    # Remove duplicates while preserving order
    seen = set()
    unique_controls = []
    for ctrl in controls:
        if ctrl[0] not in seen:
            seen.add(ctrl[0])
            unique_controls.append(ctrl)
    
    return unique_controls


def extract_frr_metadata(file_path: Path) -> Dict:
    """Extract FRR_ID, family, statement, and current CODE_DETECTABLE from file."""
    content = file_path.read_text(encoding='utf-8')
    
    frr_id_match = re.search(r'FRR_ID = ["\']([^"\']+)["\']', content)
    family_match = re.search(r'FAMILY = ["\']([^"\']+)["\']', content)
    # Match triple-quoted strings for FRR_STATEMENT
    statement_match = re.search(r'FRR_STATEMENT = """([^"]*(?:"{1,2}[^"]*)*)"""', content, re.DOTALL)
    code_det_match = re.search(r'CODE_DETECTABLE = ["\']([^"\']+)["\']', content)
    
    return {
        'frr_id': frr_id_match.group(1) if frr_id_match else None,
        'family': family_match.group(1) if family_match else None,
        'statement': statement_match.group(1) if statement_match else None,
        'current_detectable': code_det_match.group(1) if code_det_match else 'Unknown',
        'content': content,
    }


def update_frr_file(file_path: Path, metadata: Dict) -> bool:
    """Update FRR file with correct NIST controls and CODE_DETECTABLE."""
    content = metadata['content']
    frr_id = metadata['frr_id']
    family = metadata['family']
    statement = metadata['statement']
    
    if not all([frr_id, family, statement]):
        print(f"[SKIP] {file_path.name}: Missing required metadata")
        return False
    
    # Determine correct CODE_DETECTABLE
    correct_detectable = analyze_frr_detectability(statement, family)
    current_detectable = metadata['current_detectable']
    
    # Get NIST controls
    nist_controls = get_nist_controls(family, statement)
    
    # Check if NIST_CONTROLS is empty (has TODO)
    has_empty_controls = re.search(r'NIST_CONTROLS = \[\s*# TODO', content)
    
    # Only update if needed
    needs_update = False
    changes = []
    
    if current_detectable != correct_detectable:
        needs_update = True
        changes.append(f"CODE_DETECTABLE: {current_detectable} -> {correct_detectable}")
    
    if has_empty_controls and nist_controls:
        needs_update = True
        changes.append(f"Added {len(nist_controls)} NIST controls")
    
    if not needs_update:
        return False
    
    # Update CODE_DETECTABLE
    if current_detectable != correct_detectable:
        content = re.sub(
            r'CODE_DETECTABLE = ["\']' + re.escape(current_detectable) + r'["\']',
            f'CODE_DETECTABLE = "{correct_detectable}"',
            content
        )
    
    # Update NIST_CONTROLS if empty
    if has_empty_controls and nist_controls:
        controls_str = 'NIST_CONTROLS = [\n'
        for ctrl_id, ctrl_name in nist_controls:
            controls_str += f'        ("{ctrl_id}", "{ctrl_name}"),\n'
        controls_str += '    ]'
        
        content = re.sub(
            r'NIST_CONTROLS = \[\s*# TODO[^\]]*\]',
            controls_str,
            content
        )
    
    # Write back
    file_path.write_text(content, encoding='utf-8')
    
    print(f"[UPDATED] {frr_id}: {', '.join(changes)}")
    return True


def main():
    """Review and fix all FRR analyzers."""
    analyzer_dir = Path('src/fedramp_20x_mcp/analyzers/frr')
    
    total = 0
    updated = 0
    skipped = 0
    
    for frr_file in sorted(analyzer_dir.glob('frr_*.py')):
        total += 1
        metadata = extract_frr_metadata(frr_file)
        
        if update_frr_file(frr_file, metadata):
            updated += 1
        else:
            skipped += 1
    
    print(f"\n{'='*60}")
    print(f"Total FRRs reviewed: {total}")
    print(f"Updated: {updated}")
    print(f"Skipped (no changes): {skipped}")
    print(f"{'='*60}")


if __name__ == '__main__':
    main()
