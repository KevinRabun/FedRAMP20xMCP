"""
Review all FRR analyzers marked as CODE_DETECTABLE = "No" to reassess detectability.

This script:
1. Loads all FRR analyzers currently marked as not code-detectable
2. Reads their official statements from the fedramp_controls cache
3. Analyzes whether they describe technical requirements detectable in:
   - Application code (Python, C#, Java, TypeScript/JavaScript)
   - Infrastructure code (Bicep, Terraform)  
   - CI/CD pipelines (GitHub Actions, Azure Pipelines, GitLab CI)
4. Provides recommendations for each FRR with justification
"""

import json
import re
import os
from pathlib import Path
from typing import Dict, List, Tuple


def load_fedramp_cache() -> Dict:
    """Load the official FedRAMP controls cache."""
    cache_path = Path("src/fedramp_20x_mcp/__fedramp_cache__/fedramp_controls.json")
    with open(cache_path, 'r', encoding='utf-8') as f:
        return json.load(f)


def extract_frr_id_from_file(file_path: str) -> str:
    """Extract FRR ID from analyzer file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        # Match patterns like: FRR-ADS-01, FRR-ADS-TC-01, FRR-CCM-AG-01, FRR-VDR-TF-HI-01, etc.
        match = re.search(r'FRR_ID\s*=\s*"(FRR-[A-Z]+-[A-Z0-9-]+)"', content)
        if match:
            return match.group(1)
    return None


def extract_frr_statement_from_file(file_path: str) -> str:
    """Extract FRR statement from analyzer file for local comparison."""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        match = re.search(r'FRR_STATEMENT\s*=\s*"""(.+?)"""', content, re.DOTALL)
        if match:
            return match.group(1).strip()
    return None


def assess_code_detectability(frr_id: str, statement: str, name: str) -> Tuple[str, str, List[str]]:
    """
    Assess if an FRR could be code-detectable based on its statement.
    
    Returns:
        (assessment, reasoning, detection_opportunities)
        assessment: "CODE_DETECTABLE", "PARTIALLY_DETECTABLE", "NOT_DETECTABLE"
        reasoning: Explanation of the assessment
        detection_opportunities: List of specific detection strategies
    """
    statement_lower = statement.lower()
    
    # Keywords indicating code-detectability
    code_indicators = {
        'encryption': ['IaC: Check encryption settings in resources', 'Code: Verify encryption libraries usage'],
        'tls': ['IaC: Verify TLS/SSL configuration', 'Code: Check TLS version enforcement'],
        'authentication': ['Code: Verify auth mechanisms', 'IaC: Check identity provider config'],
        'authorization': ['Code: Check access control implementation', 'IaC: Verify RBAC/IAM policies'],
        'logging': ['Code: Verify logging framework usage', 'CI/CD: Check log aggregation config'],
        'monitoring': ['IaC: Verify monitoring resource deployment', 'CI/CD: Check monitoring integration'],
        'vulnerability': ['CI/CD: Verify vulnerability scanning in pipeline', 'IaC: Check security scanning tools'],
        'scanning': ['CI/CD: Detect security scanning steps', 'IaC: Verify scanner deployment'],
        'api': ['Code: Check API security implementations', 'IaC: Verify API gateway config'],
        'database': ['IaC: Check database security settings', 'Code: Verify connection security'],
        'network': ['IaC: Check network security groups', 'IaC: Verify firewall rules'],
        'firewall': ['IaC: Verify firewall deployment', 'IaC: Check ingress/egress rules'],
        'backup': ['IaC: Verify backup configuration', 'CI/CD: Check backup automation'],
        'access control': ['IaC: Verify IAM/RBAC policies', 'Code: Check authorization checks'],
        'multi-factor': ['Code: Verify MFA implementation', 'IaC: Check MFA enforcement'],
        'password': ['Code: Verify password policy enforcement', 'IaC: Check password policies'],
        'session': ['Code: Verify session management', 'Code: Check session timeout'],
        'timeout': ['Code: Check timeout configuration', 'IaC: Verify timeout settings'],
        'certificate': ['IaC: Verify certificate management', 'CI/CD: Check cert rotation'],
        'key management': ['IaC: Verify key vault usage', 'Code: Check encryption key handling'],
        'secrets': ['Code: Check secrets management', 'CI/CD: Verify secrets handling'],
        'container': ['IaC: Verify container security', 'CI/CD: Check container scanning'],
        'deployment': ['CI/CD: Analyze deployment process', 'IaC: Verify deployment config'],
        'version control': ['CI/CD: Check VCS integration', 'CI/CD: Verify branch protection'],
        'automated': ['CI/CD: Detect automation steps', 'IaC: Check automated deployments'],
        'testing': ['CI/CD: Verify test stages', 'CI/CD: Check security testing'],
        'compliance': ['CI/CD: Detect compliance checks', 'IaC: Verify compliance tags'],
        'audit': ['Code: Verify audit logging', 'IaC: Check audit trail config'],
        'alerting': ['IaC: Verify alert rules', 'CI/CD: Check alerting integration'],
        'incident': ['Code: Check incident logging', 'IaC: Verify incident response resources'],
        'patching': ['CI/CD: Check patch automation', 'IaC: Verify update policies'],
        'configuration': ['IaC: Check configuration management', 'Code: Verify config security'],
        'infrastructure': ['IaC: Analyze infrastructure code', 'CI/CD: Check IaC validation'],
    }
    
    # Process/documentation keywords that indicate NOT code-detectable
    non_code_indicators = [
        'must document', 'must provide', 'must submit', 'must share', 'must notify',
        'must report', 'must maintain', 'must demonstrate', 'must describe',
        'must coordinate', 'must communicate', 'must establish', 'must define',
        'public information', 'publicly share', 'documentation', 'fedramp ',
        'pmo', 'authorization package', 'system security plan', 'ssp',
        'continuous monitoring', 'conmon', 'assessment', 'auditor', 'assessor',
        'annually', 'monthly', 'quarterly', 'schedule', 'timeline', 'timeframe',
        'deviation request', 'exemption', 'approval', 'agreement',
        'significant change', 'major change', 'substantial change',
        'third party', '3pao', 'independent', 'external',
        'process', 'procedure', 'policy', 'plan',
    ]
    
    # Check for non-code indicators first
    non_code_count = sum(1 for indicator in non_code_indicators if indicator in statement_lower)
    
    # Check for code indicators
    detected_opportunities = []
    code_count = 0
    for keyword, opportunities in code_indicators.items():
        if keyword in statement_lower:
            code_count += 1
            detected_opportunities.extend(opportunities)
    
    # Make assessment
    if non_code_count > 2 and code_count == 0:
        return "NOT_DETECTABLE", "Pure process/documentation requirement with no technical implementation aspects", []
    elif code_count > 0 and non_code_count > code_count:
        return "PARTIALLY_DETECTABLE", f"Mixed requirement: {code_count} technical aspects but {non_code_count} process aspects. Some code detection possible.", detected_opportunities[:3]
    elif code_count > 0:
        return "CODE_DETECTABLE", f"Technical requirement with {code_count} detectable aspects in code, IaC, or CI/CD", detected_opportunities[:5]
    else:
        # Analyze statement structure for implicit technical requirements
        if any(x in statement_lower for x in ['must use', 'must implement', 'must configure', 'must enable', 'must enforce']):
            if any(x in statement_lower for x in ['system', 'service', 'application', 'infrastructure', 'component']):
                return "PARTIALLY_DETECTABLE", "Implicit technical requirement - may be detectable through infrastructure or configuration analysis", ['IaC: Analyze resource configurations', 'Code: Check implementation patterns']
        
        return "NOT_DETECTABLE", "No clear technical implementation aspects detectable in code, IaC, or CI/CD", []


def main():
    """Review all FRR analyzers marked as not code-detectable."""
    print("=" * 120)
    print("FRR CODE DETECTABILITY REASSESSMENT")
    print("=" * 120)
    
    # Load official data
    cache = load_fedramp_cache()
    requirements = cache.get('requirements', {})
    
    # Find all FRR analyzers marked as not detectable
    frr_dir = Path("src/fedramp_20x_mcp/analyzers/frr")
    not_detectable_files = []
    
    for file in sorted(frr_dir.glob("frr_*.py")):
        with open(file, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'CODE_DETECTABLE = "No"' in content:
                not_detectable_files.append(file)
    
    print(f"\nFound {len(not_detectable_files)} FRR analyzers marked as CODE_DETECTABLE = \"No\"\n")
    
    # Organize by family (use first 3 letters of family part for grouping)
    by_family = {}
    for file in not_detectable_files:
        frr_id = extract_frr_id_from_file(file)
        if frr_id:
            # Extract family - handle formats like "ADS-01", "ADS-TC-01", "CCM-AG-01", etc.
            parts = frr_id.split('-')
            family = parts[1][:3] if len(parts) > 1 else "UNKNOWN"  # First 3 chars of family
            if family not in by_family:
                by_family[family] = []
            by_family[family].append((file, frr_id))
    
    # Track summary stats
    total_reviewed = 0
    can_detect = []
    partial_detect = []
    truly_not_detectable = []
    
    # Review each family
    for family in sorted(by_family.keys()):
        print(f"\n{'=' * 120}")
        print(f"FAMILY: {family} ({len(by_family[family])} requirements)")
        print(f"{'=' * 120}\n")
        
        for file, frr_id in sorted(by_family[family], key=lambda x: x[1]):
            total_reviewed += 1
            
            # Get official data
            official = requirements.get(frr_id, {})
            statement = official.get('statement', 'N/A')
            name = official.get('name', 'N/A')
            
            # Assess detectability
            assessment, reasoning, opportunities = assess_code_detectability(frr_id, statement, name)
            
            # Track stats
            if assessment == "CODE_DETECTABLE":
                can_detect.append((frr_id, file.name, reasoning, opportunities))
            elif assessment == "PARTIALLY_DETECTABLE":
                partial_detect.append((frr_id, file.name, reasoning, opportunities))
            else:
                truly_not_detectable.append((frr_id, file.name, reasoning))
            
            # Print result (ASCII-safe markers for Windows)
            status_marker = "[YES]" if assessment == "CODE_DETECTABLE" else ("[PARTIAL]" if assessment == "PARTIALLY_DETECTABLE" else "[NO]")
            print(f"{status_marker} | {frr_id} | {name[:60]}")
            print(f"      File: {file.name}")
            print(f"      Assessment: {assessment}")
            print(f"      Reasoning: {reasoning}")
            
            if opportunities:
                print(f"      Detection Opportunities:")
                for opp in opportunities:
                    print(f"        - {opp}")
            
            # Show first 150 chars of statement for context
            print(f"      Statement: {statement[:150]}...")
            print()
    
    # Print summary
    print("\n" + "=" * 120)
    print("SUMMARY")
    print("=" * 120)
    print(f"\nTotal Reviewed: {total_reviewed}")
    print(f"Could Be Code-Detectable: {len(can_detect)} ({len(can_detect)/total_reviewed*100:.1f}%)")
    print(f"Partially Code-Detectable: {len(partial_detect)} ({len(partial_detect)/total_reviewed*100:.1f}%)")
    print(f"Truly Not Detectable: {len(truly_not_detectable)} ({len(truly_not_detectable)/total_reviewed*100:.1f}%)")
    
    # Recommendations section
    if can_detect:
        print(f"\n\n{'=' * 120}")
        print("RECOMMENDATIONS: CHANGE TO CODE_DETECTABLE = True")
        print(f"{'=' * 120}\n")
        print(f"The following {len(can_detect)} FRR analyzers SHOULD be changed to CODE_DETECTABLE = True:\n")
        
        for frr_id, filename, reasoning, opportunities in can_detect:
            print(f"  {frr_id} ({filename})")
            print(f"    Reason: {reasoning}")
            print(f"    Opportunities: {', '.join(opportunities[:2])}")
            print()
    
    if partial_detect:
        print(f"\n\n{'=' * 120}")
        print("RECOMMENDATIONS: CONSIDER PARTIAL IMPLEMENTATION")
        print(f"{'=' * 120}\n")
        print(f"The following {len(partial_detect)} FRR analyzers have PARTIAL code detectability:\n")
        
        for frr_id, filename, reasoning, opportunities in partial_detect:
            print(f"  {frr_id} ({filename})")
            print(f"    Reason: {reasoning}")
            if opportunities:
                print(f"    Opportunities: {', '.join(opportunities[:2])}")
            print()


if __name__ == "__main__":
    main()
