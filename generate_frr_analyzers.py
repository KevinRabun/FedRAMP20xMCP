"""
Generate FRR analyzer files from CSV data using FRR-VDR-08 as template.

This script:
1. Reads FRR_REQUIREMENTS_DETAIL.csv
2. For each FRR with Code_Detectable = "Yes" or "Partial"
3. Creates analyzer file using FRR-VDR-08 structure
4. Adds TODOs and placeholders for implementation
5. Creates corresponding test file
"""

import csv
import os
from pathlib import Path


def get_frr_data_from_csv():
    """Read FRR data from CSV file."""
    csv_path = Path(__file__).parent / "FRR_REQUIREMENTS_DETAIL.csv"
    frrs = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Generate analyzers for ALL FRRs, not just code-detectable ones
            # Even non-code-detectable FRRs need analyzers for evidence collection guidance
            frrs.append({
                'id': row['FRR_ID'],
                'family': row['Family'],
                'title': row['Title'],
                'keyword': row['Primary_Keyword'],
                'impact_low': row['Impact_Low'] == 'Yes',
                'impact_moderate': row['Impact_Moderate'] == 'Yes',
                'impact_high': row['Impact_High'] == 'Yes',
                'code_detectable': row['Code_Detectable'],
                'statement': row['Statement']
            })
    
    return frrs


def generate_analyzer_template(frr):
    """Generate analyzer Python file content from template."""
    
    # Determine implementation status
    status = "COMPLETE" if frr['code_detectable'] == 'Yes' else "PARTIAL"
    
    template = f'''"""
{frr['id']}: {frr['title']}

{frr['statement']}

Official FedRAMP 20x Requirement
Source: FRR-{frr['family']} ({get_family_name(frr['family'])}) family
Primary Keyword: {frr['keyword']}
Impact Levels: {get_impact_levels(frr)}
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class {get_class_name(frr['id'])}_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for {frr['id']}: {frr['title']}
    
    **Official Statement:**
    {frr['statement']}
    
    **Family:** {frr['family']} - {get_family_name(frr['family'])}
    
    **Primary Keyword:** {frr['keyword']}
    
    **Impact Levels:**
    - Low: {'Yes' if frr['impact_low'] else 'No'}
    - Moderate: {'Yes' if frr['impact_moderate'] else 'No'}
    - High: {'Yes' if frr['impact_high'] else 'No'}
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** {frr['code_detectable']}
    
    **Detection Strategy:**
    {'TODO: This requirement is not directly code-detectable. This analyzer provides:' if frr['code_detectable'] == 'No' else 'TODO: Describe what this analyzer detects and how:'}
    {'    1. Evidence collection guidance and automation recommendations' if frr['code_detectable'] == 'No' else '    1. Application code patterns (Python, C#, Java, TypeScript) - Use AST'}
    {'    2. Manual validation procedures and checklists' if frr['code_detectable'] == 'No' else '    2. Infrastructure patterns (Bicep, Terraform) - Use regex'}
    {'    3. Related documentation and artifact requirements' if frr['code_detectable'] == 'No' else '    3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex'}
    {'    4. Integration points with other compliance tools' if frr['code_detectable'] == 'No' else ''}
    """
    
    FRR_ID = "{frr['id']}"
    FRR_NAME = "{frr['title']}"
    FRR_STATEMENT = """{frr['statement']}"""
    FAMILY = "{frr['family']}"
    FAMILY_NAME = "{get_family_name(frr['family'])}"
    PRIMARY_KEYWORD = "{frr['keyword']}"
    IMPACT_LOW = {frr['impact_low']}
    IMPACT_MODERATE = {frr['impact_moderate']}
    IMPACT_HIGH = {frr['impact_high']}
    NIST_CONTROLS = [
        # TODO: Add NIST controls (e.g., ("RA-5", "Vulnerability Monitoring and Scanning"))
    ]
    CODE_DETECTABLE = "{frr['code_detectable']}"
    IMPLEMENTATION_STATUS = "{status}"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize {frr['id']} analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for {frr['id']} compliance using AST.
        
        TODO: Implement Python analysis
        - Use ASTParser(CodeLanguage.PYTHON)
        - Use tree.root_node and code_bytes
        - Use find_nodes_by_type() for AST nodes
        - Fallback to regex if AST fails
        
        Detection targets:
        - TODO: List what patterns to detect
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement AST-based analysis
        # Example from FRR-VDR-08:
        # try:
        #     parser = ASTParser(CodeLanguage.PYTHON)
        #     tree = parser.parse(code)
        #     code_bytes = code.encode('utf8')
        #     
        #     if tree and tree.root_node:
        #         # Find relevant nodes
        #         nodes = parser.find_nodes_by_type(tree.root_node, 'node_type')
        #         for node in nodes:
        #             node_text = parser.get_node_text(node, code_bytes)
        #             # Check for violations
        #         
        #         return findings
        # except Exception:
        #     pass
        
        # TODO: Implement regex fallback
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for {frr['id']} compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for {frr['id']} compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for {frr['id']} compliance using AST.
        
        TODO: Implement TypeScript analysis
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for {frr['id']} compliance.
        
        TODO: Implement Bicep analysis
        - Detect relevant Azure resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement Bicep regex patterns
        # Example:
        # resource_pattern = r"resource\\s+\\w+\\s+'Microsoft\\.\\w+/\\w+@[\\d-]+'\\s*="
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for {frr['id']} compliance.
        
        TODO: Implement Terraform analysis
        - Detect relevant resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement Terraform regex patterns
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for {frr['id']} compliance.
        
        TODO: Implement GitHub Actions analysis
        - Check for required steps/actions
        - Verify compliance configuration
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement GitHub Actions analysis
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for {frr['id']} compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for {frr['id']} compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for {frr['id']}.
        
        {'This requirement is not directly code-detectable. Provides manual validation guidance.' if frr['code_detectable'] == 'No' else 'TODO: Add evidence collection guidance'}
        """
        return {{
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': '{frr['code_detectable']}',
            'automation_approach': '{get_automation_guidance(frr['code_detectable'])}',
            'evidence_artifacts': [
                # TODO: List evidence artifacts to collect
                # Examples:
                # - "Configuration export from service X"
                # - "Access logs showing activity Y"
                # - "Documentation showing policy Z"
            ],
            'collection_queries': [
                # TODO: Add KQL or API queries for evidence
                # Examples for Azure:
                # - "AzureDiagnostics | where Category == 'X' | project TimeGenerated, Property"
                # - "GET https://management.azure.com/subscriptions/{{subscriptionId}}/..."
            ],
            'manual_validation_steps': [
                # TODO: Add manual validation procedures
                # 1. "Review documentation for X"
                # 2. "Verify configuration setting Y"
                # 3. "Interview stakeholder about Z"
            ],
            'recommended_services': [
                # TODO: List Azure/AWS services that help with this requirement
                # Examples:
                # - "Azure Policy - for configuration validation"
                # - "Azure Monitor - for activity logging"
                # - "Microsoft Defender for Cloud - for security posture"
            ],
            'integration_points': [
                # TODO: List integration with other tools
                # Examples:
                # - "Export to OSCAL format for automated reporting"
                # - "Integrate with ServiceNow for change management"
            ]
        }}
'''
    
    return template


def generate_test_template(frr):
    """Generate test file content from template."""
    
    template = f'''"""
Tests for {frr['id']}: {frr['title']}
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.frr.{frr['id'].lower().replace('-', '_')} import {get_class_name(frr['id'])}_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# TODO: Implement tests for {frr['id']}
# Follow the pattern from test_frr_vdr_08.py and test_frr_ucm_02.py


def test_analyzer_metadata():
    """Test {frr['id']} analyzer metadata."""
    analyzer = {get_class_name(frr['id'])}_Analyzer()
    
    assert analyzer.FRR_ID == "{frr['id']}", "FRR_ID should be {frr['id']}"
    assert analyzer.FAMILY == "{frr['family']}", "Family should be {frr['family']}"
    assert analyzer.FRR_NAME == "{frr['title']}", "Title mismatch"
    assert analyzer.PRIMARY_KEYWORD == "{frr['keyword']}", "Keyword mismatch"
    assert analyzer.IMPACT_LOW == {frr['impact_low']}, "Impact Low mismatch"
    assert analyzer.IMPACT_MODERATE == {frr['impact_moderate']}, "Impact Moderate mismatch"
    assert analyzer.IMPACT_HIGH == {frr['impact_high']}, "Impact High mismatch"
    
    print("✓ test_analyzer_metadata PASSED")


def test_evidence_automation_recommendations():
    """Test evidence automation recommendations."""
    analyzer = {get_class_name(frr['id'])}_Analyzer()
    
    recommendations = analyzer.get_evidence_automation_recommendations()
    assert recommendations['frr_id'] == "{frr['id']}", "FRR_ID mismatch"
    # TODO: Add more assertions for evidence recommendations
    
    print("✓ test_evidence_automation_recommendations PASSED")


# TODO: Add language-specific tests
# Examples:
# - test_python_detection()
# - test_csharp_detection()
# - test_java_detection()
# - test_typescript_detection()
# - test_bicep_detection()
# - test_terraform_detection()
# - test_github_actions_detection()
# - test_azure_pipelines_detection()
# - test_compliant_code_passes()


def run_all_tests():
    """Run all {frr['id']} tests."""
    test_functions = [
        ("Analyzer metadata", test_analyzer_metadata),
        ("Evidence automation recommendations", test_evidence_automation_recommendations),
        # TODO: Add more test functions
    ]
    
    passed = 0
    failed = 0
    
    print("\\n" + "=" * 70)
    print(f"Running {frr['id']} Tests ({{len(test_functions)}} tests)")
    print("=" * 70 + "\\n")
    
    for test_name, test_func in test_functions:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"✗ {{test_name}} FAILED: {{e}}")
            failed += 1
        except Exception as e:
            print(f"✗ {{test_name}} ERROR: {{e}}")
            failed += 1
    
    print("\\n" + "=" * 70)
    print(f"Test Results: {{passed}}/{{len(test_functions)}} passed, {{failed}} failed")
    print("=" * 70)
    
    if failed == 0:
        print("\\nALL TESTS PASSED ✓\\n")
    else:
        print(f"\\nSOME TESTS FAILED ✗\\n")
        print("TODO: Implement remaining tests to achieve 100% pass rate")
        exit(1)


if __name__ == "__main__":
    run_all_tests()
'''
    
    return template


def get_class_name(frr_id):
    """Convert FRR-XXX-01 to FRR_XXX_01."""
    return frr_id.replace('-', '_')


def get_family_name(family):
    """Get full family name from abbreviation."""
    family_names = {
        'ADS': 'Authorization Data Sharing',
        'CCM': 'Collaborative Continuous Monitoring',
        'FSI': 'FedRAMP Security Incident',
        'RSC': 'Resource Categorization',
        'UCM': 'Using Cryptographic Modules',
        'VDR': 'Vulnerability Detection and Response'
    }
    return family_names.get(family, family)


def get_impact_levels(frr):
    """Get comma-separated impact levels."""
    levels = []
    if frr['impact_low']:
        levels.append('Low')
    if frr['impact_moderate']:
        levels.append('Moderate')
    if frr['impact_high']:
        levels.append('High')
    return ', '.join(levels)


def get_automation_guidance(code_detectable):
    """Get automation approach based on code detectability."""
    if code_detectable == 'No':
        return 'Manual validation required - use evidence collection queries and documentation review'
    elif code_detectable == 'Partial':
        return 'TODO: Combine automated code analysis with manual validation procedures'
    else:
        return 'TODO: Fully automated detection through code, IaC, and CI/CD analysis'


def main():
    """Generate all FRR analyzer files."""
    print("Generating FRR analyzer files from CSV...")
    print("NOTE: Creating analyzers for ALL FRRs, including non-code-detectable ones.")
    print("Non-code-detectable analyzers provide evidence collection guidance.\\n")
    
    frrs = get_frr_data_from_csv()
    print(f"Found {len(frrs)} total FRRs\\n")
    
    analyzers_dir = Path(__file__).parent / "src" / "fedramp_20x_mcp" / "analyzers" / "frr"
    tests_dir = Path(__file__).parent / "tests"
    
    created = []
    skipped = []
    
    for frr in frrs:
        analyzer_file = analyzers_dir / f"{frr['id'].lower().replace('-', '_')}.py"
        test_file = tests_dir / f"test_{frr['id'].lower().replace('-', '_')}.py"
        
        # Check if already exists
        if analyzer_file.exists():
            skipped.append(frr['id'])
            print(f"⊘ {frr['id']} - Already exists, skipping")
            continue
        
        # Create analyzer file
        analyzer_content = generate_analyzer_template(frr)
        with open(analyzer_file, 'w', encoding='utf-8') as f:
            f.write(analyzer_content)
        
        # Create test file
        test_content = generate_test_template(frr)
        with open(test_file, 'w', encoding='utf-8') as f:
            f.write(test_content)
        
        created.append(frr['id'])
        print(f"✓ {frr['id']} - Created analyzer and test files")
    
    print(f"\\n{'='*70}")
    print(f"Summary:")
    print(f"  Created: {len(created)} FRR analyzers")
    print(f"  Skipped: {len(skipped)} (already exist)")
    print(f"{'='*70}\\n")
    
    if created:
        print("Next steps:")
        print("1. Visit each created file and implement the TODOs")
        print("2. Follow the pattern from FRR-VDR-08 and FRR-UCM-02")
        print("3. Use AST for application code, regex for IaC/CI/CD")
        print("4. Run tests: python tests/test_frr_xxx_yy.py")
        print("5. Update CSV Code_Detectable to 'Yes' when complete")


if __name__ == "__main__":
    main()
