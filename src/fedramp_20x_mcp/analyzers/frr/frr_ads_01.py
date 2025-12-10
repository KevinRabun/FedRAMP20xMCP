"""
FRR-ADS-01: Public Information

Providers MUST publicly share up-to-date information about the _cloud service offering_ in both human-readable and _machine-readable_ formats, including at least:

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-01: Public Information
    
    **Official Statement:**
    Providers MUST publicly share up-to-date information about the _cloud service offering_ in both human-readable and _machine-readable_ formats, including at least:
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-ADS-01"
    FRR_NAME = "Public Information"
    FRR_STATEMENT = """Providers MUST publicly share up-to-date information about the _cloud service offering_ in both human-readable and _machine-readable_ formats, including at least:"""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        # TODO: Add NIST controls (e.g., ("RA-5", "Vulnerability Monitoring and Scanning"))
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Automated FedRAMP Data Publication
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-01 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    def analyze_documentation(self, content: str, file_path: str = "") -> List[Finding]:
        """
        Analyze documentation for public information about cloud service offering.
        
        Checks for:
        - Human-readable documentation (README, website)
        - Machine-readable formats (JSON, YAML, OSCAL)
        - Service information completeness
        """
        findings = []
        
        # Only analyze documentation files
        doc_keywords = ['readme', 'index', 'about', 'service', 'offering', 'fedramp', 'oscal', 'ssp']
        if not any(keyword in file_path.lower() for keyword in doc_keywords):
            return findings
        
        content_lower = content.lower()
        
        # Check for machine-readable format indicators
        has_machine_readable = any(fmt in content_lower for fmt in [
            'oscal', 'json', 'yaml', 'api endpoint', 'schema', 'openapi', 'swagger'
        ])
        
        # Check for service offering information
        has_service_info = any(info in content_lower for info in [
            'cloud service', 'fedramp authorized', 'service offering',
            'authorized services', 'impact level', 'authorization boundary'
        ])
        
        if not has_machine_readable and len(content) > 100:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing machine-readable format documentation",
                description=f"Documentation in '{file_path}' lacks references to machine-readable formats. FRR-ADS-01 requires public information in both human-readable AND machine-readable formats (e.g., OSCAL, JSON schema).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Add machine-readable format: 1) Publish OSCAL SSP/SAP/SAR, 2) Provide JSON/YAML API endpoint, 3) Include schema documentation, 4) Reference public FedRAMP marketplace entry"
            ))
        
        if not has_service_info and len(content) > 100:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing cloud service offering information",
                description=f"Documentation in '{file_path}' does not describe cloud service offering details. FRR-ADS-01 requires public sharing of service information.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Document: 1) Service name and description, 2) FedRAMP authorization status, 3) Impact levels, 4) Authorized services list, 5) Authorization boundary"
            ))
        
        return findings
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not application code."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not application code."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not application code."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not application code."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-01 compliance.
        
        TODO: Implement Bicep analysis
        - Detect relevant Azure resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Bicep regex patterns
        # Example:
        # resource_pattern = r"resource\s+\w+\s+'Microsoft\.\w+/\w+@[\d-]+'\s*="
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-01 compliance.
        
        TODO: Implement Terraform analysis
        - Detect relevant resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Terraform regex patterns
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not CI/CD."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not CI/CD."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-01 is documentation-focused, not CI/CD."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-01.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Automated documentation scanning for public information completeness, combined with manual verification of publication channels',
            'evidence_artifacts': [
                'README.md or public documentation',
                'OSCAL SSP/SAP/SAR files (machine-readable)',
                'Public website content (human-readable)',
                'FedRAMP Marketplace listing',
                'JSON/YAML service schema files',
                'API documentation (OpenAPI/Swagger)',
                'Service catalog or offerings page'
            ],
            'collection_queries': [
                'Documentation scan: Check for both human-readable and machine-readable formats',
                'Web scrape: Verify public accessibility of documentation',
                'FedRAMP API: GET marketplace listing status',
                'Git repository: List documentation files (README, OSCAL, schemas)',
                'Website crawl: Validate service offering information is publicly available'
            ],
            'manual_validation_steps': [
                '1. Verify documentation is publicly accessible (no authentication required)',
                '2. Check for both human-readable (HTML/MD) and machine-readable (OSCAL/JSON) formats',
                '3. Confirm service offering details are complete (name, impact level, boundary)',
                '4. Validate FedRAMP Marketplace listing matches documentation',
                '5. Ensure documentation is up-to-date (review timestamp/version)',
                '6. Verify all required information elements are present per FRR-ADS-01'
            ],
            'recommended_services': [
                'GitHub Pages / Azure Static Web Apps - for public documentation hosting',
                'FedRAMP Marketplace - official public listing',
                'OSCAL Tools - for machine-readable format generation',
                'Documentation generators (Sphinx, MkDocs, Docusaurus)',
                'CI/CD pipelines - auto-publish documentation on updates'
            ],
            'integration_points': [
                'OSCAL format export for automated compliance reporting',
                'FedRAMP Marketplace API for status verification',
                'Documentation as code - version control integration',
                'Automated documentation testing in CI/CD',
                'Public website monitoring for availability'
            ]
        }
