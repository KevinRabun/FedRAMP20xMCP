"""
FRR-ADS-03: Detailed Service List

Providers MUST share a detailed list of specific services and their impact levels that are included in the _cloud service offering_ using clear feature or service names that align with standard public marketing materials; this list MUST be complete enough for a potential customer to determine which services are and are not included in the FedRAMP authorization without requesting access to underlying _authorization data_.

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


class FRR_ADS_03_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-03: Detailed Service List
    
    **Official Statement:**
    Providers MUST share a detailed list of specific services and their impact levels that are included in the _cloud service offering_ using clear feature or service names that align with standard public marketing materials; this list MUST be complete enough for a potential customer to determine which services are and are not included in the FedRAMP authorization without requesting access to underlying _authorization data_.
    
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
    
    **Detectability:** Partial
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
    1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
    2. Infrastructure patterns (Bicep, Terraform) - Use regex
    3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    """
    
    FRR_ID = "FRR-ADS-03"
    FRR_NAME = "Detailed Service List"
    FRR_STATEMENT = """Providers MUST share a detailed list of specific services and their impact levels that are included in the _cloud service offering_ using clear feature or service names that align with standard public marketing materials; this list MUST be complete enough for a potential customer to determine which services are and are not included in the FedRAMP authorization without requesting access to underlying _authorization data_."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PM-9", "Risk Management Strategy"),
        ("PL-2", "System Security Plan"),
        ("SA-4", "Acquisition Process"),
        ("SA-9", "External System Services"),
        ("AC-2", "Account Management"),
        ("AC-3", "Access Enforcement"),
        ("AU-2", "Event Logging"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",  # Automated FedRAMP Data Publication
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-03 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_documentation(self, content: str, file_path: str = "") -> List[Finding]:
        """
        Analyze documentation for FRR-ADS-03 compliance - service list with impact levels.
        
        Checks for:
        - Presence of service/feature list
        - Impact level designation (Low, Moderate, High)
        - Clear service names
        - Completeness indicators
        """
        findings = []
        
        # Only analyze documentation files
        doc_keywords = ['readme', 'services', 'features', 'authorization', 'compliance', 'fedramp']
        if not any(keyword in file_path.lower() for keyword in doc_keywords):
            return findings
        
        lines = content.split('\n')
        content_lower = content.lower()
        
        # Check for service list indicators
        has_service_list = any(indicator in content_lower for indicator in [
            'service list', 'feature list', 'included services', 'authorized services',
            'services included', 'service offering', 'features included'
        ])
        
        # Check for impact level mentions
        has_impact_levels = any(level in content_lower for level in [
            'impact level', 'low impact', 'moderate impact', 'high impact',
            'fips 199', 'security categorization'
        ])
        
        # Check for specific service names (Azure, AWS, GCP - require specific product names)
        # Note: We require specific product names like "Azure Key Vault", "AWS Lambda", not just "storage" or "database"
        has_service_names = any(service in content for service in [
            # Azure specific services
            'Azure Virtual Machines', 'Azure Storage', 'Azure SQL', 'Azure Key Vault',
            'Azure App Service', 'Azure Functions', 'Azure Kubernetes Service', 'AKS',
            'Azure Container', 'Azure Monitor', 'Azure Application Insights',
            # AWS specific services
            'Amazon EC2', 'AWS EC2', 'Amazon S3', 'AWS S3', 'Amazon RDS', 'AWS RDS',
            'AWS Lambda', 'AWS CloudFormation', 'Amazon CloudWatch', 'AWS CloudWatch',
            'AWS Elastic Beanstalk', 'Amazon EKS', 'AWS EKS',
            # GCP specific services
            'Google Compute Engine', 'GCE', 'Google Cloud Storage', 'GCS',
            'Google Kubernetes Engine', 'GKE', 'Cloud Functions', 'Cloud Run'
        ])
        
        if not has_service_list:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing service list documentation",
                description=f"File '{file_path}' does not appear to contain a detailed list of services included in the cloud service offering. FRR-ADS-03 requires providers to share a detailed list of specific services.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="""Add a comprehensive service list to your documentation. Example:

## Services Included in FedRAMP Authorization

### High Impact Level
- Azure Virtual Machines (all SKUs)
- Azure Key Vault (Premium tier)
- Azure Storage (all tiers)

### Moderate Impact Level
- Azure App Service
- Azure Functions
- Azure Container Instances

### Services NOT Included
- Azure DevOps
- Microsoft 365 services"""
            ))
        
        if has_service_list and not has_impact_levels:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Service list missing impact level designation",
                description=f"File '{file_path}' contains a service list but does not clearly indicate which impact levels apply. FRR-ADS-03 requires service lists to include impact level information.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Clearly indicate which services are authorized at which impact levels (Low, Moderate, High)"
            ))
        
        # Check for vague service names separately (this applies even if impact levels are present)
        if has_service_list and not has_service_names:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Service list lacks specific service names",
                description=f"File '{file_path}' has a service list but uses vague descriptions. FRR-ADS-03 requires 'clear feature or service names that align with standard public marketing materials'.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Use specific service names (e.g., 'Azure Key Vault', 'Amazon RDS') rather than generic terms like 'database service' or 'storage'"
            ))
        
        return findings
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not code analysis."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not code analysis."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not code analysis."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not code analysis."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not IaC analysis."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not IaC analysis."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not CI/CD analysis."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not CI/CD analysis."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-ADS-03 is documentation-focused, not CI/CD analysis."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-03.
        
        This is a documentation requirement - automated checking ensures service
        lists are published and maintained with proper impact level designations.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Automated documentation scanning for service lists with impact level designations',
            'evidence_artifacts': [
                'README.md or SERVICES.md containing service list',
                'Authorization package with service inventory',
                'Public-facing documentation URLs',
                'Service catalog or feature matrix'
            ],
            'collection_queries': [
                'Documentation scan results showing service list presence',
                'Verification that impact levels (Low/Moderate/High) are specified',
                'List of services with their authorization scope'
            ],
            'manual_validation_steps': [
                '1. Review README.md for service list section',
                '2. Verify each service has clear name matching public marketing',
                '3. Confirm impact level designation for each service',
                '4. Check that excluded services are explicitly listed',
                '5. Validate completeness - can customer determine scope without contacting provider?'
            ],
            'recommended_services': [
                'GitHub Pages - for publishing service documentation',
                'Azure Static Web Apps - for hosting service catalogs',
                'Trust Center platforms - for centralized authorization data'
            ],
            'integration_points': [
                'Export to OSCAL SSP (System Security Plan) format',
                'Link to public trust center URLs',
                'CI/CD checks to validate documentation completeness'
            ]
        }
