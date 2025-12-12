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
            'automation_feasibility': 'High - Can automate documentation scanning, service name extraction, impact level verification, and completeness checking',
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
            'azure_services': [
                'Azure Static Web Apps (hosting service catalog documentation)',
                'Azure Repos (version control for service documentation)',
                'Azure DevOps (CI/CD for documentation validation)',
                'Azure CDN (global distribution of service documentation)',
                'Azure Storage Static Website (alternative hosting for service catalogs)'
            ],
            'collection_methods': [
                'Automated documentation file scanning (README.md, SERVICES.md, docs/)',
                'Natural language processing to extract service names',
                'Impact level keyword detection (Low, Moderate, High)',
                'Service name validation against cloud provider marketing names',
                'Completeness scoring based on required sections',
                'Public URL accessibility verification'
            ],
            'implementation_steps': [
                '1. Scan repository for documentation files (README.md, SERVICES.md, docs/ folder)',
                '2. Parse documentation for "service list" or "authorized services" sections',
                '3. Extract service names and categorize by impact level (Low/Moderate/High)',
                '4. Validate service names match public cloud provider marketing names (e.g., "Azure Key Vault" not "key vault")',
                '5. Check for excluded services section (services NOT included)',
                '6. Verify documentation is publicly accessible via web URL',
                '7. Generate completeness report with findings and recommendations'
            ],
            'integration_points': [
                'Export to OSCAL SSP (System Security Plan) format',
                'Link to public trust center URLs',
                'CI/CD checks to validate documentation completeness'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get specific queries for collecting FRR-ADS-03 evidence.
        
        Returns:
            List of evidence collection queries specific to service list documentation
        """
        return [
            {
                'method_type': 'Documentation Scan',
                'name': 'Service List Documentation Discovery',
                'description': 'Scan repository for documentation files containing service lists with impact level designations',
                'command': 'find . -type f \\( -name "README.md" -o -name "SERVICES.md" -o -path "*/docs/*" \\) -exec grep -l -i "service.*list\\|authorized.*services\\|included.*services" {} \\;',
                'purpose': 'Locate documentation files that should contain the detailed service list required by FRR-ADS-03',
                'evidence_type': 'Documentation file inventory with service list indicators',
                'validation_checks': [
                    'At least one documentation file contains "service list" keywords',
                    'Documentation includes section headers like "Services Included" or "Authorization Scope"',
                    'File is in standard documentation location (README, docs/)',
                    'Content is human-readable (Markdown, HTML, or plain text)'
                ],
                'storage_location': 'Evidence/ADS-03/documentation-scans/'
            },
            {
                'method_type': 'Content Analysis',
                'name': 'Impact Level Verification',
                'description': 'Extract and verify impact level designations (Low, Moderate, High) for each listed service',
                'command': 'grep -E -i "(low|moderate|high)\\s+(impact|level)" README.md SERVICES.md docs/*.md | python scripts/parse_impact_levels.py',
                'purpose': 'Confirm that each service in the list is clearly designated with its authorized impact level',
                'evidence_type': 'Impact level designation report',
                'validation_checks': [
                    'Each service has explicit impact level (Low, Moderate, or High)',
                    'Impact levels use FedRAMP standard terminology',
                    'Services are grouped or tagged by impact level',
                    'No ambiguous or missing impact level designations'
                ],
                'storage_location': 'Evidence/ADS-03/impact-level-reports/'
            },
            {
                'method_type': 'Service Name Extraction',
                'name': 'Specific Service Name Validation',
                'description': 'Extract service names and validate they match standard public cloud marketing materials (not generic terms)',
                'command': 'python scripts/extract_service_names.py --input README.md --cloud-provider azure --validate-marketing-names',
                'purpose': 'Ensure service names are "clear feature or service names that align with standard public marketing materials" per FRR-ADS-03',
                'evidence_type': 'Service name inventory with marketing name validation',
                'validation_checks': [
                    'Service names match official cloud provider marketing names (e.g., "Azure Key Vault" not "key vault service")',
                    'No vague or generic terms like "storage service" or "compute resources"',
                    'Service names include appropriate qualifiers (SKUs, tiers, editions)',
                    'Names are consistent with cloud provider documentation'
                ],
                'storage_location': 'Evidence/ADS-03/service-name-validation/'
            },
            {
                'method_type': 'Completeness Check',
                'name': 'Authorization Scope Completeness Assessment',
                'description': 'Verify service list is complete enough for customers to determine authorization scope without requesting additional information',
                'command': 'python scripts/assess_completeness.py --documentation README.md --checklist frr-ads-03-completeness.json',
                'purpose': 'Validate that the service list meets FRR-ADS-03 requirement: "complete enough for a potential customer to determine which services are and are not included"',
                'evidence_type': 'Completeness assessment report',
                'validation_checks': [
                    'All major service categories represented (compute, storage, database, networking, etc.)',
                    'Services NOT included explicitly listed',
                    'Edge cases addressed (e.g., regional limitations, SKU restrictions)',
                    'No ambiguous statements requiring customer to contact provider for clarification'
                ],
                'storage_location': 'Evidence/ADS-03/completeness-reports/'
            },
            {
                'method_type': 'Public Accessibility Verification',
                'name': 'Service Documentation Public URL Check',
                'description': 'Verify service list documentation is publicly accessible without authentication',
                'command': 'curl -I -s https://github.com/{owner}/{repo}/blob/main/README.md | grep "HTTP/2 200"',
                'purpose': 'Confirm service list is publicly shared as required by FRR-ADS-03 (customers can access without requesting authorization data)',
                'evidence_type': 'HTTP accessibility report',
                'validation_checks': [
                    'Documentation URL returns HTTP 200 (accessible)',
                    'No authentication required to view service list',
                    'URL is stable and versioned appropriately',
                    'Content is indexed by search engines (if applicable)'
                ],
                'storage_location': 'Evidence/ADS-03/accessibility-checks/'
            },
            {
                'method_type': 'OSCAL Integration',
                'name': 'Service List in OSCAL SSP Verification',
                'description': 'Verify service list is also represented in machine-readable OSCAL System Security Plan format',
                'command': 'jq \'.["system-security-plan"].["system-characteristics"].["authorization-boundary"].diagrams[] | select(.description | contains("service"))\' ssp.json',
                'purpose': 'Ensure service list is available in both human-readable (README) and machine-readable (OSCAL) formats per ADS family requirements',
                'evidence_type': 'OSCAL SSP service inventory',
                'validation_checks': [
                    'OSCAL SSP includes service inventory section',
                    'Services listed in OSCAL match those in README/SERVICES.md',
                    'Impact levels in OSCAL match documentation',
                    'OSCAL format validates against FedRAMP schema'
                ],
                'storage_location': 'Evidence/ADS-03/oscal-service-lists/'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for FRR-ADS-03 compliance.
        
        Returns:
            List of evidence artifacts specific to service list documentation
        """
        return [
            {
                'artifact_name': 'Service List Documentation',
                'artifact_type': 'Markdown/HTML Documentation',
                'description': 'README.md, SERVICES.md, or docs/ files containing the detailed service list with impact levels',
                'collection_method': 'Extract from Git repository at main/master branch, verify content includes required sections',
                'validation_checks': [
                    'File exists in repository root or docs/ folder',
                    'Contains "Services Included" or equivalent section',
                    'Lists specific services with clear names',
                    'Includes impact level designations (Low, Moderate, High)',
                    'Specifies services NOT included in authorization'
                ],
                'storage_location': 'Evidence/ADS-03/documentation/service-list-README.md',
                'retention_period': '7 years per FedRAMP requirements'
            },
            {
                'artifact_name': 'Service Name Validation Report',
                'artifact_type': 'Automated Analysis Report',
                'description': 'Report validating that service names match standard cloud provider public marketing materials',
                'collection_method': 'Run automated script to extract service names and compare against official cloud provider service catalogs',
                'validation_checks': [
                    'All service names validated against cloud provider marketing names',
                    'No generic or vague terms used (e.g., "storage" → "Azure Blob Storage")',
                    'Naming conventions consistent with cloud provider documentation',
                    'Report includes confidence scores for name matching'
                ],
                'storage_location': 'Evidence/ADS-03/reports/service-name-validation.json',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Impact Level Designation Matrix',
                'artifact_type': 'Compliance Matrix',
                'description': 'Table or matrix showing each service mapped to its authorized impact level(s)',
                'collection_method': 'Parse documentation to extract service-to-impact-level mappings, generate structured matrix',
                'validation_checks': [
                    'Every service has at least one impact level designation',
                    'Impact levels use FedRAMP standard terminology (Low, Moderate, High)',
                    'No services with ambiguous or missing impact levels',
                    'Matrix cross-references with OSCAL SSP service inventory'
                ],
                'storage_location': 'Evidence/ADS-03/matrices/impact-level-matrix.csv',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Completeness Assessment Report',
                'artifact_type': 'Validation Report',
                'description': 'Report assessing whether service list is complete enough for customers to determine authorization scope',
                'collection_method': 'Automated checklist evaluation + manual review to confirm no critical gaps',
                'validation_checks': [
                    'All major service categories addressed (compute, storage, network, database, security, identity)',
                    'Services NOT included are explicitly listed',
                    'Edge cases documented (regional limitations, SKU exclusions)',
                    'No statements requiring customer to contact provider for clarification',
                    'Reviewer confirms a potential customer could determine scope independently'
                ],
                'storage_location': 'Evidence/ADS-03/reports/completeness-assessment.pdf',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Public Accessibility Evidence',
                'artifact_type': 'HTTP Test Results',
                'description': 'Evidence showing service list documentation is publicly accessible via web URL without authentication',
                'collection_method': 'Automated HTTP tests with curl/wget, screenshots of public-facing pages',
                'validation_checks': [
                    'URL returns HTTP 200 status',
                    'No authentication required to view',
                    'Content is served over HTTPS',
                    'Page loads successfully in standard web browser'
                ],
                'storage_location': 'Evidence/ADS-03/accessibility/public-url-tests.json',
                'retention_period': '7 years (monthly snapshots)'
            },
            {
                'artifact_name': 'OSCAL SSP Service Inventory',
                'artifact_type': 'OSCAL JSON Document',
                'description': 'Machine-readable OSCAL System Security Plan (SSP) containing service inventory section',
                'collection_method': 'Extract service inventory component from OSCAL SSP file, validate against FedRAMP schema',
                'validation_checks': [
                    'OSCAL SSP validates against FedRAMP profile schema',
                    'Service inventory section present in system-characteristics',
                    'Services listed match human-readable documentation',
                    'Impact levels in OSCAL match README/SERVICES.md designations'
                ],
                'storage_location': 'Evidence/ADS-03/oscal/ssp-service-inventory.json',
                'retention_period': '7 years'
            }
        ]
