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
        ("PM-9", "Risk Management Strategy"),
        ("PL-2", "System Security Plan"),
        ("SA-4", "Acquisition Process"),
        ("SA-9", "External System Services"),
        ("SC-8", "Transmission Confidentiality and Integrity"),
        ("IA-2", "Identification and Authentication"),
    ]
    CODE_DETECTABLE = "No"
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
        
        FRR-ADS-01 is a documentation requirement about public information sharing.
        Infrastructure code analysis is not applicable.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-01 compliance.
        
        FRR-ADS-01 is a documentation requirement about public information sharing.
        Infrastructure code analysis is not applicable.
        """
        return []
    
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
            'automation_feasibility': 'High',
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
            'azure_services': [
                'Azure Static Web Apps - for hosting public documentation',
                'Azure CDN - for global documentation availability',
                'Azure Storage (Blob with Static Website) - for document hosting',
                'Azure App Service - for dynamic documentation portals',
                'Azure Front Door - for high-availability documentation access'
            ],
            'collection_methods': [
                'Automated git repository scanning for documentation files',
                'HTTP accessibility testing for public URLs',
                'FedRAMP Marketplace API queries for listing verification',
                'OSCAL format validation using official validators',
                'Documentation timestamp and currency analysis',
                'Content completeness checking via keyword search'
            ],
            'implementation_steps': [
                '1. Ensure README.md and docs/ directory exist in repository root',
                '2. Publish OSCAL SSP or component definition in machine-readable format',
                '3. Configure GitHub Pages or Azure Static Web Apps for public hosting',
                '4. Submit service listing to FedRAMP Marketplace',
                '5. Add CI/CD checks to validate documentation completeness',
                '6. Set up automated publishing on documentation updates',
                '7. Monitor public accessibility monthly via automated tests'
            ],
            'integration_points': [
                'OSCAL format export for automated compliance reporting',
                'FedRAMP Marketplace API for status verification',
                'Documentation as code - version control integration',
                'Automated documentation testing in CI/CD',
                'Public website monitoring for availability'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get evidence collection queries for FRR-ADS-01: Public Information.
        
        Returns queries to gather evidence that cloud service offering information
        is publicly shared in both human-readable and machine-readable formats.
        """
        return [
            {
                'method_type': 'Git Repository Scan',
                'name': 'Documentation File Inventory',
                'description': 'List all documentation files including README, OSCAL, and schema files',
                'command': 'git ls-files | grep -E "(README|OSCAL|oscal|schema|\.json$|\.yaml$|\.md$)" | head -30',
                'purpose': 'Identify what documentation exists in the repository',
                'evidence_type': 'File listing showing presence of human-readable and machine-readable documentation',
                'validation_checks': 'Verify at least one human-readable file (README.md) and one machine-readable file (OSCAL XML/JSON or schema) exist',
                'storage_location': 'Evidence system under "FRR-ADS-01/DocumentationInventory"'
            },
            {
                'method_type': 'HTTP/Web Verification',
                'name': 'Public Accessibility Check',
                'description': 'Verify documentation is publicly accessible without authentication',
                'command': 'curl -I https://[service-url]/documentation OR curl -I https://[github-pages-url]',
                'purpose': 'Confirm documentation is publicly available, not behind authentication',
                'evidence_type': 'HTTP response headers showing 200 OK status for public documentation URLs',
                'validation_checks': 'HTTP 200 response; No authentication required; Content-Type indicates documentation (text/html or application/json)',
                'storage_location': 'Evidence system under "FRR-ADS-01/PublicAccessibility"'
            },
            {
                'method_type': 'FedRAMP Marketplace API',
                'name': 'FedRAMP Listing Verification',
                'description': 'Verify service is listed in FedRAMP Marketplace with complete information',
                'command': 'GET https://marketplace.fedramp.gov/api/public/products/[product-id] OR check https://marketplace.fedramp.gov',
                'purpose': 'Confirm service has official FedRAMP public listing with service details',
                'evidence_type': 'FedRAMP Marketplace API response or screenshot showing service listing',
                'validation_checks': 'Service appears in marketplace; Listing includes service name, CSP, impact level, authorization date',
                'storage_location': 'Evidence system under "FRR-ADS-01/FedRAMPListing"'
            },
            {
                'method_type': 'Format Validation',
                'name': 'Machine-Readable Format Verification',
                'description': 'Validate machine-readable files are well-formed and contain required information',
                'command': 'Validate OSCAL files with OSCAL validator; Validate JSON schemas with JSON Schema validator',
                'purpose': 'Ensure machine-readable formats are valid and contain service offering information',
                'evidence_type': 'Validation reports showing OSCAL/JSON files are well-formed and complete',
                'validation_checks': 'Files pass format validation; Files contain service information (name, boundary, impact level)',
                'storage_location': 'Evidence system under "FRR-ADS-01/FormatValidation"'
            },
            {
                'method_type': 'Timestamp Analysis',
                'name': 'Documentation Currency Check',
                'description': 'Verify documentation is up-to-date (modified within acceptable timeframe)',
                'command': 'git log -1 --format="%ai %s" -- README.md docs/ OR stat command for file modification time',
                'purpose': 'Confirm documentation is current and maintained, not stale',
                'evidence_type': 'File modification timestamps and git commit history',
                'validation_checks': 'Documentation updated within last 90 days OR matches current authorization package date',
                'storage_location': 'Evidence system under "FRR-ADS-01/DocumentationCurrency"'
            },
            {
                'method_type': 'Content Analysis',
                'name': 'Required Information Completeness',
                'description': 'Analyze documentation content to ensure all required information elements are present',
                'command': 'grep -i "cloud service\\|fedramp\\|authorized\\|impact level\\|boundary" README.md docs/*',
                'purpose': 'Verify documentation contains all required service offering information',
                'evidence_type': 'Content excerpts showing presence of required information elements',
                'validation_checks': 'Documentation mentions: service name, FedRAMP authorization, impact level(s), authorization boundary',
                'storage_location': 'Evidence system under "FRR-ADS-01/ContentCompleteness"'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get evidence artifacts for FRR-ADS-01: Public Information.
        
        Returns descriptions of evidence artifacts that demonstrate public sharing
        of cloud service offering information in required formats.
        """
        return [
            {
                'artifact_name': 'Documentation File Inventory',
                'artifact_type': 'File Listing',
                'description': 'Complete list of all documentation files in repository (README, OSCAL, schemas)',
                'collection_method': 'Execute git ls-files or directory listing command; filter for documentation file types',
                'validation_checks': [
                    'At least one human-readable file present (README.md, docs/*.md, or website)',
                    'At least one machine-readable file present (OSCAL XML/JSON, JSON schema, YAML)',
                    'Files are in main/master branch (not hidden in development branches)',
                    'Files are not gitignored or excluded from public view'
                ],
                'storage_location': 'Central evidence repository under "FRR-ADS-01/FileInventory"',
                'retention_period': '730 days (2 years)'
            },
            {
                'artifact_name': 'Public Accessibility Report',
                'artifact_type': 'Verification Report',
                'description': 'Test results showing documentation is publicly accessible without authentication',
                'collection_method': 'Execute HTTP requests to documentation URLs; verify no authentication required; capture response codes and headers',
                'validation_checks': [
                    'HTTP 200 OK response for documentation URLs',
                    'No authentication challenge (no 401/403 responses)',
                    'Content is returned (not empty or error page)',
                    'URLs are listed in README or other discovery documentation'
                ],
                'storage_location': 'Central evidence repository under "FRR-ADS-01/PublicAccessibility"',
                'retention_period': '730 days (2 years)'
            },
            {
                'artifact_name': 'FedRAMP Marketplace Listing',
                'artifact_type': 'Screenshot/API Response',
                'description': 'FedRAMP Marketplace entry showing service is publicly listed with complete information',
                'collection_method': 'Query FedRAMP Marketplace API OR capture screenshot of marketplace listing page',
                'validation_checks': [
                    'Service appears in FedRAMP Marketplace',
                    'Listing shows: service name, CSP name, impact level(s), authorization date, authorization type',
                    'Listing status is "Authorized" or "FedRAMP Authorized"',
                    'Listing is publicly visible (no login required to view)'
                ],
                'storage_location': 'Central evidence repository under "FRR-ADS-01/MarketplaceListing"',
                'retention_period': '730 days (2 years)'
            },
            {
                'artifact_name': 'Format Compliance Report',
                'artifact_type': 'Validation Report',
                'description': 'Validation results for machine-readable formats (OSCAL, JSON Schema)',
                'collection_method': 'Run OSCAL validator on OSCAL files; run JSON Schema validator on schema files; capture validation output',
                'validation_checks': [
                    'OSCAL files validate against official OSCAL schema',
                    'JSON files are well-formed JSON',
                    'Files contain service offering information (not empty or placeholder)',
                    'Validation tools report zero errors'
                ],
                'storage_location': 'Central evidence repository under "FRR-ADS-01/FormatCompliance"',
                'retention_period': '730 days (2 years)'
            },
            {
                'artifact_name': 'OSCAL System Security Plan (SSP)',
                'artifact_type': 'Machine-Readable Document',
                'description': 'OSCAL-formatted SSP or component definition containing service offering details',
                'collection_method': 'Export or locate OSCAL SSP XML/JSON file from repository or documentation site',
                'validation_checks': [
                    'File is valid OSCAL format (SSP, SAP, SAR, or component definition)',
                    'File contains system-information section with service details',
                    'File includes authorization-boundary information',
                    'File is publicly accessible (in public repo or on public website)'
                ],
                'storage_location': 'Central evidence repository under "FRR-ADS-01/OSCAL"',
                'retention_period': '730 days (2 years)'
            },
            {
                'artifact_name': 'Monthly Attestation of Public Availability',
                'artifact_type': 'Attestation Statement',
                'description': 'Signed statement from CSP confirming documentation remains publicly available and up-to-date',
                'collection_method': 'Obtain signed attestation from CSP representative or automated monitoring report',
                'validation_checks': [
                    'Attestation signed by authorized CSP representative',
                    'Attestation dated within last 30 days',
                    'Attestation specifically addresses public availability of documentation',
                    'Attestation confirms both human-readable and machine-readable formats are current'
                ],
                'storage_location': 'Central evidence repository under "FRR-ADS-01/Attestation"',
                'retention_period': '730 days (2 years)'
            }
        ]
