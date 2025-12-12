"""
FRR-ADS-06: USDA Connect Community Portal

Providers of FedRAMP Rev5 Authorized _cloud service offerings_ MUST share _authorization data_ via the USDA Connect Community Portal UNLESS they use a FedRAMP-compatible _trust center_.

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


class FRR_ADS_06_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-06: USDA Connect Community Portal
    
    **Official Statement:**
    Providers of FedRAMP Rev5 Authorized _cloud service offerings_ MUST share _authorization data_ via the USDA Connect Community Portal UNLESS they use a FedRAMP-compatible _trust center_.
    
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
    
    FRR_ID = "FRR-ADS-06"
    FRR_NAME = "USDA Connect Community Portal"
    FRR_STATEMENT = """Providers of FedRAMP Rev5 Authorized _cloud service offerings_ MUST share _authorization data_ via the USDA Connect Community Portal UNLESS they use a FedRAMP-compatible _trust center_."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SA-9", "External System Services"),
        ("PM-15", "Security and Privacy Groups and Associations"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-06 analyzer."""
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
        Analyze Python code for FRR-ADS-06 compliance using AST.
        
        Detects portal and trust center integrations:
        - USDA Connect API references
        - Trust center configurations
        - Authorization data sharing endpoints
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for import statements
                imports = parser.find_nodes_by_type(tree.root_node, 'import_statement')
                imports.extend(parser.find_nodes_by_type(tree.root_node, 'import_from_statement'))
                
                for imp in imports:
                    imp_text = parser.get_node_text(imp, code_bytes).decode('utf8').lower()
                    if any(keyword in imp_text for keyword in ['usda', 'connect', 'trust_center', 'fedramp_portal']):
                        line_num = imp.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Portal/trust center integration import detected",
                            description=f"Found portal/trust center import",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Ensure authorization data is shared via USDA Connect Community Portal or FedRAMP-compatible trust center."
                        ))
                
                # Look for string literals with portal/trust center URLs
                strings = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in strings:
                    string_text = parser.get_node_text(string_node, code_bytes).decode('utf8').lower()
                    if any(keyword in string_text for keyword in ['usda', 'connect', 'trust-center', 'fedramp', 'portal']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Portal/trust center URL detected",
                            description="Found portal or trust center reference in code",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Verify authorization data sharing via USDA Connect or FedRAMP-compatible trust center."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        integration_patterns = [
            r'usda.*connect',
            r'community.*portal',
            r'trust.*center',
            r'fedramp.*portal',
            r'authorization.*portal',
            r'compliance.*portal',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in integration_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Portal/trust center integration detected",
                        description=f"Found integration pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure authorization data is shared via USDA Connect Community Portal or FedRAMP-compatible trust center."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-06 compliance using AST.
        
        FRR-ADS-06 is about USDA Connect portal submissions or trust center usage,
        which is typically a deployment/configuration concern rather than application code.
        Code analysis focuses on detecting portal/trust center API integrations.
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for string literals with portal/trust center references
                strings = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for string_node in strings:
                    string_text = parser.get_node_text(string_node, code_bytes).decode('utf8').lower()
                    if any(keyword in string_text for keyword in ['usda', 'connect', 'trust-center', 'fedramp', 'portal']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Portal/trust center reference detected (C#)",
                            description="Found portal or trust center reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Verify authorization data sharing method."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(usda|connect|trust.*center|fedramp.*portal)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Portal/trust center integration detected (C#)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-06 compliance using AST.
        
        FRR-ADS-06 is about USDA Connect portal submissions or trust center usage,
        which is typically a deployment/configuration concern rather than application code.
        Code analysis focuses on detecting portal/trust center API integrations.
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for string literals
                strings = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for string_node in strings:
                    string_text = parser.get_node_text(string_node, code_bytes).decode('utf8').lower()
                    if any(keyword in string_text for keyword in ['usda', 'connect', 'trust-center', 'fedramp', 'portal']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Portal/trust center reference detected (Java)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(usda|connect|trust.*center|fedramp.*portal)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Portal/trust center integration detected (Java)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-06 compliance using AST.
        
        FRR-ADS-06 is about USDA Connect portal submissions or trust center usage,
        which is typically a deployment/configuration concern rather than application code.
        Code analysis focuses on detecting portal/trust center API integrations.
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for string literals
                strings = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in strings:
                    string_text = parser.get_node_text(string_node, code_bytes).decode('utf8').lower()
                    if any(keyword in string_text for keyword in ['usda', 'connect', 'trust-center', 'fedramp', 'portal']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Portal/trust center reference detected (TypeScript)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(usda|connect|trust.*center|fedramp.*portal)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Portal/trust center integration detected (TypeScript)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-06 compliance.
        
        FRR-ADS-06 is about USDA Connect portal submissions or trust center usage,
        which is primarily a process/documentation requirement rather than infrastructure code.
        Infrastructure analysis focuses on trust center hosting resources.
        """
        findings = []
        lines = code.split('\n')
        
        # Detect Azure resources that might host trust center
        trust_center_resources = [
            r"resource\s+\w+\s+'Microsoft\.Web/sites",  # Static Web App or App Service
            r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts",  # Storage for static website
            r"resource\s+\w+\s+'Microsoft\.Cdn/profiles",  # CDN for trust center
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_center_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Potential trust center hosting resource detected",
                        description="Found Azure resource that could host FedRAMP-compatible trust center",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="If hosting trust center, ensure it meets FedRAMP-compatible requirements for authorization data sharing."
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-06 compliance.
        
        FRR-ADS-06 is about USDA Connect portal submissions or trust center usage,
        which is primarily a process/documentation requirement rather than infrastructure code.
        Infrastructure analysis focuses on trust center hosting resources.
        """
        findings = []
        lines = code.split('\n')
        
        # Detect resources that might host trust center
        trust_center_resources = [
            r'resource\s+"azurerm_app_service"',  # App Service
            r'resource\s+"azurerm_static_site"',  # Static Web App
            r'resource\s+"azurerm_storage_account"',  # Storage for static website
            r'resource\s+"azurerm_cdn_profile"',  # CDN
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_center_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Potential trust center hosting resource detected",
                        description="Found resource that could host FedRAMP-compatible trust center",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="If hosting trust center, ensure it meets FedRAMP-compatible requirements."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-06 compliance.
        
        Detects automation for authorization data submission to USDA Connect or trust center.
        """
        findings = []
        lines = code.split('\n')
        
        # Detect steps that might submit to portal or trust center
        submission_patterns = [
            r'usda.*connect',
            r'portal.*upload',
            r'trust.*center.*publish',
            r'authorization.*data.*submit',
            r'fedramp.*submission',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in submission_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Authorization data submission automation detected",
                        description="Found GitHub Actions step for portal/trust center submission",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify automation submits to USDA Connect or FedRAMP-compatible trust center."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-06 compliance.
        
        Detects automation for authorization data submission to USDA Connect or trust center.
        """
        findings = []
        lines = code.split('\n')
        
        # Detect tasks that might submit to portal or trust center
        submission_patterns = [
            r'usda.*connect',
            r'portal.*upload',
            r'trust.*center.*publish',
            r'authorization.*data.*submit',
            r'fedramp.*submission',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in submission_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Authorization data submission automation detected",
                        description="Found Azure Pipelines task for portal/trust center submission",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify automation submits to USDA Connect or FedRAMP-compatible trust center."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-06 compliance.
        
        Detects automation for authorization data submission to USDA Connect or trust center.
        """
        findings = []
        lines = code.split('\n')
        
        # Detect scripts that might submit to portal or trust center
        submission_patterns = [
            r'usda.*connect',
            r'portal.*upload',
            r'trust.*center.*publish',
            r'authorization.*data.*submit',
            r'fedramp.*submission',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in submission_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Authorization data submission automation detected",
                        description="Found GitLab CI job for portal/trust center submission",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify automation submits to USDA Connect or FedRAMP-compatible trust center."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-06.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - Can automate detection of trust center configurations and portal integration code, but requires manual verification of USDA Connect portal submissions',
            'automation_approach': 'Automated detection of trust center integrations and portal API code, combined with manual verification of USDA Connect Community Portal submissions or FedRAMP-compatible trust center usage',
            'evidence_artifacts': [
                'USDA Connect Community Portal submission confirmation',
                'Trust center configuration (if using FedRAMP-compatible trust center)',
                'Authorization data submission logs',
                'Portal integration code or trust center API configuration',
                'Screenshots showing portal/trust center authorization data',
                'Documentation explaining chosen sharing method (portal vs trust center)'
            ],
            'collection_queries': [
                'USDA Connect: Portal submission confirmation emails/receipts',
                'Trust center: Configuration showing FedRAMP-compatible status',
                'API logs: Requests to USDA Connect or trust center APIs',
                'Documentation: Policy stating chosen authorization data sharing method'
            ],
            'manual_validation_steps': [
                '1. Verify authorization data shared via USDA Connect Community Portal OR FedRAMP-compatible trust center',
                '2. If using portal: Obtain submission confirmation from USDA Connect',
                '3. If using trust center: Verify trust center is FedRAMP-compatible',
                '4. Review authorization data content to ensure completeness',
                '5. Confirm sharing method documented in authorization package',
                '6. Validate regular updates to portal or trust center'
            ],
            'recommended_services': [
                'USDA Connect Community Portal - primary sharing method',
                'FedRAMP-compatible Trust Centers (OneTrust, ServiceNow Trust Center)',
                'Azure Static Web Apps - hosting trust center website',
                'Azure API Management - trust center API gateway',
                'Azure AD B2C - trust center authentication'
            ],
            'azure_services': [
                'Azure Static Web Apps (hosting FedRAMP-compatible trust center)',
                'Azure API Management (trust center API for authorization data)',
                'Azure AD B2C (authentication for trust center access)',
                'Azure Storage (storing authorization data for trust center)',
                'Azure CDN (global distribution of trust center content)'
            ],
            'collection_methods': [
                'Manual: Obtain USDA Connect portal submission confirmation',
                'Manual: Verify trust center FedRAMP-compatible certification',
                'Automated: Scan code for portal/trust center API integration',
                'Automated: Review API logs for authorization data submissions',
                'Manual: Review documentation explaining sharing method choice',
                'Automated: Monitor trust center uptime and accessibility'
            ],
            'implementation_steps': [
                '1. Choose authorization data sharing method: USDA Connect Portal OR FedRAMP-compatible trust center',
                '2. If choosing portal: Register with USDA Connect Community Portal',
                '3. If choosing trust center: Verify trust center meets FedRAMP-compatible criteria',
                '4. Implement integration (portal API or trust center configuration)',
                '5. Submit authorization data (SSP, service list, controls) via chosen method',
                '6. Obtain confirmation of successful submission/publication',
                '7. Document chosen method and rationale in authorization package'
            ],
            'integration_points': [
                'USDA Connect Community Portal API integration',
                'FedRAMP-compatible trust center configuration',
                'OSCAL export to portal or trust center format',
                'Automated authorization data synchronization'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get specific queries for collecting FRR-ADS-06 evidence.
        
        Returns:
            List of evidence collection queries specific to USDA Connect portal or trust center verification
        """
        return [
            {
                'method_type': 'Manual Verification',
                'name': 'USDA Connect Community Portal Submission Confirmation',
                'description': 'Obtain confirmation that authorization data was successfully submitted to USDA Connect Community Portal',
                'command': '# Manual: Login to USDA Connect portal, navigate to submissions, export confirmation/receipt',
                'purpose': 'Verify compliance with FRR-ADS-06 requirement to share authorization data via USDA Connect portal',
                'evidence_type': 'Portal submission confirmation email or screenshot',
                'validation_checks': [
                    'Submission confirmation shows authorization data uploaded',
                    'Confirmation includes timestamp and submission ID',
                    'Authorization data includes SSP, service list, and control descriptions',
                    'Submission is for FedRAMP Rev5 authorized cloud service offering'
                ],
                'storage_location': 'Evidence/ADS-06/portal-submissions/'
            },
            {
                'method_type': 'Trust Center Verification',
                'name': 'FedRAMP-Compatible Trust Center Validation',
                'description': 'Verify trust center is FedRAMP-compatible if using trust center exemption instead of USDA Connect portal',
                'command': '# Manual: Review trust center documentation, verify FedRAMP-compatible certification or attestation',
                'purpose': 'Validate exemption from USDA Connect portal requirement by using FedRAMP-compatible trust center per FRR-ADS-06',
                'evidence_type': 'Trust center FedRAMP-compatible certification document',
                'validation_checks': [
                    'Trust center explicitly certified or attested as FedRAMP-compatible',
                    'Trust center hosts authorization data (SSP, service list, controls)',
                    'Trust center accessible to FedRAMP, CISA, and agency customers',
                    'Trust center meets FedRAMP data sharing requirements'
                ],
                'storage_location': 'Evidence/ADS-06/trust-center-certification/'
            },
            {
                'method_type': 'Code Analysis',
                'name': 'Portal or Trust Center Integration Detection',
                'description': 'Scan code for API integrations with USDA Connect portal or trust center platforms',
                'command': 'grep -r -E "(usda.*connect|community.*portal|trust.*center.*api)" src/ --include="*.py" --include="*.cs" --include="*.java" --include="*.ts"',
                'purpose': 'Identify automated integration code for authorization data submission to portal or trust center',
                'evidence_type': 'Source code with portal/trust center API integration',
                'validation_checks': [
                    'Code references USDA Connect API endpoints or trust center APIs',
                    'Integration includes authentication and authorization data submission',
                    'Code handles submission errors and retries',
                    'Automated synchronization keeps authorization data current'
                ],
                'storage_location': 'Evidence/ADS-06/integration-code/'
            },
            {
                'method_type': 'API Log Analysis',
                'name': 'Authorization Data Submission Log Review',
                'description': 'Review API logs showing authorization data submissions to USDA Connect or trust center',
                'command': 'az monitor activity-log list --resource-group {rg} --query "[?contains(operationName.value, \'usda\') || contains(operationName.value, \'trust\')]" | jq ".[] | {timestamp: .eventTimestamp, operation: .operationName.value}"',
                'purpose': 'Verify regular authorization data submissions to comply with FRR-ADS-06',
                'evidence_type': 'API submission log showing successful uploads',
                'validation_checks': [
                    'Logs show successful HTTP 200/201 responses from portal or trust center',
                    'Submissions occur regularly (monthly or on authorization updates)',
                    'Payload includes complete authorization data (SSP, service list)',
                    'No submission failures or only failures with documented resolution'
                ],
                'storage_location': 'Evidence/ADS-06/api-logs/'
            },
            {
                'method_type': 'Documentation Review',
                'name': 'Authorization Data Sharing Method Documentation',
                'description': 'Review documentation explaining chosen method (USDA Connect portal or FedRAMP-compatible trust center)',
                'command': '# Manual: Review SSP, authorization package, or compliance documentation for sharing method',
                'purpose': 'Confirm provider has documented their chosen authorization data sharing method per FRR-ADS-06',
                'evidence_type': 'Documentation section explaining portal vs trust center choice',
                'validation_checks': [
                    'Documentation explicitly states: "USDA Connect portal" OR "FedRAMP-compatible trust center"',
                    'Rationale provided for trust center choice (if applicable)',
                    'Documentation includes URLs or access instructions for authorization data',
                    'Method documented in SSP or authorization package'
                ],
                'storage_location': 'Evidence/ADS-06/documentation/'
            },
            {
                'method_type': 'Accessibility Test',
                'name': 'Trust Center Authorization Data Accessibility Verification',
                'description': 'Test trust center URL to verify authorization data is publicly accessible (if using trust center exemption)',
                'command': 'curl -I -s https://{trustCenterUrl}/authorization-data | grep "HTTP/2 200"',
                'purpose': 'Validate trust center makes authorization data accessible to FedRAMP, CISA, and agencies per FRR-ADS-06',
                'evidence_type': 'HTTP accessibility test results',
                'validation_checks': [
                    'Trust center URL returns HTTP 200 (accessible)',
                    'Authorization data viewable without special credentials (or with FedRAMP/agency credentials)',
                    'Content includes SSP, service list, control descriptions',
                    'Trust center uptime meets availability requirements'
                ],
                'storage_location': 'Evidence/ADS-06/accessibility-tests/'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for FRR-ADS-06 compliance.
        
        Returns:
            List of evidence artifacts specific to USDA Connect portal or trust center verification
        """
        return [
            {
                'artifact_name': 'USDA Connect Portal Submission Confirmation',
                'artifact_type': 'Portal Submission Receipt',
                'description': 'Confirmation email or screenshot showing successful authorization data submission to USDA Connect Community Portal',
                'collection_method': 'Login to USDA Connect portal, navigate to submissions history, export confirmation or take screenshot',
                'validation_checks': [
                    'Confirmation shows submission timestamp and unique ID',
                    'Authorization data submission includes SSP, service list, controls',
                    'Submission is for FedRAMP Rev5 authorized offering',
                    'Confirmation issued by USDA Connect system'
                ],
                'storage_location': 'Evidence/ADS-06/portal-confirmations/submission-{date}.pdf',
                'retention_period': '7 years per FedRAMP requirements'
            },
            {
                'artifact_name': 'FedRAMP-Compatible Trust Center Certification',
                'artifact_type': 'Certification Document',
                'description': 'Certificate or attestation showing trust center is FedRAMP-compatible (if using trust center exemption)',
                'collection_method': 'Obtain certification from trust center vendor or FedRAMP program office',
                'validation_checks': [
                    'Certificate explicitly states "FedRAMP-compatible"',
                    'Issued by recognized authority (FedRAMP PMO, trust center vendor)',
                    'Certification current and not expired',
                    'Trust center meets FedRAMP authorization data sharing requirements'
                ],
                'storage_location': 'Evidence/ADS-06/trust-center/fedramp-compatible-cert.pdf',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Portal/Trust Center Integration Code',
                'artifact_type': 'Source Code',
                'description': 'Source code implementing API integration with USDA Connect portal or FedRAMP-compatible trust center',
                'collection_method': 'Export source code files containing portal or trust center API calls',
                'validation_checks': [
                    'Code references USDA Connect API endpoints or trust center APIs',
                    'Authentication implemented (API keys, OAuth tokens)',
                    'Error handling for submission failures',
                    'Automated synchronization logic to keep data current'
                ],
                'storage_location': 'Evidence/ADS-06/code/integration-implementation/',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Authorization Data Submission Logs',
                'artifact_type': 'API Activity Logs',
                'description': 'Logs showing successful authorization data submissions to USDA Connect or trust center',
                'collection_method': 'Export API logs from application monitoring (Azure Monitor, CloudWatch), filter for portal/trust center submissions',
                'validation_checks': [
                    'Logs show HTTP 200/201 success responses',
                    'Submissions occur regularly (monthly minimum)',
                    'Payload size indicates complete authorization data (SSP + service list)',
                    'No unresolved submission failures'
                ],
                'storage_location': 'Evidence/ADS-06/logs/submission-history.json',
                'retention_period': '7 years (monthly samples)'
            },
            {
                'artifact_name': 'Authorization Data Sharing Method Documentation',
                'artifact_type': 'Policy/Procedure Document',
                'description': 'Documentation section in SSP or authorization package explaining chosen sharing method (portal or trust center)',
                'collection_method': 'Extract relevant section from SSP or authorization documentation',
                'validation_checks': [
                    'Documentation states: "USDA Connect Community Portal" OR "FedRAMP-compatible trust center"',
                    'Rationale provided for trust center choice (if applicable)',
                    'URLs or access instructions included',
                    'Method approved by authorizing official'
                ],
                'storage_location': 'Evidence/ADS-06/documentation/sharing-method-policy.pdf',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Trust Center Accessibility Test Results',
                'artifact_type': 'HTTP Test Report',
                'description': 'Results from automated testing of trust center URL showing authorization data is publicly accessible (if using trust center)',
                'collection_method': 'Run automated HTTP tests against trust center URL, verify accessibility and content',
                'validation_checks': [
                    'Trust center returns HTTP 200 status',
                    'Authorization data (SSP, service list) accessible',
                    'No authentication errors (or appropriate FedRAMP/agency credentials work)',
                    'Monthly uptime >=99.9%'
                ],
                'storage_location': 'Evidence/ADS-06/testing/trust-center-accessibility.json',
                'retention_period': '7 years (monthly snapshots)'
            }
        ]
