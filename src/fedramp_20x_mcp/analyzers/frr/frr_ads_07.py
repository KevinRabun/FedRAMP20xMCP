"""
FRR-ADS-07: FedRAMP-Compatible Trust Centers

Providers of FedRAMP 20x Authorized _cloud service offerings_ MUST use a FedRAMP-compatible _trust center_ to store and share _authorization data_ with all necessary parties.

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


class FRR_ADS_07_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-07: FedRAMP-Compatible Trust Centers
    
    **Official Statement:**
    Providers of FedRAMP 20x Authorized _cloud service offerings_ MUST use a FedRAMP-compatible _trust center_ to store and share _authorization data_ with all necessary parties.
    
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
    
    FRR_ID = "FRR-ADS-07"
    FRR_NAME = "FedRAMP-Compatible Trust Centers"
    FRR_STATEMENT = """Providers of FedRAMP 20x Authorized _cloud service offerings_ MUST use a FedRAMP-compatible _trust center_ to store and share _authorization data_ with all necessary parties."""
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
        ("SC-28", "Protection of Information at Rest"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-07 analyzer."""
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
        Analyze Python code for FRR-ADS-07 compliance using AST.
        
        Detects FedRAMP-compatible trust center usage:
        - Trust center API integrations
        - Storage configurations
        - Data sharing mechanisms
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for trust center imports
                imports = parser.find_nodes_by_type(tree.root_node, 'import_statement')
                imports.extend(parser.find_nodes_by_type(tree.root_node, 'import_from_statement'))
                
                for imp in imports:
                    imp_text = parser.get_node_text(imp, code_bytes).decode('utf8').lower()
                    if any(keyword in imp_text for keyword in ['trustcenter', 'trust_center', 'fedramp_trust']):
                        line_num = imp.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center integration import detected",
                            description="Found trust center library import",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Ensure using FedRAMP-compatible trust center."
                        ))
                
                # Look for string literals with trust center URLs/configs
                strings = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in strings:
                    string_text = parser.get_node_text(string_node, code_bytes).decode('utf8').lower()
                    if any(keyword in string_text for keyword in ['trust-center', 'trustcenter', 'fedramp-trust']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center URL/config detected",
                            description="Found trust center reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Verify trust center is FedRAMP-compatible."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        trust_center_patterns = [
            r'trust.*center',
            r'fedramp.*trust',
            r'compliance.*center',
            r'authorization.*store',
            r'trustcenter',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_center_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center integration detected",
                        description=f"Found trust center pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure using FedRAMP-compatible trust center."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-07 compliance using AST.
        
        Detects trust center integrations in C#.
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for string literals with trust center references
                strings = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for string_node in strings:
                    string_text = parser.get_node_text(string_node, code_bytes).decode('utf8').lower()
                    if any(keyword in string_text for keyword in ['trust-center', 'trustcenter', 'fedramp']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center reference detected (C#)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(trust.*center|fedramp.*trust)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Trust center integration detected (C#)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-07 compliance using AST.
        
        Detects trust center integrations in Java.
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
                    if any(keyword in string_text for keyword in ['trust-center', 'trustcenter', 'fedramp']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center reference detected (Java)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(trust.*center|fedramp.*trust)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Trust center integration detected (Java)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-07 compliance using AST.
        
        Detects trust center integrations in TypeScript.
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
                    if any(keyword in string_text for keyword in ['trust-center', 'trustcenter', 'fedramp']):
                        line_num = string_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center reference detected (TypeScript)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(trust.*center|fedramp.*trust)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Trust center integration detected (TypeScript)",
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
        Analyze Bicep infrastructure code for FRR-ADS-07 compliance.
        
        Detects trust center hosting resources:
        - Static Web Apps for trust center frontend
        - App Service for trust center hosting
        - Storage accounts with static website
        """
        findings = []
        lines = code.split('\n')
        
        # Trust center hosting resources
        trust_resources = [
            r"resource\s+\w+\s+'Microsoft\.Web/staticSites",  # Static Web App
            r"resource\s+\w+\s+'Microsoft\.Web/sites",  # App Service
            r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts",  # Storage (static website)
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center hosting resource detected",
                        description="Found resource that could host FedRAMP-compatible trust center",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure trust center meets FedRAMP-compatible requirements for authorization data."
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-07 compliance.
        
        Detects trust center hosting resources.
        """
        findings = []
        lines = code.split('\n')
        
        # Trust center hosting resources
        trust_resources = [
            r'resource\s+"azurerm_static_site"',  # Static Web App
            r'resource\s+"azurerm_app_service"',  # App Service
            r'resource\s+"azurerm_storage_account"',  # Storage account
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center hosting resource detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure trust center is FedRAMP-compatible."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-07 compliance.
        
        Detects trust center deployment automation.
        """
        findings = []
        lines = code.split('\n')
        
        # Trust center automation patterns
        trust_patterns = [
            r'deploy.*trust.*center',
            r'trust.*center.*publish',
            r'static.*site.*deploy',
            r'authorization.*data.*sync',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center deployment automation detected",
                        description="Found trust center deployment workflow",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify trust center is FedRAMP-compatible."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-07 compliance.
        
        Detects trust center deployment automation.
        """
        findings = []
        lines = code.split('\n')
        
        # Trust center automation patterns
        trust_patterns = [
            r'deploy.*trust.*center',
            r'trust.*center.*publish',
            r'static.*site.*deploy',
            r'authorization.*data.*sync',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center deployment automation detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify trust center is FedRAMP-compatible."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-07 compliance.
        
        Detects trust center deployment automation.
        """
        findings = []
        lines = code.split('\n')
        
        # Trust center automation patterns
        trust_patterns = [
            r'deploy.*trust.*center',
            r'trust.*center.*publish',
            r'static.*site.*deploy',
            r'authorization.*data.*sync',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in trust_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center deployment automation detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify trust center is FedRAMP-compatible."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-07.
        
        Returns comprehensive guidance for collecting evidence of FedRAMP-compatible
        trust center usage.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'High - trust center configuration and usage can be detected through code analysis, infrastructure templates, and deployment automation',
            'azure_services': [
                'Azure Static Web Apps - for hosting FedRAMP-compatible trust center',
                'Azure App Service - for trust center backend services',
                'Azure Storage - for static website hosting of trust center',
                'Azure Key Vault - for secure storage of trust center credentials',
                'Azure Monitor - for tracking trust center access and usage'
            ],
            'collection_methods': [
                'Code scanning for trust center API integrations and configurations',
                'Infrastructure analysis for trust center hosting resources',
                'CI/CD pipeline inspection for trust center deployment automation',
                'Azure Resource Graph queries for trust center resource identification',
                'Access logs review for trust center usage verification',
                'Documentation review for trust center FedRAMP compatibility certification'
            ],
            'implementation_steps': [
                '1. Identify trust center platform and verify FedRAMP compatibility',
                '2. Scan code repositories for trust center API integrations',
                '3. Review infrastructure templates for trust center hosting configuration',
                '4. Analyze CI/CD pipelines for trust center deployment automation',
                '5. Query Azure resources for trust center infrastructure',
                '6. Review access logs to verify authorization data is stored in trust center',
                '7. Collect trust center FedRAMP compatibility documentation'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get specific queries for collecting FRR-ADS-07 evidence.
        """
        return [
            {
                'query_name': 'Trust Center Resource Identification',
                'query_type': 'Azure Resource Graph',
                'query': "Resources | where type in~ ('microsoft.web/staticsites', 'microsoft.web/sites', 'microsoft.storage/storageaccounts') | where tags contains 'trust-center' or name contains 'trust' | project name, type, resourceGroup, location, tags",
                'purpose': 'Identify Azure resources hosting FedRAMP-compatible trust center'
            },
            {
                'query_name': 'Trust Center Access Logs',
                'query_type': 'Azure Monitor KQL',
                'query': "AzureDiagnostics | where Category == 'ApplicationGatewayAccessLog' or Category == 'FrontDoorAccessLog' | where requestUri_s contains 'trust' | project TimeGenerated, requestUri_s, httpStatus_d, clientIP_s | order by TimeGenerated desc",
                'purpose': 'Verify trust center is being accessed for authorization data sharing'
            },
            {
                'query_name': 'Trust Center Deployment History',
                'query_type': 'Azure Resource Graph',
                'query': "ResourceChanges | where resourceGroup contains 'trust' or resourceId contains 'trust-center' | extend changeType = properties.changeType, timestamp = properties.changeAttributes.timestamp | project timestamp, changeType, resourceId, properties",
                'purpose': 'Track trust center deployment and configuration changes'
            },
            {
                'query_name': 'Code Repository Scan',
                'query_type': 'GitHub/Azure DevOps Query',
                'query': 'Search code repositories for trust center API integrations: trust_center, trustcenter, fedramp_trust',
                'purpose': 'Identify application code integrating with trust center'
            },
            {
                'query_name': 'Trust Center Storage Activity',
                'query_type': 'Azure Storage Analytics',
                'query': "StorageBlobLogs | where AccountName contains 'trust' | where OperationName == 'PutBlob' or OperationName == 'GetBlob' | project TimeGenerated, OperationName, Uri, CallerIpAddress | order by TimeGenerated desc",
                'purpose': 'Verify authorization data storage and retrieval from trust center'
            },
            {
                'query_name': 'Trust Center FedRAMP Certification Check',
                'query_type': 'Manual Documentation Review',
                'query': 'Review trust center vendor documentation for FedRAMP-compatible certification or attestation',
                'purpose': 'Verify trust center meets FedRAMP compatibility requirements'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts to collect for FRR-ADS-07.
        """
        return [
            {
                'artifact_name': 'Trust Center Configuration Export',
                'artifact_type': 'Configuration File',
                'collection_method': 'Export trust center configuration settings and FedRAMP compatibility documentation',
                'validation': 'Verify trust center is FedRAMP-compatible and properly configured for authorization data storage'
            },
            {
                'artifact_name': 'Trust Center Resource List',
                'artifact_type': 'Azure Resource Graph Query Result',
                'collection_method': 'Run Resource Graph query to identify all trust center resources',
                'validation': 'Confirm resources are dedicated to FedRAMP-compatible trust center hosting'
            },
            {
                'artifact_name': 'Trust Center Access Logs',
                'artifact_type': 'Log Files',
                'collection_method': 'Export Azure Monitor logs showing trust center access by authorized parties',
                'validation': 'Verify FedRAMP, CISA, and agency customers can access authorization data'
            },
            {
                'artifact_name': 'Trust Center Deployment Pipelines',
                'artifact_type': 'CI/CD Configuration',
                'collection_method': 'Export GitHub Actions/Azure Pipelines workflows for trust center deployment',
                'validation': 'Confirm automated deployment maintains FedRAMP compatibility'
            },
            {
                'artifact_name': 'Trust Center FedRAMP Certification',
                'artifact_type': 'Documentation',
                'collection_method': 'Obtain FedRAMP compatibility certification or attestation from trust center vendor',
                'validation': 'Verify certification is current and covers authorization data storage requirements'
            },
            {
                'artifact_name': 'Trust Center Code Integrations',
                'artifact_type': 'Code Snippets',
                'collection_method': 'Extract code samples showing trust center API integrations from application repositories',
                'validation': 'Confirm applications properly integrate with FedRAMP-compatible trust center'
            }
        ]
