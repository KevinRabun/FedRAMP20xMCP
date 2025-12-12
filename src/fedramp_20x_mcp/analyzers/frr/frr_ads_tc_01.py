"""
FRR-ADS-TC-01: Trust Center Assessment

_Trust centers_ MUST be included as an _information resource_ included in the _cloud service offering_ for assessment if FRR-MAS-01 applies. 

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


class FRR_ADS_TC_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-01: Trust Center Assessment
    
    **Official Statement:**
    _Trust centers_ MUST be included as an _information resource_ included in the _cloud service offering_ for assessment if FRR-MAS-01 applies. 
    
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
    
    FRR_ID = "FRR-ADS-TC-01"
    FRR_NAME = "Trust Center Assessment"
    FRR_STATEMENT = """_Trust centers_ MUST be included as an _information resource_ included in the _cloud service offering_ for assessment if FRR-MAS-01 applies. """
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CA-2", "Security Assessments"),
        ("CA-8", "Penetration Testing"),
        ("SA-9", "External System Services"),
        ("SA-11", "Developer Testing and Evaluation"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-01 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-01 compliance using AST.
        
        Detects trust center assessment mechanisms:
        - Trust center as information resource
        - Assessment scope inclusion
        - Resource inventory functions
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function definitions for assessment and inventory
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in function_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    # Check for trust center assessment functions
                    if any(keyword in func_name_lower for keyword in ['trust_center_assessment', 'assess_trust_center', 'trust_center_inventory', 'information_resource']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center assessment function detected",
                            description="Found function for trust center assessment or inventory",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify trust center included as information resource in CSO assessment scope."
                        ))
                
                # Check string literals for trust center references
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if 'trust center' in string_text and any(keyword in string_text for keyword in ['assessment', 'information resource', 'scope', 'inventory']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center assessment reference detected",
                            description="Found trust center as information resource in assessment context",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="Ensure trust center is properly included in assessment scope."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        assessment_patterns = [
            r'trust.*center.*assessment',
            r'trust.*center.*information.*resource',
            r'assess.*trust.*center',
            r'inventory.*trust.*center',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in assessment_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Trust center assessment pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure trust center included as information resource in CSO assessment."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-01 compliance using AST.
        
        Detects trust center assessment in C# applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['trustcenterassessment', 'assesstrustcenter', 'trustcenterinventory', 'informationresource']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center assessment method detected",
                            description="Found method for trust center assessment",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify trust center included as information resource in assessment."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'TrustCenter.*(?:Assessment|Inventory)|InformationResource.*TrustCenter', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Trust center assessment detected",
                    description="Found trust center assessment reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure trust center included in CSO assessment scope."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-01 compliance using AST.
        
        Detects trust center assessment in Java applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['trustcenterassessment', 'assesstrustcenter', 'trustcenterinventory', 'informationresource']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center assessment method detected",
                            description="Found method for trust center assessment",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Verify trust center included as information resource in assessment."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'trustCenter.*(?:Assessment|Inventory)|informationResource.*TrustCenter', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Trust center assessment detected",
                    description="Found trust center assessment reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure trust center included in CSO assessment scope."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-01 compliance using AST.
        
        Detects trust center assessment in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function declarations
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    if any(keyword in func_name_lower for keyword in ['trustcenterassessment', 'assesstrustcenter', 'trustcenterinventory', 'informationresource']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center assessment function detected",
                            description="Found function for trust center assessment",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify trust center included as information resource in assessment."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['trustcenter', 'assessment', 'informationresource']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Trust center assessment handler detected",
                            description="Found trust center assessment handler",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure trust center in assessment scope."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'trustCenter.*(?:Assessment|Inventory)|informationResource.*TrustCenter', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Trust center assessment detected",
                    description="Found trust center assessment reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure trust center included in CSO assessment scope."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-01 compliance.
        
        NOT APPLICABLE: Trust center assessment inclusion is a security assessment
        scoping requirement, not an infrastructure configuration requirement. The
        requirement mandates that trust centers be included as information resources
        in the cloud service offering assessment scope if FRR-MAS-01 applies.
        
        This is determined through:
        1. Assessment planning and scoping documentation
        2. Information resource inventory (manual or automated)
        3. Assessor inclusion of trust center in assessment activities
        4. Security Assessment Plan (SAP) documentation
        
        These are assessment process and documentation concerns, not infrastructure
        code concerns.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-01 compliance.
        
        NOT APPLICABLE: Trust center assessment inclusion is a security assessment
        scoping requirement, not an infrastructure configuration requirement. The
        requirement mandates that trust centers be included as information resources
        in the cloud service offering assessment scope if FRR-MAS-01 applies.
        
        This is determined through:
        1. Assessment planning and scoping documentation
        2. Information resource inventory (manual or automated)
        3. Assessor inclusion of trust center in assessment activities
        4. Security Assessment Plan (SAP) documentation
        
        These are assessment process and documentation concerns, not infrastructure
        code concerns.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-01 compliance.
        
        NOT APPLICABLE: Trust center assessment inclusion is a security assessment
        scoping and planning requirement, not a CI/CD pipeline concern. The requirement
        mandates that assessors include trust centers as information resources in
        their assessment scope, which is an assessment process documentation issue,
        not a build or deployment automation concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-01 compliance.
        
        NOT APPLICABLE: Trust center assessment inclusion is a security assessment
        scoping and planning requirement, not a CI/CD pipeline concern. The requirement
        mandates that assessors include trust centers as information resources in
        their assessment scope, which is an assessment process documentation issue,
        not a build or deployment automation concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-01 compliance.
        
        NOT APPLICABLE: Trust center assessment inclusion is a security assessment
        scoping and planning requirement, not a CI/CD pipeline concern. The requirement
        mandates that assessors include trust centers as information resources in
        their assessment scope, which is an assessment process documentation issue,
        not a build or deployment automation concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-TC-01.
        
        Partially code-detectable (can find inventory functions), but requires assessment documentation review.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Medium - can detect resource inventory code, but requires Security Assessment Plan review',
            'automation_approach': 'Hybrid - automated inventory detection + manual SAP review',
            'recommended_services': [
                'Azure Resource Graph - Query and inventory all Azure resources including trust center components',
                'Azure Resource Manager (ARM) - Retrieve resource metadata and configurations',
                'Microsoft Defender for Cloud - Security assessment and compliance monitoring',
                'Azure Policy - Enforce resource tagging and inventory requirements',
                'Azure Service Health - Monitor trust center service availability for assessment',
            ],
            'collection_methods': [
                'Automated resource discovery and inventory',
                'Configuration Management Database (CMDB) queries',
                'Security Assessment Plan (SAP) review',
                'System Security Plan (SSP) boundary diagram review',
                'Assessor interview and documentation review',
                'Trust center resource tagging verification',
            ],
            'implementation_steps': [
                '1. Implement automated information resource inventory system',
                '2. Tag trust center resources in Azure/AWS for discovery',
                '3. Document trust center as information resource in SSP',
                '4. Include trust center in Security Assessment Plan (SAP) scope',
                '5. Brief assessor on trust center role and location',
                '6. Verify FRR-MAS-01 applicability to determine trust center assessment requirement',
                '7. Coordinate with 3PAO to include trust center in assessment activities',
                '8. Collect assessment evidence (security testing, interviews, documentation review)',
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get automated queries for collecting evidence of FRR-ADS-TC-01 compliance.
        
        Returns queries for verifying trust center assessment inclusion.
        """
        return [
            {
                'query_name': 'Azure Resource Inventory Including Trust Center',
                'query_type': 'Azure Resource Graph',
                'query': '''Resources
| where tags["component"] == "trust-center" or tags["service"] == "trust-center" or name contains "trust-center"
| project name, type, location, resourceGroup, subscriptionId, tags
| order by name asc''',
                'data_source': 'Azure Resource Graph',
                'evidence_type': 'Trust center resource inventory for assessment scope',
            },
            {
                'query_name': 'FRR-MAS-01 Applicability Check',
                'query_type': 'Manual',
                'query': 'Review FRR-MAS-01 requirements to determine if trust center assessment is required',
                'data_source': 'FedRAMP 20x requirements documentation',
                'evidence_type': 'Conditional requirement applicability determination',
            },
            {
                'query_name': 'Security Assessment Plan (SAP) Review',
                'query_type': 'Manual',
                'query': 'Review SAP Section 2 (Scope) to confirm trust center listed as information resource',
                'data_source': 'Security Assessment Plan (SAP) documentation',
                'evidence_type': 'Assessment scope documentation showing trust center inclusion',
            },
            {
                'query_name': 'System Security Plan (SSP) Boundary Diagram',
                'query_type': 'Manual',
                'query': 'Review SSP authorization boundary diagram to confirm trust center within scope',
                'data_source': 'System Security Plan (SSP) Section 9',
                'evidence_type': 'System boundary documentation showing trust center as CSO component',
            },
            {
                'query_name': 'Defender for Cloud Assessment Coverage',
                'query_type': 'KQL',
                'query': '''SecurityAssessment
| where ResourceDetails contains "trust-center" or ResourceDetails contains "trust center"
| summarize AssessmentCount = count() by AssessmentName, RecommendationState
| order by AssessmentCount desc''',
                'data_source': 'Microsoft Defender for Cloud',
                'evidence_type': 'Security assessments performed on trust center resources',
            },
            {
                'query_name': '3PAO Assessment Report Review',
                'query_type': 'Manual',
                'query': 'Review Security Assessment Report (SAR) to confirm trust center testing was performed',
                'data_source': 'Security Assessment Report (SAR) from 3PAO',
                'evidence_type': 'Independent assessment evidence of trust center evaluation',
            },
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts for FRR-ADS-TC-01 compliance.
        
        Returns specific documents needed to demonstrate trust center assessment inclusion.
        """
        return [
            'Security Assessment Plan (SAP) showing trust center in assessment scope',
            'System Security Plan (SSP) with authorization boundary diagram including trust center',
            'Information resource inventory listing trust center components',
            'Azure Resource Graph query results showing trust center resources',
            'FRR-MAS-01 applicability determination memo or documentation',
            'Security Assessment Report (SAR) with trust center testing results',
            '3PAO attestation that trust center was included in assessment activities',
            'Trust center configuration and architecture documentation',
            'Assessment test evidence (penetration testing, vulnerability scanning) for trust center',
            'Interview notes with assessor confirming trust center assessment inclusion',
        ]
