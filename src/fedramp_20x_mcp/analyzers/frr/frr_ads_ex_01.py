"""
FRR-ADS-EX-01: Legacy Self-Managed Repository Exception

Providers of FedRAMP Rev5 Authorized _cloud service offerings_ at FedRAMP High using a legacy self-managed repository for _authorization data_ MAY ignore the requirements in this Authorization Data Sharing document until future notice.

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: MAY
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_EX_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-EX-01: Legacy Self-Managed Repository Exception
    
    **Official Statement:**
    Providers of FedRAMP Rev5 Authorized _cloud service offerings_ at FedRAMP High using a legacy self-managed repository for _authorization data_ MAY ignore the requirements in this Authorization Data Sharing document until future notice.
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** MAY
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-ADS-EX-01"
    FRR_NAME = "Legacy Self-Managed Repository Exception"
    FRR_STATEMENT = """Providers of FedRAMP Rev5 Authorized _cloud service offerings_ at FedRAMP High using a legacy self-managed repository for _authorization data_ MAY ignore the requirements in this Authorization Data Sharing document until future notice."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MAY"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SA-9", "External System Services"),
        ("SI-12", "Information Management and Retention"),
        ("PL-2", "System Security Plan"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-EX-01 analyzer."""
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
        Analyze Python code for FRR-ADS-EX-01 compliance using AST.
        
        Detects legacy self-managed repository usage:
        - Legacy repository configuration references
        - Rev5 authorization level indicators
        - Self-managed storage systems
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check string literals for legacy repository references
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if any(keyword in string_text for keyword in ['legacy repository', 'self-managed repository', 'rev5', 'fedramp high']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository reference detected",
                            description="Found legacy self-managed repository or Rev5 High reference",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="If FedRAMP Rev5 High authorized with legacy self-managed repository, may be exempt from ADS requirements."
                        ))
                
                # Check variable assignments for repository configuration
                assignments = parser.find_nodes_by_type(tree.root_node, 'assignment')
                for assignment in assignments:
                    assign_text = parser.get_node_text(assignment, code_bytes).lower()
                    if any(keyword in assign_text for keyword in ['legacy_repository', 'self_managed_repo', 'rev5_authorized', 'fedramp_high']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository configuration detected",
                            description="Found legacy repository or Rev5 High configuration variable",
                            severity=Severity.INFO,
                            line_number=assignment.start_point[0] + 1,
                            code_snippet=assign_text.split('\n')[0],
                            recommendation="Document legacy repository exemption status for compliance."
                        ))
                
                # Check comments for exemption documentation
                if tree.root_node.children:
                    for child in tree.root_node.children:
                        if child.type == 'comment':
                            comment_text = parser.get_node_text(child, code_bytes).lower()
                            if 'legacy' in comment_text and 'exempt' in comment_text:
                                findings.append(Finding(
                                    frr_id=self.FRR_ID,
                                    title="Legacy exemption documentation detected",
                                    description="Found documentation of legacy repository exemption",
                                    severity=Severity.INFO,
                                    line_number=child.start_point[0] + 1,
                                    code_snippet=comment_text[:100],
                                    recommendation="Maintain exemption documentation for audit purposes."
                                ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        legacy_patterns = [
            r'legacy.*repository',
            r'self.*managed.*repo',
            r'rev5.*(?:authorized|high)',
            r'fedramp.*high',
            r'legacy.*exempt',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in legacy_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Legacy repository pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Rev5 High providers with legacy self-managed repository may be exempt from ADS requirements."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-EX-01 compliance using AST.
        
        Detects legacy self-managed repository usage in C# applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check string literals
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if any(keyword in string_text for keyword in ['legacy repository', 'self-managed', 'rev5', 'fedramp high']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository reference detected",
                            description="Found legacy self-managed repository or Rev5 reference",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="Document legacy repository exemption if applicable."
                        ))
                
                # Check variable declarations
                variable_declarations = parser.find_nodes_by_type(tree.root_node, 'variable_declaration')
                for var_decl in variable_declarations:
                    var_text = parser.get_node_text(var_decl, code_bytes).lower()
                    if any(keyword in var_text for keyword in ['legacyrepository', 'selfmanagedrepo', 'rev5authorized']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository configuration detected",
                            description="Found legacy repository configuration variable",
                            severity=Severity.INFO,
                            line_number=var_decl.start_point[0] + 1,
                            code_snippet=var_text.split('\n')[0],
                            recommendation="Maintain exemption documentation for compliance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:legacy|self-managed).*repository|Rev5.*(?:High|Authorized)|FedRAMP.*High', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Legacy repository reference detected",
                    description="Found legacy repository or Rev5 High reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Document exemption status for audit purposes."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-EX-01 compliance using AST.
        
        Detects legacy self-managed repository usage in Java applications.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check string literals
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if any(keyword in string_text for keyword in ['legacy repository', 'self-managed', 'rev5', 'fedramp high']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository reference detected",
                            description="Found legacy self-managed repository or Rev5 reference",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="Document legacy repository exemption if applicable."
                        ))
                
                # Check field declarations
                field_declarations = parser.find_nodes_by_type(tree.root_node, 'field_declaration')
                for field_decl in field_declarations:
                    field_text = parser.get_node_text(field_decl, code_bytes).lower()
                    if any(keyword in field_text for keyword in ['legacyrepository', 'selfmanagedrepo', 'rev5authorized']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository configuration detected",
                            description="Found legacy repository field declaration",
                            severity=Severity.INFO,
                            line_number=field_decl.start_point[0] + 1,
                            code_snippet=field_text.split('\n')[0],
                            recommendation="Maintain exemption documentation for compliance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:legacy|self-managed).*repository|Rev5.*(?:High|Authorized)|FedRAMP.*High', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Legacy repository reference detected",
                    description="Found legacy repository or Rev5 High reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Document exemption status for audit purposes."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-EX-01 compliance using AST.
        
        Detects legacy self-managed repository usage in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check string literals
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for string_node in string_literals:
                    string_text = parser.get_node_text(string_node, code_bytes).lower()
                    if any(keyword in string_text for keyword in ['legacy repository', 'self-managed', 'rev5', 'fedramp high']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository reference detected",
                            description="Found legacy self-managed repository or Rev5 reference",
                            severity=Severity.INFO,
                            line_number=string_node.start_point[0] + 1,
                            code_snippet=string_text[:100],
                            recommendation="Document legacy repository exemption if applicable."
                        ))
                
                # Check variable declarations
                variable_declarations = parser.find_nodes_by_type(tree.root_node, 'variable_declaration')
                for var_decl in variable_declarations:
                    var_text = parser.get_node_text(var_decl, code_bytes).lower()
                    if any(keyword in var_text for keyword in ['legacyrepository', 'selfmanagedrepo', 'rev5authorized']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Legacy repository configuration detected",
                            description="Found legacy repository configuration variable",
                            severity=Severity.INFO,
                            line_number=var_decl.start_point[0] + 1,
                            code_snippet=var_text.split('\n')[0],
                            recommendation="Maintain exemption documentation for compliance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:legacy|self-managed).*repository|Rev5.*(?:High|Authorized)|FedRAMP.*High', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Legacy repository reference detected",
                    description="Found legacy repository or Rev5 High reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Document exemption status for audit purposes."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-EX-01 compliance.
        
        NOT APPLICABLE: Legacy self-managed repository exemption is a policy
        and authorization status determination, not an infrastructure configuration
        requirement. The exemption applies to FedRAMP Rev5 High authorized providers
        who use legacy self-managed repositories for authorization data.
        
        This is determined through:
        1. Authorization status documentation (Rev5 High)
        2. Repository type assessment (self-managed vs. trust center)
        3. Policy decision (exemption granted by FedRAMP)
        
        These are organizational and policy-level determinations, not
        infrastructure code concerns.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-EX-01 compliance.
        
        NOT APPLICABLE: Legacy self-managed repository exemption is a policy
        and authorization status determination, not an infrastructure configuration
        requirement. The exemption applies to FedRAMP Rev5 High authorized providers
        who use legacy self-managed repositories for authorization data.
        
        This is determined through:
        1. Authorization status documentation (Rev5 High)
        2. Repository type assessment (self-managed vs. trust center)
        3. Policy decision (exemption granted by FedRAMP)
        
        These are organizational and policy-level determinations, not
        infrastructure code concerns.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-EX-01 compliance.
        
        NOT APPLICABLE: Legacy self-managed repository exemption is a policy
        and authorization status determination, not a CI/CD pipeline concern.
        The exemption applies based on organizational authorization status
        (Rev5 High) and repository architecture decisions (legacy self-managed),
        not on build or deployment automation configurations.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-EX-01 compliance.
        
        NOT APPLICABLE: Legacy self-managed repository exemption is a policy
        and authorization status determination, not a CI/CD pipeline concern.
        The exemption applies based on organizational authorization status
        (Rev5 High) and repository architecture decisions (legacy self-managed),
        not on build or deployment automation configurations.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-EX-01 compliance.
        
        NOT APPLICABLE: Legacy self-managed repository exemption is a policy
        and authorization status determination, not a CI/CD pipeline concern.
        The exemption applies based on organizational authorization status
        (Rev5 High) and repository architecture decisions (legacy self-managed),
        not on build or deployment automation configurations.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-EX-01.
        
        This is an exemption requirement - not code-detectable, requires documentation review.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'No',
            'automation_feasibility': 'Low - exemption determination requires manual policy review',
            'automation_approach': 'Manual validation - review authorization status, repository architecture, and exemption documentation',
            'recommended_services': [
                'N/A - This is a policy exemption requirement, not a technical implementation',
            ],
            'collection_methods': [
                'Review FedRAMP authorization letter (confirm Rev5 High status)',
                'Review repository architecture documentation (confirm self-managed vs. trust center)',
                'Review exemption decision documentation from FedRAMP',
                'Interview CSO/compliance officer about exemption status',
                'Validate authorization data management approach',
            ],
            'implementation_steps': [
                '1. Verify organization has FedRAMP Rev5 High authorization',
                '2. Document current repository architecture (self-managed vs. trust center)',
                '3. If using legacy self-managed repository, request exemption confirmation from FedRAMP',
                '4. Maintain exemption documentation for audit purposes',
                '5. Monitor for FedRAMP policy updates (exemption is "until future notice")',
                '6. Plan for eventual migration to trust center when exemption expires',
                '7. Document exemption applicability in SSP and POA&M',
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get automated queries for collecting evidence of FRR-ADS-EX-01 compliance.
        
        Returns queries for exemption documentation validation.
        """
        return [
            {
                'query_name': 'FedRAMP Authorization Package Review',
                'query_type': 'Manual',
                'query': 'Review FedRAMP authorization letter to confirm Rev5 High authorization status',
                'data_source': 'FedRAMP authorization documentation',
                'evidence_type': 'Authorization status verification (Rev5 High)',
            },
            {
                'query_name': 'Repository Architecture Documentation',
                'query_type': 'Manual',
                'query': 'Review system architecture diagrams and SSP to confirm self-managed repository usage',
                'data_source': 'System Security Plan (SSP) and architecture documents',
                'evidence_type': 'Repository type verification (legacy self-managed)',
            },
            {
                'query_name': 'Exemption Decision Documentation',
                'query_type': 'Manual',
                'query': 'Obtain and review FedRAMP exemption decision memo or communication',
                'data_source': 'FedRAMP correspondence and policy decisions',
                'evidence_type': 'Exemption authorization from FedRAMP',
            },
            {
                'query_name': 'Configuration Management Database Query',
                'query_type': 'Manual',
                'query': 'Query CMDB for authorization data repository configuration and classification',
                'data_source': 'Configuration Management Database (CMDB)',
                'evidence_type': 'Repository configuration and ownership details',
            },
            {
                'query_name': 'Policy Change Tracking',
                'query_type': 'Manual',
                'query': 'Monitor FedRAMP policy updates and guidance documents for exemption status changes',
                'data_source': 'FedRAMP website, policy announcements, GSA communications',
                'evidence_type': 'Current exemption status and policy changes',
            },
            {
                'query_name': 'Continuous Monitoring Plan Review',
                'query_type': 'Manual',
                'query': 'Review ConMon plan for exemption documentation and ADS requirement applicability',
                'data_source': 'Continuous Monitoring (ConMon) plan and POA&M',
                'evidence_type': 'Exemption tracking in continuous monitoring',
            },
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts for FRR-ADS-EX-01 compliance.
        
        Returns specific documents needed to demonstrate exemption eligibility.
        """
        return [
            'FedRAMP Rev5 High authorization letter',
            'System Security Plan (SSP) documenting legacy self-managed repository',
            'Repository architecture diagram showing self-managed authorization data storage',
            'Exemption decision memo or email from FedRAMP',
            'Documentation of "until future notice" exemption applicability',
            'POA&M entry for eventual migration to trust center (if planned)',
            'Authorization data management policy document',
            'Continuous Monitoring (ConMon) plan with exemption notation',
            'Audit trail of FedRAMP policy monitoring (for exemption status changes)',
            'Interview notes with CSO/compliance officer confirming exemption status',
        ]
