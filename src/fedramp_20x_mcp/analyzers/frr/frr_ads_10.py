"""
FRR-ADS-10: Best Practices and Technical Assistance

Providers SHOULD follow FedRAMP’s best practices and technical assistance for sharing _authorization data_ where applicable.

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_10_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-10: Best Practices and Technical Assistance
    
    **Official Statement:**
    Providers SHOULD follow FedRAMP’s best practices and technical assistance for sharing _authorization data_ where applicable.
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** SHOULD
    
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
    
    FRR_ID = "FRR-ADS-10"
    FRR_NAME = "Best Practices and Technical Assistance"
    FRR_STATEMENT = """Providers SHOULD follow FedRAMP’s best practices and technical assistance for sharing _authorization data_ where applicable."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("PL-2", "System Security Plan"),
        ("SA-9", "External System Services"),
        ("SI-12", "Information Management and Retention"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-10 analyzer."""
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
        Analyze Python code for FRR-ADS-10 compliance.
        
        Detects references to FedRAMP best practices:
        - Comments mentioning FedRAMP best practices
        - Docstrings referencing technical assistance
        - String literals with compliance guidance
        
        Uses AST for accurate detection with regex fallback.
        """
        findings = []
        
        # AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Check comments for best practices references
                comment_nodes = parser.find_nodes_by_type(tree.root_node, 'comment')
                best_practice_keywords = ['fedramp', 'best practice', 'technical assistance', 'compliance guidance']
                for comment_node in comment_nodes:
                    comment_text = parser.get_node_text(comment_node, code_bytes).lower()
                    if any(keyword in comment_text for keyword in best_practice_keywords):
                        line_num = comment_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference in comment",
                            description="Found reference to FedRAMP best practices in code comment",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(comment_node, code_bytes)[:100],
                            recommendation="Verify implementation follows FedRAMP best practices for authorization data sharing."
                        ))
                
                # Check string literals for best practices references
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in best_practice_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference in string",
                            description="Found reference to FedRAMP best practices or guidance",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Ensure implementation aligns with FedRAMP best practices."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        best_practice_patterns = [
            r'fedramp.*best.*practice',
            r'best.*practice.*authorization',
            r'technical.*assistance.*fedramp',
            r'fedramp.*guidance',
            r'compliance.*best.*practice',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in best_practice_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Best practices reference detected",
                        description=f"Found FedRAMP best practices pattern",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure following FedRAMP best practices for authorization data sharing."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-10 compliance using AST.
        
        Detects references to FedRAMP best practices:
        - Comments mentioning FedRAMP best practices
        - String literals with compliance guidance
        - Documentation references
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Check comments for best practices
                comment_nodes = parser.find_nodes_by_type(tree.root_node, 'comment')
                best_practice_keywords = ['fedramp', 'best practice', 'technical assistance', 'compliance guidance']
                for comment_node in comment_nodes:
                    comment_text = parser.get_node_text(comment_node, code_bytes).lower()
                    if any(keyword in comment_text for keyword in best_practice_keywords):
                        line_num = comment_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference detected",
                            description="Found reference to FedRAMP best practices",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(comment_node, code_bytes)[:100],
                            recommendation="Verify implementation follows FedRAMP best practices."
                        ))
                
                # Check string literals
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in best_practice_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference in string",
                            description="Found FedRAMP guidance reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Ensure alignment with FedRAMP best practices."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(FedRAMP|best.*practice|technical.*assistance|compliance.*guidance)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Best practices reference detected",
                    description="Found potential FedRAMP best practices reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure following FedRAMP best practices."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-10 compliance using AST.
        
        Detects references to FedRAMP best practices:
        - Javadoc and comments mentioning FedRAMP
        - String literals with compliance guidance
        - Documentation references
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Check comments for best practices
                comment_nodes = parser.find_nodes_by_type(tree.root_node, 'comment')
                best_practice_keywords = ['fedramp', 'best practice', 'technical assistance', 'compliance guidance']
                for comment_node in comment_nodes:
                    comment_text = parser.get_node_text(comment_node, code_bytes).lower()
                    if any(keyword in comment_text for keyword in best_practice_keywords):
                        line_num = comment_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference detected",
                            description="Found reference to FedRAMP best practices",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(comment_node, code_bytes)[:100],
                            recommendation="Verify implementation follows FedRAMP best practices."
                        ))
                
                # Check string literals
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string_literal')
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in best_practice_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference in string",
                            description="Found FedRAMP guidance reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Ensure alignment with FedRAMP best practices."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(FedRAMP|best.*practice|technical.*assistance|compliance.*guidance)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Best practices reference detected",
                    description="Found potential FedRAMP best practices reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure following FedRAMP best practices."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-10 compliance using AST.
        
        Detects references to FedRAMP best practices:
        - Comments mentioning FedRAMP best practices
        - String literals with compliance guidance
        - Documentation references
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf-8')
            
            if tree and tree.root_node:
                # Check comments for best practices
                comment_nodes = parser.find_nodes_by_type(tree.root_node, 'comment')
                best_practice_keywords = ['fedramp', 'best practice', 'technical assistance', 'compliance guidance']
                for comment_node in comment_nodes:
                    comment_text = parser.get_node_text(comment_node, code_bytes).lower()
                    if any(keyword in comment_text for keyword in best_practice_keywords):
                        line_num = comment_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference detected",
                            description="Found reference to FedRAMP best practices",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(comment_node, code_bytes)[:100],
                            recommendation="Verify implementation follows FedRAMP best practices."
                        ))
                
                # Check string literals
                string_literals = parser.find_nodes_by_type(tree.root_node, 'string')
                for str_node in string_literals:
                    str_text = parser.get_node_text(str_node, code_bytes).lower()
                    if any(keyword in str_text for keyword in best_practice_keywords):
                        line_num = str_node.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="FedRAMP best practices reference in string",
                            description="Found FedRAMP guidance reference",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=parser.get_node_text(str_node, code_bytes)[:100],
                            recommendation="Ensure alignment with FedRAMP best practices."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(FedRAMP|best.*practice|technical.*assistance|compliance.*guidance)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Best practices reference detected",
                    description="Found potential FedRAMP best practices reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Ensure following FedRAMP best practices."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-10 compliance.
        
        Note: FRR-ADS-10 is a SHOULD requirement recommending providers follow
        FedRAMP best practices and technical assistance. Best practices are documented
        in code comments, application logic, and operational procedures, not in
        infrastructure resource definitions.
        
        Bicep defines Azure infrastructure resources, which don't directly implement
        or reference FedRAMP best practices documentation.
        
        Return: Empty findings list (requirement is not infrastructure-related)
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-10 compliance.
        
        Note: FRR-ADS-10 is a SHOULD requirement recommending providers follow
        FedRAMP best practices and technical assistance. Best practices are documented
        in code comments, application logic, and operational procedures, not in
        infrastructure resource definitions.
        
        Terraform defines infrastructure resources, which don't directly implement
        or reference FedRAMP best practices documentation.
        
        Return: Empty findings list (requirement is not infrastructure-related)
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-10 compliance.
        
        Detects FedRAMP best practices validation:
        - Compliance checking workflows
        - Best practices validation steps
        - FedRAMP guidance automation
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Best practices validation patterns
        validation_patterns = [
            r'fedramp.*compliance',
            r'compliance.*check',
            r'best.*practice.*validation',
            r'fedramp.*validation',
            r'authorization.*compliance',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="FedRAMP compliance validation detected",
                        description=f"Found best practices validation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure workflow validates adherence to FedRAMP best practices."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-10 compliance.
        
        Detects FedRAMP best practices validation:
        - Compliance checking tasks
        - Best practices validation steps
        - FedRAMP guidance automation
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Best practices validation patterns
        validation_patterns = [
            r'fedramp.*compliance',
            r'compliance.*check',
            r'best.*practice.*validation',
            r'fedramp.*validation',
            r'authorization.*compliance',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="FedRAMP compliance validation detected",
                        description=f"Found best practices validation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure pipeline validates adherence to FedRAMP best practices."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-10 compliance.
        
        Detects FedRAMP best practices validation:
        - Compliance checking jobs
        - Best practices validation stages
        - FedRAMP guidance automation
        
        Note: Uses regex patterns as tree-sitter does not support YAML.
        """
        findings = []
        lines = code.split('\n')
        
        # Best practices validation patterns
        validation_patterns = [
            r'fedramp.*compliance',
            r'compliance.*check',
            r'best.*practice.*validation',
            r'fedramp.*validation',
            r'authorization.*compliance',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in validation_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="FedRAMP compliance validation detected",
                        description=f"Found best practices validation: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure job validates adherence to FedRAMP best practices."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-10.
        
        FRR-ADS-10 is a SHOULD requirement recommending providers follow FedRAMP
        best practices. Evidence focuses on documentation reviews, compliance
        checklists, and implementation alignment with published guidance.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_feasibility': 'Low - Best practices adherence is primarily assessed through documentation review and manual validation',
            'azure_services': [
                'Azure DevOps - Track compliance with best practices in work items',
                'Azure Repos - Code comments and documentation referencing FedRAMP guidance',
                'Azure Boards - Best practices implementation tracking',
                'Azure Policy - Enforce configuration standards aligned with FedRAMP guidance',
                'Microsoft Defender for Cloud - Security best practices recommendations'
            ],
            'collection_methods': [
                'Review code comments and documentation for FedRAMP best practices references',
                'Search codebase for FedRAMP guidance implementation notes',
                'Collect compliance checklists and best practices assessments',
                'Review technical assistance engagement records with FedRAMP',
                'Audit implementation decisions aligned with published FedRAMP guidance',
                'Gather evidence of best practices training and awareness'
            ],
            'implementation_steps': [
                '1. Obtain FedRAMP best practices documentation from official sources',
                '2. Review authorization data sharing implementation against published guidance',
                '3. Document alignment with FedRAMP technical assistance recommendations',
                '4. Create compliance checklist mapping implementation to best practices',
                '5. Track technical assistance engagement and guidance application',
                '6. Maintain evidence of best practices awareness and training',
                '7. Document rationale for any deviations from recommended approaches'
            ]
        }
    
    def get_evidence_collection_queries(self) -> list:
        """
        Get specific queries for collecting FRR-ADS-10 evidence.
        
        Returns queries for documentation, compliance tracking, and best practices validation.
        Note: This SHOULD requirement is primarily manual validation.
        """
        return [
            {
                'name': 'Code Documentation References to FedRAMP Best Practices',
                'type': 'Code Search',
                'query': '''grep -r -i "fedramp.*best.*practice\\|best.*practice.*authorization\\|fedramp.*guidance\\|technical.*assistance" --include="*.py" --include="*.cs" --include="*.java" --include="*.ts" --include="*.js" .''',
                'description': 'Search codebase for comments and documentation referencing FedRAMP best practices and technical assistance'
            },
            {
                'name': 'Azure DevOps Work Items for Best Practices Implementation',
                'type': 'Azure DevOps REST API',
                'query': '''GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0
Body: {
  "query": "SELECT [System.Id], [System.Title], [System.State] FROM WorkItems WHERE [System.Tags] CONTAINS \'FedRAMP\' OR [System.Title] CONTAINS \'best practices\' OR [System.Description] CONTAINS \'FedRAMP guidance\' ORDER BY [System.CreatedDate] DESC"
}''',
                'description': 'Query work items tracking FedRAMP best practices implementation and technical assistance application'
            },
            {
                'name': 'Azure Policy Compliance for FedRAMP-Aligned Standards',
                'type': 'Azure Resource Graph',
                'query': '''policyresources
| where type == "microsoft.policyinsights/policystates"
| where properties.policyDefinitionName contains "FedRAMP" or properties.policyDefinitionName contains "authorization"
| extend complianceState = tostring(properties.complianceState)
| summarize CompliantResources=countif(complianceState=="Compliant"), NonCompliantResources=countif(complianceState=="NonCompliant") by policyDefinitionName=tostring(properties.policyDefinitionName)
| project PolicyName=policyDefinitionName, CompliantResources, NonCompliantResources, ComplianceRate=round((todouble(CompliantResources)/(todouble(CompliantResources)+todouble(NonCompliantResources)))*100, 2)''',
                'description': 'Track compliance with Azure policies aligned to FedRAMP best practices and guidance'
            },
            {
                'name': 'Microsoft Defender Recommendations Aligned with FedRAMP',
                'type': 'KQL',
                'query': '''SecurityRecommendation
| where RecommendationDisplayName contains "authorization" or RecommendationDisplayName contains "data sharing" or RecommendationDisplayName contains "compliance"
| where RecommendationState == "Active"
| project TimeGenerated, ResourceId, RecommendationDisplayName, RecommendationSeverity, RemediationDescription, AdditionalData
| order by RecommendationSeverity desc, TimeGenerated desc''',
                'description': 'Review Microsoft Defender security recommendations that align with FedRAMP best practices for authorization data'
            },
            {
                'name': 'Documentation Repository Changes for Best Practices',
                'type': 'Git Log Query',
                'query': '''git log --all --grep="FedRAMP" --grep="best practice" --grep="technical assistance" --grep="compliance guidance" -i --pretty=format:"%h|%an|%ad|%s" --date=short''',
                'description': 'Track documentation commits referencing FedRAMP best practices, technical assistance, and compliance guidance'
            },
            {
                'name': 'Training and Awareness Records',
                'type': 'Manual Query',
                'query': 'N/A - Manual collection required',
                'description': 'Collect records of FedRAMP best practices training, technical assistance sessions, and guidance awareness programs for team members working on authorization data sharing'
            }
        ]
    
    def get_evidence_artifacts(self) -> list:
        """
        Get list of evidence artifacts to collect for FRR-ADS-10.
        
        Returns artifacts demonstrating adherence to FedRAMP best practices.
        """
        return [
            {
                'name': 'FedRAMP Best Practices Documentation',
                'description': 'Copy of FedRAMP published best practices and technical assistance guidance referenced during implementation',
                'location': 'FedRAMP.gov website / project documentation repository',
                'format': 'PDF or Markdown documents with publication dates and version numbers'
            },
            {
                'name': 'Best Practices Compliance Checklist',
                'description': 'Checklist mapping authorization data sharing implementation to FedRAMP recommended best practices with compliance status',
                'location': 'Compliance documentation / project management system',
                'format': 'Spreadsheet or checklist document showing practice, implementation status, evidence location'
            },
            {
                'name': 'Technical Assistance Engagement Records',
                'description': 'Documentation of technical assistance sessions, consultations, or guidance received from FedRAMP regarding authorization data sharing',
                'location': 'Meeting notes / email correspondence / support tickets',
                'format': 'Email archives, meeting minutes, consultation summaries with dates and topics'
            },
            {
                'name': 'Implementation Decision Documentation',
                'description': 'Design documents and architectural decisions showing how FedRAMP best practices were applied to authorization data sharing',
                'location': 'Architecture documentation / design decision records (ADRs)',
                'format': 'Markdown or PDF documents with decision rationale, alternatives considered, best practices alignment'
            },
            {
                'name': 'Code Documentation and Comments',
                'description': 'Export of code comments, docstrings, and README files referencing FedRAMP best practices and guidance',
                'location': 'Source code repository / documentation generation output',
                'format': 'Generated documentation or code snippets showing best practices references'
            },
            {
                'name': 'Training and Awareness Evidence',
                'description': 'Records of FedRAMP best practices training completion, technical assistance awareness sessions, and guidance dissemination',
                'location': 'Learning management system / HR training records',
                'format': 'Training certificates, attendance records, training materials referencing FedRAMP best practices'
            }
        ]
