"""
FRR-SCN-02: Procedures and Documentation

Providers MUST follow the procedures documented in their security plan to plan, evaluate, test, perform, assess, and document changes.

Official FedRAMP 20x Requirement
Source: FRR-SCN (SCN) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_SCN_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-SCN-02: Procedures and Documentation
    
    **Official Statement:**
    Providers MUST follow the procedures documented in their security plan to plan, evaluate, test, perform, assess, and document changes.
    
    **Family:** SCN - SCN
    
    **Primary Keyword:** MUST
    
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
    
    FRR_ID = "FRR-SCN-02"
    FRR_NAME = "Procedures and Documentation"
    FRR_STATEMENT = """Providers MUST follow the procedures documented in their security plan to plan, evaluate, test, perform, assess, and document changes."""
    FAMILY = "SCN"
    FAMILY_NAME = "SCN"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CM-3", "Configuration Change Control"),
        ("CM-4", "Impact Analysis"),
        ("SA-10", "Developer Configuration Management")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-CMT-01", "KSI-CMT-02"]
    
    def __init__(self):
        """Initialize FRR-SCN-02 analyzer."""
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
        Check for change management procedures (testing, approval, documentation).
        
        Detects:
        - Testing/validation code for changes
        - Approval workflow implementation
        - Change documentation generation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for change management patterns
        patterns = [
            r'def.*test_', r'pytest', r'unittest',
            r'approval.*workflow', r'change.*request',
            r'document.*change', r'changelog', r'release.*notes'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Change management procedure detected",
                        description=f"Line {i} implements change management. FRR-SCN-02 requires following documented procedures to plan, evaluate, test, perform, assess, and document changes.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Ensure procedures cover: (1) Change planning, (2) Evaluation/testing, (3) Performance/deployment, (4) Assessment, (5) Documentation"
                    ))
                    return findings
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Check C# for change management (testing frameworks)."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Java for change management."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for change management."""
        return []
    
    # Note: SCN-02 is primarily process/documentation, limited code detection
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
        Analyze C# code for FRR-SCN-02 compliance using AST.
        
        TODO: Implement C# analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for C#
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-SCN-02 compliance using AST.
        
        TODO: Implement Java analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for Java
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-SCN-02 compliance using AST.
        
        TODO: Implement TypeScript analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-SCN-02 compliance.
        
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
        Analyze Terraform infrastructure code for FRR-SCN-02 compliance.
        
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
        """
        Analyze GitHub Actions workflow for FRR-SCN-02 compliance.
        
        TODO: Implement GitHub Actions analysis
        - Check for required steps/actions
        - Verify compliance configuration
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitHub Actions analysis
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-SCN-02 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-SCN-02 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get automated queries for collecting evidence of change management procedures.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'azure_resource_graph': [
                "// Find DevOps projects with change management policies",
                "Resources | where type =~ 'microsoft.visualstudio/account/project' | project name, properties.policies",
                "// Find App Configuration stores with change tracking",
                "Resources | where type =~ 'microsoft.appconfiguration/configurationstores' | project name, properties.changeTracking"
            ],
            'azure_monitor_kql': [
                "// Change management activity logs",
                "AzureActivity | where OperationNameValue contains 'Microsoft.Resources/deployments' | where ActivityStatusValue == 'Success' | project TimeGenerated, Caller, OperationNameValue, ResourceGroup",
                "// DevOps pipeline runs for change validation",
                "AppTraces | where Properties.PipelineStage in ('Test', 'Approval', 'Deploy') | project timestamp, Properties.ChangeId, Properties.Stage"
            ],
            'azure_cli': [
                "az pipelines list --organization <org> --project <project>",
                "az devops policy list --organization <org> --project <project>",
                "az repos policy list --repository <repo>"
            ]
        }

    def get_evidence_artifacts(self) -> dict:
        """
        Get evidence artifacts demonstrating change management procedures.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_locations': [
                'CI/CD pipeline definitions (.github/workflows/, azure-pipelines.yml, .gitlab-ci.yml)',
                'Change management scripts (scripts/change-management/)',
                'Testing frameworks (tests/, test-plans/)',
                'Approval workflows (CODEOWNERS, branch protection rules)'
            ],
            'documentation': [
                'Change management procedures document',
                'Security plan section on change control (CM-3, CM-4)',
                'Pipeline approval logs and evidence',
                'Test results and validation reports',
                'Post-change assessment reports'
            ],
            'configuration_samples': [
                'Azure DevOps pipeline with approval gates',
                'GitHub branch protection rules',
                'Automated test suite configuration',
                'Change tracking database schema'
            ]
        }

    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for change procedures.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'implementation_notes': [
                'CI/CD pipelines provide automated change planning and testing evidence',
                'Approval gates and branch protection enforce documented procedures',
                'Automated testing validates changes before deployment',
                'Change tracking tools provide documentation and assessment records',
                'DevOps platforms (Azure DevOps, GitHub Actions, GitLab CI) enforce workflow procedures'
            ],
            'recommended_services': [
                'Azure DevOps - Pipeline approvals, work item tracking, test management',
                'GitHub Actions - Workflow automation, required reviewers, status checks',
                'Azure Repos - Branch policies, required approvals, build validation',
                'Azure Test Plans - Test case management and execution tracking'
            ],
            'integration_points': [
                'DevOps API for pipeline execution history and approval records',
                'Git history for change documentation and traceability',
                'Test frameworks for automated validation evidence',
                'Change management tools for procedure compliance tracking'
            ]
        }
