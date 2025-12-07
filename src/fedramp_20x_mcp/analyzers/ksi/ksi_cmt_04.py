"""
KSI-CMT-04: Change Management Procedure

Always follow a documented change management procedure.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CMT-04: Change Management Procedure
    
    **Official Statement:**
    Always follow a documented change management procedure.
    
    **Family:** CMT - Change Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-3
    - cm-3.2
    - cm-3.4
    - cm-5
    - cm-7.1
    - cm-9
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CMT-04"
    KSI_NAME = "Change Management Procedure"
    KSI_STATEMENT = """Always follow a documented change management procedure."""
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["cm-3", "cm-3.2", "cm-3.4", "cm-5", "cm-7.1", "cm-9"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self):
        super().__init__(
            ksi_id=self.KSI_ID,
            ksi_name=self.KSI_NAME,
            ksi_statement=self.KSI_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-CMT-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Always follow a documented change management procedure....
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CMT-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Always follow a documented change management procedure....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CMT-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Always follow a documented change management procedure....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CMT-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Always follow a documented change management procedure....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CMT-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Always follow a documented change management procedure....
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CMT-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Always follow a documented change management procedure....
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CMT-04 compliance.
        
        Detects:
        - Missing approval gates for production deployments
        - Unprotected environment deployments
        - Missing change tracking
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Production deployment without approval (HIGH)
        has_prod_env = bool(re.search(r'environment:\s*(production|prod)', code, re.IGNORECASE))
        has_approval = bool(re.search(r'(required_reviewers|protection_rules)', code, re.IGNORECASE))
        
        if has_prod_env and not has_approval:
            line_num = self._find_line(lines, 'environment')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Production Deployment Without Approval Gate",
                description=(
                    "Workflow deploys to production without approval gates. KSI-CMT-04 requires "
                    "documented change management procedures per NIST CM-3. Production changes "
                    "must require manual approval."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add approval gate using GitHub Environment protection:\n"
                    "jobs:\n"
                    "  deploy:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    environment:\n"
                    "      name: production\n"
                    "      # Configure in Settings > Environments > production:\n"
                    "      # - Required reviewers: Select approvers\n"
                    "      # - Wait timer: Optional delay\n"
                    "      # - Deployment branches: Limit to main/release\n"
                    "    steps:\n"
                    "      - name: Deploy to production\n"
                    "        run: ./deploy.sh\n\n"
                    "Alternative with manual trigger:\n"
                    "on:\n"
                    "  workflow_dispatch:  # Manual trigger only\n"
                    "    inputs:\n"
                    "      approval_ticket:\n"
                    "        description: 'Change ticket number'\n"
                    "        required: true\n\n"
                    "Ref: GitHub Environments (https://docs.github.com/en/actions/deployment/targeting-different-environments)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: No change tracking (MEDIUM)
        has_issue_link = bool(re.search(r'(issue|ticket|jira|change.*request)', code, re.IGNORECASE))
        has_prod_deploy = bool(re.search(r'(deploy|publish|release).*production', code, re.IGNORECASE))
        
        if has_prod_deploy and not has_issue_link and len(code) > 150:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Change Tracking in Deployment",
                description=(
                    "Production deployment lacks change tracking/ticketing. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add change tracking requirement:\n"
                    "on:\n"
                    "  workflow_dispatch:\n"
                    "    inputs:\n"
                    "      change_ticket:\n"
                    "        description: 'Change/JIRA ticket number'\n"
                    "        required: true\n"
                    "      approval_date:\n"
                    "        description: 'CAB approval date (YYYY-MM-DD)'\n"
                    "        required: true\n\n"
                    "jobs:\n"
                    "  validate:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Log change details\n"
                    "        run: |\n"
                    "          echo \"Change Ticket: ${{ github.event.inputs.change_ticket }}\"\n"
                    "          echo \"Approved: ${{ github.event.inputs.approval_date }}\"\n"
                    "          echo \"Triggered by: ${{ github.actor }}\"\n\n"
                    "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CMT-04 compliance.
        
        Detects:
        - Missing approval gates for production
        - Unprotected environment deployments
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Production deployment without approval (HIGH)
        has_prod_env = bool(re.search(r'(environment:.*production|deploy.*production)', code, re.IGNORECASE))
        has_approval = bool(re.search(r'(ManualValidation|approval)', code, re.IGNORECASE))
        
        if has_prod_env and not has_approval and len(code) > 100:
            line_num = self._find_line(lines, 'production')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Production Deployment Without Approval Gate",
                description=(
                    "Pipeline deploys to production without approval. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add manual approval gate:\n"
                    "stages:\n"
                    "- stage: Production\n"
                    "  jobs:\n"
                    "  - deployment: DeployProd\n"
                    "    environment:\n"
                    "      name: production\n"
                    "      # Configure in Pipelines > Environments > production:\n"
                    "      # - Add Approvals and checks\n"
                    "      # - Required reviewers\n"
                    "    strategy:\n"
                    "      runOnce:\n"
                    "        deploy:\n"
                    "          steps:\n"
                    "          - script: ./deploy.sh\n\n"
                    "Or use ManualValidation task:\n"
                    "- task: ManualValidation@0\n"
                    "  displayName: 'Approve Production Deployment'\n"
                    "  inputs:\n"
                    "    notifyUsers: 'change-board@example.com'\n"
                    "    instructions: 'Review change ticket and approve'\n\n"
                    "Ref: Azure Pipeline Approvals (https://learn.microsoft.com/azure/devops/pipelines/process/approvals)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CMT-04 compliance.
        
        Detects:
        - Missing protected environments
        - Production deployments without approval
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Production deployment without protection (HIGH)
        has_prod_deploy = bool(re.search(r'(environment:.*production|deploy.*production)', code, re.IGNORECASE))
        has_manual = bool(re.search(r'(when:\s*manual|protected)', code, re.IGNORECASE))
        
        if has_prod_deploy and not has_manual and len(code) > 100:
            line_num = self._find_line(lines, 'production')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Production Deployment Without Manual Approval",
                description=(
                    "Pipeline deploys to production without manual approval. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add manual approval for production:\n"
                    "deploy_production:\n"
                    "  stage: deploy\n"
                    "  environment:\n"
                    "    name: production\n"
                    "    # Configure in Settings > CI/CD > Environments:\n"
                    "    # - Mark as protected\n"
                    "    # - Required approvals: 2+\n"
                    "    # - Allowed to deploy: Maintainers only\n"
                    "  when: manual  # Requires manual trigger\n"
                    "  only:\n"
                    "    - main  # Only from protected branch\n"
                    "  script:\n"
                    "    - ./deploy.sh\n\n"
                    "With change tracking:\n"
                    "  before_script:\n"
                    "    - echo \"Change ticket: $CHANGE_TICKET\"\n"
                    "    - echo \"Approved by: $APPROVER\"\n"
                    "    - '[ -n \"$CHANGE_TICKET\" ] || exit 1'  # Require ticket\n\n"
                    "Ref: GitLab Protected Environments (https://docs.gitlab.com/ee/ci/environments/protected_environments.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
