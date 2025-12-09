"""
KSI-CMT-04: Change Management Procedure

Always follow a documented change management procedure.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import ast
import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_04_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced Analyzer for KSI-CMT-04: Change Management Procedure
    
    **Official Statement:**
    Always follow a documented change management procedure.
    
    **Family:** CMT - Change Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-3: Configuration Change Control
    - cm-3.2: Testing / Validation / Documentation
    - cm-3.4: Security Representative
    - cm-5: Access Restrictions for Change
    - cm-7.1: Periodic Review
    - cm-9: Configuration Management Plan
    
    **Detection Focus:**
    Focuses on CI/CD pipelines (GitHub Actions, Azure Pipelines, GitLab CI) as primary
    enforcers of change management procedures. Detects missing approval gates, unprotected
    environments, lack of change tracking/ticketing, and automated deployments without controls.
    
    **Languages Supported:**
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    - IaC: Bicep (basic checks), Terraform (basic checks)
    - Application: Limited detection (config-based)
    """
    
    KSI_ID = "KSI-CMT-04"
    KSI_NAME = "Change Management Procedure"
    KSI_STATEMENT = """Always follow a documented change management procedure."""
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cm-3", "Configuration Change Control"),
        ("cm-3.2", "Testing, Validation, and Documentation of Changes"),
        ("cm-3.4", "Security and Privacy Representatives"),
        ("cm-5", "Access Restrictions for Change"),
        ("cm-7.1", "Periodic Review"),
        ("cm-9", "Configuration Management Plan")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (PRIMARY DETECTION)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CMT-04 compliance.
        
        Detects:
        - Production deployments without approval gates (HIGH)
        - Missing change tracking/ticketing (MEDIUM)
        - Deployments on every push without controls (MEDIUM)
        - Missing rollback procedures (MEDIUM)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Production deployment without approval gate (HIGH)
        has_prod_env = bool(re.search(r'environment:\s*(production|prod)\b', code, re.IGNORECASE))
        has_approval = bool(re.search(r'(required_reviewers|protection_rules)', code, re.IGNORECASE))
        has_manual_trigger = bool(re.search(r'workflow_dispatch', code, re.IGNORECASE))
        
        if has_prod_env and not has_approval and not has_manual_trigger:
            result = self._find_line(lines, 'environment')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Production Deployment Without Approval Gate",
                description=(
                    "Workflow deploys to production without approval gates or manual trigger. "
                    "KSI-CMT-04 requires documented change management procedures per NIST CM-3. "
                    "Production changes must require manual approval before deployment."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add approval gate using GitHub Environment protection:\n"
                    "```yaml\n"
                    "jobs:\n"
                    "  deploy:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    environment:\n"
                    "      name: production\n"
                    "      # Configure in Settings > Environments > production:\n"
                    "      # 1. Required reviewers: Select 1+ approvers\n"
                    "      # 2. Wait timer: Optional delay (e.g., 5 minutes)\n"
                    "      # 3. Deployment branches: Limit to main/release\n"
                    "    steps:\n"
                    "      - name: Deploy to production\n"
                    "        run: ./deploy.sh\n"
                    "```\n\n"
                    "Alternative with manual trigger:\n"
                    "```yaml\n"
                    "on:\n"
                    "  workflow_dispatch:  # Manual trigger only\n"
                    "    inputs:\n"
                    "      approval_ticket:\n"
                    "        description: 'Change ticket number (REQUIRED)'\n"
                    "        required: true\n"
                    "      approver:\n"
                    "        description: 'CAB approver name'\n"
                    "        required: true\n"
                    "```\n\n"
                    "Ref: GitHub Environments (https://docs.github.com/en/actions/deployment/targeting-different-environments)\n"
                    "NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing change tracking/ticketing (MEDIUM)
        has_deploy = bool(re.search(r'(deploy|publish|release)', code, re.IGNORECASE))
        has_change_tracking = bool(re.search(r'(ticket|issue|jira|change.*request|approval.*ticket|change_ticket)', code, re.IGNORECASE))
        
        if has_deploy and not has_change_tracking and len(code) > 150:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Change Tracking in Deployment",
                description=(
                    "Deployment workflow lacks change tracking/ticketing mechanism. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3. All changes should be traceable to "
                    "approved change requests."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add change tracking requirement:\n"
                    "```yaml\n"
                    "on:\n"
                    "  workflow_dispatch:\n"
                    "    inputs:\n"
                    "      change_ticket:\n"
                    "        description: 'Change/JIRA ticket number (REQUIRED)'\n"
                    "        required: true\n"
                    "      approval_date:\n"
                    "        description: 'CAB approval date (YYYY-MM-DD)'\n"
                    "        required: true\n"
                    "      approver:\n"
                    "        description: 'Change Advisory Board approver'\n"
                    "        required: true\n\n"
                    "jobs:\n"
                    "  validate:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - name: Log change details\n"
                    "        run: |\n"
                    "          echo \"=== Change Management Record ===\"\n"
                    "          echo \"Change Ticket: ${{ github.event.inputs.change_ticket }}\"\n"
                    "          echo \"Approved: ${{ github.event.inputs.approval_date }}\"\n"
                    "          echo \"Approver: ${{ github.event.inputs.approver }}\"\n"
                    "          echo \"Triggered by: ${{ github.actor }}\"\n"
                    "          echo \"Timestamp: $(date -u +'%Y-%m-%d %H:%M:%S UTC')\"\n"
                    "```\n\n"
                    "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Automated deployment on every push without controls (MEDIUM)
        has_auto_push_trigger = bool(re.search(r'on:\s*\n\s*push:', code))
        has_prod_deploy = bool(re.search(r'(deploy.*production|production.*deploy)', code, re.IGNORECASE))
        
        if has_auto_push_trigger and has_prod_deploy and not has_approval:
            result = self._find_line(lines, 'on:')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Automated Production Deployment on Push",
                description=(
                    "Workflow automatically deploys to production on every push without approval controls. "
                    "KSI-CMT-04 requires documented change management per NIST CM-3. Production deployments "
                    "should require explicit approval, not automatic triggers."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Replace automatic push trigger with controlled deployment:\n"
                    "```yaml\n"
                    "# Option 1: Manual trigger only\n"
                    "on:\n"
                    "  workflow_dispatch:\n"
                    "    inputs:\n"
                    "      change_ticket:\n"
                    "        required: true\n\n"
                    "# Option 2: Tag-based with approval\n"
                    "on:\n"
                    "  push:\n"
                    "    tags:\n"
                    "      - 'v*.*.*'  # Only on version tags\n\n"
                    "jobs:\n"
                    "  deploy:\n"
                    "    environment:\n"
                    "      name: production  # Requires approval\n"
                    "```\n\n"
                    "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 4: Missing rollback procedure (MEDIUM)
        has_deploy_job = bool(re.search(r'(deploy|publish)', code, re.IGNORECASE))
        has_rollback = bool(re.search(r'rollback', code, re.IGNORECASE))
        
        if has_deploy_job and not has_rollback and len(code) > 100:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Rollback Procedure",
                description=(
                    "Deployment workflow lacks rollback procedure. KSI-CMT-04 requires documented change "
                    "management per NIST CM-3.2, which includes rollback procedures for failed changes."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Add rollback job:\n"
                    "```yaml\n"
                    "jobs:\n"
                    "  deploy:\n"
                    "    # ... deployment steps ...\n\n"
                    "  rollback:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    if: failure()  # Runs if deploy fails\n"
                    "    steps:\n"
                    "      - name: Rollback to previous version\n"
                    "        run: |\n"
                    "          echo \"Rolling back to previous stable version\"\n"
                    "          ./scripts/rollback.sh\n"
                    "      - name: Notify change board\n"
                    "        run: |\n"
                    "          echo \"Rollback executed. Change ticket: ${{ github.event.inputs.change_ticket }}\"\n"
                    "```\n\n"
                    "Or add manual rollback trigger:\n"
                    "```yaml\n"
                    "on:\n"
                    "  workflow_dispatch:\n"
                    "    inputs:\n"
                    "      action:\n"
                    "        type: choice\n"
                    "        options:\n"
                    "          - deploy\n"
                    "          - rollback\n"
                    "```\n\n"
                    "Ref: NIST CM-3.2 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CMT-04 compliance.
        
        Detects:
        - Production deployments without approval gates (HIGH)
        - Missing change tracking (MEDIUM)
        - Unprotected environments (MEDIUM)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Production deployment without approval (HIGH)
        has_prod_env = bool(re.search(r'(environment:.*production|deploy.*production|stage:.*Production)', code, re.IGNORECASE))
        has_approval = bool(re.search(r'(ManualValidation|approval|environment:.*\n.*checks)', code, re.IGNORECASE))
        
        if has_prod_env and not has_approval:
            result = self._find_line(lines, 'production')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Production Deployment Without Approval Gate",
                description=(
                    "Pipeline deploys to production without approval. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3. Production changes must "
                    "require manual approval before deployment."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add manual approval gate using environment:\n"
                    "```yaml\n"
                    "stages:\n"
                    "- stage: Production\n"
                    "  jobs:\n"
                    "  - deployment: DeployProd\n"
                    "    environment:\n"
                    "      name: production\n"
                    "      # Configure in Pipelines > Environments > production:\n"
                    "      # 1. Approvals and checks > Approvals\n"
                    "      # 2. Add required reviewers (1+)\n"
                    "      # 3. Timeout: 24 hours\n"
                    "      # 4. Instructions for approvers\n"
                    "    strategy:\n"
                    "      runOnce:\n"
                    "        deploy:\n"
                    "          steps:\n"
                    "          - script: ./deploy.sh\n"
                    "```\n\n"
                    "Or use ManualValidation task:\n"
                    "```yaml\n"
                    "- task: ManualValidation@0\n"
                    "  displayName: 'Approve Production Deployment'\n"
                    "  inputs:\n"
                    "    notifyUsers: 'change-board@example.com'\n"
                    "    instructions: |\n"
                    "      Review change ticket and approve deployment.\n"
                    "      Change Ticket: $(ChangeTicket)\n"
                    "      Approved by: $(Approver)\n"
                    "    onTimeout: 'reject'\n"
                    "```\n\n"
                    "Ref: Azure Pipeline Approvals (https://learn.microsoft.com/azure/devops/pipelines/process/approvals)\n"
                    "NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing change tracking (MEDIUM)
        has_deploy = bool(re.search(r'(deployment:|deploy)', code, re.IGNORECASE))
        has_change_tracking = bool(re.search(r'(ticket|issue|change.*request)', code, re.IGNORECASE))
        
        if has_deploy and not has_change_tracking and len(code) > 150:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Change Tracking in Deployment",
                description=(
                    "Deployment pipeline lacks change tracking mechanism. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3. All changes should be traceable "
                    "to approved change requests."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add change tracking parameters:\n"
                    "```yaml\n"
                    "parameters:\n"
                    "- name: changeTicket\n"
                    "  type: string\n"
                    "  displayName: 'Change Ticket Number'\n"
                    "- name: approvalDate\n"
                    "  type: string\n"
                    "  displayName: 'CAB Approval Date (YYYY-MM-DD)'\n"
                    "- name: approver\n"
                    "  type: string\n"
                    "  displayName: 'Change Advisory Board Approver'\n\n"
                    "stages:\n"
                    "- stage: Validate\n"
                    "  jobs:\n"
                    "  - job: LogChangeDetails\n"
                    "    steps:\n"
                    "    - script: |\n"
                    "        echo \"=== Change Management Record ===\"\n"
                    "        echo \"Change Ticket: ${{ parameters.changeTicket }}\"\n"
                    "        echo \"Approval Date: ${{ parameters.approvalDate }}\"\n"
                    "        echo \"Approver: ${{ parameters.approver }}\"\n"
                    "        echo \"Triggered by: $(Build.RequestedFor)\"\n"
                    "      displayName: 'Log change management details'\n"
                    "```\n\n"
                    "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CMT-04 compliance.
        
        Detects:
        - Production deployments without manual approval (HIGH)
        - Missing protected environment configuration (MEDIUM)
        - Missing change tracking (MEDIUM)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Production deployment without manual approval (HIGH)
        has_prod_deploy = bool(re.search(r'(environment:.*production|deploy.*production)', code, re.IGNORECASE))
        has_manual = bool(re.search(r'when:\s*manual', code, re.IGNORECASE))
        has_protected = bool(re.search(r'protected', code, re.IGNORECASE))
        
        if has_prod_deploy and not has_manual:
            result = self._find_line(lines, 'production')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Production Deployment Without Manual Approval",
                description=(
                    "Pipeline deploys to production without manual approval. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3. Production changes must require "
                    "explicit manual trigger and approval."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Add manual approval for production:\n"
                    "```yaml\n"
                    "deploy_production:\n"
                    "  stage: deploy\n"
                    "  environment:\n"
                    "    name: production\n"
                    "    # Configure in Settings > CI/CD > Environments > production:\n"
                    "    # 1. Mark as protected environment\n"
                    "    # 2. Required approvals: 2+ reviewers\n"
                    "    # 3. Allowed to deploy: Maintainers only\n"
                    "    # 4. Deployment branch: main only\n"
                    "  when: manual  # Requires manual trigger\n"
                    "  only:\n"
                    "    - main  # Only from protected branch\n"
                    "  script:\n"
                    "    - echo \"Change Ticket: $CHANGE_TICKET\"\n"
                    "    - echo \"Approved by: $APPROVER\"\n"
                    "    - ./deploy.sh\n"
                    "```\n\n"
                    "With change tracking validation:\n"
                    "```yaml\n"
                    "  before_script:\n"
                    "    - |\n"
                    "      if [ -z \"$CHANGE_TICKET\" ]; then\n"
                    "        echo \"ERROR: CHANGE_TICKET variable required\"\n"
                    "        exit 1\n"
                    "      fi\n"
                    "    - echo \"Deploying with change ticket: $CHANGE_TICKET\"\n"
                    "```\n\n"
                    "Ref: GitLab Protected Environments (https://docs.gitlab.com/ee/ci/environments/protected_environments.html)\n"
                    "NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing change tracking (MEDIUM)
        has_deploy = bool(re.search(r'deploy', code, re.IGNORECASE))
        has_change_tracking = bool(re.search(r'(CHANGE_TICKET|APPROVAL|ticket|change.*request)', code, re.IGNORECASE))
        
        if has_deploy and not has_change_tracking and len(code) > 150:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Change Tracking in Deployment",
                description=(
                    "Deployment job lacks change tracking mechanism. KSI-CMT-04 requires "
                    "documented change management per NIST CM-3. All deployments should "
                    "reference approved change requests."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add change tracking requirements:\n"
                    "```yaml\n"
                    "deploy_production:\n"
                    "  stage: deploy\n"
                    "  environment:\n"
                    "    name: production\n"
                    "  when: manual\n"
                    "  before_script:\n"
                    "    - |\n"
                    "      echo \"=== Change Management Record ===\"\n"
                    "      echo \"Change Ticket: ${CHANGE_TICKET:?Required}\"\n"
                    "      echo \"Approval Date: ${APPROVAL_DATE:?Required}\"\n"
                    "      echo \"Approver: ${APPROVER:?Required}\"\n"
                    "      echo \"Triggered by: $GITLAB_USER_LOGIN\"\n"
                    "      echo \"Timestamp: $(date -u +'%Y-%m-%d %H:%M:%S UTC')\"\n"
                    "  script:\n"
                    "    - ./deploy.sh\n"
                    "```\n\n"
                    "Set required variables in GitLab CI/CD settings:\n"
                    "- CHANGE_TICKET (protected, environment-specific)\n"
                    "- APPROVAL_DATE (protected)\n"
                    "- APPROVER (protected)\n\n"
                    "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS (LIMITED DETECTION)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Python analysis - detects database modifications without approval (AST-based).
        
        Detects:
        - Direct production database modifications without approval checks
        - .execute(), .commit() calls without change tracking
        - DROP/ALTER/TRUNCATE statements without approval validation
        """
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
            
            # Check for production context (case-insensitive string search)
            has_prod_context = bool(re.search(r'(production|prod)', code, re.IGNORECASE))
            
            if has_prod_context:
                # Pattern 1: .execute() or .commit() calls without approval parameter
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Attribute):
                            method_name = node.func.attr
                            if method_name in ['execute', 'commit', 'executemany']:
                                # Check if approval/ticket/change_request in scope
                                func_node = self._find_parent_function(node, tree)
                                if func_node:
                                    func_code = ast.unparse(func_node) if hasattr(ast, 'unparse') else ''
                                    has_approval = bool(re.search(r'(approval|ticket|change.*request)', func_code, re.IGNORECASE))
                                    
                                    if not has_approval:
                                        line_num = node.lineno
                                        findings.append(Finding(
                                            severity=Severity.MEDIUM,
                                            title="Direct Database Modification Without Approval Check",
                                            description=(
                                                f".{method_name}() at line {line_num} in production context without change management approval. "
                                                "KSI-CMT-04 requires documented change management per NIST CM-3."
                                            ),
                                            file_path=file_path,
                                            line_number=line_num,
                                            snippet=self._get_snippet(lines, line_num, context=2),
                                            remediation=(
                                                "Add change management validation:\n"
                                                "```python\n"
                                                "def apply_db_change(change_ticket: str, approved_by: str):\n"
                                                "    \"\"\"Apply database change with approval tracking.\"\"\"\n"
                                                "    if not change_ticket or not approved_by:\n"
                                                "        raise ValueError(\"Change ticket and approval required\")\n"
                                                "    \n"
                                                "    logger.info(f\"Applying change: ticket={change_ticket}, approver={approved_by}\")\n"
                                                "    \n"
                                                "    with connection.cursor() as cursor:\n"
                                                "        cursor.execute(query)\n"
                                                "        connection.commit()\n"
                                                "```\n\n"
                                                "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                                            ),
                                            ksi_id=self.KSI_ID
                                        ))
                
                # Pattern 2: SQL DDL statements (DROP, ALTER, TRUNCATE) without approval
                for node in ast.walk(tree):
                    if isinstance(node, ast.Constant) and isinstance(node.value, str):
                        sql_statement = node.value.upper()
                        if any(ddl in sql_statement for ddl in ['DROP', 'ALTER', 'TRUNCATE']):
                            # Check if in function with approval parameter
                            func_node = self._find_parent_function(node, tree)
                            if func_node:
                                has_approval_param = any(
                                    arg.arg and 'approval' in arg.arg.lower() or 'ticket' in arg.arg.lower()
                                    for arg in func_node.args.args
                                )
                                
                                if not has_approval_param:
                                    line_num = node.lineno
                                    findings.append(Finding(
                                        severity=Severity.HIGH,
                                        title="DDL Statement Without Change Approval",
                                        description=(
                                            f"DDL statement ({sql_statement[:20]}...) at line {line_num} without approval parameter. "
                                            "KSI-CMT-04 requires documented change management per NIST CM-3."
                                        ),
                                        file_path=file_path,
                                        line_number=line_num,
                                        snippet=self._get_snippet(lines, line_num, context=2),
                                        remediation=(
                                            "Require approval parameter:\n"
                                            "```python\n"
                                            "def execute_ddl(sql: str, change_ticket: str, approved_by: str):\n"
                                            "    \"\"\"Execute DDL with change management.\"\"\"\n"
                                            "    if not change_ticket or not approved_by:\n"
                                            "        raise ValueError(\"Change ticket and approver required\")\n"
                                            "    \n"
                                            "    logger.warning(f\"DDL execution: {sql[:50]}, ticket={change_ticket}\")\n"
                                            "    cursor.execute(sql)\n"
                                            "```"
                                        ),
                                        ksi_id=self.KSI_ID
                                    ))
        
        except SyntaxError:
            # Fallback to regex
            return self._python_regex_fallback(code, file_path, lines)
        
        return findings
    
    def _find_parent_function(self, node: ast.AST, tree: ast.AST) -> ast.FunctionDef:
        """Find the parent function definition containing this node."""
        for potential_parent in ast.walk(tree):
            if isinstance(potential_parent, ast.FunctionDef):
                for child in ast.walk(potential_parent):
                    if child is node:
                        return potential_parent
        return None
    
    def _python_regex_fallback(self, code: str, file_path: str, lines: List[str]) -> List[Finding]:
        """Regex fallback for Python when AST fails."""
        findings = []
        
        has_prod_context = bool(re.search(r'(production|prod)', code, re.IGNORECASE))
        has_db_modify = bool(re.search(r'(\.execute\(|\.commit\(|DROP|ALTER|TRUNCATE)', code, re.IGNORECASE))
        has_approval = bool(re.search(r'(approval|ticket|change.*request)', code, re.IGNORECASE))
        
        if has_prod_context and has_db_modify and not has_approval and len(code) > 100:
            result = self._find_line(lines, '.execute(')

            line_num = result['line_num'] if result else 0 or self._find_line(lines, '.commit(')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Direct Production Database Modification Without Approval Check (Regex Fallback)",
                description=(
                    "Code modifies production database without change management approval checks. "
                    "KSI-CMT-04 requires documented change management per NIST CM-3."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Add change management validation - see AST-based detection for examples."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Limited C# analysis - focuses on config-based change control bypasses.
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Direct database modification in production context (MEDIUM)
        has_prod_context = bool(re.search(r'(Production|Prod)', code))
        has_db_modify = bool(re.search(r'(ExecuteSqlRaw|SaveChanges|Database\.ExecuteSql)', code))
        has_approval = bool(re.search(r'(Approval|Ticket|ChangeRequest)', code))
        
        if has_prod_context and has_db_modify and not has_approval and len(code) > 100:
            result = self._find_line(lines, 'ExecuteSqlRaw')

            line_num = result['line_num'] if result else 0 or self._find_line(lines, 'SaveChanges')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Direct Production Database Modification Without Approval Check",
                description=(
                    "Code modifies production database without change management approval checks. "
                    "KSI-CMT-04 requires documented change management per NIST CM-3."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Add change management validation:\n"
                    "```csharp\n"
                    "public void ApplyDbChange(string changeTicket, string approvedBy)\n"
                    "{\n"
                    "    if (string.IsNullOrEmpty(changeTicket) || string.IsNullOrEmpty(approvedBy))\n"
                    "        throw new InvalidOperationException(\"Change ticket and approval required\");\n"
                    "    \n"
                    "    _logger.LogInformation($\"Applying change: ticket={changeTicket}, approver={approvedBy}\");\n"
                    "    \n"
                    "    _context.Database.ExecuteSqlRaw(query);\n"
                    "    _context.SaveChanges();\n"
                    "}\n"
                    "```\n\n"
                    "Ref: NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Limited Java analysis."""
        return []  # Minimal detection for Java
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Limited TypeScript analysis."""
        return []  # Minimal detection for TypeScript
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (BASIC CHECKS)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Basic Bicep analysis for change management controls.
        
        Detects:
        - Missing resource locks on critical resources
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Critical resources without locks (MEDIUM)
        has_critical_resource = bool(re.search(r"resource\s+\w+\s+'Microsoft\.(KeyVault|Storage|Sql)", code, re.IGNORECASE))
        has_lock = bool(re.search(r'Microsoft\.Authorization/locks', code, re.IGNORECASE))
        
        if has_critical_resource and not has_lock and len(code) > 100:
            result = self._find_line(lines, 'resource')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Critical Resource Without Lock",
                description=(
                    "Critical resource lacks Azure Resource Lock. KSI-CMT-04 requires change management "
                    "controls per NIST CM-3. Locks prevent unauthorized changes."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Add resource lock:\n"
                    "```bicep\n"
                    "resource lock 'Microsoft.Authorization/locks@2020-05-01' = {\n"
                    "  name: '${resourceName}-lock'\n"
                    "  scope: resourceName\n"
                    "  properties: {\n"
                    "    level: 'CanNotDelete'  // or 'ReadOnly'\n"
                    "    notes: 'Protect from unauthorized changes - requires change ticket to modify'\n"
                    "  }\n"
                    "}\n"
                    "```\n\n"
                    "Ref: Azure Resource Locks (https://learn.microsoft.com/azure/azure-resource-manager/management/lock-resources)\n"
                    "NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Basic Terraform analysis for change management controls.
        
        Detects:
        - Missing resource locks on critical resources
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Critical resources without locks (MEDIUM)
        has_critical_resource = bool(re.search(r'resource\s+"azurerm_(sql_database|key_vault|storage_account)"', code))
        has_lock = bool(re.search(r'azurerm_management_lock', code))
        
        if has_critical_resource and not has_lock and len(code) > 100:
            result = self._find_line(lines, 'resource')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Critical Resource Without Management Lock",
                description=(
                    "Critical resource lacks Azure Management Lock. KSI-CMT-04 requires change management "
                    "controls per NIST CM-3. Locks prevent unauthorized changes."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Add management lock:\n"
                    "```terraform\n"
                    "resource \"azurerm_management_lock\" \"resource_lock\" {\n"
                    "  name       = \"${var.resource_name}-lock\"\n"
                    "  scope      = azurerm_resource.resource.id\n"
                    "  lock_level = \"CanNotDelete\"  # or \"ReadOnly\"\n"
                    "  notes      = \"Protect from unauthorized changes - requires change ticket to modify\"\n"
                    "}\n"
                    "```\n\n"
                    "Ref: Azure Management Locks (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/management_lock)\n"
                    "NIST CM-3 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-3)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

        """Find line number containing search term (case-insensitive)."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

