"""
FRR-RSC-01: Top-Level Administrative Accounts Guidance

Providers MUST create and maintain guidance that includes instructions on how to securely access, configure, operate, and decommission _top-level administrative accounts_ that control enterprise access to the entire _cloud service offering_.

Official FedRAMP 20x Requirement
Source: FRR-RSC (Resource Categorization) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_RSC_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-01: Top-Level Administrative Accounts Guidance
    
    **Official Statement:**
    Providers MUST create and maintain guidance that includes instructions on how to securely access, configure, operate, and decommission _top-level administrative accounts_ that control enterprise access to the entire _cloud service offering_.
    
    **Family:** RSC - Resource Categorization
    
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
    
    FRR_ID = "FRR-RSC-01"
    FRR_NAME = "Top-Level Administrative Accounts Guidance"
    FRR_STATEMENT = """Providers MUST create and maintain guidance that includes instructions on how to securely access, configure, operate, and decommission _top-level administrative accounts_ that control enterprise access to the entire _cloud service offering_."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-2", "Account Management"),
        ("IA-2", "Identification and Authentication"),
        ("IA-4", "Identifier Management")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-IAM-01", "KSI-IAM-02"]
    
    def __init__(self):
        """Initialize FRR-RSC-01 analyzer."""
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
        Analyze Python code for admin account management patterns.
        
        Checks for:
        - Admin user creation/provisioning code
        - Missing documentation references
        - Hardcoded admin credentials
        """
        findings = []
        lines = code.split('\n')
        
        # Check for admin account creation without documented procedures
        admin_patterns = [
            r'create.*admin', r'provision.*admin', r'setup.*admin',
            r'admin.*user', r'root.*account', r'superuser'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in admin_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Admin account management requires documented procedures",
                        description=f"Line {i} contains admin account creation code. FRR-RSC-01 requires documented guidance for securely accessing, configuring, operating, and decommissioning top-level administrative accounts.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Create documentation (e.g., ADMIN-ACCOUNTS.md) covering: (1) How to securely create admin accounts, (2) Required security settings, (3) MFA requirements, (4) Audit logging, (5) Decommissioning procedures"
                    ))
                    break
        
        # Check for hardcoded admin credentials (security issue)
        credential_patterns = [
            r'admin.*password', r'root.*password', r'admin.*token',
            r'password.*=.*[\'"]admin', r'username.*=.*[\'"]admin'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in credential_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Hardcoded admin credentials detected",
                        description=f"Line {i} contains hardcoded admin credentials. This violates secure admin account practices required by FRR-RSC-01.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 2),
                        recommendation="Remove hardcoded credentials. Use environment variables, Azure Key Vault, or managed identities. Document proper credential management in admin account guidance."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """C# admin account analysis (similar patterns to Python)."""
        return self._analyze_admin_patterns(code, file_path)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Java admin account analysis (similar patterns to Python)."""
        return self._analyze_admin_patterns(code, file_path)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """TypeScript/JavaScript admin account analysis (similar patterns to Python)."""
        return self._analyze_admin_patterns(code, file_path)
    
    def _analyze_admin_patterns(self, code: str, file_path: str) -> List[Finding]:
        """Shared logic for admin account detection across languages."""
        findings = []
        lines = code.split('\n')
        
        admin_patterns = [
            r'create.*admin', r'provision.*admin', r'Admin.*User',
            r'root.*account', r'superuser', r'Administrator'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in admin_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Admin account management requires documented procedures",
                        description=f"Admin account code detected. FRR-RSC-01 requires documentation for secure access, configuration, operation, and decommissioning.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Document admin account lifecycle in ADMIN-ACCOUNTS.md or SECURITY.md"
                    ))
                    return findings  # Only report once per file
        
        return findings
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep for admin account provisioning.
        
        Checks for SQL admins, Key Vault admins, etc. requiring documented procedures.
        """
        findings = []
        lines = code.split('\n')
        
        # Check for SQL admin configuration
        if re.search(r'Microsoft\.Sql/servers.*administratorLogin', code, re.DOTALL):
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="SQL Server admin accounts require documented guidance",
                description="Bicep configures SQL Server administrative accounts. FRR-RSC-01 requires documentation for accessing, configuring, operating, and decommissioning top-level admin accounts.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Create ADMIN-ACCOUNTS.md documenting: (1) How to create/configure SQL admins, (2) MFA requirements, (3) Privilege levels, (4) Decommissioning steps"
            ))
        
        # Check for Key Vault access policies (admin-level access)
        if re.search(r'accessPolicies.*permissions.*\[(.*all.*|.*\*.*)\]', code, re.IGNORECASE | re.DOTALL):
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Key Vault admin access requires documented procedures",
                description="Bicep grants administrative Key Vault permissions. FRR-RSC-01 requires documented guidance for admin account lifecycle.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Document Key Vault admin access procedures including role requirements and audit logging"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for admin account provisioning."""
        findings = []
        
        # Check for azurerm_sql_server admin
        if 'azurerm_sql_server' in code and 'administrator_login' in code:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="SQL admin accounts require documented guidance (Terraform)",
                description="Terraform configures SQL admin accounts. FRR-RSC-01 requires documentation.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Document SQL admin lifecycle in ADMIN-ACCOUNTS.md"
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Check GitHub Actions for admin account operations."""
        findings = []
        
        # Look for admin provisioning steps
        if re.search(r'(azure/login|az\s+ad|create.*admin|provision.*admin)', code, re.IGNORECASE):
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Admin provisioning in CI/CD requires documented procedures",
                description="GitHub Actions performs admin account operations. FRR-RSC-01 requires documented guidance.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Document CI/CD admin provisioning procedures including approval workflow and audit logging"
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Azure Pipelines for admin operations."""
        return self.analyze_github_actions(code, file_path)  # Similar logic
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Check GitLab CI for admin operations."""
        return self.analyze_github_actions(code, file_path)  # Similar logic
    
    # ============================================================================
    # DOCUMENTATION ANALYSIS
    # ============================================================================
    
    def analyze_documentation(self, file_content: str, file_path: str = "") -> List[Finding]:
        """
        Check if documentation exists for admin account procedures.
        
        Looks for:
        - Admin account guidance
        - Secure access procedures
        - Configuration instructions
        - Decommissioning steps
        """
        findings = []
        
        # Check if this is a relevant documentation file
        doc_files = ['readme', 'admin', 'security', 'ops', 'runbook']
        if not any(keyword in file_path.lower() for keyword in doc_files):
            return findings
        
        # Check for admin account documentation
        has_admin_guidance = re.search(r'(admin.*account|administrative.*account|root.*account|top.*level.*admin)', file_content, re.IGNORECASE)
        has_access_procedures = re.search(r'(access|login|authentication).*admin', file_content, re.IGNORECASE)
        has_decommission = re.search(r'(decommission|delete|remove|offboard).*admin', file_content, re.IGNORECASE)
        
        if has_admin_guidance:
            if not has_access_procedures:
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Incomplete admin documentation: Missing access procedures",
                    description="Documentation mentions admin accounts but lacks secure access procedures required by FRR-RSC-01.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Add section documenting: (1) MFA requirements, (2) Access approval process, (3) Session timeouts, (4) Login monitoring"
                ))
            
            if not has_decommission:
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Incomplete admin documentation: Missing decommissioning procedures",
                    description="Documentation lacks admin account decommissioning procedures required by FRR-RSC-01.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Document: (1) When to decommission, (2) Access revocation steps, (3) Audit log preservation, (4) Knowledge transfer"
                ))
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-RSC-01.
        
        This requirement is primarily documentation-focused.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Documentation review + code analysis for admin provisioning',
            'evidence_artifacts': [
                "ADMIN-ACCOUNTS.md or equivalent documentation",
                "Procedures for secure admin access",
                "Configuration instructions",
                "Decommissioning procedures",
                "Code analysis showing admin account creation points"
                # - "Documentation showing policy Z"
            ],
            'collection_queries': [
                # TODO: Add KQL or API queries for evidence
                # Examples for Azure:
                # - "AzureDiagnostics | where Category == 'X' | project TimeGenerated, Property"
                # - "GET https://management.azure.com/subscriptions/{subscriptionId}/..."
            ],
            'manual_validation_steps': [
                # TODO: Add manual validation procedures
                # 1. "Review documentation for X"
                # 2. "Verify configuration setting Y"
                # 3. "Interview stakeholder about Z"
            ],
            'recommended_services': [
                # TODO: List Azure/AWS services that help with this requirement
                # Examples:
                # - "Azure Policy - for configuration validation"
                # - "Azure Monitor - for activity logging"
                # - "Microsoft Defender for Cloud - for security posture"
            ],
            'integration_points': [
                # TODO: List integration with other tools
                # Examples:
                # - "Export to OSCAL format for automated reporting"
                # - "Integrate with ServiceNow for change management"
            ]
        }
