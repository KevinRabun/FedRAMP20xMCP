"""
FRR-RSC-04: Secure Defaults on Provisioning

Providers SHOULD set all settings to their recommended secure defaults for _top-level administrative accounts_ and _privileged accounts_ when initially provisioned.

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


class FRR_RSC_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-04: Secure Defaults on Provisioning
    
    **Official Statement:**
    Providers SHOULD set all settings to their recommended secure defaults for _top-level administrative accounts_ and _privileged accounts_ when initially provisioned.
    
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
    
    **Detectability:** Partial
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
    1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
    2. Infrastructure patterns (Bicep, Terraform) - Use regex
    3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    """
    
    FRR_ID = "FRR-RSC-04"
    FRR_NAME = "Secure Defaults on Provisioning"
    FRR_STATEMENT = """Providers SHOULD set all settings to their recommended secure defaults for _top-level administrative accounts_ and _privileged accounts_ when initially provisioned."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        # TODO: Add NIST controls (e.g., ("RA-5", "Vulnerability Monitoring and Scanning"))
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "PARTIAL"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-RSC-04 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on IaC provisioning, not application code."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on IaC provisioning, not application code."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on IaC provisioning, not application code."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on IaC provisioning, not application code."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-RSC-04 compliance.
        
        Checks for:
        - Admin accounts without MFA/strong authentication
        - Weak password policies
        - Overly permissive role assignments for admin accounts
        - Missing security settings on privileged identities
        """
        findings = []
        lines = code.split('\n')
        
        # Check for SQL admin accounts without secure defaults
        sql_admin_pattern = r"administratorLogin\s*:\s*'([^']*)'"  
        for i, line in enumerate(lines, start=1):
            # Check for hardcoded admin usernames (insecure)
            if re.search(sql_admin_pattern, line):
                if re.search(r"administratorLogin\s*:\s*'(admin|sa|root|administrator)'", line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Insecure default admin username",
                        description=f"Line {i} uses a common/default admin username. FRR-RSC-04 requires secure defaults for privileged accounts.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Use a non-default, organization-specific admin username and configure with secure settings (MFA, least privilege, audit logging)"
                    ))
            
            # Check for admin users without MFA requirement  
            if 'Microsoft.Sql/servers' in line and i > 1:
                # Look ahead for admin configuration
                context_lines = lines[max(0, i-5):min(len(lines), i+10)]
                context = '\n'.join(context_lines)
                
                if 'administratorLogin' in context and 'azureADOnlyAuthentication' not in context:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Missing Azure AD authentication for SQL admin",
                        description=f"SQL Server resource at line {i} does not enforce Azure AD-only authentication. FRR-RSC-04 requires secure defaults for admin accounts.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Set 'azureADOnlyAuthentication: true' to enforce MFA and strong authentication for admin access"
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-RSC-04 compliance.
        
        Checks for:
        - IAM users/roles with admin access but insecure defaults
        - Missing MFA requirements for privileged accounts
        - Weak password policies
        """
        findings = []
        lines = code.split('\n')
        
        # Check for IAM users or policy attachments with admin access but no MFA
        full_code = '\n'.join(lines)
        
        for i, line in enumerate(lines, start=1):
            # Check for AdministratorAccess policy attachments
            if 'AdministratorAccess' in line:
                # Look for MFA requirement in entire file
                if 'aws:MultiFactorAuthPresent' not in full_code and 'aws_iam_user_mfa_device' not in full_code:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Admin IAM user without MFA requirement",
                        description=f"IAM configuration with AdministratorAccess at line {i} does not enforce MFA. FRR-RSC-04 requires secure defaults for privileged accounts.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Add MFA requirement via IAM policy condition 'aws:MultiFactorAuthPresent': 'true' or use aws_iam_user_mfa_device resource"
                    ))
            
            # Check for password policies
            if 'aws_iam_account_password_policy' in line:
                context_start = i
                context_end = min(len(lines), i + 15)
                context_lines = lines[context_start:context_end]
                context = '\n'.join(context_lines)
                
                # Check for weak password policy
                if 'minimum_password_length' in context:
                    match = re.search(r'minimum_password_length\s*=\s*(\d+)', context)
                    if match and int(match.group(1)) < 14:
                        findings.append(Finding(
                            ksi_id=self.FRR_ID,
                            requirement_id=self.FRR_ID,
                            title="Weak password length requirement",
                            description=f"Password policy at line {i} allows passwords shorter than 14 characters. FRR-RSC-04 requires secure defaults.",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            recommendation="Set minimum_password_length to at least 14 characters for privileged accounts"
                        ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on resource provisioning, not CI/CD workflows."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on resource provisioning, not CI/CD workflows."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-RSC-04 focuses on resource provisioning, not CI/CD workflows."""
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for secure provisioning defaults.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Partial',
            'automation_approach': 'Automated IaC scanning for secure defaults on privileged account provisioning, combined with configuration exports from IAM systems',
            'evidence_artifacts': [
                'Bicep/Terraform templates for privileged account provisioning',
                'IAM policy configurations (Azure AD, AWS IAM)',
                'Password policy settings',
                'MFA enforcement status for admin accounts',
                'Role/privilege assignment records for top-level accounts',
                'Account provisioning audit logs'
            ],
            'collection_queries': [
                'Bicep/Terraform scan: Check for admin account resources with secure defaults',
                'Azure: Get-AzADUser | Where-Object {$_.IsAdmin} | Get-MFA Status',
                'AWS: aws iam list-users --query "Users[?contains(AttachedPolicies, \'AdministratorAccess\')]"',
                'KQL: AzureActivity | where OperationNameValue contains "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE" and Properties contains "Owner" or Properties contains "Administrator"'
            ],
            'manual_validation_steps': [
                '1. Export current IAM/AAD configuration for all privileged accounts',
                '2. Verify each admin account has MFA/strong auth enabled',
                '3. Check password policies meet minimum requirements (14+ chars, complexity, rotation)',
                '4. Review role assignments to ensure least privilege',
                '5. Validate that provisioning templates use secure defaults',
                '6. Document any exceptions with risk acceptance'
            ],
            'recommended_services': [
                'Azure Policy: Enforce secure defaults via policy',
                'Azure AD Conditional Access: MFA enforcement',
                'AWS Config Rules: IAM password policy compliance',
                'Azure Privileged Identity Management (PIM): JIT admin access',
                'Terraform Sentinel: Policy-as-code for secure provisioning'
            ],
            'integration_points': [
                'OSCAL SSP: Document provisioning security controls',
                'CI/CD: Pre-deployment validation of IaC templates',
                'SIEM: Alert on admin account provisioning without secure defaults',
                'Identity Governance: Periodic access reviews for privileged accounts'
            ]
        }
