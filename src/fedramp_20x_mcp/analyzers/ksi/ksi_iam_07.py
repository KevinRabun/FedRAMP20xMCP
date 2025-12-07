"""
KSI-IAM-07: Automated Account Management

Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_IAM_07_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-07: Automated Account Management
    
    **Official Statement:**
    Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.2
    - ac-2.3
    - ac-2.13
    - ac-6.7
    - ia-4.4
    - ia-12
    - ia-12.2
    - ia-12.3
    - ia-12.5
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-IAM-07"
    KSI_NAME = "Automated Account Management"
    KSI_STATEMENT = """Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation."""
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2.2", "ac-2.3", "ac-2.13", "ac-6.7", "ia-4.4", "ia-12", "ia-12.2", "ia-12.3", "ia-12.5"]
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
        Analyze Python code for KSI-IAM-07 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Manual user creation without automation
        - Missing automated provisioning/deprovisioning
        - No inactive account detection
        - Missing integration with IdP/SCIM
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual user creation without automation hooks (MEDIUM)
        manual_user_patterns = [
            r'User\.objects\.create\(',
            r'create_user\s*\(',
            r'user\.save\s*\(\s*\)',
            r'UserManager.*create',
        ]
        
        for pattern in manual_user_patterns:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check if there's automation/provisioning logic nearby
                context_lines = lines[max(0, line_num-5):min(len(lines), line_num+10)]
                context_text = '\n'.join(context_lines)
                if not re.search(r'(provisioning|automation|workflow|lifecycle|signal|event)', context_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Manual User Creation Without Lifecycle Automation",
                        description=(
                            f"Manual user creation at line {line_num} without automated lifecycle management. "
                            f"Account management should use automated provisioning, approval workflows, "
                            f"and deprovisioning to ensure secure lifecycle management."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement automated account lifecycle management:\n"
                            "- Use Django signals (post_save, pre_delete) for lifecycle hooks\n"
                            "- Integrate with IdP (Azure AD, Okta) for automated provisioning\n"
                            "- Implement SCIM endpoint for automated user/group management\n"
                            "- Add approval workflows for account creation/privilege changes\n"
                            "- Schedule periodic review of inactive accounts"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Report once
        
        # Pattern 2: Missing deprovisioning/deletion handling (HIGH)
        if re.search(r'(User\.objects\.filter|get_user_model)', code):
            if not re.search(r'(is_active\s*=\s*False|disable.*user|deactivate|deprovision|delete.*user)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Missing Automated Account Deprovisioning",
                    description=(
                        "User management code found but no automated deprovisioning/deactivation logic. "
                        "Automated account lifecycle requires disabling accounts when users leave, "
                        "change roles, or become inactive."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement automated deprovisioning:\n"
                        "- Sync with HR system to detect employee departures\n"
                        "- Automatically disable accounts after X days of inactivity\n"
                        "- Remove group memberships and revoke privileges\n"
                        "- Schedule periodic cleanup of orphaned accounts\n"
                        "- Implement offboarding workflows"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No inactive account detection (MEDIUM)
        if re.search(r'User|Account', code, re.IGNORECASE):
            if not re.search(r'(last_login|last_activity|inactive|expir)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="No Inactive Account Detection Logic",
                    description=(
                        "User/account management without tracking last activity or detecting inactive accounts. "
                        "Automated lifecycle management requires identifying and disabling inactive accounts."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement inactive account detection:\n"
                        "- Track last_login and last_activity timestamps\n"
                        "- Schedule job to identify accounts inactive for 30/60/90 days\n"
                        "- Send warnings before automatic deactivation\n"
                        "- Automatically disable accounts after threshold period\n"
                        "- Generate reports of inactive accounts for review"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-07 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Manual UserManager operations without automation
        - Missing account lifecycle events
        - No automated expiration tracking
        - Missing integration with Azure AD provisioning
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual UserManager.CreateAsync without automation (MEDIUM)
        if re.search(r'UserManager.*CreateAsync\s*\(', code):
            create_matches = list(re.finditer(r'UserManager.*CreateAsync\s*\(', code))
            for match in create_matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check for lifecycle management in surrounding code
                context_lines = lines[max(0, line_num-5):min(len(lines), line_num+15)]
                context_text = '\n'.join(context_lines)
                if not re.search(r'(IUserStore|IUserClaimStore|provisioning|lifecycle|automation)', context_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Manual User Creation Without Lifecycle Automation",
                        description=(
                            f"UserManager.CreateAsync at line {line_num} without automated lifecycle management. "
                            f"Account creation should integrate with provisioning workflows, approval processes, "
                            f"and automated onboarding/offboarding."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement automated account lifecycle:\n"
                            "- Create custom IUserStore with lifecycle events\n"
                            "- Integrate with Azure AD B2C/B2E for automated provisioning\n"
                            "- Use Microsoft Graph API for user lifecycle management\n"
                            "- Implement approval workflows before account activation\n"
                            "- Add lifecycle policies (expiration, review cycles)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 2: Missing account expiration/review tracking (HIGH)
        if re.search(r'(UserManager|IdentityUser|ApplicationUser)', code):
            if not re.search(r'(Expir|LastLogin|LastActivity|AccountReview|Inactive)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Missing Account Expiration and Review Tracking",
                    description=(
                        "User/identity management without expiration dates or activity tracking. "
                        "Automated lifecycle management requires tracking account status, "
                        "last activity, and periodic access reviews."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Add lifecycle tracking to user model:\n"
                        "public DateTime? AccountExpirationDate { get; set; }\n"
                        "public DateTime LastLoginDate { get; set; }\n"
                        "public DateTime? LastAccessReviewDate { get; set; }\n"
                        "Implement background jobs to:\n"
                        "- Disable expired accounts\n"
                        "- Flag inactive accounts (no login in 30+ days)\n"
                        "- Schedule periodic access reviews"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No automated role/group management (MEDIUM)
        if re.search(r'AddToRoleAsync|RemoveFromRoleAsync', code):
            if not re.search(r'(workflow|approval|automation|lifecycle|event)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Role Management Without Automation or Approval",
                    description=(
                        "Role assignments/removals without automated workflows or approval processes. "
                        "Privilege changes should require approval, logging, and automated expiration."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'AddToRoleAsync|RemoveFromRoleAsync'),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'AddToRoleAsync|RemoveFromRoleAsync')),
                    remediation=(
                        "Implement automated role lifecycle management:\n"
                        "- Require approval workflow for role assignments\n"
                        "- Set expiration dates for temporary/elevated privileges\n"
                        "- Log all role changes with justification\n"
                        "- Automate role removal when users change departments/leave\n"
                        "- Schedule periodic role membership reviews"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Manual account operations without automation
        - Missing SCIM provisioning integration
        - No automated account expiration
        - Missing lifecycle event handlers
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual user repository saves without lifecycle (MEDIUM)
        if re.search(r'userRepository\.(save|saveAndFlush)\(', code, re.IGNORECASE):
            save_matches = list(re.finditer(r'userRepository\.(save|saveAndFlush)\(', code, re.IGNORECASE))
            for match in save_matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check for lifecycle/event handling
                context_lines = lines[max(0, line_num-5):min(len(lines), line_num+10)]
                context_text = '\n'.join(context_lines)
                if not re.search(r'(@PrePersist|@PostPersist|@PreRemove|@EventListener|lifecycle|provisioning)', context_text):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="User Save Operation Without Lifecycle Management",
                        description=(
                            f"User save operation at line {line_num} without lifecycle event handling. "
                            f"Automated account management requires lifecycle hooks for provisioning, "
                            f"notifications, audit logging, and integration with external systems."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement lifecycle event handlers:\n"
                            "@PrePersist / @PostPersist for user creation\n"
                            "@PreUpdate for privilege changes\n"
                            "@PreRemove for deprovisioning\n"
                            "Use Spring Application Events for cross-service coordination\n"
                            "Integrate with SCIM for automated provisioning"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 2: Missing account expiration tracking (HIGH)
        if re.search(r'(User|Account|UserEntity)', code):
            if not re.search(r'(expirationDate|lastLoginDate|accountExpiry|inactive|enabled.*false)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="User Entity Missing Expiration and Activity Tracking",
                    description=(
                        "User/Account entity without expiration date or last activity tracking. "
                        "Automated lifecycle management requires tracking account status and "
                        "implementing automatic expiration/deactivation."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Add lifecycle fields to user entity:\n"
                        "private LocalDateTime accountExpirationDate;\n"
                        "private LocalDateTime lastLoginDate;\n"
                        "private LocalDateTime lastAccessReviewDate;\n"
                        "private boolean enabled = true;\n\n"
                        "Implement scheduled tasks:\n"
                        "- @Scheduled job to disable expired accounts\n"
                        "- Detect inactive accounts (no login 30+ days)\n"
                        "- Send notifications before expiration"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No SCIM/provisioning integration (MEDIUM)
        if re.search(r'UserRepository|UserService', code):
            if not re.search(r'(SCIM|provisioning|UserProvisioning|SCIMUserService)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="No SCIM Provisioning Integration Detected",
                    description=(
                        "User management code without SCIM (System for Cross-domain Identity Management) integration. "
                        "Automated account lifecycle should integrate with IdP for automated provisioning/deprovisioning."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement SCIM integration for automated provisioning:\n"
                        "- Add Spring SCIM library dependency\n"
                        "- Expose SCIM endpoints (/scim/v2/Users, /scim/v2/Groups)\n"
                        "- Integrate with Azure AD, Okta, or other IdP\n"
                        "- Implement automatic user creation/deletion via SCIM\n"
                        "- Sync group memberships and attributes automatically"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Manual CRUD operations without lifecycle hooks
        - Missing automated provisioning integration
        - No account expiration/inactivity handling
        - Missing event-driven lifecycle management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual user create/save without lifecycle events (MEDIUM)
        user_create_patterns = [
            r'User\.create\s*\(',
            r'userRepository\.save\s*\(',
            r'createUser\s*\(',
            r'insertOne\s*\(.*user',
        ]
        
        for pattern in user_create_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check for lifecycle/event handling
                context_lines = lines[max(0, line_num-5):min(len(lines), line_num+15)]
                context_text = '\n'.join(context_lines)
                if not re.search(r'(emit|event|trigger|hook|middleware|lifecycle)', context_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="User Creation Without Lifecycle Event Handling",
                        description=(
                            f"User creation at line {line_num} without lifecycle event emission or hooks. "
                            f"Automated account management requires event-driven architecture for "
                            f"provisioning notifications, audit logging, and integration with external systems."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement lifecycle events:\n"
                            "eventEmitter.emit('user.created', user);\n"
                            "or (NestJS): @EventPattern('user.created')\n"
                            "or use ORM hooks: @BeforeInsert(), @AfterInsert()\n\n"
                            "Add lifecycle listeners for:\n"
                            "- Sending welcome emails\n"
                            "- Provisioning access to systems\n"
                            "- Audit logging\n"
                            "- Syncing with IdP"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 2: Missing account expiration fields (HIGH)
        if re.search(r'(interface User|class User|type User)', code):
            if not re.search(r'(expiresAt|expirationDate|lastLoginAt|lastActivityAt|isActive)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="User Model Missing Lifecycle Tracking Fields",
                    description=(
                        "User type/interface without lifecycle tracking fields (expiration, last activity). "
                        "Automated account management requires tracking account status for "
                        "automatic deactivation of expired/inactive accounts."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'interface User|class User|type User'),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'interface User|class User|type User')),
                    remediation=(
                        "Add lifecycle fields to user model:\n"
                        "expirationDate?: Date;\n"
                        "lastLoginAt: Date;\n"
                        "lastActivityAt: Date;\n"
                        "isActive: boolean;\n"
                        "accountStatus: 'active' | 'inactive' | 'suspended' | 'expired';\n\n"
                        "Implement cron job to:\n"
                        "- Disable expired accounts\n"
                        "- Flag inactive users (no activity 30+ days)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No automated deprovisioning (MEDIUM)
        if re.search(r'(deleteUser|removeUser|User\.delete)', code, re.IGNORECASE):
            if not re.search(r'(deprovision|offboard|revokeAccess|lifecycle)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="User Deletion Without Deprovisioning Workflow",
                    description=(
                        "User deletion logic without comprehensive deprovisioning workflow. "
                        "Automated lifecycle management requires revoking all access, cleaning up "
                        "resources, and notifying dependent systems."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'deleteUser|removeUser|User\.delete'),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'deleteUser|removeUser|User\.delete')),
                    remediation=(
                        "Implement complete deprovisioning workflow:\n"
                        "- Revoke all API tokens and sessions\n"
                        "- Remove from all groups/roles\n"
                        "- Delete or archive user data per retention policy\n"
                        "- Notify dependent systems via events\n"
                        "- Audit log the deprovisioning\n"
                        "- Consider soft-delete with grace period"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-07 compliance.
        
        Detects:
        - Manual user/group provisioning in Bicep
        - Missing Azure AD lifecycle policies
        - No automated access reviews configuration
        - Missing entitlement management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual user creation in Bicep (INFO - should use IdP)
        if re.search(r"'Microsoft\.AzureActiveDirectory/b2cDirectories/users'|'Microsoft\.Graph/users'", code):
            findings.append(Finding(
                severity=Severity.INFO,
                title="Manual User Provisioning in Infrastructure Code",
                description=(
                    "Users being provisioned directly in Bicep templates. "
                    "Automated account lifecycle should use Azure AD identity governance, "
                    "SCIM provisioning, or HR-driven automation, not infrastructure code."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, r"users'"),
                snippet=self._get_snippet(lines, self._find_line(lines, r"users'")),
                remediation=(
                    "Use Azure AD identity governance instead:\n"
                    "- Configure Azure AD Connect for on-prem sync\n"
                    "- Use SCIM provisioning from IdP (Workday, HR system)\n"
                    "- Implement Azure AD Entitlement Management for access packages\n"
                    "- Configure lifecycle workflows for automated provisioning/deprovisioning\n"
                    "Infrastructure code should focus on resources, not user accounts."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing access reviews configuration (MEDIUM)
        if re.search(r"'Microsoft\.Authorization/roleAssignments'", code):
            if not re.search(r'accessReview|governanceInsight', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Role Assignments Without Automated Access Reviews",
                    description=(
                        "Role assignments deployed without Azure AD Access Reviews configuration. "
                        "Automated lifecycle management requires periodic access reviews to validate "
                        "continued need for privileges."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Configure Azure AD Access Reviews:\n"
                        "- Set up recurring access reviews (quarterly/semi-annual)\n"
                        "- Require justification for continued access\n"
                        "- Auto-remove access if not approved\n"
                        "- Review privileged role assignments more frequently\n"
                        "- Use Microsoft Graph API to automate review creation\n"
                        "Note: Access Reviews are configured via Azure Portal/Graph API, not Bicep."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No entitlement management (INFO)
        if re.search(r'roleAssignment|role.*Definition', code, re.IGNORECASE):
            if not re.search(r'accessPackage|entitlementManagement', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider Azure AD Entitlement Management",
                    description=(
                        "Role-based access detected without Azure AD Entitlement Management. "
                        "Entitlement Management provides automated access request, approval, "
                        "lifecycle, and access packages for automated role management."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement Azure AD Entitlement Management:\n"
                        "- Create access packages grouping related resources/roles\n"
                        "- Configure self-service access requests with approval workflows\n"
                        "- Set automatic assignment/removal based on user attributes\n"
                        "- Define expiration policies for time-limited access\n"
                        "- Integrate with Azure AD lifecycle workflows\n"
                        "Reference: https://learn.microsoft.com/azure/active-directory/governance/entitlement-management-overview"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-07 compliance.
        
        Detects:
        - Manual azuread_user resource creation
        - Missing lifecycle policies
        - No automated group membership management
        - Static user/group configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Static azuread_user resources (MEDIUM)
        user_resources = list(re.finditer(r'resource\s+"azuread_user"\s+"\w+"', code))
        if len(user_resources) > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Static User Provisioning in Terraform",
                description=(
                    f"Found {len(user_resources)} azuread_user resources. "
                    f"Users should be managed via Azure AD identity governance and SCIM provisioning, "
                    f"not static Terraform resources. Infrastructure code managing users creates "
                    f"manual lifecycle overhead."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, r'resource\s+"azuread_user"'),
                snippet=self._get_snippet(lines, self._find_line(lines, r'resource\s+"azuread_user"')),
                remediation=(
                    "Replace static user provisioning with automated lifecycle management:\n"
                    "- Use Azure AD Connect for on-premises directory sync\n"
                    "- Configure SCIM provisioning from HR/IdP (Workday, Okta)\n"
                    "- Implement Azure AD lifecycle workflows for automation\n"
                    "- Use dynamic groups based on user attributes\n"
                    "- Configure Azure AD Entitlement Management for access packages\n"
                    "Terraform should manage infrastructure, not user accounts."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Static group membership (MEDIUM)
        if re.search(r'resource\s+"azuread_group_member"', code):
            static_members = len(re.findall(r'resource\s+"azuread_group_member"', code))
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Static Group Membership Management",
                description=(
                    f"Found {static_members} static azuread_group_member assignments. "
                    f"Automated lifecycle management should use dynamic group membership rules "
                    f"based on user attributes, not static assignments."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, r'azuread_group_member'),
                snippet=self._get_snippet(lines, self._find_line(lines, r'azuread_group_member')),
                remediation=(
                    "Use dynamic group membership instead:\n"
                    "resource \"azuread_group\" \"example\" {\n"
                    "  display_name     = \"Dynamic Group\"\n"
                    "  types            = [\"DynamicMembership\"]\n"
                    "  dynamic_membership {\n"
                    "    enabled = true\n"
                    "    rule    = \"user.department -eq 'Engineering'\"\n"
                    "  }\n"
                    "}\n"
                    "Benefits: Automatic membership updates based on user attributes."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Missing lifecycle policies (INFO)
        if re.search(r'azuread_(user|group)', code):
            if not re.search(r'(lifecycle|access_review|entitlement)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider Azure AD Lifecycle Workflows",
                    description=(
                        "Azure AD resources managed without lifecycle workflow configuration. "
                        "Azure AD Lifecycle Workflows automate common lifecycle tasks: "
                        "onboarding, joiner-mover-leaver processes, and scheduled account management."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement Azure AD Lifecycle Workflows (preview):\n"
                        "- Pre-hire: Prepare accounts before start date\n"
                        "- Onboarding: Generate temporary password, send welcome email, assign groups\n"
                        "- Joiner-Mover-Leaver: Automate department changes, offboarding\n"
                        "- Scheduled: Remove inactive users, expire accounts\n\n"
                        "Note: Lifecycle Workflows configured via Azure Portal/Graph API.\n"
                        "Reference: https://learn.microsoft.com/azure/active-directory/governance/what-are-lifecycle-workflows"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> int:
        """Find line number matching regex pattern (case-insensitive)."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    return i
        except re.error:
            # Fallback to literal string search if pattern is invalid
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
