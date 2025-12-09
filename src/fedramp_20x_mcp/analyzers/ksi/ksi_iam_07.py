"""
KSI-IAM-07: Automated Account Management (Enhanced AST-Based Analyzer)

Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)

NIST Controls: ac-2.2, ac-2.3, ac-2.13, ac-6.7, ia-4.4, ia-12, ia-12.2, ia-12.3, ia-12.5
"""

import ast
import re
from typing import List
from ..base import Finding, Severity, AnalysisResult
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_IAM_07_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced AST-based analyzer for KSI-IAM-07: Automated Account Management
    
    **Official Statement:**
    Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.2: Automated account management
    - ac-2.3: Disable accounts after conditions
    - ac-2.13: Disable accounts after inactivity
    - ac-6.7: Review and re-approve privileged accounts
    - ia-4.4: Identify user status
    - ia-12: Identity proofing
    - ia-12.2: Identity evidence
    - ia-12.3: Identity evidence validation
    - ia-12.5: Address confirmation
    
    **Detectability:** Code-Detectable (AST-based analysis)
    
    **Detection Strategy:**
    Uses AST parsing to identify:
    1. Manual account creation without lifecycle automation/event hooks
    2. Missing account deprovisioning/deactivation logic
    3. No inactive account detection or expiration tracking
    4. Missing integration with IdP/SCIM provisioning
    5. Role management without approval workflows
    6. Static user/group provisioning in IaC
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI (placeholder)
    """
    
    KSI_ID = "KSI-IAM-07"
    KSI_NAME = "Automated Account Management"
    KSI_STATEMENT = "Securely manage the lifecycle and privileges of all accounts, roles, and groups, using automation."
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2.2", "Automated Temporary and Emergency Account Management"),
        ("ac-2.3", "Disable Accounts"),
        ("ac-2.13", "Disable Accounts for High-risk Individuals"),
        ("ac-6.7", "Review of User Privileges"),
        ("ia-4.4", "Identify User Status"),
        ("ia-12", "Identity Proofing"),
        ("ia-12.2", "Identity Evidence"),
        ("ia-12.3", "Identity Evidence Validation and Verification"),
        ("ia-12.5", "Address Confirmation")
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
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-IAM-07 compliance (AST-based).
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Manual user creation without automation (User.objects.create without hooks)
        - Missing deprovisioning logic (no is_active=False or disable_user)
        - No inactive account detection (no last_login or last_activity tracking)
        - Missing IdP/SCIM integration
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            tree = ast.parse(code)
            
            # Pattern 1: Manual user creation without lifecycle automation (MEDIUM)
            # Look for User.objects.create(), create_user(), user.save() calls
            user_creation_calls = []
            has_automation = False
            has_receiver_decorator = False
            
            for node in ast.walk(tree):
                # Check for @receiver decorator (Django signals)
                if isinstance(node, ast.FunctionDef):
                    for decorator in node.decorator_list:
                        decorator_name = ""
                        if isinstance(decorator, ast.Name):
                            decorator_name = decorator.id
                        elif isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Name):
                            decorator_name = decorator.func.id
                        
                        if 'receiver' in decorator_name.lower():
                            has_receiver_decorator = True
                            has_automation = True
                
                # Detect user creation calls
                if isinstance(node, ast.Call):
                    call_str = ast.unparse(node) if hasattr(ast, 'unparse') else ""
                    
                    # User.objects.create()
                    if isinstance(node.func, ast.Attribute):
                        if (isinstance(node.func.value, ast.Attribute) and
                            isinstance(node.func.value.value, ast.Name) and
                            node.func.value.value.id == 'User' and
                            node.func.value.attr == 'objects' and
                            node.func.attr == 'create'):
                            user_creation_calls.append((node, node.lineno))
                        
                        # create_user() or user.save()
                        if (node.func.attr in ['create_user', 'save'] and
                            'user' in call_str.lower()):
                            user_creation_calls.append((node, node.lineno))
                
                # Check for automation keywords in function/class names
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    name_lower = node.name.lower()
                    if any(keyword in name_lower for keyword in ['provision', 'automation', 'workflow', 'lifecycle']):
                        has_automation = True
            
            # Report user creation without automation
            for call_node, line_num in user_creation_calls:
                if not has_automation:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Manual User Creation Without Lifecycle Automation",
                        description=(
                            f"Manual user creation at line {line_num} without automated lifecycle management hooks. "
                            f"FedRAMP 20x requires automated account provisioning with approval workflows, "
                            f"lifecycle events, and integration with identity providers."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement automated account lifecycle management:\n"
                            "1. Use Django signals for lifecycle hooks:\n"
                            "   from django.db.models.signals import post_save\n"
                            "   @receiver(post_save, sender=User)\n"
                            "   def on_user_created(sender, instance, created, **kwargs):\n"
                            "       if created:\n"
                            "           # Trigger provisioning workflow\n"
                            "           provision_user_accounts(instance)\n"
                            "2. Integrate with IdP (Azure AD, Okta) for SCIM provisioning\n"
                            "3. Implement approval workflows before account activation\n"
                            "4. Add automated onboarding tasks (send welcome email, provision resources)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Report once
            
            # Pattern 2: Missing deprovisioning/deactivation logic (HIGH)
            # Look for User references but no deactivation logic
            has_user_management = False
            has_deprovisioning = False
            
            for node in ast.walk(tree):
                # Check for User.objects or get_user_model
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == 'User' and node.attr == 'objects':
                        has_user_management = True
                
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == 'get_user_model':
                        has_user_management = True
                
                # Check for deactivation logic
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Attribute) and target.attr == 'is_active':
                            if isinstance(node.value, ast.Constant) and node.value.value is False:
                                has_deprovisioning = True
                
                # Check for function names with deactivation keywords
                if isinstance(node, ast.FunctionDef):
                    name_lower = node.name.lower()
                    if any(keyword in name_lower for keyword in ['disable', 'deactivate', 'deprovision', 'delete_user']):
                        has_deprovisioning = True
            
            if has_user_management and not has_automation and not has_deprovisioning:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Missing Automated Account Deprovisioning Logic",
                    description=(
                        "User management code detected but no automated deprovisioning/deactivation logic. "
                        "FedRAMP 20x AC-2.3 requires disabling accounts when users leave, change roles, or become inactive. "
                        "Manual deprovisioning creates security risks and compliance gaps."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement automated deprovisioning:\n"
                        "1. Integrate with HR system to detect employee departures:\n"
                        "   def sync_with_hr_system():\n"
                        "       departed_users = hr_api.get_terminated_employees()\n"
                        "       for user_id in departed_users:\n"
                        "           User.objects.filter(id=user_id).update(is_active=False)\n"
                        "           revoke_all_sessions(user_id)\n"
                        "2. Implement scheduled job for inactivity detection (AC-2.13):\n"
                        "   threshold = timezone.now() - timedelta(days=90)\n"
                        "   User.objects.filter(last_login__lt=threshold).update(is_active=False)\n"
                        "3. Remove group memberships and revoke API tokens on deactivation"
                    ),
                    ksi_id=self.KSI_ID
                ))
            
            # Pattern 3: User model without lifecycle tracking fields (MEDIUM)
            has_user_class = False
            has_lifecycle_fields = False
            user_class_line = 1
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    if 'User' in node.name:
                        has_user_class = True
                        user_class_line = node.lineno
                        
                        # Check for lifecycle tracking fields
                        for class_node in node.body:
                            if isinstance(class_node, ast.Assign):
                                for target in class_node.targets:
                                    if isinstance(target, ast.Name):
                                        field_name = target.id.lower()
                                        if any(keyword in field_name for keyword in ['last_login', 'last_activity', 'expir', 'inactive']):
                                            has_lifecycle_fields = True
            
            if has_user_class and not has_automation and not has_lifecycle_fields:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="User Model Missing Lifecycle Tracking Fields",
                    description=(
                        "User/account model without last_login, last_activity, or expiration tracking. "
                        "FedRAMP 20x AC-2.13 requires automated detection and disabling of inactive accounts. "
                        "Without activity tracking, compliance cannot be demonstrated."
                    ),
                    file_path=file_path,
                    line_number=user_class_line,
                    snippet=self._get_snippet(lines, user_class_line),
                    remediation=(
                        "Add lifecycle tracking fields to user model:\n"
                        "class User(models.Model):\n"
                        "    last_login = models.DateTimeField(null=True)\n"
                        "    last_activity = models.DateTimeField(auto_now=True)\n"
                        "    account_expiration_date = models.DateTimeField(null=True)\n"
                        "    is_active = models.BooleanField(default=True)\n"
                        "\n"
                        "Implement scheduled task for compliance:\n"
                        "@shared_task\n"
                        "def disable_inactive_accounts():\n"
                        "    threshold = timezone.now() - timedelta(days=90)\n"
                        "    inactive = User.objects.filter(last_login__lt=threshold, is_active=True)\n"
                        "    for user in inactive:\n"
                        "        user.is_active = False\n"
                        "        user.save()\n"
                        "        notify_security_team(user)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        except SyntaxError:
            # Fallback to regex if AST parsing fails
            findings.extend(self._python_regex_fallback(code, file_path, lines))
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str, lines: List[str]) -> List[Finding]:
        """Regex fallback for Python analysis when AST parsing fails."""
        findings = []
        
        # Pattern 1: Manual user creation
        manual_user_patterns = [
            r'User\.objects\.create\s*\(',
            r'create_user\s*\(',
            r'user\.save\s*\(\s*\)',
        ]
        
        for pattern in manual_user_patterns:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                context_start = max(0, line_num - 15)
                context_end = min(len(lines), line_num + 10)
                context_lines = lines[context_start:context_end]
                context_text = '\n'.join(context_lines)
                
                if not re.search(r'(provisioning|automation|workflow|lifecycle|signal|event|@receiver)', context_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Manual User Creation Without Lifecycle Automation (Regex Fallback)",
                        description=(
                            f"Manual user creation at line {line_num} without automated lifecycle management hooks. "
                            f"FedRAMP 20x requires automated account provisioning with approval workflows."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Implement automated account lifecycle management with Django signals or IdP integration.",
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-07 compliance (Tree-Sitter AST-based).
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Manual UserManager.CreateAsync without automation
        - Missing account lifecycle events
        - No automated expiration tracking
        - Missing Azure AD integration
        """
        findings = []
        lines = code.split('\n')
        
        try:
            # Use tree-sitter for C# AST parsing
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            root = tree.root_node
            code_bytes = code.encode('utf8')
            
            # Pattern 1: Manual UserManager.CreateAsync without automation (MEDIUM)
            user_creation_calls = []
            has_automation = False
            
            # Find all invocation_expression nodes (method calls)
            invocation_nodes = parser.find_nodes_by_type(tree.root_node, "invocation_expression")
            for node in invocation_nodes:
                # Check if it's CreateAsync call
                call_text = parser.get_node_text(node, code_bytes)
                if "CreateAsync" in call_text and ("UserManager" in call_text or "_userManager" in call_text):
                    user_creation_calls.append((node, node.start_point[0] + 1))
            
            # Check for automation-related interfaces and services
            identifier_nodes = parser.find_nodes_by_type(tree.root_node, "identifier")
            for node in identifier_nodes:
                identifier_text = parser.get_node_text(node, code_bytes)
                if identifier_text in ["IUserStore", "IUserClaimStore", "ProvisioningService", 
                                      "LifecycleService", "IEventPublisher", "EventHandler"]:
                    has_automation = True
                    break
            
            # Check for class names with lifecycle management
            class_nodes = parser.find_nodes_by_type(tree.root_node, "class_declaration")
            for node in class_nodes:
                class_name = None
                for child in node.children:
                    if child.type == "identifier":
                        class_name = parser.get_node_text(child, code_bytes)
                        break
                if class_name and any(keyword in class_name for keyword in ["Provisioning", "Lifecycle", "Automation"]):
                    has_automation = True
                    break
            
            # Report user creation without automation
            for call_node, line_num in user_creation_calls:
                if not has_automation:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Manual User Creation Without Lifecycle Automation",
                        description=(
                            f"UserManager.CreateAsync at line {line_num} without automated lifecycle management. "
                            f"FedRAMP 20x requires automated provisioning workflows with approval, logging, and "
                            f"integration with identity providers."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement automated account lifecycle:\n"
                            "1. Create custom IUserStore with lifecycle events:\n"
                            "   public class AuditableUserStore : IUserStore<ApplicationUser>\n"
                            "   {\n"
                            "       public async Task<IdentityResult> CreateAsync(ApplicationUser user)\n"
                            "       {\n"
                            "           // Trigger provisioning workflow\n"
                            "           await _provisioningService.OnUserCreatedAsync(user);\n"
                            "           return await base.CreateAsync(user);\n"
                            "       }\n"
                            "   }\n"
                            "2. Integrate with Azure AD B2C/B2E for SCIM provisioning\n"
                            "3. Use Microsoft Graph API for automated user lifecycle\n"
                            "4. Implement approval workflows before account activation"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Report once
            
            # Pattern 2: Missing account expiration/review tracking (HIGH)
            has_user_class = False
            has_lifecycle_properties = False
            user_class_line = 1
            
            class_nodes = parser.find_nodes_by_type(tree.root_node, "class_declaration")
            for node in class_nodes:
                class_name = None
                for child in node.children:
                    if child.type == "identifier":
                        class_name = parser.get_node_text(child, code_bytes)
                        break
                
                if class_name and ("User" in class_name or "ApplicationUser" in class_name or "IdentityUser" in class_name):
                    has_user_class = True
                    user_class_line = node.start_point[0] + 1
                    
                    # Check for lifecycle tracking properties within class
                    for class_child in node.children:
                        if class_child.type == "property_declaration":
                            prop_text = parser.get_node_text(class_child, code_bytes)
                            if any(keyword in prop_text for keyword in ["Expir", "LastLogin", "LastActivity", 
                                                                        "AccountReview", "Inactive"]):
                                has_lifecycle_properties = True
                                break
            
            if has_user_class and not has_automation and not has_lifecycle_properties:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="User Model Missing Lifecycle Tracking Properties",
                    description=(
                        "User/identity management without expiration dates or activity tracking properties. "
                        "FedRAMP 20x AC-2.13 requires tracking account status and last activity for "
                        "automated detection of inactive accounts (90-day threshold)."
                    ),
                    file_path=file_path,
                    line_number=user_class_line,
                    snippet=self._get_snippet(lines, user_class_line),
                    remediation=(
                        "Add lifecycle tracking properties to user model:\n"
                        "public class ApplicationUser : IdentityUser\n"
                        "{\n"
                        "    public DateTime? AccountExpirationDate { get; set; }\n"
                        "    public DateTime LastLoginDate { get; set; }\n"
                        "    public DateTime? LastAccessReviewDate { get; set; }\n"
                        "    public bool IsActive { get; set; } = true;\n"
                        "}\n"
                        "\n"
                        "Implement background job for compliance (AC-2.13):\n"
                        "public class DisableInactiveAccountsJob : IHostedService\n"
                        "{\n"
                        "    public async Task ExecuteAsync()\n"
                        "    {\n"
                        "        var threshold = DateTime.UtcNow.AddDays(-90);\n"
                        "        var inactive = await _userManager.Users\n"
                        "            .Where(u => u.LastLoginDate < threshold && u.IsActive)\n"
                        "            .ToListAsync();\n"
                        "        foreach (var user in inactive)\n"
                        "        {\n"
                        "            user.IsActive = false;\n"
                        "            await _userManager.UpdateAsync(user);\n"
                        "        }\n"
                        "    }\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        except Exception:
            # Fallback to regex if tree-sitter parsing fails
            findings.extend(self._csharp_regex_fallback(code, file_path, lines))
        
        return findings
    
    def _csharp_regex_fallback(self, code: str, file_path: str, lines: List[str]) -> List[Finding]:
        """Regex fallback for C# analysis when tree-sitter parsing fails."""
        findings = []
        
        # Pattern 1: Manual UserManager.CreateAsync without automation (MEDIUM)
        if re.search(r'(UserManager|_userManager).*CreateAsync\s*\(', code):
            create_matches = list(re.finditer(r'(UserManager|_userManager).*CreateAsync\s*\(', code))
            for match in create_matches:
                line_num = code[:match.start()].count('\n') + 1
                context_start = max(0, line_num - 6)
                context_end = min(len(lines), line_num + 15)
                context_lines = lines[context_start:context_end]
                context_text = '\n'.join(context_lines)
                
                # Remove comments
                context_no_comments = re.sub(r'//.*$', '', context_text, flags=re.MULTILINE)
                context_no_comments = re.sub(r'/\*.*?\*/', '', context_no_comments, flags=re.DOTALL)
                
                if not re.search(r'(IUserStore|IUserClaimStore|ProvisioningService|LifecycleService|IEventPublisher|EventHandler)', context_no_comments, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Manual User Creation Without Lifecycle Automation (Regex Fallback)",
                        description=(
                            f"UserManager.CreateAsync at line {line_num} without automated lifecycle management. "
                            f"FedRAMP 20x requires automated provisioning workflows."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Implement automated account lifecycle management with IUserStore or lifecycle services.",
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Manual userRepository.save without lifecycle events
        - Missing SCIM provisioning integration
        - No account expiration tracking
        - Missing lifecycle event handlers
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual user save without lifecycle events (MEDIUM)
        if re.search(r'userRepository\.(save|saveAndFlush)\s*\(', code, re.IGNORECASE):
            save_matches = list(re.finditer(r'userRepository\.(save|saveAndFlush)\s*\(', code, re.IGNORECASE))
            for match in save_matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check ±10 lines for lifecycle/event handling
                context_start = max(0, line_num - 6)
                context_end = min(len(lines), line_num + 10)
                context_lines = lines[context_start:context_end]
                context_text = '\n'.join(context_lines)
                
                if not re.search(r'(@PrePersist|@PostPersist|@PreRemove|@EventListener|lifecycle|provisioning)', context_text):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="User Save Operation Without Lifecycle Management",
                        description=(
                            f"User save operation at line {line_num} without lifecycle event handling. "
                            f"FedRAMP 20x requires automated account management with provisioning workflows, "
                            f"audit logging, and integration with identity providers."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement lifecycle event handlers:\n"
                            "@Entity\n"
                            "public class User {\n"
                            "    @PrePersist\n"
                            "    protected void onCreate() {\n"
                            "        // Trigger provisioning workflow\n"
                            "        applicationEventPublisher.publishEvent(new UserCreatedEvent(this));\n"
                            "    }\n"
                            "    \n"
                            "    @PreRemove\n"
                            "    protected void onDelete() {\n"
                            "        // Trigger deprovisioning workflow\n"
                            "        applicationEventPublisher.publishEvent(new UserDeletedEvent(this));\n"
                            "    }\n"
                            "}\n"
                            "\n"
                            "@EventListener\n"
                            "public void handleUserCreated(UserCreatedEvent event) {\n"
                            "    provisionUserAccounts(event.getUser());\n"
                            "    sendWelcomeEmail(event.getUser());\n"
                            "}"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 2: Missing account expiration tracking (HIGH)
        if re.search(r'(@Entity.*User|class\s+\w*User.*Entity|public\s+class\s+\w*User)', code):
            if not re.search(r'(expirationDate|lastLoginDate|accountExpiry|inactive|enabled\s*=\s*false)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="User Entity Missing Lifecycle Tracking Fields",
                    description=(
                        "User/Account entity without expiration date or last activity tracking fields. "
                        "FedRAMP 20x AC-2.13 requires automated detection and disabling of inactive accounts "
                        "after 90 days of inactivity."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'@Entity.*User|class\s+\w*User'),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'@Entity.*User|class\s+\w*User')),
                    remediation=(
                        "Add lifecycle tracking fields to user entity:\n"
                        "@Entity\n"
                        "public class User {\n"
                        "    @Column(name = \"account_expiration_date\")\n"
                        "    private LocalDateTime accountExpirationDate;\n"
                        "    \n"
                        "    @Column(name = \"last_login_date\", nullable = false)\n"
                        "    private LocalDateTime lastLoginDate;\n"
                        "    \n"
                        "    @Column(name = \"last_access_review_date\")\n"
                        "    private LocalDateTime lastAccessReviewDate;\n"
                        "    \n"
                        "    @Column(name = \"enabled\", nullable = false)\n"
                        "    private boolean enabled = true;\n"
                        "}\n"
                        "\n"
                        "Implement scheduled task for compliance (AC-2.13):\n"
                        "@Scheduled(cron = \"0 0 2 * * ?\") // Daily at 2 AM\n"
                        "public void disableInactiveAccounts() {\n"
                        "    LocalDateTime threshold = LocalDateTime.now().minusDays(90);\n"
                        "    List<User> inactive = userRepository.findByLastLoginDateBeforeAndEnabledTrue(threshold);\n"
                        "    inactive.forEach(user -> {\n"
                        "        user.setEnabled(false);\n"
                        "        userRepository.save(user);\n"
                        "    });\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No SCIM/provisioning integration (MEDIUM)
        if re.search(r'(UserRepository|UserService|@Service.*User)', code):
            if not re.search(r'(SCIM|provisioning|UserProvisioning|SCIMUserService)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="No SCIM Provisioning Integration Detected",
                    description=(
                        "User management code without SCIM (System for Cross-domain Identity Management) integration. "
                        "FedRAMP 20x requires automated account lifecycle with IdP integration for "
                        "automated provisioning/deprovisioning."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement SCIM integration for automated provisioning:\n"
                        "1. Add Spring SCIM library dependency:\n"
                        "   <dependency>\n"
                        "       <groupId>com.unboundid.product.scim2</groupId>\n"
                        "       <artifactId>scim2-sdk-server</artifactId>\n"
                        "   </dependency>\n"
                        "\n"
                        "2. Expose SCIM endpoints:\n"
                        "   @RestController\n"
                        "   @RequestMapping(\"/scim/v2\")\n"
                        "   public class SCIMUserController {\n"
                        "       @PostMapping(\"/Users\")\n"
                        "       public ResponseEntity<UserResource> createUser(@RequestBody UserResource user) {\n"
                        "           // Automated user creation from IdP\n"
                        "       }\n"
                        "       @DeleteMapping(\"/Users/{id}\")\n"
                        "       public ResponseEntity<Void> deleteUser(@PathVariable String id) {\n"
                        "           // Automated user deprovisioning from IdP\n"
                        "       }\n"
                        "   }\n"
                        "\n"
                        "3. Integrate with Azure AD, Okta, or other IdP for automated lifecycle"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Manual user CRUD without lifecycle events
        - Missing automated provisioning integration
        - No account expiration/inactivity handling
        - Missing event-driven lifecycle management
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Manual user create without lifecycle events (MEDIUM)
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
                # Check ±15 lines for lifecycle/event handling
                context_start = max(0, line_num - 6)
                context_end = min(len(lines), line_num + 15)
                context_lines = lines[context_start:context_end]
                context_text = '\n'.join(context_lines)
                
                if not re.search(r'(emit|event|trigger|hook|middleware|lifecycle|@EventPattern)', context_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="User Creation Without Lifecycle Event Handling",
                        description=(
                            f"User creation at line {line_num} without lifecycle event emission or hooks. "
                            f"FedRAMP 20x requires event-driven account management for automated provisioning, "
                            f"audit logging, and integration with identity providers."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement lifecycle event emission:\n"
                            "// Option 1: Node.js EventEmitter\n"
                            "const user = await User.create(userData);\n"
                            "eventEmitter.emit('user.created', user);\n"
                            "\n"
                            "// Option 2: NestJS Events\n"
                            "@Injectable()\n"
                            "export class UserService {\n"
                            "  constructor(private eventEmitter: EventEmitter2) {}\n"
                            "  \n"
                            "  async createUser(data: CreateUserDto) {\n"
                            "    const user = await this.userRepository.save(data);\n"
                            "    this.eventEmitter.emit('user.created', user);\n"
                            "    return user;\n"
                            "  }\n"
                            "}\n"
                            "\n"
                            "@OnEvent('user.created')\n"
                            "handleUserCreated(user: User) {\n"
                            "  // Trigger provisioning workflow\n"
                            "  this.provisioningService.provisionUser(user);\n"
                            "}"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break
        
        # Pattern 2: User model missing lifecycle fields (HIGH)
        if re.search(r'(interface\s+User|class\s+User|type\s+User)', code):
            if not re.search(r'(expiresAt|expirationDate|lastLoginAt|lastActivityAt|isActive)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="User Model Missing Lifecycle Tracking Fields",
                    description=(
                        "User type/interface without lifecycle tracking fields (expiration, last activity). "
                        "FedRAMP 20x AC-2.13 requires tracking account status for automated deactivation "
                        "of expired/inactive accounts after 90 days."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'interface\s+User|class\s+User|type\s+User'),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'interface\s+User|class\s+User|type\s+User')),
                    remediation=(
                        "Add lifecycle tracking fields to user model:\n"
                        "interface User {\n"
                        "  id: string;\n"
                        "  email: string;\n"
                        "  expirationDate?: Date;\n"
                        "  lastLoginAt: Date;\n"
                        "  lastActivityAt: Date;\n"
                        "  isActive: boolean;\n"
                        "  accountStatus: 'active' | 'inactive' | 'suspended' | 'expired';\n"
                        "}\n"
                        "\n"
                        "Implement scheduled job for compliance (AC-2.13):\n"
                        "import { Cron } from '@nestjs/schedule';\n"
                        "\n"
                        "@Injectable()\n"
                        "export class AccountLifecycleService {\n"
                        "  @Cron('0 0 2 * * *') // Daily at 2 AM\n"
                        "  async disableInactiveAccounts() {\n"
                        "    const threshold = new Date();\n"
                        "    threshold.setDate(threshold.getDate() - 90);\n"
                        "    \n"
                        "    const inactive = await this.userRepository.find({\n"
                        "      where: {\n"
                        "        lastLoginAt: { $lt: threshold },\n"
                        "        isActive: true\n"
                        "      }\n"
                        "    });\n"
                        "    \n"
                        "    for (const user of inactive) {\n"
                        "      user.isActive = false;\n"
                        "      user.accountStatus = 'inactive';\n"
                        "      await this.userRepository.save(user);\n"
                        "    }\n"
                        "  }\n"
                        "}"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: User deletion without deprovisioning workflow (MEDIUM)
        if re.search(r'(deleteUser|removeUser|User\.delete|\.remove\s*\()', code, re.IGNORECASE):
            if not re.search(r'(deprovision|offboard|revokeAccess|lifecycle)', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="User Deletion Without Comprehensive Deprovisioning",
                    description=(
                        "User deletion logic without comprehensive deprovisioning workflow. "
                        "FedRAMP 20x AC-2.3 requires automated deprovisioning that revokes all access, "
                        "cleans up resources, and notifies dependent systems."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r'deleteUser|removeUser|User\.delete|\.remove\s*\('),
                    snippet=self._get_snippet(lines, self._find_line(lines, r'deleteUser|removeUser|User\.delete')),
                    remediation=(
                        "Implement comprehensive deprovisioning workflow:\n"
                        "async deleteUser(userId: string): Promise<void> {\n"
                        "  // 1. Revoke all active sessions and API tokens\n"
                        "  await this.sessionService.revokeAllSessions(userId);\n"
                        "  await this.tokenService.revokeAllTokens(userId);\n"
                        "  \n"
                        "  // 2. Remove from all groups and roles\n"
                        "  await this.groupService.removeUserFromAllGroups(userId);\n"
                        "  await this.roleService.revokeAllRoles(userId);\n"
                        "  \n"
                        "  // 3. Delete or archive user data per retention policy\n"
                        "  await this.dataRetentionService.handleUserData(userId);\n"
                        "  \n"
                        "  // 4. Notify dependent systems\n"
                        "  this.eventEmitter.emit('user.deprovisioned', { userId });\n"
                        "  \n"
                        "  // 5. Audit log the deprovisioning\n"
                        "  await this.auditService.log('USER_DEPROVISIONED', { userId });\n"
                        "  \n"
                        "  // 6. Soft-delete with grace period\n"
                        "  await this.userRepository.update(userId, {\n"
                        "    isActive: false,\n"
                        "    accountStatus: 'deleted',\n"
                        "    deletedAt: new Date()\n"
                        "  });\n"
                        "}"
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
        if re.search(r"Microsoft\.(AzureActiveDirectory/b2cDirectories/users|Graph/users)", code):
            findings.append(Finding(
                severity=Severity.INFO,
                title="Manual User Provisioning in Infrastructure Code",
                description=(
                    "Users being provisioned directly in Bicep templates. "
                    "FedRAMP 20x requires automated account lifecycle using Azure AD identity governance, "
                    "SCIM provisioning, or HR-driven automation, not static infrastructure code."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, r"users'"),
                snippet=self._get_snippet(lines, self._find_line(lines, r"users'")),
                remediation=(
                    "Use Azure AD identity governance instead:\n"
                    "1. Configure Azure AD Connect for on-premises directory sync\n"
                    "2. Implement SCIM provisioning from IdP (Workday, Okta, HR system)\n"
                    "3. Deploy Azure AD Entitlement Management for access packages\n"
                    "4. Configure lifecycle workflows for automated provisioning/deprovisioning\n"
                    "\n"
                    "Infrastructure code should manage resources, not user accounts. "
                    "User lifecycle should be driven by HR systems and IdP automation."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Role assignments without access reviews (MEDIUM)
        if re.search(r"Microsoft\.Authorization/roleAssignments", code):
            if not re.search(r'accessReview|governanceInsight', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Role Assignments Without Automated Access Reviews",
                    description=(
                        "Role assignments deployed without Azure AD Access Reviews configuration. "
                        "FedRAMP 20x AC-6.7 requires periodic access reviews to validate continued need "
                        "for privileges and ensure least privilege."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, r"roleAssignments'"),
                    snippet=self._get_snippet(lines, self._find_line(lines, r"roleAssignments'")),
                    remediation=(
                        "Configure Azure AD Access Reviews for role assignments:\n"
                        "1. Set up recurring access reviews (quarterly for standard, monthly for privileged)\n"
                        "2. Require justification for continued access\n"
                        "3. Configure auto-removal of access if not approved\n"
                        "4. Review privileged role assignments more frequently (AC-6.7)\n"
                        "\n"
                        "Note: Access Reviews are configured via Azure Portal or Microsoft Graph API:\n"
                        "POST https://graph.microsoft.com/v1.0/identityGovernance/accessReviews/definitions\n"
                        "{\n"
                        "  \"displayName\": \"Quarterly Role Assignment Review\",\n"
                        "  \"scope\": { \"@odata.type\": \"#microsoft.graph.principalResourceMembershipsScope\" },\n"
                        "  \"reviewers\": [{ \"query\": \"/users/{managerId}\" }],\n"
                        "  \"settings\": {\n"
                        "    \"recurrence\": { \"pattern\": { \"type\": \"absoluteMonthly\", \"interval\": 3 } },\n"
                        "    \"defaultDecisionEnabled\": true,\n"
                        "    \"defaultDecision\": \"Deny\"\n"
                        "  }\n"
                        "}\n"
                        "\n"
                        "Reference: https://learn.microsoft.com/azure/active-directory/governance/access-reviews-overview"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: No entitlement management (INFO)
        if re.search(r'roleAssignment|roleDefinition', code, re.IGNORECASE):
            if not re.search(r'accessPackage|entitlementManagement', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider Azure AD Entitlement Management for Automated Access",
                    description=(
                        "Role-based access detected without Azure AD Entitlement Management. "
                        "Entitlement Management provides automated access request, approval workflows, "
                        "lifecycle management, and access packages for role automation."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement Azure AD Entitlement Management for automated access lifecycle:\n"
                        "1. Create access packages grouping related resources/roles\n"
                        "2. Configure self-service access requests with approval workflows\n"
                        "3. Set automatic assignment/removal based on user attributes (department, job title)\n"
                        "4. Define expiration policies for time-limited access (contractors, temporary privileges)\n"
                        "5. Integrate with Azure AD lifecycle workflows for onboarding/offboarding\n"
                        "\n"
                        "Benefits:\n"
                        "- Automated provisioning and deprovisioning (AC-2.2, AC-2.3)\n"
                        "- Self-service reduces manual overhead\n"
                        "- Built-in approval workflows and audit trails\n"
                        "- Access reviews integrated with entitlement lifecycle\n"
                        "\n"
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
        - Static group membership management
        - No dynamic group configuration
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
                    f"Found {len(user_resources)} azuread_user resources managed in Terraform. "
                    f"FedRAMP 20x requires automated account lifecycle using Azure AD identity governance "
                    f"and SCIM provisioning, not static infrastructure code. Manual user management "
                    f"creates security gaps and compliance risks."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, r'resource\s+"azuread_user"'),
                snippet=self._get_snippet(lines, self._find_line(lines, r'resource\s+"azuread_user"')),
                remediation=(
                    "Replace static user provisioning with automated lifecycle management:\n"
                    "1. Configure Azure AD Connect for on-premises directory sync\n"
                    "2. Implement SCIM provisioning from HR/IdP (Workday, Okta, BambooHR)\n"
                    "3. Deploy Azure AD lifecycle workflows:\n"
                    "   - Pre-hire: Prepare accounts before start date\n"
                    "   - Onboarding: Generate credentials, assign groups, send welcome email\n"
                    "   - Joiner-Mover-Leaver: Automate department changes, offboarding\n"
                    "   - Scheduled: Remove inactive users, expire accounts\n"
                    "4. Use dynamic groups based on user attributes (department, jobTitle)\n"
                    "5. Configure Azure AD Entitlement Management for access packages\n"
                    "\n"
                    "Terraform should manage infrastructure resources, not user accounts. "
                    "User lifecycle should be driven by HR systems and automated provisioning."
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
                    f"FedRAMP 20x requires automated lifecycle management with dynamic group membership "
                    f"based on user attributes, not static assignments."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, r'azuread_group_member'),
                snippet=self._get_snippet(lines, self._find_line(lines, r'azuread_group_member')),
                remediation=(
                    "Use dynamic group membership for automated lifecycle:\n"
                    "resource \"azuread_group\" \"engineering\" {\n"
                    "  display_name     = \"Engineering Team\"\n"
                    "  types            = [\"DynamicMembership\"]\n"
                    "  security_enabled = true\n"
                    "  \n"
                    "  dynamic_membership {\n"
                    "    enabled = true\n"
                    "    rule    = \"(user.department -eq 'Engineering') and (user.accountEnabled -eq true)\"\n"
                    "  }\n"
                    "}\n"
                    "\n"
                    "Benefits of dynamic groups:\n"
                    "- Automatic membership updates based on user attributes\n"
                    "- No manual provisioning/deprovisioning required\n"
                    "- Membership changes instantly when user attributes change\n"
                    "- Supports complex rules with AND/OR logic\n"
                    "\n"
                    "Examples:\n"
                    "- user.department -eq 'Engineering'\n"
                    "- user.jobTitle -contains 'Manager'\n"
                    "- user.country -eq 'US' and user.companyName -eq 'Contoso'\n"
                    "\n"
                    "Reference: https://learn.microsoft.com/azure/active-directory/enterprise-users/groups-dynamic-membership"
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
                        "Azure AD Lifecycle Workflows automate common account management tasks "
                        "required by FedRAMP 20x: joiner-mover-leaver processes and scheduled account management."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement Azure AD Lifecycle Workflows for automated account management:\n"
                        "\n"
                        "1. Pre-hire workflow:\n"
                        "   - Trigger: 7 days before start date\n"
                        "   - Actions: Create account, generate temporary password, assign to pre-hire group\n"
                        "\n"
                        "2. Onboarding workflow:\n"
                        "   - Trigger: Employee start date\n"
                        "   - Actions: Send welcome email, assign licenses, add to department groups, provision resources\n"
                        "\n"
                        "3. Joiner-Mover workflow:\n"
                        "   - Trigger: Department change\n"
                        "   - Actions: Update group memberships, revoke old access, grant new access\n"
                        "\n"
                        "4. Leaver workflow (AC-2.3):\n"
                        "   - Trigger: Employee departure\n"
                        "   - Actions: Disable account, revoke access, remove from groups, archive mailbox\n"
                        "\n"
                        "5. Scheduled workflow (AC-2.13):\n"
                        "   - Trigger: Daily or weekly\n"
                        "   - Actions: Disable inactive accounts (90+ days), expire temporary accounts\n"
                        "\n"
                        "Note: Lifecycle Workflows are configured via Azure Portal or Microsoft Graph API.\n"
                        "Reference: https://learn.microsoft.com/azure/active-directory/governance/what-are-lifecycle-workflows"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (PLACEHOLDERS)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-07 compliance.
        
        Note: Account lifecycle management is typically not implemented in CI/CD pipelines.
        """
        findings = []
        # No applicable patterns for GitHub Actions
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-07 compliance.
        
        Note: Account lifecycle management is typically not implemented in CI/CD pipelines.
        """
        findings = []
        # No applicable patterns for Azure Pipelines
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-07 compliance.
        
        Note: Account lifecycle management is typically not implemented in CI/CD pipelines.
        """
        findings = []
        # No applicable patterns for GitLab CI
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
            # Fallback to literal string search
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 1  # Return 1 instead of 0 for valid line numbers
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number <= 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

