"""
KSI-IAM-04: Just-in-Time Authorization

Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_IAM_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-04: Just-in-Time Authorization
    
    **Official Statement:**
    Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2
    - ac-2.1
    - ac-2.2
    - ac-2.3
    - ac-2.4
    - ac-2.6
    - ac-3
    - ac-4
    - ac-5
    - ac-6
    - ac-6.1
    - ac-6.2
    - ac-6.5
    - ac-6.7
    - ac-6.9
    - ac-6.10
    - ac-7
    - ac-20.1
    - ac-17
    - au-9.4
    - cm-5
    - cm-7
    - cm-7.2
    - cm-7.5
    - cm-9
    - ia-4
    - ia-4.4
    - ia-7
    - ps-2
    - ps-3
    - ps-4
    - ps-5
    - ps-6
    - ps-9
    - ra-5.5
    - sc-2
    - sc-23
    - sc-39
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use a least-privileged, role and attribute-based, and just-in-time security authorization model for ...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-IAM-04"
    KSI_NAME = "Just-in-Time Authorization"
    KSI_STATEMENT = """Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services."""
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2", "ac-2.1", "ac-2.2", "ac-2.3", "ac-2.4", "ac-2.6", "ac-3", "ac-4", "ac-5", "ac-6", "ac-6.1", "ac-6.2", "ac-6.5", "ac-6.7", "ac-6.9", "ac-6.10", "ac-7", "ac-20.1", "ac-17", "au-9.4", "cm-5", "cm-7", "cm-7.2", "cm-7.5", "cm-9", "ia-4", "ia-4.4", "ia-7", "ps-2", "ps-3", "ps-4", "ps-5", "ps-6", "ps-9", "ra-5.5", "sc-2", "sc-23", "sc-39"]
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
        Analyze Python code for KSI-IAM-04 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Permanent admin/privileged access
        - Missing role-based authorization decorators
        - Lack of time-limited access controls
        - Azure PIM integration checks
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Permanent admin access without time limits (HIGH)
        admin_patterns = [
            r'is_superuser\s*=\s*True',
            r'is_staff\s*=\s*True',
            r'user\.admin\s*=\s*True',
            r'role\s*=\s*["\']admin["\']',
            r'permissions\s*=\s*\[\s*["\']\*["\']\s*\]',  # Wildcard permissions
        ]
        
        for pattern in admin_patterns:
            line_num = self._find_line(lines, pattern)
            if line_num:
                # Check if there's no expiration or time limit in surrounding code
                snippet_lines = code.split('\n')[max(0, line_num-5):min(len(lines), line_num+5)]
                snippet_text = '\n'.join(snippet_lines)
                if not re.search(r'expir|ttl|time_limit|duration|valid_until', snippet_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Permanent Privileged Access Without Time Limits",
                        description=(
                            f"Permanent admin/privileged access granted at line {line_num} without time limits. "
                            f"JIT authorization requires time-limited, on-demand privilege elevation with expiration."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Implement time-limited privilege elevation using Azure PIM, temporary role assignments, "
                            "or session-based permissions with expiration. Grant admin access only when needed and "
                            "automatically revoke after a defined period (e.g., 1-8 hours)."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Missing role/permission decorators (MEDIUM)
        # Check for route handlers without authorization
        route_patterns = [r'@app\.route', r'@api\.route', r'@router\.(get|post|put|delete)']
        for pattern in route_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check next 10 lines for authorization decorator
                check_lines = lines[max(0, line_num-3):min(len(lines), line_num+10)]
                check_text = '\n'.join(check_lines)
                if not re.search(r'@(login_required|permission_required|roles_required|requires_auth|authorize)', 
                                check_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Route Without Role-Based Authorization",
                        description=(
                            f"API route at line {line_num} missing role-based authorization decorator. "
                            f"All endpoints must implement role-based or attribute-based access control."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add role-based authorization decorators:\n"
                            "@login_required\n"
                            "@permission_required('resource.action')\n"
                            "or @roles_required('user', 'admin')\n"
                            "Implement least-privilege access with specific roles, not blanket permissions."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 3: Missing Azure PIM integration (INFO)
        if re.search(r'from azure\.', code) and re.search(r'RoleAssignment|role_assignment', code, re.IGNORECASE):
            if not re.search(r'EligibleRoleAssignment|PIM|PrivilegedIdentityManagement', code, re.IGNORECASE):
                line_num = self._find_line(lines, r'RoleAssignment')
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider Azure PIM for JIT Privilege Management",
                    description=(
                        f"Azure role assignments detected at line {line_num} but no Azure PIM integration found. "
                        f"Azure Privileged Identity Management provides JIT access with time-limited role activations."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Integrate Azure PIM for JIT access management:\n"
                        "- Use eligible role assignments instead of permanent assignments\n"
                        "- Require approval for role activation\n"
                        "- Set maximum activation duration (1-24 hours)\n"
                        "- Enable MFA for role activation"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Controllers/endpoints without [Authorize] attributes
        - Permanent admin role assignments
        - Missing role-based authorization policies
        - Azure PIM integration for JIT access
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Controller without [Authorize] attribute (HIGH)
        controller_matches = list(re.finditer(r'(public|internal)\s+class\s+\w+Controller\s*:', code))
        for match in controller_matches:
            line_num = code[:match.start()].count('\n') + 1
            # Check previous 5 lines for [Authorize] or [AllowAnonymous]
            check_lines = lines[max(0, line_num-6):line_num]
            check_text = '\n'.join(check_lines)
            if not re.search(r'\[Authorize|\[AllowAnonymous', check_text):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Controller Without Authorization Attribute",
                    description=(
                        f"Controller class at line {line_num} missing [Authorize] attribute. "
                        f"All controllers must implement role-based or policy-based authorization."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Add [Authorize] attribute with role or policy:\n"
                        "[Authorize(Roles = \"User,Admin\")]\n"
                        "[Authorize(Policy = \"RequireAdminRole\")]\n"
                        "Use least-privilege access with specific roles, not blanket authorization."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Permanent admin role assignment (HIGH)
        if re.search(r'AddToRoleAsync\([^,]+,\s*["\']Admin["\']\)', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'AddToRoleAsync.*Admin')
            # Check if there's no time limit or PIM integration
            snippet_lines = code.split('\n')[max(0, line_num-5):min(len(lines), line_num+5)]
            snippet_text = '\n'.join(snippet_lines)
            if not re.search(r'Expir|PIM|Eligible|TimeSpan|DateTime\.Add', snippet_text, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Permanent Admin Role Assignment Without JIT",
                    description=(
                        f"Permanent admin role assignment at line {line_num} without time limits or PIM integration. "
                        f"Admin privileges should be granted just-in-time with automatic expiration."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Implement time-limited role assignments using:\n"
                        "- Azure PIM for eligible role assignments with activation\n"
                        "- Custom temporary role assignment with expiration logic\n"
                        "- Session-based permissions that expire after defined period"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Missing authorization policy configuration (MEDIUM)
        if re.search(r'services\.AddAuthentication|AddJwtBearer', code):
            if not re.search(r'AddAuthorization\s*\(|AddPolicy', code):
                line_num = self._find_line(lines, r'AddAuthentication|AddJwtBearer')
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Role-Based Authorization Policies",
                    description=(
                        f"Authentication configured at line {line_num} but no authorization policies defined. "
                        f"Implement role-based and attribute-based authorization policies for least-privilege access."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Add authorization policies in ConfigureServices:\n"
                        "services.AddAuthorization(options => {\n"
                        "  options.AddPolicy(\"RequireAdminRole\", policy => policy.RequireRole(\"Admin\"));\n"
                        "  options.AddPolicy(\"RequireClaim\", policy => policy.RequireClaim(\"permission\", \"read\"));\n"
                        "});"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Endpoints without @Secured/@PreAuthorize annotations
        - Permanent admin privileges
        - Missing role-based access control
        - Time-limited authorization validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: REST endpoints without authorization (HIGH)
        endpoint_patterns = [r'@GetMapping', r'@PostMapping', r'@PutMapping', r'@DeleteMapping', r'@RequestMapping']
        for pattern in endpoint_patterns:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check for authorization annotations in previous 5 lines
                check_lines = lines[max(0, line_num-6):line_num]
                check_text = '\n'.join(check_lines)
                if not re.search(r'@(Secured|PreAuthorize|RolesAllowed|DenyAll)', check_text):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Endpoint Without Role-Based Authorization",
                        description=(
                            f"REST endpoint at line {line_num} missing authorization annotation. "
                            f"All endpoints must implement role-based or permission-based access control."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add authorization annotation:\n"
                            "@PreAuthorize(\"hasRole('USER')\")\n"
                            "@Secured({\"ROLE_USER\", \"ROLE_ADMIN\"})\n"
                            "or @RolesAllowed(\"ADMIN\")\n"
                            "Use least-privilege access with specific roles."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Permanent admin role assignment (HIGH)
        if re.search(r'grantedAuthorities\.add\([^)]*ROLE_ADMIN|hasRole\(["\']ADMIN["\'].*true', code, re.IGNORECASE):
            line_num = self._find_line(lines, r'ROLE_ADMIN')
            snippet_lines = code.split('\n')[max(0, line_num-5):min(len(lines), line_num+5)]
            snippet_text = '\n'.join(snippet_lines)
            if not re.search(r'Duration|Instant|LocalDateTime|expir|ttl', snippet_text, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Permanent Admin Privileges Without Time Limits",
                    description=(
                        f"Permanent admin role granted at line {line_num} without time limits or expiration. "
                        f"Privileged access should be granted just-in-time with automatic expiration."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Implement time-limited privilege elevation:\n"
                        "- Store role assignments with expiration timestamps\n"
                        "- Use session-based temporary permissions\n"
                        "- Integrate Azure PIM for eligible role assignments\n"
                        "- Automatically revoke privileges after defined period (1-8 hours)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Missing global method security (MEDIUM)
        if re.search(r'@SpringBootApplication|@Configuration', code):
            if not re.search(r'@EnableGlobalMethodSecurity|@EnableMethodSecurity', code):
                line_num = self._find_line(lines, r'@SpringBootApplication|@Configuration')
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Global Method Security Not Enabled",
                    description=(
                        f"Spring Boot application at line {line_num} without global method security enabled. "
                        f"Enable method-level security to enforce role-based authorization across all service methods."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Enable method security in configuration class:\n"
                        "@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)\n"
                        "or (Spring Security 6+):\n"
                        "@EnableMethodSecurity"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Routes without authorization middleware
        - Missing role-based access guards
        - Permanent tokens without expiration
        - Time-limited authorization checks
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Express routes without auth middleware (HIGH)
        route_patterns = [r'app\.(get|post|put|delete|patch)\s*\(', r'router\.(get|post|put|delete|patch)\s*\(']
        for pattern in route_patterns:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                # Get the route definition line
                route_line = lines[line_num - 1]
                # Check if auth middleware is present
                if not re.search(r'authenticate|authorize|requireAuth|checkRole|isAuthenticated|@UseGuards', route_line):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Route Without Authorization Middleware",
                        description=(
                            f"API route at line {line_num} missing authorization middleware or guard. "
                            f"All routes must implement role-based or permission-based access control."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add authorization middleware:\n"
                            "app.get('/api/resource', authenticate, checkRole('admin'), handler);\n"
                            "or (NestJS):\n"
                            "@UseGuards(AuthGuard, RolesGuard)\n"
                            "@Roles('admin', 'user')"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: JWT tokens without expiration (HIGH)
        if re.search(r'jwt\.sign\s*\(', code):
            sign_matches = list(re.finditer(r'jwt\.sign\s*\([^)]+\)', code, re.DOTALL))
            for match in sign_matches:
                token_config = match.group(0)
                if not re.search(r'expiresIn|exp:', token_config):
                    line_num = code[:match.start()].count('\n') + 1
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="JWT Token Without Expiration",
                        description=(
                            f"JWT token generation at line {line_num} without expiration time. "
                            f"JIT authorization requires time-limited tokens that expire after defined period."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add expiration to JWT tokens:\n"
                            "jwt.sign(payload, secret, { expiresIn: '1h' });  // 1 hour\n"
                            "For elevated privileges, use shorter expiration (15-60 minutes)."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 3: NestJS controllers without guards (MEDIUM)
        if re.search(r'@Controller\s*\(', code):
            controller_matches = list(re.finditer(r'@Controller\s*\([^)]*\)', code))
            for match in controller_matches:
                line_num = code[:match.start()].count('\n') + 1
                # Check next 5 lines for guards
                check_lines = lines[line_num:min(len(lines), line_num+5)]
                check_text = '\n'.join(check_lines)
                if not re.search(r'@UseGuards|@Roles|@SetMetadata', check_text):
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="NestJS Controller Without Guards",
                        description=(
                            f"NestJS controller at line {line_num} without authorization guards. "
                            f"Implement role-based guards to enforce access control."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation=(
                            "Add guards to controller or routes:\n"
                            "@UseGuards(AuthGuard('jwt'), RolesGuard)\n"
                            "@Roles('admin')\n"
                            "Use least-privilege access with specific roles."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-04 compliance.
        
        Detects:
        - Permanent role assignments vs PIM eligible
        - Overly permissive role assignments (Owner, Contributor)
        - Missing role assignment conditions
        - Azure PIM configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Permanent Owner/Contributor role assignments (HIGH)
        if re.search(r"roleDefinitionId.*\/(Owner|Contributor)'", code):
            line_num = self._find_line(lines, r"(Owner|Contributor)'")
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Permanent Owner/Contributor Role Assignment",
                description=(
                    f"Permanent Owner or Contributor role assignment at line {line_num}. "
                    f"Highly privileged roles should use Azure PIM eligible assignments with JIT activation, "
                    f"not permanent assignments."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use Azure PIM for privileged role assignments:\n"
                    "1. Create PIM eligible assignment via Azure Portal or ARM template\n"
                    "2. Configure activation requirements (MFA, approval, justification)\n"
                    "3. Set maximum activation duration (1-24 hours)\n"
                    "4. Use least-privilege roles like Reader, Contributor (specific resources) instead of Owner"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Role assignments without conditions (MEDIUM)
        role_assignments = list(re.finditer(r'resource\s+\w+\s+\'Microsoft\.Authorization/roleAssignments', code))
        for match in role_assignments:
            line_num = code[:match.start()].count('\n') + 1
            # Check if role assignment has condition property
            # Get next 200 chars of the resource block
            block = code[match.start():match.start() + 400]
            if 'condition:' not in block:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Role Assignment Without Conditions",
                    description=(
                        f"Role assignment at line {line_num} without conditional access policy. "
                        f"Attribute-based access control (ABAC) conditions can enforce least-privilege "
                        f"based on resource attributes, tags, or context."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Add ABAC conditions to role assignment:\n"
                        "condition: '@Resource[Microsoft.Storage/storageAccounts/blobServices/containers:name] "
                        "StringEquals \\'production\\''\n"
                        "conditionVersion: '2.0'"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Recommend PIM configuration (INFO)
        if re.search(r"'Microsoft\.Authorization/roleAssignments", code):
            if not re.search(r'PIM|Privileged|Eligible', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider Azure PIM for JIT Access Management",
                    description=(
                        "Role assignments detected but no Azure PIM configuration found. "
                        "Azure PIM provides JIT privilege activation, approval workflows, and time-limited access."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement Azure PIM for privileged roles:\n"
                        "- Convert permanent assignments to eligible assignments\n"
                        "- Require MFA and approval for activation\n"
                        "- Set maximum activation duration (1-8 hours)\n"
                        "- Enable access reviews for periodic validation\n"
                        "- Use notifications for activation events"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-04 compliance.
        
        Detects:
        - Permanent privileged role assignments
        - azurerm_role_assignment without PIM
        - Overly broad role scopes
        - Missing role assignment conditions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Owner/Contributor permanent assignments (HIGH)
        owner_contrib = list(re.finditer(r'resource\s+"azurerm_role_assignment"[^}]+role_definition_name\s*=\s*"(Owner|Contributor)"', code, re.DOTALL))
        for match in owner_contrib:
            line_num = code[:match.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Permanent Owner/Contributor Role Assignment",
                description=(
                    f"Permanent Owner/Contributor role assignment at line {line_num}. "
                    f"Highly privileged roles must use Azure PIM eligible assignments with JIT activation, "
                    f"not permanent Terraform-managed assignments."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "For privileged roles, use Azure PIM instead of Terraform role assignments:\n"
                    "1. Configure PIM via Azure Portal or azurerm_pim_eligible_role_assignment\n"
                    "2. Require MFA, approval, and justification for activation\n"
                    "3. Set maximum activation duration (1-24 hours)\n"
                    "4. Use least-privilege roles (Reader, specific resource Contributor) instead"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Role assignment at subscription scope (MEDIUM)
        sub_scope_assignments = list(re.finditer(r'resource\s+"azurerm_role_assignment"[^}]+scope\s*=\s*(data\.azurerm_subscription|azurerm_subscription)', code, re.DOTALL))
        for match in sub_scope_assignments:
            line_num = code[:match.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Role Assignment at Subscription Scope",
                description=(
                    f"Role assignment at subscription scope detected at line {line_num}. "
                    f"Least-privilege principle requires narrowing scope to specific resource groups or resources."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Narrow the scope to specific resources:\n"
                    "scope = azurerm_resource_group.example.id  # Resource group scope\n"
                    "scope = azurerm_storage_account.example.id  # Resource scope\n"
                    "Avoid subscription-wide permissions unless absolutely necessary."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Missing PIM configuration (INFO)
        if re.search(r'resource\s+"azurerm_role_assignment"', code):
            if not re.search(r'azurerm_pim|eligible_role_assignment', code, re.IGNORECASE):
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider Azure PIM for Privileged Role Management",
                    description=(
                        "Terraform role assignments detected without Azure PIM eligible assignments. "
                        "PIM provides JIT access with time-limited activation for privileged roles."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Implement Azure PIM for privileged access:\n"
                        "- Use azurerm_pim_eligible_role_assignment for eligible assignments\n"
                        "- Configure activation settings (duration, approval, MFA)\n"
                        "- Replace permanent high-privilege assignments with eligible ones\n"
                        "- Enable access reviews and notifications"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-04 compliance.
        
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
