"""
KSI-IAM-04: Just-in-Time Authorization

Use a least-privileged, role and attribute-based, and just-in-time security authorization model for all user and non-user accounts and services.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


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
    NIST_CONTROLS = [
        ("ac-2", "Account Management"),
        ("ac-2.1", "Automated System Account Management"),
        ("ac-2.2", "Automated Temporary and Emergency Account Management"),
        ("ac-2.3", "Disable Accounts"),
        ("ac-2.4", "Automated Audit Actions"),
        ("ac-2.6", "Dynamic Privilege Management"),
        ("ac-3", "Access Enforcement"),
        ("ac-4", "Information Flow Enforcement"),
        ("ac-5", "Separation of Duties"),
        ("ac-6", "Least Privilege"),
        ("ac-6.1", "Authorize Access to Security Functions"),
        ("ac-6.2", "Non-privileged Access for Nonsecurity Functions"),
        ("ac-6.5", "Privileged Accounts"),
        ("ac-6.7", "Review of User Privileges"),
        ("ac-6.9", "Log Use of Privileged Functions"),
        ("ac-6.10", "Prohibit Non-privileged Users from Executing Privileged Functions"),
        ("ac-7", "Unsuccessful Logon Attempts"),
        ("ac-20.1", "Limits on Authorized Use"),
        ("ac-17", "Remote Access"),
        ("au-9.4", "Access by Subset of Privileged Users"),
        ("cm-5", "Access Restrictions for Change"),
        ("cm-7", "Least Functionality"),
        ("cm-7.2", "Prevent Program Execution"),
        ("cm-7.5", "Authorized Software — Allow-by-exception"),
        ("cm-9", "Configuration Management Plan"),
        ("ia-4", "Identifier Management"),
        ("ia-4.4", "Identify User Status"),
        ("ia-7", "Cryptographic Module Authentication"),
        ("ps-2", "Position Risk Designation"),
        ("ps-3", "Personnel Screening"),
        ("ps-4", "Personnel Termination"),
        ("ps-5", "Personnel Transfer"),
        ("ps-6", "Access Agreements"),
        ("ps-9", "Position Descriptions"),
        ("ra-5.5", "Privileged Access"),
        ("sc-2", "Separation of System and User Functionality"),
        ("sc-23", "Session Authenticity"),
        ("sc-39", "Process Isolation")
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
        Analyze Python code for KSI-IAM-04 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Permanent admin/privileged access without time limits
        - Missing role-based authorization decorators on routes
        - Azure PIM integration for JIT access
        """
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Python code."""
        findings = []
        code_bytes = code.encode('utf-8')
        
        # Pattern 1: Permanent admin access without time limits (HIGH)
        # Find assignments like is_superuser = True, role = "admin"
        assignment_nodes = parser.find_nodes_by_type(tree.root_node, "assignment")
        
        for assign_node in assignment_nodes:
            assign_text = parser.get_node_text(assign_node, code_bytes)
            line_num = assign_node.start_point[0] + 1
            
            # Check for permanent admin/privileged assignments
            admin_patterns = ['is_superuser = True', 'is_staff = True', 'admin = True', 
                            'role = "admin"', "role = 'admin'", 'permissions = ["*"]']
            
            if any(pattern in assign_text for pattern in admin_patterns):
                # Check if there's an expiration in surrounding scope
                parent = assign_node.parent
                depth = 0
                has_expiration = False
                
                while parent and depth < 5:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    if any(keyword in parent_text.lower() for keyword in ['expir', 'ttl', 'time_limit', 'duration', 'valid_until']):
                        has_expiration = True
                        break
                    parent = parent.parent
                    depth += 1
                
                if not has_expiration:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Permanent Privileged Access Without Time Limits",
                        description=(
                            f"Permanent admin/privileged access granted at line {line_num} without time limits. "
                            f"JIT authorization requires time-limited, on-demand privilege elevation with expiration."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=assign_text[:200],
                        remediation=(
                            "Implement time-limited privilege elevation using Azure PIM, temporary role assignments, "
                            "or session-based permissions with expiration. Grant admin access only when needed and "
                            "automatically revoke after a defined period (e.g., 1-8 hours)."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Routes without authorization decorators (MEDIUM)
        # Find decorator nodes for @app.route, @api.route, @router.get/post/etc
        decorator_nodes = parser.find_nodes_by_type(tree.root_node, "decorator")
        
        for dec_node in decorator_nodes:
            dec_text = parser.get_node_text(dec_node, code_bytes)
            line_num = dec_node.start_point[0] + 1
            
            # Check if it's a route decorator
            if any(route in dec_text for route in ['@app.route', '@api.route', '@router.get', '@router.post', 
                                                    '@router.put', '@router.delete', '@router.patch']):
                # Get the function being decorated
                parent = dec_node.parent
                if parent and parent.type == 'decorated_definition':
                    # Check if there's an authorization decorator
                    all_decorators = parser.find_nodes_by_type(parent, "decorator")
                    auth_decorators = ['login_required', 'permission_required', 'roles_required', 
                                     'requires_auth', 'authorize', 'authenticated']
                    
                    has_auth = False
                    for auth_dec in all_decorators:
                        auth_text = parser.get_node_text(auth_dec, code_bytes)
                        if any(auth in auth_text for auth in auth_decorators):
                            has_auth = True
                            break
                    
                    if not has_auth:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Route Without Role-Based Authorization",
                            description=(
                                f"API route at line {line_num} missing role-based authorization decorator. "
                                f"All endpoints must implement role-based or attribute-based access control."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=dec_text[:200],
                            remediation=(
                                "Add role-based authorization decorators:\n"
                                "@login_required\n"
                                "@permission_required('resource.action')\n"
                                "or @roles_required('user', 'admin')\n"
                                "Implement least-privilege access with specific roles, not blanket permissions."
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        # Pattern 3: Azure PIM integration check (INFO)
        # Check for Azure imports and role assignments without PIM
        import_nodes = parser.find_nodes_by_type(tree.root_node, "import_from_statement")
        
        has_azure = False
        has_role_assignment = False
        has_pim = False
        
        for imp_node in import_nodes:
            imp_text = parser.get_node_text(imp_node, code_bytes)
            if 'from azure.' in imp_text:
                has_azure = True
            if 'PrivilegedIdentityManagement' in imp_text or 'PIM' in imp_text or 'EligibleRoleAssignment' in imp_text:
                has_pim = True
        
        # Check for RoleAssignment usage
        for node in parser.find_nodes_by_type(tree.root_node, "call"):
            call_text = parser.get_node_text(node, code_bytes)
            if 'RoleAssignment' in call_text or 'role_assignment' in call_text:
                has_role_assignment = True
                break
        
        if has_azure and has_role_assignment and not has_pim:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Consider Azure PIM for JIT Privilege Management",
                description=(
                    "Azure role assignments detected but no Azure PIM integration found. "
                    "Azure Privileged Identity Management provides JIT access with time-limited role activations."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
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
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based Python analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Permanent admin access (HIGH)
        admin_patterns = [
            r'is_superuser\s*=\s*True',
            r'is_staff\s*=\s*True',
            r'role\s*=\s*["\']admin["\']',
        ]
        
        for pattern in admin_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Permanent Privileged Access Without Time Limits",
                    description=f"Permanent admin access at line {line_num} without time limits.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Implement time-limited privilege elevation with expiration.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-04 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Controllers/endpoints without [Authorize] attributes
        - Permanent admin role assignments
        - Missing role-based authorization policies
        """
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for C# code."""
        findings = []
        code_bytes = code.encode('utf-8')
        
        # Pattern 1: Controller without [Authorize] attribute (HIGH)
        class_nodes = parser.find_nodes_by_type(tree.root_node, "class_declaration")
        
        for class_node in class_nodes:
            class_text = parser.get_node_text(class_node, code_bytes)
            line_num = class_node.start_point[0] + 1
            
            # Check if it's a Controller class
            if 'Controller' in class_text and ('public class' in class_text or 'internal class' in class_text):
                # Check for [Authorize] or [AllowAnonymous] attributes
                attribute_lists = parser.find_nodes_by_type(class_node, "attribute_list")
                has_auth = False
                
                for attr_list in attribute_lists:
                    attr_text = parser.get_node_text(attr_list, code_bytes)
                    if '[Authorize' in attr_text or '[AllowAnonymous' in attr_text:
                        has_auth = True
                        break
                
                if not has_auth:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Controller Without Authorization Attribute",
                        description=(
                            f"Controller class at line {line_num} missing [Authorize] attribute. "
                            f"All controllers must implement role-based or policy-based authorization."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=class_text[:200],
                        remediation=(
                            "Add [Authorize] attribute with role or policy:\n"
                            "[Authorize(Roles = \"User,Admin\")]\n"
                            "[Authorize(Policy = \"RequireAdminRole\")]\n"
                            "Use least-privilege access with specific roles, not blanket authorization."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Permanent admin role assignment (HIGH)
        invocation_nodes = parser.find_nodes_by_type(tree.root_node, "invocation_expression")
        
        for inv_node in invocation_nodes:
            inv_text = parser.get_node_text(inv_node, code_bytes)
            line_num = inv_node.start_point[0] + 1
            
            # Check for AddToRoleAsync with Admin role
            if 'AddToRoleAsync' in inv_text and ('Admin' in inv_text or 'admin' in inv_text):
                # Check surrounding context for time limits
                parent = inv_node.parent
                depth = 0
                has_time_limit = False
                
                while parent and depth < 5:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    if any(keyword in parent_text for keyword in ['Expir', 'PIM', 'Eligible', 'TimeSpan', 'DateTime.Add']):
                        has_time_limit = True
                        break
                    parent = parent.parent
                    depth += 1
                
                if not has_time_limit:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Permanent Admin Role Assignment Without JIT",
                        description=(
                            f"Permanent admin role assignment at line {line_num} without time limits or PIM integration. "
                            f"Admin privileges should be granted just-in-time with automatic expiration."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=inv_text[:200],
                        remediation=(
                            "Implement time-limited role assignments using:\n"
                            "- Azure PIM for eligible role assignments with activation\n"
                            "- Custom temporary role assignment with expiration logic\n"
                            "- Session-based permissions that expire after defined period"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 3: Missing authorization policy configuration (MEDIUM)
        has_auth_setup = False
        has_authz_setup = False
        auth_line = 0
        
        for inv_node in parser.find_nodes_by_type(tree.root_node, "invocation_expression"):
            inv_text = parser.get_node_text(inv_node, code_bytes)
            if 'AddAuthentication' in inv_text or 'AddJwtBearer' in inv_text:
                has_auth_setup = True
                auth_line = inv_node.start_point[0] + 1
            if 'AddAuthorization' in inv_text or 'AddPolicy' in inv_text:
                has_authz_setup = True
        
        if has_auth_setup and not has_authz_setup:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Role-Based Authorization Policies",
                description=(
                    f"Authentication configured at line {auth_line} but no authorization policies defined. "
                    f"Implement role-based and attribute-based authorization policies for least-privilege access."
                ),
                file_path=file_path,
                line_number=auth_line,
                snippet="",
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
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based C# analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Controller without [Authorize] (HIGH)
        controller_matches = list(re.finditer(r'(public|internal)\s+class\s+\w+Controller\s*:', code))
        for match in controller_matches:
            line_num = code[:match.start()].count('\n') + 1
            check_lines = lines[max(0, line_num-6):line_num]
            check_text = '\n'.join(check_lines)
            if not re.search(r'\[Authorize|\[AllowAnonymous', check_text):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Controller Without Authorization Attribute",
                    description=f"Controller at line {line_num} missing [Authorize] attribute.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Add [Authorize] attribute with role or policy.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-04 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Endpoints without @Secured/@PreAuthorize annotations
        - Permanent admin privileges
        - Missing role-based access control
        """
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Java code."""
        findings = []
        code_bytes = code.encode('utf-8')
        
        # Pattern 1: REST endpoints without authorization (HIGH)
        method_nodes = parser.find_nodes_by_type(tree.root_node, "method_declaration")
        
        for method_node in method_nodes:
            method_text = parser.get_node_text(method_node, code_bytes)
            line_num = method_node.start_point[0] + 1
            
            # Check if it has REST mapping annotation
            annotations = parser.find_nodes_by_type(method_node, "marker_annotation")
            annotations.extend(parser.find_nodes_by_type(method_node, "annotation"))
            
            has_rest_mapping = False
            has_security = False
            
            for ann in annotations:
                ann_text = parser.get_node_text(ann, code_bytes)
                if any(mapping in ann_text for mapping in ['@GetMapping', '@PostMapping', '@PutMapping', '@DeleteMapping', '@RequestMapping']):
                    has_rest_mapping = True
                if any(sec in ann_text for sec in ['@Secured', '@PreAuthorize', '@RolesAllowed', '@DenyAll']):
                    has_security = True
            
            if has_rest_mapping and not has_security:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Endpoint Without Role-Based Authorization",
                    description=(
                        f"REST endpoint at line {line_num} missing authorization annotation. "
                        f"All endpoints must implement role-based or permission-based access control."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=method_text[:200],
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
        # Check for admin role assignments in method invocations and assignments
        for node in parser.find_nodes_by_type(tree.root_node, "method_invocation"):
            node_text = parser.get_node_text(node, code_bytes)
            line_num = node.start_point[0] + 1
            
            # Check for admin role assignments: addRole("ADMIN"), setRole("ADMIN"), etc.
            is_admin_assignment = (
                'ROLE_ADMIN' in node_text or 
                ('hasRole' in node_text and 'ADMIN' in node_text) or
                (('addRole' in node_text or 'setRole' in node_text or 'assignRole' in node_text) and 
                 ('ADMIN' in node_text or 'admin' in node_text))
            )
            
            if is_admin_assignment:
                # Check surrounding context for time limits
                parent = node.parent
                depth = 0
                has_time_limit = False
                
                while parent and depth < 5:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    if any(keyword in parent_text for keyword in ['Duration', 'Instant', 'LocalDateTime', 'expir', 'ttl']):
                        has_time_limit = True
                        break
                    parent = parent.parent
                    depth += 1
                
                if not has_time_limit:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Permanent Admin Privileges Without Time Limits",
                        description=(
                            f"Permanent admin role granted at line {line_num} without time limits or expiration. "
                            f"Privileged access should be granted just-in-time with automatic expiration."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=node_text[:200],
                        remediation=(
                            "Implement time-limited privilege elevation:\n"
                            "- Store role assignments with expiration timestamps\n"
                            "- Use session-based temporary permissions\n"
                            "- Integrate Azure PIM for eligible role assignments\n"
                            "- Automatically revoke privileges after defined period (1-8 hours)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Only report once per file
        
        # Pattern 3: Missing global method security (MEDIUM)
        class_nodes = parser.find_nodes_by_type(tree.root_node, "class_declaration")
        
        has_spring_app = False
        has_method_security = False
        spring_line = 0
        
        for class_node in class_nodes:
            annotations = parser.find_nodes_by_type(class_node, "marker_annotation")
            annotations.extend(parser.find_nodes_by_type(class_node, "annotation"))
            
            for ann in annotations:
                ann_text = parser.get_node_text(ann, code_bytes)
                if '@SpringBootApplication' in ann_text or '@Configuration' in ann_text:
                    has_spring_app = True
                    spring_line = ann.start_point[0] + 1
                if '@EnableGlobalMethodSecurity' in ann_text or '@EnableMethodSecurity' in ann_text:
                    has_method_security = True
        
        if has_spring_app and not has_method_security:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Global Method Security Not Enabled",
                description=(
                    f"Spring Boot application at line {spring_line} without global method security enabled. "
                    f"Enable method-level security to enforce role-based authorization across all service methods."
                ),
                file_path=file_path,
                line_number=spring_line,
                snippet="",
                remediation=(
                    "Enable method security in configuration class:\n"
                    "@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)\n"
                    "or (Spring Security 6+):\n"
                    "@EnableMethodSecurity"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based Java analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: REST endpoints without authorization (HIGH)
        endpoint_patterns = [r'@GetMapping', r'@PostMapping', r'@PutMapping', r'@DeleteMapping', r'@RequestMapping']
        for pattern in endpoint_patterns:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                check_lines = lines[max(0, line_num-6):line_num]
                check_text = '\n'.join(check_lines)
                if not re.search(r'@(Secured|PreAuthorize|RolesAllowed|DenyAll)', check_text):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Endpoint Without Role-Based Authorization",
                        description=f"REST endpoint at line {line_num} missing authorization annotation.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add authorization annotation like @PreAuthorize or @Secured.",
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-04 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Routes without authorization middleware
        - Missing role-based access guards
        - Permanent tokens without expiration
        """
        parser = ASTParser(CodeLanguage.JAVASCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for TypeScript code."""
        findings = []
        code_bytes = code.encode('utf-8')
        
        # Pattern 1: Express routes without auth middleware (HIGH)
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call_expression")
        
        for call_node in call_nodes:
            call_text = parser.get_node_text(call_node, code_bytes)
            line_num = call_node.start_point[0] + 1
            
            # Check if it's a route definition (app.get, router.post, etc.)
            if any(route in call_text for route in ['app.get(', 'app.post(', 'app.put(', 'app.delete(',
                                                     'router.get(', 'router.post(', 'router.put(', 'router.delete(']):
                # Check if auth middleware is in the call arguments
                has_auth = any(auth in call_text for auth in ['authenticate', 'authorize', 'requireAuth', 
                                                              'checkRole', 'isAuthenticated', '@UseGuards'])
                
                if not has_auth:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Route Without Authorization Middleware",
                        description=(
                            f"API route at line {line_num} missing authorization middleware or guard. "
                            f"All routes must implement role-based or permission-based access control."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=call_text[:200],
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
        for call_node in parser.find_nodes_by_type(tree.root_node, "call_expression"):
            call_text = parser.get_node_text(call_node, code_bytes)
            line_num = call_node.start_point[0] + 1
            
            # Check for jwt.sign calls
            if 'jwt.sign' in call_text:
                # Check if expiresIn is present in the call
                has_expiration = 'expiresIn' in call_text or 'exp:' in call_text
                
                if not has_expiration:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="JWT Token Without Expiration",
                        description=(
                            f"JWT token generation at line {line_num} without expiration time. "
                            f"JIT authorization requires time-limited tokens that expire after defined period."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=call_text[:200],
                        remediation=(
                            "Add expiration to JWT tokens:\n"
                            "jwt.sign(payload, secret, { expiresIn: '1h' });  // 1 hour\n"
                            "For elevated privileges, use shorter expiration (15-60 minutes)."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 3: Permanent admin role assignment (HIGH)
        # Check for admin role assignments in assignment expressions
        assignment_nodes = parser.find_nodes_by_type(tree.root_node, "assignment_expression")
        assignment_nodes.extend(parser.find_nodes_by_type(tree.root_node, "pair"))
        
        for assign_node in assignment_nodes:
            assign_text = parser.get_node_text(assign_node, code_bytes)
            line_num = assign_node.start_point[0] + 1
            
            # Check for admin role assignments: user.role = 'admin', role: 'admin', etc.
            is_admin_assignment = (
                ('role' in assign_text.lower() and 'admin' in assign_text.lower()) or
                ('permission' in assign_text.lower() and 'admin' in assign_text.lower())
            )
            
            if is_admin_assignment and ('=' in assign_text or ':' in assign_text):
                # Check surrounding context for time limits or expiration
                parent = assign_node.parent
                depth = 0
                has_time_limit = False
                
                while parent and depth < 5:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    if any(keyword in parent_text.lower() for keyword in ['expir', 'ttl', 'duration', 'timeout', 'minutes', 'hours']):
                        has_time_limit = True
                        break
                    parent = parent.parent
                    depth += 1
                
                if not has_time_limit:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Permanent Admin Privileges Without Time Limits",
                        description=(
                            f"Permanent admin role granted at line {line_num} without time limits or expiration. "
                            f"Privileged access should be granted just-in-time with automatic expiration."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=assign_text[:200],
                        remediation=(
                            "Implement time-limited privilege elevation:\n"
                            "- Store role assignments with expiration timestamps\n"
                            "- Use session-based temporary permissions\n"
                            "- Set TTL on admin tokens (e.g., jwt.sign with expiresIn: '1h'))\n"
                            "- Automatically revoke privileges after defined period"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Only report once per file
        
        # Pattern 4: NestJS controllers without guards (MEDIUM)
        # Check for @Controller decorators without @UseGuards
        decorator_nodes = parser.find_nodes_by_type(tree.root_node, "decorator")
        
        for dec_node in decorator_nodes:
            dec_text = parser.get_node_text(dec_node, code_bytes)
            line_num = dec_node.start_point[0] + 1
            
            if '@Controller' in dec_text:
                # Get the class being decorated
                parent = dec_node.parent
                if parent and parent.type == 'class_declaration':
                    # Check for guard decorators
                    all_decorators = parser.find_nodes_by_type(parent, "decorator")
                    has_guards = False
                    
                    for guard_dec in all_decorators:
                        guard_text = parser.get_node_text(guard_dec, code_bytes)
                        if any(guard in guard_text for guard in ['@UseGuards', '@Roles', '@SetMetadata']):
                            has_guards = True
                            break
                    
                    if not has_guards:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="NestJS Controller Without Guards",
                            description=(
                                f"NestJS controller at line {line_num} without authorization guards. "
                                f"Implement role-based guards to enforce access control."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=dec_text[:200],
                            remediation=(
                                "Add guards to controller or routes:\n"
                                "@UseGuards(AuthGuard('jwt'), RolesGuard)\n"
                                "@Roles('admin')\n"
                                "Use least-privilege access with specific roles."
                            ),
                            ksi_id=self.KSI_ID
                        ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based TypeScript analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Express routes without auth middleware (HIGH)
        route_patterns = [r'app\.(get|post|put|delete|patch)\s*\(', r'router\.(get|post|put|delete|patch)\s*\(']
        for pattern in route_patterns:
            matches = list(re.finditer(pattern, code))
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                route_line = lines[line_num - 1]
                if not re.search(r'authenticate|authorize|requireAuth|checkRole|isAuthenticated', route_line):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Route Without Authorization Middleware",
                        description=f"API route at line {line_num} missing authorization middleware.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Add authorization middleware to route.",
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
            result = self._find_line(lines, r"(Owner|Contributor)'", use_regex=True)
            line_num = result['line_num'] if result else 0
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
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-IAM-04.
        
        **KSI-IAM-04: Just-in-Time Authorization**
        Use a least-privileged, role and attribute-based, and just-in-time security authorization model.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-IAM-04",
            "ksi_name": "Just-in-Time Authorization",
            "azure_services": [
                {
                    "service": "Azure AD Privileged Identity Management (PIM)",
                    "purpose": "Just-in-time privileged access with time-bound elevation",
                    "capabilities": [
                        "Time-bound role activations",
                        "Approval workflows for elevation",
                        "MFA on activation",
                        "Access reviews and audit logs"
                    ]
                },
                {
                    "service": "Azure RBAC",
                    "purpose": "Role-based access control with least-privilege assignments",
                    "capabilities": [
                        "Fine-grained role assignments",
                        "Custom roles for least privilege",
                        "Deny assignments",
                        "Conditional access integration"
                    ]
                },
                {
                    "service": "Azure AD Conditional Access",
                    "purpose": "Attribute-based access control with context-aware policies",
                    "capabilities": [
                        "Location-based access",
                        "Device compliance requirements",
                        "Risk-based adaptive access",
                        "Session controls"
                    ]
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "Audit JIT access activations and authorization decisions",
                    "capabilities": [
                        "PIM activation logs",
                        "RBAC assignment changes",
                        "Conditional Access decision logs",
                        "Failed authorization attempts"
                    ]
                },
                {
                    "service": "Microsoft Graph",
                    "purpose": "Programmatic access to PIM and RBAC configurations",
                    "capabilities": [
                        "Query eligible assignments",
                        "Access package management",
                        "Role assignment history",
                        "Approval request tracking"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "PIM Activation Monitoring",
                    "description": "Track all JIT role activations with justification and duration",
                    "automation": "Azure AD audit logs via KQL",
                    "frequency": "Continuous (with daily reports)",
                    "evidence_produced": "PIM activation log with approval evidence"
                },
                {
                    "method": "RBAC Assignment Audit",
                    "description": "Verify all permanent role assignments follow least-privilege principle",
                    "automation": "Resource Graph queries for role assignments",
                    "frequency": "Weekly",
                    "evidence_produced": "RBAC assignment report with least-privilege analysis"
                },
                {
                    "method": "Conditional Access Policy Compliance",
                    "description": "Document attribute-based access policies and enforcement",
                    "automation": "Microsoft Graph API for CA policies",
                    "frequency": "Monthly",
                    "evidence_produced": "CA policy configuration with coverage analysis"
                },
                {
                    "method": "Access Review Results",
                    "description": "Periodic access reviews demonstrating least-privilege maintenance",
                    "automation": "Azure AD Access Reviews API",
                    "frequency": "Quarterly",
                    "evidence_produced": "Access review decisions and certifications"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["log-based", "config-based"],
            "implementation_guidance": {
                "quick_start": "Enable PIM for privileged roles, configure RBAC with least privilege, deploy Conditional Access policies, enable audit logging, schedule access reviews",
                "azure_well_architected": "Follows Azure WAF security pillar for zero-trust and least-privilege access",
                "compliance_mapping": "Addresses extensive NIST AC family controls (ac-2, ac-3, ac-4, ac-5, ac-6, etc.)"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-IAM-04 evidence.
        """
        return {
            "ksi_id": "KSI-IAM-04",
            "queries": [
                {
                    "name": "PIM Role Activations",
                    "type": "kql",
                    "workspace": "Log Analytics with Azure AD logs",
                    "query": """
                        AuditLogs
                        | where TimeGenerated > ago(30d)
                        | where OperationName == 'Add member to role completed (PIM activation)'
                        | extend RoleName = tostring(TargetResources[0].displayName)
                        | extend UserPrincipal = tostring(InitiatedBy.user.userPrincipalName)
                        | extend Justification = tostring(AdditionalDetails[0].value)
                        | project TimeGenerated, UserPrincipal, RoleName, Justification, Duration
                        | order by TimeGenerated desc
                        """,
                    "purpose": "Show JIT role activations with justifications",
                    "expected_result": "All activations have justification and limited duration"
                },
                {
                    "name": "Least-Privilege RBAC Analysis",
                    "type": "azure_resource_graph",
                    "query": """
                        authorizationresources
                        | where type == 'microsoft.authorization/roleassignments'
                        | extend roleDefinitionId = tostring(properties.roleDefinitionId)
                        | extend principalType = tostring(properties.principalType)
                        | join kind=inner (authorizationresources
                            | where type == 'microsoft.authorization/roledefinitions'
                            | extend roleDefinitionId = id
                            | extend roleName = tostring(properties.roleName)
                        ) on roleDefinitionId
                        | summarize AssignmentCount = count() by roleName, principalType
                        | where roleName in ('Owner', 'Contributor', 'User Access Administrator')
                        | order by AssignmentCount desc
                        """,
                    "purpose": "Identify overly permissive role assignments",
                    "expected_result": "Minimal assignments to high-privilege roles"
                },
                {
                    "name": "Conditional Access Policy Coverage",
                    "type": "microsoft_graph",
                    "endpoint": "/identity/conditionalAccess/policies",
                    "method": "GET",
                    "purpose": "Show attribute-based access controls",
                    "expected_result": "Comprehensive CA policies covering location, device, risk"
                },
                {
                    "name": "PIM Eligible Assignments",
                    "type": "microsoft_graph",
                    "endpoint": "/privilegedAccess/azureResources/roleAssignmentRequests?$filter=assignmentState eq 'Eligible'",
                    "method": "GET",
                    "purpose": "List all JIT-eligible role assignments",
                    "expected_result": "Privileged roles configured as eligible vs. permanent"
                },
                {
                    "name": "Access Review Completion Status",
                    "type": "microsoft_graph",
                    "endpoint": "/identityGovernance/accessReviews/definitions",
                    "method": "GET",
                    "purpose": "Track access review cycles and decisions",
                    "expected_result": "Regular access reviews with documented decisions"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity",
                "permissions_required": [
                    "Log Analytics Reader for KQL queries",
                    "Reader for Resource Graph queries",
                    "PrivilegedAccess.Read.AzureResources for PIM queries",
                    "Policy.Read.ConditionalAccess for CA policies",
                    "AccessReview.Read.All for access reviews"
                ],
                "automation_tools": [
                    "Azure CLI (az role assignment list)",
                    "PowerShell Az.Resources module",
                    "Microsoft Graph PowerShell SDK"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-IAM-04.
        """
        return {
            "ksi_id": "KSI-IAM-04",
            "artifacts": [
                {
                    "name": "PIM Activation Log",
                    "description": "Complete log of JIT role activations with justifications and durations",
                    "source": "Azure AD Audit Logs",
                    "format": "CSV from KQL query",
                    "collection_frequency": "Weekly",
                    "retention_period": "7 years (access audit)",
                    "automation": "Scheduled KQL query"
                },
                {
                    "name": "Least-Privilege RBAC Report",
                    "description": "Analysis of role assignments showing least-privilege adherence",
                    "source": "Azure Resource Graph",
                    "format": "CSV with analysis notes",
                    "collection_frequency": "Monthly",
                    "retention_period": "3 years",
                    "automation": "Resource Graph query with analysis template"
                },
                {
                    "name": "Conditional Access Policy Configuration",
                    "description": "Complete export of attribute-based access policies",
                    "source": "Microsoft Graph API",
                    "format": "JSON configuration export",
                    "collection_frequency": "Monthly",
                    "retention_period": "3 years",
                    "automation": "Graph API query"
                },
                {
                    "name": "PIM Configuration Evidence",
                    "description": "PIM role settings showing approval, MFA, and duration requirements",
                    "source": "Microsoft Graph API",
                    "format": "JSON export",
                    "collection_frequency": "Quarterly",
                    "retention_period": "3 years",
                    "automation": "PowerShell script with Graph SDK"
                },
                {
                    "name": "Access Review Certification Results",
                    "description": "Quarterly access review results showing least-privilege maintenance",
                    "source": "Azure AD Access Reviews",
                    "format": "PDF certification report",
                    "collection_frequency": "Quarterly",
                    "retention_period": "7 years",
                    "automation": "Access Reviews API with automated reporting"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["ac-2", "ac-3", "ac-4", "ac-5", "ac-6", "ac-6.1", "ac-6.2", "ac-6.5", "ac-6.7", "ac-6.9"],
                "evidence_purpose": "Demonstrate JIT, least-privilege, role-based, and attribute-based access control"
            }
        }
