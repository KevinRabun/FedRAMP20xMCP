"""
KSI-IAM-05: Least Privilege

Configure identity and access management with measures that always verify each user or device can only access the resources they need.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_IAM_05_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-05: Least Privilege
    
    **Official Statement:**
    Configure identity and access management with measures that always verify each user or device can only access the resources they need.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.5
    - ac-2.6
    - ac-3
    - ac-4
    - ac-6
    - ac-12
    - ac-14
    - ac-17
    - ac-17.1
    - ac-17.2
    - ac-17.3
    - ac-20
    - ac-20.1
    - cm-2.7
    - cm-9
    - ia-2
    - ia-3
    - ia-4
    - ia-4.4
    - ia-5.2
    - ia-5.6
    - ia-11
    - ps-2
    - ps-3
    - ps-4
    - ps-5
    - ps-6
    - sc-4
    - sc-20
    - sc-21
    - sc-22
    - sc-23
    - sc-39
    - si-3
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Configure identity and access management with measures that always verify each user or device can on...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-IAM-05"
    KSI_NAME = "Least Privilege"
    KSI_STATEMENT = """Configure identity and access management with measures that always verify each user or device can only access the resources they need."""
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2.5", "Inactivity Logout"),
        ("ac-2.6", "Dynamic Privilege Management"),
        ("ac-3", "Access Enforcement"),
        ("ac-4", "Information Flow Enforcement"),
        ("ac-6", "Least Privilege"),
        ("ac-12", "Session Termination"),
        ("ac-14", "Permitted Actions Without Identification or Authentication"),
        ("ac-17", "Remote Access"),
        ("ac-17.1", "Monitoring and Control"),
        ("ac-17.2", "Protection of Confidentiality and Integrity Using Encryption"),
        ("ac-17.3", "Managed Access Control Points"),
        ("ac-20", "Use of External Systems"),
        ("ac-20.1", "Limits on Authorized Use"),
        ("cm-2.7", "Configure Systems and Components for High-risk Areas"),
        ("cm-9", "Configuration Management Plan"),
        ("ia-2", "Identification and Authentication (Organizational Users)"),
        ("ia-3", "Device Identification and Authentication"),
        ("ia-4", "Identifier Management"),
        ("ia-4.4", "Identify User Status"),
        ("ia-5.2", "Public Key-based Authentication"),
        ("ia-5.6", "Protection of Authenticators"),
        ("ia-11", "Re-authentication"),
        ("ps-2", "Position Risk Designation"),
        ("ps-3", "Personnel Screening"),
        ("ps-4", "Personnel Termination"),
        ("ps-5", "Personnel Transfer"),
        ("ps-6", "Access Agreements"),
        ("sc-4", "Information in Shared System Resources"),
        ("sc-20", "Secure Name/Address Resolution Service (Authoritative Source)"),
        ("sc-21", "Secure Name/Address Resolution Service (Recursive or Caching Resolver)"),
        ("sc-22", "Architecture and Provisioning for Name/Address Resolution Service"),
        ("sc-23", "Session Authenticity"),
        ("sc-39", "Process Isolation"),
        ("si-3", "Malicious Code Protection")
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
        Analyze Python code for KSI-IAM-05 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Wildcard/overly broad permissions in assignments
        - Missing resource-level access checks in ORM queries
        - Overly permissive CORS configuration
        - Public access flags set to True
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
        
        # Pattern 1: Wildcard permissions in assignments (CRITICAL)
        # Find assignment nodes: permissions = ["*"], scope = "*", allow_all = True
        assignment_nodes = parser.find_nodes_by_type(tree.root_node, "assignment")
        
        for assign_node in assignment_nodes:
            assign_text = parser.get_node_text(assign_node, code_bytes)
            line_num = assign_node.start_point[0] + 1
            
            # Check for wildcard patterns in assignments
            if any(pattern in assign_text for pattern in [
                'permissions = ["*"]', 'permissions = [\'*\']',
                'scope = "*"', 'scope = \'*\'',
                'actions = ["*"]', 'actions = [\'*\']',
                'allow_all = True', 'public_access = True'
            ]):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Wildcard Permissions Grant Excessive Access",
                    description=(
                        f"Wildcard permission detected at line {line_num} violates least privilege. "
                        f"Users/services should only have access to specific resources they need, "
                        f"not unrestricted access to all resources."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=assign_text[:200],
                    remediation=(
                        "Replace wildcard permissions with specific, granular permissions:\n"
                        "permissions = ['read:resource', 'write:specific_resource']\n"
                        "Define explicit scopes for each operation and resource type. "
                        "Use role-based access with minimum required permissions."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Missing resource-level authorization in ORM queries (HIGH)
        # Find attribute access nodes for .filter(), .get(), .all()
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call")
        
        for call_node in call_nodes:
            call_text = parser.get_node_text(call_node, code_bytes)
            line_num = call_node.start_point[0] + 1
            
            # Check for ORM query methods without authorization
            if any(method in call_text for method in ['.filter(', '.get(', '.all()']):
                # Get surrounding context (function scope)
                parent = call_node.parent
                depth = 0
                while parent and depth < 5:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    # Check if authorization keywords present in scope
                    if any(keyword in parent_text for keyword in [
                        'user', 'owner', 'created_by', 'check_permission',
                        'has_access', 'authorize', 'check_access'
                    ]):
                        break
                    parent = parent.parent
                    depth += 1
                else:
                    # No authorization found in scope
                    if '.filter(' in call_text:
                        # Check if filter already contains user/owner filtering
                        if not any(arg in call_text for arg in ['user=', 'owner=', 'created_by=']):
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                title="Data Access Without Resource-Level Authorization",
                                description=(
                                    f"Data query at line {line_num} without resource-level authorization check. "
                                    f"Least privilege requires verifying user access to specific resources, "
                                    f"not just authentication."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                snippet=call_text[:200],
                                remediation=(
                                    "Add resource-level authorization:\n"
                                    "queryset.filter(owner=request.user)  # Ownership check\n"
                                    "if not user.has_permission('read', resource): raise PermissionDenied\n"
                                    "Verify user access to each resource before returning data."
                                ),
                                ksi_id=self.KSI_ID
                            ))
                            break  # Report once
        
        # Pattern 3: Overly permissive CORS (MEDIUM)
        # Find CORS() calls with origins="*"
        for call_node in parser.find_nodes_by_type(tree.root_node, "call"):
            call_text = parser.get_node_text(call_node, code_bytes)
            line_num = call_node.start_point[0] + 1
            
            if 'CORS(' in call_text and ('origins="*"' in call_text or "origins='*'" in call_text):
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Overly Permissive CORS Configuration",
                    description=(
                        f"CORS configured to allow all origins at line {line_num}. "
                        f"Least privilege requires restricting API access to specific trusted domains."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=call_text[:200],
                    remediation=(
                        "Restrict CORS to specific origins:\n"
                        "CORS(app, origins=['https://trusted-domain.com', 'https://app.example.com'])\n"
                        "Never use wildcard (*) in production environments."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based Python analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Wildcard permissions (CRITICAL)
        wildcard_patterns = [
            r'permissions\s*=\s*\[\s*["\']\*["\']\s*\]',
            r'scope\s*=\s*["\']\*["\']',
            r'actions\s*=\s*\[\s*["\']\*["\']\s*\]',
            r'allow_all\s*=\s*True',
            r'public_access\s*=\s*True',
        ]
        
        for pattern in wildcard_patterns:
            result = self._find_line(lines, pattern)

            line_num = result['line_num'] if result else 0
            if line_num:
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Wildcard Permissions Grant Excessive Access",
                    description=f"Wildcard permission detected at line {line_num} violates least privilege.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Replace wildcard permissions with specific, granular permissions.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-05 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - [AllowAnonymous] on sensitive endpoints
        - Missing resource-based authorization in controllers
        - Overly permissive authorization policies
        - Wildcard claims/permissions
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
        
        # Pattern 1: [AllowAnonymous] on sensitive endpoints (HIGH)
        # Find attribute nodes
        attribute_nodes = parser.find_nodes_by_type(tree.root_node, "attribute")
        
        for attr_node in attribute_nodes:
            attr_text = parser.get_node_text(attr_node, code_bytes)
            
            if 'AllowAnonymous' in attr_text:
                line_num = attr_node.start_point[0] + 1
                
                # Get parent method to check if it's sensitive
                parent = attr_node.parent
                depth = 0
                while parent and depth < 10:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    
                    # Check if it's a sensitive operation
                    sensitive_operations = ['Delete', 'Update', 'Create', 'Admin', 'Manage', 'Configure']
                    public_operations = ['Login', 'Register', 'SignIn', 'SignUp', 'Public']
                    
                    has_sensitive = any(op in parent_text for op in sensitive_operations)
                    has_public = any(op in parent_text for op in public_operations)
                    
                    if has_sensitive and not has_public:
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Sensitive Endpoint Allows Anonymous Access",
                            description=(
                                f"[AllowAnonymous] attribute on sensitive operation at line {line_num}. "
                                f"Least privilege requires authentication and authorization for non-public operations."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=attr_text[:200],
                            remediation=(
                                "Remove [AllowAnonymous] and add appropriate authorization:\n"
                                "[Authorize(Roles = \"User\")]\n"
                                "[Authorize(Policy = \"RequireSpecificPermission\")]\n"
                                "Only use [AllowAnonymous] for truly public endpoints like login/register."
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break
                    
                    parent = parent.parent
                    depth += 1
        
        # Pattern 2: Missing resource authorization in controller actions (HIGH)
        # Find method declarations with 'int id' parameter
        method_nodes = parser.find_nodes_by_type(tree.root_node, "method_declaration")
        
        for method_node in method_nodes:
            method_text = parser.get_node_text(method_node, code_bytes)
            line_num = method_node.start_point[0] + 1
            
            # Check if method has 'int id' parameter
            if 'int id' in method_text or 'int? id' in method_text:
                # Check if method body contains authorization checks
                auth_keywords = ['AuthorizeAsync', 'HasPermission', 'CheckAccess', 'UserId', 'OwnerId']
                
                if not any(keyword in method_text for keyword in auth_keywords):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Controller Action Without Resource Authorization",
                        description=(
                            f"Action method at line {line_num} accepts resource ID but missing ownership/permission check. "
                            f"Least privilege requires verifying user access to specific resources."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=method_text[:300],
                        remediation=(
                            "Add resource-level authorization:\n"
                            "var resource = await _context.Resources.FindAsync(id);\n"
                            "if (resource.OwnerId != User.GetUserId()) return Forbid();\n"
                            "or use IAuthorizationService.AuthorizeAsync() for policy-based checks."
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Report once
        
        # Pattern 3: Overly permissive authorization policy (MEDIUM)
        # Find RequireAssertion with 'true' literal
        invocation_nodes = parser.find_nodes_by_type(tree.root_node, "invocation_expression")
        
        for inv_node in invocation_nodes:
            inv_text = parser.get_node_text(inv_node, code_bytes)
            line_num = inv_node.start_point[0] + 1
            
            if 'RequireAssertion' in inv_text and ' true' in inv_text:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Authorization Policy Always Succeeds",
                    description=(
                        f"Authorization policy at line {line_num} configured to always return true. "
                        f"This grants unrestricted access, violating least privilege principle."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=inv_text[:200],
                    remediation=(
                        "Implement proper authorization logic with specific requirements:\n"
                        "RequireAssertion(context => context.User.HasClaim(\"permission\", \"read\"))\n"
                        "RequireClaim(\"role\", \"Admin\", \"Manager\")\n"
                        "RequireRole(\"SpecificRole\")"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based C# analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: AllowAnonymous on non-public endpoints (HIGH)
        allow_anon_matches = list(re.finditer(r'\[AllowAnonymous\]', code))
        for match in allow_anon_matches:
            line_num = code[:match.start()].count('\n') + 1
            context_lines = lines[line_num:min(len(lines), line_num+10)]
            context_text = '\n'.join(context_lines)
            if re.search(r'(Delete|Update|Create|Admin|Manage|Configure)', context_text, re.IGNORECASE):
                if not re.search(r'(Login|Register|SignIn|SignUp|Public)', context_text, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Sensitive Endpoint Allows Anonymous Access",
                        description=f"[AllowAnonymous] on sensitive operation at line {line_num}.",
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num),
                        remediation="Remove [AllowAnonymous] and add proper authorization.",
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-05 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - permitAll() on sensitive endpoints
        - Missing method-level authorization annotations
        - Overly broad authority assignments (wildcards)
        - Missing resource ownership checks in REST endpoints
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
        
        # Pattern 1: permitAll() usage (CRITICAL)
        # Find method invocations
        method_invocation_nodes = parser.find_nodes_by_type(tree.root_node, "method_invocation")
        
        for inv_node in method_invocation_nodes:
            inv_text = parser.get_node_text(inv_node, code_bytes)
            line_num = inv_node.start_point[0] + 1
            
            if 'permitAll()' in inv_text:
                # Check if it's for a public endpoint (get surrounding context)
                parent = inv_node.parent
                depth = 0
                is_public_endpoint = False
                
                while parent and depth < 5:
                    parent_text = parser.get_node_text(parent, code_bytes)
                    if any(path in parent_text for path in ['/public/', '/login', '/register', '/health', '/static/']):
                        is_public_endpoint = True
                        break
                    parent = parent.parent
                    depth += 1
                
                if not is_public_endpoint:
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Overly Permissive Access Control with permitAll()",
                        description=(
                            f"permitAll() used at line {line_num} granting unrestricted access. "
                            f"Least privilege requires authentication and authorization for non-public resources."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=inv_text[:200],
                        remediation=(
                            "Replace permitAll() with specific authorization:\n"
                            ".hasRole(\"USER\")\n"
                            ".hasAuthority(\"READ_RESOURCE\")\n"
                            ".authenticated()\n"
                            "Only use permitAll() for truly public endpoints (login, public content)."
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: hasAnyAuthority with wildcard (HIGH)
        for inv_node in method_invocation_nodes:
            inv_text = parser.get_node_text(inv_node, code_bytes)
            line_num = inv_node.start_point[0] + 1
            
            if 'hasAnyAuthority' in inv_text and '"*"' in inv_text:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Wildcard Authority Grants Excessive Permissions",
                    description=(
                        f"Wildcard authority at line {line_num} grants access to users with any permission. "
                        f"Least privilege requires specific, granular authorities."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=inv_text[:200],
                    remediation=(
                        "Specify explicit authorities:\n"
                        "hasAnyAuthority(\"READ_RESOURCE\", \"WRITE_RESOURCE\")\n"
                        "hasRole(\"USER\")\n"
                        "Never use wildcard permissions in access control."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: REST endpoints with @PathVariable id but no ownership check (HIGH)
        # Find method declarations with annotations
        method_nodes = parser.find_nodes_by_type(tree.root_node, "method_declaration")
        
        for method_node in method_nodes:
            method_text = parser.get_node_text(method_node, code_bytes)
            line_num = method_node.start_point[0] + 1
            
            # Check if method has REST mapping annotation and @PathVariable with id
            has_mapping = any(anno in method_text for anno in ['@GetMapping', '@PutMapping', '@DeleteMapping', '@PatchMapping'])
            has_pathvar_id = '@PathVariable' in method_text and ('Long id' in method_text or 'Integer id' in method_text)
            
            if has_mapping and has_pathvar_id:
                # Check if method body contains ownership validation
                auth_keywords = ['getUserId', 'getOwnerId', 'checkOwnership', 'principal.getName']
                
                if not any(keyword in method_text for keyword in auth_keywords):
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Endpoint Missing Resource Ownership Check",
                        description=(
                            f"REST endpoint at line {line_num} accepts resource ID without ownership validation. "
                            f"Least privilege requires verifying user access to specific resources."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=method_text[:300],
                        remediation=(
                            "Add resource ownership validation:\n"
                            "Resource resource = repository.findById(id)\n"
                            "  .orElseThrow(() -> new NotFoundException());\n"
                            "if (!resource.getOwnerId().equals(principal.getName())) {\n"
                            "  throw new AccessDeniedException(\"Not authorized\");\n"
                            "}"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                    break  # Report once
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based Java analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: permitAll() usage (CRITICAL)
        permit_all_matches = list(re.finditer(r'\.permitAll\s*\(\s*\)', code))
        for match in permit_all_matches:
            line_num = code[:match.start()].count('\n') + 1
            context_lines = lines[max(0, line_num-2):line_num]
            context_text = '\n'.join(context_lines)
            if not re.search(r'("/public/|"/login|"/register|"/health|"/static/)', context_text):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Overly Permissive Access Control with permitAll()",
                    description=f"permitAll() at line {line_num} granting unrestricted access.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation="Replace permitAll() with specific authorization.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-05 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Overly permissive CORS (wildcard origins)
        - Routes with ID parameters but no ownership checks
        - Wildcard permissions in middleware
        - Public access to sensitive operations
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
        
        # Pattern 1: Wildcard CORS origin (CRITICAL)
        # Check variable declarators for corsOptions/origin: "*"
        assignment_nodes = parser.find_nodes_by_type(tree.root_node, "variable_declarator")
        
        for assign_node in assignment_nodes:
            assign_text = parser.get_node_text(assign_node, code_bytes)
            line_num = assign_node.start_point[0] + 1
            
            # Check for CORS config with wildcard origin
            if 'origin' in assign_text and (': "*"' in assign_text or ": '*'" in assign_text):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="CORS Configured to Allow All Origins",
                    description=(
                        f"CORS origin set to wildcard (*) at line {line_num}. "
                        f"Least privilege requires restricting API access to specific trusted origins."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=assign_text[:200],
                    remediation=(
                        "Restrict CORS to specific origins:\n"
                        "cors({ origin: ['https://trusted-app.com', 'https://admin.example.com'] })\n"
                        "or use dynamic origin validation function. Never use '*' in production."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Also check inline cors() calls
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call_expression")
        for call_node in call_nodes:
            call_text = parser.get_node_text(call_node, code_bytes)
            line_num = call_node.start_point[0] + 1
            
            if 'cors(' in call_text and ('origin: "*"' in call_text or "origin: '*'" in call_text):
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="CORS Configured to Allow All Origins",
                    description=(
                        f"CORS origin set to wildcard (*) at line {line_num}. "
                        f"Least privilege requires restricting API access to specific trusted origins."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=call_text[:200],
                    remediation=(
                        "Restrict CORS to specific origins:\n"
                        "cors({ origin: ['https://trusted-app.com', 'https://admin.example.com'] })\n"
                        "or use dynamic origin validation function. Never use '*' in production."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Routes with /:id parameter but no ownership check (HIGH)
        # Find route definitions (.get, .put, .delete with /:id)
        for call_node in call_nodes:
            call_text = parser.get_node_text(call_node, code_bytes)
            line_num = call_node.start_point[0] + 1
            
            # Check for route methods with /:id parameter
            route_methods = ['.get(', '.put(', '.patch(', '.delete(']
            has_route_method = any(method in call_text for method in route_methods)
            has_id_param = '/:id' in call_text
            
            if has_route_method and has_id_param:
                # Get the callback function to check for ownership validation
                # Look for arrow function or function expression
                function_nodes = []
                for child in call_node.children:
                    if child.type in ['arrow_function', 'function', 'function_expression']:
                        function_nodes.append(child)
                
                for func_node in function_nodes:
                    func_text = parser.get_node_text(func_node, code_bytes)
                    
                    # Check for ownership/permission checks
                    auth_keywords = ['req.user', 'userId', 'ownerId', 'checkOwnership', 'authorize', 'hasPermission']
                    
                    if not any(keyword in func_text for keyword in auth_keywords):
                        findings.append(Finding(
                            severity=Severity.HIGH,
                            title="Route With ID Parameter Missing Ownership Check",
                            description=(
                                f"Route at line {line_num} accepts resource ID without verifying user ownership. "
                                f"Least privilege requires checking user access to specific resources."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=call_text[:300],
                            remediation=(
                                "Add resource ownership validation:\n"
                                "const resource = await Resource.findById(req.params.id);\n"
                                "if (resource.ownerId !== req.user.id) {\n"
                                "  return res.status(403).json({ error: 'Forbidden' });\n"
                                "}"
                            ),
                            ksi_id=self.KSI_ID
                        ))
                        break  # Report once
        
        # Pattern 3: Permission assignment with wildcard (HIGH)
        # Check variable declarators for permissions = ["*"] or similar
        for assign_node in assignment_nodes:
            assign_text = parser.get_node_text(assign_node, code_bytes)
            line_num = assign_node.start_point[0] + 1
            
            if 'permission' in assign_text.lower() and ('"*"' in assign_text or "'*'" in assign_text):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Wildcard Permission Grants Unrestricted Access",
                    description=(
                        f"Wildcard permission at line {line_num} grants unrestricted access. "
                        f"Least privilege requires explicit, granular permissions for each operation."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=assign_text[:200],
                    remediation=(
                        "Define specific permissions:\n"
                        "permissions: ['read:resource', 'write:resource']\n"
                        "@Permissions('manage:users')\n"
                        "Use role-based or permission-based access control with explicit grants."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based TypeScript/JavaScript analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Wildcard CORS origin (CRITICAL)
        if re.search(r'cors\s*\(\s*\{[^}]*origin\s*:\s*["\']\*["\']', code, re.IGNORECASE):
            result = self._find_line(lines, r'origin\s*:\s*["\']\*')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="CORS Configured to Allow All Origins",
                description=f"CORS origin set to wildcard (*) at line {line_num}.",
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation="Restrict CORS to specific origins.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-05 compliance.
        
        Detects:
        - Overly broad role assignments (Owner, Contributor at subscription)
        - Wildcard permissions in custom roles
        - Missing scope restrictions
        - Role assignments without conditions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Owner/Contributor at subscription/management group scope (CRITICAL)
        broad_role_patterns = [
            r"roleDefinitionId:.*subscription\(\)\.id.*['\"]/(Owner|Contributor)['\"]",
            r"roleDefinitionId:.*managementGroup.*['\"]/(Owner|Contributor)['\"]",
        ]
        
        for pattern in broad_role_patterns:
            if re.search(pattern, code):
                result = self._find_line(lines, pattern)

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title="Overly Broad Role Assignment at Subscription/MG Scope",
                    description=(
                        f"Owner or Contributor role assigned at subscription/management group scope at line {line_num}. "
                        f"Least privilege requires limiting role scope to specific resource groups or resources."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Narrow the role assignment scope:\n"
                        "scope: resourceGroup().id  // Resource group scope\n"
                        "scope: storageAccount.id   // Specific resource\n"
                        "Use more restrictive roles like Reader, specific Contributor roles "
                        "(Storage Blob Data Contributor) instead of Owner/Contributor."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Custom role with wildcard actions (CRITICAL)
        if re.search(r'actions\s*:\s*\[\s*["\']\*["\']\s*\]', code):
            result = self._find_line(lines, r'actions\s*:\s*\[.*\*')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Custom Role With Wildcard Actions",
                description=(
                    f"Custom role definition at line {line_num} uses wildcard (*) for actions. "
                    f"Least privilege requires explicit, minimal permissions for each operation."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Define specific actions:\n"
                    "actions: [\n"
                    "  'Microsoft.Storage/storageAccounts/read'\n"
                    "  'Microsoft.Storage/storageAccounts/blobServices/containers/read'\n"
                    "]\n"
                    "Never use wildcard (*) in custom role definitions."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Role assignment without ABAC conditions (INFO)
        role_assignments = list(re.finditer(r"resource\s+\w+\s+'Microsoft\.Authorization/roleAssignments", code))
        if role_assignments:
            has_condition = bool(re.search(r'condition\s*:', code))
            if not has_condition:
                findings.append(Finding(
                    severity=Severity.INFO,
                    title="Consider ABAC Conditions for Role Assignments",
                    description=(
                        "Role assignments without attribute-based access control (ABAC) conditions. "
                        "ABAC conditions can further restrict access based on resource tags, "
                        "names, or other attributes for enhanced least privilege."
                    ),
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation=(
                        "Add ABAC conditions to role assignments:\n"
                        "condition: '@Resource[Microsoft.Storage/storageAccounts:name] StringLike \\'prod*\\''\n"
                        "conditionVersion: '2.0'\n"
                        "Restrict access based on resource attributes, tags, or naming patterns."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-05 compliance.
        
        Detects:
        - Subscription-scoped role assignments
        - Owner/Contributor role overuse
        - Custom roles with wildcard permissions
        - Missing role assignment conditions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Owner/Contributor at subscription scope (CRITICAL)
        sub_owner_matches = list(re.finditer(
            r'resource\s+"azurerm_role_assignment"[^}]*role_definition_name\s*=\s*"(Owner|Contributor)"[^}]*scope\s*=\s*data\.azurerm_subscription',
            code, re.DOTALL
        ))
        
        for match in sub_owner_matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Owner/Contributor Assigned at Subscription Scope",
                description=(
                    f"Owner or Contributor role at subscription scope at line {line_num}. "
                    f"Least privilege requires narrowing scope to resource groups or specific resources."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Narrow the scope:\n"
                    "scope = azurerm_resource_group.example.id\n"
                    "scope = azurerm_storage_account.example.id\n"
                    "Use more restrictive built-in roles like Reader, specific Contributor "
                    "roles (e.g., \"Storage Blob Data Contributor\")."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Custom role with wildcard actions (CRITICAL)
        if re.search(r'resource\s+"azurerm_role_definition"[^}]*actions\s*=\s*\[\s*"\*"', code, re.DOTALL):
            result = self._find_line(lines, r'actions\s*=\s*\[\s*"\*"')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Custom Role Definition With Wildcard Actions",
                description=(
                    f"Custom role at line {line_num} grants wildcard (*) actions. "
                    f"Least privilege requires specific, minimal permissions."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Specify explicit actions:\n"
                    "actions = [\n"
                    '  "Microsoft.Storage/storageAccounts/read",\n'
                    '  "Microsoft.Storage/storageAccounts/listKeys/action"\n'
                    "]\n"
                    "Never use wildcard in production role definitions."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Multiple broad role assignments (MEDIUM)
        owner_contrib_count = len(re.findall(
            r'role_definition_name\s*=\s*"(Owner|Contributor)"',
            code
        ))
        
        if owner_contrib_count >= 3:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Excessive Use of Owner/Contributor Roles",
                description=(
                    f"Found {owner_contrib_count} Owner/Contributor role assignments. "
                    f"Least privilege recommends using more restrictive built-in roles or custom roles "
                    f"with minimal required permissions."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Replace with least-privilege roles:\n"
                    "- Reader (read-only access)\n"
                    "- Storage Blob Data Contributor (blob-specific)\n"
                    "- Key Vault Secrets User (secret read-only)\n"
                    "- Virtual Machine Contributor (VM-specific)\n"
                    "Review Azure built-in roles: https://learn.microsoft.com/azure/role-based-access-control/built-in-roles"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    

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
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

