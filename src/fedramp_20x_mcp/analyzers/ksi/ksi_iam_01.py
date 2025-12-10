"""
KSI-IAM-01: Phishing-Resistant MFA

Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_IAM_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-01: Phishing-Resistant MFA
    
    **Official Statement:**
    Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2
    - ia-2
    - ia-2.1
    - ia-2.2
    - ia-2.8
    - ia-5
    - ia-8
    - sc-23
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersona...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-IAM-01"
    KSI_NAME = "Phishing-Resistant MFA"
    KSI_STATEMENT = """Enforce multi-factor authentication (MFA) using methods that are difficult to intercept or impersonate (phishing-resistant MFA) for all user authentication."""
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-2", "Account Management"),
        ("ia-2", "Identification and Authentication (Organizational Users)"),
        ("ia-2.1", "Multi-factor Authentication to Privileged Accounts"),
        ("ia-2.2", "Multi-factor Authentication to Non-privileged Accounts"),
        ("ia-2.8", "Access to Accounts — Replay Resistant"),
        ("ia-5", "Authenticator Management"),
        ("ia-8", "Identification and Authentication (Non-organizational Users)"),
        ("sc-23", "Session Authenticity")
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
        Analyze Python code for KSI-IAM-01 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing FIDO2/WebAuthn (phishing-resistant MFA)
        - TOTP/SMS-based MFA (less secure)
        - Django/Flask/FastAPI MFA configuration
        - Azure AD MFA enforcement
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Python analysis for MFA implementation."""
        findings = []
        code_bytes = code.encode('utf-8')
        
        # Check for phishing-resistant MFA imports
        import_nodes = parser.find_nodes_by_type(tree.root_node, "import_statement")
        import_nodes.extend(parser.find_nodes_by_type(tree.root_node, "import_from_statement"))
        
        has_fido2 = False
        has_webauthn = False
        has_certificate_auth = False
        has_totp = False
        has_sms_mfa = False
        django_mfa_found = False
        flask_mfa_found = False
        has_azure_ad = False
        
        for imp_node in import_nodes:
            imp_text = parser.get_node_text(imp_node, code_bytes)
            
            # Phishing-resistant methods
            if 'fido2' in imp_text.lower():
                has_fido2 = True
            if 'webauthn' in imp_text.lower():
                has_webauthn = True
            if 'certificate' in imp_text.lower() and 'auth' in imp_text.lower():
                has_certificate_auth = True
            
            # Less secure methods
            if 'pyotp' in imp_text.lower() or 'totp' in imp_text.lower():
                has_totp = True
            if 'twilio' in imp_text.lower() or ('sms' in imp_text.lower() and 'mfa' in imp_text.lower()):
                has_sms_mfa = True
            
            # Framework-specific
            if 'django_otp' in imp_text or 'django_two_factor' in imp_text:
                django_mfa_found = True
            if 'flask_security' in imp_text:
                flask_mfa_found = True
            if 'msal' in imp_text.lower() or 'azure' in imp_text.lower():
                has_azure_ad = True
        
        # Check Django OTP configuration
        if django_mfa_found:
            # Check for phishing-resistant device classes
            has_resistant_device = False
            for imp_node in import_nodes:
                imp_text = parser.get_node_text(imp_node, code_bytes)
                if any(device in imp_text for device in ['WebAuthnDevice', 'U2FDevice']):
                    has_resistant_device = True
                    break
            
            if not has_resistant_device:
                line_num = 1
                for imp_node in import_nodes:
                    imp_text = parser.get_node_text(imp_node, code_bytes)
                    if 'django_otp' in imp_text:
                        line_num = imp_node.start_point[0] + 1
                        break
                
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Django OTP without phishing-resistant device",
                    description="django-otp is configured but no phishing-resistant device (WebAuthn, U2F) is detected. Consider using WebAuthnDevice or U2FDevice instead of TOTPDevice for phishing-resistant MFA.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    snippet="",
                    remediation="Configure WebAuthnDevice or U2FDevice in django-otp: from django_otp.plugins.otp_webauthn.models import WebAuthnDevice"
                ))
        
        # Check Flask MFA enforcement
        if flask_mfa_found:
            # Look for SECURITY_TWO_FACTOR configuration
            has_mfa_enforced = False
            assignment_nodes = parser.find_nodes_by_type(tree.root_node, "assignment")
            
            for assign_node in assignment_nodes:
                assign_text = parser.get_node_text(assign_node, code_bytes)
                if 'SECURITY_TWO_FACTOR' in assign_text and 'True' in assign_text:
                    has_mfa_enforced = True
                    break
            
            if not has_mfa_enforced:
                line_num = 1
                for imp_node in import_nodes:
                    imp_text = parser.get_node_text(imp_node, code_bytes)
                    if 'flask_security' in imp_text:
                        line_num = imp_node.start_point[0] + 1
                        break
                
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Flask-Security MFA not enforced",
                    description="Flask-Security is present but SECURITY_TWO_FACTOR is not set to True or @two_factor_required decorator is not used.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    snippet="",
                    remediation="Enable MFA: SECURITY_TWO_FACTOR = True and SECURITY_TWO_FACTOR_REQUIRED = True"
                ))
        
        # Check FastAPI MFA middleware
        has_fastapi = any('fastapi' in parser.get_node_text(imp, code_bytes).lower() for imp in import_nodes)
        
        if has_fastapi and not (has_fido2 or has_webauthn):
            # Check for MFA middleware in function definitions
            has_mfa_middleware = False
            func_nodes = parser.find_nodes_by_type(tree.root_node, "function_definition")
            
            for func_node in func_nodes:
                func_text = parser.get_node_text(func_node, code_bytes)
                if 'mfa' in func_text.lower() and 'middleware' in func_text.lower():
                    has_mfa_middleware = True
                    break
            
            if not has_mfa_middleware:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="FastAPI missing MFA middleware",
                    description="FastAPI application detected without MFA middleware or FIDO2/WebAuthn implementation.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation="Implement MFA middleware with FIDO2/WebAuthn or integrate with Azure AD B2C for phishing-resistant MFA"
                ))
        
        # Check Azure AD MFA enforcement
        if has_azure_ad:
            # Check for MFA enforcement configuration
            has_mfa_config = False
            for node in parser.find_nodes_by_type(tree.root_node, "string"):
                node_text = parser.get_node_text(node, code_bytes)
                if any(keyword in node_text.lower() for keyword in ['require_mfa', 'enforce_mfa', 'conditional_access']):
                    has_mfa_config = True
                    break
            
            if not has_mfa_config:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD configuration missing MFA enforcement",
                    description="Azure AD/MSAL authentication detected but MFA enforcement not configured. Azure AD Conditional Access should require MFA for all users.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    snippet="",
                    remediation="Configure Azure AD Conditional Access policy to require phishing-resistant MFA (certificate-based, FIDO2, or Windows Hello for Business)"
                ))
        
        # Warn about non-phishing-resistant MFA methods
        if has_totp and not (has_fido2 or has_webauthn or has_certificate_auth):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="Time-based One-Time Password (TOTP) MFA is vulnerable to phishing attacks. FedRAMP 20x requires phishing-resistant MFA methods.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation="Migrate to phishing-resistant MFA: FIDO2 (py_webauthn), WebAuthn, or certificate-based authentication"
            ))
        
        if has_sms_mfa:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS-based MFA is vulnerable to SIM swapping and phishing attacks. FedRAMP 20x requires phishing-resistant MFA methods.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation="Replace SMS MFA with phishing-resistant methods: FIDO2, WebAuthn, or certificate-based authentication"
            ))
        
        # Check for login functions without MFA
        func_nodes = parser.find_nodes_by_type(tree.root_node, "function_definition")
        
        for func_node in func_nodes:
            func_text = parser.get_node_text(func_node, code_bytes)
            line_num = func_node.start_point[0] + 1
            
            # Check if function name contains 'login'
            func_name = ''
            for child in func_node.children:
                if child.type == 'identifier':
                    func_name = parser.get_node_text(child, code_bytes).lower()
                    break
            
            # Check decorators for login routes
            is_login_route = 'login' in func_name
            decorators = parser.find_nodes_by_type(func_node, "decorator")
            for dec in decorators:
                dec_text = parser.get_node_text(dec, code_bytes)
                if 'login' in dec_text.lower() or '/login' in dec_text:
                    is_login_route = True
                    break
            
            if is_login_route:
                # Check if this login function/route has MFA implementation
                has_mfa_in_func = (
                    'fido2' in func_text.lower() or 
                    'webauthn' in func_text.lower() or
                    'totp' in func_text.lower() or
                    'two_factor' in func_text.lower() or
                    'mfa' in func_text.lower()
                )
                
                if not has_mfa_in_func:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Login without MFA",
                        description="Login functionality detected without multi-factor authentication implementation. KSI-IAM-01 requires phishing-resistant MFA for all user authentication.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        snippet=func_text[:200] if len(func_text) < 200 else func_text[:200] + '...',
                        remediation="Implement phishing-resistant MFA using FIDO2 (py_webauthn), WebAuthn, or integrate with Azure AD Conditional Access"
                    ))
        
        # Check for @login_required decorator without MFA enforcement
        all_decorators = parser.find_nodes_by_type(tree.root_node, "decorator")
        for dec_node in all_decorators:
            dec_text = parser.get_node_text(dec_node, code_bytes)
            if 'login_required' in dec_text:
                # Check if there's also an MFA decorator
                parent_func = dec_node.parent
                if parent_func and parent_func.type == 'decorated_definition':
                    full_text = parser.get_node_text(parent_func, code_bytes)
                    has_mfa_decorator = any(mfa in full_text.lower() for mfa in ['mfa_required', 'two_factor_required', 'fido2', 'webauthn'])
                    
                    if not has_mfa_decorator:
                        line_num = dec_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title="Authentication decorator without MFA",
                            description="@login_required decorator found without MFA enforcement. Password-only authentication does not meet KSI-IAM-01 phishing-resistant MFA requirements.",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_num,
                            snippet=dec_text,
                            remediation="Add @mfa_required or @two_factor_required decorator, or implement FIDO2/WebAuthn authentication"
                        ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based Python analysis when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Check for phishing-resistant MFA methods
        has_fido2 = bool(re.search(r'import\s+fido2|from\s+fido2', code, re.IGNORECASE))
        has_webauthn = bool(re.search(r'import\s+webauthn|from\s+webauthn', code, re.IGNORECASE))
        
        # Check for TOTP (non-phishing-resistant)
        if re.search(r'import\s+pyotp|from\s+pyotp|totp', code, re.IGNORECASE) and not (has_fido2 or has_webauthn):
            result = self._find_line(lines, r'pyotp|totp', use_regex=True)
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="TOTP MFA is vulnerable to phishing attacks.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number = result['line_num'] if result else 0,
                snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                remediation="Migrate to phishing-resistant MFA: FIDO2, WebAuthn"
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-01 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Patterns Detected:
        - ASP.NET Core Identity MFA configuration
        - Azure AD authentication with MFA enforcement
        - Certificate-based authentication
        - FIDO2/WebAuthn implementation
        - SMS/Email MFA (non-phishing-resistant, flagged)
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# analysis for MFA implementation."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        # Track MFA implementations
        has_certificate_auth = False
        has_fido2 = False
        has_email_mfa = False
        has_sms_mfa = False
        aspnet_identity_found = False
        has_mfa_enforcement = False
        has_azure_ad = False
        has_azure_ad_mfa_validation = False
        has_authorization = False
        
        # Check using statements for MFA-related namespaces
        using_nodes = parser.find_nodes_by_type(root_node, 'using_directive')
        for node in using_nodes:
            using_text = parser.get_node_text(node, code_bytes)
            
            # Phishing-resistant MFA
            if any(keyword in using_text for keyword in ['Certificate', 'X509', 'ClientCertificate']):
                has_certificate_auth = True
            if any(keyword in using_text.lower() for keyword in ['fido2', 'webauthn']):
                has_fido2 = True
            
            # Non-phishing-resistant MFA (vulnerable)
            if 'EmailTokenProvider' in using_text or 'SendGrid' in using_text:
                has_email_mfa = True
            if 'PhoneNumberTokenProvider' in using_text or 'Twilio' in using_text:
                has_sms_mfa = True
            
            # ASP.NET Core Identity
            if 'Microsoft.AspNetCore.Identity' in using_text:
                aspnet_identity_found = True
            
            # Azure AD / Microsoft Identity Web
            if 'Microsoft.Identity.Web' in using_text or 'Microsoft.Graph' in using_text:
                has_azure_ad = True
        
        # Check for AddIdentity<> configuration
        invocation_nodes = parser.find_nodes_by_type(root_node, 'invocation_expression')
        for node in invocation_nodes:
            invocation_text = parser.get_node_text(node, code_bytes)
            if 'AddIdentity<' in invocation_text or 'AddDefaultIdentity<' in invocation_text:
                aspnet_identity_found = True
            
            # Check for phishing-resistant authentication methods
            if 'AddCertificate' in invocation_text or 'AddClientCertificate' in invocation_text:
                has_certificate_auth = True
            
            # Check for Azure AD configuration
            if 'AddMicrosoftIdentityWebApp' in invocation_text or 'AddMicrosoftIdentityPlatform' in invocation_text:
                has_azure_ad = True
        
        # Check for RequireTwoFactor configuration and token provider assignments
        assignment_nodes = parser.find_nodes_by_type(root_node, 'assignment_expression')
        for node in assignment_nodes:
            assignment_text = parser.get_node_text(node, code_bytes)
            if 'RequireTwoFactor' in assignment_text and '= true' in assignment_text:
                has_mfa_enforcement = True
            
            # Check for email/SMS token provider assignments
            if 'EmailTokenProvider' in assignment_text:
                has_email_mfa = True
            if 'PhoneNumberTokenProvider' in assignment_text or 'SmsTokenProvider' in assignment_text:
                has_sms_mfa = True
        
        # Check for Azure AD MFA claim validation
        member_access_nodes = parser.find_nodes_by_type(root_node, 'member_access_expression')
        for node in member_access_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if 'amr' in node_text.lower() and 'mfa' in node_text.lower():
                has_azure_ad_mfa_validation = True
            if 'ConditionalAccess' in node_text or 'RequireMfa' in node_text:
                has_azure_ad_mfa_validation = True
        
        # Check for authorization attributes/middleware
        attribute_nodes = parser.find_nodes_by_type(root_node, 'attribute')
        for node in attribute_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if '[Authorize]' in node_text or 'UseAuthentication()' in node_text:
                has_authorization = True
        
        # Check for [Authorize] attribute without MFA requirement
        attribute_list_nodes = parser.find_nodes_by_type(root_node, 'attribute_list')
        for attr_list_node in attribute_list_nodes:
            attr_text = parser.get_node_text(attr_list_node, code_bytes)
            if '[Authorize]' in attr_text or '[Authorize(' in attr_text:
                # Check if there's an MFA policy requirement
                has_mfa_policy = 'RequireMfa' in attr_text or 'TwoFactor' in attr_text or 'Mfa' in attr_text
                
                if not has_mfa_policy and not (has_certificate_auth or has_fido2):
                    line_num = attr_list_node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="[Authorize] without MFA requirement",
                        description="[Authorize] attribute detected without MFA policy requirement. Password-only authentication does not meet KSI-IAM-01 phishing-resistant MFA requirements.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=attr_text[:200] if len(attr_text) < 200 else attr_text[:200] + '...',
                        recommendation="Add MFA policy requirement: [Authorize(Policy = \"RequireMfa\")] or configure Azure AD Conditional Access to require MFA"
                    ))
        
        # Generate findings based on analysis
        
        # Finding 1: ASP.NET Core Identity without MFA enforcement
        if aspnet_identity_found and not has_mfa_enforcement:
            result = self._find_line(lines, r'AddIdentity|AddDefaultIdentity')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="ASP.NET Core Identity without MFA enforcement",
                description="ASP.NET Core Identity is configured but RequireTwoFactor is not set to true. KSI-IAM-01 requires phishing-resistant MFA for all user authentication.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Configure MFA enforcement: services.Configure<IdentityOptions>(options => { options.SignIn.RequireTwoFactor = true; });"
            ))
        
        # Finding 2: Non-phishing-resistant MFA methods
        if aspnet_identity_found and not (has_certificate_auth or has_fido2):
            if has_email_mfa or has_sms_mfa:
                result = self._find_line(lines, r'EmailTokenProvider|PhoneNumberTokenProvider|Twilio|SendGrid')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="ASP.NET Core Identity using non-phishing-resistant MFA",
                    description="Email or SMS token providers detected. These are vulnerable to phishing. FedRAMP 20x requires phishing-resistant MFA.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Implement FIDO2/WebAuthn or certificate-based authentication instead of email/SMS tokens"
                ))
        
        # Finding 3: Azure AD without MFA validation
        if has_azure_ad and not has_azure_ad_mfa_validation:
            result = self._find_line(lines, r'AddMicrosoftIdentityWebApp|Microsoft\.Identity\.Web')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Azure AD authentication without MFA validation",
                description="Azure AD authentication configured but no validation of MFA claim (amr claim) or Conditional Access enforcement detected.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Validate MFA claim: if (!User.Claims.Any(c => c.Type == \"amr\" && c.Value == \"mfa\")) { return Challenge(); }"
            ))
        
        # Finding 4: Authorization without MFA
        if has_authorization and not aspnet_identity_found:
            if not (has_certificate_auth or has_fido2 or has_azure_ad):
                result = self._find_line(lines, r'\[Authorize\]|UseAuthentication')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Authentication without MFA implementation",
                    description="Authorization is configured but no MFA implementation detected.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Implement phishing-resistant MFA: ASP.NET Core Identity with FIDO2, Azure AD with Conditional Access, or certificate-based authentication"
                ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for C# analysis."""
        findings = []
        lines = code.split('\n')
        
        # Check for phishing-resistant MFA methods
        has_certificate_auth = bool(re.search(r'AddCertificate|CertificateAuthentication|ClientCertificate', code))
        has_fido2 = bool(re.search(r'Fido2|WebAuthn', code, re.IGNORECASE))
        
        # Check for non-phishing-resistant methods
        has_email_mfa = bool(re.search(r'EmailTokenProvider|SendEmailAsync.*token', code, re.IGNORECASE))
        has_sms_mfa = bool(re.search(r'PhoneNumberTokenProvider|SendSmsAsync|Twilio', code, re.IGNORECASE))
        
        # Check ASP.NET Core Identity MFA configuration
        aspnet_identity_found = False
        if re.search(r'using\s+Microsoft\.AspNetCore\.Identity|AddIdentity<', code):
            aspnet_identity_found = True
            
            # Check if MFA is enforced
            if not re.search(r'RequireAuthenticatedSignIn\s*=\s*true|RequireTwoFactor\s*=\s*true|\[RequiresTwoFactor\]', code, re.IGNORECASE):
                result = self._find_line(lines, r'AddIdentity', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="ASP.NET Core Identity MFA not enforced",
                    description="ASP.NET Core Identity is configured but MFA is not enforced. SignInOptions should set RequireTwoFactor = true.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Configure MFA enforcement: services.Configure<IdentityOptions>(options => { options.SignIn.RequireTwoFactor = true; });"
                ))
            
            # Check for phishing-resistant token providers
            if not (has_certificate_auth or has_fido2):
                if has_email_mfa or has_sms_mfa:
                    result = self._find_line(lines, r'EmailTokenProvider|PhoneNumberTokenProvider', use_regex=True)
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="ASP.NET Core Identity using non-phishing-resistant MFA",
                        description="Email or SMS token providers detected. These are vulnerable to phishing. FedRAMP 20x requires phishing-resistant MFA.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number = result['line_num'] if result else 0,
                        code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                        recommendation="Implement FIDO2/WebAuthn or certificate-based authentication instead of email/SMS tokens"
                    ))
        
        # Check Azure AD/Entra ID configuration
        if re.search(r'Microsoft\.Identity\.Web|AddMicrosoftIdentityWebApp|AzureAD', code):
            if not re.search(r'ConditionalAccess|RequireMfa|ClaimsPrincipal.*amr.*mfa', code, re.IGNORECASE):
                result = self._find_line(lines, r'AddMicrosoftIdentityWebApp', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD authentication without MFA validation",
                    description="Azure AD authentication configured but no validation of MFA claim (amr claim) or Conditional Access enforcement detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Validate MFA claim: if (!User.Claims.Any(c => c.Type == \"amr\" && c.Value == \"mfa\")) { return Challenge(); }"
                ))
        
        # Check for any authentication without MFA
        if re.search(r'\[Authorize\]|UseAuthentication\(\)', code) and not aspnet_identity_found:
            if not (has_certificate_auth or has_fido2 or re.search(r'AddMicrosoftIdentityWebApp', code)):
                result = self._find_line(lines, r'\[Authorize\]|UseAuthentication', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Authentication without MFA implementation",
                    description="Authorization is configured but no MFA implementation detected.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Implement phishing-resistant MFA: ASP.NET Core Identity with FIDO2, Azure AD with Conditional Access, or certificate-based authentication"
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-01 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Patterns Detected:
        - Spring Security MFA configuration
        - Custom authentication providers with MFA
        - Azure AD Spring Boot integration
        - FIDO2/WebAuthn implementation (phishing-resistant)
        - TOTP/SMS-based MFA (non-phishing-resistant, flagged)
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java analysis for MFA implementation."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        # Track MFA implementations
        has_fido2 = False
        has_certificate_auth = False
        has_totp = False
        has_sms_mfa = False
        spring_security_found = False
        has_mfa_filter = False
        has_azure_ad = False
        has_azure_ad_mfa_validation = False
        
        # Check import statements
        for node in parser.find_nodes_by_type(root_node, 'import_declaration'):
            import_text = parser.get_node_text(node, code_bytes)
            
            # Phishing-resistant MFA
            if any(keyword in import_text.lower() for keyword in ['webauthn4j', 'yubico.webauthn', 'fido2']):
                has_fido2 = True
            if 'X509AuthenticationFilter' in import_text or 'CertificateAuthentication' in import_text:
                has_certificate_auth = True
            
            # Non-phishing-resistant MFA (vulnerable)
            if any(keyword in import_text.lower() for keyword in ['googleauthenticator', 'totp', 'timebasedonetimepassword']):
                has_totp = True
            if any(keyword in import_text.lower() for keyword in ['twilio', 'smsauthenticationprovider']):
                has_sms_mfa = True
            
            # Spring Security
            if 'springframework.security' in import_text.lower():
                spring_security_found = True
            
            # Azure AD Spring Boot
            if 'azure-spring-boot' in import_text.lower() or 'AzureActiveDirectory' in import_text:
                has_azure_ad = True
            
        # Check for Spring Security annotations
        for node in parser.find_nodes_by_type(root_node, 'marker_annotation'):
            annotation_text = parser.get_node_text(node, code_bytes)
            if '@EnableWebSecurity' in annotation_text:
                spring_security_found = True
        
        # Check for MFA filter classes
        class_nodes = parser.find_nodes_by_type(root_node, 'class_declaration')
        method_nodes = parser.find_nodes_by_type(root_node, 'method_declaration')
        for node in class_nodes + method_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if any(keyword in node_text for keyword in ['TwoFactorAuthenticationFilter', 'MultiFactorAuthentication', 'mfaRequired', 'requireMfa']):
                has_mfa_filter = True
        
        # Check for Azure AD MFA validation
        for node in parser.find_nodes_by_type(root_node, 'method_invocation'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'amr' in node_text.lower() and ('claim' in node_text.lower() or 'mfa' in node_text.lower()):
                has_azure_ad_mfa_validation = True
            if 'conditionalAccess' in node_text or 'validateMfa' in node_text:
                has_azure_ad_mfa_validation = True
        
        # Generate findings based on analysis
        
        # Finding 1: Spring Security without MFA enforcement
        if spring_security_found and not has_mfa_filter and not (has_fido2 or has_certificate_auth):
            result = self._find_line(lines, r'@EnableWebSecurity|WebSecurityConfigurerAdapter|formLogin')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Spring Security without MFA",
                    description="Spring Security is configured with form login but no MFA enforcement is detected. KSI-IAM-01 requires phishing-resistant MFA for all user authentication.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Implement phishing-resistant MFA: add WebAuthn4J or Yubico WebAuthn library with TwoFactorAuthenticationFilter"
                ))
            
        # Finding 2: Azure AD without MFA validation
        if has_azure_ad and not has_azure_ad_mfa_validation:
            result = self._find_line(lines, r'azure-spring-boot-starter|AzureActiveDirectory')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD integration without MFA validation",
                    description="Azure AD authentication configured but no validation of MFA claims or Conditional Access configuration detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Validate MFA claim from Azure AD token or configure Azure AD Conditional Access"
                ))
            
        # Finding 3: TOTP warning
        if has_totp and not (has_fido2 or has_certificate_auth):
            result = self._find_line(lines, r'GoogleAuthenticator|totp|TimeBasedOneTimePassword')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="TOTP-based MFA is not phishing-resistant",
                    description="TOTP is vulnerable to phishing attacks. FedRAMP 20x requires phishing-resistant MFA.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Migrate to phishing-resistant MFA: WebAuthn4J (FIDO2) or certificate-based authentication"
                ))
            
        # Finding 4: SMS warning
        if has_sms_mfa:
            result = self._find_line(lines, r'sendSms.*verification|Twilio|SmsAuthenticationProvider')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="SMS-based MFA is not phishing-resistant",
                    description="SMS-based MFA is vulnerable to SIM swapping and phishing attacks.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Replace SMS MFA with WebAuthn4J (FIDO2) or certificate-based authentication"
                ))
            
        # Finding 5: No MFA implementation
            if spring_security_found and not (has_fido2 or has_certificate_auth or has_totp or has_sms_mfa):
                if not has_azure_ad:
                    result = self._find_line(lines, r'@EnableWebSecurity')

                    line_num = result['line_num'] if result else 0
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="No MFA implementation detected",
                        description="Spring Security authentication configured but no MFA implementation detected.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation="Implement phishing-resistant MFA using WebAuthn4J (FIDO2) or integrate with Azure AD Conditional Access"
                    ))
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for Java analysis."""
        findings = []
        lines = code.split('\n')
        
        # Check for phishing-resistant MFA
        has_fido2 = bool(re.search(r'import.*webauthn4j|import.*yubico.*webauthn', code, re.IGNORECASE))
        has_certificate_auth = bool(re.search(r'X509AuthenticationFilter|CertificateAuthentication', code))
        
        # Check for non-phishing-resistant MFA
        has_totp = bool(re.search(r'import.*GoogleAuthenticator|import.*totp|TimeBasedOneTimePassword', code, re.IGNORECASE))
        has_sms_mfa = bool(re.search(r'SmsAuthenticationProvider|sendSms.*verification|Twilio', code, re.IGNORECASE))
        
        # Check Spring Security configuration
        spring_security_found = False
        if re.search(r'import.*springframework\.security|@EnableWebSecurity', code):
            spring_security_found = True
            
            # Check for MFA configuration
            if not re.search(r'TwoFactorAuthenticationFilter|MultiFactorAuthentication|mfaRequired|requireMfa', code, re.IGNORECASE):
                result = self._find_line(lines, r'@EnableWebSecurity', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Spring Security without MFA enforcement",
                    description="Spring Security is configured but no MFA enforcement filter or configuration is detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Implement MFA filter: create a TwoFactorAuthenticationFilter with phishing-resistant methods"
                ))
        
        # Check Azure AD Spring Boot integration
        if re.search(r'azure-spring-boot-starter-active-directory|AzureActiveDirectoryB2CAutoConfiguration', code):
            if not re.search(r'conditionalAccess|amr.*claim.*mfa|validateMfa', code, re.IGNORECASE):
                result = self._find_line(lines, r'azure-spring-boot-starter', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD integration without MFA validation",
                    description="Azure AD authentication configured but no validation of MFA claims or Conditional Access configuration detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Validate MFA claim from Azure AD token or configure Azure AD Conditional Access"
                ))
        
        # Warn about non-phishing-resistant MFA
        if has_totp and not (has_fido2 or has_certificate_auth):
            result = self._find_line(lines, r'GoogleAuthenticator|totp', use_regex=True)
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="TOTP is vulnerable to phishing attacks. FedRAMP 20x requires phishing-resistant MFA.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number = result['line_num'] if result else 0,
                code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                recommendation="Migrate to phishing-resistant MFA: WebAuthn4J (FIDO2) or certificate-based authentication"
            ))
        
        if has_sms_mfa:
            result = self._find_line(lines, r'sendSms.*verification|Twilio', use_regex=True)
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS-based MFA is vulnerable to SIM swapping and phishing attacks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number = result['line_num'] if result else 0,
                code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                recommendation="Replace SMS MFA with WebAuthn4J (FIDO2) or certificate-based authentication"
            ))
        
        # Check if authentication exists without MFA
        if spring_security_found and not (has_fido2 or has_certificate_auth or has_totp or has_sms_mfa):
            if not re.search(r'azure-spring-boot-starter-active-directory', code):
                result = self._find_line(lines, r'@EnableWebSecurity', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No MFA implementation detected",
                    description="Spring Security authentication configured but no MFA implementation detected.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Implement phishing-resistant MFA using WebAuthn4J (FIDO2) or integrate with Azure AD Conditional Access"
                ))
        
        return findings
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-01 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Patterns Detected:
        - Passport.js MFA strategies
        - NextAuth.js configuration
        - MSAL (Microsoft Authentication Library) for Azure AD
        - WebAuthn/FIDO2 implementation (phishing-resistant)
        - TOTP/OTP-based MFA (non-phishing-resistant, flagged)
        """
        # AST-first dispatcher
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based TypeScript/JavaScript analysis for MFA implementation."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        root_node = tree.root_node
        
        # Track MFA implementations
        has_webauthn = False
        has_totp = False
        has_sms_mfa = False
        passport_found = False
        has_passport_mfa = False
        has_nextauth = False
        has_nextauth_mfa = False
        has_msal = False
        has_msal_mfa_validation = False
        has_authentication = False
        
        # Check import statements (ES6 imports)
        for node in parser.find_nodes_by_type(root_node, 'import_statement'):
            import_text = parser.get_node_text(node, code_bytes)
            
            # Phishing-resistant MFA
            if any(keyword in import_text.lower() for keyword in ['@simplewebauthn', 'fido2-lib', 'webauthn']):
                has_webauthn = True
            
            # Non-phishing-resistant MFA (vulnerable)
            if any(keyword in import_text.lower() for keyword in ['speakeasy', 'otplib', 'authenticator', 'totp']):
                has_totp = True
            if any(keyword in import_text.lower() for keyword in ['twilio', 'nexmo']):
                has_sms_mfa = True
            
            # Authentication frameworks
            if 'passport' in import_text.lower():
                passport_found = True
                if any(keyword in import_text.lower() for keyword in ['passport-totp', 'passport-webauthn', 'passport-mfa', 'passport-2fa']):
                    has_passport_mfa = True
            
            if 'next-auth' in import_text.lower():
                has_nextauth = True
            
            if '@azure/msal' in import_text.lower() or 'PublicClientApplication' in import_text or 'ConfidentialClientApplication' in import_text:
                has_msal = True
        
        # Check require statements (CommonJS imports)
        for node in parser.find_nodes_by_type(root_node, 'call_expression'):
            call_text = parser.get_node_text(node, code_bytes)
            if 'require(' in call_text:
                # Phishing-resistant MFA
                if any(keyword in call_text.lower() for keyword in ['@simplewebauthn', 'fido2-lib', 'webauthn']):
                    has_webauthn = True
                
                # Non-phishing-resistant MFA (vulnerable)
                if any(keyword in call_text.lower() for keyword in ['speakeasy', 'otplib', 'authenticator', 'totp']):
                    has_totp = True
                if any(keyword in call_text.lower() for keyword in ['twilio', 'nexmo']):
                    has_sms_mfa = True
                
                # Authentication frameworks
                if 'passport' in call_text.lower():
                    passport_found = True
                    if any(keyword in call_text.lower() for keyword in ['passport-totp', 'passport-webauthn', 'passport-mfa', 'passport-2fa']):
                        has_passport_mfa = True
                
                if 'next-auth' in call_text.lower():
                    has_nextauth = True
                
                if '@azure/msal' in call_text.lower() or 'PublicClientApplication' in call_text or 'ConfidentialClientApplication' in call_text:
                    has_msal = True
            
        # Check for NextAuth MFA configuration (look for actual MFA providers, not just credential providers)
        for node in parser.find_nodes_by_type(root_node, 'object'):
            node_text = parser.get_node_text(node, code_bytes)
            if has_nextauth and any(keyword in node_text.lower() for keyword in ['webauthn', 'totp', 'authenticator', 'fido']):
                has_nextauth_mfa = True
            
        # Check for MSAL MFA validation
        for node in parser.find_nodes_by_type(root_node, 'call_expression'):
            node_text = parser.get_node_text(node, code_bytes)
            if has_msal:
                if 'amr' in node_text.lower() and 'mfa' in node_text.lower():
                    has_msal_mfa_validation = True
                if 'claimsRequest' in node_text or 'conditionalAccess' in node_text:
                    has_msal_mfa_validation = True
            
        # Check for WebAuthn implementation
        for node in parser.find_nodes_by_type(root_node, 'call_expression'):
            node_text = parser.get_node_text(node, code_bytes)
            if 'navigator.credentials.create' in node_text or 'navigator.credentials.get' in node_text:
                has_webauthn = True
        
        # Check for authentication logic
        for node in parser.find_nodes_by_type(root_node, 'call_expression'):
            node_text = parser.get_node_text(node, code_bytes)
            if any(keyword in node_text.lower() for keyword in ['jwt.sign', 'bcrypt.compare', 'authenticate']):
                has_authentication = True
            
        # Generate findings based on analysis
        
        # Finding 1: Passport.js without MFA
        if passport_found and not (has_passport_mfa or has_webauthn):
            # Check for LocalStrategy (password-only authentication)
            has_local_strategy = 'LocalStrategy' in code or 'passport-local' in code
            
            result = self._find_line(lines, r'passport|LocalStrategy')

            
            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Passport.js without MFA",
                description="Passport.js is configured with LocalStrategy (password-only) without MFA enforcement. KSI-IAM-01 requires phishing-resistant MFA for all user authentication.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Add phishing-resistant MFA: implement passport-webauthn strategy or integrate with Azure AD B2C for phishing-resistant MFA"
            ))
        
        # Finding 2: NextAuth.js without MFA
        if has_nextauth and not has_nextauth_mfa:
            result = self._find_line(lines, r'next-auth')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="NextAuth.js without MFA configuration",
                description="NextAuth.js is configured but no MFA provider or adapter is detected.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Configure MFA: use AzureADProvider with Conditional Access or implement WebAuthn provider"
            ))
        
        # Finding 3: MSAL without MFA validation
        if has_msal and not has_msal_mfa_validation:
            result = self._find_line(lines, r'msal|PublicClientApplication|ConfidentialClientApplication')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="MSAL without MFA validation",
                description="MSAL is configured but no MFA claim validation or Conditional Access enforcement detected.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Validate MFA claim: check for 'amr' claim containing 'mfa' or configure Azure AD Conditional Access"
            ))
        
        # Finding 4: TOTP warning
        if has_totp and not has_webauthn:
            result = self._find_line(lines, r'speakeasy|otplib|authenticator')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="TOTP is vulnerable to phishing attacks.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Migrate to @simplewebauthn/server (FIDO2/WebAuthn) or fido2-lib"
            ))
        
        # Finding 5: SMS warning
        if has_sms_mfa:
            result = self._find_line(lines, r'twilio|nexmo|sns.*sms')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS is vulnerable to SIM swapping and phishing attacks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Replace SMS MFA with @simplewebauthn/server (FIDO2/WebAuthn)"
            ))
        
        # Finding 6: No MFA implementation
        if (passport_found or has_authentication) and not (has_webauthn or has_totp or has_sms_mfa):
            if not has_msal:
                result = self._find_line(lines, r'passport|jwt\.sign|authenticate')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No MFA implementation detected",
                    description="Authentication logic detected but no MFA implementation found.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Implement phishing-resistant MFA: @simplewebauthn/server (FIDO2) or integrate with Azure AD/MSAL"
                ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based fallback for TypeScript/JavaScript analysis."""
        findings = []
        lines = code.split('\n')
        
        # Check for phishing-resistant MFA
        has_webauthn = bool(re.search(r'import.*@simplewebauthn|import.*fido2-lib|navigator\.credentials\.create', code, re.IGNORECASE))
        
        # Check for non-phishing-resistant MFA
        has_totp = bool(re.search(r'import.*speakeasy|import.*otplib|import.*authenticator', code, re.IGNORECASE))
        has_sms_mfa = bool(re.search(r'twilio|nexmo|sns\.publish.*sms', code, re.IGNORECASE))
        
        # Check Passport.js configuration
        passport_found = False
        if re.search(r'import.*passport|require\(["\']passport', code):
            passport_found = True
            
            # Check for MFA strategy
            if not re.search(r'passport-totp|passport-webauthn|passport.*mfa|passport.*2fa', code, re.IGNORECASE):
                result = self._find_line(lines, r'passport', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Passport.js without MFA strategy",
                    description="Passport.js is configured but no MFA strategy detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Implement MFA strategy: use passport-webauthn for phishing-resistant MFA"
                ))
        
        # Check NextAuth.js configuration
        if re.search(r'import.*next-auth|from ["\']next-auth', code):
            if not re.search(r'credentials.*mfa|webauthn|adapter.*mfa', code, re.IGNORECASE):
                result = self._find_line(lines, r'next-auth', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="NextAuth.js without MFA configuration",
                    description="NextAuth.js is configured but no MFA provider or adapter is detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Configure MFA: use AzureADProvider with Conditional Access or implement WebAuthn provider"
                ))
        
        # Check MSAL (Azure AD) configuration
        if re.search(r'@azure/msal|PublicClientApplication|ConfidentialClientApplication', code):
            if not re.search(r'amr.*mfa|claimsRequest.*mfa|conditionalAccess', code, re.IGNORECASE):
                result = self._find_line(lines, r'msal|PublicClientApplication', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="MSAL without MFA validation",
                    description="MSAL is configured but no MFA claim validation or Conditional Access enforcement detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Validate MFA claim: check for 'amr' claim containing 'mfa' or configure Azure AD Conditional Access"
                ))
        
        # Warn about non-phishing-resistant MFA
        if has_totp and not has_webauthn:
            result = self._find_line(lines, r'speakeasy|otplib|authenticator', use_regex=True)
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="TOTP is vulnerable to phishing attacks.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number = result['line_num'] if result else 0,
                code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                recommendation="Migrate to @simplewebauthn/server (FIDO2/WebAuthn) or fido2-lib"
            ))
        
        if has_sms_mfa:
            result = self._find_line(lines, r'twilio|nexmo|sns.*sms', use_regex=True)
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS is vulnerable to SIM swapping and phishing attacks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number = result['line_num'] if result else 0,
                code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                recommendation="Replace SMS MFA with @simplewebauthn/server (FIDO2/WebAuthn)"
            ))
        
        # Check for authentication without MFA
        if (passport_found or re.search(r'jwt\.sign|bcrypt\.compare|authenticate', code)) and not (has_webauthn or has_totp or has_sms_mfa):
            if not re.search(r'@azure/msal', code):
                result = self._find_line(lines, r'passport|jwt\.sign|authenticate', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No MFA implementation detected",
                    description="Authentication logic detected but no MFA implementation found.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Implement phishing-resistant MFA: @simplewebauthn/server (FIDO2) or integrate with Azure AD/MSAL"
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-01 compliance.
        
        Checks:
        - Azure AD Conditional Access policies requiring MFA
        - Authentication strength configurations (phishing-resistant)
        - Multi-factor authentication settings in Azure resources
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Conditional Access policy resources
        has_conditional_access = bool(re.search(r'Microsoft\.AAD/conditionalAccessPolicies|conditionalAccessPolicy', code, re.IGNORECASE))
        
        if has_conditional_access:
            # Check if MFA is required in grant controls
            if not re.search(r'grantControls.*requireMultiFactorAuthentication|mfa.*required', code, re.IGNORECASE):
                result = self._find_line(lines, r'conditionalAccessPolic', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without MFA enforcement",
                    description="Azure AD Conditional Access policy found but does not require MFA in grant controls.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Add grantControls with requireMultiFactorAuthentication: true in Conditional Access policy"
                ))
            
            # Check for authentication strength (phishing-resistant)
            if not re.search(r'authenticationStrength|phishingResistant', code, re.IGNORECASE):
                result = self._find_line(lines, r'conditionalAccessPolic', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without authentication strength",
                    description="Conditional Access policy does not specify authentication strength. FedRAMP 20x requires phishing-resistant MFA.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Configure authentication strength policy requiring phishing-resistant MFA methods (certificate, FIDO2, Windows Hello for Business)"
                ))
        else:
            # No Conditional Access policy found - critical for Azure AD environments
            if re.search(r'Microsoft\.Web/sites|Microsoft\.App/containerApps|Microsoft\.ApiManagement', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Conditional Access policy for MFA enforcement",
                    description="Azure resources detected but no Conditional Access policy requiring MFA is defined in infrastructure.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Create Azure AD Conditional Access policy: resource conditionalAccessPolicy 'RequireMFA' = { properties: { grantControls: { builtInControls: ['mfa'], operator: 'OR' } } }"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-01 compliance.
        
        Checks:
        - azuread_conditional_access_policy resources requiring MFA
        - Authentication strength configurations
        - Multi-factor authentication enforcement
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Conditional Access policy resources
        has_conditional_access = bool(re.search(r'resource\s+"azuread_conditional_access_policy"|azuread_conditional_access_policy', code, re.IGNORECASE))
        
        if has_conditional_access:
            # Check if MFA is required in grant controls
            if not re.search(r'grant_controls.*require_mfa|built_in_controls.*=.*\[.*"mfa".*\]', code, re.IGNORECASE):
                result = self._find_line(lines, r'azuread_conditional_access_policy', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without MFA enforcement",
                    description="azuread_conditional_access_policy resource found but does not require MFA in grant_controls.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation='Add grant_controls { built_in_controls = ["mfa"] operator = "OR" } to Conditional Access policy'
                ))
            
            # Check for authentication strength
            if not re.search(r'authentication_strength_policy_id|phishing.*resistant', code, re.IGNORECASE):
                result = self._find_line(lines, r'azuread_conditional_access_policy', use_regex=True)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without authentication strength",
                    description="Conditional Access policy does not reference authentication strength policy. FedRAMP 20x requires phishing-resistant MFA.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number = result['line_num'] if result else 0,
                    code_snippet=self._get_snippet(lines, result['line_num'] if result else 0),
                    recommendation="Configure authentication_strength_policy_id requiring phishing-resistant MFA methods (certificate, FIDO2, WHfB)"
                ))
        else:
            # No Conditional Access policy found
            if re.search(r'resource\s+"azurerm_|azurerm_app_service|azurerm_container_app|azurerm_api_management', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Conditional Access policy for MFA enforcement",
                    description="Azure resources detected but no azuread_conditional_access_policy requiring MFA is defined.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation='Create Conditional Access policy: resource "azuread_conditional_access_policy" "require_mfa" { grant_controls { built_in_controls = ["mfa"] } }'
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # EVIDENCE AUTOMATION METHODS
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get evidence automation recommendations for KSI-IAM-01 (Phishing-Resistant MFA).
        
        Returns structured guidance for automating evidence collection demonstrating
        that phishing-resistant MFA is enforced for all user authentication.
        """
        return {
            "ksi_id": self.KSI_ID,
            "ksi_name": self.KSI_NAME,
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": [
                {
                    "service": "Azure AD Sign-in Logs",
                    "purpose": "Track authentication events with MFA details",
                    "configuration": "Enable Azure AD Premium P1/P2 for sign-in logs"
                },
                {
                    "service": "Azure Monitor / Log Analytics",
                    "purpose": "Query and analyze authentication logs",
                    "configuration": "Connect Azure AD logs to Log Analytics workspace"
                },
                {
                    "service": "Azure Blob Storage",
                    "purpose": "Long-term evidence storage (3+ years)",
                    "configuration": "Use immutable storage with legal hold or time-based retention"
                },
                {
                    "service": "Microsoft Graph API",
                    "purpose": "Query Conditional Access policies and authentication methods",
                    "configuration": "Service principal with Policy.Read.All and AuditLog.Read.All permissions"
                }
            ],
            "collection_methods": [
                {
                    "method": "Sign-in Log Analysis",
                    "description": "Query Azure AD sign-in logs to verify MFA usage and authentication methods",
                    "frequency": "Daily",
                    "data_points": [
                        "Authentication methods used (FIDO2, certificate, WHfB)",
                        "MFA success/failure rates",
                        "Users bypassing MFA (if any)",
                        "Authentication strength applied"
                    ]
                },
                {
                    "method": "Conditional Access Policy Audit",
                    "description": "Export and verify Conditional Access policies require phishing-resistant MFA",
                    "frequency": "On-change + weekly verification",
                    "data_points": [
                        "Policy configurations requiring MFA",
                        "Authentication strength requirements",
                        "User/group assignments",
                        "Policy state (enabled/disabled)"
                    ]
                },
                {
                    "method": "Authentication Methods Report",
                    "description": "Track registered authentication methods per user",
                    "frequency": "Weekly",
                    "data_points": [
                        "Users with FIDO2 keys registered",
                        "Users with certificate-based auth",
                        "Users with Windows Hello for Business",
                        "Users without phishing-resistant methods"
                    ]
                }
            ],
            "storage_requirements": {
                "retention_period": "3 years minimum (FedRAMP Moderate)",
                "format": "JSON (structured logs) + CSV (reports)",
                "immutability": "Required - use Azure Blob immutable storage with WORM",
                "encryption": "AES-256 at rest, TLS 1.2+ in transit",
                "estimated_size": "~10-50 MB/day for 1000 users (sign-in logs)"
            },
            "api_integration": {
                "frr_ads_endpoints": [
                    "/evidence/iam-01/signin-logs",
                    "/evidence/iam-01/conditional-access-policies",
                    "/evidence/iam-01/authentication-methods"
                ],
                "authentication": "Azure AD OAuth 2.0 with client credentials",
                "response_format": "JSON with FIPS 140-2 validated signatures",
                "rate_limits": "Follow Microsoft Graph API limits (varies by license)"
            },
            "code_examples": {
                "python": "Uses Azure SDK for Python - query sign-in logs and CA policies",
                "csharp": "Uses Microsoft.Graph SDK - automated evidence collection service",
                "powershell": "Uses Microsoft.Graph PowerShell - scheduled evidence export",
                "kusto": "KQL queries for Log Analytics - sign-in analysis"
            },
            "infrastructure_templates": {
                "bicep": "Deploys Log Analytics workspace, Storage Account, Function App for automation",
                "terraform": "Deploys Azure Monitor, Blob Storage, automation resources"
            },
            "retention_policy": "3 years minimum per FedRAMP Moderate requirements",
            "implementation_effort": "medium",
            "implementation_time": "2-4 weeks",
            "prerequisites": [
                "Azure AD Premium P1 or P2 license",
                "Log Analytics workspace",
                "Service principal with appropriate permissions",
                "Conditional Access policies already configured"
            ],
            "notes": "Evidence automation for KSI-IAM-01 is highly feasible. Azure AD provides comprehensive logging of authentication events including MFA method details. Key evidence: (1) Sign-in logs showing phishing-resistant MFA usage, (2) Conditional Access policies requiring MFA, (3) Authentication methods registered per user."
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get Azure KQL queries for collecting KSI-IAM-01 evidence.
        """
        return [
            {
                "name": "MFA Authentication Methods Used (Last 30 Days)",
                "query_type": "kusto",
                "query": """SigninLogs
| where TimeGenerated > ago(30d)
| where ResultType == 0  // Successful sign-ins
| extend MfaDetail = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| extend AuthenticationMethod = case(
    MfaDetail contains "FIDO2", "FIDO2 Security Key (Phishing-Resistant)",
    MfaDetail contains "Certificate", "Certificate-Based Auth (Phishing-Resistant)",
    MfaDetail contains "WindowsHello", "Windows Hello for Business (Phishing-Resistant)",
    MfaDetail contains "Authenticator", "Microsoft Authenticator (OTP - Not Phishing-Resistant)",
    MfaDetail contains "SMS", "SMS OTP (Not Phishing-Resistant)",
    "Other/Unknown"
)
| summarize SignInCount = count(), UniqueUsers = dcount(UserPrincipalName) by AuthenticationMethod
| extend ComplianceStatus = case(
    AuthenticationMethod contains "Phishing-Resistant", "Compliant",
    "Non-Compliant"
)
| order by SignInCount desc""",
                "data_source": "Log Analytics - SigninLogs",
                "schedule": "daily",
                "output_format": "json",
                "description": "Analyzes sign-in logs to identify which MFA methods are being used and whether they are phishing-resistant"
            },
            {
                "name": "Users Without Phishing-Resistant MFA Registered",
                "query_type": "kusto",
                "query": """// This query requires Azure AD audit logs in Log Analytics
AuditLogs
| where TimeGenerated > ago(1d)
| where OperationName == "User registered security info"
| extend AuthMethod = tostring(parse_json(TargetResources)[0].modifiedProperties)
| extend UserPrincipalName = tostring(parse_json(TargetResources)[0].userPrincipalName)
| extend HasFIDO2 = AuthMethod contains "FIDO2"
| extend HasCert = AuthMethod contains "Certificate"
| extend HasWHfB = AuthMethod contains "WindowsHelloForBusiness"
| extend HasPhishingResistant = HasFIDO2 or HasCert or HasWHfB
| where not(HasPhishingResistant)
| project TimeGenerated, UserPrincipalName, AuthMethod, ComplianceStatus = "Non-Compliant - Missing Phishing-Resistant MFA"
| distinct UserPrincipalName, ComplianceStatus""",
                "data_source": "Log Analytics - AuditLogs",
                "schedule": "weekly",
                "output_format": "json",
                "description": "Identifies users who have not registered phishing-resistant MFA methods"
            },
            {
                "name": "Conditional Access Policy Compliance Check",
                "query_type": "rest_api",
                "query": """GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies
Authorization: Bearer {token}

# Filter for policies requiring MFA
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies?$filter=grantControls/builtInControls/any(c: c eq 'mfa')&$select=displayName,state,grantControls,conditions""",
                "data_source": "Microsoft Graph API",
                "schedule": "on-change + daily verification",
                "output_format": "json",
                "description": "Retrieves all Conditional Access policies requiring MFA to verify enforcement"
            },
            {
                "name": "Authentication Strength Policy Analysis",
                "query_type": "rest_api",
                "query": """GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies
Authorization: Bearer {token}

# Get policy details including allowed authentication methods
GET https://graph.microsoft.com/v1.0/identity/conditionalAccess/authenticationStrength/policies/{id}?$expand=allowedCombinations""",
                "data_source": "Microsoft Graph API",
                "schedule": "weekly",
                "output_format": "json",
                "description": "Analyzes authentication strength policies to verify they require phishing-resistant methods"
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for KSI-IAM-01.
        """
        return [
            {
                "artifact_name": "azure-ad-signin-logs-mfa-summary.json",
                "artifact_type": "log",
                "description": "30-day summary of authentication methods used, showing percentage of phishing-resistant MFA",
                "collection_method": "KQL query against SigninLogs in Log Analytics",
                "format": "json",
                "frequency": "daily",
                "retention": "3 years"
            },
            {
                "artifact_name": "conditional-access-policies-export.json",
                "artifact_type": "config",
                "description": "Export of all Conditional Access policies showing MFA requirements",
                "collection_method": "Microsoft Graph API - GET /identity/conditionalAccess/policies",
                "format": "json",
                "frequency": "on-change + weekly verification",
                "retention": "3 years (retain all historical versions)"
            },
            {
                "artifact_name": "authentication-methods-report.csv",
                "artifact_type": "report",
                "description": "Per-user report showing registered authentication methods and compliance status",
                "collection_method": "Microsoft Graph API - GET /reports/authenticationMethods/userRegistrationDetails",
                "format": "csv",
                "frequency": "weekly",
                "retention": "3 years"
            },
            {
                "artifact_name": "mfa-non-compliant-users.json",
                "artifact_type": "report",
                "description": "List of users without phishing-resistant MFA registered",
                "collection_method": "KQL query against AuditLogs + Graph API",
                "format": "json",
                "frequency": "weekly",
                "retention": "3 years"
            },
            {
                "artifact_name": "authentication-strength-policies.json",
                "artifact_type": "config",
                "description": "Export of authentication strength policies showing required MFA methods",
                "collection_method": "Microsoft Graph API - GET /identity/conditionalAccess/authenticationStrength/policies",
                "format": "json",
                "frequency": "on-change + weekly verification",
                "retention": "3 years"
            }
        ]
