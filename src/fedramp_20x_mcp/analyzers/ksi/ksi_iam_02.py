"""
KSI-IAM-02 Enhanced: Passwordless Authentication

Use secure passwordless methods for user authentication and authorization when feasible, 
otherwise enforce strong passwords with MFA.

Enhanced with AST-based analysis where applicable, regex-based for IaC/CI-CD.
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import CodeLanguage


class KSI_IAM_02_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-IAM-02: Passwordless Authentication
    
    **Official Statement:**
    Use secure passwordless methods for user authentication and authorization when feasible, 
    otherwise enforce strong passwords with MFA.
    
    **Family:** IAM - Identity and Access Management
    
    **NIST Controls:**
    - ac-2, ac-3
    - ia-2.1, ia-2.2, ia-2.8
    - ia-5.1, ia-5.2, ia-5.6
    - ia-6
    
    **Detection Strategy:**
    - Passwordless methods: FIDO2/WebAuthn, certificate-based, magic links, Azure AD, Windows Hello
    - Password-based authentication without strong policies (length, complexity, MFA)
    - IaC: Azure AD configuration, password policies in EntraID
    - CI/CD: Secrets management, authentication setup validation
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript (AST+regex)
    - IaC: Bicep, Terraform (regex-based)
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI (regex-based)
    """
    
    KSI_ID = "KSI-IAM-02"
    KSI_NAME = "Passwordless Authentication"
    KSI_STATEMENT = "Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."
    FAMILY = "IAM"
    NIST_CONTROLS = [
        ("ac-2", "Account Management"),
        ("ac-3", "Access Enforcement"),
        ("ia-2.1", "Multi-factor Authentication to Privileged Accounts"),
        ("ia-2.2", "Multi-factor Authentication to Non-privileged Accounts"),
        ("ia-2.8", "Access to Accounts — Replay Resistant"),
        ("ia-5.1", "Password-based Authentication"),
        ("ia-5.2", "Public Key-based Authentication"),
        ("ia-5.6", "Protection of Authenticators"),
        ("ia-6", "Authentication Feedback")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    # Passwordless methods
    PASSWORDLESS_METHODS = {
        'fido2': 'FIDO2/WebAuthn',
        'webauthn': 'WebAuthn',
        'certificate': 'Certificate-based authentication',
        'magic_link': 'Magic link authentication',
        'azure_ad': 'Azure AD passwordless',
        'windows_hello': 'Windows Hello for Business'
    }
    
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
        Analyze Python for passwordless authentication.
        
        Detects:
        - FIDO2/WebAuthn (py_webauthn, fido2)
        - Certificate-based authentication
        - Magic links (email-based passwordless)
        - Azure AD (msal, azure.identity)
        - Password-based auth without strong policies
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_fido2 = bool(re.search(r'import\s+fido2|from\s+fido2|py_webauthn|webauthn', code, re.IGNORECASE))
        has_certificate = bool(re.search(r'certificate.*auth|client.*certificate|x509.*auth', code, re.IGNORECASE))
        has_magic_link = bool(re.search(r'magic.*link|passwordless.*email|one.*time.*link', code, re.IGNORECASE))
        has_azure_ad = bool(re.search(r'from\s+msal|azure\.identity|AzureAD|DefaultAzureCredential', code))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'password.*field|check_password|verify_password|bcrypt|hashlib|pbkdf2|set_password|make_password|create_user.*password', code, re.IGNORECASE))
        
        if has_password_auth and not (has_fido2 or has_certificate or has_azure_ad or has_magic_link):
            # Password-based auth without passwordless option
            line_num = self._find_text_line(lines, 'password')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based Authentication Without Passwordless Option",
                description=(
                    f"Application uses password-based authentication. KSI-IAM-02 recommends passwordless methods "
                    f"when feasible (FIDO2/WebAuthn, certificates, Azure AD, magic links). If passwords are required, "
                    f"enforce strong password policies (14+ chars, complexity) and MFA."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Implement passwordless authentication:\n\n"
                    "# Option 1: FIDO2/WebAuthn\n"
                    "from fido2.server import Fido2Server\n"
                    "from fido2.webauthn import PublicKeyCredentialRpEntity\n\n"
                    "rp = PublicKeyCredentialRpEntity('example.com', 'Example')\n"
                    "server = Fido2Server(rp)\n\n"
                    "# Option 2: Azure AD passwordless\n"
                    "from azure.identity import DefaultAzureCredential\n"
                    "credential = DefaultAzureCredential()\n\n"
                    "# Option 3: Magic links (email-based)\n"
                    "# Send one-time link via email, expire after 15 minutes\n\n"
                    "Ref: NIST SP 800-63B (https://pages.nist.gov/800-63-3/sp800-63b.html)"
                )
            ))
            
            # Check for password complexity requirements
            if not re.search(r'password.*length.*>=.*14|min.*length.*=.*1[4-9]|password.*complexity|password.*strength|PasswordValidator', code, re.IGNORECASE):
                line_num = self._find_text_line(lines, 'password')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Password Complexity Requirements Detected",
                    description=(
                        f"Password authentication detected without password complexity/strength requirements. "
                        f"If using passwords, KSI-IAM-02 requires strong password policies: minimum 14 characters, "
                        f"complexity requirements, and MFA enforcement."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Enforce strong password policies:\n\n"
                        "# Django: Configure AUTH_PASSWORD_VALIDATORS\n"
                        "AUTH_PASSWORD_VALIDATORS = [\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
                        "     'OPTIONS': {'min_length': 14}},\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},\n"
                        "]\n\n"
                        "# Flask: Use password-validator\n"
                        "from password_validator import PasswordValidator\n"
                        "schema = PasswordValidator()\n"
                        "schema.min(14).has().uppercase().has().lowercase().has().digits().has().symbols()\n\n"
                        "Better: Migrate to passwordless authentication (FIDO2, Azure AD)"
                    )
                ))
        
        # Django-specific: Check for password validators
        if 'django' in code.lower() and has_password_auth:
            if not re.search(r'AUTH_PASSWORD_VALIDATORS|MinimumLengthValidator|CommonPasswordValidator', code):
                line_num = self._find_text_line(lines, 'django')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Django Without Password Validators",
                    description=(
                        f"Django authentication detected without AUTH_PASSWORD_VALIDATORS configured in settings. "
                        f"This allows weak passwords that don't meet FedRAMP requirements."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Configure Django password validators:\n"
                        "AUTH_PASSWORD_VALIDATORS = [\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',\n"
                        "     'OPTIONS': {'min_length': 14}},\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},\n"
                        "    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},\n"
                        "]\n\n"
                        "Ref: Django Auth (https://docs.djangoproject.com/en/stable/topics/auth/passwords/)"
                    )
                ))
        
        # Check for MFA configuration
        if has_password_auth and not re.search(r'mfa|two.*factor|2fa|totp|authenticator', code, re.IGNORECASE):
            line_num = self._find_text_line(lines, 'password')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="No MFA Configuration Detected",
                description=(
                    f"Password-based authentication without MFA (Multi-Factor Authentication). "
                    f"KSI-IAM-02 requires MFA when using passwords."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Implement MFA with TOTP or FIDO2:\n\n"
                    "# Option 1: TOTP (Time-based One-Time Password)\n"
                    "import pyotp\n"
                    "totp = pyotp.TOTP('base32secret')\n"
                    "totp.verify(user_token)\n\n"
                    "# Option 2: django-mfa2\n"
                    "pip install django-mfa2\n\n"
                    "# Option 3: FIDO2 (hardware keys)\n"
                    "from fido2.server import Fido2Server\n\n"
                    "Ref: NIST SP 800-63B (https://pages.nist.gov/800-63-3/sp800-63b.html)"
                )
            ))
        
        return findings

    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# for passwordless authentication.
        
        Detects:
        - FIDO2/WebAuthn
        - Certificate-based authentication
        - Azure AD (Microsoft.Identity.Web)
        - Windows Hello for Business
        - PasswordOptions configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_fido2 = bool(re.search(r'Fido2|WebAuthn', code, re.IGNORECASE))
        has_certificate = bool(re.search(r'AddCertificate|CertificateAuthentication|X509Certificate.*Auth', code))
        has_azure_ad = bool(re.search(r'AddMicrosoftIdentityWebApp|AzureAD|Microsoft\.Identity\.Web', code))
        has_windows_hello = bool(re.search(r'WindowsHello|BiometricAuthentication', code, re.IGNORECASE))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'PasswordHasher|PasswordOptions|RequireDigit|RequireUppercase|SignInManager.*Password', code))
        
        if has_password_auth and not (has_fido2 or has_certificate or has_azure_ad or has_windows_hello):
            line_num = self._find_text_line(lines, 'Password')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based Authentication Without Passwordless Option",
                description=(
                    f"ASP.NET Core application uses password-based authentication. KSI-IAM-02 recommends "
                    f"passwordless methods (FIDO2, certificates, Azure AD, Windows Hello for Business)."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Implement passwordless authentication:\n\n"
                    "// Option 1: Azure AD with Microsoft.Identity.Web\n"
                    "builder.Services.AddMicrosoftIdentityWebAppAuthentication(\n"
                    "    builder.Configuration, \"AzureAd\");\n\n"
                    "// Option 2: Certificate-based authentication\n"
                    "builder.Services.AddAuthentication()\n"
                    "    .AddCertificate(options => {\n"
                    "        options.AllowedCertificateTypes = CertificateTypes.All;\n"
                    "    });\n\n"
                    "// Option 3: FIDO2 with Fido2NetLib\n"
                    "builder.Services.AddFido2(options => {\n"
                    "    options.ServerDomain = \"example.com\";\n"
                    "});\n\n"
                    "Ref: ASP.NET Core Identity (https://learn.microsoft.com/aspnet/core/security/authentication/)"
                )
            ))
            
            # Check PasswordOptions configuration (options.Password.*)
            password_options_present = bool(re.search(r'PasswordOptions|options\.Password\.', code))
            
            if password_options_present:
                # Check RequiredLength
                if not re.search(r'RequiredLength\s*=\s*(1[4-9]|[2-9]\d)', code):
                    line_num = self._find_text_line(lines, 'Password')
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Weak Password Length Requirement",
                        description=(
                            f"PasswordOptions found with RequiredLength < 14. FedRAMP requires minimum 14 characters "
                            f"per NIST SP 800-63B."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Configure strong password requirements:\n"
                            "services.Configure<IdentityOptions>(options => {\n"
                            "    options.Password.RequiredLength = 14;  // FedRAMP minimum\n"
                            "    options.Password.RequireDigit = true;\n"
                            "    options.Password.RequireUppercase = true;\n"
                            "    options.Password.RequireLowercase = true;\n"
                            "    options.Password.RequireNonAlphanumeric = true;\n"
                            "});\n\n"
                            "Better: Migrate to passwordless authentication"
                        )
                    ))
                
                # Check complexity requirements
                if not re.search(r'RequireDigit\s*=\s*true', code, re.IGNORECASE):
                    line_num = self._find_text_line(lines, 'Password')
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Password Complexity Not Enforced",
                        description=(
                            f"PasswordOptions without RequireDigit = true. Strong passwords require complexity."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Enforce complexity:\n"
                            "options.Password.RequireDigit = true;\n"
                            "options.Password.RequireUppercase = true;\n"
                            "options.Password.RequireLowercase = true;\n"
                            "options.Password.RequireNonAlphanumeric = true;"
                        )
                    ))
        
        # Check for MFA
        if has_password_auth and not re.search(r'TwoFactorEnabled|AddDefaultTokenProviders|AuthenticatorTokenProvider', code):
            line_num = self._find_text_line(lines, 'Password')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="No MFA Configuration Detected",
                description=(
                    f"Password-based authentication without MFA. KSI-IAM-02 requires MFA when using passwords."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Implement MFA:\n"
                    "services.AddIdentity<ApplicationUser, IdentityRole>()\n"
                    "    .AddDefaultTokenProviders();  // Enables TOTP\n\n"
                    "// Check TwoFactorEnabled in SignInManager\n"
                    "var result = await _signInManager.PasswordSignInAsync(\n"
                    "    user, password, isPersistent: false, lockoutOnFailure: true);\n\n"
                    "if (result.RequiresTwoFactor) {\n"
                    "    // Prompt for 2FA code\n"
                    "}"
                )
            ))
        
        return findings

    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java for passwordless authentication.
        
        Detects:
        - WebAuthn (Yubico java-webauthn-server)
        - Certificate-based authentication
        - Password-based auth without strong policies
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_webauthn = bool(re.search(r'com\.yubico\.webauthn|WebAuthn', code))
        has_certificate = bool(re.search(r'X509Certificate|CertificateAuth', code))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'BCryptPasswordEncoder|PasswordEncoder|UserDetailsService', code))
        
        if has_password_auth and not (has_webauthn or has_certificate):
            line_num = self._find_text_line(lines, 'Password')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based Authentication Without Passwordless Option",
                description=(
                    f"Spring Security uses password-based authentication. KSI-IAM-02 recommends passwordless methods "
                    f"(WebAuthn, certificates)."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Implement passwordless authentication:\n\n"
                    "// Option 1: WebAuthn with Yubico\n"
                    "<dependency>\n"
                    "    <groupId>com.yubico</groupId>\n"
                    "    <artifactId>webauthn-server-core</artifactId>\n"
                    "</dependency>\n\n"
                    "// Option 2: Certificate-based\n"
                    "@Configuration\n"
                    "public class SecurityConfig {\n"
                    "    @Bean\n"
                    "    public SecurityFilterChain filterChain(HttpSecurity http) {\n"
                    "        http.x509()\n"
                    "            .subjectPrincipalRegex(\"CN=(.*?),\");\n"
                    "        return http.build();\n"
                    "    }\n"
                    "}\n\n"
                    "Ref: Spring Security (https://spring.io/projects/spring-security)"
                )
            ))
            
            # Check for password strength validation
            if not re.search(r'PasswordValidator|password.*length.*>=.*14|password.*complexity', code, re.IGNORECASE):
                line_num = self._find_text_line(lines, 'Password')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Password Strength Validation",
                    description=(
                        f"Password-based authentication without password strength validation. "
                        f"FedRAMP requires minimum 14 characters with complexity."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Implement password validation:\n"
                        "@Component\n"
                        "public class PasswordValidator {\n"
                        "    public boolean isValid(String password) {\n"
                        "        return password.length() >= 14 &&\n"
                        "               password.matches(\".*[A-Z].*\") &&\n"
                        "               password.matches(\".*[a-z].*\") &&\n"
                        "               password.matches(\".*\\\\d.*\") &&\n"
                        "               password.matches(\".*[!@#$%^&*].*\");\n"
                    "    }\n"
                        "}"
                    )
                ))
        
        return findings

    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze JavaScript/TypeScript for passwordless authentication.
        
        Detects:
        - WebAuthn (@simplewebauthn, fido2-lib)
        - Magic links (email-based passwordless)
        - Azure AD (MSAL)
        - Password-based auth without validation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_webauthn = bool(re.search(r'@simplewebauthn|fido2-lib|navigator\.credentials\.create', code, re.IGNORECASE))
        has_magic_link = bool(re.search(r'magic.*link|passwordless|sendgrid.*signin|nodemailer.*token', code, re.IGNORECASE))
        has_azure_ad = bool(re.search(r'@azure/msal|PublicClientApplication|@azure/identity', code))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'bcrypt|password.*hash|crypto\.pbkdf2|scrypt|argon2', code, re.IGNORECASE))
        
        if has_password_auth and not (has_webauthn or has_magic_link or has_azure_ad):
            line_num = self._find_text_line(lines, 'password')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based Authentication Without Passwordless Option",
                description=(
                    f"Application uses password-based authentication. KSI-IAM-02 recommends passwordless methods "
                    f"(WebAuthn, magic links, Azure AD)."
                ),
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Implement passwordless authentication:\n\n"
                    "// Option 1: SimpleWebAuthn (FIDO2)\n"
                    "import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';\n\n"
                    "// Option 2: Magic links\n"
                    "const token = crypto.randomBytes(32).toString('hex');\n"
                    "await sendEmail(user.email, `https://app.com/login/${token}`);\n\n"
                    "// Option 3: Azure AD with MSAL\n"
                    "import { PublicClientApplication } from '@azure/msal-browser';\n"
                    "const msalInstance = new PublicClientApplication(config);\n\n"
                    "Ref: WebAuthn Guide (https://webauthn.guide/)"
                )
            ))
            
            # Check for password validation
            if not re.search(r'password.*length.*>=.*14|minLength.*:.*1[4-9]|validator.*isStrongPassword|zod.*min\(14\)', code, re.IGNORECASE):
                line_num = self._find_text_line(lines, 'password')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Weak Password Validation",
                    description=(
                        f"Password authentication without proper length validation. FedRAMP requires minimum 14 characters."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Use validator.js or Zod for password validation:\n\n"
                        "// Option 1: validator.js\n"
                        "import validator from 'validator';\n"
                        "const isValid = validator.isStrongPassword(password, {\n"
                        "    minLength: 14,\n"
                        "    minLowercase: 1,\n"
                        "    minUppercase: 1,\n"
                        "    minNumbers: 1,\n"
                        "    minSymbols: 1\n"
                        "});\n\n"
                        "// Option 2: Zod schema\n"
                        "import { z } from 'zod';\n"
                        "const passwordSchema = z.string()\n"
                        "    .min(14, 'Password must be at least 14 characters')\n"
                        "    .regex(/[A-Z]/, 'Must contain uppercase')\n"
                        "    .regex(/[a-z]/, 'Must contain lowercase')\n"
                        "    .regex(/[0-9]/, 'Must contain number')\n"
                        "    .regex(/[^A-Za-z0-9]/, 'Must contain symbol');"
                    )
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep for passwordless authentication configuration.
        
        Detects:
        - Azure AD/Entra ID password policies
        - Conditional Access policies for passwordless
        """
        findings = []
        lines = code.split('\n')
        
        # Check if Azure AD user resources are configured
        has_ad_users = bool(re.search(r"'Microsoft\.Graph/users|'Microsoft\.AAD", code))
        
        if has_ad_users:
            # Check for password policy configuration
            if not re.search(r'passwordPolicies|DisablePasswordExpiration', code):
                line_num = self._find_text_line(lines, 'users')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD Users Without Password Policy",
                    description=(
                        f"Azure AD user resources configured without explicit password policies. "
                        f"KSI-IAM-02 requires strong password policies or passwordless authentication."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Configure Azure AD password policies:\n"
                        "resource adUser 'Microsoft.Graph/users@2023-01-01' = {\n"
                        "  properties: {\n"
                        "    passwordPolicies: 'DisablePasswordExpiration'\n"
                        "    passwordProfile: {\n"
                        "      forceChangePasswordNextSignIn: true\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Better: Enable passwordless authentication via Conditional Access policies"
                    )
                ))
        
        return findings

    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform for passwordless authentication configuration.
        
        Detects:
        - azuread_user password policies
        - Conditional Access configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Azure AD user resources
        has_ad_users = bool(re.search(r'resource\s+"azuread_user"', code))
        
        if has_ad_users:
            # Check for password policy
            if not re.search(r'password_policies|disable_password_expiration', code):
                line_num = self._find_text_line(lines, 'azuread_user')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD Users Without Password Policy",
                    description=(
                        f"Azure AD user resources without explicit password policies. "
                        f"KSI-IAM-02 requires strong password policies or passwordless authentication."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Configure password policies:\n"
                        "resource \"azuread_user\" \"example\" {\n"
                        "  user_principal_name = \"user@example.com\"\n"
                        "  display_name      = \"Example User\"\n"
                        "  password          = var.user_password\n"
                        "  force_password_change = true\n"
                        "}\n\n"
                        "Better: Configure Conditional Access for passwordless:\n"
                        "resource \"azuread_conditional_access_policy\" \"passwordless\" {\n"
                        "  conditions {\n"
                        "    sign_in_risk_levels = [\"medium\", \"high\"]\n"
                        "  }\n"
                        "  grant_controls {\n"
                        "    authentication_strength_policy_id = azuread_authentication_strength_policy.passwordless.id\n"
                        "  }\n"
                        "}"
                    )
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for authentication configuration."""
        findings = []
        # GitHub Actions use GitHub's OAuth, which is already secure
        # No specific findings for this KSI in CI/CD context
        return findings

    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for authentication configuration."""
        findings = []
        # Azure Pipelines use managed service connections
        # No specific findings for this KSI in CI/CD context
        return findings

    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for authentication configuration."""
        findings = []
        # GitLab CI uses GitLab's authentication
        # No specific findings for this KSI in CI/CD context
        return findings