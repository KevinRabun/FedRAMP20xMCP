"""
KSI-IAM-02: Passwordless Authentication

Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_IAM_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-IAM-02: Passwordless Authentication
    
    **Official Statement:**
    Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA.
    
    **Family:** IAM - Identity and Access Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2
    - ac-3
    - ia-2.1
    - ia-2.2
    - ia-2.8
    - ia-5.1
    - ia-5.2
    - ia-5.6
    - ia-6
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use secure passwordless methods for user authentication and authorization when feasible, otherwise e...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-IAM-02"
    KSI_NAME = "Passwordless Authentication"
    KSI_STATEMENT = """Use secure passwordless methods for user authentication and authorization when feasible, otherwise enforce strong passwords with MFA."""
    FAMILY = "IAM"
    FAMILY_NAME = "Identity and Access Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2", "ac-3", "ia-2.1", "ia-2.2", "ia-2.8", "ia-5.1", "ia-5.2", "ia-5.6", "ia-6"]
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
        Analyze Python code for KSI-IAM-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Patterns Detected:
        - Passwordless methods: FIDO2/WebAuthn, certificate-based, magic links, Azure AD
        - Password-based authentication (should have strong password policies + MFA)
        - Weak password configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless authentication methods
        has_fido2 = bool(re.search(r'import\s+fido2|from\s+fido2|webauthn', code, re.IGNORECASE))
        has_certificate = bool(re.search(r'certificate.*auth|client.*certificate|x509', code, re.IGNORECASE))
        has_magic_link = bool(re.search(r'magic.*link|passwordless.*email|one.*time.*link', code, re.IGNORECASE))
        has_azure_ad = bool(re.search(r'from\s+msal|azure\.identity|AzureAD', code, re.IGNORECASE))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'password.*field|check_password|verify_password|bcrypt|hashlib|pbkdf2', code, re.IGNORECASE))
        
        if has_password_auth and not (has_fido2 or has_certificate or has_azure_ad):
            # Password-based auth without passwordless option
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based authentication without passwordless option",
                description="Application uses password-based authentication. KSI-IAM-02 recommends passwordless methods when feasible (FIDO2, certificates, Azure AD).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'password|bcrypt|hashlib'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'password|bcrypt')),
                recommendation="Implement passwordless authentication: py_webauthn (FIDO2), Azure AD with Conditional Access, or certificate-based authentication"
            ))
            
            # Check for password complexity requirements
            if not re.search(r'password.*length|min.*length.*=.*\d+|password.*complexity|password.*strength', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No password complexity requirements detected",
                    description="Password authentication detected without password complexity/strength requirements. If using passwords, enforce strong password policies.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'password'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'password')),
                    recommendation="Enforce strong passwords: min 14 chars, complexity requirements, and MFA. Better: migrate to passwordless authentication."
                ))
        
        # Check Django password validators
        if 'django' in code.lower() and has_password_auth:
            if not re.search(r'AUTH_PASSWORD_VALIDATORS|MinimumLengthValidator|CommonPasswordValidator', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Django without password validators",
                    description="Django authentication detected without AUTH_PASSWORD_VALIDATORS configured.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'django'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'django')),
                    recommendation="Configure AUTH_PASSWORD_VALIDATORS with MinimumLengthValidator (14+), CommonPasswordValidator, and NumericPasswordValidator"
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Patterns Detected:
        - Passwordless: FIDO2, certificate authentication, Azure AD, Windows Hello
        - Password-based authentication (should have strong policies + MFA)
        - PasswordOptions configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_fido2 = bool(re.search(r'Fido2|WebAuthn', code, re.IGNORECASE))
        has_certificate = bool(re.search(r'AddCertificate|CertificateAuthentication|X509Certificate', code))
        has_azure_ad = bool(re.search(r'AddMicrosoftIdentityWebApp|AzureAD|Microsoft\.Identity', code))
        has_windows_hello = bool(re.search(r'WindowsHello|BiometricAuthentication', code, re.IGNORECASE))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'PasswordHasher|PasswordOptions|RequireDigit|RequireUppercase', code))
        
        if has_password_auth and not (has_fido2 or has_certificate or has_azure_ad or has_windows_hello):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based authentication without passwordless option",
                description="Application uses password-based authentication. KSI-IAM-02 recommends passwordless methods (FIDO2, certificates, Azure AD, Windows Hello).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'PasswordHasher|PasswordOptions'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'PasswordHasher|PasswordOptions')),
                recommendation="Implement passwordless: FIDO2 WebAuthn, certificate-based auth, or Azure AD with Windows Hello for Business"
            ))
            
            # Check PasswordOptions configuration
            if re.search(r'PasswordOptions', code):
                if not re.search(r'RequiredLength\s*=\s*(1[4-9]|[2-9]\d)', code):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Weak password length requirement",
                        description="PasswordOptions found with RequiredLength < 14. FedRAMP requires minimum 14 characters.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=self._find_line(lines, r'PasswordOptions'),
                        code_snippet=self._get_snippet(lines, self._find_line(lines, r'PasswordOptions')),
                        recommendation="Set RequiredLength = 14 or higher, or migrate to passwordless authentication"
                    ))
                
                if not re.search(r'RequireDigit\s*=\s*true', code, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Password complexity not enforced",
                        description="PasswordOptions without RequireDigit = true. Strong passwords require complexity.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=self._find_line(lines, r'PasswordOptions'),
                        code_snippet=self._get_snippet(lines, self._find_line(lines, r'PasswordOptions')),
                        recommendation="Configure: RequireDigit = true, RequireUppercase = true, RequireLowercase = true, RequireNonAlphanumeric = true"
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Patterns Detected:
        - Passwordless: WebAuthn, certificate authentication, Azure AD
        - Password-based: PasswordEncoder, BCrypt (should have strong policies)
        - Password validation rules
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_webauthn = bool(re.search(r'import.*webauthn4j|import.*yubico.*webauthn', code, re.IGNORECASE))
        has_certificate = bool(re.search(r'X509AuthenticationFilter|CertificateAuthentication', code))
        has_azure_ad = bool(re.search(r'azure-spring-boot-starter-active-directory|AzureActiveDirectory', code))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'PasswordEncoder|BCryptPasswordEncoder|password.*validation', code, re.IGNORECASE))
        
        if has_password_auth and not (has_webauthn or has_certificate or has_azure_ad):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based authentication without passwordless option",
                description="Application uses password-based authentication. KSI-IAM-02 recommends passwordless methods (WebAuthn, certificates, Azure AD).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'PasswordEncoder|BCrypt'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'PasswordEncoder')),
                recommendation="Implement passwordless: WebAuthn4J, Yubico WebAuthn, or Azure AD Spring Boot integration"
            ))
            
            # Check for password validation
            if not re.search(r'@Size.*min.*=.*(1[4-9]|[2-9]\d)|password.*length.*>=.*14', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Weak password length validation",
                    description="Password authentication detected without minimum length validation (14+ chars required).",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'PasswordEncoder'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'PasswordEncoder')),
                    recommendation="Add password validation: @Size(min = 14) or use Spring Security password complexity rules"
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Patterns Detected:
        - Passwordless: WebAuthn, magic links, Azure AD, OAuth without password
        - Password-based: bcrypt, password hashing (should have validation)
        - Password strength validation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for passwordless methods
        has_webauthn = bool(re.search(r'@simplewebauthn|fido2-lib|navigator\.credentials', code, re.IGNORECASE))
        has_magic_link = bool(re.search(r'magic.*link|passwordless|sendgrid.*signin|nodemailer.*token', code, re.IGNORECASE))
        has_azure_ad = bool(re.search(r'@azure/msal|PublicClientApplication', code))
        
        # Check for password-based authentication
        has_password_auth = bool(re.search(r'bcrypt|password.*hash|crypto\.pbkdf2|scrypt', code, re.IGNORECASE))
        
        if has_password_auth and not (has_webauthn or has_magic_link or has_azure_ad):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password-based authentication without passwordless option",
                description="Application uses password-based authentication. KSI-IAM-02 recommends passwordless methods (WebAuthn, magic links, Azure AD).",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'bcrypt|password.*hash'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'bcrypt|password')),
                recommendation="Implement passwordless: @simplewebauthn/server (FIDO2), magic links via email, or Azure AD/MSAL"
            ))
            
            # Check for password validation
            if not re.search(r'password.*length.*>=.*14|minLength.*:.*1[4-9]|validator.*isStrongPassword', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Weak password validation",
                    description="Password authentication without proper length validation (14+ chars required).",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'password'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'password')),
                    recommendation="Use validator.js isStrongPassword() or enforce minLength: 14, requireUppercase, requireLowercase, requireNumbers, requireSymbols"
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-IAM-02 compliance.
        
        Checks:
        - Azure AD authentication methods (passwordless: FIDO2, WHfB, certificate)
        - Password policies in Azure AD
        - Authentication strength policies
        """
        findings = []
        lines = code.split('\n')
        
        # Check for authentication strength policies (passwordless)
        has_auth_strength = bool(re.search(r'authenticationStrengthPolicy|passwordless', code, re.IGNORECASE))
        
        # Check for password policies
        has_password_policy = bool(re.search(r'passwordPolicy|passwordRules', code, re.IGNORECASE))
        
        if has_password_policy and not has_auth_strength:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password policy without passwordless authentication strength",
                description="Password policy configured but no authentication strength policy for passwordless methods.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'passwordPolicy'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'passwordPolicy')),
                recommendation="Configure authentication strength policy requiring passwordless methods: FIDO2, Windows Hello for Business, or certificate-based"
            ))
        
        # Check for Conditional Access with authentication strength
        if re.search(r'conditionalAccessPolicy', code, re.IGNORECASE):
            if not re.search(r'authenticationStrength|phishingResistant', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access without authentication strength requirement",
                    description="Conditional Access policy without authentication strength requirement for passwordless methods.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'conditionalAccessPolicy'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'conditionalAccessPolicy')),
                    recommendation="Reference authentication strength policy requiring passwordless authentication"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-IAM-02 compliance.
        
        Checks:
        - Azure AD authentication methods and strength policies
        - Password policies
        - Conditional Access requiring passwordless
        """
        findings = []
        lines = code.split('\n')
        
        # Check for authentication strength policies
        has_auth_strength = bool(re.search(r'azuread_authentication_strength_policy|passwordless', code, re.IGNORECASE))
        
        # Check for password policies
        has_password_policy = bool(re.search(r'password_policy', code, re.IGNORECASE))
        
        if has_password_policy and not has_auth_strength:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Password policy without passwordless authentication strength",
                description="Password policy configured but no authentication strength policy for passwordless methods.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'password_policy'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'password_policy')),
                recommendation="Create azuread_authentication_strength_policy requiring passwordless: FIDO2, Windows Hello for Business, certificate-based"
            ))
        
        # Check Conditional Access with authentication strength
        if re.search(r'azuread_conditional_access_policy', code):
            if not re.search(r'authentication_strength_policy_id|passwordless', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access without authentication strength",
                    description="Conditional Access policy without authentication strength requirement for passwordless methods.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azuread_conditional_access_policy'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azuread_conditional_access_policy')),
                    recommendation="Reference authentication_strength_policy_id requiring passwordless authentication"
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-IAM-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-IAM-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-IAM-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> int:
        """Find line number matching regex pattern."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, 1):
                if regex.search(line):
                    return i
        except re.error:
            # Fallback to substring search if regex fails
            for i, line in enumerate(lines, 1):
                if pattern.lower() in line.lower():
                    return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0 or line_number > len(lines):
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
