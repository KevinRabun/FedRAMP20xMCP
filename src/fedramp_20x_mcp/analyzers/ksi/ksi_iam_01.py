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
    NIST_CONTROLS = ["ac-2", "ia-2", "ia-2.1", "ia-2.2", "ia-2.8", "ia-5", "ia-8", "sc-23"]
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
        Analyze Python code for KSI-IAM-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Patterns Detected:
        - Django MFA configuration (django-mfa3, django-otp, django-two-factor-auth)
        - Flask MFA implementation (Flask-Two-Factor)
        - FastAPI MFA middleware
        - Azure AD B2C MFA configuration
        - FIDO2/WebAuthn implementation (phishing-resistant)
        - TOTP/SMS-based MFA (less secure, flagged as warning)
        """
        findings = []
        lines = code.split('\n')
        
        # Check for phishing-resistant MFA methods (FIDO2, WebAuthn, certificate-based)
        has_fido2 = bool(re.search(r'import\s+fido2|from\s+fido2', code, re.IGNORECASE))
        has_webauthn = bool(re.search(r'import\s+webauthn|from\s+webauthn', code, re.IGNORECASE))
        has_certificate_auth = bool(re.search(r'certificate.*auth|client.*certificate', code, re.IGNORECASE))
        
        # Check for less secure MFA methods (TOTP, SMS)
        has_totp = bool(re.search(r'import\s+pyotp|from\s+pyotp|totp', code, re.IGNORECASE))
        has_sms_mfa = bool(re.search(r'sms.*mfa|twilio.*verify|send.*sms.*code', code, re.IGNORECASE))
        
        # Check Django MFA configurations
        django_mfa_found = False
        if 'django' in code.lower():
            # Check for django-otp
            if re.search(r'from\s+django_otp|import\s+django_otp|\'django_otp\'', code):
                django_mfa_found = True
                # Check if FIDO2/WebAuthn device is configured
                if not re.search(r'TOTPDevice|WebAuthnDevice|U2FDevice', code):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Django OTP without phishing-resistant device",
                        description="django-otp is configured but no phishing-resistant device (WebAuthn, U2F) is detected. Consider using WebAuthnDevice or U2FDevice instead of TOTPDevice for phishing-resistant MFA.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=self._find_line(lines, r'django_otp'),
                        code_snippet=self._get_snippet(lines, r'django_otp'),
                        recommendation="Configure WebAuthnDevice or U2FDevice in django-otp: from django_otp.plugins.otp_webauthn.models import WebAuthnDevice"
                    ))
            
            # Check for django-mfa3 or django-two-factor-auth
            if re.search(r'django.mfa|django_two_factor', code):
                django_mfa_found = True
        
        # Check Flask MFA
        flask_mfa_found = False
        if 'flask' in code.lower():
            if re.search(r'from\s+flask_security|import\s+flask_security', code):
                flask_mfa_found = True
                # Check if MFA is enforced
                if not re.search(r'SECURITY_TWO_FACTOR\s*=\s*True|@two_factor_required', code):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Flask-Security MFA not enforced",
                        description="Flask-Security is present but SECURITY_TWO_FACTOR is not set to True or @two_factor_required decorator is not used.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=self._find_line(lines, r'flask_security'),
                        code_snippet=self._get_snippet(lines, r'flask_security'),
                        recommendation="Enable MFA: SECURITY_TWO_FACTOR = True and SECURITY_TWO_FACTOR_REQUIRED = True"
                    ))
        
        # Check FastAPI MFA
        if 'fastapi' in code.lower():
            if re.search(r'from\s+fastapi|import\s+fastapi', code):
                # Check for MFA dependencies or middleware
                if not (has_fido2 or has_webauthn or re.search(r'mfa.*middleware|auth.*middleware', code, re.IGNORECASE)):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="FastAPI missing MFA middleware",
                        description="FastAPI application detected without MFA middleware or FIDO2/WebAuthn implementation.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=self._find_line(lines, r'FastAPI'),
                        code_snippet=self._get_snippet(lines, r'FastAPI'),
                        recommendation="Implement MFA middleware with FIDO2/WebAuthn or integrate with Azure AD B2C for phishing-resistant MFA"
                    ))
        
        # Check Azure AD B2C configuration
        if re.search(r'msal|azure.*identity|azure.*ad', code, re.IGNORECASE):
            # Check if MFA is enforced in configuration
            if not re.search(r'require.*mfa|enforce.*mfa|conditional.*access', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD configuration missing MFA enforcement",
                    description="Azure AD/MSAL authentication detected but MFA enforcement not configured. Azure AD Conditional Access should require MFA for all users.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'msal|azure.*identity'),
                    code_snippet=self._get_snippet(lines, r'msal|azure.*identity'),
                    recommendation="Configure Azure AD Conditional Access policy to require phishing-resistant MFA (certificate-based, FIDO2, or Windows Hello for Business)"
                ))
        
        # Warn about non-phishing-resistant MFA methods
        if has_totp and not (has_fido2 or has_webauthn or has_certificate_auth):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="Time-based One-Time Password (TOTP) MFA is vulnerable to phishing attacks. FedRAMP 20x requires phishing-resistant MFA methods.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'pyotp|totp'),
                code_snippet=self._get_snippet(lines, r'pyotp|totp'),
                recommendation="Migrate to phishing-resistant MFA: FIDO2 (py_webauthn), WebAuthn, or certificate-based authentication"
            ))
        
        if has_sms_mfa:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS-based MFA is vulnerable to SIM swapping and phishing attacks. FedRAMP 20x requires phishing-resistant MFA methods.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=self._find_line(lines, r'sms.*mfa|twilio.*verify'),
                code_snippet=self._get_snippet(lines, r'sms.*mfa|twilio.*verify'),
                recommendation="Replace SMS MFA with phishing-resistant methods: FIDO2, WebAuthn, or certificate-based authentication"
            ))
        
        # Check if ANY MFA is implemented
        any_mfa = django_mfa_found or flask_mfa_found or has_fido2 or has_webauthn or has_totp or has_sms_mfa
        if not any_mfa and re.search(r'@app\.route|@login|def\s+login|class.*Login', code):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="No MFA implementation detected",
                description="Login functionality detected without any multi-factor authentication implementation. KSI-IAM-01 requires phishing-resistant MFA for all user authentication.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=self._find_line(lines, r'@app\.route.*login|def\s+login'),
                code_snippet=self._get_snippet(lines, r'@app\.route.*login|def\s+login'),
                recommendation="Implement phishing-resistant MFA using FIDO2 (py_webauthn), WebAuthn, or integrate with Azure AD Conditional Access"
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-IAM-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Patterns Detected:
        - ASP.NET Core Identity MFA configuration
        - Azure AD authentication with MFA enforcement
        - Certificate-based authentication
        - FIDO2/WebAuthn implementation
        - SMS/Email MFA (non-phishing-resistant, flagged)
        """
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
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="ASP.NET Core Identity MFA not enforced",
                    description="ASP.NET Core Identity is configured but MFA is not enforced. SignInOptions should set RequireTwoFactor = true.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'AddIdentity'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'AddIdentity')),
                    recommendation="Configure MFA enforcement: services.Configure<IdentityOptions>(options => { options.SignIn.RequireTwoFactor = true; });"
                ))
            
            # Check for phishing-resistant token providers
            if not (has_certificate_auth or has_fido2):
                if has_email_mfa or has_sms_mfa:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="ASP.NET Core Identity using non-phishing-resistant MFA",
                        description="Email or SMS token providers detected. These are vulnerable to phishing. FedRAMP 20x requires phishing-resistant MFA.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=self._find_line(lines, r'EmailTokenProvider|PhoneNumberTokenProvider'),
                        code_snippet=self._get_snippet(lines, self._find_line(lines, r'EmailTokenProvider|PhoneNumberTokenProvider')),
                        recommendation="Implement FIDO2/WebAuthn or certificate-based authentication instead of email/SMS tokens"
                    ))
        
        # Check Azure AD/Entra ID configuration
        if re.search(r'Microsoft\.Identity\.Web|AddMicrosoftIdentityWebApp|AzureAD', code):
            if not re.search(r'ConditionalAccess|RequireMfa|ClaimsPrincipal.*amr.*mfa', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD authentication without MFA validation",
                    description="Azure AD authentication configured but no validation of MFA claim (amr claim) or Conditional Access enforcement detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'AddMicrosoftIdentityWebApp'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'AddMicrosoftIdentityWebApp')),
                    recommendation="Validate MFA claim: if (!User.Claims.Any(c => c.Type == \"amr\" && c.Value == \"mfa\")) { return Challenge(); }"
                ))
        
        # Check for any authentication without MFA
        if re.search(r'\[Authorize\]|UseAuthentication\(\)', code) and not aspnet_identity_found:
            if not (has_certificate_auth or has_fido2 or re.search(r'AddMicrosoftIdentityWebApp', code)):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Authentication without MFA implementation",
                    description="Authorization is configured but no MFA implementation detected.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'\[Authorize\]|UseAuthentication'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'\[Authorize\]|UseAuthentication')),
                    recommendation="Implement phishing-resistant MFA: ASP.NET Core Identity with FIDO2, Azure AD with Conditional Access, or certificate-based authentication"
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-IAM-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Patterns Detected:
        - Spring Security MFA configuration
        - Custom authentication providers with MFA
        - Azure AD Spring Boot integration
        - FIDO2/WebAuthn implementation (phishing-resistant)
        - TOTP/SMS-based MFA (non-phishing-resistant, flagged)
        """
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
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Spring Security without MFA enforcement",
                    description="Spring Security is configured but no MFA enforcement filter or configuration is detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'@EnableWebSecurity'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'@EnableWebSecurity')),
                    recommendation="Implement MFA filter: create a TwoFactorAuthenticationFilter with phishing-resistant methods"
                ))
        
        # Check Azure AD Spring Boot integration
        if re.search(r'azure-spring-boot-starter-active-directory|AzureActiveDirectoryB2CAutoConfiguration', code):
            if not re.search(r'conditionalAccess|amr.*claim.*mfa|validateMfa', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Azure AD integration without MFA validation",
                    description="Azure AD authentication configured but no validation of MFA claims or Conditional Access configuration detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azure-spring-boot-starter'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azure-spring-boot-starter')),
                    recommendation="Validate MFA claim from Azure AD token or configure Azure AD Conditional Access"
                ))
        
        # Warn about non-phishing-resistant MFA
        if has_totp and not (has_fido2 or has_certificate_auth):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="TOTP is vulnerable to phishing attacks. FedRAMP 20x requires phishing-resistant MFA.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'GoogleAuthenticator|totp'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'GoogleAuthenticator|totp')),
                recommendation="Migrate to phishing-resistant MFA: WebAuthn4J (FIDO2) or certificate-based authentication"
            ))
        
        if has_sms_mfa:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS-based MFA is vulnerable to SIM swapping and phishing attacks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=self._find_line(lines, r'sendSms.*verification|Twilio'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'sendSms.*verification|Twilio')),
                recommendation="Replace SMS MFA with WebAuthn4J (FIDO2) or certificate-based authentication"
            ))
        
        # Check if authentication exists without MFA
        if spring_security_found and not (has_fido2 or has_certificate_auth or has_totp or has_sms_mfa):
            if not re.search(r'azure-spring-boot-starter-active-directory', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No MFA implementation detected",
                    description="Spring Security authentication configured but no MFA implementation detected.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'@EnableWebSecurity'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'@EnableWebSecurity')),
                    recommendation="Implement phishing-resistant MFA using WebAuthn4J (FIDO2) or integrate with Azure AD Conditional Access"
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-IAM-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Patterns Detected:
        - Passport.js MFA strategies
        - NextAuth.js configuration
        - MSAL (Microsoft Authentication Library) for Azure AD
        - WebAuthn/FIDO2 implementation (phishing-resistant)
        - TOTP/OTP-based MFA (non-phishing-resistant, flagged)
        """
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
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Passport.js without MFA strategy",
                    description="Passport.js is configured but no MFA strategy detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'passport'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'passport')),
                    recommendation="Implement MFA strategy: use passport-webauthn for phishing-resistant MFA"
                ))
        
        # Check NextAuth.js configuration
        if re.search(r'import.*next-auth|from ["\']next-auth', code):
            if not re.search(r'credentials.*mfa|webauthn|adapter.*mfa', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="NextAuth.js without MFA configuration",
                    description="NextAuth.js is configured but no MFA provider or adapter is detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'next-auth'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'next-auth')),
                    recommendation="Configure MFA: use AzureADProvider with Conditional Access or implement WebAuthn provider"
                ))
        
        # Check MSAL (Azure AD) configuration
        if re.search(r'@azure/msal|PublicClientApplication|ConfidentialClientApplication', code):
            if not re.search(r'amr.*mfa|claimsRequest.*mfa|conditionalAccess', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="MSAL without MFA validation",
                    description="MSAL is configured but no MFA claim validation or Conditional Access enforcement detected.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'msal|PublicClientApplication'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'msal|PublicClientApplication')),
                    recommendation="Validate MFA claim: check for 'amr' claim containing 'mfa' or configure Azure AD Conditional Access"
                ))
        
        # Warn about non-phishing-resistant MFA
        if has_totp and not has_webauthn:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="TOTP-based MFA is not phishing-resistant",
                description="TOTP is vulnerable to phishing attacks.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=self._find_line(lines, r'speakeasy|otplib|authenticator'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'speakeasy|otplib|authenticator')),
                recommendation="Migrate to @simplewebauthn/server (FIDO2/WebAuthn) or fido2-lib"
            ))
        
        if has_sms_mfa:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SMS-based MFA is not phishing-resistant",
                description="SMS is vulnerable to SIM swapping and phishing attacks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=self._find_line(lines, r'twilio|nexmo|sns.*sms'),
                code_snippet=self._get_snippet(lines, self._find_line(lines, r'twilio|nexmo|sns.*sms')),
                recommendation="Replace SMS MFA with @simplewebauthn/server (FIDO2/WebAuthn)"
            ))
        
        # Check for authentication without MFA
        if (passport_found or re.search(r'jwt\.sign|bcrypt\.compare|authenticate', code)) and not (has_webauthn or has_totp or has_sms_mfa):
            if not re.search(r'@azure/msal', code):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No MFA implementation detected",
                    description="Authentication logic detected but no MFA implementation found.",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'passport|jwt\.sign|authenticate'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'passport|jwt\.sign|authenticate')),
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
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without MFA enforcement",
                    description="Azure AD Conditional Access policy found but does not require MFA in grant controls.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'conditionalAccessPolic'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'conditionalAccessPolic')),
                    recommendation="Add grantControls with requireMultiFactorAuthentication: true in Conditional Access policy"
                ))
            
            # Check for authentication strength (phishing-resistant)
            if not re.search(r'authenticationStrength|phishingResistant', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without authentication strength",
                    description="Conditional Access policy does not specify authentication strength. FedRAMP 20x requires phishing-resistant MFA.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'conditionalAccessPolic'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'conditionalAccessPolic')),
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
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without MFA enforcement",
                    description="azuread_conditional_access_policy resource found but does not require MFA in grant_controls.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azuread_conditional_access_policy'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azuread_conditional_access_policy')),
                    recommendation='Add grant_controls { built_in_controls = ["mfa"] operator = "OR" } to Conditional Access policy'
                ))
            
            # Check for authentication strength
            if not re.search(r'authentication_strength_policy_id|phishing.*resistant', code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Conditional Access policy without authentication strength",
                    description="Conditional Access policy does not reference authentication strength policy. FedRAMP 20x requires phishing-resistant MFA.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=self._find_line(lines, r'azuread_conditional_access_policy'),
                    code_snippet=self._get_snippet(lines, self._find_line(lines, r'azuread_conditional_access_policy')),
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
