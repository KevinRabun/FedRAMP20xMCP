"""
KSI-AFR-11: Using Cryptographic Modules

Ensure that cryptographic modules used to protect potentially sensitive federal customer data are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) guidance and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_11_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-11: Using Cryptographic Modules
    
    **Official Statement:**
    Ensure that cryptographic modules used to protect potentially sensitive federal customer data are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) guidance and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-11"
    KSI_NAME = "Using Cryptographic Modules"
    KSI_STATEMENT = """Ensure that cryptographic modules used to protect potentially sensitive federal customer data are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) guidance and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = []
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
        Analyze Python code for KSI-AFR-11 compliance.
        
        Detects:
        - Weak cryptographic algorithms (MD5, SHA1, DES, RC4)
        - Insecure TLS versions (< TLS 1.2)
        - Hardcoded cryptographic keys
        - Non-FIPS compliant crypto usage
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hash algorithms (CRITICAL)
        weak_hashes = ['md5', 'sha1', 'md4']
        for i, line in enumerate(lines, 1):
            for weak_hash in weak_hashes:
                if re.search(rf'\bhashlib\.{weak_hash}\b|\b{weak_hash.upper()}\b', line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Weak Cryptographic Hash Algorithm ({weak_hash.upper()})",
                        description=(
                            f"Code uses {weak_hash.upper()}, which is cryptographically broken. "
                            "KSI-AFR-11 requires FIPS-compliant cryptographic modules. "
                            f"{weak_hash.upper()} is vulnerable to collision attacks and must not be used "
                            "for protecting federal customer data. FedRAMP requires SHA-256 or stronger."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=2),
                        remediation=(
                            f"Replace {weak_hash.upper()} with FIPS-approved algorithms:\n"
                            "import hashlib\n\n"
                            "# Use SHA-256 or stronger\n"
                            "hash_obj = hashlib.sha256(data.encode())\n"
                            "# Or SHA-384/SHA-512 for higher security\n"
                            "hash_obj = hashlib.sha512(data.encode())\n\n"
                            "# For password hashing, use bcrypt or Argon2\n"
                            "from bcrypt import hashpw, gensalt\n"
                            "hashed = hashpw(password.encode(), gensalt())\n\n"
                            "Ref: NIST SP 800-131A (https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Weak encryption algorithms (CRITICAL)
        weak_ciphers = [
            (r'\bDES\b', 'DES'),
            (r'\bRC4\b|\bARCFOUR\b', 'RC4'),
            (r'\b3DES\b|DES3', '3DES'),
            (r'\bBlowfish\b', 'Blowfish')
        ]
        for i, line in enumerate(lines, 1):
            for pattern, cipher_name in weak_ciphers:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Weak Encryption Algorithm ({cipher_name})",
                        description=(
                            f"Code uses {cipher_name} encryption, which is deprecated and insecure. "
                            "KSI-AFR-11 requires FIPS 140-2/140-3 validated cryptographic modules. "
                            f"{cipher_name} has known vulnerabilities and insufficient key sizes for federal data protection."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=2),
                        remediation=(
                            f"Replace {cipher_name} with AES-256 in GCM mode:\n"
                            "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
                            "from cryptography.hazmat.backends import default_backend\n"
                            "import os\n\n"
                            "# Use AES-256-GCM (FIPS-approved)\n"
                            "key = os.urandom(32)  # 256-bit key\n"
                            "iv = os.urandom(12)   # 96-bit IV for GCM\n"
                            "cipher = Cipher(\n"
                            "    algorithms.AES(key),\n"
                            "    modes.GCM(iv),\n"
                            "    backend=default_backend()\n"
                            ")\n\n"
                            "Ref: FIPS 140-2 Annex A (https://csrc.nist.gov/publications/detail/fips/140/2/final)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 3: Insecure TLS versions (HIGH)
        if re.search(r'PROTOCOL_TLSv1\b|TLSv1_0|TLSv1_1|SSLv[23]', code, re.IGNORECASE):
            line_num = self._find_line(lines, 'PROTOCOL_TLS')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure TLS Version (< TLS 1.2)",
                description=(
                    "Code configures TLS 1.0/1.1 or SSLv2/v3, which are cryptographically insecure. "
                    "KSI-AFR-11 requires secure cryptographic protocols. TLS 1.2+ is mandatory "
                    "for federal systems per NIST SP 800-52 Rev 2. Older TLS versions are "
                    "vulnerable to BEAST, POODLE, and other attacks."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Use TLS 1.2 or 1.3 exclusively:\n"
                    "import ssl\n\n"
                    "# Create context with minimum TLS 1.2\n"
                    "context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
                    "context.minimum_version = ssl.TLSVersion.TLSv1_2\n"
                    "context.maximum_version = ssl.TLSVersion.TLSv1_3\n\n"
                    "# For servers\n"
                    "context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
                    "context.minimum_version = ssl.TLSVersion.TLSv1_2\n\n"
                    "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 4: Hardcoded cryptographic keys (CRITICAL)
        key_patterns = [
            r'[\'"](secret_key|api_key|private_key|encryption_key)[\'\"]\s*[:=]\s*[\'"][^\'"]{16,}[\'"]',
            r'[\'"](AES|RSA)_KEY[\'\"]\s*[:=]',
            r'key\s*=\s*b?[\'"][A-Za-z0-9+/=]{32,}[\'"]'
        ]
        for i, line in enumerate(lines, 1):
            for pattern in key_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title="Hardcoded Cryptographic Key",
                        description=(
                            "Code contains hardcoded cryptographic keys. KSI-AFR-11 requires "
                            "secure key management aligned with FIPS standards. Hardcoded keys "
                            "are visible in source control, cannot be rotated, and violate "
                            "separation of code and secrets. This is a critical security vulnerability."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=2),
                        remediation=(
                            "Store cryptographic keys in Azure Key Vault:\n"
                            "from azure.identity import DefaultAzureCredential\n"
                            "from azure.keyvault.secrets import SecretClient\n\n"
                            "# Retrieve keys from Key Vault\n"
                            "credential = DefaultAzureCredential()\n"
                            "client = SecretClient(\n"
                            "    vault_url='https://<vault-name>.vault.azure.net',\n"
                            "    credential=credential\n"
                            ")\n"
                            "encryption_key = client.get_secret('encryption-key').value\n\n"
                            "# Or use environment variables (better than hardcoding)\n"
                            "import os\n"
                            "key = os.environ['ENCRYPTION_KEY']\n\n"
                            "Ref: Azure Key Vault (https://learn.microsoft.com/azure/key-vault/)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-AFR-11 compliance.
        
        Detects:
        - Weak hash algorithms (MD5, SHA1)
        - Weak encryption (DES, RC2, TripleDES)
        - Insecure TLS versions
        - Hardcoded keys
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hash algorithms (CRITICAL)
        weak_hashes = [
            ('MD5', 'MD5CryptoServiceProvider|MD5.Create'),
            ('SHA1', 'SHA1CryptoServiceProvider|SHA1Managed|SHA1.Create')
        ]
        for hash_name, pattern in weak_hashes:
            if re.search(pattern, code, re.IGNORECASE):
                line_num = self._find_line(lines, pattern.split('|')[0])
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"Weak Cryptographic Hash ({hash_name})",
                    description=(
                        f"Code uses {hash_name} hashing algorithm, which is cryptographically broken. "
                        "KSI-AFR-11 requires FIPS 140-2 validated algorithms. "
                        f"{hash_name} is vulnerable to collision attacks and prohibited for federal data."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=2),
                    remediation=(
                        f"Replace {hash_name} with SHA256 or stronger:\n"
                        "using System.Security.Cryptography;\n\n"
                        "// Use SHA256 (FIPS-approved)\n"
                        "using (var sha256 = SHA256.Create())\n"
                        "{\n"
                        "    byte[] hash = sha256.ComputeHash(data);\n"
                        "}\n\n"
                        "// For password hashing, use Rfc2898DeriveBytes (PBKDF2)\n"
                        "using (var pbkdf2 = new Rfc2898DeriveBytes(\n"
                        "    password, salt, 100000, HashAlgorithmName.SHA256))\n"
                        "{\n"
                        "    byte[] hash = pbkdf2.GetBytes(32);\n"
                        "}\n\n"
                        "Ref: FIPS 140-2 (https://csrc.nist.gov/publications/detail/fips/140/2/final)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Weak encryption algorithms (CRITICAL)
        weak_ciphers = [
            ('DES', 'DESCryptoServiceProvider|DES.Create'),
            ('RC2', 'RC2CryptoServiceProvider|RC2.Create'),
            ('TripleDES', 'TripleDESCryptoServiceProvider|TripleDES.Create')
        ]
        for cipher_name, pattern in weak_ciphers:
            if re.search(pattern, code, re.IGNORECASE):
                line_num = self._find_line(lines, pattern.split('|')[0])
                findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"Weak Encryption Algorithm ({cipher_name})",
                    description=(
                        f"Code uses {cipher_name} encryption, which is deprecated. "
                        "KSI-AFR-11 requires FIPS 140-2 validated cryptographic modules. "
                        f"{cipher_name} has insufficient key strength for federal data protection."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=2),
                    remediation=(
                        f"Replace {cipher_name} with AES:\n"
                        "using System.Security.Cryptography;\n\n"
                        "// Use AES with GCM mode (FIPS-approved)\n"
                        "using (var aes = new AesGcm(key))\n"
                        "{\n"
                        "    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];\n"
                        "    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];\n"
                        "    RandomNumberGenerator.Fill(nonce);\n"
                        "    aes.Encrypt(nonce, plaintext, ciphertext, tag);\n"
                        "}\n\n"
                        "Ref: .NET AES (https://learn.microsoft.com/dotnet/api/system.security.cryptography.aes)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Insecure TLS (HIGH)
        if re.search(r'SecurityProtocolType\.(Ssl3|Tls|Tls11)\b', code):
            line_num = self._find_line(lines, 'SecurityProtocolType')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure TLS Version",
                description=(
                    "Code enables TLS 1.0/1.1 or SSL 3.0. KSI-AFR-11 requires secure "
                    "cryptographic protocols. Only TLS 1.2+ is acceptable per NIST SP 800-52 Rev 2."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Use TLS 1.2+ exclusively:\n"
                    "using System.Net;\n\n"
                    "// Set minimum TLS 1.2\n"
                    "ServicePointManager.SecurityProtocol = \n"
                    "    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;\n\n"
                    "// Or configure in app.config/web.config:\n"
                    "<system.net>\n"
                    "  <settings>\n"
                    "    <servicePointManager checkCertificateRevocationList='true'\n"
                    "                          enableSchUseStrongCrypto='true'/>\n"
                    "  </settings>\n"
                    "</system.net>\n\n"
                    "Ref: NIST SP 800-52 Rev 2"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 4: Hardcoded keys (CRITICAL)
        if re.search(r'(byte\[\]|string)\s+\w*(key|Key|KEY)\w*\s*=\s*new\s+byte\[\]|=\s*"[A-Za-z0-9+/=]{32,}"', code):
            line_num = self._find_line(lines, 'key')
            findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Hardcoded Cryptographic Key",
                description=(
                    "Code contains hardcoded cryptographic keys. KSI-AFR-11 requires "
                    "secure key management. Use Azure Key Vault or secure configuration."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Use Azure Key Vault for key management:\n"
                    "using Azure.Identity;\n"
                    "using Azure.Security.KeyVault.Secrets;\n\n"
                    "var client = new SecretClient(\n"
                    "    new Uri(\"https://<vault-name>.vault.azure.net\"),\n"
                    "    new DefaultAzureCredential());\n"
                    "KeyVaultSecret secret = await client.GetSecretAsync(\"encryption-key\");\n"
                    "byte[] key = Convert.FromBase64String(secret.Value);\n\n"
                    "Ref: Azure Key Vault SDK (https://learn.microsoft.com/azure/key-vault/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-11 compliance.
        
        Detects weak hash/encryption algorithms, insecure TLS
        """
        findings = []
        lines = code.split('\n')
        
        # Weak algorithms (CRITICAL)
        weak_algos = ['MD5', 'SHA-1', 'SHA1', 'DES', 'DESede', 'RC4']
        for i, line in enumerate(lines, 1):
            for algo in weak_algos:
                if re.search(rf'getInstance\(["\']({algo})["\']', line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Weak Cryptographic Algorithm ({algo})",
                        description=(
                            f"Code uses {algo} via MessageDigest/Cipher.getInstance(). "
                            "KSI-AFR-11 requires FIPS 140-2 validated algorithms."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=2),
                        remediation=(
                            f"Replace {algo} with SHA-256 or AES/GCM:\n"
                            "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n"
                            "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n\n"
                            "Ref: Java Security (https://docs.oracle.com/javase/8/docs/technotes/guides/security/)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-11 compliance.
        
        Detects weak crypto algorithms in Node.js crypto module
        """
        findings = []
        lines = code.split('\n')
        
        # Weak algorithms (CRITICAL)
        weak_algos = ['md5', 'sha1', 'des', 'rc4']
        for i, line in enumerate(lines, 1):
            for algo in weak_algos:
                if re.search(rf"createHash\(['\"]({algo})['\")|createCipher\(['\"]({algo})['\"]", line, re.IGNORECASE):
                    findings.append(Finding(
                        severity=Severity.CRITICAL,
                        title=f"Weak Cryptographic Algorithm ({algo.upper()})",
                        description=(
                            f"Code uses {algo.upper()} via crypto.createHash/createCipher. "
                            "KSI-AFR-11 requires FIPS-compliant algorithms."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=2),
                        remediation=(
                            f"Replace {algo.upper()} with SHA-256 or AES-256-GCM:\n"
                            "const hash = crypto.createHash('sha256').update(data).digest('hex');\n"
                            "const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n\n"
                            "Ref: Node.js Crypto (https://nodejs.org/api/crypto.html)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-11 compliance.
        
        Detects:
        - Insecure TLS/SSL policies
        - Weak encryption settings
        - Missing HTTPS enforcement
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure TLS minimum version (HIGH)
        if re.search(r"minTlsVersion:\s*['\"]?(1\.[01]|TLS1_[01])", code, re.IGNORECASE):
            line_num = self._find_line(lines, 'minTlsVersion')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure TLS Minimum Version",
                description=(
                    "Resource configured with TLS 1.0/1.1. KSI-AFR-11 requires TLS 1.2+ "
                    "for cryptographic protection of federal data per NIST SP 800-52 Rev 2."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Set minimum TLS version to 1.2 or 1.3:\n"
                    "// For Storage Account\n"
                    "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                    "  properties: {\n"
                    "    minimumTlsVersion: 'TLS1_2'  // Or 'TLS1_3'\n"
                    "  }\n"
                    "}\n\n"
                    "// For App Service\n"
                    "resource webapp 'Microsoft.Web/sites@2023-01-01' = {\n"
                    "  properties: {\n"
                    "    siteConfig: {\n"
                    "      minTlsVersion: '1.2'\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure TLS (https://learn.microsoft.com/azure/storage/common/transport-layer-security-configure-minimum-version)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: HTTPS not enforced (HIGH)
        if re.search(r"supportsHttpsTrafficOnly:\s*false|httpsOnly:\s*false", code, re.IGNORECASE):
            line_num = self._find_line(lines, 'HttpsOnly')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="HTTPS Not Enforced",
                description=(
                    "Resource allows unencrypted HTTP traffic. KSI-AFR-11 requires "
                    "cryptographic protection for data in transit. HTTPS must be enforced."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Enforce HTTPS only:\n"
                    "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                    "  properties: {\n"
                    "    supportsHttpsTrafficOnly: true\n"
                    "  }\n"
                    "}\n\n"
                    "resource webapp 'Microsoft.Web/sites@2023-01-01' = {\n"
                    "  properties: {\n"
                    "    httpsOnly: true\n"
                    "  }\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-11 compliance.
        
        Detects:
        - Insecure TLS/SSL policies
        - Weak encryption settings
        - Missing HTTPS enforcement
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure TLS minimum version (HIGH)
        if re.search(r'minimum_tls_version\s*=\s*["\']?(1\.[01]|TLS1_[01])', code, re.IGNORECASE):
            line_num = self._find_line(lines, 'minimum_tls_version')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure TLS Minimum Version",
                description=(
                    "Resource configured with TLS 1.0/1.1. KSI-AFR-11 requires TLS 1.2+ "
                    "for cryptographic protection of federal data per NIST SP 800-52 Rev 2."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Set minimum TLS version to 1.2 or 1.3:\n"
                    "# Azure Storage Account\n"
                    "resource \"azurerm_storage_account\" \"example\" {\n"
                    "  min_tls_version = \"TLS1_2\"\n"
                    "}\n\n"
                    "# Azure App Service\n"
                    "resource \"azurerm_linux_web_app\" \"example\" {\n"
                    "  site_config {\n"
                    "    minimum_tls_version = \"1.2\"\n"
                    "  }\n"
                    "}\n\n"
                    "# AWS ALB\n"
                    "resource \"aws_lb_listener\" \"example\" {\n"
                    "  ssl_policy = \"ELBSecurityPolicy-TLS-1-2-2017-01\"  # TLS 1.2+\n"
                    "}\n\n"
                    "Ref: NIST SP 800-52 Rev 2 (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: HTTPS not enforced (HIGH)
        if re.search(r'https_only\s*=\s*false|enable_https_traffic_only\s*=\s*false', code, re.IGNORECASE):
            line_num = self._find_line(lines, 'https')
            findings.append(Finding(
                severity=Severity.HIGH,
                title="HTTPS Not Enforced",
                description=(
                    "Resource allows unencrypted HTTP traffic. KSI-AFR-11 requires "
                    "cryptographic protection for data in transit. HTTPS must be enforced."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Enforce HTTPS only:\n"
                    "resource \"azurerm_storage_account\" \"example\" {\n"
                    "  enable_https_traffic_only = true\n"
                    "}\n\n"
                    "resource \"azurerm_linux_web_app\" \"example\" {\n"
                    "  https_only = true\n"
                    "}"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 3: Weak SSL policy on AWS (MEDIUM)
        if re.search(r'ssl_policy\s*=\s*"ELBSecurityPolicy-(2015|2016|TLS-1-0|TLS-1-1)', code):
            line_num = self._find_line(lines, 'ssl_policy')
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Weak SSL Policy on AWS Load Balancer",
                description=(
                    "Load balancer uses outdated SSL policy that may allow TLS 1.0/1.1. "
                    "KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=2),
                remediation=(
                    "Use modern SSL policy:\n"
                    "resource \"aws_lb_listener\" \"example\" {\n"
                    "  ssl_policy = \"ELBSecurityPolicy-TLS13-1-2-2021-06\"  # TLS 1.3+\n"
                    "  # Or: \"ELBSecurityPolicy-TLS-1-2-2017-01\" for TLS 1.2+\n"
                    "}\n\n"
                    "Ref: AWS SSL Policies (https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-11 compliance.
        
        Detects:
        - Missing cryptographic scanning tools
        - Missing secret scanning
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing secret scanning (MEDIUM)
        has_secret_scan = bool(re.search(r'(trufflesecurity/trufflehog|gitleaks|detect-secrets)', code, re.IGNORECASE))
        if not has_secret_scan and len(code) > 100:  # Only flag if substantial workflow
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Secret Scanning",
                description=(
                    "Workflow lacks secret scanning. KSI-AFR-11 requires detection of "
                    "hardcoded cryptographic keys and secrets in code."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add secret scanning step:\n"
                    "jobs:\n"
                    "  security:\n"
                    "    runs-on: ubuntu-latest\n"
                    "    steps:\n"
                    "      - uses: actions/checkout@v4\n"
                    "        with:\n"
                    "          fetch-depth: 0  # Full history for scanning\n"
                    "      \n"
                    "      - name: TruffleHog Secret Scan\n"
                    "        uses: trufflesecurity/trufflehog@main\n"
                    "        with:\n"
                    "          path: ./\n"
                    "          base: ${{ github.event.repository.default_branch }}\n"
                    "          head: HEAD\n\n"
                    "Ref: GitHub Secret Scanning (https://docs.github.com/en/code-security/secret-scanning)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing SAST for crypto (MEDIUM)
        has_sast = bool(re.search(r'(github/codeql-action|semgrep|bandit|safety)', code, re.IGNORECASE))
        if not has_sast and len(code) > 100:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing SAST for Cryptographic Issues",
                description=(
                    "Workflow lacks static analysis to detect weak cryptography. "
                    "KSI-AFR-11 requires validation of cryptographic implementations."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add SAST scanning:\n"
                    "      - name: Initialize CodeQL\n"
                    "        uses: github/codeql-action/init@v3\n"
                    "        with:\n"
                    "          languages: python, javascript, csharp\n"
                    "          queries: security-and-quality\n"
                    "      \n"
                    "      - name: Perform CodeQL Analysis\n"
                    "        uses: github/codeql-action/analyze@v3\n\n"
                    "Or use Semgrep:\n"
                    "      - name: Semgrep Security Scan\n"
                    "        uses: returntocorp/semgrep-action@v1\n"
                    "        with:\n"
                    "          config: p/security-audit p/owasp-top-ten\n\n"
                    "Ref: CodeQL (https://codeql.github.com/docs/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings

    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-11 compliance.
        
        Detects:
        - Missing cryptographic scanning tools
        - Missing secret scanning
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing secret scanning (MEDIUM)
        has_secret_scan = bool(re.search(r'(CredScan|secretscanner|trufflehog)', code, re.IGNORECASE))
        if not has_secret_scan and len(code) > 100:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Secret Scanning",
                description=(
                    "Pipeline lacks secret scanning. KSI-AFR-11 requires detection of "
                    "hardcoded cryptographic keys and secrets in code."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add secret scanning task:\n"
                    "- task: CredScan@3\n"
                    "  displayName: 'Run Credential Scanner'\n"
                    "  inputs:\n"
                    "    outputFormat: 'sarif'\n"
                    "    verboseOutput: true\n\n"
                    "Or use Microsoft Security DevOps:\n"
                    "- task: MicrosoftSecurityDevOps@1\n"
                    "  displayName: 'Run Microsoft Security DevOps'\n"
                    "  inputs:\n"
                    "    categories: 'secrets'\n\n"
                    "Ref: Azure DevOps Security (https://learn.microsoft.com/azure/devops/pipelines/security/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing security analysis (MEDIUM)
        has_security = bool(re.search(r'(MicrosoftSecurityDevOps|Semmle|semgrep)', code, re.IGNORECASE))
        if not has_security and len(code) > 100:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Security Analysis",
                description=(
                    "Pipeline lacks security analysis. KSI-AFR-11 requires validation "
                    "of cryptographic implementations for weak algorithms."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add security analysis:\n"
                    "- task: MicrosoftSecurityDevOps@1\n"
                    "  displayName: 'Security Analysis'\n"
                    "  inputs:\n"
                    "    categories: 'code,dependencies,secrets'\n"
                    "    break: true  # Fail build on HIGH findings\n\n"
                    "Ref: MSDO Task (https://learn.microsoft.com/azure/defender-for-cloud/azure-devops-extension)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings

    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-11 compliance.
        
        Detects:
        - Missing secret scanning
        - Missing SAST for cryptography
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing secret detection job (MEDIUM)
        has_secret_detection = bool(re.search(r'(secret_detection|gitleaks)', code, re.IGNORECASE))
        if not has_secret_detection and len(code) > 100:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing Secret Detection",
                description=(
                    "Pipeline lacks secret detection. KSI-AFR-11 requires detection of "
                    "hardcoded cryptographic keys and secrets in code."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add GitLab Secret Detection:\n"
                    "include:\n"
                    "  - template: Security/Secret-Detection.gitlab-ci.yml\n\n"
                    "Or use Gitleaks:\n"
                    "secrets-scan:\n"
                    "  stage: test\n"
                    "  image: zricethezav/gitleaks:latest\n"
                    "  script:\n"
                    "    - gitleaks detect --source . --verbose\n"
                    "  allow_failure: false\n\n"
                    "Ref: GitLab Secret Detection (https://docs.gitlab.com/ee/user/application_security/secret_detection/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Missing SAST job (MEDIUM)
        has_sast = bool(re.search(r'(include:.*SAST|semgrep)', code, re.IGNORECASE))
        if not has_sast and len(code) > 100:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Missing SAST for Cryptography",
                description=(
                    "Pipeline lacks SAST scanning. KSI-AFR-11 requires validation of "
                    "cryptographic implementations for weak algorithms."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add GitLab SAST:\n"
                    "include:\n"
                    "  - template: Security/SAST.gitlab-ci.yml\n\n"
                    "Or use Semgrep:\n"
                    "sast:\n"
                    "  stage: test\n"
                    "  image: returntocorp/semgrep:latest\n"
                    "  script:\n"
                    "    - semgrep --config=p/security-audit --config=p/owasp-top-ten .\n"
                    "  allow_failure: false\n\n"
                    "Ref: GitLab SAST (https://docs.gitlab.com/ee/user/application_security/sast/)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings

    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
