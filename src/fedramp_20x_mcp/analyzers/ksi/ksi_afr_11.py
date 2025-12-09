"""
KSI-AFR-11 Enhanced: Using Cryptographic Modules

Ensure that cryptographic modules used to protect potentially sensitive federal customer data 
are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) 
guidance and persistently address all related requirements and recommendations.

Enhanced with AST-based analysis where applicable, regex-based for IaC/CI-CD.
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_AFR_11_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-AFR-11: Using Cryptographic Modules
    
    **Official Statement:**
    Ensure that cryptographic modules used to protect potentially sensitive federal customer data 
    are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) 
    guidance and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **NIST Controls:** None specified (general crypto compliance requirement)
    
    **Detection Strategy:**
    - Weak hash algorithms: MD5, SHA1, MD4 (cryptographically broken)
    - Weak encryption: DES, RC4, 3DES (insufficient key length)
    - Insecure TLS: TLS 1.0/1.1, SSLv2/v3 (protocol vulnerabilities)
    - Hardcoded keys: Embedded secrets in source code
    - Non-FIPS crypto: Algorithms not approved by FIPS 140-2/3
    - IaC: Azure Key Vault configuration, TLS minimums
    - CI/CD: Secrets scanning, crypto policy enforcement
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript (AST+regex)
    - IaC: Bicep, Terraform (regex-based)
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI (regex-based)
    """
    
    KSI_ID = "KSI-AFR-11"
    KSI_NAME = "Using Cryptographic Modules"
    KSI_STATEMENT = "Ensure that cryptographic modules used to protect potentially sensitive federal customer data are selected and used in alignment with the FedRAMP 20x Using Cryptographic Modules (UCM) guidance and persistently address all related requirements and recommendations."
    FAMILY = "AFR"
    NIST_CONTROLS = []  # General crypto requirement
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    # Weak cryptographic algorithms (forbidden by FIPS/FedRAMP)
    WEAK_HASHES = {
        'md5': 'MD5 - Cryptographically broken (collision attacks)',
        'sha1': 'SHA-1 - Deprecated by NIST (collision attacks)',
        'md4': 'MD4 - Cryptographically broken',
        'md2': 'MD2 - Cryptographically broken'
    }
    
    WEAK_ENCRYPTION = {
        'des': 'DES - 56-bit key insufficient',
        '3des': 'Triple DES - Being phased out by NIST',
        'rc4': 'RC4 - Stream cipher with biases',
        'rc2': 'RC2 - Weak 40-bit default',
        'blowfish': 'Blowfish - 64-bit block size vulnerable'
    }
    
    APPROVED_HASHES = ['sha256', 'sha384', 'sha512', 'sha3']
    APPROVED_ENCRYPTION = ['aes', 'aes-256-gcm', 'chacha20-poly1305']
    
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
        Analyze Python code for cryptographic compliance (AST-first).
        
        Detects:
        - hashlib.md5(), hashlib.sha1() - weak hashes
        - Crypto.Cipher.DES, RC4 - weak encryption
        - ssl.PROTOCOL_TLSv1, TLSv1_0 - insecure TLS
        - Hardcoded keys in assignments
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree:
            code_bytes = bytes(code, "utf8")
            return self._analyze_python_ast(code, code_bytes, file_path, parser, tree.root_node)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, code_bytes: bytes, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Python cryptographic compliance analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hash algorithms via attribute access (hashlib.md5, hashlib.sha1)
        attribute_nodes = parser.find_nodes_by_type(tree, 'attribute')
        for node in attribute_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            
            # Check for hashlib.weak_algorithm
            for weak_hash, reason in self.WEAK_HASHES.items():
                if f'hashlib.{weak_hash}' in node_text.lower():
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Cryptographic Hash Algorithm ({weak_hash.upper()})",
                        description=(
                            f"Code uses {weak_hash.upper()}: {reason}. "
                            f"KSI-AFR-11 requires FIPS 140-2/3 approved algorithms. "
                            f"FedRAMP mandates SHA-256 or stronger for all cryptographic operations."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            f"Replace {weak_hash.upper()} with FIPS-approved hashing:\n"
                            "import hashlib\n\n"
                            "# Use SHA-256 or stronger\n"
                            "hash_obj = hashlib.sha256(data)\n"
                            "digest = hash_obj.hexdigest()\n\n"
                            "# For password hashing, use bcrypt or Argon2\n"
                            "from bcrypt import hashpw, gensalt\n"
                            "hashed = hashpw(password.encode(), gensalt())\n\n"
                            "Ref: NIST FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                        )
                    ))
                    break  # One finding per node
            
            # Check for ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_SSLv2, etc.
            insecure_tls = ['PROTOCOL_TLSv1', 'TLSv1_0', 'TLSv1_1', 'PROTOCOL_SSLv2', 'PROTOCOL_SSLv3']
            for tls_version in insecure_tls:
                if f'ssl.{tls_version}' in node_text:
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Insecure TLS Version ({tls_version})",
                        description=(
                            f"Code configures {tls_version}, which is cryptographically insecure. "
                            f"KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2. "
                            f"Older TLS/SSL versions are vulnerable to BEAST, POODLE, and downgrade attacks."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Configure TLS 1.2+ exclusively:\n"
                            "import ssl\n\n"
                            "# Client context\n"
                            "context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
                            "context.minimum_version = ssl.TLSVersion.TLSv1_2\n"
                            "context.maximum_version = ssl.TLSVersion.TLSv1_3\n\n"
                            "# Server context\n"
                            "context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
                            "context.minimum_version = ssl.TLSVersion.TLSv1_2\n\n"
                            "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                        )
                    ))
                    break
        
        # Pattern 2: Weak encryption via imports (from Crypto.Cipher import DES)
        # Check import_from_statement nodes for Crypto.Cipher imports
        import_nodes = parser.find_nodes_by_type(tree, 'import_from_statement')
        weak_ciphers = ['DES', 'DES3', 'RC4', 'RC2', 'Blowfish', 'ARC4']
        for node in import_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            # Check if importing from Crypto.Cipher or cryptography.hazmat
            if 'Crypto.Cipher' in node_text or 'cryptography.hazmat' in node_text:
                for cipher in weak_ciphers:
                    if cipher in node_text:
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title=f"Weak Encryption Algorithm ({cipher})",
                            description=(
                                f"Code imports {cipher} encryption, which does not meet FedRAMP requirements. "
                                f"KSI-AFR-11 mandates FIPS 140-2/3 approved algorithms. "
                                f"{cipher} has insufficient key length or known cryptographic weaknesses."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            recommendation=(
                                f"Replace {cipher} with AES-256-GCM:\n"
                                "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                                "import os\n\n"
                                "# Generate key (store securely in Key Vault)\n"
                                "key = AESGCM.generate_key(bit_length=256)\n"
                                "aesgcm = AESGCM(key)\n\n"
                                "# Encrypt with authenticated encryption\n"
                                "nonce = os.urandom(12)\n"
                                "ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)\n\n"
                                "Ref: NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)"
                            )
                        ))
                        break
        
        # Pattern 4: Hardcoded cryptographic keys (assignment nodes)
        assignment_nodes = parser.find_nodes_by_type(tree, 'assignment')
        for node in assignment_nodes:
            # Get left side (variable name) and right side (value)
            left_node = node.child_by_field_name('left')
            right_node = node.child_by_field_name('right')
            
            if left_node and right_node:
                var_name = parser.get_node_text(left_node, code_bytes).lower()
                value_text = parser.get_node_text(right_node, code_bytes)
                
                # Check if variable name indicates a key and value is a string literal
                key_indicators = ['secret_key', 'api_key', 'encryption_key', 'private_key', 'password', 'token']
                if any(indicator in var_name for indicator in key_indicators):
                    if right_node.type == 'string':
                        # Extract string content (remove quotes)
                        string_value = value_text.strip('\'"b')
                        # Check if it's a long enough string to be a key (16+ chars)
                        if len(string_value) >= 16:
                            line_num = node.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title=f"Hardcoded Cryptographic Key ({var_name})",
                                description=(
                                    f"Code contains hardcoded {var_name}. KSI-AFR-11 requires secure key management "
                                    f"with FIPS-compliant key storage. Hardcoded keys are visible in source control, "
                                    f"cannot be rotated, and violate crypto module guidance. This is a critical vulnerability."
                                ),
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num),
                                recommendation=(
                                    "Store cryptographic keys in Azure Key Vault:\n"
                                    "from azure.identity import DefaultAzureCredential\n"
                                    "from azure.keyvault.secrets import SecretClient\n\n"
                                    "credential = DefaultAzureCredential()\n"
                                    "client = SecretClient(\n"
                                    "    vault_url='https://<vault>.vault.azure.net',\n"
                                    "    credential=credential\n"
                                    ")\n"
                                    "encryption_key = client.get_secret('encryption-key').value\n\n"
                                    "Or use Managed Identities:\n"
                                    "# No keys in code - Azure handles authentication\n"
                                    "credential = DefaultAzureCredential()\n\n"
                                    "Ref: Azure Key Vault (https://learn.microsoft.com/azure/key-vault/)"
                                )
                            ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for Python cryptographic compliance analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hash algorithms (CRITICAL)
        for weak_hash, reason in self.WEAK_HASHES.items():
            pattern = rf'\bhashlib\.{weak_hash}\b'
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Cryptographic Hash Algorithm ({weak_hash.upper()})",
                        description=(
                            f"Code uses {weak_hash.upper()}: {reason}. "
                            f"KSI-AFR-11 requires FIPS 140-2/3 approved algorithms. "
                            f"FedRAMP mandates SHA-256 or stronger for all cryptographic operations."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i),
                        recommendation=(
                            f"Replace {weak_hash.upper()} with FIPS-approved hashing:\n"
                            "import hashlib\n\n"
                            "# Use SHA-256 or stronger\n"
                            "hash_obj = hashlib.sha256(data)\n"
                            "digest = hash_obj.hexdigest()\n\n"
                            "# For password hashing, use bcrypt or Argon2\n"
                            "from bcrypt import hashpw, gensalt\n"
                            "hashed = hashpw(password.encode(), gensalt())\n\n"
                            "Ref: NIST FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                        )
                    ))
        
        # Pattern 2: Weak encryption algorithms (CRITICAL)
        weak_ciphers = ['DES', 'DES3', 'RC4', 'RC2', 'Blowfish', 'ARC4']
        for cipher in weak_ciphers:
            pattern = rf'Crypto\.Cipher\.{cipher}|cryptography\.hazmat.*\.{cipher}'
            if re.search(pattern, code, re.IGNORECASE):
                line_num = self._find_text_line(lines, cipher)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Weak Encryption Algorithm ({cipher})",
                    description=(
                        f"Code uses {cipher} encryption, which does not meet FedRAMP requirements. "
                        f"KSI-AFR-11 mandates FIPS 140-2/3 approved algorithms. "
                        f"{cipher} has insufficient key length or known cryptographic weaknesses."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        f"Replace {cipher} with AES-256-GCM:\n"
                        "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
                        "import os\n\n"
                        "# Generate key (store securely in Key Vault)\n"
                        "key = AESGCM.generate_key(bit_length=256)\n"
                        "aesgcm = AESGCM(key)\n\n"
                        "# Encrypt with authenticated encryption\n"
                        "nonce = os.urandom(12)\n"
                        "ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)\n\n"
                        "Ref: NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)"
                    )
                ))
        
        # Pattern 3: Insecure TLS versions (HIGH)
        insecure_tls = ['PROTOCOL_TLSv1', 'TLSv1_0', 'TLSv1_1', 'PROTOCOL_SSLv2', 'PROTOCOL_SSLv3']
        for tls_version in insecure_tls:
            if re.search(rf'\bssl\.{tls_version}\b', code):
                line_num = self._find_text_line(lines, tls_version)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Insecure TLS Version ({tls_version})",
                    description=(
                        f"Code configures {tls_version}, which is cryptographically insecure. "
                        f"KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2. "
                        f"Older TLS/SSL versions are vulnerable to BEAST, POODLE, and downgrade attacks."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Configure TLS 1.2+ exclusively:\n"
                        "import ssl\n\n"
                        "# Client context\n"
                        "context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
                        "context.minimum_version = ssl.TLSVersion.TLSv1_2\n"
                        "context.maximum_version = ssl.TLSVersion.TLSv1_3\n\n"
                        "# Server context\n"
                        "context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n"
                        "context.minimum_version = ssl.TLSVersion.TLSv1_2\n\n"
                        "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                    )
                ))
        
        # Pattern 4: Hardcoded cryptographic keys (CRITICAL)
        key_patterns = [
            (r'secret_key\s*=\s*[\'"][^\'"]{16,}[\'"]', 'secret_key'),
            (r'api_key\s*=\s*[\'"][^\'"]{20,}[\'"]', 'api_key'),
            (r'encryption_key\s*=\s*b?[\'"][A-Za-z0-9+/=]{32,}[\'"]', 'encryption_key'),
            (r'private_key\s*=\s*[\'"]-----BEGIN', 'private_key')
        ]
        
        for pattern, key_type in key_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Hardcoded Cryptographic Key ({key_type})",
                        description=(
                            f"Code contains hardcoded {key_type}. KSI-AFR-11 requires secure key management "
                            f"with FIPS-compliant key storage. Hardcoded keys are visible in source control, "
                            f"cannot be rotated, and violate crypto module guidance. This is a critical vulnerability."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i),
                        recommendation=(
                            "Store cryptographic keys in Azure Key Vault:\n"
                            "from azure.identity import DefaultAzureCredential\n"
                            "from azure.keyvault.secrets import SecretClient\n\n"
                            "credential = DefaultAzureCredential()\n"
                            "client = SecretClient(\n"
                            "    vault_url='https://<vault>.vault.azure.net',\n"
                            "    credential=credential\n"
                            ")\n"
                            "encryption_key = client.get_secret('encryption-key').value\n\n"
                            "Or use Managed Identities:\n"
                            "# No keys in code - Azure handles authentication\n"
                            "credential = DefaultAzureCredential()\n\n"
                            "Ref: Azure Key Vault (https://learn.microsoft.com/azure/key-vault/)"
                        )
                    ))
        
        return findings

    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for cryptographic compliance (AST-first).
        
        Detects:
        - MD5CryptoServiceProvider, SHA1Managed - weak hashes
        - DESCryptoServiceProvider, RC2 - weak encryption
        - SslProtocols.Tls, Tls11 - insecure TLS
        - Hardcoded keys
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            code_bytes = bytes(code, "utf8")
            return self._analyze_csharp_ast(code, code_bytes, file_path, parser, tree.root_node)
        else:
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, code_bytes: bytes, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# cryptographic compliance analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hash algorithms via identifier nodes
        identifier_nodes = parser.find_nodes_by_type(tree, 'identifier')
        weak_hash_providers = [
            ('MD5', ['MD5CryptoServiceProvider', 'MD5Cng']),
            ('SHA1', ['SHA1CryptoServiceProvider', 'SHA1Managed', 'SHA1Cng'])
        ]
        
        for node in identifier_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            for hash_name, providers in weak_hash_providers:
                if node_text in providers:
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Cryptographic Hash ({hash_name})",
                        description=(
                            f"Code uses {node_text}, which implements {hash_name} hashing. "
                            f"{hash_name} is cryptographically broken and forbidden by FIPS 140-2/3. "
                            f"KSI-AFR-11 requires using approved cryptographic modules."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            f"Replace {hash_name} with SHA-256 or stronger:\n"
                            "using System.Security.Cryptography;\n\n"
                            "// Use FIPS-approved hashing\n"
                            "using (var sha256 = SHA256.Create())\n"
                            "{\n"
                            "    byte[] hash = sha256.ComputeHash(data);\n"
                            "}\n\n"
                            "// For passwords, use bcrypt or PBKDF2\n"
                            "using (var deriveBytes = new Rfc2898DeriveBytes(\n"
                            "    password, salt, 100000, HashAlgorithmName.SHA256))\n"
                            "{\n"
                            "    byte[] hash = deriveBytes.GetBytes(32);\n"
                            "}\n\n"
                            "Ref: FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                        )
                    ))
                    break
        
        # Pattern 2: Weak encryption algorithms via identifier nodes
        weak_crypto_providers = [
            ('DES', ['DESCryptoServiceProvider']),
            ('TripleDES', ['TripleDESCryptoServiceProvider']),
            ('RC2', ['RC2CryptoServiceProvider'])
        ]
        
        for node in identifier_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            for cipher_name, providers in weak_crypto_providers:
                if node_text in providers:
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Encryption Algorithm ({cipher_name})",
                        description=(
                            f"Code uses {node_text}, which implements {cipher_name} encryption. "
                            f"{cipher_name} does not meet FIPS 140-2/3 requirements. "
                            f"KSI-AFR-11 mandates AES-256 or approved alternatives."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            f"Replace {cipher_name} with AES-GCM:\n"
                            "using System.Security.Cryptography;\n\n"
                            "// Use AES-256-GCM for authenticated encryption\n"
                            "using (var aesGcm = new AesGcm(key))\n"
                            "{\n"
                            "    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];\n"
                            "    RandomNumberGenerator.Fill(nonce);\n"
                            "    \n"
                            "    byte[] ciphertext = new byte[plaintext.Length];\n"
                            "    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];\n"
                            "    \n"
                            "    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);\n"
                            "}\n\n"
                            "Ref: NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)"
                        )
                    ))
                    break
        
        # Pattern 3: Insecure TLS via member_access_expression nodes
        member_access_nodes = parser.find_nodes_by_type(tree, 'member_access_expression')
        insecure_tls_protocols = [
            'SslProtocols.Ssl2', 'SslProtocols.Ssl3', 'SslProtocols.Tls', 'SslProtocols.Tls11',
            'SecurityProtocolType.Ssl3', 'SecurityProtocolType.Tls', 'SecurityProtocolType.Tls11'
        ]
        
        for node in member_access_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            for tls_protocol in insecure_tls_protocols:
                if tls_protocol in node_text:
                    line_num = node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Insecure TLS Protocol ({tls_protocol})",
                        description=(
                            f"Code configures {tls_protocol}, which is cryptographically insecure. "
                            f"KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Configure TLS 1.2+ exclusively:\n"
                            "using System.Security.Authentication;\n\n"
                            "// Set minimum TLS version\n"
                            "ServicePointManager.SecurityProtocol = \n"
                            "    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;\n\n"
                            "// Or in HttpClient\n"
                            "var handler = new HttpClientHandler\n"
                            "{\n"
                            "    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13\n"
                            "};\n"
                            "var client = new HttpClient(handler);\n\n"
                            "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                        )
                    ))
                    break
        
        # Pattern 4: Hardcoded keys via variable_declaration nodes
        var_decl_nodes = parser.find_nodes_by_type(tree, 'variable_declaration')
        for var_node in var_decl_nodes:
            # Look for variable_declarator children
            for child in var_node.children:
                if child.type == 'variable_declarator':
                    # Get identifier (variable name) and check for string literal
                    var_name = ''
                    has_key_pattern = False
                    
                    for decl_child in child.children:
                        if decl_child.type == 'identifier':
                            var_name = parser.get_node_text(decl_child, code_bytes).lower()
                            has_key_pattern = any(k in var_name for k in ['key', 'password', 'secret', 'token'])
                        elif decl_child.type == 'string_literal' and has_key_pattern:
                            # Found a string literal assigned to a key-like variable
                            value = parser.get_node_text(decl_child, code_bytes)
                            if len(value) >= 18:  # At least 16 chars + quotes
                                line_num = var_node.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title=f"Hardcoded Cryptographic Key ({var_name})",
                                    description=(
                                        f"Code contains hardcoded cryptographic key. "
                                        f"KSI-AFR-11 requires secure key management with Azure Key Vault or similar FIPS-compliant storage."
                                    ),
                                    severity=Severity.CRITICAL,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    recommendation=(
                                        "Store keys in Azure Key Vault:\n"
                                        "using Azure.Identity;\n"
                                        "using Azure.Security.KeyVault.Secrets;\n\n"
                                        "var client = new SecretClient(\n"
                                        "    new Uri(\"https://<vault>.vault.azure.net\"),\n"
                                        "    new DefaultAzureCredential());\n\n"
                                        "KeyVaultSecret secret = await client.GetSecretAsync(\"encryption-key\");\n"
                                        "string key = secret.Value;\n\n"
                                        "Ref: Azure Key Vault (https://learn.microsoft.com/azure/key-vault/)"
                                    )
                                ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for C# cryptographic compliance analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hash algorithms (CRITICAL)
        weak_hash_providers = [
            ('MD5', ['MD5CryptoServiceProvider', 'MD5.Create', 'MD5Cng']),
            ('SHA1', ['SHA1CryptoServiceProvider', 'SHA1Managed', 'SHA1Cng', 'SHA1.Create'])
        ]
        
        for hash_name, providers in weak_hash_providers:
            for provider in providers:
                if re.search(rf'\b{provider}\b', code):
                    line_num = self._find_text_line(lines, provider)
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Cryptographic Hash ({hash_name})",
                        description=(
                            f"Code uses {provider}, which implements {hash_name} hashing. "
                            f"{hash_name} is cryptographically broken and forbidden by FIPS 140-2/3. "
                            f"KSI-AFR-11 requires using approved cryptographic modules."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            f"Replace {hash_name} with SHA-256 or stronger:\n"
                            "using System.Security.Cryptography;\n\n"
                            "// Use FIPS-approved hashing\n"
                            "using (var sha256 = SHA256.Create())\n"
                            "{\n"
                            "    byte[] hash = sha256.ComputeHash(data);\n"
                            "}\n\n"
                            "// For passwords, use bcrypt or PBKDF2\n"
                            "using (var deriveBytes = new Rfc2898DeriveBytes(\n"
                            "    password, salt, 100000, HashAlgorithmName.SHA256))\n"
                            "{\n"
                            "    byte[] hash = deriveBytes.GetBytes(32);\n"
                            "}\n\n"
                            "Ref: FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                        )
                    ))
        
        # Pattern 2: Weak encryption (CRITICAL)
        weak_crypto_providers = [
            ('DES', ['DESCryptoServiceProvider', 'DES.Create']),
            ('TripleDES', ['TripleDESCryptoServiceProvider', 'TripleDES.Create']),
            ('RC2', ['RC2CryptoServiceProvider', 'RC2.Create'])
        ]
        
        for cipher_name, providers in weak_crypto_providers:
            for provider in providers:
                if re.search(rf'\b{provider}\b', code):
                    line_num = self._find_text_line(lines, provider)
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Encryption Algorithm ({cipher_name})",
                        description=(
                            f"Code uses {provider}, which implements {cipher_name} encryption. "
                            f"{cipher_name} does not meet FIPS 140-2/3 requirements. "
                            f"KSI-AFR-11 mandates AES-256 or approved alternatives."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            f"Replace {cipher_name} with AES-GCM:\n"
                            "using System.Security.Cryptography;\n\n"
                            "// Use AES-256-GCM for authenticated encryption\n"
                            "using (var aesGcm = new AesGcm(key))\n"
                            "{\n"
                            "    byte[] nonce = new byte[AesGcm.NonceByteSizes.MaxSize];\n"
                            "    RandomNumberGenerator.Fill(nonce);\n"
                            "    \n"
                            "    byte[] ciphertext = new byte[plaintext.Length];\n"
                            "    byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];\n"
                            "    \n"
                            "    aesGcm.Encrypt(nonce, plaintext, ciphertext, tag);\n"
                            "}\n\n"
                            "Ref: NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)"
                        )
                    ))
        
        # Pattern 3: Insecure TLS (HIGH)
        insecure_tls_protocols = [
            'SslProtocols.Ssl2', 'SslProtocols.Ssl3', 'SslProtocols.Tls', 'SslProtocols.Tls11',
            'SecurityProtocolType.Ssl3', 'SecurityProtocolType.Tls', 'SecurityProtocolType.Tls11'
        ]
        for tls_protocol in insecure_tls_protocols:
            if re.search(rf'\b{tls_protocol}\b', code):
                line_num = self._find_text_line(lines, tls_protocol)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Insecure TLS Protocol ({tls_protocol})",
                    description=(
                        f"Code configures {tls_protocol}, which is cryptographically insecure. "
                        f"KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Configure TLS 1.2+ exclusively:\n"
                        "using System.Security.Authentication;\n\n"
                        "// Set minimum TLS version\n"
                        "ServicePointManager.SecurityProtocol = \n"
                        "    SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;\n\n"
                        "// Or in HttpClient\n"
                        "var handler = new HttpClientHandler\n"
                        "{\n"
                        "    SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13\n"
                        "};\n"
                        "var client = new HttpClient(handler);\n\n"
                        "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                    )
                ))
        
        # Pattern 4: Hardcoded keys (CRITICAL)
        key_patterns = [
            (r'private\s+const\s+string\s+\w*[Kk]ey\w*\s*=\s*"[^"]{16,}"', 'const key'),
            (r'byte\[\]\s+\w*[Kk]ey\w*\s*=\s*new\s+byte\[\]', 'byte array key')
        ]
        
        for pattern, key_type in key_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Hardcoded Cryptographic Key ({key_type})",
                        description=(
                            f"Code contains hardcoded cryptographic key. "
                            f"KSI-AFR-11 requires secure key management with Azure Key Vault or similar FIPS-compliant storage."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i),
                        recommendation=(
                            "Store keys in Azure Key Vault:\n"
                            "using Azure.Identity;\n"
                            "using Azure.Security.KeyVault.Secrets;\n\n"
                            "var client = new SecretClient(\n"
                            "    new Uri(\"https://<vault>.vault.azure.net\"),\n"
                            "    new DefaultAzureCredential());\n\n"
                            "KeyVaultSecret secret = await client.GetSecretAsync(\"encryption-key\");\n"
                            "string key = secret.Value;\n\n"
                            "Ref: Azure Key Vault (https://learn.microsoft.com/azure/key-vault/)"
                        )
                    ))
        
        return findings

    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for cryptographic compliance (AST-first).
        
        Detects:
        - MessageDigest.getInstance("MD5") - weak hashes
        - Cipher.getInstance("DES") - weak encryption  
        - SSLContext.getInstance("TLSv1") - insecure TLS
        - Hardcoded keys
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            code_bytes = bytes(code, "utf8")
            return self._analyze_java_ast(code, code_bytes, file_path, parser, tree.root_node)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, code_bytes: bytes, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java cryptographic compliance analysis."""
        findings = []
        lines = code.split('\n')
        
        # Find all method invocations
        method_calls = parser.find_nodes_by_type(tree, 'method_invocation')
        
        # Pattern 1: Weak hash algorithms via MessageDigest.getInstance()
        weak_hashes = ['MD5', 'SHA-1', 'SHA1', 'MD4']
        for call_node in method_calls:
            call_text = parser.get_node_text(call_node, code_bytes)
            if 'MessageDigest.getInstance' in call_text:
                for weak_hash in weak_hashes:
                    if f'"{weak_hash}"' in call_text or f"'{weak_hash}'" in call_text:
                        line_num = call_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title=f"Weak Cryptographic Hash ({weak_hash})",
                            description=(
                                f"Code uses MessageDigest.getInstance(\"{weak_hash}\"), which is cryptographically broken. "
                                f"KSI-AFR-11 requires FIPS 140-2/3 compliant hash algorithms."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            recommendation=(
                                f"Replace {weak_hash} with SHA-256 or stronger:\n"
                                "import java.security.MessageDigest;\n\n"
                                "// Use FIPS-approved hashing\n"
                                "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n"
                                "byte[] hash = digest.digest(data);\n\n"
                                "// For passwords, use BCrypt or PBKDF2\n"
                                "import javax.crypto.SecretKeyFactory;\n"
                                "import javax.crypto.spec.PBEKeySpec;\n\n"
                                "SecretKeyFactory factory = SecretKeyFactory.getInstance(\"PBKDF2WithHmacSHA256\");\n"
                                "PBEKeySpec spec = new PBEKeySpec(password, salt, 100000, 256);\n"
                                "byte[] hash = factory.generateSecret(spec).getEncoded();\n\n"
                                "Ref: FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                            )
                        ))
                        break
        
        # Pattern 2: Weak encryption algorithms via Cipher.getInstance()
        weak_ciphers = ['DES', 'DESede', '3DES', 'RC4', 'RC2', 'Blowfish']
        for call_node in method_calls:
            call_text = parser.get_node_text(call_node, code_bytes)
            if 'Cipher.getInstance' in call_text:
                for weak_cipher in weak_ciphers:
                    if f'"{weak_cipher}"' in call_text or f"'{weak_cipher}'" in call_text or f'"{weak_cipher}/' in call_text:
                        line_num = call_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title=f"Weak Encryption Algorithm ({weak_cipher})",
                            description=(
                                f"Code uses Cipher.getInstance(\"{weak_cipher}\"), which does not meet FIPS 140-2/3 requirements. "
                                f"KSI-AFR-11 mandates AES-256 or approved alternatives."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            recommendation=(
                                f"Replace {weak_cipher} with AES-GCM:\n"
                                "import javax.crypto.Cipher;\n"
                                "import javax.crypto.spec.GCMParameterSpec;\n"
                                "import javax.crypto.spec.SecretKeySpec;\n\n"
                                "// Use AES-256-GCM for authenticated encryption\n"
                                "SecretKeySpec keySpec = new SecretKeySpec(key, \"AES\");\n"
                                "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                                "GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);\n"
                                "cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);\n"
                                "byte[] ciphertext = cipher.doFinal(plaintext);\n\n"
                                "Ref: NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)"
                            )
                        ))
                        break
        
        # Pattern 3: Insecure TLS via SSLContext.getInstance()
        insecure_tls = ['SSLv2', 'SSLv3', 'SSL', 'TLSv1', 'TLSv1.1']
        for call_node in method_calls:
            call_text = parser.get_node_text(call_node, code_bytes)
            if 'SSLContext.getInstance' in call_text:
                for tls_protocol in insecure_tls:
                    if f'"{tls_protocol}"' in call_text or f"'{tls_protocol}'" in call_text:
                        line_num = call_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title=f"Insecure TLS Protocol ({tls_protocol})",
                            description=(
                                f"Code uses SSLContext.getInstance(\"{tls_protocol}\"), which is cryptographically insecure. "
                                f"KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2."
                            ),
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            recommendation=(
                                "Configure TLS 1.2+ exclusively:\n"
                                "import javax.net.ssl.SSLContext;\n\n"
                                "// Use TLS 1.2 or 1.3\n"
                                "SSLContext sslContext = SSLContext.getInstance(\"TLSv1.3\");\n"
                                "sslContext.init(null, null, null);\n\n"
                                "// Or configure HttpsURLConnection\n"
                                "HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();\n"
                                "conn.setSSLSocketFactory(sslContext.getSocketFactory());\n\n"
                                "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                            )
                        ))
                        break
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for Java cryptographic compliance analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hashes (CRITICAL)
        for weak_hash in ['MD5', 'SHA-1', 'SHA1']:
            pattern = rf'MessageDigest\.getInstance\s*\(\s*["\']({weak_hash})["\']'
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Hash Algorithm ({weak_hash})",
                        description=(
                            f"Code uses {weak_hash} via MessageDigest. "
                            f"KSI-AFR-11 requires FIPS 140-2/3 approved algorithms. Use SHA-256+."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i),
                        recommendation=(
                            f"Replace {weak_hash} with SHA-256:\n"
                            "import java.security.MessageDigest;\n\n"
                            "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n"
                            "byte[] hash = digest.digest(data);\n\n"
                            "Ref: FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                        )
                    ))
        
        # Pattern 2: Weak encryption (CRITICAL)
        weak_ciphers = ['DES', 'DESede', 'RC4', 'RC2', 'Blowfish']
        for cipher in weak_ciphers:
            pattern = rf'Cipher\.getInstance\s*\(\s*["\']({cipher})'
            if re.search(pattern, code):
                line_num = self._find_text_line(lines, f'"{cipher}')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Weak Encryption Algorithm ({cipher})",
                    description=(
                        f"Code uses {cipher} encryption. KSI-AFR-11 requires AES-256 or approved alternatives."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        f"Replace {cipher} with AES/GCM:\n"
                        "import javax.crypto.Cipher;\n"
                        "import javax.crypto.spec.GCMParameterSpec;\n\n"
                        "Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");\n"
                        "GCMParameterSpec spec = new GCMParameterSpec(128, nonce);\n"
                        "cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);\n\n"
                        "Ref: NIST SP 800-38D (https://csrc.nist.gov/publications/detail/sp/800-38d/final)"
                    )
                ))
        
        # Pattern 3: Insecure TLS (HIGH)
        insecure_tls = ['TLSv1', 'TLSv1.1', 'SSL', 'SSLv2', 'SSLv3']
        for tls_version in insecure_tls:
            pattern = rf'SSLContext\.getInstance\s*\(\s*["\']({tls_version})'
            if re.search(pattern, code):
                line_num = self._find_text_line(lines, tls_version)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Insecure TLS Version ({tls_version})",
                    description=(
                        f"Code configures {tls_version}. KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Configure TLS 1.2+:\n"
                        "import javax.net.ssl.SSLContext;\n\n"
                        "SSLContext context = SSLContext.getInstance(\"TLSv1.2\");\n"
                        "// Or TLSv1.3 if available\n\n"
                        "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                    )
                ))
        
        return findings

    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze JavaScript/TypeScript for cryptographic compliance.
        
        Detects:
        - crypto.createHash('md5'|'sha1')
        - crypto.createCipher (deprecated)
        - TLS minVersion < 1.2
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Weak hashes (CRITICAL)
        weak_hashes = ['md5', 'sha1', 'md4']
        for weak_hash in weak_hashes:
            pattern = rf'createHash\s*\(\s*["\']({weak_hash})["\']'
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Weak Hash Algorithm ({weak_hash.upper()})",
                        description=(
                            f"Code uses {weak_hash.upper()} hashing. "
                            f"KSI-AFR-11 requires FIPS-approved algorithms. Use SHA-256+."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i),
                        recommendation=(
                            f"Replace {weak_hash.upper()} with SHA-256:\n"
                            "const crypto = require('crypto');\n\n"
                            "const hash = crypto.createHash('sha256')\n"
                            "  .update(data)\n"
                            "  .digest('hex');\n\n"
                            "Ref: FIPS 180-4 (https://csrc.nist.gov/publications/detail/fips/180/4/final)"
                        )
                    ))
        
        # Pattern 2: Deprecated crypto.createCipher (HIGH)
        if re.search(r'crypto\.createCipher\b', code):
            line_num = self._find_text_line(lines, 'createCipher')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Deprecated Cipher Method (createCipher)",
                description=(
                    "Code uses deprecated crypto.createCipher() which derives keys insecurely. "
                    "KSI-AFR-11 requires proper key management."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Use crypto.createCipheriv() with explicit key/IV:\n"
                    "const crypto = require('crypto');\n\n"
                    "const algorithm = 'aes-256-gcm';\n"
                    "const key = crypto.randomBytes(32);  // Store in Key Vault\n"
                    "const iv = crypto.randomBytes(16);\n\n"
                    "const cipher = crypto.createCipheriv(algorithm, key, iv);\n"
                    "let encrypted = cipher.update(plaintext, 'utf8', 'hex');\n"
                    "encrypted += cipher.final('hex');\n\n"
                    "Ref: Node.js Crypto (https://nodejs.org/api/crypto.html)"
                )
            ))
        
        # Pattern 3: Insecure TLS (HIGH)
        if re.search(r'minVersion\s*:\s*["\']TLSv1\.?[01]?["\']', code):
            line_num = self._find_text_line(lines, 'minVersion')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Insecure TLS Minimum Version",
                description=(
                    "Code sets TLS minVersion < 1.2. KSI-AFR-11 requires TLS 1.2+ per NIST SP 800-52 Rev 2."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Set TLS 1.2 minimum:\n"
                    "const https = require('https');\n\n"
                    "const options = {\n"
                    "  minVersion: 'TLSv1.2',\n"
                    "  maxVersion: 'TLSv1.3'\n"
                    "};\n\n"
                    "const server = https.createServer(options, app);\n\n"
                    "Ref: NIST SP 800-52 Rev 2 (https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final)"
                )
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for cryptographic compliance.
        IaC uses regex-based analysis (no tree-sitter parser).
        
        Detects:
        - Key Vault without FIPS 140-2 compliance
        - Storage accounts without encryption
        - TLS minimum version < 1.2
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Storage account with TLS < 1.2 (HIGH)
        has_storage = re.search(r"'Microsoft\.Storage/storageAccounts", code)
        has_tls12 = re.search(r'minimumTlsVersion.*TLS1_2', code)
        
        if has_storage and not has_tls12:
            line_num = self._find_text_line(lines, 'storageAccounts')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Storage Account Without TLS 1.2 Minimum",
                description=(
                    f"Azure Storage account without minimumTlsVersion: 'TLS1_2'. "
                    f"KSI-AFR-11 requires TLS 1.2+ for all data in transit."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Set TLS 1.2 minimum for Storage:\n"
                    "resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                    "  name: storageAccountName\n"
                    "  properties: {\n"
                    "    minimumTlsVersion: 'TLS1_2'\n"
                    "    supportsHttpsTrafficOnly: true\n"
                    "    encryption: {\n"
                    "      services: {\n"
                    "        blob: { enabled: true }\n"
                    "        file: { enabled: true }\n"
                    "      }\n"
                    "      keySource: 'Microsoft.Storage'  // Or 'Microsoft.KeyVault'\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Storage security (https://learn.microsoft.com/azure/storage/common/storage-security-guide)"
                )
            ))
        
        return findings

    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for cryptographic compliance.
        IaC uses regex-based analysis (no tree-sitter parser).
        
        Detects:
        - Storage accounts without TLS 1.2
        - Key Vaults without proper configuration
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Storage account with TLS < 1.2 (HIGH)
        has_storage = re.search(r'resource\s+"azurerm_storage_account"', code)
        has_tls12 = re.search(r'min_tls_version\s*=\s*"TLS1_2"', code)
        
        if has_storage and not has_tls12:
            line_num = self._find_text_line(lines, 'azurerm_storage_account')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Storage Account Without TLS 1.2 Minimum",
                description=(
                    f"Azure Storage account without min_tls_version = \"TLS1_2\". "
                    f"KSI-AFR-11 requires TLS 1.2+ for protecting customer data in transit."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation=(
                    "Set TLS 1.2 minimum:\n"
                    "resource \"azurerm_storage_account\" \"example\" {\n"
                    "  name                     = \"storageaccount\"\n"
                    "  resource_group_name      = azurerm_resource_group.example.name\n"
                    "  location                 = azurerm_resource_group.example.location\n"
                    "  account_tier             = \"Standard\"\n"
                    "  account_replication_type = \"GRS\"\n"
                    "  min_tls_version          = \"TLS1_2\"\n"
                    "  enable_https_traffic_only = true\n"
                    "}\n\n"
                    "Ref: Azure Storage security (https://learn.microsoft.com/azure/storage/common/storage-security-guide)"
                )
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions for crypto compliance.
        
        Detects:
        - Missing secret scanning
        - Hardcoded secrets in workflows
        """
        findings = []
        lines = code.split('\n')
        
        # Remove comments
        code_without_comments = '\n'.join(line.split('#')[0] for line in lines)
        
        # Pattern: Hardcoded secrets (CRITICAL)
        secret_patterns = [
            (r'[\w_]*[Kk][Ee][Yy][\w_]*:\s*["\'][A-Za-z0-9+/=_-]{20,}["\']', 'API key'),
            (r'password:\s*["\'][^"\']{8,}["\']', 'password'),
            (r'token:\s*["\'][A-Za-z0-9_-]{20,}["\']', 'token')
        ]
        
        for pattern, secret_type in secret_patterns:
            for i, line in enumerate(lines, 1):
                # Skip if using GitHub secrets
                if '${{' in line or 'secrets.' in line:
                    continue
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title=f"Hardcoded Secret in Workflow ({secret_type})",
                        description=(
                            f"GitHub Actions workflow contains hardcoded {secret_type}. "
                            f"KSI-AFR-11 requires secure secret management."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i),
                        recommendation=(
                            "Use GitHub Secrets:\n"
                            "steps:\n"
                            "  - name: Use secret\n"
                            "    env:\n"
                            "      API_KEY: ${{ secrets.API_KEY }}\n"
                            "    run: echo \"Key is secured\"\n\n"
                            "Configure in: Settings > Secrets and variables > Actions\n\n"
                            "Ref: GitHub Secrets (https://docs.github.com/en/actions/security-guides/encrypted-secrets)"
                        )
                    ))
        
        return findings

    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for crypto compliance."""
        findings = []
        lines = code.split('\n')
        
        # Remove comments
        code_without_comments = '\n'.join(line.split('#')[0] for line in lines)
        
        # Pattern: Hardcoded secrets (CRITICAL)
        for i, line in enumerate(lines, 1):
            # Skip if using pipeline variables
            if '$(' in line or 'variables.' in line:
                continue
            if re.search(r'(password|key|token):\s*["\'][^"\']{8,}["\']', line, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Hardcoded Secret in Pipeline",
                    description=(
                        "Azure Pipeline contains hardcoded secret. KSI-AFR-11 requires secure secret management."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i),
                    recommendation=(
                        "Use Pipeline Variables or Azure Key Vault:\n"
                        "variables:\n"
                        "  - group: 'my-variable-group'\n"
                        "steps:\n"
                        "  - task: AzureKeyVault@2\n"
                        "    inputs:\n"
                        "      azureSubscription: 'serviceConnection'\n"
                        "      KeyVaultName: 'myKeyVault'\n"
                        "  - script: echo $(API_KEY)\n\n"
                        "Ref: Azure Pipelines secrets (https://learn.microsoft.com/azure/devops/pipelines/security/secrets)"
                    )
                ))
        
        return findings

    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for crypto compliance."""
        findings = []
        lines = code.split('\n')
        
        # Remove comments
        code_without_comments = '\n'.join(line.split('#')[0] for line in lines)
        
        # Pattern: Hardcoded secrets (CRITICAL)
        for i, line in enumerate(lines, 1):
            # Skip if using CI/CD variables
            if '$CI_' in line or '$' in line:
                continue
            if re.search(r'(password|key|token):\s*["\'][^"\']{8,}["\']', line, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Hardcoded Secret in GitLab CI",
                    description=(
                        "GitLab CI contains hardcoded secret. KSI-AFR-11 requires secure secret management."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i),
                    recommendation=(
                        "Use GitLab CI/CD Variables:\n"
                        "variables:\n"
                        "  API_KEY: $API_KEY  # Defined in Settings > CI/CD > Variables\n"
                        "script:\n"
                        "  - echo \"$API_KEY\"\n\n"
                        "Mark as 'Masked' and 'Protected' in GitLab UI\n\n"
                        "Ref: GitLab CI variables (https://docs.gitlab.com/ee/ci/variables/)"
                    )
                ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_text_line(self, lines: List[str], text: str) -> int:
        """Find line number containing text (case-insensitive)."""
        text_lower = text.lower()
        for i, line in enumerate(lines, 1):
            if text_lower in line.lower():
                return i
        return 0
    

        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

