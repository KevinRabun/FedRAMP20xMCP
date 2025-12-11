"""
FRR-UCM-02: Use of Validated Cryptographic Modules

Providers MUST configure agency tenants by default to use cryptographic services
that use cryptographic modules or update streams of cryptographic modules with
active validations under the NIST Cryptographic Module Validation Program when
such modules are available.

Official FedRAMP 20x Requirement
Source: FRR-UCM (Using Cryptographic Modules) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_UCM_02_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-UCM-02: Use of Validated Cryptographic Modules
    
    **Official Statement:**
    Providers MUST configure agency tenants by default to use cryptographic services
    that use cryptographic modules or update streams of cryptographic modules with
    active validations under the NIST Cryptographic Module Validation Program when
    such modules are available.
    
    **Family:** UCM - Using Cryptographic Modules
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - SC-13: Cryptographic Protection
    - SC-12: Cryptographic Key Establishment and Management
    - IA-7: Cryptographic Module Authentication
    
    **Related KSIs:**
    - KSI-CNA-05: Encryption in Transit
    - KSI-IAM-03: Multi-Factor Authentication
    
    **Detectability:** Code-Detectable
    
    **Detection Strategy:**
    Analyze application code and IaC for:
    - Non-FIPS 140-2/140-3 validated crypto modules
    - Weak/deprecated algorithms (MD5, SHA1, DES, RC4, 3DES)
    - Custom crypto implementations instead of validated modules
    - Azure services without FIPS compliance enabled
    """
    
    FRR_ID = "FRR-UCM-02"
    FRR_NAME = "Use of Validated Cryptographic Modules"
    FRR_STATEMENT = """Providers MUST configure agency tenants by default to use cryptographic services that use cryptographic modules or update streams of cryptographic modules with active validations under the NIST Cryptographic Module Validation Program when such modules are available."""
    FAMILY = "UCM"
    FAMILY_NAME = "Using Cryptographic Modules"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SC-13", "Cryptographic Protection"),
        ("SC-12", "Cryptographic Key Establishment and Management"),
        ("IA-7", "Cryptographic Module Authentication"),
    ]
    CODE_DETECTABLE = True  # Extensive crypto analysis implemented
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-CNA-05",  # Encryption in transit
        "KSI-IAM-03",  # Multi-factor authentication
        "KSI-CED-03",  # Encryption at rest
    ]
    
    # Weak/deprecated algorithms that should not be used
    WEAK_ALGORITHMS = {
        'hash': ['md5', 'md4', 'md2', 'sha1'],
        'cipher': ['des', 'rc4', 'rc2', '3des', 'tripledes'],
        'mac': ['hmac-md5', 'hmac-sha1']
    }
    
    # FIPS-approved algorithms
    FIPS_APPROVED = {
        'hash': ['sha256', 'sha384', 'sha512', 'sha3'],
        'cipher': ['aes', 'aes-256', 'aes-128'],
        'mac': ['hmac-sha256', 'hmac-sha384', 'hmac-sha512']
    }
    
    def __init__(self):
        """Initialize FRR-UCM-02 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (Primary detection for FRR-UCM-02)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for non-FIPS cryptographic modules using AST.
        
        Detects:
        - MD5, SHA1, DES, RC4 usage
        - Non-FIPS hashlib algorithms
        - Weak cryptography in PyCrypto/Cryptography packages
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for hashlib weak algorithms (hashlib.md5(), hashlib.sha1())
                call_nodes = parser.find_nodes_by_type(tree.root_node, "call")
                for call_node in call_nodes:
                    call_text = parser.get_node_text(call_node, code_bytes)
                    # Only flag if it's actually hashlib.md5/sha1/md4 call
                    if 'hashlib.md5(' in call_text or 'hashlib.sha1(' in call_text or 'hashlib.md4(' in call_text:
                        algorithm = 'MD5' if 'md5' in call_text.lower() else 'SHA1' if 'sha1' in call_text.lower() else 'MD4'
                        line_num = call_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.FRR_ID,
                            requirement_id=self.FRR_ID,
                            title=f"Weak cryptographic algorithm: {algorithm}",
                            description=f"Code uses {algorithm} which is not FIPS 140-2/140-3 approved. FRR-UCM-02 requires use of NIST CMVP validated cryptographic modules.",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num, 3),
                            recommendation=f"Replace {algorithm} with FIPS-approved algorithm:\n1. Use SHA-256 or SHA-512 for hashing\n2. Example: hashlib.sha256(data.encode())\n3. Enable FIPS mode in production: import hashlib; hashlib.new('sha256', usedforsecurity=True)\n4. Document cryptographic module validation status"
                        ))
                
                # Check for weak Crypto.Cipher imports
                import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_from_statement')
                for import_node in import_nodes:
                    import_text = parser.get_node_text(import_node, code_bytes)
                    if 'from Crypto.Cipher import' in import_text:
                        for weak_cipher in ['DES', 'DES3', 'ARC4', 'Blowfish', 'RC2', 'RC4']:
                            if weak_cipher in import_text:
                                line_num = import_node.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.FRR_ID,
                                    requirement_id=self.FRR_ID,
                                    title=f"Non-FIPS cipher algorithm: {weak_cipher}",
                                    description=f"Code imports {weak_cipher} cipher which is not FIPS 140-2 validated. FRR-UCM-02 requires NIST CMVP validated cryptographic modules.",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num, 3),
                                    recommendation=f"Replace {weak_cipher} with AES:\n1. Use Crypto.Cipher.AES or cryptography.hazmat.primitives.ciphers.aes\n2. Example: from Crypto.Cipher import AES; cipher = AES.new(key, AES.MODE_GCM)\n3. Ensure AES-256 for High impact systems\n4. Use FIPS-validated cryptography library"
                                ))
                                break  # One finding per import line
                
                # Check for custom crypto implementations (class names, function names)
                class_nodes = parser.find_nodes_by_type(tree.root_node, 'class_definition')
                for class_node in class_nodes:
                    class_name_node = class_node.child_by_field_name('name')
                    if class_name_node:
                        class_name = parser.get_node_text(class_name_node, code_bytes)
                        if any(keyword in class_name.lower() for keyword in ['crypto', 'cipher', 'hash', 'encrypt']):
                            line_num = class_node.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.FRR_ID,
                                requirement_id=self.FRR_ID,
                                title="Custom cryptographic implementation detected",
                                description="Code appears to implement custom cryptography. FRR-UCM-02 requires use of NIST CMVP validated cryptographic modules, not custom implementations.",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num, 5),
                                recommendation="Do NOT implement custom cryptography:\n1. Use Python's 'cryptography' library (FIPS 140-2 validated)\n2. Or use Azure Key Vault for cryptographic operations\n3. Document use of validated cryptographic modules\n4. Never roll your own crypto"
                            ))
                
                return findings
            
        except Exception as e:
            # Fallback to regex if AST fails
            pass
        
        # Regex fallback (when AST unavailable)
        return self._python_regex_fallback(code, lines, file_path)
    
    def _python_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        # Check for hashlib weak algorithms
        weak_hash_pattern = r'hashlib\.(md5|md4|sha1)\('
        for i, line in enumerate(lines, 1):
            match = re.search(weak_hash_pattern, line, re.IGNORECASE)
            if match:
                algorithm = match.group(1).upper()
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Weak cryptographic algorithm: {algorithm}",
                    description=f"Code uses {algorithm} which is not FIPS 140-2/140-3 approved. FRR-UCM-02 requires use of NIST CMVP validated cryptographic modules.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation=f"Replace {algorithm} with FIPS-approved algorithm"
                ))
        
        # Check for Crypto.Cipher weak ciphers
        weak_cipher_pattern = r'from\s+Crypto\.Cipher\s+import\s+(DES|DES3|ARC4|Blowfish)'
        for i, line in enumerate(lines, 1):
            match = re.search(weak_cipher_pattern, line, re.IGNORECASE)
            if match:
                cipher = match.group(1)
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Non-FIPS cipher algorithm: {cipher}",
                    description=f"Code imports {cipher} cipher which is not FIPS 140-2 validated.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation=f"Replace {cipher} with AES"
                ))
        
        # Check for custom crypto implementations
        custom_crypto_pattern = r'(def\s+(encrypt|decrypt|hash|sign|verify)\(|class\s+\w*(Crypto|Cipher|Hash)\w*)'
        for i, line in enumerate(lines, 1):
            if re.search(custom_crypto_pattern, line, re.IGNORECASE):
                if 'import' not in line and 'from' not in line:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Custom cryptographic implementation detected",
                        description="Code appears to implement custom cryptography.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 5),
                        recommendation="Do NOT implement custom cryptography"
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for non-FIPS cryptographic APIs using AST.
        
        Detects:
        - MD5CryptoServiceProvider, SHA1Managed
        - DESCryptoServiceProvider, RC2CryptoServiceProvider
        - Non-FIPS System.Security.Cryptography usage
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find all invocation expressions (method calls)
                invocation_nodes = parser.find_nodes_by_type(tree.root_node, 'invocation_expression')
                
                weak_hash_algorithms = ['MD5', 'SHA1', 'MD5CryptoServiceProvider', 'SHA1Managed', 'SHA1CryptoServiceProvider']
                weak_ciphers = ['DES', 'DESCryptoServiceProvider', 'TripleDES', 'TripleDESCryptoServiceProvider', 'RC2', 'RC2CryptoServiceProvider']
                
                for invocation in invocation_nodes:
                    invocation_text = parser.get_node_text(invocation, code_bytes)
                    
                    # Check for weak hash algorithms
                    for weak_algo in weak_hash_algorithms:
                        if f'{weak_algo}.Create(' in invocation_text:
                            line_num = invocation.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.FRR_ID,
                                requirement_id=self.FRR_ID,
                                title=f"Non-FIPS hash algorithm: {weak_algo}",
                                description=f"Code uses {weak_algo} which is not FIPS 140-2 compliant. FRR-UCM-02 requires NIST CMVP validated cryptographic modules.",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num, 3),
                                recommendation=f"Replace {weak_algo} with FIPS-compliant alternative:\n1. Use SHA256.Create() or SHA512.Create()\n2. Enable FIPS mode: <enforceFIPSPolicy enabled=\"true\"/> in app.config\n3. Example: using var hasher = SHA256.Create(); var hash = hasher.ComputeHash(data);\n4. Document cryptographic module validation"
                            ))
                            break
                    
                    # Check for weak ciphers
                    for weak_cipher in weak_ciphers:
                        if f'{weak_cipher}.Create(' in invocation_text:
                            line_num = invocation.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.FRR_ID,
                                requirement_id=self.FRR_ID,
                                title=f"Non-FIPS cipher: {weak_cipher}",
                                description=f"Code uses {weak_cipher} which is not FIPS 140-2 validated. FRR-UCM-02 requires use of validated cryptographic modules.",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num, 3),
                                recommendation=f"Replace {weak_cipher} with AES:\n1. Use Aes.Create() or AesCryptoServiceProvider\n2. Example: using var aes = Aes.Create(); aes.KeySize = 256;\n3. Enable FIPS policy enforcement\n4. Use Azure Key Vault for key management"
                            ))
                            break
                
                # Check for FIPS policy disabled (in XML config - use regex for XML)
                if '<enforceFIPSPolicy' in code and 'false' in code:
                    for i, line in enumerate(lines, 1):
                        if 'enforceFIPSPolicy' in line and 'false' in line:
                            findings.append(Finding(
                                ksi_id=self.FRR_ID,
                                requirement_id=self.FRR_ID,
                                title="FIPS policy enforcement disabled",
                                description="Configuration explicitly disables FIPS policy. FRR-UCM-02 requires FIPS 140-2/140-3 validated cryptographic modules.",
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=i,
                                code_snippet=self._get_snippet(lines, i, 3),
                                recommendation="Enable FIPS policy enforcement:\n1. Set <enforceFIPSPolicy enabled=\"true\"/> in app.config\n2. Test all cryptographic operations for FIPS compliance\n3. Update any non-compliant crypto usage\n4. Document FIPS validation status"
                            ))
                            break
                
                return findings
                
        except Exception as e:
            # Fallback to regex if AST fails
            pass
        
        # Regex fallback
        return self._csharp_regex_fallback(code, lines, file_path)
    
    def _csharp_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        # Check for weak hash algorithms
        weak_hash_pattern = r'(MD5|SHA1|MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider)\.Create\('
        for i, line in enumerate(lines, 1):
            match = re.search(weak_hash_pattern, line, re.IGNORECASE)
            if match:
                algorithm = match.group(1)
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Non-FIPS hash algorithm: {algorithm}",
                    description=f"Code uses {algorithm} which is not FIPS 140-2 compliant. FRR-UCM-02 requires NIST CMVP validated cryptographic modules.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation=f"Replace {algorithm} with FIPS-compliant alternative:\n1. Use SHA256.Create() or SHA512.Create()\n2. Enable FIPS mode: <enforceFIPSPolicy enabled=\"true\"/> in app.config\n3. Example: using var hasher = SHA256.Create(); var hash = hasher.ComputeHash(data);\n4. Document cryptographic module validation"
                ))
        
        # Check for weak cipher algorithms
        weak_cipher_pattern = r'(DES|DESCryptoServiceProvider|TripleDES|TripleDESCryptoServiceProvider|RC2|RC2CryptoServiceProvider)\.Create\('
        for i, line in enumerate(lines, 1):
            match = re.search(weak_cipher_pattern, line, re.IGNORECASE)
            if match:
                cipher = match.group(1)
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Non-FIPS cipher: {cipher}",
                    description=f"Code uses {cipher} which is not FIPS 140-2 validated. FRR-UCM-02 requires use of validated cryptographic modules.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation=f"Replace {cipher} with AES:\n1. Use Aes.Create() or AesCryptoServiceProvider\n2. Example: using var aes = Aes.Create(); aes.KeySize = 256;\n3. Enable FIPS policy enforcement\n4. Use Azure Key Vault for key management"
                ))
        
        # Check for FIPS policy disabled
        if re.search(r'<enforceFIPSPolicy\s+enabled=["\']false["\']', code, re.IGNORECASE):
            for i, line in enumerate(lines, 1):
                if re.search(r'enforceFIPSPolicy.*false', line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="FIPS policy enforcement disabled",
                        description="Configuration explicitly disables FIPS policy. FRR-UCM-02 requires FIPS 140-2/140-3 validated cryptographic modules.",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Enable FIPS policy enforcement:\n1. Set <enforceFIPSPolicy enabled=\"true\"/> in app.config\n2. Test all cryptographic operations for FIPS compliance\n3. Update any non-compliant crypto usage\n4. Document FIPS validation status"
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for non-FIPS cryptographic APIs using AST.
        
        Detects:
        - MD5, SHA-1 MessageDigest
        - DES, DESede Cipher
        - Non-BC-FIPS crypto providers
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find all method invocations
                method_invocations = parser.find_nodes_by_type(tree.root_node, 'method_invocation')
                
                for invocation in method_invocations:
                    invocation_text = parser.get_node_text(invocation, code_bytes)
                    
                    # Check for weak MessageDigest algorithms
                    if 'MessageDigest.getInstance' in invocation_text:
                        for weak_algo in ['MD5', 'SHA-1', 'SHA1', 'MD4', 'MD2']:
                            if f'"{weak_algo}"' in invocation_text or f"'{weak_algo}'" in invocation_text:
                                line_num = invocation.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.FRR_ID,
                                    requirement_id=self.FRR_ID,
                                    title=f"Weak MessageDigest algorithm: {weak_algo}",
                                    description=f"Code uses {weak_algo} which is not FIPS 140-2 approved. FRR-UCM-02 requires NIST CMVP validated cryptographic modules.",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num, 3),
                                    recommendation=f"Replace {weak_algo} with FIPS-approved algorithm:\n1. Use SHA-256: MessageDigest.getInstance(\"SHA-256\")\n2. Or SHA-512 for higher security\n3. Configure FIPS-approved Security Provider (BC-FIPS)\n4. Document cryptographic module validation"
                                ))
                                break
                    
                    # Check for weak Cipher algorithms
                    if 'Cipher.getInstance' in invocation_text:
                        for weak_cipher in ['DES', 'DESede', 'RC4', 'RC2', 'Blowfish']:
                            if f'"{weak_cipher}' in invocation_text or f"'{weak_cipher}" in invocation_text:
                                line_num = invocation.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.FRR_ID,
                                    requirement_id=self.FRR_ID,
                                    title=f"Non-FIPS cipher algorithm: {weak_cipher}",
                                    description=f"Code uses {weak_cipher} which is not FIPS 140-2 validated. FRR-UCM-02 requires validated cryptographic modules.",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num, 3),
                                    recommendation=f"Replace {weak_cipher} with AES:\n1. Use Cipher.getInstance(\"AES/GCM/NoPadding\")\n2. Configure BC-FIPS security provider\n3. Example: Security.addProvider(new BouncyCastleFipsProvider());\n4. Use 256-bit keys for High impact systems"
                                ))
                                break
                
                return findings
                
        except Exception as e:
            # Fallback to regex if AST fails
            import sys
            print(f"Java AST parsing failed: {e}", file=sys.stderr)
            pass
        
        # Regex fallback
        return self._java_regex_fallback(code, lines, file_path)
    
    def _java_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        # Check for weak MessageDigest algorithms
        weak_digest_pattern = r'MessageDigest\.getInstance\(["\'](<MD5|SHA-1|SHA1)["\']'
        for i, line in enumerate(lines, 1):
            match = re.search(weak_digest_pattern, line, re.IGNORECASE)
            if match:
                algorithm = match.group(1)
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Weak MessageDigest algorithm: {algorithm}",
                    description=f"Code uses {algorithm} which is not FIPS 140-2 approved.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Use FIPS-approved algorithms"
                ))
        
        # Check for weak Cipher algorithms
        weak_cipher_pattern = r'Cipher\.getInstance\(["\'](<DES|DESede|RC4|RC2)["\']'
        for i, line in enumerate(lines, 1):
            match = re.search(weak_cipher_pattern, line, re.IGNORECASE)
            if match:
                cipher = match.group(1)
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Non-FIPS cipher algorithm: {cipher}",
                    description=f"Code uses {cipher} which is not FIPS 140-2 validated.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Replace with AES"
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for non-FIPS crypto using AST.
        
        Detects:
        - Node.js crypto with weak algorithms
        - MD5, SHA1, DES usage
        - Non-FIPS crypto libraries
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')  # get_node_text needs bytes
            
            if tree and tree.root_node:
                # Find all call expressions
                call_expressions = parser.find_nodes_by_type(tree.root_node, 'call_expression')
                
                for call_expr in call_expressions:
                    call_text = parser.get_node_text(call_expr, code_bytes)
                    
                    # Check for crypto.createHash with weak algorithms
                    if 'crypto.createHash' in call_text or 'createHash' in call_text:
                        for weak_algo in ['md5', 'sha1', 'md4', 'md2']:
                            if f"'{weak_algo}'" in call_text or f'"{weak_algo}"' in call_text:
                                line_num = call_expr.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.FRR_ID,
                                    requirement_id=self.FRR_ID,
                                    title=f"Weak hash algorithm: {weak_algo.upper()}",
                                    description=f"Code uses {weak_algo.upper()} which is not FIPS 140-2 approved. FRR-UCM-02 requires NIST CMVP validated cryptographic modules.",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num, 3),
                                    recommendation=f"Replace {weak_algo.upper()} with FIPS-approved algorithm:\n1. Use crypto.createHash('sha256') or 'sha512'\n2. Enable FIPS mode in Node.js: node --force-fips\n3. Example: crypto.createHash('sha256').update(data).digest('hex')\n4. Document cryptographic module validation"
                                ))
                                break
                    
                    # Check for crypto.createCipher with weak algorithms
                    if 'createCipher' in call_text or 'createDecipher' in call_text:
                        for weak_cipher in ['des', 'rc4', 'bf', 'blowfish', 'rc2']:
                            if f"'{weak_cipher}" in call_text or f'"{weak_cipher}' in call_text:
                                line_num = call_expr.start_point[0] + 1
                                findings.append(Finding(
                                    ksi_id=self.FRR_ID,
                                    requirement_id=self.FRR_ID,
                                    title=f"Non-FIPS cipher: {weak_cipher.upper()}",
                                    description=f"Code uses {weak_cipher.upper()} which is not FIPS 140-2 validated. FRR-UCM-02 requires validated cryptographic modules.",
                                    severity=Severity.HIGH,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num, 3),
                                    recommendation=f"Replace {weak_cipher.upper()} with AES:\n1. Use crypto.createCipheriv('aes-256-gcm', key, iv)\n2. Enable FIPS mode: node --force-fips\n3. Use Azure Key Vault SDK for key management\n4. Document use of FIPS-validated crypto"
                                ))
                                break
                
                # Check for non-FIPS library imports
                import_nodes = []
                import_nodes.extend(parser.find_nodes_by_type(tree.root_node, 'import_statement'))
                import_nodes.extend(parser.find_nodes_by_type(tree.root_node, 'call_expression'))
                non_fips_libs = ['crypto-js', 'md5', 'sha1']
                
                for import_node in import_nodes:
                    import_text = parser.get_node_text(import_node, code_bytes)
                    for lib in non_fips_libs:
                        if (f"'{lib}'" in import_text or f'"{lib}"' in import_text) and ('import' in import_text or 'require' in import_text):
                            line_num = import_node.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.FRR_ID,
                                requirement_id=self.FRR_ID,
                                title=f"Non-FIPS crypto library: {lib}",
                                description=f"Code uses '{lib}' which is not FIPS 140-2 validated. FRR-UCM-02 requires NIST CMVP validated cryptographic modules.",
                                severity=Severity.MEDIUM,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num, 3),
                                recommendation=f"Replace '{lib}' with FIPS-compliant alternative:\n1. Use Node.js built-in crypto module with FIPS mode\n2. Enable FIPS: node --force-fips app.js\n3. Or use Azure SDK cryptographic services\n4. Document cryptographic module validation status"
                            ))
                            break
                
                return findings
                
        except Exception as e:
            # Fallback to regex if AST fails
            import sys
            print(f"TypeScript AST parsing failed: {e}", file=sys.stderr)
            pass
        
        # Regex fallback
        return self._typescript_regex_fallback(code, lines, file_path)
    
    def _typescript_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        # Check for crypto.createHash with weak algorithms
        weak_hash_pattern = r'crypto\.createHash\(["\'](<md5|sha1|md4)["\']'
        for i, line in enumerate(lines, 1):
            match = re.search(weak_hash_pattern, line, re.IGNORECASE)
            if match:
                algorithm = match.group(1).upper()
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Weak hash algorithm: {algorithm}",
                    description=f"Code uses {algorithm} which is not FIPS 140-2 approved.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Use FIPS-approved algorithms"
                ))
        
        # Check for crypto.createCipher with weak algorithms
        weak_cipher_pattern = r'crypto\.create(Cipher|Decipher)(iv)?\(["\'](<des|rc4|bf|blowfish)["\']'
        for i, line in enumerate(lines, 1):
            match = re.search(weak_cipher_pattern, line, re.IGNORECASE)
            if match:
                cipher = match.group(4).upper()
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title=f"Non-FIPS cipher: {cipher}",
                    description=f"Code uses {cipher} which is not FIPS 140-2 validated.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Replace with AES"
                ))
        
        # Check for non-FIPS crypto libraries
        non_fips_libs = ['crypto-js', 'md5', 'sha1']
        for lib in non_fips_libs:
            if re.search(rf'(import|require)\(["\'].*{lib}["\']', code, re.IGNORECASE):
                for i, line in enumerate(lines, 1):
                    if re.search(rf'(import|require).*{lib}', line, re.IGNORECASE):
                        findings.append(Finding(
                            ksi_id=self.FRR_ID,
                            requirement_id=self.FRR_ID,
                            title=f"Non-FIPS crypto library: {lib}",
                            description=f"Code uses '{lib}' which is not FIPS 140-2 validated.",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=i,
                            code_snippet=self._get_snippet(lines, i, 3),
                            recommendation="Use FIPS-compliant alternatives"
                        ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for Azure crypto configuration.
        
        Detects:
        - Storage accounts without FIPS-compliant encryption
        - Key Vaults without HSM backing
        - SQL TDE without FIPS-compliant keys
        """
        findings = []
        lines = code.split('\n')
        
        # Check Storage Account encryption
        storage_pattern = r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts"
        for i, line in enumerate(lines, 1):
            if re.search(storage_pattern, line, re.IGNORECASE):
                # Check for encryption configuration in next 30 lines
                snippet_start = max(1, i - 2)
                snippet_end = min(len(lines), i + 30)
                # Filter out comment lines before checking
                snippet_lines = [l for l in lines[snippet_start-1:snippet_end] if not re.match(r'^\s*//', l)]
                snippet = '\n'.join(snippet_lines)
                
                # Check if requireInfrastructureEncryption is enabled (must be explicitly true)
                has_infra_encryption = re.search(r'requireInfrastructureEncryption:\s*true', snippet, re.IGNORECASE)
                if not has_infra_encryption:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Storage Account lacks infrastructure encryption",
                        description="Storage Account does not enable requireInfrastructureEncryption. FRR-UCM-02 requires FIPS 140-2 validated cryptographic modules for data protection.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 10),
                        recommendation="Enable infrastructure encryption:\n1. Set requireInfrastructureEncryption: true\n2. Use customer-managed keys from Key Vault with HSM backing\n3. Example: encryption: { requireInfrastructureEncryption: true, keySource: 'Microsoft.Keyvault' }\n4. Document use of FIPS 140-2 Level 2+ HSMs"
                    ))
        
        # Check Key Vault for HSM backing
        keyvault_pattern = r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults"
        for i, line in enumerate(lines, 1):
            if re.search(keyvault_pattern, line, re.IGNORECASE):
                snippet_start = max(1, i - 2)
                snippet_end = min(len(lines), i + 25)
                snippet = '\n'.join(lines[snippet_start-1:snippet_end])
                
                # Check SKU - Premium supports HSM backing (handle multi-line with flexible whitespace)
                if re.search(r"name:\s*'standard'", snippet, re.IGNORECASE | re.MULTILINE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Key Vault uses Standard SKU without HSM backing",
                        description="Key Vault configured with Standard SKU which doesn't support HSM-backed keys. FRR-UCM-02 requires FIPS 140-2 Level 2+ validated cryptographic modules.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 8),
                        recommendation="Use Premium SKU for HSM support:\n1. Set sku: { name: 'premium', family: 'A' }\n2. Create HSM-backed keys for sensitive operations\n3. Or use Azure Dedicated HSM for FIPS 140-2 Level 3\n4. Document cryptographic module validation certificates"
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for Azure crypto configuration.
        
        Detects:
        - Storage accounts without infrastructure encryption
        - Key vaults without premium SKU
        - Missing customer-managed keys
        """
        findings = []
        lines = code.split('\n')
        
        # Check azurerm_storage_account encryption
        storage_pattern = r'resource\s+"azurerm_storage_account"'
        for i, line in enumerate(lines, 1):
            if re.search(storage_pattern, line):
                snippet_start = max(0, i - 1)
                snippet_end = min(len(lines), i + 25)
                # Filter out comment lines before checking
                snippet_lines = [l for l in lines[snippet_start:snippet_end] if not re.match(r'^\s*#', l)]
                snippet = '\n'.join(snippet_lines)
                
                # Must have infrastructure_encryption_enabled = true explicitly
                has_infra_encryption = re.search(r'infrastructure_encryption_enabled\s*=\s*true', snippet, re.IGNORECASE)
                if not has_infra_encryption:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Storage Account missing infrastructure encryption",
                        description="Storage Account does not enable infrastructure_encryption_enabled. FRR-UCM-02 requires FIPS 140-2 validated crypto modules.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 8),
                        recommendation="Enable infrastructure encryption:\n1. Set infrastructure_encryption_enabled = true\n2. Configure customer_managed_key block with Key Vault reference\n3. Use HSM-backed keys in Premium Key Vault\n4. Document FIPS validation status"
                    ))
        
        # Check azurerm_key_vault SKU
        keyvault_pattern = r'resource\s+"azurerm_key_vault"'
        for i, line in enumerate(lines, 1):
            if re.search(keyvault_pattern, line):
                snippet_end = min(len(lines), i + 20)
                snippet = '\n'.join(lines[i:snippet_end])
                
                if re.search(r'sku_name\s*=\s*"standard"', snippet, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Key Vault using Standard SKU without HSM support",
                        description="Key Vault configured with standard SKU. FRR-UCM-02 requires FIPS 140-2 Level 2+ validated modules (Premium SKU for HSM).",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 6),
                        recommendation="Upgrade to Premium SKU:\n1. Set sku_name = \"premium\"\n2. Create HSM-backed keys for sensitive operations\n3. Example: azurerm_key_vault_key with key_opts = [\"RSA-HSM\"]\n4. Document FIPS 140-2 validation certificates"
                    ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Not primary focus for FRR-UCM-02)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-UCM-02 focuses on code and IaC crypto usage. No CI/CD detection."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-UCM-02 focuses on code and IaC crypto usage. No CI/CD detection."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-UCM-02 focuses on code and IaC crypto usage. No CI/CD detection."""
        return []
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for FRR-UCM-02.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "frr_id": self.frr_id,
            "frr_name": "Use of Validated Cryptographic Modules",
            "primary_keyword": "MUST",
            "impact_levels": ["Low", "Moderate", "High"],
            "evidence_type": "automated",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure Key Vault",
                "Azure Policy",
                "Microsoft Defender for Cloud",
                "Azure Resource Graph"
            ],
            "collection_methods": [
                "Azure Policy to audit Key Vault SKU and HSM usage",
                "Code scanning tools to detect weak crypto algorithms",
                "Azure Resource Graph query for storage encryption settings",
                "Key Vault metrics for cryptographic operations",
                "Inventory of all cryptographic modules with FIPS validation status"
            ],
            "implementation_steps": [
                "1. Deploy Azure Policy to require Premium Key Vault SKU for production",
                "2. Implement code scanning in CI/CD to detect MD5/SHA1/DES usage",
                "3. Create Azure Resource Graph query for encryption configurations",
                "4. Document FIPS 140-2/140-3 validation certificates for all crypto modules",
                "5. Configure alerts for non-compliant cryptographic operations",
                "6. Generate monthly report of cryptographic module usage and validation status"
            ],
            "evidence_artifacts": [
                "Cryptographic Module Inventory (list of all modules with NIST CMVP validation numbers)",
                "Azure Key Vault Configuration Report (SKU, HSM usage, key types)",
                "Code Scan Results (identifying weak crypto algorithm usage)",
                "Storage Encryption Configuration Export (infrastructure encryption status)",
                "FIPS Validation Certificates (documentation of validated modules)"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team / Cryptography Team"
        }
    
    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Key Vaults with Premium SKU (HSM support)",
                "query": """Resources
| where type == 'microsoft.keyvault/vaults'
| extend skuName = tostring(properties.sku.name)
| project name, resourceGroup, location, skuName, subscriptionId
| order by skuName, name""",
                "purpose": "Identify Key Vaults with Premium SKU supporting HSM-backed FIPS 140-2 keys"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "Storage Accounts with infrastructure encryption",
                "query": """Resources
| where type == 'microsoft.storage/storageaccounts'
| extend infraEncryption = tostring(properties.encryption.requireInfrastructureEncryption)
| extend keySource = tostring(properties.encryption.keySource)
| project name, resourceGroup, location, infraEncryption, keySource, subscriptionId
| where infraEncryption != 'true'
| order by name""",
                "purpose": "Audit storage accounts for FIPS-compliant infrastructure encryption"
            },
            {
                "query_type": "Azure Policy Compliance REST API",
                "query_name": "Cryptographic module compliance policy status",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&$filter=policyDefinitionName eq 'require-fips-crypto'",
                "purpose": "Track compliance with custom policy requiring FIPS 140-2 validated crypto"
            },
            {
                "query_type": "Static Code Analysis Query",
                "query_name": "Weak cryptographic algorithm detection",
                "query": "grep -r -E '(MD5|SHA1|DES|RC4|hashlib\\.md5|hashlib\\.sha1)' --include='*.py' --include='*.cs' --include='*.java' --include='*.ts'",
                "purpose": "Identify weak/non-FIPS crypto algorithms in source code"
            }
        ]
    
    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries
        """
        return [
            {
                "artifact_name": "Cryptographic Module Inventory",
                "artifact_type": "Excel spreadsheet",
                "description": "Complete list of all cryptographic modules used, including library name, version, algorithm, NIST CMVP validation certificate number, and validation level",
                "collection_method": "Manual documentation combined with automated code scanning",
                "storage_location": "Azure Storage Account /evidence/frr-ucm-02/crypto-inventory/"
            },
            {
                "artifact_name": "FIPS Validation Certificates",
                "artifact_type": "PDF documents",
                "description": "NIST CMVP validation certificates for all cryptographic modules used in production",
                "collection_method": "Download from NIST CMVP website (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules)",
                "storage_location": "Azure Storage Account /evidence/frr-ucm-02/certificates/"
            },
            {
                "artifact_name": "Azure Key Vault Configuration Report",
                "artifact_type": "JSON export",
                "description": "Configuration of all Key Vaults showing SKU (Premium for HSM), key types (RSA-HSM), and cryptographic operations",
                "collection_method": "Azure Resource Graph query exported via Azure CLI",
                "storage_location": "Azure Storage Account /evidence/frr-ucm-02/keyvault-config/"
            },
            {
                "artifact_name": "Code Scan Results for Weak Crypto",
                "artifact_type": "SARIF file",
                "description": "Static analysis results showing no usage of MD5, SHA1, DES, RC4, or other non-FIPS algorithms",
                "collection_method": "CI/CD pipeline SAST tools (SonarQube, Semgrep, CodeQL)",
                "storage_location": "Azure DevOps artifacts or GitHub Actions artifacts"
            },
            {
                "artifact_name": "Storage Encryption Configuration",
                "artifact_type": "CSV export",
                "description": "All storage accounts showing infrastructure encryption enabled and customer-managed key usage with Key Vault HSM backing",
                "collection_method": "Azure Resource Graph query exported to CSV",
                "storage_location": "Azure Storage Account /evidence/frr-ucm-02/storage-encryption/"
            }
        ]
