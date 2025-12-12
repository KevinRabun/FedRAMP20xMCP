"""
FRR-UCM-01: Cryptographic Module Documentation

Providers MUST document the cryptographic modules used in each service (or groups of 
services that use the same modules) where cryptographic services are used to protect 
federal customer data, including whether these modules are validated under the NIST 
Cryptographic Module Validation Program or are update streams of such modules.

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


class FRR_UCM_01_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-UCM-01: Cryptographic Module Documentation
    
    **Official Statement:**
    Providers MUST document the cryptographic modules used in each service (or groups of 
    services that use the same modules) where cryptographic services are used to protect 
    federal customer data, including whether these modules are validated under the NIST 
    Cryptographic Module Validation Program or are update streams of such modules.
    
    **Family:** UCM - Using Cryptographic Modules
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes  
    - High: Yes
    
    **NIST Controls:**
    - SC-13: Cryptographic Protection
    - SA-4(9): Functions, Ports, Protocols, and Services in Use
    
    **Related KSIs:**
    - KSI-AFR-01: Use of Validated Cryptographic Modules
    
    **Detectability:** Partial (can detect crypto usage, but documentation verification requires human review)
    
    **Detection Strategy:**
    1. Detect crypto library usage in application code (Python, C#, Java, TypeScript)
    2. Identify crypto services in IaC (Key Vault, KMS, etc.)
    3. Scan documentation for CMVP references
    4. Flag undocumented crypto usage
    """
    
    FRR_ID = "FRR-UCM-01"
    FRR_NAME = "Cryptographic Module Documentation"
    FRR_STATEMENT = """Providers MUST document the cryptographic modules used in each service (or groups of services that use the same modules) where cryptographic services are used to protect federal customer data, including whether these modules are validated under the NIST Cryptographic Module Validation Program or are update streams of such modules."""
    FAMILY = "UCM"
    FAMILY_NAME = "Using Cryptographic Modules"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("SC-13", "Cryptographic Protection"),
        ("SA-4", "Acquisition Process"),
    ]
    CODE_DETECTABLE = "No"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-CNA-05",  # Encryption in transit
        "KSI-CED-03",  # Encryption at rest
    ]
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-AFR-01"]
    
    def __init__(self):
        """Initialize FRR-UCM-01 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (Detect crypto usage needing documentation)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for cryptographic library usage using AST.
        
        Detects usage of:
        - hashlib (hashing)
        - cryptography library
        - Crypto.Cipher (PyCrypto/PyCryptodome)
        - Azure Key Vault SDK
        - AWS KMS SDK
        
        Flags crypto usage that may need documentation per FRR-UCM-01.
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for crypto library imports
                import_nodes = parser.find_nodes_by_type(tree.root_node, 'import_from_statement')
                crypto_imports = []
                
                for import_node in import_nodes:
                    import_text = parser.get_node_text(import_node, code_bytes)
                    
                    # Check for common crypto libraries
                    if any(lib in import_text for lib in [
                        'hashlib', 'cryptography', 'Crypto.Cipher', 'Crypto.PublicKey',
                        'azure.keyvault', 'boto3', 'google.cloud.kms'
                    ]):
                        line_num = import_node.start_point[0] + 1
                        crypto_imports.append((import_text, line_num))
                
                if crypto_imports:
                    # Create a single finding for crypto usage
                    modules = ', '.join([imp[0].split()[1] if 'from' in imp[0] else imp[0] for imp in crypto_imports[:3]])
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Cryptographic modules detected - documentation required",
                        description=f"Python code imports cryptographic libraries ({modules}). FRR-UCM-01 requires documentation of all cryptographic modules including NIST CMVP validation status.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=crypto_imports[0][1],
                        code_snippet=self._get_snippet(lines, crypto_imports[0][1], 3),
                        recommendation="""Document the following for each cryptographic module:
1. Module name and version (e.g., cryptography 41.0.7)
2. NIST CMVP validation status
3. Certificate number if validated (e.g., Cert #4282)
4. Whether it's an update stream of a validated module
5. Which services use which modules

Add this to SECURITY.md or create docs/cryptography.md"""
                    ))
                
                return findings
                
        except Exception:
            pass
        
        # Regex fallback
        return self._python_regex_fallback(code, lines, file_path)
    
    def _python_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis for Python crypto imports."""
        findings = []
        
        crypto_pattern = r'(import\s+(hashlib|cryptography|Crypto)|from\s+(hashlib|cryptography|Crypto|azure\.keyvault|boto3)\s+import)'
        
        for i, line in enumerate(lines, 1):
            if re.search(crypto_pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Cryptographic module usage detected",
                    description=f"Cryptographic library import detected. FRR-UCM-01 requires documenting all crypto modules with CMVP validation status.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Document this module's NIST CMVP validation status in SECURITY.md"
                ))
                break  # Only report once per file
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for cryptographic API usage using AST.
        
        Detects usage of:
        - System.Security.Cryptography
        - BouncyCastle
        - Azure Key Vault SDK
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for using directives with crypto namespaces
                using_nodes = parser.find_nodes_by_type(tree.root_node, 'using_directive')
                
                for using_node in using_nodes:
                    using_text = parser.get_node_text(using_node, code_bytes)
                    
                    if any(ns in using_text for ns in [
                        'System.Security.Cryptography', 'BouncyCastle', 'Azure.Security.KeyVault'
                    ]):
                        line_num = using_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.FRR_ID,
                            requirement_id=self.FRR_ID,
                            title="Cryptographic namespace detected - documentation required",
                            description=f"C# code uses cryptographic APIs. FRR-UCM-01 requires documentation of crypto modules including CMVP validation status.",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num, 3),
                            recommendation="Document: (1) Module name/version, (2) NIST CMVP Cert #, (3) Update stream status"
                        ))
                        break  # Only report once per file
                
                return findings
                
        except Exception:
            pass
        
        # Regex fallback
        return self._csharp_regex_fallback(code, lines, file_path)
    
    def _csharp_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex for C# crypto usage."""
        findings = []
        
        crypto_pattern = r'using\s+(System\.Security\.Cryptography|BouncyCastle|Azure\.Security\.KeyVault)'
        
        for i, line in enumerate(lines, 1):
            if re.search(crypto_pattern, line):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Cryptographic namespace usage detected",
                    description="Cryptographic API usage requires CMVP validation documentation per FRR-UCM-01.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Document module validation status in SECURITY.md"
                ))
                break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for cryptographic API usage using AST.
        
        Detects:
        - javax.crypto.*
        - java.security.*
        - BouncyCastle
        """
        findings = []
        lines = code.split('\n')
        
        crypto_pattern = r'import\s+(javax\.crypto|java\.security|org\.bouncycastle)'
        
        for i, line in enumerate(lines, 1):
            if re.search(crypto_pattern, line):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Cryptographic API usage detected",
                    description="Java cryptographic library import detected. FRR-UCM-01 requires CMVP validation documentation.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Document crypto provider (e.g., BC-FIPS Cert #4616) in SECURITY.md"
                ))
                break
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for cryptographic library usage using AST.
        
        Detects:
        - Node.js crypto module
        - crypto-js
        - forge
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Find import statements
                import_nodes = []
                import_nodes.extend(parser.find_nodes_by_type(tree.root_node, 'import_statement'))
                
                for import_node in import_nodes:
                    import_text = parser.get_node_text(import_node, code_bytes)
                    
                    if any(lib in import_text for lib in ['crypto', 'crypto-js', 'node-forge', 'bcrypt']):
                        line_num = import_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.FRR_ID,
                            requirement_id=self.FRR_ID,
                            title="Cryptographic library detected - documentation required",
                            description="TypeScript/JavaScript code imports crypto library. FRR-UCM-01 requires CMVP validation documentation.",
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num, 3),
                            recommendation="Document crypto module validation. For Node.js crypto, enable FIPS mode and document."
                        ))
                        break
                
                return findings
                
        except Exception:
            pass
        
        # Regex fallback
        return self._typescript_regex_fallback(code, lines, file_path)
    
    def _typescript_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex for TypeScript crypto usage."""
        findings = []
        
        crypto_pattern = r"(import.*['\"]crypto['\"]|require\(['\"]crypto['\"]|import.*['\"]crypto-js['\"])"
        
        for i, line in enumerate(lines, 1):
            if re.search(crypto_pattern, line):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Cryptographic module import detected",
                    description="Crypto library usage requires CMVP documentation per FRR-UCM-01.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="Document module validation status"
                ))
                break
        
        return findings
    
    # ============================================================================
    # DOCUMENTATION ANALYZERS
    # ============================================================================
    
    def analyze_documentation(self, file_content: str, file_path: str = "") -> List[Finding]:
        """
        Analyze documentation files for cryptographic module information.
        
        Checks for:
        - Presence of crypto module documentation
        - CMVP validation references
        - Module names and versions
        - Update stream information
        """
        findings = []
        lines = file_content.split('\n')
        
        # Check if this is a documentation file
        doc_keywords = ['readme', 'security', 'crypto', 'compliance', 'fedramp']
        if not any(keyword in file_path.lower() for keyword in doc_keywords):
            return findings
        
        # Look for cryptographic module documentation
        has_crypto_section = False
        has_cmvp_reference = False
        has_module_names = False
        has_validation_status = False
        
        crypto_keywords = [
            'cryptographic module', 'crypto module', 'fips 140', 'cmvp',
            'nist validated', 'cryptography', 'encryption module'
        ]
        
        cmvp_keywords = [
            'cmvp', 'cryptographic module validation program',
            'nist cmvp', 'validation certificate', 'certificate #'
        ]
        
        module_keywords = [
            'bouncycastle', 'bcfips', 'openssl', 'cryptography',
            'azure key vault', 'aws kms', 'cloud kms'
        ]
        
        validation_keywords = [
            'validated', 'validation', 'fips 140-2', 'fips 140-3',
            'update stream', 'cert #', 'certificate'
        ]
        
        for line in lines:
            line_lower = line.lower()
            
            if any(keyword in line_lower for keyword in crypto_keywords):
                has_crypto_section = True
            
            if any(keyword in line_lower for keyword in cmvp_keywords):
                has_cmvp_reference = True
            
            if any(keyword in line_lower for keyword in module_keywords):
                has_module_names = True
            
            if any(keyword in line_lower for keyword in validation_keywords):
                has_validation_status = True
        
        # If crypto documentation exists, check completeness
        if has_crypto_section:
            if not has_cmvp_reference:
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Incomplete crypto documentation: Missing CMVP reference",
                    description=f"File '{file_path}' mentions cryptographic modules but does not reference the NIST Cryptographic Module Validation Program (CMVP). FRR-UCM-01 requires documentation of whether modules are CMVP validated.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="""Add CMVP validation information to your documentation:
1. Document specific cryptographic modules used (e.g., BouncyCastle FIPS, Azure Key Vault HSM)
2. Include CMVP certificate numbers for validated modules
3. Identify update streams if using derivatives of validated modules
4. Example:
   ## Cryptographic Modules
   
   We use the following NIST CMVP validated cryptographic modules:
   - BouncyCastle FIPS for Java (Cert #4616)
   - Azure Key Vault Premium HSM (Cert #3980)
   
   See: https://csrc.nist.gov/projects/cryptographic-module-validation-program"""
                ))
            
            if not has_module_names:
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Incomplete crypto documentation: Missing module names",
                    description=f"File '{file_path}' discusses cryptography but does not name specific cryptographic modules. FRR-UCM-01 requires documentation of which modules are used.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Document specific module names: BouncyCastle FIPS, OpenSSL FIPS, Azure Key Vault, AWS KMS, etc."
                ))
            
            if not has_validation_status:
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Incomplete crypto documentation: Missing validation status",
                    description=f"File '{file_path}' mentions crypto modules but does not document their FIPS 140-2/140-3 validation status. FRR-UCM-01 requires validation status documentation.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="For each module, document: (1) FIPS validation status, (2) Certificate number if validated, (3) Whether it's an update stream"
                ))
        
        return findings
    
    def check_missing_crypto_documentation(self, project_files: List[str]) -> List[Finding]:
        """
        Check if project has any crypto documentation at all.
        
        Args:
            project_files: List of file paths in the project
        
        Returns:
            Findings if no crypto documentation found
        """
        findings = []
        
        # Look for documentation files
        doc_files = [f for f in project_files if any(
            keyword in f.lower() 
            for keyword in ['readme', 'security', 'crypto', 'compliance', 'doc', 'fedramp']
        )]
        
        if not doc_files:
            findings.append(Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Missing cryptographic module documentation",
                description="No documentation files found (README.md, SECURITY.md, docs/). FRR-UCM-01 requires documenting all cryptographic modules used to protect federal customer data.",
                severity=Severity.HIGH,
                file_path="",
                line_number=0,
                code_snippet="",
                recommendation="""Create documentation that includes:
1. List of all cryptographic modules used
2. Which services use which modules
3. NIST CMVP validation status for each module
4. Certificate numbers for validated modules
5. Update stream information if applicable

Suggested file: SECURITY.md or docs/cryptography.md"""
            ))
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, List[str]]:
        """
        Provides queries for collecting evidence of FRR-UCM-01 compliance.
        
        Returns:
            Dict containing query strings for various platforms
        """
        return {
            "azure_resource_graph": [
                "Resources | where type =~ 'microsoft.keyvault/vaults' | project id, name, properties",
                "Resources | where type =~ 'microsoft.security/compliances' | project id, name"
            ],
            "azure_cli": [
                "az keyvault list --query '[].{Name:name, Location:location}'",
                "az security compliance list --query '[].{Name:name, State:state}'"
            ]
        }
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Lists artifacts to collect as evidence of FRR-UCM-01 compliance.
        
        Returns:
            List of artifact descriptions
        """
        return [
            "Cryptographic module documentation (SECURITY.md or equivalent)",
            "NIST CMVP validation certificates for each module",
            "List mapping services to cryptographic modules used",
            "Update stream documentation for validated modules",
            "Cryptographic module inventory and validation status matrix"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, str]:
        """
        Provides recommendations for automating evidence collection for FRR-UCM-01.
        
        Returns:
            Dict mapping automation areas to implementation guidance
        """
        return {
            "module_inventory": "Automate scanning of code repositories for cryptographic library usage",
            "validation_tracking": "Maintain database of CMVP certificates linked to deployed modules",
            "documentation_generation": "Generate cryptographic module documentation from inventory"
        }
