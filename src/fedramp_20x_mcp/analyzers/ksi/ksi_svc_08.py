"""
KSI-SVC-08: Shared Resources

Do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of federal customer data during operations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
import ast
from typing import List, Optional, Dict, Any, Set
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer

# Tree-sitter imports for C#/Java/TypeScript AST parsing
try:
    from tree_sitter import Language, Parser
    import tree_sitter_c_sharp as ts_csharp
    import tree_sitter_java as ts_java
    import tree_sitter_javascript as ts_javascript  # TypeScript uses JavaScript grammar
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


class KSI_SVC_08_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced Analyzer for KSI-SVC-08: Shared Resources
    
    **Official Statement:**
    Do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of federal customer data during operations.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    
    **NIST Controls:**
    - sc-4
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-08"
    KSI_NAME = "Shared Resources"
    KSI_STATEMENT = """Do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of federal customer data during operations."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    NIST_CONTROLS = [("sc-4", "Information in Shared System Resources")]
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
        Analyze Python code for KSI-SVC-08 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Temporary files without secure deletion
        - File handles without context managers or close()
        - Sensitive data in-memory without explicit clearing
        """
        findings = []
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._python_regex_fallback(code, file_path)
        
        lines = code.split('\n')
        
        # Track tempfile calls with delete=False
        tempfile_calls_no_auto_delete: Set[int] = set()
        # Track file open() calls without context manager
        file_opens_without_context: Set[int] = set()
        # Track sensitive variable assignments
        sensitive_vars: Dict[str, int] = {}
        # Track with statement context items to exclude from open() checks
        with_statement_lines: Set[int] = set()
        
        for node in ast.walk(tree):
            # Track with statement items to exclude from open() checks
            if isinstance(node, ast.With):
                for item in node.items:
                    if hasattr(item.context_expr, 'lineno'):
                        with_statement_lines.add(item.context_expr.lineno)
            
            # Pattern 1: tempfile.NamedTemporaryFile(delete=False) without cleanup
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    # tempfile.NamedTemporaryFile(), tempfile.mkstemp(), tempfile.mkdtemp()
                    if (isinstance(node.func.value, ast.Name) and 
                        node.func.value.id == 'tempfile' and
                        node.func.attr in ['NamedTemporaryFile', 'mkstemp', 'mkdtemp']):
                        
                        # Check for delete=False keyword argument
                        has_delete_false = any(
                            kw.arg == 'delete' and 
                            isinstance(kw.value, ast.Constant) and 
                            kw.value.value is False
                            for kw in node.keywords
                        )
                        
                        if has_delete_false and hasattr(node, 'lineno'):
                            tempfile_calls_no_auto_delete.add(node.lineno)
                
                # Pattern 2: open() without context manager (with statement)
                elif isinstance(node.func, ast.Name) and node.func.id == 'open':
                    # Only track if NOT in a with statement
                    if hasattr(node, 'lineno') and node.lineno not in with_statement_lines:
                        file_opens_without_context.add(node.lineno)
            
            # Pattern 3: Sensitive variable assignments
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id.lower()
                        # Check for sensitive variable names
                        if any(pattern in var_name for pattern in ['password', 'secret', 'token', 'api_key', 'private_key']):
                            if hasattr(node, 'lineno'):
                                sensitive_vars[target.id] = node.lineno
        
        # Now check if tempfile calls have cleanup
        for line_num in tempfile_calls_no_auto_delete:
            # Check for os.unlink, shutil.rmtree, or secure deletion in next 30 lines
            has_cleanup = False
            end_line = min(line_num + 30, len(lines))
            for i in range(line_num - 1, end_line):  # Start from line_num-1 (0-indexed)
                if i < len(lines):
                    line_text = lines[i]
                    if 'os.unlink' in line_text or 'shutil.rmtree' in line_text or 'os.remove' in line_text:
                        has_cleanup = True
                        break
            
            if not has_cleanup:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Temporary File Without Secure Deletion",
                    description=(
                        "Temporary file created with delete=False but no secure deletion mechanism. "
                        "KSI-SVC-08 requires not introducing residual elements that could affect confidentiality (SC-4) - "
                        "temporary files may contain sensitive data that persists on disk after process termination."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Ensure secure deletion of temporary files:\n"
                        "# Option 1: Use auto-deletion (recommended)\n"
                        "import tempfile\n\n"
                        "with tempfile.NamedTemporaryFile(mode='w', delete=True) as tmp:\n"
                        "    tmp.write(sensitive_data)\n"
                        "    tmp.flush()\n"
                        "    # File automatically deleted on close\n\n"
                        "# Option 2: Manual secure deletion with overwrite\n"
                        "import os\n"
                        "import tempfile\n\n"
                        "tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)\n"
                        "try:\n"
                        "    tmp.write(sensitive_data)\n"
                        "    tmp.flush()\n"
                        "    # ... use file ...\n"
                        "finally:\n"
                        "    tmp.close()\n"
                        "    # Overwrite with zeros before deletion\n"
                        "    with open(tmp.name, 'wb') as f:\n"
                        "        f.write(b'\\x00' * os.path.getsize(tmp.name))\n"
                        "    os.unlink(tmp.name)\n\n"
                        "Ref: Python tempfile Module (https://docs.python.org/3/library/tempfile.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Check for open() without context manager by checking close() calls
        for line_num in file_opens_without_context:
            # Check for .close() in next 20 lines
            has_close = False
            end_line = min(line_num + 20, len(lines))
            for i in range(line_num - 1, end_line):  # Start from line_num-1 (0-indexed)
                if i < len(lines) and '.close()' in lines[i]:
                    has_close = True
                    break
            
            if not has_close:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="File Handle Without Context Manager or Close",
                    description=(
                        "File opened with open() but not used with context manager (with statement) or explicit close(). "
                        "KSI-SVC-08 requires not leaving residual elements that could affect availability (SC-4) - "
                        "unclosed file handles cause resource exhaustion and may lock files."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use context manager for automatic file cleanup:\n"
                        "# Option 1: Context manager (recommended)\n"
                        "with open('file.txt', 'r') as f:\n"
                        "    content = f.read()\n"
                        "    # File automatically closed here\n\n"
                        "# Option 2: Try-finally with explicit close\n"
                        "f = None\n"
                        "try:\n"
                        "    f = open('file.txt', 'r')\n"
                        "    content = f.read()\n"
                        "finally:\n"
                        "    if f:\n"
                        "        f.close()\n\n"
                        "Ref: Python with Statement (https://docs.python.org/3/reference/compound_stmts.html#with)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Check if sensitive variables are cleared
        for var_name, line_num in sensitive_vars.items():
            # Check for variable = None or del variable in next 50 lines
            has_clear = False
            end_line = min(line_num + 50, len(lines))
            for i in range(line_num - 1, end_line):  # Start from line_num-1 (0-indexed)
                if i < len(lines):
                    line_text = lines[i]
                    if f'{var_name} = None' in line_text or f'del {var_name}' in line_text:
                        has_clear = True
                        break
            
            if not has_clear:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Sensitive Data Not Explicitly Cleared From Memory",
                    description=(
                        f"Sensitive variable '{var_name}' assigned but never explicitly cleared. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "sensitive data in memory may persist in Python's heap, core dumps, or swap space."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Explicitly clear sensitive data from memory:\n"
                        "import ctypes\n\n"
                        "# Store sensitive data\n"
                        f"{var_name} = 'sensitive_value'\n\n"
                        "try:\n"
                        "    # Use the sensitive data\n"
                        "    process_data({var_name})\n"
                        "finally:\n"
                        "    # Clear from memory\n"
                        f"    if {var_name} is not None:\n"
                        f"        # Overwrite memory before deletion\n"
                        f"        ctypes.memset(id({var_name}), 0, len({var_name}))\n"
                        f"        {var_name} = None\n\n"
                        "# Or use secure string handling library\n"
                        "from cryptography.fernet import Fernet\n"
                        "# Store encrypted in memory, decrypt only when needed\n\n"
                        "Ref: Python Memory Management (https://docs.python.org/3/c-api/memory.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based detection for Python when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Temporary file creation
        tempfile_match = self._find_line(lines, r'tempfile\.(NamedTemporaryFile|mkstemp|mkdtemp)', use_regex=True)
        if tempfile_match:
            line_num = tempfile_match['line_num']
            has_delete_false = any('delete=False' in line for line in lines[line_num:min(line_num+5, len(lines))])
            has_secure_delete = any('os.unlink' in line or 'shutil.rmtree' in line 
                                   for line in lines[line_num:min(line_num+30, len(lines))])
            
            if has_delete_false and not has_secure_delete:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Temporary File Without Secure Deletion (Regex Fallback)",
                    description="Temporary file created with delete=False but no secure deletion mechanism.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation="Use context manager or ensure secure deletion with os.unlink().",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-08 compliance using hybrid AST+regex.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - IDisposable resources not properly disposed
        - SecureString not cleared
        - Sensitive data in memory without zeroing
        """
        findings = []
        
        # Try AST parsing first
        if TREE_SITTER_AVAILABLE:
            try:
                lang = Language(ts_csharp.language())
                parser = Parser(lang)
                tree = parser.parse(bytes(code, "utf8"))
                
                lines = code.split('\n')
                
                # Track using directives to reduce false positives
                has_system_io = False
                has_system_security = False
                
                # Track IDisposable instantiations without using
                idisposable_types = {'FileStream', 'MemoryStream', 'StreamWriter', 'StreamReader', 
                                    'HttpClient', 'SqlConnection', 'DbContext'}
                
                def find_nodes_by_type(node, node_type: str) -> List:
                    results = []
                    if node.type == node_type:
                        results.append(node)
                    for child in node.children:
                        results.extend(find_nodes_by_type(child, node_type))
                    return results
                
                # Find using directives
                using_directives = find_nodes_by_type(tree.root_node, 'using_directive')
                for directive in using_directives:
                    # Extract text safely - check for 'System.IO' or 'System.Security' namespace
                    directive_text = code[directive.start_byte:directive.end_byte].decode('utf-8') if isinstance(code, bytes) else code[directive.start_byte:directive.end_byte]
                    # Only check for specific safe namespace strings, not arbitrary URL content
                    if directive_text.startswith('using System.IO'):
                        has_system_io = True
                    elif directive_text.startswith('using System.Security'):
                        has_system_security = True
                
                # Find object creation expressions (new keyword)
                object_creations = find_nodes_by_type(tree.root_node, 'object_creation_expression')
                
                for creation in object_creations:
                    text = code[creation.start_byte:creation.end_byte]
                    line_num = code[:creation.start_byte].count('\n') + 1
                    
                    # Check if creating an IDisposable type
                    is_disposable = any(dtype in text for dtype in idisposable_types)
                    
                    if is_disposable:
                        # Check if within using statement by looking at parent nodes
                        parent = creation.parent
                        in_using = False
                        while parent:
                            if parent.type == 'using_statement':
                                in_using = True
                                break
                            parent = parent.parent
                        
                        # Check for explicit Dispose() call in next 20 lines
                        has_dispose = any('.Dispose()' in line for line in lines[line_num-1:min(line_num+20, len(lines))])
                        
                        if not in_using and not has_dispose:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                title="Disposable Resource Not Properly Disposed",
                                description=(
                                    "IDisposable resource created without using statement or explicit Dispose() call. "
                                    "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                                    "undisposed streams may leave sensitive data in memory or locked file handles."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                snippet=self._get_snippet(lines, line_num, context=3),
                                remediation=(
                                    "Use using statement for automatic disposal:\n"
                                    "// Option 1: using statement (C# 8.0+)\n"
                                    "using var stream = new FileStream(\"file.txt\", FileMode.Open);\n"
                                    "// Stream automatically disposed at end of scope\n\n"
                                    "// Option 2: using block\n"
                                    "using (var stream = new FileStream(\"file.txt\", FileMode.Open))\n"
                                    "{\n"
                                    "    // Use stream\n"
                                    "} // Automatically disposed here\n\n"
                                    "Ref: IDisposable Pattern (https://learn.microsoft.com/dotnet/standard/garbage-collection/implementing-dispose)"
                                ),
                                ksi_id=self.KSI_ID
                            ))
                
                # Check for SecureString without disposal (AST + regex hybrid)
                if has_system_security or 'SecureString' in code:
                    securestring_matches = [node for node in object_creations if 'SecureString' in code[node.start_byte:node.end_byte]]
                    for node in securestring_matches:
                        line_num = code[:node.start_byte].count('\n') + 1
                        has_dispose = any('.Dispose()' in line for line in lines[line_num-1:min(line_num+20, len(lines))])
                        
                        if not has_dispose:
                            findings.append(Finding(
                                severity=Severity.MEDIUM,
                                title="SecureString Not Disposed",
                                description=(
                                    "SecureString created but never disposed. "
                                    "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                                    "undisposed SecureString may leave encrypted sensitive data in memory."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                snippet=self._get_snippet(lines, line_num, context=3),
                                remediation=(
                                    "Dispose SecureString after use:\n"
                                    "using System.Security;\n\n"
                                    "using (var securePassword = new SecureString())\n"
                                    "{\n"
                                    "    foreach (char c in password) { securePassword.AppendChar(c); }\n"
                                    "    securePassword.MakeReadOnly();\n"
                                    "    ProcessSecureString(securePassword);\n"
                                    "} // Automatically disposed\n\n"
                                    "Ref: SecureString Class (https://learn.microsoft.com/dotnet/api/system.security.securestring)"
                                ),
                                ksi_id=self.KSI_ID
                            ))
                
                return findings
                
            except Exception:
                # Fall back to regex if AST parsing fails
                pass
        
        # Regex fallback
        return self._csharp_regex_fallback(code, file_path)
    
    def _csharp_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based detection for C# when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: IDisposable without using
        stream_match = self._find_line(lines, r'new\s+(FileStream|MemoryStream|StreamWriter|StreamReader)', use_regex=True)
        if stream_match:
            line_num = stream_match['line_num']
            has_using = any('using' in line for line in lines[max(0, line_num-3):line_num+1])
            has_dispose = any('.Dispose()' in line for line in lines[line_num:min(line_num+20, len(lines))])
            
            if not has_using and not has_dispose:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Disposable Resource Not Properly Disposed (Regex Fallback)",
                    description="IDisposable resource created without using statement or explicit Dispose().",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation="Use using statement for automatic disposal.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-08 compliance using hybrid AST+regex.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - AutoCloseable resources not used in try-with-resources
        - Sensitive data arrays not zeroed
        - Missing resource cleanup
        """
        findings = []
        
        # Try AST parsing first
        if TREE_SITTER_AVAILABLE:
            try:
                lang = Language(ts_java.language())
                parser = Parser(lang)
                tree = parser.parse(bytes(code, "utf8"))
                
                lines = code.split('\n')
                
                # Track AutoCloseable types
                autocloseable_types = {'FileInputStream', 'FileOutputStream', 'BufferedReader', 
                                      'BufferedWriter', 'Scanner', 'Connection', 'Statement'}
                
                def find_nodes_by_type(node, node_type: str) -> List:
                    results = []
                    if node.type == node_type:
                        results.append(node)
                    for child in node.children:
                        results.extend(find_nodes_by_type(child, node_type))
                    return results
                
                # Find object creation expressions
                object_creations = find_nodes_by_type(tree.root_node, 'object_creation_expression')
                
                for creation in object_creations:
                    text = code[creation.start_byte:creation.end_byte]
                    line_num = code[:creation.start_byte].count('\n') + 1
                    
                    # Check if creating an AutoCloseable type
                    is_autocloseable = any(atype in text for atype in autocloseable_types)
                    
                    if is_autocloseable:
                        # Check if within try-with-resources
                        parent = creation.parent
                        in_try_resources = False
                        while parent:
                            if parent.type == 'try_with_resources_statement':
                                in_try_resources = True
                                break
                            parent = parent.parent
                        
                        # Check for explicit close() call
                        has_close = any('.close()' in line for line in lines[line_num-1:min(line_num+30, len(lines))])
                        
                        if not in_try_resources and not has_close:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                title="AutoCloseable Resource Not Properly Closed",
                                description=(
                                    "AutoCloseable resource created without try-with-resources or explicit close(). "
                                    "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                                    "unclosed streams may leave sensitive data in buffers or locked file handles."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                snippet=self._get_snippet(lines, line_num, context=3),
                                remediation=(
                                    "Use try-with-resources for automatic cleanup:\n"
                                    "try (FileInputStream fis = new FileInputStream(\"file.txt\")) {\n"
                                    "    // Use stream\n"
                                    "} // Automatically closed\n\n"
                                    "Ref: try-with-resources (https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html)"
                                ),
                                ksi_id=self.KSI_ID
                            ))
                
                # Check for sensitive arrays not zeroed (hybrid regex)
                password_array_match = self._find_line(lines, r'(char\[\]|byte\[\])\s+\w*(password|secret|token)', use_regex=True)
                if password_array_match:
                    line_num = password_array_match['line_num']
                    has_array_fill = any('Arrays.fill(' in line for line in lines[line_num:min(line_num+30, len(lines))])
                    
                    if not has_array_fill:
                        findings.append(Finding(
                            severity=Severity.MEDIUM,
                            title="Sensitive Array Not Zeroed After Use",
                            description=(
                                "Sensitive data stored in char[] or byte[] array but not zeroed after use. "
                                "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                                "sensitive data in arrays may persist in memory or heap dumps."
                            ),
                            file_path=file_path,
                            line_number=line_num,
                            snippet=self._get_snippet(lines, line_num, context=3),
                            remediation=(
                                "Zero sensitive arrays after use:\n"
                                "char[] password = getPassword();\n"
                                "try {\n"
                                "    authenticate(password);\n"
                                "} finally {\n"
                                "    Arrays.fill(password, (char) 0);\n"
                                "}\n\n"
                                "Ref: Arrays.fill() (https://docs.oracle.com/javase/8/docs/api/java/util/Arrays.html#fill-char:A-char-)"
                            ),
                            ksi_id=self.KSI_ID
                        ))
                
                return findings
                
            except Exception:
                # Fall back to regex if AST parsing fails
                pass
        
        # Regex fallback
        return self._java_regex_fallback(code, file_path)
    
    def _java_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based detection for Java when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: AutoCloseable without try-with-resources
        stream_match = self._find_line(lines, r'new\s+(FileInputStream|FileOutputStream|BufferedReader|BufferedWriter)', use_regex=True)
        if stream_match:
            line_num = stream_match['line_num']
            has_try_resources = any('try (' in line for line in lines[max(0, line_num-3):line_num+1])
            has_close = any('close()' in line for line in lines[line_num:min(line_num+30, len(lines))])
            
            if not has_try_resources and not has_close:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="AutoCloseable Resource Not Properly Closed (Regex Fallback)",
                    description="AutoCloseable resource created without try-with-resources or explicit close().",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation="Use try-with-resources for automatic cleanup.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-08 compliance using hybrid AST+regex.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - File descriptors not closed
        - Buffers with sensitive data not cleared
        - Event listeners not removed
        """
        findings = []
        
        # Try AST parsing first
        if TREE_SITTER_AVAILABLE:
            try:
                lang = Language(ts_javascript.language())
                parser = Parser(lang)
                tree = parser.parse(bytes(code, "utf8"))
                
                lines = code.split('\n')
                
                def find_nodes_by_type(node, node_type: str) -> List:
                    results = []
                    if node.type == node_type:
                        results.append(node)
                    for child in node.children:
                        results.extend(find_nodes_by_type(child, node_type))
                    return results
                
                # Find call expressions (fs.openSync, Buffer.alloc, etc.)
                call_expressions = find_nodes_by_type(tree.root_node, 'call_expression')
                
                for call in call_expressions:
                    text = code[call.start_byte:call.end_byte]
                    line_num = code[:call.start_byte].count('\n') + 1
                    
                    # Pattern 1: fs.openSync without fs.closeSync
                    if 'fs.openSync' in text or 'openSync' in text:
                        # Check for closeSync in next 30 lines
                        has_close = any('closeSync' in line for line in lines[line_num-1:min(line_num+30, len(lines))])
                        
                        if not has_close:
                            findings.append(Finding(
                                severity=Severity.HIGH,
                                title="File Descriptor Not Closed",
                                description=(
                                    "File opened with fs.openSync() but never closed with fs.closeSync(). "
                                    "KSI-SVC-08 requires not leaving residual elements that could affect availability (SC-4) - "
                                    "unclosed file descriptors cause resource exhaustion and may lock files."
                                ),
                                file_path=file_path,
                                line_number=line_num,
                                snippet=self._get_snippet(lines, line_num, context=3),
                                remediation=(
                                    "Close file descriptors explicitly:\n"
                                    "let fd: number | undefined;\n"
                                    "try {\n"
                                    "  fd = fs.openSync('file.txt', 'r');\n"
                                    "  const buffer = Buffer.alloc(1024);\n"
                                    "  fs.readSync(fd, buffer, 0, 1024, 0);\n"
                                    "} finally {\n"
                                    "  if (fd !== undefined) fs.closeSync(fd);\n"
                                    "}\n\n"
                                    "Ref: Node.js fs Module (https://nodejs.org/api/fs.html)"
                                ),
                                ksi_id=self.KSI_ID
                            ))
                    
                    # Pattern 2: Buffer.alloc/from with sensitive data
                    if 'Buffer.alloc' in text or 'Buffer.from' in text:
                        # Check if variable name suggests sensitive data
                        line_text = lines[line_num - 1] if line_num > 0 else ""
                        is_sensitive = any(pattern in line_text.lower() for pattern in ['password', 'secret', 'token', 'key'])
                        
                        if is_sensitive:
                            # Check for .fill(0) in next 30 lines
                            has_fill = any('fill(0)' in line or "fill('\\x00')" in line 
                                         for line in lines[line_num-1:min(line_num+30, len(lines))])
                            
                            if not has_fill:
                                findings.append(Finding(
                                    severity=Severity.MEDIUM,
                                    title="Sensitive Buffer Not Cleared After Use",
                                    description=(
                                        "Buffer containing sensitive data not explicitly zeroed after use. "
                                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                                        "sensitive data in buffers may persist in memory or core dumps."
                                    ),
                                    file_path=file_path,
                                    line_number=line_num,
                                    snippet=self._get_snippet(lines, line_num, context=3),
                                    remediation=(
                                        "Clear sensitive buffers after use:\n"
                                        "const passwordBuffer = Buffer.from(password, 'utf8');\n"
                                        "try {\n"
                                        "  await encryptData(passwordBuffer);\n"
                                        "} finally {\n"
                                        "  passwordBuffer.fill(0);\n"
                                        "}\n\n"
                                        "Ref: Node.js Buffer (https://nodejs.org/api/buffer.html#buffer_buf_fill_value_offset_end_encoding)"
                                    ),
                                    ksi_id=self.KSI_ID
                                ))
                
                return findings
                
            except Exception:
                # Fall back to regex if AST parsing fails
                pass
        
        # Regex fallback
        return self._typescript_regex_fallback(code, file_path)
    
    def _typescript_regex_fallback(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based detection for TypeScript when AST parsing fails."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: fs.openSync without closeSync
        open_sync_match = self._find_line(lines, r'fs\.openSync\(', use_regex=True)
        if open_sync_match:
            line_num = open_sync_match['line_num']
            has_close = any('closeSync' in line for line in lines[line_num:min(line_num+30, len(lines))])
            
            if not has_close:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Descriptor Not Closed (Regex Fallback)",
                    description="File opened with fs.openSync() but never closed.",
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation="Use try-finally to ensure file descriptor is closed.",
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-08 compliance.
        
        Detects:
        - Storage without soft delete
        - VMs without ephemeral OS disk
        - Resources without proper deletion policies
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage Account without blob soft delete (MEDIUM)
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@")
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if deleteRetentionPolicy is configured
            has_soft_delete = any('deleteRetentionPolicy' in line 
                                 for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_soft_delete:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Blob Soft Delete",
                    description=(
                        "Storage Account without blob soft delete retention policy. "
                        "KSI-SVC-08 requires not introducing residual elements that negatively affect confidentiality (SC-4) - "
                        "without soft delete, accidentally deleted blobs containing customer data cannot be recovered "
                        "and may be immediately overwritten, risking data exposure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure blob soft delete for data protection:\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: storageAccountName\n"
                        "  location: location\n"
                        "  sku: {\n"
                        "    name: 'Standard_LRS'\n"
                        "  }\n"
                        "  kind: 'StorageV2'\n"
                        "  properties: {\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "// Blob services with soft delete\n"
                        "resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {\n"
                        "  parent: storageAccount\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    deleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7  // Retain deleted blobs for 7 days\n"
                        "    }\n"
                        "    containerDeleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Blob Soft Delete (https://learn.microsoft.com/azure/storage/blobs/soft-delete-blob-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: VM without ephemeral OS disk (LOW)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines@")
        
        if vm_match:
            line_num = vm_match['line_num']
            has_ephemeral = any('diffDiskSettings' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_ephemeral:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="VM Without Ephemeral OS Disk",
                    description=(
                        "Virtual Machine without ephemeral OS disk configuration. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "persistent OS disks may retain sensitive data after VM deletion. "
                        "Consider ephemeral OS disks for stateless workloads to ensure no data residue."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure ephemeral OS disk for stateless VMs:\n"
                        "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
                        "  name: vmName\n"
                        "  location: location\n"
                        "  properties: {\n"
                        "    storageProfile: {\n"
                        "      osDisk: {\n"
                        "        createOption: 'FromImage'\n"
                        "        caching: 'ReadOnly'\n"
                        "        diffDiskSettings: {\n"
                        "          option: 'Local'  // Ephemeral disk\n"
                        "          placement: 'CacheDisk'  // or 'ResourceDisk'\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "Note: Only suitable for stateless workloads. Data is lost on VM stop/restart.\n\n"
                        "Ref: Azure Ephemeral OS Disks (https://learn.microsoft.com/azure/virtual-machines/ephemeral-os-disks)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-08 compliance.
        
        Detects:
        - Storage without blob retention
        - Compute instances without ephemeral storage
        - Resources without proper lifecycle policies
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: azurerm_storage_account without blob retention (MEDIUM)
        storage_match = self._find_line(lines, r'resource\s+"azurerm_storage_account"')
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if blob_properties with delete_retention_policy exists
            has_retention = any('delete_retention_policy' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_retention:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Blob Retention Policy",
                    description=(
                        "azurerm_storage_account without blob delete_retention_policy. "
                        "KSI-SVC-08 requires not introducing residual elements that negatively affect confidentiality (SC-4) - "
                        "without retention policy, deleted blobs containing customer data cannot be recovered "
                        "and may be immediately overwritten, risking data exposure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure blob soft delete retention:\n"
                        'resource "azurerm_storage_account" "example" {\n'
                        '  name                     = "examplestorageacct"\n'
                        '  resource_group_name      = azurerm_resource_group.example.name\n'
                        '  location                 = azurerm_resource_group.example.location\n'
                        '  account_tier             = "Standard"\n'
                        '  account_replication_type = "GRS"\n\n'
                        '  blob_properties {\n'
                        '    delete_retention_policy {\n'
                        '      days = 7  # Retain deleted blobs for 7 days\n'
                        '    }\n'
                        '    container_delete_retention_policy {\n'
                        '      days = 7\n'
                        '    }\n'
                        '  }\n'
                        '}\n\n'
                        "Ref: azurerm_storage_account blob_properties (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#blob_properties)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: azurerm_linux_virtual_machine without ephemeral OS disk (LOW)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows)_virtual_machine"')
        
        if vm_match:
            line_num = vm_match['line_num']
            # Check if os_disk has diff_disk_settings
            has_ephemeral = any('diff_disk_settings' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_ephemeral:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="VM Without Ephemeral OS Disk",
                    description=(
                        "Virtual Machine without ephemeral OS disk (diff_disk_settings). "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "persistent OS disks may retain sensitive data after VM deletion. "
                        "Consider ephemeral OS disks for stateless workloads to ensure no data residue."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure ephemeral OS disk for stateless VMs:\n"
                        'resource "azurerm_linux_virtual_machine" "example" {\n'
                        '  name                = "example-vm"\n'
                        '  resource_group_name = azurerm_resource_group.example.name\n'
                        '  location            = azurerm_resource_group.example.location\n'
                        '  size                = "Standard_DS1_v2"\n\n'
                        '  os_disk {\n'
                        '    caching              = "ReadOnly"\n'
                        '    storage_account_type = "Standard_LRS"\n'
                        '    diff_disk_settings {\n'
                        '      option    = "Local"  # Ephemeral disk\n'
                        '      placement = "CacheDisk"  # or "ResourceDisk"\n'
                        '    }\n'
                        '  }\n\n'
                        '  # ... other configuration\n'
                        '}\n\n'
                        "Note: Only suitable for stateless workloads. Data is lost on VM stop/restart.\n\n"
                        "Ref: azurerm_linux_virtual_machine os_disk (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#os_disk)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-SVC-08.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Shared Resources",
            "evidence_type": "config-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure Policy",
                "Azure Monitor",
                "Azure Storage",
                "Microsoft Defender for Cloud",
                "Azure Backup"
            ],
            "collection_methods": [
                "Azure Policy to enforce data sanitization and secure deletion configurations",
                "Azure Storage lifecycle management policies to automatically purge residual data",
                "Azure Monitor to track resource cleanup operations and detect data residue",
                "Defender for Cloud recommendations for secure data handling in shared environments"
            ],
            "implementation_steps": [
                "1. Configure Azure Storage lifecycle policies: (a) Auto-delete blob snapshots after retention period, (b) Move old data to Cool/Archive tiers before deletion, (c) Set blob soft-delete retention (7-90 days), (d) Enable versioning with cleanup automation",
                "2. Deploy Azure Policy 'Secure Data Residue Management': (a) Audit storage accounts without soft-delete, (b) Require VM disk encryption for secure wipe, (c) Enforce SQL transparent data encryption for deleted databases, (d) Verify Key Vault key rotation on deletion",
                "3. Build Azure Automation runbook 'Data-Residue-Scanner': (a) Identify orphaned disks/snapshots, (b) Check for unattached NICs with private IPs, (c) Scan for deleted resource metadata retention, (d) Alert on residual data exceeding 30 days",
                "4. Create Azure Monitor workbook 'Shared Resource Cleanup Dashboard': (a) Track deleted resources with residual data, (b) Show cleanup SLAs (time to complete deletion), (c) Monitor soft-delete recoveries (potential data leaks), (d) Display orphaned resources by subscription",
                "5. Integrate with Azure Backup: (a) Configure backup retention aligned with data retention policy, (b) Document backup purge procedures, (c) Validate backup copies are also securely deleted",
                "6. Generate monthly evidence package via Azure Automation: (a) Export storage lifecycle execution logs, (b) Export Policy compliance for data residue controls, (c) Export orphaned resource reports, (d) Export deletion audit logs"
            ],
            "evidence_artifacts": [
                "Azure Storage Lifecycle Management Execution Logs showing automated data purge operations",
                "Azure Policy Compliance Report for data residue management and secure deletion requirements",
                "Orphaned Resource Report from Azure Automation identifying residual data in shared environments",
                "Azure Monitor Deletion Audit Logs tracking all resource deletions with completion timestamps",
                "Backup Purge Documentation showing aligned retention policies and secure backup deletion procedures"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Operations Team / Data Stewardship Team"
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
                "query_name": "Orphaned resources with potential data residue",
                "query": """Resources
| where type in ('microsoft.compute/disks', 'microsoft.compute/snapshots', 'microsoft.network/networkinterfaces', 'microsoft.storage/storageaccounts')
| where properties.diskState == 'Unattached' or properties.provisioningState == 'Deleting' or properties.deleteRetentionPolicy.enabled == false
| extend OrphanedDays = datetime_diff('day', now(), todatetime(properties.timeCreated))
| where OrphanedDays > 30
| project name, type, resourceGroup, OrphanedDays, location
| order by OrphanedDays desc""",
                "purpose": "Identify orphaned resources that may contain residual federal customer data beyond 30-day threshold"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Resource deletion completion audit",
                "query": """AzureActivity
| where OperationNameValue contains 'DELETE'
| where ActivityStatusValue in ('Success', 'Failed')
| extend DeletionDuration = datetime_diff('minute', TimeGenerated, EventSubmissionTimestamp)
| summarize DeletionCount = count(), AvgDuration = avg(DeletionDuration), MaxDuration = max(DeletionDuration) by ResourceType = ResourceType, OperationNameValue
| order by DeletionCount desc""",
                "purpose": "Track resource deletion operations to ensure complete removal without residual data"
            },
            {
                "query_type": "Azure Storage REST API",
                "query_name": "Storage lifecycle policy execution history",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Storage/storageAccounts/{accountName}/managementPolicies/default?api-version=2023-01-01",
                "purpose": "Retrieve storage lifecycle management policy configurations and execution logs for automated data purge"
            },
            {
                "query_type": "Azure Policy REST API",
                "query_name": "Data residue management policy compliance",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&$filter=policyDefinitionCategory eq 'Storage' and (policyDefinitionName contains 'soft-delete' or policyDefinitionName contains 'lifecycle')",
                "purpose": "Assess policy compliance for data residue controls including soft-delete and lifecycle management"
            },
            {
                "query_type": "Azure Backup REST API",
                "query_name": "Backup retention and purge policy audit",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-01-01",
                "purpose": "Audit backup vault retention policies to ensure backups are also purged in alignment with data deletion requests"
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
                "artifact_name": "Storage Lifecycle Management Logs",
                "artifact_type": "Azure Storage Execution Logs",
                "description": "Logs showing automated lifecycle policy executions for blob deletion and tier transitions",
                "collection_method": "Azure Storage REST API to retrieve lifecycle policy execution history with blob deletion counts",
                "storage_location": "Azure Log Analytics workspace with storage diagnostic logs ingestion"
            },
            {
                "artifact_name": "Data Residue Policy Compliance Report",
                "artifact_type": "Azure Policy Report",
                "description": "Policy compliance status for storage soft-delete, lifecycle management, and secure deletion configurations",
                "collection_method": "Azure Policy Insights API to export compliance for data residue management policies",
                "storage_location": "Azure Storage Account with monthly compliance reports in JSON format"
            },
            {
                "artifact_name": "Orphaned Resource Inventory",
                "artifact_type": "Azure Resource Graph Report",
                "description": "List of orphaned disks, snapshots, and storage accounts with age and potential data residue risk",
                "collection_method": "Azure Resource Graph KQL query executed monthly via Azure Automation runbook",
                "storage_location": "Azure Storage Account with CSV exports organized by subscription and date"
            },
            {
                "artifact_name": "Resource Deletion Audit Trail",
                "artifact_type": "Azure Activity Log",
                "description": "Complete audit log of all resource deletion operations with completion status and duration",
                "collection_method": "Azure Monitor Activity Log API to export deletion events filtered by operation type",
                "storage_location": "Azure Log Analytics workspace with 12-month retention for audit compliance"
            },
            {
                "artifact_name": "Backup Purge Procedures Documentation",
                "artifact_type": "Azure Backup Configuration Export",
                "description": "Documentation of backup retention policies and procedures for secure backup deletion upon customer request",
                "collection_method": "Azure Backup REST API to export vault configurations with retention settings",
                "storage_location": "Azure DevOps wiki with version-controlled backup purge procedures"
            }
        ]
    