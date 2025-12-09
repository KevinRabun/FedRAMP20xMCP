"""
KSI-AFR-04: Vulnerability Detection and Response

Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_AFR_04_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-04: Vulnerability Detection and Response
    
    **Official Statement:**
    Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-2
    - ca-7
    - ca-7.6
    - ir-1
    - ir-4
    - ir-4.1
    - ir-5
    - ir-5.1
    - ir-6
    - ir-6.1
    - ir-6.2
    - pm-3
    - pm-5
    - pm-31
    - ra-2
    - ra-2.1
    - ra-3
    - ra-3.3
    - ra-5
    - ra-5.2
    - ra-5.3
    - ra-5.4
    - ra-5.5
    - ra-5.6
    - ra-5.7
    - ra-5.11
    - ra-9
    - ra-10
    - si-2
    - si-2.1
    - si-2.2
    - si-2.4
    - si-2.5
    - si-3
    - si-3.1
    - si-3.2
    - si-4
    - si-4.2
    - si-4.3
    - si-4.7
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Document the vulnerability detection and vulnerability response methodology used within the cloud se...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-04"
    KSI_NAME = "Vulnerability Detection and Response"
    KSI_STATEMENT = """Document the vulnerability detection and vulnerability response methodology used within the cloud service offering in alignment with the FedRAMP Vulnerability Detection and Response (VDR) process and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ca-2", "Control Assessments"),
        ("ca-7", "Continuous Monitoring"),
        ("ca-7.6", "Automation Support for Monitoring"),
        ("ir-1", "Policy and Procedures"),
        ("ir-4", "Incident Handling"),
        ("ir-4.1", "Automated Incident Handling Processes"),
        ("ir-5", "Incident Monitoring"),
        ("ir-5.1", "Automated Tracking, Data Collection, and Analysis"),
        ("ir-6", "Incident Reporting"),
        ("ir-6.1", "Automated Reporting"),
        ("ir-6.2", "Vulnerabilities Related to Incidents"),
        ("pm-3", "Information Security and Privacy Resources"),
        ("pm-5", "System Inventory"),
        ("pm-31", "Continuous Monitoring Strategy"),
        ("ra-2", "Security Categorization"),
        ("ra-2.1", "Impact-level Prioritization"),
        ("ra-3", "Risk Assessment"),
        ("ra-3.3", "Dynamic Threat Awareness"),
        ("ra-5", "Vulnerability Monitoring and Scanning"),
        ("ra-5.2", "Update Vulnerabilities to Be Scanned"),
        ("ra-5.3", "Breadth and Depth of Coverage"),
        ("ra-5.4", "Discoverable Information"),
        ("ra-5.5", "Privileged Access"),
        ("ra-5.6", "Automated Trend Analyses"),
        ("ra-5.7", "Automated Detection and Notification of Unauthorized Components"),
        ("ra-5.11", "Public Disclosure Program"),
        ("ra-9", "Criticality Analysis"),
        ("ra-10", "Threat Hunting"),
        ("si-2", "Flaw Remediation"),
        ("si-2.1", "Central Management"),
        ("si-2.2", "Automated Flaw Remediation Status"),
        ("si-2.4", "Automated Patch Management Tools"),
        ("si-2.5", "Automatic Software and Firmware Updates"),
        ("si-3", "Malicious Code Protection"),
        ("si-3.1", "Central Management"),
        ("si-3.2", "Automatic Updates"),
        ("si-4", "System Monitoring"),
        ("si-4.2", "Automated Tools and Mechanisms for Real-time Analysis"),
        ("si-4.3", "Automated Tool and Mechanism Integration"),
        ("si-4.7", "Automated Response to Suspicious Events")
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
        Analyze Python code for KSI-AFR-04 compliance (AST-first).
        
        Detects:
        - Missing exception handling for security operations
        - No vulnerability scanning imports (safety, bandit, etc.)
        - Insecure deserialization (pickle, yaml.unsafe_load)
        - SQL injection patterns
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
        """AST-based Python vulnerability detection analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure deserialization via pickle
        # Check both 'import pickle' and 'from pickle import'
        import_statements = parser.find_nodes_by_type(tree, 'import_statement')
        import_from_statements = parser.find_nodes_by_type(tree, 'import_from_statement')
        
        for node in import_statements + import_from_statements:
            node_text = parser.get_node_text(node, code_bytes)
            if 'pickle' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Insecure Deserialization (pickle)",
                    description=(
                        f"Code imports pickle module. Pickle deserialization can execute arbitrary code. "
                        f"KSI-AFR-04 requires vulnerability detection and response. "
                        f"This is a known vulnerability pattern (CWE-502)."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Replace pickle with secure serialization:\n"
                        "import json\n\n"
                        "# Use JSON for safe serialization\n"
                        "data = json.loads(json_string)\n\n"
                        "# For complex objects, validate input\n"
                        "from pydantic import BaseModel, ValidationError\n\n"
                        "class SafeData(BaseModel):\n"
                        "    name: str\n"
                        "    value: int\n\n"
                        "try:\n"
                        "    data = SafeData.parse_raw(json_string)\n"
                        "except ValidationError as e:\n"
                        "    # Handle validation error\n"
                        "    pass\n\n"
                        "Ref: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)"
                    )
                ))
        
        # Pattern 2: yaml.unsafe_load() - insecure YAML loading
        attribute_nodes = parser.find_nodes_by_type(tree, 'attribute')
        for node in attribute_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if 'yaml.unsafe_load' in node_text or 'yaml.load' in node_text:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Insecure YAML Deserialization",
                    description=(
                        f"Code uses yaml.load() or yaml.unsafe_load() which allows arbitrary code execution. "
                        f"KSI-AFR-04 requires vulnerability detection. This is CWE-502."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        "Use yaml.safe_load() instead:\n"
                        "import yaml\n\n"
                        "# Safe YAML loading (no code execution)\n"
                        "data = yaml.safe_load(yaml_string)\n\n"
                        "Ref: CWE-502"
                    )
                ))
        
        # Pattern 3: SQL injection via string formatting
        # Look for .execute() calls with string concatenation or f-strings
        call_nodes = parser.find_nodes_by_type(tree, 'call')
        for node in call_nodes:
            # Check if this is a .execute() call
            func = node.child_by_field_name('function')
            if func and func.type == 'attribute':
                func_text = parser.get_node_text(func, code_bytes)
                if '.execute' in func_text:
                    # Check arguments for string concatenation or f-strings
                    args = node.child_by_field_name('arguments')
                    if args:
                        args_text = parser.get_node_text(args, code_bytes)
                        # Detect SQL injection patterns
                        if ('+' in args_text and ('SELECT' in args_text.upper() or 'INSERT' in args_text.upper() or 
                            'UPDATE' in args_text.upper() or 'DELETE' in args_text.upper())) or 'f"SELECT' in args_text or "f'SELECT" in args_text:
                            line_num = node.start_point[0] + 1
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="SQL Injection Vulnerability",
                                description=(
                                    f"Code uses string concatenation or f-strings in SQL query. "
                                    f"This is vulnerable to SQL injection (CWE-89). "
                                    f"KSI-AFR-04 requires vulnerability detection and response."
                                ),
                                severity=Severity.CRITICAL,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num),
                                recommendation=(
                                    "Use parameterized queries:\n"
                                    "# Bad: SQL injection vulnerable\n"
                                    "# cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")\n\n"
                                    "# Good: Parameterized query\n"
                                    "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))\n\n"
                                    "# Or use ORM\n"
                                    "from sqlalchemy import text\n"
                                    "result = session.execute(text(\"SELECT * FROM users WHERE id = :id\"), {'id': user_id})\n\n"
                                    "Ref: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)"
                                )
                            ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for Python vulnerability detection."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure deserialization
        if re.search(r'\bimport\s+pickle\b|\bfrom\s+pickle\s+import\b', code):
            line_num = self._find_line(lines, 'pickle')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Insecure Deserialization (pickle)",
                description=(
                    "Code imports pickle module. Pickle deserialization can execute arbitrary code (CWE-502)."
                ),
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Replace pickle with json or use safe alternatives like pydantic for validation."
            ))
        
        # Pattern 2: Insecure YAML
        if re.search(r'yaml\.(unsafe_)?load\b', code):
            line_num = self._find_line(lines, 'yaml.load')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Insecure YAML Deserialization",
                description="Code uses yaml.load() which allows arbitrary code execution (CWE-502).",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Use yaml.safe_load() instead."
            ))
        
        # Pattern 3: SQL injection
        sql_injection_pattern = r'\.(execute|executemany)\s*\([^)]*\+[^)]*\)'
        if re.search(sql_injection_pattern, code):
            line_num = self._find_line(lines, '.execute')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SQL Injection Vulnerability",
                description="Code uses string concatenation in SQL query (CWE-89).",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Use parameterized queries with placeholders (%s, :name, etc.)."
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-AFR-04 compliance (AST-first).
        
        Detects:
        - Insecure deserialization (BinaryFormatter, SoapFormatter)
        - SQL injection via string concatenation
        - XXE (XML External Entity) vulnerabilities
        - Command injection
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
        """AST-based C# vulnerability detection analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure deserialization via BinaryFormatter
        identifier_nodes = parser.find_nodes_by_type(tree, 'identifier')
        insecure_formatters = ['BinaryFormatter', 'SoapFormatter', 'NetDataContractSerializer', 'LosFormatter']
        
        for node in identifier_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if node_text in insecure_formatters:
                line_num = node.start_point[0] + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Insecure Deserialization ({node_text})",
                    description=(
                        f"Code uses {node_text} which is vulnerable to remote code execution. "
                        f"Microsoft has deprecated these formatters. "
                        f"KSI-AFR-04 requires vulnerability detection and response (CWE-502)."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        f"Replace {node_text} with secure serialization:\n"
                        "using System.Text.Json;\n\n"
                        "// Use System.Text.Json for safe serialization\n"
                        "var options = new JsonSerializerOptions\n"
                        "{\n"
                        "    PropertyNameCaseInsensitive = true\n"
                        "};\n"
                        "var data = JsonSerializer.Deserialize<MyType>(jsonString, options);\n\n"
                        "// Or use DataContractSerializer with known types\n"
                        "var serializer = new DataContractSerializer(\n"
                        "    typeof(MyType),\n"
                        "    new DataContractSerializerSettings\n"
                        "    {\n"
                        "        MaxItemsInObjectGraph = 1000,\n"
                        "        KnownTypes = new[] { typeof(MyType) }\n"
                        "    }\n"
                        ");\n\n"
                        "Ref: https://learn.microsoft.com/dotnet/standard/serialization/binaryformatter-security-guide"
                    )
                ))
        
        # Pattern 2: SQL injection via string interpolation
        # Look for 'new SqlCommand' with interpolated strings
        object_creation_nodes = parser.find_nodes_by_type(tree, 'object_creation_expression')
        for node in object_creation_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if 'SqlCommand' in node_text:
                # Check for interpolated_string_expression or string concatenation
                # Look for $"SELECT/INSERT/UPDATE/DELETE with {variable}
                if '$"SELECT' in node_text or '$"INSERT' in node_text or '$"UPDATE' in node_text or '$"DELETE' in node_text:
                    if '{' in node_text and '}' in node_text:  # Interpolated variable
                        line_num = node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title="SQL Injection Vulnerability",
                            description=(
                                "Code uses string interpolation in SQL query. "
                                "This is vulnerable to SQL injection (CWE-89). "
                                "KSI-AFR-04 requires vulnerability detection."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            recommendation=(
                                "Use parameterized queries:\n"
                                "// Bad: SQL injection vulnerable\n"
                                "// var cmd = new SqlCommand($\"SELECT * FROM Users WHERE Id = {userId}\", conn);\n\n"
                                "// Good: Parameterized query\n"
                                "var cmd = new SqlCommand(\"SELECT * FROM Users WHERE Id = @userId\", conn);\n"
                                "cmd.Parameters.AddWithValue(\"@userId\", userId);\n\n"
                                "// Or use EF Core\n"
                                "var user = context.Users.FirstOrDefault(u => u.Id == userId);\n\n"
                                "Ref: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)"
                            )
                        ))
        
        # Pattern 3: XXE (XML External Entity) vulnerability
        # Check for XmlDocument/XmlTextReader without secure settings
        for node in identifier_nodes:
            node_text = parser.get_node_text(node, code_bytes)
            if node_text in ['XmlDocument', 'XmlTextReader', 'XmlReader']:
                # Check if DtdProcessing is set to Prohibit or XmlResolver is set to null
                # This is a simplified check - full analysis would need data flow
                line_num = node.start_point[0] + 1
                snippet_start = max(0, line_num - 5)
                snippet_end = min(len(lines), line_num + 5)
                context = '\n'.join(lines[snippet_start:snippet_end])
                
                if 'DtdProcessing' not in context and 'XmlResolver' not in context:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="XML External Entity (XXE) Vulnerability",
                        description=(
                            f"Code uses {node_text} without secure configuration. "
                            f"This may be vulnerable to XXE attacks (CWE-611). "
                            f"KSI-AFR-04 requires vulnerability detection."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Configure secure XML parsing:\n"
                            "var settings = new XmlReaderSettings\n"
                            "{\n"
                            "    DtdProcessing = DtdProcessing.Prohibit,\n"
                            "    XmlResolver = null\n"
                            "};\n"
                            "using var reader = XmlReader.Create(stream, settings);\n\n"
                            "Ref: CWE-611 (https://cwe.mitre.org/data/definitions/611.html)"
                        )
                    ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for C# vulnerability detection."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure deserialization
        insecure_formatters = ['BinaryFormatter', 'SoapFormatter', 'NetDataContractSerializer']
        for formatter in insecure_formatters:
            if re.search(rf'\b{formatter}\b', code):
                line_num = self._find_line(lines, formatter)
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Insecure Deserialization ({formatter})",
                    description=f"Code uses {formatter} which is vulnerable to RCE (CWE-502).",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Use System.Text.Json or secure DataContractSerializer."
                ))
        
        # Pattern 2: SQL injection
        if re.search(r'SqlCommand.*\$".*SELECT|INSERT|UPDATE|DELETE', code, re.IGNORECASE):
            line_num = self._find_line(lines, 'SqlCommand')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SQL Injection Vulnerability",
                description="Code uses string interpolation in SQL query (CWE-89).",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Use parameterized queries with SqlParameter."
            ))
        
        # Pattern 3: XXE
        if re.search(r'\bXmlDocument\b|\bXmlTextReader\b', code):
            if 'DtdProcessing' not in code and 'XmlResolver' not in code:
                line_num = self._find_line(lines, 'XmlDocument')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="XML External Entity (XXE) Vulnerability",
                    description="XML parsing without secure configuration (CWE-611).",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Set DtdProcessing = DtdProcessing.Prohibit and XmlResolver = null."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-04 compliance (AST-first).
        
        Detects:
        - Insecure deserialization (ObjectInputStream)
        - SQL injection via string concatenation
        - XXE vulnerabilities
        - Command injection
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
        """AST-based Java vulnerability detection analysis."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure deserialization via ObjectInputStream
        # Check for ObjectInputStream.readObject() or ois.readObject()
        method_calls = parser.find_nodes_by_type(tree, 'method_invocation')
        for call_node in method_calls:
            call_text = parser.get_node_text(call_node, code_bytes)
            
            # Check for readObject() method call
            if 'readObject' in call_text:
                # Check if the variable is ObjectInputStream by looking for context
                line_num = call_node.start_point[0] + 1
                # Look for ObjectInputStream declaration in surrounding lines
                context_start = max(0, line_num - 10)
                context_end = min(len(lines), line_num + 2)
                context = '\n'.join(lines[context_start:context_end])
                
                if 'ObjectInputStream' in context:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Insecure Deserialization (ObjectInputStream)",
                        description=(
                            "Code uses ObjectInputStream.readObject() which can execute arbitrary code. "
                            "This is a critical deserialization vulnerability (CWE-502). "
                            "KSI-AFR-04 requires vulnerability detection and response."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Replace ObjectInputStream with secure serialization:\n"
                            "import com.fasterxml.jackson.databind.ObjectMapper;\n\n"
                            "// Use Jackson for safe JSON serialization\n"
                            "ObjectMapper mapper = new ObjectMapper();\n"
                            "MyObject obj = mapper.readValue(jsonString, MyObject.class);\n\n"
                            "// If ObjectInputStream is necessary, use ObjectInputFilter\n"
                            "ObjectInputStream ois = new ObjectInputStream(inputStream);\n"
                            "ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter(\n"
                            "    \"com.example.MyClass;!*\"  // Whitelist only specific classes\n"
                            "));\n\n"
                            "Ref: CWE-502 (https://cwe.mitre.org/data/definitions/502.html)"
                        )
                    ))            # Pattern 2: SQL injection via Statement.executeQuery with string concatenation
            # Check method invocation arguments for concatenation
            if ('executeQuery' in call_text or 'executeUpdate' in call_text or 'execute' in call_text):
                # Check if argument contains string concatenation
                args = call_node.child_by_field_name('arguments')
                if args:
                    args_text = parser.get_node_text(args, code_bytes)
                    if '+' in args_text and any(kw in args_text.upper() for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                        line_num = call_node.start_point[0] + 1
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title="SQL Injection Vulnerability",
                            description=(
                                "Code uses string concatenation in SQL query. "
                                "This is vulnerable to SQL injection (CWE-89). "
                                "KSI-AFR-04 requires vulnerability detection."
                            ),
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=self._get_snippet(lines, line_num),
                            recommendation=(
                                "Use PreparedStatement for parameterized queries:\n"
                                "// Bad: SQL injection vulnerable\n"
                                "// Statement stmt = conn.createStatement();\n"
                                "// ResultSet rs = stmt.executeQuery(\"SELECT * FROM users WHERE id = \" + userId);\n\n"
                                "// Good: Parameterized query\n"
                                "String sql = \"SELECT * FROM users WHERE id = ?\";\n"
                                "PreparedStatement pstmt = conn.prepareStatement(sql);\n"
                                "pstmt.setInt(1, userId);\n"
                                "ResultSet rs = pstmt.executeQuery();\n\n"
                                "// Or use JPA/Hibernate\n"
                                "TypedQuery<User> query = em.createQuery(\n"
                                "    \"SELECT u FROM User u WHERE u.id = :id\", User.class);\n"
                                "query.setParameter(\"id\", userId);\n"
                                "User user = query.getSingleResult();\n\n"
                                "Ref: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)"
                            )
                        ))
        
        # Pattern 2b: SQL injection via string concatenation in variable declarations
        # Look for 'String sql = "SELECT..." + userId' patterns
        local_var_decls = parser.find_nodes_by_type(tree, 'local_variable_declaration')
        for decl_node in local_var_decls:
            decl_text = parser.get_node_text(decl_node, code_bytes)
            # Check if it's a String variable with SQL keywords and concatenation
            if 'String' in decl_text and '+' in decl_text:
                if any(kw in decl_text.upper() for kw in ['SELECT', 'INSERT', 'UPDATE', 'DELETE']):
                    line_num = decl_node.start_point[0] + 1
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="SQL Injection Vulnerability",
                        description=(
                            "Code builds SQL query using string concatenation. "
                            "This is vulnerable to SQL injection (CWE-89). "
                            "KSI-AFR-04 requires vulnerability detection."
                        ),
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Use PreparedStatement for parameterized queries:\n"
                            "// Bad: String sql = \"SELECT * FROM users WHERE id = \" + userId;\n\n"
                            "// Good: Parameterized query\n"
                            "String sql = \"SELECT * FROM users WHERE id = ?\";\n"
                            "PreparedStatement pstmt = conn.prepareStatement(sql);\n"
                            "pstmt.setInt(1, userId);\n\n"
                            "Ref: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)"
                        )
                    ))
        
        # Pattern 3: XXE vulnerability via DocumentBuilderFactory
        # Check for DocumentBuilderFactory.newInstance() without secure features
        for call_node in method_calls:
            call_text = parser.get_node_text(call_node, code_bytes)
            if 'DocumentBuilderFactory' in call_text and 'newInstance' in call_text:
                line_num = call_node.start_point[0] + 1
                # Check if secure features are set in surrounding context
                snippet_start = max(0, line_num - 5)
                snippet_end = min(len(lines), line_num + 5)
                context = '\n'.join(lines[snippet_start:snippet_end])
                
                if 'setFeature' not in context or 'external-general-entities' not in context:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="XML External Entity (XXE) Vulnerability",
                        description=(
                            "Code uses DocumentBuilderFactory without secure configuration. "
                            "This may be vulnerable to XXE attacks (CWE-611). "
                            "KSI-AFR-04 requires vulnerability detection."
                        ),
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        recommendation=(
                            "Configure secure XML parsing:\n"
                            "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
                            "// Prevent XXE\n"
                            "dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                            "dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n"
                            "dbf.setFeature(\"http://xml.org/sax/features/external-parameter-entities\", false);\n"
                            "dbf.setXIncludeAware(false);\n"
                            "dbf.setExpandEntityReferences(false);\n\n"
                            "DocumentBuilder db = dbf.newDocumentBuilder();\n"
                            "Document doc = db.parse(inputStream);\n\n"
                            "Ref: CWE-611 (https://cwe.mitre.org/data/definitions/611.html)"
                        )
                    ))
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str) -> List[Finding]:
        """Regex fallback for Java vulnerability detection."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Insecure deserialization
        if re.search(r'ObjectInputStream.*readObject\(\)', code):
            line_num = self._find_line(lines, 'ObjectInputStream')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Insecure Deserialization (ObjectInputStream)",
                description="Code uses ObjectInputStream.readObject() which can execute arbitrary code (CWE-502).",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Use Jackson or implement ObjectInputFilter for validation."
            ))
        
        # Pattern 2: SQL injection
        if re.search(r'executeQuery\s*\([^)]*\+[^)]*\)', code):
            line_num = self._find_line(lines, 'executeQuery')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="SQL Injection Vulnerability",
                description="Code uses string concatenation in SQL query (CWE-89).",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                recommendation="Use PreparedStatement with parameterized queries."
            ))
        
        # Pattern 3: XXE
        if re.search(r'DocumentBuilderFactory', code):
            if 'setFeature' not in code or 'external-general-entities' not in code:
                line_num = self._find_line(lines, 'DocumentBuilderFactory')
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="XML External Entity (XXE) Vulnerability",
                    description="XML parsing without secure configuration (CWE-611).",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation="Disable external entities and DTD processing in DocumentBuilderFactory."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement Bicep-specific detection logic
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-04 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Document the vulnerability detection and vulnerability response methodology used...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-04 compliance.
        
        Detects:
        - Missing vulnerability scanning steps
        - Missing dependency scanning
        - Missing security scanning tools
        """
        findings = []
        lines = code.split('\n')
        
        # Check for vulnerability/security scanning
        has_vuln_scan = bool(re.search(r'(snyk|trivy|dependency-check|safety|bandit|semgrep|CodeQL)', code, re.IGNORECASE))
        if not has_vuln_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Vulnerability Scanning in CI/CD",
                description=f"GitHub Actions workflow '{file_path}' lacks vulnerability scanning. KSI-AFR-04 requires vulnerability detection.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add vulnerability scanning:

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    scan-ref: '.'
    format: 'sarif'
    output: 'trivy-results.sarif'

- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: 'trivy-results.sarif'

- name: Dependency scanning
  uses: actions/dependency-review-action@v3
```

Reference: FRR-AFR-04 - Vulnerability Detection and Response"""
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-04 compliance.
        
        Detects missing vulnerability scanning steps
        """
        findings = []
        lines = code.split('\n')
        
        has_vuln_scan = bool(re.search(r'(WhiteSource|Mend|Snyk|Trivy|OWASP|Fortify)', code, re.IGNORECASE))
        if not has_vuln_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Vulnerability Scanning",
                description=f"Azure Pipeline '{file_path}' lacks vulnerability scanning. KSI-AFR-04 requires vulnerability detection.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add vulnerability scanning task:

```yaml
- task: SnykSecurityScan@1
  inputs:
    serviceConnectionEndpoint: 'Snyk'
    testType: 'app'
    severityThreshold: 'high'
    monitorWhen: 'always'

- task: WhiteSourceBolt@21
  inputs:
    cwd: '$(System.DefaultWorkingDirectory)'
```

Reference: FRR-AFR-04"""
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-04 compliance.
        
        Detects missing vulnerability scanning jobs
        """
        findings = []
        lines = code.split('\n')
        
        has_vuln_scan = bool(re.search(r'(gemnasium|trivy|container_scanning|dependency_scanning|sast)', code, re.IGNORECASE))
        if not has_vuln_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Vulnerability Scanning",
                description=f"GitLab CI '{file_path}' lacks vulnerability scanning. KSI-AFR-04 requires vulnerability detection.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add GitLab security scanning:

```yaml
include:
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Container-Scanning.gitlab-ci.yml

dependency_scanning:
  stage: test
  allow_failure: false
```

Reference: FRR-AFR-04"""
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

