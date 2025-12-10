"""KSI-PIY-02 Enhanced: Data Minimization"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_PIY_02_Analyzer(BaseKSIAnalyzer):
    """
    KSI-PIY-02: Data Minimization (Reinterpreted from "Security Objectives")
    
    Focus: Detect excessive data collection, unnecessary PII fields,
    overly broad queries, and lack of data retention policies.
    
    NIST: PL-1, PL-2, PL-4 (Planning), SR-2, SR-3 (Supply Chain)
    """
    
    KSI_ID = "KSI-PIY-02"
    KSI_NAME = "Data Minimization"
    KSI_STATEMENT = """Minimize data collection to necessary fields only."""
    FAMILY = "PIY"
    FAMILY_NAME = "Privacy"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-1", "Policy and Procedures"),
        ("ac-21", "Information Sharing"),
        ("at-1", "Policy and Procedures"),
        ("au-1", "Policy and Procedures"),
        ("ca-1", "Policy and Procedures"),
        ("cm-1", "Policy and Procedures"),
        ("cp-1", "Policy and Procedures"),
        ("cp-2.1", "Coordinate with Related Plans"),
        ("cp-2.8", "Identify Critical Assets"),
        ("cp-4.1", "Coordinate with Related Plans"),
        ("ia-1", "Policy and Procedures"),
        ("ir-1", "Policy and Procedures"),
        ("ma-1", "Policy and Procedures"),
        ("mp-1", "Policy and Procedures"),
        ("pe-1", "Policy and Procedures"),
        ("pl-1", "Policy and Procedures"),
        ("pl-2", "System Security and Privacy Plans"),
        ("pl-4", "Rules of Behavior"),
        ("pl-4.1", "Social Media and External Site/Application Usage Restrictions"),
        ("ps-1", "Policy and Procedures"),
        ("ra-1", "Policy and Procedures"),
        ("ra-9", "Criticality Analysis"),
        ("sa-1", "Policy and Procedures"),
        ("sc-1", "Policy and Procedures"),
        ("si-1", "Policy and Procedures"),
        ("sr-1", "Policy and Procedures"),
        ("sr-2", "Supply Chain Risk Management Plan"),
        ("sr-3", "Supply Chain Controls and Processes"),
        ("sr-11", "Component Authenticity")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Python: SELECT *, overly broad queries, unnecessary PII"""
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Python analysis"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Check for string nodes containing SQL SELECT *
        string_nodes = parser.find_nodes_by_type(tree.root_node, "string")
        for node in string_nodes:
            text = parser.get_node_text(node, code_bytes).upper()
            if 'SELECT' in text and '*' in text and 'FROM' in text:
                line_num = code[:node.start_byte].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Overly broad data query",
                    description=f"SELECT * at line {line_num} retrieves unnecessary columns",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet_from_bytes(code, node.start_byte, node.end_byte),
                    remediation="Select only required columns (PL-2 data minimization)"
                ))
        
        # Check for .all() method calls (query.all(), objects.all())
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call")
        for call in call_nodes:
            call_text = parser.get_node_text(call, code_bytes)
            if '.all()' in call_text and ('query' in call_text or 'objects' in call_text):
                line_num = code[:call.start_byte].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data retrieval",
                    description=f"Retrieving all records at line {line_num} without filters",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet_from_bytes(code, call.start_byte, call.end_byte),
                    remediation="Add filters to minimize data exposure"
                ))
        
        # Check for PII field assignments in class definitions
        assignment_nodes = parser.find_nodes_by_type(tree.root_node, "assignment")
        pii_keywords = ['ssn', 'social_security', 'date_of_birth', 'dob', 'drivers_license', 'passport_number']
        
        for assign in assignment_nodes:
            assign_text = parser.get_node_text(assign, code_bytes).lower()
            if any(keyword in assign_text for keyword in pii_keywords):
                line_num = code[:assign.start_byte].count('\n') + 1
                
                # Check surrounding lines for justification comment
                context_start = max(0, assign.start_byte - 500)
                context_end = min(len(code_bytes), assign.end_byte + 500)
                context = code[context_start:context_end]
                
                has_justification = bool(re.search(r'#.*required|#.*necessary|#.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII collection",
                        description=f"PII field at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet_from_bytes(code, assign.start_byte, assign.end_byte),
                        remediation="Document necessity or remove field (SR-2, SR-3)"
                    ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback for Python analysis"""
        findings = []
        lines = code.split('\n')
        
        # Check for SELECT *
        if re.search(r'SELECT\s+\*\s+FROM', code, re.IGNORECASE):
            for match in re.finditer(r'SELECT\s+\*\s+FROM', code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Overly broad data query",
                    description=f"SELECT * at line {line_num} retrieves unnecessary columns",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Select only required columns (PL-2 data minimization)"
                ))
        
        # Check for .all() without filtering
        all_patterns = [
            r'\.query\.all\(\)',
            r'\.objects\.all\(\)',
            r'User\.query\.all\(',
        ]
        for pattern in all_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data retrieval",
                    description=f"Retrieving all records at line {line_num} without filters",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add filters to minimize data exposure"
                ))
        
        # Check for unnecessary PII fields in models
        pii_patterns = [
            r'ssn\s*=|social_security',
            r'date_of_birth|dob\s*=',
            r'drivers_license',
            r'passport_number',
        ]
        for pattern in pii_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                # Check if there's justification comment
                has_justification = bool(re.search(r'#.*required|#.*necessary|#.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII collection",
                        description=f"PII field at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Document necessity or remove field (SR-2, SR-3)"
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """C#: Overly broad queries, unnecessary PII"""
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        if tree:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based C# analysis"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Check for .ToList() method calls
        invocations = parser.find_nodes_by_type(tree.root_node, "invocation_expression")
        for invoc in invocations:
            invoc_text = parser.get_node_text(invoc, code_bytes)
            if '.ToList()' in invoc_text and '_context' in invoc_text and '.Where' not in invoc_text:
                line_num = code[:invoc.start_byte].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data retrieval",
                    description=f"ToList() at line {line_num} without Where clause",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet_from_bytes(code, invoc.start_byte, invoc.end_byte),
                    remediation="Add Where() filter to minimize data"
                ))
        
        # Check for PII properties in class declarations
        property_nodes = parser.find_nodes_by_type(tree.root_node, "property_declaration")
        pii_keywords = ['SocialSecurityNumber', 'DateOfBirth', 'DriversLicense', 'PassportNumber']
        
        for prop in property_nodes:
            prop_text = parser.get_node_text(prop, code_bytes)
            if any(keyword in prop_text for keyword in pii_keywords) and 'public' in prop_text:
                line_num = code[:prop.start_byte].count('\n') + 1
                
                # Check surrounding lines for justification comment
                context_start = max(0, prop.start_byte - 500)
                context_end = min(len(code_bytes), prop.end_byte + 500)
                context = code[context_start:context_end]
                
                has_justification = bool(re.search(r'//.*required|//.*necessary|///.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII property",
                        description=f"PII property at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet_from_bytes(code, prop.start_byte, prop.end_byte),
                        remediation="Document necessity or remove property"
                    ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback for C# analysis"""
        findings = []
        lines = code.split('\n')
        
        # Check for .ToList() without filtering
        if re.search(r'_context\.\w+\.ToList\(\)', code):
            for match in re.finditer(r'_context\.(\w+)\.ToList\(\)', code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data retrieval",
                    description=f"ToList() at line {line_num} without Where clause",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add Where() filter to minimize data"
                ))
        
        # Check for unnecessary PII properties
        pii_patterns = [
            r'public\s+\w+\s+SocialSecurityNumber',
            r'public\s+\w+\s+DateOfBirth',
            r'public\s+\w+\s+DriversLicense',
            r'public\s+\w+\s+PassportNumber',
        ]
        for pattern in pii_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                # Check for summary comment
                has_justification = bool(re.search(r'//.*required|//.*necessary|///.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII property",
                        description=f"PII property at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Document necessity or remove property"
                    ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Java: Overly broad queries, unnecessary PII"""
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        if tree:
            return self._analyze_java_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based Java analysis"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Check for findAll() method invocations
        method_invocations = parser.find_nodes_by_type(tree.root_node, "method_invocation")
        for invoc in method_invocations:
            invoc_text = parser.get_node_text(invoc, code_bytes)
            if '.findAll()' in invoc_text:
                line_num = code[:invoc.start_byte].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data retrieval",
                    description=f"findAll() at line {line_num} without pagination",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet_from_bytes(code, invoc.start_byte, invoc.end_byte),
                    remediation="Use Pageable or filtering to minimize data"
                ))
        
        # Check for PII field declarations
        field_declarations = parser.find_nodes_by_type(tree.root_node, "field_declaration")
        pii_keywords = ['socialSecurityNumber', 'dateOfBirth', 'driversLicense', 'passportNumber']
        
        for field in field_declarations:
            field_text = parser.get_node_text(field, code_bytes)
            if any(keyword in field_text for keyword in pii_keywords) and 'private' in field_text:
                line_num = code[:field.start_byte].count('\n') + 1
                
                # Check surrounding lines for justification comment
                context_start = max(0, field.start_byte - 500)
                context_end = min(len(code_bytes), field.end_byte + 500)
                context = code[context_start:context_end]
                
                has_justification = bool(re.search(r'//.*required|//.*necessary|/\*.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII field",
                        description=f"PII field at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet_from_bytes(code, field.start_byte, field.end_byte),
                        remediation="Document necessity or remove field"
                    ))
        
        return findings
    
    def _analyze_java_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback for Java analysis"""
        findings = []
        lines = code.split('\n')
        
        # Check for findAll() without pagination
        if re.search(r'\.findAll\(\)', code):
            for match in re.finditer(r'\.findAll\(\)', code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data retrieval",
                    description=f"findAll() at line {line_num} without pagination",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Use Pageable or filtering to minimize data"
                ))
        
        # Check for unnecessary PII fields
        pii_patterns = [
            r'private\s+\w+\s+socialSecurityNumber',
            r'private\s+\w+\s+dateOfBirth',
            r'private\s+\w+\s+driversLicense',
            r'private\s+\w+\s+passportNumber',
        ]
        for pattern in pii_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_justification = bool(re.search(r'//.*required|//.*necessary|/\*.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII field",
                        description=f"PII field at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Document necessity or remove field"
                    ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """TypeScript: Overly broad queries, unnecessary PII"""
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        if tree:
            findings = self._analyze_typescript_ast(code, file_path, parser, tree)
            # TypeScript AST doesn't parse interface properties correctly, so also run regex for PII detection
            pii_findings = self._analyze_typescript_pii_regex(code, file_path)
            findings.extend(pii_findings)
            return findings
        
        # Fallback to regex
        return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based TypeScript analysis"""
        findings = []
        code_bytes = code.encode('utf8')
        
        # Check for .find({}) calls
        call_nodes = parser.find_nodes_by_type(tree.root_node, "call_expression")
        for call in call_nodes:
            call_text = parser.get_node_text(call, code_bytes)
            # Only match if it contains .find({}) specifically, not just any call
            if '.find({})' in call_text and 'find' in call_text:
                line_num = code[:call.start_byte].count('\n') + 1
                # Skip if we already found this line (avoid duplicates from nested calls)
                if not any(f.line_number == line_num and f.title == "Unfiltered data query" for f in findings):
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unfiltered data query",
                        description=f"find() with empty object at line {line_num}",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet_from_bytes(code, call.start_byte, call.end_byte),
                        remediation="Add query filters to minimize data"
                    ))
        
        # Note: TypeScript AST doesn't parse interface properties correctly, use regex for PII detection
        return findings
    
    def _analyze_typescript_pii_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex-based PII detection for TypeScript (interfaces not parsed correctly by tree-sitter)"""
        findings = []
        lines = code.split('\n')
        
        # Check for unnecessary PII fields in interfaces/types
        pii_patterns = [
            r'socialSecurityNumber[?:]',
            r'dateOfBirth[?:]',
            r'driversLicense[?:]',
            r'passportNumber[?:]',
        ]
        for pattern in pii_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_justification = bool(re.search(r'//.*required|//.*necessary|/\*.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII field",
                        description=f"PII field at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Document necessity or remove field"
                    ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Regex fallback for TypeScript analysis"""
        findings = []
        lines = code.split('\n')
        
        # Check for .find() without filters
        if re.search(r'\.find\(\{\}\)', code):
            for match in re.finditer(r'\.find\(\{\}\)', code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Unfiltered data query",
                    description=f"find() with empty object at line {line_num}",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add query filters to minimize data"
                ))
        
        # Check for unnecessary PII fields in interfaces/types
        pii_patterns = [
            r'socialSecurityNumber[?:]',
            r'dateOfBirth[?:]',
            r'driversLicense[?:]',
            r'passportNumber[?:]',
        ]
        for pattern in pii_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                has_justification = bool(re.search(r'//.*required|//.*necessary|/\*.*compliance', context, re.IGNORECASE))
                if not has_justification:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Unnecessary PII field",
                        description=f"PII field at line {line_num} without justification",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Document necessity or remove field"
                    ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Bicep: Data retention policies, storage lifecycle"""
        # Note: Using regex - tree-sitter not available for Bicep
        findings = []
        lines = code.split('\n')
        
        # Check Storage accounts without lifecycle policies
        if re.search(r"Microsoft\.Storage/storageAccounts", code):
            has_lifecycle = bool(re.search(r"managementPolicies|lifecycleManagement", code))
            if not has_lifecycle:
                result = self._find_line(lines, 'Storage/storageAccounts')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Storage without lifecycle policy",
                    description="Storage account missing data retention policy",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add managementPolicies for data minimization (PL-4)"
                ))
        
        # Check databases without retention
        if re.search(r"Microsoft\.Sql/servers/databases", code):
            has_retention = bool(re.search(r"retentionDays|backupRetention", code))
            if not has_retention:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Database without retention policy",
                    description="SQL database missing retention configuration",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Database detected",
                    remediation="Configure retention policies for data minimization"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Terraform: Data retention policies"""
        # Note: Using regex - tree-sitter not available for Terraform
        findings = []
        lines = code.split('\n')
        
        # Check Storage without lifecycle
        if re.search(r'azurerm_storage_account', code):
            has_lifecycle = bool(re.search(r'azurerm_storage_management_policy|lifecycle_rule', code))
            if not has_lifecycle:
                result = self._find_line(lines, 'azurerm_storage_account')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Storage without lifecycle policy",
                    description="Storage account missing lifecycle management",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add lifecycle_rule for data retention"
                ))
        
        # Check databases without retention
        if re.search(r'azurerm_mssql_database|azurerm_postgresql', code):
            has_retention = bool(re.search(r'retention_days|backup_retention', code))
            if not has_retention:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Database without retention policy",
                    description="Database missing retention configuration",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="Database detected",
                    remediation="Configure retention policies"
                ))
        
        return findings
    

        """Find line number containing pattern"""
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 1

    def _get_code_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """Get code snippet around line"""
        if not lines or line_num < 1:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])

    def _get_snippet_from_bytes(self, code: str, start_byte: int, end_byte: int, context: int = 50) -> str:
        """Get code snippet from byte positions with context"""
        snippet_start = max(0, start_byte - context)
        snippet_end = min(len(code), end_byte + context)
        return code[snippet_start:snippet_end]

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Data Minimization",
            "evidence_type": "code-based",
            "automation_feasibility": "medium",
            "azure_services": ["Microsoft Purview", "Azure SQL Database", "Azure Policy", "GitHub Advanced Security", "Azure Monitor"],
            "collection_methods": [
                "Microsoft Purview Data Map to classify data assets and identify PII/sensitive data fields for minimization review",
                "Azure SQL Database dynamic data masking and column-level encryption to enforce data minimization controls",
                "Azure Policy to enforce data retention policies and prevent overly broad data queries",
                "GitHub Advanced Security CodeQL scanning to detect overly broad SQL queries, excessive data collection, and missing retention policies in code",
                "Azure Monitor to track data access patterns and alert on excessive data retrieval (e.g., SELECT * without filters)"
            ],
            "implementation_steps": [
                "1. Enable Microsoft Purview Data Map: (a) Scan all data sources (Azure SQL, Cosmos DB, Storage, Dataverse), (b) Auto-classify sensitive data (SSN, email, credit card) using built-in classifiers, (c) Generate data minimization report: Total fields, Sensitive fields, Justification for retention, (d) Flag unjustified sensitive data for review",
                "2. Enforce SQL data minimization controls: (a) Enable Azure SQL dynamic data masking for PII columns, (b) Implement column-level encryption for highly sensitive data, (c) Audit queries with SELECT * or missing WHERE clauses, (d) Require stored procedures with parameter validation to prevent overly broad queries",
                "3. Configure Azure Policy for retention: (a) Policy: Require data retention tags on storage accounts and databases, (b) Policy: Require lifecycle management policies for blobs (auto-delete after retention period), (c) Policy: Audit databases without data classification, (d) Generate monthly retention compliance report",
                "4. Enable GitHub Advanced Security CodeQL: (a) Scan for SQL injection and overly broad queries (SELECT * FROM users WHERE 1=1), (b) Detect excessive PII collection (>= 5 PII fields in single query), (c) Flag missing data retention policies in application code, (d) Require code review for queries accessing sensitive tables",
                "5. Track with Azure Monitor: (a) Log Analytics: Query for SELECT * patterns in SQL audit logs, (b) Alert on queries returning > 10,000 rows (potential excessive data retrieval), (c) Track data access frequency by user and application, (d) Generate monthly data access pattern report",
                "6. Generate quarterly evidence package: (a) Export Purview data classification report with sensitive data inventory, (b) Export Azure SQL masking/encryption configuration, (c) Export Policy retention compliance report, (d) Export GitHub CodeQL scan results for data minimization violations"
            ],
            "evidence_artifacts": [
                "Microsoft Purview Data Classification Report identifying PII/sensitive data with justification for retention",
                "Azure SQL Data Minimization Controls: Dynamic data masking and column-level encryption configurations",
                "Azure Policy Retention Compliance Report enforcing data retention tags and lifecycle management policies",
                "GitHub Advanced Security CodeQL Scan Results detecting overly broad queries and missing retention policies",
                "Azure Monitor Data Access Pattern Report tracking excessive data retrieval and SELECT * query usage"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Data Governance Team / Privacy Officer"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        return [
            {"query_type": "Microsoft Purview REST API", "query_name": "Data classification and sensitive data inventory", "query": "GET https://{purview-account}.purview.azure.com/catalog/api/atlas/v2/search/basic?query=*&classification=SensitiveData&limit=1000", "purpose": "Retrieve data classification report identifying PII/sensitive data fields for minimization review"},
            {"query_type": "Azure SQL REST API", "query_name": "Dynamic data masking configuration", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/dataMaskingPolicies/Default?api-version=2014-04-01", "purpose": "Retrieve dynamic data masking configuration showing PII columns protected by masking rules"},
            {"query_type": "Azure Policy REST API", "query_name": "Data retention policy compliance", "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/queryResults?api-version=2019-10-01&$filter=policyDefinitionName eq 'require-data-retention-tags'", "purpose": "Retrieve policy compliance for data retention tagging and lifecycle management requirements"},
            {"query_type": "GitHub REST API", "query_name": "CodeQL data minimization scan results", "query": "GET https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts?state=open&tool_name=CodeQL&query=overly-broad-sql-query OR excessive-pii-collection OR missing-retention-policy", "purpose": "Retrieve CodeQL scan results detecting overly broad queries, excessive PII collection, and missing retention policies"},
            {"query_type": "Azure Monitor KQL", "query_name": "Excessive data retrieval patterns", "query": "AzureDiagnostics\n| where Category == 'SQLSecurityAuditEvents'\n| where statement_s contains 'SELECT *' or statement_s !contains 'WHERE'\n| extend RowCount = toint(rows_affected_d)\n| where RowCount > 10000\n| summarize ExcessiveQueries = count(), TotalRows = sum(RowCount) by database_name_s, server_principal_name_s, bin(TimeGenerated, 1d)\n| extend AvgRowsPerQuery = round(TotalRows / ExcessiveQueries, 2)", "purpose": "Track queries with excessive data retrieval (> 10,000 rows) indicating potential data minimization violations"}
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        return [
            {"artifact_name": "Microsoft Purview Data Classification Report", "artifact_type": "Data Inventory with Sensitivity Classification", "description": "Complete data inventory showing PII/sensitive data fields with classification, retention justification, and minimization recommendations", "collection_method": "Microsoft Purview REST API to export data assets with SensitiveData classification", "storage_location": "Azure Storage Account with quarterly snapshots for data governance review"},
            {"artifact_name": "Azure SQL Data Minimization Controls", "artifact_type": "Database Protection Configuration", "description": "Dynamic data masking rules and column-level encryption for PII columns preventing excessive data exposure", "collection_method": "Azure SQL REST API to export dataMaskingPolicies and transparent data encryption settings", "storage_location": "Azure Storage Account with configuration baselines for compliance verification"},
            {"artifact_name": "Azure Policy Retention Compliance Report", "artifact_type": "Policy Compliance Report", "description": "Policy compliance for data retention tagging, lifecycle management, and data classification requirements (>= 95% target)", "collection_method": "Azure Policy REST API to retrieve policyStates for data retention policies", "storage_location": "Azure Storage Account with monthly compliance reports"},
            {"artifact_name": "GitHub CodeQL Data Minimization Scan", "artifact_type": "Code Security Scan Results", "description": "CodeQL scan results detecting overly broad SQL queries, excessive PII collection (>= 5 fields), and missing retention policies in code", "collection_method": "GitHub REST API to export code-scanning alerts for data minimization violations", "storage_location": "GitHub Security tab with historical scan results and remediation tracking"},
            {"artifact_name": "Azure Monitor Data Access Pattern Report", "artifact_type": "Data Access Audit Report", "description": "Report tracking excessive data retrieval patterns: SELECT * queries, queries without WHERE clauses, queries returning > 10,000 rows", "collection_method": "Azure Monitor KQL query analyzing SQL audit logs for excessive data retrieval", "storage_location": "Azure Log Analytics workspace with monthly access pattern summaries"}
        ]

