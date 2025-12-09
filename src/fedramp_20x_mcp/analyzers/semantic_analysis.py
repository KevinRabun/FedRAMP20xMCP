"""
Semantic Analysis Module for Advanced Code Analysis.

Goes beyond syntactic AST analysis to understand:
1. Type inference and tracking
2. Control flow analysis
3. Inter-procedural data flow
4. Security-relevant semantic patterns
5. Framework-specific behaviors
"""

from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from .ast_utils import ASTParser, SymbolTable, Symbol, DataFlowAnalyzer, CodeLanguage
from tree_sitter import Node


class SecurityContext(Enum):
    """Security contexts for data classification."""
    PUBLIC = "public"  # No sensitivity
    INTERNAL = "internal"  # Internal use only
    CONFIDENTIAL = "confidential"  # Sensitive data
    SECRET = "secret"  # Credentials, keys
    PII = "pii"  # Personal identifiable information


@dataclass
class TypeInfo:
    """Type information for variables and expressions."""
    name: str
    base_type: str  # "str", "int", "dict", "User", etc.
    is_nullable: bool = False
    is_collection: bool = False
    element_type: Optional[str] = None  # For collections
    security_context: SecurityContext = SecurityContext.PUBLIC
    

@dataclass
class ControlFlowNode:
    """Node in control flow graph."""
    node_id: int
    node_type: str  # "entry", "exit", "statement", "branch", "loop"
    ast_node: Optional[Node] = None
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)


@dataclass
class Function:
    """Function/method metadata."""
    name: str
    parameters: List[Tuple[str, Optional[TypeInfo]]]  # (name, type)
    return_type: Optional[TypeInfo] = None
    is_sensitive: bool = False  # Returns/handles sensitive data
    calls: Set[str] = field(default_factory=set)  # Functions called
    modifies: Set[str] = field(default_factory=set)  # Global vars modified
    line_number: int = 0


class SemanticAnalyzer:
    """
    Performs semantic analysis on code.
    
    Capabilities:
    1. Type inference across assignments
    2. Control flow graph construction
    3. Inter-procedural analysis
    4. Security context propagation
    5. Framework pattern recognition
    """
    
    def __init__(self, language: CodeLanguage):
        """Initialize semantic analyzer for language."""
        self.language = language
        self.parser = ASTParser(language)
        self.symbol_table = SymbolTable(language)
        self.type_info: Dict[str, TypeInfo] = {}
        self.functions: Dict[str, Function] = {}
        self.control_flow: Dict[str, List[ControlFlowNode]] = {}  # func_name -> CFG
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """
        Perform complete semantic analysis.
        
        Returns dict with:
        - types: Type information for all symbols
        - functions: Function metadata and call graph
        - control_flow: Control flow graphs per function
        - sensitive_flows: Data flows involving sensitive data
        """
        tree = self.parser.parse(code)
        code_bytes = bytes(code, "utf8")
        
        # Phase 1: Build symbol table and extract functions
        self._extract_functions(tree.root_node, code_bytes)
        
        # Phase 2: Infer types
        self._infer_types(tree.root_node, code_bytes)
        
        # Phase 3: Build control flow graphs
        for func_name in self.functions.keys():
            self._build_cfg(func_name, tree.root_node, code_bytes)
        
        # Phase 4: Analyze data flows
        sensitive_flows = self._analyze_sensitive_flows(tree.root_node, code_bytes)
        
        return {
            "types": self.type_info,
            "functions": self.functions,
            "control_flow": self.control_flow,
            "sensitive_flows": sensitive_flows
        }
    
    def _extract_functions(self, root_node: Node, code_bytes: bytes):
        """Extract all function/method definitions."""
        # Language-specific function node types
        func_types = {
            CodeLanguage.PYTHON: "function_definition",
            CodeLanguage.CSHARP: "method_declaration",
            CodeLanguage.JAVA: "method_declaration",
            CodeLanguage.JAVASCRIPT: "function_declaration",
            CodeLanguage.TYPESCRIPT: "function_declaration",
        }
        
        func_type = func_types.get(self.language)
        if not func_type:
            return
        
        func_nodes = self.parser.find_nodes_by_type(root_node, func_type)
        
        for func_node in func_nodes:
            func_name = self._extract_function_name(func_node, code_bytes)
            if not func_name:
                continue
            
            params = self._extract_parameters(func_node, code_bytes)
            
            self.functions[func_name] = Function(
                name=func_name,
                parameters=params,
                line_number=func_node.start_point[0] + 1
            )
    
    def _extract_function_name(self, func_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract function name from function definition node."""
        for child in func_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _extract_parameters(self, func_node: Node, code_bytes: bytes) -> List[Tuple[str, Optional[TypeInfo]]]:
        """Extract function parameters with type hints if available."""
        params = []
        
        # Find parameters/parameter_list node
        for child in func_node.children:
            if "parameter" in child.type:
                # Extract parameter names
                for param_node in child.children:
                    if param_node.type == "identifier":
                        param_name = self.parser.get_node_text(param_node, code_bytes)
                        params.append((param_name, None))  # Type inference comes later
        
        return params
    
    def _infer_types(self, root_node: Node, code_bytes: bytes):
        """
        Infer types for variables through assignments.
        
        Simple inference:
        - String literals -> str
        - Numeric literals -> int/float
        - Function calls -> return type if known
        - Assignments propagate types
        """
        assignments = self.parser.find_nodes_by_type(root_node, "assignment")
        
        for assignment in assignments:
            target_name = None
            value_type = None
            
            # Extract target and infer type from value
            for child in assignment.children:
                if child.type == "identifier" and target_name is None:
                    target_name = self.parser.get_node_text(child, code_bytes)
                elif child.type == "string":
                    value_type = "str"
                elif child.type == "integer":
                    value_type = "int"
                elif child.type == "float":
                    value_type = "float"
                elif child.type == "call":
                    # Try to infer from function return type
                    func_name = self._extract_call_name(child, code_bytes)
                    if func_name and func_name in self.functions:
                        ret_type = self.functions[func_name].return_type
                        value_type = ret_type.base_type if ret_type else "unknown"
            
            if target_name and value_type:
                # Check if variable name suggests sensitive data
                security_ctx = self._infer_security_context(target_name)
                
                self.type_info[target_name] = TypeInfo(
                    name=target_name,
                    base_type=value_type,
                    security_context=security_ctx
                )
    
    def _infer_security_context(self, var_name: str) -> SecurityContext:
        """Infer security context from variable name."""
        name_lower = var_name.lower()
        
        # Secret/credential patterns
        secret_patterns = ["password", "passwd", "pwd", "secret", "token", "key", "credential"]
        if any(pattern in name_lower for pattern in secret_patterns):
            return SecurityContext.SECRET
        
        # PII patterns
        pii_patterns = ["ssn", "social_security", "email", "phone", "address", "name", "dob"]
        if any(pattern in name_lower for pattern in pii_patterns):
            return SecurityContext.PII
        
        # Confidential patterns
        conf_patterns = ["internal", "confidential", "private"]
        if any(pattern in name_lower for pattern in conf_patterns):
            return SecurityContext.CONFIDENTIAL
        
        return SecurityContext.PUBLIC
    
    def _extract_call_name(self, call_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract function name from call expression."""
        for child in call_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _build_cfg(self, func_name: str, root_node: Node, code_bytes: bytes):
        """Build control flow graph for function."""
        # Simplified CFG construction
        # Full implementation would handle:
        # - Branches (if/else)
        # - Loops (for/while)
        # - Try/except
        # - Returns
        # - Gotos (in C#)
        
        self.control_flow[func_name] = []
        
        # For now, create linear CFG
        entry = ControlFlowNode(0, "entry")
        exit_node = ControlFlowNode(1, "exit")
        
        entry.successors.append(exit_node.node_id)
        exit_node.predecessors.append(entry.node_id)
        
        self.control_flow[func_name] = [entry, exit_node]
    
    def _analyze_sensitive_flows(self, root_node: Node, code_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Analyze flows of sensitive data.
        
        Tracks:
        - Sensitive variable assignments
        - Sensitive data passed to functions
        - Sensitive data in return statements
        - Sensitive data in logging/output
        """
        flows = []
        
        # Find all assignments involving sensitive variables
        assignments = self.parser.find_nodes_by_type(root_node, "assignment")
        
        for assignment in assignments:
            target_name = None
            source_name = None
            
            # Extract target and source
            identifiers = [child for child in assignment.children if child.type == "identifier"]
            if len(identifiers) >= 2:
                target_name = self.parser.get_node_text(identifiers[0], code_bytes)
                source_name = self.parser.get_node_text(identifiers[1], code_bytes)
            elif len(identifiers) == 1:
                target_name = self.parser.get_node_text(identifiers[0], code_bytes)
            
            # Check if source is sensitive
            if source_name and source_name in self.type_info:
                source_type = self.type_info[source_name]
                if source_type.security_context in (SecurityContext.SECRET, SecurityContext.PII):
                    flows.append({
                        "type": "assignment",
                        "source": source_name,
                        "target": target_name,
                        "security_context": source_type.security_context.value,
                        "line": assignment.start_point[0] + 1
                    })
                    
                    # Propagate security context to target
                    if target_name and target_name not in self.type_info:
                        self.type_info[target_name] = TypeInfo(
                            name=target_name,
                            base_type=source_type.base_type,
                            security_context=source_type.security_context
                        )
        
        return flows
    
    def get_function_call_graph(self) -> Dict[str, Set[str]]:
        """
        Build function call graph.
        
        Returns: Dict mapping function name to set of functions it calls.
        """
        call_graph = {}
        
        for func_name, func_info in self.functions.items():
            call_graph[func_name] = func_info.calls
        
        return call_graph
    
    def find_sensitive_sinks(self, root_node: Node, code_bytes: bytes) -> List[Dict[str, Any]]:
        """
        Find sensitive data flowing to dangerous sinks.
        
        Sinks:
        - Logging functions (print, log, console)
        - External APIs (post, send, put)
        - File operations (write, save)
        - Database operations (insert, update)
        """
        sinks = []
        
        # Dangerous sink function names
        sink_functions = {
            "print", "log", "console.log", "logger.info", "logger.debug",
            "post", "send", "put", "requests.post",
            "write", "save", "insert", "update"
        }
        
        # Find all function calls
        calls = self.parser.find_nodes_by_type(root_node, "call")
        
        for call in calls:
            func_name = self._extract_call_name(call, code_bytes)
            
            if func_name in sink_functions:
                # Check if arguments contain sensitive variables
                for child in call.children:
                    if child.type == "identifier":
                        arg_name = self.parser.get_node_text(child, code_bytes)
                        if arg_name in self.type_info:
                            arg_type = self.type_info[arg_name]
                            if arg_type.security_context in (SecurityContext.SECRET, SecurityContext.PII):
                                sinks.append({
                                    "function": func_name,
                                    "variable": arg_name,
                                    "security_context": arg_type.security_context.value,
                                    "line": call.start_point[0] + 1
                                })
        
        return sinks


class FrameworkAnalyzer:
    """
    Framework-specific semantic analysis.
    
    Recognizes and analyzes patterns from:
    - Flask/Django (Python)
    - ASP.NET Core (C#)
    - Spring Boot (Java)
    - Express/NestJS (TypeScript)
    """
    
    def __init__(self, language: CodeLanguage):
        self.language = language
        self.detected_frameworks: Set[str] = set()
    
    def detect_frameworks(self, code: str) -> Set[str]:
        """Detect which frameworks are used in code."""
        frameworks = set()
        
        # Python frameworks
        if "from flask import" in code or "import flask" in code:
            frameworks.add("Flask")
        if "from django" in code or "import django" in code:
            frameworks.add("Django")
        if "from fastapi import" in code or "import fastapi" in code:
            frameworks.add("FastAPI")
        
        # .NET frameworks
        if "using Microsoft.AspNetCore" in code:
            frameworks.add("ASP.NET Core")
        if "using Microsoft.EntityFrameworkCore" in code:
            frameworks.add("Entity Framework Core")
        
        # Java frameworks
        if "import org.springframework" in code:
            frameworks.add("Spring Boot")
        
        # JavaScript/TypeScript frameworks
        if "from 'express'" in code or 'from "express"' in code:
            frameworks.add("Express")
        if "from '@nestjs" in code:
            frameworks.add("NestJS")
        
        self.detected_frameworks = frameworks
        return frameworks
    
    def analyze_framework_patterns(self, code: str, framework: str) -> List[Dict[str, Any]]:
        """
        Analyze framework-specific security patterns.
        
        Returns list of findings specific to framework.
        """
        findings = []
        
        if framework == "Flask":
            findings.extend(self._analyze_flask(code))
        elif framework == "Django":
            findings.extend(self._analyze_django(code))
        elif framework == "ASP.NET Core":
            findings.extend(self._analyze_aspnet(code))
        elif framework == "Spring Boot":
            findings.extend(self._analyze_spring(code))
        
        return findings
    
    def _analyze_flask(self, code: str) -> List[Dict[str, Any]]:
        """Analyze Flask-specific patterns."""
        findings = []
        
        # Check for debug mode in production
        if "app.run(debug=True)" in code or "app.debug = True" in code:
            findings.append({
                "type": "flask_debug_enabled",
                "severity": "HIGH",
                "message": "Flask debug mode enabled - exposes sensitive debugging information"
            })
        
        # Check for secret key configuration
        if "app.secret_key = " in code and '"' in code:
            findings.append({
                "type": "flask_hardcoded_secret_key",
                "severity": "CRITICAL",
                "message": "Flask secret_key is hardcoded"
            })
        
        return findings
    
    def _analyze_django(self, code: str) -> List[Dict[str, Any]]:
        """Analyze Django-specific patterns."""
        findings = []
        
        # Check for DEBUG = True in settings
        if "DEBUG = True" in code:
            findings.append({
                "type": "django_debug_enabled",
                "severity": "HIGH",
                "message": "Django DEBUG=True in settings - should be False in production"
            })
        
        # Check for ALLOWED_HOSTS = []
        if "ALLOWED_HOSTS = []" in code:
            findings.append({
                "type": "django_empty_allowed_hosts",
                "severity": "HIGH",
                "message": "Django ALLOWED_HOSTS is empty - allows any host"
            })
        
        return findings
    
    def _analyze_aspnet(self, code: str) -> List[Dict[str, Any]]:
        """Analyze ASP.NET Core-specific patterns."""
        findings = []
        
        # Check for missing HTTPS redirection
        if "app.UseHttpsRedirection()" not in code and "app.Run(" in code:
            findings.append({
                "type": "aspnet_missing_https_redirect",
                "severity": "MEDIUM",
                "message": "Missing app.UseHttpsRedirection() in ASP.NET Core startup"
            })
        
        return findings
    
    def _analyze_spring(self, code: str) -> List[Dict[str, Any]]:
        """Analyze Spring Boot-specific patterns."""
        findings = []
        
        # Check for @CrossOrigin without restrictions
        if "@CrossOrigin" in code and "origins" not in code:
            findings.append({
                "type": "spring_unrestricted_cors",
                "severity": "MEDIUM",
                "message": "@CrossOrigin without origin restrictions - allows all origins"
            })
        
        return findings
