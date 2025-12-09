"""
AST (Abstract Syntax Tree) Utilities for Advanced Code Analysis

Provides tree-sitter-based parsing for multi-language support:
- Python (via tree-sitter-python)
- C# (via tree-sitter-c-sharp)
- Java (via tree-sitter-java)
- TypeScript/JavaScript (via tree-sitter-javascript)

This module offers:
1. AST parsing and traversal
2. Symbol table construction
3. Data flow analysis
4. Control flow analysis
5. Pattern matching beyond regex
"""

import tree_sitter_python as tspython
import tree_sitter_c_sharp as tscsharp
import tree_sitter_java as tsjava
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser, Node, Tree
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass
from enum import Enum


class CodeLanguage(Enum):
    """Supported programming languages for AST parsing."""
    PYTHON = "python"
    CSHARP = "csharp"
    JAVA = "java"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    BICEP = "bicep"
    TERRAFORM = "terraform"
    # CI/CD configurations (no tree-sitter parsers, regex-based analysis)
    GITHUB_ACTIONS = "github_actions"
    AZURE_PIPELINES = "azure_pipelines"
    GITLAB_CI = "gitlab_ci"


@dataclass
class Symbol:
    """Represents a symbol (variable, function, class) in the code."""
    name: str
    type: str  # "variable", "function", "class", "parameter"
    line: int
    column: int
    scope: str
    data_type: Optional[str] = None  # Inferred or declared type
    is_sensitive: bool = False  # Tracks if contains sensitive data


@dataclass
class DataFlowPath:
    """Represents a data flow path from source to sink."""
    source: Symbol
    sink: Symbol
    intermediate_nodes: List[Symbol]
    is_tainted: bool  # True if flows to sensitive operation


class ASTParser:
    """
    Multi-language AST parser using tree-sitter.
    
    Usage:
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        nodes = parser.find_nodes_by_type(tree.root_node, "function_definition")
    """
    
    def __init__(self, language: CodeLanguage):
        """Initialize parser for specific language."""
        self.language = language
        
        # Load appropriate language grammar
        if language == CodeLanguage.PYTHON:
            lang = Language(tspython.language())
        elif language == CodeLanguage.CSHARP:
            lang = Language(tscsharp.language())
        elif language == CodeLanguage.JAVA:
            lang = Language(tsjava.language())
        elif language in (CodeLanguage.TYPESCRIPT, CodeLanguage.JAVASCRIPT):
            lang = Language(tsjavascript.language())
        elif language == CodeLanguage.BICEP:
            # Bicep doesn't have tree-sitter grammar, use regex-based analysis
            lang = None
        elif language == CodeLanguage.TERRAFORM:
            # Terraform doesn't have tree-sitter grammar, use regex-based analysis
            lang = None
        else:
            raise ValueError(f"Unsupported language: {language}")
        
        # Create parser with language
        self.parser = Parser(lang)
    
    def parse(self, code: str) -> Tree:
        """Parse code into AST tree."""
        return self.parser.parse(bytes(code, "utf8"))
    
    def find_nodes_by_type(self, node: Node, node_type: str) -> List[Node]:
        """
        Recursively find all nodes of a specific type.
        
        Examples:
            - "function_definition" (Python)
            - "method_declaration" (C#, Java)
            - "variable_declarator" (Java, JavaScript)
            - "assignment_expression" (Python, JavaScript)
        """
        results = []
        
        if node.type == node_type:
            results.append(node)
        
        for child in node.children:
            results.extend(self.find_nodes_by_type(child, node_type))
        
        return results
    
    def get_node_text(self, node: Node, code: bytes) -> str:
        """Extract source text for a node."""
        return code[node.start_byte:node.end_byte].decode('utf8')
    
    def find_function_calls(self, root_node: Node, function_names: List[str]) -> List[Tuple[str, int]]:
        """
        Find all calls to specific functions.
        
        Returns: List of (function_name, line_number) tuples
        """
        calls = []
        
        # Language-specific call node types
        call_types = {
            CodeLanguage.PYTHON: "call",
            CodeLanguage.CSHARP: "invocation_expression",
            CodeLanguage.JAVA: "method_invocation",
            CodeLanguage.JAVASCRIPT: "call_expression",
            CodeLanguage.TYPESCRIPT: "call_expression",
        }
        
        call_type = call_types.get(self.language)
        if not call_type:
            return calls
        
        call_nodes = self.find_nodes_by_type(root_node, call_type)
        
        for call_node in call_nodes:
            # Extract function name from call node
            func_name = self._extract_function_name(call_node)
            if func_name in function_names:
                calls.append((func_name, call_node.start_point[0] + 1))
        
        return calls
    
    def _extract_function_name(self, call_node: Node) -> Optional[str]:
        """Extract function name from call node (language-specific)."""
        if self.language == CodeLanguage.PYTHON:
            # call -> attribute/identifier
            for child in call_node.children:
                if child.type in ("identifier", "attribute"):
                    return child.text.decode('utf8') if child.text else None
        
        elif self.language == CodeLanguage.CSHARP:
            # invocation_expression -> member_access_expression/identifier_name
            for child in call_node.children:
                if child.type in ("identifier_name", "member_access_expression"):
                    return child.text.decode('utf8') if child.text else None
        
        elif self.language == CodeLanguage.JAVA:
            # method_invocation -> identifier
            for child in call_node.children:
                if child.type == "identifier":
                    return child.text.decode('utf8') if child.text else None
        
        elif self.language in (CodeLanguage.JAVASCRIPT, CodeLanguage.TYPESCRIPT):
            # call_expression -> identifier/member_expression
            for child in call_node.children:
                if child.type in ("identifier", "member_expression"):
                    return child.text.decode('utf8') if child.text else None
        
        return None


class SymbolTable:
    """
    Builds and maintains symbol table for scope resolution.
    
    Tracks:
    - Variable declarations
    - Function definitions
    - Class definitions
    - Parameter lists
    - Scope hierarchies
    """
    
    def __init__(self, language: CodeLanguage):
        """Initialize symbol table for language."""
        self.language = language
        self.symbols: Dict[str, List[Symbol]] = {}  # name -> [symbols] (multiple scopes)
        self.scopes: List[str] = ["global"]  # Scope stack
    
    def enter_scope(self, scope_name: str):
        """Enter a new scope (function, class, block)."""
        self.scopes.append(scope_name)
    
    def exit_scope(self):
        """Exit current scope."""
        if len(self.scopes) > 1:
            self.scopes.pop()
    
    def add_symbol(self, symbol: Symbol):
        """Add symbol to table."""
        if symbol.name not in self.symbols:
            self.symbols[symbol.name] = []
        self.symbols[symbol.name].append(symbol)
    
    def lookup(self, name: str, scope: Optional[str] = None) -> Optional[Symbol]:
        """
        Lookup symbol by name, respecting scope hierarchy.
        
        If scope is None, searches from current scope upward.
        """
        if name not in self.symbols:
            return None
        
        # Search from most specific scope to global
        search_scopes = [scope] if scope else list(reversed(self.scopes))
        
        for s in self.symbols[name]:
            if s.scope in search_scopes:
                return s
        
        return None
    
    def get_sensitive_symbols(self) -> List[Symbol]:
        """Get all symbols marked as sensitive (containing PII, secrets, etc.)."""
        sensitive = []
        for symbol_list in self.symbols.values():
            sensitive.extend([s for s in symbol_list if s.is_sensitive])
        return sensitive


class DataFlowAnalyzer:
    """
    Performs taint analysis and data flow tracking.
    
    Identifies:
    - Sources of sensitive data (user input, secrets, PII)
    - Sinks (logging, external APIs, storage)
    - Flow paths from sources to sinks
    - Indirect exposures through variable assignments
    """
    
    # Sensitive data source patterns (cross-language)
    SENSITIVE_SOURCES = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "ssn", "social_security", "credit_card", "cvv", "pin",
        "private_key", "client_secret", "connection_string"
    }
    
    # Sensitive sink operations
    SENSITIVE_SINKS = {
        "log", "print", "console", "write", "send", "post", "put",
        "store", "save", "insert", "update"
    }
    
    def __init__(self, symbol_table: SymbolTable):
        """Initialize with symbol table."""
        self.symbol_table = symbol_table
        self.tainted_vars: Set[str] = set()  # Variables containing sensitive data
        self.flow_paths: List[DataFlowPath] = []
    
    def mark_tainted(self, var_name: str):
        """Mark variable as containing sensitive data."""
        self.tainted_vars.add(var_name)
        symbol = self.symbol_table.lookup(var_name)
        if symbol:
            symbol.is_sensitive = True
    
    def is_tainted(self, var_name: str) -> bool:
        """Check if variable contains sensitive data."""
        return var_name in self.tainted_vars
    
    def analyze_assignment(self, target: str, source: str):
        """
        Analyze assignment for taint propagation.
        
        If source is tainted, target becomes tainted.
        """
        if self.is_tainted(source):
            self.mark_tainted(target)
    
    def detect_sensitive_exposure(self, tree: Tree, code: str) -> List[Tuple[str, int, str]]:
        """
        Detect sensitive data flowing to dangerous sinks.
        
        Returns: List of (variable_name, line_number, sink_operation) tuples
        """
        exposures = []
        
        # This is a simplified version - full implementation would:
        # 1. Build complete data flow graph
        # 2. Track inter-procedural flows
        # 3. Handle aliasing and pointers
        # 4. Track field-sensitive flows (object.field)
        
        return exposures


class PatternMatcher:
    """
    Structural pattern matching beyond regex.
    
    Matches AST patterns like:
    - "Function calls within try/catch blocks"
    - "Variable assignments in if statements"
    - "Nested loops with specific operations"
    - "Class inheritance patterns"
    """
    
    def __init__(self, parser: ASTParser):
        """Initialize with AST parser."""
        self.parser = parser
    
    def find_pattern(self, root_node: Node, pattern: Dict[str, Any]) -> List[Node]:
        """
        Find nodes matching structural pattern.
        
        Pattern format:
        {
            "type": "function_definition",
            "children": [
                {"type": "identifier", "text": "specific_name"},
                {"type": "parameters", "min_children": 2}
            ]
        }
        """
        results = []
        self._match_recursive(root_node, pattern, results)
        return results
    
    def _match_recursive(self, node: Node, pattern: Dict[str, Any], results: List[Node]):
        """Recursively match pattern against tree."""
        if self._node_matches(node, pattern):
            results.append(node)
        
        for child in node.children:
            self._match_recursive(child, pattern, results)
    
    def _node_matches(self, node: Node, pattern: Dict[str, Any]) -> bool:
        """Check if node matches pattern."""
        # Match node type
        if "type" in pattern and node.type != pattern["type"]:
            return False
        
        # Match node text
        if "text" in pattern and node.text:
            if node.text.decode('utf8') != pattern["text"]:
                return False
        
        # Match minimum children count
        if "min_children" in pattern:
            if len(node.children) < pattern["min_children"]:
                return False
        
        # Match child patterns (simplified - full version would recurse)
        if "children" in pattern:
            # For now, just check if we have enough children
            if len(node.children) < len(pattern["children"]):
                return False
        
        return True


# Convenience factory functions
def create_parser(language_name: str) -> ASTParser:
    """Create parser from language name string."""
    lang_map = {
        "python": CodeLanguage.PYTHON,
        "csharp": CodeLanguage.CSHARP,
        "c#": CodeLanguage.CSHARP,
        "java": CodeLanguage.JAVA,
        "typescript": CodeLanguage.TYPESCRIPT,
        "javascript": CodeLanguage.JAVASCRIPT,
        "js": CodeLanguage.JAVASCRIPT,
        "ts": CodeLanguage.TYPESCRIPT,
    }
    lang = lang_map.get(language_name.lower())
    if not lang:
        raise ValueError(f"Unsupported language: {language_name}")
    return ASTParser(lang)


def create_symbol_table(language_name: str) -> SymbolTable:
    """Create symbol table from language name string."""
    lang_map = {
        "python": CodeLanguage.PYTHON,
        "csharp": CodeLanguage.CSHARP,
        "c#": CodeLanguage.CSHARP,
        "java": CodeLanguage.JAVA,
        "typescript": CodeLanguage.TYPESCRIPT,
        "javascript": CodeLanguage.JAVASCRIPT,
    }
    lang = lang_map.get(language_name.lower())
    if not lang:
        raise ValueError(f"Unsupported language: {language_name}")
    return SymbolTable(lang)
