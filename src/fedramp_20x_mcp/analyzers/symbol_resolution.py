"""
Symbol Resolution Module.

Resolves symbols across files and modules:
1. Import statement tracking
2. Cross-file symbol lookup
3. Class inheritance hierarchies
4. Method override detection
5. Polymorphism handling
6. Module dependency graph
"""

from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path
from .ast_utils import ASTParser, CodeLanguage
from tree_sitter import Node
import re


@dataclass
class ImportStatement:
    """Represents an import statement."""
    module: str  # Module/package being imported
    imported_names: List[str]  # Specific names imported (empty for 'import x')
    alias: Optional[str] = None  # Alias if any ('import x as y')
    source_file: str = ""  # File containing the import
    line_number: int = 0


@dataclass
class ClassDefinition:
    """Represents a class definition."""
    name: str
    base_classes: List[str]  # Parent classes
    methods: Dict[str, 'MethodDefinition'] = field(default_factory=dict)
    fields: Set[str] = field(default_factory=set)
    source_file: str = ""
    line_number: int = 0


@dataclass
class MethodDefinition:
    """Represents a method definition."""
    name: str
    parameters: List[str]
    class_name: str  # Class containing this method
    is_override: bool = False
    overrides: Optional[str] = None  # Name of base class method being overridden
    source_file: str = ""
    line_number: int = 0


@dataclass
class ModuleInfo:
    """Information about a module/file."""
    path: str
    imports: List[ImportStatement] = field(default_factory=list)
    classes: Dict[str, ClassDefinition] = field(default_factory=dict)
    functions: Set[str] = field(default_factory=set)
    exports: Set[str] = field(default_factory=set)  # Public API


class SymbolResolver:
    """
    Resolves symbols across files and modules.
    
    Capabilities:
    - Track imports and build dependency graph
    - Resolve imported symbols to definitions
    - Build class hierarchy (inheritance)
    - Detect method overrides
    - Handle polymorphic calls
    """
    
    def __init__(self, language: CodeLanguage):
        """Initialize symbol resolver."""
        self.language = language
        self.parser = ASTParser(language)
        self.modules: Dict[str, ModuleInfo] = {}  # path -> ModuleInfo
        self.class_hierarchy: Dict[str, Set[str]] = {}  # class -> parents
        self.reverse_hierarchy: Dict[str, Set[str]] = {}  # class -> children
        self.symbol_definitions: Dict[str, List[str]] = {}  # symbol -> [files]
    
    def analyze_project(self, file_paths: List[str]) -> Dict[str, Any]:
        """
        Analyze entire project for symbol resolution.
        
        Args:
            file_paths: List of source file paths to analyze
        
        Returns:
            Dictionary with modules, imports, class_hierarchy, method_overrides
        """
        # Phase 1: Parse all files and extract module info
        for file_path in file_paths:
            self._analyze_file(file_path)
        
        # Phase 2: Build class hierarchy
        self._build_class_hierarchy()
        
        # Phase 3: Detect method overrides
        overrides = self._detect_method_overrides()
        
        # Phase 4: Build dependency graph
        dep_graph = self._build_dependency_graph()
        
        return {
            "modules": self.modules,
            "class_hierarchy": self.class_hierarchy,
            "method_overrides": overrides,
            "dependency_graph": dep_graph,
            "symbol_definitions": self.symbol_definitions
        }
    
    def _analyze_file(self, file_path: str):
        """Analyze single file and extract symbols."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
        except Exception as e:
            print(f"Warning: Could not read {file_path}: {e}")
            return
        
        tree = self.parser.parse(code)
        code_bytes = bytes(code, "utf8")
        
        module_info = ModuleInfo(path=file_path)
        
        # Extract imports
        module_info.imports = self._extract_imports(tree.root_node, code_bytes, file_path)
        
        # Extract classes
        module_info.classes = self._extract_classes(tree.root_node, code_bytes, file_path)
        
        # Extract top-level functions
        module_info.functions = self._extract_functions(tree.root_node, code_bytes)
        
        # Register symbol definitions
        for class_name in module_info.classes:
            self._register_symbol(class_name, file_path)
        
        for func_name in module_info.functions:
            self._register_symbol(func_name, file_path)
        
        self.modules[file_path] = module_info
    
    def _extract_imports(self, root_node: Node, code_bytes: bytes, file_path: str) -> List[ImportStatement]:
        """Extract import statements from AST."""
        imports = []
        
        if self.language == CodeLanguage.PYTHON:
            # Handle 'import x' and 'from x import y'
            import_nodes = self.parser.find_nodes_by_type(root_node, "import_statement")
            from_import_nodes = self.parser.find_nodes_by_type(root_node, "import_from_statement")
            
            for node in import_nodes:
                module_name = self.parser.get_node_text(node, code_bytes)
                imports.append(ImportStatement(
                    module=module_name.replace("import ", "").strip(),
                    imported_names=[],
                    source_file=file_path,
                    line_number=node.start_point[0] + 1
                ))
            
            for node in from_import_nodes:
                text = self.parser.get_node_text(node, code_bytes)
                # Parse "from x import y, z"
                match = re.match(r'from\s+([\w.]+)\s+import\s+(.*)', text)
                if match:
                    module = match.group(1)
                    names = [n.strip() for n in match.group(2).split(',')]
                    imports.append(ImportStatement(
                        module=module,
                        imported_names=names,
                        source_file=file_path,
                        line_number=node.start_point[0] + 1
                    ))
        
        elif self.language == CodeLanguage.JAVA:
            # Handle Java imports
            import_nodes = self.parser.find_nodes_by_type(root_node, "import_declaration")
            for node in import_nodes:
                text = self.parser.get_node_text(node, code_bytes)
                # Remove 'import' and ';'
                module_name = text.replace("import", "").replace(";", "").strip()
                imports.append(ImportStatement(
                    module=module_name,
                    imported_names=[],
                    source_file=file_path,
                    line_number=node.start_point[0] + 1
                ))
        
        elif self.language in (CodeLanguage.JAVASCRIPT, CodeLanguage.TYPESCRIPT):
            # Handle ES6 imports
            import_nodes = self.parser.find_nodes_by_type(root_node, "import_statement")
            for node in import_nodes:
                text = self.parser.get_node_text(node, code_bytes)
                # Parse "import { x, y } from 'module'"
                match = re.match(r'import\s+(?:{([^}]+)}|(\w+))\s+from\s+["\']([^"\']+)["\']', text)
                if match:
                    if match.group(1):  # Named imports
                        names = [n.strip() for n in match.group(1).split(',')]
                    else:  # Default import
                        names = [match.group(2)]
                    module = match.group(3)
                    imports.append(ImportStatement(
                        module=module,
                        imported_names=names,
                        source_file=file_path,
                        line_number=node.start_point[0] + 1
                    ))
        
        return imports
    
    def _extract_classes(self, root_node: Node, code_bytes: bytes, file_path: str) -> Dict[str, ClassDefinition]:
        """Extract class definitions from AST."""
        classes = {}
        
        class_types = {
            CodeLanguage.PYTHON: "class_definition",
            CodeLanguage.JAVA: "class_declaration",
            CodeLanguage.CSHARP: "class_declaration",
            CodeLanguage.JAVASCRIPT: "class_declaration",
            CodeLanguage.TYPESCRIPT: "class_declaration",
        }
        
        class_type = class_types.get(self.language)
        if not class_type:
            return classes
        
        class_nodes = self.parser.find_nodes_by_type(root_node, class_type)
        
        for class_node in class_nodes:
            class_name = self._extract_class_name(class_node, code_bytes)
            if not class_name:
                continue
            
            base_classes = self._extract_base_classes(class_node, code_bytes)
            methods = self._extract_methods(class_node, code_bytes, class_name, file_path)
            
            classes[class_name] = ClassDefinition(
                name=class_name,
                base_classes=base_classes,
                methods=methods,
                source_file=file_path,
                line_number=class_node.start_point[0] + 1
            )
        
        return classes
    
    def _extract_class_name(self, class_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract class name from class definition."""
        for child in class_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _extract_base_classes(self, class_node: Node, code_bytes: bytes) -> List[str]:
        """Extract base classes from class definition."""
        base_classes = []
        
        if self.language == CodeLanguage.PYTHON:
            # Look for argument_list after class name
            for child in class_node.children:
                if child.type == "argument_list":
                    for arg_child in child.children:
                        if arg_child.type == "identifier":
                            base = self.parser.get_node_text(arg_child, code_bytes)
                            base_classes.append(base)
        
        elif self.language == CodeLanguage.JAVA:
            # Look for 'extends' keyword
            for i, child in enumerate(class_node.children):
                if child.type == "extends":
                    if i + 1 < len(class_node.children):
                        base = self.parser.get_node_text(class_node.children[i + 1], code_bytes)
                        base_classes.append(base)
        
        return base_classes
    
    def _extract_methods(self, class_node: Node, code_bytes: bytes, class_name: str, 
                        file_path: str) -> Dict[str, MethodDefinition]:
        """Extract methods from class definition."""
        methods = {}
        
        method_types = {
            CodeLanguage.PYTHON: "function_definition",
            CodeLanguage.JAVA: "method_declaration",
            CodeLanguage.CSHARP: "method_declaration",
        }
        
        method_type = method_types.get(self.language)
        if not method_type:
            return methods
        
        method_nodes = self.parser.find_nodes_by_type(class_node, method_type)
        
        for method_node in method_nodes:
            method_name = self._extract_method_name(method_node, code_bytes)
            if not method_name:
                continue
            
            params = self._extract_method_parameters(method_node, code_bytes)
            
            methods[method_name] = MethodDefinition(
                name=method_name,
                parameters=params,
                class_name=class_name,
                source_file=file_path,
                line_number=method_node.start_point[0] + 1
            )
        
        return methods
    
    def _extract_method_name(self, method_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract method name from method definition."""
        for child in method_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _extract_method_parameters(self, method_node: Node, code_bytes: bytes) -> List[str]:
        """Extract parameter names from method definition."""
        params = []
        
        for child in method_node.children:
            if "parameter" in child.type:
                for param_child in child.children:
                    if param_child.type == "identifier":
                        param = self.parser.get_node_text(param_child, code_bytes)
                        # Skip 'self' in Python
                        if param != "self":
                            params.append(param)
        
        return params
    
    def _extract_functions(self, root_node: Node, code_bytes: bytes) -> Set[str]:
        """Extract top-level function names."""
        functions = set()
        
        func_types = {
            CodeLanguage.PYTHON: "function_definition",
            CodeLanguage.JAVA: "method_declaration",
            CodeLanguage.JAVASCRIPT: "function_declaration",
        }
        
        func_type = func_types.get(self.language)
        if not func_type:
            return functions
        
        # Find only top-level functions (not nested in classes)
        for child in root_node.children:
            if child.type == func_type:
                func_name = self._extract_function_name(child, code_bytes)
                if func_name:
                    functions.add(func_name)
        
        return functions
    
    def _extract_function_name(self, func_node: Node, code_bytes: bytes) -> Optional[str]:
        """Extract function name from function definition."""
        for child in func_node.children:
            if child.type == "identifier":
                return self.parser.get_node_text(child, code_bytes)
        return None
    
    def _register_symbol(self, symbol: str, file_path: str):
        """Register symbol definition location."""
        if symbol not in self.symbol_definitions:
            self.symbol_definitions[symbol] = []
        self.symbol_definitions[symbol].append(file_path)
    
    def _build_class_hierarchy(self):
        """Build complete class inheritance hierarchy."""
        # Build forward hierarchy (class -> parents)
        for module_info in self.modules.values():
            for class_def in module_info.classes.values():
                class_name = class_def.name
                if class_name not in self.class_hierarchy:
                    self.class_hierarchy[class_name] = set()
                
                for base in class_def.base_classes:
                    self.class_hierarchy[class_name].add(base)
                    
                    # Build reverse hierarchy (parent -> children)
                    if base not in self.reverse_hierarchy:
                        self.reverse_hierarchy[base] = set()
                    self.reverse_hierarchy[base].add(class_name)
    
    def _detect_method_overrides(self) -> List[Dict[str, Any]]:
        """Detect method overrides in class hierarchy."""
        overrides = []
        
        for module_info in self.modules.values():
            for class_def in module_info.classes.values():
                # Check each method against parent classes
                for method_name, method_def in class_def.methods.items():
                    # Get all parent classes
                    parents = self._get_all_parents(class_def.name)
                    
                    for parent in parents:
                        # Find parent class definition
                        parent_class = self._find_class(parent)
                        if not parent_class:
                            continue
                        
                        # Check if parent has this method
                        if method_name in parent_class.methods:
                            method_def.is_override = True
                            method_def.overrides = parent
                            
                            overrides.append({
                                "class": class_def.name,
                                "method": method_name,
                                "overrides_class": parent,
                                "file": class_def.source_file,
                                "line": method_def.line_number
                            })
        
        return overrides
    
    def _get_all_parents(self, class_name: str) -> Set[str]:
        """Get all parent classes recursively."""
        parents = set()
        
        if class_name not in self.class_hierarchy:
            return parents
        
        direct_parents = self.class_hierarchy[class_name]
        parents.update(direct_parents)
        
        # Recursively get parents of parents
        for parent in direct_parents:
            parents.update(self._get_all_parents(parent))
        
        return parents
    
    def _find_class(self, class_name: str) -> Optional[ClassDefinition]:
        """Find class definition by name."""
        for module_info in self.modules.values():
            if class_name in module_info.classes:
                return module_info.classes[class_name]
        return None
    
    def _build_dependency_graph(self) -> Dict[str, Set[str]]:
        """Build module dependency graph."""
        dep_graph = {}
        
        for file_path, module_info in self.modules.items():
            deps = set()
            
            for import_stmt in module_info.imports:
                # Try to resolve import to actual file
                deps.add(import_stmt.module)
            
            dep_graph[file_path] = deps
        
        return dep_graph
    
    def resolve_symbol(self, symbol: str, context_file: str) -> List[str]:
        """
        Resolve symbol to its definition file(s).
        
        Args:
            symbol: Symbol name to resolve
            context_file: File where symbol is used
        
        Returns:
            List of files where symbol is defined
        """
        # Check if symbol is defined locally
        if context_file in self.modules:
            module = self.modules[context_file]
            
            if symbol in module.classes or symbol in module.functions:
                return [context_file]
        
        # Check imported symbols
        if context_file in self.modules:
            for import_stmt in self.modules[context_file].imports:
                if symbol in import_stmt.imported_names:
                    # Try to find module defining this symbol
                    if symbol in self.symbol_definitions:
                        return self.symbol_definitions[symbol]
        
        # Fall back to global symbol table
        if symbol in self.symbol_definitions:
            return self.symbol_definitions[symbol]
        
        return []


def analyze_project_symbols(file_paths: List[str], language: str = "python") -> Dict[str, Any]:
    """
    Convenience function for project-wide symbol resolution.
    
    Args:
        file_paths: List of source file paths
        language: Programming language
    
    Returns:
        Dictionary with modules, class_hierarchy, method_overrides, dependency_graph
    """
    lang_map = {
        "python": CodeLanguage.PYTHON,
        "java": CodeLanguage.JAVA,
        "csharp": CodeLanguage.CSHARP,
        "c#": CodeLanguage.CSHARP,
        "javascript": CodeLanguage.JAVASCRIPT,
        "typescript": CodeLanguage.TYPESCRIPT,
    }
    
    lang = lang_map.get(language.lower())
    if not lang:
        raise ValueError(f"Unsupported language: {language}")
    
    resolver = SymbolResolver(lang)
    return resolver.analyze_project(file_paths)
