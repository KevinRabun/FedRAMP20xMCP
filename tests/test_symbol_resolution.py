"""
Tests for symbol resolution.

Validates:
1. Import statement extraction
2. Class hierarchy building
3. Method override detection
4. Cross-file symbol resolution
5. Dependency graph construction
"""

import sys
import os
import tempfile
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.symbol_resolution import (
    SymbolResolver,
    analyze_project_symbols,
)
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage


def test_import_extraction():
    """Test that imports are correctly extracted."""
    code = """
import os
import sys
from pathlib import Path
from typing import List, Dict
"""
    
    # Create temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        file_path = f.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        resolver._analyze_file(file_path)
        
        module_info = resolver.modules[file_path]
        imports = module_info.imports
        
        assert len(imports) >= 2
        
        # Check that os and sys are imported
        modules = [imp.module for imp in imports]
        assert "os" in modules or "sys" in modules
        
        print("[PASS] Import extraction working")
    finally:
        os.unlink(file_path)


def test_class_extraction():
    """Test that classes and methods are correctly extracted."""
    code = """
class Animal:
    def speak(self):
        pass

class Dog(Animal):
    def speak(self):
        return "Woof"
    
    def fetch(self, item):
        return item
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        file_path = f.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        resolver._analyze_file(file_path)
        
        module_info = resolver.modules[file_path]
        classes = module_info.classes
        
        assert "Animal" in classes
        assert "Dog" in classes
        
        # Check Animal methods
        assert "speak" in classes["Animal"].methods
        
        # Check Dog inheritance
        assert "Animal" in classes["Dog"].base_classes
        
        # Check Dog methods
        assert "speak" in classes["Dog"].methods
        assert "fetch" in classes["Dog"].methods
        
        # Check method parameters
        fetch_method = classes["Dog"].methods["fetch"]
        assert "item" in fetch_method.parameters
        
        print("[PASS] Class extraction working")
    finally:
        os.unlink(file_path)


def test_class_hierarchy():
    """Test that class hierarchy is correctly built."""
    code = """
class Base:
    pass

class Middle(Base):
    pass

class Derived(Middle):
    pass
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        file_path = f.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        resolver.analyze_project([file_path])
        
        # Check hierarchy
        assert "Base" in resolver.class_hierarchy["Middle"]
        assert "Middle" in resolver.class_hierarchy["Derived"]
        
        # Check reverse hierarchy
        assert "Middle" in resolver.reverse_hierarchy["Base"]
        assert "Derived" in resolver.reverse_hierarchy["Middle"]
        
        # Check all parents
        all_parents = resolver._get_all_parents("Derived")
        assert "Middle" in all_parents
        assert "Base" in all_parents
        
        print("[PASS] Class hierarchy construction working")
    finally:
        os.unlink(file_path)


def test_method_override_detection():
    """Test that method overrides are detected."""
    code = """
class Parent:
    def process(self):
        pass
    
    def calculate(self):
        pass

class Child(Parent):
    def process(self):
        return "override"
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        file_path = f.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        results = resolver.analyze_project([file_path])
        
        overrides = results["method_overrides"]
        
        # Should detect Child.process overriding Parent.process
        assert len(overrides) > 0
        
        override = overrides[0]
        assert override["class"] == "Child"
        assert override["method"] == "process"
        assert override["overrides_class"] == "Parent"
        
        # Check that method is marked as override
        child_class = resolver.modules[file_path].classes["Child"]
        assert child_class.methods["process"].is_override
        
        print("[PASS] Method override detection working")
    finally:
        os.unlink(file_path)


def test_symbol_resolution():
    """Test that symbols are resolved to their definitions."""
    code = """
class MyClass:
    pass

def my_function():
    pass
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        file_path = f.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        resolver.analyze_project([file_path])
        
        # Resolve MyClass
        locations = resolver.resolve_symbol("MyClass", file_path)
        assert len(locations) > 0
        assert file_path in locations
        
        # Resolve my_function
        locations = resolver.resolve_symbol("my_function", file_path)
        assert len(locations) > 0
        assert file_path in locations
        
        print("[PASS] Symbol resolution working")
    finally:
        os.unlink(file_path)


def test_cross_file_resolution():
    """Test symbol resolution across multiple files."""
    # File 1: Define a class
    code1 = """
class SharedClass:
    def shared_method(self):
        pass
"""
    
    # File 2: Import and use the class
    code2 = """
from module1 import SharedClass

class DerivedClass(SharedClass):
    pass
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f1, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f2:
        
        f1.write(code1)
        f2.write(code2)
        file1_path = f1.name
        file2_path = f2.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        resolver.analyze_project([file1_path, file2_path])
        
        # Check that SharedClass is defined in file1
        assert "SharedClass" in resolver.symbol_definitions
        assert file1_path in resolver.symbol_definitions["SharedClass"]
        
        # Check that DerivedClass inherits from SharedClass
        derived_class = resolver._find_class("DerivedClass")
        assert derived_class is not None
        assert "SharedClass" in derived_class.base_classes
        
        print("[PASS] Cross-file resolution working")
    finally:
        os.unlink(file1_path)
        os.unlink(file2_path)


def test_dependency_graph():
    """Test that dependency graph is built correctly."""
    code1 = """
import os
import sys
"""
    
    code2 = """
from pathlib import Path
from typing import List
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f1, \
         tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f2:
        
        f1.write(code1)
        f2.write(code2)
        file1_path = f1.name
        file2_path = f2.name
    
    try:
        resolver = SymbolResolver(CodeLanguage.PYTHON)
        results = resolver.analyze_project([file1_path, file2_path])
        
        dep_graph = results["dependency_graph"]
        
        # Check that file1 depends on os and sys
        assert file1_path in dep_graph
        deps1 = dep_graph[file1_path]
        assert "os" in deps1 or "sys" in deps1
        
        # Check that file2 depends on pathlib and typing
        assert file2_path in dep_graph
        deps2 = dep_graph[file2_path]
        assert "pathlib" in deps2 or "typing" in deps2
        
        print("[PASS] Dependency graph construction working")
    finally:
        os.unlink(file1_path)
        os.unlink(file2_path)


def test_convenience_function():
    """Test the convenience function for project analysis."""
    code = """
class TestClass:
    def test_method(self):
        pass
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(code)
        file_path = f.name
    
    try:
        results = analyze_project_symbols([file_path], language="python")
        
        assert "modules" in results
        assert "class_hierarchy" in results
        assert "method_overrides" in results
        assert "dependency_graph" in results
        
        print("[PASS] Convenience function working")
    finally:
        os.unlink(file_path)


def run_all_tests():
    """Run all symbol resolution tests."""
    print("Running symbol resolution tests...\n")
    
    tests = [
        test_import_extraction,
        test_class_extraction,
        test_class_hierarchy,
        test_method_override_detection,
        test_symbol_resolution,
        test_cross_file_resolution,
        test_dependency_graph,
        test_convenience_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} error: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"Symbol Resolution Tests: {passed}/{len(tests)} passed")
    
    if failed == 0:
        print("ALL TESTS PASSED [PASS]")
        return 0
    else:
        print(f"FAILURES: {failed}")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
