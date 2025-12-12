"""
Pattern Compiler for FedRAMP 20x Compliance Analysis

Compiles YAML pattern definitions into optimized detection functions
with caching for improved performance.

The compiler pre-processes patterns to:
- Compile regex patterns
- Build AST query trees
- Cache language-specific logic
- Optimize pattern composition checks
"""

import re
from typing import Dict, Any, List, Callable, Optional, Set, TYPE_CHECKING
from dataclasses import dataclass, field
from functools import lru_cache

from .pattern_engine import Pattern, PatternType
from .ast_utils import create_parser, CodeLanguage

if TYPE_CHECKING:
    from .pattern_engine import PatternEngine


@dataclass
class CompiledPattern:
    """Compiled pattern with optimized detection logic"""
    pattern: Pattern
    compiled_regexes: Dict[str, re.Pattern] = field(default_factory=dict)
    ast_query_cache: Dict[str, Any] = field(default_factory=dict)
    detection_functions: Dict[str, Callable] = field(default_factory=dict)
    dependencies: Set[str] = field(default_factory=set)
    dependents: Set[str] = field(default_factory=set)


class PatternCompiler:
    """
    Compiles YAML patterns into optimized detection functions.
    
    Pre-compiles regex patterns, builds dependency graphs,
    and caches compiled logic for fast execution.
    """
    
    def __init__(self):
        self.compiled_patterns: Dict[str, CompiledPattern] = {}
        self.dependency_graph: Dict[str, Set[str]] = {}
        self.execution_order: List[str] = []
        
    def compile_pattern(self, pattern: Pattern) -> CompiledPattern:
        """
        Compile a single pattern.
        
        Args:
            pattern: Pattern to compile
            
        Returns:
            CompiledPattern with optimized detection logic
        """
        compiled = CompiledPattern(pattern=pattern)
        
        # Compile regex patterns for each language
        for language, lang_config in pattern.languages.items():
            if 'regex_fallback' in lang_config:
                try:
                    regex = re.compile(
                        lang_config['regex_fallback'],
                        re.MULTILINE | re.IGNORECASE
                    )
                    compiled.compiled_regexes[language] = regex
                except re.error as e:
                    print(f"Warning: Failed to compile regex for {pattern.pattern_id} ({language}): {e}",
                          file=__import__('sys').stderr)
        
        # Build AST query cache
        for language, lang_config in pattern.languages.items():
            if 'ast_queries' in lang_config:
                compiled.ast_query_cache[language] = self._optimize_ast_queries(
                    lang_config['ast_queries']
                )
        
        # Build dependency sets
        if pattern.requires_all:
            compiled.dependencies.update(pattern.requires_all)
        if pattern.requires_any:
            compiled.dependencies.update(pattern.requires_any)
        if pattern.requires_absence:
            compiled.dependencies.update(pattern.requires_absence)
        if pattern.conflicts_with:
            compiled.dependencies.update(pattern.conflicts_with)
        
        return compiled
    
    def compile_patterns(self, patterns: Dict[str, Pattern]) -> None:
        """
        Compile multiple patterns and build dependency graph.
        
        Args:
            patterns: Dictionary of pattern_id -> Pattern
        """
        # Compile each pattern
        for pattern_id, pattern in patterns.items():
            self.compiled_patterns[pattern_id] = self.compile_pattern(pattern)
        
        # Build dependency graph
        self._build_dependency_graph()
        
        # Calculate execution order (topological sort)
        self.execution_order = self._topological_sort()
    
    def _optimize_ast_queries(self, queries: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Optimize AST queries for faster execution.
        
        Groups queries by type, pre-processes conditions,
        and builds query execution plan.
        """
        optimized = {
            'by_type': {},
            'with_conditions': [],
            'simple': []
        }
        
        for query in queries:
            query_type = query.get('query_type', '')
            
            # Group by query type for batching
            if query_type not in optimized['by_type']:
                optimized['by_type'][query_type] = []
            optimized['by_type'][query_type].append(query)
            
            # Separate queries with/without conditions
            if 'conditions' in query:
                optimized['with_conditions'].append(query)
            else:
                optimized['simple'].append(query)
        
        return optimized
    
    def _build_dependency_graph(self) -> None:
        """Build pattern dependency graph"""
        self.dependency_graph.clear()
        
        for pattern_id, compiled in self.compiled_patterns.items():
            if pattern_id not in self.dependency_graph:
                self.dependency_graph[pattern_id] = set()
            
            # Add dependencies
            for dep_id in compiled.dependencies:
                if dep_id in self.compiled_patterns:
                    self.dependency_graph[pattern_id].add(dep_id)
                    self.compiled_patterns[dep_id].dependents.add(pattern_id)
    
    def _topological_sort(self) -> List[str]:
        """
        Topological sort of patterns based on dependencies.
        
        Patterns with no dependencies come first, then patterns
        that depend on them, etc.
        """
        # Count incoming edges (dependencies)
        in_degree = {pid: 0 for pid in self.compiled_patterns}
        
        for pattern_id, deps in self.dependency_graph.items():
            in_degree[pattern_id] = len(deps)
        
        # Start with patterns that have no dependencies
        queue = [pid for pid, degree in in_degree.items() if degree == 0]
        result = []
        
        while queue:
            # Sort by pattern_id for deterministic order
            queue.sort()
            current = queue.pop(0)
            result.append(current)
            
            # Reduce in-degree for dependents
            if current in self.compiled_patterns:
                for dependent in self.compiled_patterns[current].dependents:
                    in_degree[dependent] -= 1
                    if in_degree[dependent] == 0:
                        queue.append(dependent)
        
        # Check for cycles
        if len(result) != len(self.compiled_patterns):
            # Some patterns not included - circular dependency
            remaining = set(self.compiled_patterns.keys()) - set(result)
            print(f"Warning: Circular dependencies detected in patterns: {remaining}",
                  file=__import__('sys').stderr)
            # Add remaining patterns at the end
            result.extend(sorted(remaining))
        
        return result
    
    def get_execution_order(
        self,
        pattern_ids: Optional[List[str]] = None,
        family: Optional[str] = None
    ) -> List[str]:
        """
        Get optimal execution order for patterns.
        
        Args:
            pattern_ids: Specific patterns to execute (None = all)
            family: Family filter
            
        Returns:
            Ordered list of pattern IDs to execute
        """
        if pattern_ids:
            # Filter execution order to requested patterns
            return [pid for pid in self.execution_order if pid in pattern_ids]
        
        if family:
            # Filter by family
            family_patterns = [
                pid for pid in self.execution_order
                if self.compiled_patterns[pid].pattern.family.upper() == family.upper()
            ]
            return family_patterns
        
        return self.execution_order
    
    def can_skip_pattern(
        self,
        pattern_id: str,
        matched_patterns: Set[str]
    ) -> bool:
        """
        Determine if pattern can be skipped based on composition rules
        and already-matched patterns.
        
        Args:
            pattern_id: Pattern to check
            matched_patterns: Patterns that have already matched
            
        Returns:
            True if pattern can be skipped, False otherwise
        """
        if pattern_id not in self.compiled_patterns:
            return True
        
        compiled = self.compiled_patterns[pattern_id]
        pattern = compiled.pattern
        
        # Check requires_all: All required patterns must have matched
        if pattern.requires_all:
            if not all(pid in matched_patterns for pid in pattern.requires_all):
                return True  # Skip - dependencies not met
        
        # Check requires_any: At least one required pattern must have matched
        if pattern.requires_any:
            if not any(pid in matched_patterns for pid in pattern.requires_any):
                return True  # Skip - no alternative dependency met
        
        # Check requires_absence: None of these patterns should have matched
        if pattern.requires_absence:
            if any(pid in matched_patterns for pid in pattern.requires_absence):
                return True  # Skip - conflicting pattern matched
        
        # Check conflicts_with: These patterns should not have matched
        if pattern.conflicts_with:
            if any(pid in matched_patterns for pid in pattern.conflicts_with):
                return True  # Skip - conflict detected
        
        return False  # Don't skip - all checks passed
    
    def get_optimized_regex(self, pattern_id: str, language: str) -> Optional[re.Pattern]:
        """Get compiled regex for pattern and language"""
        if pattern_id in self.compiled_patterns:
            return self.compiled_patterns[pattern_id].compiled_regexes.get(language)
        return None
    
    def get_optimized_ast_queries(self, pattern_id: str, language: str) -> Optional[Dict[str, Any]]:
        """Get optimized AST queries for pattern and language"""
        if pattern_id in self.compiled_patterns:
            return self.compiled_patterns[pattern_id].ast_query_cache.get(language)
        return None
    
    def get_pattern_statistics(self) -> Dict[str, Any]:
        """Get compiler statistics"""
        total_patterns = len(self.compiled_patterns)
        
        patterns_with_regex = sum(
            1 for c in self.compiled_patterns.values()
            if c.compiled_regexes
        )
        
        patterns_with_ast = sum(
            1 for c in self.compiled_patterns.values()
            if c.ast_query_cache
        )
        
        patterns_with_deps = sum(
            1 for c in self.compiled_patterns.values()
            if c.dependencies
        )
        
        return {
            'total_patterns': total_patterns,
            'patterns_with_regex': patterns_with_regex,
            'patterns_with_ast': patterns_with_ast,
            'patterns_with_dependencies': patterns_with_deps,
            'execution_order_length': len(self.execution_order),
            'has_circular_deps': len(self.execution_order) != total_patterns
        }
    
    def validate_patterns(self) -> List[str]:
        """
        Validate compiled patterns.
        
        Returns:
            List of validation warnings/errors
        """
        warnings = []
        
        # Check for missing dependencies
        for pattern_id, compiled in self.compiled_patterns.items():
            for dep_id in compiled.dependencies:
                if dep_id not in self.compiled_patterns:
                    warnings.append(
                        f"Pattern {pattern_id} references missing dependency: {dep_id}"
                    )
        
        # Check for patterns with neither AST nor regex
        for pattern_id, compiled in self.compiled_patterns.items():
            if not compiled.compiled_regexes and not compiled.ast_query_cache:
                warnings.append(
                    f"Pattern {pattern_id} has no detection logic (no AST queries or regex)"
                )
        
        # Check for circular dependencies
        if len(self.execution_order) != len(self.compiled_patterns):
            warnings.append(
                "Circular dependencies detected in pattern graph"
            )
        
        return warnings
    
    def export_execution_plan(self) -> Dict[str, Any]:
        """
        Export execution plan for debugging/optimization.
        
        Returns:
            Dictionary with execution plan details
        """
        plan = {
            'execution_order': self.execution_order,
            'patterns': {},
            'dependency_graph': {}
        }
        
        for pattern_id in self.execution_order:
            if pattern_id in self.compiled_patterns:
                compiled = self.compiled_patterns[pattern_id]
                plan['patterns'][pattern_id] = {
                    'name': compiled.pattern.name,
                    'family': compiled.pattern.family,
                    'severity': compiled.pattern.severity,
                    'dependencies': list(compiled.dependencies),
                    'dependents': list(compiled.dependents),
                    'has_regex': bool(compiled.compiled_regexes),
                    'has_ast': bool(compiled.ast_query_cache),
                    'languages': list(compiled.pattern.languages.keys())
                }
        
        for pattern_id, deps in self.dependency_graph.items():
            plan['dependency_graph'][pattern_id] = list(deps)
        
        return plan


# Singleton compiler instance
_compiler_instance: Optional[PatternCompiler] = None


def get_compiler() -> PatternCompiler:
    """Get singleton pattern compiler instance"""
    global _compiler_instance
    if _compiler_instance is None:
        _compiler_instance = PatternCompiler()
    return _compiler_instance


def compile_patterns_from_engine(engine: 'PatternEngine') -> PatternCompiler:
    """
    Compile patterns from a pattern engine.
    
    Args:
        engine: PatternEngine with loaded patterns
        
    Returns:
        PatternCompiler with compiled patterns
    """
    compiler = PatternCompiler()
    compiler.compile_patterns(engine.patterns)
    return compiler


@lru_cache(maxsize=128)
def get_cached_pattern_order(family: Optional[str] = None) -> tuple:
    """
    Get cached execution order for patterns.
    
    LRU cache for frequently requested execution orders.
    
    Args:
        family: Family filter (None = all patterns)
        
    Returns:
        Tuple of pattern IDs in execution order
    """
    compiler = get_compiler()
    return tuple(compiler.get_execution_order(family=family))
