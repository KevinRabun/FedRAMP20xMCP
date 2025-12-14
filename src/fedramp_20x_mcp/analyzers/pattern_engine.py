"""
Pattern Engine for FedRAMP 20x Compliance Analysis

Loads YAML pattern definitions and executes AST-based detection logic
across multiple programming languages and platforms.

AST-first approach: Use tree-sitter for accurate detection, regex as fallback.
"""

import re
import yaml
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum

from .base import AnalysisResult, Finding, Severity
from .ast_utils import create_parser, CodeLanguage


class PatternType(Enum):
    """Pattern detection types"""
    IMPORT = "import"
    FUNCTION_CALL = "function_call"
    CONFIGURATION = "configuration"
    DECORATOR = "decorator"
    RESOURCE = "resource"
    PIPELINE = "pipeline"


@dataclass
class Pattern:
    """
    Represents a single detection pattern.
    
    Uses dict format: languages is Dict[str, Dict] with per-language configs.
    Each language has its own ast_queries and regex_fallback.
    """
    pattern_id: str
    name: str
    description: str
    family: str
    severity: str
    pattern_type: str
    languages: Dict[str, Dict[str, Any]]
    finding: Dict[str, Any]
    tags: List[str]
    nist_controls: List[str]
    related_ksis: List[str]
    requires_all: Optional[List[str]] = None
    requires_any: Optional[List[str]] = None
    requires_absence: Optional[List[str]] = None
    conflicts_with: Optional[List[str]] = None


class PatternEngine:
    """
    Pattern-based code analysis engine.
    
    Loads YAML pattern definitions and executes detection logic using:
    - Tree-sitter AST queries (preferred)
    - Regex patterns (fallback)
    - Pattern composition (boolean logic)
    """
    
    def __init__(self):
        self.patterns: Dict[str, Pattern] = {}
        self.pattern_cache: Dict[str, List[Pattern]] = {}
        
    def load_patterns(self, pattern_file: str) -> int:
        """
        Load patterns from YAML file.
        
        Args:
            pattern_file: Path to YAML pattern file
            
        Returns:
            Number of patterns loaded
        """
        pattern_path = Path(pattern_file)
        if not pattern_path.exists():
            raise FileNotFoundError(f"Pattern file not found: {pattern_file}")
            
        with open(pattern_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Parse YAML with multiple documents (separated by ---)
        documents = yaml.safe_load_all(content)
        count = 0
        
        for doc in documents:
            if doc and isinstance(doc, dict):
                pattern = self._parse_pattern(doc)
                if pattern:
                    self.patterns[pattern.pattern_id] = pattern
                    count += 1
                    
        return count
    
    def load_all_patterns(self, patterns_dir: str = "data/patterns") -> int:
        """
        Load all pattern files from directory.
        
        Args:
            patterns_dir: Directory containing YAML pattern files
            
        Returns:
            Total number of patterns loaded
        """
        patterns_path = Path(patterns_dir)
        if not patterns_path.exists():
            raise FileNotFoundError(f"Patterns directory not found: {patterns_dir}")
            
        total_count = 0
        for pattern_file in patterns_path.glob("*.yaml"):
            count = self.load_patterns(str(pattern_file))
            total_count += count
            
        return total_count
    
    def _parse_pattern(self, data: Dict[str, Any]) -> Optional[Pattern]:
        """Parse YAML document into Pattern object"""
        try:
            return Pattern(
                pattern_id=data.get('pattern_id', ''),
                name=data.get('name', ''),
                description=data.get('description', ''),
                family=data.get('family', ''),
                severity=data.get('severity', 'MEDIUM'),
                pattern_type=data.get('pattern_type', ''),
                languages=data.get('languages', {}),
                finding=data.get('finding', {}),
                tags=data.get('tags', []),
                nist_controls=data.get('nist_controls', []),
                related_ksis=data.get('related_ksis', []),
                requires_all=data.get('requires_all'),
                requires_any=data.get('requires_any'),
                requires_absence=data.get('requires_absence'),
                conflicts_with=data.get('conflicts_with')
            )
        except Exception as e:
            print(f"Warning: Failed to parse pattern: {e}", file=__import__('sys').stderr)
            return None
    
    def analyze(
        self,
        code: str,
        language: str,
        file_path: Optional[str] = None,
        family: Optional[str] = None,
        pattern_ids: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Analyze code against loaded patterns.
        
        Args:
            code: Source code to analyze
            language: Programming language (python, csharp, java, typescript, bicep, terraform, etc.)
            file_path: Optional file path for context
            family: Optional family filter (IAM, MLA, SVC, VDR, etc.)
            pattern_ids: Optional specific pattern IDs to check
            
        Returns:
            AnalysisResult with findings
        """
        findings: List[Finding] = []
        
        # Normalize language name
        language = self._normalize_language(language)
        
        # Filter patterns
        patterns_to_check = self._filter_patterns(family, pattern_ids)
        
        # Parse code with AST (if supported)
        tree = None
        try:
            lang_enum = self._get_language_enum(language)
            if lang_enum:
                parser = create_parser(lang_enum.value)
                tree = parser.parse(code)
        except Exception:
            tree = None  # Fallback to regex if AST parsing fails
        
        # Check each pattern
        matched_pattern_ids: Set[str] = set()
        
        for pattern in patterns_to_check:
            # Skip if language not supported
            if language not in pattern.languages:
                continue
                
            # Check pattern composition first
            if not self._check_pattern_composition(pattern, matched_pattern_ids):
                continue
                
            # Execute pattern detection
            matches = self._execute_pattern(pattern, code, language, tree, file_path)
            
            if matches:
                matched_pattern_ids.add(pattern.pattern_id)
                findings.extend(matches)
        
        # Count findings by severity
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        
        return AnalysisResult(
            ksi_id=family or "PATTERN_ENGINE",
            findings=findings,
            files_analyzed=1,
            total_issues=len(findings),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count
        )
    
    def _normalize_language(self, language: str) -> str:
        """Normalize language name"""
        language = language.lower().strip()
        
        # Handle variations
        mapping = {
            'c#': 'csharp',
            'cs': 'csharp',
            '.net': 'csharp',
            'js': 'javascript',
            'ts': 'typescript',
            'py': 'python',
            'tf': 'terraform',
            'hcl': 'terraform',
            'github_actions': 'github_actions',
            'azure_pipelines': 'azure_pipelines',
            'gitlab_ci': 'gitlab_ci'
        }
        
        return mapping.get(language, language)
    
    def _get_language_enum(self, language: str) -> Optional[CodeLanguage]:
        """Convert language string to CodeLanguage enum"""
        try:
            return CodeLanguage(language)
        except ValueError:
            return None
    
    def _get_node_text(self, node, code: str) -> str:
        """Extract text from AST node"""
        if hasattr(node, 'text'):
            return node.text.decode('utf-8') if isinstance(node.text, bytes) else node.text
        return ""
    
    def _find_nodes_by_type(self, node, node_type: str) -> List:
        """Find all nodes of a specific type"""
        matches = []
        if hasattr(node, 'type') and node.type == node_type:
            matches.append(node)
        if hasattr(node, 'children'):
            for child in node.children:
                matches.extend(self._find_nodes_by_type(child, node_type))
        return matches
    
    def _filter_patterns(
        self,
        family: Optional[str],
        pattern_ids: Optional[List[str]]
    ) -> List[Pattern]:
        """Filter patterns by family or specific IDs"""
        if pattern_ids:
            return [self.patterns[pid] for pid in pattern_ids if pid in self.patterns]
        
        if family:
            cache_key = f"family_{family}"
            if cache_key not in self.pattern_cache:
                self.pattern_cache[cache_key] = [
                    p for p in self.patterns.values() 
                    if p.family.upper() == family.upper()
                ]
            return self.pattern_cache[cache_key]
        
        return list(self.patterns.values())
    
    def _check_pattern_composition(
        self,
        pattern: Pattern,
        matched_patterns: Set[str]
    ) -> bool:
        """
        Check if pattern composition requirements are met.
        
        Returns True if pattern should be checked, False otherwise.
        """
        # Check requires_all: All patterns must have matched
        if pattern.requires_all:
            if not all(pid in matched_patterns for pid in pattern.requires_all):
                return False
        
        # Check requires_any: At least one pattern must have matched
        if pattern.requires_any:
            if not any(pid in matched_patterns for pid in pattern.requires_any):
                return False
        
        # Check requires_absence: None of these patterns should have matched
        if pattern.requires_absence:
            if any(pid in matched_patterns for pid in pattern.requires_absence):
                return False
        
        # Check conflicts_with: These patterns should not have matched
        if pattern.conflicts_with:
            if any(pid in matched_patterns for pid in pattern.conflicts_with):
                return False
        
        return True
    
    def _execute_pattern(
        self,
        pattern: Pattern,
        code: str,
        language: str,
        tree: Any,
        file_path: Optional[str]
    ) -> List[Finding]:
        """Execute pattern detection logic"""
        lang_config = pattern.languages.get(language, {})
        if not lang_config:
            return []
        
        findings: List[Finding] = []
        
        # Try AST-based detection first
        if tree and 'ast_queries' in lang_config:
            ast_findings = self._execute_ast_queries(
                pattern, lang_config['ast_queries'], tree, code, file_path
            )
            if ast_findings:
                findings.extend(ast_findings)
                # AST found issues, use them and skip regex fallback
                return findings
        
        # Fallback to regex (if AST unavailable or found nothing)
        if 'regex_fallback' in lang_config:
            regex_findings = self._execute_regex(
                pattern, lang_config, code, file_path
            )
            findings.extend(regex_findings)
        
        return findings
    
    def _execute_ast_queries(
        self,
        pattern: Pattern,
        queries: List[Dict[str, Any]],
        tree: Any,
        code: str,
        file_path: Optional[str]
    ) -> List[Finding]:
        """Execute AST queries for pattern detection"""
        findings: List[Finding] = []
        
        for query in queries:
            query_type = query.get('query_type', '')
            target = query.get('target', '')
            
            # Different query types
            if query_type == 'import_statement':
                matches = self._find_imports(tree.root_node if hasattr(tree, 'root_node') else tree, target, code)
            elif query_type == 'function_call':
                matches = self._find_function_calls(tree.root_node if hasattr(tree, 'root_node') else tree, target, code)
            elif query_type == 'function_definition':
                matches = self._find_function_definitions(tree.root_node if hasattr(tree, 'root_node') else tree, target, code)
            elif query_type == 'class_definition':
                matches = self._find_class_definitions(tree.root_node if hasattr(tree, 'root_node') else tree, target)
            elif query_type == 'decorator':
                matches = self._find_decorators(tree.root_node if hasattr(tree, 'root_node') else tree, target, code)
            elif query_type == 'assignment':
                matches = self._find_assignments(tree.root_node if hasattr(tree, 'root_node') else tree, target, code)
            elif query_type == 'resource_type':
                matches = self._find_resources(tree.root_node if hasattr(tree, 'root_node') else tree, target, code)
            else:
                continue
            
            # Check conditions
            if matches and 'conditions' in query:
                matches = self._filter_by_conditions(matches, query['conditions'], tree, code)
            
            if matches:
                finding = self._create_finding(pattern, matches, code, file_path)
                findings.append(finding)
        
        return findings
    
    def _execute_regex(
        self,
        pattern: Pattern,
        lang_config: Dict[str, Any],
        code: str,
        file_path: Optional[str]
    ) -> List[Finding]:
        """Execute regex-based pattern detection"""
        regex_pattern = lang_config.get('regex_fallback', '')
        if not regex_pattern:
            return []
        
        findings: List[Finding] = []
        
        try:
            matches = list(re.finditer(regex_pattern, code, re.MULTILINE | re.IGNORECASE))
            
            if matches:
                # Check positive/negative indicators
                positive = lang_config.get('positive_indicators', [])
                negative = lang_config.get('negative_indicators', [])
                
                # Positive indicators: at least one must be present
                if positive:
                    if not any(ind.lower() in code.lower() for ind in positive):
                        return []
                
                # Negative indicators: none should be present (for security gaps)
                if negative:
                    # This is a negative finding - check if positive patterns are absent
                    has_mitigation = any(ind.lower() in code.lower() for ind in 
                                       pattern.languages.get('mitigation_indicators', []))
                    if has_mitigation:
                        return []  # Mitigation present, no finding
                
                finding = self._create_finding(pattern, matches, code, file_path)
                findings.append(finding)
                
        except re.error as e:
            print(f"Regex error in pattern {pattern.pattern_id}: {e}", file=__import__('sys').stderr)
        
        return findings
    
    def _create_finding(
        self,
        pattern: Pattern,
        matches: Any,
        code: str,
        file_path: Optional[str]
    ) -> Finding:
        """Create Finding from pattern and matches"""
        finding_config = pattern.finding
        
        # Extract placeholders from matches if available
        placeholders = {}
        if hasattr(matches, '__iter__') and matches:
            first_match = matches[0] if isinstance(matches, list) else matches
            if hasattr(first_match, 'group'):
                placeholders = first_match.groupdict()
        
        # Format templates
        title = finding_config.get('title_template', pattern.name)
        description = finding_config.get('description_template', pattern.description)
        remediation = finding_config.get('remediation_template', '')
        
        # Replace placeholders
        for key, value in placeholders.items():
            title = title.replace(f'{{{key}}}', str(value))
            description = description.replace(f'{{{key}}}', str(value))
            remediation = remediation.replace(f'{{{key}}}', str(value))
        
        # Map severity
        severity_map = {
            'INFO': Severity.INFO,
            'MEDIUM': Severity.MEDIUM,
            'HIGH': Severity.HIGH,
            'CRITICAL': Severity.CRITICAL
        }
        severity = severity_map.get(pattern.severity.upper(), Severity.MEDIUM)
        
        return Finding(
            title=title,
            description=description,
            severity=severity,
            line_number=self._extract_line_number(matches, code),
            code_snippet=self._extract_code_snippet(matches, code),
            remediation=remediation,
            file_path=file_path,
            requirement_id=pattern.pattern_id
        )
    
    def _extract_line_number(self, matches: Any, code: str) -> int:
        """Extract line number from matches"""
        if not matches:
            return 1
        
        if isinstance(matches, list) and matches:
            match = matches[0]
            if hasattr(match, 'start'):
                return code[:match.start()].count('\n') + 1
            elif hasattr(match, 'start_point'):
                return match.start_point[0] + 1
        elif hasattr(matches, 'start'):
            return code[:matches.start()].count('\n') + 1
        elif hasattr(matches, 'start_point'):
            return matches.start_point[0] + 1
        
        return 1
    
    def _extract_code_snippet(self, matches: Any, code: str, context_lines: int = 2) -> str:
        """Extract code snippet with context"""
        line_num = self._extract_line_number(matches, code)
        lines = code.split('\n')
        
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        return '\n'.join(lines[start:end])
    
    # AST helper methods
    
    def _find_imports(self, tree: Any, target: str, code: str) -> List[Any]:
        """Find import statements"""
        # Simplified - real implementation would use tree-sitter properly
        import_nodes = self._find_nodes_by_type(tree, 'import_statement')
        matches = []
        for node in import_nodes:
            text = self._get_node_text(node, code)
            if target.lower() in text.lower():
                matches.append(node)
        return matches
    
    def _find_function_calls(self, tree: Any, target: str, code: str) -> List[Any]:
        """Find function call expressions"""
        call_nodes = self._find_nodes_by_type(tree, 'call')
        matches = []
        for node in call_nodes:
            text = self._get_node_text(node, code)
            if target.lower() in text.lower():
                matches.append(node)
        return matches
    
    def _find_function_definitions(self, tree: Any, target: str, code: str) -> List[Any]:
        """Find function definitions"""
        func_nodes = self._find_nodes_by_type(tree, 'function_definition')
        matches = []
        for node in func_nodes:
            text = self._get_node_text(node, code)
            if target.lower() in text.lower():
                matches.append(node)
        return matches
    
    def _find_class_definitions(self, tree: Any, target: str) -> List[Any]:
        """Find class definitions"""
        return self._find_nodes_by_type(tree, 'class_definition')
    
    def _find_decorators(self, tree: Any, target: str, code: str) -> List[Any]:
        """Find decorators"""
        decorator_nodes = self._find_nodes_by_type(tree, 'decorator')
        matches = []
        for node in decorator_nodes:
            text = self._get_node_text(node, code)
            if target.lower() in text.lower():
                matches.append(node)
        return matches
    
    def _find_assignments(self, tree: Any, target: str, code: str) -> List[Any]:
        """Find variable assignments"""
        assign_nodes = self._find_nodes_by_type(tree, 'assignment')
        matches = []
        for node in assign_nodes:
            text = self._get_node_text(node, code)
            if target.lower() in text.lower():
                matches.append(node)
        return matches
    
    def _find_resources(self, tree: Any, target: str, code: str) -> List[Any]:
        """Find IaC resource definitions"""
        # For Bicep/Terraform
        resource_nodes = self._find_nodes_by_type(tree, 'resource_declaration')
        matches = []
        for node in resource_nodes:
            text = self._get_node_text(node, code)
            if target in text:
                matches.append(node)
        return matches
    
    def _filter_by_conditions(
        self,
        matches: List[Any],
        conditions: List[str],
        tree: Any,
        code: str
    ) -> List[Any]:
        """Filter matches by additional conditions"""
        # Simplified - real implementation would parse conditions
        filtered = []
        for match in matches:
            match_text = self._get_node_text(match, code) if hasattr(match, 'type') else str(match)
            
            passes = True
            for condition in conditions:
                if 'not_contains' in condition:
                    pattern = condition.split(':')[1]
                    if pattern.lower() in match_text.lower():
                        passes = False
                        break
                elif 'contains' in condition:
                    pattern = condition.split(':')[1]
                    if pattern.lower() not in match_text.lower():
                        passes = False
                        break
            
            if passes:
                filtered.append(match)
        
        return filtered
    
    def get_patterns_by_family(self, family: str) -> List[Pattern]:
        """Get all patterns for a specific family"""
        return self._filter_patterns(family, None)
    
    def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """Get specific pattern by ID"""
        return self.patterns.get(pattern_id)
    
    def list_families(self) -> List[str]:
        """List all unique families in loaded patterns"""
        return sorted(set(p.family for p in self.patterns.values()))
    
    def list_pattern_ids(self) -> List[str]:
        """List all loaded pattern IDs"""
        return sorted(self.patterns.keys())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get pattern engine statistics"""
        families = {}
        for pattern in self.patterns.values():
            if pattern.family not in families:
                families[pattern.family] = 0
            families[pattern.family] += 1
        
        languages = set()
        for pattern in self.patterns.values():
            # Handle both list and dict formats for languages
            if isinstance(pattern.languages, dict):
                languages.update(pattern.languages.keys())
            elif isinstance(pattern.languages, list):
                languages.update(pattern.languages)
        
        return {
            'total_patterns': len(self.patterns),
            'families': families,
            'languages': sorted(languages),
            'pattern_types': list(set(p.pattern_type for p in self.patterns.values()))
        }
