"""
Generic pattern-driven analyzer.

Loads V2 patterns from YAML files and performs analysis based on pattern definitions.
This replaces 271 traditional analyzers with a single pattern-driven architecture.
"""

import yaml
import re
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass

from .base import Finding, AnalysisResult, Severity
from .ast_utils import ASTParser, CodeLanguage


@dataclass
class Pattern:
    """V2 pattern loaded from YAML."""
    pattern_id: str
    name: str
    description: str
    family: str
    severity: str
    pattern_type: str
    languages: Dict[str, Any]
    finding: Dict[str, Any]
    tags: List[str]
    nist_controls: List[str]
    related_ksis: List[str]
    related_frrs: List[str]
    requires_absence: Optional[List[str]] = None
    evidence_collection: Optional[Dict[str, Any]] = None
    evidence_artifacts: Optional[List[Dict[str, Any]]] = None
    automation: Optional[Dict[str, Any]] = None
    implementation: Optional[Dict[str, Any]] = None
    ssp_mapping: Optional[Dict[str, Any]] = None
    azure_guidance: Optional[Dict[str, Any]] = None
    compliance_frameworks: Optional[Dict[str, Any]] = None
    testing: Optional[Dict[str, Any]] = None


class PatternLoader:
    """Loads and caches V2 patterns from YAML files."""
    
    def __init__(self, patterns_dir: Optional[Path] = None):
        """
        Initialize pattern loader.
        
        Args:
            patterns_dir: Directory containing pattern YAML files.
                         If None, uses default location.
        """
        if patterns_dir is None:
            # Default to data/patterns relative to project root
            # __file__ is in src/fedramp_20x_mcp/analyzers/generic_analyzer.py
            # Project root is 4 levels up
            base_dir = Path(__file__).parent.parent.parent.parent
            patterns_dir = base_dir / "data" / "patterns"
        
        self.patterns_dir = Path(patterns_dir)
        self._patterns: Dict[str, Pattern] = {}
        self._patterns_by_family: Dict[str, List[Pattern]] = {}
        self._patterns_by_language: Dict[str, List[Pattern]] = {}
        self._loaded = False
    
    def load_patterns(self, pattern_files: Optional[List[str]] = None) -> None:
        """
        Load patterns from YAML files.
        
        Args:
            pattern_files: Specific pattern files to load.
                          If None, loads all *_patterns.yaml files.
        """
        if pattern_files is None:
            # Load all pattern files
            pattern_files = [f.name for f in self.patterns_dir.glob("*_patterns.yaml")]
        
        for filename in pattern_files:
            filepath = self.patterns_dir / filename
            if not filepath.exists():
                continue
            
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    # YAML files may contain multiple documents
                    for doc in yaml.safe_load_all(f):
                        if doc is None:
                            continue
                        
                        # Verify required fields exist
                        required_fields = ['pattern_id', 'name', 'description', 'family', 'severity', 'pattern_type', 'finding']
                        missing = [f for f in required_fields if f not in doc]
                        if missing:
                            print(f"Warning: Pattern in {filename} missing fields: {missing}")
                            continue
                        
                        pattern = Pattern(
                            pattern_id=doc['pattern_id'],
                            name=doc['name'],
                            description=doc['description'],
                            family=doc['family'],
                            severity=doc['severity'],
                            pattern_type=doc['pattern_type'],
                            languages=doc.get('languages', {}),
                            finding=doc['finding'],
                            tags=doc.get('tags', []),
                            nist_controls=doc.get('nist_controls', []),
                            related_ksis=doc.get('related_ksis', []),
                            related_frrs=doc.get('related_frrs', []),
                            requires_absence=doc.get('requires_absence'),
                            evidence_collection=doc.get('evidence_collection'),
                            evidence_artifacts=doc.get('evidence_artifacts'),
                            automation=doc.get('automation'),
                            implementation=doc.get('implementation'),
                            ssp_mapping=doc.get('ssp_mapping'),
                            azure_guidance=doc.get('azure_guidance'),
                            compliance_frameworks=doc.get('compliance_frameworks'),
                            testing=doc.get('testing')
                        )
                        
                        self._patterns[pattern.pattern_id] = pattern
                        
                        # Index by family
                        if pattern.family not in self._patterns_by_family:
                            self._patterns_by_family[pattern.family] = []
                        self._patterns_by_family[pattern.family].append(pattern)
                        
                        # Index by language
                        for lang in pattern.languages.keys():
                            if lang not in self._patterns_by_language:
                                self._patterns_by_language[lang] = []
                            self._patterns_by_language[lang].append(pattern)
            except Exception as e:
                print(f"Error loading {filename}: {e}")
                continue
        
        self._loaded = True
    
    def get_pattern(self, pattern_id: str) -> Optional[Pattern]:
        """Get a specific pattern by ID."""
        if not self._loaded:
            self.load_patterns()
        return self._patterns.get(pattern_id)
    
    def get_patterns_for_language(self, language: str) -> List[Pattern]:
        """Get all patterns applicable to a language."""
        if not self._loaded:
            self.load_patterns()
        return self._patterns_by_language.get(language.lower(), [])
    
    def get_patterns_for_family(self, family: str) -> List[Pattern]:
        """Get all patterns in a family."""
        if not self._loaded:
            self.load_patterns()
        return self._patterns_by_family.get(family.upper(), [])
    
    def get_all_patterns(self) -> List[Pattern]:
        """Get all loaded patterns."""
        if not self._loaded:
            self.load_patterns()
        return list(self._patterns.values())


class GenericPatternAnalyzer:
    """
    Generic analyzer that uses V2 patterns for detection.
    
    Replaces 271 traditional analyzers with pattern-driven architecture.
    """
    
    def __init__(self, pattern_loader: Optional[PatternLoader] = None):
        """
        Initialize generic analyzer.
        
        Args:
            pattern_loader: PatternLoader instance. If None, creates default.
        """
        self.pattern_loader = pattern_loader or PatternLoader()
        if not self.pattern_loader._loaded:
            self.pattern_loader.load_patterns()
        
        # Metadata dictionary for easy access and updates
        self.metadata = {
            'analyzer_type': 'GenericPatternAnalyzer',
            'version': '2.0',
            'pattern_count': len(self.pattern_loader._patterns),
            'supported_languages': ['python', 'csharp', 'java', 'typescript', 'javascript', 
                                   'bicep', 'terraform', 'markdown', 'md',
                                   'github_actions', 'azure_pipelines', 'gitlab_ci'],
            'families': list(set(p.family for p in self.pattern_loader._patterns.values())),
            'architecture': 'pattern-based',
            'pattern_files': list(self.pattern_loader.patterns_dir.glob('*_patterns.yaml'))
        }
    
    def analyze(
        self,
        code: str,
        language: str,
        file_path: str = "",
        families: Optional[List[str]] = None,
        ksi_ids: Optional[List[str]] = None
    ) -> AnalysisResult:
        """
        Analyze code using pattern matching.
        
        Args:
            code: Source code to analyze
            language: Programming language (python, csharp, java, typescript, bicep, terraform, etc.)
            file_path: Optional file path for context
            families: Optional list of families to check (e.g., ['IAM', 'SCN'])
            ksi_ids: Optional list of specific KSI IDs to check
            
        Returns:
            AnalysisResult with findings
        """
        findings: List[Finding] = []
        
        # Get applicable patterns
        patterns = self._get_applicable_patterns(language, families, ksi_ids)
        
        # Parse code with tree-sitter if available
        tree = None
        parser = None
        
        # Normalize language aliases
        language = language.lower()
        if language == 'md':
            language = 'markdown'
        
        try:
            # Map language string to CodeLanguage enum
            lang_map = {
                'python': CodeLanguage.PYTHON,
                'csharp': CodeLanguage.CSHARP,
                'java': CodeLanguage.JAVA,
                'typescript': CodeLanguage.TYPESCRIPT,
                'javascript': CodeLanguage.JAVASCRIPT,
                'bicep': CodeLanguage.BICEP,
                'terraform': CodeLanguage.TERRAFORM,
            }
            
            code_lang = lang_map.get(language.lower())
            if code_lang and code_lang not in (CodeLanguage.BICEP, CodeLanguage.TERRAFORM):
                parser = ASTParser(code_lang)
                tree = parser.parse(code)
        except Exception as e:
            # Fall back to regex if AST parsing fails
            tree = None
            parser = None
        
        # Check each pattern (except requires_absence patterns)
        absence_patterns = []
        for pattern in patterns:
            # Skip requires_absence patterns - we'll check them separately
            if hasattr(pattern, 'requires_absence') and pattern.requires_absence:
                absence_patterns.append(pattern)
                continue
            
            pattern_findings = self._check_pattern(
                pattern, code, language, file_path, tree, parser
            )
            findings.extend(pattern_findings)
        
        # Check for patterns that require absence of other patterns
        for pattern in absence_patterns:
            absence_findings = self._check_requires_absence(
                pattern, code, language, file_path, tree, parser, findings
            )
            findings.extend(absence_findings)
        
        return AnalysisResult(findings=findings)
    
    def get_evidence_automation_recommendations(self, families: Optional[List[str]] = None, 
                                              frr_id: Optional[str] = None) -> dict:
        """
        Get recommendations for automating evidence collection.
        
        Args:
            families: Optional list of families to get recommendations for
            frr_id: Optional specific FRR ID to get recommendations for
            
        Returns:
            Dictionary with automation recommendations including:
            - automation_feasibility: How automatable evidence collection is
            - evidence_artifacts: List of artifact types to collect
            - collection_methods: Methods for collecting evidence
            - azure_services: Recommended Azure services for evidence collection
            - implementation_steps: Steps to implement evidence automation
        """
        patterns = []
        
        if frr_id:
            # Get patterns for specific FRR
            patterns = [p for p in self.pattern_loader._patterns.values() 
                       if frr_id.upper() in [f.upper() for f in p.related_frrs]]
        elif families:
            # Get patterns for families
            for family in families:
                patterns.extend(self.pattern_loader.get_patterns_for_family(family.upper()))
        else:
            # Get all patterns
            patterns = list(self.pattern_loader._patterns.values())
        
        # Aggregate evidence collection info from patterns
        evidence_artifacts = set()
        collection_methods = set()
        azure_services = set()
        
        for pattern in patterns:
            if pattern.evidence_artifacts:
                for artifact in pattern.evidence_artifacts:
                    if isinstance(artifact, dict):
                        evidence_artifacts.add(artifact.get('artifact_name', str(artifact)))
                    else:
                        evidence_artifacts.add(str(artifact))
            
            if pattern.evidence_collection:
                if 'method' in pattern.evidence_collection:
                    collection_methods.add(pattern.evidence_collection['method'])
                if 'methods' in pattern.evidence_collection:
                    for method in pattern.evidence_collection['methods']:
                        collection_methods.add(method)
            
            if pattern.azure_guidance and 'services' in pattern.azure_guidance:
                for service in pattern.azure_guidance['services']:
                    azure_services.add(service)
        
        # Determine automation feasibility
        code_detectable_patterns = [p for p in patterns if 'code_detectable' in p.tags or 'automated' in p.tags]
        automation_feasibility = 'High' if len(code_detectable_patterns) > len(patterns) * 0.5 else 'Medium'
        
        return {
            'pattern_count': len(patterns),
            'families': list(set(p.family for p in patterns)),
            'automation_feasibility': automation_feasibility,
            'code_detectable_patterns': len(code_detectable_patterns),
            'total_patterns': len(patterns),
            'evidence_artifacts': sorted(list(evidence_artifacts)),
            'collection_methods': sorted(list(collection_methods)),
            'azure_services': sorted(list(azure_services)),
            'implementation_steps': [
                '1. Enable pattern-based analysis in CI/CD pipelines',
                '2. Configure evidence collection for detected patterns',
                '3. Store findings and evidence in compliance repository',
                '4. Set up automated reporting for pattern matches',
                '5. Monitor evidence collection coverage and completeness'
            ],
            'recommended_services': [
                'Azure DevOps - CI/CD pipeline integration',
                'Azure Monitor - Log aggregation for evidence',
                'Azure Storage - Evidence artifact storage',
                'Azure Policy - Compliance state tracking',
                'Microsoft Defender for Cloud - Security findings'
            ]
        }
    
    def get_evidence_collection_queries(self, families: Optional[List[str]] = None,
                                       frr_id: Optional[str] = None) -> List[dict]:
        """
        Get evidence collection queries for specific patterns.
        
        Args:
            families: Optional list of families to get queries for
            frr_id: Optional specific FRR ID to get queries for
            
        Returns:
            List of evidence collection query dictionaries with:
            - method_type: Type of collection method
            - name: Query name
            - description: What the query does
            - purpose: Why this evidence is collected
        """
        patterns = []
        
        if frr_id:
            # Get patterns for specific FRR
            patterns = [p for p in self.pattern_loader._patterns.values() 
                       if frr_id.upper() in [f.upper() for f in p.related_frrs]]
        elif families:
            # Get patterns for families
            for family in families:
                patterns.extend(self.pattern_loader.get_patterns_for_family(family.upper()))
        else:
            # Get all patterns
            patterns = list(self.pattern_loader._patterns.values())
        
        queries = []
        
        for pattern in patterns:
            if pattern.evidence_collection:
                # Extract queries from evidence_collection field
                if 'queries' in pattern.evidence_collection:
                    for query in pattern.evidence_collection['queries']:
                        queries.append(query)
                elif 'query' in pattern.evidence_collection:
                    queries.append(pattern.evidence_collection['query'])
        
        # Add generic queries if no pattern-specific ones exist
        if not queries:
            queries = [
                {
                    'method_type': 'Code Analysis',
                    'name': 'Pattern-based code scanning',
                    'description': 'Scan codebase for compliance patterns',
                    'purpose': 'Identify code-level compliance with FedRAMP requirements',
                    'command': 'Run GenericPatternAnalyzer.analyze() across codebase',
                    'evidence_type': 'Analysis results with findings and severities'
                },
                {
                    'method_type': 'IaC Analysis',
                    'name': 'Infrastructure pattern scanning',
                    'description': 'Analyze Bicep/Terraform for infrastructure compliance',
                    'purpose': 'Verify infrastructure meets FedRAMP configuration requirements',
                    'command': 'Analyze *.bicep and *.tf files with pattern analyzer',
                    'evidence_type': 'Infrastructure findings and configuration validation'
                }
            ]
        
        return queries
    
    def get_evidence_artifacts(self, families: Optional[List[str]] = None,
                              frr_id: Optional[str] = None) -> List[dict]:
        """
        Get evidence artifacts for specific patterns.
        
        Args:
            families: Optional list of families to get artifacts for
            frr_id: Optional specific FRR ID to get artifacts for
            
        Returns:
            List of evidence artifact dictionaries with:
            - artifact_name: Name of the artifact
            - artifact_type: Type (log, config, scan, etc.)
            - description: What the artifact contains
            - collection_method: How to collect it
            - storage_location: Where to store it
        """
        patterns = []
        
        if frr_id:
            # Get patterns for specific FRR
            patterns = [p for p in self.pattern_loader._patterns.values() 
                       if frr_id.upper() in [f.upper() for f in p.related_frrs]]
        elif families:
            # Get patterns for families
            for family in families:
                patterns.extend(self.pattern_loader.get_patterns_for_family(family.upper()))
        else:
            # Get all patterns
            patterns = list(self.pattern_loader._patterns.values())
        
        artifacts = []
        seen_artifacts = set()
        
        for pattern in patterns:
            if pattern.evidence_artifacts:
                for artifact in pattern.evidence_artifacts:
                    if isinstance(artifact, dict):
                        artifact_name = artifact.get('artifact_name', artifact.get('name', 'Unknown'))
                        if artifact_name not in seen_artifacts:
                            artifacts.append(artifact)
                            seen_artifacts.add(artifact_name)
                    elif isinstance(artifact, str):
                        if artifact not in seen_artifacts:
                            artifacts.append({
                                'artifact_name': artifact,
                                'artifact_type': 'pattern_evidence',
                                'description': f'Evidence for pattern {pattern.pattern_id}',
                                'collection_method': 'Pattern-based analysis',
                                'storage_location': f'evidence/{pattern.family}/{pattern.pattern_id}'
                            })
                            seen_artifacts.add(artifact)
        
        # Add generic artifacts if none exist
        if not artifacts:
            artifacts = [
                {
                    'artifact_name': 'Pattern Analysis Results',
                    'artifact_type': 'scan_results',
                    'description': 'Findings from pattern-based code analysis',
                    'collection_method': 'GenericPatternAnalyzer.analyze()',
                    'storage_location': 'evidence/analysis_results.json'
                },
                {
                    'artifact_name': 'Compliance Findings Report',
                    'artifact_type': 'report',
                    'description': 'Summary of all compliance findings by severity',
                    'collection_method': 'Aggregate findings from analysis results',
                    'storage_location': 'evidence/compliance_report.json'
                }
            ]
        
        return artifacts
    
    def _get_applicable_patterns(
        self,
        language: str,
        families: Optional[List[str]],
        ksi_ids: Optional[List[str]]
    ) -> List[Pattern]:
        """Get patterns applicable to this analysis."""
        if ksi_ids:
            # Get specific patterns by KSI ID
            patterns = []
            for ksi_id in ksi_ids:
                # Find patterns related to this KSI
                for pattern in self.pattern_loader.get_all_patterns():
                    if ksi_id in pattern.related_ksis:
                        patterns.append(pattern)
            return patterns
        
        if families:
            # Get patterns for specific families
            patterns = []
            for family in families:
                patterns.extend(self.pattern_loader.get_patterns_for_family(family))
            return patterns
        
        # Get all patterns for this language
        return self.pattern_loader.get_patterns_for_language(language)
    
    def _check_pattern(
        self,
        pattern: Pattern,
        code: str,
        language: str,
        file_path: str,
        tree: Any,
        parser: Optional[ASTParser]
    ) -> List[Finding]:
        """Check code against a single pattern."""
        findings: List[Finding] = []
        
        # Get language-specific detection rules
        lang_lower = language.lower()
        if lang_lower not in pattern.languages:
            return findings
        
        lang_config = pattern.languages[lang_lower]
        
        # Try AST queries first (if tree-sitter is available)
        if tree and parser and 'ast_queries' in lang_config:
            ast_findings = self._check_ast_queries(
                pattern, lang_config['ast_queries'], code, tree, parser, file_path
            )
            findings.extend(ast_findings)
        
        # Try regex fallback
        if 'regex_fallback' in lang_config:
            regex_findings = self._check_regex(
                pattern, lang_config['regex_fallback'], code, file_path
            )
            findings.extend(regex_findings)
        
        # Check positive/negative indicators
        # For "missing" patterns with BOTH positive and negative indicators:
        # - positive_indicators = things that trigger the check (e.g., hardcoded secrets)
        # - negative_indicators = things that make it compliant (e.g., proper handling)
        # Only flag if positive exists BUT negative doesn't
        pattern_id = pattern.pattern_id.lower() if hasattr(pattern, 'pattern_id') else ''
        is_missing_pattern = 'missing' in pattern_id
        has_both_indicators = ('positive_indicators' in lang_config and 
                              'negative_indicators' in lang_config)
        
        if has_both_indicators and is_missing_pattern:
            # Check if ANY positive indicator exists
            positive_found = any(
                indicator.lower() in code.lower() 
                for indicator in lang_config['positive_indicators']
            )
            
            # Only check negative indicators if positive was found
            if positive_found:
                # Check if ANY negative indicator exists (would make it compliant)
                negative_found = any(
                    indicator.lower() in code.lower()
                    for indicator in lang_config['negative_indicators']
                )
                
                if not negative_found:
                    # Has the problem (positive) but lacks the fix (negative)
                    findings.append(self._create_finding(
                        pattern, file_path, None, good_practice=False
                    ))
        else:
            # Original logic for patterns without both indicators
            if 'positive_indicators' in lang_config:
                indicator_findings = self._check_indicators(
                    pattern, lang_config['positive_indicators'], code, file_path, positive=True
                )
                findings.extend(indicator_findings)
            
            if 'negative_indicators' in lang_config:
                indicator_findings = self._check_indicators(
                    pattern, lang_config['negative_indicators'], code, file_path, positive=False
                )
                findings.extend(indicator_findings)
        
        return findings
    
    def _check_requires_absence(
        self,
        pattern: Pattern,
        code: str,
        language: str,
        file_path: str,
        tree: Any,
        parser: Optional[ASTParser],
        existing_findings: List[Finding]
    ) -> List[Finding]:
        """
        Check if required patterns are absent.
        
        This is used for patterns like 'missing_machine_readable' that should fire
        when certain other patterns are NOT detected.
        
        Args:
            pattern: Pattern with requires_absence field
            code: Code to analyze
            language: Programming language
            file_path: File path
            tree: AST tree (if available)
            parser: AST parser (if available)
            existing_findings: Findings already detected in this code
            
        Returns:
            List of findings if required patterns are absent
        """
        findings: List[Finding] = []
        
        # Get the pattern IDs that should be absent
        required_absent = pattern.requires_absence if hasattr(pattern, 'requires_absence') else []
        if not required_absent:
            return findings
        
        # Check if any of the required patterns were detected
        detected_pattern_ids = {f.pattern_id for f in existing_findings if hasattr(f, 'pattern_id')}
        
        # If NONE of the required patterns are present, create a finding
        if not any(req_id in detected_pattern_ids for req_id in required_absent):
            findings.append(self._create_finding(
                pattern, file_path, None, None, None, None, good_practice=False
            ))
        
        return findings
    
    def _check_ast_queries(
        self,
        pattern: Pattern,
        ast_queries: List[Dict[str, Any]],
        code: str,
        tree: Any,
        parser: ASTParser,
        file_path: str
    ) -> List[Finding]:
        """Check code using AST queries."""
        findings: List[Finding] = []
        
        code_bytes = bytes(code, "utf8")
        root_node = tree.root_node
        
        for query in ast_queries:
            query_type = query.get('query_type')
            target = query.get('target')
            
            # Skip queries without a target
            if not target:
                continue
            
            if query_type == 'import_statement':
                # Check for imports (both 'import X' and 'from X import Y')
                import_nodes = parser.find_nodes_by_type(root_node, 'import_statement')
                # Also check for 'from X import Y' style imports (import_from_statement)
                import_nodes.extend(parser.find_nodes_by_type(root_node, 'import_from_statement'))
                for node in import_nodes:
                    node_text = parser.get_node_text(node, code_bytes)
                    if target in node_text:
                        findings.append(self._create_finding(pattern, file_path, node, code_bytes))
            
            elif query_type == 'function_call':
                # Check for function calls
                calls = parser.find_function_calls(root_node, [target])
                for func_name, line_num in calls:
                    findings.append(self._create_finding(pattern, file_path, None, code_bytes, line_num))
            
            elif query_type == 'using_directive':
                # C# using directives
                using_nodes = parser.find_nodes_by_type(root_node, 'using_directive')
                for node in using_nodes:
                    node_text = parser.get_node_text(node, code_bytes)
                    if target in node_text:
                        findings.append(self._create_finding(pattern, file_path, node, code_bytes))
            
            elif query_type == 'import_declaration':
                # Java imports
                import_nodes = parser.find_nodes_by_type(root_node, 'import_declaration')
                for node in import_nodes:
                    node_text = parser.get_node_text(node, code_bytes)
                    if target in node_text:
                        findings.append(self._create_finding(pattern, file_path, node, code_bytes))
            
            elif query_type == 'decorator':
                # Python decorators
                decorator_nodes = parser.find_nodes_by_type(root_node, 'decorator')
                for node in decorator_nodes:
                    node_text = parser.get_node_text(node, code_bytes)
                    # Remove @ prefix for comparison if target has it
                    search_target = target.lstrip('@')
                    if search_target in node_text:
                        findings.append(self._create_finding(pattern, file_path, node, code_bytes))
            
            elif query_type == 'resource_type':
                # Bicep/Terraform resource types
                # For Bicep: resource name 'Microsoft.*/***' = {
                # For Terraform: resource "azurerm_***" "name" {
                if re.search(re.escape(target), code, re.IGNORECASE):
                    line_number = code.find(target)
                    if line_number != -1:
                        line_number = code[:line_number].count('\n') + 1
                        findings.append(self._create_finding(pattern, file_path, None, code_bytes, line_number))
        
        return findings
    
    def _check_regex(
        self,
        pattern: Pattern,
        regex_pattern: str,
        code: str,
        file_path: str
    ) -> List[Finding]:
        """Check code using regex pattern."""
        findings: List[Finding] = []
        
        matches = re.finditer(regex_pattern, code, re.IGNORECASE | re.DOTALL)
        for match in matches:
            # Find line number
            line_number = code[:match.start()].count('\n') + 1
            
            findings.append(self._create_finding(
                pattern, file_path, None, line_number, match.group(0)
            ))
        
        return findings
    
    def _check_indicators(
        self,
        pattern: Pattern,
        indicators: List[str],
        code: str,
        file_path: str,
        positive: bool = True
    ) -> List[Finding]:
        """Check for positive/negative indicators.
        
        SEMANTICS:
        - Positive indicators: Their PRESENCE is good (create finding when found)
        - Negative indicators: Depends on pattern type:
          * For "missing_*" patterns: These are REQUIRED things - create finding when ABSENT
          * For other patterns: These are BAD things - create finding when PRESENT
        """
        findings: List[Finding] = []
        
        if positive:
            # Positive indicators - finding them is good
            for indicator in indicators:
                if indicator.lower() in code.lower():
                    # Positive indicator found - this is good practice
                    findings.append(self._create_finding(
                        pattern, file_path, None, good_practice=True
                    ))
        else:
            # Negative indicators - semantics depend on pattern type
            pattern_id = pattern.pattern_id.lower() if hasattr(pattern, 'pattern_id') else ''
            is_missing_pattern = 'missing' in pattern_id or 'absence' in pattern_id
            
            if is_missing_pattern:
                # For "missing_*" patterns: negative_indicators are REQUIRED things
                # Create finding if NONE are present (something is missing)
                any_found = any(indicator.lower() in code.lower() for indicator in indicators)
                
                if not any_found:
                    # None of the required indicators found - this is bad
                    findings.append(self._create_finding(
                        pattern, file_path, None, good_practice=False
                    ))
            else:
                # For detection patterns: negative_indicators are BAD things
                # Create finding if ANY are present
                for indicator in indicators:
                    if indicator.lower() in code.lower():
                        # Negative indicator found - this is bad
                        findings.append(self._create_finding(
                            pattern, file_path, None, good_practice=False
                        ))
        
        return findings
    
    def _create_finding(
        self,
        pattern: Pattern,
        file_path: str,
        node: Any = None,
        code_bytes: Optional[bytes] = None,
        line_number: Optional[int] = None,
        code_snippet: Optional[str] = None,
        good_practice: bool = False
    ) -> Finding:
        """Create a Finding from a pattern match."""
        # Map severity string to enum
        severity_map = {
            'CRITICAL': Severity.CRITICAL,
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFO': Severity.INFO
        }
        severity = severity_map.get(pattern.severity.upper(), Severity.INFO)
        
        # Determine if this is a positive finding
        is_positive = 'positive' in pattern.tags or good_practice
        
        # Extract requirement ID (prefer KSI over FRR)
        requirement_id = None
        if pattern.related_ksis:
            requirement_id = pattern.related_ksis[0]
        elif pattern.related_frrs:
            requirement_id = pattern.related_frrs[0]
        else:
            requirement_id = f"{pattern.family}-{pattern.pattern_id}"
        
        # Get line number from node if available
        if node and hasattr(node, 'start_point'):
            line_number = node.start_point[0] + 1
        
        # Create finding
        return Finding(
            requirement_id=requirement_id,
            severity=severity,
            title=pattern.finding.get('title_template', pattern.name),
            description=pattern.finding.get('description_template', pattern.description),
            file_path=file_path,
            line_number=line_number,
            code_snippet=code_snippet,
            recommendation=pattern.finding.get('remediation_template', ''),
            good_practice=is_positive,
            ksi_id=pattern.related_ksis[0] if pattern.related_ksis else None,
            pattern_id=pattern.pattern_id
        )


# Convenience function for backward compatibility
def analyze_code(
    code: str,
    language: str,
    file_path: str = "",
    families: Optional[List[str]] = None,
    ksi_ids: Optional[List[str]] = None
) -> AnalysisResult:
    """
    Analyze code using generic pattern analyzer.
    
    This is the main entry point for pattern-based analysis.
    
    Args:
        code: Source code to analyze
        language: Programming language
        file_path: Optional file path
        families: Optional list of families to check
        ksi_ids: Optional list of KSI IDs to check
        
    Returns:
        AnalysisResult with findings
    """
    analyzer = GenericPatternAnalyzer()
    return analyzer.analyze(code, language, file_path, families, ksi_ids)
