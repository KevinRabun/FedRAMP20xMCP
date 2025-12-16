#!/usr/bin/env python3
"""
Test pattern language parity across application languages.

Ensures that all patterns with application language implementations have
complete coverage across Python, C#, Java, and TypeScript to prevent
inconsistent compliance checking.
"""

import pytest
import yaml
from pathlib import Path
from typing import Dict, List, Set, Tuple


# Define application languages that MUST have parity
APP_LANGUAGES = {'python', 'csharp', 'java', 'typescript'}

# Infrastructure/platform languages (don't require parity)
INFRA_LANGUAGES = {
    'bicep', 'terraform', 'azure_pipelines', 'github_actions', 
    'gitlab_ci', 'docker', 'dockerfile', 'yaml', 'json', 
    'powershell', 'markdown', 'javascript'  # javascript is separate from typescript
}


def load_all_patterns() -> List[Tuple[str, dict]]:
    """Load all patterns from pattern files."""
    patterns_dir = Path(__file__).parent.parent / 'data' / 'patterns'
    all_patterns = []
    
    for pattern_file in patterns_dir.glob('*_patterns.yaml'):
        with open(pattern_file, 'r', encoding='utf-8') as f:
            # Use safe_load_all to handle multiple documents separated by ---
            try:
                pattern_docs = list(yaml.safe_load_all(f))
                for pattern in pattern_docs:
                    if pattern and isinstance(pattern, dict):
                        all_patterns.append((pattern_file.name, pattern))
            except yaml.YAMLError as e:
                print(f"Warning: Error loading {pattern_file.name}: {e}")
                continue
    
    return all_patterns


def get_app_languages_in_pattern(pattern: dict) -> Set[str]:
    """Get application languages defined in a pattern."""
    languages = pattern.get('languages', {})
    return set(languages.keys()) & APP_LANGUAGES


def get_all_languages_in_pattern(pattern: dict) -> Set[str]:
    """Get all languages defined in a pattern."""
    languages = pattern.get('languages', {})
    return set(languages.keys())


class TestPatternLanguageParity:
    """Test suite for pattern language parity."""
    
    def test_app_language_parity_complete(self):
        """
        CRITICAL: All patterns with app languages must have ALL 4 app languages.
        
        This test prevents the issue where some patterns only had Python/C# but
        not Java/TypeScript, causing inconsistent compliance checking across
        different technology stacks.
        """
        patterns = load_all_patterns()
        gaps = []
        
        for file_name, pattern in patterns:
            pattern_id = pattern.get('pattern_id', 'UNKNOWN')
            app_langs = get_app_languages_in_pattern(pattern)
            
            # Skip patterns with no app languages (infra-only patterns)
            if not app_langs:
                continue
            
            # If pattern has ANY app language, it must have ALL app languages
            missing_langs = APP_LANGUAGES - app_langs
            if missing_langs:
                gaps.append({
                    'file': file_name,
                    'pattern_id': pattern_id,
                    'has_languages': sorted(app_langs),
                    'missing_languages': sorted(missing_langs)
                })
        
        # Format error message
        if gaps:
            error_msg = "\n\nAPP LANGUAGE PARITY VIOLATIONS:\n"
            error_msg += "=" * 70 + "\n"
            error_msg += f"Found {len(gaps)} patterns with incomplete app language coverage.\n"
            error_msg += "All patterns must have Python, C#, Java, AND TypeScript.\n\n"
            
            for gap in gaps:
                error_msg += f"File: {gap['file']}\n"
                error_msg += f"  Pattern: {gap['pattern_id']}\n"
                error_msg += f"  Has: {', '.join(gap['has_languages'])}\n"
                error_msg += f"  Missing: {', '.join(gap['missing_languages'])}\n\n"
            
            error_msg += "Fix: Add missing language implementations to achieve parity.\n"
            error_msg += "=" * 70 + "\n"
            
            pytest.fail(error_msg)
    
    def test_app_language_counts_match(self):
        """
        Verify that all 4 app languages have identical pattern counts.
        
        This is a sanity check - if Python has 60 patterns, C#/Java/TypeScript
        should also have exactly 60 patterns.
        """
        patterns = load_all_patterns()
        language_counts = {lang: 0 for lang in APP_LANGUAGES}
        
        for _, pattern in patterns:
            app_langs = get_app_languages_in_pattern(pattern)
            for lang in app_langs:
                language_counts[lang] += 1
        
        # Check if all counts are equal
        counts = list(language_counts.values())
        if len(set(counts)) > 1:
            error_msg = "\n\nAPP LANGUAGE COUNT MISMATCH:\n"
            error_msg += "=" * 70 + "\n"
            for lang in sorted(APP_LANGUAGES):
                error_msg += f"  {lang}: {language_counts[lang]} patterns\n"
            error_msg += "\nAll app languages must have identical pattern counts.\n"
            error_msg += "=" * 70 + "\n"
            pytest.fail(error_msg)
    
    def test_no_mixed_javascript_typescript(self):
        """
        Ensure patterns use TypeScript (not JavaScript) for app code.
        
        JavaScript is used for package.json analysis (infrastructure),
        but TypeScript should be used for application code patterns.
        """
        patterns = load_all_patterns()
        violations = []
        
        for file_name, pattern in patterns:
            pattern_id = pattern.get('pattern_id', 'UNKNOWN')
            all_langs = get_all_languages_in_pattern(pattern)
            app_langs = get_app_languages_in_pattern(pattern)
            
            # If pattern has app languages AND javascript, that's suspicious
            if app_langs and 'javascript' in all_langs:
                # Allow javascript ONLY if it's for dependency file analysis
                lang_config = pattern.get('languages', {}).get('javascript', {})
                file_path = lang_config.get('file_path', '')
                
                # javascript is OK for package.json, node_modules, etc.
                if 'package.json' not in file_path.lower():
                    violations.append({
                        'file': file_name,
                        'pattern_id': pattern_id,
                        'issue': 'Uses JavaScript instead of TypeScript for app code'
                    })
        
        if violations:
            error_msg = "\n\nJAVASCRIPT/TYPESCRIPT USAGE VIOLATIONS:\n"
            error_msg += "=" * 70 + "\n"
            for v in violations:
                error_msg += f"File: {v['file']}\n"
                error_msg += f"  Pattern: {v['pattern_id']}\n"
                error_msg += f"  Issue: {v['issue']}\n\n"
            error_msg += "Use TypeScript for app code, JavaScript only for dependency files.\n"
            error_msg += "=" * 70 + "\n"
            pytest.fail(error_msg)
    
    def test_pattern_language_structure_consistency(self):
        """
        Verify that app languages in the same pattern have similar structure.
        
        All app languages should have either regex_fallback or ast_queries,
        not a mix where some have advanced features and others are bare minimum.
        """
        patterns = load_all_patterns()
        inconsistencies = []
        
        for file_name, pattern in patterns:
            pattern_id = pattern.get('pattern_id', 'UNKNOWN')
            app_langs = get_app_languages_in_pattern(pattern)
            
            if len(app_langs) < 2:
                continue
            
            languages = pattern.get('languages', {})
            
            # Check if all app languages have similar structural elements
            has_ast = {lang: 'ast_queries' in languages[lang] for lang in app_langs}
            has_regex = {lang: 'regex_fallback' in languages[lang] for lang in app_langs}
            has_positive = {lang: 'positive_indicators' in languages[lang] for lang in app_langs}
            has_negative = {lang: 'negative_indicators' in languages[lang] for lang in app_langs}
            
            # If structure is inconsistent across languages
            if len(set(has_ast.values())) > 1 or \
               len(set(has_regex.values())) > 1 or \
               len(set(has_positive.values())) > 1 or \
               len(set(has_negative.values())) > 1:
                
                structure_info = {}
                for lang in sorted(app_langs):
                    structure_info[lang] = {
                        'has_ast': has_ast[lang],
                        'has_regex': has_regex[lang],
                        'has_positive': has_positive[lang],
                        'has_negative': has_negative[lang]
                    }
                
                inconsistencies.append({
                    'file': file_name,
                    'pattern_id': pattern_id,
                    'structure': structure_info
                })
        
        if inconsistencies:
            error_msg = "\n\nPATTERN STRUCTURE INCONSISTENCIES:\n"
            error_msg += "=" * 70 + "\n"
            error_msg += f"Found {len(inconsistencies)} patterns with inconsistent language structures.\n\n"
            
            for inc in inconsistencies:
                error_msg += f"File: {inc['file']}\n"
                error_msg += f"  Pattern: {inc['pattern_id']}\n"
                for lang, struct in inc['structure'].items():
                    error_msg += f"    {lang}: AST={struct['has_ast']}, Regex={struct['has_regex']}, "
                    error_msg += f"Positive={struct['has_positive']}, Negative={struct['has_negative']}\n"
                error_msg += "\n"
            
            error_msg += "Consider: All app languages should have similar detection capabilities.\n"
            error_msg += "=" * 70 + "\n"
            pytest.fail(error_msg)
    
    def test_expected_pattern_count_minimum(self):
        """
        Verify minimum expected pattern count to catch regressions.
        
        As of this test creation, we have 60 patterns per app language.
        This test will fail if patterns are accidentally removed.
        """
        patterns = load_all_patterns()
        language_counts = {lang: 0 for lang in APP_LANGUAGES}
        
        for _, pattern in patterns:
            app_langs = get_app_languages_in_pattern(pattern)
            for lang in app_langs:
                language_counts[lang] += 1
        
        # Minimum expected (based on current state: 60 patterns per language)
        MIN_EXPECTED = 60
        
        for lang in APP_LANGUAGES:
            assert language_counts[lang] >= MIN_EXPECTED, \
                f"{lang} has only {language_counts[lang]} patterns, expected at least {MIN_EXPECTED}. " \
                f"Patterns may have been accidentally removed or lost language implementations."


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
