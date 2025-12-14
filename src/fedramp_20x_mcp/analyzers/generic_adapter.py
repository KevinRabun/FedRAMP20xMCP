"""
Integration layer for GenericPatternAnalyzer with existing MCP tools.

This module provides a bridge between the new GenericPatternAnalyzer (Phase 3)
and the existing tool infrastructure, allowing gradual migration from traditional
analyzers to pattern-driven analysis.
"""

import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

from .base import AnalysisResult, Finding
from .generic_analyzer import GenericPatternAnalyzer, PatternLoader, analyze_code

logger = logging.getLogger(__name__)

# Singleton instances for performance
_generic_analyzer: Optional[GenericPatternAnalyzer] = None
_pattern_loader: Optional[PatternLoader] = None


def get_generic_analyzer() -> GenericPatternAnalyzer:
    """
    Get singleton GenericPatternAnalyzer instance.
    
    Patterns are loaded once and cached for all subsequent analyses.
    
    Returns:
        GenericPatternAnalyzer instance with patterns loaded
    """
    global _generic_analyzer, _pattern_loader
    
    if _generic_analyzer is None:
        logger.info("Initializing GenericPatternAnalyzer singleton")
        _pattern_loader = PatternLoader()
        _pattern_loader.load_patterns()
        
        pattern_count = len(_pattern_loader.get_all_patterns())
        logger.info(f"Loaded {pattern_count} patterns")
        
        _generic_analyzer = GenericPatternAnalyzer(_pattern_loader)
    
    return _generic_analyzer


async def analyze_with_generic_analyzer(
    code: str,
    language: str,
    file_path: Optional[str] = None,
    families: Optional[List[str]] = None,
    ksi_ids: Optional[List[str]] = None
) -> AnalysisResult:
    """
    Analyze code using GenericPatternAnalyzer.
    
    This is the primary entry point for pattern-based analysis using
    the new generic analyzer architecture from Phase 3.
    
    Args:
        code: Source code to analyze
        language: Programming language (python, csharp, java, typescript, bicep, terraform, etc.)
        file_path: Optional file path for context
        families: Optional list of families to check (e.g., ['IAM', 'SCN'])
        ksi_ids: Optional list of specific KSI IDs to check
        
    Returns:
        AnalysisResult with findings from pattern matching
        
    Example:
        >>> result = await analyze_with_generic_analyzer(
        ...     code="import fido2",
        ...     language="python",
        ...     families=["IAM"]
        ... )
        >>> print(f"Found {len(result.findings)} findings")
    """
    try:
        analyzer = get_generic_analyzer()
        
        # Synchronous analyze call (no await needed)
        result = analyzer.analyze(
            code=code,
            language=language,
            file_path=file_path or "",
            families=families,
            ksi_ids=ksi_ids
        )
        
        logger.debug(f"Generic analyzer found {len(result.findings)} findings")
        return result
        
    except Exception as e:
        logger.error(f"Generic analyzer failed: {e}", exc_info=True)
        # Return empty result on error
        return AnalysisResult(findings=[])


async def get_pattern_statistics() -> Dict[str, Any]:
    """
    Get statistics about loaded patterns.
    
    Returns:
        Dictionary with pattern statistics:
        - total_patterns: Total number of patterns loaded
        - by_family: Count of patterns per family
        - by_language: Count of patterns per language
        - by_severity: Count of patterns per severity level
        - by_type: Count of patterns per pattern type
    """
    try:
        analyzer = get_generic_analyzer()
        loader = analyzer.pattern_loader
        
        all_patterns = loader.get_all_patterns()
        
        # Count by family
        by_family: Dict[str, int] = {}
        for pattern in all_patterns:
            by_family[pattern.family] = by_family.get(pattern.family, 0) + 1
        
        # Count by language
        by_language: Dict[str, int] = {}
        for pattern in all_patterns:
            for lang in pattern.languages.keys():
                by_language[lang] = by_language.get(lang, 0) + 1
        
        # Count by severity
        by_severity: Dict[str, int] = {}
        for pattern in all_patterns:
            severity = pattern.severity.upper()
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Count by type
        by_type: Dict[str, int] = {}
        for pattern in all_patterns:
            ptype = pattern.pattern_type
            by_type[ptype] = by_type.get(ptype, 0) + 1
        
        return {
            "total_patterns": len(all_patterns),
            "by_family": by_family,
            "by_language": by_language,
            "by_severity": by_severity,
            "by_type": by_type,
            "families": sorted(by_family.keys()),
            "languages": sorted(by_language.keys()),
            "severity_levels": sorted(by_severity.keys())
        }
        
    except Exception as e:
        logger.error(f"Failed to get pattern statistics: {e}", exc_info=True)
        return {
            "total_patterns": 0,
            "error": str(e)
        }


async def get_patterns_for_requirement(
    requirement_id: str
) -> List[Dict[str, Any]]:
    """
    Get all patterns related to a specific requirement (KSI or FRR).
    
    Args:
        requirement_id: KSI or FRR ID (e.g., 'KSI-IAM-01', 'FRR-ADS-01')
        
    Returns:
        List of pattern dictionaries with metadata
    """
    try:
        analyzer = get_generic_analyzer()
        loader = analyzer.pattern_loader
        
        all_patterns = loader.get_all_patterns()
        
        # Find patterns related to this requirement
        related_patterns = []
        for pattern in all_patterns:
            if (requirement_id in pattern.related_ksis or 
                requirement_id in pattern.related_frrs):
                related_patterns.append({
                    "pattern_id": pattern.pattern_id,
                    "name": pattern.name,
                    "description": pattern.description,
                    "family": pattern.family,
                    "severity": pattern.severity,
                    "pattern_type": pattern.pattern_type,
                    "languages": list(pattern.languages.keys()),
                    "tags": pattern.tags,
                    "nist_controls": pattern.nist_controls
                })
        
        return related_patterns
        
    except Exception as e:
        logger.error(f"Failed to get patterns for requirement {requirement_id}: {e}", exc_info=True)
        return []


async def validate_pattern_coverage(
    families: Optional[List[str]] = None,
    languages: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Validate pattern coverage for specified families and languages.
    
    Args:
        families: Optional list of families to check
        languages: Optional list of languages to check
        
    Returns:
        Dictionary with coverage information:
        - total_requirements: Total requirements in families
        - covered_requirements: Requirements with patterns
        - uncovered_requirements: Requirements without patterns
        - coverage_percentage: Coverage percentage
        - patterns_per_family: Pattern counts per family
    """
    try:
        analyzer = get_generic_analyzer()
        loader = analyzer.pattern_loader
        
        all_patterns = loader.get_all_patterns()
        
        # Filter patterns
        if families:
            patterns = [p for p in all_patterns if p.family in families]
        else:
            patterns = all_patterns
        
        if languages:
            patterns = [p for p in patterns if any(lang in p.languages for lang in languages)]
        
        # Count coverage
        covered_ksis = set()
        covered_frrs = set()
        
        for pattern in patterns:
            covered_ksis.update(pattern.related_ksis)
            covered_frrs.update(pattern.related_frrs)
        
        patterns_per_family = {}
        for pattern in patterns:
            patterns_per_family[pattern.family] = patterns_per_family.get(pattern.family, 0) + 1
        
        return {
            "total_patterns": len(patterns),
            "covered_ksis": sorted(covered_ksis),
            "covered_frrs": sorted(covered_frrs),
            "ksi_count": len(covered_ksis),
            "frr_count": len(covered_frrs),
            "patterns_per_family": patterns_per_family,
            "filters": {
                "families": families,
                "languages": languages
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to validate pattern coverage: {e}", exc_info=True)
        return {
            "error": str(e)
        }


# Backward compatibility aliases
analyze_with_patterns = analyze_with_generic_analyzer
get_pattern_coverage = get_pattern_statistics
