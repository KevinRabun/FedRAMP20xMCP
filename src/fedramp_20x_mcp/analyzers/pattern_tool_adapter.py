"""
Tool adapter for integrating pattern engine with existing analyzer tools.

Provides hybrid analysis combining pattern-based and traditional analyzer approaches.
Updated to use GenericPatternAnalyzer from Phase 3 refactoring.
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from .base import AnalysisResult, Finding
from .generic_adapter import (
    analyze_with_generic_analyzer,
    get_pattern_statistics,
    get_patterns_for_requirement,
    validate_pattern_coverage
)


logger = logging.getLogger(__name__)


async def analyze_with_patterns(
    code: str,
    language: str,
    file_path: Optional[str] = None,
    requirement_id: Optional[str] = None,
    family: Optional[str] = None
) -> AnalysisResult:
    """
    Analyze code using pattern engine (GenericPatternAnalyzer).
    
    Args:
        code: Source code to analyze
        language: Programming language
        file_path: Optional file path for context
        requirement_id: Optional specific requirement to check (KSI or FRR ID)
        family: Optional family filter (IAM, MLA, VDR, etc.)
        
    Returns:
        AnalysisResult with findings from pattern engine
    """
    # Convert parameters to match GenericPatternAnalyzer API
    families = [family] if family else None
    ksi_ids = [requirement_id] if requirement_id else None
    
    return await analyze_with_generic_analyzer(
        code=code,
        language=language,
        file_path=file_path,
        families=families,
        ksi_ids=ksi_ids
    )


async def get_pattern_coverage() -> Dict[str, Any]:
    """
    Get pattern coverage statistics.
    
    Returns:
        Dictionary with pattern statistics and coverage information
    """
    return await get_pattern_statistics()
