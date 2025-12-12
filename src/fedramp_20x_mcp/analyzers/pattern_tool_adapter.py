"""
Tool adapter for integrating pattern engine with existing analyzer tools.

Provides hybrid analysis combining pattern-based and traditional analyzer approaches.
The pattern engine already returns AnalysisResult with Finding objects, so this
adapter provides a simple interface for tool integration.
"""

import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from .base import AnalysisResult, Finding
from .pattern_engine import PatternEngine
from .pattern_compiler import PatternCompiler


logger = logging.getLogger(__name__)


# Singleton instances
_pattern_engine: Optional[PatternEngine] = None
_pattern_compiler: Optional[PatternCompiler] = None
_patterns_loaded = False


class PatternToolAdapter:
    """
    Adapter for integrating pattern engine with analyzer tools.
    
    Loads patterns from YAML files, compiles them for optimization,
    and provides a unified interface for pattern-based analysis.
    """
    
    def __init__(self, patterns_dir: Optional[Path] = None):
        """
        Initialize pattern tool adapter.
        
        Args:
            patterns_dir: Directory containing pattern YAML files
                         (defaults to data/patterns)
        """
        if patterns_dir is None:
            # Default to data/patterns directory
            module_dir = Path(__file__).parent.parent
            patterns_dir = module_dir.parent.parent / "data" / "patterns"
        
        self.patterns_dir = Path(patterns_dir)
        self.engine: Optional[PatternEngine] = None
        self.compiler: Optional[PatternCompiler] = None
        self.patterns_loaded = False
        
        logger.info(f"Initialized PatternToolAdapter with patterns_dir: {self.patterns_dir}")
    
    def _ensure_loaded(self) -> None:
        """Ensure patterns are loaded (lazy loading)."""
        if self.patterns_loaded:
            return
        
        try:
            # Initialize pattern engine
            self.engine = PatternEngine()
            
            # Load all pattern files
            if not self.patterns_dir.exists():
                logger.warning(f"Patterns directory not found: {self.patterns_dir}")
                self.patterns_loaded = True  # Mark as loaded to avoid repeated attempts
                return
            
            pattern_files = list(self.patterns_dir.glob("*.yaml"))
            logger.info(f"Found {len(pattern_files)} pattern files")
            
            for pattern_file in pattern_files:
                try:
                    count = self.engine.load_patterns(str(pattern_file))
                    logger.info(f"Loaded {count} patterns from {pattern_file.name}")
                except Exception as e:
                    logger.error(f"Failed to load {pattern_file}: {e}")
            
            # Initialize compiler for optimization
            self.compiler = PatternCompiler()
            
            logger.info("Pattern engine initialized successfully")
            
            self.patterns_loaded = True
            
        except Exception as e:
            logger.error(f"Failed to initialize pattern engine: {e}")
            self.patterns_loaded = True  # Mark as loaded to avoid repeated attempts
    
    async def analyze_with_patterns(
        self,
        code: str,
        language: str,
        file_path: Optional[str] = None,
        requirement_id: Optional[str] = None,
        family: Optional[str] = None
    ) -> AnalysisResult:
        """
        Analyze code using pattern engine.
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_path: Optional file path for context
            requirement_id: Optional specific requirement to check
            family: Optional family filter (IAM, MLA, VDR, etc.)
            
        Returns:
            AnalysisResult with findings from pattern engine
        """
        self._ensure_loaded()
        
        # If engine failed to load, return empty result
        if self.engine is None:
            logger.warning("Pattern engine not available, returning empty result")
            return AnalysisResult(
                ksi_id=requirement_id or "PATTERN_ENGINE",
                findings=[],
                files_analyzed=0
            )
        
        try:
            # Run pattern analysis
            result = self.engine.analyze(
                code=code,
                language=language,
                file_path=file_path,
                family=family,
                pattern_ids=[requirement_id] if requirement_id else None
            )
            
            logger.debug(f"Pattern analysis found {len(result.findings)} findings")
            return result
            
        except Exception as e:
            import traceback
            logger.error(f"Pattern analysis failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return AnalysisResult(
                ksi_id=requirement_id or "PATTERN_ENGINE",
                findings=[],
                files_analyzed=0
            )
    
    async def analyze_with_hybrid_approach(
        self,
        code: str,
        language: str,
        file_path: Optional[str] = None,
        traditional_result: Optional[AnalysisResult] = None,
        requirement_id: Optional[str] = None,
        family: Optional[str] = None
    ) -> AnalysisResult:
        """
        Combine pattern-based and traditional analyzer results.
        
        Deduplicates findings and merges results, preferring pattern findings
        when duplicates are detected (faster, clearer source).
        
        Args:
            code: Source code to analyze
            language: Programming language
            file_path: Optional file path
            traditional_result: Optional results from traditional analyzers
            requirement_id: Optional requirement filter
            family: Optional family filter
            
        Returns:
            AnalysisResult with merged findings
        """
        # Get pattern results
        pattern_result = await self.analyze_with_patterns(
            code=code,
            language=language,
            file_path=file_path,
            requirement_id=requirement_id,
            family=family
        )
        
        # If no traditional result, just return pattern result
        if traditional_result is None:
            return pattern_result
        
        # Merge findings with deduplication
        merged_findings = self._merge_findings(
            pattern_result.findings,
            traditional_result.findings
        )
        
        # Create merged result
        return AnalysisResult(
            ksi_id=requirement_id or "HYBRID",
            findings=merged_findings,
            files_analyzed=max(
                pattern_result.files_analyzed,
                traditional_result.files_analyzed
            ),
            metadata={
                "pattern_findings": len(pattern_result.findings),
                "traditional_findings": len(traditional_result.findings),
                "total_findings": len(merged_findings),
                "duplicates_removed": (
                    len(pattern_result.findings) + 
                    len(traditional_result.findings) - 
                    len(merged_findings)
                )
            }
        )
    
    def _merge_findings(
        self,
        pattern_findings: List[Finding],
        traditional_findings: List[Finding]
    ) -> List[Finding]:
        """
        Merge and deduplicate findings.
        
        Strategy:
        - Same requirement_id + similar description = duplicate (keep pattern finding)
        - Different descriptions = both kept (different issues)
        
        Args:
            pattern_findings: Findings from pattern engine
            traditional_findings: Findings from traditional analyzers
            
        Returns:
            Merged list of unique findings
        """
        # Start with pattern findings (pattern engine is primary)
        merged = list(pattern_findings)
        
        # Track what we've seen for deduplication
        seen_keys = set()
        for finding in pattern_findings:
            # Create deduplication key: req_id + first 50 chars of description
            desc_key = finding.description[:50].strip().lower() if finding.description else ""
            req_id = getattr(finding, 'requirement_id', 'UNKNOWN')
            key = (req_id, desc_key)
            seen_keys.add(key)
        
        # Add traditional findings that aren't duplicates
        for finding in traditional_findings:
            desc_key = finding.description[:50].strip().lower() if finding.description else ""
            req_id = getattr(finding, 'requirement_id', 'UNKNOWN')
            key = (req_id, desc_key)
            
            if key not in seen_keys:
                merged.append(finding)
                seen_keys.add(key)
        
        return merged
    
    def get_pattern_coverage(self) -> Dict[str, Any]:
        """
        Get statistics about pattern coverage.
        
        Returns:
            Dictionary with coverage information
        """
        self._ensure_loaded()
        
        if self.engine is None:
            return {
                "total_patterns": 0,
                "families": [],
                "languages": []
            }
        
        # Count patterns by family
        family_counts = {}
        languages = set()
        
        for pattern in self.engine.patterns.values():
            # Count by family
            family = pattern.family
            family_counts[family] = family_counts.get(family, 0) + 1
            
            # Track languages
            languages.update(pattern.languages.keys())
        
        return {
            "total_patterns": len(self.engine.patterns),
            "families": sorted(family_counts.items()),
            "languages": sorted(languages),
            "patterns_by_family": family_counts
        }


# Singleton accessor
_adapter_instance: Optional[PatternToolAdapter] = None


def get_adapter() -> PatternToolAdapter:
    """Get singleton pattern tool adapter instance."""
    global _adapter_instance
    if _adapter_instance is None:
        _adapter_instance = PatternToolAdapter()
    return _adapter_instance


# Convenience functions for tools
async def analyze_with_patterns(
    code: str,
    language: str,
    file_path: Optional[str] = None,
    requirement_id: Optional[str] = None,
    family: Optional[str] = None
) -> AnalysisResult:
    """
    Analyze code using pattern engine (convenience function).
    
    Args:
        code: Source code to analyze
        language: Programming language
        file_path: Optional file path
        requirement_id: Optional requirement filter
        family: Optional family filter
        
    Returns:
        AnalysisResult with findings
    """
    adapter = get_adapter()
    return await adapter.analyze_with_patterns(
        code=code,
        language=language,
        file_path=file_path,
        requirement_id=requirement_id,
        family=family
    )


def get_pattern_coverage() -> Dict[str, Any]:
    """
    Get pattern coverage statistics (convenience function).
    
    Returns:
        Dictionary with coverage information
    """
    adapter = get_adapter()
    return adapter.get_pattern_coverage()
