"""
KSI Analyzer Factory - Pattern-Based Architecture

Uses GenericPatternAnalyzer for all KSI analysis (replaces 72 individual analyzer files).
Provides backward-compatible API while delegating to pattern-driven engine.
"""

import logging
from typing import Dict, Optional, List, Any
from ..base import AnalysisResult
from ..generic_adapter import (
    get_generic_analyzer,
    analyze_with_generic_analyzer,
    get_pattern_statistics,
    get_patterns_for_requirement
)

logger = logging.getLogger(__name__)


class KSIAnalyzerFactory:
    """
    Factory for KSI analysis using GenericPatternAnalyzer.
    
    Provides backward-compatible interface while using pattern-driven architecture.
    All analysis delegated to GenericPatternAnalyzer with 248 loaded patterns.
    """
    
    def __init__(self):
        """Initialize factory with GenericPatternAnalyzer."""
        self._generic_analyzer = None
        logger.info("KSI Factory initialized with pattern-based architecture")
    
    def _ensure_analyzer(self):
        """Lazy-load GenericPatternAnalyzer."""
        if self._generic_analyzer is None:
            self._generic_analyzer = get_generic_analyzer()
    
    def register(self, analyzer):
        """
        Register analyzer (legacy compatibility - no-op).
        
        Args:
            analyzer: Unused (kept for backward compatibility)
        """
        pass  # Pattern-based architecture doesn't need registration
    
    async def sync_with_authoritative_data(self, data_loader) -> Dict[str, Any]:
        """
        Sync with authoritative data (pattern-based - uses pattern metadata).
        
        Args:
            data_loader: DataLoader instance (unused in pattern-based architecture)
            
        Returns:
            Dictionary with sync status
        """
        self._ensure_analyzer()
        stats = await get_pattern_statistics()
        
        return {
            "synced_count": 0,
            "mismatches": [],
            "total_analyzers": stats.get("total_patterns", 0),
            "note": "Pattern-based architecture syncs via pattern files"
        }
    
    def get_analyzer(self, ksi_id: str) -> Optional['PatternBasedAnalyzer']:
        """
        Get analyzer for specific KSI (returns adapter, not traditional analyzer).
        
        Args:
            ksi_id: KSI identifier (e.g., "KSI-IAM-01")
            
        Returns:
            Pattern-based analyzer adapter
        """
        self._ensure_analyzer()
        return PatternBasedAnalyzer(ksi_id, self._generic_analyzer)
    
    def list_ksis(self) -> List[str]:
        """
        List all KSI IDs with available patterns.
        
        Returns:
            List of KSI identifiers
        """
        self._ensure_analyzer()
        # Extract KSI IDs from loaded patterns
        ksi_ids = set()
        for pattern in self._generic_analyzer.pattern_loader._patterns.values():
            # Check ksi_id field
            if hasattr(pattern, 'ksi_id') and pattern.ksi_id and isinstance(pattern.ksi_id, str) and pattern.ksi_id.startswith("KSI-"):
                ksi_ids.add(pattern.ksi_id)
            # Also check related_ksis list
            if hasattr(pattern, 'related_ksis') and pattern.related_ksis:
                for ksi_id in pattern.related_ksis:
                    if isinstance(ksi_id, str) and ksi_id.startswith("KSI-"):
                        ksi_ids.add(ksi_id)
        return sorted(ksi_ids)
    
    async def analyze(self, ksi_id: str, code: str, language: str, file_path: str = "") -> Optional[AnalysisResult]:
        """
        Analyze code for specific KSI using pattern engine.
        
        Args:
            ksi_id: KSI identifier
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            AnalysisResult from pattern matching
        """
        self._ensure_analyzer()
        
        return await analyze_with_generic_analyzer(
            code=code,
            language=language,
            file_path=file_path,
            families=None,
            ksi_ids=[ksi_id]
        )
    
    async def analyze_all_ksis(self, code: str, language: str, file_path: str = "") -> List[AnalysisResult]:
        """
        Analyze code against all KSI patterns.
        
        Args:
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            List of AnalysisResults with findings
        """
        self._ensure_analyzer()
        
        # Analyze with all KSI patterns
        result = await analyze_with_generic_analyzer(
            code=code,
            language=language,
            file_path=file_path,
            families=None,
            ksi_ids=None  # All KSIs
        )
        
        # Return as list for compatibility
        return [result] if result.findings else []
    
    def get_ksi_metadata(self, ksi_id: str) -> Optional[dict]:
        """
        Get metadata for specific KSI from patterns.
        
        Args:
            ksi_id: KSI identifier
            
        Returns:
            KSI metadata dictionary or None
        """
        self._ensure_analyzer()
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        patterns = loop.run_until_complete(get_patterns_for_requirement(ksi_id))
        if patterns:
            return {
                "ksi_id": ksi_id,
                "pattern_count": len(patterns),
                "patterns": patterns
            }
        return None
    
    def get_all_metadata(self) -> List[dict]:
        """
        Get metadata for all KSIs from pattern statistics.
        
        Returns:
            List of metadata dictionaries
        """
        self._ensure_analyzer()
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        stats = loop.run_until_complete(get_pattern_statistics())
        
        # Convert pattern statistics to metadata format
        metadata = []
        for family, count in stats.get("by_family", {}).items():
            metadata.append({
                "family": family,
                "pattern_count": count
            })
        
        return metadata


class PatternBasedAnalyzer:
    """
    Adapter class to provide analyzer-like interface for pattern-based analysis.
    
    Used for backward compatibility with code expecting traditional analyzer objects.
    """
    
    def __init__(self, ksi_id: str, generic_analyzer):
        self.ksi_id = ksi_id
        self._generic_analyzer = generic_analyzer
        self.RETIRED = False  # Default, patterns handle retired status
    
    def analyze(self, code: str, language: str, file_path: str = "") -> AnalysisResult:
        """Analyze using pattern engine."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        return loop.run_until_complete(
            analyze_with_generic_analyzer(
                code=code,
                language=language,
                file_path=file_path,
                families=None,
                ksi_ids=[self.ksi_id]
            )
        )
    
    def get_metadata(self) -> dict:
        """Get metadata from patterns."""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        patterns = loop.run_until_complete(get_patterns_for_requirement(self.ksi_id))
        return {
            "ksi_id": self.ksi_id,
            "pattern_count": len(patterns),
            "retired": self.RETIRED
        }


# Global factory instance
_factory: Optional[KSIAnalyzerFactory] = None


def get_factory() -> KSIAnalyzerFactory:
    """
    Get global KSI analyzer factory instance.
    
    Returns:
        Singleton KSIAnalyzerFactory instance
    """
    global _factory
    if _factory is None:
        _factory = KSIAnalyzerFactory()
    return _factory
