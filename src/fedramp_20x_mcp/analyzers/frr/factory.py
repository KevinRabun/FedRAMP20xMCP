"""
FRR Analyzer Factory - Pattern-Based Architecture

Uses GenericPatternAnalyzer for all FRR analysis (replaces 199 individual analyzer files).
Provides backward-compatible API while delegating to pattern-driven engine.
"""

import re
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


class FRRAnalyzerFactory:
    """
    Factory for FRR analysis using GenericPatternAnalyzer.
    
    Provides backward-compatible interface while using pattern-driven architecture.
    All analysis delegated to GenericPatternAnalyzer with 248 loaded patterns.
    """
    
    def __init__(self):
        """Initialize factory with GenericPatternAnalyzer."""
        self._generic_analyzer = None
        logger.info("FRR Factory initialized with pattern-based architecture")
    
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
    
    def get_analyzer(self, frr_id: str) -> Optional['PatternBasedFRRAnalyzer']:
        """
        Get analyzer for specific FRR (returns adapter, not traditional analyzer).
        
        Args:
            frr_id: FRR identifier (e.g., "FRR-VDR-01")
            
        Returns:
            Pattern-based analyzer adapter
        """
        self._ensure_analyzer()
        return PatternBasedFRRAnalyzer(frr_id, self._generic_analyzer)
    
    def list_frrs(self) -> List[str]:
        """
        List all FRR IDs with available patterns.
        
        Note: FRR patterns are organized by family, not individual FRR IDs.
        This method returns an empty list. Use list_frrs_by_family() instead or
        get FRRs from FedRAMPDataLoader.
        
        Returns:
            Empty list (FRRs not stored in patterns)
        """
        self._ensure_analyzer()
        # FRR patterns don't have frr_id field - they use family field
        # Return empty list - use data_loader to get actual FRR list
        return []
    
    def list_frrs_by_family(self, family: str) -> List[str]:
        """
        List FRR IDs for a specific family.
        
        Args:
            family: Family code (e.g., "VDR", "RSC", "UCM")
            
        Returns:
            List of FRR identifiers in that family
        """
        all_frrs = self.list_frrs()
        return sorted([
            frr_id for frr_id in all_frrs
            if frr_id.startswith(f"FRR-{family.upper()}-")
        ])
    
    async def analyze(self, frr_id: str, code: str, language: str, file_path: str = "") -> Optional[AnalysisResult]:
        """
        Analyze code for specific FRR using pattern engine.
        
        Args:
            frr_id: FRR identifier
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            AnalysisResult from pattern matching
        """
        self._ensure_analyzer()
        
        # Extract family from FRR ID
        match = re.match(r'FRR-([A-Z]+)-\d+', frr_id)
        families = [match.group(1)] if match else None
        
        return await analyze_with_generic_analyzer(
            code=code,
            language=language,
            file_path=file_path,
            families=families,
            ksi_ids=None  # FRRs use family filtering
        )
    
    async def analyze_all_frrs(self, code: str, language: str, file_path: str = "") -> List[AnalysisResult]:
        """
        Analyze code against all FRR patterns.
        
        Args:
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            List of AnalysisResults with findings
        """
        self._ensure_analyzer()
        
        # Analyze with all FRR patterns
        result = await analyze_with_generic_analyzer(
            code=code,
            language=language,
            file_path=file_path,
            families=None,
            ksi_ids=None
        )
        
        return [result] if result.findings else []
    
    async def analyze_by_family(self, family: str, code: str, language: str, file_path: str = "") -> List[AnalysisResult]:
        """
        Analyze code against all FRRs in a specific family.
        
        Args:
            family: Family code (e.g., "VDR", "RSC", "UCM")
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            List of AnalysisResults for FRRs in that family
        """
        self._ensure_analyzer()
        
        result = await analyze_with_generic_analyzer(
            code=code,
            language=language,
            file_path=file_path,
            families=[family.upper()],
            ksi_ids=None
        )
        
        return [result] if result.findings else []
    
    async def get_frr_metadata(self, frr_id: str) -> Optional[dict]:
        """
        Get metadata for specific FRR from patterns.
        
        Args:
            frr_id: FRR identifier
            
        Returns:
            FRR metadata dictionary or None
        """
        self._ensure_analyzer()
        
        patterns = await get_patterns_for_requirement(frr_id)
        if patterns:
            # Extract family from FRR ID
            match = re.match(r'FRR-([A-Z]+)-\d+', frr_id)
            family = match.group(1) if match else "UNKNOWN"
            
            return {
                "frr_id": frr_id,
                "family": family,
                "pattern_count": len(patterns),
                "patterns": patterns
            }
        return None
    
    def get_all_metadata(self) -> List[dict]:
        """
        Get metadata for all FRRs from pattern statistics.
        
        Returns:
            List of metadata dictionaries
        """
        all_frrs = self.list_frrs()
        return [self.get_frr_metadata(frr_id) for frr_id in all_frrs]
    
    async def get_implementation_status_summary(self) -> Dict[str, Any]:
        """
        Get summary of FRR implementation status from patterns.
        
        Returns:
            Dictionary with implementation statistics
        """
        self._ensure_analyzer()
        
        stats = await get_pattern_statistics()
        
        # Count FRR patterns
        total_frrs = len([p for p in self._generic_analyzer.patterns if hasattr(p, 'frr_id') and p.frr_id and p.frr_id.startswith("FRR-")])
        
        return {
            "total_frrs": total_frrs,
            "total_patterns": stats.get("total_patterns", 0),
            "families": len(stats.get("by_family", {})),
            "languages": len(stats.get("by_language", {})),
            "note": "Pattern-based architecture - implementation tracked via patterns"
        }


class PatternBasedFRRAnalyzer:
    """
    Adapter class to provide analyzer-like interface for FRR pattern-based analysis.
    
    Used for backward compatibility with code expecting traditional analyzer objects.
    """
    
    def __init__(self, frr_id: str, generic_analyzer):
        self.frr_id = frr_id
        self._generic_analyzer = generic_analyzer
        
        # Extract family from FRR ID
        match = re.match(r'FRR-([A-Z]+)-\d+', frr_id)
        self.FAMILY = match.group(1) if match else "UNKNOWN"
        self.FAMILY_NAME = self.FAMILY  # Simplified
        
        # Default attributes for compatibility
        self.frr_name = frr_id
        self.frr_statement = f"Pattern-based analysis for {frr_id}"
        self.IMPACT_LOW = "Unknown"
        self.IMPACT_MODERATE = "Unknown"
        self.NIST_CONTROLS = []
        self.CODE_DETECTABLE = True  # Pattern-based is code-detectable
        self.IMPLEMENTATION_STATUS = "IMPLEMENTED"  # Patterns are implemented
        self.RELATED_KSIS = []
    
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
                families=[self.FAMILY],
                ksi_ids=None
            )
        )


# Global factory instance
_factory: Optional[FRRAnalyzerFactory] = None


def get_factory() -> FRRAnalyzerFactory:
    """
    Get global FRR analyzer factory instance.
    
    Returns:
        Singleton FRRAnalyzerFactory instance
    """
    global _factory
    if _factory is None:
        _factory = FRRAnalyzerFactory()
    return _factory
