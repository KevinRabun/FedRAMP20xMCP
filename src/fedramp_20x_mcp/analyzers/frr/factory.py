"""
FRR Analyzer Factory and Registration System

Automatically discovers and registers all FRR analyzers in the frr/ directory.
Each FRR analyzer is self-contained with complete language support.
"""

import os
import re
import logging
from pathlib import Path
from importlib import import_module
from typing import Dict, Optional, List, Any
from .base import BaseFRRAnalyzer
from ..base import AnalysisResult

logger = logging.getLogger(__name__)


class FRRAnalyzerFactory:
    """
    Factory for creating and managing FRR analyzers.
    
    Automatically discovers all FRR analyzer classes and provides
    unified interface for analysis across all FRRs.
    """
    
    def __init__(self):
        self._analyzers: Dict[str, BaseFRRAnalyzer] = {}
        self._register_all_analyzers()
    
    def _register_all_analyzers(self):
        """
        Automatically discover and register all FRR analyzers.
        
        Scans the frr/ directory for files matching frr_*.py pattern,
        dynamically imports them, and registers the analyzer classes.
        """
        # Get directory containing this factory.py file
        frr_dir = Path(__file__).parent
        
        # Find all frr_*.py files (excluding special files)
        frr_files = sorted([
            f.stem for f in frr_dir.glob('frr_*.py')
            if f.stem not in ('frr_base', '__init__')
        ])
        
        failed_imports = []
        
        # Dynamically import and register each analyzer
        for module_name in frr_files:
            try:
                # Convert module name to class name (frr_vdr_01 -> FRR_VDR_01_Analyzer)
                class_name = module_name.upper() + '_Analyzer'
                
                # Import module
                module = import_module(f'.{module_name}', package='fedramp_20x_mcp.analyzers.frr')
                
                # Get analyzer class and instantiate
                analyzer_class = getattr(module, class_name)
                self.register(analyzer_class())
                
            except (ImportError, AttributeError) as e:
                # Log which analyzers failed to load
                failed_imports.append((module_name, str(e)))
                logger.warning(f"Failed to load FRR analyzer {module_name}: {e}")
        
        # Log summary
        logger.info(f"Registered {len(self._analyzers)} FRR analyzers out of {len(frr_files)} files")
        if failed_imports:
            logger.warning(f"Failed to load {len(failed_imports)} FRR analyzers:")
            for module_name, error in failed_imports:
                logger.warning(f"  - {module_name}: {error}")
    
    def register(self, analyzer: BaseFRRAnalyzer):
        """
        Register an FRR analyzer.
        
        Args:
            analyzer: Instance of BaseFRRAnalyzer subclass
        """
        self._analyzers[analyzer.frr_id] = analyzer
    
    async def sync_with_authoritative_data(self, data_loader) -> Dict[str, Any]:
        """
        Sync analyzer metadata with authoritative FedRAMP JSON data.
        
        This ensures requirement statements and metadata stay accurate
        when the authoritative source is updated.
        
        Args:
            data_loader: DataLoader instance with loaded FRR data
            
        Returns:
            Dictionary with sync results
        """
        await data_loader.load_data()
        
        synced = 0
        mismatches = []
        
        for frr_id, analyzer in self._analyzers.items():
            # Extract family from FRR ID (e.g., "FRR-VDR-01" -> "VDR")
            match = re.match(r'FRR-([A-Z]+)-\d+', frr_id)
            if match:
                family = match.group(1)
                # Get requirement from data loader
                requirements = data_loader.get_requirements_by_family(family)
                frr_data = next((r for r in requirements if r.get("id") == frr_id), None)
                
                if frr_data:
                    # Check if statement matches
                    statement_in_data = frr_data.get("statement", "")
                    if analyzer.FRR_STATEMENT != statement_in_data:
                        mismatches.append({
                            "frr_id": frr_id,
                            "analyzer_statement": analyzer.FRR_STATEMENT[:100] + "...",
                            "data_statement": statement_in_data[:100] + "..."
                        })
                        # Update the analyzer's statement dynamically
                        analyzer.FRR_STATEMENT = statement_in_data
                        synced += 1
        
        return {
            "synced_count": synced,
            "mismatches": mismatches,
            "total_analyzers": len(self._analyzers)
        }
    
    def get_analyzer(self, frr_id: str) -> Optional[BaseFRRAnalyzer]:
        """
        Get analyzer for specific FRR.
        
        Args:
            frr_id: FRR identifier (e.g., "FRR-VDR-01")
            
        Returns:
            FRR analyzer instance or None if not found
        """
        return self._analyzers.get(frr_id)
    
    def list_frrs(self) -> List[str]:
        """
        List all registered FRR IDs.
        
        Returns:
            List of FRR identifiers
        """
        return sorted(self._analyzers.keys())
    
    def list_frrs_by_family(self, family: str) -> List[str]:
        """
        List FRR IDs for a specific family.
        
        Args:
            family: Family code (e.g., "VDR", "RSC", "UCM")
            
        Returns:
            List of FRR identifiers in that family
        """
        return sorted([
            frr_id for frr_id in self._analyzers.keys()
            if frr_id.startswith(f"FRR-{family.upper()}-")
        ])
    
    def analyze(self, frr_id: str, code: str, language: str, file_path: str = "") -> Optional[AnalysisResult]:
        """
        Analyze code for specific FRR.
        
        Args:
            frr_id: FRR identifier
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            AnalysisResult or None if FRR not found
        """
        analyzer = self.get_analyzer(frr_id)
        if analyzer:
            return analyzer.analyze(code, language, file_path)
        return None
    
    def analyze_all_frrs(self, code: str, language: str, file_path: str = "") -> List[AnalysisResult]:
        """
        Analyze code against all registered FRRs.
        
        Args:
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            List of AnalysisResults, one per FRR with findings
        """
        results = []
        for analyzer in self._analyzers.values():
            result = analyzer.analyze(code, language, file_path)
            if result.findings:  # Only include FRRs with findings
                results.append(result)
        return results
    
    def analyze_by_family(self, family: str, code: str, language: str, file_path: str = "") -> List[AnalysisResult]:
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
        results = []
        for frr_id in self.list_frrs_by_family(family):
            analyzer = self.get_analyzer(frr_id)
            if analyzer:
                result = analyzer.analyze(code, language, file_path)
                if result.findings:
                    results.append(result)
        return results
    
    def get_frr_metadata(self, frr_id: str) -> Optional[dict]:
        """
        Get metadata for specific FRR.
        
        Args:
            frr_id: FRR identifier
            
        Returns:
            FRR metadata dictionary or None
        """
        analyzer = self.get_analyzer(frr_id)
        if analyzer:
            return {
                "frr_id": analyzer.frr_id,
                "frr_name": analyzer.frr_name,
                "frr_statement": analyzer.frr_statement,
                "family": analyzer.FAMILY,
                "family_name": analyzer.FAMILY_NAME,
                "impact_low": analyzer.IMPACT_LOW,
                "impact_moderate": analyzer.IMPACT_MODERATE,
                "nist_controls": analyzer.NIST_CONTROLS,
                "code_detectable": analyzer.CODE_DETECTABLE,
                "implementation_status": analyzer.IMPLEMENTATION_STATUS,
                "related_ksis": analyzer.RELATED_KSIS
            }
        return None
    
    def get_all_metadata(self) -> List[dict]:
        """
        Get metadata for all registered FRRs.
        
        Returns:
            List of metadata dictionaries
        """
        return [self.get_frr_metadata(frr_id) for frr_id in self.list_frrs()]
    
    def get_implementation_status_summary(self) -> Dict[str, Any]:
        """
        Get summary of FRR implementation status.
        
        Returns:
            Dictionary with implementation statistics
        """
        total = len(self._analyzers)
        implemented = sum(1 for a in self._analyzers.values() if a.IMPLEMENTATION_STATUS == "IMPLEMENTED")
        partial = sum(1 for a in self._analyzers.values() if a.IMPLEMENTATION_STATUS == "PARTIAL")
        not_implemented = sum(1 for a in self._analyzers.values() if a.IMPLEMENTATION_STATUS == "NOT_IMPLEMENTED")
        code_detectable = sum(1 for a in self._analyzers.values() if a.CODE_DETECTABLE)
        
        return {
            "total_frrs": total,
            "implemented": implemented,
            "partial": partial,
            "not_implemented": not_implemented,
            "code_detectable": code_detectable,
            "implementation_rate": round((implemented / total * 100), 2) if total > 0 else 0.0
        }


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
