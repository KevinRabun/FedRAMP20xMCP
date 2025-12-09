"""
KSI Analyzer Factory and Registration System

Automatically discovers and registers all KSI analyzers in the ksi/ directory.
Each KSI analyzer is self-contained with complete language support.
"""

import os
import re
import logging
from pathlib import Path
from importlib import import_module
from typing import Dict, Optional, List, Any
from .base import BaseKSIAnalyzer
from ..base import AnalysisResult

logger = logging.getLogger(__name__)


class KSIAnalyzerFactory:
    """
    Factory for creating and managing KSI analyzers.
    
    Automatically discovers all KSI analyzer classes and provides
    unified interface for analysis across all KSIs.
    """
    
    def __init__(self):
        self._analyzers: Dict[str, BaseKSIAnalyzer] = {}
        self._register_all_analyzers()
    
    def _register_all_analyzers(self):
        """
        Automatically discover and register all KSI analyzers.
        
        Scans the ksi/ directory for files matching ksi_*.py pattern,
        dynamically imports them, and registers the analyzer classes.
        """
        # Get directory containing this factory.py file
        ksi_dir = Path(__file__).parent
        
        # Find all ksi_*.py files (excluding special files)
        ksi_files = sorted([
            f.stem for f in ksi_dir.glob('ksi_*.py')
            if f.stem not in ('ksi_base', '__init__')
        ])
        
        failed_imports = []
        
        # Dynamically import and register each analyzer
        for module_name in ksi_files:
            try:
                # Convert module name to class name (ksi_iam_06 -> KSI_IAM_06_Analyzer)
                class_name = module_name.upper() + '_Analyzer'
                
                # Import module
                module = import_module(f'.{module_name}', package='fedramp_20x_mcp.analyzers.ksi')
                
                # Get analyzer class and instantiate
                analyzer_class = getattr(module, class_name)
                self.register(analyzer_class())
                
            except (ImportError, AttributeError) as e:
                # Log which analyzers failed to load
                failed_imports.append((module_name, str(e)))
                logger.warning(f"Failed to load KSI analyzer {module_name}: {e}")
        
        # Log summary
        logger.info(f"Registered {len(self._analyzers)} KSI analyzers out of {len(ksi_files)} files")
        if failed_imports:
            logger.warning(f"Failed to load {len(failed_imports)} KSI analyzers:")
            for module_name, error in failed_imports:
                logger.warning(f"  - {module_name}: {error}")
    
    def register(self, analyzer: BaseKSIAnalyzer):
        """
        Register a KSI analyzer.
        
        Args:
            analyzer: Instance of BaseKSIAnalyzer subclass
        """
        self._analyzers[analyzer.ksi_id] = analyzer
    
    async def sync_with_authoritative_data(self, data_loader) -> Dict[str, Any]:
        """
        Sync analyzer metadata with authoritative FedRAMP JSON data.
        
        This ensures RETIRED status and other metadata stays accurate
        when the authoritative source is updated.
        
        Args:
            data_loader: DataLoader instance with loaded KSI data
            
        Returns:
            Dictionary with sync results
        """
        await data_loader.load_data()
        
        synced = 0
        mismatches = []
        
        for ksi_id, analyzer in self._analyzers.items():
            ksi_data = data_loader.get_ksi(ksi_id)
            if ksi_data:
                # Check if retired status matches
                retired_in_data = ksi_data.get("retired", False)
                if analyzer.RETIRED != retired_in_data:
                    mismatches.append({
                        "ksi_id": ksi_id,
                        "analyzer_retired": analyzer.RETIRED,
                        "data_retired": retired_in_data
                    })
                    # Update the analyzer's RETIRED status dynamically
                    analyzer.RETIRED = retired_in_data
                    synced += 1
        
        return {
            "synced_count": synced,
            "mismatches": mismatches,
            "total_analyzers": len(self._analyzers)
        }
    
    def get_analyzer(self, ksi_id: str) -> Optional[BaseKSIAnalyzer]:
        """
        Get analyzer for specific KSI.
        
        Args:
            ksi_id: KSI identifier (e.g., "KSI-IAM-06")
            
        Returns:
            KSI analyzer instance or None if not found
        """
        return self._analyzers.get(ksi_id)
    
    def list_ksis(self) -> List[str]:
        """
        List all registered KSI IDs.
        
        Returns:
            List of KSI identifiers
        """
        return sorted(self._analyzers.keys())
    
    def analyze(self, ksi_id: str, code: str, language: str, file_path: str = "") -> Optional[AnalysisResult]:
        """
        Analyze code for specific KSI.
        
        Args:
            ksi_id: KSI identifier
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            AnalysisResult or None if KSI not found
        """
        analyzer = self.get_analyzer(ksi_id)
        if analyzer:
            return analyzer.analyze(code, language, file_path)
        return None
    
    def analyze_all_ksis(self, code: str, language: str, file_path: str = "") -> List[AnalysisResult]:
        """
        Analyze code against all registered KSIs.
        
        Args:
            code: Source code or configuration
            language: Language/framework
            file_path: Optional file path
            
        Returns:
            List of AnalysisResults, one per KSI
        """
        results = []
        for analyzer in self._analyzers.values():
            result = analyzer.analyze(code, language, file_path)
            if result.findings:  # Only include KSIs with findings
                results.append(result)
        return results
    
    def get_ksi_metadata(self, ksi_id: str) -> Optional[dict]:
        """
        Get metadata for specific KSI.
        
        Args:
            ksi_id: KSI identifier
            
        Returns:
            KSI metadata dictionary or None
        """
        analyzer = self.get_analyzer(ksi_id)
        if analyzer:
            return analyzer.get_metadata()
        return None
    
    def get_all_metadata(self) -> List[dict]:
        """
        Get metadata for all registered KSIs.
        
        Returns:
            List of metadata dictionaries
        """
        return [analyzer.get_metadata() for analyzer in self._analyzers.values()]


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
