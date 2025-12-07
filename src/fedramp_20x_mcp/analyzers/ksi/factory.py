"""
KSI Analyzer Factory and Registration System

Automatically discovers and registers all KSI analyzers in the ksi/ directory.
Each KSI analyzer is self-contained with complete language support.
"""

from typing import Dict, Optional, List
from .base import BaseKSIAnalyzer
from ..base import AnalysisResult


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
        
        Dynamically imports all KSI analyzer modules and registers them.
        """
        # All 72 KSI analyzer modules
        ksi_modules = [
            'ksi_afr_01', 'ksi_afr_02', 'ksi_afr_03', 'ksi_afr_04', 'ksi_afr_05',
            'ksi_afr_06', 'ksi_afr_07', 'ksi_afr_08', 'ksi_afr_09', 'ksi_afr_10',
            'ksi_afr_11', 'ksi_ced_01', 'ksi_ced_02', 'ksi_ced_03', 'ksi_ced_04',
            'ksi_cmt_01', 'ksi_cmt_02', 'ksi_cmt_03', 'ksi_cmt_04', 'ksi_cmt_05',
            'ksi_cna_01', 'ksi_cna_02', 'ksi_cna_03', 'ksi_cna_04', 'ksi_cna_05',
            'ksi_cna_06', 'ksi_cna_07', 'ksi_cna_08', 'ksi_iam_01', 'ksi_iam_02',
            'ksi_iam_03', 'ksi_iam_04', 'ksi_iam_05', 'ksi_iam_06', 'ksi_iam_07',
            'ksi_inr_01', 'ksi_inr_02', 'ksi_inr_03', 'ksi_mla_01', 'ksi_mla_02',
            'ksi_mla_03', 'ksi_mla_04', 'ksi_mla_05', 'ksi_mla_06', 'ksi_mla_07',
            'ksi_mla_08', 'ksi_piy_01', 'ksi_piy_02', 'ksi_piy_03', 'ksi_piy_04',
            'ksi_piy_05', 'ksi_piy_06', 'ksi_piy_07', 'ksi_piy_08', 'ksi_rpl_01',
            'ksi_rpl_02', 'ksi_rpl_03', 'ksi_rpl_04', 'ksi_svc_01', 'ksi_svc_02',
            'ksi_svc_03', 'ksi_svc_04', 'ksi_svc_05', 'ksi_svc_06', 'ksi_svc_07',
            'ksi_svc_08', 'ksi_svc_09', 'ksi_svc_10', 'ksi_tpr_01', 'ksi_tpr_02',
            'ksi_tpr_03', 'ksi_tpr_04',
        ]
        
        # Dynamically import and register each analyzer
        for module_name in ksi_modules:
            try:
                # Convert module name to class name (ksi_iam_06 -> KSI_IAM_06_Analyzer)
                class_name = module_name.upper() + '_Analyzer'
                
                # Import module using importlib
                from importlib import import_module
                module = import_module(f'.{module_name}', package='fedramp_20x_mcp.analyzers.ksi')
                
                # Get analyzer class and instantiate
                analyzer_class = getattr(module, class_name)
                self.register(analyzer_class())
                
            except (ImportError, AttributeError) as e:
                # Skip if module or class not found (shouldn't happen with generated files)
                pass
    
    def register(self, analyzer: BaseKSIAnalyzer):
        """
        Register a KSI analyzer.
        
        Args:
            analyzer: Instance of BaseKSIAnalyzer subclass
        """
        self._analyzers[analyzer.ksi_id] = analyzer
    
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
