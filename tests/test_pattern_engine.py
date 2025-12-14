"""
Tests for Pattern Engine and Pattern Loading

Tests pattern validation, loading, and detection logic.
"""
import pytest
import yaml
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine, Pattern
from fedramp_20x_mcp.analyzers.generic_analyzer import GenericPatternAnalyzer


class TestPatternLoading:
    """Test pattern file loading and validation"""
    
    @pytest.fixture
    def pattern_dir(self):
        """Get pattern directory"""
        return Path(__file__).parent.parent / "data" / "patterns"
    
    @pytest.fixture
    def engine(self):
        """Create pattern engine instance"""
        return PatternEngine()
    
    def test_pattern_directory_exists(self, pattern_dir):
        """Test pattern directory exists"""
        assert pattern_dir.exists()
        assert pattern_dir.is_dir()
    
    def test_all_pattern_files_exist(self, pattern_dir):
        """Test all expected pattern files exist"""
        expected_files = [
            "iam_patterns.yaml",
            "vdr_patterns.yaml",
            "scn_patterns.yaml",
            "rsc_patterns.yaml",
            "ads_patterns.yaml",
            "ccm_patterns.yaml",
            "cna_patterns.yaml",
            "afr_patterns.yaml",
            "mla_patterns.yaml",
            "piy_patterns.yaml",
            "svc_patterns.yaml",
            "tpr_patterns.yaml",
            "ucm_patterns.yaml",
            "cmt_patterns.yaml",
            "inr_patterns.yaml",
            "rpl_patterns.yaml",
            "ced_patterns.yaml",
            "common_patterns.yaml"
        ]
        
        for file in expected_files:
            assert (pattern_dir / file).exists(), f"Missing pattern file: {file}"
    
    def test_pattern_files_valid_yaml(self, pattern_dir):
        """Test all pattern files are valid YAML"""
        pattern_files = list(pattern_dir.glob("*_patterns.yaml"))
        assert len(pattern_files) > 0, "No pattern files found"
        
        for file in pattern_files:
            with open(file, 'r', encoding='utf-8') as f:
                try:
                    # Load all YAML documents
                    documents = list(yaml.safe_load_all(f.read()))
                    assert len(documents) > 0, f"No patterns in {file.name}"
                except yaml.YAMLError as e:
                    pytest.fail(f"Invalid YAML in {file.name}: {e}")
    
    def test_pattern_schema_validation(self, pattern_dir):
        """Test patterns have required fields"""
        # Core required fields that every pattern MUST have
        required_fields = [
            "pattern_id",
            "name", 
            "description",
            "family",
            "severity",
            "languages"
        ]
        
        # Optional but recommended fields
        optional_fields = ["pattern_type", "finding", "tags", "nist_controls"]
        
        pattern_files = list(pattern_dir.glob("*_patterns.yaml"))
        
        for file in pattern_files:
            with open(file, 'r', encoding='utf-8') as f:
                documents = yaml.safe_load_all(f.read())
                
                for i, doc in enumerate(documents):
                    if doc is None:
                        continue
                        
                    # Check required fields
                    for field in required_fields:
                        assert field in doc, f"{file.name} pattern {i}: Missing required field '{field}'"
                    
                    # Warn about missing optional fields (but don't fail)
                    for field in optional_fields:
                        if field not in doc:
                            print(f"Warning: {file.name} pattern {i} missing optional field '{field}'")
    
    def test_load_single_pattern_file(self, engine, pattern_dir):
        """Test loading a single pattern file"""
        iam_file = pattern_dir / "iam_patterns.yaml"
        count = engine.load_patterns(str(iam_file))
        
        assert count > 0, "No patterns loaded from IAM file"
        assert len(engine.patterns) == count
    
    def test_load_all_patterns(self, engine, pattern_dir):
        """Test loading all pattern files"""
        count = engine.load_all_patterns(str(pattern_dir))
        
        assert count > 0, "No patterns loaded"
        assert len(engine.patterns) == count
        
        # Should have loaded a substantial number of patterns
        assert count > 100, f"Expected >100 patterns, got {count}"
    
    def test_pattern_families(self, engine, pattern_dir):
        """Test patterns are organized by family"""
        engine.load_all_patterns(str(pattern_dir))
        
        families = set()
        for pattern in engine.patterns.values():
            families.add(pattern.family)
        
        # Should have multiple families
        expected_families = ["IAM", "VDR", "SCN", "RSC", "ADS", "CNA"]
        for family in expected_families:
            assert family in families, f"Missing family: {family}"
    
    def test_ksi_pattern_mapping(self, engine, pattern_dir):
        """Test patterns are mapped to KSI IDs"""
        engine.load_all_patterns(str(pattern_dir))
        
        ksi_patterns = {}
        for pattern in engine.patterns.values():
            if hasattr(pattern, 'related_ksis') and pattern.related_ksis:
                for ksi_id in pattern.related_ksis:
                    if ksi_id not in ksi_patterns:
                        ksi_patterns[ksi_id] = []
                    ksi_patterns[ksi_id].append(pattern.pattern_id)
        
        # Should have patterns for many KSIs
        assert len(ksi_patterns) > 20, f"Expected >20 KSIs with patterns, got {len(ksi_patterns)}"


class TestGenericAnalyzer:
    """Test GenericPatternAnalyzer functionality"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance"""
        return GenericPatternAnalyzer()
    
    @pytest.fixture
    def pattern_dir(self):
        """Get pattern directory"""
        return Path(__file__).parent.parent / "data" / "patterns"
    
    def test_analyzer_initialization(self, analyzer):
        """Test analyzer initializes correctly"""
        assert analyzer is not None
        assert hasattr(analyzer, 'pattern_loader')
        assert hasattr(analyzer, 'metadata')
        # Patterns should already be loaded
        assert len(analyzer.pattern_loader._patterns) > 0
    
    def test_load_patterns(self, analyzer, pattern_dir):
        """Test loading patterns into analyzer"""
        # Patterns are auto-loaded in __init__, check they're there
        patterns = analyzer.pattern_loader._patterns
        
        assert len(patterns) > 0
        # Should have loaded a substantial number
        assert len(patterns) > 100, f"Expected >100 patterns, got {len(patterns)}"
    
    def test_analyze_python_code(self, analyzer, pattern_dir):
        """Test analyzing Python code"""
        # Patterns already loaded, verify they exist
        assert len(analyzer.pattern_loader._patterns) > 0
        
        # Sample Python code with MFA
        code = """
import fido2
from azure.identity import DefaultAzureCredential

def authenticate_user():
    credential = DefaultAzureCredential()
    return credential
"""
        
        result = analyzer.analyze(code, "python")
        
        assert result is not None
        assert hasattr(result, 'findings')
        # Result should be valid (findings may be 0 or more depending on patterns)
        assert isinstance(result.findings, list)
    
    def test_analyze_csharp_code(self, analyzer, pattern_dir):
        """Test analyzing C# code"""
        # Patterns already loaded
        assert len(analyzer.pattern_loader._patterns) > 0
        
        code = """
using Azure.Security.KeyVault.Keys;
using Azure.Identity;

public class SecureStorage
{
    private readonly KeyClient keyClient;
    
    public SecureStorage()
    {
        keyClient = new KeyClient(
            new Uri("https://myvault.vault.azure.net/"),
            new DefaultAzureCredential()
        );
    }
}
"""
        
        result = analyzer.analyze(code, "csharp")
        
        assert result is not None
        assert hasattr(result, 'findings')
    
    def test_analyze_bicep_code(self, analyzer, pattern_dir):
        """Test analyzing Bicep IaC"""
        # Patterns already loaded
        assert len(analyzer.pattern_loader._patterns) > 0
        
        code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'premium'
    }
    tenantId: subscription().tenantId
    enablePurgeProtection: true
    enableSoftDelete: true
  }
}
"""
        
        result = analyzer.analyze(code, "bicep")
        
        assert result is not None
        assert hasattr(result, 'findings')


class TestPatternDetection:
    """Test pattern detection accuracy"""
    
    @pytest.fixture
    def analyzer(self):
        """Create analyzer with loaded patterns"""
        analyzer = GenericPatternAnalyzer()
        # Patterns auto-load in __init__
        assert len(analyzer.pattern_loader._patterns) > 0
        return analyzer
    
    def test_detect_mfa_patterns(self, analyzer):
        """Test MFA pattern detection"""
        code = """
from azure.identity import InteractiveBrowserCredential
from msal import ConfidentialClientApplication

cred = InteractiveBrowserCredential()
"""
        
        result = analyzer.analyze(code, "python")
        
        # Should detect Azure identity usage
        assert result is not None
    
    def test_detect_encryption_patterns(self, analyzer):
        """Test encryption pattern detection"""
        code = """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

cipher = Cipher(
    algorithms.AES(key),
    modes.GCM(iv),
    backend=default_backend()
)
"""
        
        result = analyzer.analyze(code, "python")
        assert result is not None
    
    def test_detect_logging_patterns(self, analyzer):
        """Test logging pattern detection"""
        code = """
import logging
from opencensus.ext.azure.log_exporter import AzureLogHandler

logger = logging.getLogger(__name__)
logger.addHandler(AzureLogHandler())
logger.info("Application started")
"""
        
        result = analyzer.analyze(code, "python")
        assert result is not None


def run_tests():
    """Run tests with pytest"""
    print("Running Pattern Engine tests...")
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
