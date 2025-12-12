"""
Debug AFR pattern detection

Tests individual pattern regex/AST queries to identify matching issues.
"""

import re
import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

# Test code samples
BICEP_TLS_WEAK = '''
resource storageAccountWeak 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'weakstorageacct'
  properties: {
    minimumTlsVersion: 'TLS1_0'
  }
}
'''

BICEP_HTTPS_DISABLED = '''
resource storageInsecure 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  properties: {
    supportsHttpsTrafficOnly: false
  }
}
'''

BICEP_DEBUG_MODE = '''
resource appServiceDebug 'Microsoft.Web/sites@2023-01-01' = {
  properties: {
    siteConfig: {
      appSettings: [
        {
          name: 'ASPNETCORE_ENVIRONMENT'
          value: 'Development'
        }
      ]
    }
  }
}
'''

PYTHON_MD5 = '''
import hashlib
def hash_password_weak(password):
    hash_obj = hashlib.md5(password.encode())
    return hash_obj.hexdigest()
'''

PYTHON_DEBUG = '''
from flask import Flask
app = Flask(__name__)
app.debug = True
'''

def test_regex_pattern(pattern: str, code: str, description: str):
    """Test if a regex pattern matches code."""
    print(f"\nTesting: {description}")
    print(f"Pattern: {pattern}")
    print(f"Code snippet: {code[:100]}...")
    
    match = re.search(pattern, code, re.IGNORECASE | re.MULTILINE)
    if match:
        print(f"[PASS] MATCH FOUND: {match.group()}")
        return True
    else:
        print("[FAIL] NO MATCH")
        return False

def main():
    print("=" * 60)
    print("AFR PATTERN DEBUGGING")
    print("=" * 60)
    
    # Test 1: Bicep TLS 1.0 detection
    print("\n" + "=" * 60)
    print("TEST 1: Bicep TLS 1.0 Detection")
    print("=" * 60)
    
    # Pattern from afr_patterns.yaml (bicep section)
    # Looking for minimumTlsVersion: 'TLS1_0' or 'TLS1_1'
    bicep_tls_pattern = r"minimumTlsVersion['\"]?\s*[:=]\s*['\"]?(TLS1_0|TLS1_1)"
    test_regex_pattern(bicep_tls_pattern, BICEP_TLS_WEAK, "Bicep TLS 1.0")
    
    # Test 2: Bicep HTTPS disabled
    print("\n" + "=" * 60)
    print("TEST 2: Bicep HTTPS Disabled")
    print("=" * 60)
    
    bicep_https_pattern = r"supportsHttpsTrafficOnly['\"]?\s*[:=]\s*false"
    test_regex_pattern(bicep_https_pattern, BICEP_HTTPS_DISABLED, "Bicep HTTPS disabled")
    
    # Test 3: Bicep debug mode
    print("\n" + "=" * 60)
    print("TEST 3: Bicep Debug Mode")
    print("=" * 60)
    
    bicep_debug_pattern = r"name['\"]?\s*[:=]\s*['\"]ASPNETCORE_ENVIRONMENT['\"].*?value['\"]?\s*[:=]\s*['\"]Development['\"]"
    test_regex_pattern(bicep_debug_pattern, BICEP_DEBUG_MODE, "Bicep debug mode")
    
    # Test 4: Python MD5
    print("\n" + "=" * 60)
    print("TEST 4: Python MD5 Detection")
    print("=" * 60)
    
    # Pattern from afr_patterns.yaml (python section)
    python_md5_pattern = r"hashlib\.(md5|sha1|md4)"
    test_regex_pattern(python_md5_pattern, PYTHON_MD5, "Python MD5")
    
    # Test 5: Python debug mode
    print("\n" + "=" * 60)
    print("TEST 5: Python Debug Mode")
    print("=" * 60)
    
    python_debug_pattern = r"(debug\s*=\s*True|DEBUG\s*=\s*True|app\.debug\s*=\s*True)"
    test_regex_pattern(python_debug_pattern, PYTHON_DEBUG, "Python debug mode")
    
    # Now test actual pattern engine
    print("\n" + "=" * 60)
    print("PATTERN ENGINE TEST")
    print("=" * 60)
    
    from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine
    
    engine = PatternEngine()
    
    # Load AFR patterns
    afr_file = Path(__file__).parent.parent / 'data' / 'patterns' / 'afr_patterns.yaml'
    if afr_file.exists():
        count = engine.load_patterns(str(afr_file))
        print(f"\nLoaded {count} AFR patterns from {afr_file.name}")
        
        # List loaded patterns
        afr_patterns = {k: v for k, v in engine.patterns.items() if k.startswith('afr.')}
        print(f"\nAFR patterns loaded:")
        for pattern_id in afr_patterns.keys():
            print(f"  - {pattern_id}")
        
        # Test each pattern
        print("\n" + "=" * 60)
        print("TESTING LOADED PATTERNS")
        print("=" * 60)
        
        # Test Bicep TLS
        print("\nTesting afr.crypto.weak_algorithms on Bicep TLS code...")
        result = engine.analyze(BICEP_TLS_WEAK, "bicep", "test.bicep")
        print(f"Findings: {len(result.findings)}")
        if result.findings:
            for finding in result.findings:
                print(f"  - {finding.title}")
                print(f"    Pattern: {finding.requirement_id}")
                print(f"    Severity: {finding.severity.value}")
        
        # Test Python MD5
        print("\nTesting afr.crypto.weak_algorithms on Python MD5 code...")
        result = engine.analyze(PYTHON_MD5, "python", "test.py")
        print(f"Findings: {len(result.findings)}")
        if result.findings:
            for finding in result.findings:
                print(f"  - {finding.title}")
                print(f"    Pattern: {finding.requirement_id}")
                print(f"    Severity: {finding.severity.value}")
        
        # Test Python debug
        print("\nTesting afr.config.debug_mode on Python debug code...")
        result = engine.analyze(PYTHON_DEBUG, "python", "test.py")
        print(f"Findings: {len(result.findings)}")
        if result.findings:
            for finding in result.findings:
                print(f"  - {finding.title}")
                print(f"    Pattern: {finding.requirement_id}")
                print(f"    Severity: {finding.severity.value}")
    else:
        print(f"AFR patterns file not found: {afr_file}")
    
    print("\n" + "=" * 60)
    print("DEBUG COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
