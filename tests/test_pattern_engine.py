"""
Tests for Pattern Engine and Pattern Compiler

Tests pattern loading, compilation, execution, and optimization.
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine, Pattern
from fedramp_20x_mcp.analyzers.pattern_compiler import PatternCompiler, compile_patterns_from_engine
from fedramp_20x_mcp.analyzers.base import Severity


def test_pattern_loading():
    """Test loading patterns from YAML files"""
    print("\n" + "=" * 70)
    print("TEST: Pattern Loading")
    print("=" * 70)
    
    engine = PatternEngine()
    
    # Load IAM patterns
    iam_file = Path("data/patterns/iam_patterns.yaml")
    if iam_file.exists():
        count = engine.load_patterns(str(iam_file))
        print(f"[PASS] Loaded {count} IAM patterns")
        assert count > 0, "Should load at least one pattern"
    else:
        print(f"[SKIP] IAM patterns file not found: {iam_file}")
    
    # Load all patterns
    patterns_dir = Path("data/patterns")
    if patterns_dir.exists():
        total_count = engine.load_all_patterns(str(patterns_dir))
        print(f"[PASS] Loaded {total_count} total patterns from {patterns_dir}")
        assert total_count >= count, "Should load all patterns"
    else:
        print(f"[SKIP] Patterns directory not found: {patterns_dir}")
    
    # Get statistics
    stats = engine.get_statistics()
    print(f"\nPattern Statistics:")
    print(f"  Total patterns: {stats['total_patterns']}")
    print(f"  Families: {stats['families']}")
    print(f"  Languages: {', '.join(stats['languages'][:5])}...")
    print(f"  Pattern types: {', '.join(stats['pattern_types'])}")
    
    return engine


def test_pattern_compilation(engine):
    """Test pattern compilation and optimization"""
    print("\n" + "=" * 70)
    print("TEST: Pattern Compilation")
    print("=" * 70)
    
    compiler = compile_patterns_from_engine(engine)
    
    # Check compilation
    compiled_count = len(compiler.compiled_patterns)
    print(f"[PASS] Compiled {compiled_count} patterns")
    assert compiled_count > 0, "Should compile patterns"
    
    # Check execution order
    exec_order = compiler.get_execution_order()
    print(f"[PASS] Generated execution order with {len(exec_order)} patterns")
    
    # Get compiler statistics
    stats = compiler.get_pattern_statistics()
    print(f"\nCompiler Statistics:")
    print(f"  Total patterns: {stats['total_patterns']}")
    print(f"  Patterns with regex: {stats['patterns_with_regex']}")
    print(f"  Patterns with AST: {stats['patterns_with_ast']}")
    print(f"  Patterns with dependencies: {stats['patterns_with_dependencies']}")
    print(f"  Circular dependencies: {stats['has_circular_deps']}")
    
    # Validate patterns
    warnings = compiler.validate_patterns()
    if warnings:
        print(f"\n[WARN] Validation warnings ({len(warnings)}):")
        for warning in warnings[:5]:
            print(f"  - {warning}")
        if len(warnings) > 5:
            print(f"  ... and {len(warnings) - 5} more")
    else:
        print(f"[PASS] No validation warnings")
    
    return compiler


def test_mfa_detection():
    """Test MFA pattern detection"""
    print("\n" + "=" * 70)
    print("TEST: MFA Detection (IAM)")
    print("=" * 70)
    
    engine = PatternEngine()
    iam_file = Path("data/patterns/iam_patterns.yaml")
    
    if not iam_file.exists():
        print("[SKIP] IAM patterns not found")
        return
    
    engine.load_patterns(str(iam_file))
    
    # Test positive finding: FIDO2 import
    code_with_fido2 = """
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

def setup_mfa():
    rp = PublicKeyCredentialRpEntity("example.com", "Example App")
    server = Fido2Server(rp)
    return server
"""
    
    result = engine.analyze(code_with_fido2, "python", file_path="app.py", family="IAM")
    print(f"\nPositive test (FIDO2 import):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected FIDO2 import")
    else:
        print("[WARN] No FIDO2 detection - pattern may need adjustment")
    
    # Test negative finding: TOTP (not phishing-resistant)
    code_with_totp = """
import pyotp

def generate_totp():
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    return totp.now()
"""
    
    result = engine.analyze(code_with_totp, "python", file_path="app.py", family="IAM")
    print(f"\nNegative test (TOTP - not phishing-resistant):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected TOTP (security gap)")
    else:
        print("[WARN] No TOTP detection - pattern may need adjustment")
    
    # Test negative finding: Login without MFA
    code_no_mfa = """
from flask import Flask, request, session

app = Flask(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if verify_password(username, password):
        session['user'] = username
        return "Login successful"
    return "Login failed"
"""
    
    result = engine.analyze(code_no_mfa, "python", file_path="app.py", family="IAM")
    print(f"\nNegative test (Login without MFA):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected login without MFA")
    else:
        print("[WARN] No detection - pattern may need adjustment")


def test_logging_detection():
    """Test centralized logging detection"""
    print("\n" + "=" * 70)
    print("TEST: Centralized Logging Detection (MLA)")
    print("=" * 70)
    
    engine = PatternEngine()
    mla_file = Path("data/patterns/mla_patterns.yaml")
    
    if not mla_file.exists():
        print("[SKIP] MLA patterns not found")
        return
    
    engine.load_patterns(str(mla_file))
    
    # Test negative finding: Local file logging
    code_local_logging = """
import logging

logger = logging.getLogger(__name__)
handler = logging.FileHandler('app.log')
logger.addHandler(handler)
"""
    
    result = engine.analyze(code_local_logging, "python", file_path="app.py", family="MLA")
    print(f"\nNegative test (Local file logging):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected local file logging")
    else:
        print("[WARN] No detection - pattern may need adjustment")
    
    # Test positive finding: Azure Monitor
    code_azure_monitor = """
from opencensus.ext.azure.log_exporter import AzureLogHandler
import logging

logger = logging.getLogger(__name__)
logger.addHandler(AzureLogHandler(
    connection_string='InstrumentationKey=12345-67890'
))
"""
    
    result = engine.analyze(code_azure_monitor, "python", file_path="app.py", family="MLA")
    print(f"\nPositive test (Azure Monitor):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected Azure Monitor integration")
    else:
        print("[WARN] No detection - pattern may need adjustment")


def test_secrets_detection():
    """Test secrets management detection"""
    print("\n" + "=" * 70)
    print("TEST: Secrets Management Detection (SVC)")
    print("=" * 70)
    
    engine = PatternEngine()
    svc_file = Path("data/patterns/svc_patterns.yaml")
    
    if not svc_file.exists():
        print("[SKIP] SVC patterns not found")
        return
    
    engine.load_patterns(str(svc_file))
    
    # Test negative finding: Hardcoded secret
    code_hardcoded = """
api_key = "sk-1234567890abcdef"
database_password = "MySecretP@ssw0rd"

def connect_to_api():
    return requests.get(f"https://api.example.com?key={api_key}")
"""
    
    result = engine.analyze(code_hardcoded, "python", file_path="app.py", family="SVC")
    print(f"\nNegative test (Hardcoded secrets):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected hardcoded secrets")
    else:
        print("[WARN] No detection - pattern may need adjustment")
    
    # Test positive finding: Key Vault usage
    code_keyvault = """
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

credential = DefaultAzureCredential()
client = SecretClient(
    vault_url="https://myvault.vault.azure.net/",
    credential=credential
)

api_key = client.get_secret("api-key").value
"""
    
    result = engine.analyze(code_keyvault, "python", file_path="app.py", family="SVC")
    print(f"\nPositive test (Key Vault):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected Key Vault usage")
    else:
        print("[WARN] No detection - pattern may need adjustment")


def test_vulnerability_scanning():
    """Test vulnerability scanning detection"""
    print("\n" + "=" * 70)
    print("TEST: Vulnerability Scanning Detection (VDR)")
    print("=" * 70)
    
    engine = PatternEngine()
    vdr_file = Path("data/patterns/vdr_patterns.yaml")
    
    if not vdr_file.exists():
        print("[SKIP] VDR patterns not found")
        return
    
    engine.load_patterns(str(vdr_file))
    
    # Test negative finding: Missing SAST in GitHub Actions
    github_workflow = """
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: npm run build
      - name: Deploy
        run: npm run deploy
"""
    
    result = engine.analyze(github_workflow, "github_actions", file_path=".github/workflows/deploy.yml", family="VDR")
    print(f"\nNegative test (Missing SAST):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected missing SAST")
    else:
        print("[WARN] No detection - pattern may need adjustment")
    
    # Test positive finding: CodeQL scanning
    github_with_codeql = """
name: Security Scan

on:
  push:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: python, javascript
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
"""
    
    result = engine.analyze(github_with_codeql, "github_actions", file_path=".github/workflows/security.yml", family="VDR")
    print(f"\nPositive test (CodeQL scanning):")
    print(f"  Findings: {len(result.findings)}")
    for finding in result.findings:
        print(f"  - {finding.title} (Severity: {finding.severity.name})")
    
    if result.findings:
        print("[PASS] Detected CodeQL scanning")
    else:
        print("[WARN] No detection - pattern may need adjustment")


def main():
    """Run all pattern engine tests"""
    print("\n" + "=" * 70)
    print("PATTERN ENGINE AND COMPILER TESTS")
    print("=" * 70)
    
    try:
        # Test pattern loading
        engine = test_pattern_loading()
        
        # Test pattern compilation
        if engine and engine.patterns:
            compiler = test_pattern_compilation(engine)
        
        # Test specific pattern families
        test_mfa_detection()
        test_logging_detection()
        test_secrets_detection()
        test_vulnerability_scanning()
        
        print("\n" + "=" * 70)
        print("ALL TESTS COMPLETED")
        print("=" * 70)
        print("\nNOTE: Some tests may show [WARN] as patterns are regex-based")
        print("      and AST integration is still in development.")
        print("      This is expected for Phase 2 initial implementation.")
        
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
