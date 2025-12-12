"""
FedRAMP 20x MCP Test Runner

Runs all tests and provides comprehensive reporting.
"""
import sys
import os
import subprocess
from pathlib import Path
from datetime import datetime

# Test files to run
TEST_FILES = [
    "test_data_loader.py",
    "test_cve_fetcher.py",
    "test_pattern_engine.py",
    "test_ksi_analyzers.py",
    "test_frr_analyzers.py",
    "test_mcp_tools.py"
]


def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def check_prerequisites():
    """Check if prerequisites are installed"""
    print_header("Checking Prerequisites")
    
    errors = []
    
    # Check Python version
    if sys.version_info < (3, 10):
        errors.append(f"Python 3.10+ required, found {sys.version}")
    else:
        print(f"[OK] Python version: {sys.version.split()[0]}")
    
    # Check pytest
    try:
        import pytest
        print(f"[OK] pytest installed: {pytest.__version__}")
    except ImportError:
        errors.append("pytest not installed - run: pip install pytest pytest-asyncio")
    
    # Check GitHub token (optional but recommended)
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        print(f"[OK] GITHUB_TOKEN is set")
    else:
        print("[WARN] GITHUB_TOKEN not set - CVE tests may be limited")
        print("      Set token with: $env:GITHUB_TOKEN = (gh auth token)")
    
    # Check if pattern files exist
    pattern_dir = Path(__file__).parent.parent / "data" / "patterns"
    if pattern_dir.exists():
        pattern_count = len(list(pattern_dir.glob("*_patterns.yaml")))
        print(f"[OK] Pattern directory exists with {pattern_count} files")
    else:
        errors.append("Pattern directory not found at data/patterns")
    
    if errors:
        print("\n[ERROR] Prerequisites check failed:")
        for error in errors:
            print(f"  - {error}")
        return False
    
    print("\n[OK] All prerequisites met")
    return True


def run_test_file(test_file):
    """Run a single test file"""
    test_path = Path(__file__).parent / test_file
    
    if not test_path.exists():
        print(f"[SKIP] {test_file} - file not found")
        return None
    
    print(f"\nRunning {test_file}...")
    print("-" * 80)
    
    try:
        # Run pytest with verbose output
        result = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_path), "-v", "--tb=short"],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout per file
        )
        
        # Print output
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(result.stderr)
        
        return result.returncode == 0
        
    except subprocess.TimeoutExpired:
        print(f"[TIMEOUT] {test_file} exceeded 5 minute timeout")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to run {test_file}: {e}")
        return False


def run_all_tests():
    """Run all test files and report results"""
    print_header("FedRAMP 20x MCP Test Suite")
    print(f"Starting test run at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check prerequisites
    if not check_prerequisites():
        print("\n[ABORT] Fix prerequisites before running tests")
        return False
    
    # Run each test file
    print_header("Running Tests")
    
    results = {}
    for test_file in TEST_FILES:
        success = run_test_file(test_file)
        results[test_file] = success
    
    # Print summary
    print_header("Test Summary")
    
    passed = sum(1 for r in results.values() if r is True)
    failed = sum(1 for r in results.values() if r is False)
    skipped = sum(1 for r in results.values() if r is None)
    total = len(results)
    
    print(f"Total test files: {total}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Skipped: {skipped}")
    print()
    
    # Detailed results
    for test_file, success in results.items():
        if success is True:
            print(f"  [PASS] {test_file}")
        elif success is False:
            print(f"  [FAIL] {test_file}")
        else:
            print(f"  [SKIP] {test_file}")
    
    print()
    
    # Overall result
    if failed == 0 and passed > 0:
        print("[SUCCESS] ALL TESTS PASSED")
        print_header("Next Steps")
        print("Tests passed! You can now:")
        print("  1. Commit changes: git add . && git commit -m 'Your message'")
        print("  2. Push to repository: git push")
        return True
    elif failed > 0:
        print("[FAILURE] SOME TESTS FAILED")
        print("\nDo NOT commit until all tests pass!")
        print("Review the output above to fix failing tests.")
        return False
    else:
        print("[WARNING] No tests were run")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
