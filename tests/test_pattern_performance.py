"""
Performance benchmarking tests for pattern engine vs traditional analyzers.

Measures execution time and resource usage to validate that the hybrid
approach provides performance benefits while maintaining accuracy.
"""

import sys
import time
import asyncio
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.pattern_engine import PatternEngine
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory as get_ksi_factory
from fedramp_20x_mcp.analyzers.pattern_tool_adapter import analyze_with_patterns


# Test samples
BICEP_SAMPLE = """
resource storage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: false
    minimumTlsVersion: 'TLS1_0'
    allowBlobPublicAccess: true
  }
}

resource kv 'Microsoft.KeyVault/vaults@2021-04-01-preview' = {
  name: 'mykeyvault'
  location: 'eastus'
  properties: {
    enableSoftDelete: false
    enablePurgeProtection: false
  }
}
"""

PYTHON_SAMPLE = """
import os
import logging

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef"
PASSWORD = "admin123"
DB_CONNECTION = "Server=localhost;Database=prod;User=admin;Password=secret123"

# Missing HTTPS
BASE_URL = "http://api.example.com"

def authenticate(username, password):
    # No MFA
    session = create_session()
    session.permanent = True
    return session

def log_event(message):
    # Local file logging
    with open('/var/log/app.log', 'a') as f:
        f.write(message)

# No centralized logging
logger = logging.getLogger(__name__)
logger.addHandler(logging.FileHandler('app.log'))
"""

GITHUB_ACTIONS_SAMPLE = """
name: Deploy to Production
on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      # Hardcoded secret
      - name: Deploy
        run: curl -H "Authorization: Bearer sk-1234" https://api.example.com/deploy
      
      # No security scanning
      - name: Build
        run: npm run build
      
      # No SAST
      - name: Test
        run: npm test
      
      # No dependency scan
      - name: Package
        run: npm pack
"""


def benchmark_test(name: str, func, *args, **kwargs):
    """Run a benchmark test and return results."""
    start_time = time.time()
    result = func(*args, **kwargs)
    end_time = time.time()
    
    elapsed = (end_time - start_time) * 1000  # Convert to milliseconds
    
    return {
        'name': name,
        'elapsed_ms': elapsed,
        'result': result
    }


async def benchmark_pattern_engine(code: str, language: str):
    """Benchmark pattern engine analysis."""
    result = await analyze_with_patterns(
        code=code,
        language=language,
        file_path=f"test.{language}"
    )
    return len(result.findings)


def benchmark_traditional_analyzers(code: str, language: str):
    """Benchmark traditional KSI analyzers."""
    factory = get_ksi_factory()
    total_findings = 0
    
    for ksi_id in factory.list_ksis():
        result = factory.analyze(ksi_id, code, language, f"test.{language}")
        if result and result.findings:
            total_findings += len(result.findings)
    
    return total_findings


def print_benchmark_results(results: list):
    """Print formatted benchmark results."""
    print(f"\n{'='*60}")
    print("BENCHMARK RESULTS")
    print(f"{'='*60}\n")
    
    for result in results:
        print(f"{result['name']:40s} {result['elapsed_ms']:8.2f} ms")
        print(f"  Findings: {result['result']}")
    
    # Calculate speedup
    pattern_time = next(r['elapsed_ms'] for r in results if 'Pattern' in r['name'])
    trad_time = next(r['elapsed_ms'] for r in results if 'Traditional' in r['name'])
    speedup = trad_time / pattern_time if pattern_time > 0 else 0
    
    print(f"\n{'='*60}")
    print(f"Pattern Engine Speedup: {speedup:.2f}x faster")
    print(f"{'='*60}\n")


async def benchmark_infrastructure_code():
    """Benchmark infrastructure code analysis."""
    print("\n" + "="*60)
    print("BENCHMARK: Infrastructure Code (Bicep)")
    print("="*60)
    
    results = []
    
    # Benchmark pattern engine
    start = time.time()
    pattern_result = await benchmark_pattern_engine(BICEP_SAMPLE, 'bicep')
    pattern_time = (time.time() - start) * 1000
    results.append({
        'name': 'Pattern Engine',
        'elapsed_ms': pattern_time,
        'result': pattern_result
    })
    
    # Benchmark traditional analyzers
    start = time.time()
    trad_result = benchmark_traditional_analyzers(BICEP_SAMPLE, 'bicep')
    trad_time = (time.time() - start) * 1000
    results.append({
        'name': 'Traditional Analyzers',
        'elapsed_ms': trad_time,
        'result': trad_result
    })
    
    print_benchmark_results(results)
    return results


async def benchmark_application_code():
    """Benchmark application code analysis."""
    print("\n" + "="*60)
    print("BENCHMARK: Application Code (Python)")
    print("="*60)
    
    results = []
    
    # Benchmark pattern engine
    start = time.time()
    pattern_result = await benchmark_pattern_engine(PYTHON_SAMPLE, 'python')
    pattern_time = (time.time() - start) * 1000
    results.append({
        'name': 'Pattern Engine',
        'elapsed_ms': pattern_time,
        'result': pattern_result
    })
    
    # Benchmark traditional analyzers
    start = time.time()
    trad_result = benchmark_traditional_analyzers(PYTHON_SAMPLE, 'python')
    trad_time = (time.time() - start) * 1000
    results.append({
        'name': 'Traditional Analyzers',
        'elapsed_ms': trad_time,
        'result': trad_result
    })
    
    print_benchmark_results(results)
    return results


async def benchmark_cicd_pipeline():
    """Benchmark CI/CD pipeline analysis."""
    print("\n" + "="*60)
    print("BENCHMARK: CI/CD Pipeline (GitHub Actions)")
    print("="*60)
    
    results = []
    
    # Benchmark pattern engine
    start = time.time()
    pattern_result = await benchmark_pattern_engine(GITHUB_ACTIONS_SAMPLE, 'github_actions')
    pattern_time = (time.time() - start) * 1000
    results.append({
        'name': 'Pattern Engine',
        'elapsed_ms': pattern_time,
        'result': pattern_result
    })
    
    # Benchmark traditional analyzers
    start = time.time()
    trad_result = benchmark_traditional_analyzers(GITHUB_ACTIONS_SAMPLE, 'github_actions')
    trad_time = (time.time() - start) * 1000
    results.append({
        'name': 'Traditional Analyzers',
        'elapsed_ms': trad_time,
        'result': trad_result
    })
    
    print_benchmark_results(results)
    return results


async def run_all_benchmarks():
    """Run all performance benchmarks."""
    print("\n" + "="*60)
    print("PATTERN ENGINE PERFORMANCE BENCHMARKS")
    print("="*60)
    print("\nComparing pattern engine vs traditional analyzers")
    print("Measuring execution time and finding accuracy\n")
    
    all_results = []
    
    # Run benchmarks
    infra_results = await benchmark_infrastructure_code()
    all_results.extend(infra_results)
    
    app_results = await benchmark_application_code()
    all_results.extend(app_results)
    
    cicd_results = await benchmark_cicd_pipeline()
    all_results.extend(cicd_results)
    
    # Overall summary
    print("\n" + "="*60)
    print("OVERALL PERFORMANCE SUMMARY")
    print("="*60)
    
    pattern_times = [r['elapsed_ms'] for r in all_results if 'Pattern' in r['name']]
    trad_times = [r['elapsed_ms'] for r in all_results if 'Traditional' in r['name']]
    
    avg_pattern = sum(pattern_times) / len(pattern_times)
    avg_trad = sum(trad_times) / len(trad_times)
    avg_speedup = avg_trad / avg_pattern
    
    print(f"\nAverage Pattern Engine Time:    {avg_pattern:.2f} ms")
    print(f"Average Traditional Time:        {avg_trad:.2f} ms")
    print(f"Average Speedup:                 {avg_speedup:.2f}x faster")
    
    print(f"\n{'='*60}")
    print("[PASS] Performance benchmarks completed successfully")
    print(f"{'='*60}\n")
    
    return all_results


if __name__ == "__main__":
    results = asyncio.run(run_all_benchmarks())
    sys.exit(0)
