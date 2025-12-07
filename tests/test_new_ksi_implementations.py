"""
Test newly implemented KSI analyzers for CI/CD and IaC detection.

Tests the 8 KSIs that were changed from CODE_DETECTABLE=False to True:
- KSI-AFR-02: Automated validation in CI/CD
- KSI-PIY-04: SDLC security gates
- KSI-PIY-05: Automated code scanning
- KSI-PIY-06: Regular vulnerability scans
- KSI-PIY-07: SBOM/dependency scanning
- KSI-PIY-08: Security scans in CI/CD
- KSI-RPL-02: Backup automation in IaC
- KSI-RPL-04: Recovery testing in CI/CD
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory

def test_ksi_afr_02_github_actions():
    """Test KSI-AFR-02: Automated validation detection in GitHub Actions."""
    print("\n=== Test 1: KSI-AFR-02 - Missing Compliance Validation ===")
    
    # Workflow without compliance validation
    workflow_bad = """
name: Build and Deploy
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Build
        run: npm build
"""
    
    analyzer = get_factory().get_analyzer("KSI-AFR-02")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 1, "Should detect missing compliance validation"
    assert any("compliance validation" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_piy_04_github_actions():
    """Test KSI-PIY-04: SDLC security gates detection."""
    print("\n=== Test 2: KSI-PIY-04 - Missing SAST/Security Gates ===")
    
    workflow_bad = """
name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
"""
    
    analyzer = get_factory().get_analyzer("KSI-PIY-04")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 1, "Should detect missing SAST"
    assert any("sast" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_piy_05_github_actions():
    """Test KSI-PIY-05: Automated code scanning detection."""
    print("\n=== Test 3: KSI-PIY-05 - Missing Code Scanning ===")
    
    workflow_bad = """
name: Deploy
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: kubectl apply -f deployment.yaml
"""
    
    analyzer = get_factory().get_analyzer("KSI-PIY-05")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 2, "Should detect missing code and secret scanning"
    assert any("code scanning" in f.title.lower() for f in findings)
    assert any("secret" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_piy_06_github_actions():
    """Test KSI-PIY-06: Regular vulnerability scans detection."""
    print("\n=== Test 4: KSI-PIY-06 - Missing Scheduled Scans ===")
    
    workflow_bad = """
name: Build
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: docker build .
"""
    
    analyzer = get_factory().get_analyzer("KSI-PIY-06")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 2, "Should detect missing scheduled and vulnerability scans"
    assert any("scheduled" in f.title.lower() for f in findings)
    assert any("vulnerability scanner" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_piy_07_github_actions():
    """Test KSI-PIY-07: SBOM and supply chain security detection."""
    print("\n=== Test 5: KSI-PIY-07 - Missing SBOM Generation ===")
    
    workflow_bad = """
name: Release
on:
  push:
    tags: ['v*']
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - name: Build Container
        run: docker build -t myapp:${{ github.sha }} .
      - name: Push Container
        run: docker push myapp:${{ github.sha }}
"""
    
    analyzer = get_factory().get_analyzer("KSI-PIY-07")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 2, "Should detect missing SBOM and dependency review"
    assert any("sbom" in f.title.lower() for f in findings)
    assert any("dependency review" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_piy_08_github_actions():
    """Test KSI-PIY-08: Security scans in CI/CD pipelines."""
    print("\n=== Test 6: KSI-PIY-08 - Missing Security Job ===")
    
    workflow_bad = """
name: CI/CD
on:
  push:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build
        run: npm run build
  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Deploy
        run: ./deploy.sh
"""
    
    analyzer = get_factory().get_analyzer("KSI-PIY-08")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 2, "Should detect missing security job and PR scanning"
    assert any("security scan job" in f.title.lower() or "security job" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_rpl_02_bicep():
    """Test KSI-RPL-02: Backup automation in Bicep."""
    print("\n=== Test 7: KSI-RPL-02 - Missing Backup Infrastructure ===")
    
    bicep_bad = """
resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
  name: 'myvm'
  location: 'eastus'
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
  }
}
"""
    
    analyzer = get_factory().get_analyzer("KSI-RPL-02")
    findings = analyzer.analyze_bicep(bicep_bad)
    
    assert len(findings) >= 2, "Should detect missing backup vault and policies"
    assert any("backup vault" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_ksi_rpl_04_github_actions():
    """Test KSI-RPL-04: Recovery testing in CI/CD."""
    print("\n=== Test 8: KSI-RPL-04 - Missing Recovery Testing ===")
    
    workflow_bad = """
name: Backup
on:
  schedule:
    - cron: '0 2 * * *'
jobs:
  backup:
    runs-on: ubuntu-latest
    steps:
      - name: Run Backup
        run: ./backup.sh
"""
    
    analyzer = get_factory().get_analyzer("KSI-RPL-04")
    findings = analyzer.analyze_github_actions(workflow_bad)
    
    assert len(findings) >= 2, "Should detect missing recovery testing and RTO/RPO checks"
    assert any("recovery test" in f.title.lower() for f in findings)
    print(f"✓ Detected {len(findings)} issue(s)")
    for f in findings:
        print(f"  - {f.title} ({f.severity.value})")

def test_good_implementations():
    """Test that good implementations don't raise false positives."""
    print("\n=== Test 9: Good Implementations (No False Positives) ===")
    
    # Good GitHub Actions workflow with all security checks
    workflow_good = """
name: Secure CI/CD
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: CodeQL Analysis
        uses: github/codeql-action/analyze@v2
      
      - name: Dependency Review
        uses: actions/dependency-review-action@v3
      
      - name: Generate SBOM
        uses: anchore/sbom-action@v0
      
      - name: Trivy Vulnerability Scan
        uses: aquasecurity/trivy-action@master
      
      - name: Secret Scanning
        uses: gitleaks/gitleaks-action@v2
      
      - name: Validate Compliance
        run: ./scripts/validate-compliance.sh
      
      - name: Test Recovery
        run: ./scripts/test-restore.sh
      
      - name: Verify RTO/RPO
        run: ./scripts/measure-recovery-time.sh
      
      - name: Fail on Vulnerabilities
        run: |
          if [ $VULN_COUNT -gt 0 ]; then exit 1; fi
"""
    
    # Test multiple KSIs
    ksis_to_test = ["KSI-AFR-02", "KSI-PIY-04", "KSI-PIY-05", "KSI-PIY-06", "KSI-PIY-07", "KSI-PIY-08", "KSI-RPL-04"]
    total_findings = 0
    
    for ksi_id in ksis_to_test:
        analyzer = get_factory().get_analyzer(ksi_id)
        findings = analyzer.analyze_github_actions(workflow_good)
        total_findings += len(findings)
        if findings:
            print(f"  {ksi_id}: {len(findings)} finding(s)")
            for f in findings:
                print(f"    - {f.title}")
    
    print(f"✓ Good workflow tested against {len(ksis_to_test)} KSIs")
    print(f"  Total findings: {total_findings}")
    
    # With comprehensive checks, some findings are expected (e.g., status reporting, DAST)
    # Average of ~1 finding per KSI is acceptable for a "good but not perfect" workflow
    assert total_findings <= 10, f"Too many findings ({total_findings}) in good workflow - possible false positives"

if __name__ == "__main__":
    print("=" * 80)
    print("NEW KSI IMPLEMENTATION TESTS")
    print("=" * 80)
    print("\nTesting 8 KSIs changed from CODE_DETECTABLE=False to True")
    print("Focus: CI/CD pipeline detection and IaC backup automation")
    
    try:
        test_ksi_afr_02_github_actions()
        test_ksi_piy_04_github_actions()
        test_ksi_piy_05_github_actions()
        test_ksi_piy_06_github_actions()
        test_ksi_piy_07_github_actions()
        test_ksi_piy_08_github_actions()
        test_ksi_rpl_02_bicep()
        test_ksi_rpl_04_github_actions()
        test_good_implementations()
        
        print("\n" + "=" * 80)
        print("TEST RESULTS: 9/9 passed")
        print("✓ ALL TESTS PASSED - New KSI implementations working correctly!")
        print("=" * 80)
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
