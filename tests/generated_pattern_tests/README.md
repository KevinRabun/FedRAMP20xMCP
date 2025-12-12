# Generated Pattern Tests

This directory contains **automatically generated** comprehensive test suites for all 153 FedRAMP 20x compliance patterns.

## Overview

- **18 test files** (one per pattern family)
- **306 total tests** (153 patterns × 2 tests each)
  - **153 positive tests**: Verify patterns detect non-compliant code
  - **153 negative tests**: Verify patterns don't false-positive on compliant code

## Test Files

| File | Family | Patterns | Tests |
|------|--------|----------|-------|
| test_ads_patterns.py | Authorization Data Sharing | 10 | 20 |
| test_afr_patterns.py | Architecture, Features, Resources | 4 | 8 |
| test_ccm_patterns.py | Collaborative Continuous Monitoring | 12 | 24 |
| test_ced_patterns.py | Continuous Evidence Delivery | 4 | 8 |
| test_cmt_patterns.py | Continuous Monitoring and Testing | 4 | 8 |
| test_cna_patterns.py | Cloud Native Architecture | 11 | 22 |
| test_common_patterns.py | Common Patterns | 8 | 16 |
| test_iam_patterns.py | Identity and Access Management | 11 | 22 |
| test_inr_patterns.py | Incident and Near-Miss Reporting | 2 | 4 |
| test_mla_patterns.py | Monitoring, Logging, and Alerting | 11 | 22 |
| test_piy_patterns.py | Privacy and Transparency | 8 | 16 |
| test_rpl_patterns.py | Resilience and Recovery Planning | 2 | 4 |
| test_rsc_patterns.py | Recommended Secure Configuration | 11 | 22 |
| test_scn_patterns.py | Significant Change Notifications | 13 | 26 |
| test_svc_patterns.py | Secure Coding and Vulnerability Mgmt | 17 | 34 |
| test_tpr_patterns.py | Third-Party Risk Management | 4 | 8 |
| test_ucm_patterns.py | Using Cryptographic Modules | 11 | 22 |
| test_vdr_patterns.py | Vulnerability Detection and Response | 10 | 20 |

## Running Tests

### Run All Generated Tests
```bash
pytest tests/generated_pattern_tests/ -v
```

### Run Specific Family
```bash
pytest tests/generated_pattern_tests/test_iam_patterns.py -v
```

### Run Single Pattern Test
```bash
pytest tests/generated_pattern_tests/test_iam_patterns.py::TestIamPatterns::test_iam_mfa_fido2_import_positive -v
```

### Generate Summary Report
```bash
pytest tests/generated_pattern_tests/ --tb=no -q
```

## Test Structure

Each pattern has two tests:

### Positive Test
Verifies the pattern **detects** code that should trigger it.

Example:
```python
def test_iam_mfa_fido2_import_positive(self, analyzer):
    """Test iam.mfa.fido2_import: FIDO2 Library Import - Should detect"""
    code = """import fido2
def main():
    pass"""
    
    result = analyzer.analyze(code, "python")
    findings = [f for f in result.findings if "iam.mfa.fido2_import" in f.requirement_id]
    assert len(findings) > 0, "Pattern should detect this code"
```

### Negative Test
Verifies the pattern **does NOT** detect compliant/unrelated code.

Example:
```python
def test_iam_mfa_fido2_import_negative(self, analyzer):
    """Test iam.mfa.fido2_import: FIDO2 Library Import - Should NOT detect"""
    code = """def compliant_function():
    return True"""
    
    result = analyzer.analyze(code, "python")
    findings = [f for f in result.findings if "iam.mfa.fido2_import" in f.requirement_id]
    assert len(findings) == 0, "Pattern should NOT detect compliant code"
```

## Regenerating Tests

If patterns change, regenerate all tests:

```bash
python tests/generate_pattern_tests.py
```

This will:
1. Read all pattern YAML files from `data/patterns/`
2. Generate positive/negative test cases for each pattern
3. Create/overwrite test files in this directory

## Test Coverage Goals

- [x] **Schema Validation**: All patterns have required fields
- [x] **Loading**: All pattern files parse correctly
- [ ] **Detection Accuracy**: All patterns detect intended code (IN PROGRESS)
- [ ] **False Positive Prevention**: No false positives on compliant code
- [ ] **Multi-Language**: Patterns work across all declared languages
- [ ] **Edge Cases**: Boundary conditions handled correctly

## Known Issues

Some generated tests may fail initially because:
1. Pattern AST queries need refinement
2. Generated test code doesn't perfectly match pattern expectations
3. Patterns may need language-specific adjustments

**This is EXPECTED** - these tests help identify and fix pattern issues!

## Contributing

When adding new patterns:
1. Add pattern to appropriate `data/patterns/*_patterns.yaml` file
2. Run `python tests/generate_pattern_tests.py` to generate tests
3. Run tests: `pytest tests/generated_pattern_tests/`
4. Fix any failing tests by refining pattern queries or test code
5. Commit both pattern and test changes

## Integration with CI/CD

These tests are integrated into the main test suite via `tests/run_all_tests.py`.

To include in CI:
```yaml
- name: Run Pattern Tests
  run: pytest tests/generated_pattern_tests/ --junitxml=junit/pattern-tests.xml
```
