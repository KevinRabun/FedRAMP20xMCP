# Data-Driven Architecture Refactoring Plan

## Current State Analysis

### Problems Identified

1. **Massive Code Duplication** (~6MB of analyzer code)
   - 72 KSI analyzers: ~2.8MB (2,857,745 bytes)
   - 199 FRR analyzers: ~3.1MB (3,107,355 bytes)
   - Each analyzer contains 9 language-specific methods (Python, C#, Java, TypeScript, Bicep, Terraform, GitHub Actions, Azure Pipelines, GitLab CI)
   - Similar patterns repeated across all analyzers

2. **Maintenance Burden**
   - Adding new detection pattern requires editing 271 files (72 KSI + 199 FRR)
   - Adding new language support requires editing 271 files
   - Bug fixes must be replicated across similar code
   - No single source of truth for detection logic

3. **Testing Overhead**
   - 271+ test files mirroring analyzer structure
   - Difficult to maintain test coverage
   - Tests are mostly structural validation, not behavior validation

4. **Scalability Issues**
   - Adding new FedRAMP families becomes prohibitively expensive
   - Cannot easily extend to new compliance frameworks
   - Hard to add cross-cutting features (e.g., severity scoring, related requirements)

### Current Architecture

```
analyzers/
├── ksi/
│   ├── ksi_iam_01.py (1,659 lines)
│   ├── ksi_iam_02.py
│   └── ... (72 files)
├── frr/
│   ├── frr_vdr_01.py (562 lines)
│   ├── frr_vdr_02.py
│   └── ... (199 files)
└── base.py
```

Each analyzer:
- Hardcodes metadata (ID, name, statement, NIST controls, etc.)
- Implements 9 `analyze_*` methods
- Contains language-specific detection patterns
- Duplicates AST parsing logic

## Proposed Data-Driven Architecture

### Core Principles

1. **Metadata as Data** - Store all requirement metadata in JSON/YAML
2. **Pattern Libraries** - Centralized detection pattern definitions
3. **Generic Analyzers** - Language-specific analyzers that consume patterns
4. **Composition over Inheritance** - Build complex analyzers from simple components

### New Architecture

```
data/
├── requirements/
│   ├── ksi_metadata.json          # All 72 KSI definitions
│   └── frr_metadata.json          # All 199 FRR definitions
├── patterns/
│   ├── iam_patterns.yaml          # MFA, RBAC patterns
│   ├── vdr_patterns.yaml          # Vulnerability scanning patterns
│   ├── ads_patterns.yaml          # API/data sharing patterns
│   └── ... (pattern libraries by domain)
└── language_mappings.yaml         # Language-specific pattern translations

analyzers/
├── pattern_engine.py              # Core pattern matching engine
├── language_analyzers/
│   ├── python_analyzer.py         # Generic Python analyzer
│   ├── csharp_analyzer.py         # Generic C# analyzer
│   ├── bicep_analyzer.py          # Generic Bicep analyzer
│   └── ...
├── requirement_analyzer.py        # Loads metadata + patterns, orchestrates language analyzers
└── base.py                        # Shared base classes

tools/
├── analyzer.py                    # Updated to use requirement_analyzer
└── ...
```

### Data Schema

#### requirements/ksi_metadata.json
```json
{
  "KSI-IAM-01": {
    "id": "KSI-IAM-01",
    "name": "Phishing-Resistant MFA",
    "statement": "Enforce multi-factor authentication (MFA) using methods that are difficult to intercept...",
    "family": "IAM",
    "family_name": "Identity and Access Management",
    "impact_levels": ["Low", "Moderate"],
    "nist_controls": [
      {"id": "ac-2", "name": "Account Management"},
      {"id": "ia-2", "name": "Identification and Authentication"}
    ],
    "code_detectable": true,
    "implementation_status": "IMPLEMENTED",
    "retired": false,
    "detection_patterns": ["iam.mfa", "iam.phishing_resistant"],
    "related_ksis": ["KSI-IAM-02"],
    "related_frrs": ["FRR-ADS-AC-01"]
  }
}
```

#### patterns/iam_patterns.yaml
```yaml
iam.mfa:
  description: "Detect MFA configuration in code"
  languages:
    python:
      ast_queries:
        - type: function_call
          name: "enable_mfa|configure_mfa|setup_mfa"
      regex_fallback: "(enable|configure|setup)_mfa"
    csharp:
      ast_queries:
        - type: method_invocation
          name: "EnableMfa|ConfigureMfa"
      regex_fallback: "EnableMfa|ConfigureMfa"
    bicep:
      ast_queries:
        - type: resource_property
          resource_type: "Microsoft.Authorization"
          property: "strongAuthenticationMethod"
      regex_fallback: "strongAuthenticationMethod"

iam.phishing_resistant:
  description: "Detect phishing-resistant MFA methods (FIDO2, WebAuthn)"
  severity: "HIGH"
  languages:
    python:
      ast_queries:
        - type: import_module
          module: "fido2|webauthn"
      positive_indicators: ["FIDO2", "WebAuthn", "Passkey"]
      negative_indicators: ["TOTP", "SMS", "OTP"]
```

### Implementation Phases

#### Phase 1: Data Extraction (Week 1)
- [ ] Extract all KSI metadata to `ksi_metadata.json`
- [ ] Extract all FRR metadata to `frr_metadata.json`
- [ ] Create migration script to validate extracted data against current analyzers
- [ ] Build data loader module

**Files Created:**
- `data/requirements/ksi_metadata.json`
- `data/requirements/frr_metadata.json`
- `scripts/extract_metadata.py`
- `src/fedramp_20x_mcp/data_loader_v2.py`

**Expected LOC Reduction:** 0 (data extraction only)

#### Phase 2: Pattern Library (Week 2)
- [ ] Identify common detection patterns across analyzers
- [ ] Create pattern library files (YAML)
- [ ] Implement pattern engine for AST-based matching
- [ ] Build pattern compiler (YAML → executable detection logic)

**Files Created:**
- `data/patterns/iam_patterns.yaml`
- `data/patterns/vdr_patterns.yaml`
- `data/patterns/...` (10-15 pattern files)
- `src/fedramp_20x_mcp/analyzers/pattern_engine.py`
- `src/fedramp_20x_mcp/analyzers/pattern_compiler.py`

**Expected LOC Reduction:** 0 (building new infrastructure)

#### Phase 3: Generic Language Analyzers (Week 3)
- [ ] Implement `GenericPythonAnalyzer` consuming patterns
- [ ] Implement `GenericCSharpAnalyzer` consuming patterns
- [ ] Implement `GenericBicepAnalyzer` consuming patterns
- [ ] Implement CI/CD pipeline analyzers
- [ ] Create `RequirementAnalyzer` orchestrator

**Files Created:**
- `src/fedramp_20x_mcp/analyzers/language_analyzers/python_analyzer.py`
- `src/fedramp_20x_mcp/analyzers/language_analyzers/csharp_analyzer.py`
- `src/fedramp_20x_mcp/analyzers/language_analyzers/bicep_analyzer.py`
- `src/fedramp_20x_mcp/analyzers/requirement_analyzer.py`

**Expected LOC Reduction:** 0 (parallel implementation)

#### Phase 4: Integration & Testing (Week 4)
- [ ] Update factories to use new RequirementAnalyzer
- [ ] Create backward-compatible API wrappers
- [ ] Run full test suite against new implementation
- [ ] Performance benchmarking
- [ ] Fix regressions

**Files Modified:**
- `src/fedramp_20x_mcp/analyzers/ksi/factory.py`
- `src/fedramp_20x_mcp/analyzers/frr/factory.py`
- `src/fedramp_20x_mcp/tools/analyzer.py`

**Expected LOC Reduction:** 0 (validation phase)

#### Phase 5: Cutover & Cleanup (Week 5)
- [ ] Remove old analyzer files (271 files)
- [ ] Consolidate tests into data-driven test framework
- [ ] Update documentation
- [ ] Deprecation warnings for old API

**Files Deleted:**
- `src/fedramp_20x_mcp/analyzers/ksi/*.py` (72 files)
- `src/fedramp_20x_mcp/analyzers/frr/*.py` (199 files)
- `tests/test_ksi_*.py` (72+ files)
- `tests/test_frr_*.py` (199+ files)

**Expected LOC Reduction:** ~5.5MB code + ~1MB tests = ~6.5MB total

### Migration Strategy

#### Backward Compatibility
1. Keep old API surface: `KSIAnalyzerFactory.analyze(ksi_id, code, language)`
2. New factory internally uses `RequirementAnalyzer` with metadata lookup
3. Deprecation warnings logged but no breaking changes

#### Validation
1. Run both old and new analyzers on test corpus
2. Compare results for regressions
3. Accept as validation pass if results match >95%

#### Rollback Plan
1. Keep old analyzers in `analyzers/legacy/` for 2 releases
2. Feature flag to switch between old/new implementation
3. Automated rollback if tests fail

## Benefits

### Immediate Benefits
- **90%+ code reduction** (from ~6MB to ~600KB analyzers)
- **Single source of truth** for detection patterns
- **Easier maintenance** - update pattern in one YAML file
- **Consistent behavior** across all requirements

### Long-term Benefits
- **Easy extensibility** - add new compliance framework by adding JSON + patterns
- **Better testing** - test pattern engine once, not 271 analyzers
- **Performance** - shared pattern compilation, caching
- **Collaboration** - non-developers can contribute patterns via YAML
- **Version control** - track pattern changes in git
- **Documentation** - patterns are self-documenting

### Example: Adding New Language

**Before (Old Architecture):**
1. Edit 72 KSI analyzer files
2. Edit 199 FRR analyzer files
3. Add 271 new test methods
4. Update 271 docstrings
Estimated: 40-60 hours of work

**After (New Architecture):**
1. Create `rust_analyzer.py` (200 lines)
2. Add Rust patterns to `language_mappings.yaml` (50 lines)
3. Add 1 parameterized test suite (50 lines)
Estimated: 4-6 hours of work

### Example: Fixing Bug in AST Parsing

**Before:**
1. Identify bug affects 50 analyzers
2. Edit 50 files with same fix
3. Run 50 test files
4. Risk introducing inconsistency

**After:**
1. Fix bug in `pattern_engine.py` (1 file)
2. Run consolidated test suite
3. All 271 requirements automatically fixed

## Risks & Mitigation

### Risk: Performance Regression
- **Mitigation:** Benchmark before/after, optimize pattern engine
- **Fallback:** Add caching layer for compiled patterns

### Risk: Loss of Fidelity
- **Mitigation:** Exhaustive validation phase, accept >95% match rate
- **Fallback:** Keep edge cases as custom analyzer extensions

### Risk: Pattern Complexity
- **Mitigation:** Start with simple patterns, iterate based on coverage
- **Fallback:** Allow Python code injection for complex patterns

### Risk: Migration Timeline
- **Mitigation:** Phased approach with parallel implementation
- **Fallback:** Extend timeline, no hard cutover deadline

## Success Metrics

- [ ] **Code Reduction:** >85% reduction in analyzer code (target: 6MB → 1MB)
- [ ] **Test Coverage:** Maintain >95% test coverage
- [ ] **Performance:** Analysis time within 20% of current baseline
- [ ] **Accuracy:** >95% detection result parity with old implementation
- [ ] **Maintainability:** New requirement addition time <2 hours (vs. 8 hours currently)
- [ ] **Documentation:** All patterns documented in YAML with examples

## Timeline

- **Week 1:** Data extraction + validation
- **Week 2:** Pattern library design + implementation
- **Week 3:** Generic analyzers + orchestrator
- **Week 4:** Integration + testing + benchmarking
- **Week 5:** Cutover + cleanup + documentation
- **Total:** 5 weeks (25 working days)

## Next Steps

1. Review and approve this plan
2. Create feature branch: `refactor/data-driven-architecture` ✅ (Done)
3. Set up project tracking (GitHub issues/project board)
4. Begin Phase 1: Data extraction

---

**Branch:** `refactor/data-driven-architecture`  
**Status:** Planning  
**Created:** 2024-12-12  
**Target Completion:** 2025-01-16
