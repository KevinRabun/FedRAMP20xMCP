# Pattern Expansion Plan - Phase 4.5

## Current State Analysis

**Pattern Engine Coverage Gap:**
- Current patterns: 120 across 11 families
- Pattern findings: 5-10% of traditional analyzer findings
- Traditional analyzers: 72 KSIs with AST-based detection
- Gap: ~60-70 KSI-specific patterns missing

**Example Gap (Bicep Storage Analysis):**
```
Pattern Engine (5 findings):
- common.tagging.required_tags
- common.diagnostics.missing_diagnostic_settings
- mla.audit.resource_logs_missing
- svc.encryption.storage_encryption
- svc.tls.minimum_version

Traditional Analyzers (19 findings):
- KSI-AFR-05, KSI-AFR-11, KSI-CMT-01, KSI-CMT-03, KSI-CMT-04
- KSI-CNA-07, KSI-IAM-06, KSI-INR-01, KSI-INR-02
- KSI-MLA-01, KSI-MLA-02, KSI-MLA-07
- KSI-PIY-01, KSI-PIY-02
- KSI-RPL-02, KSI-RPL-03
- KSI-SVC-01, KSI-SVC-02, KSI-SVC-10

Missing: 19 KSI-specific patterns
```

## Root Cause

**Design Difference:**
1. **Traditional Analyzers**: One analyzer per KSI (72 analyzers = 72 KSIs)
   - Deep, context-aware AST analysis
   - Language-specific detection logic
   - Handles complex patterns (e.g., missing resource properties)

2. **Pattern Engine**: Generic patterns across families (120 patterns ≠ 72 KSIs)
   - Fast, declarative YAML patterns
   - Regex + basic AST queries
   - Good for common issues, missing KSI-specific depth

## Solution: Two-Phase Pattern Expansion

### Phase 4.5a: Add Missing KSI Patterns (Priority: HIGH)

**Goal:** Achieve 80%+ parity with traditional analyzers

**Approach:** Create KSI-specific patterns for high-value KSIs

**Priority KSIs to Add (based on gap analysis):**

1. **AFR (Automated FedRAMP) - 2 patterns needed:**
   - KSI-AFR-05: SCN (Security Scanning)
   - KSI-AFR-11: UCM (User Capability Management)

2. **CMT (Change Management & Testing) - 4 patterns needed:**
   - KSI-CMT-01: Version control integration
   - KSI-CMT-03: Pre-deployment testing
   - KSI-CMT-04: Rollback capability

3. **CNA (Cloud-Native Architecture) - 1 pattern needed:**
   - KSI-CNA-07: IaC policy enforcement

4. **IAM (Identity & Access Management) - 1 pattern needed:**
   - KSI-IAM-06: Service account management

5. **INR (Incident Response) - 2 patterns needed:**
   - KSI-INR-01: Alert configuration
   - KSI-INR-02: Incident logging

6. **MLA (Monitoring, Logging & Audit) - 3 patterns needed:**
   - KSI-MLA-01: Centralized logging
   - KSI-MLA-02: Log retention
   - KSI-MLA-07: Performance monitoring

7. **PIY (Privacy) - 2 patterns needed:**
   - KSI-PIY-01: Data classification
   - KSI-PIY-02: PII handling

8. **RPL (Replication) - 2 patterns needed:**
   - KSI-RPL-02: Backup configuration
   - KSI-RPL-03: Geo-redundancy

9. **SVC (Services) - 3 patterns needed:**
   - KSI-SVC-01: Secret management
   - KSI-SVC-02: Encryption at rest
   - KSI-SVC-10: Network isolation

**Total new patterns needed: ~20-25**

### Phase 4.5b: Enhance Pattern Detection Logic (Priority: MEDIUM)

**Goal:** Improve pattern detection accuracy for complex scenarios

**Enhancements:**

1. **Advanced AST Queries:**
   - Add property-absence detection (e.g., missing `networkRules` in Storage)
   - Add conditional logic (e.g., if X exists, Y must also exist)
   - Add value validation (e.g., `minimumTlsVersion` must be >= TLS1.2)

2. **Pattern Composition:**
   - Add `requires_property` field for resource-specific checks
   - Add `requires_value` field for value validation
   - Add `context_aware` field for relationship checks

3. **Language-Specific Optimizations:**
   - Bicep: Property path queries (e.g., `properties.networkAcls.defaultAction`)
   - Terraform: Resource attribute queries
   - Python/C#/Java: AST-based control flow analysis

## Implementation Strategy

### Week 1: High-Priority KSI Patterns (Target: +15 patterns)

**Day 1-2: SVC & IAM patterns (6 patterns)**
- KSI-SVC-01: Secret management detection
- KSI-SVC-02: Encryption at rest validation
- KSI-SVC-10: Network isolation checks
- KSI-IAM-06: Service account detection

**Day 3-4: MLA & INR patterns (5 patterns)**
- KSI-MLA-01: Centralized logging
- KSI-MLA-02: Log retention policies
- KSI-MLA-07: Performance monitoring
- KSI-INR-01: Alert configuration
- KSI-INR-02: Incident logging

**Day 5: CMT & CNA patterns (4 patterns)**
- KSI-CMT-01: Version control
- KSI-CMT-03: Testing gates
- KSI-CMT-04: Rollback capability
- KSI-CNA-07: Policy enforcement

### Week 2: Medium-Priority Patterns (Target: +10 patterns)

**RPL, PIY, AFR patterns (10 patterns)**
- Backup, replication, privacy, automation patterns

### Week 3: Pattern Enhancement & Testing

**Enhanced detection logic + comprehensive testing**

## Expected Outcomes

**After Phase 4.5a (Week 1):**
- Pattern coverage: 135 patterns (120 + 15)
- Pattern findings: 40-50% of traditional analyzer findings
- Bicep analysis: 15-20 findings (vs current 5)

**After Phase 4.5b (Week 2):**
- Pattern coverage: 145 patterns (135 + 10)
- Pattern findings: 60-80% of traditional analyzer findings
- Bicep analysis: 25-30 findings (vs current 5)

**After Phase 4.5c (Week 3):**
- Pattern coverage: 145 patterns with enhanced detection
- Pattern findings: 80-90% of traditional analyzer findings
- Bicep analysis: 30-35 findings (approaching traditional 32)

## Decision Point

**Immediate Options:**

1. **Continue Phase 4 (Documentation)** - Accept current 10-15% pattern coverage as baseline
   - Pros: Completes current phase, establishes foundation
   - Cons: Pattern engine significantly underperforms traditional analyzers

2. **Pivot to Phase 4.5 (Pattern Expansion)** - Pause documentation, boost pattern accuracy
   - Pros: Achieves accuracy parity, validates hybrid architecture value
   - Cons: Delays documentation completion

3. **Parallel Track** - Document current state while expanding patterns
   - Pros: Progress on both fronts
   - Cons: More complex coordination

## Recommendation

**Option 3: Parallel Track with Focus on Accuracy**

**Reasoning:**
- User correctly identified accuracy as more important than speed
- Hybrid architecture is only valuable if pattern engine catches most issues
- Current 10-15% coverage makes pattern engine appear weak
- Adding 20-25 KSI patterns is faster than documenting (1-2 weeks vs 2-3 weeks)

**Immediate Actions:**
1. Complete Phase 4 documentation (1-2 days)
2. Begin Phase 4.5a pattern expansion (1 week)
3. Re-run comprehensive tests to validate improved accuracy
4. Update documentation with new coverage metrics

**Success Metrics:**
- Pattern engine catches 80%+ of issues traditional analyzers find
- Hybrid architecture provides value (not just redundancy)
- Pattern authoring guide enables community contributions
