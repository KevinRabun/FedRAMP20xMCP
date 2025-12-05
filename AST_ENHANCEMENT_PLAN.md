# AST Enhancement Prioritization Plan
## 18 Regex-Based Checks Ready for AST Upgrade

**Current State:**
- 3 checks already use AST (authentication, secrets, authorization)
- 18 checks use regex patterns
- All 56 tests passing (baseline established)

**Goal:** Incrementally enhance regex checks with AST for semantic analysis

---

## Priority Tier 1: High Value + Straightforward (Start Here) ✅

### 1. Error Handling (KSI-SVC-01) - **HIGHEST PRIORITY**
**Current Regex Approach:**
- Detects `catch () {}` empty blocks
- Detects generic `catch (Exception e)` usage
- Cannot analyze exception propagation or context

**AST Enhancement Value:** 🟢 **VERY HIGH**
- Extract all try-catch-finally blocks with structure
- Analyze exception types and catch block content
- Detect rethrow patterns (`throw;` vs `throw ex;`)
- Track exception flow across methods
- Verify logging calls within catch blocks

**Implementation Complexity:** 🟡 Medium
- Need try-catch statement extraction
- Need block content analysis
- Need method call detection (logging)

**Example AST Queries:**
```python
def _extract_try_catch_blocks(self, tree):
    """Extract all try-catch-finally statements."""
    query = self.ts_lang.query("""
        (try_statement
          body: (block) @try_body
          (catch_clause
            declaration: (catch_declaration
              type: (identifier) @exception_type
              name: (identifier)? @exception_var
            )
            body: (block) @catch_body
          )*
          (finally_clause)? @finally
        )
    """)
    return query.captures(tree.root_node)
```

**Estimated Impact:** Reduce false positives by 60%, add 5 new detection patterns

---

### 2. Input Validation (KSI-SVC-02) - **SECOND PRIORITY**
**Current Regex Approach:**
- Detects data annotation attributes `[Required]`, `[StringLength]`
- Detects model binding `[FromBody]`, `[FromQuery]`
- Detects `ModelState.IsValid` checks
- Cannot verify validation coverage or parameter usage

**AST Enhancement Value:** 🟢 **VERY HIGH**
- Extract all controller methods with parameters
- Verify each parameter has validation attributes
- Track parameter usage to detect missing validation
- Analyze ModelState.IsValid placement in control flow
- Detect custom validation logic

**Implementation Complexity:** 🟡 Medium
- Need method parameter extraction
- Need attribute parsing on parameters
- Need control flow analysis for ModelState checks

**Example AST Queries:**
```python
def _extract_controller_methods_with_params(self, tree):
    """Get all controller methods and their parameters."""
    query = self.ts_lang.query("""
        (method_declaration
          (attribute_list (attribute name: (identifier) @attr_name))? @attrs
          type: (_) @return_type
          name: (identifier) @method_name
          parameters: (parameter_list) @params
          body: (block) @body
        ) @method
    """)
```

**Estimated Impact:** Improve validation coverage detection by 75%

---

### 3. Secure Coding Practices (KSI-SVC-07) - **THIRD PRIORITY**
**Current Regex Approach:**
- Detects `UseHttpsRedirection`, `UseHsts`
- Detects `UseCors` with wildcard `*`
- Cannot analyze middleware ordering or policy details

**AST Enhancement Value:** 🟢 **HIGH**
- Extract middleware pipeline configuration
- Verify middleware ordering (Auth before Authorization)
- Parse CORS policy configuration details
- Detect missing security headers
- Analyze cookie security settings

**Implementation Complexity:** 🟢 Easy-Medium
- Need method call chain extraction
- Need argument parsing for middleware configuration
- Similar to existing AST method extraction

**Example Patterns:**
- Middleware ordering validation
- Policy configuration analysis
- Security header detection

**Estimated Impact:** Add 8 new security configuration checks

---

## Priority Tier 2: High Value + Complex (After Tier 1)

### 4. Least Privilege Authorization (KSI-IAM-04)
**Current:** Detects `[Authorize]` without `Roles` or `Policy`
**AST Value:** 🟢 HIGH - Track authorization checks across method bodies
**Complexity:** 🔴 High - Requires control flow analysis
**Why Complex:** Need to verify authorization checks before sensitive operations

### 5. Session Management (KSI-IAM-07)
**Current:** Detects session configuration patterns
**AST Value:** 🟢 HIGH - Analyze cookie configuration objects
**Complexity:** 🟡 Medium - Object initialization parsing
**Why Valuable:** Can extract exact security flag values (HttpOnly, Secure, SameSite)

### 6. Logging Implementation (KSI-MLA-05)
**Current:** Detects `ILogger<>`, `LogInformation`, checks for sensitive data
**AST Value:** 🟢 HIGH - Track what's being logged and redaction functions
**Complexity:** 🟡 Medium - Need string interpolation/concatenation analysis
**Why Valuable:** Can detect PII in log statements more accurately

---

## Priority Tier 3: Moderate Value (Incremental Improvements)

### 7. Security Monitoring (KSI-MLA-03)
**Current:** Detects Application Insights, `TrackEvent`, `ILogger`
**AST Value:** 🟡 MEDIUM - Verify security events are tracked
**Complexity:** 🟡 Medium
**Enhancement:** Extract event tracking patterns, verify coverage

### 8. Performance Monitoring (KSI-MLA-06)
**Current:** Detects `TrackDependency`, `Stopwatch`
**AST Value:** 🟡 MEDIUM - Analyze monitoring coverage
**Complexity:** 🟡 Medium
**Enhancement:** Track dependency call patterns

### 9. Anomaly Detection (KSI-MLA-04)
**Current:** Detects `TrackMetric`, `GetMetric`
**AST Value:** 🟡 MEDIUM - Verify metrics tracked
**Complexity:** 🟢 Easy
**Enhancement:** Extract metric dimensions

### 10. Incident Response (KSI-INR-01)
**Current:** Detects webhook/alert integration
**AST Value:** 🟡 MEDIUM - Verify error→alert flow
**Complexity:** 🟡 Medium
**Enhancement:** Track exception→alert patterns

---

## Priority Tier 4: Low Value or Already Sufficient

### 11. Service Account Management (KSI-IAM-02)
**Current:** Detects `DefaultAzureCredential`, hardcoded secrets
**AST Value:** 🟡 LOW-MEDIUM - Already effective with regex
**Why Low Priority:** Credential patterns are straightforward string matches

### 12. Microservices Security (KSI-CNA-07)
**Current:** Detects Dapr, HttpClient, authentication handlers
**AST Value:** 🟡 LOW - Already captures key patterns
**Complexity:** 🟡 Medium

### 13. Data Classification (KSI-PIY-01)
**Current:** Detects `[SensitiveData]` attributes, PII property names
**AST Value:** 🟡 LOW - Simple attribute detection
**Complexity:** 🟢 Easy

### 14. Privacy Controls (KSI-PIY-03)
**Current:** Detects consent tracking properties
**AST Value:** 🟡 LOW - Property presence checks
**Complexity:** 🟢 Easy

### 15. Configuration Management (KSI-CMT-01)
**Current:** Detects hardcoded configs, checks for IConfiguration
**AST Value:** 🟡 MEDIUM - Better literal string detection
**Complexity:** 🟡 Medium
**Enhancement:** Extract all string literals, analyze context

### 16. Version Control Enforcement (KSI-CMT-02)
**Current:** Detects direct deployment patterns
**AST Value:** 🟢 LOW - Edge case detection
**Complexity:** 🟢 Easy

### 17. Automated Testing (KSI-CMT-03)
**Current:** Detects test frameworks, security tests
**AST Value:** 🟡 LOW-MEDIUM - Test structure analysis
**Complexity:** 🟡 Medium

### 18. Audit Logging (KSI-AFR-01)
**Current:** Detects auth code + logging presence
**AST Value:** 🟢 MEDIUM - Track logging in auth flows
**Complexity:** 🟡 Medium
**Enhancement:** Verify logging calls after auth operations

### 19. Log Integrity (KSI-AFR-02)
**Current:** Detects file logging vs centralized
**AST Value:** 🟡 LOW - Simple pattern detection
**Complexity:** 🟢 Easy

### 20. Key Management (KSI-CED-01)
**Current:** Detects hardcoded keys, local generation, Key Vault
**AST Value:** 🟡 LOW-MEDIUM - String literal analysis
**Complexity:** 🟡 Medium

---

## Recommended Implementation Sequence

### Phase 1: Foundation (Weeks 1-2)
✅ **1. Error Handling (KSI-SVC-01)**
- Highest immediate value
- Establishes try-catch AST pattern
- Tests AST control flow analysis

✅ **2. Input Validation (KSI-SVC-02)**
- Critical security check
- Parameter + attribute parsing
- Builds on AST foundation

### Phase 2: Security Core (Weeks 3-4)
✅ **3. Secure Coding (KSI-SVC-07)**
- Middleware analysis patterns
- Configuration parsing
- Essential for FedRAMP compliance

✅ **4. Least Privilege (KSI-IAM-04)**
- Authorization verification
- Control flow analysis practice
- High compliance value

### Phase 3: Monitoring & Observability (Week 5)
✅ **5. Logging Implementation (KSI-MLA-05)**
- PII detection improvement
- String analysis patterns
- Redaction verification

✅ **6. Session Management (KSI-IAM-07)**
- Cookie configuration analysis
- Object initialization parsing

### Phase 4: Advanced Analysis (Weeks 6-7)
✅ **7. Security Monitoring (KSI-MLA-03)**
✅ **8. Audit Logging (KSI-AFR-01)**
✅ **9. Configuration Management (KSI-CMT-01)**

### Phase 5: Polish & Optimize (Week 8+)
- Remaining checks based on value/complexity
- Performance optimization
- Documentation and best practices

---

## Success Metrics

**Per Check Enhancement:**
- [ ] Maintain 100% test pass rate
- [ ] Add 2-5 new detection patterns
- [ ] Reduce false positives by 30%+
- [ ] Document AST queries with examples
- [ ] Compare AST vs regex results

**Overall Project Metrics:**
- [ ] 50%+ of checks use AST (12 of 21)
- [ ] Zero test regressions
- [ ] Improved detection accuracy by 40%+
- [ ] Apply patterns to Java/TypeScript analyzers

---

## AST Helper Methods Needed

Based on analysis, we'll need these common helpers:

### 1. Exception Handling
```python
def _extract_try_catch_blocks(self, tree)
def _analyze_catch_block(self, catch_node)
def _detect_exception_rethrow(self, catch_body)
```

### 2. Method Analysis
```python
def _extract_method_parameters(self, method_node)
def _get_parameter_attributes(self, param_node)
def _analyze_method_body_for_pattern(self, body, pattern)
```

### 3. Configuration/Middleware
```python
def _extract_middleware_chain(self, tree)
def _parse_method_arguments(self, method_call_node)
def _extract_object_initializer(self, init_node)
```

### 4. Control Flow
```python
def _find_if_statements_with_condition(self, body, condition_pattern)
def _verify_code_path_contains(self, start_node, required_call)
```

---

## Implementation Notes

### Testing Strategy
1. Keep regex version alongside AST during development
2. Run both, compare results on test files
3. Add new test cases for AST-specific improvements
4. Document differences in detection

### Rollout Approach
- **Conservative:** One check at a time, validate thoroughly
- **Update tests immediately** after each enhancement
- **Document learnings** for Java/TypeScript ports
- **Maintain backward compatibility** via fallback to regex if AST parsing fails

### Risk Mitigation
- AST parsing errors → fallback to regex
- Tree-sitter syntax changes → pin versions
- Performance issues → cache parsed trees
- False positives → add negative test cases

---

## Next Steps

**IMMEDIATE (Today):**
1. Start with Error Handling (KSI-SVC-01)
2. Create AST helper methods for try-catch extraction
3. Implement enhanced error handling check
4. Add 5 new test cases
5. Validate against existing 56 tests

**THIS WEEK:**
1. Complete Tier 1 (Error Handling, Input Validation, Secure Coding)
2. Document AST patterns and lessons learned
3. Update TESTING.md with new test cases
4. Commit each enhancement separately

**NEXT WEEK:**
1. Begin Tier 2 (Least Privilege, Session Management, Logging)
2. Refactor common AST patterns into shared helpers
3. Performance profiling and optimization

---

## Resource Links

**Tree-sitter C# Documentation:**
- https://github.com/tree-sitter/tree-sitter-c-sharp
- Grammar reference: https://github.com/tree-sitter/tree-sitter-c-sharp/blob/master/grammar.js

**C# Language Spec:**
- Exception handling: https://learn.microsoft.com/dotnet/csharp/language-reference/statements/exception-handling-statements
- Attributes: https://learn.microsoft.com/dotnet/csharp/advanced-topics/reflection-and-attributes/
- Methods: https://learn.microsoft.com/dotnet/csharp/programming-guide/classes-and-structs/methods

**FedRAMP Requirements:**
- Error handling requirements: KSI-SVC-01
- Input validation: KSI-SVC-02
- Secure coding: KSI-SVC-07

---

## Conclusion

**Start with Tier 1** - these provide immediate, measurable value:
1. Error Handling (foundational control flow analysis)
2. Input Validation (critical for security)
3. Secure Coding (middleware + configuration)

These three checks will:
- Establish AST patterns for 15+ other checks
- Demonstrate 40%+ accuracy improvement
- Build expertise for Java/TypeScript ports
- Provide immediate FedRAMP compliance value

**Estimated Timeline:** 2-3 months for all 18 checks if working incrementally
**Realistic Target:** Complete Tier 1-2 (6 checks) in 4 weeks = 70% of value
