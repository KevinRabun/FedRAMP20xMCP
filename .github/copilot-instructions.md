
# Copilot Instructions for FedRAMP 20x MCP Server  
**Applies to all assistants in this repo (GitHub Copilot, Claude Sonnet 4.5)**  
**Scope:** analyzers, tools, tests, templates, code generation, reviews, releases.

---

# 1. MACHINE EXECUTION CONTRACT (READ FIRST — NON‑NEGOTIABLE)
```yaml
contract:
  goals:
    - eliminate_shortcuts
    - require_evidence
    - obey_user_instructions_exactly
    - enforce_AST_first_policy
    - ensure_full_test_validation
  prohibited:
    - weakening_tests
    - changing_test_semantics
    - partial_coverage_when_ALL_required
    - substituting_"better_ideas"
    - inventing_FRR_or_KSI_definitions
    - regex_when_AST_available
    - silent_changes_without_diff
    - prioritize_speed_over_correctness
  required:
    - fix_root_cause_not_tests
    - verify_authoritative_sources_first
    - show_commands_and_outputs
    - report_progress_quantitatively
    - ask_questions_when_ambiguous
    - use_replace_selection_or_diff_only
    - follow_named_algorithm_exactly
  validation_gate:
    - run_full_local_test_suite
    - block_output_if_any_check_fails
```

---

# 2. PRIORITY HIERARCHY (EXPLICIT GOAL ORDERING)

**When goals conflict, follow this strict priority order:**

1. **CORRECTNESS** - Code must be accurate and comply with requirements
2. **COMPLETENESS** - All tests must pass, all requirements must be met
3. **EVIDENCE** - Every claim must be verified with commands/output
4. **TRANSPARENCY** - Show all work, never hide failures
5. **SPEED** - Only optimize for speed AFTER 1-4 are satisfied

**CRITICAL RULES:**
- NEVER sacrifice correctness for speed
- NEVER commit with failing tests to "fix later"
- NEVER skip verification steps to save time
- NEVER assume something works without running it
- NEVER hide failures hoping CI will pass

**If I am about to violate priority order:**
- STOP immediately
- State: "About to prioritize [SPEED] over [CORRECTNESS] - this violates priority hierarchy"
- Ask: "Should I continue with slower but correct approach?"

**Red Flags That Indicate Wrong Prioritization:**
- "I'll fix this in the next commit" ← Violates COMPLETENESS
- "This will probably work" ← Violates EVIDENCE
- "Tests can wait" ← Violates COMPLETENESS
- "CI will catch it" ← Violates TRANSPARENCY

---

# 3. ACCOUNTABILITY — **NO SHORTCUTS EVER**
- Fix **root cause** in analyzers; NEVER weaken assertions to pass tests.  
- “ALL” = **EVERY SINGLE ITEM** (tests, KSIs, FRRs).  
- Report **honest numeric progress**:  
  - _“15/63 analyzers fixed, 48 remaining”_  
- If tempted to shortcut, explicitly state:  
  - _“Considered shortcut X → rejected → performing required hard work Y.”_

**Wrong:**  
```python
assert len(result.findings) > 0   →  assert result is not None
```

**Right:**  
Fix analyzer so findings actually appear.

---

# 4. NEVER ASSUME — VERIFY FIRST, CODE SECOND
Always read authoritative sources BEFORE code:
- **KSI**: `FRMR.KSI.key-security-indicators.json`
- **FRR Families**: `FRMR.*.json`
- **FRD**: `FRMR.FRD.fedramp-definitions.json`

Costly assumption errors (never repeat):
- PIY‑01 ≠ “Encryption at Rest” → **It is Automated Inventory**  
- PIY‑02 ≠ “Encryption in Transit” → **It is Security Objectives & Requirements**  
- SVC‑01 ≠ “Secrets Management” → **SVC‑06 is secrets**

If requirement meaning unclear → **STOP & ask** (do not infer).

---

# 5. USER INSTRUCTION COMPLIANCE (ABSOLUTE)
- Follow **exact** approach, no substitutions.  
- If user requests **pattern-by-pattern**, do not batch.  
- If user requests **file-by-file**, do exactly that.  
- Only ask questions when requirement is ambiguous — not to propose alternatives.  
- Never claim coverage without **verification + evidence**.

---

# 6. PROJECT OVERVIEW (REFERENCE)
- Loads FedRAMP 20x FRRs, KSIs, FRDs from JSON + docs.  
- 48 MCP tools across 13 modules.  
- Multi-language analyzers: Python, C#, Java, TS/JS, Bicep, Terraform, CI/CD.  
- Cache refresh: 1 hour.  
- **OSCAL optional**, NOT required by FRR‑ADS‑01.

---

# 7. DATA & STATUS (REFERENCE)
- **199 FRRs** (11 families)  
- **50 FRDs**  
- **72 KSIs**  
- **65 active**, **7 retired**

Retired KSIs (never use):
- CMT‑05, MLA‑03/04/06, SVC‑03, TPR‑01/02

Pattern coverage: **100% of 65 active KSIs**.

Authoritative sync auto-updates RETIRED flags based on upstream JSON.

---

# 8. ANALYZER ARCHITECTURE & AST-FIRST REQUIREMENT
**Absolute rule:** Use **tree‑sitter AST** whenever available.

Supported languages: Python, C#, Java, TS/JS, Bicep, Terraform.

Regex allowed ONLY when:
1. AST **not available**, AND  
2. You add comment:
   ```
   # regex fallback — tree-sitter not available for <language>
   ```

AST utilities (must use):
- `find_nodes_by_type`
- `find_function_calls`
- `find_class_definitions`
- `find_method_definitions`
- `check_attribute_usage`
- `get_node_text`

Checklist (must be true):
- AST supported?  
- AST helpers used?  
- Regex used only with justification?  
- Tests verify AST detection accuracy?

---

# 9. DEVELOPMENT RULES
- Python 3.10+, MCP Python SDK 1.2+.  
- Logging → stderr only.  
- STDIO transport for MCP server.  
- Test output: ASCII (`[OK]`, `[FAIL]`).  
- Never use deprecated APIs without explicit confirmation of maintenance.

Tool registration:
- Add `*_impl` + wrapper in `tools/__init__.py`  
- Add matching tests in `tests/test_*_tools.py`

Template management:
- Use `get_infrastructure_template()`, `get_code_template()`, `load_prompt()`

---

# 10. TESTING & COMMIT WORKFLOW (CRITICAL)
1. Set GitHub token for CVE tests:
   ```powershell
   $env:GITHUB_TOKEN = (gh auth token)
   ```
2. Run tests:
   ```bash
   python tests/run_all_tests.py
   ```
3. Require:
   - **0 FAILURES**
   - Count passing tests & include summary in commit.
4. Commit only after all pass.
5. Never “hope CI passes” — must pass locally first.
6. Remove temporary scripts before commit.
7. Remove temporary files before commit.
8. Verify that documentation is accurate and up to date before commit.

---

# 11. VERSION MANAGEMENT — ALL 3 FILES REQUIRED
Update version **every release** in:
1. `pyproject.toml`
2. `server.json` (top-level + packages[0])
3. `src/fedramp_20x_mcp/__init__.py`

Tag release:
```bash
git tag -a vX.Y.Z -m "Release vX.Y.Z"
git push --tags
```

All 3 versions must match.

---

# 12. CONTENT SOURCING REQUIREMENTS
All recommendations must cite authoritative FedRAMP IDs or Azure Well-Architected/CAF/Security Benchmark.

**Correct:**  
“Configure Azure Bastion per Azure WAF Security (addresses KSI‑CNA‑01).”

**Incorrect:**  
“Use encryption everywhere.” (too vague, no ID)

---

# 13. PROHIBITED VS REQUIRED ACTIONS TABLE

| **Prohibited** | **Why** |
|----------------|---------|
| Weakening tests | Invalidates compliance & trust |
| Changing test semantics | Masks defects |
| Partial fixes | Violates “ALL” requirement |
| Substituting “better idea” | Breaks traceability to FedRAMP |
| Inventing FRR/KSI meanings | Produces false compliance |
| Regex when AST exists | Low accuracy |
| Silent changes | Prevents auditability |

| **Required** | **Why** |
|--------------|---------|
| Fix root cause | Ensures real compliance |
| Verify first | Ensures correctness |
| Provide evidence | Reproducibility |
| Use exact algorithm | No shortcuts |
| Show diffs | Transparency |
| Report numeric progress | Clarity |
| Ask when ambiguous | No assumptions |

---

# 14. COMPLIANCE VALIDATION GATE (SELF‑CHECK BEFORE ANY OUTPUT)
Assistant must verify:

- No shortcuts taken.  
- Instructions followed **literally**.  
- All authoritative sources read and cited.  
- Evidence shown (commands + outputs + counts).  
- AST used (regex fallback documented if used).  
- Numeric progress included.  
- Local test suite fully passed.  
- Version files updated (if release).

If ANY check fails → **stop and ask user**.

---

# 15. CONTRASTIVE EXAMPLES

**DO:**
- Keep tests strict; fix analyzers.  
- Quote authoritative JSON definitions.  
- Implement user-specified algorithm exactly.  
- Use AST-first.

**DON’T:**
- Relax assertions.  
- Infer meanings from memory.  
- Choose easier algorithms.  
- Use regex when AST exists.

---

# 16. VS CODE INLINE CHAT PROMPT TEMPLATE
Paste this when applying fixes:

```
Fix analyzer for KSI <ID> using EXACT user instructions.

Constraints:
- AST-first via analyzers/ast_utils.py
- No regex if AST exists
- Do NOT modify tests except to ADD missing valid cases
- Use replace-selection or diff-only output

Required Evidence:
1. Commands run
2. Test results with [OK]/[FAIL]
3. Numeric progress (X/Y analyzers)
```

---

# 17. APPENDIX — RECENT VIOLATION (DO NOT REPEAT)
- 63 tests originally failing due to missing findings.  
- Shortcut taken (weakened assertion).  
- Tests “passed” but validated nothing.  
- Wasted reviewer time, destroyed trust, caused rework.

**Lesson:**  
Always fix root cause; never weaken tests.
---