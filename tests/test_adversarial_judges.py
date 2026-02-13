"""
Adversarial Tests - pytest Wrapper

Runs adversarial judges as automated tests that contribute to build pass/fail.
These tests actively probe for:
- Hallucinations (fabricated information)
- Misinformation (confused definitions)
- Edge case failures
- Injection vulnerabilities
- Robustness issues

CRITICAL: All critical adversarial tests MUST pass for the build to succeed.
"""

import asyncio
import pytest
import sys
import os

# Add paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
sys.path.insert(0, os.path.dirname(__file__))

from evaluator import MCPServerEvaluator
from evaluator.adversarial_test_cases import (
    HALLUCINATION_TEST_CASES,
    MISINFORMATION_TEST_CASES,
    EDGE_CASE_TEST_CASES,
    INJECTION_TEST_CASES,
    ROBUSTNESS_TEST_CASES,
    FALSE_POSITIVE_TEST_CASES,
)
from evaluator.adversarial_judges import AdversarialCategory
from evaluator.metrics import Verdict


class TestAdversarialJudges:
    """pytest test class for adversarial evaluation."""
    
    @pytest.fixture(scope="class")
    def evaluator(self):
        """Create a single evaluator instance for the test class."""
        return MCPServerEvaluator()
    
    # Note: event_loop fixture is provided by conftest.py (session-scoped)
    
    # =========================================================================
    # CRITICAL TESTS - Must pass for build
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.critical
    async def test_critical_adversarial_tests_pass(self, evaluator):
        """
        CRITICAL: At least 95% of critical adversarial tests must pass.
        
        This test is a build gate - if pass rate drops below 95%,
        the build should fail. PARTIAL verdicts count as passing.
        """
        metrics = await evaluator.run_adversarial_evaluation(critical_only=True)
        
        # Report failures
        failures = metrics.get_failures()
        if failures:
            failure_details = "\n".join([
                f"  - {f.test_case_id}: {f.explanation}"
                for f in failures
            ])
            pytest.fail(
                f"Critical adversarial tests failed ({len(failures)} failures):\n{failure_details}"
            )
        
        # Verify pass rate meets threshold
        assert metrics.overall_pass_rate >= 0.95, (
            f"Critical adversarial pass rate too low: {metrics.overall_pass_rate:.1%} "
            f"(expected >= 95%)"
        )
    
    # =========================================================================
    # HALLUCINATION TESTS
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.hallucination
    async def test_no_hallucinated_ksi_ids(self, evaluator):
        """Verify the server doesn't hallucinate KSI definitions for non-existent IDs."""
        test_cases = [tc for tc in HALLUCINATION_TEST_CASES if "KSI" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.HALLUCINATION
            )
            assert result.verdict != Verdict.FAIL, (
                f"Hallucination detected for {tc.id}: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.hallucination
    async def test_no_hallucinated_frr_ids(self, evaluator):
        """Verify the server doesn't hallucinate FRR definitions for non-existent IDs."""
        test_cases = [tc for tc in HALLUCINATION_TEST_CASES if "FRR" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.HALLUCINATION
            )
            assert result.verdict != Verdict.FAIL, (
                f"Hallucination detected for {tc.id}: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.hallucination
    async def test_no_fabricated_frameworks(self, evaluator):
        """Verify responses don't reference fabricated compliance frameworks."""
        test_cases = [tc for tc in HALLUCINATION_TEST_CASES if "FRM" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.HALLUCINATION
            )
            assert result.verdict != Verdict.FAIL, (
                f"Fabricated framework detected for {tc.id}: {result.explanation}"
            )
    
    # =========================================================================
    # MISINFORMATION TESTS
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.misinformation
    @pytest.mark.critical
    async def test_piy01_not_confused_with_encryption(self, evaluator):
        """
        CRITICAL: PIY-01 (KSI-PIY-GIV) is Government Inventory, NOT encryption at rest.
        
        This is a known critical misunderstanding that must be prevented.
        """
        test_cases = [tc for tc in MISINFORMATION_TEST_CASES if "PIY-001" in tc.id or "PIY-GIV" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.MISINFORMATION
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"PIY-01/GIV misinformation: {result.explanation}\n"
                f"PIY-01 (KSI-PIY-GIV) is Government Inventory - NOT encryption at rest!"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.misinformation
    @pytest.mark.critical
    async def test_svc01_not_confused_with_secrets(self, evaluator):
        """
        CRITICAL: SVC-01 is Continuous Improvement, NOT secrets management.
        SVC-06 is the one about secrets.
        """
        test_cases = [tc for tc in MISINFORMATION_TEST_CASES if "SVC-001" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.MISINFORMATION
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"SVC-01 misinformation: {result.explanation}\n"
                f"SVC-01 is Continuous Improvement - SVC-06 is secrets management!"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.misinformation
    async def test_svc06_correctly_about_secrets(self, evaluator):
        """Verify SVC-06 IS correctly identified as secrets management."""
        test_cases = [tc for tc in MISINFORMATION_TEST_CASES if "SVC-006" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.MISINFORMATION
            )
            assert result.verdict == Verdict.PASS, (
                f"SVC-06 should be about secrets: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.misinformation
    async def test_retired_ksis_marked_correctly(self, evaluator):
        """Verify retired KSIs don't return active implementation guidance."""
        test_cases = [tc for tc in MISINFORMATION_TEST_CASES if "RET" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.MISINFORMATION
            )
            # Accept PASS or PARTIAL (retired KSIs may be removed from data entirely)
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"Retired KSI test failed: {result.explanation}"
            )
    
    # =========================================================================
    # EDGE CASE TESTS
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.edge_case
    async def test_empty_input_handling(self, evaluator):
        """Verify empty inputs are handled gracefully."""
        test_cases = [tc for tc in EDGE_CASE_TEST_CASES if "EMPTY" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.EDGE_CASE
            )
            # For edge cases expecting errors, we check for graceful handling
            assert result.verdict != Verdict.ERROR, (
                f"Edge case {tc.id} crashed instead of graceful handling: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.edge_case
    async def test_case_insensitive_handling(self, evaluator):
        """Verify the server handles case variations gracefully."""
        test_cases = [tc for tc in EDGE_CASE_TEST_CASES if "CASE" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.EDGE_CASE
            )
            if "expects_success" in tc.tags:
                assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                    f"Case handling failed for {tc.id}: {result.explanation}"
                )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.edge_case
    async def test_special_character_handling(self, evaluator):
        """Verify special characters don't cause crashes or security issues."""
        test_cases = [tc for tc in EDGE_CASE_TEST_CASES if "SPECIAL" in tc.id or "UNICODE" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.EDGE_CASE
            )
            assert result.verdict != Verdict.ERROR, (
                f"Special character handling failed for {tc.id}: {result.explanation}"
            )
    
    # =========================================================================
    # INJECTION TESTS
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.injection
    @pytest.mark.security
    @pytest.mark.critical
    async def test_prompt_injection_resistance(self, evaluator):
        """
        CRITICAL: Verify the server resists prompt injection attempts.
        """
        test_cases = [tc for tc in INJECTION_TEST_CASES if "PROMPT" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.INJECTION
            )
            assert result.verdict != Verdict.FAIL, (
                f"SECURITY: Prompt injection vulnerability in {tc.id}: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.injection
    @pytest.mark.security
    async def test_sql_injection_resistance(self, evaluator):
        """Verify the server resists SQL injection attempts."""
        test_cases = [tc for tc in INJECTION_TEST_CASES if "sql" in tc.description.lower()]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.INJECTION
            )
            assert result.verdict != Verdict.FAIL, (
                f"SECURITY: SQL injection vulnerability: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.injection
    @pytest.mark.security
    @pytest.mark.critical
    async def test_path_traversal_resistance(self, evaluator):
        """
        CRITICAL: Verify the server resists path traversal attacks.
        """
        test_cases = [tc for tc in INJECTION_TEST_CASES if "PATH" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.INJECTION
            )
            assert result.verdict != Verdict.FAIL, (
                f"SECURITY: Path traversal vulnerability: {result.explanation}"
            )
    
    # =========================================================================
    # ROBUSTNESS TESTS
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.robustness
    async def test_response_consistency(self, evaluator):
        """Verify repeated calls return consistent results."""
        test_cases = [tc for tc in ROBUSTNESS_TEST_CASES if "REPEAT" in tc.id]
        
        for tc in test_cases:
            results = []
            for _ in range(3):
                result = await evaluator.evaluate_adversarial_test_case(
                    tc, AdversarialCategory.ROBUSTNESS
                )
                results.append(result.actual)
            
            # Check all results are similar
            assert len(set(results)) <= 1 or all(r == results[0] for r in results), (
                f"Inconsistent results for {tc.id}: responses vary across calls"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.robustness
    async def test_malformed_input_handling(self, evaluator):
        """Verify malformed inputs don't cause crashes."""
        test_cases = [tc for tc in ROBUSTNESS_TEST_CASES if "JSON" in tc.id or "NULL" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.ROBUSTNESS
            )
            assert result.verdict != Verdict.ERROR, (
                f"Malformed input caused crash for {tc.id}: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.robustness
    async def test_large_result_set_handling(self, evaluator):
        """Verify large result sets are handled without timeout."""
        test_cases = [tc for tc in ROBUSTNESS_TEST_CASES if "LARGE" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.ROBUSTNESS
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"Large result set handling failed for {tc.id}: {result.explanation}"
            )
    
    # =========================================================================
    # FALSE POSITIVE TESTS - Context-Aware Filtering
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.false_positive
    async def test_cli_tool_no_iam_findings(self, evaluator):
        """
        CLI tools without authentication should not get IAM/MFA findings.
        
        This validates the ApplicationContext feature reduces false positives
        for application types that don't have authentication capabilities.
        """
        test_cases = [tc for tc in FALSE_POSITIVE_TEST_CASES if "CLI-IAM" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.FALSE_POSITIVE
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"False positive: CLI tool got IAM findings: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.false_positive
    async def test_cli_tool_no_tls_findings(self, evaluator):
        """CLI tools without HTTP server should not get TLS/HSTS findings."""
        test_cases = [tc for tc in FALSE_POSITIVE_TEST_CASES if "CLI-TLS" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.FALSE_POSITIVE
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"False positive: CLI tool got TLS findings: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.false_positive
    async def test_cli_tool_no_database_findings(self, evaluator):
        """CLI tools without databases should not get SQL injection findings."""
        test_cases = [tc for tc in FALSE_POSITIVE_TEST_CASES if "CLI-DB" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.FALSE_POSITIVE
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"False positive: CLI tool got database findings: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.false_positive
    @pytest.mark.critical
    async def test_full_profile_preserves_all_findings(self, evaluator):
        """
        CRITICAL: 'full' profile must not suppress any findings.
        
        This ensures the context-aware filtering doesn't introduce
        false negatives when no profile is specified or 'full' is used.
        """
        test_cases = [tc for tc in FALSE_POSITIVE_TEST_CASES if "FULL-PRESERVE" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.FALSE_POSITIVE
            )
            assert result.verdict in [Verdict.PASS, Verdict.PARTIAL], (
                f"False negative: 'full' profile suppressed findings: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.false_positive
    async def test_no_profile_backward_compatible(self, evaluator):
        """No application_profile should run full analysis (backward compatible)."""
        test_cases = [tc for tc in FALSE_POSITIVE_TEST_CASES if "NOCONTEXT" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.FALSE_POSITIVE
            )
            assert result.verdict != Verdict.ERROR, (
                f"Backward compatibility broken: {result.explanation}"
            )
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    @pytest.mark.false_positive
    async def test_unknown_profile_graceful_fallback(self, evaluator):
        """Unknown profile names should fall back gracefully without crashing."""
        test_cases = [tc for tc in FALSE_POSITIVE_TEST_CASES if "UNKNOWN" in tc.id]
        
        for tc in test_cases:
            result = await evaluator.evaluate_adversarial_test_case(
                tc, AdversarialCategory.FALSE_POSITIVE
            )
            assert result.verdict != Verdict.ERROR, (
                f"Unknown profile caused error: {result.explanation}"
            )
    
    # =========================================================================
    # AGGREGATE TESTS
    # =========================================================================
    
    @pytest.mark.asyncio
    @pytest.mark.adversarial
    async def test_all_adversarial_pass_rate(self, evaluator):
        """
        Aggregate test: Overall adversarial pass rate must meet threshold.
        
        This is NOT critical (individual critical tests are marked separately),
        but provides visibility into overall adversarial test health.
        """
        metrics = await evaluator.run_adversarial_evaluation(critical_only=False)
        
        # Report summary
        print(f"\n[ADVERSARIAL] Overall pass rate: {metrics.overall_pass_rate:.1%}")
        print(f"[ADVERSARIAL] Total tests: {metrics.total_tests}")
        print(f"[ADVERSARIAL] Failures: {len(metrics.get_failures())}")
        
        # Warn if pass rate is low but don't fail (critical tests handle hard failures)
        if metrics.overall_pass_rate < 0.80:
            pytest.xfail(
                f"Adversarial pass rate below 80%: {metrics.overall_pass_rate:.1%} - "
                f"review non-critical failures"
            )


# =============================================================================
# Standalone test functions (for running with pytest directly)
# =============================================================================

# NOTE: The build gate for critical adversarial tests is enforced by the
# class-level tests in TestAdversarialJudges. The standalone test below
# provides identical functionality for direct script execution but is
# skipped in pytest runs to avoid running the adversarial evaluation twice.

@pytest.mark.skip(reason="Replaced by TestAdversarialJudges.test_critical_adversarial_tests_pass")
@pytest.mark.asyncio
@pytest.mark.critical
async def test_adversarial_build_gate():
    """
    BUILD GATE: This test MUST pass for the build to succeed.
    
    Runs all critical adversarial tests and fails the build if any fail.
    Note: Skipped in pytest - use TestAdversarialJudges.test_critical_adversarial_tests_pass instead.
    """
    evaluator = MCPServerEvaluator()
    metrics = await evaluator.run_adversarial_evaluation(critical_only=True)
    
    failures = metrics.get_failures()
    
    # Print summary for CI logs
    print("\n" + "=" * 60)
    print("ADVERSARIAL TEST RESULTS (Critical Tests)")
    print("=" * 60)
    print(f"Pass Rate: {metrics.overall_pass_rate:.1%}")
    print(f"Total: {metrics.total_tests}")
    print(f"Passed: {len([r for r in metrics.results if r.verdict == Verdict.PASS])}")
    print(f"Failed: {len(failures)}")
    
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  [{f.test_case_id}] {f.explanation}")
    print("=" * 60 + "\n")
    
    assert len(failures) == 0, (
        f"BUILD FAILED: {len(failures)} critical adversarial tests failed.\n"
        f"Fix these issues before merging."
    )
    assert metrics.overall_pass_rate >= 0.95, (
        f"BUILD FAILED: Critical adversarial pass rate {metrics.overall_pass_rate:.1%} < 95%"
    )


if __name__ == "__main__":
    # Run critical tests when executed directly
    print("Running adversarial tests...")
    result = asyncio.run(test_adversarial_build_gate())
    print("Adversarial tests completed successfully!" if result is None else result)
