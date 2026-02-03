"""
Judge Implementations

Each judge evaluates a specific aspect of MCP server quality.
Judges can use different strategies:
- Ground truth comparison
- LLM-as-judge (optional, for subjective quality)
- Rule-based validation
- Statistical analysis
"""

import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Callable
from .metrics import EvaluationResult, EvaluationCategory, Verdict
from .test_cases import EvaluationTestCase

logger = logging.getLogger(__name__)


class BaseJudge(ABC):
    """Base class for all judges."""
    
    @property
    @abstractmethod
    def category(self) -> EvaluationCategory:
        """The evaluation category this judge handles."""
        pass
    
    @abstractmethod
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        """
        Evaluate a test case result.
        
        Args:
            test_case: The test case definition
            actual_result: The actual result from the tool
            latency_ms: Response latency in milliseconds
            
        Returns:
            EvaluationResult with verdict and score
        """
        pass
    
    def _check_contains(self, result: str, expected: List[str]) -> tuple[bool, List[str]]:
        """Check if result contains all expected strings (case-insensitive)."""
        result_lower = result.lower()
        missing = []
        for exp in expected:
            if exp.lower() not in result_lower:
                missing.append(exp)
        return len(missing) == 0, missing
    
    def _check_not_contains(self, result: str, forbidden: List[str]) -> tuple[bool, List[str]]:
        """Check if result does not contain forbidden strings."""
        result_lower = result.lower()
        found = []
        for forb in forbidden:
            if forb.lower() in result_lower:
                found.append(forb)
        return len(found) == 0, found
    
    def _check_pattern(self, result: str, pattern: str) -> bool:
        """Check if result matches regex pattern."""
        return bool(re.search(pattern, result, re.IGNORECASE | re.MULTILINE))
    
    def _check_min_length(self, result: str, min_length: int) -> bool:
        """Check if result meets minimum length."""
        return len(result) >= min_length
    
    def _check_json_keys(self, result: str, expected_keys: List[str]) -> tuple[bool, List[str]]:
        """Check if JSON result has expected keys."""
        try:
            data = json.loads(result)
            if isinstance(data, dict):
                missing = [k for k in expected_keys if k not in data]
                return len(missing) == 0, missing
        except json.JSONDecodeError:
            pass
        return False, expected_keys


class AccuracyJudge(BaseJudge):
    """
    Judges accuracy of tool responses against ground truth.
    
    Evaluates whether the MCP server returns factually correct information
    when compared to authoritative FedRAMP 20x sources.
    """
    
    @property
    def category(self) -> EvaluationCategory:
        return EvaluationCategory.ACCURACY
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        # Track all checks
        checks_passed = 0
        total_checks = 0
        issues = []
        
        # Check expected value (exact match)
        if test_case.expected_value is not None:
            total_checks += 1
            if result_str == str(test_case.expected_value):
                checks_passed += 1
            else:
                issues.append(f"Expected exact value not found")
        
        # Check expected contains
        if test_case.expected_contains:
            total_checks += 1
            passed, missing = self._check_contains(result_str, test_case.expected_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Missing expected content: {missing}")
        
        # Check expected not contains
        if test_case.expected_not_contains:
            total_checks += 1
            passed, found = self._check_not_contains(result_str, test_case.expected_not_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Found forbidden content: {found}")
        
        # Check pattern
        if test_case.expected_pattern:
            total_checks += 1
            if self._check_pattern(result_str, test_case.expected_pattern):
                checks_passed += 1
            else:
                issues.append(f"Pattern not matched: {test_case.expected_pattern}")
        
        # Check min length
        if test_case.expected_min_length:
            total_checks += 1
            if self._check_min_length(result_str, test_case.expected_min_length):
                checks_passed += 1
            else:
                issues.append(f"Result too short: {len(result_str)} < {test_case.expected_min_length}")
        
        # Check custom validation function
        if test_case.validation_func:
            total_checks += 1
            try:
                if test_case.validation_func(result_str):
                    checks_passed += 1
                else:
                    issues.append("Custom validation failed")
            except Exception as e:
                issues.append(f"Custom validation error: {e}")
        
        # Calculate score and verdict
        if total_checks == 0:
            # No validation criteria - just check we got a non-empty response
            if result_str and len(result_str) > 10:
                score = 1.0
                verdict = Verdict.PASS
                explanation = "Response received (no specific validation criteria)"
            else:
                score = 0.0
                verdict = Verdict.FAIL
                explanation = "Empty or minimal response"
        else:
            score = checks_passed / total_checks
            if score >= 1.0:
                verdict = Verdict.PASS
                explanation = f"All {total_checks} accuracy checks passed"
            elif score >= 0.5:
                verdict = Verdict.PARTIAL
                explanation = f"Partial accuracy: {checks_passed}/{total_checks} checks passed. Issues: {'; '.join(issues)}"
            else:
                verdict = Verdict.FAIL
                explanation = f"Accuracy check failed: {checks_passed}/{total_checks}. Issues: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=self.category,
            verdict=verdict,
            score=score,
            explanation=explanation,
            expected=test_case.expected_contains or test_case.expected_value,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"checks_passed": checks_passed, "total_checks": total_checks},
        )


class CompletenessJudge(BaseJudge):
    """
    Judges completeness of tool responses.
    
    Evaluates whether tools return all relevant information,
    not just partial results.
    """
    
    @property
    def category(self) -> EvaluationCategory:
        return EvaluationCategory.COMPLETENESS
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        checks_passed = 0
        total_checks = 0
        issues = []
        
        # Check expected contains
        if test_case.expected_contains:
            total_checks += 1
            passed, missing = self._check_contains(result_str, test_case.expected_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Missing expected items: {missing}")
        
        # Check custom validation (often used for count checks)
        if test_case.validation_func:
            total_checks += 1
            try:
                if test_case.validation_func(result_str):
                    checks_passed += 1
                else:
                    issues.append("Completeness validation failed (insufficient results)")
            except Exception as e:
                issues.append(f"Validation error: {e}")
        
        # Check JSON keys if specified
        if test_case.expected_json_keys:
            total_checks += 1
            passed, missing = self._check_json_keys(result_str, test_case.expected_json_keys)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Missing JSON keys: {missing}")
        
        # Calculate score
        if total_checks == 0:
            score = 1.0 if result_str else 0.0
            verdict = Verdict.PASS if result_str else Verdict.FAIL
            explanation = "Response received" if result_str else "No response"
        else:
            score = checks_passed / total_checks
            if score >= 1.0:
                verdict = Verdict.PASS
                explanation = f"Complete: all {total_checks} completeness checks passed"
            elif score >= 0.5:
                verdict = Verdict.PARTIAL
                explanation = f"Partial completeness: {checks_passed}/{total_checks}. {'; '.join(issues)}"
            else:
                verdict = Verdict.FAIL
                explanation = f"Incomplete: {checks_passed}/{total_checks}. {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=self.category,
            verdict=verdict,
            score=score,
            explanation=explanation,
            expected=test_case.expected_contains,
            actual=result_str[:500],
            latency_ms=latency_ms,
        )


class AnalysisQualityJudge(BaseJudge):
    """
    Judges quality of code analysis results.
    
    Evaluates whether analyzers correctly detect security issues
    and compliance violations with minimal false positives/negatives.
    """
    
    @property
    def category(self) -> EvaluationCategory:
        return EvaluationCategory.ANALYSIS_QUALITY
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        checks_passed = 0
        total_checks = 0
        issues = []
        
        # For analysis, we check if expected issues are detected
        if test_case.expected_contains:
            total_checks += 1
            passed, missing = self._check_contains(result_str, test_case.expected_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Expected findings not detected: {missing}")
        
        # Check for false positives (things that shouldn't be flagged)
        if test_case.expected_not_contains:
            total_checks += 1
            passed, found = self._check_not_contains(result_str, test_case.expected_not_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Possible false positives: {found}")
        
        # Custom validation for complex analysis checks
        if test_case.validation_func:
            total_checks += 1
            try:
                if test_case.validation_func(result_str):
                    checks_passed += 1
                else:
                    issues.append("Analysis quality validation failed")
            except Exception as e:
                issues.append(f"Validation error: {e}")
        
        # Check minimum length for analysis results
        if test_case.expected_min_length:
            total_checks += 1
            if self._check_min_length(result_str, test_case.expected_min_length):
                checks_passed += 1
            else:
                issues.append(f"Analysis result too short")
        
        # Calculate score
        if total_checks == 0:
            score = 1.0 if result_str and len(result_str) > 50 else 0.0
            verdict = Verdict.PASS if score > 0 else Verdict.FAIL
            explanation = "Analysis completed" if score > 0 else "No analysis results"
        else:
            score = checks_passed / total_checks
            if score >= 1.0:
                verdict = Verdict.PASS
                explanation = f"Analysis quality: all {total_checks} checks passed"
            elif score >= 0.5:
                verdict = Verdict.PARTIAL
                explanation = f"Partial detection: {checks_passed}/{total_checks}. {'; '.join(issues)}"
            else:
                verdict = Verdict.FAIL
                explanation = f"Analysis quality issues: {checks_passed}/{total_checks}. {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=self.category,
            verdict=verdict,
            score=score,
            explanation=explanation,
            expected=test_case.expected_contains,
            actual=result_str[:500],
            latency_ms=latency_ms,
        )


class RelevanceJudge(BaseJudge):
    """
    Judges relevance of search results and recommendations.
    
    Evaluates whether returned results are actually relevant
    to the query or request.
    """
    
    @property
    def category(self) -> EvaluationCategory:
        return EvaluationCategory.RELEVANCE
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        checks_passed = 0
        total_checks = 0
        issues = []
        
        # Check if relevant terms appear in results
        if test_case.expected_contains:
            total_checks += 1
            passed, missing = self._check_contains(result_str, test_case.expected_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Missing relevant terms: {missing}")
        
        # Custom relevance validation
        if test_case.validation_func:
            total_checks += 1
            try:
                if test_case.validation_func(result_str):
                    checks_passed += 1
                else:
                    issues.append("Relevance validation failed")
            except Exception as e:
                issues.append(f"Validation error: {e}")
        
        # Calculate score
        if total_checks == 0:
            score = 1.0 if result_str else 0.0
            verdict = Verdict.PASS if result_str else Verdict.FAIL
            explanation = "Results returned" if result_str else "No results"
        else:
            score = checks_passed / total_checks
            if score >= 1.0:
                verdict = Verdict.PASS
                explanation = f"Relevant results: all {total_checks} relevance checks passed"
            elif score >= 0.5:
                verdict = Verdict.PARTIAL
                explanation = f"Partially relevant: {checks_passed}/{total_checks}. {'; '.join(issues)}"
            else:
                verdict = Verdict.FAIL
                explanation = f"Irrelevant results: {checks_passed}/{total_checks}. {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=self.category,
            verdict=verdict,
            score=score,
            explanation=explanation,
            expected=test_case.expected_contains,
            actual=result_str[:500],
            latency_ms=latency_ms,
        )


class ConsistencyJudge(BaseJudge):
    """
    Judges consistency of repeated tool calls.
    
    Evaluates whether the same query returns consistent results
    across multiple invocations.
    """
    
    @property
    def category(self) -> EvaluationCategory:
        return EvaluationCategory.CONSISTENCY
    
    def __init__(self):
        self._result_cache: Dict[str, List[str]] = {}
    
    def record_result(self, test_case_id: str, result: str) -> None:
        """Record a result for consistency checking."""
        if test_case_id not in self._result_cache:
            self._result_cache[test_case_id] = []
        self._result_cache[test_case_id].append(result)
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        # Record this result
        self.record_result(test_case.id, result_str)
        
        # Get previous results
        previous_results = self._result_cache.get(test_case.id, [])
        
        # First check - also do standard validation
        checks_passed = 0
        total_checks = 0
        issues = []
        
        # Standard content checks
        if test_case.expected_contains:
            total_checks += 1
            passed, missing = self._check_contains(result_str, test_case.expected_contains)
            if passed:
                checks_passed += 1
            else:
                issues.append(f"Missing expected content: {missing}")
        
        # Consistency check if we have multiple results
        if len(previous_results) >= 2:
            total_checks += 1
            # Compare last two results
            last_result = previous_results[-1]
            prev_result = previous_results[-2]
            
            # Results should be identical for deterministic queries
            if last_result == prev_result:
                checks_passed += 1
            else:
                # Check if at least 90% similar
                similarity = self._calculate_similarity(last_result, prev_result)
                if similarity >= 0.9:
                    checks_passed += 0.9  # Partial credit
                    issues.append(f"Results slightly different (similarity: {similarity:.1%})")
                else:
                    issues.append(f"Results inconsistent (similarity: {similarity:.1%})")
        
        # Calculate score
        if total_checks == 0:
            score = 1.0 if result_str else 0.0
            verdict = Verdict.PASS if result_str else Verdict.FAIL
            explanation = "First result recorded" if result_str else "No result"
        else:
            score = checks_passed / total_checks
            if score >= 0.95:
                verdict = Verdict.PASS
                explanation = f"Consistent results across {len(previous_results)} calls"
            elif score >= 0.7:
                verdict = Verdict.PARTIAL
                explanation = f"Mostly consistent: {'; '.join(issues)}"
            else:
                verdict = Verdict.FAIL
                explanation = f"Inconsistent results: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=self.category,
            verdict=verdict,
            score=score,
            explanation=explanation,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"call_count": len(previous_results)},
        )
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity ratio between two strings."""
        if str1 == str2:
            return 1.0
        if not str1 or not str2:
            return 0.0
        
        # Simple word-based Jaccard similarity
        words1 = set(str1.lower().split())
        words2 = set(str2.lower().split())
        
        intersection = len(words1 & words2)
        union = len(words1 | words2)
        
        return intersection / union if union > 0 else 0.0
    
    def reset(self) -> None:
        """Reset the result cache."""
        self._result_cache.clear()


# Factory function to get appropriate judge
def get_judge(category: EvaluationCategory) -> BaseJudge:
    """Get the appropriate judge for a category."""
    judges = {
        EvaluationCategory.ACCURACY: AccuracyJudge,
        EvaluationCategory.COMPLETENESS: CompletenessJudge,
        EvaluationCategory.ANALYSIS_QUALITY: AnalysisQualityJudge,
        EvaluationCategory.RELEVANCE: RelevanceJudge,
        EvaluationCategory.CONSISTENCY: ConsistencyJudge,
    }
    return judges[category]()
