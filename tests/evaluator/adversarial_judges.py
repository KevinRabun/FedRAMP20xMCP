"""
Adversarial Judges

Actively probe and challenge the MCP server to detect:
- Hallucinations (fabricated information)
- Misinformation (confused/mixed-up definitions)
- Edge case failures
- Prompt injection vulnerabilities
- Robustness issues with malformed input

These judges are part of the build gate: the build must not pass if they
detect quality or accuracy issues that standard unit tests miss.
"""

import re
import json
import logging
from abc import ABC, abstractmethod
from typing import Any, List, Optional, Set, Tuple
from .metrics import EvaluationResult, EvaluationCategory, Verdict
from .test_cases import EvaluationTestCase

logger = logging.getLogger(__name__)


class AdversarialCategory:
    """Extended categories for adversarial testing."""
    HALLUCINATION = "hallucination"
    MISINFORMATION = "misinformation"
    EDGE_CASE = "edge_case"
    INJECTION = "injection"
    ROBUSTNESS = "robustness"
    FALSE_POSITIVE = "false_positive"


class BaseAdversarialJudge(ABC):
    """Base class for adversarial judges."""
    
    @property
    @abstractmethod
    def adversarial_type(self) -> str:
        """The adversarial test type this judge handles."""
        pass
    
    @abstractmethod
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        """Evaluate a test case result adversarially."""
        pass


class HallucinationJudge(BaseAdversarialJudge):
    """
    Detects hallucinated (fabricated) information in responses.
    
    Strategies:
    1. Check for references to non-existent KSIs/FRRs
    2. Verify cited IDs actually exist in authoritative data
    3. Detect made-up compliance frameworks or standards
    4. Catch fabricated implementation guidance
    """
    
    def __init__(self):
        # Lists of valid IDs loaded from authoritative sources
        self._valid_ksi_ids: Optional[Set[str]] = None
        self._valid_frr_ids: Optional[Set[str]] = None
        self._valid_families: Set[str] = {
            "ADS", "AFR", "CCM", "CED", "CMT", "CNA", "FSI", 
            "IAM", "ICP", "INR", "MAS", "MLA", "PIY", "PVA",
            "RPL", "RSC", "SCN", "SVC", "TPR", "UCM", "VDR"
        }
        # Retired KSI IDs that should be marked as such
        self._retired_ksi_ids: Set[str] = {
            "KSI-CMT-05", "KSI-MLA-03", "KSI-MLA-04", "KSI-MLA-06",
            "KSI-SVC-03", "KSI-TPR-01", "KSI-TPR-02"
        }
        
    @property
    def adversarial_type(self) -> str:
        return AdversarialCategory.HALLUCINATION
    
    def _load_valid_ids(self, data_loader=None) -> None:
        """Load valid IDs from data sources.

        If a data_loader is provided, it should return a mapping that includes
        iterables of KSI and FRR IDs (e.g., {"ksi_ids": [...], "frr_ids": [...]}).
        When no loader is provided or loading fails, fall back to synthetic
        generation of legacy numeric IDs to preserve existing behavior.
        """
        # If we've already populated both KSI and FRR IDs, no work is needed.
        if self._valid_ksi_ids is not None and self._valid_frr_ids is not None:
            return

        # First, try to load IDs from an authoritative data source if provided.
        if data_loader is not None:
            try:
                data = data_loader()
                ksi_ids = None
                frr_ids = None
                if isinstance(data, dict):
                    ksi_ids = data.get("ksi_ids")
                    frr_ids = data.get("frr_ids")
                # Accept any iterable collections for IDs.
                if ksi_ids is not None and frr_ids is not None:
                    self._valid_ksi_ids = set(ksi_ids)
                    self._valid_frr_ids = set(frr_ids)
                    return
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning(
                    "Failed to load KSI/FRR IDs from data_loader, "
                    "falling back to synthetic ID generation: %s",
                    exc,
                )

        # Fall back to building legacy numeric KSI IDs from known patterns.
        self._valid_ksi_ids = set()
        for family in self._valid_families:
            for i in range(1, 20):  # Max expected per family
                self._valid_ksi_ids.add(f"KSI-{family}-{i:02d}")

        # Build legacy numeric FRR IDs.
        self._valid_frr_ids = set()
        for family in self._valid_families:
            for i in range(1, 50):  # Max expected per family
                self._valid_frr_ids.add(f"FRR-{family}-{i:02d}")
    
    def _extract_ids(self, text: str) -> Tuple[Set[str], Set[str]]:
        """Extract KSI and FRR IDs from text.

        Supports both legacy numeric IDs (e.g., KSI-PIY-01, FRR-IAM-12)
        and newer descriptive suffix IDs (e.g., KSI-PIY-GIV, KSI-IAM-MFA).
        """
        # Match family (2–3 uppercase letters) and either a numeric or short
        # alphabetic suffix. Word boundaries prevent partial matches.
        ksi_pattern = r'\bKSI-[A-Z]{2,3}-(?:\d{1,2}|[A-Z]{2,4})\b'
        frr_pattern = r'\bFRR-[A-Z]{2,3}-(?:\d{1,2}|[A-Z]{2,4})\b'

        ksi_ids = set(re.findall(ksi_pattern, text))
        frr_ids = set(re.findall(frr_pattern, text))
        
        return ksi_ids, frr_ids
    
    def _detect_hallucinated_frameworks(self, text: str) -> List[str]:
        """Detect references to made-up compliance frameworks."""
        # Real frameworks we accept
        real_frameworks = {
            "fedramp", "nist", "cis", "iso", "soc", "pci", "hipaa", "gdpr",
            "fisma", "fips", "sp 800", "800-53", "csf", "ramp"
        }
        
        # Patterns that look like framework references but are suspicious
        suspicious_patterns = [
            r'\b[A-Z]{3,5}-\d{3,5}\b',  # Like "COMP-12345"
            r'\bSection\s+\d+\.\d+\.\d+\s+of\s+\w+\b',  # Made-up section refs
        ]
        
        hallucinations = []
        for pattern in suspicious_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                # Check if it's not a real known pattern
                match_lower = match.lower()
                if not any(real in match_lower for real in real_frameworks):
                    # Check if it's not a valid KSI/FRR format
                    if not re.match(r'(KSI|FRR)-[A-Z]{2,3}-\d{1,2}', match):
                        hallucinations.append(match)
        
        return hallucinations
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        self._load_valid_ids()
        result_str = str(actual_result) if actual_result else ""
        result_lower = result_str.lower()
        
        issues = []
        score = 1.0
        
        # Check for "not found" or error response patterns - these are expected for invalid inputs
        is_error_response = any(phrase in result_lower for phrase in [
            "not found", "invalid", "error", "unknown", "does not exist"
        ])
        
        # Check 1: Verify all referenced KSI IDs exist (but skip if it's in error context)
        ksi_ids, frr_ids = self._extract_ids(result_str)
        
        invalid_ksis = []
        for ksi_id in ksi_ids:
            # Normalize format - handle both numeric (KSI-IAM-01) and descriptive (KSI-IAM-MFA)
            parts = ksi_id.split('-')
            if len(parts) == 3:
                suffix = parts[2]
                # Try to normalize numeric IDs
                if suffix.isdigit():
                    normalized = f"KSI-{parts[1]}-{int(parts[2]):02d}"
                else:
                    normalized = ksi_id  # Keep descriptive IDs as-is
                if normalized not in self._valid_ksi_ids:
                    # Only flag if NOT in an error response context
                    # (error messages legitimately echo invalid IDs back)
                    if not is_error_response:
                        invalid_ksis.append(ksi_id)
        
        if invalid_ksis:
            issues.append(f"Hallucinated KSI IDs: {invalid_ksis}")
            score -= 0.3 * len(invalid_ksis)
        
        # Check 2: Verify all referenced FRR IDs exist (same logic)
        invalid_frrs = []
        for frr_id in frr_ids:
            parts = frr_id.split('-')
            if len(parts) == 3:
                suffix = parts[2]
                # Try to normalize numeric IDs
                if suffix.isdigit():
                    normalized = f"FRR-{parts[1]}-{int(parts[2]):02d}"
                else:
                    normalized = frr_id  # Keep descriptive IDs as-is
                if normalized not in self._valid_frr_ids:
                    if not is_error_response:
                        invalid_frrs.append(frr_id)
        
        if invalid_frrs:
            issues.append(f"Hallucinated FRR IDs: {invalid_frrs}")
            score -= 0.3 * len(invalid_frrs)
        
        # Check 3: Detect hallucinated frameworks
        fake_frameworks = self._detect_hallucinated_frameworks(result_str)
        if fake_frameworks:
            issues.append(f"Suspicious framework references: {fake_frameworks[:3]}")
            score -= 0.2
        
        # Check 4: Validate against expected content if provided
        if test_case.expected_not_contains:
            for forbidden in test_case.expected_not_contains:
                if forbidden.lower() in result_lower:
                    issues.append(f"Contains forbidden hallucination trigger: '{forbidden}'")
                    score -= 0.4
        
        score = max(0.0, score)
        
        if score >= 0.9:
            verdict = Verdict.PASS
            explanation = "No hallucinations detected"
        elif score >= 0.5:
            verdict = Verdict.PARTIAL
            explanation = f"Possible hallucinations: {'; '.join(issues)}"
        else:
            verdict = Verdict.FAIL
            explanation = f"Hallucinations detected: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=EvaluationCategory.ACCURACY,  # Maps to accuracy
            verdict=verdict,
            score=score,
            explanation=explanation,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"adversarial_type": self.adversarial_type, "issues": issues},
        )


class MisinformationJudge(BaseAdversarialJudge):
    """
    Detects misinformation (confused/mixed-up definitions).
    
    Critical misunderstandings to catch (from copilot-instructions.md):
    - PIY-01 (KSI-PIY-GIV) = Government Inventory, NOT encryption at rest
    - SVC-01 ≠ "Secrets Management" → SVC-06 is secrets
    
    Note: KSI IDs have transitioned to new format (e.g., KSI-PIY-GIV instead of KSI-PIY-01)
    Legacy IDs are mapped via fka (formerly-known-as) mapping in the data loader.
    """
    
    def __init__(self):
        # Known critical misunderstandings to check
        # Supports both legacy (KSI-XXX-01) and new (KSI-XXX-ABC) formats
        # Note: For SVC-01, we don't require specific wording since descriptive IDs
        # may use different terminology - we only check it's NOT about secrets
        self._critical_mappings = {
            # KSI-ID: (correct_topic, wrong_associations)
            "KSI-PIY-01": {
                "correct": ["inventory", "inventories", "asset", "government"],
                "wrong": ["encryption at rest", "encrypt data"],
            },
            "KSI-PIY-GIV": {  # New format for Government Inventory
                "correct": ["inventory", "inventories", "asset", "government"],
                "wrong": ["encryption at rest", "encrypt data"],
            },
            "KSI-SVC-01": {
                "correct": [],  # Don't require specific wording - may vary with descriptive ID
                "wrong": ["secrets", "secret management", "key rotation", "credential"],
            },
            "KSI-SVC-06": {
                "correct": ["secret", "secrets management", "keys", "certificates", "credential"],
                "wrong": [],  # This IS about secrets
            },
        }
        
    @property
    def adversarial_type(self) -> str:
        return AdversarialCategory.MISINFORMATION
    
    def _check_ksi_accuracy(self, ksi_id: str, response: str) -> Tuple[bool, List[str]]:
        """Check if response about a KSI contains correct information."""
        if ksi_id not in self._critical_mappings:
            return True, []
        
        mapping = self._critical_mappings[ksi_id]
        response_lower = response.lower()
        issues = []
        
        # Check for wrong associations
        for wrong_term in mapping["wrong"]:
            if wrong_term in response_lower:
                # Allow if correct terms are also present (context might be comparison)
                has_correct = any(c in response_lower for c in mapping["correct"]) if mapping["correct"] else False
                if not has_correct:
                    correct_desc = mapping['correct'][0] if mapping['correct'] else "not related to this topic"
                    issues.append(
                        f"Misinformation: {ksi_id} associated with '{wrong_term}' "
                        f"(should be: {correct_desc})"
                    )
        
        # Check if correct information is present
        has_any_correct = any(c in response_lower for c in mapping["correct"])
        if not has_any_correct and mapping["correct"]:
            issues.append(
                f"Missing correct association for {ksi_id}: expected one of {mapping['correct']}"
            )
        
        return len(issues) == 0, issues
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        issues = []
        score = 1.0
        
        # Extract KSI ID from test case if present
        ksi_id = test_case.tool_params.get("ksi_id", "")
        
        if ksi_id:
            passed, ksi_issues = self._check_ksi_accuracy(ksi_id, result_str)
            if not passed:
                issues.extend(ksi_issues)
                score -= 0.5 * len(ksi_issues)
        
        # Generic misinformation checks
        # Check for contradictory statements
        if "encrypt" in result_str.lower() and "inventory" in result_str.lower():
            # Context-dependent - if discussing PIY-01, encryption is wrong
            if "PIY-01" in result_str or ksi_id == "KSI-PIY-01":
                if not any(phrase in result_str.lower() for phrase in ["does not", "is not", "unrelated"]):
                    issues.append("Possible confusion: PIY-01 is about inventory, not encryption")
                    score -= 0.3
        
        # Check expected validation criteria
        if test_case.expected_contains:
            missing = []
            for expected in test_case.expected_contains:
                if expected.lower() not in result_str.lower():
                    missing.append(expected)
            if missing:
                issues.append(f"Missing expected accurate content: {missing}")
                score -= 0.2 * len(missing)
        
        if test_case.expected_not_contains:
            found = []
            for forbidden in test_case.expected_not_contains:
                if forbidden.lower() in result_str.lower():
                    found.append(forbidden)
            if found:
                issues.append(f"Contains misinformation triggers: {found}")
                score -= 0.3 * len(found)
        
        score = max(0.0, min(1.0, score))
        
        if score >= 0.9:
            verdict = Verdict.PASS
            explanation = "No misinformation detected"
        elif score >= 0.5:
            verdict = Verdict.PARTIAL
            explanation = f"Possible misinformation: {'; '.join(issues)}"
        else:
            verdict = Verdict.FAIL
            explanation = f"Misinformation detected: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=EvaluationCategory.ACCURACY,
            verdict=verdict,
            score=score,
            explanation=explanation,
            expected=test_case.expected_contains,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"adversarial_type": self.adversarial_type, "issues": issues},
        )


class EdgeCaseJudge(BaseAdversarialJudge):
    """
    Tests edge cases and boundary conditions.
    
    Probes:
    - Empty inputs
    - Invalid IDs
    - Boundary values
    - Unusual but valid inputs
    - Unicode and special characters
    """
    
    @property
    def adversarial_type(self) -> str:
        return AdversarialCategory.EDGE_CASE
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        issues = []
        score = 1.0
        
        # Check for graceful error handling
        error_indicators = ["error", "exception", "traceback", "failed", "invalid"]
        
        # For edge case tests, we expect either:
        # 1. Graceful error message (for invalid inputs)
        # 2. Valid response (for unusual but valid inputs)
        
        is_error_response = any(ind in result_str.lower() for ind in error_indicators)
        is_empty_response = len(result_str.strip()) < 10
        
        # Check test case expectations
        expects_error = test_case.tags and "expects_error" in test_case.tags
        expects_success = test_case.tags and "expects_success" in test_case.tags
        
        if expects_error:
            # Should get a clear error, not crash or empty
            if is_empty_response:
                issues.append("Empty response for invalid input (should return clear error)")
                score -= 0.5
            elif "traceback" in result_str.lower() or "exception" in result_str.lower():
                issues.append("Raw exception leaked instead of graceful error")
                score -= 0.3
            elif not is_error_response:
                issues.append("No error indication for invalid input")
                score -= 0.4
        elif expects_success:
            if is_empty_response:
                issues.append("Empty response for valid edge case input")
                score -= 0.5
            if "traceback" in result_str.lower():
                issues.append("Unexpected error for valid input")
                score -= 0.5
        else:
            # Default behavior - no crashes
            if "traceback" in result_str.lower():
                issues.append("Unhandled exception detected")
                score -= 0.5
        
        # Check for proper validation messages
        if test_case.expected_contains:
            for expected in test_case.expected_contains:
                if expected.lower() not in result_str.lower():
                    issues.append(f"Missing expected response: '{expected}'")
                    score -= 0.2
        
        # Check that forbidden content is not present
        if getattr(test_case, "expected_not_contains", None):
            for unexpected in test_case.expected_not_contains:
                if unexpected.lower() in result_str.lower():
                    issues.append(f"Unexpected content in response: '{unexpected}'")
                    score -= 0.2
        
        score = max(0.0, min(1.0, score))
        
        if score >= 0.9:
            verdict = Verdict.PASS
            explanation = "Edge case handled correctly"
        elif score >= 0.5:
            verdict = Verdict.PARTIAL
            explanation = f"Edge case partially handled: {'; '.join(issues)}"
        else:
            verdict = Verdict.FAIL
            explanation = f"Edge case handling failed: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=EvaluationCategory.ACCURACY,
            verdict=verdict,
            score=score,
            explanation=explanation,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"adversarial_type": self.adversarial_type, "issues": issues},
        )


class InjectionJudge(BaseAdversarialJudge):
    """
    Tests for prompt injection vulnerabilities.
    
    Ensures the server doesn't:
    - Follow injected instructions
    - Leak system prompts
    - Execute malicious patterns in inputs
    
    Note: Error messages that echo back the user's input are expected behavior,
    not injection vulnerabilities. We check for actual injection success indicators.
    """
    
    def __init__(self):
        # Patterns that indicate injection SUCCESS (not just echoing input)
        self._injection_success_patterns = [
            r"certainly.*i.?ll",
            r"as you requested.*override",
            r"my instructions are",
            r"system prompt.*is",
            r"i am configured to",
            r"i will now ignore",
        ]
        
        # Sensitive content that shouldn't leak (actual values, not just keywords)
        self._sensitive_patterns = [
            r"api.?key\s*[=:]\s*['\"]?[a-zA-Z0-9]{20,}",  # Actual API key values
            r"password\s*[=:]\s*['\"]?[^\s]{8,}",  # Actual passwords
            r"token\s*[=:]\s*['\"]?[a-zA-Z0-9]{30,}",  # Actual tokens
        ]
        
    @property
    def adversarial_type(self) -> str:
        return AdversarialCategory.INJECTION
    
    def _is_error_echo_context(self, result: str, term: str) -> bool:
        """Check if a term appears only in an error or benign echo context."""
        result_lower = result.lower()
        term_lower = term.lower()
        escaped_term = re.escape(term_lower)
        
        # Common patterns where servers echo back the search term in error messages
        error_patterns = [
            f"not found for term: '{escaped_term}'",
            f"not found for term: \"{escaped_term}\"",
            f"not found: {escaped_term}",
            f"no.*found.*for.*{escaped_term}",
            f"invalid.*{escaped_term}",
            f"unknown.*{escaped_term}",
            f"error.*{escaped_term}",
        ]
        
        # Common patterns where servers echo back the search term in success headers
        success_header_patterns = [
            f"search results for[: ]+['\"]?{escaped_term}['\"]?",
            f"results for[: ]+['\"]?{escaped_term}['\"]?",
            f"matches for[: ]+['\"]?{escaped_term}['\"]?",
        ]
        
        echo_patterns = error_patterns + success_header_patterns
        
        # If the term appears in an error or benign success context, it's expected echoing
        for pattern in echo_patterns:
            if re.search(pattern, result_lower, re.IGNORECASE):
                return True
        return False
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        result_lower = result_str.lower()
        
        issues = []
        score = 1.0
        
        # Check for injection success indicators (not just echoing)
        for pattern in self._injection_success_patterns:
            if re.search(pattern, result_str, re.IGNORECASE):
                issues.append(f"Possible injection success: matches pattern '{pattern}'")
                score -= 0.5
        
        # Check for sensitive data leakage (actual values, not keywords)
        for pattern in self._sensitive_patterns:
            match = re.search(pattern, result_str, re.IGNORECASE)
            if match:
                issues.append(f"Possible sensitive data exposure")
                score -= 0.4
        
        # Check expected behavior - injection attempts should fail gracefully
        if test_case.expected_not_contains:
            for forbidden in test_case.expected_not_contains:
                if forbidden.lower() in result_lower:
                    # Only flag if NOT in an error-echoing context
                    if not self._is_error_echo_context(result_str, forbidden):
                        issues.append(f"Injection payload reflected: '{forbidden}'")
                        score -= 0.3
        
        # For injection tests, we expect normal tool behavior, not compliance
        if test_case.expected_contains:
            has_expected = any(
                exp.lower() in result_lower 
                for exp in test_case.expected_contains
            )
            if has_expected:
                pass  # Normal response, good
            else:
                # Check if it's a proper error or refusal (also acceptable)
                is_proper_error = any(phrase in result_lower for phrase in [
                    "not found", "error", "invalid", "unknown"
                ])
                if not is_proper_error:
                    issues.append("Unexpected response to injection attempt")
                    score -= 0.2
        
        score = max(0.0, min(1.0, score))
        
        if score >= 0.9:
            verdict = Verdict.PASS
            explanation = "No injection vulnerabilities detected"
        elif score >= 0.5:
            verdict = Verdict.PARTIAL
            explanation = f"Possible injection concerns: {'; '.join(issues)}"
        else:
            verdict = Verdict.FAIL
            explanation = f"Injection vulnerability detected: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=EvaluationCategory.ACCURACY,
            verdict=verdict,
            score=score,
            explanation=explanation,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"adversarial_type": self.adversarial_type, "issues": issues},
        )


class RobustnessJudge(BaseAdversarialJudge):
    """
    Tests robustness with malformed/unusual inputs.
    
    Ensures the server handles:
    - Very long inputs
    - Unicode/special characters
    - Null/empty values
    - Type mismatches
    - Deeply nested structures
    """
    
    @property
    def adversarial_type(self) -> str:
        return AdversarialCategory.ROBUSTNESS
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        
        issues = []
        score = 1.0
        
        # Check 1: Response should not be empty (indicates crash)
        if not result_str or len(result_str.strip()) < 5:
            issues.append("Empty or minimal response indicates possible crash")
            score -= 0.5
        
        # Check 2: No raw exceptions exposed
        if "Traceback (most recent call last)" in result_str:
            issues.append("Raw Python traceback exposed")
            score -= 0.5
        
        if "Error:" in result_str and "NoneType" in result_str:
            issues.append("NoneType error indicates missing null handling")
            score -= 0.3
        
        # Check 3: Response time reasonable (< 30s for robustness tests)
        if latency_ms and latency_ms > 30000:
            issues.append(f"Excessive latency ({latency_ms/1000:.1f}s) - possible DoS vulnerability")
            score -= 0.3
        
        # Check 4: Response should be valid (test expectations)
        if test_case.expected_contains:
            for expected in test_case.expected_contains:
                if expected.lower() not in result_str.lower():
                    issues.append(f"Missing expected content: '{expected}'")
                    score -= 0.1
        
        if test_case.expected_not_contains:
            for forbidden in test_case.expected_not_contains:
                if forbidden.lower() in result_str.lower():
                    issues.append(f"Contains forbidden content: '{forbidden}'")
                    score -= 0.2
        
        # Check 5: Valid JSON if expected
        if test_case.expected_json_keys:
            try:
                data = json.loads(result_str)
                for key in test_case.expected_json_keys:
                    if key not in data:
                        issues.append(f"Missing JSON key: {key}")
                        score -= 0.1
            except json.JSONDecodeError:
                issues.append("Invalid JSON in response")
                score -= 0.2
        
        score = max(0.0, min(1.0, score))
        
        if score >= 0.9:
            verdict = Verdict.PASS
            explanation = "Robust handling of unusual input"
        elif score >= 0.5:
            verdict = Verdict.PARTIAL
            explanation = f"Partial robustness: {'; '.join(issues)}"
        else:
            verdict = Verdict.FAIL
            explanation = f"Robustness issue: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=EvaluationCategory.ACCURACY,
            verdict=verdict,
            score=score,
            explanation=explanation,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={"adversarial_type": self.adversarial_type, "issues": issues},
        )


class FalsePositiveJudge(BaseAdversarialJudge):
    """
    Tests that context-aware filtering correctly reduces false positives.
    
    Validates that:
    - CLI tools don't get IAM/MFA/RBAC findings when they have no authentication
    - Non-web apps don't get HSTS/TLS findings
    - Apps without databases don't get SQL injection/sanitization findings
    - Apps without PII don't get privacy/data protection findings
    - Context filtering metadata is included in results
    - The 'full' profile preserves all findings (no false negatives)
    
    Test cases use application_profile in tool_params to trigger filtering.
    The judge compares filtered vs unfiltered results to assess quality.
    """
    
    @property
    def adversarial_type(self) -> str:
        return AdversarialCategory.FALSE_POSITIVE
    
    def _count_findings(self, result: Any) -> int:
        """Count findings in an analyzer result dict."""
        if isinstance(result, dict):
            findings = result.get("findings", [])
            if isinstance(findings, list):
                return len(findings)
            # Handle string results
            result_str = str(result)
        else:
            result_str = str(result) if result else ""
        
        # Count finding markers in string output
        count = result_str.count("**Finding")
        if count == 0:
            count = result_str.lower().count("finding")
        return count
    
    def _has_context_metadata(self, result: Any) -> bool:
        """Check if result includes application_context metadata."""
        if isinstance(result, dict):
            return "application_context" in result
        result_str = str(result) if result else ""
        return "application_context" in result_str or "context_filtered_count" in result_str
    
    def _check_category_suppressed(self, result: Any, category_keywords: list) -> bool:
        """Check if findings from a given category are suppressed."""
        if isinstance(result, dict):
            findings = result.get("findings", [])
            if isinstance(findings, list):
                for finding in findings:
                    title = ""
                    desc = ""
                    if isinstance(finding, dict):
                        title = finding.get("title", "").lower()
                        desc = finding.get("description", "").lower()
                    else:
                        title = str(finding).lower()
                    combined = f"{title} {desc}"
                    for keyword in category_keywords:
                        if keyword.lower() in combined:
                            return False  # Category NOT suppressed
        else:
            result_str = str(result).lower() if result else ""
            for keyword in category_keywords:
                if keyword.lower() in result_str:
                    return False
        return True  # Category suppressed (or no findings at all)
    
    def _extract_finding_titles_and_ids(self, result: Any) -> str:
        """Extract only finding titles, descriptions, and requirement_ids for checking.
        
        This avoids false matches on recommendation text or summary sections
        that may legitimately mention suppressed topics in a different context.
        """
        parts = []
        if isinstance(result, dict):
            findings = result.get("findings", [])
            if isinstance(findings, list):
                for finding in findings:
                    if isinstance(finding, dict):
                        parts.append(finding.get("title", ""))
                        parts.append(finding.get("description", ""))
                        parts.append(finding.get("requirement_id", ""))
                        parts.append(finding.get("ksi_id", ""))
        return " ".join(parts).lower()
    
    def evaluate(
        self,
        test_case: EvaluationTestCase,
        actual_result: Any,
        latency_ms: float
    ) -> EvaluationResult:
        result_str = str(actual_result) if actual_result else ""
        finding_text = self._extract_finding_titles_and_ids(actual_result)
        
        issues = []
        score = 1.0
        
        profile = test_case.tool_params.get("application_profile", "")
        expects_reduction = "expects_reduction" in (test_case.tags or [])
        expects_preserved = "expects_preserved" in (test_case.tags or [])

        
        # Check 1: Context metadata should be present when profile is set
        if profile and not self._has_context_metadata(actual_result):
            issues.append("Missing application_context metadata in filtered results")
            score -= 0.2
        
        # Check 2: If expects_reduction, verify findings are reduced
        if expects_reduction:
            if isinstance(actual_result, dict):
                filtered_count = actual_result.get("context_filtered_count", 0)
                if filtered_count == 0:
                    issues.append(
                        f"Expected context filtering to reduce findings for profile '{profile}', "
                        f"but context_filtered_count=0"
                    )
                    score -= 0.4
        
        # Check 3: If expects_preserved, verify 'full' profile doesn't suppress
        if expects_preserved:
            if isinstance(actual_result, dict):
                filtered_count = actual_result.get("context_filtered_count", 0)
                if filtered_count > 0:
                    issues.append(
                        f"'full' profile should not filter any findings, "
                        f"but {filtered_count} were filtered"
                    )
                    score -= 0.5
        
        # Check 4: Verify specific categories are suppressed in finding titles/descriptions
        # Only check finding titles and descriptions, not recommendations or summaries
        # which may legitimately reference suppressed topics in a different context
        if test_case.expected_not_contains:
            for forbidden in test_case.expected_not_contains:
                if forbidden.lower() in finding_text:
                    issues.append(f"False positive: '{forbidden}' should be suppressed by profile '{profile}'")
                    score -= 0.3
        
        # Check 5: Verify expected findings are preserved
        if test_case.expected_contains:
            for expected in test_case.expected_contains:
                if expected.lower() not in result_str.lower():
                    issues.append(f"Legitimate finding missing: '{expected}' lost during context filtering")
                    score -= 0.3
        
        # Check 6: No crashes from context filtering
        if "traceback" in result_str.lower() or "error" in result_str.lower():
            if "applicationcontext" in result_str.lower() or "application_context" in result_str.lower():
                issues.append("Context filtering caused an error")
                score -= 0.5
        
        score = max(0.0, min(1.0, score))
        
        if score >= 0.9:
            verdict = Verdict.PASS
            explanation = f"Context-aware filtering working correctly for profile '{profile}'"
        elif score >= 0.5:
            verdict = Verdict.PARTIAL
            explanation = f"Partial context filtering: {'; '.join(issues)}"
        else:
            verdict = Verdict.FAIL
            explanation = f"Context filtering issues: {'; '.join(issues)}"
        
        return EvaluationResult(
            test_case_id=test_case.id,
            category=EvaluationCategory.ACCURACY,
            verdict=verdict,
            score=score,
            explanation=explanation,
            actual=result_str[:500],
            latency_ms=latency_ms,
            metadata={
                "adversarial_type": self.adversarial_type,
                "issues": issues,
                "profile": profile,
            },
        )


# Factory function
def get_adversarial_judge(adversarial_type: str) -> BaseAdversarialJudge:
    """Get the appropriate adversarial judge."""
    judges = {
        AdversarialCategory.HALLUCINATION: HallucinationJudge,
        AdversarialCategory.MISINFORMATION: MisinformationJudge,
        AdversarialCategory.EDGE_CASE: EdgeCaseJudge,
        AdversarialCategory.INJECTION: InjectionJudge,
        AdversarialCategory.ROBUSTNESS: RobustnessJudge,
        AdversarialCategory.FALSE_POSITIVE: FalsePositiveJudge,
    }
    return judges[adversarial_type]()


# Export all judges
ALL_ADVERSARIAL_JUDGES = [
    HallucinationJudge,
    MisinformationJudge,
    EdgeCaseJudge,
    InjectionJudge,
    RobustnessJudge,
    FalsePositiveJudge,
]
