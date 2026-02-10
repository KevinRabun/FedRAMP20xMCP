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
from typing import Any, Dict, List, Optional, Set, Tuple
from .metrics import EvaluationResult, EvaluationCategory, Verdict
from .test_cases import EvaluationTestCase, TestCaseCategory, Importance

logger = logging.getLogger(__name__)


class AdversarialCategory:
    """Extended categories for adversarial testing."""
    HALLUCINATION = "hallucination"
    MISINFORMATION = "misinformation"
    EDGE_CASE = "edge_case"
    INJECTION = "injection"
    ROBUSTNESS = "robustness"


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
        """Load valid IDs from data sources."""
        if self._valid_ksi_ids is not None:
            return
            
        # Build valid KSI IDs from known patterns
        self._valid_ksi_ids = set()
        for family in self._valid_families:
            for i in range(1, 20):  # Max expected per family
                self._valid_ksi_ids.add(f"KSI-{family}-{i:02d}")
        
        # Build valid FRR IDs
        self._valid_frr_ids = set()
        for family in self._valid_families:
            for i in range(1, 50):  # Max expected per family
                self._valid_frr_ids.add(f"FRR-{family}-{i:02d}")
    
    def _extract_ids(self, text: str) -> Tuple[Set[str], Set[str]]:
        """Extract KSI and FRR IDs from text."""
        ksi_pattern = r'KSI-[A-Z]{2,3}-\d{1,2}'
        frr_pattern = r'FRR-[A-Z]{2,3}-\d{1,2}'
        
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
            # Normalize format
            parts = ksi_id.split('-')
            if len(parts) == 3:
                normalized = f"KSI-{parts[1]}-{int(parts[2]):02d}"
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
                normalized = f"FRR-{parts[1]}-{int(parts[2]):02d}"
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
                "correct": ["continuous", "improvement", "maturity"],
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
                has_correct = any(c in response_lower for c in mapping["correct"])
                if not has_correct:
                    issues.append(
                        f"Misinformation: {ksi_id} associated with '{wrong_term}' "
                        f"(should be: {mapping['correct'][0]})"
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
        """Check if a term appears only in an error-echoing context."""
        result_lower = result.lower()
        term_lower = term.lower()
        
        # Common patterns where servers echo back the search term in error messages
        error_patterns = [
            f"not found for term: '{term_lower}'",
            f"not found for term: \"{term_lower}\"",
            f"not found: {term_lower}",
            f"no.*found.*for.*{term_lower}",
            f"invalid.*{term_lower}",
            f"unknown.*{term_lower}",
            f"error.*{term_lower}",
        ]
        
        # If the term appears in an error context, it's expected echoing
        for pattern in error_patterns:
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


# Factory function
def get_adversarial_judge(adversarial_type: str) -> BaseAdversarialJudge:
    """Get the appropriate adversarial judge."""
    judges = {
        AdversarialCategory.HALLUCINATION: HallucinationJudge,
        AdversarialCategory.MISINFORMATION: MisinformationJudge,
        AdversarialCategory.EDGE_CASE: EdgeCaseJudge,
        AdversarialCategory.INJECTION: InjectionJudge,
        AdversarialCategory.ROBUSTNESS: RobustnessJudge,
    }
    return judges[adversarial_type]()


# Export all judges
ALL_ADVERSARIAL_JUDGES = [
    HallucinationJudge,
    MisinformationJudge,
    EdgeCaseJudge,
    InjectionJudge,
    RobustnessJudge,
]
