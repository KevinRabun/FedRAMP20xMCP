"""
FedRAMP 20x MCP Server Evaluator/Judge Framework

This module provides comprehensive evaluation capabilities to assess the
effectiveness and accuracy of the MCP server's tools and responses.

Evaluation Categories:
1. Data Accuracy - Are tool responses factually correct vs authoritative sources?
2. Tool Completeness - Do tools return all relevant information?
3. Analysis Quality - Are code analyzers detecting issues correctly?
4. Relevance - Are search results and recommendations relevant?
5. Consistency - Do repeated queries return consistent results?
6. Performance - Are response times acceptable?

Adversarial Testing Categories:
7. Hallucination Detection - Does the server fabricate information?
8. Misinformation Detection - Are KSI/FRR definitions confused?
9. Edge Case Handling - Does the server handle unusual inputs?
10. Injection Resistance - Is the server secure against prompt injection?
11. Robustness - Does the server handle malformed inputs gracefully?

Usage:
    from tests.evaluator import MCPServerEvaluator
    
    evaluator = MCPServerEvaluator()
    results = await evaluator.run_full_evaluation()
    evaluator.generate_report(results)
    
    # Run adversarial tests
    adversarial_results = await evaluator.run_adversarial_evaluation()
"""

from .evaluator import MCPServerEvaluator
from .test_cases import EvaluationTestCase, TestCaseCategory
from .judges import (
    AccuracyJudge,
    CompletenessJudge,
    AnalysisQualityJudge,
    RelevanceJudge,
    ConsistencyJudge,
)
from .adversarial_judges import (
    HallucinationJudge,
    MisinformationJudge,
    EdgeCaseJudge,
    InjectionJudge,
    RobustnessJudge,
    AdversarialCategory,
    get_adversarial_judge,
)
from .adversarial_test_cases import (
    ALL_ADVERSARIAL_TEST_CASES,
    CRITICAL_ADVERSARIAL_TEST_CASES,
    HALLUCINATION_TEST_CASES,
    MISINFORMATION_TEST_CASES,
    EDGE_CASE_TEST_CASES,
    INJECTION_TEST_CASES,
    ROBUSTNESS_TEST_CASES,
    get_adversarial_test_cases_by_type,
)
from .metrics import EvaluationMetrics, EvaluationResult

__all__ = [
    # Core evaluator
    "MCPServerEvaluator",
    "EvaluationTestCase",
    "TestCaseCategory",
    "EvaluationMetrics",
    "EvaluationResult",
    # Standard judges
    "AccuracyJudge",
    "CompletenessJudge", 
    "AnalysisQualityJudge",
    "RelevanceJudge",
    "ConsistencyJudge",
    # Adversarial judges
    "HallucinationJudge",
    "MisinformationJudge",
    "EdgeCaseJudge",
    "InjectionJudge",
    "RobustnessJudge",
    "AdversarialCategory",
    "get_adversarial_judge",
    # Adversarial test cases
    "ALL_ADVERSARIAL_TEST_CASES",
    "CRITICAL_ADVERSARIAL_TEST_CASES",
    "HALLUCINATION_TEST_CASES",
    "MISINFORMATION_TEST_CASES",
    "EDGE_CASE_TEST_CASES",
    "INJECTION_TEST_CASES",
    "ROBUSTNESS_TEST_CASES",
    "get_adversarial_test_cases_by_type",
]
