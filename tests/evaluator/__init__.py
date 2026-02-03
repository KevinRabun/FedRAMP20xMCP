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

Usage:
    from tests.evaluator import MCPServerEvaluator
    
    evaluator = MCPServerEvaluator()
    results = await evaluator.run_full_evaluation()
    evaluator.generate_report(results)
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
from .metrics import EvaluationMetrics, EvaluationResult

__all__ = [
    "MCPServerEvaluator",
    "EvaluationTestCase",
    "TestCaseCategory",
    "AccuracyJudge",
    "CompletenessJudge", 
    "AnalysisQualityJudge",
    "RelevanceJudge",
    "ConsistencyJudge",
    "EvaluationMetrics",
    "EvaluationResult",
]
