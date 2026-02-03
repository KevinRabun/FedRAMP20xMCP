"""
Evaluation Metrics and Result Data Structures

Provides structured data classes for capturing evaluation results,
computing metrics, and generating reports.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import statistics


class EvaluationCategory(Enum):
    """Categories of evaluation."""
    ACCURACY = "accuracy"
    COMPLETENESS = "completeness"
    ANALYSIS_QUALITY = "analysis_quality"
    RELEVANCE = "relevance"
    CONSISTENCY = "consistency"
    PERFORMANCE = "performance"


class Verdict(Enum):
    """Evaluation verdict."""
    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class EvaluationResult:
    """Result of a single evaluation test case."""
    test_case_id: str
    category: EvaluationCategory
    verdict: Verdict
    score: float  # 0.0 to 1.0
    explanation: str
    expected: Optional[Any] = None
    actual: Optional[Any] = None
    latency_ms: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "test_case_id": self.test_case_id,
            "category": self.category.value,
            "verdict": self.verdict.value,
            "score": self.score,
            "explanation": self.explanation,
            "expected": self.expected,
            "actual": str(self.actual)[:500] if self.actual else None,
            "latency_ms": self.latency_ms,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class CategoryMetrics:
    """Aggregated metrics for an evaluation category."""
    category: EvaluationCategory
    total_tests: int
    passed: int
    failed: int
    partial: int
    errors: int
    skipped: int
    average_score: float
    min_score: float
    max_score: float
    average_latency_ms: Optional[float]
    
    @property
    def pass_rate(self) -> float:
        """Calculate pass rate (including partial as 0.5)."""
        if self.total_tests == 0:
            return 0.0
        effective_passes = self.passed + (self.partial * 0.5)
        return effective_passes / self.total_tests
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "partial": self.partial,
            "errors": self.errors,
            "skipped": self.skipped,
            "pass_rate": round(self.pass_rate, 3),
            "average_score": round(self.average_score, 3),
            "min_score": round(self.min_score, 3),
            "max_score": round(self.max_score, 3),
            "average_latency_ms": round(self.average_latency_ms, 2) if self.average_latency_ms else None,
        }


@dataclass
class EvaluationMetrics:
    """Complete evaluation metrics across all categories."""
    results: List[EvaluationResult] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    def add_result(self, result: EvaluationResult) -> None:
        """Add an evaluation result."""
        self.results.append(result)
    
    def finalize(self) -> None:
        """Mark evaluation as complete."""
        self.end_time = datetime.now()
    
    @property
    def duration_seconds(self) -> Optional[float]:
        """Total evaluation duration in seconds."""
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None
    
    @property
    def total_tests(self) -> int:
        """Total number of tests run."""
        return len(self.results)
    
    @property
    def overall_score(self) -> float:
        """Calculate overall weighted score."""
        if not self.results:
            return 0.0
        return statistics.mean(r.score for r in self.results)
    
    @property
    def overall_pass_rate(self) -> float:
        """Calculate overall pass rate."""
        if not self.results:
            return 0.0
        passes = sum(1 for r in self.results if r.verdict == Verdict.PASS)
        partials = sum(1 for r in self.results if r.verdict == Verdict.PARTIAL)
        return (passes + partials * 0.5) / len(self.results)
    
    def get_category_metrics(self, category: EvaluationCategory) -> CategoryMetrics:
        """Get metrics for a specific category."""
        category_results = [r for r in self.results if r.category == category]
        
        if not category_results:
            return CategoryMetrics(
                category=category,
                total_tests=0,
                passed=0,
                failed=0,
                partial=0,
                errors=0,
                skipped=0,
                average_score=0.0,
                min_score=0.0,
                max_score=0.0,
                average_latency_ms=None,
            )
        
        scores = [r.score for r in category_results]
        latencies = [r.latency_ms for r in category_results if r.latency_ms is not None]
        
        return CategoryMetrics(
            category=category,
            total_tests=len(category_results),
            passed=sum(1 for r in category_results if r.verdict == Verdict.PASS),
            failed=sum(1 for r in category_results if r.verdict == Verdict.FAIL),
            partial=sum(1 for r in category_results if r.verdict == Verdict.PARTIAL),
            errors=sum(1 for r in category_results if r.verdict == Verdict.ERROR),
            skipped=sum(1 for r in category_results if r.verdict == Verdict.SKIPPED),
            average_score=statistics.mean(scores),
            min_score=min(scores),
            max_score=max(scores),
            average_latency_ms=statistics.mean(latencies) if latencies else None,
        )
    
    def get_all_category_metrics(self) -> Dict[EvaluationCategory, CategoryMetrics]:
        """Get metrics for all categories."""
        return {
            category: self.get_category_metrics(category)
            for category in EvaluationCategory
        }
    
    def get_failures(self) -> List[EvaluationResult]:
        """Get all failed test results."""
        return [r for r in self.results if r.verdict == Verdict.FAIL]
    
    def get_errors(self) -> List[EvaluationResult]:
        """Get all error test results."""
        return [r for r in self.results if r.verdict == Verdict.ERROR]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        category_metrics = self.get_all_category_metrics()
        
        return {
            "summary": {
                "total_tests": self.total_tests,
                "overall_score": round(self.overall_score, 3),
                "overall_pass_rate": round(self.overall_pass_rate, 3),
                "duration_seconds": round(self.duration_seconds, 2) if self.duration_seconds else None,
                "start_time": self.start_time.isoformat(),
                "end_time": self.end_time.isoformat() if self.end_time else None,
            },
            "category_metrics": {
                cat.value: metrics.to_dict()
                for cat, metrics in category_metrics.items()
                if metrics.total_tests > 0
            },
            "failures": [r.to_dict() for r in self.get_failures()],
            "errors": [r.to_dict() for r in self.get_errors()],
            "all_results": [r.to_dict() for r in self.results],
        }
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    def print_summary(self) -> None:
        """Print a formatted summary to stdout."""
        print("\n" + "=" * 70)
        print("FedRAMP 20x MCP Server Evaluation Report")
        print("=" * 70)
        print(f"\nOverall Score: {self.overall_score:.1%}")
        print(f"Overall Pass Rate: {self.overall_pass_rate:.1%}")
        print(f"Total Tests: {self.total_tests}")
        if self.duration_seconds:
            print(f"Duration: {self.duration_seconds:.1f}s")
        
        print("\n" + "-" * 70)
        print("Results by Category")
        print("-" * 70)
        
        for category in EvaluationCategory:
            metrics = self.get_category_metrics(category)
            if metrics.total_tests > 0:
                print(f"\n{category.value.upper()}:")
                print(f"  Pass Rate: {metrics.pass_rate:.1%} ({metrics.passed}/{metrics.total_tests})")
                print(f"  Average Score: {metrics.average_score:.1%}")
                if metrics.average_latency_ms:
                    print(f"  Avg Latency: {metrics.average_latency_ms:.0f}ms")
        
        failures = self.get_failures()
        if failures:
            print("\n" + "-" * 70)
            print(f"FAILURES ({len(failures)})")
            print("-" * 70)
            for f in failures[:10]:  # Show first 10
                print(f"\n  [{f.test_case_id}] {f.category.value}")
                print(f"    {f.explanation[:100]}...")
        
        errors = self.get_errors()
        if errors:
            print("\n" + "-" * 70)
            print(f"ERRORS ({len(errors)})")
            print("-" * 70)
            for e in errors[:5]:  # Show first 5
                print(f"\n  [{e.test_case_id}] {e.explanation}")
        
        print("\n" + "=" * 70)
