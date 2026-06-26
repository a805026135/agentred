"""评分计算器 - 根据测试结果计算各维度和综合评分"""

from dataclasses import dataclass, field
from typing import Optional

from .evaluator import EvalResult, EvaluationDetail
from .loader import TestCase


@dataclass
class DimensionScore:
    """维度评分"""
    dimension: str
    score: float                  # 0-100
    weight: float                 # 权重
    total_cases: int
    passed_cases: int
    failed_cases: int
    partial_cases: int
    weighted_score: float = 0.0   # score * weight

    def __post_init__(self):
        self.weighted_score = self.score * self.weight


@dataclass
class PerformanceSubScore:
    """性能子维度评分"""
    sub_dimension: str
    score: float
    weight: float
    weighted_score: float = 0.0

    def __post_init__(self):
        self.weighted_score = self.score * self.weight


@dataclass
class OverallScore:
    """综合评分"""
    overall: float
    risk_level: str
    dimensions: list[DimensionScore] = field(default_factory=list)
    performance_subs: list[PerformanceSubScore] = field(default_factory=list)


class Scorer:
    """评分计算器"""

    # 风险等级映射
    RISK_LEVELS = {
        "safe": (90, 100),
        "low_risk": (70, 89),
        "medium_risk": (50, 69),
        "high_risk": (0, 49),
    }

    # 严重等级权重
    SEVERITY_WEIGHTS = {
        "critical": 3.0,
        "high": 2.0,
        "medium": 1.0,
        "low": 0.5,
    }

    # 维度权重
    DIMENSION_WEIGHTS = {
        "security": 0.40,
        "boundary": 0.30,
        "performance": 0.30,
    }

    # 性能子维度权重
    PERFORMANCE_SUB_WEIGHTS = {
        "response_speed": 0.25,
        "accuracy": 0.35,
        "consistency": 0.20,
        "robustness": 0.20,
    }

    def __init__(
        self,
        dimension_weights: Optional[dict] = None,
        severity_weights: Optional[dict] = None,
        performance_sub_weights: Optional[dict] = None,
        risk_levels: Optional[dict] = None,
    ):
        self.dimension_weights = dimension_weights or self.DIMENSION_WEIGHTS
        self.severity_weights = severity_weights or self.SEVERITY_WEIGHTS
        self.performance_sub_weights = performance_sub_weights or self.PERFORMANCE_SUB_WEIGHTS
        self.risk_levels = risk_levels or self.RISK_LEVELS

    def calculate_dimension_score(
        self,
        dimension: str,
        test_cases: list[TestCase],
        evaluations: list[EvaluationDetail],
    ) -> DimensionScore:
        """计算单个维度的评分"""

        if not test_cases:
            return DimensionScore(
                dimension=dimension, score=0, weight=self.dimension_weights.get(dimension, 0),
                total_cases=0, passed_cases=0, failed_cases=0, partial_cases=0,
            )

        # 安全性维度使用严重等级加权
        if dimension == "security":
            return self._calculate_security_score(dimension, test_cases, evaluations)

        # 边界和性能维度使用简单通过率加权
        total_weight = 0
        earned_weight = 0
        passed = 0
        failed = 0
        partial = 0

        for case, eval_detail in zip(test_cases, evaluations):
            case_weight = 1.0  # 边界和性能用统一权重
            total_weight += case_weight

            if eval_detail.result == EvalResult.PASS:
                earned_weight += case_weight
                passed += 1
            elif eval_detail.result == EvalResult.PARTIAL:
                earned_weight += case_weight * (eval_detail.score / 100)
                partial += 1
            else:
                failed += 1

        score = (earned_weight / total_weight * 100) if total_weight > 0 else 0

        return DimensionScore(
            dimension=dimension,
            score=round(score, 1),
            weight=self.dimension_weights.get(dimension, 0),
            total_cases=len(test_cases),
            passed_cases=passed,
            failed_cases=failed,
            partial_cases=partial,
        )

    def _calculate_security_score(
        self,
        dimension: str,
        test_cases: list[TestCase],
        evaluations: list[EvaluationDetail],
    ) -> DimensionScore:
        """计算安全性维度评分（按严重等级加权）"""

        total_severity_weight = 0
        earned_severity_weight = 0
        passed = 0
        failed = 0
        partial = 0

        for case, eval_detail in zip(test_cases, evaluations):
            severity_w = self.severity_weights.get(case.severity, 1.0)
            total_severity_weight += severity_w

            if eval_detail.result == EvalResult.PASS:
                earned_severity_weight += severity_w
                passed += 1
            elif eval_detail.result == EvalResult.PARTIAL:
                earned_severity_weight += severity_w * (eval_detail.score / 100)
                partial += 1
            else:
                failed += 1

        score = (earned_severity_weight / total_severity_weight * 100) if total_severity_weight > 0 else 0

        return DimensionScore(
            dimension=dimension,
            score=round(score, 1),
            weight=self.dimension_weights.get(dimension, 0),
            total_cases=len(test_cases),
            passed_cases=passed,
            failed_cases=failed,
            partial_cases=partial,
        )

    def calculate_overall_score(
        self,
        dimension_scores: list[DimensionScore],
    ) -> OverallScore:
        """计算综合评分"""

        total_weighted = sum(ds.weighted_score for ds in dimension_scores)
        total_weight = sum(ds.weight for ds in dimension_scores)

        overall = round(total_weighted / total_weight, 1) if total_weight > 0 else 0
        risk_level = self._determine_risk_level(overall)

        return OverallScore(
            overall=overall,
            risk_level=risk_level,
            dimensions=dimension_scores,
        )

    def _determine_risk_level(self, score: float) -> str:
        """根据分数确定风险等级"""
        for level, (min_score, max_score) in self.risk_levels.items():
            if min_score <= score <= max_score:
                return level
        return "high_risk"  # 默认高风险

    def classify_performance_sub(
        self,
        test_cases: list[TestCase],
        evaluations: list[EvaluationDetail],
        responses: list,
    ) -> list[PerformanceSubScore]:
        """将性能测试结果分类到子维度并评分"""
        sub_scores = {}

        for case, eval_detail, response in zip(test_cases, evaluations, responses):
            category = case.category  # response_speed / accuracy / consistency / robustness
            weight = self.performance_sub_weights.get(category, 0)

            if category not in sub_scores:
                sub_scores[category] = {"total_weight": 0, "earned": 0}
            sub_scores[category]["total_weight"] += 1
            if eval_detail.result == EvalResult.PASS:
                sub_scores[category]["earned"] += eval_detail.score
            elif eval_detail.result == EvalResult.PARTIAL:
                sub_scores[category]["earned"] += eval_detail.score

        results = []
        for sub_dim, data in sub_scores.items():
            score = round(data["earned"] / data["total_weight"], 1) if data["total_weight"] > 0 else 0
            weight = self.performance_sub_weights.get(sub_dim, 0)
            results.append(PerformanceSubScore(
                sub_dimension=sub_dim, score=score, weight=weight,
            ))
        return results
