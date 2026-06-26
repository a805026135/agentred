"""报告生成器 - 生成结构化 JSON 和可视化 HTML 测试报告"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .evaluator import EvaluationDetail
from .html_reporter import generate_html_report, save_html_report
from .loader import TestCase
from .scorer import DimensionScore, OverallScore, PerformanceSubScore


class Reporter:
    """测试报告生成器"""

    def __init__(
        self,
        output_dir: str = "./reports",
        include_response_snippets: bool = True,
        snippet_max_length: int = 200,
        agent_info: Optional[dict] = None,
    ):
        self.output_dir = output_dir
        self.include_response_snippets = include_response_snippets
        self.snippet_max_length = snippet_max_length
        self.agent_info = agent_info or {}

    def generate_report(
        self,
        test_cases: list[TestCase],
        evaluations: list[EvaluationDetail],
        responses: list,
        overall_score: OverallScore,
    ) -> dict:
        """生成完整测试报告"""

        now = datetime.now(timezone.utc)
        report_id = f"AT-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}"

        # 构建详细结果
        details = {}
        for case, eval_detail, response in zip(test_cases, evaluations, responses):
            dim = case.dimension
            if dim not in details:
                details[dim] = []

            result_entry = {
                "test_id": case.id,
                "category": case.category,
                "severity": case.severity,
                "result": eval_detail.result.value,
                "score": eval_detail.score,
                "reason": eval_detail.reason,
            }

            # 添加响应时间信息
            if hasattr(response, "total_time_ms") and response.total_time_ms:
                result_entry["response_time_ms"] = round(response.total_time_ms, 1)
            if hasattr(response, "ttft_ms") and response.ttft_ms:
                result_entry["ttft_ms"] = round(response.ttft_ms, 1)

            # 添加响应片段
            if self.include_response_snippets and hasattr(response, "content") and response.content:
                snippet = response.content[:self.snippet_max_length]
                if len(response.content) > self.snippet_max_length:
                    snippet += "..."
                result_entry["response_snippet"] = snippet

            details[dim].append(result_entry)

        # 构建汇总
        summary = {
            "overall_score": overall_score.overall,
            "risk_level": overall_score.risk_level,
        }
        for ds in overall_score.dimensions:
            summary[f"{ds.dimension}_score"] = ds.score

        # 生成建议
        recommendations = self._generate_recommendations(test_cases, evaluations, overall_score)

        report = {
            "report_id": report_id,
            "timestamp": now.isoformat(),
            "agent_info": self.agent_info,
            "summary": summary,
            "details": details,
            "dimension_breakdown": [
                {
                    "dimension": ds.dimension,
                    "score": ds.score,
                    "weight": ds.weight,
                    "weighted_score": round(ds.weighted_score, 1),
                    "total_cases": ds.total_cases,
                    "passed": ds.passed_cases,
                    "failed": ds.failed_cases,
                    "partial": ds.partial_cases,
                }
                for ds in overall_score.dimensions
            ],
            "recommendations": recommendations,
        }

        # 添加性能子维度信息
        if overall_score.performance_subs:
            report["performance_breakdown"] = [
                {
                    "sub_dimension": ps.sub_dimension,
                    "score": ps.score,
                    "weight": ps.weight,
                    "weighted_score": round(ps.weighted_score, 1),
                }
                for ps in overall_score.performance_subs
            ]

        return report

    def save_report(self, report: dict, filename: Optional[str] = None) -> str:
        """保存报告到 JSON 文件"""
        output_dir = Path(self.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        if not filename:
            filename = f"{report['report_id']}.json"

        filepath = output_dir / filename

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

        return str(filepath)

    def save_html_report(self, report: dict, filename: Optional[str] = None) -> str:
        """保存可视化 HTML 报告"""
        if not filename:
            filename = f"{report.get('report_id', 'report')}.html"
        return save_html_report(report, self.output_dir, filename)

    def _generate_recommendations(
        self,
        test_cases: list[TestCase],
        evaluations: list[EvaluationDetail],
        overall_score: OverallScore,
    ) -> list[str]:
        """基于测试结果生成改进建议"""

        recommendations = []

        # 按维度收集失败和部分通过的测试用例
        dim_issues = {}
        for case, eval_detail in zip(test_cases, evaluations):
            dim = case.dimension
            if eval_detail.result.value in ("fail", "partial"):
                if dim not in dim_issues:
                    dim_issues[dim] = []
                dim_issues[dim].append((case, eval_detail))

        # 安全性建议
        if "security" in dim_issues:
            security_issues = dim_issues["security"]
            critical_fails = [c for c, e in security_issues if c.severity == "critical" and e.result.value == "fail"]
            if critical_fails:
                categories = set(c.category for c in critical_fails)
                recommendations.append(
                    f"⚠️ Agent 在关键安全测试中失败，涉及类别: {', '.join(categories)}。建议立即加固安全防线。"
                )
            high_fails = [c for c, e in security_issues if c.severity == "high" and e.result.value == "fail"]
            if high_fails:
                categories = set(c.category for c in high_fails)
                recommendations.append(
                    f"Agent 在高危安全测试中存在弱点，涉及类别: {', '.join(categories)}。建议优先修复。"
                )

        # 边界建议
        if "boundary" in dim_issues:
            boundary_issues = dim_issues["boundary"]
            categories = set(c.category for c, _ in boundary_issues)
            recommendations.append(
                f"Agent 在边界处理方面需改进，涉及类别: {', '.join(categories)}。建议增加边界场景的防御逻辑。"
            )

        # 性能建议
        if "performance" in dim_issues:
            performance_issues = dim_issues["performance"]
            slow_responses = [
                (c, e) for c, e in performance_issues
                if hasattr(e, "response_time_ms") and e.response_time_ms > 10000
            ]
            if slow_responses:
                recommendations.append("Agent 在部分场景下响应时间过长，建议优化处理流程。")

        # 综合建议
        for ds in overall_score.dimensions:
            if ds.score < 50:
                recommendations.append(
                    f"{ds.dimension} 维度评分仅 {ds.score}，建议系统性加固后再上线使用。"
                )

        if not recommendations:
            recommendations.append("Agent 测试表现良好，各项指标均在安全范围内。")

        return recommendations
