"""测试用例加载器 - 从 YAML 文件加载和管理测试用例"""

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class TestCase:
    """单个测试用例"""
    id: str
    dimension: str                    # security / boundary / performance
    category: str                     # 子分类
    severity: str = "medium"          # critical / high / medium / low
    prompt: str = ""
    expected_behavior: str = "refuse" # refuse / expect / clarify / graceful_degrade
    evaluation_type: str = "keyword_match"
    refuse_keywords: list[str] = field(default_factory=list)
    harmful_keywords: list[str] = field(default_factory=list)
    expected_patterns: list[str] = field(default_factory=list)
    description: str = ""
    reference: str = ""
    multi_turn_prompts: list[str] = field(default_factory=list)  # 多轮测试的后续 prompt
    timeout_override: Optional[float] = None


def load_testcases_from_yaml(filepath: str | Path) -> list[TestCase]:
    """从 YAML 文件加载测试用例"""
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"测试用例文件不存在: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        raw_cases = yaml.safe_load(f)

    if not raw_cases:
        return []

    cases = []
    for raw in raw_cases:
        evaluation = raw.get("evaluation", {})
        metadata = raw.get("metadata", {})

        case = TestCase(
            id=raw["id"],
            dimension=raw["dimension"],
            category=raw["category"],
            severity=raw.get("severity", "medium"),
            prompt=raw.get("prompt", ""),
            expected_behavior=raw.get("expected_behavior", "refuse"),
            evaluation_type=evaluation.get("type", "keyword_match"),
            refuse_keywords=evaluation.get("refuse_keywords", []),
            harmful_keywords=evaluation.get("harmful_keywords", []),
            expected_patterns=evaluation.get("expected_patterns", []),
            description=metadata.get("description", ""),
            reference=metadata.get("reference", ""),
            multi_turn_prompts=raw.get("multi_turn_prompts", []),
            timeout_override=raw.get("timeout_override", None),
        )
        cases.append(case)

    return cases


def load_all_testcases(testcases_dir: str | Path) -> list[TestCase]:
    """从目录加载所有 YAML 测试用例文件"""
    testcases_dir = Path(testcases_dir)
    all_cases = []

    for yaml_file in testcases_dir.glob("*.yaml"):
        cases = load_testcases_from_yaml(yaml_file)
        all_cases.extend(cases)

    return all_cases


def filter_testcases(
    cases: list[TestCase],
    dimension: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
) -> list[TestCase]:
    """按维度/分类/严重等级过滤测试用例"""
    filtered = cases
    if dimension:
        filtered = [c for c in filtered if c.dimension == dimension]
    if category:
        filtered = [c for c in filtered if c.category == category]
    if severity:
        filtered = [c for c in filtered if c.severity == severity]
    return filtered
