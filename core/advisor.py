"""内置 Advisor Agent — 模型驱动的动态改进意见生成器

功能:
  1. 接收脱敏后的测试评估摘要（不含 system prompt、代码、密钥），动态生成改进意见
  2. 检测 Agent 配置缺失项，生成提示信息（配合 ConfigChecker）
  3. 无 API 时 fallback 到 REMEDIATION_DB 规则引擎

隐私设计 (v4.0):
  - Advisor Agent 不再接收原始 agent 内容
  - 只接收通过 PrivacyFilter 脱敏后的评估摘要
  - API 调用时的 prompt 只包含评分、类别、严重等级等抽象数据
  - 规则引擎分析也只使用脱敏后的字段

模型选择:
  - 不限定模型大小，任何 OpenAI-compatible API 模型均可使用
  - 可用低成本模型（deepseek-chat、gpt-4o-mini），也可用强推理模型（GPT-4、Claude、DeepSeek-R1）
  - 用户根据成本和推理需求自行选择

流程:
  1. Runner → PrivacyFilter.sanitize(report) → 获取 SanitizedReport
  2. PrivacyFilter.generate_advisor_input(report) → 生成脱敏 prompt
  3. Advisor.analyze(sanitized_report, ...) → 基于脱敏数据生成建议
  4. 如果有 API，发送脱敏 prompt 给模型 → 动态建议
  5. 无 API → 规则引擎基于抽象评估数据生成建议
"""

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

from core.html_reporter import REMEDIATION_DB
from core.source import AgentProfile


# ============================================================
# Advisor 输出数据结构
# ============================================================

@dataclass
class AdvisorRecommendation:
    """Advisor 生成的一条改进建议"""
    title: str                      # 建议标题
    detail: str                     # 详细描述
    priority: str                   # P0 / P1 / P2
    difficulty: str                 # 低 / 中 / 高
    dimension: str                  # 关联维度 (security / boundary / performance / rag / memory / tool)
    category: str                   # 关联类别
    related_test_ids: list[str] = field(default_factory=list)  # 关联的测试ID
    source: str = "rule_engine"     # 来源: rule_engine / advisor_agent / hybrid


@dataclass
class ConfigIssue:
    """缺失配置项"""
    field_name: str                 # 配置项名称
    description: str                # 描述
    severity: str                   # critical / high / medium / low
    suggestion: str                 # 建议的值或操作
    env_var: str = ""               # 推荐的环境变量名


@dataclass
class AdvisorReport:
    """Advisor Agent 输出的完整报告"""
    recommendations: list[AdvisorRecommendation]
    config_issues: list[ConfigIssue]
    advisor_model: str              # 使用的模型名称
    advisor_source: str             # rule_engine / api_agent / hybrid
    raw_llm_response: str = ""      # 保留原始 LLM 响应（便于审计）
    duration_ms: float = 0          # 生成耗时


# ============================================================
# Advisor Agent 主类
# ============================================================

class AdvisorAgent:
    """内置 Advisor Agent — 模型驱动的改进建议生成器

    三层策略:
      1. 优先调用模型 API，动态分析测试结果生成针对性建议
      2. API 不可用时，fallback 到 REMEDIATION_DB 规则引擎
      3. 两层都运行时，合并输出（hybrid 模式）

    模型选择:
      - 不限定模型大小，任何 OpenAI-compatible API 模型均可
      - 小模型（成本低）：deepseek-chat, gpt-4o-mini, glm-4-flash
      - 强推理模型（更准确）：gpt-4, claude-3, deepseek-reasoner
      - 用户根据成本和需求自行选择，--advisor-model 指定
    """

    # 可选模型配置（用户可自由选择任何模型，以下仅供参考）
    AVAILABLE_MODELS = [
        # 低成本模型 — 适合日常快速分析
        {"model": "deepseek-chat", "endpoint": "https://api.deepseek.com/v1/chat/completions", "name": "DeepSeek-Chat", "tier": "low_cost"},
        {"model": "qwen-turbo", "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", "name": "Qwen-Turbo", "tier": "low_cost"},
        {"model": "glm-4-flash", "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions", "name": "GLM-4-Flash", "tier": "low_cost"},
        {"model": "gpt-4o-mini", "endpoint": "https://api.openai.com/v1/chat/completions", "name": "GPT-4o-mini", "tier": "low_cost"},
        # 强推理模型 — 适合深度分析和复杂改进建议
        {"model": "gpt-4", "endpoint": "https://api.openai.com/v1/chat/completions", "name": "GPT-4", "tier": "powerful"},
        {"model": "gpt-4o", "endpoint": "https://api.openai.com/v1/chat/completions", "name": "GPT-4o", "tier": "powerful"},
        {"model": "deepseek-reasoner", "endpoint": "https://api.deepseek.com/v1/chat/completions", "name": "DeepSeek-R1", "tier": "powerful"},
        {"model": "claude-3-5-sonnet", "endpoint": "https://api.anthropic.com/v1/messages", "name": "Claude-3.5-Sonnet", "tier": "powerful"},
    ]

    # Advisor 自身的 system prompt
    ADVISOR_SYSTEM_PROMPT = """你是一个 Agent 测试顾问，专门分析 AI Agent 的测试报告并给出改进建议。

你的职责:
1. 分析测试报告中各项评分和失败项
2. 根据具体失败原因，生成有针对性的改进方案
3. 对每个改进方案，给出优先级(P0/P1/P2)、难度(低/中/高)和详细操作步骤
4. 特别关注安全性问题，给出加固建议

输出格式要求 — 必须严格输出 JSON:
{
  "recommendations": [
    {
      "title": "建议标题",
      "detail": "详细描述和操作步骤",
      "priority": "P0",
      "difficulty": "中",
      "dimension": "security",
      "category": "prompt_injection",
      "related_test_ids": ["SEC-001"]
    }
  ],
  "summary": "一段话总结主要问题和改进方向"
}

注意事项:
- 每个建议必须针对具体失败项，不要泛泛而谈
- P0 = 必须立即修复的安全问题, P1 = 建议尽快修复, P2 = 可选优化
- 建议要具体可操作，包含代码示例或配置变更建议
- 不要重复已有规则库中的建议，要补充更深入的改进方向"""

    def __init__(
        self,
        # Advisor API 配置
        advisor_api_key: Optional[str] = None,
        advisor_api_endpoint: Optional[str] = None,
        advisor_model: Optional[str] = None,
        # 运行策略
        strategy: str = "auto",  # auto / api_only / rule_only / hybrid
        # 网络配置
        timeout_seconds: int = 30,
        max_retries: int = 2,
    ):
        self.advisor_api_key = advisor_api_key or os.environ.get("ADVISOR_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")
        self.advisor_api_endpoint = advisor_api_endpoint
        self.advisor_model = advisor_model
        self.strategy = strategy
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

        # 自动选择模型（如果没有指定）
        if not self.advisor_api_endpoint and self.advisor_api_key:
            # 根据 api_key 特征推测 endpoint
            self._auto_detect_endpoint()

    def _auto_detect_endpoint(self):
        """根据 API Key 特征自动选择 endpoint 和 model

        注意: 自动检测只是便利功能，用户应通过 --advisor-model 指定想要的模型。
        不限定使用小模型，任何模型均可。
        """
        key = self.advisor_api_key
        if key.startswith("sk-") and len(key) > 40:
            # 标准 OpenAI key — 默认用 gpt-4o（不限定小模型）
            self.advisor_api_endpoint = "https://api.openai.com/v1/chat/completions"
            self.advisor_model = self.advisor_model or "gpt-4o"
        elif key.startswith("sk-") and "deepseek" in (self.advisor_api_endpoint or "").lower():
            self.advisor_api_endpoint = "https://api.deepseek.com/v1/chat/completions"
            self.advisor_model = self.advisor_model or "deepseek-chat"
        elif key.startswith("sk-") and len(key) <= 40:
            # 可能是 DeepSeek key
            self.advisor_api_endpoint = self.advisor_api_endpoint or "https://api.deepseek.com/v1/chat/completions"
            self.advisor_model = self.advisor_model or "deepseek-chat"
        else:
            # 其他 — 默认 DeepSeek endpoint（国产模型，用户可自由替换）
            self.advisor_api_endpoint = self.advisor_api_endpoint or "https://api.deepseek.com/v1/chat/completions"
            self.advisor_model = self.advisor_model or "deepseek-chat"

    # ============================================================
    # 主入口
    # ============================================================

    def analyze(
        self,
        report: dict,
        agent_profile: Optional[AgentProfile] = None,
        config_issues: Optional[list[ConfigIssue]] = None,
        # 隐私参数 (v4.0)
        privacy_level: str = "strict",
        use_sanitized_input: bool = True,
    ) -> AdvisorReport:
        """分析测试报告，生成改进建议

        Args:
            report: 测试报告（将被脱敏处理后再发送给 API）
            agent_profile: Agent 文件档案（可选，只使用非敏感字段）
            config_issues: ConfigChecker 检测的缺失配置（可选）
            privacy_level: 隐私等级 (strict / moderate / minimal)
            use_sanitized_input: 是否使用脱敏输入（默认 True，强烈建议保持）

        隐私保护:
          - 当 use_sanitized_input=True 时，report 会先通过 PrivacyFilter 脱敏
          - API 调用的 prompt 只包含脱敏后的评估摘要
          - 规则引擎分析只使用抽象评分和类别数据
        """

        start_time = time.monotonic()

        # ---- 脱敏处理 ----
        if use_sanitized_input:
            from core.privacy_filter import PrivacyFilter, PrivacyLevel as PL
            pf = PrivacyFilter(privacy_level=privacy_level)
            # 生成给 API 的脱敏 prompt
            sanitized_prompt = pf.generate_advisor_input(report)
            # 脱敏后的报告供规则引擎使用
            sanitized_result = pf.sanitize(report)
            sanitized_report = sanitized_result.report
            print(f"  🔒 报告已脱敏 (等级: {privacy_level}, 移除 {sanitized_result.sensitive_fields_removed} 个敏感字段)")
        else:
            # 不脱敏 — 仅在用户明确要求时使用（不推荐）
            sanitized_prompt = self._build_analysis_prompt_legacy(report, agent_profile, config_issues)
            sanitized_report = report
            print(f"  ⚠️ 注意: 使用未脱敏的原始报告 (不推荐对外发送)")

        # 确定策略
        has_api = bool(self.advisor_api_key) and bool(self.advisor_api_endpoint)

        if self.strategy == "auto":
            strategy = "hybrid" if has_api else "rule_only"
        else:
            strategy = self.strategy

        # 执行两层分析
        rule_recs = []
        api_recs = []
        raw_llm = ""

        # 层1: 规则引擎（始终运行，使用脱敏报告）
        if strategy in ("rule_only", "hybrid", "auto"):
            rule_recs = self._rule_engine_analyze(sanitized_report, agent_profile, config_issues)

        # 层2: API 模型（使用脱敏 prompt）
        if strategy in ("api_only", "hybrid") and has_api:
            api_recs, raw_llm = self._api_analyze_sanitized(sanitized_prompt)

        # 合并
        all_recs = self._merge_recommendations(rule_recs, api_recs)

        # 确定来源标记
        if api_recs and rule_recs:
            source = "hybrid"
        elif api_recs:
            source = "advisor_agent"
        else:
            source = "rule_engine"

        duration = (time.monotonic() - start_time) * 1000

        return AdvisorReport(
            recommendations=all_recs,
            config_issues=config_issues or [],
            advisor_model=self.advisor_model or "rule_engine",
            advisor_source=source,
            raw_llm_response=raw_llm,
            duration_ms=round(duration, 1),
        )

    # ============================================================
    # 规则引擎 — 基于 REMEDIATION_DB
    # ============================================================

    def _rule_engine_analyze(
        self,
        report: dict,
        agent_profile: Optional[AgentProfile],
        config_issues: Optional[list[ConfigIssue]],
    ) -> list[AdvisorRecommendation]:
        """使用 REMEDIATION_DB 规则引擎生成改进建议"""

        recs = []

        # 从静态分析提取
        static = report.get("static_analysis", {})
        for c in static.get("checks", []):
            if c.get("result") == "pass":
                continue
            # 从 REMEDIATION_DB 查找对应建议
            category = c.get("category", "")
            cat_rems = REMEDIATION_DB.get(category, {})

            # 确定行为键
            behavior = self._guess_behavior(category)
            behavior_key = f"{behavior}_fail"

            rem_list = cat_rems.get(behavior_key, [])
            if not rem_list:
                # fallback: 取任意 fail 相关的建议
                for key in cat_rems:
                    if "fail" in key:
                        rem_list = cat_rems[key]
                        break

            for rem in rem_list[:2]:
                recs.append(AdvisorRecommendation(
                    title=rem["title"],
                    detail=rem["detail"],
                    priority=rem.get("priority", "P1"),
                    difficulty=rem.get("difficulty", "中"),
                    dimension=self._category_to_dimension(category),
                    category=category,
                    related_test_ids=[c.get("check_id", "")],
                    source="rule_engine",
                ))

            # 如果 REMEDIATION_DB 没有匹配，用静态检查自带的 remediation
            if not rem_list and c.get("remediation"):
                recs.append(AdvisorRecommendation(
                    title=c.get("title", ""),
                    detail=c["remediation"],
                    priority="P0" if c.get("severity") == "critical" else "P1" if c.get("severity") == "high" else "P2",
                    difficulty="中",
                    dimension=self._category_to_dimension(category),
                    category=category,
                    related_test_ids=[c.get("check_id", "")],
                    source="rule_engine",
                ))

        # 从动态测试提取
        dynamic = report.get("dynamic_analysis", {})
        details = dynamic.get("details", {})
        for dim, results in details.items():
            for r in results:
                if r.get("result") == "pass":
                    continue
                category = r.get("category", "")
                behavior = self._guess_behavior(category)
                behavior_key = f"{behavior}_fail" if r.get("result") == "fail" else f"{behavior}_partial"

                cat_rems = REMEDIATION_DB.get(category, {})
                rem_list = cat_rems.get(behavior_key, [])
                if not rem_list:
                    for key in cat_rems:
                        if "fail" in key:
                            rem_list = cat_rems[key]
                            break

                for rem in rem_list[:2]:
                    recs.append(AdvisorRecommendation(
                        title=rem["title"],
                        detail=rem["detail"],
                        priority=rem.get("priority", "P1"),
                        difficulty=rem.get("difficulty", "中"),
                        dimension=dim,
                        category=category,
                        related_test_ids=[r.get("test_id", "")],
                        source="rule_engine",
                    ))

        # 配置缺失相关建议
        if config_issues:
            for issue in config_issues:
                if issue.severity in ("critical", "high"):
                    recs.append(AdvisorRecommendation(
                        title=f"补全缺失配置: {issue.field_name}",
                        detail=f"{issue.description}。建议: {issue.suggestion}",
                        priority="P0" if issue.severity == "critical" else "P1",
                        difficulty="低",
                        dimension="config",
                        category="config_missing",
                        related_test_ids=[],
                        source="rule_engine",
                    ))

        # 去重
        recs = self._deduplicate(recs)

        return recs

    # ============================================================
    # API 模型 — 使用脱敏 prompt
    # ============================================================

    def _api_analyze_sanitized(
        self,
        sanitized_prompt: str,
    ) -> tuple[list[AdvisorRecommendation], str]:
        """调用模型 API，使用脱敏后的 prompt（不含任何原始内容）

        模型不限定大小，用户通过 --advisor-model 自行选择。
        """

        # 调用 API
        try:
            response_text = self._call_api(sanitized_prompt)
        except Exception as e:
            print(f"  Advisor API 调用失败: {e}")
            print(f"  将 fallback 到规则引擎建议")
            return [], ""

        # 解析 JSON
        try:
            parsed = self._parse_llm_response(response_text)
            recs = []
            for item in parsed.get("recommendations", []):
                recs.append(AdvisorRecommendation(
                    title=item.get("title", ""),
                    detail=item.get("detail", ""),
                    priority=item.get("priority", "P1"),
                    difficulty=item.get("difficulty", "中"),
                    dimension=item.get("dimension", ""),
                    category=item.get("category", ""),
                    related_test_ids=item.get("related_test_ids", []),
                    source="advisor_agent",
                ))
            return recs, response_text
        except Exception as e:
            print(f"  Advisor 响应解析失败: {e}")
            return [], response_text

    # ============================================================
    # API 模型 — 旧版（不推荐，保留兼容）
    # ============================================================

    def _api_analyze(
        self,
        report: dict,
        agent_profile: Optional[AgentProfile],
        config_issues: Optional[list[ConfigIssue]],
    ) -> tuple[list[AdvisorRecommendation], str]:
        """调用模型 API 动态生成改进建议（旧版，未脱敏）"""

        # 构造输入 prompt
        user_prompt = self._build_analysis_prompt(report, agent_profile, config_issues)

        # 调用 API
        try:
            response_text = self._call_api(user_prompt)
        except Exception as e:
            print(f"  Advisor API 调用失败: {e}")
            print(f"  将 fallback 到规则引擎建议")
            return [], ""

        # 解析 JSON
        try:
            parsed = self._parse_llm_response(response_text)
            recs = []
            for item in parsed.get("recommendations", []):
                recs.append(AdvisorRecommendation(
                    title=item.get("title", ""),
                    detail=item.get("detail", ""),
                    priority=item.get("priority", "P1"),
                    difficulty=item.get("difficulty", "中"),
                    dimension=item.get("dimension", ""),
                    category=item.get("category", ""),
                    related_test_ids=item.get("related_test_ids", []),
                    source="advisor_agent",
                ))
            return recs, response_text
        except Exception as e:
            print(f"  Advisor 响应解析失败: {e}")
            return [], response_text

    def _build_analysis_prompt_legacy(
        self,
        report: dict,
        agent_profile: Optional[AgentProfile],
        config_issues: Optional[list[ConfigIssue]],
    ) -> str:
        """构造给 Advisor 模型的输入 prompt（旧版，含原始内容，不推荐）"""

        # 摘要化报告（避免过长）
        summary = report.get("summary", {})
        overall_score = summary.get("overall_score", 0)
        risk_level = summary.get("risk_level", "")

        # 静态分析摘要
        static_summary = ""
        static = report.get("static_analysis", {})
        if static:
            static_score = static.get("overall_score", 0)
            checks = static.get("checks", [])
            failed_checks = [c for c in checks if c.get("result") != "pass"]
            static_summary = f"静态分析评分: {static_score}/100\n"
            static_summary += f"失败/警告检查项 ({len(failed_checks)} 个):\n"
            for c in failed_checks[:10]:
                static_summary += f"  - {c.get('check_id', '')} [{c.get('severity', '')}] {c.get('title', '')}: {c.get('detail', '')[:100]}\n"

        # 动态测试摘要
        dynamic_summary = ""
        dynamic = report.get("dynamic_analysis", {})
        if dynamic:
            dim_breakdown = dynamic.get("dimension_breakdown", [])
            dynamic_summary = "动态测试维度评分:\n"
            for ds in dim_breakdown:
                dynamic_summary += f"  - {ds.get('dimension', '')}: {ds.get('score', 0)}/100 (通过{ds.get('passed', 0)}, 部分{ds.get('partial', 0)}, 失败{ds.get('failed', 0)})\n"

            details = dynamic.get("details", {})
            failed_tests = []
            for dim, results in details.items():
                for r in results:
                    if r.get("result") != "pass":
                        failed_tests.append(r)

            if failed_tests:
                dynamic_summary += f"\n失败/部分通过的测试 ({len(failed_tests)} 个):\n"
                for r in failed_tests[:15]:
                    dynamic_summary += f"  - {r.get('test_id', '')} [{r.get('severity', '')}] {r.get('category', '')}: score={r.get('score', 0)}, reason={r.get('reason', '')[:80]}\n"
                    snippet = r.get("response_snippet", "")
                    if snippet:
                        dynamic_summary += f"    响应片段: {snippet[:100]}\n"

        # Agent 档架信息
        profile_info = ""
        if agent_profile:
            profile_info = f"Agent 框架: {agent_profile.framework}\n"
            profile_info += f"Agent 名称: {agent_profile.name}\n"
            if agent_profile.system_prompts:
                profile_info += f"System Prompt 预览: {agent_profile.system_prompts[0][:200]}\n"

        # 配置缺失信息
        config_info = ""
        if config_issues:
            config_info = f"缺失配置项 ({len(config_issues)} 个):\n"
            for issue in config_issues:
                config_info += f"  - {issue.field_name}: {issue.description}\n"

        # 组装 prompt
        prompt = f"""请分析以下 Agent 测试报告并生成改进建议。

=== 报告概览 ===
综合评分: {overall_score}/100
风险等级: {risk_level}

=== Agent 信息 ===
{profile_info}

=== 静态分析结果 ===
{static_summary}

=== 动态测试结果 ===
{dynamic_summary}

=== 缺失配置 ===
{config_info}

请根据以上测试结果，生成针对性的改进建议。每个建议需要:
1. 对应具体的失败项
2. 给出优先级(P0/P1/P2)和难度(低/中/高)
3. 包含可操作的具体步骤

严格按照 JSON 格式输出。"""

        return prompt

    def _call_api(self, user_prompt: str) -> str:
        """调用 OpenAI-compatible API"""

        import urllib.request
        import urllib.error

        url = self.advisor_api_endpoint
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.advisor_api_key}",
        }

        payload = {
            "model": self.advisor_model,
            "messages": [
                {"role": "system", "content": self.ADVISOR_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.3,  # 低温度，更确定性
            "max_tokens": 2000,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        for attempt in range(self.max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                    content = body["choices"][0]["message"]["content"]
                    print(f"  Advisor Agent ({self.advisor_model}) 响应成功 ({len(content)} chars)")
                    return content
            except urllib.error.HTTPError as e:
                print(f"  Advisor API HTTP 错误: {e.code} {e.reason}")
                if attempt < self.max_retries:
                    time.sleep(1)
                else:
                    raise
            except urllib.error.URLError as e:
                print(f"  Advisor API 网络错误: {e.reason}")
                if attempt < self.max_retries:
                    time.sleep(1)
                else:
                    raise
            except Exception as e:
                print(f"  Advisor API 异常: {e}")
                if attempt < self.max_retries:
                    time.sleep(1)
                else:
                    raise

        return ""

    def _parse_llm_response(self, response_text: str) -> dict:
        """解析 LLM 响应中的 JSON

        LLM 输出可能包含 markdown 代码块包裹的 JSON，需要清理。
        """

        # 去除 markdown 代码块标记
        text = response_text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
        text = text.strip()

        # 尝试直接解析
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # 尝试提取 JSON 部分
            json_match = re.search(r'\{[\s\S]*\}', text)
            if json_match:
                return json.loads(json_match.group())
            raise

    # ============================================================
    # 合并策略
    # ============================================================

    def _merge_recommendations(
        self,
        rule_recs: list[AdvisorRecommendation],
        api_recs: list[AdvisorRecommendation],
    ) -> list[AdvisorRecommendation]:
        """合并规则引擎和 API 两个来源的建议

        策略:
        - API 建议优先（更针对性）
        - 规则引擎建议补充（更可靠）
        - 去重: 相同 category+title 只保留一个
        """

        merged = []

        # API 建议优先加入
        seen_keys = set()
        for rec in api_recs:
            key = (rec.category, rec.title)
            if key not in seen_keys:
                seen_keys.add(key)
                # 标记为 hybrid 来源
                rec.source = "advisor_agent"
                merged.append(rec)

        # 规则引擎建议补充不重复的
        for rec in rule_recs:
            key = (rec.category, rec.title)
            if key not in seen_keys:
                seen_keys.add(key)
                merged.append(rec)

        # 按优先级排序
        merged.sort(key=lambda x: {"P0": 0, "P1": 1, "P2": 2}.get(x.priority, 99))

        return merged

    # ============================================================
    # 辅助方法
    # ============================================================

    def _guess_behavior(self, category: str) -> str:
        """根据测试类别推测预期行为"""
        behavior_map = {
            "prompt_injection": "refuse", "harmful_content": "refuse", "data_security": "refuse",
            "input_boundary": "clarify", "task_boundary": "graceful_degrade", "context_boundary": "refuse",
            "response_speed": "expect", "accuracy": "expect", "consistency": "expect", "robustness": "graceful_degrade",
        }
        return behavior_map.get(category, "refuse")

    def _category_to_dimension(self, category: str) -> str:
        """将测试类别映射到维度"""
        dim_map = {
            "prompt_injection": "security", "harmful_content": "security", "data_security": "security",
            "input_boundary": "boundary", "task_boundary": "boundary", "context_boundary": "boundary",
            "response_speed": "performance", "accuracy": "performance", "consistency": "performance", "robustness": "performance",
            # 静态分析类别
            "prompt_security": "security", "boundary_declaration": "boundary",
            "code_security": "security", "config_security": "security",
            "data_security": "security", "safety_coverage": "security",
        }
        return dim_map.get(category, category)

    def _deduplicate(self, recs: list[AdvisorRecommendation]) -> list[AdvisorRecommendation]:
        """去重"""
        seen = set()
        unique = []
        for rec in recs:
            key = (rec.category, rec.title)
            if key not in seen:
                seen.add(key)
                unique.append(rec)
        unique.sort(key=lambda x: {"P0": 0, "P1": 1, "P2": 2}.get(x.priority, 99))
        return unique


# ============================================================
# 便捷函数
# ============================================================

def run_advisor(
    report: dict,
    agent_profile: Optional[AgentProfile] = None,
    config_issues: Optional[list[ConfigIssue]] = None,
    advisor_api_key: Optional[str] = None,
    advisor_api_endpoint: Optional[str] = None,
    advisor_model: Optional[str] = None,
    strategy: str = "auto",
    # 隐私参数 (v4.0)
    privacy_level: str = "strict",
    use_sanitized_input: bool = True,
) -> AdvisorReport:
    """便捷函数: 一行代码运行 Advisor 分析（默认使用脱敏输入）"""

    advisor = AdvisorAgent(
        advisor_api_key=advisor_api_key,
        advisor_api_endpoint=advisor_api_endpoint,
        advisor_model=advisor_model,
        strategy=strategy,
    )

    print("\n🧠 Advisor Agent 分析")
    print("-" * 40)

    result = advisor.analyze(
        report, agent_profile, config_issues,
        privacy_level=privacy_level,
        use_sanitized_input=use_sanitized_input,
    )

    print(f"  来源: {result.advisor_source}")
    print(f"  建议: {len(result.recommendations)} 条")
    if result.duration_ms > 0:
        print(f"  耗时: {result.duration_ms:.0f} ms")

    # 打印关键建议
    for rec in result.recommendations[:5]:
        icon = {"P0": "🔴", "P1": "🟠", "P2": "🟡"}.get(rec.priority, "⚪")
        print(f"  {icon} [{rec.priority}] {rec.title} ({rec.dimension}/{rec.category})")

    return result
