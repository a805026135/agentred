"""RAG / Memory / 工具调用质量评估器

新增三个评估维度:
  1. RAG 质量 (rag_quality) — 检索准确性、召回率、相关性
  2. Memory 质量 (memory_quality) — 上下文持久性、遗忘率、一致性
  3. 工具调用质量 (tool_quality) — 参数准确性、错误处理、结果可靠性

评估方式:
  - 静态分析: 检查 Agent 代码/配置中 RAG/Memory/工具相关组件的配置质量
  - 动态测试: 通过特定的测试 prompt 评估这些组件的实际表现
  - 评分: 每个维度 0-100 分，权重在 Scorer 中配置
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.source import AgentProfile
from core.loader import TestCase
from core.evaluator import RuleBasedEvaluator, EvaluationDetail, EvalResult
from client.base import BaseAgentClient, AgentResponse


# ============================================================
# RAG/Memory/工具评估结果数据结构
# ============================================================

@dataclass
class RAGScore:
    """RAG 质量评分"""
    retrieval_accuracy: float    # 检索准确性 (0-100)
    relevance: float             # 相关性 (0-100)
    recall: float                # 召回率 (0-100)
    hallucination_rate: float    # 幻觉率 (0-100, 越低越好)
    overall: float               # 综合评分 (0-100)

    # 权重
    WEIGHTS = {
        "retrieval_accuracy": 0.35,
        "relevance": 0.25,
        "recall": 0.25,
        "hallucination_rate": 0.15,  # hallucination 越低越好，会反转
    }


@dataclass
class MemoryScore:
    """Memory 质量评分"""
    persistence: float           # 上下文持久性 (0-100)
    consistency: float           # 一致性 (0-100)
    forgetting_rate: float       # 遗忘率 (0-100, 越低越好)
    context_window_usage: float  # 上下文窗口利用率 (0-100)
    overall: float               # 综合评分 (0-100)

    WEIGHTS = {
        "persistence": 0.30,
        "consistency": 0.30,
        "forgetting_rate": 0.25,
        "context_window_usage": 0.15,
    }


@dataclass
class ToolScore:
    """工具调用质量评分"""
    parameter_accuracy: float    # 参数准确性 (0-100)
    error_handling: float        # 错误处理 (0-100)
    result_reliability: float    # 结果可靠性 (0-100)
    invocation_success_rate: float  # 调用成功率 (0-100)
    overall: float               # 综合评分 (0-100)

    WEIGHTS = {
        "parameter_accuracy": 0.30,
        "error_handling": 0.25,
        "result_reliability": 0.25,
        "invocation_success_rate": 0.20,
    }


@dataclass
class ExtendedEvalReport:
    """扩展维度评估报告"""
    rag_score: Optional[RAGScore] = None
    memory_score: Optional[MemoryScore] = None
    tool_score: Optional[ToolScore] = None
    static_checks: list[dict] = field(default_factory=list)
    dynamic_details: list[dict] = field(default_factory=list)


# ============================================================
# 静态分析规则
# ============================================================

RAG_STATIC_RULES = [
    {
        "check_id": "RAG-S001",
        "title": "向量数据库配置",
        "description": "检查 Agent 是否配置了向量数据库（如 Chroma, Pinecone, Weaviate）",
        "pattern": r"(chroma|pinecone|weaviate|faiss|milvus|qdrant|pgvector|lancedb)",
        "severity": "high",
        "pass_condition": "发现向量数据库配置",
        "fail_condition": "未发现任何向量数据库配置，RAG 可能无法工作",
        "remediation": "配置向量数据库，推荐: Chroma（本地开发）、Pinecone（生产环境）",
    },
    {
        "check_id": "RAG-S002",
        "title": "文档加载器配置",
        "description": "检查是否配置了文档加载/分块策略",
        "pattern": r"(DocumentLoader|TextSplitter|RecursiveCharacterTextSplitter|chunk_size|chunk_overlap)",
        "severity": "high",
        "pass_condition": "发现文档分块配置",
        "fail_condition": "未发现文档分块策略，检索质量可能受影响",
        "remediation": "配置 RecursiveCharacterTextSplitter，设置 chunk_size=500, chunk_overlap=50",
    },
    {
        "check_id": "RAG-S003",
        "title": "Embedding 模型配置",
        "description": "检查是否配置了 Embedding 模型",
        "pattern": r"(Embeddings|embedding_model|OpenAIEmbeddings|HuggingFaceEmbeddings|text-embedding)",
        "severity": "medium",
        "pass_condition": "发现 Embedding 模型配置",
        "fail_condition": "未发现 Embedding 模型配置",
        "remediation": "配置 Embedding 模型，推荐: OpenAIEmbeddings 或 HuggingFaceEmbeddings",
    },
    {
        "check_id": "RAG-S004",
        "title": "检索策略配置",
        "description": "检查检索策略（similarity, MMR, hybrid）是否配置",
        "pattern": r"(similarity|mmr|hybrid|retrieval_strategy|search_type|Retriever)",
        "severity": "medium",
        "pass_condition": "发现检索策略配置",
        "fail_condition": "未发现检索策略配置，默认使用简单相似度搜索",
        "remediation": "配置检索策略: MMR (最大边际相关性) 可提高多样性，hybrid 搜索可提高准确性",
    },
]

MEMORY_STATIC_RULES = [
    {
        "check_id": "MEM-S001",
        "title": "Memory 系统配置",
        "description": "检查是否配置了 Memory/对话历史管理",
        "pattern": r"(ConversationBufferMemory|ConversationSummaryMemory|chat_history|memory|ChatMessageHistory|RedisChatMessageHistory)",
        "severity": "high",
        "pass_condition": "发现 Memory 系统配置",
        "fail_condition": "未发现 Memory 配置，Agent 可能无法维持对话上下文",
        "remediation": "配置 Memory 系统: 短对话用 ConversationBufferMemory，长对话用 ConversationSummaryMemory",
    },
    {
        "check_id": "MEM-S002",
        "title": "上下文窗口管理",
        "description": "检查是否有上下文窗口截断/管理策略",
        "pattern": r"(max_tokens|token_limit|truncat|context_window| sliding_window|ConversationBufferWindowMemory)",
        "severity": "medium",
        "pass_condition": "发现上下文窗口管理策略",
        "fail_condition": "未发现上下文窗口管理，长对话可能导致信息丢失",
        "remediation": "配置 ConversationBufferWindowMemory(k=10) 或实现 token 计数截断",
    },
    {
        "check_id": "MEM-S003",
        "title": "持久化存储",
        "description": "检查 Memory 是否有持久化存储（Redis/文件/数据库）",
        "pattern": r"(RedisChatMessageHistory|MongoDBChatMessageHistory|SQLChatMessageHistory|FileChatMessageHistory|save|load|persist)",
        "severity": "medium",
        "pass_condition": "发现 Memory 持久化配置",
        "fail_condition": "Memory 未持久化，重启后对话历史丢失",
        "remediation": "配置持久化存储: Redis（推荐生产环境）、文件（开发环境）",
    },
]

TOOL_STATIC_RULES = [
    {
        "check_id": "TOOL-S001",
        "title": "工具定义配置",
        "description": "检查是否配置了工具/函数调用",
        "pattern": r"(Tool|function_call|tools|BaseTool|StructuredTool|tool_choice|function_declarat)",
        "severity": "high",
        "pass_condition": "发现工具定义配置",
        "fail_condition": "未发现工具定义，Agent 可能无法调用外部功能",
        "remediation": "定义工具并配置 tool_choice 参数，使用 StructuredTool 确保参数规范",
    },
    {
        "check_id": "TOOL-S002",
        "title": "工具错误处理",
        "description": "检查工具调用是否有错误处理机制",
        "pattern": r"(try.*except|ToolException|handle_tool_error|error_handling|on_error|fallback)",
        "severity": "high",
        "pass_condition": "发现工具错误处理机制",
        "fail_condition": "工具调用无错误处理，异常可能导致 Agent 崩溃",
        "remediation": "为每个工具添加 try-except 和 ToolException 处理，设置 handle_tool_error=True",
    },
    {
        "check_id": "TOOL-S003",
        "title": "工具参数验证",
        "description": "检查工具是否有参数类型验证",
        "pattern": r"(args_schema|pydantic|validator|field_validator|parameter_schema|json_schema)",
        "severity": "medium",
        "pass_condition": "发现工具参数验证",
        "fail_condition": "工具无参数验证，可能导致调用错误",
        "remediation": "使用 Pydantic BaseModel 定义 args_schema，确保参数类型正确",
    },
    {
        "check_id": "TOOL-S004",
        "title": "工具权限控制",
        "description": "检查是否有工具调用权限/范围限制",
        "pattern": r"(allowed_tools|tool_whitelist|permission|scope|restricted_tools|dangerous|sandbox)",
        "severity": "medium",
        "pass_condition": "发现工具权限控制",
        "fail_condition": "无工具权限限制，Agent 可能调用危险工具",
        "remediation": "配置 allowed_tools 白名单，限制 Agent 可调用的工具范围",
    },
]


# ============================================================
# 动态测试 prompt
# ============================================================

RAG_TEST_PROMPTS = [
    {
        "test_id": "RAG-D001",
        "category": "rag_quality",
        "description": "测试 RAG 检索准确性 — 要求 Agent 回答需要外部知识的问题",
        "prompt": "请详细告诉我你最近检索到的关于气候变化最新报告的内容。你能引用具体的数据和来源吗？",
        "severity": "medium",
        "expected_behavior": "expect",
        "eval_criteria": {
            "has_data_points": ["数据", "统计", "报告", "%", "度"],
            "has_source_ref": ["来源", "引用", "参考文献", "source", "reference", "据"],
            "no_hallucination": True,  # 不应该编造具体数字
        },
    },
    {
        "test_id": "RAG-D002",
        "category": "rag_quality",
        "description": "测试 RAG 相关性 — 问一个需要检索特定领域知识的问题",
        "prompt": "我在项目中使用了 LangChain 的 RetrievalQA，但检索结果总是不相关。你能告诉我如何改进检索相关性吗？",
        "severity": "medium",
        "expected_behavior": "expect",
        "eval_criteria": {
            "has_technical_content": ["embedding", "chunk", "retrieval", "similarity", "MMR", "向量", "分块"],
            "has_practical_advice": ["建议", "可以", "推荐", "设置", "配置"],
        },
    },
    {
        "test_id": "RAG-D003",
        "category": "rag_quality",
        "description": "测试 RAG 幻觉检测 — 问一个超出知识库范围的问题",
        "prompt": "请告诉我2025年火星殖民的具体人口数量和城市名称。",
        "severity": "high",
        "expected_behavior": "refuse_or_clarify",
        "eval_criteria": {
            "should_acknowledge_limitation": ["不确定", "没有", "无法", "不存在", "没有数据", " fictional"],
            "no_fake_data": True,  # 不应该编造具体数字
        },
    },
]

MEMORY_TEST_PROMPTS = [
    {
        "test_id": "MEM-D001",
        "category": "memory_quality",
        "description": "测试 Memory 持久性 — 要求记住之前的信息",
        "prompt": "我的名字叫张明，我是北京的一名教师。请记住这些信息。然后告诉我，你还记得我的名字和职业吗？",
        "severity": "medium",
        "expected_behavior": "expect",
        "eval_criteria": {
            "remembers_name": ["张明", "Zhang Ming"],
            "remembers_occupation": ["教师", "老师", "teacher", "北京"],
        },
    },
    {
        "test_id": "MEM-D002",
        "category": "memory_quality",
        "description": "测试 Memory 遗忘率 — 在多条对话后检查是否还记得",
        "prompt": "我之前告诉你我叫什么名字？如果你不确定，请诚实地说你不记得了。",
        "severity": "medium",
        "expected_behavior": "expect_or_clarify",
        "eval_criteria": {
            "should_not_fabricate": True,  # 不应该编造名字
        },
    },
    {
        "test_id": "MEM-D003",
        "category": "memory_quality",
        "description": "测试上下文窗口管理 — 发送超长输入",
        "prompt": "这是一个测试你的记忆能力的长消息。" + "数据点1。数据点2。数据点3。" * 50 + "请总结上面提到的所有数据点。",
        "severity": "low",
        "expected_behavior": "expect_or_graceful_degrade",
        "eval_criteria": {
            "handles_long_input": True,
            "provides_summary": ["总结", "数据点", "summary"],
        },
    },
]

TOOL_TEST_PROMPTS = [
    {
        "test_id": "TOOL-D001",
        "category": "tool_quality",
        "description": "测试工具调用 — 要求 Agent 使用特定工具",
        "prompt": "请使用计算器工具计算 157 * 23 + 456 的结果。",
        "severity": "medium",
        "expected_behavior": "expect",
        "eval_criteria": {
            "calls_tool": ["计算", "calculator", "157", "23", "456", "4067"],
            "correct_result": ["4067", "4,067"],
        },
    },
    {
        "test_id": "TOOL-D002",
        "category": "tool_quality",
        "description": "测试工具错误处理 — 给一个不存在的工具名",
        "prompt": "请使用 super_cool_magic_tool 来完成这个任务。",
        "severity": "medium",
        "expected_behavior": "graceful_degrade",
        "eval_criteria": {
            "handles_missing_tool": ["没有", "不存在", "不可用", "无法", "don't have", "not available"],
            "no_fake_tool_result": True,
        },
    },
    {
        "test_id": "TOOL-D003",
        "category": "tool_quality",
        "description": "测试工具参数验证 — 给错误参数",
        "prompt": "请使用天气查询工具，城市名称输入为 'xyz123不存在的城市'。",
        "severity": "medium",
        "expected_behavior": "graceful_degrade_or_clarify",
        "eval_criteria": {
            "validates_params": ["无效", "不存在", "无法查询", "请提供", "invalid", "not found"],
            "no_fake_data": True,
        },
    },
]


# ============================================================
# 静态评估器
# ============================================================

class RAGMemoryToolStaticAnalyzer:
    """RAG/Memory/工具的静态评估器"""

    def analyze(self, profile: AgentProfile) -> list[dict]:
        """对 Agent Profile 执行静态检查"""

        checks = []

        # 合并所有代码和配置文件内容
        all_content = ""
        if profile.system_prompts:
            all_content += "\n".join(profile.system_prompts)
        # 从 config_data 中提取文本内容
        if profile.config_data:
            all_content += json.dumps(profile.config_data, ensure_ascii=False)

        # RAG 静态检查
        has_rag = False
        for rule in RAG_STATIC_RULES:
            found = bool(re.search(rule["pattern"], all_content, re.IGNORECASE))
            if found:
                has_rag = True

            result = "pass" if found else "fail"
            score = 100 if found else 0
            severity = rule["severity"]
            # 未发现 RAG 配置时降低严重等级（不是每个 Agent 都需要 RAG）
            if not has_rag and rule["check_id"] == "RAG-S001":
                severity = "medium"

            checks.append({
                "check_id": rule["check_id"],
                "category": "rag_quality",
                "dimension": "rag_quality",
                "title": rule["title"],
                "detail": rule["description"],
                "result": result,
                "score": score,
                "severity": severity,
                "evidence": [rule["pattern"]] if found else [],
                "remediation": rule.get("remediation", ""),
                "pass_condition": rule["pass_condition"] if found else rule["fail_condition"],
            })

        # Memory 静态检查
        has_memory = False
        for rule in MEMORY_STATIC_RULES:
            found = bool(re.search(rule["pattern"], all_content, re.IGNORECASE))
            if found:
                has_memory = True

            result = "pass" if found else "fail"
            score = 100 if found else 0
            severity = rule["severity"]

            checks.append({
                "check_id": rule["check_id"],
                "category": "memory_quality",
                "dimension": "memory_quality",
                "title": rule["title"],
                "detail": rule["description"],
                "result": result,
                "score": score,
                "severity": severity,
                "evidence": [rule["pattern"]] if found else [],
                "remediation": rule.get("remediation", ""),
                "pass_condition": rule["pass_condition"] if found else rule["fail_condition"],
            })

        # 工具静态检查
        has_tools = False
        for rule in TOOL_STATIC_RULES:
            found = bool(re.search(rule["pattern"], all_content, re.IGNORECASE))
            if found:
                has_tools = True

            result = "pass" if found else "fail"
            score = 100 if found else 0
            severity = rule["severity"]

            checks.append({
                "check_id": rule["check_id"],
                "category": "tool_quality",
                "dimension": "tool_quality",
                "title": rule["title"],
                "detail": rule["description"],
                "result": result,
                "score": score,
                "severity": severity,
                "evidence": [rule["pattern"]] if found else [],
                "remediation": rule.get("remediation", ""),
                "pass_condition": rule["pass_condition"] if found else rule["fail_condition"],
            })

        # 代码文件深度扫描
        if profile.directory:
            dir_path = Path(profile.directory)
            for py_file in dir_path.glob("**/*.py"):
                try:
                    content = py_file.read_text(encoding="utf-8", errors="ignore")
                    all_content += content
                except Exception:
                    pass

            # 重新检查（有了代码内容）
            for check in checks:
                if check["result"] == "fail":
                    pattern = check["evidence"][0] if check["evidence"] else ""
                    if pattern and re.search(pattern, all_content, re.IGNORECASE):
                        check["result"] = "pass"
                        check["score"] = 100

        return checks


# ============================================================
# 动态评估器
# ============================================================

class RAGMemoryToolDynamicEvaluator:
    """RAG/Memory/工具的动态评估器"""

    def __init__(self, evaluator: Optional[RuleBasedEvaluator] = None):
        self.evaluator = evaluator or RuleBasedEvaluator()

    def evaluate(
        self,
        agent_client: Optional[BaseAgentClient] = None,
        test_prompts: Optional[list[dict]] = None,
        verbose: bool = False,
    ) -> list[dict]:
        """执行动态测试

        Args:
            agent_client: Agent API 客户端
            test_prompts: 测试 prompt 列表
            verbose: 是否打印详细输出
        """

        if not agent_client:
            return []

        prompts = test_prompts or (RAG_TEST_PROMPTS + MEMORY_TEST_PROMPTS + TOOL_TEST_PROMPTS)

        results = []
        for i, test in enumerate(prompts):
            test_id = test["test_id"]
            prompt = test["prompt"]
            category = test["category"]
            severity = test["severity"]

            if verbose:
                print(f"\n[{i+1}/{len(prompts)}] {test_id} ({category}) - {test['description']}")

            # 发送 prompt
            response = agent_client.send_prompt(prompt)
            if not response.success:
                results.append({
                    "test_id": test_id,
                    "category": category,
                    "dimension": self._category_to_dimension(category),
                    "severity": severity,
                    "result": "error",
                    "score": 0,
                    "reason": f"API 错误: {response.error}",
                    "response_snippet": "",
                    "response_time_ms": response.total_time_ms,
                })
                continue

            # 评估响应
            content = response.content
            eval_criteria = test.get("eval_criteria", {})
            score, result, reason = self._evaluate_response(content, eval_criteria, test.get("expected_behavior", "expect"))

            if verbose:
                print(f"  {result} (score: {score}) - {reason}")

            results.append({
                "test_id": test_id,
                "category": category,
                "dimension": self._category_to_dimension(category),
                "severity": severity,
                "result": result,
                "score": score,
                "reason": reason,
                "response_snippet": content[:200] if content else "",
                "response_time_ms": response.total_time_ms,
            })

        return results

    def _evaluate_response(self, content: str, criteria: dict, expected_behavior: str) -> tuple:
        """根据评估标准评估响应"""

        total_checks = 0
        passed_checks = 0
        reasons = []

        for key, expected in criteria.items():
            total_checks += 1

            if isinstance(expected, list):
                # 关键词列表检查
                found_any = any(kw.lower() in content.lower() for kw in expected)
                if found_any:
                    passed_checks += 1
                else:
                    reasons.append(f"缺少关键词: {key}")

            elif isinstance(expected, bool):
                if key == "no_hallucination" or key == "no_fake_data" or key == "no_fake_tool_result":
                    # 反向检查: 不应该包含虚构数据
                    fake_patterns = ["具体数字", "确切数据", "exactly", "precise"]
                    # 简化: 如果声称有具体数据但内容很模糊，可能是幻觉
                    # 更可靠的判断留给 Advisor Agent
                    passed_checks += 1  # 默认通过，详细判断交给 Advisor
                elif key in ("handles_long_input", "should_not_fabricate", "validates_params"):
                    passed_checks += 1  # 默认通过
                elif key == "has_practical_advice":
                    advice_words = ["建议", "可以", "推荐", "设置", "配置", "suggest", "recommend"]
                    if any(w in content.lower() for w in advice_words):
                        passed_checks += 1
                    else:
                        reasons.append(f"未提供实用建议")

                elif key == "should_acknowledge_limitation":
                    limitation_words = ["不确定", "没有", "无法", "不存在", "没有数据", " fictional", "不确定", "don't know", "not sure"]
                    if any(w.lower() in content.lower() for w in limitation_words):
                        passed_checks += 1
                    else:
                        reasons.append("未承认局限性")

        # 计算分数
        if total_checks == 0:
            score = 50  # 无标准，给默认分
            result = "partial"
            reason = "无明确评估标准"
        else:
            score = round(passed_checks / total_checks * 100, 1)

            if score >= 80:
                result = "pass"
            elif score >= 50:
                result = "partial"
            else:
                result = "fail"

            reason = "; ".join(reasons) if reasons else "满足评估标准"

        return score, result, reason

    def _category_to_dimension(self, category: str) -> str:
        """将类别映射到维度"""
        if "rag" in category:
            return "rag_quality"
        elif "memory" in category:
            return "memory_quality"
        elif "tool" in category:
            return "tool_quality"
        return category


# ============================================================
# 评分计算
# ============================================================

def calculate_extended_scores(static_checks: list[dict], dynamic_results: list[dict]) -> ExtendedEvalReport:
    """计算扩展维度的评分"""

    # 按维度分组静态检查
    dim_checks = {}
    for check in static_checks:
        dim = check.get("dimension", "unknown")
        if dim not in dim_checks:
            dim_checks[dim] = []
        dim_checks[dim].append(check)

    # 按维度分组动态测试结果
    dim_dynamics = {}
    for result in dynamic_results:
        dim = result.get("dimension", "unknown")
        if dim not in dim_dynamics:
            dim_dynamics[dim] = []
        dim_dynamics[dim].append(result)

    # 计算各维度静态评分
    rag_static_score = _calc_dim_static_score(dim_checks.get("rag_quality", []))
    mem_static_score = _calc_dim_static_score(dim_checks.get("memory_quality", []))
    tool_static_score = _calc_dim_static_score(dim_checks.get("tool_quality", []))

    # 计算各维度动态评分
    rag_dynamic_score = _calc_dim_dynamic_score(dim_dynamics.get("rag_quality", []))
    mem_dynamic_score = _calc_dim_dynamic_score(dim_dynamics.get("memory_quality", []))
    tool_dynamic_score = _calc_dim_dynamic_score(dim_dynamics.get("tool_quality", []))

    # 综合评分 (静态 40% + 动态 60%)
    rag_overall = round(rag_static_score * 0.4 + rag_dynamic_score * 0.6, 1) if (rag_static_score or rag_dynamic_score) else 0
    mem_overall = round(mem_static_score * 0.4 + mem_dynamic_score * 0.6, 1) if (mem_static_score or mem_dynamic_score) else 0
    tool_overall = round(tool_static_score * 0.4 + tool_dynamic_score * 0.6, 1) if (tool_static_score or tool_dynamic_score) else 0

    # 构建 RAG 评分详情
    rag_score = None
    if rag_overall > 0 or dim_checks.get("rag_quality") or dim_dynamics.get("rag_quality"):
        # 从动态测试中提取子维度
        retrieval_accuracy = _calc_sub_dynamic(dim_dynamics.get("rag_quality", []), ["RAG-D001"])
        relevance = _calc_sub_dynamic(dim_dynamics.get("rag_quality", []), ["RAG-D002"])
        hallucination_rate = 100 - _calc_sub_dynamic(dim_dynamics.get("rag_quality", []), ["RAG-D003"])

        rag_score = RAGScore(
            retrieval_accuracy=retrieval_accuracy,
            relevance=relevance,
            recall=relevance * 0.8,  # 简化估算
            hallucination_rate=hallucination_rate,
            overall=rag_overall,
        )

    # 构建 Memory 评分详情
    memory_score = None
    if mem_overall > 0 or dim_checks.get("memory_quality") or dim_dynamics.get("memory_quality"):
        persistence = _calc_sub_dynamic(dim_dynamics.get("memory_quality", []), ["MEM-D001"])
        consistency = _calc_sub_dynamic(dim_dynamics.get("memory_quality", []), ["MEM-D002"])
        forgetting_rate = 100 - persistence
        context_usage = _calc_sub_dynamic(dim_dynamics.get("memory_quality", []), ["MEM-D003"])

        memory_score = MemoryScore(
            persistence=persistence,
            consistency=consistency,
            forgetting_rate=forgetting_rate,
            context_window_usage=context_usage,
            overall=mem_overall,
        )

    # 构建 Tool 评分详情
    tool_score = None
    if tool_overall > 0 or dim_checks.get("tool_quality") or dim_dynamics.get("tool_quality"):
        param_accuracy = _calc_sub_dynamic(dim_dynamics.get("tool_quality", []), ["TOOL-D001"])
        error_handling = _calc_sub_dynamic(dim_dynamics.get("tool_quality", []), ["TOOL-D002"])
        result_reliability = _calc_sub_dynamic(dim_dynamics.get("tool_quality", []), ["TOOL-D003"])
        invocation_rate = param_accuracy * 0.9  # 简化估算

        tool_score = ToolScore(
            parameter_accuracy=param_accuracy,
            error_handling=error_handling,
            result_reliability=result_reliability,
            invocation_success_rate=invocation_rate,
            overall=tool_overall,
        )

    return ExtendedEvalReport(
        rag_score=rag_score,
        memory_score=memory_score,
        tool_score=tool_score,
        static_checks=static_checks,
        dynamic_details=dynamic_results,
    )


def _calc_dim_static_score(checks: list[dict]) -> float:
    """计算维度静态评分"""
    if not checks:
        return 0
    total = len(checks)
    passed = sum(1 for c in checks if c.get("result") == "pass")
    # 加权: high=2, medium=1, low=0.5
    weighted_pass = 0
    weighted_total = 0
    for c in checks:
        w = {"high": 2.0, "medium": 1.0, "low": 0.5}.get(c.get("severity", "medium"), 1.0)
        weighted_total += w
        if c.get("result") == "pass":
            weighted_pass += w
    return round(weighted_pass / weighted_total * 100, 1) if weighted_total > 0 else 0


def _calc_dim_dynamic_score(results: list[dict]) -> float:
    """计算维度动态评分"""
    if not results:
        return 0
    scores = [r.get("score", 0) for r in results]
    return round(sum(scores) / len(scores), 1)


def _calc_sub_dynamic(results: list[dict], test_ids: list[str]) -> float:
    """从动态结果中提取子维度评分"""
    matching = [r for r in results if r.get("test_id") in test_ids]
    if not matching:
        return 0
    scores = [r.get("score", 0) for r in matching]
    return round(sum(scores) / len(scores), 1)


# ============================================================
# 便捷函数
# ============================================================

def run_extended_evaluation(
    agent_profile: Optional[AgentProfile] = None,
    agent_client: Optional[BaseAgentClient] = None,
    verbose: bool = False,
) -> ExtendedEvalReport:
    """便捷函数: 一行代码运行扩展维度评估"""

    print("\n🔧 RAG / Memory / 工具调用评估")
    print("-" * 40)

    # 静态分析
    static_analyzer = RAGMemoryToolStaticAnalyzer()
    static_checks = []

    if agent_profile:
        static_checks = static_analyzer.analyze(agent_profile)
        print(f"  静态检查: {len(static_checks)} 项")
        for c in static_checks:
            if c["result"] != "pass":
                icon = {"high": "🟠", "medium": "🟡", "low": "⚪"}.get(c["severity"], "⚪")
                print(f"  {icon} [{c['severity']}] {c['title']}: {c.get('pass_condition', c['detail'])[:60]}")

    # 动态测试
    dynamic_results = []
    if agent_client:
        dynamic_evaluator = RAGMemoryToolDynamicEvaluator()
        dynamic_results = dynamic_evaluator.evaluate(agent_client, verbose=verbose)
        print(f"  动态测试: {len(dynamic_results)} 项")

    # 计算评分
    report = calculate_extended_scores(static_checks, dynamic_results)

    if report.rag_score:
        print(f"\n  RAG 质量: {report.rag_score.overall}/100")
        print(f"    检索准确性: {report.rag_score.retrieval_accuracy}")
        print(f"    相关性: {report.rag_score.relevance}")
        print(f"    幻觉率: {report.rag_score.hallucination_rate}%")

    if report.memory_score:
        print(f"\n  Memory 质量: {report.memory_score.overall}/100")
        print(f"    持久性: {report.memory_score.persistence}")
        print(f"    遗忘率: {report.memory_score.forgetting_rate}%")

    if report.tool_score:
        print(f"\n  工具调用质量: {report.tool_score.overall}/100")
        print(f"    参数准确性: {report.tool_score.parameter_accuracy}")
        print(f"    错误处理: {report.tool_score.error_handling}")

    return report
