"""Agent 来源抽象层 - 支持多种方式接入 Agent

三种输入模式:
  1. APIAgentSource   — 通过 OpenAI-compatible API 动态测试
  2. LocalAgentSource — 拖入本地 Agent 目录，做静态分析 + (可选)动态测试
  3. PromptAgentSource — 直接输入 system prompt 文本，做静态分析 + (可选)动态测试
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SourceType(Enum):
    """Agent 来源类型"""
    API = "api"
    LOCAL = "local"
    PROMPT = "prompt"


@dataclass
class AgentProfile:
    """从 Agent 来源提取的综合档案 — 无论哪种输入方式，最终都生成这个"""
    source_type: SourceType

    # 基本信息
    name: str = "unknown"
    framework: str = "unknown"          # langchain / autogen / crewai / openai / custom
    description: str = ""

    # System Prompt 相关
    system_prompts: list[str] = field(default_factory=list)
    prompt_files: list[str] = field(default_factory=list)  # 来源文件路径

    # 配置相关
    config_files: list[str] = field(default_factory=list)
    config_data: dict = field(default_factory=dict)

    # 代码文件相关
    code_files: list[str] = field(default_factory=list)
    total_files: int = 0
    total_size_kb: float = 0.0

    # API 相关 (仅 API/Prompt+API 模式)
    api_endpoint: str = ""
    model: str = ""
    api_key_available: bool = False

    # 静态分析标记
    has_safety_filter: bool = False
    has_input_validation: bool = False
    has_output_filter: bool = False
    has_logging: bool = False
    has_hardcoded_keys: bool = False

    # 原始目录路径 (仅 LOCAL 模式)
    directory: str = ""

    # 原始 prompt 文本 (仅 PROMPT 模式)
    raw_prompt: str = ""
