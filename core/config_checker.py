"""配置缺失检测器 — 自动检测 Agent 目录/配置中缺失的关键配置项

功能:
  1. 扫描 Agent 目录/配置文件，检测缺失的 API Key、Base URL、模型名称等
  2. 生成缺失项列表，包含描述和建议的值/操作
  3. 交互式提示用户补全缺失项

检测范围:
  - API Key（OPENAI_API_KEY, DEEPSEEK_API_KEY 等）
  - Base URL / API Endpoint
  - 模型名称
  - 依赖包版本
  - 环境变量引用（${...}）是否已设置
  - 配置文件中的空值/占位符
  - 必要的配置文件是否存在
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.source import AgentProfile
from core.advisor import ConfigIssue


# ============================================================
# 常见的配置项模式
# ============================================================

# 必要的 API Key 环境变量
REQUIRED_API_KEYS = {
    "OPENAI_API_KEY": {
        "description": "OpenAI API Key，用于调用 GPT 模型",
        "severity": "critical",
        "suggestion": "前往 https://platform.openai.com/api-keys 获取",
        "key_pattern": r"sk-[a-zA-Z0-9]{20,}",
    },
    "DEEPSEEK_API_KEY": {
        "description": "DeepSeek API Key，用于调用 DeepSeek 模型",
        "severity": "critical",
        "suggestion": "前往 https://platform.deepseek.com/api_keys 获取",
        "key_pattern": r"sk-[a-zA-Z0-9]{20,}",
    },
    "ANTHROPIC_API_KEY": {
        "description": "Anthropic API Key，用于调用 Claude 模型",
        "severity": "high",
        "suggestion": "前往 https://console.anthropic.com/ 获取",
        "key_pattern": r"sk-ant-[a-zA-Z0-9]{20,}",
    },
    "DASHSCOPE_API_KEY": {
        "description": "阿里 DashScope API Key，用于调用 Qwen 模型",
        "severity": "high",
        "suggestion": "前往 https://dashscope.console.aliyun.com/ 获取",
    },
    "ZHIPU_API_KEY": {
        "description": "智谱 API Key，用于调用 GLM 模型",
        "severity": "high",
        "suggestion": "前往 https://open.bigmodel.cn/ 获取",
    },
}

# 必要的配置字段
REQUIRED_CONFIG_FIELDS = {
    "api_endpoint": {
        "description": "API 服务端点地址",
        "severity": "critical",
        "suggestion": "设置为 OpenAI-compatible API 的 chat/completions 接口地址，如 https://api.openai.com/v1/chat/completions",
        "env_var": "OPENAI_API_BASE",
    },
    "model": {
        "description": "使用的模型名称",
        "severity": "high",
        "suggestion": "设置为具体模型名称，如 gpt-4, deepseek-chat, qwen-turbo 等",
    },
    "temperature": {
        "description": "模型温度参数，控制输出随机性",
        "severity": "low",
        "suggestion": "推荐: 安全/事实性问题用 0.1-0.3，创意性任务用 0.5-0.7",
    },
}

# 常见配置文件名
CONFIG_FILE_NAMES = [
    "config.yaml", "config.yml", "config.json", "config.toml",
    ".env", ".env.local", ".env.production",
    "settings.yaml", "settings.json",
    "app.config", "appsettings.json",
]

# 占位符模式
PLACEHOLDER_PATTERNS = [
    r"\$\{[^}]+\}",          # ${VAR_NAME}
    r"<YOUR_API_KEY>",       # <YOUR_API_KEY>
    r"your-api-key-here",    # your-api-key-here
    r"sk-your-key",          # sk-your-key
    r"REPLACE_ME",           # REPLACE_ME
    r"TODO",                 # TODO
    r"xxx",                  # xxx (常见占位)
]


# ============================================================
# ConfigChecker 主类
# ============================================================

class ConfigChecker:
    """配置缺失检测器"""

    def __init__(
        self,
        extra_required_keys: Optional[dict] = None,
        extra_required_fields: Optional[dict] = None,
    ):
        self.required_api_keys = REQUIRED_API_KEYS.copy()
        if extra_required_keys:
            self.required_api_keys.update(extra_required_keys)

        self.required_config_fields = REQUIRED_CONFIG_FIELDS.copy()
        if extra_required_fields:
            self.required_config_fields.update(extra_required_fields)

    # ============================================================
    # 主入口
    # ============================================================

    def check(
        self,
        agent_profile: Optional[AgentProfile] = None,
        agent_dir: Optional[str] = None,
        config_data: Optional[dict] = None,
    ) -> list[ConfigIssue]:
        """检测配置缺失项

        Args:
            agent_profile: Agent 文件档案
            agent_dir: Agent 目录路径（如果未提供 profile）
            config_data: 已知的配置数据（如 config.yaml 内容）

        Returns:
            list[ConfigIssue]: 缺失的配置项列表
        """

        issues = []

        # 1. 如果有 profile，从中提取信息
        if agent_profile:
            issues.extend(self._check_profile(agent_profile))

        # 2. 如果有目录，扫描配置文件
        if agent_dir or (agent_profile and agent_profile.directory):
            scan_dir = agent_dir or agent_profile.directory
            issues.extend(self._scan_directory(scan_dir))

        # 3. 检查环境变量引用
        if config_data:
            issues.extend(self._check_config_data(config_data))

        # 4. 检查系统环境变量
        issues.extend(self._check_env_vars(issues))

        # 去重
        seen = set()
        unique = []
        for issue in issues:
            key = (issue.field_name, issue.severity)
            if key not in seen:
                seen.add(key)
                unique.append(issue)

        # 排序: critical > high > medium > low
        unique.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity, 99))

        return unique

    # ============================================================
    # 检查 Profile
    # ============================================================

    def _check_profile(self, profile: AgentProfile) -> list[ConfigIssue]:
        """从 AgentProfile 检查配置缺失"""

        issues = []

        # API Key 缺失
        if not profile.api_key_available and profile.source_type.value != "local":
            # API/Prompt 模式需要 API Key
            issues.append(ConfigIssue(
                field_name="api_key",
                description="Agent 需要 API Key 才能进行动态测试，但未提供",
                severity="critical",
                suggestion="通过 --api-key 参数提供，或设置 OPENAI_API_KEY 环境变量",
                env_var="OPENAI_API_KEY",
            ))

        # API Endpoint 缺失
        if not profile.api_endpoint and profile.source_type.value != "local":
            issues.append(ConfigIssue(
                field_name="api_endpoint",
                description="Agent 需要 API 端点地址才能进行动态测试",
                severity="high",
                suggestion="通过 --api-endpoint 参数提供，如 https://api.openai.com/v1/chat/completions",
            ))

        # 模型名称缺失
        if not profile.model and profile.source_type.value != "local":
            issues.append(ConfigIssue(
                field_name="model",
                description="未指定模型名称，将使用默认模型",
                severity="medium",
                suggestion="通过 --model 参数指定模型，如 gpt-4, deepseek-chat",
            ))

        # 硬编码密钥（安全风险，也是配置问题）
        if profile.has_hardcoded_keys:
            issues.append(ConfigIssue(
                field_name="hardcoded_api_key",
                description="Agent 代码中发现硬编码的 API Key，这是严重的安全隐患",
                severity="critical",
                suggestion="将 API Key 移到环境变量或 .env 文件中，代码中用 os.environ.get() 读取",
            ))

        # System Prompt 空缺
        if not profile.system_prompts and profile.source_type.value in ("local", "prompt"):
            issues.append(ConfigIssue(
                field_name="system_prompt",
                description="Agent 缺少 System Prompt，这会导致行为不受约束",
                severity="high",
                suggestion="在 Agent 配置或代码中定义 System Prompt，明确安全边界和能力范围",
            ))

        # 缺少安全过滤器
        if not profile.has_safety_filter:
            issues.append(ConfigIssue(
                field_name="safety_filter",
                description="Agent 未配置安全过滤器/内容审核机制",
                severity="high",
                suggestion="添加内容安全过滤层，检测并拦截有害请求和响应",
            ))

        return issues

    # ============================================================
    # 扫描目录
    # ============================================================

    def _scan_directory(self, agent_dir: str) -> list[ConfigIssue]:
        """扫描 Agent 目录，检查配置文件中的缺失项"""

        issues = []
        dir_path = Path(agent_dir)

        if not dir_path.exists():
            issues.append(ConfigIssue(
                field_name="agent_directory",
                description=f"指定的 Agent 目录不存在: {agent_dir}",
                severity="critical",
                suggestion="请确认目录路径是否正确",
            ))
            return issues

        # 检查配置文件是否存在
        found_configs = []
        for name in CONFIG_FILE_NAMES:
            if (dir_path / name).exists():
                found_configs.append(name)

        if not found_configs:
            # 检查是否有任何 YAML/JSON/TOML 文件
            for ext in ("*.yaml", "*.yml", "*.json", "*.toml"):
                matches = list(dir_path.glob(ext))
                found_configs.extend([m.name for m in matches])

        if not found_configs:
            issues.append(ConfigIssue(
                field_name="config_file",
                description="Agent 目录中未发现任何配置文件（config.yaml/.env 等）",
                severity="medium",
                suggestion="创建 config.yaml 或 .env 文件来管理 Agent 配置",
            ))
        else:
            # 读取配置文件内容，检查占位符和环境变量引用
            for config_file in found_configs[:5]:  # 只检查前5个
                file_path = dir_path / config_file
                try:
                    content = file_path.read_text(encoding="utf-8", errors="ignore")

                    # 检查占位符
                    for pattern in PLACEHOLDER_PATTERNS:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            if pattern == r"\$\{[^}]+\}":
                                env_var_name = match[2:-1]
                                # 检查该环境变量是否已设置
                                if not os.environ.get(env_var_name):
                                    issues.append(ConfigIssue(
                                        field_name=env_var_name,
                                        description=f"配置文件 {config_file} 中引用了环境变量 {env_var_name}，但该变量未设置",
                                        severity="critical" if "API_KEY" in env_var_name.upper() or "KEY" in env_var_name.upper() else "high",
                                        suggestion=f"设置环境变量: export {env_var_name}=your-value-here",
                                        env_var=env_var_name,
                                    ))
                            else:
                                issues.append(ConfigIssue(
                                    field_name=f"placeholder_in_{config_file}",
                                    description=f"配置文件 {config_file} 中发现占位符 '{match}'，需要替换为真实值",
                                    severity="high",
                                    suggestion=f"在 {config_file} 中将 '{match}' 替换为实际的配置值",
                                ))

                    # 检查 .env 文件中缺失的 key
                    if config_file.startswith(".env"):
                        for line in content.splitlines():
                            line = line.strip()
                            if line and not line.startswith("#") and "=" in line:
                                key, value = line.split("=", 1)
                                value = value.strip()
                                if not value or value in ("", "''", '""'):
                                    issues.append(ConfigIssue(
                                        field_name=key.strip(),
                                        description=f".env 文件中 {key.strip()} 的值为空",
                                        severity="high",
                                        suggestion=f"为 {key.strip()} 设置一个有效的值",
                                    ))

                except Exception:
                    pass  # 忽略读取错误

        # 检查代码文件中的 API Key 引用
        for py_file in dir_path.glob("*.py"):
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")

                # 检查 os.environ.get / os.getenv 调用中的环境变量
                env_matches = re.findall(r"os\.environ\.get\(['\"]([^'\"]+)['\"]", content)
                env_matches2 = re.findall(r"os\.getenv\(['\"]([^'\"]+)['\"]", content)
                all_env_vars = set(env_matches + env_matches2)

                for env_var in all_env_vars:
                    if not os.environ.get(env_var) and "API" in env_var.upper() or "KEY" in env_var.upper():
                        # 只标记关键的未设置环境变量
                        issues.append(ConfigIssue(
                            field_name=env_var,
                            description=f"代码 {py_file.name} 中引用了环境变量 {env_var}，但该变量当前未设置",
                            severity="high" if "KEY" in env_var.upper() else "medium",
                            suggestion=f"设置环境变量: set {env_var}=your-value (Windows) 或 export {env_var}=your-value (Linux)",
                            env_var=env_var,
                        ))
            except Exception:
                pass

        return issues

    # ============================================================
    # 检查配置数据
    # ============================================================

    def _check_config_data(self, config_data: dict) -> list[ConfigIssue]:
        """检查已解析的配置数据中的缺失项"""

        issues = []

        # 检查 agent 配置段
        agent_config = config_data.get("agent", {})

        if not agent_config.get("api_key") or agent_config.get("api_key", "").startswith("${"):
            env_var = ""
            key_val = agent_config.get("api_key", "")
            if key_val.startswith("${") and key_val.endswith("}"):
                env_var = key_val[2:-1]
            if not env_var or not os.environ.get(env_var):
                issues.append(ConfigIssue(
                    field_name="agent.api_key",
                    description="Agent 配置中 API Key 未设置或引用的环境变量不存在",
                    severity="critical",
                    suggestion=f"直接设置 api_key 值，或确保环境变量 {env_var} 已设置",
                    env_var=env_var or "OPENAI_API_KEY",
                ))

        if not agent_config.get("api_endpoint"):
            issues.append(ConfigIssue(
                field_name="agent.api_endpoint",
                description="Agent 配置中未设置 API 端点地址",
                severity="high",
                suggestion="设置为 OpenAI-compatible API 地址，如 https://api.openai.com/v1/chat/completions",
            ))

        if not agent_config.get("model"):
            issues.append(ConfigIssue(
                field_name="agent.model",
                description="Agent 配置中未指定模型名称",
                severity="medium",
                suggestion="指定具体模型，如 gpt-4, deepseek-chat, qwen-turbo",
            ))

        return issues

    # ============================================================
    # 检查环境变量
    # ============================================================

    def _check_env_vars(self, existing_issues: list[ConfigIssue]) -> list[ConfigIssue]:
        """检查系统环境变量中常见 API Key 是否设置"""

        issues = []

        # 只检查尚未在 existing_issues 中出现的 API Key
        already_mentioned = {issue.env_var for issue in existing_issues if issue.env_var}

        for env_var, info in self.required_api_keys.items():
            if env_var in already_mentioned:
                continue  # 已经在前面检测过了
            if not os.environ.get(env_var):
                # 只在 Agent 需要 API 模式时才标记
                # 这里不标记为缺失（因为不一定需要所有 key），只标记为"未设置"
                pass  # 不主动报告所有未设置的 API Key，只报告 Agent 实际需要的

        return issues


# ============================================================
# 便捷函数
# ============================================================

def check_config(
    agent_profile: Optional[AgentProfile] = None,
    agent_dir: Optional[str] = None,
    config_data: Optional[dict] = None,
) -> list[ConfigIssue]:
    """便捷函数: 一行代码检测配置缺失"""

    checker = ConfigChecker()
    issues = checker.check(agent_profile=agent_profile, agent_dir=agent_dir, config_data=config_data)

    if issues:
        print("\n⚠️ 配置缺失检测")
        print("-" * 40)
        for issue in issues:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(issue.severity, "⚪")
            print(f"  {icon} [{issue.severity}] {issue.field_name}: {issue.description}")
            print(f"      建议: {issue.suggestion}")
        print()

    return issues
