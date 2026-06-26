"""Agent 目录扫描器 - 扫描本地目录，识别 Agent 框架，提取关键文件

支持的框架识别:
  - LangChain (langchain/, chains/, agents/)
  - AutoGen (autogen/, agent.py)
  - CrewAI (crewai/, crew.py, agents.yaml)
  - OpenAI SDK (openai/, assistant)
  - 自定义 Agent (agent.py, bot.py, chatbot.py)

扫描流程:
  1. 遍历目录树，识别文件类型
  2. 通过特征文件判断 Agent 框架
  3. 提取 system prompt（从代码、配置、独立文件）
  4. 提取安全配置（safety filter, input validation）
  5. 检测风险标记（hardcoded keys, eval(), logging）
"""

import json
import os
import re
from pathlib import Path
from typing import Optional

import yaml

from core.source import AgentProfile, SourceType


# ============================================================
# 框架识别规则 — 每个框架的特征文件和特征目录
# ============================================================

FRAMEWORK_RULES = {
    "langchain": {
        "files": ["chains.py", "agents.py", "langchain_config.yaml"],
        "dirs": ["chains", "agents", "langchain", "prompts"],
        "imports": ["langchain", "langchain.chains", "langchain.agents", "langchain.prompts"],
        "config_files": ["langchain_config.yaml", "config.yaml"],
    },
    "autogen": {
        "files": ["autogen_config.json", "agent.py", "oai_config.json"],
        "dirs": ["autogen", "agents"],
        "imports": ["autogen", "autogen.Agent", "pyautogen"],
        "config_files": ["autogen_config.json", "oai_config.json", "config.json"],
    },
    "crewai": {
        "files": ["crew.py", "agents.yaml", "tasks.yaml"],
        "dirs": ["crewai", "crew", "agents"],
        "imports": ["crewai", "crewai.Agent", "crewai.Crew", "crewai.Task"],
        "config_files": ["agents.yaml", "tasks.yaml", "crew_config.yaml"],
    },
    "openai_sdk": {
        "files": ["assistant.py", "openai_config.yaml", "bot.py"],
        "dirs": ["openai", "assistant"],
        "imports": ["openai", "openai.OpenAI", "openai.beta.assistants"],
        "config_files": ["openai_config.yaml", "config.yaml"],
    },
    "custom": {
        "files": ["agent.py", "bot.py", "chatbot.py", "main.py", "app.py", "server.py"],
        "dirs": ["agent", "bot", "chatbot", "src", "lib"],
        "imports": [],
        "config_files": ["config.yaml", "config.json", "settings.yaml", "settings.json"],
    },
}


# ============================================================
# Prompt 提取规则 — 从不同格式的文件中提取 system prompt
# ============================================================

PROMPT_FILE_PATTERNS = [
    # 独立 prompt 文件
    "**/system_prompt.txt",
    "**/system_prompt.md",
    "**/prompt.txt",
    "**/prompt.md",
    "**/prompts/*.txt",
    "**/prompts/*.md",
    "**/system.txt",
    "**/system.md",
    "**/*.prompt",
]

# 从 Python 代码中提取 system prompt 的正则模式
PYTHON_PROMPT_PATTERNS = [
    # 变量赋值
    re.compile(r'(?:SYSTEM_PROMPT|system_prompt|SYS_PROMPT|prompt)\s*=\s*["\'](.+?)["\']', re.DOTALL),
    re.compile(r'(?:SYSTEM_PROMPT|system_prompt|SYS_PROMPT|prompt)\s*=\s*f["\'](.+?)["\']', re.DOTALL),
    # 多行字符串
    re.compile(r'(?:SYSTEM_PROMPT|system_prompt|SYS_PROMPT)\s*=\s*"""(.+?)"""', re.DOTALL),
    re.compile(r'(?:SYSTEM_PROMPT|system_prompt|SYS_PROMPT)\s*=\s*\'\'\'(.+?)\'\'\'', re.DOTALL),
    # ChatCompletion 调用中的 system message
    re.compile(r'role\s*=\s*"system".*?content\s*=\s*["\'](.+?)["\']', re.DOTALL),
    re.compile(r'\{"role":\s*"system",\s*"content":\s*["\'](.+?)["\']', re.DOTALL),
    # LangChain prompt template
    re.compile(r'PromptTemplate\s*\(\s*template\s*=\s*["\'](.+?)["\']', re.DOTALL),
    re.compile(r'ChatPromptTemplate\.from_messages\s*\(\s*\[(.+?)\]\s*\)', re.DOTALL),
]

# 安全特征检测模式
SAFETY_FEATURE_PATTERNS = {
    "has_safety_filter": [
        re.compile(r'safety|content_filter|moderation|guard|guardrail|safe', re.IGNORECASE),
        re.compile(r'openai\.Moderation|Moderation\.create|content_filter', re.IGNORECASE),
    ],
    "has_input_validation": [
        re.compile(r'validate|sanitiz|clean|strip|escape|encode_input|check_input', re.IGNORECASE),
        re.compile(r'max_length|max_tokens|input_limit|char_limit', re.IGNORECASE),
        re.compile(r're\.sub|regex_filter|pattern_filter|block_pattern', re.IGNORECASE),
    ],
    "has_output_filter": [
        re.compile(r'output_filter|response_filter|post_process|screen_output', re.IGNORECASE),
        re.compile(r' Moderation\.create|check_response|filter_response', re.IGNORECASE),
    ],
    "has_logging": [
        re.compile(r'logging|logger|log\.(info|warning|error)|print\(|console\.log', re.IGNORECASE),
    ],
    "has_hardcoded_keys": [
        re.compile(r'(?:api_key|API_KEY|secret|token)\s*=\s*["\'][a-zA-Z0-9\-]{8,}["\']', re.IGNORECASE),
        re.compile(r'sk-[a-zA-Z0-9]{20,}', re.IGNORECASE),
    ],
}

# 风险代码模式
RISK_CODE_PATTERNS = {
    "eval_usage": re.compile(r'eval\s*\(', re.IGNORECASE),
    "exec_usage": re.compile(r'exec\s*\(', re.IGNORECASE),
    "sql_injection_risk": re.compile(r'f".*?SELECT.*?FROM|f".*?INSERT.*?INTO|f".*?DELETE.*?FROM', re.IGNORECASE),
    "command_injection_risk": re.compile(r'os\.system\s*\(|subprocess\.call\s*\(|subprocess\.run\s*\(', re.IGNORECASE),
    "pickle_usage": re.compile(r'pickle\.loads\s*\(', re.IGNORECASE),
    "yaml_load": re.compile(r'yaml\.load\s*\((?!Loader)', re.IGNORECASE),
    "unhandled_exception": re.compile(r'except\s*:', re.IGNORECASE),
}


class DirectoryScanner:
    """本地目录扫描器"""

    def __init__(self, max_depth: int = 5, max_files: int = 500):
        self.max_depth = max_depth
        self.max_files = max_files

    def scan(self, directory: str, name: Optional[str] = None) -> AgentProfile:
        """扫描本地 Agent 目录并生成 Agent Profile"""

        dir_path = Path(directory)
        if not dir_path.exists():
            raise FileNotFoundError(f"目录不存在: {directory}")
        if not dir_path.is_dir():
            raise ValueError(f"路径不是目录: {directory}")

        profile = AgentProfile(
            source_type=SourceType.LOCAL,
            name=name or dir_path.name,
            directory=str(dir_path),
        )

        # 1. 遍历目录树
        all_files = self._walk_directory(dir_path)
        profile.total_files = len(all_files)
        profile.total_size_kb = sum(f.stat().st_size for f in all_files) / 1024

        # 2. 分类文件
        code_files, config_files, prompt_files, other_files = self._classify_files(all_files)
        profile.code_files = [str(f.relative_to(dir_path)) for f in code_files]
        profile.config_files = [str(f.relative_to(dir_path)) for f in config_files]
        profile.prompt_files = [str(f.relative_to(dir_path)) for f in prompt_files]

        # 3. 识别框架
        framework = self._detect_framework(code_files, config_files, dir_path)
        profile.framework = framework

        # 4. 提取 system prompts
        prompts = self._extract_prompts(prompt_files, code_files, config_files, dir_path)
        profile.system_prompts = prompts

        # 5. 提取配置数据
        profile.config_data = self._extract_config_data(config_files, dir_path)

        # 6. 检测安全特征
        self._detect_safety_features(code_files, dir_path, profile)

        # 7. 检测风险代码
        self._detect_risk_patterns(code_files, dir_path, profile)

        return profile

    def _walk_directory(self, dir_path: Path) -> list[Path]:
        """遍历目录树，排除不需要的文件"""
        excluded_dirs = {
            "__pycache__", ".git", ".venv", "venv", "node_modules",
            ".env", ".idea", ".vscode", "dist", "build", ".pytest_cache",
            "egg-info", "__pypackages__",
        }
        excluded_extensions = {
            ".pyc", ".pyo", ".so", ".dll", ".exe", ".png", ".jpg",
            ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        }

        files = []
        for root, dirs, filenames in os.walk(dir_path):
            # 深度控制
            depth = len(Path(root).relative_to(dir_path).parts)
            if depth > self.max_depth:
                dirs.clear()
                continue

            # 排除不需要的目录
            dirs[:] = [d for d in dirs if d not in excluded_dirs and not d.startswith(".")]

            for filename in filenames:
                fpath = Path(root) / filename
                if fpath.suffix in excluded_extensions:
                    continue
                files.append(fpath)
                if len(files) >= self.max_files:
                    return files

        return files

    def _classify_files(self, all_files: list[Path]) -> tuple:
        """分类文件为代码、配置、prompt 和其他"""

        code_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".rs"}
        config_extensions = {".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".env", ".conf"}
        prompt_extensions = {".txt", ".md", ".prompt", ".tmpl"}

        code_files = []
        config_files = []
        prompt_files = []
        other_files = []

        for f in all_files:
            ext = f.suffix.lower()
            # 特殊文件名优先判断
            name_lower = f.name.lower()
            if any(kw in name_lower for kw in ["prompt", "system", "template"]):
                prompt_files.append(f)
            elif ext in code_extensions:
                code_files.append(f)
            elif ext in config_extensions:
                config_files.append(f)
            elif ext in prompt_extensions:
                prompt_files.append(f)
            else:
                other_files.append(f)

        return code_files, config_files, prompt_files, other_files

    def _detect_framework(self, code_files: list[Path], config_files: list[Path], dir_path: Path) -> str:
        """识别 Agent 框架"""

        # 检查 import 语句
        import_lines = []
        code_contents = {}
        for cf in code_files[:30]:  # 只读前 30 个代码文件
            try:
                content = cf.read_text(encoding="utf-8", errors="ignore")
                code_contents[str(cf)] = content
                for line in content.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("import ") or stripped.startswith("from "):
                        import_lines.append(stripped)
            except Exception:
                pass

        # 检查特征文件
        relative_names = set()
        for f in code_files + config_files:
            try:
                relative_names.add(str(f.relative_to(dir_path)))
            except ValueError:
                relative_names.add(f.name)

        # 检查特征目录
        subdirs = set()
        for item in dir_path.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                subdirs.add(item.name)

        # 按规则匹配
        best_framework = "custom"
        best_score = 0

        for framework, rules in FRAMEWORK_RULES.items():
            score = 0
            for fname in rules["files"]:
                if fname in relative_names:
                    score += 3
            for dname in rules["dirs"]:
                if dname in subdirs:
                    score += 2
            for imp in rules["imports"]:
                for line in import_lines:
                    if imp in line:
                        score += 5
                        break
            if score > best_score:
                best_score = score
                best_framework = framework

        return best_framework

    def _extract_prompts(self, prompt_files: list[Path], code_files: list[Path], config_files: list[Path], dir_path: Path) -> list[str]:
        """从各类文件中提取 system prompt"""

        prompts = []

        # 1. 从独立 prompt 文件提取
        for pf in prompt_files:
            try:
                content = pf.read_text(encoding="utf-8", errors="ignore").strip()
                if content and len(content) > 10:  # 忽略极短内容
                    prompts.append(content)
            except Exception:
                pass

        # 2. 从 Python 代码中提取
        for cf in code_files[:20]:
            try:
                content = cf.read_text(encoding="utf-8", errors="ignore")
                for pattern in PYTHON_PROMPT_PATTERNS:
                    matches = pattern.findall(content)
                    for match in matches:
                        # 清理提取的内容
                        prompt_text = match.strip()
                        if len(prompt_text) > 10:
                            # 去掉 f-string 的花括号标记
                            prompt_text = re.sub(r'\{[^}]+\}', '<VAR>', prompt_text)
                            prompts.append(prompt_text)
            except Exception:
                pass

        # 3. 从配置文件提取
        for cf in config_files[:10]:
            try:
                content = cf.read_text(encoding="utf-8", errors="ignore")
                ext = cf.suffix.lower()

                if ext in (".yaml", ".yml"):
                    data = yaml.safe_load(content)
                    prompts.extend(self._extract_prompts_from_dict(data))
                elif ext == ".json":
                    data = json.loads(content)
                    prompts.extend(self._extract_prompts_from_dict(data))
            except Exception:
                pass

        return prompts

    def _extract_prompts_from_dict(self, data: dict, depth: int = 0) -> list[str]:
        """递归从 dict 结构中提取 prompt 相关字段"""

        if depth > 5 or not isinstance(data, dict):
            return []

        prompts = []
        prompt_keys = {
            "system_prompt", "system_message", "system", "prompt",
            "template", "instruction", "instructions", "description",
            "role_prompt", "persona", "character_prompt",
        }

        for key, value in data.items():
            key_lower = key.lower()
            if key_lower in prompt_keys and isinstance(value, str) and len(value) > 10:
                prompts.append(value.strip())
            elif isinstance(value, dict):
                prompts.extend(self._extract_prompts_from_dict(value, depth + 1))
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        prompts.extend(self._extract_prompts_from_dict(item, depth + 1))
                    elif isinstance(item, str) and len(item) > 10:
                        # 检查是否是 role: system 的消息
                        pass

        return prompts

    def _extract_config_data(self, config_files: list[Path], dir_path: Path) -> dict:
        """提取配置数据摘要"""

        config_data = {}
        for cf in config_files[:5]:
            try:
                content = cf.read_text(encoding="utf-8", errors="ignore")
                ext = cf.suffix.lower()

                if ext in (".yaml", ".yml"):
                    data = yaml.safe_load(content)
                    if isinstance(data, dict):
                        config_data[str(cf.relative_to(dir_path))] = self._summarize_config(data)
                elif ext == ".json":
                    data = json.loads(content)
                    if isinstance(data, dict):
                        config_data[str(cf.relative_to(dir_path))] = self._summarize_config(data)
            except Exception:
                pass

        return config_data

    def _summarize_config(self, data: dict, depth: int = 0) -> dict:
        """摘要配置数据（提取关键字段，不暴露敏感信息）"""

        if depth > 3:
            return {"...": "nested"}

        result = {}
        important_keys = {
            "model", "temperature", "max_tokens", "top_p", "frequency_penalty",
            "presence_penalty", "name", "description", "version", "api_endpoint",
            "safety", "guard", "filter", "moderation", "timeout",
        }

        for key, value in data.items():
            key_lower = key.lower()

            # 脱敏处理
            if any(kw in key_lower for kw in ["key", "secret", "token", "password", "credential"]):
                result[key] = "<REDACTED>"
                continue

            if key_lower in important_keys:
                result[key] = value
            elif isinstance(value, dict):
                result[key] = self._summarize_config(value, depth + 1)
            elif isinstance(value, (str, int, float, bool)):
                # 只保留短的值
                if isinstance(value, str) and len(value) > 100:
                    result[key] = value[:100] + "..."
                else:
                    result[key] = value

        return result

    def _detect_safety_features(self, code_files: list[Path], dir_path: Path, profile: AgentProfile):
        """检测安全特征"""

        # 合并所有代码文件内容
        combined_content = ""
        for cf in code_files[:30]:
            try:
                combined_content += cf.read_text(encoding="utf-8", errors="ignore") + "\n"
            except Exception:
                pass

        for feature_name, patterns in SAFETY_FEATURE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(combined_content):
                    setattr(profile, feature_name, True)
                    break

    def _detect_risk_patterns(self, code_files: list[Path], dir_path: Path, profile: AgentProfile):
        """检测风险代码模式 — 结果存储在 profile.config_data 中"""

        risk_findings = []

        for cf in code_files[:30]:
            try:
                content = cf.read_text(encoding="utf-8", errors="ignore")
                rel_path = str(cf.relative_to(dir_path))

                for risk_name, pattern in RISK_CODE_PATTERNS.items():
                    matches = pattern.findall(content)
                    if matches:
                        # 找到行号
                        lines = content.splitlines()
                        for i, line in enumerate(lines):
                            if pattern.search(line):
                                risk_findings.append({
                                    "file": rel_path,
                                    "line": i + 1,
                                    "risk_type": risk_name,
                                    "snippet": line.strip()[:100],
                                })
                                break  # 每种风险每个文件只报告一次
            except Exception:
                pass

        if risk_findings:
            profile.config_data["_risk_findings"] = risk_findings


def scan_prompt_text(prompt_text: str, name: str = "prompt-agent") -> AgentProfile:
    """从纯文本 prompt 创建 Agent Profile — 用于 --prompt 模式"""

    profile = AgentProfile(
        source_type=SourceType.PROMPT,
        name=name,
        framework="custom",
        system_prompts=[prompt_text],
        raw_prompt=prompt_text,
    )

    # 对 prompt 文本做基本安全特征检测
    prompt_lower = prompt_text.lower()

    # 检查 prompt 是否包含安全相关指令
    safety_indicators = [
        "安全", "禁止", "不得", "不允许", "限制", "边界",
        "safety", "prohibited", "not allowed", "restricted", "boundary",
        "guardrail", "filter", "moderation",
    ]
    profile.has_safety_filter = any(ind in prompt_lower for ind in safety_indicators)

    # 检查是否有输入验证相关指令
    validation_indicators = [
        "验证", "检查输入", "格式要求",
        "validate", "check input", "format requirement",
    ]
    profile.has_input_validation = any(ind in prompt_lower for ind in validation_indicators)

    return profile
