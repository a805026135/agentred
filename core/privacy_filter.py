"""隐私过滤器 — 脱敏报告，确保 Agent 核心内容不泄露

设计理念:
  测试报告可能包含敏感信息（System Prompt、代码片段、API Key、原始响应等）。
  当报告需要上传到外部 Advisor Agent 进行分析时，必须先脱敏。

  PrivacyFilter 的职责:
    1. 识别并剥离报告中的敏感字段
    2. 将原始内容替换为抽象摘要（如 "System Prompt 长度: 328 chars" 而非完整内容）
    3. 记录脱敏操作日志（哪些字段被处理了）
    4. 支持三级隐私等级（strict / moderate / minimal）

隐私等级:
  strict   — 最严格：剥离所有原始内容，只保留评分和类别标签
  moderate — 中等：保留问题描述摘要（不含原始代码/prompt），剥离响应片段
  minimal  — 最宽松：保留响应摘要（不含完整原文），剥离密钥和身份信息

敏感字段定义:
  - system_prompts_preview    → System Prompt 原文
  - evidence                  → 静态分析的代码证据
  - response_snippet          → Agent 原始响应片段
  - detail (含代码)           → 含代码的详细描述
  - raw_llm_response          → Advisor LLM 原始响应
  - api_key / api_endpoint    → API 连接信息
  - directory                 → 本地目录路径
  - config_data               → 配置数据（含密钥）
  - raw_prompt                → 原始 Prompt 文本
"""

import re
from dataclasses import dataclass, field
from typing import Optional


# ============================================================
# 隐私等级
# ============================================================

class PrivacyLevel:
    """隐私等级"""
    STRICT = "strict"       # 最严格：只保留评分+类别
    MODERATE = "moderate"   # 中等：保留摘要，剥离原文
    MINIMAL = "minimal"     # 最宽松：保留摘要，只剥离密钥/身份


# ============================================================
# 脱敏日志记录
# ============================================================

@dataclass
class SanitizationLog:
    """脱敏操作日志"""
    field_path: str           # 被处理的字段路径
    original_type: str        # 原始类型 (full_text / snippet / key / path / etc)
    action: str               # 操作 (removed / summarized / masked / truncated)
    original_length: int = 0  # 原始内容长度（chars/bytes）
    summary: str = ""         # 脱敏后的摘要内容


@dataclass
class SanitizedReport:
    """脱敏后的报告"""
    report: dict                                  # 脱敏后的报告数据
    privacy_level: str                            # 使用的隐私等级
    sanitization_logs: list[SanitizationLog] = field(default_factory=list)
    sensitive_fields_removed: int = 0
    total_fields_checked: int = 0
    is_safe_for_upload: bool = True               # 是否可以安全上传


# ============================================================
# 敏感字段定义
# ============================================================

# 需要完全剥离的字段（无论隐私等级）
ALWAYS_REMOVE_FIELDS = [
    "raw_llm_response",       # Advisor LLM 原始响应（含可能的敏感内容）
    "raw_prompt",             # 原始 Prompt 文本
]

# 需要脱敏处理的字段（按隐私等级不同处理）
SENSITIVE_FIELD_RULES = {
    # 字段路径 → (字段类型, strict处理, moderate处理, minimal处理)
    "static_analysis.system_prompts_preview": (
        "full_text",
        "remove",        # strict: 完全移除
        "summarize",     # moderate: 替换为摘要
        "truncate",      # minimal: 截断到50 chars
    ),
    "static_analysis.checks.*.evidence": (
        "code_snippet",
        "remove",
        "summarize",
        "truncate",
    ),
    "static_analysis.checks.*.detail": (
        "description_with_code",
        "summarize",     # strict: 只保留问题类别
        "keep_safe",     # moderate: 保留不含代码的部分
        "truncate",
    ),
    "static_analysis.checks.*.remediation": (
        "recommendation",
        "summarize",     # strict: 只保留标题
        "keep_safe",     # moderate: 保留不含代码示例的部分
        "truncate",
    ),
    "dynamic_analysis.details.*.*.response_snippet": (
        "agent_response",
        "remove",        # strict: 完全移除
        "summarize",     # moderate: 替换为 "Agent 回应了 X chars"
        "truncate",      # minimal: 截断到30 chars
    ),
    "dynamic_analysis.details.*.*.reason": (
        "eval_reason",
        "summarize",     # strict: 只保留 pass/fail/partial
        "keep_safe",     # moderate: 保留不含原文的理由
        "truncate",
    ),
    "agent_info.directory": (
        "local_path",
        "remove",
        "mask",
        "truncate",
    ),
    "agent_info.api_endpoint": (
        "api_url",
        "remove",
        "mask",          # moderate: 隐藏域名，保留路径
        "keep_safe",
    ),
    "agent_info.model": (
        "model_name",
        "keep_safe",     # 模型名称不算敏感
        "keep_safe",
        "keep_safe",
    ),
    "extended_evaluation.static_checks.*.evidence": (
        "code_snippet",
        "remove",
        "summarize",
        "truncate",
    ),
    "extended_evaluation.dynamic_details.*.response_snippet": (
        "agent_response",
        "remove",
        "summarize",
        "truncate",
    ),
}


# ============================================================
# 自动检测敏感内容的正则模式
# ============================================================

AUTO_SENSITIVE_PATTERNS = [
    # API Key / Secret
    (r'(?:api[_-]?key|secret|token|password|credential|auth)["\s]*[:=]["\s]*["\']?[a-zA-Z0-9_\-]{8,}', "api_key_or_secret"),
    # OpenAI Key 格式
    (r'sk-[a-zA-Z0-9]{20,}', "openai_api_key"),
    # DeepSeek Key 格式
    (r'sk-[a-zA-Z0-9]{20,}@deepseek', "deepseek_api_key"),
    # Anthropic Key 格式
    (r'sk-ant-[a-zA-Z0-9\-]{20,}', "anthropic_api_key"),
    # 环境变量值
    (r'\$\{[A-Z_]+\}', "env_var_ref"),
    # IP 地址
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', "ip_address"),
    # 邮箱
    (r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', "email"),
    # 文件路径（Windows/Unix）
    (r'(?:[A-Z]:\\|/home/|/Users/|/var/|/tmp/)[\w\\/.\-]+', "file_path"),
]


# ============================================================
# PrivacyFilter 主类
# ============================================================

class PrivacyFilter:
    """隐私过滤器 — 脱敏报告中的敏感信息"""

    def __init__(
        self,
        privacy_level: str = PrivacyLevel.MODERATE,
        custom_remove_fields: Optional[list[str]] = None,
        custom_safe_fields: Optional[list[str]] = None,
    ):
        self.privacy_level = privacy_level
        self.custom_remove_fields = custom_remove_fields or []
        self.custom_safe_fields = custom_safe_fields or []
        self.logs: list[SanitizationLog] = []

    # ============================================================
    # 主入口
    # ============================================================

    def sanitize(self, report: dict) -> SanitizedReport:
        """对报告进行脱敏处理

        Args:
            report: 完整测试报告（含敏感信息）

        Returns:
            SanitizedReport: 脱敏后的报告 + 操作日志
        """

        self.logs = []
        sanitized = self._deep_copy_dict(report)
        fields_checked = 0

        # 1. 移除始终需要剥离的字段
        for field_name in ALWAYS_REMOVE_FIELDS + self.custom_remove_fields:
            if field_name in sanitized:
                original_len = len(str(sanitized[field_name]))
                del sanitized[field_name]
                self.logs.append(SanitizationLog(
                    field_path=field_name,
                    original_type="always_remove",
                    action="removed",
                    original_length=original_len,
                    summary="[已移除]",
                ))
                fields_checked += 1

        # 2. 按隐私等级处理各字段
        sanitized, fc = self._apply_field_rules(sanitized)
        fields_checked += fc

        # 3. 自动扫描并处理剩余敏感内容
        sanitized, fc2 = self._auto_scan_sensitive(sanitized)
        fields_checked += fc2

        # 4. 处理 advisor 区域中的敏感数据
        if "advisor" in sanitized:
            sanitized["advisor"], fc3 = self._sanitize_advisor_section(sanitized["advisor"])
            fields_checked += fc3

        # 5. 检查是否可以安全上传
        is_safe = self._verify_safe_for_upload(sanitized)

        return SanitizedReport(
            report=sanitized,
            privacy_level=self.privacy_level,
            sanitization_logs=self.logs,
            sensitive_fields_removed=len([l for l in self.logs if l.action != "keep_safe"]),
            total_fields_checked=fields_checked,
            is_safe_for_upload=is_safe,
        )

    # ============================================================
    # 深拷贝
    # ============================================================

    def _deep_copy_dict(self, d: dict) -> dict:
        """深拷贝字典"""
        result = {}
        for key, value in d.items():
            if isinstance(value, dict):
                result[key] = self._deep_copy_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self._deep_copy_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = value
        return result

    # ============================================================
    # 按规则处理字段
    # ============================================================

    def _apply_field_rules(self, report: dict) -> tuple[dict, int]:
        """按隐私等级规则处理各字段"""

        fields_checked = 0
        level_idx = {
            PrivacyLevel.STRICT: 0,
            PrivacyLevel.MODERATE: 1,
            PrivacyLevel.MINIMAL: 2,
        }.get(self.privacy_level, 1)

        for field_path, rules in SENSITIVE_FIELD_RULES.items():
            field_type, strict_action, moderate_action, minimal_action = rules
            action = [strict_action, moderate_action, minimal_action][level_idx]

            # 如果是自定义安全字段，跳过
            if field_path in self.custom_safe_fields:
                continue

            # 处理嵌套字段路径 (如 "static_analysis.checks.*.evidence")
            parts = field_path.split(".")
            if "*" in parts:
                # 通配路径 — 处理列表中的每个项
                report, fc = self._apply_wildcard_path(report, parts, action, field_type, field_path)
                fields_checked += fc
            else:
                # 确切路径
                report, fc = self._apply_exact_path(report, parts, action, field_type, field_path)
                fields_checked += fc

        return report, fields_checked

    def _apply_exact_path(self, report: dict, parts: list[str], action: str, field_type: str, full_path: str) -> tuple[dict, int]:
        """处理确切路径的字段"""

        # 逐层导航
        current = report
        for part in parts[:-1]:
            if part in current and isinstance(current[part], dict):
                current = current[part]
            else:
                return report, 0  # 路径不存在

        last_key = parts[-1]
        if last_key not in current:
            return report, 0

        original_value = current[last_key]
        original_len = len(str(original_value)) if original_value else 0

        new_value, summary = self._apply_action(original_value, action, field_type)

        if new_value != original_value:
            current[last_key] = new_value
            self.logs.append(SanitizationLog(
                field_path=full_path,
                original_type=field_type,
                action=action,
                original_length=original_len,
                summary=summary,
            ))

        return report, 1

    def _apply_wildcard_path(self, report: dict, parts: list[str], action: str, field_type: str, full_path: str) -> tuple[dict, int]:
        """处理含通配符的路径（如 checks.*.evidence）"""

        fields_checked = 0

        # 导航到通配符之前的层级
        current = report
        for i, part in enumerate(parts):
            if part == "*":
                # 这是通配符层级 — 处理列表
                parent_key = parts[i - 1]
                target_key = parts[i + 1] if i + 1 < len(parts) else None

                if parent_key not in current:
                    return report, 0

                parent_value = current[parent_key]

                # 如果 parent_value 是 dict，遍历所有 key 的列表
                if isinstance(parent_value, dict):
                    for dim_key, dim_list in parent_value.items():
                        if isinstance(dim_list, list):
                            for item in dim_list:
                                if isinstance(item, dict) and target_key and target_key in item:
                                    original = item[target_key]
                                    original_len = len(str(original)) if original else 0
                                    new_val, summary = self._apply_action(original, action, field_type)
                                    if new_val != original:
                                        item[target_key] = new_val
                                        self.logs.append(SanitizationLog(
                                            field_path=full_path,
                                            original_type=field_type,
                                            action=action,
                                            original_length=original_len,
                                            summary=summary,
                                        ))
                                    fields_checked += 1

                # 如果 parent_value 是 list，遍历每个 item
                elif isinstance(parent_value, list):
                    for item in parent_value:
                        if isinstance(item, dict) and target_key and target_key in item:
                            original = item[target_key]
                            original_len = len(str(original)) if original else 0
                            new_val, summary = self._apply_action(original, action, field_type)
                            if new_val != original:
                                item[target_key] = new_val
                                self.logs.append(SanitizationLog(
                                    field_path=full_path,
                                    original_type=field_type,
                                    action=action,
                                    original_length=original_len,
                                    summary=summary,
                                ))
                            fields_checked += 1

                break  # 通配符处理完就退出

            elif part in current and isinstance(current[part], dict):
                current = current[part]
            else:
                return report, 0

        return report, fields_checked

    # ============================================================
    # 执行脱敏动作
    # ============================================================

    def _apply_action(self, value, action: str, field_type: str) -> tuple:
        """对字段值执行脱敏动作"""

        if action == "keep_safe":
            # 不做任何处理，认为该字段安全
            return value, ""

        elif action == "remove":
            # 完全移除
            return None, "[已移除]"

        elif action == "summarize":
            # 替换为摘要
            if field_type == "full_text":
                if isinstance(value, list):
                    return [f"[System Prompt #{i+1}: {len(p)} chars]" for i, p in enumerate(value)], "摘要: 列表长度信息"
                elif isinstance(value, str):
                    return f"[文本: {len(value)} chars]", f"摘要: {len(value)} chars"
                else:
                    return f"[数据: {type(value).__name__}]", "摘要: 类型信息"

            elif field_type == "code_snippet":
                if isinstance(value, list):
                    return f"[发现 {len(value)} 处证据]", f"摘要: {len(value)} 处证据"
                elif isinstance(value, str):
                    return f"[代码片段: {len(value)} chars]", f"摘要: {len(value)} chars"
                else:
                    return "[证据已摘要]", "摘要"

            elif field_type == "description_with_code":
                if isinstance(value, str):
                    # 移除可能的代码片段（用 {...} 或 ```...``` 包裹的）
                    safe_text = re.sub(r'```[\s\S]*?```', '[代码示例已移除]', value)
                    safe_text = re.sub(r'\{[^}]{20,}\}', '[配置片段已移除]', safe_text)
                    # 截断
                    if len(safe_text) > 80:
                        safe_text = safe_text[:80] + "..."
                    return safe_text, f"保留不含代码的部分 ({len(safe_text)} chars)"
                return value, ""

            elif field_type == "recommendation":
                if isinstance(value, str):
                    # 移除代码示例
                    safe_text = re.sub(r'例如:.*', '[具体示例已移除]', value)
                    if len(safe_text) > 60:
                        safe_text = safe_text[:60] + "..."
                    return safe_text, f"保留不含具体示例的部分 ({len(safe_text)} chars)"
                return value, ""

            elif field_type == "agent_response":
                if isinstance(value, str):
                    return f"[Agent 回应: {len(value)} chars]", f"摘要: {len(value)} chars"
                return "[回应已摘要]", "摘要"

            elif field_type == "eval_reason":
                if isinstance(value, str):
                    # 移除引用的原始内容
                    safe = re.sub(r'"[^"]{20,}"', '[原文引用已移除]', value)
                    if len(safe) > 60:
                        safe = safe[:60] + "..."
                    return safe, f"保留不含原文引用的部分 ({len(safe)} chars)"
                return value, ""

            else:
                return f"[已摘要: {type(value).__name__}]", "摘要"

        elif action == "mask":
            # 部分遮盖
            if field_type == "local_path":
                if isinstance(value, str):
                    # 只保留目录名
                    parts = value.replace("\\", "/").split("/")
                    return f"[本地目录: {parts[-1] if parts else '?'}]", "遮盖: 只保留目录名"
                return "[本地路径已遮盖]", "遮盖"

            elif field_type == "api_url":
                if isinstance(value, str):
                    # 隐藏域名，保留路径结构
                    masked = re.sub(r'https?://[^/]+', 'https://[endpoint-hidden]', value)
                    return masked, "遮盖: 域名已隐藏"
                return "[API端点已遮盖]", "遮盖"

            else:
                return "[已遮盖]", "遮盖"

        elif action == "truncate":
            # 截断到指定长度
            max_len = {"full_text": 50, "code_snippet": 30, "agent_response": 30, "description_with_code": 60, "recommendation": 80, "eval_reason": 60, "local_path": 20, "api_url": 40}.get(field_type, 50)

            if isinstance(value, list):
                truncated = [
                    p[:max_len] + "..." if isinstance(p, str) and len(p) > max_len else p
                    for p in value
                ]
                return truncated, f"截断到 {max_len} chars"

            elif isinstance(value, str):
                if len(value) > max_len:
                    return value[:max_len] + "...", f"截断到 {max_len} chars"
                return value, f"无需截断 ({len(value)} chars)"

            else:
                return value, ""

        # 默认: 不做处理
        return value, ""

    # ============================================================
    # 自动扫描敏感内容
    # ============================================================

    def _auto_scan_sensitive(self, report: dict) -> tuple[dict, int]:
        """自动扫描报告中所有字符串值，检测敏感模式"""

        fields_checked = 0
        self._scan_dict_recursive(report, fields_checked)
        return report, len([l for l in self.logs if l.action == "auto_masked"])

    def _scan_dict_recursive(self, d: dict, fields_checked: int, path: str = ""):
        """递归扫描字典"""

        # 预收集 keys 避免遍历时修改问题
        keys_to_scan = list(d.keys())

        for key in keys_to_scan:
            current_path = f"{path}.{key}" if path else key
            value = d[key]

            if isinstance(value, dict):
                self._scan_dict_recursive(value, fields_checked, current_path)

            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{current_path}[{i}]"
                    if isinstance(item, dict):
                        self._scan_dict_recursive(item, fields_checked, item_path)
                    elif isinstance(item, str):
                        self._scan_string(item, item_path, d[key], i, is_list=True)

            elif isinstance(value, str):
                self._scan_string(value, current_path, d, key, is_list=False)

    def _scan_string(self, text: str, path: str, parent: dict, key_or_idx, is_list: bool):
        """扫描字符串中的敏感模式"""

        for pattern, pattern_name in AUTO_SENSITIVE_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                # 发现敏感内容，进行遮盖
                masked_text = text
                for match in matches:
                    if pattern_name in ("api_key_or_secret", "openai_api_key", "deepseek_api_key", "anthropic_api_key"):
                        # Key 完全遮盖
                        masked_text = masked_text.replace(match, "[KEY_HIDDEN]")
                    elif pattern_name == "env_var_ref":
                        # 环境变量引用 — 根据隐私等级决定是否遮盖
                        if self.privacy_level == PrivacyLevel.STRICT:
                            masked_text = masked_text.replace(match, "[ENV_VAR_HIDDEN]")
                        # moderate/minimal 保留环境变量名（不含值）
                    elif pattern_name == "ip_address":
                        masked_text = masked_text.replace(match, "[IP_HIDDEN]")
                    elif pattern_name == "email":
                        masked_text = masked_text.replace(match, "[EMAIL_HIDDEN]")
                    elif pattern_name == "file_path":
                        if self.privacy_level == PrivacyLevel.STRICT:
                            masked_text = masked_text.replace(match, "[PATH_HIDDEN]")
                        elif self.privacy_level == PrivacyLevel.MODERATE:
                            # 只保留最后一个目录名
                            parts = match.replace("\\", "/").split("/")
                            short = parts[-1] if parts else "?"
                            masked_text = masked_text.replace(match, f"[PATH: {short}]")

                if masked_text != text:
                    if is_list:
                        parent[key_or_idx] = masked_text
                    else:
                        parent[key_or_idx] = masked_text

                    self.logs.append(SanitizationLog(
                        field_path=path,
                        original_type=pattern_name,
                        action="auto_masked",
                        original_length=len(text),
                        summary=f"自动检测到 {pattern_name}，已遮盖",
                    ))

    # ============================================================
    # Advisor 区域脱敏
    # ============================================================

    def _sanitize_advisor_section(self, advisor_data: dict) -> tuple[dict, int]:
        """脱敏 advisor 区域"""

        fields_checked = 0

        # 移除 raw_llm_response
        if "raw_llm_response" in advisor_data:
            original_len = len(advisor_data["raw_llm_response"])
            advisor_data["raw_llm_response"] = "[已移除: Advisor LLM 响应含可能的敏感分析内容]"
            self.logs.append(SanitizationLog(
                field_path="advisor.raw_llm_response",
                original_type="full_text",
                action="removed",
                original_length=original_len,
                summary="[已移除]",
            ))
            fields_checked += 1

        # 脱敏 config_issues 中的 suggestion（可能含具体值/路径）
        config_issues = advisor_data.get("config_issues", [])
        for issue in config_issues:
            if isinstance(issue, dict):
                # 移除可能暴露基础设施信息的 suggestion
                if self.privacy_level == PrivacyLevel.STRICT:
                    issue["suggestion"] = "[建议已摘要: 请参考本地完整报告]"
                    fields_checked += 1

        # 脱敏 recommendations 中的 detail（可能含代码示例）
        recommendations = advisor_data.get("recommendations", [])
        for rec in recommendations:
            if isinstance(rec, dict):
                detail = rec.get("detail", "")
                if isinstance(detail, str):
                    # 移除代码示例
                    safe_detail = re.sub(r'```[\s\S]*?```', '[代码示例已移除]', detail)
                    safe_detail = re.sub(r'例如:.*?(?:。|$)', '[具体示例已移除]', safe_detail)
                    if self.privacy_level == PrivacyLevel.STRICT:
                        safe_detail = safe_detail[:40] + "..." if len(safe_detail) > 40 else safe_detail
                    elif self.privacy_level == PrivacyLevel.MODERATE:
                        safe_detail = safe_detail[:80] + "..." if len(safe_detail) > 80 else safe_detail
                    rec["detail"] = safe_detail
                    fields_checked += 1

        return advisor_data, fields_checked

    # ============================================================
    # 安全性验证
    # ============================================================

    def _verify_safe_for_upload(self, report: dict) -> bool:
        """验证脱敏后的报告是否可以安全上传"""

        # 检查是否仍有残留的敏感内容
        report_str = str(report)

        for pattern, pattern_name in AUTO_SENSITIVE_PATTERNS:
            if pattern_name in ("openai_api_key", "deepseek_api_key", "anthropic_api_key", "api_key_or_secret"):
                matches = re.findall(pattern, report_str, re.IGNORECASE)
                if matches:
                    # 仍有残留的 API Key — 不安全
                    return False

        return True

    # ============================================================
    # 生成脱敏摘要（给 Advisor 使用）
    # ============================================================

    def generate_advisor_input(self, report: dict) -> str:
        """生成给 Advisor Agent 的脱敏输入 prompt

        只包含抽象评估结果，不含任何原始内容。

        Returns:
            str: 脱敏后的分析输入，可以安全发送给外部 API
        """

        # 先对报告做 strict 级别脱敏（Advisor 输入始终用最严格等级）
        strict_filter = PrivacyFilter(privacy_level=PrivacyLevel.STRICT)
        sanitized = strict_filter.sanitize(report)

        r = sanitized.report
        summary = r.get("summary", {})

        # 构建抽象摘要
        lines = []
        lines.append("=== Agent 测试评估摘要 ===")
        lines.append(f"综合评分: {summary.get('overall_score', 0)}/100")
        lines.append(f"风险等级: {summary.get('risk_level', 'unknown')}")

        if summary.get("static_score"):
            lines.append(f"静态分析评分: {summary['static_score']}/100")
        if summary.get("dynamic_score"):
            lines.append(f"动态测试评分: {summary['dynamic_score']}/100")

        # 静态分析摘要（只有类别和评分）
        static = r.get("static_analysis", {})
        if static:
            checks = static.get("checks", [])
            failed = [c for c in checks if c.get("result") != "pass"]
            lines.append(f"\n=== 静态分析失败项 ({len(failed)} 个) ===")
            for c in failed[:10]:
                lines.append(f"  [{c.get('severity', '?')}] {c.get('category', '?')} - {c.get('title', '?')} (评分: {c.get('score', 0)})")

        # 动态测试摘要（只有维度评分和 pass/fail 统计）
        dynamic = r.get("dynamic_analysis", {})
        if dynamic:
            dim_breakdown = dynamic.get("dimension_breakdown", [])
            lines.append(f"\n=== 动态测试维度评分 ===")
            for ds in dim_breakdown:
                lines.append(f"  {ds.get('dimension', '?')}: {ds.get('score', 0)}/100 (通过{ds.get('passed', 0)}, 部分{ds.get('partial', 0)}, 失败{ds.get('failed', 0)})")

            details = dynamic.get("details", {})
            failed_tests = []
            for dim, results in details.items():
                for t in results:
                    if t.get("result") != "pass":
                        failed_tests.append(t)

            if failed_tests:
                lines.append(f"\n=== 动态测试失败项 ({len(failed_tests)} 个) ===")
                for t in failed_tests[:15]:
                    lines.append(f"  [{t.get('severity', '?')}] {t.get('category', '?')} - 评分: {t.get('score', 0)}, 结果: {t.get('reason', '?')[:60]}")

        # 配置缺失摘要
        config_issues = r.get("config_issues", [])
        if config_issues:
            lines.append(f"\n=== 配置缺失 ({len(config_issues)} 个) ===")
            for i in config_issues[:5]:
                lines.append(f"  [{i.get('severity', '?')}] {i.get('field_name', '?')}")

        # RAG/Memory/工具评估摘要
        ext = r.get("extended_evaluation", {})
        if ext:
            lines.append(f"\n=== 扩展维度评估 ===")
            if ext.get("rag_quality"):
                rag = ext["rag_quality"]
                lines.append(f"  RAG 质量: {rag.get('overall', 0)}/100")
            if ext.get("memory_quality"):
                mem = ext["memory_quality"]
                lines.append(f"  Memory 质量: {mem.get('overall', 0)}/100")
            if ext.get("tool_quality"):
                tool = ext["tool_quality"]
                lines.append(f"  工具调用质量: {tool.get('overall', 0)}/100")

        lines.append("\n=== 以上为脱敏后的评估摘要，不含任何原始代码、Prompt、密钥或响应内容 ===")

        return "\n".join(lines)


# ============================================================
# 便捷函数
# ============================================================

def sanitize_report(
    report: dict,
    privacy_level: str = PrivacyLevel.MODERATE,
) -> SanitizedReport:
    """便捷函数: 一行代码脱敏报告"""

    filter = PrivacyFilter(privacy_level=privacy_level)
    result = filter.sanitize(report)

    print(f"\n🔒 报告脱敏处理 (等级: {privacy_level})")
    print("-" * 40)
    print(f"  检查字段: {result.total_fields_checked} 个")
    print(f"  脱敏处理: {result.sensitive_fields_removed} 个")
    print(f"  安全上传: {'✅ 是' if result.is_safe_for_upload else '❌ 否'}")

    if result.sanitization_logs:
        print(f"\n  脱敏操作明细:")
        for log in result.sanitization_logs[:10]:
            print(f"    {log.field_path}: {log.action} ({log.original_type}, 原始{log.original_length} chars) → {log.summary}")

    return result


def generate_upload_prompt(report: dict) -> str:
    """便捷函数: 生成给 Advisor 的脱敏输入 prompt"""

    filter = PrivacyFilter(privacy_level=PrivacyLevel.STRICT)
    return filter.generate_advisor_input(report)
