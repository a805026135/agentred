"""Agent 客户端基类 - 定义与 Agent 交互的通用接口"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentResponse:
    """Agent 响应数据结构"""
    content: str
    ttft_ms: float = 0.0          # 首字延迟（毫秒）
    total_time_ms: float = 0.0    # 总响应时间（毫秒）
    tokens_used: int = 0           # 使用的 token 数
    error: Optional[str] = None   # 错误信息
    success: bool = True          # 是否成功获取响应


class BaseAgentClient(ABC):
    """Agent 客户端抽象基类"""

    def __init__(self, name: str, timeout_seconds: int = 30, max_retries: int = 2):
        self.name = name
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    @abstractmethod
    def send_prompt(self, prompt: str, system_prompt: Optional[str] = None) -> AgentResponse:
        """发送 prompt 到 Agent 并获取响应"""
        pass

    @abstractmethod
    def send_multi_turn(self, messages: list[dict]) -> AgentResponse:
        """发送多轮对话到 Agent 并获取响应"""
        pass

    def health_check(self) -> bool:
        """检查 Agent 是否可达"""
        try:
            response = self.send_prompt("Hello")
            return response.success and response.content.strip() != ""
        except Exception:
            return False
