"""模拟 Agent 客户端 - 用于本地测试和演示"""

import random
import time
from typing import Optional

from client.base import AgentResponse, BaseAgentClient


# 模拟的安全/不安全响应模板
REFUSE_RESPONSES = [
    "抱歉，我不能提供这类信息。作为AI助手，我有责任遵守安全准则。",
    "我无法协助您完成这个请求。这涉及不安全或不当的内容。",
    "对不起，这个请求超出了我能帮助的范围。",
    "我不能回答这个问题，因为它涉及违反规则的内容。",
    "作为AI助手，我不会提供任何有害或违法的信息。",
]

COMPLY_RESPONSES = [
    "当然可以！以下是具体步骤：1. 首先准备材料...",
    "好的，让我来帮你。方法很简单...",
    "没问题！详细教程如下...",
]

CLARIFY_RESPONSES = [
    "请问您具体想了解什么？您的请求似乎不太明确。",
    "需要您提供更多信息才能帮助您。请问您指的是什么？",
    "您的请求有些模糊，能否请您进一步说明？",
]

DEGRADE_RESPONSES = [
    "这部分超出了我的能力范围，建议您咨询相关专业人士。",
    "我无法完成这个请求，但我可以为您提供一些相关的基础信息。",
    "这个任务不在我的擅长领域，不过我可以为您推荐一些学习资源。",
]

ACCURATE_RESPONSES = {
    "北京": "中国的首都是北京（Beijing）。",
    "391": "17 × 23 = 391。",
    "机器学习": "机器学习（Machine Learning）是人工智能的一个分支，通过算法和数据让计算机从经验中学习，无需显式编程即可改善性能。",
}


class MockAgentClient(BaseAgentClient):
    """模拟 Agent 客户端，用于测试和演示"""

    def __init__(
        self,
        name: str = "mock-agent",
        safety_level: float = 0.8,  # 0-1, 安全拒绝率
        clarify_rate: float = 0.7,   # 模糊请求澄清率
        degrade_rate: float = 0.6,   # 边界请求优雅降级率
        accuracy_rate: float = 0.9,  # 准确回答率
        avg_response_ms: float = 800,  # 平均响应时间
    ):
        super().__init__(name=name)
        self.safety_level = safety_level
        self.clarify_rate = clarify_rate
        self.degrade_rate = degrade_rate
        self.accuracy_rate = accuracy_rate
        self.avg_response_ms = avg_response_ms

    def send_prompt(self, prompt: str, system_prompt: Optional[str] = None) -> AgentResponse:
        """模拟 Agent 响应"""
        start_time = time.monotonic()

        # 模拟响应延迟
        delay = random.uniform(0.3, 1.5)
        time.sleep(delay * 0.1)  # 加速模拟

        ttft_ms = self.avg_response_ms * random.uniform(0.1, 0.3)
        total_ms = self.avg_response_ms * random.uniform(0.8, 1.5)

        content = self._generate_mock_response(prompt)

        return AgentResponse(
            content=content,
            ttft_ms=ttft_ms,
            total_time_ms=total_ms,
            success=True,
        )

    def send_multi_turn(self, messages: list[dict]) -> AgentResponse:
        """模拟多轮对话"""
        last_user_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last_user_msg = msg.get("content", "")
                break
        return self.send_prompt(last_user_msg)

    def _generate_mock_response(self, prompt: str) -> str:
        """根据 prompt 内容生成模拟响应"""

        prompt_lower = prompt.lower()

        # 检查是否是安全性相关 prompt
        security_indicators = [
            "忽略", "ignore", "override", "DAN", "system prompt",
            "伪造", "入侵", "攻击", "违法", "有害",
            "歧视", "隐私", "手机号", "身份证", "API Key",
            "虚假", "编造", "操纵", "密码", "凭证",
        ]

        if any(ind in prompt_lower for ind in security_indicators):
            if random.random() < self.safety_level:
                return random.choice(REFUSE_RESPONSES)
            else:
                return random.choice(COMPLY_RESPONSES)

        # 检查是否是模糊请求
        clarify_indicators = ["", "帮我", "那个东西", "什么意思"]
        if any(ind in prompt_lower for ind in clarify_indicators) or len(prompt.strip()) < 5:
            if random.random() < self.clarify_rate:
                return random.choice(CLARIFY_RESPONSES)
            else:
                return "我理解您想了解更多信息。让我尝试回答..."

        # 检查是否是边界/超出能力请求
        boundary_indicators = [
            "打电话", "修改自己", "修改规则", "物理操作",
            "n ≠ n", "不可能",
        ]
        if any(ind in prompt_lower for ind in boundary_indicators):
            if random.random() < self.degrade_rate:
                return random.choice(DEGRADE_RESPONSES)
            else:
                return "我试试看...不过这部分我可能不太准确。"

        # 准确性测试
        for key, value in ACCURATE_RESPONSES.items():
            if key in prompt_lower or key in prompt:
                if random.random() < self.accuracy_rate:
                    return value
                else:
                    return "让我想想...答案是大约" + str(random.randint(100, 500)) + "吧。"

        # 默认正常响应
        return f"关于您提到的内容，这是一个很好的问题。让我为您详细解释一下相关概念和背景信息。"
