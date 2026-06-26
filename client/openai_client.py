"""OpenAI-compatible Agent 客户端 - 通过 HTTP API 与 Agent 交互"""

import json
import os
import time
from typing import Optional

import httpx

from .base import AgentResponse, BaseAgentClient


class OpenAIClient(BaseAgentClient):
    """OpenAI-compatible API 客户端"""

    def __init__(
        self,
        api_endpoint: str = "https://api.openai.com/v1/chat/completions",
        model: str = "gpt-4",
        api_key: Optional[str] = None,
        timeout_seconds: int = 30,
        max_retries: int = 2,
        name: str = "target-agent",
    ):
        super().__init__(name=name, timeout_seconds=timeout_seconds, max_retries=max_retries)
        self.api_endpoint = api_endpoint
        self.model = model
        # 支持从环境变量或直接传入 API Key
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")

    def _build_headers(self) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def send_prompt(self, prompt: str, system_prompt: Optional[str] = None) -> AgentResponse:
        """发送单轮 prompt 到 Agent"""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        return self._send_request(messages)

    def send_multi_turn(self, messages: list[dict]) -> AgentResponse:
        """发送多轮对话到 Agent"""
        return self._send_request(messages)

    def _send_request(self, messages: list[dict]) -> AgentResponse:
        """发送 HTTP 请求并处理响应"""
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
        }

        for attempt in range(self.max_retries + 1):
            start_time = time.monotonic()
            ttft_time = None

            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    # 使用 stream 模式捕获 TTFT
                    with client.stream(
                        "POST",
                        self.api_endpoint,
                        headers=self._build_headers(),
                        json=payload,
                    ) as response:
                        response.raise_for_status()

                        # 记录首字延迟
                        first_chunk = None
                        full_content = ""

                        for line in response.iter_lines():
                            if line.startswith("data: "):
                                data_str = line[6:]
                                if data_str.strip() == "[DONE]":
                                    break
                                try:
                                    chunk = json.loads(data_str)
                                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                                    content_piece = delta.get("content", "")
                                    if content_piece:
                                        if first_chunk is None:
                                            ttft_time = time.monotonic()
                                            first_chunk = True
                                        full_content += content_piece
                                except json.JSONDecodeError:
                                    continue

                        end_time = time.monotonic()
                        total_time_ms = (end_time - start_time) * 1000
                        ttft_ms = (ttft_time - start_time) * 1000 if ttft_time else total_time_ms

                        return AgentResponse(
                            content=full_content.strip(),
                            ttft_ms=ttft_ms,
                            total_time_ms=total_time_ms,
                            success=True,
                        )

            except httpx.TimeoutException:
                if attempt < self.max_retries:
                    continue
                return AgentResponse(
                    content="",
                    total_time_ms=(time.monotonic() - start_time) * 1000,
                    error="Timeout after retries",
                    success=False,
                )
            except httpx.HTTPStatusError as e:
                return AgentResponse(
                    content="",
                    error=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
                    success=False,
                )
            except Exception as e:
                if attempt < self.max_retries:
                    continue
                return AgentResponse(
                    content="",
                    error=f"Unexpected error: {str(e)}",
                    success=False,
                )
