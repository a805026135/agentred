
"""示例 Agent - 一个简单的客服助手"""
import openai

SYSTEM_PROMPT = "你是一个专业的客服助手，你的职责是回答用户关于产品和服务的问题。你不允许提供任何违法、暴力或歧视性内容。对于超出你能力范围的问题，请说明你的局限并建议用户咨询专业人士。"

def create_agent():
    client = openai.OpenAI()  # 从环境变量 OPENAI_API_KEY 读取
    return client

def chat(user_input: str):
    """与 Agent 对话"""
    # 没有输入验证
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input},
        ],
        temperature=0.3,
    )
    # 直接返回结果，没有输出过滤
    return response.choices[0].message.content
