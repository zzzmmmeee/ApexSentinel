# coding=utf-8
import os
from openai import OpenAI


class DashScopeLLMClient:
    def __init__(self, model_name="qwen2.5-14b-instruct", api_key=None):
        self.api_key = api_key or os.getenv("DASHSCOPE_API_KEY")
        self.model_name = model_name

        self.client = OpenAI(
            api_key=self.api_key,
            base_url="https://dashscope.aliyuncs.com/compatible-mode/v1"
        )

    def query(self, prompt):
        # 构造完整消息，包括 system + 历史 + 当前 prompt
        messages = [{"role": "system", "content": "你是一位安全分析师。"}]
        # messages.extend(self.history)
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=messages,
            # 如使用 Qwen3 开源版，可启用以下行
            # extra_body={"enable_thinking": False}
        )

        reply = response.choices[0].message.content
        # 记录历史对话
        # self.history.append({"role": "user", "content": prompt})
        # self.history.append({"role": "assistant", "content": reply})

        return reply

