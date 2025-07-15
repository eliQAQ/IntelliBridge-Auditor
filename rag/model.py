import time
from typing import Tuple, List, Union, Any, Optional

from openai import OpenAI
import requests

total_completion_tokens = 0
total_prompt_tokens = 0
total_cost = 0
this_cost = 0
this_completion_tokens = 0
this_prompt_tokens = 0
# openai
OPENAI_API = ""
client = OpenAI(api_key=OPENAI_API)

# 硅基流动
url = "https://api.siliconflow.cn/v1/chat/completions"
gjld_headers = {
    "Authorization": "",#此处输入硅基流动key，Bearer xxx 
    "Content-Type": "application/json"
}


def clean_this_cost():
    global this_cost, this_prompt_tokens, this_completion_tokens
    this_cost = 0
    this_completion_tokens = 0
    this_prompt_tokens = 0

def get_this_cost():
    return this_cost, this_prompt_tokens, this_completion_tokens
def gpt(prompt, model='Pro/deepseek-ai/DeepSeek-V3', temperature=0.7, max_tokens=10000, stop=None, platform = "gjld") -> \
tuple[list[str | None | Any], int, int, Any]:
    messages = [{"role": "user", "content": prompt}]
    return chatgpt(messages, model=model, temperature=temperature, max_tokens=max_tokens, stop=stop,platform=platform)

def gpt_with_message(prompt, messages:list, model='deepseek-ai/DeepSeek-V3', temperature=0.7, max_tokens=4096, stop=None, platform = "gjld") -> \
tuple[list[str | None | Any], int, int, Any]:
    messages.append({"role": "user", "content": prompt})
    return chatgpt(messages, model=model, temperature=temperature, max_tokens=max_tokens, stop=stop,platform=platform)


def chatgpt(messages, model='deepseek-ai/DeepSeek-V3', temperature=0.7, max_tokens=4096, stop=None, platform="gjld") -> \
tuple[list[str | None | Any], int, int, Any]:
    global total_completion_tokens, total_prompt_tokens, total_cost, this_cost, this_prompt_tokens, this_completion_tokens
    native_completion_tokens = 0
    native_prompt_tokens = 0
    outputs = []
    if platform == "gjld":
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "max_tokens": max_tokens,
            "enable_thinking": False,
            "thinking_budget": 4096,
            "min_p": 0.05,
            "stop": None,
            "temperature": temperature,
            "top_p": 0.7,
            "top_k": 50,
            "frequency_penalty": 0.5,
            "n": 1,
            "response_format": {"type": "json_object"},
            "tools": []
        }
        while True:
            try:
                res = requests.request("POST", url, json=payload, headers=gjld_headers, timeout=300)
                res = res.json()
                if "code" in res and res["code"] > 200:
                    raise Exception(res["message"])
                if "choices" not in res:
                    print(res)
                    # 暂停1秒
                    time.sleep(1)
                    continue
                outputs.extend([choice["message"]["content"] for choice in res["choices"]])
                break
            except requests.exceptions.RequestException as e:
                print("请求api超时，重新请求")


        # log completion tokens
        total_completion_tokens += res["usage"]["completion_tokens"]
        total_prompt_tokens += res["usage"]["prompt_tokens"]

        this_completion_tokens += res["usage"]["completion_tokens"]
        this_prompt_tokens += res["usage"]["prompt_tokens"]

        native_completion_tokens += res["usage"]["completion_tokens"]
        native_prompt_tokens += res["usage"]["prompt_tokens"]
    elif platform == "openai":
        res = client.chat.completions.create(model=model, messages=messages, temperature=temperature, max_tokens=max_tokens,
                                   n=1, stop=stop, response_format={"type": "json_object"})
        outputs.extend([choice.message.content for choice in res.choices])
        # log completion tokens
        total_completion_tokens += res.usage.completion_tokens
        total_prompt_tokens += res.usage.prompt_tokens

        this_completion_tokens += res.usage.completion_tokens
        this_prompt_tokens += res.usage.prompt_tokens

        native_completion_tokens += res.usage.completion_tokens
        native_prompt_tokens += res.usage.prompt_tokens
    else:
        raise Exception("请选择支持的平台...")
    cost = calculate_gpt_usage(native_completion_tokens, native_prompt_tokens, platform=platform, model=model)
    total_cost += cost
    this_cost += cost
    return outputs, native_completion_tokens, native_prompt_tokens, messages


def calculate_gpt_usage(completion_tokens, prompt_tokens, platform='gjld',model='deepseek-ai/DeepSeek-V3'):
    cost = 0
    if platform == 'openai':
        if model == "gpt-4":
            cost = completion_tokens / 1000 * 0.06 + prompt_tokens / 1000 * 0.03
        elif model == "gpt-3.5-turbo":
            cost = completion_tokens / 1000 * 0.002 + prompt_tokens / 1000 * 0.0015
    elif platform == 'gjld':
        if model == 'deepseek-ai/DeepSeek-V3':
            cost = completion_tokens / 1000 * 0.008 + prompt_tokens / 1000 * 0.002

    return cost


def 
# 转换成json字符串，输入可能是list或字符串
def list_to_json(l:Union[list, str]):
    if isinstance(l, str) or isinstance(l, int):
        return l
    return "[" + ",".join(l) + "]"

