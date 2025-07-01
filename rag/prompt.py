import json


def get_prompt1(attribute: list, code: list) -> str:
    return f"""
你是一位经验丰富的跨链协议分析专家。你的任务是将根据提供的 Solidity 代码，将指定的跨链属性映射到代码中的参数上；如果某属性在代码中找不到对应参数，则不在输出中列出该属性。请严格遵循以下定义的输入格式和输出格式：

输入格式：
你将接收一个 JSON 对象作为输入，其结构如下：
{{
"attribute": [], // 给定的跨链属性数组
"code": [] // Solidity 合约代码函数数组
}}

输出格式：

返回一个 JSON 对象数组，每项结构：

- parameter: 参数名
- attribute：对应的跨链属性
- reason：选择的原因，以及潜在的模糊点

[
{{
"parameter": "...",  // 代码中最可能对应该属性的参数名
"attribute": "...",  // 输入的跨链属性
"reason": "..."      // 简要说明：为何选择此参数，以及可能的歧义
}},
...
]

每个属性至多提供 3 种映射方案，按“最可能”排序。

reason 中请同时指出该映射的核心依据和潜在的不确定点（例如：参数名相似度、上下文含义模糊等）。

输入：
{{
"attribute": {json.dumps(attribute, ensure_ascii=False)}, // 给定的跨链属性数组
"code": {json.dumps(code, ensure_ascii=False)} // Solidity 合约代码函数数组
}}
"""

def get_prompt2(parameter: str, code: list) -> str:
    return f"""
你将扮演一个专业的智能合约静态分析引擎，核心能力是进行污点分析。你的任务是根据提供的 Solidity 代码，将给定的事件参数函数声明所在位置标记为污点源，精准地追踪污点数据的完整传播路径，请严格遵循以下定义的输入格式、分析流程和输出格式:

输入格式：
你将接收一个 JSON 对象作为输入，其结构如下：
{{
"parameter": "...", // 给定的参数名
"code": [] // Solidity 合约代码字符串数组
}}

分析流程：
你需要执行如下完整的分析：

1. 标记污点源
    - 对指定的参数`parameter` ，在它对应的函数声明位置处，标记对应的参数为‘污点变量’。

2.数据流追踪

- 从污点源函数开始，模拟执行并追踪“污点”的传播。你必须追踪所有可能的数据流路径，直到污点消失或到达一个“汇点”。
- 追踪规则:
1.函数内传播:
A.直接赋值: localVariable = tainted_parameter;
派生计算: derivedVariable = localVariable + 1;（derivedVariable 现在也是污点）
结构体/数组元素: data.field = tainted_parameter; 或 array[i] = tainted_parameter;
2.控制流:
当污点变量用于条件判断时（如 if (tainted_variable > 10) 或 require(tainted_variable == owner)），必须将该条件判断语句本身包含进来。
分析必须同时进入所有可能的分支（if 和 else），并继续在分支内追踪污点。
3.函数间传播:
当污点变量作为参数传递给另一个函数时（内部、外部或库函数），追踪必须进入被调用的函数。在被调用函数内，对应的参数被视为新的“污点变量”，并递归应用相同的追踪规则。
4.污点汇点 (Taint Sink):
当污点数据被用于更新状态变量、触发事件、作为返回值或传递给外部调用（如 .call）时，这些操作被视为“汇点”。所有通向汇点的路径都必须被完整记录。

3.代码提取

- 收集在追踪过程中涉及污点变量的所有相关代码行。
- 关键要求: 提取的代码必须是逻辑完整的代码块。例如，如果 if 语句内的一行代码相关，则必须提取整个 if {{ ... }} 结构。如果涉及 else，则也应包含 else {{ ... }}。函数调用和定义也应是完整的。

输出格式：

以 JSON 格式返回，字段包含：

- `parameter`: 参数名
- `dataflow`: 所有事件参数为污点的相关代码，注意函数和条件分支均为闭合的。
{{
"<函数名1>": [
    "<相关源码片段 1>",
    "<相关源码片段 2>",
    …
],
"<函数名2>": [
    …
],
…
}}

输入：
{{
"parameter": {parameter}, // 给定的参数名
"code": {json.dumps(code, ensure_ascii=False)} // Solidity 合约代码字符串
}}
"""

def get_prompt3(parameter: str, constraint: str, code: list) -> str:
    return f"""
你将扮演一个专业的智能合约符号执行引擎。你的任务是根据提供的 Solidity 代码，判断给定的参数相关代码是否覆盖如下约束条件，请严格遵循以下定义的输入格式和输出格式:

输入格式：
你将接收一个 JSON 对象作为输入，其结构如下：
{{
"parameter": "...", // 给定的参数
"constraint": "...", // 给定的约束条件
"code": [] // 参数相关合约代码字符串数组
}}

输出格式：
返回一个 JSON 对象，其结构如下：
{{
"parameter": "...", // 给定的参数
"constraint": "...", // 给定的约束条件
"result": true | false, //表明该代码中是否覆盖的当前约束条件
"details": ["...", "..."], //如果 result 为 true，列出与约束条件相关的所有代码，否则返回一个空数组。
"reason": "...", // 如果 result 为 true，解释怎么覆盖的当前约束条件，否则则返回无。
}}

输入：
{{
"parameter": {parameter}, // 给定的参数
"constraint": {constraint}, // 给定的约束条件
"code": {json.dumps(code, ensure_ascii=False)} // 参数相关合约代码字符串数组
}}
"""