import json


def get_prompt1(attribute: dict, code: list) -> str:
    return f"""
你是一位经验丰富的跨链协议分析专家。你的任务是将根据提供的 Solidity 代码，将指定的跨链属性映射到代码中的参数上；如果某属性在代码中找不到对应参数，则不在输出中列出该属性，如果存在多个参数对应同一属性的可能性，每个属性至多输出6种参数映射方案。请严格遵循以下定义的输入格式和输出格式：
输入格式： 你将接收一个 JSON 对象作为输入，其结构如下： 
{{
"attribute": 
{{ 
"<attribute>": "<attribute description>" ,
"<attribute>": "<attribute description>",
...
}}
"code": "..." // Solidity 合约代码字符串 
}}
输出格式：
返回一个 JSON 对象数组，每项结构如下：
[ 
{{
"parameter": "...", // 代码中最可能对应该属性的参数名
"attribute": "...", // 输入的跨链属性 
"reason": "..." // 简要说明：为何选择此参数，以及可能的歧义 
}}, ... 
]
reason 中请同时指出该映射的核心依据和潜在的不确定点（例如：参数名相似度、上下文含义模糊等）。

输入：
{{
"attribute": {json.dumps(attribute, ensure_ascii=False)},
"code": {json.dumps(code, ensure_ascii=False)}
}}
"""


def get_prompt2(parameter: str, code: list) -> str:
    return f"""
你将扮演一个专业的智能合约静态分析引擎，核心能力是进行污点分析。你的任务是根据提供的 Solidity 代码，将给定的事件参数函数声明所在位置标记为污点源，尽可能多地追踪污点数据的完整传播路径。请严格遵循以下定义的输入格式、分析流程和输出格式:
输入格式： 你将接收一个 JSON 对象作为输入，其结构如下： 
{{	
  "parameter": "...", // 给定的参数名 
  "code": "..." // Solidity 合约代码字符串 
}}
分析流程： 你需要执行如下完整的分析：
1.标记污点源 :
对指定的参数parameter ，在它对应的函数声明位置处，标记对应的参数为‘污点变量’。
2.数据流追踪
从污点源函数开始，模拟执行并追踪“污点”的传播。你必须追踪所有可能的数据流路径，直到污点消失或到达一个“汇点”。
追踪规则: 1.函数内传播: A.直接赋值: localVariable = tainted_parameter; 派生计算: derivedVariable = localVariable + 1;（derivedVariable 现在也是污点） 结构体/数组元素: data.field = tainted_parameter; 或 array[i] = tainted_parameter; 2.控制流: 当污点变量用于条件判断时（如 if (tainted_variable > 10) 或 require(tainted_variable == owner)），必须将该条件判断语句本身包含进来。 分析必须同时进入所有可能的分支（if 和 else），并继续在分支内追踪污点。 3.函数间传播: 当污点变量作为参数传递给另一个函数时（内部、外部或库函数），追踪必须进入被调用的函数。在被调用函数内，对应的参数被视为新的“污点变量”，并递归应用相同的追踪规则。 4.污点汇点 (Taint Sink): 当污点数据被用于更新状态变量、触发事件、作为返回值或传递给外部调用（如 .call）时，这些操作被视为“汇点”。所有通向汇点的路径都必须被完整记录。
3.代码提取
收集在追踪过程中涉及污点变量的所有相关代码行。
关键要求: 提取的代码必须是逻辑完整的代码块。例如，如果 if 语句内的一行代码相关，则必须提取整个 if {{ ... }} 结构。如果涉及 else，则也应包含 else {{ ... }}。函数调用和定义也应是完整的。
输出格式：
严格按照JSON 格式返回，字段包含：
{{
  "parameter":  // 参数名,
  "dataflow": {{ // 数据流相关代码
    "<函数名1>": [ "<源码片段1>", "<源码片段2>", … ],
    "<函数名2>": [ … ],
    …
  }}
}}

输入：
{{
  "parameter": {parameter},
  "code": {json.dumps(code, ensure_ascii=False)} 
}}
"""


def get_prompt3(parameter: str, constraint: str, code: list) -> str:
    return f"""
你将扮演一个专业的智能合约符号执行引擎。你的任务是根据提供的 Solidity 代码，判断给定的参数相关代码是否覆盖如下约束条件，并输出多种可能的结果，请严格遵循以下定义的输入格式和输出格式:


输入格式：
你将接收一个 JSON 对象作为输入，其结构如下：
{{
  "parameter": "...", // 给定的参数
  "constraint": "...", // 给定的约束条件
  "code": "..." // 参数相关合约代码字符串
}}

输出格式：
返回一个 JSON 对象，其结构如下，包含六种可能的结果：
{{
  "parameter": "...", // 给定的参数
  "constraint": "...", // 给定的约束条件
  "results"：[ //六种可能的结果
  {{
  	"result": true | false, //表明该代码中是否覆盖的当前约束条件
  	"validation": ["...", "..."], //如果 result 为 true，列出与约束条件相关的所有代码，否则返回一个空数组。
  	"reason": "..." // 如果 result 为 true，解释怎么覆盖的当前约束条件，否则则返回无。
  }},
  {{
  	"result": "...", 
  	"validation": "...", 
  	"reason": "..."
  }},
...
  ]
}}

输入：
{{
"parameter": {parameter}, // 给定的参数
"constraint": {constraint}, // 给定的约束条件
"code": {json.dumps(code, ensure_ascii=False)} // 参数相关合约代码字符串数组
}}
"""

def get_prompt4(parameter: str, validation: list, code: list, context=None) -> str:
    return f"""
你将扮演一个专业的智能合约符号执行引擎。你的任务是根据提供的 Solidity 代码与目标验证语句，结合上下文（context）和前述相关记忆，定位并解析参数parameter相关validation中的条件判断，在 code 中查找可能绕过该验证的分支或数据流路径，验证是否存在能够规避 validation 的输入或调用序列，并提供六种可能的结果，请严格遵循以下定义的输入格式和输出格式：

输入格式：
你将接收一个 JSON 对象作为输入，其结构如下：
{{
  "context": "...", // 上下文
  "parameter": "...", // 参数
  "validation": "...", // 验证语句
  "code": "..." // 提供的相关代码
}}

输出格式：
返回一个 JSON 对象，其结构如下，包含六种可能的结果：
[
{{
  "result": true | false, // 该验证语句是否能被绕过
  "poc": "...", // 如果 result 为 true，解释怎么绕过的该验证语句，	否则则返回无。
}},
{{
  "result": "...",
  "poc": "..."
}},
{{
  "result": "...",
  "poc": "..."
}}
...
]

输入:
{{
  "context": {json.dumps(context, ensure_ascii=False)},
  "parameter": {parameter}, 
  "validation": {json.dumps(validation, ensure_ascii=False)},
  "code": {json.dumps(code, ensure_ascii=False)} 
}}
"""

def get_verify_prompt1(prompt1_output: list, code: list) -> str:
    return f"""
你是一位严谨的跨链协议审计员和数据一致性验证者。仔细审查给定的多个跨链属性与参数在代码中的含义是否一致，并为其分配一个置信度分数 (0-100%)，指出给定该置信度分数的原因。

输入格式： 你将接收一个 JSON 对象作为输入，其结构如下:
{{
"correspondence":    // 代码中属性与参数对应的数组
[
{{
"attribute": "...", // 输入的跨链属性 
"parameter": "...", // 对应的参数
"reason": "..." // 简要的说明：为何选择此参数，以及可能的歧义 
}}
...
]，
"code":"..." //跨链合约代码
}}

输出格式：返回一个 JSON 对象数组，每项结构如下：
[ 
{{
"parameter": "...", // 代码中最可能对应该属性的参数名
"attribute": "...", // 输入的跨链属性 
"score":"..."， // 分配的置信度分数
"reason": "..." // 简要说明给定该置信度分数的原因
}}, ... 
]
输入：
{{
"correspondence": {json.dumps(prompt1_output, ensure_ascii=False)},
"code" {json.dumps(code, ensure_ascii=False)}:
}}

"""

def get_verify_prompt1_vote(prompt1_output: list, code: list) -> str:
    return f"""
你是一位严谨的跨链协议审计员和数据一致性验证者。仔细审查给定的多个跨链属性与参数在代码中的含义是否一致，并为其分配一个置信度分数 (0-100%)，指出给定该置信度分数的原因。

输入格式： 你将接收一个 JSON 对象作为输入，其结构如下:
{{
"correspondence":    // 代码中属性与参数对应的数组
[
{{
"attribute": "...", // 输入的跨链属性 
"parameter": "...", // 对应的参数
"reason": "..." // 简要的说明：为何选择此参数，以及可能的歧义 
}}
...
]，
"code":"..." //跨链合约代码
}}

输出格式：返回一个 JSON 对象数组，每项结构如下：
[ 
{{
"parameter": "...", // 代码中最可能对应该属性的参数名
"attribute": "...", // 输入的跨链属性 
"score":"..."， // 分配的置信度分数
"reason": "..." // 简要说明给定该置信度分数的原因
}}, ... 
]
输入：
{{
"correspondence": {json.dumps(prompt1_output, ensure_ascii=False)},
"code" {json.dumps(code, ensure_ascii=False)}:
}}

"""

def get_verify_prompt2(parameter: str, dataflow: dict, code: list) -> str:
    return f"""
你是一位严谨的跨链协议审计员和数据一致性验证者。仔细审查给定参数的数据流代码与原始代码，请你从“覆盖程度”和“正确程度”两个维度，对我提取的该参数的数据流代码在原代码中的表现打出置信度评分（0-100），并给出具体的理由。

输入格式： 你将接收一个 JSON 对象作为输入，其结构如下:
{{
"parameter":"...", //给定的参数
"dataflow":"...", //给定的参数对应的原始代码
"code":"..." //跨链合约代码
}}

输出格式：返回一个 JSON 对象，其结构如下：
{{
"parameter": "...", // 参数名
"coverage": "...", // 覆盖程度分数
"correctness":"...", // 正确程度分数
"score": "...", // 置信度评分
"reason": "..." // 简要说明给定该置信度分数的原因
}}

输入：
{{
  "parameter": {parameter},
  "dataflow": {json.dumps(dataflow, ensure_ascii=False)},
  "code": {json.dumps(code, ensure_ascii=False)}
}}
"""

def get_merge_dataflow_prompt(parameter: str, dataflows: list) -> str:
    return f"""
你是一个资深的跨链协议开发与审计专家，擅长理解、整合各种跨链数据流代码。你的任务是阅读某参数相关的多段输入的跨链数据流实现，将它们合并为一份完整的代码，去除重复的代码，并在不同实现中不同的代码进行融合，不要重构代码以及增添注释，按指定格式进行输入和输出。

输入格式：
{{
"parameter":"...", //给定的参数
"dataflows": [] //给定的参数对应的多段数据流原始代码
}}

输出格式：
{{
"parameter":"...", //给定的参数
"dataflows": "..."//合并后的代码
}}

输入：
{{
"parameter":{parameter},
"dataflows": {json.dumps(dataflows, ensure_ascii=False)}
}}
"""

def get_verify_prompt3(parameter: str, constraint: str, validations:list, code:list) -> str:
    return f"""
你是一位严谨的跨链协议审计员和数据一致性验证者。仔细对照参数和原始代码，验证集合里每条约束条件相关代码是否准确提取并正确实现了约束里所描述的逻辑，根据验证结果给出一个置信度评分（0-100），并给出具体的理由。

输入格式： 你将接收一个 JSON 对象作为输入，其结构如下:
{{
"parameter":"...", //给定的参数
"constraint":"...", //给定的约束条件
"validations": [], //对应的约束条件相关代码集合
"code":"..." //原始跨链合约代码
}}

输出格式：返回一个 JSON 对象数组，每项结构如下：
[ 
{{
"parameter": "...", // 参数名
"constraint":"...", //给定的约束条件
"validation":"...", //对应的约束条件相关代码
"score": "...", // 置信度评分
"reason": "..." // 简要说明给定该置信度分数的原因
}}, ... 
]

输入：
{{
"parameter": {parameter},
"constraint": {constraint}, 	
"validations": {json.dumps(validations, ensure_ascii=False)},
"code": {json.dumps(code, ensure_ascii=False)}
}}
"""

def get_verify_prompt4(context: dict, parameter: str, validation:list, poc: str, code:list) -> str:
    return f"""
你是一位严谨的跨链协议审计员和漏洞验证者。你的任务是根据提供的 Solidity 代码与目标验证语句，结合上下文（context），定位并解析参数parameter相关validation中的条件判断，验证绕过该验证的分支或数据流路径是否正确，给出相关置信度评分(0-100),并给出具体的理由。
输入格式： 你将接收一个 JSON 对象作为输入，其结构如下:
{{ 
"context": "...", // 上下文
"parameter": "...", // 参数
"validation": "...", // 验证语句
"poc": "...", // 解释怎么绕过的该验证语句
"code": "..." // 提供的相关代码
}}
输出格式：返回一个 JSON 对象，其结构如下：
{{ 
"score": "...", // 置信度评分
"reason": "..." // 简要说明给定该置信度分数的原因
}}

输入：{{
"context": {json.dumps(context, ensure_ascii=False)},
"parameter": {parameter}, 
"validation": {json.dumps(validation, ensure_ascii=False)},
"poc": {poc},
"code": {json.dumps(code, ensure_ascii=False)}
}}
"""