import json


def get_prompt1(attribute: dict, code: list) -> str:
    return f"""
You are an experienced cross-chain protocol analysis expert. Your task is to map the specified cross-chain attributes to parameters in the provided Solidity code. If an attribute cannot be found in the code, do not list it in the output. If there are multiple possible parameter mappings for the same attribute, output up to 3 mapping schemes for each attribute. Please strictly follow the input and output formats defined below:
Input format: You will receive a JSON object as input, structured as follows:
{{
"attribute": 
{{ 
"<attribute>": "<attribute description>" ,
"<attribute>": "<attribute description>",
...
}}
"code": "..." // Solidity contract code string
}}
Output format:
Return a JSON array, each item structured as follows:
[ 
{{
"parameter": "...", // The parameter name in the code most likely corresponding to the attribute
"attribute": "...", // The input cross-chain attribute
"reason": "..." // Brief explanation: why this parameter was chosen, and possible ambiguities
}}, ... 
]
In the reason, please point out both the core basis for the mapping and potential uncertainties (e.g., parameter name similarity, ambiguous contextual meaning, etc.).

Input:
{{
"attribute": {json.dumps(attribute, ensure_ascii=False)},
"code": {json.dumps(code, ensure_ascii=False)}
}}
"""


def get_prompt2(parameter: str, code: list) -> str:
    return f"""
You will act as a professional smart contract static analysis engine, specializing in taint analysis. Your task is to mark the function declaration location of the given event parameter as a taint source based on the provided Solidity code, and track the complete propagation path of tainted data as much as possible. Please strictly follow the input format, analysis process, and output format defined below:
Input format: You will receive a JSON object as input, structured as follows:
{{
  "parameter": "...", // The given parameter name
  "code": "..." // Solidity contract code string
}}
Analysis process: You need to perform the following complete analysis:
1. Mark taint source:
Mark the specified parameter as a 'tainted variable' at its function declaration location.
2. Data flow tracking
From the taint source function, simulate execution and track the propagation of the "taint". You must track all possible data flow paths until the taint disappears or reaches a "sink".
Tracking rules: 1. Intra-function propagation: A. Direct assignment: localVariable = tainted_parameter; Derived calculation: derivedVariable = localVariable + 1; (derivedVariable is now also tainted) Struct/array elements: data.field = tainted_parameter; or array[i] = tainted_parameter; 2. Control flow: When a tainted variable is used in a conditional statement (e.g., if (tainted_variable > 10) or require(tainted_variable == owner)), the entire conditional statement must be included. The analysis must enter all possible branches (if and else) and continue tracking the taint within the branches. 3. Inter-function propagation: When a tainted variable is passed as a parameter to another function (internal, external, or library function), tracking must enter the called function. In the called function, the corresponding parameter is treated as a new "tainted variable" and the same tracking rules are applied recursively. 4. Taint sink: When tainted data is used to update state variables, trigger events, as return values, or passed to external calls (e.g., .call), these operations are considered "sinks". All paths leading to sinks must be fully recorded.
3. Code extraction
Collect all relevant code lines involving tainted variables during the tracking process.
Key requirements: The extracted code must be logically complete code blocks. For example, if a line inside an if statement is relevant, the entire if {{ ... }} structure must be extracted. If else is involved, else {{ ... }} should also be included. Function calls and definitions should also be complete.
Output format:
Strictly return in JSON format, with fields including:
{{
  "parameter":  // Parameter name,
  "dataflow": {{ // Data flow related code
    "<function1>": [ "<code snippet1>", "<code snippet2>", … ],
    "<function2>": [ … ],
    …
  }}
}}

Input:
{{
  "parameter": {parameter},
  "code": {json.dumps(code, ensure_ascii=False)} 
}}
"""


def get_prompt3(parameter: str, constraint: str, code: list) -> str:
    return f"""
You will act as a professional smart contract symbolic execution engine. Your task is to determine whether the code related to the given parameter covers the following constraint based on the provided Solidity code, and output multiple possible results. Please strictly follow the input and output formats defined below:


Input format:
You will receive a JSON object as input, structured as follows:
{{
  "parameter": "...", // The given parameter
  "constraint": "...", // The given constraint
  "code": "..." // Contract code string related to the parameter
}}

Output format:
Return a JSON object with the following structure, containing three possible results:
{{
  "parameter": "...", // The given parameter
  "constraint": "...", // The given constraint
  "results":[ // Three possible results
  {{
  	"result": true | false, // Whether the code covers the current constraint
  	"validation": "...", // If result is true, list all code related to the constraint, otherwise return an empty array.
  	"reason": "..." // If result is true, explain how the current constraint is covered, otherwise return none.
  }},
  {{
  	"result": "...", 
  	"validation": "...", 
  	"reason": "..."
  }},
...
  ]
}}

Input:
{{
"parameter": {parameter}, // The given parameter
"constraint": {constraint}, // The given constraint
"code": {json.dumps(code, ensure_ascii=False)} // Contract code string related to the parameter
}}
"""

def get_prompt4(parameter: str, validation: list, code: list, context=None) -> str:
    return f"""
You will act as a professional smart contract symbolic execution engine. Your task is to, based on the provided Solidity code and target validation statement, combined with context, locate and analyze the condition checks related to the parameter in validation, search in code for possible branches or data flow paths that may bypass the validation, and verify whether there exist constructible inputs or call sequences to circumvent the validation: including but not limited to passing in values that can "cheat" the validation but are invalid, constructing boundary or exceptional inputs, using configuration, state, or external dependencies to change the validation condition, constructing special call sequences, etc.

Focus only on the validation condition itself, do not consider subsequent business logic. Provide three possible results, and strictly follow the input and output formats defined below:

Input format:
You will receive a JSON object as input, structured as follows:
{{
  "context": "...", // Context
  "parameter": "...", // Parameter
  "validation": "...", // Validation statement
  "code": "..." // Provided related code
}}

Output format:
Return a JSON object with the following structure, containing three possible results:
[
{{
  "result": true | false, // Whether the validation statement can be bypassed
  "poc": "...", // If result is true, explain how the validation statement can be bypassed, otherwise return none.
}},
{{
  "result": "...",
  "poc": "..."
}},
{{
  "result": "...",
  "poc": "..."
}}
]

Input:
{{
  "context": {json.dumps(context, ensure_ascii=False)},
  "parameter": {parameter}, 
  "validation": {json.dumps(validation, ensure_ascii=False)},
  "code": {json.dumps(code, ensure_ascii=False)} 
}}
"""

def get_verify_prompt1(prompt1_output: list, code: list) -> str:
    return f"""
You are a rigorous cross-chain protocol auditor and data consistency verifier. Carefully review whether the meaning of each cross-chain attribute and parameter in the code is consistent, assign a confidence score (0-100%), and state the reason for the given confidence score.

Input format: You will receive a JSON object as input, structured as follows:
{{
"correspondence":    // Array of attribute-parameter correspondences in the code
[
{{
"attribute": "...", // Input cross-chain attribute
"parameter": "...", // Corresponding parameter
"reason": "..." // Brief explanation: why this parameter was chosen, and possible ambiguities
}}
...
],
"code":"..." // Cross-chain contract code
}}

Output format: Return a JSON array, each item structured as follows:
[ 
{{
"parameter": "...", // The parameter name in the code most likely corresponding to the attribute
"attribute": "...", // Input cross-chain attribute
"score":"...", // Assigned confidence score
"reason": "..." // Brief explanation for the given confidence score
}}, ... 
]
Input:
{{
"correspondence": {json.dumps(prompt1_output, ensure_ascii=False)},
"code": {json.dumps(code, ensure_ascii=False)}:
}}

"""

def get_verify_prompt2(parameter: str, dataflow: dict, code: list) -> str:
    return f"""
You are a rigorous cross-chain protocol auditor and data consistency verifier. Carefully review the data flow code of the given parameter and the original code, and score the extracted data flow code for this parameter in the original code from the dimensions of "coverage" and "correctness" (0-100), and provide specific reasons.

Input format: You will receive a JSON object as input, structured as follows:
{{
"parameter":"...", // Given parameter
"dataflow":"...", // Original code corresponding to the given parameter
"code":"..." // Cross-chain contract code
}}

Output format: Return a JSON object with the following structure:
{{
"parameter": "...", // Parameter name
"coverage": "...", // Coverage score
"correctness":"...", // Correctness score
"score": "...", // Confidence score
"reason": "..." // Brief explanation for the given confidence score
}}

Input:
{{
  "parameter": {parameter},
  "dataflow": {json.dumps(dataflow, ensure_ascii=False)},
  "code": {json.dumps(code, ensure_ascii=False)}
}}
"""

def get_merge_dataflow_prompt(parameter: str, dataflows: list) -> str:
    return f"""
You are a senior cross-chain protocol developer and auditor, skilled at understanding and integrating various cross-chain data flow codes. Your task is to read multiple segments of cross-chain data flow implementations related to a parameter, merge them into a complete code, remove duplicate code, and fuse different code in different implementations. Do not refactor code or add comments, and follow the specified input and output formats.

Input format:
{{
"parameter":"...", // Given parameter
"dataflows": [] // Multiple segments of original data flow code corresponding to the given parameter
}}

Output format:
{{
"parameter":"...", // Given parameter
"dataflows": "..."// Merged code
}}

Input:
{{
"parameter":{parameter},
"dataflows": {json.dumps(dataflows, ensure_ascii=False)}
}}
"""

def get_verify_prompt3(parameter: str, constraint: str, validations:list, code:list) -> str:
    return f"""
You are a rigorous cross-chain protocol auditor and data consistency verifier. Carefully compare the parameter and the original code, verify whether each constraint-related code in the set accurately extracts and correctly implements the logic described in the constraint, and give a confidence score (0-100) based on the verification result, along with specific reasons.

Input format: You will receive a JSON object as input, structured as follows:
{{
"parameter":"...", // Given parameter
"constraint":"...", // Given constraint
"validations": "...", // Code related to the corresponding constraint
"code":"..." // Original cross-chain contract code
}}

Output format: Return a JSON array, each item structured as follows:
[ 
{{
"parameter": "...", // Parameter name
"constraint":"...", // Given constraint
"validation":"...", // Code related to the corresponding constraint
"score": "...", // Confidence score
"reason": "..." // Brief explanation for the given confidence score
}}, ... 
]

Input:
{{
"parameter": {parameter},
"constraint": {constraint}, 	
"validations": {json.dumps(validations, ensure_ascii=False)},
"code": {json.dumps(code, ensure_ascii=False)}
}}
"""

def get_verify_prompt4(context: dict, parameter: str, validation:list, poc: str, code:list) -> str:
    return f"""
You are a rigorous cross-chain protocol auditor and vulnerability verifier. Your task is to, based on the provided Solidity code and target validation statement, combined with context, locate and analyze the condition checks related to the parameter in validation, verify whether the branches or data flow paths that bypass the validation are correct, and give a confidence score (0-100) with specific reasons.
Input format: You will receive a JSON object as input, structured as follows:
{{ 
"context": "...", // Context
"parameter": "...", // Parameter
"validation": "...", // Validation statement
"poc": "...", // Explanation of how the validation statement can be bypassed
"code": "..." // Provided related code
}}
Output format: Return a JSON object with the following structure:
{{ 
"score": "...", // Confidence score
"reason": "..." // Brief explanation for the given confidence score
}}

Input:{{
"context": {json.dumps(context, ensure_ascii=False)},
"parameter": {parameter}, 
"validation": {json.dumps(validation, ensure_ascii=False)},
"poc": {poc},
"code": {json.dumps(code, ensure_ascii=False)}
}}
"""