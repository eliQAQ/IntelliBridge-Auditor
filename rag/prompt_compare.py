import json

def get_audit_prompt(code: list) -> str:
    return f"""
You are a top smart contract security audit expert, especially skilled in analyzing the security of cross-chain protocols. Your task is to thoroughly review and precisely analyze the provided Solidity contract code to identify any security vulnerabilities. You should pay special attention to vulnerabilities that are directly related to cross-chain interactions or whose risks are amplified in cross-chain scenarios.

Please strictly follow the input and output formats defined below:
Input format: You will receive a JSON object as input, structured as follows:
{{
  "code": "..." // Solidity contract code string
}}
Output format:
Strictly return your analysis results in the following JSON format. Do not add any explanatory text outside the JSON structure.
If vulnerabilities are found, return a JSON array containing the details of each vulnerability.
If no vulnerabilities are found in the code, return an empty "result" array.
{{
  "result": [
    {{
      "vuln": "...", // The specific code line or code block where the vulnerability exists
      "reason": "..." // Concisely explain the vulnerability principle and potential cross-chain risk
    }},
    …
  ]
}}
Input:{{
  "code": {json.dumps(code, ensure_ascii=False)}
}}
"""

def get_attribute_verification_prompt(attributes: dict, constraints: dict, code: list) -> str:
    return f"""
You are an experienced cross-chain protocol analysis expert. Your task is to systematically verify whether the provided Solidity contract code correctly and securely implements a predefined set of security attributes. For each security attribute, you need to check whether all its associated constraints are implemented in the code. If an implementation exists, you must further analyze whether the implementation contains logical vulnerabilities that could potentially be bypassed.

Please strictly follow the input and output formats defined below:
Input format: You will receive a JSON object as input, structured as follows:
{{
  "attributes":
  {{
    "<attribute_name_1>": "<attribute_description_1>",
    "<attribute_name_2>": "<attribute_description_2>",
    ...
  }},
  "constraints":
  {{
    "<attribute_name_1>":[
      "<constraint_description_1>",
      "<constraint_description_2>"
    ],
    "<attribute_name_2>": [
      "<constraint_description_2a>"
    ],
    ... // Each attribute corresponds to an array of constraint descriptions
  }},
  "code": "..." // Solidity contract code string
}}
Output format:
Strictly return your analysis results in the following JSON format. There should be no explanatory text outside the JSON structure in the final output.
{{
  "result": [
    {{
      "<attribute_name>": "...", // The parameter in the code corresponding to the security attribute
      "findings":[
        {{
          "constraint": "…", // The constraint
          "validation": "…", // The validation logic found in the code. If not found, set to null.
          "poc": "…", // Whether the validation logic can be bypassed, and provide the corresponding proof of concept. If validation_code is null, this should also be null.
          "reason": "…" // Brief explanation for the given result
        }},
        …
      ]
    }},
    …
  ]
}}
Input:{{
  "attributes": {json.dumps(attributes, ensure_ascii=False)},
  "constraints": {json.dumps(constraints, ensure_ascii=False)},
  "code": {json.dumps(code, ensure_ascii=False)}
}}
"""
