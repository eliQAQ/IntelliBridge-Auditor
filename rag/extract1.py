import argparse
import hashlib
import os.path
import re
import json
import subprocess
import sys
import time

from model import gpt, gpt_with_message, clean_this_cost, get_this_cost
from read_function_call import handle
from enum import Enum
from prompt_E import *
from  prompt_compare import *
import chardet

keywords = {
    "pragma", "import", "as", "error"
                              "abstract", "contract", "library", "interface",
    "using", "for",
    "struct", "enum", "function", "modifier", "event",
    "public", "private", "internal", "external",
    "constant", "immutable",
    "memory", "storage", "calldata",
    "payable", "view", "pure",
    "virtual", "override",
    "returns",
    "emit", "require", "assert", "revert",
    "assembly", "unchecked"
                "if", "else", "while", "do",
    "break", "continue", "return", "throw", "try", "catch", "finally",
    "bytes", "string", "address", "bool", "mapping", "fixed", "unfixed"
                                                              "uint", "int",
    "uint8", "uint16", "uint24", "uint32", "uint40", "uint48", "uint56", "uint64", "uint72", "uint80", "uint88",
    "uint96", "uint104", "uint112", "uint120", "uint128", "uint136", "uint144", "uint152", "uint160", "uint168",
    "uint176", "uint184", "uint192", "uint200", "uint208", "uint216", "uint224", "uint232", "uint240", "uint248",
    "uint256",
    "int8", "int16", "int24", "int32", "int40", "int48", "int56", "int64", "int72", "int80", "int88",
    "int96", "int104", "int112", "int120", "int128", "int136", "int144", "int152", "int160", "int168",
    "int176", "int184", "int192", "int200", "int208", "int216", "int224", "int232", "int240", "int248",
    "int256",
    "byte", "bytes1", "bytes2", "bytes3", "bytes4", "bytes5", "bytes6", "bytes7", "bytes8", "bytes9",
    "bytes10", "bytes11", "bytes12", "bytes13", "bytes14", "bytes15", "bytes16", "bytes17", "bytes18", "bytes19",
    "bytes20", "bytes21", "bytes22", "bytes23", "bytes24", "bytes25", "bytes26", "bytes27", "bytes28", "bytes29",
    "bytes30", "bytes31", "bytes32",

    "block", "msg", "tx", "blockhash", "now", "gasleft", "super", "this", "abi"
                                                                          "add", "sub", "mul", "div", "pow", "sqrt",
    "addmod", "mulmod",
    "keccak256", "ecrecover", "ripemd160", "sha256"
}

base_functions = {
    "call", "delegatecall", "staticcall", "send", "transfer", "send", "transferFrom"
}

visibility_set = {'public', 'private', 'internal', 'external'}

define_type_set = {'function', 'modifier', 'event', 'enum', 'error', 'constructor', 'struct', 'type', 'import',
                   'pragma', 'using', 'contract', 'library', 'interface', 'abstract'}


class ContractType(Enum):
    CONTRACT = 1
    LIBRARY = 2
    INTERFACE = 3

    FUNCTION = 10
    MODIFIER = 11
    EVENT = 12
    STRUCT = 13
    ENUM = 14
    ERROR = 15
    CUSTOM_TYPE = 16
    USING_DIRECTIVE = 17
    STATE_VARIABLE = 18

    UNKNOWN = 0


class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            if len(obj) > 0:
                return {"__set__": True, "values": list(obj)}
            else:
                return {"__set__": True}
        elif isinstance(obj, ContractType):
            return {"__CT__": True, "value": obj.value}
        return super().default(obj)


def set_decoder(obj):
    if "__set__" in obj:
        if "values" in obj:
            return set(obj["values"])
        else:
            return set()
    elif "__CT__" in obj:
        return ContractType(obj["value"])
    return obj


def closed_split(s: str, pattern: str = " ") -> list[str]:
    """
    顺序遍历字符串，分割的每一部分需要保证括号完整（闭合）
    如 external payable nonReentrant refundExcessNative(payable(msg.sender)) validateBridgeData(_bridgeData)
    """

    # 先获取一串字符串，必须括号闭合的时候遇到了pattern
    result = []
    stack = []
    start = 0
    for i in range(len(s)):
        if s[i] == pattern:
            if len(stack) == 0:
                if start != i:
                    result.append(s[start:i].strip())
                start = i + 1
        elif s[i] == '(' or s[i] == '[' or s[i] == '{':
            stack.append(s[i])
        elif s[i] == ')':
            if stack[-1] == '(':
                stack.pop()
            else:
                raise Exception(f"{s}中第{i}个字符{s[i]}不是括号闭合")
        elif s[i] == ']':
            if stack[-1] == '[':
                stack.pop()
            else:
                raise Exception(f"{s}中第{i}个字符{s[i]}不是括号闭合")
        elif s[i] == '}':
            if stack[-1] == '{':
                stack.pop()
            else:
                raise Exception(f"{s}中第{i}个字符{s[i]}不是括号闭合")
    if len(stack) != 0:
        raise Exception(f"{s}中存在括号未闭合")

    if start != len(s):
        result.append(s[start:].strip())
    return result


def capture_closed(s: str, pattern: str = ";", start: int = 0) -> str:
    """
    捕获从给定区域开始括号封闭的字符串, 必须匹配到pattern且括号的时候封闭时返回
    """
    stack = []
    for i in range(start, len(s)):
        if len(stack) == 0 and s[i] == pattern:
            return s[start: i].strip()

        if s[i] == '(':
            stack.append(s[i])
        elif s[i] == ')':
            if stack[-1] == '(':
                stack.pop()
                if len(stack) == 0 and pattern == ')':
                    return s[start: i + 1].strip()
            else:
                raise Exception(f"{s}中第{i}个字符{s[i]}不是括号闭合")
        elif s[i] == '[':
            stack.append(s[i])
        elif s[i] == ']':
            if stack[-1] == '[':
                stack.pop()
                if len(stack) == 0 and pattern == ']':
                    return s[start: i + 1].strip()
            else:
                raise Exception(f"{s}中第{i}个字符{s[i]}不是括号闭合")
        elif s[i] == '{':
            stack.append(s[i])
        elif s[i] == '}':
            if stack[-1] == '{':
                stack.pop()
                if len(stack) == 0 and pattern == '}':
                    return s[start: i + 1].strip()
            else:
                raise Exception(f"{s}中第{i}个字符{s[i]}不是括号闭合")
    raise Exception(f"{s}中无法找到{pattern}结尾")


class SolidityContextExtractor:
    # handled_md5来部分地避免重复
    all_data = {
        'solidity_file': {},
        'handled_md5': set()
    } if not os.path.exists("all_data.json") else json.load(open("all_data.json", "r"), object_hook=set_decoder)

    # key为md5，value为[filepath, contract]
    index_data = {

    } if not os.path.exists("index_data.json") else json.load(open("index_data.json", "r"), object_hook=set_decoder)

    def __init__(self):
        self.dataset_path = os.path.join(os.path.dirname(__file__), "dataset")
        self.processing_file_state_stack = []
        self.processing_file_set = set()
        self.contracts = {}
        self.func_to_call = {}
        self.state_variable_to_call = []
        self.current_contract = None
        self.current_function = None
        self.current_modifier = None
        self.current_file = None
        self.brace_level = 0
        self.imported_contracts = {}
        self.custom_types = {}
        self.structs = {}
        self.enums = {}
        self.solidity_file: dict[str, any] = {
            "filepath": None,
            "filename": None,
            "imported_contracts": None,
            "contracts": None,
            'state_variables': {},
            'functions': {},
            'modifiers': {},
            'structs': {},
            'events': {},
            'enums': {},
            'errors': {},
            'custom_types': {},
            'using_directives': {},
            'external_functions': {}
        }

    def reset(self):
        # self.process_file_stack = []
        self.contracts = {}
        self.func_to_call = {}
        self.state_variable_to_call = []
        self.current_contract = None
        self.current_function = None
        self.current_modifier = None
        self.current_file = None
        self.brace_level = 0
        self.imported_contracts = {}
        self.custom_types = {}
        self.structs = {}
        self.enums = {}
        self.solidity_file: dict[str, any] = {
            "filepath": None,
            "filename": None,
            "imported_contracts": None,
            "contracts": None,
            'state_variables': {},
            'functions': {},
            'modifiers': {},
            'structs': {},
            'events': {},
            'enums': {},
            'errors': {},
            'custom_types': {},
            'using_directives': {},
            'external_functions': {}
        }

    def parse_dataset(self, dataset_name:str = ""):
        # 递归遍历所有sol文件

        if not dataset_name:
            for root, dirs, files in os.walk(self.dataset_path):
                for file in files:
                    if file.endswith(".sol"):
                        file_path = os.path.join(root, file)
                        result = self.parse_file(file_path)
                        self.save_result(result, file_path)
        else:
            SolidityContextExtractor.all_data = {
                'solidity_file': {},
                'handled_md5': set()
            } if not os.path.exists(f"dataset_data\\{dataset_name}\\all_data.json") else json.load(open(f"dataset_data\\{dataset_name}\\all_data.json", "r"), object_hook=set_decoder)

            SolidityContextExtractor.index_data = {

            } if not os.path.exists(f"dataset_data\\{dataset_name}\\index_data.json") else json.load(open(f"dataset_data\\{dataset_name}\\index_data.json", "r"),
                                                                      object_hook=set_decoder)

            for root, dirs, files in os.walk(os.path.join(self.dataset_path,dataset_name)):
                for file in files:
                    if file.endswith(".sol"):
                        file_path = os.path.join(root, file)
                        result = self.parse_file(file_path)
                        self.save_result(result, file_path)
        self.save_data_as_file(dataset_name)

    def save_data_as_file(self, dataset_name:str = ""):
        if not dataset_name:
            json.dump(SolidityContextExtractor.all_data, open("all_data.json", "w"), indent=4, ensure_ascii=False,
                      cls=SetEncoder)
            json.dump(SolidityContextExtractor.index_data, open("index_data.json", "w"), indent=4, ensure_ascii=False,
                      cls=SetEncoder)
        else:
            if not os.path.exists(f"dataset_data\\{dataset_name}"):
                os.mkdir(f"dataset_data\\{dataset_name}")
            json.dump(SolidityContextExtractor.all_data, open(f"dataset_data\\{dataset_name}\\all_data.json", "w"), indent=4, ensure_ascii=False,
                      cls=SetEncoder)
            json.dump(SolidityContextExtractor.index_data, open(f"dataset_data\\{dataset_name}\\index_data.json", "w"), indent=4, ensure_ascii=False,
                      cls=SetEncoder)

    def save_result(self, result, file_path):
        if result:
            SolidityContextExtractor.all_data['solidity_file'][file_path] = result
            SolidityContextExtractor.all_data['handled_md5'].add(result['md5'])
            for function_name, function in result['functions'].items():
                if function['md5'] not in SolidityContextExtractor.index_data:
                    SolidityContextExtractor.index_data[function['md5']] = [
                        file_path, '', 0
                    ]
            for modifier_name, modifier in result['modifiers'].items():
                if modifier['md5'] not in SolidityContextExtractor.index_data:
                    SolidityContextExtractor.index_data[modifier['md5']] = [
                        file_path, '', 1
                    ]
            for contract_name, contract in result['contracts'].items():
                for function_name, functions in contract['functions'].items():
                    for function in contract['functions'][function_name]:
                        if function['md5'] not in SolidityContextExtractor.index_data:
                            SolidityContextExtractor.index_data[function['md5']] = [
                                file_path, contract_name, 0
                            ]
                for modifier_name, modifier in contract['modifiers'].items():
                    if modifier['md5'] not in SolidityContextExtractor.index_data:
                        SolidityContextExtractor.index_data[modifier['md5']] = [
                            file_path, contract_name, 1
                        ]

    def parse_file(self, file_path: str):
        self.reset()
        if file_path in SolidityContextExtractor.all_data['solidity_file']:
            return {}

        with open(file_path, 'rb') as file:
            binary_data = file.read()
            # 使用chardet检测编码
        encoding = chardet.detect(binary_data)["encoding"]
        source_code = binary_data.decode(encoding)

        if file_path in self.all_data['solidity_file']:
            return {}

        self.current_file = file_path.split("/")[-1].split("\\")[-1]

        self.solidity_file['filepath'] = file_path
        self.solidity_file['filename'] = self.current_file

        self.func_to_call = SolidityContextExtractor.parse_graph_output(
            SolidityContextExtractor.run_surya_graph(file_path))

        result = self.parse_source(source_code)
        self.current_file = None
        return result

    def find_functions(self, code: str):
        self.reset()
        return self._parse_functions_content(code)

    def parse_source(self, source_code: str):
        """解析Solidity源代码并提取上下文信息"""
        # try:
        # 预处理代码
        source_code = self.preprocess_code(source_code)

        md5 = None
        if self.current_file is not None:
            # 获取处理后的内容的md5
            md5 = hashlib.md5(source_code.encode()).hexdigest()
            if md5 in self.all_data['handled_md5']:
                # 具体输出什么不重要
                return {}

        # 提取导入声明
        self._extract_imports(source_code)

        # 提取合约定义
        # todo 考虑合约的嵌套问题
        contract_matches = re.finditer(
            r'(abstract\s+)?(contract|library|interface)\s+(\w+)(\s+is\s+[\w\s,]+)?\s*\{',
            source_code
        )

        has_contract = False

        # 解析每个合约
        for i, match in enumerate(contract_matches):
            has_contract = True
            # 分割合约内容
            contract_contents = self._split_contract_contents(source_code, match.start())
            is_abstract = bool(match.group(1))
            contract_type = match.group(2)
            contract_name = match.group(3)
            inheritance = match.group(4)

            self.current_contract = contract_name

            if contract_type == "contract":
                contract_type = ContractType.CONTRACT
            elif contract_type == "library":
                contract_type = ContractType.LIBRARY
            elif contract_type == "interface":
                contract_type = ContractType.INTERFACE
            else:
                raise Exception(f"无法识别的合约类型：{contract_type}")

            self.contracts[contract_name] = {
                'type': contract_type,
                'is_abstract': is_abstract,
                'inherits': [],
                'state_variables': {},
                'functions': {},
                'modifiers': {},
                'structs': {},
                'events': {},
                'enums': {},
                'errors': {},
                'custom_types': {},
                # 'potential_vulnerabilities': [],
                'using_directives': {}
            }
            if contract_type == ContractType.INTERFACE:
                self.contracts[contract_name]["implement"] = []

            if self.current_file is not None:
                self.solidity_file['md5'] = md5

            # 处理继承
            # todo 考虑继承来的函数等数据
            if inheritance:
                self.contracts[contract_name]['inherits'] = [
                    base.strip() for base in re.findall(r'\w+', inheritance)
                ]
                for interface in self.contracts[contract_name]['inherits']:
                    if interface in self.contracts and self.contracts[interface]["type"] == ContractType.INTERFACE:
                        self.contracts[interface]['implement'].append([
                            self.solidity_file['filepath'],
                            contract_name
                        ])
                        continue

                    for imported_path in self.imported_contracts:
                        if self.imported_contracts[imported_path]["in_database"]:
                            if self.imported_contracts[imported_path]["import_all"]:
                                if interface in self.all_data["solidity_file"][imported_path]["contracts"] and\
                                    self.all_data["solidity_file"][imported_path]["contracts"][interface]["type"] == ContractType.INTERFACE:
                                    self.all_data["solidity_file"][imported_path]["contracts"][interface]['implement'].append([
                                        self.solidity_file['filepath'],
                                        contract_name
                                    ])
                                    break
                            else:
                                if interface in self.imported_contracts[imported_path]["imported"] and\
                                        self.all_data["solidity_file"][imported_path]["contracts"][interface]["type"] == ContractType.INTERFACE:
                                    self.all_data["solidity_file"][imported_path]["contracts"][interface]['implement'].append([
                                        self.solidity_file['filepath'],
                                        contract_name
                                    ])
                                    break


            # 解析合约内容
            self._parse_contract_content(contract_contents)

            # 重置当前合约上下文
            self.current_contract = None

        self.solidity_file['imported_contracts'] = self.imported_contracts
        self.solidity_file['contracts'] = self.contracts

        # 如果没有找到合约定义，尝试处理为代码片段
        if not has_contract:
            self.current_contract = None
            if self.current_file is not None:
                self.solidity_file['md5'] = md5
            self._parse_contract_content(source_code)
        # 最后处理函数内调用的其他函数
        elif self.current_file:
            if self.func_to_call:
                for key in self.func_to_call:
                    for call in self.func_to_call[key]:
                        contract = call.split(".")[0]
                        function = call.split(".")[1]
                        if contract in self.contracts:
                            if self.contracts[contract]["type"] != ContractType.INTERFACE:
                                if function in self.contracts[contract]['functions']:
                                    self.solidity_file["external_functions"][call] = \
                                    self.contracts[contract]['functions'][function][0]["md5"]
                                    continue
                                elif function in self.contracts[contract]['modifiers']:
                                    self.solidity_file["external_functions"][call] = \
                                    self.contracts[contract]['modifiers'][function]["md5"]
                                    continue
                            else:
                                if function in self.contracts[contract]['functions']:
                                    t_f = None
                                    for implement in self.contracts[contract]["implement"]:
                                        if implement[0] == self.solidity_file['filepath']:
                                            if function in self.contracts[implement[1]]['functions']:
                                                t_f = self.contracts[implement[1]]['functions'][function][0]["md5"]
                                                break
                                        elif not t_f and function in self.all_data["solidity_file"][implement[0]]["contracts"][implement[1]]['functions']:
                                            t_f = self.all_data["solidity_file"][implement[0]]["contracts"][implement[1]]['functions'][function][0]["md5"]
                                    if t_f:
                                        self.solidity_file["external_functions"][call] = t_f
                                        continue
                                    else:
                                        self.solidity_file["external_functions"][call] = \
                                        self.contracts[contract]['functions'][function][0]["md5"]
                                        continue
                                elif function in self.contracts[contract]['modifiers']:
                                    self.solidity_file["external_functions"][call] = \
                                    self.contracts[contract]['modifiers'][function]["md5"]
                                    continue

                        # 遍历import进来的合约进行查找
                        flag = False
                        for imported_path in self.imported_contracts:
                            if self.imported_contracts[imported_path]["in_database"]:
                                if self.imported_contracts[imported_path]["import_all"]:
                                    for cont_name in self.all_data["solidity_file"][imported_path]["contracts"]:
                                        if function in \
                                                self.all_data["solidity_file"][imported_path]["contracts"][cont_name][
                                                    'functions']:
                                            if self.all_data["solidity_file"][imported_path]["contracts"][cont_name]["type"] != ContractType.INTERFACE:
                                                self.solidity_file["external_functions"][call] = \
                                                self.all_data["solidity_file"][imported_path]["contracts"][cont_name][
                                                    'functions'][function][0]["md5"]
                                                flag = True
                                            else:
                                                t_f = None
                                                for implement in self.all_data["solidity_file"][imported_path]["contracts"][cont_name]["implement"]:
                                                    if implement[0] == self.solidity_file['filepath']:
                                                        if function in self.contracts[implement[1]]['functions']:
                                                            t_f = self.contracts[implement[1]]['functions'][function][0]["md5"]
                                                            break
                                                    elif function in \
                                                            self.all_data["solidity_file"][implement[0]]["contracts"][
                                                                implement[1]]['functions']:
                                                        t_f = self.all_data["solidity_file"][implement[0]]["contracts"][
                                                                implement[1]]['functions'][function][0]["md5"]
                                                        break
                                                if t_f:
                                                    self.solidity_file["external_functions"][call] = t_f
                                                else:
                                                    self.solidity_file["external_functions"][call] = \
                                                        self.all_data["solidity_file"][imported_path]["contracts"][
                                                            cont_name][
                                                            'functions'][function][0]["md5"]
                                                flag = True
                                            break

                                        elif function in \
                                                self.all_data["solidity_file"][imported_path]["contracts"][cont_name][
                                                    'modifiers']:
                                            self.solidity_file["external_functions"][call] = \
                                            self.all_data["solidity_file"][imported_path]["contracts"][cont_name][
                                                'modifiers'][function]["md5"]
                                            flag = True
                                            break
                                    if flag:
                                        break

                                else:
                                    flag = False
                                    for name in self.imported_contracts[imported_path]["imported"]:
                                        if self.imported_contracts[imported_path]["imported"][name][
                                            "type"] != ContractType.CONTRACT:
                                            continue
                                        o_name = self.imported_contracts[imported_path]["imported"][name]["original_name"]
                                        if function in \
                                                self.all_data["solidity_file"][imported_path]["contracts"][o_name][
                                                    'functions']:
                                            if self.all_data["solidity_file"][imported_path]["contracts"][o_name][
                                                "type"] != ContractType.INTERFACE:
                                                self.solidity_file["external_functions"][call] = \
                                                    self.all_data["solidity_file"][imported_path]["contracts"][o_name][
                                                        'functions'][function][0]["md5"]
                                                flag = True
                                            else:
                                                t_f = None
                                                for implement in \
                                                self.all_data["solidity_file"][imported_path]["contracts"][o_name][
                                                    "implement"]:
                                                    if implement[0] == self.solidity_file['filepath'] and function in \
                                                            self.contracts[implement[1]]['functions']:
                                                        t_f = self.contracts[implement[1]]['functions'][function][0]["md5"]
                                                        break
                                                    elif function in \
                                                            self.all_data["solidity_file"][
                                                                implement[0]][
                                                                "contracts"][
                                                                implement[1]]['functions']:
                                                        t_f = self.all_data["solidity_file"][
                                                            implement[0]]["contracts"][
                                                            implement[1]]['functions'][function][0]["md5"]
                                                        break
                                                if t_f:
                                                    self.solidity_file["external_functions"][call] = t_f
                                                else:
                                                    self.solidity_file["external_functions"][call] = \
                                                        self.all_data["solidity_file"][imported_path]["contracts"][
                                                            o_name][
                                                            'functions'][function][0]["md5"]
                                                flag = True
                                            break
                                        elif function in \
                                                self.all_data["solidity_file"][imported_path]["contracts"][o_name][
                                                    'modifiers']:
                                            self.solidity_file["external_functions"][call] = \
                                                self.all_data["solidity_file"][imported_path]["contracts"][o_name][
                                                    'modifiers'][function]["md5"]
                                            flag = True
                                            break
                                    if flag:
                                        break

            self._generate_state_variable_to_call()

            for contract in self.contracts:
                self.current_contract = contract
                for mod_name in self.contracts[contract]['modifiers']:
                    self.current_function = mod_name
                    self._process_modifier_body(self.contracts[contract]['modifiers'][mod_name]['content'])
                    self.current_function = None
                for func_name in self.contracts[contract]['functions']:
                    self.current_function = func_name
                    for index in range(len(self.contracts[contract]['functions'][func_name])):
                        self._process_function_body(self.contracts[contract]['functions'][func_name][index]['content'],
                                                    index)
                    self.current_function = None
                self.current_contract = None

        return self.solidity_file

        #
        # except Exception as e:
        #     # 错误处理：返回基本上下文信息
        #     print(e)
        #     return {
        #         "error": str(e),
        #         "contracts": self.contracts
        #     }

    def preprocess_code(self, source_code):
        """预处理代码：移除注释、压缩空白、处理多行定义"""
        # 移除多行注释
        source_code = re.sub(r'/\*.*?\*/', '', source_code, flags=re.DOTALL)
        # 移除单行注释
        source_code = re.sub(r'//.*', '', source_code)
        # 压缩连续空白
        source_code = re.sub(r'\s+', ' ', source_code)
        # 处理多行定义：将换行后的定义合并到前一行
        source_code = re.sub(r'(\w)\s*\n\s*(\w)', r'\1 \2', source_code)
        return source_code.strip()

    def _extract_imports(self, source_code):
        """提取导入声明"""
        # 考虑四种情况：
        # import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
        # import { InvalidContract, NoSwapFromZeroBalance, InsufficientBalance } from "../Errors/GenericErrors.sol";
        # import * as symbolName from "filename";
        # import {symbol1 as alias, symbol2} from "filename";
        import_contract_matches = re.findall(r'import\s+(.+?)\s*;', source_code)
        for imp in import_contract_matches:
            # 简化导入路径为合约名
            contract_path = re.findall(r'"(.*?)"|\'(.*?)\'', imp)
            if len(contract_path) > 0 and len(contract_path[0]) > 0:
                contract_path: str = contract_path[0][0]
            else:
                contract_path: str = ""
            if contract_path and contract_path[0] == "@":
                contract_path: str = contract_path[1:]

            in_database = False

            if 'from' not in imp:
                # contract_name = re.sub(r'.*/', '', imp).replace('.sol', '')
                contract_name = re.sub(r'.*/', '', imp.replace("\"", "")).replace("\"", "").replace("\'", "")
            else:
                imps = imp.split("from")
                contract_name = re.sub(r'.*/', '', imps[1]).replace("\"", "").replace("\'", "")

            # 理论上需要递归执行import的文件，不然外部调用查找的时候可能这些文件的内容还没加载进来，但是如果只标记的话好像不加载也可以
            if self.solidity_file["filepath"] and self.solidity_file["filepath"].startswith(
                    self.dataset_path) and contract_path:
                # 获取dataset_path后面的一个层级
                package_path = os.path.join(self.dataset_path,
                                            self.solidity_file["filepath"][len(self.dataset_path) + 1:].split("\\")[0])
                contract_path: str = os.path.normpath(os.path.join(os.path.dirname(self.solidity_file["filepath"]), contract_path))
                if not os.path.exists(contract_path):
                    if os.path.isdir(package_path):
                        # 只考虑合约名
                        for root, dirs, files in os.walk(package_path):
                            for file in files:
                                if file == contract_name:
                                    contract_path = os.path.join(root, file)
                                    in_database = True
                                    break
                            if in_database:
                                break
                else:
                    in_database = True

            if in_database and contract_path not in SolidityContextExtractor.all_data["solidity_file"] \
                    and contract_path not in self.processing_file_set:
                # 保存当前状态
                self.processing_file_state_stack.append(
                    {
                        "contracts": self.contracts,
                        "func_to_call": self.func_to_call,
                        "state_variable_to_call": self.state_variable_to_call,
                        "current_contract": self.current_contract,
                        "current_function": self.current_function,
                        "current_modifier": self.current_modifier,
                        "current_file": self.current_file,
                        "brace_level": self.brace_level,
                        "imported_contracts": self.imported_contracts,
                        "custom_types": self.custom_types,
                        "structs": self.structs,
                        "enums": self.enums,
                        "solidity_file": self.solidity_file
                    }
                )
                self.processing_file_set.add(contract_path)
                # 递归解析
                result = self.parse_file(contract_path)
                self.save_result(result, contract_path)

                # 恢复状态
                state = self.processing_file_state_stack.pop()
                self.processing_file_set.remove(contract_path)
                self.contracts = state['contracts']
                self.func_to_call = state['func_to_call']
                self.state_variable_to_call = state['state_variable_to_call']
                self.current_contract = state['current_contract']
                self.current_function = state['current_function']
                self.current_modifier = state['current_modifier']
                self.current_file = state['current_file']
                self.brace_level = state['brace_level']
                self.imported_contracts = state['imported_contracts']
                self.custom_types = state['custom_types']
                self.structs = state['structs']
                self.enums = state['enums']
                self.solidity_file = state['solidity_file']

            if 'from' in imp:
                imps = imp.split("from")
                if "*" in imps[0]:
                    new_name = None
                    if "as" in imps[0]:
                        temp = imps[0].split()
                        for i in range(len(temp)):
                            if (temp[i] == "as"):
                                new_name = temp[i + 1]
                                break

                    self.imported_contracts[contract_path] = {
                        "in_database": in_database,
                        "import_all": True,
                        "all_alias": new_name,
                        "imported": {}
                    }
                else:
                    import_things = imps[0].strip().replace("{", "").replace("}", "").split(",")
                    imported = {}
                    for item in import_things:
                        if " as " in item:
                            temp = item.split()
                            original_name = temp[0]
                            new_name = temp[2]
                        else:
                            original_name = item.strip()
                            new_name = original_name
                        imported[new_name] = {
                            'original_name': original_name,
                            'type': ContractType.UNKNOWN
                        }

                    # 获取这些import进来的东西的具体类型
                    if contract_path in SolidityContextExtractor.all_data['solidity_file']:
                        imported_contract = SolidityContextExtractor.all_data['solidity_file'][contract_path]
                        for key in imported:
                            if imported[key]['original_name'] in imported_contract['state_variables']:
                                imported[key]['type'] = ContractType.STATE_VARIABLE
                            elif imported[key]['original_name'] in imported_contract['contracts']:
                                imported[key]['type'] = ContractType.CONTRACT
                            elif imported[key]['original_name'] in imported_contract['functions']:
                                imported[key]['type'] = ContractType.FUNCTION
                            elif imported[key]['original_name'] in imported_contract['modifiers']:
                                imported[key]['type'] = ContractType.MODIFIER
                            elif imported[key]['original_name'] in imported_contract['structs']:
                                imported[key]['type'] = ContractType.STRUCT
                            elif imported[key]['original_name'] in imported_contract['events']:
                                imported[key]['type'] = ContractType.EVENT
                            elif imported[key]['original_name'] in imported_contract['enums']:
                                imported[key]['type'] = ContractType.ENUM
                            elif imported[key]['original_name'] in imported_contract['errors']:
                                imported[key]['type'] = ContractType.ERROR
                            elif imported[key]['original_name'] in imported_contract['custom_types']:
                                imported[key]['type'] = ContractType.CUSTOM_TYPE
                            elif imported[key]['original_name'] in imported_contract['using_directives']:
                                imported[key]['type'] = ContractType.USING_DIRECTIVE

                    self.imported_contracts[contract_path] = {
                        "in_database": in_database,
                        "import_all": False,
                        "all_alias": None,
                        "imported": imported
                    }
            else:
                self.imported_contracts[contract_path] = {
                    "in_database": in_database,
                    "import_all": True,
                    "all_alias": None,
                    "imported": {}
                }

    def _split_contract_contents(self, source_code: str, start: int = 0) -> str:
        """分割合约内容，处理嵌套结构"""
        brace_level = 0

        for i in range(start, len(source_code)):
            char = source_code[i]
            if char == '{':
                if brace_level == 0:
                    start = i + 1
                brace_level += 1
            elif char == '}':
                brace_level -= 1
                if brace_level == 0:
                    return source_code[start:i]

        raise Exception(f"{source_code[start:]}中无法找到合约结束")

    # {
    #   "func_name":{
    #       "state_variables": {
    #
    #       },
    #       "called_functions": [
    #
    #       ]
    # }
    def _parse_functions_content(self, content):
        """解析合约内容（状态变量、函数、修饰符）"""
        content = self.preprocess_code(content)
        # 使用状态机处理内容
        tokens = re.split(r'(\b(?:function|modifier|event|enum|struct|error|constructor|'
                          r'type|import|pragma|using|'
                          r'contract|library|interface|abstract)\b|[{},;])', content)

        current_definition = None
        current_data = ""
        brace_level = 0

        # 收集function，最后处理
        function_list = []

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            # 处理定义开始
            if token in define_type_set and brace_level == 0:
                if token == 'struct':
                    pass
                current_definition = token
                current_data = token
                continue

            # 处理特殊字符
            if token in {'{', '}', ',', ';'}:
                if token == '{':
                    brace_level += 1
                elif token == '}':
                    brace_level -= 1

                current_data += token

                # 处理定义结束
                if token == ';' and brace_level == 0:
                    if current_definition == "function" or current_definition == "constructor":
                        function_list.append(current_data)
                    else:
                        # 可能是状态变量
                        pass
                    current_definition = None
                    current_data = ""
                elif token == '}' and brace_level == 0:
                    # 函数体结束
                    if current_definition == "function" or current_definition == "constructor":
                        function_list.append(current_data)
                    else:
                        pass
                    current_definition = None
                    current_data = ""
                continue

            # 添加token到当前数据
            current_data += " " + token if current_data else token

            # 处理没有特殊字符的定义结束
            if not current_definition and token.endswith(';'):
                current_data = ""

        result = []
        for f in function_list:
            # [filepath, contract]
            if f.startswith("constructor"):
                define_pattern = (
                    r'(\w+)\s*\(([^)]*)\)\s*'
                    r'([^\{]*?)?\s*'
                    r'(?:returns\s*\(([^)]*)\))?\s*;'
                )

                realize_pattern = (
                    r'(\w+)\s*\(([^)]*)\)\s*'
                    r'([^\{]*?)?\s*'
                    r'(?:returns\s*\(([^)]*)\))?\s*\{'
                )
            else:
                define_pattern = (
                    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
                    r'([^\{]*?)?\s*'
                    r'(?:returns\s*\(([^)]*)\))?\s*;'
                )

                realize_pattern = (
                    r'function\s+(\w+)\s*\(([^)]*)\)\s*'
                    r'([^\{]*?)?\s*'
                    r'(?:returns\s*\(([^)]*)\))?\s*\{'
                )

            match = re.match(define_pattern, f)
            if not match:
                match = re.match(realize_pattern, f)
                if not match:
                    return

            func_name = match.group(1)
            md5 = hashlib.md5(f.encode()).hexdigest()
            function_info = self.find_function_by_md5(func_name, md5)

            state_variable_dict = {}
            if function_info is not None:
                detail = SolidityContextExtractor.index_data[md5]
                state_variables = function_info["reads"]
                for state_variable in state_variables:
                    state_variable_name = state_variable[0]
                    path = state_variable[1]
                    contract = state_variable[2]
                    if not path:
                        path = detail[0]
                    if contract:
                        content = SolidityContextExtractor.all_data['solidity_file'][path]['contracts'][contract][
                            'state_variables'][state_variable_name]
                    else:
                        content = SolidityContextExtractor.all_data['solidity_file'][path]['state_variables'][
                            state_variable_name]
                    state_variable_dict[state_variable_name] = content

                called_function_list = []
                external_functions = SolidityContextExtractor.all_data['solidity_file'][detail[0]]['external_functions']
                called_functions = function_info['external_calls']
                for called_function in set(called_functions):
                    if called_function in external_functions:
                        funcs = self.find_functions_by_md5(external_functions[called_function])
                        called_function_list.append(funcs)
                        for fun in funcs:
                            state_variables_1 = fun["reads"]
                            for state_variable in state_variables_1:
                                state_variable_name = state_variable[0]
                                path = state_variable[1]
                                contract = state_variable[2]
                                if not path:
                                    path = SolidityContextExtractor.index_data[external_functions[called_function]][0]
                                if contract:
                                    content = SolidityContextExtractor.all_data['solidity_file'][path]['contracts'][contract][
                                        'state_variables'][state_variable_name]
                                else:
                                    content = SolidityContextExtractor.all_data['solidity_file'][path]['state_variables'][
                                        state_variable_name]
                                state_variable_dict[state_variable_name] = content

                        if self.is_modifier_by_md5(external_functions[called_function]):
                            modifier_detail = SolidityContextExtractor.index_data[external_functions[called_function]]
                            modifier_external_functions = SolidityContextExtractor.all_data['solidity_file'][modifier_detail[0]]['external_functions']
                            modifier_called_functions = funcs[0]["external_calls"]
                            for modifier_called_function in set(modifier_called_functions):
                                if modifier_called_function in modifier_external_functions:
                                    funcs2 = self.find_functions_by_md5(modifier_external_functions[modifier_called_function])
                                    called_function_list.append(funcs2)
                                    for fun in funcs2:
                                        state_variables_1 = fun["reads"]
                                        for state_variable in state_variables_1:
                                            state_variable_name = state_variable[0]
                                            path = state_variable[1]
                                            contract = state_variable[2]
                                            if not path:
                                                path = SolidityContextExtractor.index_data[
                                                    external_functions[called_function]][0]
                                            if contract:
                                                content = \
                                                SolidityContextExtractor.all_data['solidity_file'][path]['contracts'][
                                                    contract][
                                                    'state_variables'][state_variable_name]
                                            else:
                                                content = SolidityContextExtractor.all_data['solidity_file'][path][
                                                    'state_variables'][
                                                    state_variable_name]
                                            state_variable_dict[state_variable_name] = content
                        continue

                d = {
                    "func_name": func_name,
                    "state_variables": {},
                    "called_functions": []
                }
                d["state_variables"] = state_variable_dict
                d["called_functions"] = called_function_list
                d["md5"] = function_info["md5"]
                result.append(d)

        return result

    def find_function_by_md5(self, func_name, md5):
        if md5 in SolidityContextExtractor.index_data:
            detail = SolidityContextExtractor.index_data[md5]
            if detail[1]:
                if detail[2] == 0:
                    function_infos = \
                        SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]][
                            'functions'][
                            func_name]
                else:
                    function_infos = \
                        [SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]][
                             'modifiers'][
                             func_name]]
            else:
                if detail[2] == 0:
                    function_infos = SolidityContextExtractor.all_data['solidity_file'][detail[0]]['functions'][
                        func_name]
                else:
                    function_infos = \
                        [SolidityContextExtractor.all_data['solidity_file'][detail[0]][
                             'modifiers'][
                             func_name]]
            function_info = None
            for function in function_infos:
                if function['md5'] == md5:
                    function_info = function
                    break
            return function_info

    def is_modifier_by_md5(self, md5):
        if md5 in SolidityContextExtractor.index_data:
            detail = SolidityContextExtractor.index_data[md5]
            if detail[2] == 1:
                return True
        return False

    def find_contract_name_by_md5(self, md5):
        if md5 in SolidityContextExtractor.index_data:
            return SolidityContextExtractor.index_data[md5][1]
        else:
            return ""
    def find_functions_by_md5(self, md5):
        if md5 in SolidityContextExtractor.index_data:
            detail = SolidityContextExtractor.index_data[md5]
            if detail[2] == 0:
                if detail[1]:
                    for function_name in \
                    SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]]['functions']:
                        for function_info in \
                        SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]][
                            'functions'][function_name]:
                            if function_info['md5'] == md5:
                                return \
                                SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]][
                                    'functions'][function_name]
                else:
                    for function_name in SolidityContextExtractor.all_data['solidity_file'][detail[0]]['functions']:
                        for function_info in SolidityContextExtractor.all_data['solidity_file'][detail[0]]['functions'][
                            function_name]:
                            if function_info['md5'] == md5:
                                return SolidityContextExtractor.all_data['solidity_file'][detail[0]]['functions'][
                                    function_name]
            else:
                if detail[1]:
                    for modifier_name in \
                    SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]]['modifiers']:
                        if SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]][
                            'modifiers'][modifier_name]['md5'] == md5:
                            return [
                                SolidityContextExtractor.all_data['solidity_file'][detail[0]]['contracts'][detail[1]][
                                    'modifiers'][modifier_name]]
                else:
                    for modifier_name in SolidityContextExtractor.all_data['solidity_file'][detail[0]]['modifiers']:
                        if SolidityContextExtractor.all_data['solidity_file'][detail[0]]['modifiers'][modifier_name][
                            'md5'] == md5:
                            return [SolidityContextExtractor.all_data['solidity_file'][detail[0]]['modifiers'][
                                        modifier_name]]

    def _parse_contract_content(self, content):
        """解析合约内容（状态变量、函数、修饰符）"""
        # 提取using指令
        using_matches = re.findall(
            r'using\s+(\w+)\s+for\s+(\w+(?:\s*\[\s*\d*\s*\])?);',
            content
        )

        for lib_match, type_match in using_matches:
            if self.current_contract is not None:
                self.contracts[self.current_contract]['using_directives'][type_match] = lib_match
            else:
                self.solidity_file['using_directives'][type_match] = lib_match

        # 使用状态机处理内容
        tokens = re.split(r'(\b(?:function|modifier|event|enum|struct|error|constructor|'
                          r'type|import|pragma|using|'
                          r'contract|library|interface|abstract)\b|[{},;])', content)

        current_definition = None
        current_data = ""
        brace_level = 0

        # 收集function，最后处理
        function_list = []
        moderfier_list = []

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            # 处理定义开始
            if token in define_type_set and brace_level == 0:
                if token == 'struct':
                    pass
                current_definition = token
                current_data = token
                continue

            # 处理特殊字符
            if token in {'{', '}', ',', ';'}:
                if token == '{':
                    brace_level += 1
                elif token == '}':
                    brace_level -= 1

                current_data += token

                # 处理定义结束
                if token == ';' and brace_level == 0:
                    if current_definition == "function" or current_definition == "constructor":
                        function_list.append(current_data)
                    elif current_definition == "modifier":
                        self._process_modifier_signature(current_data)
                    elif current_definition == "event":
                        self._process_event_definition(current_data)
                    elif current_definition == "error":
                        self._process_error_definition(current_data)
                    elif current_definition == "type":
                        self._process_custom_type_definition(current_data)
                    elif current_definition == "import" or current_definition == "pragma" or current_definition == "using":
                        pass
                    elif current_definition == "contract" or current_definition == "library" or current_definition == "interface" or \
                            current_definition == "abstract":
                        pass
                    elif not current_definition:
                        # 可能是状态变量
                        self._process_state_variable(current_data)
                    current_definition = None
                    current_data = ""
                elif token == '}' and brace_level == 0:
                    # 忽略import
                    if current_definition == "import":
                        continue
                    # 函数体结束
                    if current_definition == "function" or current_definition == "constructor":
                        function_list.append(current_data)
                    elif current_definition == "modifier":
                        moderfier_list.append(current_data)
                    elif current_definition == "struct":
                        self._process_struct_definition(current_data)
                    elif current_definition == "enum":
                        self._process_enum_definition(current_data)
                    current_definition = None
                    current_data = ""
                continue

            # 添加token到当前数据
            current_data += " " + token if current_data else token

            # 处理没有特殊字符的定义结束
            if not current_definition and token.endswith(';'):
                self._process_state_variable(current_data)
                current_data = ""

        for m in moderfier_list:
            self._process_modifier_signature(m)

        for f in function_list:
            # [current_data, token]
            self._process_function_signature(f)
        #
        # for f in function_list:
        #     self._process_function_body(f)

    def _process_state_variable(self, definition):
        """处理状态变量定义"""
        # 简化模式匹配
        pattern = (
            r'(\w+(?:\s*\[\s*\d*\s*\])*|mapping.+(?:\s*\)+)+|'
            r'function\(.+\s*\)\s+(?:external|internal)?\s*(?:pure|view|payable)?\s*(?:returns\s*\(.*\))?)\s+'
            r'(public|private|internal)?\s*'
            r'(constant|immutable)?\s*'
            r'(override)?\s*'
            r'(\w+)'
            r'(\s*=\s*[^\>;][^;]*)?\s*;'
        )

        match = re.match(pattern, definition)
        if not match:
            return

        var_type = match.group(1)
        visibility = match.group(2) or 'internal'
        is_constant = bool(match.group(3) == 'constant')
        is_immutable = bool(match.group(3) == 'immutable')
        is_override = bool(match.group(4))
        var_name = match.group(5)
        initial_value = match.group(6).strip()[1:].strip() if match.group(6) else None

        # 检测潜在漏洞
        # if visibility == 'public' and not (is_constant or is_immutable):
        #     self.contracts[self.current_contract]['potential_vulnerabilities'].append(
        #         f"Public mutable state variable: {var_name}"
        #     )

        data = {
            'type': var_type,
            'visibility': visibility,
            'is_constant': is_constant,
            'is_immutable': is_immutable,
            'is_override': is_override,
            'initial_value': initial_value,
            'content': definition
        }
        # 保存状态变量
        if self.current_contract is not None:
            self.contracts[self.current_contract]['state_variables'][var_name] = data
        else:
            self.solidity_file['state_variables'][var_name] = data

    def _process_function_signature(self, signature):
        """处理函数签名"""
        if signature.startswith("constructor"):
            define_pattern = (
                r'(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*;'
            )

            realize_pattern = (
                r'(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*\{'
            )
        else:
            define_pattern = (
                r'function\s+(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*;'
            )

            realize_pattern = (
                r'function\s+(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*\{'
            )

        is_realized = False

        match = re.match(define_pattern, signature)
        if not match:
            match = re.match(realize_pattern, signature)
            is_realized = True
            if not match:
                return

        func_name = match.group(1)
        params_str = match.group(2)
        modifier = closed_split(match.group(3))
        visibility = 'public'

        # 可见性
        for i in range(len(modifier)):
            if modifier[i] in visibility_set:
                visibility = modifier[i]
                modifier.remove(modifier[i])
                break

        # todo pure view 暂时不考虑

        # todo payable 暂时不考虑

        # todo virtual override  暂时不考虑

        returns_str = match.group(4)
        # 解析参数 参数的修饰可能还有payable, calldata, memory, storage 等修饰符，可以按空格分隔取最后一项
        parameters = []
        if params_str.strip():
            for param in closed_split(params_str, ','):
                if param:
                    parts = closed_split(param)
                    param_name = None
                    if len(parts) >= 2:
                        if parts[-1] not in keywords:
                            param_name = parts[-1]
                            parts.pop()
                        param_type = " ".join(parts)
                        parameters.append({
                            'type': param_type,
                            'name': param_name
                        })
                    elif parts:  # 只有类型没有名称
                        parameters.append({
                            'type': parts[0],
                            'name': param_name
                        })

        # 解析返回值
        returns = []
        if returns_str:
            for ret in closed_split(returns_str, ','):
                if ret:
                    parts = closed_split(ret)
                    return_name = None
                    if parts:
                        if len(parts) >= 2:
                            if parts[-1] not in keywords:
                                return_name = parts[-1]
                                parts.pop()
                            return_type = " ".join(parts)
                            returns.append({
                                'type': return_type,
                                'name': return_name
                            })
                        else:
                            returns.append({
                                'type': parts[0],
                                'name': return_name
                            })

        data = {
            'visibility': visibility,
            'content': signature,
            'modifiers': modifier,
            'parameters': parameters,
            'returns': returns,
            'reads': [],
            'writes': [],
            'external_calls': [],
            'is_payable': 'payable' in modifier,
            'md5': hashlib.md5(signature.encode()).hexdigest()
        }
        # 初始化函数信息
        if self.current_contract is not None:
            if func_name not in self.contracts[self.current_contract]['functions']:
                self.contracts[self.current_contract]['functions'][func_name] = []
            self.contracts[self.current_contract]['functions'][func_name].append(data)
        else:
            if func_name not in self.solidity_file['functions']:
                self.solidity_file['functions'][func_name] = []
            self.solidity_file['functions'][func_name].append(data)

        # 检测潜在漏洞：未保护的payable函数
        # if 'payable' in signature and not any(
        #         'only' in mod for mod in self.contracts[self.current_contract]['functions'][func_name]['modifiers']):
        #     self.contracts[self.current_contract]['potential_vulnerabilities'].append(
        #         f"Unprotected payable function: {func_name}"
        #     )

    def _process_function_body(self, body, index):
        """处理函数体内容"""
        if body.startswith("constructor"):
            define_pattern = (
                r'(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*;'
            )

            realize_pattern = (
                r'(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*\{'
            )
        else:
            define_pattern = (
                r'function\s+(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*;'
            )

            realize_pattern = (
                r'function\s+(\w+)\s*\(([^)]*)\)\s*'
                r'([^\{]*?)?\s*'
                r'(?:returns\s*\(([^)]*)\))?\s*\{'
            )

        is_realized = False

        match = re.match(define_pattern, body)
        if not match:
            match = re.match(realize_pattern, body)
            is_realized = True
            if not match:
                return

        if not self.current_contract or not is_realized:
            return

        func_name = match.group(1)
        self.current_function = func_name

        # 合约能够使用的状态变量，仅收集当前合约内（contract）、当前sol文件内的全局变量（常量）和import进来的合约的状态变量。
        # [var_name, filepath, contract]
        state_variables = self.state_variable_to_call

        # 分析状态变量访问
        for state_variable in state_variables:

            # 检测读取
            if re.search(rf'(\b|\.){state_variable}(\b|\[|\.|\()', body):
                if self.current_contract is not None:
                    self.contracts[self.current_contract]['functions'][self.current_function][index]['reads'].append(
                        state_variables[state_variable])
                else:
                    self.solidity_file['functions'][self.current_function][index]['reads'].append(
                        state_variables[state_variable])

            # 检测写入
            if re.search(
                    rf'(\b|\.){state_variable}(\[[^;=]*\]|\([^;=]*\)|\.[^;=]*)?([^;=]*\))?\s*([+*%/&|^-]|<<|>>)?=(?![=>])',
                    body):
                if self.current_contract is not None:
                    self.contracts[self.current_contract]['functions'][self.current_function][index]['writes'].append(
                        state_variables[state_variable])
                else:
                    self.solidity_file['functions'][self.current_function][index]['writes'].append(
                        state_variables[state_variable])

        # 函数能够使用的外部函数
        if self.current_contract and self.current_function and self.func_to_call:
            if f'{self.current_contract}.{self.current_function}' in self.func_to_call:
                self.contracts[self.current_contract]['functions'][self.current_function][index]['external_calls'] = \
                self.func_to_call[f'{self.current_contract}.{self.current_function}']

        # 检测外部调用
        # 1. 直接函数调用
        # direct_calls = re.findall(r'\b(\w+)\s*\(', body)
        # for call in direct_calls:
        #     # 排除内置函数和当前合约函数
        #     if call not in keywords and call not in self.contracts[self.current_contract]['functions'].keys():
        #         self.contracts[self.current_contract]['functions'][self.current_function][-1]['external_calls'].add(call)

        # 2. 成员函数调用
        # member_calls = re.findall(r'\b(\w+\s*\.\s*)+(\w+)\s*\(', body)
        # for call in member_calls:
        #     # 排除内置成员
        #     if call not in ['call', 'delegatecall', 'staticcall', 'send', 'transfer']:
        #         self.contracts[self.current_contract]['functions'][self.current_function]['external_calls'].add(call)

        # 3. 底层调用
        # if re.search(r'\.(call|delegatecall|staticcall)\s*\(', body):
        #     self.contracts[self.current_contract]['functions'][self.current_function]['external_calls'].add(
        #         'low_level_call')

        # 4. 事件日志
        # if re.search(r'emit\s+\w+\(', body):
        #     self.contracts[self.current_contract]['functions'][self.current_function]['external_calls'].add(
        #         'event_emit')

        # 检测潜在漏洞：未保护的外部调用
        # external_calls = self.contracts[self.current_contract]['functions'][self.current_function]['external_calls']
        # if external_calls and not self.contracts[self.current_contract]['functions'][self.current_function][
        #     'modifiers']:
        #     self.contracts[self.current_contract]['potential_vulnerabilities'].append(
        #         f"Unprotected function with external calls: {self.current_function}"
        #     )

        # 检测潜在漏洞：重入风险
        # if 'call' in body or 'delegatecall' in body or 'send' in body or 'transfer' in body:
        #     if not any('nonReentrant' in mod for mod in
        #                self.contracts[self.current_contract]['functions'][self.current_function]['modifiers']):
        #         self.contracts[self.current_contract]['potential_vulnerabilities'].append(
        #             f"Possible reentrancy vulnerability in function: {self.current_function}"
        #         )
        self.current_function = None

    def _process_modifier_signature(self, signature):
        """处理修饰符签名"""
        realize_pattern = (
            r'modifier\s+(\w+)\s*\(([^)]*)\)\s*'
        )

        match = re.match(realize_pattern, signature)
        if not match:
            return

        mod_name = match.group(1)
        params_str = match.group(2)

        # 解析参数 参数的修饰可能还有payable, calldata, memory, storage 等修饰符，可以按空格分隔取最后一项
        parameters = []
        if params_str.strip():
            for param in closed_split(params_str, ','):
                if param:
                    parts = closed_split(param)
                    param_name = None
                    if len(parts) >= 2:
                        if parts[-1] not in keywords:
                            param_name = parts[-1]
                            parts.pop()
                        param_type = " ".join(parts)
                        parameters.append({
                            'type': param_type,
                            'name': param_name
                        })
                    elif parts:  # 只有类型没有名称
                        parameters.append({
                            'type': parts[0],
                            'name': param_name
                        })

        data = {
            'parameters': parameters,
            'content': signature,
            'reads': [],
            'writes': [],
            'external_calls': [],
            'md5': hashlib.md5(signature.encode()).hexdigest()
        }
        if self.current_contract is not None:
            self.contracts[self.current_contract]['modifiers'][mod_name] = data
        else:
            self.solidity_file['modifiers'][mod_name] = data

        self.current_function = mod_name
        self._process_modifier_body(signature)
        self.current_function = None

    def _process_modifier_body(self, body):
        """处理装饰器内容"""
        realize_pattern = (
            r'modifier\s+(\w+)\s*\(([^)]*)\)\s*'
        )

        match = re.match(realize_pattern, body)

        if not self.current_contract or not match:
            return

        mod_name = match.group(1)
        self.current_function = mod_name

        # 合约能够使用的状态变量，仅收集当前合约内（contract）、当前sol文件内的全局变量（常量）和import进来的合约的状态变量。
        # [var_name, filepath, contract]
        state_variables = self.state_variable_to_call

        # 分析状态变量访问
        for state_variable in state_variables:

            # 检测读取
            if re.search(rf'(\b|\.){state_variable}(\b|\[|\.|\()', body):
                if self.current_contract is not None:
                    self.contracts[self.current_contract]['modifiers'][self.current_function]['reads'].append(
                        state_variables[state_variable])
                else:
                    self.solidity_file['modifiers'][self.current_function]['reads'].append(
                        state_variables[state_variable])

            # 检测写入
            if re.search(
                    rf'(\b|\.){state_variable}(\[[^;=]*\]|\([^;=]*\)|\.[^;=]*)?([^;=]*\))?\s*([+*%/&|^-]|<<|>>)?=(?![=>])',
                    body):
                if self.current_contract is not None:
                    self.contracts[self.current_contract]['modifiers'][self.current_function]['writes'].append(
                        state_variables[state_variable])
                else:
                    self.solidity_file['modifiers'][self.current_function]['writes'].append(
                        state_variables[state_variable])

        # 函数能够使用的外部函数
        if self.current_contract and self.current_function and self.func_to_call:
            if f'{self.current_contract}.{self.current_function}' in self.func_to_call:
                self.contracts[self.current_contract]['modifiers'][self.current_function]['external_calls'] = \
                    self.func_to_call[f'{self.current_contract}.{self.current_function}']

    def context_to_prompt(self, context, focus_functions=None):
        """将上下文转换为适合大模型的提示格式"""
        prompt = "智能合约上下文信息:\n\n"

        # 添加全局信息
        if context.get("imported_contracts"):
            prompt += f"导入的合约: {', '.join(context['imported_contracts'])}\n"

        if context.get("structs"):
            prompt += "\n结构体定义:\n"
            for struct_name, members in context["structs"].items():
                prompt += f"- {struct_name}:\n"
                for member_name, member_info in members.items():
                    prompt += f"  - {member_info['type']} {member_name}\n"

        if context.get("enums"):
            prompt += "\n枚举定义:\n"
            for enum_name, values in context["enums"].items():
                prompt += f"- {enum_name}: {', '.join(values)}\n"

        # 添加接口信息
        if context.get("interfaces"):
            prompt += "\n接口定义:\n"
            for interface_name, functions in context["interfaces"].items():
                prompt += f"- {interface_name}:\n"
                for func_name, func_info in functions.items():
                    params = ", ".join([f"{p['type']} {p['name']}" for p in func_info["parameters"]])
                    returns = ", ".join([f"{r['type']}" for r in func_info["returns"]]) if func_info[
                        "returns"] else "void"
                    prompt += f"  - function {func_name}({params}) {func_info['visibility']} returns ({returns})\n"

        # 添加合约信息
        for contract_name, contract_data in context["contracts"].items():
            # 合约基本信息
            prompt += f"\n合约: {contract_name} ({contract_data['type']})\n"
            if contract_data["is_abstract"]:
                prompt += "  - 抽象合约\n"
            if contract_data["inherits"]:
                prompt += f"  - 继承自: {', '.join(contract_data['inherits'])}\n"

            # 使用指令
            if contract_data["using_directives"]:
                prompt += "  - 使用指令:\n"
                for type_name, lib_name in contract_data["using_directives"].items():
                    prompt += f"    * using {lib_name} for {type_name}\n"

            # 状态变量
            if contract_data["state_variables"]:
                prompt += "  - 状态变量:\n"
                for var_name, var_info in contract_data["state_variables"].items():
                    prompt += f"    * {var_info['visibility']} {var_info['type']} {var_name}"
                    if var_info["is_constant"]:
                        prompt += " (constant)"
                    if var_info["is_immutable"]:
                        prompt += " (immutable)"
                    if var_info["initial_value"]:
                        prompt += f" = {var_info['initial_value']}"
                    prompt += "\n"

            # 修饰符
            if contract_data["modifiers"]:
                prompt += "  - 修饰符:\n"
                for mod_name, mod_info in contract_data["modifiers"].items():
                    params = ", ".join([f"{p['type']} {p['name']}" for p in mod_info["parameters"]])
                    prompt += f"    * modifier {mod_name}({params})\n"

            # 函数
            if contract_data["functions"]:
                prompt += "  - 函数:\n"
                for func_name, func_info in contract_data["functions"].items():
                    # 跳过非焦点函数
                    if focus_functions and func_name not in focus_functions:
                        continue

                    params = ", ".join([f"{p['type']} {p['name']}" for p in func_info["parameters"]])
                    returns = ", ".join([f"{r['type']}" for r in func_info["returns"]]) if func_info[
                        "returns"] else "void"

                    prompt += f"    * function {func_name}({params}) {func_info['visibility']}"
                    if func_info["is_payable"]:
                        prompt += " payable"
                    if func_info["modifiers"]:
                        prompt += f" modifiers: {', '.join(func_info['modifiers'])}"
                    prompt += f" returns ({returns})\n"

                    # 状态变量访问
                    if func_info["reads_state"]:
                        prompt += f"      - 读取状态变量: {', '.join(func_info['reads_state'])}\n"
                    if func_info["writes_state"]:
                        prompt += f"      - 写入状态变量: {', '.join(func_info['writes_state'])}\n"

                    # 外部调用
                    if func_info["external_calls"]:
                        prompt += f"      - 外部调用: {', '.join(func_info['external_calls'])}\n"

        return prompt

    def _process_struct_definition(self, current_data):
        # 提取 struct
        struct_matches = re.finditer(
            r'struct\s+(\w+)\s*\{',
            current_data
        )

        for struct_match in struct_matches:
            struct_name = struct_match.group(1)
            struct_content = capture_closed(current_data, "}", start=struct_match.start())
            data = {
                'content': closed_split(struct_content)[-1]
            }
            if self.current_contract is not None:
                self.contracts[self.current_contract]["structs"][struct_name] = data
            else:
                self.solidity_file["structs"][struct_name] = data

    def _process_event_definition(self, current_data):
        event_matches = re.finditer(
            r'event\s+(\w+)\s*\(',
            current_data
        )

        for event_match in event_matches:
            event_name = event_match.group(1)
            event_content = capture_closed(current_data, ";", start=event_match.start())
            data = {
                'event': event_name,
                'content': closed_split(event_content)[-1]
            }
            if self.current_contract is not None:
                self.contracts[self.current_contract]["events"][event_name] = data
            else:
                self.solidity_file["events"][event_name] = data

    def _process_enum_definition(self, current_data):
        # 提取 enum
        enum_matches = re.finditer(
            r'enum\s+(\w+)\s*\{',
            current_data
        )

        for enum_match in enum_matches:
            enum_name = enum_match.group(1)
            enum_content = capture_closed(current_data, "}", start=enum_match.start())
            data = {
                'content': closed_split(enum_content)[-1]
            }
            if self.current_contract is not None:
                self.contracts[self.current_contract]["enums"][enum_name] = data
            else:
                self.solidity_file["enums"][enum_name] = data

    def _process_error_definition(self, current_data):

        # 提取 error
        error_matches = re.finditer(
            r'error\s+(\w+)\s*\(([^)]*)\)\s*;',
            current_data
        )

        for error_match in error_matches:
            error_name = error_match.group(1)
            error_content = capture_closed(current_data, ";", start=error_match.start())
            data = {
                'content': closed_split(error_content)[-1]
            }
            if self.current_contract is not None:
                self.contracts[self.current_contract]["errors"][error_name] = data
            else:
                self.solidity_file["errors"][error_name] = data

    def _process_custom_type_definition(self, current_data):
        # 提取 error
        type_matches = re.finditer(
            r'type\s+(\w+)\s+is\s+(\w+)\s*;',
            current_data
        )
        for type_match in type_matches:
            type_name = type_match.group(1)
            original_type = type_match.group(2)
            data = {
                'original_type': original_type
            }
            if self.current_contract is not None:
                self.contracts[self.current_contract]["custom_types"][type_name] = data
            else:
                self.solidity_file["custom_types"][type_name] = data

    @staticmethod
    def run_surya_graph(file_path):
        """执行 Surya graph 命令并解析结果"""
        # print(file_path)
        try:
            # 生成 DOT 格式的图形描述
            result = subprocess.run(
                [f'surya.cmd' if sys.platform.startswith('win') else 'surya', 'graph', file_path, '-m'],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            # print(f"Surya graph 命令执行失败: {e.stderr}")
            print(f"Surya graph 命令执行失败: {file_path}")
            return None
        except FileNotFoundError:
            print("未找到 surya 命令，请确保已全局安装 surya (npm install -g surya)")
            return None

    @staticmethod
    def parse_graph_output(dot_output):
        if not dot_output:
            return
        # print(dot_output)
        # 提取节点和边信息
        node_pattern = r'"([\w\.]+)"\s*\[\s*label\s*=\s*"([\w\.]+)"[^\]]*\]'
        edge_pattern = r'"([\w\.]+)"\s*->\s*"([\w\.]+)"\s*\[\s*color\s*=\s*"([^"]*)"\s*\]'

        nodes = {}
        for match in re.finditer(node_pattern, dot_output):
            node_id = match.group(1)
            node_label = match.group(2)
            nodes[node_id] = node_label

        edges = {}
        # 解析边（函数调用关系）
        for match in re.finditer(edge_pattern, dot_output):
            source_id = match.group(1)
            target_id = match.group(2)
            color = match.group(3)
            if source_id.endswith(".payable") or target_id.endswith(".payable"):
                continue
            if source_id.endswith(".address") or target_id.endswith(".address"):
                continue
            if source_id not in edges:
                edges[source_id] = set()
            edges[source_id].add(target_id)

        return edges

    def _generate_state_variable_to_call(self):
        state_variables = {}
        for contract_name in self.contracts:
            for var_name in self.contracts[contract_name]['state_variables']:
                if var_name not in state_variables:
                    state_variables[var_name] = [var_name, "", contract_name]

        for var_name in self.solidity_file['state_variables']:
            if var_name not in state_variables:
                state_variables[var_name] = [var_name, "", ""]

        # self.imported_contracts[contract_path] = {
        #     "in_database": in_database,
        #     "import_all": False,
        #     "all_alias": None,
        #     "imported": imported
        # }
        # imported[new_name] = {
        #     'original_name': original_name,
        #     'type': ContractType.UNKNOWN
        # }
        for imported_contract in self.imported_contracts:
            if self.imported_contracts[imported_contract]["in_database"] and \
                    imported_contract in SolidityContextExtractor.all_data['solidity_file']:
                if self.imported_contracts[imported_contract]["import_all"]:
                    for var_name in SolidityContextExtractor.all_data['solidity_file'][imported_contract][
                        'state_variables']:
                        if var_name not in state_variables:
                            state_variables[var_name] = [var_name, imported_contract]
                    for contract_name, contract_info in \
                            SolidityContextExtractor.all_data['solidity_file'][imported_contract]['contracts'].items():
                        for var_name in contract_info['state_variables']:
                            if var_name not in state_variables:
                                state_variables[var_name] = [var_name, imported_contract, contract_name]
                else:
                    for imported_name, imported_info in self.imported_contracts[imported_contract]["imported"].items():
                        if imported_info['original_name'] in \
                                SolidityContextExtractor.all_data['solidity_file'][imported_contract]['contracts']:
                            for contract_name, contract_info in \
                                    SolidityContextExtractor.all_data['solidity_file'][imported_contract][
                                        'contracts'].items():
                                for var_name in contract_info['state_variables']:
                                    if var_name not in state_variables:
                                        state_variables[var_name] = [var_name, imported_contract, contract_name]

        self.state_variable_to_call = state_variables


# 创建解析器
# extractor = SolidityContextExtractor()

# 解析Solidity代码
# solidity_code = """
#
# /// @notice Swaps ERC20 tokens to native and deposits these native tokens in the GasZip router contract
# /// @dev this function can be used as a LibSwap.SwapData protocol step to combine it with any other bridge
# /// @param _swapData The swap data that executes the swap from ERC20 to native
# /// @param _destinationChains A value that represents a list of chains to which gas should be distributed (see https://dev.gas.zip/gas/code-examples/deposit for more details)
# /// @param _recipient The address to receive the gas on dst chain
# function depositToGasZipERC20(
#     LibSwap.SwapData calldata _swapData,
#     uint256 _destinationChains,
#     address _recipient
# ) public {
#     // get the current native balance
#     uint256 currentNativeBalance = address(this).balance;
#
#     // execute the swapData that swaps the ERC20 token into native
#     LibSwap.swap(0, _swapData);
#
#     // calculate the swap output amount using the initial native balance
#     uint256 swapOutputAmount = address(this).balance -
#         currentNativeBalance;
#
#     // call the gas zip router and deposit tokens
#     gasZipRouter.deposit{ value: swapOutputAmount }(
#         _destinationChains,
#         _recipient
#     );
# }
#
# struct SwapData {
#     address callTo;
#     address approveTo;
#     address sendingAssetId;
#     address receivingAssetId;
#     uint256 fromAmount;
#     bytes callData;
#     bool requiresDeposit;
# }
#
# function swap(bytes32 transactionId, SwapData calldata _swap) internal {
#     if (!LibAsset.isContract(_swap.callTo)) revert InvalidContract();
#     uint256 fromAmount = _swap.fromAmount;
#     if (fromAmount == 0) revert NoSwapFromZeroBalance();
#     uint256 nativeValue = LibAsset.isNativeAsset(_swap.sendingAssetId)
#         ? _swap.fromAmount
#         : 0;
#     uint256 initialSendingAssetBalance = LibAsset.getOwnBalance(
#         _swap.sendingAssetId
#     );
#     uint256 initialReceivingAssetBalance = LibAsset.getOwnBalance(
#         _swap.receivingAssetId
#     );
#
#     if (nativeValue == 0) {
#         LibAsset.maxApproveERC20(
#             IERC20(_swap.sendingAssetId),
#             _swap.approveTo,
#             _swap.fromAmount
#         );
#     }
#
#     if (initialSendingAssetBalance < _swap.fromAmount) {
#         revert InsufficientBalance(
#             _swap.fromAmount,
#             initialSendingAssetBalance
#         );
#     }
#
#     // solhint-disable-next-line avoid-low-level-calls
#     (bool success, bytes memory res) = _swap.callTo.call{
#         value: nativeValue
#     }(_swap.callData);
#     if (!success) {
#         LibUtil.revertWith(res);
#     }
#
#     uint256 newBalance = LibAsset.getOwnBalance(_swap.receivingAssetId);
#
#     emit AssetSwapped(
#         transactionId,
#         _swap.callTo,
#         _swap.sendingAssetId,
#         _swap.receivingAssetId,
#         _swap.fromAmount,
#         newBalance > initialReceivingAssetBalance
#             ? newBalance - initialReceivingAssetBalance
#             : newBalance,
#         block.timestamp
#     );
# }
#
# function swapAndStartBridgeTokensViaGasZip(
#     ILiFi.BridgeData memory _bridgeData,
#     LibSwap.SwapData[] calldata _swapData,
#     GasZipData calldata _gasZipData
# )
#     external
#     payable
#     nonReentrant
#     refundExcessNative(payable(msg.sender))
#     containsSourceSwaps(_bridgeData)
#     doesNotContainDestinationCalls(_bridgeData)
#     validateBridgeData(_bridgeData)
# {
#     // this function shall only be used for ERC20 assets
#     if (LibAsset.isNativeAsset(_bridgeData.sendingAssetId))
#         revert InvalidCallData();
#
#     // deposit and swap ERC20 tokens
#     _bridgeData.minAmount = _depositAndSwap(
#         _bridgeData.transactionId,
#         _bridgeData.minAmount,
#         _swapData,
#         payable(msg.sender)
#     );
#
#     // deposit to gas.zip
#     depositToGasZipNative(
#         _bridgeData.minAmount,
#         _gasZipData.gasZipChainId,
#         _bridgeData.receiver
#     );
#
#     emit LiFiTransferStarted(_bridgeData);
# }
#
# """

attributes_s = {
    "toChainID": "Specifies the destination blockchain network ID.",
    "tokenAddress": "Indicates the contract address of the token to be transferred.",
    "amount": "The number of tokens to be transferred across chains.",
    "nonce": "Check and mark that nonce has not been consumed to prevent replay",
    "recipientAddress": "The address that will receive the tokens on the destination chain.",
    "externalCallAddress": "The address of a contract to be called after the cross-chain transfer.",
    "externalCallFunction": "The specific function or calldata to be executed on the `externalCallAddress`.",
    "routerAddress": "The address of the cross-chain router or bridge handler."
}
constraints_s = {
    "toChainID": [
      "Check whether toChainID is authorized.",
      "Check that the destination chain ID is not equal to the source chain ID."
    ],
    "tokenAddress":  ["Check whether the tokenAddress is authorized to use."],
    "nonce":  ["Check if the transaction's nonce is equal to the account's current nonce."],
    "amount": [
      "Validate that amount is greater than 0",
      "Validate that msg.sender's balance change before and after equals amount",
      "Validate that the bridge's balance change before and after equals amount",
      "Validate that msg.sender's balance ≥ amount"
    ],
    "recipientAddress": ["Validate that recipientAddress is not the zero address"],
    "externalCallAddress": ["Check whether the externalCallAddress is authorized to use."],
    "externalCallFunction": ["Validate that externalCallFunction is in the allowed function signature list"],
    "routerAddress": ["Check whether the routerAddress is authorized to use."]
}

attributes_t = {
    "sourceChainID": "Indicates the originating blockchain network from which the cross-chain transaction is initiated.",
    "toChainID": "Indicates the target blockchain network where the transaction is intended to be completed.",
    "amount": "The quantity of tokens or assets to be transferred across chains.",
    "nonce": "A unique number associated with the transaction to ensure its uniqueness and order.",
    "proof": "A cryptographic artifact used to confirm the authenticity of the transaction data from the source chain.",
    "externalCallAddress": "The address of a contract to be called after the cross-chain transfer.",
    "externalCallFunction": "The specific function or calldata to be executed on the `externalCallAddress`."
}
constraints_t = {
    "sourceChainID": ["Check that sourceChainID is in the predefined list of supported chain IDs"],
    "toChainID": ["Verify that the toChainID specified in the transaction matches the current chain’s ID"],
    "amount": [
      "Validate that recipientAddress's balance change before and after equals amount",
      "Validate that the bridge's balance change before and after equals amount"
    ],
    "nonce": ["Check and mark that nonce has not been consumed to prevent replay"],
    "proof": ["Cryptographic proof that the transaction truly occurred and was finalized on the source chain (e.g., multi-signature, MPC signature, zero-knowledge proof, or Merkle proof)"],
    "externalCallAddress": ["Check whether the externalCallAddress is authorized to use."],
    "externalCallFunction": ["Validate that externalCallFunction is in the allowed function signature list"]
  }
if __name__ == "__main__":

    com = [
        ["ChainSwap20210711", "DecreaseAuthQuota", "t"],
        ["HyperBridge20231214", "Initialized", "s"],
        ["LIFI20220320", "AssetSwapped", "s"],
        ["LIFI20240716", "AssetSwapped", "s"],
        ["MeterPassport20220206", "Deposit", "s"],
        ["Multichain20220118", "LogAnySwapOut", "s"],
        ["Multichain20230215", "LogAnySwapOut", "s"],
        ["Nomad20220801", "Process", "t"],
        ["PolyNetwork20210810", "VerifyHeaderAndExecuteTxEvent", "t"],
        ["QBridge20220128", "Deposit", "s"],
        ["Qubit20220101", "Deposit", "s"],
        ["Ronin20240806", "Withdrew", "s"],
        ["Rubic20221225", "RequestSent", "s"],
        ["SocketGateway20240117", "SocketSwapTokens", "s"],
        ["thorchain20210716", "Deposit", "s"],
        ["thorchain20210723", "VaultTransfer", "s"],
        ["XBridge20240424", "TokenListed", "s"],
        ["XBridge20240424", "TokenWithdrawn", "s"]
    ]
    # 计时
    start = time.time()
    clean_this_cost()

    parser = argparse.ArgumentParser(description="get function call graph")
    parser.add_argument("--file-directory", type=str, required=True, help="要遍历的文件目录路径")
    parser.add_argument("--event-name", type=str, required=True, help="调用的事件名称")
    parser.add_argument("--position", type=str, required=False, help="源链还是目标链")
    args = parser.parse_args()
    file_directory = args.file_directory
    event_name = args.event_name
    position = args.position
    directory_name = "output/" + file_directory + "_" + event_name
    handle_s_t = time.time()
    print("handle call chain")
    if not os.path.exists(directory_name):
        handle(file_directory, event_name)
    print(f"handle_s_t: {time.time() - start}")

    extractor = SolidityContextExtractor()
    print("handle external_call and state_variables")
    extractor.parse_dataset(file_directory)
    result = {}
    all_output = {}
    # model = "deepseek/deepseek-chat-v3-0324"
    model = "deepseek-ai/DeepSeek-V3"
    # platform = "openai"
    platform = "gjld"
    # 遍历目录里面的json文件
    for file_name in os.listdir(directory_name):
        if file_name.endswith(".json") and not file_name.startswith("all_output"):
            with open(os.path.join(directory_name, file_name), 'r') as file:
                data = json.load(file)
                relation_ship = data["Function call relationship"]
                relation_ship_list = relation_ship.split("->")
                codes = data["code"]
                code = "\n".join(codes)
                result[relation_ship] = extractor.find_functions(code)
                code_prompt = {
                    "event": event_name,
                    "call_graph": '->'.join([t.split(".")[-1] for t in relation_ship_list]),
                    "state_variables": {},
                    # "code": [extractor.preprocess_code(c) for c in codes]
                    "external_functions": []
                }
                contained = set()
                for f in result[relation_ship]:
                    contained.add(f["md5"])
                for f in result[relation_ship]:
                    state_variables = f["state_variables"]
                    called_functions: list = f["called_functions"]
                    for s in state_variables:
                        state_variables[s] = state_variables[s]['content']
                    new_called_functions = []
                    for cfs in called_functions:
                        for cf in cfs:
                            if cf['md5'] not in contained:
                                contained.add(cf['md5'])
                                new_called_functions.append(cf['content'])
                    code_prompt["external_functions"].extend(new_called_functions)
                    code_prompt["state_variables"].update(state_variables)
                print(json.dumps(code_prompt, indent=4, cls=SetEncoder))


                all_output[relation_ship] = {
                    "step1": {},
                    "step2": {},
                    "step3": {},
                    "step4": {},
                    "final_result": {},
                    "context": code_prompt
                }


                # step1
                if position == "s":
                    prompt1 = get_prompt1(attributes_s, codes)
                    constraints = constraints_s
                else:
                    prompt1 = get_prompt1(attributes_t, codes)
                    constraints = constraints_t
                print(f"step1")
                outputs1, native_completion_tokens, native_prompt_tokens, messages = gpt(prompt1, model=model, platform=platform)
                outputs1 = [json.loads(o) for o in outputs1]

                all_output[relation_ship]["step1"] = {
                    "prompt1": prompt1,
                    "outputs1": outputs1,
                    "v_prompt1": '',
                    "v_outputs1": []
                }

                attribute_to_parameter = {}
                parameter_to_attribute = {}

                for i in range(len(outputs1)):
                    if isinstance(outputs1[i],dict):
                        outputs1[i] = outputs1[i][list(outputs1[i].keys())[0]]

                for output in outputs1:
                    if not output:
                        raise Exception("step1 is empty")
                    for item in output:
                        if not item or "attribute" not in item or "parameter" not in item:
                            continue
                        if item["attribute"] not in attribute_to_parameter:
                            attribute_to_parameter[item["attribute"]] = {}
                        attribute_to_parameter[item["attribute"]][item["parameter"]] = {
                            "reason": item["reason"],
                        }
                        if item["parameter"] not in parameter_to_attribute:
                            parameter_to_attribute[item["parameter"]] = {}
                        parameter_to_attribute[item["parameter"]][item["attribute"]] = {
                            "reason": item["reason"],
                        }

                # step1-verify
                v_prompt1 = get_verify_prompt1([i for arr in outputs1 for i in arr], codes)
                print(f"step1-v")
                s1_start_time = time.time()
                v_outputs1, native_completion_tokens, native_prompt_tokens, messages = gpt(v_prompt1, model=model, platform=platform)
                v_outputs1 = [json.loads(o) if isinstance(o, str) else o for o in v_outputs1]
                all_output[relation_ship]["step1"]["v_outputs1"] = v_outputs1
                all_output[relation_ship]["step1"]["v_prompt1"] = v_prompt1

                for i in range(len(v_outputs1)):
                    if isinstance(v_outputs1[i],dict):
                        v_outputs1[i] = v_outputs1[i][list(v_outputs1[i].keys())[0]]

                for v_output in v_outputs1:
                    for item in v_output:
                        if not item or "attribute" not in item or not item["attribute"]:
                            continue
                        if item["attribute"] not in attribute_to_parameter:
                            attribute_to_parameter[item["attribute"]] = {}
                        if item["parameter"] not in attribute_to_parameter[item["attribute"]]:
                            continue
                        attribute_to_parameter[item["attribute"]][item["parameter"]]["score"] = item["score"] if "reason" in item else ""
                        attribute_to_parameter[item["attribute"]][item["parameter"]]["s_reason"] = item["reason"] if "reason" in item else ""
                        if item["parameter"] not in parameter_to_attribute:
                            parameter_to_attribute[item["parameter"]] = {}
                        parameter_to_attribute[item["parameter"]][item["attribute"]]["score"] = item["score"]
                        parameter_to_attribute[item["parameter"]][item["attribute"]]["s_reason"] = item["reason"] if "reason" in item else ""

                # 每个attribute取score第一的parameter
                for attr in attribute_to_parameter:
                    # 去除没有score的项
                    attribute_to_parameter[attr] = dict(filter(lambda x: "score" in x[1] and ((x[1]["score"][0] >= "5" or x[1]["score"].startswith("100")) if isinstance(x[1]["score"],str) else x[1]["score"] >= 50), attribute_to_parameter[attr].items()))
                    attribute_to_parameter[attr] = dict(sorted(attribute_to_parameter[attr].items(), key=lambda x:int(re.findall(r'\d+', x[1]["score"])[0]) if isinstance(x[1]["score"],str) else x[1]["score"], reverse=True)[:1])
                all_output[relation_ship]["step1"]["formatted_outputs1"] = parameter_to_attribute
                all_output[relation_ship]["step1-time"] = time.time() - s1_start_time

                with open(f"{directory_name}/all_output.json", 'w', encoding='utf-8') as file:
                    json.dump(all_output, file, indent=4, cls=SetEncoder, ensure_ascii=False)

                # step2
                all_output[relation_ship]["step2"] = {}
                parameter_to_dataflow = {}
                s2_start_time = time.time()
                s2_call_api_times = 0
                for attr in attribute_to_parameter:
                    for parameter in attribute_to_parameter[attr]:
                        if attr not in all_output[relation_ship]["step2"]:
                            all_output[relation_ship]["step2"][attr] = {}
                        if parameter not in all_output[relation_ship]["step2"][attr]:
                            all_output[relation_ship]["step2"][attr][parameter] = {}
                            # todo 该过程可能需要重复6次
                            prompt2 = get_prompt2(parameter, codes)
                            for i in range(3):
                                print(f"step2-{attr}-{parameter}-{i+1}")
                                outputs2, native_completion_tokens, native_prompt_tokens, messages = gpt(prompt2, model=model, platform=platform)
                                s2_call_api_times += 1
                                outputs2 = [json.loads(o) if isinstance(o, str) else o for o in outputs2]

                                # step2-verify
                                v_prompt2 = get_verify_prompt2(parameter, outputs2[0]["dataflow"], codes)
                                v_outputs2, native_completion_tokens, native_prompt_tokens, messages = gpt(v_prompt2, model=model, platform=platform)
                                s2_call_api_times += 1
                                v_outputs2 = [json.loads(o) if isinstance(o, str) else o for o in v_outputs2]

                                # {{
                                # "parameter": "...", // 参数名
                                # "coverage": "...", // 覆盖程度分数
                                # "correctness":"...", // 正确程度分数
                                # "score": "...", // 置信度评分
                                # "reason": "..." // 简要说明给定该置信度分数的原因
                                # }}
                                outputs2[0]["coverage"] = v_outputs2[0]["coverage"]
                                outputs2[0]["correctness"] = v_outputs2[0]["correctness"]
                                outputs2[0]["score"] = v_outputs2[0]["score"]
                                outputs2[0]["reason"] = v_outputs2[0]["reason"]

                                if "dataflows" not in all_output[relation_ship]["step2"][attr][parameter]:
                                    all_output[relation_ship]["step2"][attr][parameter]["dataflows"] = []
                                all_output[relation_ship]["step2"][attr][parameter]["dataflows"].append(outputs2[0])

                            # 取得分前三的dataflow
                            all_output[relation_ship]["step2"][attr][parameter]["dataflows"] = sorted(
                                all_output[relation_ship]["step2"][attr][parameter]["dataflows"], key=lambda x: int(re.findall(r'\d+', x["score"])[0]) if isinstance(x["score"],str) else x["score"], reverse=True)[:2]


                            merged_dataflows = []
                            for dataflow in all_output[relation_ship]["step2"][attr][parameter]["dataflows"]:
                                if (dataflow["score"] >= "5" or dataflow["score"].startswith("100")) if isinstance(dataflow["score"], str) else dataflow["score"] >= 50:
                                    merged_dataflows.append(dataflow["dataflow"])
                            # step2-merge
                            merge_prompt = get_merge_dataflow_prompt(parameter, merged_dataflows)
                            merge_outputs, native_completion_tokens, native_prompt_tokens, messages = gpt(merge_prompt, model=model, platform=platform)
                            s2_call_api_times += 1

                            try:
                                merge_outputs = [json.loads(o) if isinstance(o, str) else o for o in merge_outputs]
                            except json.decoder.JSONDecodeError as e:
                                print(merge_outputs)
                                print(e.with_traceback())

                            all_output[relation_ship]["step2"][attr][parameter]["merge_dataflows"] = merge_outputs[0]["dataflows"]
                all_output[relation_ship]["step2-time"] = time.time() - s2_start_time
                all_output[relation_ship]["step2-call_api_times"] = s2_call_api_times

                with open(f"{directory_name}/all_output.json", 'w', encoding='utf-8') as file:
                    json.dump(all_output, file, indent=4, cls=SetEncoder, ensure_ascii=False)

                # step3
                all_output[relation_ship]["step3"] = {}
                parameter_to_constraint = {}
                s3_start_time = time.time()
                s3_call_api_times = 0
                for attr in all_output[relation_ship]["step2"]:
                    if attr not in all_output[relation_ship]["step3"]:
                        all_output[relation_ship]["step3"][attr] = {}
                    if attr not in all_output[relation_ship]["final_result"]:
                        all_output[relation_ship]["final_result"][attr] = {}
                    for parameter in all_output[relation_ship]["step2"][attr]:
                        if attr in constraints:
                            if parameter not in all_output[relation_ship]["step3"][attr]:
                                all_output[relation_ship]["step3"][attr][parameter] = {}
                            if parameter not in all_output[relation_ship]["final_result"][attr]:
                                all_output[relation_ship]["final_result"][attr][parameter] = {}
                            for constraint in constraints[attr]:
                                if constraint not in all_output[relation_ship]["final_result"][attr][parameter]:
                                    all_output[relation_ship]["final_result"][attr][parameter][constraint] = []
                                prompt3 = get_prompt3(parameter, constraint, all_output[relation_ship]["step2"][attr][parameter]["merge_dataflows"])
                                print(f"step3-{attr}-{parameter}-{constraint}")
                                outputs3, native_completion_tokens, native_prompt_tokens, messages = gpt(prompt3, model=model, platform=platform)
                                s3_call_api_times += 1
                                outputs3 = [json.loads(o) if isinstance(o, str) else o for o in outputs3]
                                if constraint not in all_output[relation_ship]["step3"][attr][parameter]:
                                    all_output[relation_ship]["step3"][attr][parameter][constraint] = {}
                                    all_output[relation_ship]["step3"][attr][parameter][constraint]["original"] = outputs3[0]["results"]

                                # step3-verify
                                # 取original中result为true的validation
                                validations = list(filter(lambda x: x and "result" in x and x["result"], outputs3[0]["results"]))
                                if len(validations) == 0:
                                    all_output[relation_ship]["final_result"][attr][parameter][constraint].append({
                                        "parameter": parameter,
                                        "constraint": constraint,
                                        "validation": "",
                                        "reason": "在step3中未找到约束相关代码，不执行后续步骤",
                                    })
                                    all_output[relation_ship]["step3"][attr][parameter][constraint]["verify_filtered"] = []
                                    continue
                                validations = [r["validation"] for r in validations]
                                v_prompt3 = get_verify_prompt3(parameter, constraint, validations, codes)
                                print(f"step3-v-{attr}-{parameter}-{constraint}")
                                v_outputs3, native_completion_tokens, native_prompt_tokens, messages = gpt(v_prompt3, model=model, platform=platform)
                                s3_call_api_times += 1
                                v_outputs3 = [json.loads(o) if isinstance(o, str) else o for o in v_outputs3]
                                if isinstance(v_outputs3[0], dict):
                                    v_outputs3[0] = v_outputs3[0][list(v_outputs3[0].keys())[0]]
                                # 取得分第一的results
                                all_output[relation_ship]["step3"][attr][parameter][constraint]["verify_filtered"] = sorted(list(filter(lambda x: x and "score" in x,v_outputs3[0])), key=lambda x: int(re.findall(r'\d+', x["score"])[0]) if isinstance(x["score"],str) else x["score"], reverse=True)[:1]
                all_output[relation_ship]["step3-time"] = time.time() - s3_start_time
                all_output[relation_ship]["step3-call_api_times"] = s3_call_api_times

                with open(f"{directory_name}/all_output.json", 'w', encoding='utf-8') as file:
                    json.dump(all_output, file, indent=4, cls=SetEncoder, ensure_ascii=False)

                # step4
                all_output[relation_ship]["step4"] = {}
                s4_start_time = time.time()
                s4_call_api_times = 0
                for attr in all_output[relation_ship]["step3"]:
                    if attr not in all_output[relation_ship]["step4"]:
                        all_output[relation_ship]["step4"][attr] = {}
                    for parameter in all_output[relation_ship]["step3"][attr]:
                        if parameter not in all_output[relation_ship]["step4"][attr]:
                            all_output[relation_ship]["step4"][attr][parameter] = {}
                        for constraint in all_output[relation_ship]["step3"][attr][parameter]:
                            for r in all_output[relation_ship]["step3"][attr][parameter][constraint]["verify_filtered"]:
                                if not ((r["score"][0] >= "5" or r["score"].startswith("100")) if isinstance(r["score"], str) else r["score"] >= 50):
                                    continue
                                prompt4 = get_prompt4(parameter, r["validation"], codes, code_prompt)
                                print(f"step4-{attr}-{parameter}-{constraint}")
                                outputs4, native_completion_tokens, native_prompt_tokens, messages = gpt(prompt4, model=model, platform=platform)
                                s4_call_api_times += 1
                                outputs4 = [json.loads(o) if isinstance(o, str) else o for o in outputs4]
                                if isinstance(outputs4[0], dict):
                                    outputs4[0] = outputs4[0][list(outputs4[0].keys())[0]]

                                if constraint not in all_output[relation_ship]["step4"][attr][parameter]:
                                    all_output[relation_ship]["step4"][attr][parameter][constraint] = []

                                results = list(filter(lambda x: x and "result" in x and x["result"], outputs4[0]))
                                # step4-verify
                                for r1 in results:
                                    if r1["result"]:
                                        print(f"step4-v-{attr}-{parameter}-{constraint}-{r['validation']}-{r1['poc']}")
                                        v_prompt4 = get_verify_prompt4(code_prompt, parameter, r["validation"], r1["poc"], codes)
                                        v_outputs4, native_completion_tokens, native_prompt_tokens, messages = gpt(v_prompt4, model=model, platform=platform)
                                        s4_call_api_times += 1
                                        v_outputs4 = [json.loads(o) if isinstance(o, str) else o for o in v_outputs4]
                                        r1["score"] = v_outputs4[0]["score"]
                                        r1["reason"] = v_outputs4[0]["reason"]
                                        all_output[relation_ship]["final_result"][attr][parameter][constraint].append({
                                            "validation": r['validation'],
                                            "poc": r1['poc'],
                                            "score": v_outputs4[0]["score"],
                                            "reason": v_outputs4[0]["reason"]
                                        })

                                all_output[relation_ship]["step4"][attr][parameter][constraint].append(r)
                                all_output[relation_ship]["step4"][attr][parameter][constraint][-1]["results"] = results
                all_output[relation_ship]["step4-time"] = time.time() - s4_start_time
                all_output[relation_ship]["step4-call_api_times"] = s4_call_api_times

                # compare
                prompt_a = get_audit_prompt(codes)
                print(f"compare_audit")
                outputs_a, native_completion_tokens, native_prompt_tokens, messages = gpt(prompt_a, model=model, platform=platform)
                outputs_a = [json.loads(o) if isinstance(o, str) else o for o in outputs_a]
                outputs_a = outputs_a[0]
                all_output[relation_ship]["compare_audit"] = outputs_a

                if position == "s":
                    prompt_a_v = get_attribute_verification_prompt(attributes_s, constraints, codes)
                else:
                    prompt_a_v = get_attribute_verification_prompt(attributes_t, constraints, codes)
                print(f"compare_attribute_verification")
                outputs_a_v, native_completion_tokens, native_prompt_tokens, messages = gpt(prompt_a_v, model=model, platform=platform)
                outputs_a_v = [json.loads(o) if isinstance(o, str) else o for o in outputs_a_v]
                outputs_a_v = outputs_a_v[0]
                all_output[relation_ship]["compare_attribute_verification"] = outputs_a_v

                with open(f"{directory_name}/all_output.json", 'w', encoding='utf-8') as file:
                    json.dump(all_output, file, indent=4, cls=SetEncoder, ensure_ascii=False)

    end = time.time()
    all_output["time"] = end - start
    this_cost, this_prompt_tokens, this_completion_tokens = get_this_cost()
    all_output["this_cost"] = this_cost
    all_output["this_prompt_tokens"] = this_prompt_tokens
    all_output["this_completion_tokens"] = this_completion_tokens


    # with open("result.json", 'w') as file:
    #     json.dump(result, file, indent=4, cls=SetEncoder, ensure_ascii=False)
    with open(f"{directory_name}/all_output.json", 'w', encoding='utf-8') as file:
        json.dump(all_output, file, indent=4, cls=SetEncoder, ensure_ascii=False)
    # 解析代码
# 解析代码
# context = extractor.parse_source(solidity_code)
# extractor.parse_dataset()

# print(json.dumps(extractor.find_functions(solidity_code), indent=4, cls=SetEncoder))

# # 转换为提示
# prompt = extractor.context_to_prompt(context, focus_functions=["withdraw", "rescueTokens"])
# print("\n生成的提示文本:")
# print(prompt)
# print(SolidityContextExtractor.parse_graph_output(SolidityContextExtractor.run_surya_graph('C:/Users/wy/Desktop/rag/dataset/GasZipFacet/src/Facets/GasZipFacet.sol')))
