import networkx as nx
import os
import argparse
import subprocess
import re
import json
import pydot

func_dict = {}
def traverse_directories(directory):
    """遍历指定目录下的所有子目录"""
    for root, dirs, files in os.walk(directory):
        command = "slither " + root + " --print call-graph"
        try:
            result = subprocess.run(command.split(), capture_output=True, text=True, check=True)
            print(f"执行命令输出: {result.stdout}")
        except subprocess.CalledProcessError as e:
            print(f"执行命令错误: {e.stderr}")
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            print(f"Processing path: {dir_path}")
            command = "slither " + dir_path + " --print call-graph"
            try:
                result = subprocess.run(command.split(), capture_output=True, text=True, check=True)
                print(f"执行命令输出: {result.stdout}")
            except subprocess.CalledProcessError as e:
                print(f"执行命令错误: {e.stderr}")
                continue


def traverse_files(directory):
    """遍历指定目录下的所有文件"""
    for root, dirs, files in os.walk(directory):
        for file in files:
            if not file.endswith(".sol"):
                continue
            file_path = os.path.join(root, file)


            print(f"Processing surya path: {file_path}")
            try:
                with open(f"{file_path}.dot", "w") as fout:
                    result = subprocess.run(["surya", "graph", file_path], text=True, check=True, stdout=fout, stderr=subprocess.DEVNULL)
                print(f"执行surya 命令")
            except subprocess.CalledProcessError as e:
                print(f"执行命令错误: {e.stderr}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                new_content = content.replace("0.8.0", "0.8.1")

            match = re.search(r"pragma\s+solidity\s*(?:\^|~|=|>=|<=|>|<)?\s*([0-9]+\.[0-9]+\.[0-9]+)", new_content)
            if match:
                solc_version = match.group(1)
                result = subprocess.run(["solc-select", "versions"], capture_output=True, text=True, check=True)
                if not result.stderr:
                    output = result.stdout
                    if output:
                        versions = [line.split()[0].replace('(*)', '').replace('*', '').strip() for line in output.splitlines()]
                        #print(solc_version)
                        if solc_version not in versions:
                            result = subprocess.run(["solc-select", "install", solc_version], capture_output=True, text=True, check=True)
                            #print(result.stdout)
                        result = subprocess.run(["solc-select", "use", solc_version], capture_output=True, text=True, check=True)
                        #print(result.stdout)
            
            if new_content != content:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
            
            print(f"Processing path: {file_path}")
            command = "slither " + file_path + " --print call-graph"
            try:
                result = subprocess.run(command.split(), text=True, check=True, stderr=subprocess.DEVNULL)
                print(f"执行命令")
            except subprocess.CalledProcessError as e:
                #print(f"执行命令错误: {e.stderr}")
                continue



def read_all_dot(path):
    pydot_graphs = pydot.graph_from_dot_file(path)
    G = nx.MultiDiGraph()
    for dot in pydot_graphs:
        Gi = nx.nx_pydot.from_pydot(dot)
        G.add_edges_from(Gi.edges(data=True))
        subgraphs = dot.get_subgraphs()
        for subgraph in subgraphs:
            Gj = nx.nx_pydot.from_pydot(subgraph)
            G.add_edges_from(Gj.edges(data=True))
    
    return G


def  get_function_called_graph(directory, function_name):
    G_function_graph = nx.DiGraph()
    function_stack = function_name
    clusters = {}
    pre_len = -1
    while pre_len != len(function_stack):
        pre_len = len(function_stack)
        for root, dirs, files in os.walk(directory):
            #print(pre_len)
            #print(root, dirs, files)
            for file_name in files:
                file_path = os.path.join(root, file_name)
                #print(file_path)
                if ".dot" in file_path:
                    #print(f"Processing file: {file_path}")
                    # 读取 DOT 文件，生成 networkx 图对象
                    if os.path.getsize(file_path) == 0:
                        continue
                    m1 = re.match(r"(.+?)\.sol", file_name)
                    file_prefix = os.path.join(root, m1.group(1))

                    if "call-graph" in file_path:
                        if "all_contracts" in file_path:
                            clusters = {}
                            with open(file_path, "r") as f:
                                pattern = re.compile(r'cluster_(\d+)_([A-Za-z_]\w*)\s*\{')
                                content = f.read()
                                for match in pattern.finditer(content):
                                    cluster_id = match.group(1)
                                    contract_name = match.group(2)
                                    clusters[cluster_id] = contract_name
                        else:
                            continue
                    
                    G = read_all_dot(file_path)
                    # 打印图的节点和边
                    for edge in G.edges():
                        if "call-graph" in file_name:
                            if "all_contracts" in file_name:
                                x = re.sub(r'^\d+_', '', edge[0])
                                y = re.sub(r'^\d+_', '', edge[1])
                                id_x = re.match(r'^(\d+)_', edge[0])
                                id_y = re.match(r'^(\d+)_', edge[1])
                                if id_x is None or id_y is None:
                                    continue
                                contract_prefix_x = clusters[id_x.group(1)]
                                contract_prefix_y = clusters[id_y.group(1)]
                                final_x = file_prefix + "." + contract_prefix_x + "."  + x
                                final_y = file_prefix + "." + contract_prefix_y + "."  + y
                        else:
                            # x = re.sub(r'[^.]+\.', '', edge[0])
                            # y = re.sub(r'[^.]+\.', '', edge[1])
                            x = edge[0]
                            y = edge[1]
                            final_x = file_prefix + "." + x
                            final_y = file_prefix + "." + y
                        try:
                            file_prefix_x, contract_prefix_x, func_prefix_x = final_x.split(".")
                            file_prefix_y, contract_prefix_y, func_prefix_y = final_y.split(".")                     
                            sol_file = f"{file_prefix_x}.sol"
                            if is_interface_in_file(sol_file, contract_prefix_x):
                                file_prefix_x, contract_prefix_x = find_implementing_contracts(contract_prefix_x, directory)[0]
                                file_prefix_x = file_prefix_x[:-4]
                            
                            sol_file = f"{file_prefix_y}.sol"
                            if is_interface_in_file(sol_file, contract_prefix_y):
                                file_prefix_y, contract_prefix_y = find_implementing_contracts(contract_prefix_y, directory)[0]
                                file_prefix_y = file_prefix_y[:-4]
                        except:
                            continue

                        final_x = contract_prefix_x + "." + func_prefix_x
                        final_y = contract_prefix_y + "." + func_prefix_y
                            #print(x, y)
                        #print(final_x, final_y)
                        # if file_name == "AnyswapV4Router.sol.dot":
                        #     print(G.edges())
                        # if y == "_anySwapOut":
                        #     print(x)
                        if final_y in function_stack:
                            if not G_function_graph.has_edge(final_x, final_y):
                                G_function_graph.add_edge(final_x, final_y)
                            if final_x not in function_stack:
                                function_stack.append(final_x)

                            #print(x,y)
    return G_function_graph.edges(), function_stack
                    #print("Edges:", list(G.edges()))


def  get_function_call_graph(directory, function_name):
    G_function_graph = nx.DiGraph()
    function_stack = function_name
    clusters = {}
    pre_len = -1
    
    while pre_len != len(function_stack):
        pre_len = len(function_stack)
        for root, dirs, files in os.walk(directory):
                #print(pre_len)
                #print(root, dirs, files)
            for file_name in files:
                file_path = os.path.join(root, file_name)
                #print(file_path)
                if ".dot" in file_path:
                    #print(f"Processing file: {file_path}")
                    # 读取 DOT 文件，生成 networkx 图对象
                    if os.path.getsize(file_path) == 0:
                        continue
                    m1 = re.match(r"(.+?)\.sol", file_name)
                    file_prefix = os.path.join(root, m1.group(1))
                    if "call-graph" in file_path:
                        if "all_contracts" in file_path:
                            clusters = {}
                            with open(file_path, "r") as f:
                                pattern = re.compile(r'cluster_(\d+)_([A-Za-z_]\w*)\s*\{')
                                content = f.read()
                                for match in pattern.finditer(content):
                                    cluster_id = match.group(1)
                                    contract_name = match.group(2)
                                    clusters[cluster_id] = contract_name
                        else:
                            continue
                    
                    G = read_all_dot(file_path)
                    # 打印图的节点和边
                    for edge in G.edges():
                        if "call-graph" in file_name:
                            if "all_contracts" in file_name:
                                x = re.sub(r'^\d+_', '', edge[0])
                                y = re.sub(r'^\d+_', '', edge[1])
                                id_x = re.match(r'^(\d+)_', edge[0])
                                id_y = re.match(r'^(\d+)_', edge[1])
                                if id_x is None or id_y is None:
                                    continue
                                contract_prefix_x = clusters[id_x.group(1)]
                                contract_prefix_y = clusters[id_y.group(1)]
                                final_x = file_prefix + "." + contract_prefix_x + "."  + x
                                final_y = file_prefix + "." + contract_prefix_y + "."  + y
                        else:
                            # x = re.sub(r'[^.]+\.', '', edge[0])
                            # y = re.sub(r'[^.]+\.', '', edge[1])
                            x = edge[0]
                            y = edge[1]
                            final_x = file_prefix + "." + x
                            final_y = file_prefix + "." + y
                        try:
                            file_prefix_x, contract_prefix_x, func_prefix_x = final_x.split(".")
                            file_prefix_y, contract_prefix_y, func_prefix_y = final_y.split(".")
                            sol_file = f"{file_prefix_x}.sol"
                            if is_interface_in_file(sol_file, contract_prefix_x):
                                file_prefix_x, contract_prefix_x = find_implementing_contracts(contract_prefix_x, directory)[0]
                                file_prefix_x = file_prefix_x[:-4]
                            sol_file = f"{file_prefix_y}.sol"
                            if is_interface_in_file(sol_file, contract_prefix_y):
                                file_prefix_y, contract_prefix_y = find_implementing_contracts(contract_prefix_y, directory)[0]
                                file_prefix_y = file_prefix_y[:-4]
                        except:
                            continue

                        final_x = contract_prefix_x + "." + func_prefix_x
                        final_y = contract_prefix_y + "." + func_prefix_y
                            #print(x, y)
                        #print(final_x, final_y)
                        # if file_name == "AnyswapV4Router.sol.dot":
                        #     print(G.edges())
                        # if y == "burnERC20":
                        #     print(final_x, x, function_stack)
                        #print(final_x, function_stack)
                        if final_x in function_stack:
                            if not G_function_graph.has_edge(final_x, final_y):
                                G_function_graph.add_edge(final_x, final_y)
                            if final_y not in function_stack:
                                function_stack.append(final_y)

                            #print(x,y)
    return G_function_graph.edges(), function_stack


def extract_contract_ranges(source: str):
    """
    扫描出所有 contract和library声明的名字和它们在源码里的区间 [start, end]。
    返回：列表 of (contract_name, start_index, end_index)
    """
    pattern = re.compile(r'\bcontract\s+([A-Za-z_]\w*)\s*(?:is[^{;]*)?\{')
    pattern_library = re.compile(r'\blibrary\s+([A-Za-z_]\w*)\s*(?:is[^{;]*)?\{')
    contracts = []
    for m in pattern.finditer(source):
        name = m.group(1)
        start = m.end() - 1  # '{' 的位置
        # 向后匹配找到对应的闭合 '}'
        brace = 0
        for i in range(start, len(source)):
            if source[i] == '{':
                brace += 1
            elif source[i] == '}':
                brace -= 1
                if brace == 0:
                    end = i
                    contracts.append((name, m.start(), end+1))
                    break
    
    for m in pattern_library.finditer(source):
        name = m.group(1)
        start = m.end() - 1  # '{' 的位置
        # 向后匹配找到对应的闭合 '}'
        brace = 0
        for i in range(start, len(source)):
            if source[i] == '{':
                brace += 1
            elif source[i] == '}':
                brace -= 1
                if brace == 0:
                    end = i
                    contracts.append((name, m.start(), end+1))
                    break
    return contracts


def find_contract_of_pos(contracts, pos):
    """
    给定 contracts=[(name, s, e)...] 和一个源码位置 pos，
    返回第一个满足 s<=pos<e 的 contract name，否则 None。
    """
    for name, s, e in contracts:
        if s <= pos < e:
            return name
    return None


def extract_functions_with_event(file_prefix: str, contracts, source_code: str, event_name: str):
    fn_pattern = re.compile(
    r'''
    \bfunction                   # “function” 关键字
    \s+([A-Za-z_]\w*)            # 捕获函数名
    \s*\([^)]*\)                 # 参数列表
    \s*                          # 可有空白
    (?:[^{;]*?)                   # 非 “{” 的任意字符（非贪婪），即各种修饰词
    \{                           # 紧接着的左大括号
    ''',
    re.VERBOSE
)
    contract_pattern = re.compile(r'\bcontract\s+([A-Za-z_]\w*)\s*(?:is[^{]*)?\{')
    emit_pattern = re.compile(r'\bemit\s+' + re.escape(event_name) + r'\b')

    results = []
    # 找到所有函数声明
    for m in fn_pattern.finditer(source_code):
        fn_name = m.group(1)
        whole_fn_name = m.group()

        #print(m)
        start = m.end() - 1  # '{' 所在位置
        brace_level = 0
        i = start
        
        contract_prefix = find_contract_of_pos(contracts, start)

        if contract_prefix is None:
            continue
        mark_name = contract_prefix + "." + fn_name
        if "public" or "external" in whole_fn_name:
            func_dict[mark_name] = True
        else:
            func_dict[mark_name] = False
        #print(fn_name)
        # 从函数体起始的 '{' 开始，向后扫描匹配大括号
        while i < len(source_code):
            c = source_code[i]
            if c == '{':
                brace_level += 1
            elif c == '}':
                brace_level -= 1
                if brace_level == 0:
                    end = i
                    break
            i += 1
        else:
            # 未找到匹配的 '}', 跳过
            continue

        
        fn_body = source_code[start+1:end]
        if emit_pattern.search(fn_body):
            results.append(mark_name)
    return results

def get_function_name(directory, event_name):
    check_string = "emit " + event_name 
    func_name = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_name = os.path.join(root, file)
            if not file.endswith(".sol"):
                continue
            file_prefix = file_name.replace(".sol", "")
            with open(file_name, "r") as f:
                content = f.read()
                contracts = extract_contract_ranges(content)
                results = extract_functions_with_event(file_prefix, contracts, content, event_name)
                func_name += results
    return func_name


def patrition_public_chain(called_graph, func_name):
    string_chain = [func_name]
    chain_dict = {}
    while len(string_chain) > 0:
        now_string = string_chain[0]
        parts = now_string.split("->")
        if func_dict[parts[0]]:
            chain_dict[now_string] = parts
        callers = [u for u, v in called_graph if v == parts[0]]
        for caller in callers:
            string_chain.append(caller + "->" + now_string)
        string_chain.remove(now_string)
    return chain_dict


def is_interface_in_file(sol_path, name):
    pattern = re.compile(rf'interface\s+{re.escape(name)}\b')
    with open(sol_path, "r") as f:
        content = f.read()
    return bool(pattern.search(content))


def find_implementing_contracts(interface_name, directory):
    impls = []
    inherit_pattern = re.compile(rf'contract\s+(\w+)\s+is\s+[\w,\s]*\b{re.escape(interface_name)}\b')
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".sol"):
                sol_path = os.path.join(root, file)
                with open(sol_path, "r") as f:
                    text = f.read()
                if inherit_pattern.search(text):
                    contract_name = inherit_pattern.search(text).group(1)
                    impls.append([sol_path, contract_name])
    return impls


def extract_function_code(sol_path, contract_name, func_name):
    with open(sol_path, "r") as f:
        text = f.read()
    # 先定位 contract 块范围
    # 简化匹配：contract ... { ... }
    contract_re = re.compile(
        r'\bcontract\s+' + re.escape(contract_name) + r'\b[^{]*\{'
    )
    libraray_re = re.compile(
        r'\blibrary\s+' + re.escape(contract_name) + r'\b[^{]*\{'
    )
    m = contract_re.search(text)
    if not m:
        m = libraray_re.search(text)
    if not m:
        return ''
    start = m.end()  # 合约体开始大括号之后
    # 从此处找到匹配的闭合大括号位置
    brace_count = 1
    idx = start
    while idx < len(text) and brace_count > 0:
        if text[idx] == '{':
            brace_count += 1
        elif text[idx] == '}':
            brace_count -= 1
        idx += 1
    contract_body = text[start:idx-1]

    # 在 contract_body 中提取 function func_name
    func_re = re.compile(
        r'function\s+' + re.escape(func_name) + r'\b[^\{]*\{',
    )
    fm = func_re.search(contract_body)
    if not fm:
        return ''
    f_start = fm.start()
    # 从函数体开始大括号的位置开始，继续寻找闭合大括号
    brace_count = 1
    idx2 = fm.end()
    while idx2 < len(contract_body) and brace_count > 0:
        if contract_body[idx2] == '{':
            brace_count += 1
        elif contract_body[idx2] == '}':
            brace_count -= 1
        idx2 += 1
    return contract_body[f_start:idx2]


def is_contract_func_in_file(sol_file, contract_name, func_name):
    with open(sol_file, "r") as f:
        source = f.read()
    pattern = re.compile(
        r'\b(?:contract|library)\s+' + re.escape(contract_name) + r'\b[^{]*\{',
        re.IGNORECASE
    )
    match = pattern.search(source)
    if not match:
        return None

    start = match.end() - 1  
    depth = 0
    for i in range(start, len(source)):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                source = source[match.start():i+1]
                break
    
    pattern = re.compile(
        r'\bfunction\s+' + re.escape(func_name) + r'\s*\(',
        re.IGNORECASE
    )
    return bool(pattern.search(source))


def get_code_from_func(directory, get_all_func_stack):
    results = []
    for item in get_all_func_stack:
        contract_name, func_name = item.split('.')
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if not file_path.endswith(".sol"):
                    continue
                if not is_contract_func_in_file(file_path, contract_name, func_name):
                    continue
                if is_interface_in_file(file_path, contract_name):
                    #print(sol_file, contract_name)
                    impls = find_implementing_contracts(contract_name, directory)
                    #print(impls)
                    for impl in impls:
                        code = extract_function_code(impl[0], impl[1], func_name)
                        #print(code)

                        results.append(impl[1] + "." + func_name + ":" + code)
                        break
                else:
                    # 普通合约
                    code = extract_function_code(file_path, contract_name, func_name)
                    if code:
                        results.append(contract_name + "." + func_name + ":" +code)
    return results
        


def get_code_from_graph(directory, called_and_call_graph, func_name):
    get_all_func_stack = []
    add_stack = func_name
    while len(add_stack) != 0:
        callers = [v for u, v in called_and_call_graph if u in add_stack and v not in add_stack]
        get_all_func_stack += add_stack
        add_stack = callers
    #print(get_all_func_stack)
    code = get_code_from_func(directory, get_all_func_stack)      
    return code


#接口暂时只考虑找一个接口的实现
#暂时只是函数名
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="get function call graph")
    parser.add_argument("--directory", type=str, required=False, help="要遍历的目录路径")
    parser.add_argument("--file-directory", type=str, required=False, help="要遍历的文件目录路径")
    parser.add_argument("--function-name", type=str, required=False, help="调用的原始函数名称")
    parser.add_argument("--event-name", type=str, required=False, help="调用的事件名称")
    args = parser.parse_args()
    function_names = get_function_name(args.file_directory, args.event_name)
    print(function_names)
    traverse_files(args.file_directory)
    directory_name = "output/" + args.file_directory + "_" + args.event_name
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)
    cnt = 0 
    for func_name in function_names:
        func_name = [func_name]
        called_graph, func_name_called = get_function_called_graph(args.file_directory, func_name)
        called_and_call_graph, func_name_call = get_function_call_graph(args.file_directory, func_name_called)
        call_chain = patrition_public_chain(called_graph, func_name[0])
        for key, value in call_chain.items():
            cnt += 1
            code = get_code_from_graph(args.file_directory, called_and_call_graph, value)
            data = {
                "Function call relationship":key,
                "code":code
            }
            json_name = str(cnt) + ".json"
            json_path = os.path.join(directory_name, json_name)
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            

    

