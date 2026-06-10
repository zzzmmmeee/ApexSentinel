import networkx as nx
import re
import hashlib
import os
import itertools
from collections import defaultdict, Counter
from os.path import dirname
from datetime import datetime
import config

#cadets
if config.theia == 0:
    node_type_to_index = {'SUBJECT_PROCESS':0, 'FILE_OBJECT_FILE':1, 'FILE_OBJECT_UNIX_SOCKET':2, 'UnnamedPipeObject':3, 'NetFlowObject':4, 'FILE_OBJECT_DIR':5}
    node_index_to_type = {
        0: 'SUBJECT_PROCESS',
        1: 'FILE_OBJECT_FILE',
        2: 'FILE_OBJECT_UNIX_SOCKET',
        3: 'UnnamedPipeObject',
        4: 'NetFlowObject',
        5: 'FILE_OBJECT_DIR'
    }
#theia
else:
    node_type_to_index = {'SUBJECT_PROCESS':0, 'MemoryObject':1, 'FILE_OBJECT_BLOCK':2, 'NetFlowObject':3, 'PRINCIPAL_REMOTE':4, 'PRINCIPAL_LOCAL':5, 'unknown': -1}
    node_index_to_type = {0: 'SUBJECT_PROCESS', 
                        1: 'MemoryObject', 
                        2: 'FILE_OBJECT_BLOCK', 
                        3: 'NetFlowObject', 
                        4: 'PRINCIPAL_REMOTE',
                        5: 'PRINCIPAL_LOCAL',
                        -1: 'unknown'}

def merge_edge_data(edge_data_list):
    merged_data = {}
    total_weight = 0

    for edge_data in edge_data_list:
        total_weight += edge_data.get('weight', 0)
        for action, action_data in edge_data.items():
            if action == 'weight':
                continue
            if action not in merged_data:
                merged_data[action] = {'count': 0, 'timestamps': []}
            merged_data[action]['count'] += action_data['count']
            merged_data[action]['timestamps'].extend(action_data['timestamps'])

    merged_data['weight'] = total_weight
    return merged_data

def merge_file_nodes(G):
    flag = False
    G_new = G.copy()
    
    for node in [n for n, d in G.nodes(data=True)]:
        files_by_directory = {}

        for u, v, edge_data in G.out_edges(node, data=True):
            v_data = G.nodes[v]

            path = v_data.get('target_object_path')
            if not path:
                continue
            
            directory = dirname(path)
            if directory == "" or directory == "/":
                continue
            if directory not in files_by_directory:
                files_by_directory[directory] = []
            files_by_directory[directory].append(v)

        for directory, file_nodes in files_by_directory.items():
            if len(file_nodes) > 10:
                flag = True
                #print(f"Node {node} has more than 10 files in directory {directory}. Merging them.")
                merged_node_id = f"merged_{directory.replace('/', '_')}"
                
                G_new.add_node(
                    merged_node_id,
                    type="files_in_the_same_directory",
                    target_object_path=directory,
                )

                edge_data_list = [G.get_edge_data(node, old_file_node) for old_file_node in file_nodes]
                edge_data_list = [data for data in edge_data_list if data]

                merged_edge_data = merge_edge_data(edge_data_list)

                G_new.add_edge(node, merged_node_id, **merged_edge_data)

                for old_file_node in file_nodes:
                    if old_file_node in G_new:
                        G_new.remove_node(old_file_node)

    return G_new, flag

def summarize_edges(edge_list, community, direction="in"):
    behavior_summary = defaultdict(list)
    for u, v, attr_dict in edge_list:
        source = community.nodes[u] if direction == "in" else community.nodes[v]
        proc = source.get("properties_map_exec", "unknown")
        actions = [key for key in attr_dict if key != "weight"]
        behavior_summary[proc].extend(actions)
    output = ""
    count = 0
    for proc, actions in behavior_summary.items():
        action_counts = Counter(actions)
        actions_str = ", ".join(f"{act}({cnt})" for act, cnt in action_counts.items())
        output += f"来自进程类型 {proc} 的{direction}边动作：{actions_str}\n" 
        count +=1
        if count>=20: break
    return output

def check_community_relation(suspicious_nodes, community):
    relation = ""
    permutations = itertools.permutations(suspicious_nodes, 2)
    for u, v in permutations:
        if community.has_edge(u, v):
            data = community[u][v]
            edge_info = extract_edge_info(community, (u, v, data))
            u_index = suspicious_nodes.index(u)
            v_index = suspicious_nodes.index(v)
            relation += f"进程 {u_index} {edge_info[0]['action']} 进程 {v_index}\n"

    if community.number_of_nodes() <= 5:
        return relation

    eigenvector_centrality = nx.eigenvector_centrality(community, weight=None, max_iter=1000, tol=1e-3)
    sorted_nodes = sorted(eigenvector_centrality, key=eigenvector_centrality.get, reverse=True)
    top_nodes = sorted_nodes[:2]

    output = "这些进程行为中有几个关键节点：\n" 
    for node in top_nodes:
        node_attr = community.nodes[node]
        output += f"关键节点：{node_attr['target_object_path']} ({node_attr['type']})\n" 

        in_edges = list(community.in_edges(node, data=True))
        if in_edges:
            output += summarize_edges(in_edges, community, direction="in")

        out_edges = list(community.out_edges(node, data=True))
        if out_edges:
            output += summarize_edges(out_edges, community, direction="out")

        output += "\n"

    relation += output
    return relation

def merge_dicts_with_max(dicts):
    max_dict = defaultdict(float)
    for d in dicts:
        for key, value in d.items():
            if value > max_dict[key]:
                max_dict[key] = value

    result_dict = dict(max_dict)
    return result_dict

def merge_dicts_with_mean(dicts):
    sum_dict = defaultdict(float)
    count_dict = defaultdict(int)

    for d in dicts:
        for key, value in d.items():
            sum_dict[key] += value
            count_dict[key] += 1

    result_dict = {key: sum_dict[key] / count_dict[key] for key in sum_dict}

    return result_dict

def update_and_propagate_scores(G, score_dict):
    for node in G.nodes:
        if 'suspicion_score' not in G.nodes[node] and node in score_dict:
            G.nodes[node]['suspicion_score'] = score_dict[node]
        elif 'suspicion_score' in G.nodes[node] and node in score_dict:
            # G.nodes[node]['suspicion_score'] = (G.nodes[node]['suspicion_score'] + score_dict[node]) / 2
            G.nodes[node]['suspicion_score'] = score_dict[node]

    sum_dict = defaultdict(float)
    count_dict = defaultdict(int)

    for node in G.nodes:
        if 'suspicion_score' in G.nodes[node]:
            sum_dict[node] = G.nodes[node]['suspicion_score']
            count_dict[node] = 1

    for u, v, data in G.edges(data=True):
        if 'suspicion_score' in G.nodes[u]:
            sum_dict[v] += G.nodes[u]['suspicion_score']
            count_dict[v] += 1

    for node in sum_dict:
        if count_dict[node] > 1:
            G.nodes[node]['suspicion_score'] = sum_dict[node] / count_dict[node] 
    
    return G


def propagate_scores(G, alpha=0.85, tol=1e-6, max_iter=100):
    for iteration in range(max_iter):
        max_change = 0        
        new_scores = {}        
        for node in G.nodes:
            old_score = G.nodes[node]['suspicion_score']
            neighbors = list(G.neighbors(node))
            if len(neighbors) > 0:
                neighbor_scores = [G.nodes[neighbor]['suspicion_score'] for neighbor in neighbors]
                neighbor_avg = sum(neighbor_scores) / len(neighbors)
            else:
                neighbor_avg = old_score 
            
            new_score = alpha * neighbor_avg + (1 - alpha) * old_score
            new_scores[node] = new_score
            
            max_change = max(max_change, abs(new_score - old_score))
        
        for node in G.nodes:
            G.nodes[node]['suspicion_score'] = new_scores[node]
        
        if max_change < tol:
            print(f"Converged after {iteration + 1} iterations.")
            break
    else:
        print("Reached maximum iterations without full convergence.")
    return G


        

def replace_uuid(match):
    uuid_str = match.group(0)
    hash_obj = hashlib.sha256(uuid_str.encode('utf-8'))
    hash_digest = hash_obj.hexdigest()
    hash_value = int(hash_digest[:2], 16)
    mod_value = hash_value % 100
    return str(mod_value)

def extract_edge_info(G, edge):
    u, v, data = edge
    source_node = G.nodes[u]
    target_node = G.nodes[v]
    result = []

    if 'type' not in source_node:
        source_node['type'] = -1
    if 'type' not in target_node:
        target_node['type'] = -1

    if(isinstance(source_node['type'],int)):
        source_node['type'] = node_index_to_type.get(source_node.get('type'), 'UNKNOWN')
    if(isinstance(target_node['type'],int)):
        target_node['type'] = node_index_to_type.get(target_node.get('type'), 'UNKNOWN')
    
    for key, attr in data.items():
        if key != 'weight':  
            if 'timestamps' in attr and attr['timestamps']:
                first_timestamp = int(attr['timestamps'][0])
                result.append({
                    'source': (u, source_node),
                    'target': (v, target_node),
                    'action': key,
                    'count': attr['count'],
                    'first_timestamp': first_timestamp
                })
            else:
                result.append({
                    'source': (u, source_node),
                    'target': (v, target_node),
                    'action': key,
                    'count': attr['count']
                })
    return result

def extract_logs_from_graph(G):
    logs_by_source = {}
    for edge in G.edges(data=True):
        new_log = extract_edge_info(G, edge)
        for log_entry in new_log:
            source = log_entry['source'][0]
            if source not in logs_by_source:
                logs_by_source[source] = []

            log_str = str(log_entry)
            processed_log_str = re.sub(
                r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                replace_uuid,
                log_str
            )

            processed_log_entry = eval(processed_log_str)
            logs_by_source[source].append(processed_log_entry)
    
    for source in logs_by_source:
        if logs_by_source[source] and all('first_timestamp' in log for log in logs_by_source[source]):
            logs_by_source[source].sort(key=lambda x: x['first_timestamp'])
    
    return logs_by_source

def split_with_quotes_handling(text: str):
    if text is None:
        return []

    text = text.rstrip('\r\n')
    pattern = re.compile(r'"[^"]*"')

    qmap = {} 
    def _repl(m):
        key = f"__QPH_{len(qmap)}__"
        qmap[key] = m.group(0) 
        return key

    temp = pattern.sub(_repl, text)
    parts = temp.split(' ')

    out = []
    for p in parts:
        out.append(qmap[p] if p in qmap else p)

    return out

def split_logs_by_time_window_from_file(file_path, window_size=1e9):
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"split{now}"
    os.makedirs(output_dir, exist_ok=True)

    logs = []
    with open(file_path, 'r', encoding="utf-8") as file:
        for line in file:
            line = line.rstrip('\n')
            words = split_with_quotes_handling(line)  
            logs.append(words)

    windows = split_logs_by_time_window(logs, window_size)

    n = 0
    for window in windows:
        output_file = os.path.join(output_dir, f"split_{n}.txt")
        with open(output_file, 'w', encoding="utf-8") as file:
            for log in window:
                file.write(' '.join(log) + '\n')
        n += 1

    print(f"[split.py] 已生成 {n} 个窗口文件，保存到 {output_dir}")
    return output_dir


def split_logs_by_time_window(logs, window_size=1e9):
    windows = []
    if not logs:
        return windows
    current_window = []
    window_start = int(logs[0][0])
    for log in logs:
        if int(log[0]) - window_start <= window_size:
            current_window.append(log)
        else:
            windows.append(current_window)
            current_window = [log]
            window_start = int(log[0])
    if current_window:
        windows.append(current_window)
    return windows

def extract_process_logs(logs, process):
    process_logs = []
    for log in logs:
        if log.get('subject_com.bbn.tc.schema.avro.cdm18.uuid') == process:
            process_logs.append(log)
    return process_logs


