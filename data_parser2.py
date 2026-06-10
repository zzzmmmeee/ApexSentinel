import pandas as pd
import numpy as np
import joblib
import networkx as nx
import pickle as pkl
import random
import os
import csv
import re



def split_with_quotes_handling(text):
    quote_pattern = r'"[^"]*"'
    
    quoted_parts = re.findall(quote_pattern, text)
    
    quoted_parts_iter = iter(quoted_parts)
    
    placeholder = 'QUOTE_PLACEHOLDER'
    temp_text = re.sub(quote_pattern, placeholder, text)
    
    parts = []
    for part in temp_text.split(' '):
        if part == placeholder:
            parts.append(next(quoted_parts_iter))
        elif part: 
            parts.append(part)
        else:
            parts.append('') 
    
    return parts


def safe_get(row, idx, default=None):
    return row[idx] if idx < len(row) else default

def construct_graph(file_path,G):
    edge_type_to_index = {'FORK': 0, 'CONNECT': 1, 'OTHER': 2, 'ACCEPT': 3, 'TRUNCATE': 4, 'WRITE': 5, 'CHANGE_PRINCIPAL': 6, 'MMAP': 7, 'SIGNAL': 8, 'FCNTL': 9, 'RECVMSG': 10, 'OPEN': 11, 'CREATE_OBJECT': 12, 'LINK': 13, 'SENDTO': 14, 'FLOWS_TO': 15, 'MODIFY_FILE_ATTRIBUTES': 16, 'LSEEK': 17, 'EXIT': 18, 'UNLINK': 19, 'SENDMSG': 20, 'ERENAME': 21, 'CLOSE': 22, 'READ': 23, 'MODIFY_PROCESS': 24, 'RECVFROM': 25, 'EXECUTE': 26, 'BIND': 27}
    node_type_to_index = {'SUBJECT_PROCESS':0, 'FILE_OBJECT_FILE':1, 'FILE_OBJECT_UNIX_SOCKET':2, 'UnnamedPipeObject':3, 'NetFlowObject':4, 'FILE_OBJECT_DIR':5}


    df=[]
    with open(file_path, 'r') as file:
        for line in file:
            # line = line.strip()
            line = line.rstrip('\n')
            #line = insert_na_between_spaces(line)
            words = split_with_quotes_handling(line)
            if 1: #words != previous_line:
                df.append(words)
    
    new_src = []
    for row in df:
        srcnode = row[1] #['subject_com.bbn.tc.schema.avro.cdm18.uuid']
        dstnode = row[7] #['predicateobject_com.bbn.tc.schema.avro.cdm18.uuid']
        dstnode_2 = row[12] if len(row) > 12 else '' #['predicateobject2_com.bbn.tc.schema.avro.cdm18.uuid']
        edgetype = row[5] #['type']
        process_str = row[3] #['properties_map_exec'] # row['properties_map_exec']
        timestamp = row[0] #['timestampnanos']
        cmd = row[14] if len(row) > 14 else '' #properties_map_cmdline

        new_flag = 0
        if srcnode!='' and dstnode!='' and row[6]!='': 
            new_src.append(srcnode)
            new_flag = 1
            dstnode_type = row[6] #['object_type']
            if not G.has_node(srcnode):
                # process_str = sub_name.get(srcnode, "process")
                G.add_node(srcnode, type=node_type_to_index['SUBJECT_PROCESS'], properties_map_exec= process_str)
            if 'properties_map_exec' not in G.nodes[srcnode]:
                G.nodes[srcnode]['properties_map_exec'] = process_str
            else:
                G.nodes[srcnode]['properties_map_exec'] = process_str
            if not G.has_node(dstnode):
                G.add_node(dstnode, type=node_type_to_index[dstnode_type], target_object_path= row[8])
            if 'properties_map_exec' in G.nodes[dstnode]:
                G.nodes[dstnode]['target_object_path'] = row[8]  
            if G.has_edge(srcnode, dstnode):
                edge_data = G[srcnode][dstnode]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                    edge_data[edgetype]['timestamps'].append(timestamp)
                else:
                    edge_data[edgetype] = {'count': 1, 'timestamps': [timestamp]}
            else:
                G.add_edge(srcnode, dstnode, **{edgetype: {'count': 1, 'timestamps': [timestamp]}})
           
            

        if srcnode!='' and dstnode_2!='' and row[11]!='':
            if new_flag == 0:
                new_src.append(srcnode)
            dstnode_2_type = row[11] #['object2_type']
            if not G.has_node(dstnode_2):
                G.add_node(dstnode_2, type=node_type_to_index[dstnode_2_type], target_object_path= row[13])
            if 'properties_map_exec' in G.nodes[dstnode]:
                G.nodes[dstnode]['target_object_path'] = row[13]  # 给节点添加 target_object_path 属性
            if G.has_edge(srcnode, dstnode_2):
                edge_data = G[srcnode][dstnode_2]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                    edge_data[edgetype]['timestamps'].append(timestamp)
                else:
                    edge_data[edgetype] = {'count': 1, 'timestamps': [timestamp]}
            else:
                G.add_edge(srcnode, dstnode_2, **{edgetype: {'count': 1, 'timestamps': [timestamp]}})
            
    return G, new_src

def construct_graph2(file_path,G):
    edge_type_to_index = {'EVENT_BOOT': 0, 'EVENT_MMAP': 1, 'EVENT_OPEN': 2, 'EVENT_READ': 3, 'EVENT_MPROTECT': 4, 'EVENT_CONNECT': 5, 'EVENT_SENDTO': 6, 'EVENT_RECVMSG': 7, 'EVENT_READ_SOCKET_PARAMS': 8, 'EVENT_SENDMSG': 9, 'EVENT_CLONE': 10, 'EVENT_EXECUTE': 11, 'EVENT_RECVFROM': 12, 'EVENT_WRITE': 13, 'EVENT_WRITE_SOCKET_PARAMS': 14, 'EVENT_UNLINK': 15, 'EVENT_MODIFY_FILE_ATTRIBUTES': 16, 'EVENT_SHM': 17}
    node_type_to_index = {'SUBJECT_PROCESS':0, 'MemoryObject':1, 'FILE_OBJECT_BLOCK':2, 'NetFlowObject':3, 'PRINCIPAL_REMOTE':4, 'PRINCIPAL_LOCAL':5, 'unknown': -1}


    df=[]
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            #line = insert_na_between_spaces(line)
            words = split_with_quotes_handling(line)
            if 1: #words != previous_line:
                df.append(words)
    
    new_src = []
    for row in df:
        srcnode = row[1] #['subject_com.bbn.tc.schema.avro.cdm18.uuid']
        dstnode = row[5] #['predicateobject_com.bbn.tc.schema.avro.cdm18.uuid']
        edgetype = row[4] #['type']
        process_str = row[3] #['properties_map_exec'] # row['properties_map_exec']
        timestamp = row[0] #['timestampnanos']

        new_flag = 0
        if srcnode!='' and dstnode!='' and row[6]!='': 
            new_src.append(srcnode)
            new_flag = 1
            dstnode_type = row[6] #['object_type']
            if not G.has_node(srcnode):
                # process_str = sub_name.get(srcnode, "process")
                G.add_node(srcnode, type=node_type_to_index['SUBJECT_PROCESS'], properties_map_exec= process_str)
            if 'properties_map_exec' not in G.nodes[srcnode]:
                G.nodes[srcnode]['properties_map_exec'] = process_str
            else:
                G.nodes[srcnode]['properties_map_exec'] = process_str
            if 'target_object_path' not in G.nodes[srcnode]:
                G.nodes[srcnode]['target_object_path'] = process_str
            if not G.has_node(dstnode):
                path = row[7] if len(row) > 7 else 'NA'
                G.add_node(dstnode, type=node_type_to_index[dstnode_type], target_object_path= path)
            if 1:#'properties_map_exec' in G.nodes[dstnode]:
                path = row[7] if len(row) > 7 else 'NA'
                G.nodes[dstnode]['target_object_path'] = path  
            if G.has_edge(srcnode, dstnode):
                edge_data = G[srcnode][dstnode]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                    edge_data[edgetype]['timestamps'].append(timestamp)
                else:
                    edge_data[edgetype] = {'count': 1, 'timestamps': [timestamp]}
            else:
                G.add_edge(srcnode, dstnode, **{edgetype: {'count': 1, 'timestamps': [timestamp]}})
           
            
    return G, new_src



def assign_edge_weights_by_event_type(G):
    edge_type_weights = {
        'EXECUTE': 3.0,
        'WRITE': 3.0,
        'CHANGE_PRINCIPAL': 3.0,
        'CONNECT': 3.0,
        'SENDTO': 3.0,
        'SENDMSG': 3.0,
        'RECVMSG': 3.0,
        'RECVFROM': 3.0,
        'FORK': 3.0,

        'OPEN': 2.0,
        'CREATE_OBJECT': 2.0,
        'LINK': 2.0,
        'MODIFY_FILE_ATTRIBUTES': 2.0,
        'RENAME': 2.0,
        'UNLINK': 2.0,
        'CLOSE': 2.0,
        'TRUNCATE': 2.0,
        'BIND': 2.0,
        'MMAP': 2.0,

        'OTHER': 1.0,
        'SIGNAL': 1.0,
        'FCNTL': 1.0,
        'LSEEK': 1.0,
        'EXIT': 1.0,
        'MODIFY_PROCESS': 1.0,
        'FLOWS_TO': 1.0,
        'ACCEPT': 1.0
    }

    for u, v, edge_data in G.edges(data=True):
        total_weight = 0
        for etype, attr in edge_data.items():
            if isinstance(attr, dict) and etype not in ('label', 'weight'):
                base_weight = edge_type_weights.get(etype, 1.0)
                total_weight += base_weight * attr.get('count', 1)
        G[u][v]['weight'] = total_weight

    return G

def assign_edge_weights_by_event_type2(G):
    edge_type_weights = {
        'EVENT_EXECUTE': 3.0,
        'EVENT_WRITE': 3.0,
        'EVENT_CONNECT': 3.0,
        'EVENT_SENDTO': 3.0,
        'EVENT_SENDMSG': 3.0,
        'EVENT_RECVFROM': 3.0,
        'EVENT_CLONE': 3.0,

        'EVENT_OPEN': 2.0,
        'EVENT_UNLINK': 2.0,
        'EVENT_MODIFY_FILE_ATTRIBUTES': 2.0,
        'EVENT_MMAP': 2.0,
        'EVENT_WRITE_SOCKET_PARAMS': 2.0,
        'EVENT_SHM': 2.0,

        'EVENT_READ': 1.0,
        'EVENT_RECVMSG': 1.0,
        'EVENT_READ_SOCKET_PARAMS': 1.0,
        'EVENT_MPROTECT': 1.0,
        'EVENT_BOOT': 1.0,
    }


    for u, v, edge_data in G.edges(data=True):
        total_weight = 0
        for etype, attr in edge_data.items():
            if isinstance(attr, dict) and etype not in ('label', 'weight'):
                base_weight = edge_type_weights.get(etype, 1.0)
                total_weight += base_weight * attr.get('count', 1)
        G[u][v]['weight'] = total_weight

    return G

if __name__ == '__main__':
    G = nx.DiGraph()
    G, a = construct_graph2("./dataset/resorted_logs_theia.txt", G)
    G = assign_edge_weights_by_event_type2(G)

    with open("./graph_theia/graph.pkl", "wb") as f:
        pkl.dump(G, f)
        print("complete")