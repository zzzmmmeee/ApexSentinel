import pandas as pd
import numpy as np
import joblib
import networkx as nx
import pickle as pkl
from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
import torch
from gensim.models import Word2Vec
from gensim.utils import simple_preprocess
import csv

'''
需要构建一个包含所有恶意节点的列表
'''
# for cadets
# edge_type_to_index = {'EVENT_FORK': 0, 'EVENT_CONNECT': 1, 'EVENT_OTHER': 2, 'EVENT_ACCEPT': 3, 'EVENT_TRUNCATE': 4, 'EVENT_WRITE': 5, 'EVENT_CHANGE_PRINCIPAL': 6, 'EVENT_MMAP': 7, 'EVENT_SIGNAL': 8, 'EVENT_FCNTL': 9, 'EVENT_RECVMSG': 10, 'EVENT_OPEN': 11, 'EVENT_CREATE_OBJECT': 12, 'EVENT_LINK': 13, 'EVENT_SENDTO': 14, 'EVENT_FLOWS_TO': 15, 'EVENT_MODIFY_FILE_ATTRIBUTES': 16, 'EVENT_LSEEK': 17, 'EVENT_EXIT': 18, 'EVENT_UNLINK': 19, 'EVENT_SENDMSG': 20, 'EVENT_RENAME': 21, 'EVENT_CLOSE': 22, 'EVENT_READ': 23, 'EVENT_MODIFY_PROCESS': 24, 'EVENT_RECVFROM': 25, 'EVENT_EXECUTE': 26, 'EVENT_BIND': 27}
# node_type_to_index = {'SUBJECT_PROCESS':0, 'FILE_OBJECT_FILE':1, 'FILE_OBJECT_UNIX_SOCKET':2, 'UnnamedPipeObject':3, 'NetFlowObject':4, 'FILE_OBJECT_DIR':5}
# for theia
edge_type_to_index = {'EVENT_BOOT': 0, 'EVENT_MMAP': 1, 'EVENT_OPEN': 2, 'EVENT_READ': 3, 'EVENT_MPROTECT': 4, 'EVENT_CONNECT': 5, 'EVENT_SENDTO': 6, 'EVENT_RECVMSG': 7, 'EVENT_READ_SOCKET_PARAMS': 8, 'EVENT_SENDMSG': 9, 'EVENT_CLONE': 10, 'EVENT_EXECUTE': 11, 'EVENT_RECVFROM': 12, 'EVENT_WRITE': 13, 'EVENT_WRITE_SOCKET_PARAMS': 14, 'EVENT_UNLINK': 15, 'EVENT_MODIFY_FILE_ATTRIBUTES': 16, 'EVENT_SHM': 17}
node_type_to_index = {'SUBJECT_PROCESS':0, 'MemoryObject':1, 'FILE_OBJECT_BLOCK':2, 'NetFlowObject':3, 'PRINCIPAL_REMOTE':4}


def read_UID(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    # 去除每行末尾的换行符并去重
    unique_lines = list(set(line.strip() for line in lines))
    return unique_lines

# 为什么测试集没用边的标签来筛选边
def construct_graph_from_csv(file_path):
    # 统计被标为恶意的节点数量
    num = 0
    G = nx.DiGraph()

    # if 'ta1-cadets-e3-official-2' in file_path:
    #     # csv_file = file_path.rsplit('/', 1)[0] + "/sub_name.csv"
    #     csv_file = "../dataset_log/cadets/ta1-cadets-e3-official-2/sub_name.csv"
    # else:
    #     csv_file = "../dataset_log/cadets/ta1-cadets-e3-official/sub_name.csv"
    # sub_name = {}

    # with open(csv_file, 'r') as csvfile:
    #     csv_reader = csv.reader(csvfile)
    #     next(csv_reader)
    #     for row in csv_reader:
    #         if len(row) >= 2:
    #             sub_name[row[0]] = row[1]

    # 这是一个包含所有恶意节点 UUID 的列表，后续构图时会用来给节点加 label（0=正常，1=恶意）
    malicious_id = read_UID(file_path.rsplit('/', 1)[0] + "/malicious_ID.txt")
    # malicious_id = read_UID("../dataset_log/cadets/ta1-cadets-e3-official-2/malicious_ID.txt")

    df = pd.read_csv(file_path)
    # 将节点 UUID 映射为连续的整数 ID
    node_to_id = {}
    current_id = 0

    for _, row in df.iterrows():
        srcnode = row['subject_com.bbn.tc.schema.avro.cdm18.uuid']
        dstnode = row['predicateobject_com.bbn.tc.schema.avro.cdm18.uuid']
        dstnode_2 = row['predicateobject2_com.bbn.tc.schema.avro.cdm18.uuid']
        edgetype = row['type']
        label = row['lable']
        process_str = row['cmdline'] # "properties_map_exec"

        if pd.notna(srcnode) and pd.notna(dstnode):
            dstnode_type = row['object_type']
            if not G.has_node(srcnode):
                # process_str = sub_name.get(srcnode, "process")
                if srcnode in malicious_id:
                    label = 1
                    num += 1
                else:
                    label = 0
                node_to_id[srcnode] = current_id
                current_id += 1
                G.add_node(srcnode, type=node_type_to_index['SUBJECT_PROCESS'], label = label, string= process_str, nodeID = node_to_id[srcnode])
            if not G.has_node(dstnode):
                if dstnode in malicious_id:
                    num += 1
                    label = 1
                else:
                    label = 0
                node_to_id[dstnode] = current_id
                current_id += 1
                G.add_node(dstnode, type=node_type_to_index[dstnode_type], label = label, string= row['predicateobjectpath_string'], nodeID = node_to_id[dstnode])
            if G.has_edge(srcnode, dstnode):
                edge_data = G[srcnode][dstnode]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                else:
                    edge_data[edgetype] = {'count': 1}
            else:
                G.add_edge(srcnode, dstnode, label= label, **{edgetype: {'count': 1}})

        if pd.notna(srcnode) and pd.notna(dstnode_2):
            dstnode_2_type = row['object2_type']
            if not G.has_node(dstnode_2):
                if dstnode_2 in malicious_id:
                    num += 1
                    label = 1
                else:
                    label = 0
                node_to_id[dstnode_2] = current_id
                current_id += 1
                G.add_node(dstnode_2, type=node_type_to_index[dstnode_2_type], label = label, string= row['predicateobject2path_string'], nodeID = node_to_id[dstnode_2])
            if G.has_edge(srcnode, dstnode_2):
                edge_data = G[srcnode][dstnode_2]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                else:
                    edge_data[edgetype] = {'count': 1}
            else:
                G.add_edge(srcnode, dstnode_2, label= label, **{edgetype: {'count': 1}})
    # 写一个新的 CSV 文件，保存每个 UUID 到 nodeID 的映射
    csv_file = file_path.replace(".csv","-nodeid.csv")
    with open(csv_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['node', 'node_id'])
        for node, node_id in node_to_id.items():
            writer.writerow([node, node_id])

    print(num)
    return G


# 先进行边的连接次数的计算以及标准化
# 然后组合到节点属性中s

def updata_node_attr_r(G):
    # loaded_scaler = joblib.load(path_pkl)
    for node in G.nodes():
        attr = torch.zeros(len(node_type_to_index))
        attr[G.nodes[node]['type']] = 1
        G.nodes[node]['attr'] = attr


def updata_node_attr(G, model, path_pkl):
    scaler = MinMaxScaler()
    loaded_scaler = joblib.load(path_pkl)
    # edge_times = []
    for node in G.nodes():
        edge_time = torch.zeros(len(edge_type_to_index)*2)
        out_edges = G.out_edges(node, data=True)
        for _, _, data in out_edges:
            for etype, attr in data.items():
                if etype != 'label':
                    edge_type_index = edge_type_to_index[etype]
                    edge_time[edge_type_index] += attr['count']  # 出度
        # total_out_count = sum(edge_time[:len(edge_type_to_index)])
        # if total_out_count > 0:
        #     for i in range(len(edge_type_to_index)):
        #         edge_time[i] = edge_time[i] / total_out_count
        in_edges = G.in_edges(node, data=True)
        for _, _, data in in_edges:
            for etype, attr in data.items():
                if etype != 'label':
                    edge_type_index = edge_type_to_index[etype]
                    edge_time[edge_type_index + len(edge_type_to_index)] += attr['count']  # 入度
        # total_in_count = sum(edge_time[len(edge_type_to_index):])
        # if total_in_count > 0:
        #     for i in range(len(edge_type_to_index), len(edge_type_to_index)*2):
        #         edge_time[i] = edge_time[i] / total_in_count
        # edge_time_scaled_np = loaded_scaler.transform(edge_time.numpy().reshape(1, -1))
        # edge_time_scaled = torch.tensor(edge_time_scaled_np.flatten(), dtype=torch.float32)
        
        scaled_np = scaler.fit_transform(edge_time.numpy().reshape(-1, 1))  
        # scaled_np = loaded_scaler.transform(edge_time.numpy().reshape(-1, len(edge_type_to_index)*2)) 
        edge_time_scaled = torch.from_numpy(scaled_np).flatten()

        # edge_times.append(edge_time.numpy())

    # edge_times_array = np.array(edge_times)
    # scaled_edge_times = scaler.fit_transform(edge_times_array)
    
    # for i, node in enumerate(G.nodes()):
    #     edge_time_scaled = torch.tensor(scaled_edge_times[i], dtype=torch.float32)
       
        if 'string' not in G.nodes[node]:
            print(node)
        words = G.nodes[node]['string']
        sentence_vector = torch.zeros(46)
        processed_corpus = simple_preprocess(words)
        valid_word_count = 0
        for word in processed_corpus:
            if word in model.wv:
                sentence_vector += model.wv[word]
                valid_word_count += 1
        if valid_word_count > 0:
            sentence_vector /= valid_word_count

        G.nodes[node]['attr'] = torch.cat((edge_time_scaled, sentence_vector), dim=0)


def updata_edge_attr(G):
    for src, dst, data in G.edges(data=True):
        x = torch.zeros(len(edge_type_to_index))
        for etype, attr in data.items():
            if etype != 'label':
                edge_type_index = edge_type_to_index[etype]
                x[edge_type_index] += attr['count']
        # total_sum = torch.sum(x)
        G.edges[src, dst]['attr'] = x # / total_sum


if __name__ == '__main__':
    dataset = "theia"  #cadets
    gs = []
    file_path = "../dataset_log/" + dataset + "/partion"
    path_pkl = file_path + "/scaler.pkl"
    # file_name = file_path + "/" + file + "/selected.csv"
    file_name = "../dataset_log/"+ dataset +"/test/selected.csv"
    # file_name = "../dataset_log/cadets/ta1-cadets-e3-official-2/selected_1021.csv"
    print(file_name)
    G = construct_graph_from_csv(file_name)
    # model_path = file_path + "/" + file + "/w2v.model"
    model_path = "../dataset_log/"+ dataset +"/test/w2v.model"
    # model_path = "../dataset_log/cadets/ta1-cadets-e3-official-2/w2v.model"
    model = Word2Vec.load(model_path)
    updata_node_attr(G, model, path_pkl)
    updata_edge_attr(G)
    gs.append(G)
    pkl.dump([nx.node_link_data(g) for g in gs], open('data/{}/selected.pkl'.format(dataset), 'wb'))
    