import pandas as pd
import numpy as np
import joblib
import networkx as nx
import pickle as pkl
import random
import os
import csv


# for cadets
edge_type_to_index = {'EVENT_FORK': 0, 'EVENT_CONNECT': 1, 'EVENT_OTHER': 2, 'EVENT_ACCEPT': 3, 'EVENT_TRUNCATE': 4, 'EVENT_WRITE': 5, 'EVENT_CHANGE_PRINCIPAL': 6, 'EVENT_MMAP': 7, 'EVENT_SIGNAL': 8, 'EVENT_FCNTL': 9, 'EVENT_RECVMSG': 10, 'EVENT_OPEN': 11, 'EVENT_CREATE_OBJECT': 12, 'EVENT_LINK': 13, 'EVENT_SENDTO': 14, 'EVENT_FLOWS_TO': 15, 'EVENT_MODIFY_FILE_ATTRIBUTES': 16, 'EVENT_LSEEK': 17, 'EVENT_EXIT': 18, 'EVENT_UNLINK': 19, 'EVENT_SENDMSG': 20, 'EVENT_RENAME': 21, 'EVENT_CLOSE': 22, 'EVENT_READ': 23, 'EVENT_MODIFY_PROCESS': 24, 'EVENT_RECVFROM': 25, 'EVENT_EXECUTE': 26, 'EVENT_BIND': 27}
node_type_to_index = {'SUBJECT_PROCESS':0, 'FILE_OBJECT_FILE':1, 'FILE_OBJECT_UNIX_SOCKET':2, 'UnnamedPipeObject':3, 'NetFlowObject':4, 'FILE_OBJECT_DIR':5}
# for theia
# 将事件类型映射为整数，便于处理边的类型（不同数据集不同）
# edge_type_to_index = {'EVENT_BOOT': 0, 'EVENT_MMAP': 1, 'EVENT_OPEN': 2, 'EVENT_READ': 3, 'EVENT_MPROTECT': 4, 'EVENT_CONNECT': 5, 'EVENT_SENDTO': 6, 'EVENT_RECVMSG': 7, 'EVENT_READ_SOCKET_PARAMS': 8, 'EVENT_SENDMSG': 9, 'EVENT_CLONE': 10, 'EVENT_EXECUTE': 11, 'EVENT_RECVFROM': 12, 'EVENT_WRITE': 13, 'EVENT_WRITE_SOCKET_PARAMS': 14, 'EVENT_UNLINK': 15, 'EVENT_MODIFY_FILE_ATTRIBUTES': 16, 'EVENT_SHM': 17}
# # 将节点类型映射为整数，便于处理节点属性
# node_type_to_index = {'SUBJECT_PROCESS':0, 'MemoryObject':1, 'FILE_OBJECT_BLOCK':2, 'NetFlowObject':3, 'PRINCIPAL_REMOTE':4}

# # 定义不同数据集的训练集与测试集文件名列表，用于数据加载
# metadata = {
#     'theia':{
#             'train': ['ta1-theia-e3-official-6r', 'ta1-theia-e3-official-6r.1', 'ta1-theia-e3-official-6r.2', 'ta1-theia-e3-official-6r.3'],
#             'test': ['ta1-theia-e3-official-6r.8']
#     },
#     'cadets':{
#             'train': ['ta1-cadets-e3-official','ta1-cadets-e3-official.1', 'ta1-cadets-e3-official.2', 'ta1-cadets-e3-official-2.1'],
#             'test': ['ta1-cadets-e3-official-2']
#     }
# }

def construct_graph_from_csv(file_path):
    # G.nodes[srcnode] = {
    #     'type': 0,
    #     'string': '/usr/bin/python3 script.py'
    # }

    # G.nodes[dstnode] = {
    #     'type': 1,
    #     'string': '/home/user/file.txt'
    # }

    # G[srcnode][dstnode] = {
    #     'label': 'B',
    #     'EVENT_OPEN': {'count': 1, 'timestamp': [1778921]},
    #     'EVENT_WRITE': {'count': 3, 'timestamp': [1778922, 1779000, 1892000]}
    # }
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

    df = pd.read_csv(file_path)

    for _, row in df.iterrows():
        # 事件发起者（进程）
        srcnode = row['subject_com.bbn.tc.schema.avro.cdm18.uuid']
        # 被访问的对象（如文件、网络等）
        dstnode = row['predicateobject_com.bbn.tc.schema.avro.cdm18.uuid']
        dstnode_2 = row['predicateobject2_com.bbn.tc.schema.avro.cdm18.uuid']
        # 事件类型，例如 EVENT_OPEN、EVENT_EXECUTE
        edgetype = row['type']
        # 标记是良性事件或者恶性事件，'B'代表恶性事件
        label = row['lable']
        # 进程命令行信息，用于记录在进程节点上
        process_str = row['properties_map_exec'] # row['properties_map_exec']
        # 时间戳
        timestamp = row['timestampnanos']

        if pd.notna(srcnode) and pd.notna(dstnode) and  label == "B":
            dstnode_type = row['object_type']
            if not G.has_node(srcnode):
                # process_str = sub_name.get(srcnode, "process")
                G.add_node(srcnode, type=node_type_to_index['SUBJECT_PROCESS'], string= process_str)
            if not G.has_node(dstnode):
                G.add_node(dstnode, type=node_type_to_index[dstnode_type], string= row['predicateobjectpath_string'])
            if G.has_edge(srcnode, dstnode):
                edge_data = G[srcnode][dstnode]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                    edge_data[edgetype]['timestamps'].append(timestamp)
                else:
                    edge_data[edgetype] = {'count': 1, 'timestamps': [timestamp]}
            else:
                G.add_edge(srcnode, dstnode, label= label, **{edgetype: {'count': 1, 'timestamps': [timestamp]}})

        if pd.notna(srcnode) and pd.notna(dstnode_2) and  label == "B":
            dstnode_2_type = row['object2_type']
            if not G.has_node(dstnode_2):
                G.add_node(dstnode_2, type=node_type_to_index[dstnode_2_type], string= row['predicateobject2path_string'])
            if G.has_edge(srcnode, dstnode_2):
                edge_data = G[srcnode][dstnode_2]
                if edgetype in edge_data:
                    edge_data[edgetype]['count'] += 1
                    edge_data[edgetype]['timestamps'].append(timestamp)
                else:
                    edge_data[edgetype] = {'count': 1, 'timestamps': [timestamp]}
            else:
                G.add_edge(srcnode, dstnode_2, label=label, **{edgetype: {'count': 1, 'timestamps': [timestamp]}})
    return G

# # 为图中每个节点构建一个基于边类型的“入度+出度”特征矩阵
# # 并用 MinMaxScaler 对所有数据进行归一化，然后保存标尺（scaler）对象
# def generate_scaler(files,path_pkl):
#     print("generate scaler")
#     x_list = []
#     for file in files:
#         G = construct_graph_from_csv(file)
#         node_id_to_index = {node_id: idx for idx, node_id in enumerate(G.nodes())}
#         num_nodes = G.number_of_nodes()
#         num_edge_types = len(edge_type_to_index)
#         # 每个节点一个向量
#         # 前一半是每种边类型的 出度
#         # 后一半是每种边类型的 入度
#         # 维度：[节点数, 边类型数 × 2]
#         x = torch.zeros((num_nodes, num_edge_types*2), dtype=torch.long)
#         for srcnode, dstnode, data in G.edges(data=True):
#             src_idx = node_id_to_index[srcnode]
#             dst_idx = node_id_to_index[dstnode]
#             for etype, attr in data.items():
#                 if etype != 'label' and etype != 'type':
#                     edge_type_index = edge_type_to_index[etype]
#                     x[src_idx, edge_type_index] += attr['count']  # 出度
#                     x[dst_idx, edge_type_index + num_edge_types] += attr['count']  # 入度
#         x_list.append(x)
#     # 使用 MinMaxScaler 做归一化
#     scaler = MinMaxScaler()
#     x = scaler.fit_transform(x)
#     # 保存归一化器
#     joblib.dump(scaler, path_pkl)

# # 先进行边的连接次数的计算以及标准化
# # 然后组合到节点属性中
# # 给图中每个节点添加一个 one-hot 向量，表示它的类型。
# def updata_node_attr_r(G):
#     # loaded_scaler = joblib.load(path_pkl)
#     for node in G.nodes():
#         attr = torch.zeros(len(node_type_to_index))
#         attr[G.nodes[node]['type']] = 1
#         G.nodes[node]['attr'] = attr

# # 为图中的每个节点构建一个组合特征向量
# # 边的统计信息（入度 + 出度），基于边类型
# # 节点字符串的词向量平均（来自 word2vec 模型）
# # 并把这个向量作为点的 'attr' 属性保存下来
# def updata_node_attr(G, model, path_pkl):
#     scaler = MinMaxScaler()
#     # loaded_scaler = joblib.load(path_pkl)

#     # edge_times = []
#     for node in G.nodes():
#         edge_time = torch.zeros(len(edge_type_to_index)*2)
#         out_edges = G.out_edges(node, data=True)
#         for _, _, data in out_edges:
#             for etype, attr in data.items():
#                 if etype != 'label':
#                     edge_type_index = edge_type_to_index[etype]
#                     edge_time[edge_type_index] += attr['count']  # 出度
#         # total_out_count = sum(edge_time[:len(edge_type_to_index)])
#         # if total_out_count > 0:
#         #     for i in range(len(edge_type_to_index)):
#         #         edge_time[i] = edge_time[i] / total_out_count
#         in_edges = G.in_edges(node, data=True)
#         for _, _, data in in_edges:
#             for etype, attr in data.items():
#                 if etype != 'label':
#                     edge_type_index = edge_type_to_index[etype]
#                     edge_time[edge_type_index + len(edge_type_to_index)] += attr['count']  # 入度
#         # edge_times.append(edge_time.numpy())
#         # total_in_count = sum(edge_time[len(edge_type_to_index):])
#         # if total_in_count > 0:
#         #     for i in range(len(edge_type_to_index), len(edge_type_to_index)*2):
#         #         edge_time[i] = edge_time[i] / total_in_count
    
#         # edge_time_scaled_np = loaded_scaler.transform(edge_time.numpy().reshape(1, -1))
#         # edge_time_scaled = torch.tensor(edge_time_scaled_np.flatten(), dtype=torch.float32)

#         scaled_np = scaler.fit_transform(edge_time.numpy().reshape(-1, 1))  
#         # scaled_np = loaded_scaler.transform(edge_time.numpy().reshape(-1, len(edge_type_to_index)*2)) 
#         edge_time_scaled = torch.from_numpy(scaled_np).flatten()

#     # edge_times_array = np.array(edge_times)
#     # scaled_edge_times = scaler.fit_transform(edge_times_array)
    
#     # for i, node in enumerate(G.nodes()):
#     #     edge_time_scaled = torch.tensor(scaled_edge_times[i], dtype=torch.float32)
        
#         if 'string' not in G.nodes[node]:
#             print(node)
#         words = G.nodes[node]['string']
#         # sentence_vector = torch.zeros(44)
#         sentence_vector = torch.zeros(46)
#         processed_corpus = simple_preprocess(words)
#         valid_word_count = 0
#         for word in processed_corpus:
#             if word in model.wv:
#                 sentence_vector += model.wv[word]
#                 valid_word_count += 1
#         if valid_word_count > 0:
#             sentence_vector /= valid_word_count

#         G.nodes[node]['attr'] = torch.cat((edge_time_scaled, sentence_vector), dim=0)

# #为图中每一条边生成一个稀疏向量，表示这条边上各个事件类型出现的次数，并把这个向量作为边的 'attr' 属性保存下来。
# def updata_edge_attr(G):
#     for src, dst, data in G.edges(data=True):
#         x = torch.zeros(len(edge_type_to_index))
#         for etype, attr in data.items():
#             if etype != 'label':
#                 edge_type_index = edge_type_to_index[etype]
#                 x[edge_type_index] = attr['count']
#         # total_sum = torch.sum(x)
#         # scaled_np = scaler.fit_transform(x.numpy().reshape(-1, 1))
#         # x_scaled = torch.from_numpy(scaled_np).flatten()
#         G.edges[src, dst]['attr'] = x #/ total_sum

def assign_edge_weights_by_event_type(G):
    """
    给图中的每条边分配统一的权重)('weight')
    权重根据事件类型和其发生次数加权计算。
    
    参数:
        G (networkx.DiGraph): 构建好的图，边上有事件类型和 count。

    返回:
        G (networkx.DiGraph): 边中新增 'weight' 属性。
    """
    # 预设事件类型对应的权重
    edge_type_weights = {
        'EVENT_EXECUTE': 3.0,
        'EVENT_WRITE': 3.0,
        'EVENT_CHANGE_PRINCIPAL': 3.0,
        'EVENT_CONNECT': 3.0,
        'EVENT_SENDTO': 3.0,
        'EVENT_SENDMSG': 3.0,
        'EVENT_RECVMSG': 3.0,
        'EVENT_RECVFROM': 3.0,
        'EVENT_FORK': 3.0,

        'EVENT_OPEN': 2.0,
        'EVENT_CREATE_OBJECT': 2.0,
        'EVENT_LINK': 2.0,
        'EVENT_MODIFY_FILE_ATTRIBUTES': 2.0,
        'EVENT_RENAME': 2.0,
        'EVENT_UNLINK': 2.0,
        'EVENT_CLOSE': 2.0,
        'EVENT_TRUNCATE': 2.0,
        'EVENT_BIND': 2.0,
        'EVENT_MMAP': 2.0,

        'EVENT_OTHER': 1.0,
        'EVENT_SIGNAL': 1.0,
        'EVENT_FCNTL': 1.0,
        'EVENT_LSEEK': 1.0,
        'EVENT_EXIT': 1.0,
        'EVENT_MODIFY_PROCESS': 1.0,
        'EVENT_FLOWS_TO': 1.0,
        'EVENT_ACCEPT': 1.0
    }

    for u, v, edge_data in G.edges(data=True):
        total_weight = 0
        for etype, attr in edge_data.items():
            if etype != 'label':  # 排除label字段
                base_weight = edge_type_weights.get(etype, 1.0)  # 默认权重为1.0
                total_weight += base_weight * attr.get('count', 1)
        G[u][v]['weight'] = total_weight

    return G

if __name__ == '__main__':
    dataset = "cadets"  #"cadets"
    #gs = []
    file_path = "../dataset/" + dataset
    #path_pkl = file_path + "/scaler.pkl"
    path_list = []
    for file in os.listdir(file_path):
        if '.csv' in file:
            path_file = file_path + '/' + file
            with open(path_file, 'r', encoding='utf-8') as file:
                    lines = file.readlines()
            # if len(lines) < 1000000:
            # for cadets 400000/9
            path_list.append(path_file)
    print(path_list)
    print(len(path_list))
   
    # files = random.sample(path_list, 18)
    # generate_scaler(files,path_pkl)

    # model_path = file_path + "/train/w2v.model"
    #model_path = "../dataset_log/"+ dataset +"/train/w2v.model"
    for file_name in path_list:
        G = construct_graph_from_csv(file_name)
        G = assign_edge_weights_by_event_type(G)
        #gs.append(G)

    with open("../data/graph.pkl", "wb") as f:
        pkl.dump(G, f)
    # test_gs = []
    # model_path = "../dataset_log/"+ dataset +"/test/w2v.model"
    # for file_name in path_list:
    #     if file_name.rsplit('/', 1)[-1].rsplit('-', 1)[0] in metadata[dataset]['test']:
    #         print(file_name)
    #         G = construct_graph_from_csv(file_name)
    #         model = Word2Vec.load(model_path)
    #         updata_node_attr(G, model, path_pkl)
    #         updata_edge_attr(G)
    #         test_gs.append(G)

    # with open('data/{}/train.pkl'.format(dataset), 'wb') as f:
    #     for train_g in train_gs:
    #         pkl.dump(nx.node_link_data(train_g), f)
    # pkl.dump([nx.node_link_data(train_g) for train_g in train_gs], open('data/{}/train.pkl'.format(dataset), 'wb'))
    #pkl.dump([nx.node_link_data(test_g) for test_g in test_gs], open('data/{}/test.pkl'.format(dataset), 'wb'))