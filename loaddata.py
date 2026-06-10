import pickle as pkl
import time
import torch.nn.functional as F
import dgl
import networkx as nx
import json
from tqdm import tqdm
import os


def transform_graph(g, node_feature_dim, edge_feature_dim):
    new_g = g.clone()
    new_g.ndata["attr"] = F.one_hot(g.ndata["type"].view(-1), num_classes=node_feature_dim).float()
    new_g.edata["attr"] = F.one_hot(g.edata["type"].view(-1), num_classes=edge_feature_dim).float()
    return new_g


def preload_entity_level_dataset(path):
    path = './data/' + path
    if os.path.exists(path + '/metadata.json'):
        pass
    else:
        print('transforming')
        # train_gs = [dgl.from_networkx(
        #     nx.node_link_graph(g),
        #     node_attrs=['attr'],
        #     edge_attrs=['attr']
        # ) for g in pkl.load(open(path + '/train.pkl', 'rb'))]
        train_gs = []
        train_node_types = []
        # for g in pkl.load(open(path + '/train.pkl', 'rb')):
        #     dgl_g = dgl.from_networkx(
        #         nx.node_link_graph(g), node_attrs=['attr', 'type'], edge_attrs=['attr'])
        #     train_gs.append(dgl_g)
        #     graph_node_types = dgl_g.ndata['type'].tolist()
        #     train_node_types.append(graph_node_types)
        with open(path + '/train.pkl', 'rb') as f:
            while True:
                try:
                    g = pkl.load(f)
                    dgl_g = dgl.from_networkx(
                        nx.node_link_graph(g), node_attrs=['attr', 'type'], edge_attrs=['attr'])
                    train_gs.append(dgl_g)
                    graph_node_types = dgl_g.ndata['type'].tolist()
                    train_node_types.append(graph_node_types)
                except EOFError:
                    break 
        print('transforming')
        test_gs = []
        test_node_types = []
        for g in pkl.load(open(path + '/test.pkl', 'rb')):
            dgl_g = dgl.from_networkx(
                nx.node_link_graph(g), node_attrs=['attr', 'type'], edge_attrs=['attr'])
            test_gs.append(dgl_g)
            graph_node_types = dgl_g.ndata['type'].tolist()
            test_node_types.append(graph_node_types)
        # malicious = pkl.load(open(path + '/malicious.pkl', 'rb'))

        node_feature_dim = train_gs[0].ndata["attr"][0].shape
        edge_feature_dim = train_gs[0].edata["attr"][0].shape
        result_test_gs = []
        for g in test_gs:
            result_test_gs.append(g)
        result_train_gs = []
        for g in train_gs:
            result_train_gs.append(g)
        metadata = {
            'node_feature_dim': node_feature_dim,
            'edge_feature_dim': edge_feature_dim,
            # 'malicious': malicious,
            'n_train': len(result_train_gs),
            'n_test': len(result_test_gs)
        }

        with open(path + '/metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f)
        for i, g in enumerate(result_train_gs):
            with open(path + '/train{}.pkl'.format(i), 'wb') as f:
                pkl.dump(g, f)
        for i, label in enumerate(train_node_types):
            with open(path + '/train_label{}.txt'.format(i), 'w') as f:
                for item in label:
                    f.write(f"{item}\n")
        for i, g in enumerate(result_test_gs):
            with open(path + '/test{}.pkl'.format(i), 'wb') as f:
                pkl.dump(g, f)
        for i, label in enumerate(test_node_types):
            with open(path + '/test_label{}.txt'.format(i), 'w') as f:
                for item in label:
                    f.write(f"{item}\n")


def preload_entity_level_test_dataset(path):
    path = './data/' + path
    if os.path.exists(path + '/selected_metadata.json'):
        # print(path + '/selected_metadata.json')
        pass
    else:
        print('transforming')
        train_gs = []
        train_node_types = []
        train_node_labels = []
        for g in pkl.load(open(path + '/selected.pkl', 'rb')):
            dgl_g = dgl.from_networkx(
                        nx.node_link_graph(g),
                        node_attrs=['attr', 'type', 'label', 'nodeID'],
                        edge_attrs=['attr']
                    )
            train_gs.append(dgl_g)
            graph_node_types = dgl_g.ndata['type'].tolist()
            graph_node_labels = dgl_g.ndata['label'].tolist()
            train_node_types.append(graph_node_types)
            train_node_labels.append(graph_node_labels)

        node_feature_dim = train_gs[0].ndata["attr"][0].shape
        edge_feature_dim = train_gs[0].edata["attr"][0].shape
        result_train_gs = []
        for g in train_gs:
            result_train_gs.append(g)
        metadata = {
            'node_feature_dim': node_feature_dim,
            'edge_feature_dim': edge_feature_dim,
            'n_train': len(result_train_gs),
        }

        with open(path + '/selected_metadata.json', 'w', encoding='utf-8') as f:
            json.dump(metadata, f)
        for i, g in enumerate(result_train_gs):
            with open(path + '/selected{}.pkl'.format(i), 'wb') as f:
                pkl.dump(g, f)
        for i, type in enumerate(train_node_types):
            with open(path + '/selected_type{}.txt'.format(i), 'w') as f:
                for item in type:
                    f.write(f"{item}\n")
        for i, label in enumerate(train_node_labels):
            with open(path + '/selected_label{}.txt'.format(i), 'w') as f:
                for item in label:
                    f.write(f"{item}\n")


def load_metadata(path):
    preload_entity_level_dataset(path)
    with open('./data/' + path + '/metadata.json', 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    return metadata


def load_selected_metadata(path):
    preload_entity_level_test_dataset(path)
    with open('./data/' + path + '/selected_metadata.json', 'r', encoding='utf-8') as f:
        metadata = json.load(f)
    return metadata


def load_entity_level_dataset(path, t, n):
    preload_entity_level_dataset(path)
    with open('./data/' + path + '/{}{}.pkl'.format(t, n), 'rb') as f:
        data = pkl.load(f)
    with open('./data/' + path + '/{}_label{}.txt'.format(t, n), 'r') as f: 
        label = [int(line.strip()) for line in f]
    return data, label


def load_entity_level_selected_dataset(path, t, n):
    preload_entity_level_test_dataset(path)
    with open('./data/' + path + '/{}{}.pkl'.format(t, n), 'rb') as f:
        data = pkl.load(f)
    with open('./data/' + path + '/{}_type{}.txt'.format(t, n), 'r') as f: 
        type = [int(line.strip()) for line in f]
    with open('./data/' + path + '/{}_label{}.txt'.format(t, n), 'r') as f: 
        label = [int(line.strip()) for line in f]
    return data, type, label
