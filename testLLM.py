import os
import pickle as pkl
import networkx as nx
from data_parser2 import construct_graph, assign_edge_weights_by_event_type, construct_graph2, assign_edge_weights_by_event_type2
from detect_communities import detect_communities
from cot import analyze_process_patterns, analyze_community, generate_llm_report
from log_utils import *
from llm_wrapper import LLMModel
from llm_api import DashScopeLLMClient
from evaluate_window_detection import evaluate_detection, write_tp_and_fp, get_2hop_neighbors_of_all_nodes
import copy
import json
from report_utils import extract_malicious_subgraph
from django.conf import settings
import token_count
import config

def dynamic_score_adjustment(G, decay_rate=0.3, reinforcement_threshold=0.7):
    for node in G.nodes:
        if 'suspicion_score' not in G.nodes[node]:
            continue
            
        current_score = G.nodes[node]['suspicion_score']
        new_score = current_score * (1 - decay_rate)  
        
        if (current_score >= reinforcement_threshold and 
            G.nodes[node].get('recent_evidence', False)):
            new_score = min(current_score + 0.1, 1.0)  
            
        G.nodes[node]['suspicion_score'] = max(new_score, 0)  

def test_single_window(log_file,llm_model,i):
    G = nx.DiGraph()
    G, new_src = construct_graph2(log_file,G)
    G = assign_edge_weights_by_event_type2(G)

    G_orignal = copy.deepcopy(G)
    
    flag = True
    while flag:
        G, flag = merge_file_nodes(G)

    communities, max_partition = detect_communities(G)
    
    for community_id, community_graph in communities.items():
        print(f"Community {community_id}: {len(community_graph)} nodes")

    score_dict = {}
    score_dicts = []
    behavior_summaries = {}
    for community_id, community in communities.items():
        suspicious_processes, temporal_patterns, process_scores = analyze_process_patterns(community, llm_model)
        print("Finish analyzing each process in the community")
        if len(suspicious_processes) == 0:
            continue

        community_scores = analyze_community(suspicious_processes, temporal_patterns, community, llm_model)
        print("Finish analyzing the entire community")

        for process_uuid, severity in community_scores.items():
            process_scores[process_uuid] = severity 
        
        score_dicts.append(process_scores)
     
    score_dict = merge_dicts_with_max(score_dicts) 
    print(score_dict)
    
    G_orignal = update_and_propagate_scores(G_orignal, score_dict)

    threshold = 0.8 

    malicious_nodes = [
        node for node in G_orignal.nodes 
        if G_orignal.nodes[node].get('suspicion_score', 0) >= threshold
    ]
    malicious_nodes2 = get_2hop_neighbors_of_all_nodes(G_orignal, malicious_nodes)

    if len(malicious_nodes2) > 0:
        print("Warning: There may be APT attack activities in this window!")
        print(f"Number of malicious nodes detected in window {i}: {len(malicious_nodes2)}")
        generate_llm_report(
            window_id=i,
            malicious_nodes=malicious_nodes,
            graph=G_orignal,
            llm_model=llm_model,
            behavior_summaries=behavior_summaries  
        )
        extract_malicious_subgraph(G_orignal, malicious_nodes) 


    print("Write highly suspicious nodes into a file.")
    


def time_correlation(directory, llm_model, input_graph=''):
    entries = os.listdir(directory)
    log_files = []

    #num = 0
    for file in entries:
        if file.startswith("split15m_") and file.endswith(".txt"):
            # log_files.append((num, file))
            # num += 1
            try:
                num = int(file[len("split15m_"):-len(".txt")])
                # if 0 <= num <= 0:  
                log_files.append((num, file))
                # for i in range(num):
                #    log_files.append((num, file))
            except ValueError:
                continue

    sorted_log_files = [file for num, file in sorted(log_files, key=lambda x: x[0])]
    print("Sequence of log files to be processed: ", sorted_log_files)

    i = 0 
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = os.path.join("code", "reports", now)
    os.makedirs(f"./graphs{now}", exist_ok=True)
    # report_path = f"./reports{now}"
    report_path = os.path.join(base_dir, "reports")
    os.makedirs(report_path, exist_ok=True)
    # visualize_path = f"./visualize{now}"
    visualize_path = os.path.join(base_dir, "visualize")
    os.makedirs(visualize_path, exist_ok=True)
    # graph_dir = os.path.join(settings.BASE_DIR, 'analyzer', 'tmp', 'graphs')
    # os.makedirs(graph_dir, exist_ok=True)
    theia = config.theia
    for log_file in sorted_log_files:
        # prev_graph_path = os.path.join(graph_dir, f"graph_{i-1}.pkl")
        if input_graph != '':
            with open(input_graph, "rb") as f:
                G = pkl.load(f)
        elif theia == 0:
            G = nx.DiGraph()
            log_file = os.path.join(directory, log_file)
            G, new_src = construct_graph(log_file, G) #theia
            G = assign_edge_weights_by_event_type(G) #theia
        else:
            if os.path.exists(f"./graphs{now}/graph_{i-1}.pkl"):
                with open(f"./graphs{now}/graph_{i-1}.pkl", "rb") as f:
                    G = pkl.load(f)

            else:
                G = nx.DiGraph()
        
            log_file = os.path.join(directory, log_file)
            G, new_src = construct_graph2(log_file, G) #theia
            G = assign_edge_weights_by_event_type2(G) #theia
        
        G_orignal = copy.deepcopy(G)

        flag = True
        while flag:
            G, flag = merge_file_nodes(G)

        communities, max_partition = detect_communities(G)
        
        score_dicts = []
        behavior_summaries = {}  
        for community_id, community in communities.items():
            if input_graph == '':
                if not any(node in new_src for node in community.nodes): #fenghuo暂时删去
                    continue

            suspicious_processes, temporal_patterns, process_scores = analyze_process_patterns(community, llm_model)
            if not suspicious_processes:
                continue

            for pid in temporal_patterns:
                behavior_summaries[pid] = temporal_patterns.get(pid, "Behavior not recorded")
                if pid in G.nodes:
                    G.nodes[pid]['recent_evidence'] = True
                
            community_scores = analyze_community(suspicious_processes, temporal_patterns, community, llm_model)

            for process_uuid, severity in community_scores.items():
                process_scores[process_uuid] = severity
            score_dicts.append(process_scores)
        
        score_dict = merge_dicts_with_max(score_dicts)
        G_orignal = update_and_propagate_scores(G_orignal, score_dict) 

        total_nodes = len(G_orignal.nodes)
        malicious_nodes = [
            node for node in G_orignal.nodes 
            if G_orignal.nodes[node].get('suspicion_score', 0) >= 0.8
        ]
        malicious_nodes2 = get_2hop_neighbors_of_all_nodes(G_orignal, malicious_nodes)
        malicious_ratio = len(malicious_nodes2) / total_nodes if total_nodes > 0 else 0
        
        alert_nodes = [
            node for node in G_orignal.nodes 
            if G_orignal.nodes[node].get('suspicion_score', 0) >= 0.8
        ]

        
        os.makedirs(f"./result{now}", exist_ok=True)
        result_dir = f"./result{now}"
        os.makedirs(result_dir, exist_ok=True)

        with open(os.path.join(result_dir, f"alert_{i}.txt"), "a") as f:
             for node in alert_nodes:
                 f.write(f"{node}\n")
        
        write_tp_and_fp(f"./result{now}/alert_{i}.txt", "./dataset/cadets.txt", G_orignal, i, malicious_nodes2)

        # report
        if len(malicious_nodes) > 0:
            print("Warning: There may be APT attack activities in this window!")
            print(f"Number of malicious nodes detected in window {i}: {len(malicious_nodes2)}")
            report_path = generate_llm_report(
                window_id=i,
                malicious_nodes=malicious_nodes,
                graph=G_orignal,
                llm_model=llm_model,
                behavior_summaries=behavior_summaries,
                path = report_path 
            )
            graph_path = extract_malicious_subgraph(G_orignal, malicious_nodes, visualize_path, i) 

        with open(f"./graphs{now}/graph-mid.pkl", "wb") as f:
            pkl.dump(G_orignal, f)
        
        with open(f"./graphs{now}/behavior_summaries.pkl", "wb") as f:
            pkl.dump(behavior_summaries, f)

        low_score_nodes = [
            node for node in G_orignal.nodes 
            if G_orignal.nodes[node].get('suspicion_score', 0) <= 0.5 
        ]
        for node in low_score_nodes:
            G_orignal.remove_node(node)
        
        dynamic_score_adjustment(G_orignal, decay_rate=0.3, reinforcement_threshold=0.7) 
        
        with open(f"./graphs{now}/graph_{i}.pkl", "wb") as f:
            pkl.dump(G_orignal, f)

        i += 1

        print("Prompt tokens:", token_count.get_prompt())
        print("Output tokens:", token_count.get_output())
        print("Total tokens:", token_count.get_total())

        if input_graph != '':
            break


    
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--single_log', type=str, default='')  
    parser.add_argument('--multi_dir', type=str, default='')
    args = parser.parse_args()

    llm_model = LLMModel()

    token_count.reset()
    if args.single_log:
        test_single_window(args.single_log, llm_model, 83)

    elif args.multi_dir:
        time_correlation(directory=args.multi_dir, llm_model=llm_model)

    else:
        time_correlation(directory="./dataset/split_cadets", llm_model=llm_model)

    



