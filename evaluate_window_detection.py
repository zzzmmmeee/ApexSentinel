import networkx as nx
import os
import pickle as pkl
import config

def load_node_set_from_file(file_path):
    nodes = set()
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Node:"):
                uuid = line.split(",")[0].replace("Node:", "").strip()
            else:
                uuid = line.strip()
            nodes.add(uuid)
    return nodes

def get_2hop_neighbors(G, node):
    if node not in G:
        return set()
    hop1 = set(nx.ancestors(G, node)) | set(nx.descendants(G, node))
    hop2 = set()
    for n in hop1:
        hop2.update(nx.ancestors(G, n))
        hop2.update(nx.descendants(G, n))
    return hop1 | hop2

def get_2hop_neighbors_of_all_nodes(G, nodes):
    expanded_nodes = set()
    for node in nodes:
        neighborhood = get_2hop_neighbors(G, node)
        expanded_nodes.update(neighborhood)
        expanded_nodes.add(node)
    
    return expanded_nodes

def compute_detection_metrics(predicted_nodes, ground_truth_nodes, all_nodes, G, test=False):
    if test:
        tp_set = set()
        for node in predicted_nodes:
            if node in ground_truth_nodes:
                tp_set.add(node)

        fp_set = predicted_nodes - tp_set
        fn_set = ground_truth_nodes - tp_set
        tn_set = all_nodes - ground_truth_nodes - fp_set

        return {
            "TP": len(tp_set),
            "FP": len(fp_set),
            "FN": len(fn_set),
            "TN": len(tn_set),
            "Precision": len(tp_set) / (len(tp_set) + len(fp_set) + 1e-8),
            "Recall": len(tp_set) / (len(tp_set) + len(fn_set) + 1e-8),
            "F1": 2 * len(tp_set) / (2 * len(tp_set) + len(fp_set) + len(fn_set) + 1e-8),
            "TP_UUIDs": tp_set,
            "FP_UUIDs": fp_set
        }
    
    else:
        expanded_predicted = set()
        for node in predicted_nodes:
            neighborhood = get_2hop_neighbors(G, node)
            expanded_predicted.update(neighborhood)
            expanded_predicted.add(node)
        
        tp_set = set()
        for node in expanded_predicted:
            if node in ground_truth_nodes:
                tp_set.add(node)

        fp_set = expanded_predicted - tp_set
        fn_set = ground_truth_nodes - tp_set
        tn_set = all_nodes - ground_truth_nodes - fp_set

        return {
            "TP": len(tp_set),
            "FP": len(fp_set),
            "FN": len(fn_set),
            "TN": len(tn_set),
            "Precision": len(tp_set) / (len(tp_set) + len(fp_set) + 1e-8),
            "Recall": len(tp_set) / (len(tp_set) + len(fn_set) + 1e-8),
            "F1": 2 * len(tp_set) / (2 * len(tp_set) + len(fp_set) + len(fn_set) + 1e-8),
            "TP_UUIDs": tp_set,
            "FP_UUIDs": fp_set
        }

def write_result_nodes(tp_set, fp_set, output_dir="./result_new"):
    os.makedirs(output_dir, exist_ok=True)
    with open(f"{output_dir}/tp.txt", "w") as f:
        for uuid in sorted(tp_set):
            f.write(f"{uuid}\n")
    with open(f"{output_dir}/fp.txt", "w") as f:
        for uuid in sorted(fp_set):
            f.write(f"{uuid}\n")

def write_fp(fp_set, output_path, count_path):
    existing_uuids = set()
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            for line in f:
                existing_uuids.add(line.strip())

    new_uuids = sorted(set(fp_set) - existing_uuids)
    with open(output_path, "a") as f:
        for uuid in new_uuids:
            f.write(f"{uuid}\n")
    with open(count_path, "a") as f:
        f.write(f"New False Positives This Round: {len(new_uuids)}\n")

    print(f"新增写入 {len(new_uuids)} 个假正例 UUID 到 {output_path}")

def write_all_malicious_nodes(all_malicious_nodes, output_path):
    with open(output_path, "a") as f:
        for uuid in all_malicious_nodes:
            f.write(f"{uuid}\n")

def write_tp(tp_set, output_path="./result_new3/tp_detail.txt", 
                    count_path="./result_new3/tp_detail_count.txt"):
    existing_uuids = set()
    if os.path.exists(output_path):
        with open(output_path, "r") as f:
            for line in f:
                existing_uuids.add(line.strip())

    new_uuids = sorted(set(tp_set) - existing_uuids)

    with open(output_path, "a") as f:
        for uuid in new_uuids:
            f.write(f"{uuid}\n")

    with open(count_path, "a") as f:
        f.write(f"New True Positives This Round: {len(new_uuids)}\n")

    print(f"新增写入 {len(new_uuids)} 个真正例 UUID 到 {output_path}")



def evaluate_detection(alert_file_path, ground_truth_file_path, G, output_dir="./result_new", test=False):
    predicted_nodes = load_node_set_from_file(alert_file_path)
    ground_truth_nodes = load_node_set_from_file(ground_truth_file_path)
    all_nodes = set(G.nodes)
    metrics = compute_detection_metrics(predicted_nodes, ground_truth_nodes, all_nodes, G, test=test)
    print("\n===== Detection Evaluation Result =====")
    for k, v in metrics.items():
        if k.endswith("_UUIDs"):
            continue
        print(f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}")

    return metrics

def write_tp_and_fp(alert_file_path, ground_truth_file_path, G, i, all_malicious_nodes=[]):
    predicted_nodes = load_node_set_from_file(alert_file_path)
    ground_truth_nodes = load_node_set_from_file(ground_truth_file_path)
    all_nodes = set(G.nodes)

    metrics = compute_detection_metrics(predicted_nodes, ground_truth_nodes, all_nodes, G)

    write_fp(metrics["FP_UUIDs"], 
            output_path="./result/fp_detail.txt", 
            count_path="./result/fp_detail_count.txt")
    
    write_tp(metrics["TP_UUIDs"], 
            output_path="./result/tp_detail.txt", 
            count_path="./result/tp_detail_count.txt")
    
    

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--alert_file_path', type=str, default='./result/predict.txt')  
    args = parser.parse_args()
    
    alert_file_path = args.alert_file_path
    if config.theia == 1:
        ground_truth_file_path = "./dataset/theia.txt"
        with open(f"./graph_theia/graph.pkl", "rb") as f:
            G = pkl.load(f)
    else:
        ground_truth_file_path = "./dataset/cadets.txt"
        with open(f"./graph_cadets/graph.pkl", "rb") as f:
            G = pkl.load(f)
    evaluate_detection(alert_file_path, ground_truth_file_path, G, test=True)

