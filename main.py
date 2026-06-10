import pickle
import networkx as nx
from llm_wrapper import LLMModel
import log_utils
from cot import run_cot_detection  # 假设分析函数在cot_detection.py中定义


def load_graph_from_pickle(pickle_file):
    with open(pickle_file, 'rb') as f:
        communities = pickle.load(f)
    return communities

def main():
    # 加载communities.pkl和graph.pkl文件路径
    pickle_file1 = '../data/graph.pkl'
    pickle_file = '../data/communities.pkl'  
    
    # 加载communities.pkl文件
    communities = load_graph_from_pickle(pickle_file)
    G = load_graph_from_pickle(pickle_file1)
    communities_list = list(communities.values())
    
    # 假设LLMModel已经实例化，llm_model是一个LLM模型实例
    llm_model = LLMModel()  # 实例化LLM模型，这里需要根据实际情况调整
    
    # 运行Chain-of-Thought检测分析
    alerts = run_cot_detection(communities_list, llm_model, G)
    
    # 输出警报信息到终端
    for alert in alerts:
        print("Alert:")
        print(alert)
        print("=" * 50)
    
if __name__ == "__main__":
    main()