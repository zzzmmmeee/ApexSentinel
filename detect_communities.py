import networkx as nx
import pickle as pkl
from community import community_louvain

def detect_communities(nx_graph):
    partition = community_louvain.best_partition(nx_graph.to_undirected(), weight='weight', resolution=1)
    
    communities = {}
    max_partition = 0

    for i in partition:
        if partition[i] > max_partition:
            max_partition = partition[i]
    
    for i in range(max_partition + 1):
        communities[i] = nx.DiGraph()

    for u, v, data in nx_graph.edges(data=True): 

        if u not in communities[partition[u]].nodes:
            communities[partition[u]].add_node(u, **nx_graph.nodes[u])     
        if v not in communities[partition[u]].nodes:
            communities[partition[u]].add_node(v, **nx_graph.nodes[v])
           

        if u not in communities[partition[v]].nodes:
            communities[partition[v]].add_node(u, **nx_graph.nodes[u])
        if v not in communities[partition[v]].nodes:
            communities[partition[v]].add_node(v, **nx_graph.nodes[v])
            
        communities[partition[u]].add_edge(u, v, **data)  
        communities[partition[v]].add_edge(u, v, **data)  

    print(f"{max_partition+1} communities detected.")
    
    return communities, max_partition

if __name__ == '__main__':
    with open("./graph15.pkl", "rb") as f:
        G = pkl.load(f)
    
    communities, max_partition = detect_communities(G)

    for community_id, community_graph in communities.items():
        print(f"Community {community_id}: {len(community_graph)} nodes")

    with open("./communities15.pkl", "wb") as f:
        pkl.dump(communities, f)