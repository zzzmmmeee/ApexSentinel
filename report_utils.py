from pyvis.network import Network
import networkx as nx


def extract_malicious_subgraph(G, malicious_nodes, path, i):
    extracted_graph = nx.DiGraph()

    for node in malicious_nodes:
        if node in G:
            extracted_graph.add_node(node)
            neighbors = list(G.successors(node)) + list(G.predecessors(node))
            for neighbor in neighbors:
                if neighbor not in extracted_graph:
                    extracted_graph.add_node(neighbor)
            for neighbor in neighbors:
                if G.has_edge(node, neighbor):
                    extracted_graph.add_edge(node, neighbor, **G[node][neighbor])
                if G.has_edge(neighbor, node):  
                    extracted_graph.add_edge(neighbor, node, **G[neighbor][node])
    
    for node in extracted_graph.nodes():
        extracted_graph.nodes[node]['type'] = G.nodes[node]['type']
        if 'properties_map_exec' in G.nodes[node]:
            extracted_graph.nodes[node]['STR'] = G.nodes[node]['properties_map_exec']
        elif 'target_object_path' in G.nodes[node]:
            extracted_graph.nodes[node]['STR'] = G.nodes[node]['target_object_path']

    return graph_display(extracted_graph, path, i)


def graph_display(malicious_subgraph, path, i):
    
    node_colors = {
        4: '#FFDDC1',
        1: '#A0CBE2',
        0: "#ABFFD8",
    }

    node_strs = {}
    skipped_nodes = {}
    edge_labels = {}  

    net = Network(height='750px', width='100%', directed=True)

    for node in malicious_subgraph.nodes():
        node_type = malicious_subgraph.nodes[node]['type']
        node_str = malicious_subgraph.nodes[node]['STR']
        
        if node_str in node_strs:
            skipped_nodes[node] = node_strs[node_str]
            continue

        color = node_colors.get(node_type, '#A0CBE2')
        shape = 'square' if node_type == 0 else ('diamond' if node_type == 4 else 'dot') 
        
        label = malicious_subgraph.nodes[node]['STR'][:50]
        title = malicious_subgraph.nodes[node]['STR']  
        
        net.add_node(
            node,
            label=label,
            title=title,
            color=color,
            shape=shape,
            borderWidth=1,
            borderWidthSelected=2
        )

        node_strs[node_str] = node

    for u, v, data in malicious_subgraph.edges(data=True):
        label_keys = [k for k in data if k != 'weight']
        edge_label = "\n".join(label_keys)
        
        u = skipped_nodes.get(u, u)
        v = skipped_nodes.get(v, v)

        edge_key = (u, v)
        
        if edge_key in edge_labels:
            edge_labels[edge_key] += "\n" + edge_label
        else:
            edge_labels[edge_key] = edge_label

    for (u, v), label in edge_labels.items():
        net.add_edge(
            u, v,
            title=label,
            arrows='to'
        )
    
    path = path + f'malicious_graph_{i}.html'
    net.write_html(path, open_browser=False)
    return path

