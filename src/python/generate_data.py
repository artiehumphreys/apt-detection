import networkx as nx
import matplotlib.pyplot as plt
import pygraphviz

def generate_ids_research_pipeline():
    master = nx.DiGraph()
    core_edges = [
        ("svchost.exe", "firefox.exe"), ("cmd.exe", "firefox.exe"), 
        ("firefox.exe", "*.exe"), ("*.exe", "pswd.txt"), 
        ("svchost.exe", "*.250"), ("firefox.exe", "malware.py")
    ]
    master.add_edges_from(core_edges)

    global_pid_map = {}
    next_pid = 100
    for node in sorted(master.nodes()):
        global_pid_map[node] = next_pid
        next_pid += 1
    
    inv_pid_map = {v: k for k, v in global_pid_map.items()}

    mined_graph = nx.DiGraph()
    parents = [n for n, d in master.out_degree() if d > 0]
    target_names = ["malware.py", "pswd.txt"]

    for i, parent_name in enumerate(parents):
        parent_pid = global_pid_map[parent_name]
        subtree_logs = []
        
        for child_name in master.successors(parent_name):
            child_pid = global_pid_map[child_name]
            mined_graph.add_edge(parent_pid, child_pid)
            
            is_seed = 1 if child_name in target_names else 0
            subtree_logs.append((child_pid, parent_pid, is_seed))
        
        filename = f"data/subtree_{i+1}_{parent_name}.log"
        with open(filename, "w") as f:
            for pid, ppid, s in sorted(subtree_logs):
                f.write(f"{pid} {ppid} {s}\n")
        print(f"Generated: {filename}")

    return master, mined_graph, global_pid_map, inv_pid_map, target_names

def save_plots(master, mined_graph, global_pid_map, inv_pid_map, target_names):

    def get_node_style(name):
        if name in target_names:
            return '#67bc36', 's'  # Green Rectangle
        elif name == "*.250":
            return '#03bfc1', 'd'  # Teal Diamond
        else:
            return '#ff914d', 'o'  # Orange Circle

    def draw_styled_graph(G, pid_lookup, ax=None, is_master=False):
        pos = nx.nx_agraph.graphviz_layout(G, prog='dot')

        labels = {}
        for node in G.nodes():
            name = node if is_master else pid_lookup[node]
            pid = pid_lookup[node] if is_master else node
            
            color, shape = get_node_style(name)
            labels[node] = f"{name}\nPID: {pid}"
            
            nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=[node], 
                                   node_color=color, node_shape=shape, 
                                   node_size=7500, edgecolors='black', linewidths=1.5)
        
        nx.draw_networkx_labels(G, pos, ax=ax, labels=labels, 
                                font_size=10, font_weight='bold')
        nx.draw_networkx_edges(G, pos, ax=ax, node_size=9000, arrowsize=30, width=2, edge_color='#444444', min_target_margin=12)

    plt.figure(figsize=(12, 10))
    draw_styled_graph(master, global_pid_map, is_master=True)
    plt.title("Attack Graph", fontsize=18, fontweight='bold')
    plt.axis('off')
    plt.savefig("data/attack_graph.png", dpi=300, bbox_inches='tight')
    plt.close()

    parents = [n for n, d in master.out_degree() if d > 0]
    fig, axes = plt.subplots(1, len(parents), figsize=(32, 12))

    for i, parent_name in enumerate(parents):
        parent_pid = global_pid_map[parent_name]
        star_nodes = [parent_pid] + [global_pid_map[c] for c in master.successors(parent_name)]
        subtree = mined_graph.subgraph(star_nodes)
        
        ax = axes[i]
        draw_styled_graph(subtree, inv_pid_map, ax=ax, is_master=False)
        ax.set_title(f"Subtree {i+1}: {parent_name} Star", fontsize=16, fontweight='bold')
        ax.axis('off')

    plt.suptitle("Mined Attack Trees", fontsize=24, fontweight='bold', y=0.98)
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig("data/attack_trees.png", dpi=300, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    m, mg, gpm, ipm, tn = generate_ids_research_pipeline()
    save_plots(m, mg, gpm, ipm, tn)
    print("Saved plots and log.")