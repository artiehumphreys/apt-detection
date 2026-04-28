import networkx as nx
import matplotlib.pyplot as plt
import random

def generate_ids_research_pipeline():
    master = nx.DiGraph()
    core_edges = [
        ("svchost.exe", "firefox.exe"), ("cmd.exe", "firefox.exe"), 
        ("firefox.exe", "*.exe"), ("*.exe", "pswd.txt"), 
        ("svchost.exe", "*.250"), ("firefox.exe", "malware.py")
    ]
    master.add_edges_from(core_edges)

    # --- add 1,000,000 benign processes ---
    noise_pool = ["ls", "grep", "vim", "python", "git", "awk", "sed", "chrome-render"]
    for i in range(1000000):
        noise_proc = f"{random.choice(noise_pool)}_{i}.exe"
        master.add_edge("firefox.exe", noise_proc)

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
        
        filename = f"data/larger_subtree_{i+1}_{parent_name}.log"
        with open(filename, "w") as f:
            for pid, ppid, s in sorted(subtree_logs):
                f.write(f"{pid} {ppid} {s}\n")
        print(f"Generated: {filename} ({len(subtree_logs)} entries)")

    return master, mined_graph, global_pid_map, inv_pid_map, target_names

def save_plots(master, mined_graph, global_pid_map, inv_pid_map, target_names):

    def get_node_style(name):
        if name in target_names: return '#67bc36', 's'
        elif name == "*.250": return '#03bfc1', 'd'
        else: return '#ff914d', 'o'

    def draw_styled_graph(G, pid_lookup, ax=None, is_master=False):
        H = G.copy()
        
        try:
            roots = [n for n, d in H.in_degree() if d == 0]
            for root in roots:
                lengths = nx.single_source_shortest_path_length(H, root)
                for node, dist in lengths.items():
                    H.nodes[node]['subset'] = dist
            
            for node in H.nodes():
                if 'subset' not in H.nodes[node]:
                    H.nodes[node]['subset'] = 0
                    
            pos = nx.multipartite_layout(H, subset_key="subset", align='horizontal')
        except:
            pos = nx.spring_layout(H, k=1.5, seed=42)

        labels = {}
        for node in H.nodes():
            name = node if is_master else pid_lookup[node]
            pid = pid_lookup[node] if is_master else node
            color, shape = get_node_style(name)
            labels[node] = f"{name}\nPID: {pid}"
            
            nx.draw_networkx_nodes(H, pos, ax=ax, nodelist=[node], 
                                   node_color=color, node_shape=shape, 
                                   node_size=7500, edgecolors='black', linewidths=1.5)
        
        nx.draw_networkx_labels(H, pos, ax=ax, labels=labels, font_size=9, font_weight='bold')
        nx.draw_networkx_edges(H, pos, ax=ax, node_size=9000, arrowsize=30, width=2, edge_color='#444444')

    core_nodes = ["svchost.exe", "firefox.exe", "cmd.exe", "*.exe", "pswd.txt", "*.250", "malware.py"]
    viz_noise = random.sample([n for n in master.nodes() if "_" in n], 5) # limit to 5 extra nodes
    viz_master = master.subgraph(core_nodes + viz_noise)

    plt.figure(figsize=(14, 12))
    draw_styled_graph(viz_master, global_pid_map, is_master=True)
    plt.title("Master Attack Graph", fontsize=18, fontweight='bold')
    plt.axis('off')
    plt.savefig("data/larger_attack_graph.png", dpi=300, bbox_inches='tight')
    plt.close()

    parents = ["svchost.exe", "firefox.exe", "cmd.exe", "*.exe"]
    fig, axes = plt.subplots(1, len(parents), figsize=(36, 12))

    for i, p_name in enumerate(parents):
        p_pid = global_pid_map[p_name]
        all_children = list(master.successors(p_name))
        viz_children = [c for c in all_children if "_" not in c] + [c for c in all_children if "_" in c][:2]
        star_nodes = [p_pid] + [global_pid_map[c] for c in viz_children]
        subtree = mined_graph.subgraph(star_nodes)
        
        draw_styled_graph(subtree, inv_pid_map, ax=axes[i], is_master=False)
        axes[i].set_title(f"Subtree {i+1}: {p_name}", fontsize=16, fontweight='bold')
        axes[i].axis('off')

    plt.suptitle("Mined Attack Trees", fontsize=24, fontweight='bold', y=0.98)
    plt.savefig("data/larger_attack_trees.png", dpi=300, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    m, mg, gpm, ipm, tn = generate_ids_research_pipeline()
    save_plots(m, mg, gpm, ipm, tn)
    print("Graphs and logs generated successfully.")