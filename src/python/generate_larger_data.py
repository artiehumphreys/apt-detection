import networkx as nx
import matplotlib.pyplot as plt
import random

def generate_ids_research_pipeline():
    attack_graph = nx.DiGraph()
    core_edges = [
        ("svchost.exe", "firefox.exe"), ("cmd.exe", "firefox.exe"), 
        ("firefox.exe", "*.exe"), ("*.exe", "pswd.txt"), 
        ("svchost.exe", "*.250"), ("firefox.exe", "malware.py")
    ]
    attack_graph.add_edges_from(core_edges)

    # --- inject 2,000,000 benign processes (firefox and cmd.exe) ---
    for i in range(1000000):
        attack_graph.add_edge("firefox.exe", f"browser_{i}.exe")
        attack_graph.add_edge("cmd.exe", f"shell_{i}.exe")

    global_pid_map = {}
    next_pid = 100
    for node in sorted(attack_graph.nodes()):
        global_pid_map[node] = next_pid
        next_pid += 1
    inv_pid_map = {v: k for k, v in global_pid_map.items()}

    mined_graph = nx.DiGraph()
    parents = [n for n, d in attack_graph.out_degree() if d > 0]
    target_names = ["malware.py", "pswd.txt"]
    
    log_entries = []

    # add (PID 0 0) for each root to beginning of log
    for parent_name in parents:
        parent_pid = global_pid_map[parent_name]
        log_entries.append((parent_pid, 0, 0))

    for parent_name in parents:
        parent_pid = global_pid_map[parent_name]
        for child_name in attack_graph.successors(parent_name):
            child_pid = global_pid_map[child_name]
            mined_graph.add_edge(parent_pid, child_pid)
            
            is_seed = 1 if child_name in target_names else 0
            log_entries.append((child_pid, parent_pid, is_seed))

    init_entries = [e for e in log_entries if e[1] == 0]
    stream_entries = sorted([e for e in log_entries if e[1] != 0])
    
    final_log_path = "data/big_log.txt"
    with open(final_log_path, "w") as f:
        for pid, ppid, s in init_entries:
            f.write(f"{pid} {ppid} {s}\n")
        for pid, ppid, s in stream_entries:
            f.write(f"{pid} {ppid} {s}\n")
            
    print(f"Generated unified log: {final_log_path} with {len(log_entries)} entries.")

    return attack_graph, mined_graph, global_pid_map, inv_pid_map, target_names

def save_plots(attack_graph, mined_graph, global_pid_map, inv_pid_map, target_names):
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
                for node, dist in lengths.items(): H.nodes[node]['subset'] = dist
            for node in H.nodes():
                if 'subset' not in H.nodes[node]: H.nodes[node]['subset'] = 0
            pos = nx.multipartite_layout(H, subset_key="subset", align='horizontal')
        except:
            pos = nx.spring_layout(H, k=1.5, seed=42)

        for node in H.nodes():
            name = node if is_master else pid_lookup[node]
            pid = pid_lookup[node] if is_master else node
            color, shape = get_node_style(name)
            nx.draw_networkx_nodes(H, pos, ax=ax, nodelist=[node], node_color=color, 
                                   node_shape=shape, node_size=7500, edgecolors='black', linewidths=1.5)
            nx.draw_networkx_labels(H, pos, ax=ax, labels={node: f"{name}\nPID: {pid}"}, font_size=9, font_weight='bold')
        nx.draw_networkx_edges(H, pos, ax=ax, node_size=9000, arrowsize=30, width=2, edge_color='#444444')

    core_nodes = ["svchost.exe", "firefox.exe", "cmd.exe", "*.exe", "pswd.txt", "*.250", "malware.py"]
    viz_noise = random.sample([n for n in attack_graph.nodes() if "_" in n], 5)
    viz_master = attack_graph.subgraph(core_nodes + viz_noise)

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
        all_children = list(attack_graph.successors(p_name))
        viz_children = [c for c in all_children if "_" not in c] + [c for c in all_children if "_" in c][:3]
        star_nodes = [p_pid] + [global_pid_map[c] for c in viz_children]
        subtree = mined_graph.subgraph(star_nodes)
        draw_styled_graph(subtree, inv_pid_map, ax=axes[i], is_master=False)
        axes[i].set_title(f"Subtree {i+1}: {p_name}", fontsize=16, fontweight='bold')
        axes[i].axis('off')

    plt.savefig("data/larger_attack_trees.png", dpi=300, bbox_inches='tight')
    plt.close()

if __name__ == "__main__":
    m, mg, gpm, ipm, tn = generate_ids_research_pipeline()
    save_plots(m, mg, gpm, ipm, tn)