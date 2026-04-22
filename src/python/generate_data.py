import networkx as nx
import matplotlib.pyplot as plt
import random

def generate_ids_data(num_noise=12):
    graph = nx.DiGraph()
    graph.add_edges_from([
        ("init", "svchost"), ("svchost", "shell"), ("shell", "firefox"),
        ("shell", "curl"), ("firefox", "malware.py"), ("curl", "payload.sh"),
        ("malware.py", "exfil"), ("payload.sh", "exfil")
    ])

    # 2. subgraph mining TODO: ensure this algorithm is correct and ask if it should produce multiple attack trees 
    start_node = "init"
    current = start_node
    mined_path = [current]
    
    while list(graph.successors(current)):
        current = random.choice(list(graph.successors(current)))
        mined_path.append(current)
    
    logs = []
    pid_map = {}
    next_pid = 100
    
    current_ppid = 1
    for process_name in mined_path:
        pid = next_pid
        pid_map[pid] = process_name
        
        is_target = (process_name == "shell")
        
        logs.append((pid, current_ppid, is_target))
        current_ppid = pid
        next_pid += 1

    noise_names = ["ls", "grep", "chrome", "git", "vim", "python"]
    for i in range(num_noise):
        pid = next_pid
        ppid = random.choice([1, 100, 101])
        pid_map[pid] = random.choice(noise_names)
        logs.append((pid, ppid, False))
        next_pid += 1

    return graph, logs, pid_map

def plot_separate(graph, logs, pid_map):
    plt.figure(figsize=(8, 6))
    nx.draw(graph, with_labels=True, node_color='lightgray', node_size=2000, arrowsize=20)
    plt.title("Master Attack Graph")
    plt.savefig("data/attack_graph.png")
    
    plt.figure(figsize=(10, 8))
    G_logs = nx.DiGraph()
    for pid, ppid, t in logs: 
        G_logs.add_edge(ppid, pid)
    
    colors = []
    labels = {}
    for node in G_logs:
        is_target = any(pid == node and t for pid, ppid, t in logs)
        colors.append('#ff4d4d' if is_target else '#add8e6')
        name = pid_map.get(node, "init")
        labels[node] = f"{name}\n[{node}]"

    pos = nx.shell_layout(G_logs)
    nx.draw(G_logs, pos, labels=labels, with_labels=True, node_color=colors, node_size=2500)
    plt.title("Mined Attack Tree (Red = Suspicious Shell)")
    plt.savefig("data/attack_tree.png")
    print("Plots saved as attack_graph.png and attack_tree.png")

graph, logs, pid_map = generate_ids_data()

with open("data/process_stream.log", "w") as f:
    for pid, ppid, target in sorted(logs):
        f.write(f"{pid} {ppid} {1 if target else 0}\n")

plot_separate(graph, logs, pid_map)