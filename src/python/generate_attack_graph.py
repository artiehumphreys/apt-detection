import networkx as nx
import matplotlib.pyplot as plt
import random

def generate_ids_pipeline(num_noise=10):
    # 1. MASTER ATTACK GRAPH (Threat Model)
    # This defines all potential malicious activity.
    master_graph = nx.DiGraph()
    master_graph.add_edges_from([
        ("root", "shell"),
        ("shell", "firefox"),
        ("shell", "curl"),
        ("firefox", "malware.py"),
        ("curl", "payload.sh"),
        ("malware.py", "exfil_data"),
        ("payload.sh", "exfil_data")
    ])

    # 2. INSTANTIATED ATTACK TREE (Selected Scenario)
    # We choose one specific path to simulate.
    # Scenario: shell -> curl -> payload.sh -> exfil_data
    attack_path = ["root", "shell", "curl", "payload.sh", "exfil_data"]
    
    # Flatten the tree into raw Logs (pid, ppid, is_target) for PIM
    logs = []
    pid_map = {}
    next_pid = 100
    
    current_ppid = 1 # Init
    for process_name in attack_path:
        pid = next_pid
        pid_map[pid] = process_name
        logs.append((pid, current_ppid, True))
        current_ppid = pid
        next_pid += 1

    # 3. ADDING NOISE (Benign system activity)
    noise_names = ["ls", "grep", "chrome", "svchost", "python", "git"]
    for i in range(num_noise):
        pid = next_pid
        # Noise can spawn from init (1) or randomly from other nodes
        ppid = random.choice([1, 100, 101]) 
        pid_map[pid] = random.choice(noise_names)
        logs.append((pid, ppid, False))
        next_pid += 1

    return master_graph, logs, pid_map

def plot_attack_graph(master_graph, filename="data/attack_graph.png"):
    plt.figure(figsize=(10, 8))
    pos = nx.spring_layout(master_graph, k=1.0) # Larger k for more spacing
    
    nx.draw(master_graph, pos, 
            with_labels=True, 
            node_color='#d1d1d1', # Light gray
            node_size=3000, 
            font_size=11, 
            font_weight='bold',
            arrowsize=25, 
            edge_color='#999999') # Medium gray

    plt.title("1. Master Attack Graph (Threat Model)", fontsize=16)
    plt.tight_layout()
    plt.axis('off')
    plt.savefig(filename, dpi=300) # Save high-res
    print(f"[Vizu] Saved Attack Graph to {filename}")
    # plt.show() # Uncomment if you want to see it pop up

def plot_attack_tree(logs, pid_map, filename="data/attack_tree.png"):
    G_logs = nx.DiGraph()
    colors = []
    labels = {}
    for pid, ppid, target in logs:
        G_logs.add_edge(ppid, pid)
    
    for node in G_logs:
        # Check if any part of this component is malicious
        is_malicious = any(p == node and t for p, pp, t in logs)
        # Red if malicious path, skyblue if benign noise
        colors.append('#ff4d4d' if is_malicious else '#add8e6') 
        name = pid_map.get(node, "init")
        labels[node] = f"{name}\n[{node}]"

    plt.figure(figsize=(12, 9))
    # Shell layout often looks better for process trees
    pos = nx.shell_layout(G_logs) 
    
    nx.draw(G_logs, pos, 
            labels=labels, 
            with_labels=True, 
            node_color=colors, 
            node_size=2800, 
            font_size=8, 
            font_weight='bold',
            arrowsize=20, 
            edge_color='#bbbbbb') # Light gray

    plt.title("2. Mined Attack Tree Instance (from Logs)", fontsize=16)
    plt.tight_layout()
    plt.axis('off')
    plt.savefig(filename, dpi=300) # Save high-res
    print(f"[Vizu] Saved Attack Tree to {filename}")
    # plt.show() # Uncomment if you want to see it pop up

# --- RUN THE PIPELINE ---
master, logs, pid_map = generate_ids_pipeline()

# Output the logs to a file for PIM simulator
with open("data/process_stream.log", "w") as f:
    for pid, ppid, target in sorted(logs):
        f.write(f"{pid},{ppid},{1 if target else 0}\n")
print(f"[Log] Generated {len(logs)} log entries in data/process_stream.log")

# Generate the separate plots
plot_attack_graph(master)
plot_attack_tree(logs, pid_map)