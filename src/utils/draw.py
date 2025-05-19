import networkx as nx
import matplotlib.pyplot as plt
from .constants import AssetType

def serialize_node(data)->str:
    s = ""
        
    name = data.get('name')
    _type = data.get('type')
    mac = data.get('mac')
    ip = data.get('ip')
    tags = data.get('tags')
    vendor = data.get('vendor')
    ports = data.get('ports')
    
    s+=f'{name if name else "*Unknown name*"}\n'
    s+=f'Type:{_type}\n'
    s+=f'Mac:{mac}\n'
    
    if ip: s+=f'IP:{ip}\n'
    if ports: s+=f'Open ports:{ports}\n'
    if vendor: s+=f'Device Vendor:{vendor}\n'
    if tags: s+=f'\nTags:{tags}\n'
    
    return s

def draw(assets:list, connections:list):
    G = nx.Graph()
        
    for a in assets:
        G.add_node(a.get_identifier(), type=a.type, mac=a.mac, tags=','.join(a.tags), ip=','.join(list(a.ips)),name=a.name,vendor=a.vendor, ports=','.join(list(a.ports)))
    
    for c in connections:
        G.add_edge(c.src.get_identifier(), c.dst.get_identifier(), tags=c.tags, ttl=c.ttl)
    
    plt.figure(figsize=(15, 8))
    pos = nx.spring_layout(G, k=1.9, iterations=200)

    


    node_labels = {
        node: serialize_node(data) for node, data in G.nodes(data=True)
    }

    # Custom edge labels
    edge_labels = {
        (u, v): f"TTL: {d['ttl']}" for u, v, d in G.edges(data=True)
    }
    type_colors = {
        AssetType.Switch: "#0ea5e9",
        AssetType.Router: "#3b82f6",
        AssetType.Workstation: "#10b981",
        AssetType.Server: "#22c55e",
        AssetType.Plc: "#ef4444",
        AssetType.Hmi: "#f59e0b",
        AssetType.Mtu: "#f97316",
        AssetType.Unknown: "#dbeafe",
    }
    node_colors = []
    
    for node, data in G.nodes(data=True):
        node_type = data.get("type", AssetType.Unknown)
        color = type_colors.get(node_type, "gray")
        node_colors.append(color)
    
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=1000)
    nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=6)
    nx.draw_networkx_edges(G, pos)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    
    # nx.draw(G, pos)
      
    plt.axis('off')
    plt.tight_layout()
    plt.title("Network Topology")
    plt.show()